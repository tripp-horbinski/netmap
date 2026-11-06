// netmap browser reporter: for every request Chrome makes, record which tab asked for it and what
// page that tab was showing, then POST batches to the netmap viewer on localhost. Nothing leaves
// the machine; the viewer stores it in data/netmap.sqlite next to netlog's own records.
//
// Chrome routes every tab's traffic through one Network Service process, so from outside the
// browser netlog only sees "Google Chrome Helper". This is the inside view it cannot get.

const DEFAULT_ENDPOINT = 'http://127.0.0.1:8765/api/browser/requests';
const FLUSH_MS = 1500;      // how long a request waits in the buffer so onCompleted can add its IP and end time
const HOLD_S = 10;          // an unfinished request is sent after this long with no end time

const tabs = new Map();     // tabId -> { url, host, navTs }
const buffer = new Map();   // requestId -> record
let timer = null;
let endpoint = DEFAULT_ENDPOINT;

chrome.storage.sync.get({ endpoint: DEFAULT_ENDPOINT }, (v) => { endpoint = v.endpoint || DEFAULT_ENDPOINT; });
chrome.storage.onChanged.addListener((c) => { if (c.endpoint) endpoint = c.endpoint.newValue || DEFAULT_ENDPOINT; });

const hostOf = (url) => { try { return new URL(url).hostname || null; } catch { return null; } };

function remember(tabId, url, navTs) {
  const host = hostOf(url);
  if (!host || !/^https?:/.test(url)) { tabs.delete(tabId); return; }
  tabs.set(tabId, { url, host, navTs });
}
// Seed from the open tabs so requests right after install already have a page to belong to.
chrome.tabs.query({}, (list) => { for (const t of list) if (t.url) remember(t.id, t.url, Date.now() / 1000); });
chrome.webNavigation.onCommitted.addListener((d) => { if (d.frameId === 0) remember(d.tabId, d.url, d.timeStamp / 1000); });
chrome.tabs.onRemoved.addListener((id) => tabs.delete(id));

chrome.webRequest.onBeforeRequest.addListener((d) => {
  const host = hostOf(d.url);
  if (!host || host === 'localhost' || host === '127.0.0.1') return;
  const tab = tabs.get(d.tabId);
  // Requests with no tab (service workers, extensions, prefetch) are attributed to their initiator.
  const site = d.type === 'main_frame' ? host : tab?.host ?? hostOf(d.initiator ?? '') ?? null;
  buffer.set(d.requestId, {
    ts: d.timeStamp / 1000, tab: d.tabId, nav_ts: d.type === 'main_frame' ? d.timeStamp / 1000 : tab?.navTs ?? null,
    site, host, type: d.type, initiator: hostOf(d.initiator ?? ''), ip: null, cached: false, end: null, status: null, bytes: null,
  });
  if (!timer) timer = setTimeout(flush, FLUSH_MS);
}, { urls: ['<all_urls>'] });

chrome.webRequest.onCompleted.addListener((d) => {
  const r = buffer.get(d.requestId);
  if (!r) return;
  r.ip = d.ip ?? null; r.cached = !!d.fromCache; r.end = d.timeStamp / 1000; r.status = d.statusCode;
  const len = (d.responseHeaders ?? []).find((h) => h.name.toLowerCase() === 'content-length');
  if (len) r.bytes = Number(len.value) || null;
}, { urls: ['<all_urls>'] }, ['responseHeaders']);
chrome.webRequest.onErrorOccurred.addListener((d) => {
  const r = buffer.get(d.requestId);
  if (r) { r.end = d.timeStamp / 1000; r.status = 0; }
}, { urls: ['<all_urls>'] });

async function flush() {
  timer = null;
  // Send what has finished (or has waited long enough); keep the rest for their end time.
  const now = Date.now() / 1000;
  const rows = [];
  for (const [id, r] of buffer) if (r.end != null || now - r.ts > HOLD_S) { rows.push(r); buffer.delete(id); }
  if (buffer.size && !timer) timer = setTimeout(flush, FLUSH_MS);
  if (!rows.length) return;
  try {
    await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rows }) });
    chrome.storage.local.set({ last_ok: Date.now(), last_error: null });
  } catch (e) {
    chrome.storage.local.set({ last_error: String(e) });
  }
}
