// netmap · shared page helpers: the top nav, the theme toggle, formatting, sparklines, tables
// and one EventSource per page that feeds the nav's live indicator.
window.nm = (() => {
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtN = (n) => (n ?? 0).toLocaleString();
  const compact = (n) => (n >= 10000 ? `${(n / 1000).toFixed(n >= 100000 ? 0 : 1)}K` : fmtN(n));
  const ago = (ts) => {
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 90) return `${Math.round(s)}s ago`;
    if (s < 5400) return `${Math.round(s / 60)}m ago`;
    if (s < 172800) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  };
  const when = (ts, secs = false) => new Date(ts * 1000).toLocaleString([], {
    month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', ...(secs ? { second: '2-digit' } : {}),
  });
  const ms = (s) => (s < 1 ? `${Math.round(s * 1000)} ms` : `${s.toFixed(1)} s`);

  // ---- theme: auto (OS) / light / dark, stored in localStorage, stamped on <html data-theme> ----
  const THEMES = ['auto', 'light', 'dark'];
  const ICON = { auto: '◐', light: '☀', dark: '☾' };
  const getTheme = () => { try { return localStorage.getItem('nm-theme') || 'auto'; } catch { return 'auto'; } };
  const isDark = () => {
    const t = getTheme();
    return t === 'dark' || (t === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
  };
  function setTheme(t) {
    try { t === 'auto' ? localStorage.removeItem('nm-theme') : localStorage.setItem('nm-theme', t); } catch {}
    if (t === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
    const b = document.getElementById('theme-btn');
    if (b) { b.textContent = `${ICON[t]} ${t[0].toUpperCase()}${t.slice(1)}`; b.title = 'Theme: follows the system, light, or dark'; }
    window.dispatchEvent(new CustomEvent('nm:theme', { detail: { dark: isDark() } }));
  }
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (getTheme() === 'auto') setTheme('auto'); });
  /** Read a CSS token (e.g. '--accent') as it currently resolves. */
  const token = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  // Process names from lsof are helper processes ("Google Chrome Helper (Aperitif)"); the product
  // name is what a person wants to see. The raw name stays in `raw` on the records.
  const APP_ALIAS = [
    [/^Google Chrome( Helper.*| Canary)?$/, 'Chrome'], [/^Chromium/, 'Chromium'], [/^Microsoft Edge/, 'Edge'],
    [/^Brave Browser/, 'Brave'], [/^Arc( Helper.*)?$/, 'Arc'], [/^firefox/i, 'Firefox'], [/^(Safari|com\.apple\.WebKit)/, 'Safari'],
    [/^Code Helper/, 'VS Code'], [/^Electron( Helper.*)?$/, 'Electron'],
  ];
  // Resolved by netlog from the executable's bundle (/api/apps): process name -> app.
  const apps = new Map();
  fetch('/api/apps').then((r) => (r.ok ? r.json() : [])).then((rows) => { for (const a of rows) apps.set(a.process, a); }).catch(() => {});
  const appInfo = (p) => apps.get(p) ?? null;
  function appName(p) {
    if (!p) return p;
    for (const [re, name] of APP_ALIAS) if (re.test(p)) return name; // one name per product, whatever the helper
    const a = apps.get(p);
    if (a?.path?.includes('/share/claude/versions/')) return 'Claude Code'; // its binary is named by version
    if (a?.name) return a.name;
    return p.replace(/ Helper( \(.*\))?$/, '').replace(/ \((Renderer|GPU|Plugin|Networking|Alerts|Utility)\)$/, '');
  }
  /** Rewrite process names on a /api/data snapshot in place; the raw name is kept as `raw`. */
  function aliasConnections(d) {
    for (const c of d.connections) { c.raw = c.process; c.via = d.via?.[c.process] ?? null; c.process = appName(c.process); }
    return d;
  }
  /** Group per-process counts under the app each was launched from: [{ name, n, live, children: [...] }]. */
  function groupByVia(items) {
    const top = new Map();
    const get = (name) => top.get(name) ?? top.set(name, { name, n: 0, own: 0, live: false, children: [] }).get(name);
    for (const it of items) {
      if (it.via && it.via !== it.name) { const g = get(it.via); g.children.push(it); g.n += it.n; g.live ||= it.live; }
      else { const g = get(it.name); g.own = it.n; g.n += it.n; g.live ||= it.live; }
    }
    for (const g of top.values()) g.children.sort((a, b) => b.n - a.n);
    return [...top.values()].sort((a, b) => b.n - a.n);
  }

  // Stable per-app hue; lightness suits the surface so dots read on both themes.
  function color(name) {
    let h = 0;
    for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return isDark() ? `hsl(${h % 360}, 70%, 62%)` : `hsl(${h % 360}, 65%, 40%)`;
  }

  // ---- nav ------------------------------------------------------------------------------
  const PAGES = [['/', 'Overview'], ['/map', 'Map'], ['/devices', 'Devices'], ['/sites', 'Sites']];
  function nav(active) {
    const el = document.getElementById('nav');
    el.className = 'nav';
    el.innerHTML = `<a class="brand" href="/">net<span>map</span></a>
      <nav>${PAGES.map(([h, t]) => `<a href="${h}"${h === active ? ' class="on"' : ''}>${t}</a>`).join('')}</nav>
      <div class="right"><span class="live" id="nav-live" title="Connection opens per minute, pushed live by netlog record"><i></i><span>offline</span></span>
      <button class="theme" id="theme-btn"></button></div>`;
    document.getElementById('theme-btn').onclick = () => setTheme(THEMES[(THEMES.indexOf(getTheme()) + 1) % 3]);
    setTheme(getTheme());
  }

  // ---- live stream: one EventSource, recent opens kept for rate + feeds ----------------------
  const live = { events: [], open: false, listeners: [] };
  function perMinute() { const now = Date.now() / 1000; return live.events.filter((e) => now - e.ts < 60).length; }
  function tickNav() {
    const el = document.getElementById('nav-live'); if (!el) return;
    live.open = live.src?.readyState === 1;
    el.classList.toggle('on', live.open);
    const n = perMinute();
    el.lastElementChild.textContent = !live.open ? 'offline' : n ? `${n}${n >= 60 ? '+' : ''}/min` : 'live';
  }
  function stream(onEvent) {
    if (onEvent) live.listeners.push(onEvent);
    if (live.src) return live;
    live.src = new EventSource('/api/stream');
    live.src.onopen = () => { live.open = true; tickNav(); };
    live.src.onerror = () => { live.open = false; tickNav(); };
    live.src.onmessage = (m) => {
      const e = JSON.parse(m.data);
      e.raw = e.app; e.app = appName(e.app);
      live.events.unshift(e); live.events.splice(120);
      tickNav();
      for (const f of live.listeners) f(e);
    };
    setInterval(tickNav, 5000);
    return live;
  }

  // ---- choropleth helpers ---------------------------------------------------------------
  // DB-IP country names that differ from Natural Earth's (110m) feature names. Places with no polygon at
  // this scale (Hong Kong, Singapore, Bahrain) stay unshaded; their dots still draw.
  const COUNTRY_ALIAS = {
    'United States': 'United States of America', 'The Netherlands': 'Netherlands',
    'Czech Republic': 'Czechia', 'Russian Federation': 'Russia', 'Korea, Republic of': 'South Korea', 'Republic of Korea': 'South Korea',
    "Korea, Democratic People's Republic of": 'North Korea', 'Viet Nam': 'Vietnam', 'Bosnia and Herzegovina': 'Bosnia and Herz.',
    'Dominican Republic': 'Dominican Rep.', 'Democratic Republic of the Congo': 'Dem. Rep. Congo', 'Congo, The Democratic Republic of the': 'Dem. Rep. Congo',
    'Republic of the Congo': 'Congo', "Cote d'Ivoire": "Côte d'Ivoire", 'Ivory Coast': "Côte d'Ivoire", "Lao People's Democratic Republic": 'Laos',
    'North Macedonia': 'Macedonia', 'Syrian Arab Republic': 'Syria', 'Iran, Islamic Republic of': 'Iran', 'Taiwan, Province of China': 'Taiwan',
    'Tanzania, United Republic of': 'Tanzania', 'Moldova, Republic of': 'Moldova', 'Central African Republic': 'Central African Rep.',
    'South Sudan': 'S. Sudan', 'Equatorial Guinea': 'Eq. Guinea', 'Western Sahara': 'W. Sahara', 'Solomon Islands': 'Solomon Is.',
    'Falkland Islands (Malvinas)': 'Falkland Is.', 'Eswatini': 'eSwatini', 'Brunei Darussalam': 'Brunei', 'Palestine, State of': 'Palestine',
    'Bolivia, Plurinational State of': 'Bolivia', 'Venezuela, Bolivarian Republic of': 'Venezuela', 'Türkiye': 'Turkey', 'Turkiye': 'Turkey',
    'Somaliland': 'Somalia', 'Timor-Leste': 'Timor-Leste', 'Myanmar': 'Myanmar', 'Northern Cyprus': 'N. Cyprus',
  };
  const countryKey = (name) => (name ? COUNTRY_ALIAS[name] ?? name.replace(/^The /, '') : null);
  const hex = (h) => { const m = /^#?([0-9a-f]{6})$/i.exec(h.trim()); return m ? [0, 2, 4].map((i) => parseInt(m[1].slice(i, i + 2), 16)) : null; };
  /** Mix two hex colors: t = 0 gives a, t = 1 gives b. */
  function mix(a, b, t) {
    const A = hex(a), B = hex(b); if (!A || !B) return b;
    return '#' + A.map((x, i) => Math.round(x + (B[i] - x) * t).toString(16).padStart(2, '0')).join('');
  }
  /** Sequential fill for a country with n of max: the land color stepped toward the accent, one hue. */
  const choroFill = (n, max) => (n ? mix(token('--map-land'), token('--accent'), 0.15 + 0.7 * Math.sqrt(n / max)) : token('--map-land'));

  // ---- marks ---------------------------------------------------------------------------
  /** Bar sparkline over equal time bins; last bin (now) in the text ink. One <title> per bar. */
  function spark(bins, win, { cls = '', label = 'lookups' } = {}) {
    const max = Math.max(1, ...bins);
    const w = 100, h = 100, gap = 1.2, bw = w / bins.length - gap;
    const bars = bins.map((n, i) => {
      const bh = n ? Math.max(4, (n / max) * h) : 0;
      const t0 = win.start + i * win.bin_seconds, t1 = t0 + win.bin_seconds;
      return `<rect${i === bins.length - 1 ? ' class="now"' : ''} x="${(i * (bw + gap)).toFixed(2)}" y="${(h - bh).toFixed(2)}" width="${bw.toFixed(2)}" height="${bh.toFixed(2)}" rx="1"><title>${fmtN(n)} ${label} · ${when(t0)} – ${when(t1)}</title></rect>`;
    }).join('');
    return `<svg class="spark ${cls}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="${label} over time">${bars}</svg>`;
  }
  /** Stacked bar sparkline: series = [{ name, bins, color }] over the same bins; legend below. */
  function stackedSpark(series, win, { label = 'opens' } = {}) {
    const n = series[0]?.bins.length ?? 0;
    const totals = Array.from({ length: n }, (_, i) => series.reduce((t, s) => t + s.bins[i], 0));
    const max = Math.max(1, ...totals);
    const w = 100, h = 100, gap = 1.2, bw = w / n - gap;
    let bars = '';
    for (let i = 0; i < n; i++) {
      let y = h;
      const t0 = win.start + i * win.bin_seconds, t1 = t0 + win.bin_seconds;
      const parts = series.filter((s) => s.bins[i]).map((s) => `${s.name} ${fmtN(s.bins[i])}`).join(', ');
      for (const s of series) {
        if (!s.bins[i]) continue;
        const bh = (s.bins[i] / max) * h; y -= bh;
        bars += `<rect x="${(i * (bw + gap)).toFixed(2)}" y="${y.toFixed(2)}" width="${bw.toFixed(2)}" height="${Math.max(0.5, bh - 0.6).toFixed(2)}" style="fill:${s.color}"><title>${fmtN(totals[i])} ${label} · ${when(t0)} – ${when(t1)}\n${esc(parts)}</title></rect>`;
      }
    }
    const legend = series.map((s) => `<span><i class="dot" style="background:${s.color}"></i>${esc(s.name)}</span>`).join('');
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="${label} over time by app">${bars}</svg><div class="chips">${legend}</div>`;
  }
  /** Signed change vs a named prior period; `upIsBad` colors a rise as a warning. */
  function delta(cur, prev, period, upIsBad = false) {
    if (prev == null || (!prev && !cur)) return '';
    const pct = prev ? Math.round((100 * (cur - prev)) / prev) : null;
    const dir = cur > prev ? 'up' : cur < prev ? 'down' : 'flat';
    const cls = dir === 'flat' ? '' : (dir === 'up') === upIsBad ? 'bad' : 'good';
    const txt = dir === 'flat' ? '±0' : `${dir === 'up' ? '▲' : '▼'} ${pct === null ? fmtN(Math.abs(cur - prev)) : Math.abs(pct) + '%'}`;
    return `<span class="delta ${cls}" title="${fmtN(cur)} now vs ${fmtN(prev)} in the ${period} before">${txt} <small>vs prior ${period}</small></span>`;
  }
  /** Bin timestamps into `n` equal bins ending now; returns { bins, window } like the devices API. */
  function binTimes(stamps, sinceSeconds, n = 24) {
    const now = Date.now() / 1000, start = now - sinceSeconds, bin_seconds = sinceSeconds / n;
    const bins = new Array(n).fill(0);
    for (const t of stamps) { const i = Math.floor((t - start) / bin_seconds); if (i >= 0 && i < n) bins[i]++; }
    return { bins, window: { start, bin_seconds } };
  }
  function rows(list, cols, empty) {
    if (!list.length) return `<div class="muted">${empty}</div>`;
    return `<table><thead><tr>${cols.map((c) => `<th class="${c.n ? 'n' : ''}">${c.h}</th>`).join('')}</tr></thead>
      <tbody>${list.map((r) => `<tr>${cols.map((c) => `<td class="${c.n ? 'n' : ''}">${c.f(r)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  }
  /** Rows with a proportional wash: items = [{ name, n, href? }]. */
  function bars(items, empty = 'Nothing yet.') {
    if (!items.length) return `<li class="muted">${empty}</li>`;
    const max = Math.max(1, ...items.map((i) => i.n));
    return items.map((i) => `<li style="--w:${(100 * i.n / max).toFixed(1)}%"><span class="name">${i.href ? `<a href="${esc(i.href)}">${esc(i.name)}</a>` : esc(i.name)}</span><span class="n">${fmtN(i.n)}</span></li>`).join('');
  }
  /** Segmented control: buttons with data-w inside `el`; calls onChange(value). */
  function segment(el, value, onChange) {
    const set = (v) => { for (const b of el.querySelectorAll('button')) b.classList.toggle('on', b.dataset.w === v); };
    set(value);
    el.addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; set(b.dataset.w); onChange(b.dataset.w); });
  }
  const WINDOW_SECONDS = { '1h': 3600, '24h': 86400, '7d': 604800, all: Infinity };

  return { esc, fmtN, compact, ago, when, ms, nav, stream, live, perMinute, spark, binTimes, rows, bars, segment, color, token, isDark, WINDOW_SECONDS, countryKey, mix, choroFill, stackedSpark, delta, appName, appInfo, aliasConnections, groupByVia };
})();
