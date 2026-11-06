const el = document.getElementById('endpoint');
chrome.storage.sync.get({ endpoint: 'http://127.0.0.1:8765/api/browser/requests' }, (v) => { el.value = v.endpoint; });
el.onchange = () => chrome.storage.sync.set({ endpoint: el.value.trim() });
chrome.storage.local.get(['last_ok', 'last_error'], (v) => {
  document.getElementById('status').textContent = v.last_error ? `last send failed: ${v.last_error}` : v.last_ok ? `last sent ${new Date(v.last_ok).toLocaleTimeString()}` : 'nothing sent yet';
});
