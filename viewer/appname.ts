// Product names for processes, server-side twin of appName() in static/app.js: one name per
// product whatever the helper, bundle names from the apps table, version-named binaries, and the
// " [headless]" / " [automated]" instance tags netlog records. Keep the alias table in sync.
export interface AppRowLite { process: string; name: string | null; version: string | null; path: string | null; bundle_id: string | null; feed_url: string | null }

const APP_ALIAS: [RegExp, string][] = [
  [/^Google Chrome( Helper.*| Canary)?$/, "Chrome"], [/^Chromium/, "Chromium"], [/^Microsoft Edge/, "Edge"],
  [/^Brave Browser/, "Brave"], [/^Arc( Helper.*)?$/, "Arc"], [/^firefox/i, "Firefox"], [/^(Safari|com\.apple\.WebKit)/, "Safari"],
  [/^Code Helper/, "VS Code"], [/^Electron( Helper.*)?$/, "Electron"],
];

export function appName(process: string, apps: Map<string, AppRowLite>): string {
  const kind = /^(.*) \[(headless|automated)\]$/.exec(process);
  if (kind) return `${appName(kind[1]!, apps)} (${kind[2]})`;
  for (const [re, name] of APP_ALIAS) if (re.test(process)) return name;
  const a = apps.get(process);
  if (a?.name) return a.version && process === a.version ? `${a.name} ${a.version}` : a.name;
  if (process.length === 16) {
    const full = [...apps.keys()].find((k) => k.length > 16 && k.startsWith(process));
    if (full) return appName(full, apps);
    if (/^Google Chrome/.test(process)) return "Chrome";
  }
  return process.replace(/ Helper( \(.*\))?$/, "").replace(/ \((Renderer|GPU|Plugin|Networking|Alerts|Utility)\)$/, "");
}
