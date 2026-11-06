//! Which app a process is: executable path from the pid, then the outermost `.app` bundle's
//! Info.plist (name, bundle id, version, Sparkle update feed). Lets "(unknown)" opens tagged by
//! pktap, whose process names are truncated to 16 chars, resolve to the same name lsof reports,
//! and explains update checks like releases.zentty.org.

use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::path::Path;

unsafe extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut c_char, buffersize: u32) -> i32;
    fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut u8, buffersize: i32) -> i32;
    fn sysctl(name: *const i32, namelen: u32, oldp: *mut u8, oldlenp: *mut usize, newp: *const u8, newlen: usize) -> i32;
}

const CTL_KERN: i32 = 1;
const KERN_PROCARGS2: i32 = 49;

/// A process's command line (kern.procargs2): argc, the exec path, then NUL-separated argv.
/// Needs the same uid or root; None for other users' processes or ones that have exited.
pub fn args(pid: i32) -> Option<Vec<String>> {
    let mib = [CTL_KERN, KERN_PROCARGS2, pid];
    let mut size: usize = 0;
    if unsafe { sysctl(mib.as_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null(), 0) } != 0 || size < 4 {
        return None;
    }
    let mut buf = vec![0u8; size];
    if unsafe { sysctl(mib.as_ptr(), 3, buf.as_mut_ptr(), &mut size, std::ptr::null(), 0) } != 0 {
        return None;
    }
    buf.truncate(size);
    let argc = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut i = 4;
    while i < buf.len() && buf[i] != 0 { i += 1; } // exec path
    while i < buf.len() && buf[i] == 0 { i += 1; } // padding
    let mut out = Vec::with_capacity(argc);
    while out.len() < argc && i < buf.len() {
        let start = i;
        while i < buf.len() && buf[i] != 0 { i += 1; }
        out.push(String::from_utf8_lossy(&buf[start..i]).into_owned());
        i += 1;
    }
    Some(out)
}

/// How a Chromium-family browser was started, from its flags: "headless" (no window, e.g. a
/// screenshot run from a script), "automated" (driven over DevTools by Playwright, Puppeteer,
/// Selenium or a CDP client), or None for a browser a person opened. Helpers usually inherit
/// the flags, and `Resolver::kind` also checks the parent within the same bundle.
pub fn kind_from_args(args: &[String]) -> Option<&'static str> {
    let has = |p: &str| args.iter().any(|a| a == p || a.starts_with(&format!("{p}=")));
    if has("--headless") {
        Some("headless")
    } else if has("--remote-debugging-pipe") || has("--remote-debugging-port") || has("--enable-automation") {
        Some("automated")
    } else {
        None
    }
}

/// libproc's PROC_PIDTBSDINFO: a 136-byte `proc_bsdinfo` whose parent pid sits at offset 16.
const PROC_PIDTBSDINFO: i32 = 3;
const BSDINFO_SIZE: i32 = 136;

/// Parent process id, None once the process is gone. libproc refuses other users' processes
/// unless we are root (the terminal's `login` is root-owned), so fall back to `ps`, which may ask.
pub fn parent_pid(pid: i32) -> Option<i32> {
    let mut buf = [0u8; BSDINFO_SIZE as usize];
    let n = unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, buf.as_mut_ptr(), BSDINFO_SIZE) };
    if n >= 20 {
        return Some(i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]));
    }
    let out = std::process::Command::new("ps").args(["-o", "ppid=", "-p", &pid.to_string()]).output().ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Full path of a running process's executable (libproc), None if it has exited.
pub fn exe_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let n = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut c_char, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    let s = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    Some(s.to_string_lossy().into_owned())
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppInfo {
    /// Executable file name: what lsof reports as the process name.
    pub process: String,
    pub path: String,
    pub bundle_id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub feed_url: Option<String>,
}

impl AppInfo {
    /// What to call this app in a `via` chain: the bundle or product name, with the version when
    /// the executable itself is named by its version ("Claude Code 2.1.319"), matching the pages.
    pub fn label(&self) -> Option<String> {
        let name = self.name.as_ref()?;
        Some(match &self.version {
            Some(v) if *v == self.process => format!("{name} {v}"),
            _ => name.clone(),
        })
    }
}

/// The outermost `.app` directory on the path, so helpers deep inside Chrome resolve to Chrome.
pub fn bundle_dir(path: &str) -> Option<&str> {
    let i = path.find(".app/")?;
    Some(&path[..i + 4])
}

fn plist_str(v: &plist::Value, key: &str) -> Option<String> {
    v.as_dictionary()?.get(key)?.as_string().map(str::to_string)
}

/// Describe the executable at `path`; bundle fields stay None for bare binaries and daemons.
pub fn describe(path: &str) -> AppInfo {
    let process = Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string());
    let mut info = AppInfo { process, path: path.to_string(), ..Default::default() };
    if let Some(dir) = bundle_dir(path) {
        if let Ok(v) = plist::Value::from_file(Path::new(dir).join("Contents/Info.plist")) {
            info.bundle_id = plist_str(&v, "CFBundleIdentifier");
            info.name = plist_str(&v, "CFBundleDisplayName").or_else(|| plist_str(&v, "CFBundleName"));
            info.version = plist_str(&v, "CFBundleShortVersionString");
            info.feed_url = plist_str(&v, "SUFeedURL");
        }
        if info.name.is_none() {
            info.name = Path::new(dir).file_stem().map(|s| s.to_string_lossy().into_owned());
        }
    } else if let Some((product, version)) = versioned_binary(path) {
        // Tools installed as <product>/versions/<version>: the executable is named by its version.
        info.name = Some(product);
        info.version = Some(version);
    }
    info
}

/// "/Users/me/.local/share/claude/versions/2.1.319" -> ("Claude Code", "2.1.319"). The product
/// name comes from the directory above `versions`, with the few we know spelled properly.
pub fn versioned_binary(path: &str) -> Option<(String, String)> {
    let p = Path::new(path);
    let version = p.file_name()?.to_str()?;
    if !version.chars().next().is_some_and(|c| c.is_ascii_digit()) || !version.contains('.') {
        return None;
    }
    let parent = p.parent()?;
    if parent.file_name()?.to_str()? != "versions" {
        return None;
    }
    let product = parent.parent()?.file_name()?.to_str()?;
    let name = match product {
        "claude" => "Claude Code".to_string(),
        other => other.to_string(),
    };
    Some((name, version.to_string()))
}

/// Resolves pids to apps with a cache per executable path; a pid is re-checked each time
/// because pids are recycled.
#[derive(Default)]
pub struct Resolver {
    by_path: HashMap<String, AppInfo>,
    /// pid -> the app it was launched from (see `via`), while the process lives.
    via_cache: HashMap<i32, Option<String>>,
    /// pid -> instance kind (see `kind`), while the process lives.
    kind_cache: HashMap<i32, Option<&'static str>>,
}

impl Resolver {
    pub fn for_pid(&mut self, pid: i32) -> Option<AppInfo> {
        let path = exe_path(pid)?;
        Some(self.by_path.entry(path.clone()).or_insert_with(|| describe(&path)).clone())
    }

    /// Instance kind for a pid: its own flags, else those of ancestors inside the same `.app`
    /// bundle (a helper's main browser process). Appended to the process name as " [kind]" so a
    /// headless or automated browser is a different app from the one the person uses.
    pub fn kind(&mut self, pid: i32) -> Option<&'static str> {
        if self.kind_cache.len() > 5000 {
            self.kind_cache.clear();
        }
        if let Some(k) = self.kind_cache.get(&pid) {
            return *k;
        }
        let own = exe_path(pid);
        let bundle = own.as_deref().and_then(bundle_dir).map(str::to_string);
        let mut kind = args(pid).as_deref().and_then(kind_from_args);
        let mut cur = pid;
        while kind.is_none() && bundle.is_some() {
            let Some(parent) = parent_pid(cur) else { break };
            if parent <= 1 || parent == cur { break; }
            let Some(path) = exe_path(parent) else { break };
            if bundle_dir(&path).map(str::to_string) != bundle { break; }
            kind = args(parent).as_deref().and_then(kind_from_args);
            cur = parent;
        }
        self.kind_cache.insert(pid, kind);
        kind
    }

    /// The process name netlog records: the executable name plus " [headless]" / " [automated]".
    pub fn tagged_name(&mut self, name: &str, pid: i32) -> String {
        match self.kind(pid) {
            Some(k) => format!("{name} [{k}]"),
            None => name.to_string(),
        }
    }

    /// The app a process was launched from: the nearest ancestor that resolves to an app (a
    /// different `.app` bundle, or a versioned product binary like Claude Code), so `gh` run by
    /// Claude Code in a terminal reports Claude Code, Claude Code reports the terminal, and a
    /// Chrome helper reports nothing (its parent is Chrome itself). None for daemons under launchd.
    pub fn via(&mut self, pid: i32) -> Option<String> {
        if self.via_cache.len() > 5000 {
            self.via_cache.clear();
        }
        if let Some(v) = self.via_cache.get(&pid) {
            return v.clone();
        }
        let own_path = exe_path(pid);
        let own_bundle = own_path.as_deref().and_then(bundle_dir).map(str::to_string);
        let mut cur = pid;
        let mut found = None;
        for _ in 0..12 {
            let Some(parent) = parent_pid(cur) else { break };
            if parent <= 1 || parent == cur {
                break;
            }
            if let Some(path) = exe_path(parent) {
                let same_app = Some(path.as_str()) == own_path.as_deref()
                    || (own_bundle.is_some() && bundle_dir(&path).map(str::to_string) == own_bundle);
                if !same_app {
                    let info = self.by_path.entry(path.clone()).or_insert_with(|| describe(&path));
                    if let Some(label) = info.label() {
                        found = Some(label);
                        break;
                    }
                }
            }
            cur = parent;
        }
        self.via_cache.insert(pid, found.clone());
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outermost_bundle() {
        let p = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper (Aperitif).app/Contents/MacOS/Google Chrome Helper (Aperitif)";
        assert_eq!(bundle_dir(p), Some("/Applications/Google Chrome.app"));
        assert_eq!(bundle_dir("/usr/libexec/nsurlsessiond"), None);
    }

    #[test]
    fn claude_code_binary() {
        let i = describe("/Users/tripp/.local/share/claude/versions/2.1.319");
        assert_eq!(i.process, "2.1.319");
        assert_eq!(i.name.as_deref(), Some("Claude Code"));
        assert_eq!(i.version.as_deref(), Some("2.1.319"));
        assert_eq!(i.label().as_deref(), Some("Claude Code 2.1.319"));
        assert_eq!(describe("/usr/libexec/nsurlsessiond").label(), None);
        assert_eq!(versioned_binary("/usr/bin/curl"), None);
        assert_eq!(versioned_binary("/opt/x/versions/notes"), None);
    }

    #[test]
    fn kinds() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(kind_from_args(&s(&["Google Chrome", "--headless=new", "--screenshot"])), Some("headless"));
        assert_eq!(kind_from_args(&s(&["Chromium", "--remote-debugging-pipe", "--enable-automation"])), Some("automated"));
        assert_eq!(kind_from_args(&s(&["Google Chrome", "--remote-debugging-port=9333"])), Some("automated"));
        assert_eq!(kind_from_args(&s(&["Google Chrome"])), None);
        // Our own command line is readable, and a test binary has no browser flags.
        let me = std::process::id() as i32;
        assert!(args(me).is_some_and(|a| !a.is_empty()));
        assert_eq!(Resolver::default().kind(me), None);
    }

    #[test]
    fn bare_binary() {
        let i = describe("/usr/libexec/nsurlsessiond");
        assert_eq!(i.process, "nsurlsessiond");
        assert_eq!(i.bundle_id, None);
    }

    #[test]
    fn parents_resolve() {
        let me = std::process::id() as i32;
        let p = parent_pid(me).unwrap();
        assert!(p > 0 && p != me);
        assert!(parent_pid(999_999_999).is_none());
        // Whatever launched the test binary, walking up must not panic or loop; from a terminal
        // it names the terminal app (login is root-owned, so this exercises the ps fallback).
        let via = Resolver::default().via(me);
        eprintln!("via = {via:?}"); // under Claude Code in a terminal: Some("Claude Code x.y.z")
    }

    #[test]
    fn own_pid_resolves() {
        let me = exe_path(std::process::id() as i32).unwrap();
        assert!(me.ends_with("netlog") || me.contains("netlog-"), "{me}");
    }
}

