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
}

impl Resolver {
    pub fn for_pid(&mut self, pid: i32) -> Option<AppInfo> {
        let path = exe_path(pid)?;
        Some(self.by_path.entry(path.clone()).or_insert_with(|| describe(&path)).clone())
    }

    /// The app a process was launched from: the first ancestor living in a different `.app`
    /// bundle, so `ssh` run in a terminal reports the terminal and a Chrome helper reports
    /// nothing (its parent is Chrome itself). None for daemons under launchd.
    pub fn via(&mut self, pid: i32) -> Option<String> {
        if self.via_cache.len() > 5000 {
            self.via_cache.clear();
        }
        if let Some(v) = self.via_cache.get(&pid) {
            return v.clone();
        }
        let own_bundle = exe_path(pid).as_deref().and_then(bundle_dir).map(str::to_string);
        let mut cur = pid;
        let mut found = None;
        for _ in 0..12 {
            let Some(parent) = parent_pid(cur) else { break };
            if parent <= 1 || parent == cur {
                break;
            }
            if let Some(path) = exe_path(parent) {
                if let Some(dir) = bundle_dir(&path) {
                    if own_bundle.as_deref() != Some(dir) {
                        let info = self.by_path.entry(path.clone()).or_insert_with(|| describe(&path));
                        found = info.name.clone().or_else(|| Some(info.process.clone()));
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
        assert_eq!(versioned_binary("/usr/bin/curl"), None);
        assert_eq!(versioned_binary("/opt/x/versions/notes"), None);
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
        eprintln!("via = {via:?}");
    }

    #[test]
    fn own_pid_resolves() {
        let me = exe_path(std::process::id() as i32).unwrap();
        assert!(me.ends_with("netlog") || me.contains("netlog-"), "{me}");
    }
}

