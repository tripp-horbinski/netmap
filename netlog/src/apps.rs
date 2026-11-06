//! Which app a process is: executable path from the pid, then the outermost `.app` bundle's
//! Info.plist (name, bundle id, version, Sparkle update feed). Lets "(unknown)" opens tagged by
//! pktap, whose process names are truncated to 16 chars, resolve to the same name lsof reports,
//! and explains update checks like releases.zentty.org.

use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::path::Path;

unsafe extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut c_char, buffersize: u32) -> i32;
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
    }
    info
}

/// Resolves pids to apps with a cache per executable path; a pid is re-checked each time
/// because pids are recycled.
#[derive(Default)]
pub struct Resolver {
    by_path: HashMap<String, AppInfo>,
}

impl Resolver {
    pub fn for_pid(&mut self, pid: i32) -> Option<AppInfo> {
        let path = exe_path(pid)?;
        Some(self.by_path.entry(path.clone()).or_insert_with(|| describe(&path)).clone())
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
    fn bare_binary() {
        let i = describe("/usr/libexec/nsurlsessiond");
        assert_eq!(i.process, "nsurlsessiond");
        assert_eq!(i.bundle_id, None);
    }

    #[test]
    fn own_pid_resolves() {
        let me = exe_path(std::process::id() as i32).unwrap();
        assert!(me.ends_with("netlog") || me.contains("netlog-"), "{me}");
    }
}
