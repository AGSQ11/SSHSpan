//! Finding and starting PMXSpan on this computer (INTEGRATION-SPEC
//! section 1).
//!
//! SSHSpan never needs PMXSpan: nothing here runs at startup, in a connect
//! or in the tests' hot path. It runs when the user opens Settings >
//! Integrations, opens a server's or a key's menu (the status, to enable or
//! disable "Manage in PMXSpan" / "Add to PMXSpan..."), or picks one of
//! those actions. The URL PMXSpan gets is built by `crate::handoff` and
//! carries public data only.
//!
//! Launch order: the executable started with the URL as its single
//! argument (a path set in Settings, else a discovered one - the first
//! launch of a discovered path asks in a native dialog, and the approved
//! path is remembered); else the OS opens the URL when a `pmxspan` scheme
//! handler is registered; else the action is unavailable.

#[cfg(windows)]
mod registry;

#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The executable's file name.
#[cfg(windows)]
pub const EXE_NAME: &str = "pmxspan.exe";
#[cfg(not(windows))]
pub const EXE_NAME: &str = "pmxspan";

/// The hint shown beside a PMXSpan action that cannot run (spec section 1).
pub const NOT_FOUND_HINT: &str =
    "PMXSpan was not found on this computer. Install it or set its path in Settings.";

/// The `config` row holding the path the user set in Settings.
pub const USER_PATH_KEY: &str = "pmxspan.userPath";
/// The `config` row holding the discovered path the user approved.
pub const APPROVED_PATH_KEY: &str = "pmxspan.approvedPath";

/// What discovery looks at, so tests can inject every input. Production
/// fills it from the process environment ([`DiscoveryEnv::from_system`]).
#[derive(Debug, Clone, Default)]
pub struct DiscoveryEnv {
    /// `PATH`.
    pub path_var: Option<OsString>,
    /// The home directory.
    pub home: Option<PathBuf>,
    /// Windows rules (registry, `%ProgramFiles%`, `.exe`) instead of Unix.
    pub windows: bool,
    /// `%ProgramFiles%`.
    pub program_files: Option<PathBuf>,
    /// Install directories from the Uninstall registry entries whose
    /// `DisplayName` is `PMXSpan` (`InstallLocation`, or `DisplayIcon`'s
    /// directory), in the order found.
    pub registry_dirs: Vec<PathBuf>,
    /// Prefix for the fixed Unix locations (`/usr/bin` ...): `/` in
    /// production, a temporary directory in tests.
    pub root: PathBuf,
}

impl DiscoveryEnv {
    /// The real environment.
    pub fn from_system() -> Self {
        Self {
            path_var: std::env::var_os("PATH"),
            home: dirs::home_dir(),
            windows: cfg!(windows),
            program_files: std::env::var_os("ProgramFiles").map(PathBuf::from),
            registry_dirs: registry_install_dirs(),
            root: PathBuf::from("/"),
        }
    }
}

#[cfg(windows)]
fn registry_install_dirs() -> Vec<PathBuf> {
    registry::install_dirs("PMXSpan")
}

#[cfg(not(windows))]
fn registry_install_dirs() -> Vec<PathBuf> {
    Vec::new()
}

/// Whether `path` is a file this platform can start: a regular file, on
/// Unix with an execute bit, on Windows ending in `.exe`.
pub fn is_runnable(path: &Path, windows: bool) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    if windows {
        return has_exe_extension(path);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn has_exe_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
}

/// Check a path the user set in Settings (spec section 1): absolute,
/// exists, a regular file, on Windows ending with `.exe`. The error is the
/// message the user sees.
pub fn validate_user_path(path: &Path, windows: bool) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("Choose the PMXSpan program file.".into());
    }
    if !path.is_absolute() {
        return Err("The path to PMXSpan must be absolute.".into());
    }
    let meta =
        std::fs::metadata(path).map_err(|_| format!("Nothing exists at {}.", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file.", path.display()));
    }
    if windows && !has_exe_extension(path) {
        return Err("On Windows the path to PMXSpan must end with .exe.".into());
    }
    Ok(())
}

/// The candidates discovery tries, in the spec's order.
pub fn candidates(env: &DiscoveryEnv) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let on_path = |out: &mut Vec<PathBuf>| {
        if let Some(path) = &env.path_var {
            for dir in std::env::split_paths(path) {
                if dir.is_absolute() {
                    out.push(dir.join(if env.windows {
                        "pmxspan.exe"
                    } else {
                        "pmxspan"
                    }));
                }
            }
        }
    };
    if env.windows {
        for dir in &env.registry_dirs {
            out.push(dir.join("pmxspan.exe"));
        }
        if let Some(pf) = &env.program_files {
            out.push(pf.join("PMXSpan").join("pmxspan.exe"));
        }
        on_path(&mut out);
        return out;
    }
    on_path(&mut out);
    let root = |p: &str| env.root.join(p.trim_start_matches('/'));
    out.push(root("/usr/bin/pmxspan"));
    out.push(root("/usr/local/bin/pmxspan"));
    if let Some(home) = &env.home {
        out.push(home.join(".local/bin/pmxspan"));
    }
    out.push(root("/opt/PMXSpan/pmxspan"));
    if let Some(home) = &env.home {
        // ~/Applications/PMXSpan*.AppImage, newest name last-sorted first.
        if let Ok(entries) = std::fs::read_dir(home.join("Applications")) {
            let mut images: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("PMXSpan") && n.ends_with(".AppImage"))
                })
                .collect();
            images.sort();
            images.reverse();
            out.extend(images);
        }
    }
    out.push(root("/Applications/PMXSpan.app/Contents/MacOS/pmxspan"));
    out
}

/// The first candidate that is a runnable file.
pub fn discover(env: &DiscoveryEnv) -> Option<PathBuf> {
    candidates(env)
        .into_iter()
        .find(|p| is_runnable(p, env.windows))
}

/// Whether the OS has a handler for `pmxspan://` URLs: Linux asks
/// `xdg-mime`, Windows reads the registry. macOS has no reliable check
/// without extra frameworks, so it says no (the executable is found by
/// path there).
pub fn scheme_registered() -> bool {
    #[cfg(windows)]
    {
        registry::url_scheme_registered("pmxspan")
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-mime")
            .args(["query", "default", "x-scheme-handler/pmxspan"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

/// How a PMXSpan action would reach PMXSpan right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// The path set in Settings.
    UserPath(PathBuf),
    /// A discovered path: `approved` when the user already allowed it.
    Discovered { path: PathBuf, approved: bool },
    /// No executable, but the OS opens `pmxspan://` URLs.
    Scheme,
    /// Not available.
    None,
}

/// Decide the [`Route`] from the stored settings and the environment. A
/// stored user path that no longer validates is skipped (the status line
/// says so).
pub fn route(
    user_path: Option<&str>,
    approved_path: Option<&str>,
    env: &DiscoveryEnv,
    scheme: impl FnOnce() -> bool,
) -> Route {
    if let Some(p) = user_path.filter(|p| !p.is_empty()) {
        let path = PathBuf::from(p);
        if validate_user_path(&path, env.windows).is_ok() {
            return Route::UserPath(path);
        }
    }
    if let Some(path) = discover(env) {
        let approved = approved_path.is_some_and(|a| Path::new(a) == path);
        return Route::Discovered { path, approved };
    }
    if scheme() {
        Route::Scheme
    } else {
        Route::None
    }
}

/// Start `exe` with `url` as its single argument, detached: nothing is read
/// from it and SSHSpan does not wait for it (a thread reaps it on Unix).
pub fn spawn_with_url(exe: &Path, url: &str) -> std::io::Result<()> {
    let mut child = std::process::Command::new(exe)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// The native question before the first launch of a discovered path (spec
/// section 1): the exact path, and that only public data goes to it.
pub(crate) fn launch_question(path: &Path) -> crate::commands::CredentialPrompt {
    crate::commands::CredentialPrompt {
        title: "SSHSpan - Start PMXSpan?".into(),
        message: format!(
            "SSHSpan found PMXSpan at:\n\n{}\n\n\
             Allow SSHSpan to start this program to hand it a link? The link carries \
             public data only (a host, a guest id, or a public key) - never a password \
             or a private key. SSHSpan remembers your answer for this exact path and \
             asks again if the path changes.",
            path.display()
        ),
    }
}
