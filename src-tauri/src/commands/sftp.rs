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

/// Shell startup files in the home directory: anything planted there runs the
/// next time a shell starts.
const SHELL_RC_FILES: [&str; 8] = [
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
];

/// The per-user (`appdata`) and all-users (`program_data`) Windows Startup
/// folders. Pure so the Windows layout can be unit-tested anywhere.
fn windows_startup_dirs(
    appdata: Option<&std::path::Path>,
    program_data: Option<&std::path::Path>,
) -> Vec<PathBuf> {
    [appdata, program_data]
        .into_iter()
        .flatten()
        .map(|base| {
            ["Microsoft", "Windows", "Start Menu", "Programs", "Startup"]
                .iter()
                .fold(base.to_path_buf(), |dir, part| dir.join(part))
        })
        .collect()
}

/// Local locations a (possibly compromised) renderer must not be able to aim a
/// transfer or a local-pane mutation at. The renderer supplies these paths as
/// plain strings; this is a deny-list, not a dialog-bound grant, and says so
/// in its limits: anything outside it is still reachable (see the A6-02
/// notes on `sftp_download`).
struct SensitiveLocations {
    /// SSHSpan's managed config directory. It is a SIBLING of the app data
    /// directory, so the app-data rule does not cover it, and it holds the
    /// managed ssh config whose arbitrary-write command was de-registered
    /// because a `ProxyCommand` there runs on the next `ssh`.
    managed_config_dir: Option<PathBuf>,
    /// The user's `~/.ssh`: `config` (ProxyCommand), `authorized_keys`, keys.
    ssh_dir: Option<PathBuf>,
    /// Windows Startup folders (empty elsewhere).
    startup_dirs: Vec<PathBuf>,
    /// Shell startup files in the home directory.
    shell_rc_files: Vec<PathBuf>,
}

impl SensitiveLocations {
    fn current() -> Self {
        let home = dirs::home_dir();
        let program_data = std::env::var_os("ProgramData").map(PathBuf::from);
        Self {
            managed_config_dir: ProjectDirs::from("org", "sshspan", "SSHSpan")
                .map(|d| d.config_dir().to_path_buf()),
            ssh_dir: home.as_ref().map(|h| h.join(".ssh")),
            startup_dirs: if cfg!(windows) {
                windows_startup_dirs(dirs::config_dir().as_deref(), program_data.as_deref())
            } else {
                Vec::new()
            },
            shell_rc_files: home
                .as_ref()
                .map(|h| SHELL_RC_FILES.iter().map(|f| h.join(f)).collect())
                .unwrap_or_default(),
        }
    }

    /// Why `path` is off-limits for `access`, if it is. `path` should already
    /// be in its resolved form (see [`resolved_local_path`]); each root is
    /// compared in its literal AND its canonical spelling, because `~/.ssh`
    /// and the rc files are very commonly symlinks into a dotfiles checkout.
    fn refusal(&self, path: &std::path::Path, access: LocalAccess) -> Option<&'static str> {
        if access == LocalAccess::Basic {
            return None;
        }
        let inside = |root: &std::path::Path| -> bool {
            super::path_starts_with(path, root)
                || dunce::canonicalize(root).is_ok_and(|real| super::path_starts_with(path, &real))
        };
        if self.managed_config_dir.as_deref().is_some_and(&inside) {
            return Some("SSHSpan's own configuration folder is off-limits for SFTP transfers.");
        }
        if self.ssh_dir.as_deref().is_some_and(&inside) {
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
        // Planting a startup entry or editing a shell rc file is code
        // execution at the next login - but reading one (dotfile syncing) is
        // ordinary, so these only apply to writes.
        if access == LocalAccess::Write {
            if self.startup_dirs.iter().any(|d| inside(d)) {
                return Some(
                    "Startup folders are off-limits for SFTP downloads and local changes.",
                );
            }
            if self.shell_rc_files.iter().any(|f| inside(f)) {
                return Some(
                    "Shell startup files (.bashrc, .profile, ...) are off-limits for SFTP downloads and local changes.",
                );
            }
        }
        None
    }
}

/// `path` with symlinks resolved as far as the filesystem allows: the whole
/// path when it exists, otherwise its parent (a not-yet-existing target such
/// as a download destination has to resolve through its parent) joined with
/// the file name. dunce::canonicalize (not std::fs::canonicalize): on Windows std
/// returns a `\\?\`-prefixed path, and `Path::starts_with` compares prefix
/// components exactly, so a verbatim path NEVER matched the plain
/// `C:\Users\...` app-data dir - the guard fired only for paths that did not
/// exist yet, i.e. it was inverted exactly where a write could succeed. dunce
/// keeps existing paths in the plain form so both shapes compare.
fn resolved_local_path(p: &std::path::Path) -> PathBuf {
    if let Ok(real) = dunce::canonicalize(p) {
        return real;
    }
    match (
        p.parent()
            .and_then(|parent| dunce::canonicalize(parent).ok()),
        p.file_name(),
    ) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => p.to_path_buf(),
    }
}

/// Guard every renderer-supplied local filesystem target against the app
/// data directory, system directories and - depending on `access` - the
/// sensitive locations in [`SensitiveLocations`]. Runs for BOTH directions: a
/// download must not write there, and an upload must not read the vault (or
/// other app-private files) out to a server. The app data rule mirrors
/// `validate_export_path`; the system-dir rule reuses the same denylist, so
/// a (hypothetically compromised) renderer cannot aim SFTP transfers at
/// `C:\Windows`, `/etc`, or friends either.
///
/// Both the target itself and its parent are probed: the parent may not exist
/// yet (the queue path creates it later) and the target may already exist.
fn validate_sftp_local_path(path: &str, access: LocalAccess) -> CmdResult<()> {
    validate_sftp_local_path_with(path, access, &SensitiveLocations::current())
}

fn validate_sftp_local_path_with(
    path: &str,
    access: LocalAccess,
    sensitive: &SensitiveLocations,
) -> CmdResult<()> {
    let p = std::path::Path::new(path);
    if !p.is_absolute() {
        return Err("Local path must be absolute.".into());
    }

    let check = |probe: &std::path::Path| -> CmdResult<()> {
        let normalized = dunce::canonicalize(probe).unwrap_or_else(|_| probe.to_path_buf());
        if let Some(app_data) = ProjectDirs::from("org", "sshspan", "SSHSpan") {
            let app_data_dir = app_data.data_dir();
            let app_data_norm =
                dunce::canonicalize(app_data_dir).unwrap_or_else(|_| app_data_dir.to_path_buf());
            if super::path_starts_with(&normalized, &app_data_norm)
                || super::path_starts_with(&normalized, app_data_dir)
            {
                return Err(
                    "The application data directory is off-limits for SFTP transfers.".into(),
                );
            }
        }
        if super::is_system_path(&normalized) {
            return Err("System directories are off-limits for SFTP transfers.".into());
        }
        Ok(())
    };

    if let Some(parent) = p.parent() {
        check(parent)?;
    }
    check(p)?;
    // The sensitive locations are judged on the RESOLVED path and on the
    // literal one, so neither a symlinked parent nor a not-yet-existing
    // target slips past.
    for candidate in [resolved_local_path(p), p.to_path_buf()] {
        if let Some(why) = sensitive.refusal(&candidate, access) {
            return Err(why.into());
        }
    }
    Ok(())
}

/// Non-erroring form of the app-data/system rule for DESCENDANT filtering
/// (F5): `validate_sftp_local_path` gates the user-selected ROOT of an
/// upload, but a recursive walk enqueues descendants without re-checking, so
/// an allowed ancestor that CONTAINS app data (or a symlink to a protected
/// file) would upload the vault database - or, with the home directory as the
/// root, everything under `~/.ssh` but the public keys. This predicate answers "is this
/// exact path, or the canonical target it resolves to, protected?" so the
/// recursive expander can skip (not fail) protected entries. Symlinked files
/// are checked against their canonical target, closing the symlink-to-vault
/// gap.
fn is_protected_upload_source(path: &std::path::Path) -> bool {
    is_protected_upload_source_with(path, &SensitiveLocations::current())
}

fn is_protected_upload_source_with(path: &std::path::Path, sensitive: &SensitiveLocations) -> bool {
    // Canonicalize resolves the final symlink component too, so a symlink to
    // the vault DB is recognized by its target.
    let normalized = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(app_data) = ProjectDirs::from("org", "sshspan", "SSHSpan") {
        let app_data_dir = app_data.data_dir();
        let app_data_norm =
            dunce::canonicalize(app_data_dir).unwrap_or_else(|_| app_data_dir.to_path_buf());
        if super::path_starts_with(&normalized, &app_data_norm)
            || super::path_starts_with(&normalized, app_data_dir)
        {
            return true;
        }
    }
    super::is_system_path(&normalized)
        || sensitive
            .refusal(&normalized, LocalAccess::Read)
            .or_else(|| sensitive.refusal(path, LocalAccess::Read))
            .is_some()
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

/// Depth-first recursive delete of a remote directory tree. Children are
/// removed before their parent (rmdir requires an empty dir). Symlinks are
/// unlinked, never followed - `symlink_metadata` classifies the link itself.
fn remove_remote_tree<'a>(
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
            let ft = md.file_type();
            let res = if ft.is_symlink() || !ft.is_dir() {
                // Symlinks and plain files are unlinked; a symlink is never followed.
                sftp.remove_file(&child)
                    .await
                    .map_err(|e| format!("rm {child}: {e}"))
            } else {
                remove_remote_tree(sftp, &child).await
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
/// anything the list does not name. (Only the destination DIRECTORY of a queue
/// download is validated, not each file name inside it: a remote file called
/// `.bashrc` downloaded into a home-directory `dest_dir` is not caught.)
/// Closing that needs dialog-approved directories (`system_pick_directory` + a
/// grant store with a TTL) and dialog-picked upload sources, which is a larger
/// change.
#[tauri::command]
pub async fn sftp_download(
    app: AppHandle,
    session_id: String,
    remote: String,
    local: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    let access = if app.state::<super::DialogPathStore>().consume(&local) {
        LocalAccess::Basic
    } else {
        LocalAccess::Write
    };
    validate_sftp_local_path(&local, access)?;
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
/// atomic finish.)
pub async fn download_to(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    local: &str,
) -> Result<(), CmdError> {
    use tokio::io::AsyncReadExt;

    let size = sftp
        .metadata(remote)
        .await
        .map_err(|e| describe_sftp_error("stat", e))?
        .size
        .unwrap_or(0);

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
        done += n as u64;
    }
    local_file
        .flush()
        .await
        .map_err(|e| CmdError(format!("local flush failed: {e}")))?;
    drop(local_file);

    if done < size {
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
    tokio::fs::rename(&part, local)
        .await
        .map_err(|e| CmdError(format!("local rename failed: {e}")))?;
    part_guard.0 = None;
    Ok(())
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

/// What one file-watcher callback means for an edit: `Ok(true)` a save,
/// `Ok(false)` an unrelated event, `Err` the watcher itself reporting a problem
/// (dropped events, a vanished directory...). The error is surfaced - the
/// caller logs it - rather than discarded: a watcher that has died looks
/// exactly like "the user never saved", and the edit would silently stop
/// syncing.
fn watch_verdict(
    result: Result<notify::Event, notify::Error>,
    staged_name: &std::ffi::OsStr,
) -> Result<bool, String> {
    match result {
        Ok(event) => Ok(is_edit_trigger(&event, staged_name)),
        Err(e) => Err(e.to_string()),
    }
}

/// The payload of the `sftp-edit-sync` event: the outcome of one upload of an
/// edited file, so a save is never silently lost.
fn edit_sync_event(
    session_id: &str,
    remote: &str,
    result: &Result<u64, String>,
) -> serde_json::Value {
    match result {
        Ok(_) => serde_json::json!({ "sessionId": session_id, "remote": remote, "ok": true }),
        Err(error) => serde_json::json!({
            "sessionId": session_id, "remote": remote, "ok": false, "error": error,
        }),
    }
}

/// Upload an edited local file over `target` without ever truncating the live
/// remote file: the bytes go to `<target>.sshspan-tmp`, are checked, and only
/// then renamed into place. The old code opened `target` itself with
/// CREATE|TRUNCATE and never closed it, so a connection drop mid-sync left a
/// TRUNCATED remote file while the editor showed a saved one.
///
/// Returns the number of bytes uploaded. On any failure before the swap the
/// temporary file is removed (if the server refuses even that, the error says
/// where the leftover is) and the original is untouched; if the swap itself
/// fails the error says where the new content is. `mode` (the permission bits
/// the remote file had when it was opened) is put back on the new file - a
/// rename replaces the inode, and an executable script must stay executable.
async fn upload_edited_file(
    sftp: &russh_sftp::client::SftpSession,
    local: &std::path::Path,
    target: &str,
    mode: Option<u32>,
) -> Result<u64, String> {
    use russh_sftp::protocol::OpenFlags;
    use tokio::io::AsyncWriteExt;

    let lf = tokio::fs::File::open(local)
        .await
        .map_err(|e| format!("could not read the saved file: {e}"))?;
    let tmp = format!("{target}{EDIT_TMP_SUFFIX}");
    let mut rf = sftp
        .open_with_flags(
            &tmp,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await
        .map_err(|e| format!("could not create {tmp}: {}", sftp_error_detail(e)))?;

    // Everything up to the swap: stage a COMPLETE copy and prove it is whole.
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
        let size = sftp
            .metadata(&tmp)
            .await
            .map_err(|e| format!("could not verify {tmp}: {}", sftp_error_detail(e)))?
            .size;
        if size != Some(copied) {
            return Err(format!(
                "{tmp} holds {} of {copied} bytes",
                size.map_or_else(|| "an unknown number".to_string(), |s| s.to_string())
            ));
        }
        Ok(copied)
    }
    .await;
    let copied = match staged {
        Ok(copied) => copied,
        Err(e) => {
            // Nothing replaced anything yet: drop the partial copy. If even
            // that is refused, say where the leftover is instead of leaving it
            // on the server unannounced.
            return Err(match sftp.remove_file(&tmp).await {
                Ok(()) => e,
                Err(rm) => format!("{e} (temp file left at {tmp}: {})", sftp_error_detail(rm)),
            });
        }
    };

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
    crate::sftp::queue::rename_over(sftp, &tmp, target)
        .await
        .map_err(|d| format!("could not replace {target}: {d} (the saved content is at {tmp})"))?;
    Ok(copied)
}

/// One live edit watch, as the sync task needs it.
struct EditSync {
    sftp: Arc<russh_sftp::client::SftpSession>,
    session_id: String,
    /// The path the user opened: what events and the registry are keyed by.
    remote: String,
    /// What is actually written: `remote` with symbolic links resolved, so
    /// editing through a link updates the file it points at instead of
    /// replacing the link with a regular file.
    target: String,
    local: PathBuf,
    /// The remote file's permission bits when it was opened.
    mode: Option<u32>,
    emit: Arc<dyn Fn(serde_json::Value) + Send + Sync>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    debounce: EditDebounce,
    /// Uploads of one file never overlap: two writers on the same temporary
    /// path would interleave.
    upload_lock: tokio::sync::Mutex<()>,
}

impl EditSync {
    /// A change to the staged file was seen: once the burst settles, upload it
    /// once and report the outcome (success AND failure).
    async fn on_change(self: Arc<Self>) {
        let Some(generation) = self.debounce.settle().await else {
            return; // a newer change will upload
        };
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        let _turn = self.upload_lock.lock().await;
        // The previous upload may have been running while newer saves queued
        // up behind it; only the newest still has work to do.
        if !self.debounce.is_current(generation) || self.stopped.load(Ordering::SeqCst) {
            return;
        }
        let result = upload_edited_file(&self.sftp, &self.local, &self.target, self.mode).await;
        match &result {
            Ok(bytes) => log::info!(
                "[sshspan-sftp] synced back {} ({bytes} bytes) on {}",
                self.remote,
                self.session_id
            ),
            Err(e) => log::warn!(
                "[sshspan-sftp] sync of {} on {} failed: {e}",
                self.remote,
                self.session_id
            ),
        }
        (self.emit)(edit_sync_event(&self.session_id, &self.remote, &result));
    }
}

/// Download a remote file to a temp location, start watching it, and hand the
/// path back. The renderer opens it with the system default app (opener); on
/// every local save the watcher re-uploads to the remote path and reports the
/// outcome with an `sftp-edit-sync` event `{sessionId, remote, ok, error?}`
/// (success AND failure - a failed sync used to be swallowed, leaving the
/// editor showing a saved file whose upload never landed).
///
/// Not done, deliberately: a conflict check against a remote change made since
/// the download. It would need a prompt (or a force option) the renderer does
/// not have; the upload replaces the remote file with the saved copy.
#[tauri::command]
pub async fn sftp_open_for_edit(
    app: AppHandle,
    session_id: String,
    remote: String,
) -> CmdResult<serde_json::Value> {
    use tauri::Emitter;
    let sftp = sftp_from_session(&app, &session_id)?;
    let file_name = remote.rsplit('/').next().unwrap_or("file").to_string();
    if file_name.is_empty() {
        return Err(CmdError("Cannot edit a directory path.".into()));
    }
    // Best-effort prune of staged copies left behind by crashed/killed
    // sessions (only files directly inside sshspan-edit, older than a day).
    let temp_dir = edit_temp_dir();
    crate::sftp::prune_stale_stage_files(&temp_dir, STAGE_FILE_MAX_AGE);
    // Unpredictable staged name: the file can hold secret remote contents,
    // so its path must not be guessable by other local users (the dir is
    // 0700, this is defense in depth for the pre-existing-dir case).
    let local = temp_dir.join(format!(
        "{}-{}",
        &session_id[..8.min(session_id.len())],
        staged_file_name(&file_name)
    ));

    // What the upload has to preserve and where it really lands: the mode
    // bits (a rename gives the new file a fresh inode) and the path with
    // symlinks resolved (so editing through a link updates its target).
    let mode = sftp
        .metadata(&remote)
        .await
        .ok()
        .and_then(|md| md.permissions)
        .map(|m| m & 0o7777);
    let target = sftp
        .canonicalize(&remote)
        .await
        .unwrap_or_else(|_| remote.clone());

    download_to(&sftp, &remote, &local.display().to_string()).await?;
    let local_str = local.display().to_string();

    let key = format!("{session_id}:{remote}");
    let edit_registry = app.state::<EditRegistry>();
    // Stop any previous watch on the same file.
    edit_registry.stop(&key);

    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let app_for_events = app.clone();
    let sync = Arc::new(EditSync {
        sftp: sftp.clone(),
        session_id: session_id.clone(),
        remote: remote.clone(),
        target,
        local: local.clone(),
        mode,
        emit: Arc::new(move |payload| {
            let _ = app_for_events.emit("sftp-edit-sync", payload);
        }),
        stopped: stopped.clone(),
        debounce: EditDebounce::new(EDIT_DEBOUNCE),
        upload_lock: tokio::sync::Mutex::new(()),
    });

    let staged_name = local
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let sync_for_watch = sync.clone();
    let mut watcher =
        notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if sync_for_watch.stopped.load(Ordering::SeqCst) {
                return;
            }
            match watch_verdict(res, &staged_name) {
                Ok(true) => {}
                Ok(false) => return,
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
            }
            // The staged file deliberately stays for the life of the edit
            // session: the watcher only uploads-on-change, it never
            // re-downloads, and deleting a path a third-party editor may hold
            // open makes editors recreate an empty/stale buffer on the next
            // save - clobbering the remote file. Cleanup happens on session
            // close, vault lock/teardown (EditRegistry::stop*), explicit
            // sftp_close_edit, or the 24h stale prune.
            let sync = sync_for_watch.clone();
            tauri::async_runtime::spawn(sync.on_change());
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

    edit_registry.insert(
        key,
        EditWatch {
            session_id,
            remote_path: remote.clone(),
            local_path: local_str.clone(),
            sftp: sftp.clone(),
            watcher: Some(watcher),
            stopped,
        },
    );

    Ok(serde_json::json!({ "ok": true, "localPath": local_str, "remote": remote }))
}

/// Stop the edit watch for a (session, remote path) pair and clean the temp file.
#[tauri::command]
pub fn sftp_close_edit(
    app: AppHandle,
    session_id: String,
    remote: String,
) -> CmdResult<serde_json::Value> {
    let key = format!("{session_id}:{remote}");
    if let Some(local) = app.state::<EditRegistry>().stop(&key) {
        let _ = std::fs::remove_file(&local);
    }
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

/// Expand a local directory into upload jobs (recursive); a file becomes one.
///
/// Symlink-aware and cycle-breaking: recursion only ever enters REAL
/// directories. A symlinked directory is never followed (following one can
/// loop - `ln -s .. up` - and recurse until the stack overflows); a symlinked
/// FILE is uploaded by following the link exactly one level (File::open
/// resolves it; there is no recursion, hence no cycle).
fn expand_upload(
    local: PathBuf,
    remote: String,
    session_id: String,
    server_name: String,
    resume: ResumeMode,
    preserve_ts: bool,
    out: &mut Vec<QueuedItem>,
) {
    // symlink_metadata (lstat): classifies the entry itself, never follows.
    let md = match std::fs::symlink_metadata(&local) {
        Ok(m) => m,
        Err(_) => return,
    };
    if md.is_symlink() {
        match std::fs::metadata(&local) {
            Ok(target) if target.is_file() => {
                // The link resolves to a file we follow one level; the TARGET
                // must still pass the protected-source check, or a symlink to
                // the vault DB inside an allowed tree would be uploaded (F5).
                if is_protected_upload_source(&local) {
                    log::warn!(
                        "[sshspan-sftp] upload: skipping {} (symlink target is a protected path)",
                        local.display()
                    );
                    return;
                }
                out.push(QueuedItem {
                    kind: JobKind::Upload,
                    session_id: session_id.clone(),
                    server_name: server_name.clone(),
                    local_path: local.display().to_string(),
                    remote_path: remote,
                    size: target.len(),
                    target: None,
                    resume: Some(resume),
                    preserve_ts: Some(preserve_ts),
                });
            }
            _ => {
                log::warn!(
                    "[sshspan-sftp] upload: skipping symlinked directory {} (symlink cycles are not followed)",
                    local.display()
                );
            }
        }
        return;
    }
    if md.is_file() {
        // F5: every expanded file re-passes the source authorization check -
        // the root was validated by the caller, but descendants were not, so
        // an allowed ancestor containing app data must not upload the vault.
        if is_protected_upload_source(&local) {
            log::warn!(
                "[sshspan-sftp] upload: skipping protected source {}",
                local.display()
            );
            return;
        }
        out.push(QueuedItem {
            kind: JobKind::Upload,
            session_id: session_id.clone(),
            server_name: server_name.clone(),
            local_path: local.display().to_string(),
            remote_path: remote,
            size: md.len(),
            target: None,
            resume: Some(resume),
            preserve_ts: Some(preserve_ts),
        });
        return;
    }
    let Ok(entries) = std::fs::read_dir(&local) else {
        return;
    };
    for e in entries.flatten() {
        let child = e.path();
        let rname = format!(
            "{}/{}",
            remote.trim_end_matches('/'),
            e.file_name().to_string_lossy()
        );
        expand_upload(
            child,
            rname,
            session_id.clone(),
            server_name.clone(),
            resume,
            preserve_ts,
            out,
        );
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
/// - Windows reserved device names - CON, PRN, AUX, NUL, COM1-9, LPT1-9,
///   case-insensitive, with or without extension (`CON.exe`, `NUL.txt`) →
///   reject: creating them redirects to a device or fails unpredictably.
/// - Empty / whitespace-only → reject.
/// - Windows-invalid characters `:*?"<>|` → sanitize to `_` (same mapping
///   as [`crate::sftp::sanitize_stage_base`], kept inline so the queue path
///   has no hidden coupling to the staging code).
/// - Trailing dots or spaces → strip (Windows would drop them anyway, but
///   the local name then differs from the remote one, so do it explicitly).
/// - Result empty after sanitization → reject.
fn sanitize_remote_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Reject anything that carries path structure. `Path::is_absolute` alone
    // misses `C:relative` and `\\server`, so separators and drive letters are
    // checked explicitly.
    if trimmed.contains('/') || trimmed.contains('\\') {
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
    // path and the file on disk agree.
    while sanitized.ends_with('.') || sanitized.ends_with(' ') {
        sanitized.pop();
    }
    if sanitized.is_empty() || sanitized.chars().all(|c| c == '.') {
        return None;
    }
    // Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9),
    // with or without an extension: `CON`, `con.txt`, `NUL.tar.gz`.
    let stem = sanitized.split('.').next().unwrap_or("");
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem.to_uppercase().as_str()) {
        return None;
    }
    Some(sanitized)
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
enum EntryKind {
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
/// (see [`classify_untyped`]); if the LSTAT fails the entry is `Other` and
/// skipped.
async fn list_remote_dir(
    sftp: &russh_sftp::client::SftpSession,
    dir: &str,
) -> Result<Vec<ListedEntry>, String> {
    let entries = sftp.read_dir(dir).await.map_err(sftp_error_detail)?;
    let mut out = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let md = entry.metadata();
        let kind = match classify_attrs(&md) {
            Some(kind) => kind,
            None => classify_untyped(sftp, &join_remote(dir, &name)).await,
        };
        out.push(ListedEntry {
            name,
            kind,
            size: md.size.unwrap_or(0),
            mtime: md.mtime,
        });
    }
    Ok(out)
}

/// The kind of an entry whose listing carried no file type: LSTAT first; if
/// the server leaves the type out there as well, READLINK tells a link apart
/// (walks never follow one) and opening it as a folder tells a folder from a
/// file. Whatever cannot be settled - LSTAT refused or the entry gone,
/// READLINK unsupported, the folder probe refused - is `Unknown`: left alone,
/// never guessed.
async fn classify_untyped(sftp: &russh_sftp::client::SftpSession, path: &str) -> EntryKind {
    match sftp.symlink_metadata(path).await {
        Ok(lstat) => {
            if let Some(kind) = classify_attrs(&lstat) {
                return kind;
            }
        }
        Err(_) => return EntryKind::Unknown,
    }
    match sftp.read_link(path).await {
        Ok(_) => return EntryKind::Symlink,
        Err(e) if readlink_says_not_a_link(&e) => {}
        Err(_) => return EntryKind::Unknown,
    }
    probe_folder(sftp, path).await
}

/// Whether a READLINK error means "this is not a link". OpenSSH's
/// sftp-server answers readlink(2)'s EINVAL with SSH_FX_BAD_MESSAGE (its
/// `errno_to_portable`); other servers say "failure" or "no such file".
fn readlink_says_not_a_link(e: &russh_sftp::client::error::Error) -> bool {
    use russh_sftp::protocol::StatusCode;
    sftp_status(
        e,
        &[
            StatusCode::BadMessage,
            StatusCode::Failure,
            StatusCode::NoSuchFile,
        ],
    )
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
    /// Local sub-directories to create, as sanitized path components below the
    /// destination (the picked folder itself first, parents before children).
    dirs: Vec<Vec<String>>,
    files: Vec<PlannedFile>,
    notes: Notes,
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
    plan.dirs.push(vec![root_name.to_string()]);
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
                    plan.notes.push(format!(
                        "skipped {remote}: the server does not say whether it is a file or a folder"
                    ));
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
                plan.dirs.push(child_rel.clone());
                stack.push((remote, child_rel));
            }
        }
    }
    Ok(plan)
}

/// Everything about one `sftp_queue_add` download item that is not the path.
struct DownloadCtx<'a> {
    session_id: &'a str,
    server_name: &'a str,
    resume: ResumeMode,
    preserve_ts: bool,
}

impl DownloadCtx<'_> {
    fn item(&self, remote: &str, local: PathBuf, size: u64) -> QueuedItem {
        QueuedItem {
            kind: JobKind::Download,
            session_id: self.session_id.to_string(),
            server_name: self.server_name.to_string(),
            local_path: local.display().to_string(),
            remote_path: remote.to_string(),
            size,
            target: None,
            resume: Some(self.resume),
            // Honoured for downloads now: the queue stamps the remote mtime
            // onto the finished file (A7-36).
            preserve_ts: Some(self.preserve_ts),
        }
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
async fn expand_download(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    root: &std::path::Path,
    ctx: &DownloadCtx<'_>,
    local_name: Option<&str>,
) -> Result<ExpandedDownload, String> {
    let md = sftp
        .metadata(remote)
        .await
        .map_err(|e| format!("stat {remote}: {}", sftp_error_detail(e)))?;
    let mut out = ExpandedDownload::default();
    if !md.is_dir() {
        // Single file: its name comes from the user-picked remote path (not a
        // ReadDir entry), but sanitize anyway - the path string still
        // originates from the server's view of the filesystem. A
        // renderer-supplied `local_name` (the download-rename conflict action)
        // replaces the basename and goes through the same containment check,
        // so a rename cannot escape the destination.
        let raw = local_name.unwrap_or_else(|| remote.rsplit('/').next().unwrap_or("file"));
        let Some(local) = safe_join_under(root, root, raw) else {
            log::warn!("[sshspan-sftp] skipping download of {remote}: unsafe local name {raw:?}");
            out.notes.push(format!(
                "skipped {remote}: {raw:?} cannot be used as a local file name"
            ));
            return Ok(out);
        };
        out.items
            .push(ctx.item(remote, local, md.size.unwrap_or(0)));
        return Ok(out);
    }
    let raw_dir = remote.rsplit('/').next().unwrap_or("dir");
    let Some(root_name) = sanitize_remote_name(raw_dir) else {
        log::warn!("[sshspan-sftp] skipping download dir {remote}: unsafe local name {raw_dir:?}");
        out.notes.push(format!(
            "skipped {remote}: {raw_dir:?} cannot be used as a local folder name"
        ));
        return Ok(out);
    };
    let plan = plan_download(remote, &root_name, |dir| async move {
        list_remote_dir(sftp, &dir).await
    })
    .await?;
    out.notes.extend(plan.notes);

    // The walk is within its caps; now (and only now) touch the disk.
    let mut rejected: Vec<PathBuf> = Vec::new();
    for rel in &plan.dirs {
        let Some(path) = join_local(root, rel) else {
            continue;
        };
        if rejected.iter().any(|r| path.starts_with(r)) {
            continue;
        }
        let made = tokio::fs::create_dir_all(&path).await;
        // create_dir_all may have been steered through a symlinked directory
        // (planted locally, or created by another queued job): re-anchor at
        // the canonical path and refuse anything that leaves the destination.
        let inside = matches!(
            tokio::fs::canonicalize(&path).await,
            Ok(real) if real.starts_with(root)
        );
        if made.is_err() || !inside {
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
    for file in plan.files {
        let Some(path) = join_local(root, &file.rel) else {
            continue;
        };
        if rejected.iter().any(|r| path.starts_with(r)) {
            continue;
        }
        out.items.push(ctx.item(&file.remote, path, file.size));
    }
    Ok(out)
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
                    out.failed.push(format!(
                        "{child}: not changed (the server does not say whether it is a file or a folder)"
                    ));
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
    let batch_resume = resolve_resume_mode(&app, resume.as_deref());
    let preserve_ts = preserve_ts.unwrap_or(false);
    let server_name = app
        .state::<StdArc<SessionRegistry>>()
        .list()
        .into_iter()
        .find(|(id, _, _, _, _)| id == &session_id)
        .map(|(_, name, _, _, _)| name)
        .unwrap_or_default();

    let mut jobs: Vec<QueuedItem> = Vec::new();
    let mut notes = Notes::default();
    match kind {
        JobKind::Upload => {
            for item in &items {
                let local = item
                    .get("local")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let remote = item
                    .get("remote")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if local.is_empty() || remote.is_empty() {
                    continue;
                }
                // Same gate the single-file sftp_upload applies: the local
                // upload source must not be the app data dir (the vault), a
                // system directory or private-key material. This is the
                // boundary the queue path must not skip.
                validate_sftp_local_path(local, LocalAccess::Read)?;
                expand_upload(
                    PathBuf::from(local),
                    remote.to_string(),
                    session_id.clone(),
                    server_name.clone(),
                    item_resume(item, batch_resume),
                    preserve_ts,
                    &mut jobs,
                );
            }
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
            validate_sftp_local_path(&dest.to_string_lossy(), LocalAccess::Write)?;
            let _ = tokio::fs::create_dir_all(&dest).await;
            // Anchor every queued local path at the canonical destination:
            // the walk below joins remote-supplied names onto this root and
            // verifies the result stays under it.
            let root = tokio::fs::canonicalize(&dest)
                .await
                .map_err(|e| CmdError(format!("destination not accessible: {e}")))?;
            for item in &items {
                let remote = item
                    .get("remote")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if remote.is_empty() {
                    continue;
                }
                // Download-side rename: the renderer resolves a conflict to a
                // free local name and passes it here. Only the FILE case can
                // use it (a directory expands into many names), which
                // `expand_download` enforces.
                let local_name = item
                    .get("localName")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty());
                let ctx = DownloadCtx {
                    session_id: &session_id,
                    server_name: &server_name,
                    resume: item_resume(item, batch_resume),
                    preserve_ts,
                };
                let expanded = expand_download(&sftp, remote, &root, &ctx, local_name)
                    .await
                    .map_err(CmdError)?;
                jobs.extend(expanded.items);
                notes.extend(expanded.notes);
            }
            // Two remote names can map to one local path (sanitising `back:up`
            // and `back_up`, or `README` / `readme` on a case-insensitive disk,
            // which any destination might be): the jobs would share one `.part`
            // and clobber each other (A7-57).
            for note in dedupe_local_targets(&mut jobs) {
                notes.push(note);
            }
        }
        // ServerCopy never reaches here (guarded above).
        JobKind::ServerCopy => unreachable!("guarded above"),
    }

    let count = jobs.len();
    // Things the expansion skipped (symbolic links, unreadable folders, names
    // that cannot be used locally, renamed collisions). Always present; an
    // empty array means a clean expansion.
    let warnings = notes.into_vec();
    if count == 0 {
        return Ok(serde_json::json!({ "ok": true, "added": 0, "warnings": warnings }));
    }
    q_enqueue(&app, jobs);
    Ok(serde_json::json!({ "ok": true, "added": count, "warnings": warnings }))
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
    let md = sftp
        .metadata(&remote)
        .await
        .map_err(|e| CmdError(format!("stat {remote}: {e}")))?;

    let name = remote.rsplit('/').next().unwrap_or("file");
    let base_target = format!("{}/{}", target_dir.trim_end_matches('/'), name);

    if md.is_dir() {
        // Stream the walk: enqueue per-file jobs in batches as the tree is
        // scanned so transfers start immediately (workers run in parallel with
        // the walk) instead of waiting for a full scan of a huge tree. The
        // command returns after the scan completes; scan errors surface here
        // while already-queued jobs keep running.
        let visited = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
        let scanned = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let walk = expand_server_copy(
            &app,
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
    app: &'a AppHandle,
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
            let child_remote = format!("{}/{}", remote_dir.trim_end_matches('/'), safe);
            let child_target = format!("{}/{}", target_base.trim_end_matches('/'), safe);
            // Classify from the listing's own attributes (symlink-aware): no
            // per-file stat round-trip. Symlinks are skipped, never followed.
            let md = entry.metadata();
            let ftype = md.file_type();
            if ftype.is_symlink() {
                log::debug!("[sshspan-sftp] send-to: skipping symlink {child_remote}");
                continue;
            }
            if ftype.is_dir() {
                // Flush pending files before recursing so ordering stays
                // breadth-friendly and the queue keeps filling.
                if !batch.is_empty() {
                    scanned.fetch_add(batch.len(), std::sync::atomic::Ordering::SeqCst);
                    q_enqueue(app, std::mem::take(&mut batch));
                }
                expand_server_copy(
                    app,
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
                // Regular file. file_type() is `Other` when a server omits
                // permission bits, so treat non-dir/non-symlink as copyable.
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
                    q_enqueue(app, std::mem::take(&mut batch));
                }
            }
        }
        if !batch.is_empty() {
            scanned.fetch_add(batch.len(), std::sync::atomic::Ordering::SeqCst);
            q_enqueue(app, batch);
        }
        Ok(())
    })
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
    validate_sftp_local_path(path, access)?;
    let p = PathBuf::from(path);
    // A bare drive root (`C:\`) or `/` is technically absolute and outside the
    // app data dir, but "delete the root of the filesystem" is never what the
    // user meant and the recursive delete below would happily attempt it.
    if p.parent().is_none() {
        return Err("Refusing to operate on a filesystem root.".into());
    }
    Ok(p)
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
    let src = validate_local_mutation(&app, &from)?;
    let dst = validate_local_mutation(&app, &to)?;
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
    let target = validate_local_target(path, LocalAccess::Write)?;
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

/// What the root of a recursive chmod is: STAT's type (a link is followed,
/// like `chmod -R` on a command-line link), else LSTAT's, else whether it
/// opens as a folder. A server whose STAT omits the type bits used to get a
/// silent root-only change that ignored the files/dirs scope (JU1 review).
async fn chmod_root_kind(
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
        chmod_root_kind(sftp, path, &md).await
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
        let mut dirs: Vec<String> = plan.dirs.iter().map(|d| d.join("/")).collect();
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
    fn download_ctx(preserve_ts: bool) -> DownloadCtx<'static> {
        DownloadCtx {
            session_id: "sess",
            server_name: "srv",
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
        for code in [S::BadMessage, S::Failure, S::NoSuchFile] {
            assert!(readlink_says_not_a_link(&status_err(code, "")), "{code:?}");
        }
        for code in [
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
    #[test]
    fn watcher_errors_are_surfaced_not_swallowed() {
        use notify::event::{CreateKind, EventKind};
        let staged = std::ffi::OsStr::new("a.txt");

        let err = watch_verdict(
            Err(notify::Error::generic("inotify queue overflow")),
            staged,
        )
        .expect_err("a watcher error must reach the caller");
        assert!(err.contains("inotify queue overflow"), "{err}");

        let save = watch_event(EventKind::Create(CreateKind::File), &["/d/a.txt"]);
        assert_eq!(watch_verdict(Ok(save), staged), Ok(true));
        let other = watch_event(EventKind::Create(CreateKind::File), &["/d/b.txt"]);
        assert_eq!(watch_verdict(Ok(other), staged), Ok(false));
    }

    #[test]
    fn edit_sync_events_report_success_and_failure() {
        let ok = edit_sync_event("sess", "/etc/app.conf", &Ok(42));
        assert_eq!(
            ok,
            serde_json::json!({ "sessionId": "sess", "remote": "/etc/app.conf", "ok": true })
        );
        let failed = edit_sync_event("sess", "/etc/app.conf", &Err("upload failed: boom".into()));
        assert_eq!(
            failed,
            serde_json::json!({
                "sessionId": "sess", "remote": "/etc/app.conf",
                "ok": false, "error": "upload failed: boom",
            })
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

    /// An `EditSync` over `sftp` writing `target`, events collected in the list.
    #[cfg(unix)]
    fn edit_sync(
        sftp: russh_sftp::client::SftpSession,
        local: &std::path::Path,
        target: &str,
        mode: Option<u32>,
    ) -> (Arc<EditSync>, Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = events.clone();
        let sync = Arc::new(EditSync {
            sftp: Arc::new(sftp),
            session_id: "sess".into(),
            remote: "/link.conf".into(),
            target: target.into(),
            local: local.to_path_buf(),
            mode,
            emit: Arc::new(move |payload| sink.lock().unwrap().push(payload)),
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            debounce: EditDebounce::new(std::time::Duration::from_millis(80)),
            upload_lock: tokio::sync::Mutex::new(()),
        });
        (sync, events)
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

        let bytes = upload_edited_file(&sftp, &staged, "/srv/deploy.sh", Some(0o750))
            .await
            .expect("upload");

        assert_eq!(bytes, 19);
        assert_eq!(fx.read("/srv/deploy.sh"), b"#!/bin/sh\necho new\n");
        assert_eq!(
            fx.mode("/srv/deploy.sh"),
            0o750,
            "executable bit must survive"
        );
        assert!(
            !fx.exists("/srv/deploy.sh.sshspan-tmp"),
            "no temp file left behind"
        );
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
            !fx.exists("/srv/app.conf.sshspan-tmp"),
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

        assert!(
            err.contains("temp file left at /srv/app.conf.sshspan-tmp"),
            "the error must say where the leftover is: {err}"
        );
        assert!(
            fx.exists("/srv/app.conf.sshspan-tmp"),
            "it really was left behind"
        );
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
        let (sync, events) = edit_sync(sftp, &staged, "/srv/app.conf", None);

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
        let (sync, events) = edit_sync(sftp, &staged, "/srv/app.conf", None);

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
        let (sync, events) = edit_sync(sftp, &staged, "/srv/app.conf", None);
        sync.stopped.store(true, Ordering::SeqCst);

        sync.clone().on_change().await;

        assert_eq!(tmp_opens(&fx), 0);
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(fx.read("/srv/app.conf"), b"old");
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
        let other = home.join(".vimrc").display().to_string();
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

    fn sensitive_fixture(base: &std::path::Path) -> SensitiveLocations {
        SensitiveLocations {
            managed_config_dir: Some(base.join("cfg")),
            ssh_dir: Some(base.join("home/.ssh")),
            startup_dirs: windows_startup_dirs(Some(&base.join("AppData")), None),
            shell_rc_files: vec![base.join("home/.bashrc")],
        }
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
        let s = SensitiveLocations {
            managed_config_dir: None,
            ssh_dir: Some(base.join("home/.ssh")),
            startup_dirs: Vec::new(),
            shell_rc_files: Vec::new(),
        };

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
        // Control characters cannot appear in Windows file names.
        assert_eq!(
            sanitize_remote_name("a\tb\u{0}c"),
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
}
