//! SFTP over the live SSH session. Each tab's SFTP session is stored here,
//! keyed by the tab's SSH session id, alongside a registry of "open with
//! system editor" watches that re-upload files when the local copy changes.

pub mod queue;

/// In-process SFTP server (a real `SftpSession` over an in-memory stream) for
/// the unit tests of everything that talks to a remote filesystem. Unix only:
/// it relies on symlinks and mode bits.
#[cfg(all(test, unix))]
pub(crate) mod testkit;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use russh_sftp::client::SftpSession;

/// Per-connection SFTP sessions, keyed by SSH session id, plus the recursive
/// search each session is currently running.
#[derive(Default)]
pub struct SftpRegistry {
    sessions: Mutex<HashMap<String, Arc<SftpSession>>>,
    /// The search in flight per session: the id of the newest search and its
    /// cancel flag. One per session by design - the search bar has one result
    /// list, so a new search supersedes the old one (A7-21).
    searches: Mutex<HashMap<String, (String, Arc<std::sync::atomic::AtomicBool>)>>,
}

impl SftpRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            searches: Mutex::new(HashMap::new()),
        }
    }
    pub fn insert(&self, id: String, sftp: Arc<SftpSession>) {
        self.sessions.lock().unwrap().insert(id, sftp);
    }
    pub fn get(&self, id: &str) -> Option<Arc<SftpSession>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }
    pub fn remove(&self, id: &str) -> Option<Arc<SftpSession>> {
        // A search walks THIS session; without it there is nothing to walk.
        self.cancel_session_search(id);
        self.sessions.lock().unwrap().remove(id)
    }
    /// Drop every open SFTP session. Called when the vault locks: the shell
    /// sessions are torn down there too, but an SFTP channel is opened on its
    /// OWN russh channel, so clearing the shell registry alone left these
    /// handles live and every `sftp_*` command still working against them.
    pub fn clear(&self) {
        let mut searches = self.searches.lock().unwrap();
        for (_, (_, cancel)) in searches.drain() {
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        drop(searches);
        self.sessions.lock().unwrap().clear();
    }

    /// Register a new search for `session_id` and return its cancel flag. The
    /// search it supersedes (if any) is cancelled: overlapping walks of one
    /// session used to cross-contaminate one result list, and the stale walk's
    /// `done` event killed the live listener (A7-21).
    pub fn begin_search(
        &self,
        session_id: &str,
        search_id: &str,
    ) -> Arc<std::sync::atomic::AtomicBool> {
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let previous = self.searches.lock().unwrap().insert(
            session_id.to_string(),
            (search_id.to_string(), cancel.clone()),
        );
        if let Some((_, old)) = previous {
            old.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        cancel
    }

    /// Cancel `search_id` if it is still the session's current search. A late
    /// cancel for a search that has since been replaced does nothing - it must
    /// not stop the newer one.
    pub fn cancel_search(&self, session_id: &str, search_id: &str) -> bool {
        let mut searches = self.searches.lock().unwrap();
        match searches.get(session_id) {
            Some((current, cancel)) if current == search_id => {
                cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                searches.remove(session_id);
                true
            }
            _ => false,
        }
    }

    /// The search ended on its own: forget it, unless a newer one has already
    /// taken its place.
    pub fn finish_search(&self, session_id: &str, search_id: &str) {
        let mut searches = self.searches.lock().unwrap();
        if searches
            .get(session_id)
            .is_some_and(|(current, _)| current == search_id)
        {
            searches.remove(session_id);
        }
    }

    /// Cancel whatever search the session is running (tab closed).
    pub fn cancel_session_search(&self, session_id: &str) {
        if let Some((_, cancel)) = self.searches.lock().unwrap().remove(session_id) {
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// One "open with system editor" watch: the file watcher and the sync state
/// it drives (see `commands::sftp::EditSync`).
pub struct EditWatch {
    pub session_id: String,
    pub watcher: Option<notify::RecommendedWatcher>,
    pub(crate) sync: Arc<crate::commands::sftp::EditSync>,
}

#[derive(Default)]
pub struct EditRegistry {
    watches: Mutex<HashMap<String, EditWatch>>, // key: "{sessionId}:{remotePath}"
}

impl EditRegistry {
    pub fn new() -> Self {
        Self {
            watches: Mutex::new(HashMap::new()),
        }
    }
    /// Register an edit. A watch it replaces (two opens of one file racing)
    /// is ENDED - it used to be dropped silently: its copy lingered and its
    /// saves stopped syncing without a word.
    pub fn insert(&self, key: String, watch: EditWatch) {
        let replaced = self.watches.lock().unwrap().insert(key, watch);
        if let Some(old) = replaced {
            end_watch(old);
        }
    }
    /// Register an edit - unless `key` already has one that `usable`
    /// accepts: that one is returned and `watch` is ended instead (its staged
    /// copy deleted). Decided under the registry lock, so of two opens of one
    /// file that raced through the download exactly one session survives,
    /// and none is ended after its caller handed out its copy. An edit that
    /// is not usable any more is replaced (and ended).
    pub(crate) fn insert_unless_live(
        &self,
        key: String,
        watch: EditWatch,
        usable: impl Fn(&crate::commands::sftp::EditSync) -> bool,
    ) -> Result<(), Arc<crate::commands::sftp::EditSync>> {
        let mut watches = self.watches.lock().unwrap();
        if let Some(live) = watches.get(&key).filter(|w| usable(&w.sync)) {
            let live = live.sync.clone();
            drop(watches);
            end_watch(watch);
            return Err(live);
        }
        let replaced = watches.insert(key, watch);
        drop(watches);
        if let Some(old) = replaced {
            end_watch(old);
        }
        Ok(())
    }
    /// The live edit session of `key` (`{sessionId}:{remotePath}`).
    pub(crate) fn live_for_key(&self, key: &str) -> Option<Arc<crate::commands::sftp::EditSync>> {
        self.watches
            .lock()
            .unwrap()
            .get(key)
            .map(|w| w.sync.clone())
    }
    /// The live edit session with this id (the renderer's handle on it).
    pub(crate) fn find(&self, edit_id: &str) -> Option<Arc<crate::commands::sftp::EditSync>> {
        self.watches
            .lock()
            .unwrap()
            .values()
            .find(|w| w.sync.edit_id() == edit_id)
            .map(|w| w.sync.clone())
    }
    /// End the edit of `key`: the watcher stops and the staged copy is
    /// discarded (see [`StagedCopy::discard`]). `false` when there was none.
    pub fn stop(&self, key: &str) -> bool {
        let removed = self.watches.lock().unwrap().remove(key);
        match removed {
            Some(watch) => {
                end_watch(watch);
                true
            }
            None => false,
        }
    }
    /// End the edit of `key` only while it is still `sync` - the one a
    /// caller checked; an edit of the same file opened since is left alone.
    /// `false` when it was not.
    pub(crate) fn stop_if_same(
        &self,
        key: &str,
        sync: &Arc<crate::commands::sftp::EditSync>,
    ) -> bool {
        let removed = {
            let mut watches = self.watches.lock().unwrap();
            match watches.get(key) {
                Some(watch) if Arc::ptr_eq(&watch.sync, sync) => watches.remove(key),
                _ => None,
            }
        };
        match removed {
            Some(watch) => {
                end_watch(watch);
                true
            }
            None => false,
        }
    }
    /// End every edit (vault lock, shutdown): staged copies of edited remote
    /// files must not linger in the temp dir.
    pub fn stop_all(&self) {
        let ended: Vec<EditWatch> = self
            .watches
            .lock()
            .unwrap()
            .drain()
            .map(|(_, w)| w)
            .collect();
        ended.into_iter().for_each(end_watch);
    }
    /// End the edits of one session (its tab or SFTP pane closed).
    pub fn stop_all_for_session(&self, session_id: &str) {
        let ended: Vec<EditWatch> = {
            let mut guard = self.watches.lock().unwrap();
            let keys: Vec<String> = guard
                .iter()
                .filter(|(_, w)| w.session_id == session_id)
                .map(|(k, _)| k.clone())
                .collect();
            keys.iter().filter_map(|k| guard.remove(k)).collect()
        };
        ended.into_iter().for_each(end_watch);
    }
}

/// Stop one watch - outside the registry lock - and discard its staged copy.
fn end_watch(mut watch: EditWatch) {
    // Dropped = watch stopped (notify 7 has no close()).
    let _ = watch.watcher.take();
    watch.sync.end();
}

/// The local copy of a file opened for editing, deleted when the edit ends -
/// but never while one of OUR OWN handles on it is open (an upload or hash
/// still reading it, a reload writing it): on Windows a file that is open
/// cannot be deleted, and the delete then failed and left the copy behind.
/// Whoever holds the last handle deletes it once that handle is closed.
pub(crate) struct StagedCopy {
    path: std::path::PathBuf,
    state: Mutex<StagedState>,
}

#[derive(Default)]
struct StagedState {
    /// Our handles currently open on the file.
    open: usize,
    /// The edit ended: delete as soon as `open` is zero.
    discarded: bool,
    /// The delete has been attempted (it is attempted once).
    removed: bool,
}

/// Proof that one of our handles on a [`StagedCopy`] is open; dropping it
/// (after the file handle itself is closed) may delete a discarded copy.
pub(crate) struct StagedHandle(Arc<StagedCopy>);

impl StagedCopy {
    pub(crate) fn new(path: std::path::PathBuf) -> Arc<Self> {
        Arc::new(Self {
            path,
            state: Mutex::new(StagedState::default()),
        })
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Register a handle about to be opened on the copy; `None` once the edit
    /// ended - nothing may open it any more.
    pub(crate) fn open_handle(self: &Arc<Self>) -> Option<StagedHandle> {
        let mut state = self.state.lock().unwrap();
        if state.discarded {
            return None;
        }
        state.open += 1;
        Some(StagedHandle(self.clone()))
    }

    /// The edit ended: delete the copy now, or - while one of our handles is
    /// open - as soon as the last of them closes.
    pub(crate) fn discard(&self) {
        let remove = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.discarded = true;
            state.take_removal()
        };
        if remove {
            remove_staged_file(&self.path);
        }
    }
}

impl StagedState {
    /// Whether the copy is to be deleted now (discarded, no handle open, not
    /// attempted yet); marks the attempt.
    fn take_removal(&mut self) -> bool {
        let due = self.discarded && self.open == 0 && !self.removed;
        if due {
            self.removed = true;
        }
        due
    }
}

impl Drop for StagedHandle {
    fn drop(&mut self) {
        let remove = {
            let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.open = state.open.saturating_sub(1);
            state.take_removal()
        };
        if remove {
            remove_staged_file(&self.0.path);
        }
    }
}

/// How long a staged copy's delete waits before its one retry.
const STAGED_DELETE_RETRY: std::time::Duration = std::time::Duration::from_millis(500);

/// Delete a staged copy (best effort, never blocking the caller): our own
/// handles are closed by now (see [`StagedCopy`]); if ANOTHER program holds
/// it open without delete sharing - the editor, for a moment while it saves -
/// the delete is tried once more a little later.
fn remove_staged_file(path: &std::path::Path) {
    remove_staged_file_with(
        path,
        |p: &std::path::Path| std::fs::remove_file(p),
        is_sharing_violation,
        |retry: Box<dyn FnOnce() + Send>| {
            std::thread::spawn(move || {
                std::thread::sleep(STAGED_DELETE_RETRY);
                retry();
            });
        },
    );
}

/// [`remove_staged_file`] with the delete, the "sharing violation" test and
/// the way the delayed retry is run given, so the retry policy is testable.
fn remove_staged_file_with<R, S, L>(path: &std::path::Path, remove: R, sharing: S, later: L)
where
    R: Fn(&std::path::Path) -> std::io::Result<()> + Send + 'static,
    S: Fn(&std::io::Error) -> bool,
    L: FnOnce(Box<dyn FnOnce() + Send>),
{
    match remove(path) {
        Err(e) if sharing(&e) => {
            let path = path.to_path_buf();
            later(Box::new(move || {
                report_staged_removal(&path, remove(&path))
            }));
        }
        result => report_staged_removal(path, result),
    }
}

/// Log a failed delete of a staged copy (gone already is fine).
fn report_staged_removal(path: &std::path::Path, result: std::io::Result<()>) {
    if let Err(e) = result {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!(
                "[sshspan-sftp] could not delete the staged copy {}: {e}",
                path.display()
            );
        }
    }
}

/// Windows' ERROR_SHARING_VIOLATION: another process has the file open
/// without delete sharing - typically the editor, for a moment while saving.
fn is_sharing_violation(e: &std::io::Error) -> bool {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    cfg!(windows) && e.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
}

/// Default temp dir for edited remote files.
///
/// The directory holds downloaded copies of remote files opened in a system
/// editor and "Send to" staging copies, which can be secrets (private keys,
/// config files with credentials). It must therefore not be world-readable:
/// on Unix it is created with mode 0700 so other local users cannot read
/// staged file contents. Windows `%TEMP%` is already per-user (ACLs), so no
/// permission change is needed there.
///
/// Hostile pre-plant defense: on shared-temp filesystems (Linux `/tmp`) a
/// local attacker can pre-create `sshspan-edit` as a SYMLINK to a directory
/// they own; the victim's staged files would then land in attacker-readable
/// space and the 0700 chmod would merely re-apply to the attacker's own dir.
/// The creation below therefore never follows a symlinked or non-directory
/// path: `create_dir` (not `create_dir_all`) fails on an existing name, and
/// an existing entry is accepted only when `symlink_metadata` reports a REAL
/// directory (lstat never follows the link). Anything else falls back to a
/// random per-call directory so the feature still works in that environment.
pub fn edit_temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("sshspan-edit");
    let usable = match std::fs::create_dir(&dir) {
        Ok(()) => true, // we just created it - it cannot be a symlink
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => reuse_is_safe(&dir),
        Err(_) => false,
    };
    let dir = if usable {
        dir
    } else {
        let fallback =
            std::env::temp_dir().join(format!("sshspan-edit-{}", uuid::Uuid::new_v4().simple()));
        log::warn!(
            "[sshspan-sftp] {} is missing, not a directory, a symlink, or not owned by us (possible tampering); using fallback {}",
            dir.display(),
            fallback.display()
        );
        let _ = std::fs::create_dir_all(&fallback);
        let _ = restrict_dir(&fallback);
        return fallback;
    };
    // A chmod failure on the SHARED name is not survivable: it means the
    // directory is not ours to restrict, so anything staged in it is readable
    // by whoever does own it. Fall back to a fresh unguessable directory
    // instead of logging and carrying on.
    if restrict_dir(&dir).is_err() {
        let fallback =
            std::env::temp_dir().join(format!("sshspan-edit-{}", uuid::Uuid::new_v4().simple()));
        log::warn!(
            "[sshspan-sftp] could not restrict permissions on {}; using fallback {}",
            dir.display(),
            fallback.display()
        );
        let _ = std::fs::create_dir_all(&fallback);
        let _ = restrict_dir(&fallback);
        return fallback;
    }
    dir
}

/// Is an EXISTING `/tmp/sshspan-edit` safe for us to reuse?
///
/// SECURITY: `symlink_metadata().is_dir()` alone is necessary but not
/// sufficient. On a shared machine another local user can win the race and
/// create a REAL directory at this predictable name: lstat then reports a
/// directory, the check passes, our 0700 chmod fails with EPERM because we do
/// not own it, and every file staged for "open in system editor" lands in
/// their directory - readable, and replaceable before the watcher re-uploads
/// it to the user's server. So ownership and mode are part of the test.
fn reuse_is_safe(dir: &std::path::Path) -> bool {
    let Ok(md) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    // lstat: a symlink reports is_symlink(), never is_dir().
    if !md.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // Must be ours. Root owning it is not "close enough" - we could not
        // restrict it either.
        if md.uid() != effective_uid() {
            return false;
        }
        // Group- or world-accessible means someone else may already be able to
        // read what we stage, even if we can chmod it now.
        if md.mode() & 0o077 != 0 {
            // Recoverable: we own it, so tighten it and re-check below.
            if std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).is_err() {
                return false;
            }
        }
    }
    true
}

/// The process's effective uid.
///
/// The only `unsafe` in this file. `geteuid(2)` cannot fail, takes no
/// arguments and touches no memory, so there is no invariant to uphold beyond
/// calling it - std simply does not re-export it.
#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Apply owner-only permissions to a staging directory. Unix only; on Windows
/// the per-user temp directory already carries a user-scoped ACL.
fn restrict_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Sanitize a remote file name for use as a local staged-file base name:
/// flattens path separators so a hostile remote name cannot escape the temp
/// dir, strips characters that are invalid in Windows file names, trims
/// trailing dots/spaces (Windows strips them, which could otherwise
/// re-expose a blocked extension), and neutralizes reserved device names.
fn sanitize_stage_base(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' => '_',
            ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            // Control characters are invalid in Windows file names (and the
            // staged path is re-checked as a plain file name).
            c if c.is_control() => '_',
            _ => c,
        })
        .collect();
    // Windows filenames cannot end in dots or spaces; the OS strips them,
    // so `notes.scr.` would land on disk as `notes.scr`. Trim first so the
    // extension check below always sees the on-disk name.
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    if s.is_empty() {
        return String::new();
    }
    // Reserved DOS device names apply to the stem (the part before the final
    // dot): `CON`, `NUL.txt`, `COM1.exe` all resolve to devices. If the stem
    // is a device name, prefix it so the staged file is a regular file.
    let stem = s.rsplit_once('.').map_or(s.as_str(), |(stem, _)| stem);
    if is_windows_device_name(stem) {
        s.insert(0, '_');
    }
    s
}

/// Windows reserved device names: CON, PRN, AUX, NUL, COM1-9, LPT1-9
/// (case-insensitive).
fn is_windows_device_name(stem: &str) -> bool {
    const DEVICES: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    DEVICES.iter().any(|d| d.eq_ignore_ascii_case(stem))
}

/// Extensions that may be preserved on a staged edit file: plain-text/data
/// formats whose OS handler opens an editor or viewer, never a program that
/// executes its input. EVERYTHING ELSE - including every unknown extension -
/// is forced to `.txt`. This is an allowlist rather than the old executable
/// denylist on purpose: a denylist ages badly (each new executable/packaged
/// format is a gap until someone adds it), while the edit flow is text-editor
/// based anyway, so an unknown extension has no honest handler to preserve.
/// The staged name does not affect what is uploaded back - the original
/// remote path is untouched - so collapsing names to `.txt` costs nothing
/// except a default-app association.
///
/// `pub` is deliberately absent although it is an SSH public key suffix: on
/// Windows it is the Microsoft Publisher association (an Office application
/// with macro support), which would be handed remote-supplied content. A
/// `.pub` file stages as `.txt` like any other unknown extension.
const INERT_STAGE_EXTENSIONS: [&str; 24] = [
    "txt",
    "text",
    "log",
    "md",
    "markdown",
    "rst",
    "cfg",
    "conf",
    "ini",
    "cnf",
    "json",
    "yaml",
    "yml",
    "toml",
    "xml",
    "css",
    "csv",
    "tsv",
    "sql",
    "pem",
    "crt",
    "cer",
    "key",
    "properties",
];

fn is_inert_stage_extension(ext: &str) -> bool {
    INERT_STAGE_EXTENSIONS
        .iter()
        .any(|b| b.eq_ignore_ascii_case(ext))
}

/// Is `path`'s extension on the inert (safe-to-open-in-an-editor) allowlist?
///
/// The opener (`system_open_external`) re-checks this at the point of launch
/// so the inert-extension policy is enforced by the BACKEND at the OS
/// boundary, not only by the staging flow that happens to name the file.
/// A staged file produced by [`staged_file_name`] always satisfies this; a
/// file a compromised renderer downloads into the staging directory with an
/// attacker-chosen `.exe`/`.scr`/unknown extension does not.
pub fn path_has_inert_extension(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(is_inert_stage_extension)
        .unwrap_or(false)
}

/// Unpredictable staged-file name for a remote file: `{base}.{uuid}.{ext}`
/// (no usable extension → `{base}-{uuid}.txt`). The random component prevents
/// another local user from pre-creating or guessing the path of a file that
/// will hold remote (potentially secret) contents; the sanitized base and the
/// original extension are preserved so the editor association still works.
///
/// The result ALWAYS ends in an inert extension, because
/// `system_open_external` refuses to launch anything else: if the remote
/// extension is not on the inert allowlist (executable, packaged, binary, or
/// simply unknown - e.g. `.scr`, `.exe`, `.7z`), it is NEVER preserved - the
/// staged name is forced to end in `.txt` so the OS shell opens it in an
/// editor instead of handing it to whatever handler the extension maps to.
/// Names with no usable extension at all (`Makefile`, `authorized_keys`,
/// `.conf`) get `.txt` appended for the same reason; they used to keep a bare
/// `-{uuid}` suffix, which the opener's own gate then rejected. A remote name
/// that is only a non-inert extension (`.scr`) or empty stages as
/// `file.{uuid}.txt`.
pub fn staged_file_name(remote_name: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let base = sanitize_stage_base(remote_name);
    let base = if base.is_empty() { "file" } else { &base };
    match base.rsplit_once('.') {
        // Preserve a non-empty extension, limiting it to a sane length so a
        // dot-heavy name cannot produce a pathologically long tail - but only
        // if the extension is on the inert allowlist; anything else stages as
        // `.txt`.
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.len() <= 16 => {
            if is_inert_stage_extension(ext) {
                format!("{stem}.{id}.{ext}")
            } else {
                format!("{stem}.{id}.txt")
            }
        }
        // No usable stem/extension. Three cases: no extension at all
        // ("Makefile"), a bare inert extension (".conf") and an over-long
        // "extension" take the suffix form - with `.txt` appended so the name
        // still passes the opener's inert-extension gate; a bare NON-inert
        // extension (".scr") stages as plain inert text.
        _ => {
            if base.starts_with('.') && base.len() > 1 && !is_inert_stage_extension(&base[1..]) {
                format!("file.{id}.txt")
            } else {
                format!("{base}-{id}.txt")
            }
        }
    }
}

/// Best-effort removal of files older than `max_age` inside the sshspan-edit
/// temp dir. Only ever touches plain files directly inside that directory -
/// never anything outside it, never subdirectories. Staged copies left behind
/// by a crash or a killed session are otherwise never cleaned up.
pub fn prune_stale_stage_files(dir: &std::path::Path, max_age: std::time::Duration) {
    let cutoff = std::time::SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue; // never recurse / never touch directories
        }
        let Ok(md) = entry.metadata() else { continue };
        // Modified time older than the cutoff → stale. Best-effort removal.
        if md.modified().map(|t| t < cutoff).unwrap_or(false) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Age threshold for the on-start stale-file prune (audit finding: staged
/// copies accumulate in the shared temp dir when sessions are killed or the
/// app crashes before the edit watch is closed).
pub const STAGE_FILE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Keep-alive stop flags for open SFTP sessions: a periodic cheap round-trip
/// keeps NAT/firewall state alive. Setting the flag stops the loop; the entry
/// is removed when the SFTP session closes.
#[derive(Default)]
pub struct KeepaliveRegistry {
    flags: Mutex<HashMap<String, Arc<std::sync::atomic::AtomicBool>>>,
}

impl KeepaliveRegistry {
    pub fn new() -> Self {
        Self {
            flags: Mutex::new(HashMap::new()),
        }
    }
    pub fn insert(&self, session_id: String, stopped: Arc<std::sync::atomic::AtomicBool>) {
        // Stop any previous loop for this session first.
        if let Some(old) = self.flags.lock().unwrap().insert(session_id, stopped) {
            old.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    pub fn stop(&self, session_id: &str) {
        if let Some(f) = self.flags.lock().unwrap().remove(session_id) {
            f.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    pub fn stop_all(&self) {
        let mut guard = self.flags.lock().unwrap();
        for (_, f) in guard.iter() {
            f.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        guard.clear();
    }
}

/// Create a local file for a transfer to write into, replacing whatever is
/// there WITHOUT following a symlink.
///
/// `File::create` truncates through an existing symlink, so anything able to
/// pre-create one at the destination - a world-writable download directory, a
/// hostile process running as the same user - had the transfer overwrite the
/// link target instead. `<dest>.part` is the easier target of the two, since
/// its name follows from the destination.
///
/// Same shape as [`crate::ssh::write_secret_file`]: unlink first so a planted
/// symlink is removed rather than traversed, then `create_new` so a symlink
/// re-planted in the gap fails the open instead of being followed. On Unix
/// `O_NOFOLLOW` closes that race directly as well.
///
/// The mode is deliberately left at the process default: these are the user's
/// downloaded files, not secrets, and forcing 0600 would surprise anyone
/// fetching something they then expect other tools to read.
pub async fn create_transfer_file(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    // tokio's OpenOptions carries custom_flags inherently on Unix - no
    // std OpenOptionsExt import needed.
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    opts.open(path).await
}

/// Open an EXISTING transfer file for append during a resume, without
/// following a symlink planted at the final component.
///
/// `create_transfer_file` removes-then-recreates, which is correct for a
/// fresh transfer but would delete the very `.part` a resume is supposed to
/// continue. Appending with a plain `OpenOptions::append(true).open` follows
/// a planted symlink, so an attacker who can drop `dest/name.part -> victim`
/// into a writable download folder would have remote bytes appended to
/// `victim` (the final rename then moves the LINK, leaving the modified
/// victim behind). Guard the final component at both ends of the race:
///
/// 1. lstat the path first: if it is a symlink (or anything but a regular
///    file), refuse. The caller's resume-offset logic already treats "not a
///    trustworthy regular file" as "start over".
/// 2. Open with O_NOFOLLOW (Unix) so a link swapped in between the check and
///    the open fails with ELOOP instead of being followed. On Windows the
///    FILE_FLAG_OPEN_REPARSE_POINT equivalent is not exposed through tokio's
///    OpenOptions; the pre-check plus the staging-dir/destination model
///    (queue downloads land in a user-chosen directory, and the
///    authenticated-local-attacker scenario the symlink needs is already a
///    reduced threat there) is the accepted residual, documented here.
///
/// Returns the metadata captured by the lstat so the caller can align its
/// resume offset against the SAME object it is about to append to.
pub async fn open_transfer_file_append(
    path: &std::path::Path,
) -> std::io::Result<(tokio::fs::File, std::fs::Metadata)> {
    let md = tokio::fs::symlink_metadata(path).await?;
    if md.file_type().is_symlink() || !md.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to resume into {}: not a regular file (possible planted link)",
                path.display()
            ),
        ));
    }
    let mut opts = tokio::fs::OpenOptions::new();
    opts.append(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    let file = opts.open(path).await?;
    Ok((file, md))
}

#[cfg(test)]
mod tests {
    /// A transfer must not write through a symlink planted at its
    /// destination. `File::create` truncates the link TARGET; the helper
    /// unlinks first and opens with create_new + O_NOFOLLOW, so the planted
    /// link is removed rather than followed and the victim is untouched.
    #[test]
    fn create_transfer_file_does_not_follow_a_planted_symlink() {
        let dir = std::env::temp_dir().join(format!("sshspan-nofollow-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"do not clobber me").unwrap();
        let planted = dir.join("download.part");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        #[cfg(not(unix))]
        return;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let file = rt.block_on(create_transfer_file(&planted));
        assert!(
            file.is_ok(),
            "the transfer file itself should still be created"
        );
        drop(file);
        // The victim keeps its contents, and the destination is now a real
        // file rather than a link.
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not clobber me");
        assert!(!std::fs::symlink_metadata(&planted)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    #[test]
    fn edit_temp_dir_exists() {
        let dir = edit_temp_dir();
        assert!(
            dir.is_dir(),
            "edit temp dir must exist after edit_temp_dir()"
        );
        assert!(
            dir.ends_with("sshspan-edit"),
            "unexpected dir: {}",
            dir.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn edit_temp_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = edit_temp_dir();
        let mode = std::fs::metadata(&dir)
            .expect("temp dir metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "sshspan-edit must not be readable by other users (mode {mode:o})"
        );
    }

    /// REGRESSION: `symlink_metadata().is_dir()` alone accepted a real
    /// directory another local user had pre-created at the predictable
    /// `/tmp/sshspan-edit`. The 0700 chmod then failed with EPERM and was only
    /// logged, so staged remote files landed in their directory, readable and
    /// replaceable before the watcher re-uploaded them. Ownership is now part
    /// of the test.
    #[cfg(unix)]
    #[test]
    fn reuse_rejects_a_directory_we_do_not_own() {
        use std::os::unix::fs::MetadataExt;

        let dir = std::env::temp_dir().join(format!(
            "sshspan-reuse-foreign-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Build the hostile shape directly when we can (running as root, as CI
        // containers often do): a REAL directory owned by another uid. That is
        // precisely what the old is_dir()-only check waved through.
        let made_foreign = if effective_uid() == 0 {
            let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
            // uid 65534 = nobody on every distro we ship for.
            unsafe { libc::chown(c.as_ptr(), 65534, 65534) == 0 }
        } else {
            false
        };

        if made_foreign {
            assert_ne!(
                std::fs::symlink_metadata(&dir).unwrap().uid(),
                effective_uid(),
                "fixture must be owned by someone else"
            );
            assert!(
                !reuse_is_safe(&dir),
                "a directory owned by another user must never be reused for staging"
            );
        } else {
            // Unprivileged fallback: /tmp is a real, world-writable directory
            // we do not own on any normal system.
            let shared = std::path::Path::new("/tmp");
            if shared.is_dir()
                && std::fs::symlink_metadata(shared).unwrap().uid() != effective_uid()
            {
                assert!(!reuse_is_safe(shared));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory we own and can restrict is fine to reuse.
    #[cfg(unix)]
    #[test]
    fn reuse_accepts_our_own_directory() {
        let dir = std::env::temp_dir().join(format!(
            "sshspan-reuse-ok-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(reuse_is_safe(&dir));
        // ...and reuse_is_safe tightened it on the way through.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The opener-side inert-extension gate: extensions whose
    /// OS handler could execute the file must be refused; editor/viewer
    /// extensions pass. This is the predicate `system_open_external` enforces
    /// at launch time, independent of how the staged file was named.
    #[test]
    fn inert_extension_gate_blocks_executables() {
        use std::path::Path;
        for ok in [
            "a.txt", "b.md", "c.json", "d.yaml", "e.pem", "f.log", "g.csv",
        ] {
            assert!(path_has_inert_extension(Path::new(ok)), "should open: {ok}");
        }
        for bad in [
            "x.exe", "x.scr", "x.bat", "x.cmd", "x.com", "x.msi", "x.ps1", "x.vbs", "x.js",
            "x.jar", "x.sh", "x.dll", "x.bin", "x.7z", "x", "x.pub",
        ] {
            assert!(
                !path_has_inert_extension(Path::new(bad)),
                "should refuse: {bad}"
            );
        }
    }

    /// A symlink at the staging name is refused (lstat never follows it).
    #[cfg(unix)]
    #[test]
    fn reuse_rejects_a_symlink() {
        let base = std::env::temp_dir().join(format!(
            "sshspan-reuse-link-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("real");
        std::fs::create_dir_all(&target).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(!reuse_is_safe(&link));
        let _ = std::fs::remove_dir_all(&base);
    }

    // ── in-flight searches (A7-21) ───────────────────────────────────────────

    fn is_cancelled(flag: &Arc<std::sync::atomic::AtomicBool>) -> bool {
        flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Refining a query in a big tree starts a second walk while the first is
    /// still running. The first used to keep going and mix its matches into
    /// the new result list; now it is told to stop.
    #[test]
    fn a_new_search_cancels_the_one_it_supersedes() {
        let reg = SftpRegistry::new();
        let first = reg.begin_search("sess", "s1");
        assert!(!is_cancelled(&first));

        let second = reg.begin_search("sess", "s2");

        assert!(is_cancelled(&first), "the superseded walk must stop");
        assert!(!is_cancelled(&second));
    }

    #[test]
    fn searches_of_different_sessions_do_not_affect_each_other() {
        let reg = SftpRegistry::new();
        let a = reg.begin_search("sess-a", "s1");
        let b = reg.begin_search("sess-b", "s2");
        assert!(!is_cancelled(&a) && !is_cancelled(&b));
        assert!(reg.cancel_search("sess-a", "s1"));
        assert!(is_cancelled(&a) && !is_cancelled(&b));
    }

    /// A late "Stop" for a search that was already replaced must not stop the
    /// replacement.
    #[test]
    fn cancel_search_only_hits_the_current_search() {
        let reg = SftpRegistry::new();
        let _old = reg.begin_search("sess", "old");
        let current = reg.begin_search("sess", "current");

        assert!(!reg.cancel_search("sess", "old"), "stale id");
        assert!(
            !reg.cancel_search("other-session", "current"),
            "wrong session"
        );
        assert!(!is_cancelled(&current));

        assert!(reg.cancel_search("sess", "current"));
        assert!(is_cancelled(&current));
        assert!(!reg.cancel_search("sess", "current"), "already gone");
    }

    /// The old walk finishing after a newer one started must not unregister
    /// the newer one (it would become uncancellable).
    #[test]
    fn finish_search_does_not_forget_a_newer_search() {
        let reg = SftpRegistry::new();
        reg.begin_search("sess", "s1");
        let second = reg.begin_search("sess", "s2");

        reg.finish_search("sess", "s1");

        assert!(reg.cancel_search("sess", "s2"));
        assert!(is_cancelled(&second));
        // Finishing the current one unregisters it.
        reg.begin_search("sess", "s3");
        reg.finish_search("sess", "s3");
        assert!(!reg.cancel_search("sess", "s3"));
    }

    /// Closing the SFTP tab, or locking the vault, ends the walk too.
    #[test]
    fn closing_a_session_or_locking_the_vault_cancels_its_search() {
        let reg = SftpRegistry::new();
        let a = reg.begin_search("sess-a", "s1");
        let b = reg.begin_search("sess-b", "s2");

        assert!(
            reg.remove("sess-a").is_none(),
            "no SFTP session was inserted"
        );
        assert!(is_cancelled(&a) && !is_cancelled(&b));

        reg.clear();
        assert!(is_cancelled(&b));
    }

    #[test]
    fn staged_name_contains_random_component_and_extension() {
        let a = staged_file_name("notes.txt");
        let b = staged_file_name("notes.txt");
        assert!(a.ends_with(".txt"), "extension must be preserved: {a}");
        assert!(b.ends_with(".txt"));
        assert_ne!(a, b, "two staged names must differ (random component)");
        assert!(
            a.starts_with("notes."),
            "sanitized base must be preserved: {a}"
        );
        // The random component must be a full UUID's worth of entropy (32 hex
        // chars), not something guessable like a counter.
        let middle = a
            .strip_prefix("notes.")
            .and_then(|s| s.strip_suffix(".txt"))
            .expect("expected notes.{uuid}.txt");
        assert_eq!(middle.len(), 32, "expected a 32-hex-char uuid: {a}");
        assert!(
            middle.chars().all(|c| c.is_ascii_hexdigit()),
            "random component must be hex: {a}"
        );
    }

    #[test]
    fn staged_name_no_extension_uses_suffix() {
        let a = staged_file_name("Makefile");
        assert!(a.starts_with("Makefile-"), "unexpected name: {a}");
        // No usable extension: the uuid is a suffix, and `.txt` is appended so
        // the opener's inert-extension gate accepts the staged path (A7-06).
        let middle = a
            .strip_prefix("Makefile-")
            .and_then(|s| s.strip_suffix(".txt"))
            .expect("expected Makefile-{uuid}.txt");
        assert_eq!(middle.len(), 32, "expected a 32-hex-char uuid: {a}");
        assert!(!middle.contains('.'), "no extension was given: {a}");
    }

    /// A7-06 COMPOSITION: `system_open_external` refuses any path whose
    /// extension is not on the inert allowlist, so every name the staging code
    /// can produce has to pass that same gate. Each half was unit-tested on its
    /// own while the composition failed for every extension-less name - the
    /// files people most often edit on servers (`authorized_keys`,
    /// `known_hosts`, `/etc/hosts`, `fstab`, `sshd_config`, `Makefile`).
    #[test]
    fn every_staged_name_passes_the_opener_gate() {
        for name in [
            "Makefile",
            "Dockerfile",
            "authorized_keys",
            "known_hosts",
            "hosts",
            "fstab",
            "sshd_config",
            "crontab",
            ".bashrc",
            ".conf",
            ".scr",
            "",
            ".",
            "..",
            "a.",
            "..a",
            "noext-with-dash",
            "v1.2.3.verylongextensionnamethatexceedssixteen",
            "CON",
            "NUL",
            "x.pub",
            "id_rsa.pub",
            "evil.EXE",
            "notes.txt",
            "a/b\\c",
            "日本語",
            "trailing.dot.",
            " spaced name ",
        ] {
            let staged = staged_file_name(name);
            assert!(
                path_has_inert_extension(std::path::Path::new(&staged)),
                "{name:?} staged as {staged:?}, which system_open_external would refuse"
            );
        }
    }

    /// A6-14: `.pub` was on the allowlist, but on Windows it is the Microsoft
    /// Publisher association - an Office application with macro support, handed
    /// remote-supplied content. It must stage as plain text like every other
    /// non-inert extension.
    #[test]
    fn pub_is_not_an_inert_extension() {
        assert!(!is_inert_stage_extension("pub"));
        assert!(!is_inert_stage_extension("PUB"));
        assert!(!path_has_inert_extension(std::path::Path::new(
            "id_rsa.pub"
        )));
        let staged = staged_file_name("id_rsa.pub");
        assert!(staged.starts_with("id_rsa."), "base must survive: {staged}");
        assert!(staged.ends_with(".txt"), "must stage as text: {staged}");
    }

    #[test]
    fn staged_name_flattens_separators() {
        let a = staged_file_name("a/b\\c.txt");
        assert!(
            !a.contains('/') && !a.contains('\\'),
            "separators must be flattened: {a}"
        );
        assert!(a.ends_with(".txt"));
    }

    #[test]
    fn staged_name_rejects_empty_and_long_extensions() {
        assert!(staged_file_name("").starts_with("file-"));
        // A dot-heavy name whose "extension" is non-inert stages as inert
        // text: the base survives, the tail does not.
        let a = staged_file_name("v1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17");
        assert!(a.starts_with("v1.2.3."), "base must be preserved: {a}");
        assert!(
            a.ends_with(".txt"),
            "non-inert tail must collapse to .txt: {a}"
        );
        // A genuinely over-long "extension" (>16 chars) takes the no-
        // extension suffix form instead: base preserved, uuid appended.
        let b = staged_file_name("v1.2.3.verylongextensionnamethatexceedssixteen");
        assert!(
            b.starts_with("v1.2.3.verylongextensionnamethatexceedssixteen-"),
            "over-long extension must take the suffix form: {b}"
        );
    }

    #[test]
    fn staged_name_forces_txt_for_non_inert_extensions() {
        // Known-executable names and - the point of the allowlist - every
        // UNKNOWN/binary extension stage as .txt; only inert text formats
        // keep their extension.
        for name in [
            "evil.scr",
            "x.EXE",
            "run.ps1",
            "doc.msi",
            "link.url",
            "shell.cpl",
            "app.jar",
            "setup.inf",
            "app.7z",
            "doc.docx",
            "image.jpg",
            "page.html",
            "setup.msix",
            "data.db",
            "archive.tar.gz",
            "script.py",
        ] {
            let a = staged_file_name(name);
            assert!(
                a.ends_with(".txt"),
                "non-inert extension must stage as .txt: {name} → {a}"
            );
        }
        for name in [
            "notes.txt",
            "server.conf",
            "app.ini",
            "config.yaml",
            "data.json",
            "cert.pem",
            "report.csv",
            "readme.md",
            "style.css",
            "backup.log",
        ] {
            let a = staged_file_name(name);
            let ext = a
                .rsplit_once('.')
                .map(|(_, e)| e.to_ascii_lowercase())
                .unwrap_or_default();
            let src_ext = name.rsplit('.').next().unwrap().to_ascii_lowercase();
            assert_eq!(
                ext, src_ext,
                "inert extension must be preserved: {name} → {a}"
            );
        }
        // The uuid component and sanitized base survive the rewrite.
        let a = staged_file_name("evil.scr");
        assert!(a.starts_with("evil."), "base must be preserved: {a}");
        let middle = a
            .strip_prefix("evil.")
            .and_then(|s| s.strip_suffix(".txt"))
            .expect("evil.{uuid}.txt");
        assert_eq!(middle.len(), 32, "expected a 32-hex-char uuid: {a}");
    }

    #[test]
    fn staged_name_non_inert_extension_with_trailing_dot() {
        // Windows strips a trailing dot, so `notes.txt.` would land on disk as
        // `notes.txt`; and `evil.scr.` would land as `evil.scr` (executable).
        // The sanitizer trims the dot first, so the allowlist check still
        // sees the true extension.
        let a = staged_file_name("notes.txt.");
        assert!(
            a.ends_with(".txt"),
            "trailing dot must not break staging: {a}"
        );
        assert!(a.starts_with("notes."), "base must be preserved: {a}");

        let a = staged_file_name("evil.scr.");
        assert!(
            a.ends_with(".txt"),
            "non-inert ext behind a trailing dot must still be forced to .txt: {a}"
        );
        assert!(a.starts_with("evil."), "base must be preserved: {a}");
    }

    #[test]
    fn staged_name_neutralizes_windows_device_names() {
        // A base that is only a device name gets a `_` prefix so the staged
        // file is a regular file, not a device.
        let a = staged_file_name("CON");
        assert!(a.starts_with("_CON"), "device name must be prefixed: {a}");

        // Device name with a (blocked) extension: the stem is the device
        // name, so the prefix applies AND the extension is forced to .txt.
        // Policy: `CON.exe` → `_CON.{uuid}.txt` - never a device, never
        // executable.
        let a = staged_file_name("CON.exe");
        assert!(a.starts_with("_CON."), "device stem must be prefixed: {a}");
        assert!(
            a.ends_with(".txt"),
            "blocked extension must stage as .txt: {a}"
        );

        // Device name with a benign extension keeps the extension.
        let a = staged_file_name("NUL.log");
        assert!(a.starts_with("_NUL."), "device stem must be prefixed: {a}");
        assert!(
            a.ends_with(".log"),
            "benign extension must be preserved: {a}"
        );
    }

    #[test]
    fn staged_name_bare_extension_and_empty() {
        // A remote name that is only a NON-INERT extension stages
        // deterministically as an inert text file.
        let a = staged_file_name(".scr");
        assert!(
            a.starts_with("file."),
            "bare non-inert extension must stage as file.*: {a}"
        );
        assert!(
            a.ends_with(".txt"),
            "bare non-inert extension must stage as .txt: {a}"
        );

        // A bare INERT extension keeps the suffix form (editor association).
        let a = staged_file_name(".conf");
        assert!(
            a.starts_with(".conf-"),
            "bare inert extension keeps the suffix form: {a}"
        );

        // Empty name keeps the existing deterministic fallback.
        assert!(staged_file_name("").starts_with("file-"));
    }

    #[test]
    fn prune_removes_only_stale_files_in_dir() {
        let dir = std::env::temp_dir().join(format!("sshspan-test-prune-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let stale = dir.join("stale.txt");
        let fresh = dir.join("fresh.txt");
        let keep_dir = dir.join("subdir");
        std::fs::write(&stale, "old").unwrap();
        std::fs::write(&fresh, "new").unwrap();
        std::fs::create_dir_all(&keep_dir).unwrap();
        // Backdate the stale file. The subdirectory is deliberately left
        // with a fresh mtime: prune must skip directories regardless of age.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();

        prune_stale_stage_files(&dir, std::time::Duration::from_secs(24 * 3600));

        assert!(!stale.exists(), "stale file must be pruned");
        assert!(fresh.exists(), "fresh file must survive");
        assert!(keep_dir.exists(), "directories must never be touched");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── A staged copy is deleted after OUR handles close ──

    fn scratch_file(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sshspan-staged-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(&path, b"remote secret").unwrap();
        path
    }

    /// The edit ended while an upload (or hash, or reload) still had the file
    /// open: on Windows the delete then failed and the copy of the remote
    /// file stayed in the temp dir. It waits for our handles; the last one to
    /// close deletes it, and a discarded copy cannot be opened again.
    #[test]
    fn ru6a_a_staged_copy_waits_for_our_open_handles_before_it_is_deleted() {
        let path = scratch_file("handles");
        let staged = StagedCopy::new(path.clone());
        let first = staged.open_handle().expect("not discarded yet");
        let second = staged.open_handle().expect("not discarded yet");

        staged.discard();

        assert!(path.exists(), "deleted while our handles were open");
        assert!(
            staged.open_handle().is_none(),
            "a discarded copy cannot be opened again"
        );
        drop(first);
        assert!(path.exists(), "one handle is still open");
        drop(second);
        assert!(!path.exists(), "the last handle to close deletes it");

        // With no handle open, discarding deletes at once.
        let now = scratch_file("now");
        StagedCopy::new(now.clone()).discard();
        assert!(!now.exists());
    }

    /// One later retry for a sharing violation (another program - usually
    /// the editor, for a moment while saving - has the file open without
    /// delete sharing); any other failure is not retried.
    #[test]
    fn ru6a_a_sharing_violation_is_retried_once_and_nothing_else_is() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = |failures: usize, sharing: bool| -> usize {
            let calls = Arc::new(AtomicUsize::new(0));
            let counter = calls.clone();
            remove_staged_file_with(
                std::path::Path::new("/staged-copy"),
                move |_: &std::path::Path| {
                    if counter.fetch_add(1, Ordering::SeqCst) < failures {
                        Err(std::io::Error::other("in use"))
                    } else {
                        Ok(())
                    }
                },
                move |_: &std::io::Error| sharing,
                |retry: Box<dyn FnOnce() + Send>| retry(),
            );
            calls.load(Ordering::SeqCst)
        };
        assert_eq!(attempts(0, true), 1, "it worked at once");
        assert_eq!(attempts(1, true), 2, "a sharing violation is retried");
        assert_eq!(attempts(5, true), 2, "once");
        assert_eq!(attempts(1, false), 1, "nothing else is retried");
    }

    /// Windows' ERROR_SHARING_VIOLATION (32) is a sharing
    /// violation; access denied and errors without an OS code are not.
    /// (Compile-checked on windows-gnu; it runs on Windows.)
    #[cfg(windows)]
    #[test]
    fn ru6a_a_sharing_violation_is_windows_error_32() {
        assert!(is_sharing_violation(&std::io::Error::from_raw_os_error(32)));
        assert!(!is_sharing_violation(&std::io::Error::from_raw_os_error(5)));
        assert!(!is_sharing_violation(&std::io::Error::other("in use")));
    }

    /// Elsewhere code 32 is something else (EPIPE on Linux): never a sharing
    /// violation, so nothing is retried.
    #[cfg(not(windows))]
    #[test]
    fn ru6a_there_is_no_sharing_violation_off_windows() {
        assert!(!is_sharing_violation(&std::io::Error::from_raw_os_error(
            32
        )));
        assert!(!is_sharing_violation(&std::io::Error::other("in use")));
    }
}
