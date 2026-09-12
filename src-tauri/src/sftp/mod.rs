//! SFTP over the live SSH session. Each tab's SFTP session is stored here,
//! keyed by the tab's SSH session id, alongside a registry of "open with
//! system editor" watches that re-upload files when the local copy changes.

pub mod queue;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use russh_sftp::client::SftpSession;

/// Per-connection SFTP sessions, keyed by SSH session id.
#[derive(Default)]
pub struct SftpRegistry {
    sessions: Mutex<HashMap<String, Arc<SftpSession>>>,
}

impl SftpRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
    pub fn insert(&self, id: String, sftp: Arc<SftpSession>) {
        self.sessions.lock().unwrap().insert(id, sftp);
    }
    pub fn get(&self, id: &str) -> Option<Arc<SftpSession>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }
    pub fn remove(&self, id: &str) -> Option<Arc<SftpSession>> {
        self.sessions.lock().unwrap().remove(id)
    }
}

/// One "open with system editor" watch: when the local temp file is written,
/// its contents are re-uploaded to the remote path (debounced).
pub struct EditWatch {
    pub session_id: String,
    pub remote_path: String,
    pub local_path: String,
    pub sftp: Arc<SftpSession>,
    pub watcher: Option<notify::RecommendedWatcher>,
    /// Set when the watch should stop (file closed / session ended).
    pub stopped: Arc<std::sync::atomic::AtomicBool>,
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
    pub fn get(&self, key: &str) -> Option<Arc<std::sync::atomic::AtomicBool>> {
        self.watches
            .lock()
            .unwrap()
            .get(key)
            .map(|w| w.stopped.clone())
    }
    pub fn insert(&self, key: String, watch: EditWatch) {
        self.watches.lock().unwrap().insert(key, watch);
    }
    pub fn stop(&self, key: &str) -> Option<String> {
        let mut guard = self.watches.lock().unwrap();
        if let Some(mut w) = guard.remove(key) {
            w.stopped.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = w.watcher.take(); // dropped = watch stopped (notify 7 has no close())
            Some(w.local_path)
        } else {
            None
        }
    }
    pub fn stop_all(&self) {
        let mut guard = self.watches.lock().unwrap();
        let stopped: Vec<String> = guard
            .iter_mut()
            .map(|(_, w)| {
                w.stopped.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = w.watcher.take(); // dropped = stopped
                w.local_path.clone()
            })
            .collect();
        guard.clear();
        drop(guard);
        // Clean the staged copies (best-effort) so edited remote file
        // contents do not linger in the temp dir after the app locks the
        // vault or shuts down.
        for local in stopped {
            let _ = std::fs::remove_file(&local);
        }
    }
    pub fn stop_all_for_session(&self, session_id: &str) {
        let mut guard = self.watches.lock().unwrap();
        let keys: Vec<String> = guard
            .iter()
            .filter(|(_, w)| w.session_id == session_id)
            .map(|(k, _)| k.clone())
            .collect();
        let mut locals: Vec<String> = Vec::new();
        for k in keys {
            if let Some(mut w) = guard.remove(&k) {
                w.stopped.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = w.watcher.take(); // dropped = stopped
                locals.push(w.local_path);
            }
        }
        drop(guard);
        // Clean the session's staged copies (best-effort).
        for local in locals {
            let _ = std::fs::remove_file(&local);
        }
    }
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
        Ok(()) => true, // we just created it — it cannot be a symlink
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            match std::fs::symlink_metadata(&dir) {
                // symlink_metadata().is_dir() is true only for a real
                // directory; a symlink reports is_symlink() (is_dir() false).
                Ok(md) if md.is_dir() => true,
                _ => false,
            }
        }
        Err(_) => false,
    };
    let dir = if usable {
        dir
    } else {
        let fallback =
            std::env::temp_dir().join(format!("sshspan-edit-{}", uuid::Uuid::new_v4().simple()));
        log::warn!(
            "[sshspan-sftp] {} is missing, not a directory, or a symlink (possible tampering); using fallback {}",
            dir.display(),
            fallback.display()
        );
        let _ = std::fs::create_dir_all(&fallback);
        fallback
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // create_dir leaves the mode at umask default (typically 0755), and an
        // existing dir may predate this hardening — reassert 0700. Best-effort:
        // a failure to chmod is ignored like the create above, but is logged
        // so a misconfigured environment is visible.
        if let Err(e) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)) {
            log::warn!(
                "[sshspan-sftp] could not restrict permissions on {}: {e}",
                dir.display()
            );
        }
    }
    dir
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
/// executes its input. EVERYTHING ELSE — including every unknown extension —
/// is forced to `.txt`. This is an allowlist rather than the old executable
/// denylist on purpose: a denylist ages badly (each new executable/packaged
/// format is a gap until someone adds it), while the edit flow is text-editor
/// based anyway, so an unknown extension has no honest handler to preserve.
/// The staged name does not affect what is uploaded back — the original
/// remote path is untouched — so collapsing names to `.txt` costs nothing
/// except a default-app association.
const INERT_STAGE_EXTENSIONS: [&str; 25] = [
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
    "pub",
    "properties",
];

fn is_inert_stage_extension(ext: &str) -> bool {
    INERT_STAGE_EXTENSIONS
        .iter()
        .any(|b| b.eq_ignore_ascii_case(ext))
}

/// Unpredictable staged-file name for a remote file: `{base}.{uuid}.{ext}`
/// (no extension → `{base}-{uuid}`). The random component prevents another
/// local user from pre-creating or guessing the path of a file that will
/// hold remote (potentially secret) contents; the sanitized base and the
/// original extension are preserved so the editor association still works.
///
/// If the remote extension is not on the inert allowlist (executable,
/// packaged, binary, or simply unknown — e.g. `.scr`, `.exe`, `.7z`), it is
/// NEVER preserved — the staged name is forced to end in `.txt` so the OS
/// shell opens it in an editor instead of handing it to whatever handler the
/// extension maps to. A remote name that is only a non-inert extension
/// (`.scr`) or empty stages as `file.{uuid}.txt`.
pub fn staged_file_name(remote_name: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let base = sanitize_stage_base(remote_name);
    let base = if base.is_empty() { "file" } else { &base };
    match base.rsplit_once('.') {
        // Preserve a non-empty extension, limiting it to a sane length so a
        // dot-heavy name cannot produce a pathologically long tail — but only
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
        // ("Makefile") and bare inert extensions (".conf") keep the suffix
        // form; a bare NON-inert extension (".scr") stages as inert text.
        _ => {
            if base.starts_with('.') && base.len() > 1 && !is_inert_stage_extension(&base[1..]) {
                format!("file.{id}.txt")
            } else {
                format!("{base}-{id}")
            }
        }
    }
}

/// Best-effort removal of files older than `max_age` inside the sshspan-edit
/// temp dir. Only ever touches plain files directly inside that directory —
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

#[cfg(test)]
mod tests {
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
        assert!(!a.contains('.'), "no extension was given: {a}");
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
        // Known-executable names and — the point of the allowlist — every
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
        // Policy: `CON.exe` → `_CON.{uuid}.txt` — never a device, never
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
}
