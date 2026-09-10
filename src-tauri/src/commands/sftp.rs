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

fn sftp_from_session(
    app: &AppHandle,
    session_id: &str,
) -> Result<Arc<russh_sftp::client::SftpSession>, CmdError> {
    app.state::<SftpRegistry>()
        .get(session_id)
        .ok_or_else(|| CmdError("SFTP is not open for this session — switch to SFTP first.".into()))
}

/// Render a russh-sftp error as a clean, single-layer message.
///
/// russh-sftp's `Status` Display is "{status_code}: {error_message}", which
/// for a bare SSH_FXP_FAILURE with no message becomes "Failure: " (or
/// "Failure: Failure" when the server echoes the code name as the message).
/// Re-wrapping that in "download failed: …" produced the user-facing
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
    app.state::<SftpRegistry>()
        .insert(session_id.clone(), Arc::new(sftp));
    Ok(serde_json::json!({ "ok": true, "cwd": cwd }))
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_ms: Option<i64>,
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
            is_dir: md.is_dir(),
            size: md.size.unwrap_or(0),
            modified_ms: md.mtime.map(|s| (s as i64) * 1000),
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
        sftp.remove_dir(&path)
            .await
            .map_err(|e| CmdError(format!("rmdir failed: {e}")))?;
    } else {
        sftp.remove_file(&path)
            .await
            .map_err(|e| CmdError(format!("rm failed: {e}")))?;
    }
    Ok(serde_json::json!({ "ok": true }))
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

#[tauri::command]
pub async fn sftp_download(
    app: AppHandle,
    session_id: String,
    remote: String,
    local: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
    download_to(&sftp, &remote, &local).await?;
    Ok(serde_json::json!({ "ok": true, "local": local }))
}

/// Download `remote` into local path `local`, robust against SFTP servers
/// that answer a read crossing EOF with SSH_FX_FAILURE instead of a short
/// read (seen in the wild on some sftp-server bridges/gateways; reproduced
/// against the dev-sshd fixture in EOF-FAILURE mode — the exact
/// "download failed: Failure: Failure" report).
///
/// Two defenses:
/// 1. Size-clamped reads: stat the file first and never request bytes past
///    EOF. `tokio::io::copy` always asks for a full 8 KiB buffer, so its
///    final read crosses EOF on any file whose size is not a multiple of
///    8 KiB — fatal against such servers.
/// 2. Tolerant close: if the server answers the CLOSE of a fully-copied
///    read handle with SSH_FX_FAILURE, the data has already landed locally,
///    so the transfer is treated as complete (logged, not failed).
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
    let mut local_file = tokio::fs::File::create(local)
        .await
        .map_err(|e| CmdError(format!("local create failed: {e}")))?;

    // 32 KiB chunks, each clamped to the remaining bytes. A short read (<
    // requested) means EOF on well-behaved servers; the size clamp means we
    // never ask past EOF on any server.
    let mut buf = vec![0u8; 32 * 1024];
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
    Ok(())
}

#[tauri::command]
pub async fn sftp_upload(
    app: AppHandle,
    session_id: String,
    local: String,
    remote: String,
) -> CmdResult<serde_json::Value> {
    let sftp = sftp_from_session(&app, &session_id)?;
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
                upload_one_file(sftp.clone(), local, remote).await?;
                count += 1;
            }
        }
        Ok(count)
    })
}

/// Download a remote file to a temp location, start watching it, and hand the
/// path back. The renderer opens it with the system default app (opener); on
/// every local save the watcher re-uploads to the remote path.
#[tauri::command]
pub async fn sftp_open_for_edit(
    app: AppHandle,
    session_id: String,
    remote: String,
) -> CmdResult<serde_json::Value> {
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

    download_to(&sftp, &remote, &local.display().to_string()).await?;
    let local_str = local.display().to_string();

    let key = format!("{session_id}:{remote}");
    let edit_registry = app.state::<EditRegistry>();
    // Stop any previous watch on the same file.
    edit_registry.stop(&key);

    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sftp_for_watch = sftp.clone();
    let remote_for_watch = Arc::new(remote.clone());
    let local_for_watch = Arc::new(local.display().to_string());
    let session_for_watch = Arc::new(session_id.clone());
    let stopped_for_watch = stopped.clone();

    let mut watcher =
        notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            let stopped_for_watch = stopped_for_watch.clone();
            if stopped_for_watch.load(Ordering::SeqCst) {
                return;
            }
            let Ok(event) = res else { return };
            let is_write = matches!(
                event.kind,
                notify::EventKind::Modify(notify::event::ModifyKind::Data(_))
                    | notify::EventKind::Modify(notify::event::ModifyKind::Any)
                    | notify::EventKind::Modify(notify::event::ModifyKind::Metadata(_))
            );
            if !is_write {
                return;
            }
            if !event
                .paths
                .iter()
                .any(|p| p.to_string_lossy() == local_for_watch.as_str())
            {
                return;
            }
            // Debounce: editors often write several times per save.
            let sftp = sftp_for_watch.clone();
            let remote = (*remote_for_watch).clone();
            let local = (*local_for_watch).clone();
            let session = (*session_for_watch).clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                if stopped_for_watch.load(Ordering::SeqCst) {
                    return;
                }
                let mut lf = match tokio::fs::File::open(&local).await {
                    Ok(f) => f,
                    Err(_) => return,
                };
                let mut rf = match sftp.create(&remote).await {
                    Ok(f) => f,
                    Err(_) => return,
                };
                if tokio::io::copy(&mut lf, &mut rf).await.is_ok() {
                    eprintln!("[sshspan-sftp] synced back {remote} on {session}");
                    // The staged file deliberately stays for the life of the
                    // edit session: the watcher only uploads-on-change, it
                    // never re-downloads, and deleting a path a third-party
                    // editor may hold open makes editors recreate an
                    // empty/stale buffer on the next save — clobbering the
                    // remote file. Cleanup happens on session close, vault
                    // lock/teardown (EditRegistry::stop*), explicit
                    // sftp_close_edit, or the 24h stale prune.
                }
            });
        })
        .map_err(|e| CmdError(e.to_string()))?;

    watcher
        .watch(&local, notify::RecursiveMode::NonRecursive)
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
    JobKind, QueuedItem,
};

/// Expand a local directory into upload jobs (recursive); a file becomes one.
fn expand_upload(
    local: PathBuf,
    remote: String,
    session_id: String,
    server_name: String,
    out: &mut Vec<QueuedItem>,
) {
    let md = match std::fs::metadata(&local) {
        Ok(m) => m,
        Err(_) => return,
    };
    if md.is_file() {
        out.push(QueuedItem::simple(
            JobKind::Upload,
            session_id.clone(),
            server_name.clone(),
            local.display().to_string(),
            remote,
            md.len(),
        ));
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
        expand_upload(child, rname, session_id.clone(), server_name.clone(), out);
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
/// - Windows reserved device names — CON, PRN, AUX, NUL, COM1-9, LPT1-9,
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
/// when the join would escape — the belt-and-braces check behind
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

/// Expand a remote directory into download jobs (recursive); a file becomes one.
///
/// `root` is the canonicalized user-chosen destination; every local path
/// queued by this walk is verified to stay under it.
fn expand_download(
    sftp: Arc<russh_sftp::client::SftpSession>,
    remote: String,
    local_dir: PathBuf,
    root: PathBuf,
    session_id: String,
    server_name: String,
    out: Vec<QueuedItem>,
) -> Pin<Box<dyn Future<Output = Result<Vec<QueuedItem>, String>> + Send>> {
    Box::pin(async move {
        let mut out = out;
        let md = sftp
            .metadata(&remote)
            .await
            .map_err(|e| format!("stat {remote}: {e}"))?;
        if !md.is_dir() {
            // Single file: its name comes from the user-picked remote path
            // (not a ReadDir entry), but sanitize anyway — the path string
            // still originates from the server's view of the filesystem.
            let raw = remote.rsplit('/').next().unwrap_or("file");
            let Some(local) = safe_join_under(&root, &local_dir, raw) else {
                log::warn!(
                    "[sshspan-sftp] skipping download of {remote}: unsafe local name {raw:?}"
                );
                return Ok(out);
            };
            out.push(QueuedItem::simple(
                JobKind::Download,
                session_id,
                server_name,
                local.display().to_string(),
                remote,
                md.size.unwrap_or(0),
            ));
            return Ok(out);
        }
        let raw_dir = remote.rsplit('/').next().unwrap_or("dir");
        let Some(target_dir) = safe_join_under(&root, &local_dir, raw_dir) else {
            log::warn!(
                "[sshspan-sftp] skipping download dir {remote}: unsafe local name {raw_dir:?}"
            );
            return Ok(out);
        };
        let _ = tokio::fs::create_dir_all(&target_dir).await;
        // create_dir_all above may have been raced by another queued job
        // creating a symlinked directory; re-anchor the walk at the canonical
        // path so subsequent joins stay under the real root.
        let target_dir = tokio::fs::canonicalize(&target_dir)
            .await
            .unwrap_or(target_dir);
        if !target_dir.starts_with(&root) {
            log::warn!(
                "[sshspan-sftp] skipping download dir {remote}: {} escapes destination root",
                target_dir.display()
            );
            return Ok(out);
        }
        let mut entries = sftp
            .read_dir(&remote)
            .await
            .map_err(|e| format!("list {remote}: {e}"))?;
        while let Some(entry) = entries.next() {
            let name = entry.file_name().to_string();
            if name == "." || name == ".." {
                continue;
            }
            let child_remote = format!("{}/{}", remote.trim_end_matches('/'), name);
            out = expand_download(
                sftp.clone(),
                child_remote,
                target_dir.clone(),
                root.clone(),
                session_id.clone(),
                server_name.clone(),
                out,
            )
            .await?;
        }
        Ok(out)
    })
}

/// Add transfers to the background queue. `items` is a list of
/// `{local, remote}` pairs plus a direction; directories are expanded
/// recursively. Requires a destination directory for downloads.
#[tauri::command]
pub async fn sftp_queue_add(
    app: AppHandle,
    session_id: String,
    direction: String,             // "upload" | "download"
    items: Vec<serde_json::Value>, // [{local, remote}] — remote for downloads may be a dir
    dest_dir: Option<String>,      // local dir for downloads
) -> CmdResult<serde_json::Value> {
    let kind = if direction == "upload" {
        JobKind::Upload
    } else {
        JobKind::Download
    };
    // ServerCopy jobs are enqueued via `sftp_server_copy`, never here.
    if !matches!(kind, JobKind::Upload | JobKind::Download) {
        return Err(CmdError("unsupported direction.".into()));
    }
    let server_name = app
        .state::<StdArc<SessionRegistry>>()
        .list()
        .into_iter()
        .find(|(id, _, _, _, _)| id == &session_id)
        .map(|(_, name, _, _, _)| name)
        .unwrap_or_default();

    let mut jobs: Vec<QueuedItem> = Vec::new();
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
                expand_upload(
                    PathBuf::from(local),
                    remote.to_string(),
                    session_id.clone(),
                    server_name.clone(),
                    &mut jobs,
                );
            }
        }
        JobKind::Download => {
            let sftp = sftp_from_session(&app, &session_id)?;
            let dest = dest_dir
                .map(PathBuf::from)
                .unwrap_or_else(crate::sftp::edit_temp_dir);
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
                jobs = expand_download(
                    sftp.clone(),
                    remote.to_string(),
                    root.clone(),
                    root.clone(),
                    session_id.clone(),
                    server_name.clone(),
                    jobs,
                )
                .await
                .map_err(CmdError)?;
            }
        }
        // ServerCopy never reaches here (guarded above).
        JobKind::ServerCopy => unreachable!("guarded above"),
    }

    let count = jobs.len();
    if count == 0 {
        return Ok(serde_json::json!({ "ok": true, "added": 0 }));
    }
    q_enqueue(&app, jobs);
    Ok(serde_json::json!({ "ok": true, "added": count }))
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
    q_retry(&app, job_id);
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
/// never used — some servers fail reads on the long-lived channel with
/// SSH_FX_FAILURE). The transfer queue panel shows progress; a temp staging
/// file is created by the worker and always removed on completion.
#[tauri::command]
pub async fn sftp_server_copy(
    app: AppHandle,
    from_session_id: String,
    remote: String,
    target_session_id: String,
    target_dir: String,
) -> CmdResult<serde_json::Value> {
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

    let name = remote.rsplit('/').next().unwrap_or("file");
    let target_path = format!("{}/{}", target_dir.trim_end_matches('/'), name);

    q_enqueue(
        &app,
        vec![QueuedItem {
            kind: JobKind::ServerCopy,
            session_id: from_session_id,
            server_name: source_server,
            local_path: String::new(), // no user-visible local path; worker stages a temp file
            remote_path: remote,
            size: 0, // stat'd by the worker on a fresh channel
            target: Some(tfq::ServerCopyTarget {
                session_id: target_session_id,
                server_name: target_server,
                remote_path: target_path.clone(),
            }),
        }],
    );
    Ok(serde_json::json!({ "ok": true, "target": target_path }))
}

// ─── recursive remote search ───────────────────────────────────────────────

/// Recursive walker emitting per-result `sftp-search` events with the
/// session id. Caps at 500 results to avoid runaway walks.
fn walk_search(
    sftp: Arc<russh_sftp::client::SftpSession>,
    app: AppHandle,
    dir: String,
    needle: String,
    depth: u32,
    max_depth: u32,
    matched: Arc<std::sync::atomic::AtomicUsize>,
    scanned: Arc<std::sync::atomic::AtomicUsize>,
    capped: Arc<std::sync::atomic::AtomicBool>,
    sid: String,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    use std::sync::atomic::Ordering as AtomOrd;
    use tauri::Emitter;
    Box::pin(async move {
        if depth > max_depth || capped.load(AtomOrd::SeqCst) {
            return;
        }
        let mut entries = match sftp.read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => return,
        };
        while let Some(entry) = entries.next() {
            if capped.load(AtomOrd::SeqCst) {
                return;
            }
            let name = entry.file_name().to_string();
            if name == "." || name == ".." {
                continue;
            }
            scanned.fetch_add(1, AtomOrd::SeqCst);
            let full = format!("{}/{}", dir.trim_end_matches('/'), name);
            let md = entry.metadata();
            let is_dir = md.is_dir();
            if name.to_lowercase().contains(&needle) {
                let m = matched.fetch_add(1, AtomOrd::SeqCst) + 1;
                if m > 500 {
                    capped.store(true, AtomOrd::SeqCst);
                    return;
                }
                let _ = app.emit(
                    "sftp-search",
                    serde_json::json!({
                        "sessionId": sid, "path": full, "name": name, "isDir": is_dir,
                        "size": md.size.unwrap_or(0),
                        "modifiedMs": md.mtime.map(|s| (s as i64) * 1000),
                        "done": false,
                    }),
                );
            }
            if is_dir {
                walk_search(
                    sftp.clone(),
                    app.clone(),
                    full,
                    needle.clone(),
                    depth + 1,
                    max_depth,
                    matched.clone(),
                    scanned.clone(),
                    capped.clone(),
                    sid.clone(),
                )
                .await;
            }
        }
    })
}

/// Recursively search under `root_path` for entries whose name contains
/// `query` (case-insensitive). Streams `sftp-search` events; ends with a
/// `{done:true}` summary.
#[tauri::command]
pub async fn sftp_search(
    app: AppHandle,
    session_id: String,
    root_path: String,
    query: String,
    max_depth: Option<u32>,
) -> CmdResult<serde_json::Value> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomOrd};
    use tauri::Emitter;
    let sftp = sftp_from_session(&app, &session_id)?;
    let needle = query.to_lowercase();
    let max_depth = max_depth.unwrap_or(10);

    let sid = session_id.clone();
    let root = root_path.clone();
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let matched = Arc::new(AtomicUsize::new(0));
        let scanned = Arc::new(AtomicUsize::new(0));
        let capped = Arc::new(AtomicBool::new(false));
        walk_search(
            sftp,
            app2.clone(),
            root,
            needle,
            0,
            max_depth,
            matched.clone(),
            scanned.clone(),
            capped.clone(),
            sid.clone(),
        )
        .await;
        let _ = app2.emit(
            "sftp-search",
            serde_json::json!({
                "sessionId": sid, "done": true,
                "matched": matched.load(AtomOrd::SeqCst).min(500),
                "scanned": scanned.load(AtomOrd::SeqCst),
                "capped": capped.load(AtomOrd::SeqCst),
            }),
        );
    });
    Ok(serde_json::json!({ "ok": true }))
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

/// List a local directory for the dual-pane local view. Uses the same entry
/// shape as the remote listing so the renderer can share its table renderer.
#[tauri::command]
pub fn sftp_local_list(path: String) -> CmdResult<serde_json::Value> {
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
        let Ok(md) = e.metadata() else { continue };
        let modified_ms = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64);
        entries.push(SftpEntry {
            name: e.file_name().to_string_lossy().to_string(),
            is_dir: md.is_dir(),
            size: if md.is_dir() { 0 } else { md.len() },
            modified_ms,
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
        .map_err(|e| format!("{path}: {e}"))
}

/// Remote-walk helper applying chmod to a directory tree.
fn chmod_tree(
    sftp: Arc<russh_sftp::client::SftpSession>,
    dir: String,
    mode: u32,
    apply_files: bool,
    apply_dirs: bool,
) -> Pin<Box<dyn Future<Output = Result<u32, String>> + Send>> {
    Box::pin(async move {
        let mut changed = 0u32;
        let mut entries = match sftp.read_dir(&dir).await {
            Ok(e) => e,
            Err(e) => return Err(format!("{dir}: {e}")),
        };
        while let Some(entry) = entries.next() {
            let name = entry.file_name().to_string();
            let child = format!("{}/{}", dir.trim_end_matches('/'), name);
            let is_dir = entry.metadata().is_dir();
            if (is_dir && apply_dirs) || (!is_dir && apply_files) {
                chmod_one(&sftp, &child, mode).await?;
                changed += 1;
            }
            if is_dir {
                changed += chmod_tree(sftp.clone(), child, mode, apply_files, apply_dirs).await?;
            }
        }
        Ok(changed)
    })
}

/// Change permission bits on a remote file/directory, optionally recursively.
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
    let md = sftp
        .metadata(&path)
        .await
        .map_err(|e| CmdError(format!("stat failed: {e}")))?;

    let mut changed = 0u32;
    if md.is_dir() && recursive {
        // Apply to the root path itself according to the dirs rule, then walk.
        if apply_dirs {
            chmod_one(&sftp, &path, mode).await.map_err(CmdError)?;
            changed += 1;
        }
        changed += chmod_tree(sftp.clone(), path.clone(), mode, apply_files, apply_dirs)
            .await
            .map_err(CmdError)?;
    } else {
        chmod_one(&sftp, &path, mode).await.map_err(CmdError)?;
        changed += 1;
    }
    Ok(serde_json::json!({ "ok": true, "changed": changed }))
}

// ─── new empty file ────────────────────────────────────────────────────────

/// Create an empty remote file (fails if it already exists is NOT enforced —
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

// ─── keep-alive ────────────────────────────────────────────────────────────

/// Start a 30 s keep-alive loop for the session's SFTP channel: a cheap
/// canonicalize round-trip keeps NAT/firewall state alive. The loop exits
/// silently once the SFTP session leaves the registry.
#[tauri::command]
pub async fn sftp_keepalive_start(
    app: AppHandle,
    session_id: String,
) -> CmdResult<serde_json::Value> {
    // Registry already holds a live session — verify it exists.
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
        // Windows-invalid characters become underscores — the file lands
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
        // The hostile names the walk can meet in a ReadDir — at the root or
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
}
