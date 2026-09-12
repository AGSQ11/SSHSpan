//! Background transfer queue for SFTP uploads/downloads.
//!
//! FileZilla's model: one session browses, others transfer. Each queued job
//! asks the SSH session actor for a fresh SFTP channel (via the existing
//! `sftp_tx` oneshot), so browsing stays responsive during transfers.
//! Progress is streamed to the renderer as `sftp-queue` Tauri events.

use std::io::SeekFrom;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use russh_sftp::protocol::OpenFlags;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::ssh_client::SessionRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JobKind {
    Upload,
    Download,
    /// Server-to-server copy ("Send to"): fresh-channel download from the
    /// source session into a local temp staging file, then fresh-channel
    /// upload to the target session. Never touches the interactive
    /// SftpRegistry sessions.
    ServerCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JobState {
    Queued,
    Active,
    Done,
    Failed,
    Cancelled,
}

/// How a queued transfer treats an existing destination (or a leftover
/// `.part` from an interrupted earlier attempt):
/// - `Overwrite` — truncate and start from byte 0 (the pre-resume behavior).
/// - `Resume` — continue a partial destination when its size aligns with
///   the source (a larger or size-unknown partial falls back to Overwrite).
/// - `Ask` — the UI layer resolves this to a concrete choice before
///   enqueueing; if it still reaches the backend it behaves as Overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ResumeMode {
    Overwrite,
    Resume,
    Ask,
}

impl ResumeMode {
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "resume" => ResumeMode::Resume,
            "ask" => ResumeMode::Ask,
            _ => ResumeMode::Overwrite,
        }
    }
}

/// Staging suffix for in-flight transfers. Transfers write `<dest>.part` and
/// rename to `<dest>` only after a full flush, so a crash/cancel leaves a
/// resumable partial instead of a corrupt "complete" file.
pub const PART_SUFFIX: &str = ".part";

/// Derive the `.part` staging path for a destination. The staging file stays
/// in the destination's own directory so the final rename is a same-directory
/// (atomic on POSIX, MoveFileEx-like on Windows) operation, never a
/// cross-volume move.
pub fn part_path(dest: &str) -> String {
    format!("{dest}{PART_SUFFIX}")
}

/// Best-effort ensure the parent directory of `remote_path` exists on the
/// target SFTP server, creating each missing level. Errors are logged and
/// swallowed — the subsequent open will surface a real failure if the dir is
/// genuinely not creatable. Used so a folder Send-to can place nested files
/// under directories that don't exist yet on the target.
async fn ensure_remote_dir(sftp: &russh_sftp::client::SftpSession, remote_path: &str) {
    let Some(parent) = remote_path.rsplit_once('/').map(|(p, _)| p) else {
        return;
    };
    let parent = if parent.is_empty() { "/" } else { parent };
    if parent == "/" {
        return;
    }
    // Walk down from the root, creating each missing component.
    let mut cur = String::new();
    for seg in parent.split('/').filter(|s| !s.is_empty()) {
        cur.push('/');
        cur.push_str(seg);
        match sftp.metadata(&cur).await {
            Ok(md) if md.is_dir() => continue,
            Ok(_) => {
                log::warn!("[sshspan-sftp] ensure_remote_dir: {cur} exists but is not a directory");
                return;
            }
            Err(_) => {
                if let Err(e) = sftp.create_dir(&cur).await {
                    // A concurrent job may have created it first; only log.
                    log::debug!("[sshspan-sftp] ensure_remote_dir mkdir {cur}: {e}");
                }
            }
        }
    }
}

/// Alignment check shared by both directions: a `.part` is resumable only
/// when its length is a strict prefix of a known total. A partial that
/// equals or exceeds the total is stale garbage from a different source; an
/// unknown total (the u64::MAX sentinel) cannot be verified at all.
/// Returns `Err(reason)` when the caller must fall back to Overwrite (the
/// reason is logged), `Ok(offset)` with 0 = start fresh.
fn part_alignment(part_len: u64, total: u64) -> Result<u64, String> {
    if part_len == 0 {
        return Ok(0);
    }
    if total == u64::MAX {
        return Err(
            "source size unknown; cannot verify .part alignment — starting over".into(),
        );
    }
    if part_len >= total {
        return Err(format!(
            ".part ({part_len} B) is not smaller than the source ({total} B) — starting over"
        ));
    }
    Ok(part_len)
}

/// Resume offset for a LOCAL `.part` (download direction): its length must
/// be a strict prefix of the known remote total. A missing `.part` yields
/// Ok(0) (fresh start); an existing-but-untrustworthy one yields Err.
async fn local_part_offset(lpart: &str, total: u64) -> Result<u64, String> {
    match tokio::fs::metadata(lpart).await {
        Ok(md) if md.is_file() => part_alignment(md.len(), total),
        Ok(_) => Err(format!("{lpart} exists but is not a file — starting over")),
        Err(_) => Ok(0),
    }
}

/// Resume offset for a REMOTE `.part` (upload direction, incl. the
/// server-copy target leg). A missing `.part` (or an unreadable one — the
/// create-truncate below overwrites it anyway) yields Ok(0).
async fn remote_part_offset(
    sftp: &russh_sftp::client::SftpSession,
    rpart: &str,
    total: u64,
) -> Result<u64, String> {
    let md = match sftp.metadata(rpart).await {
        Ok(md) => md,
        Err(_) => return Ok(0),
    };
    if md.is_dir() {
        return Err(format!("{rpart} exists but is a directory — starting over"));
    }
    match md.size {
        Some(len) => part_alignment(len, total),
        None => Err(format!("size of {rpart} unknown — starting over")),
    }
}

/// Read and drop exactly `n` bytes from `reader` (256 KiB chunks, the same
/// buffer size as `copy_with_progress`). russh-sftp's `File` exposes no
/// offset-taking read, so skipping a prefix on the remote side means
/// issuing reads and discarding the data locally. Returns the number of
/// bytes discarded.
async fn discard_exact<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    n: u64,
) -> Result<u64, String> {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 256 * 1024];
    let mut done: u64 = 0;
    while done < n {
        let want = ((n - done) as usize).min(buf.len());
        let read = reader
            .read(&mut buf[..want])
            .await
            .map_err(|e| e.to_string())?;
        if read == 0 {
            return Err(format!("unexpected EOF at {done} of {n} skipped bytes"));
        }
        done += read as u64;
    }
    Ok(done)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferJob {
    pub id: u64,
    pub kind: JobKind,
    pub session_id: String,
    pub server_name: String,
    pub local_path: String,
    pub remote_path: String,
    pub size: u64,
    pub bytes_done: u64,
    pub state: JobState,
    pub error: Option<String>,
    /// Cancel flag shared with the active worker.
    #[serde(skip)]
    pub cancel: Option<Arc<AtomicBool>>,
    pub started_at: Option<std::time::SystemTime>,
    /// ServerCopy only: target session (job's `session_id` is the SOURCE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_session_id: Option<String>,
    /// ServerCopy only: target server name (display in the queue panel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_server_name: Option<String>,
    /// ServerCopy only: absolute remote destination path on the target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_remote_path: Option<String>,
    /// How to treat an existing destination / leftover `.part` (None =
    /// Overwrite, the pre-resume behavior).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume: Option<ResumeMode>,
    /// Preserve timestamps (FileZilla "Preserve timestamps of transferred
    /// files"): after a successful upload / server-copy target leg, push the
    /// source mtime onto the remote destination via setstat. Additive Option
    /// so construction sites that don't care keep compiling (default false).
    #[serde(skip)]
    pub preserve_ts: Option<bool>,
}

impl TransferJob {
    fn snapshot(&self, speed: Option<f64>) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "kind": self.kind,
            "sessionId": self.session_id,
            "serverName": self.server_name,
            "localPath": self.local_path,
            "remotePath": self.remote_path,
            "size": self.size,
            "bytesDone": self.bytes_done,
            "state": self.state,
            "error": self.error,
            "speed": speed,
            "targetSessionId": self.target_session_id,
            "targetServerName": self.target_server_name,
            "targetRemotePath": self.target_remote_path,
            "resume": self.resume,
        })
    }
}

/// Global queue state (Tauri-managed).
#[derive(Default)]
pub struct TransferQueue {
    jobs: Mutex<Vec<TransferJob>>,
    next_id: AtomicU64,
    /// Generation counter — dispatcher restart when jobs are added.
    generation: AtomicU64,
}

impl TransferQueue {
    pub fn new() -> Self {
        Self::default()
    }

    fn snapshot(&self) -> Vec<serde_json::Value> {
        self.jobs
            .lock()
            .unwrap()
            .iter()
            .map(|j| j.snapshot(None))
            .collect()
    }
}

/// Emit the full queue state to the renderer.
pub fn emit_queue<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let q = app.state::<TransferQueue>();
    let jobs = q.snapshot();
    let _ = app.emit("sftp-queue", serde_json::json!({ "jobs": jobs }));
}

/// Fetch the live SFTP channel-count setting (1..=4, default 4).
/// Many small files in a folder copy are per-file round-trip bound, so a
/// higher default parallelism matters more than a larger chunk size there.
fn parallel_limit<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> usize {
    app.state::<crate::AppState>()
        .db
        .get_config("setting.sftpParallel")
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|n| n.clamp(1, 4))
        .unwrap_or(4)
}

/// One fully-expanded transfer to enqueue.
pub struct QueuedItem {
    pub kind: JobKind,
    pub session_id: String,
    pub server_name: String,
    pub local_path: String,
    pub remote_path: String,
    pub size: u64,
    /// ServerCopy only: target session id, server name, and absolute remote
    /// destination path on the target server.
    pub target: Option<ServerCopyTarget>,
    /// How to treat an existing destination / leftover `.part` (None =
    /// Overwrite; kept optional so existing callers compile unchanged).
    pub resume: Option<ResumeMode>,
    /// Preserve timestamps on upload/server-copy target legs (default false).
    pub preserve_ts: Option<bool>,
}

/// Destination half of a server-to-server copy job.
pub struct ServerCopyTarget {
    pub session_id: String,
    pub server_name: String,
    pub remote_path: String,
}

impl QueuedItem {
    /// Plain upload/download item (no copy target).
    pub fn simple(
        kind: JobKind,
        session_id: String,
        server_name: String,
        local_path: String,
        remote_path: String,
        size: u64,
    ) -> Self {
        Self {
            kind,
            session_id,
            server_name,
            local_path,
            remote_path,
            size,
            target: None,
            resume: None,
            preserve_ts: None,
        }
    }
}

/// Add jobs and kick the dispatcher. `items` are fully-expanded file pairs
/// (directories were expanded by the caller).
pub fn enqueue<R: tauri::Runtime>(app: &tauri::AppHandle<R>, items: Vec<QueuedItem>) {
    let q = app.state::<TransferQueue>();
    {
        let mut guard = q.jobs.lock().unwrap();
        for item in items {
            let id = q.next_id.fetch_add(1, Ordering::SeqCst);
            guard.push(TransferJob {
                id,
                kind: item.kind,
                session_id: item.session_id,
                server_name: item.server_name,
                local_path: item.local_path,
                remote_path: item.remote_path,
                size: item.size,
                bytes_done: 0,
                state: JobState::Queued,
                error: None,
                cancel: None,
                started_at: None,
                target_session_id: item.target.as_ref().map(|t| t.session_id.clone()),
                target_server_name: item.target.as_ref().map(|t| t.server_name.clone()),
                target_remote_path: item.target.as_ref().map(|t| t.remote_path.clone()),
                resume: item.resume,
                preserve_ts: item.preserve_ts,
            });
        }
    }
    q.generation.fetch_add(1, Ordering::SeqCst);
    drop(q);
    emit_queue(app);
    dispatch(app);
}

/// Spawn workers for queued jobs while fewer than the limit are active.
/// Cheap to call repeatedly: each call checks state under the lock and only
/// spawns when there is work and capacity.
pub fn dispatch<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let q = app.state::<TransferQueue>();
    let limit = parallel_limit(app);

    let to_start: Vec<(
        u64,
        String,
        JobKind,
        String,
        String,
        u64,
        Option<ServerCopyTarget>,
        Option<ResumeMode>,
        bool,
    )> = {
        let mut guard = q.jobs.lock().unwrap();
        let active = guard.iter().filter(|j| j.state == JobState::Active).count();
        let mut capacity = limit.saturating_sub(active);
        let mut started = Vec::new();
        if capacity == 0 {
            return;
        }
        for j in guard.iter_mut() {
            if capacity == 0 {
                break;
            }
            if j.state == JobState::Queued {
                j.state = JobState::Active;
                j.cancel = Some(Arc::new(AtomicBool::new(false)));
                j.started_at = Some(std::time::SystemTime::now());
                let target = match (
                    j.target_session_id.clone(),
                    j.target_server_name.clone(),
                    j.target_remote_path.clone(),
                ) {
                    (Some(sid), Some(name), Some(path)) => Some(ServerCopyTarget {
                        session_id: sid,
                        server_name: name,
                        remote_path: path,
                    }),
                    _ => None,
                };
                started.push((
                    j.id,
                    j.session_id.clone(),
                    j.kind,
                    j.local_path.clone(),
                    j.remote_path.clone(),
                    j.size,
                    target,
                    j.resume,
                    j.preserve_ts.unwrap_or(false),
                ));
                capacity -= 1;
            }
        }
        started
    };

    if to_start.is_empty() {
        return;
    }
    let gen = q.generation.load(Ordering::SeqCst);
    drop(q);

    for (id, session_id, kind, local, remote, size, target, resume, preserve_ts) in to_start {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            run_job(app, gen, id, session_id, kind, local, remote, size, target, resume, preserve_ts)
                .await;
        });
    }
}

/// Ask the SSH session actor for a fresh SFTP channel (browse session stays
/// untouched — each transfer gets its own channel over the same connection).
pub(crate) async fn open_transfer_channel<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    session_id: &str,
) -> Result<russh_sftp::client::SftpSession, String> {
    let tx = app
        .state::<std::sync::Arc<SessionRegistry>>()
        .get_sftp_tx(session_id)
        .ok_or_else(|| "Session closed.".to_string())?;
    let (reply, rx) = tokio::sync::oneshot::channel();
    tx.send(reply)
        .map_err(|_| "Session is closing.".to_string())?;
    rx.await
        .map_err(|_| "Session closed before channel opened.".to_string())?
        .map_err(|e| format!("channel open failed: {e}"))
}

/// Chunked copy with progress + cancellation. Returns bytes copied.
/// `max_read` clamps each read (downloads pass the remaining file size) so
/// the final read never crosses EOF — some SFTP servers answer such reads
/// with SSH_FX_FAILURE instead of a short read, which would fail the whole
/// transfer on the last chunk. When the remote size is unknown, callers pass
/// `Some(u64::MAX)`: an effectively unclamped stream that still survives the
/// "unknown size treated as 0 → silent empty file" failure mode.
/// `progress_offset` is added to the copied count when reporting job
/// progress, so a multi-leg transfer can show its overall position (0 for
/// plain uploads/downloads).
async fn copy_with_progress<RT, R, W>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    reader: &mut R,
    writer: &mut W,
    cancel: Arc<AtomicBool>,
    max_read: Option<u64>,
    progress_offset: u64,
) -> Result<u64, String>
where
    RT: tauri::Runtime,
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Unwrap russh-sftp read failures the same way download_to does, so a bare
    // server SSH_FX_FAILURE surfaces as a truthful single-layer message in the
    // queue row instead of the doubled "Failure: Failure". The helper prefixes
    // "download failed: ", which reads oddly on upload/write legs, so strip it.
    // Include the byte position so a failure reports the offset/len that the
    // server rejected (a read crossing EOF fails on some sftp bridges).
    let read_err = |e: std::io::Error, off: u64, len: usize| {
        let inner = crate::commands::sftp::describe_download_read_error(e)
            .to_string()
            .trim_start_matches("download failed: ")
            .to_string();
        format!("{inner} (at offset {off}, len {len})")
    };
    let mut buf = vec![0u8; 256 * 1024];
    let mut done: u64 = 0;
    let mut last_emit = std::time::Instant::now();
    let mut last_bytes: u64 = 0;
    let mut speed: f64 = 0.0;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        if let Some(max) = max_read {
            if done >= max {
                break;
            }
        }
        let want = match max_read {
            Some(max) => ((max - done) as usize).min(buf.len()),
            None => buf.len(),
        };
        let off = progress_offset + done;
        let n = reader
            .read(&mut buf[..want])
            .await
            .map_err(|e| read_err(e, off, want))?;
        if n == 0 {
            break;
        }
        writer
            .write_all(&buf[..n])
            .await
            .map_err(|e| e.to_string())?;
        done += n as u64;

        let now = std::time::Instant::now();
        if last_emit.elapsed().as_millis() >= 200 {
            let dt = now.duration_since(last_emit).as_secs_f64();
            if dt > 0.0 {
                speed = (done - last_bytes) as f64 / dt;
            }
            update_progress(app, job_id, progress_offset + done, Some(speed));
            last_emit = now;
            last_bytes = done;
        }
    }
    writer.flush().await.map_err(|e| e.to_string())?;
    // russh-sftp 2.4.0 File: poll_shutdown drains pending write ACKs and
    // sends the SFTP CLOSE, setting `closed = true`. File::close() calls
    // shutdown() again, which is a no-op on an already-closed file (the
    // future state was cleared), so caller-side `rf.close()` after this is
    // a cheap no-op, not a double CLOSE.
    writer.shutdown().await.map_err(|e| e.to_string())?;
    Ok(done)
}

fn update_progress<RT: tauri::Runtime>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    bytes_done: u64,
    speed: Option<f64>,
) {
    let q = app.state::<TransferQueue>();
    let job_json = {
        let mut guard = q.jobs.lock().unwrap();
        match guard.iter_mut().find(|j| j.id == job_id) {
            Some(j) => {
                j.bytes_done = bytes_done;
                Some(j.snapshot(speed))
            }
            None => None,
        }
    };
    if let Some(job) = job_json {
        let _ = app.emit("sftp-queue", serde_json::json!({ "jobs": [job] }));
    }
}

/// Set a job's terminal state and emit it.
fn finish_job<RT: tauri::Runtime>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    state: JobState,
    error: Option<String>,
) {
    let q = app.state::<TransferQueue>();
    let job_json = {
        let mut guard = q.jobs.lock().unwrap();
        match guard.iter_mut().find(|j| j.id == job_id) {
            Some(j) => {
                j.state = state;
                j.error = error;
                if state == JobState::Done {
                    j.bytes_done = j.size;
                }
                Some(j.snapshot(None))
            }
            None => None,
        }
    };
    if let Some(job) = job_json {
        let _ = app.emit("sftp-queue", serde_json::json!({ "jobs": [job] }));
    }
    drop(q);
    // Something finished — try to start the next queued job.
    dispatch(app);
}

/// Deletes a staged temp file when dropped (best-effort). Guarantees the
/// staging file never outlives the job: success, failure, cancel, and
/// worker panic all drop the guard, so the file is removed on every exit
/// path (FileZilla removes the temp file once the transfer is cleared).
struct StageGuard(std::path::PathBuf);

/// Core setstat: push `secs` as mtime (and atime) onto a remote path.
/// Tolerant — some servers refuse SETSTAT, which must never fail a
/// completed transfer.
async fn set_remote_mtime(sftp: &russh_sftp::client::SftpSession, dest_remote: &str, secs: u32) {
    let mut attrs = russh_sftp::protocol::FileAttributes::default();
    attrs.mtime = Some(secs);
    attrs.atime = Some(secs);
    match sftp.set_metadata(dest_remote, attrs).await {
        Ok(()) => log::info!("[sshspan-sftp] preserved mtime {secs} on {dest_remote}"),
        Err(e) => log::warn!(
            "[sshspan-sftp] setstat mtime on {dest_remote} refused ({e}) — \
             some servers disallow SETSTAT; timestamps not preserved"
        ),
    }
}

/// Preserve-timestamps helper (FileZilla "Preserve timestamps of transferred
/// files"): after the data has landed on the remote end, stat the LOCAL
/// source file's mtime and push it onto the remote destination via setstat.
async fn apply_preserved_mtime(
    sftp: &russh_sftp::client::SftpSession,
    source_local: &std::path::Path,
    dest_remote: &str,
) {
    let mtime = tokio::fs::metadata(source_local)
        .await
        .and_then(|md| md.modified())
        .and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        });
    match mtime {
        Ok(secs) => set_remote_mtime(sftp, dest_remote, secs).await,
        Err(e) => log::warn!(
            "[sshspan-sftp] could not read source mtime {}: {e} — timestamps not preserved",
            source_local.display()
        ),
    }
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.0) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!(
                    "[sshspan-sftp] could not remove staged copy {}: {e}",
                    self.0.display()
                );
            }
        }
    }
}

/// Diagnostic/fallback helper: perform the same size-clamped read of
/// `source_remote` into the local staging file, but over an EXISTING SFTP
/// session (the interactive browse channel) instead of a fresh channel.
/// Used by `run_server_copy` to distinguish "fresh channel read is refused"
/// from "the read pattern itself fails on this server".
async fn read_via_session<RT: tauri::Runtime>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    sftp: &russh_sftp::client::SftpSession,
    source_remote: &str,
    stage: &std::path::Path,
    size: u64,
    cancel: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut rf = sftp.open(source_remote).await.map_err(|e| {
        crate::commands::sftp::sftp_error_detail(e)
    })?;
    // Truncate the staging file (the failed fresh-channel attempt may have
    // left a partial write) before re-reading into it.
    let mut lf = tokio::fs::File::create(stage)
        .await
        .map_err(|e| format!("local recreate failed: {e}"))?;
    copy_with_progress(app, job_id, &mut rf, &mut lf, cancel, Some(size), 0).await?;
    lf.flush()
        .await
        .map_err(|e| format!("local flush failed: {e}"))?;
    drop(lf);
    if let Err(e) = rf.close().await {
        log::warn!("[sshspan-sftp] interactive close after copy of {source_remote}: {e}");
    }
    Ok(())
}

/// Run one server-to-server copy: fresh-channel download from the source
/// session into a temp staging file, then fresh-channel upload to the target
/// session. Never touches the interactive SftpRegistry sessions — both legs
/// get their own channel over the respective SSH connections, exactly like
/// plain queue downloads/uploads (that is what makes this path work on
/// servers whose interactive channel fails reads with SSH_FX_FAILURE).
/// The target leg stages into `<target>.part` and renames on success.
async fn run_server_copy<RT: tauri::Runtime>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    source_session: &str,
    source_remote: &str,
    target: &ServerCopyTarget,
    cancel: Arc<AtomicBool>,
    resume: Option<ResumeMode>,
    preserve_ts: bool,
) -> Result<(), String> {
    let file_name = source_remote.rsplit('/').next().unwrap_or("file");
    // Staged copy lives in the same 0700 temp dir + unpredictable-name
    // convention as edit/"Send to" staging (see sftp::staged_file_name).
    let stage = crate::sftp::edit_temp_dir().join(format!(
        "sendto-{}",
        crate::sftp::staged_file_name(file_name)
    ));
    // Drop guard: removed on success, failure, cancel, and panic alike.
    let _guard = StageGuard(stage.clone());

    // Stat first (same order as download_to): the size clamp below relies on
    // it, and a readable error here beats a failed first read.
    let sftp = open_transfer_channel(app, source_session).await.map_err(|e| {
        log::error!("[sshspan-sftp] sendto leg1 channel open: {e}");
        format!("source channel: {e}")
    })?;
    let size = sftp
        .metadata(source_remote)
        .await
        .map_err(|e| {
            let d = crate::commands::sftp::sftp_error_detail(e);
            log::error!("[sshspan-sftp] sendto leg1 stat {source_remote}: {d}");
            format!("source stat: {d}")
        })?
        .size;
    // Unknown remote size must never mean "0-byte file": clamp to an
    // effectively unbounded stream so the copy reads until a real short read
    // (the EOF signal on well-behaved servers).
    let size = size.unwrap_or(u64::MAX);
    let mut rf = sftp.open(source_remote).await.map_err(|e| {
        let d = crate::commands::sftp::sftp_error_detail(e);
        log::error!("[sshspan-sftp] sendto leg1 open {source_remote}: {d}");
        format!("source open: {d}")
    })?;
    let mut lf = tokio::fs::File::create(&stage)
        .await
        .map_err(|e| format!("local create failed: {e}"))?;
    // Size-clamped reads (EOF-crossing read defense), progress = first half.
    let fresh_result =
        copy_with_progress(app, job_id, &mut rf, &mut lf, cancel.clone(), Some(size), 0).await;
    if let Err(fresh_err) = fresh_result {
        // DIAGNOSTIC + FALLBACK: the fresh transfer channel failed the read.
        // Retry the identical clamped read on the interactive browse session —
        // but only after releasing every resource from the failed attempt, so
        // the retry is an independent test of the channel, not a side effect
        // of a half-open handle or a locked staging file.
        log::error!(
            "[sshspan-sftp] sendto leg1 fresh-channel read failed ({fresh_err}); \
             cleaning up before interactive-channel retry"
        );
        // 1. Flush + drop the local staging file so the retry can recreate it
        //    (Windows refuses a second create on a file still open).
        let _ = lf.flush().await;
        drop(lf);
        // 2. Close the failed fresh remote read handle.
        if let Err(e) = rf.close().await {
            log::warn!(
                "[sshspan-sftp] close of failed fresh handle for {source_remote}: {e}"
            );
        }
        // 3. Drop the fresh channel's SFTP session entirely.
        drop(sftp);

        let interactive = app
            .state::<crate::sftp::SftpRegistry>()
            .get(source_session);
        match interactive {
            Some(isftp) => {
                match read_via_session(app, job_id, &isftp, source_remote, &stage, size, cancel.clone()).await {
                    Ok(()) => {
                        log::warn!(
                            "[sshspan-sftp] sendto leg1 succeeded via INTERACTIVE browse session \
                             (fresh channel is read-blocked on this server)"
                        );
                        // Fall through to leg 2 with the staged file in place.
                    }
                    Err(ie) => {
                        return Err(format!(
                            "source read: fresh channel failed ({fresh_err}); \
                             interactive browse channel also failed ({ie}) (stat size {size})"
                        ));
                    }
                }
            }
            None => {
                return Err(format!(
                    "source read: {fresh_err} (stat size {size}); no interactive browse session to retry on"
                ));
            }
        }
    } else {
        lf.flush()
            .await
            .map_err(|e| format!("local flush failed: {e}"))?;
        drop(lf);
        // Tolerant close, same as download_to: a FAILURE reply to CLOSE after a
        // fully-copied read handle means the data already landed.
        if let Err(e) = rf.close().await {
            log::warn!(
                "[sshspan-sftp] close after copy of {source_remote}: {e}"
            );
        }
        drop(sftp);
    }

    // ── leg 2: upload to the TARGET via a second fresh channel ───────────
    let target_sftp = open_transfer_channel(app, &target.session_id)
        .await
        .map_err(|e| {
            log::error!("[sshspan-sftp] sendto leg2 channel open: {e}");
            format!("target channel: {e}")
        })?;
    let mut lf = tokio::fs::File::open(&stage)
        .await
        .map_err(|e| format!("local open failed: {e}"))?;
    // Stage into `<target>.part`; only a fully uploaded file is renamed to
    // the final name, so an interrupted copy leaves a resumable partial
    // rather than a truncated "complete" file on the target.
    let tpart = part_path(&target.remote_path);
    // Resume only the TARGET leg (the local staging file above is always
    // rebuilt from scratch by leg 1 — it is removed on every exit path).
    let offset = match resume {
        Some(ResumeMode::Resume) => {
            let aligned = remote_part_offset(&target_sftp, &tpart, size).await;
            match aligned {
                Ok(off) => off,
                Err(note) => {
                    log::info!("[sshspan-sftp] sendto leg2: {note}");
                    0
                }
            }
        }
        _ => 0,
    };
    if offset == 0 {
        if let Err(e) = target_sftp.remove_file(&tpart).await {
            log::debug!("[sshspan-sftp] sendto leg2 pre-clean of {tpart}: {e}");
        }
    } else {
        lf.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| format!("local seek to resume offset failed: {e}"))?;
    }
    // Ensure the destination's parent directory exists on the target. A folder
    // Send-to expands into nested per-file jobs, and the target SFTP server does
    // not create missing parents on open — without this the copy of a nested
    // file fails at open with "No such file".
    ensure_remote_dir(&target_sftp, &target.remote_path).await;
    let mut rf = target_sftp.open_with_flags(
        &tpart,
        if offset > 0 {
            OpenFlags::WRITE | OpenFlags::APPEND
        } else {
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE
        },
    )
    .await
    .map_err(|e| {
        let d = crate::commands::sftp::sftp_error_detail(e);
        log::error!("[sshspan-sftp] sendto leg2 open {}: {d}", tpart);
        format!("target open: {d}")
    })?;
    // Progress = second half of the overall copy, reported absolutely
    // (leg 1 already covered 0..size; a resumed leg 2 starts at
    // size + already-uploaded prefix).
    copy_with_progress(
        app,
        job_id,
        &mut lf,
        &mut rf,
        cancel.clone(),
        Some(size.saturating_sub(offset)),
        size + offset,
    )
    .await
    .map_err(|e| {
        log::error!("[sshspan-sftp] sendto leg2 write {} (size {size}): {e}", tpart);
        format!("target write: {e}")
    })?;
    // Tolerant close: a FAILURE reply to CLOSE after a fully-written .part
    // (e.g. a server that reports "No such file" for the handle) does not mean
    // the data is missing — leg-1 read-close and download_to already treat this
    // as benign. Verify the .part actually landed (size matches what we wrote)
    // before trusting it for the rename, so we never rename an empty file.
    if let Err(e) = rf.close().await {
        let expected = size;
        match target_sftp.metadata(&tpart).await {
            Ok(md) if expected == u64::MAX || md.size == Some(expected) => {
                log::warn!(
                    "[sshspan-sftp] sendto leg2 close of {tpart} failed ({e}) but size matches; proceeding"
                );
            }
            Ok(md) => {
                return Err(format!(
                    "target close failed ({e}) and staged size {:?} != expected {expected}",
                    md.size
                ));
            }
            Err(se) => {
                return Err(format!("target close failed ({e}); staged stat also failed: {se}"));
            }
        }
    }
    // Some servers refuse rename-over-an-existing-file; the .part is fully
    // uploaded at this point, so removing the final name first is a safe retry.
    if let Err(e) = target_sftp.rename(&tpart, &target.remote_path).await {
        let d = crate::commands::sftp::sftp_error_detail(e);
        if target_sftp.remove_file(&target.remote_path).await.is_ok()
            && target_sftp.rename(&tpart, &target.remote_path).await.is_ok()
        {
            return Ok(());
        }
        log::error!("[sshspan-sftp] sendto leg2 rename {tpart} -> {}: {d}", target.remote_path);
        return Err(format!("final rename failed: {d}"));
    }
    // Preserve timestamps (after the rename finalizes the destination): stat
    // the STAGED file (its data equals the remote source) and push its mtime
    // onto the target. Best-effort setstat.
    if preserve_ts {
        apply_preserved_mtime(&target_sftp, &stage, &target.remote_path).await;
    }
    Ok(())
}

async fn run_job<RT: tauri::Runtime + 'static>(
    app: tauri::AppHandle<RT>,
    _gen: u64,
    job_id: u64,
    session_id: String,
    kind: JobKind,
    local: String,
    remote: String,
    size: u64,
    target: Option<ServerCopyTarget>,
    resume: Option<ResumeMode>,
    preserve_ts: bool,
) {
    let cancel = {
        let q = app.state::<TransferQueue>();
        let guard = q.jobs.lock().unwrap();
        guard
            .iter()
            .find(|j| j.id == job_id)
            .and_then(|j| j.cancel.clone())
    };
    let Some(cancel) = cancel else {
        finish_job(&app, job_id, JobState::Failed, Some("job vanished".into()));
        return;
    };

    let result: Result<(), String> = match (kind, target) {
        (JobKind::ServerCopy, Some(target)) => {
            run_server_copy(&app, job_id, &session_id, &remote, &target, cancel, resume, preserve_ts)
                .await
        }
        (JobKind::ServerCopy, None) => Err("server copy job is missing its target".into()),
        (kind, _) => {
            async {
                let sftp = open_transfer_channel(&app, &session_id).await?;
                match kind {
                    JobKind::Upload => {
                        let mut lf = tokio::fs::File::open(&local)
                            .await
                            .map_err(|e| format!("local open failed: {e}"))?;
                        let lsize = lf
                            .metadata()
                            .await
                            .map_err(|e| format!("local stat failed: {e}"))?
                            .len();
                        // Stage into `<remote>.part`; the rename to the final
                        // name happens only after a complete upload, so an
                        // interrupted upload leaves a resumable partial (never
                        // a truncated file that looks complete).
                        let rpart = part_path(&remote);
                        let offset = match resume {
                            Some(ResumeMode::Resume) => {
                                match remote_part_offset(&sftp, &rpart, lsize).await {
                                    Ok(off) => off,
                                    Err(note) => {
                                        log::info!("[sshspan-sftp] upload {remote}: {note}");
                                        0
                                    }
                                }
                            }
                            _ => 0,
                        };
                        if offset == 0 {
                            if let Err(e) = sftp.remove_file(&rpart).await {
                                log::debug!("[sshspan-sftp] upload pre-clean of {rpart}: {e}");
                            }
                        } else {
                            lf.seek(SeekFrom::Start(offset))
                                .await
                                .map_err(|e| format!("local seek to resume offset failed: {e}"))?;
                        }
                        let mut rf = sftp
                            .open_with_flags(
                                &rpart,
                                if offset > 0 {
                                    OpenFlags::WRITE | OpenFlags::APPEND
                                } else {
                                    OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE
                                },
                            )
                            .await
                            .map_err(|e| {
                                format!(
                                    "remote open failed: {}",
                                    crate::commands::sftp::sftp_error_detail(e)
                                )
                            })?;
                        // Report progress absolutely: offset = already-uploaded
                        // prefix that this attempt skips.
                        copy_with_progress(
                            &app,
                            job_id,
                            &mut lf,
                            &mut rf,
                            cancel.clone(),
                            Some(lsize.saturating_sub(offset)),
                            offset,
                        )
                        .await?;
                        // Tolerant close (same rationale as ServerCopy leg-2):
                        // a FAILURE on CLOSE after a fully-written .part does not
                        // mean the data is missing. Verify size before the rename.
                        if let Err(e) = rf.close().await {
                            match sftp.metadata(&rpart).await {
                                Ok(md) if md.size == Some(lsize) => {
                                    log::warn!(
                                        "[sshspan-sftp] upload close of {rpart} failed ({e}) but size matches; proceeding"
                                    );
                                }
                                Ok(md) => {
                                    return Err(format!(
                                        "close failed ({e}) and staged size {:?} != expected {lsize}",
                                        md.size
                                    ));
                                }
                                Err(se) => {
                                    return Err(format!("close failed ({e}); staged stat also failed: {se}"));
                                }
                            }
                        }
                        // Some servers refuse rename-over-an-existing file;
                        // the .part is complete here, so removing the final
                        // name first is a safe retry.
                        if let Err(e) = sftp.rename(&rpart, &remote).await {
                            let d = crate::commands::sftp::sftp_error_detail(e);
                            if sftp.remove_file(&remote).await.is_ok()
                                && sftp.rename(&rpart, &remote).await.is_ok()
                            {
                                return Ok(());
                            }
                            return Err(format!("final rename failed: {d}"));
                        }
                        // Preserve timestamps (after the rename finalizes the
                        // destination): stat the local source mtime and setstat
                        // it onto the remote destination. Best-effort.
                        if preserve_ts {
                            apply_preserved_mtime(&sftp, std::path::Path::new(&local), &remote)
                                .await;
                        }
                    }
                    JobKind::Download => {
                        // Stat first: the size clamp and resume-alignment
                        // check both rely on it.
                        let size = sftp
                            .metadata(&remote)
                            .await
                            .map_err(|e| {
                                format!(
                                    "remote stat failed: {}",
                                    crate::commands::sftp::sftp_error_detail(e)
                                )
                            })?
                            .size;
                        // Unknown remote size must never mean "0-byte file":
                        // clamp to an effectively unbounded stream so the copy
                        // reads until a real short read (the EOF signal on
                        // well-behaved servers). An unknown size also makes
                        // resume alignment unverifiable → start over.
                        let size = size.unwrap_or(u64::MAX);
                        let mut rf = sftp.open(&remote).await.map_err(|e| {
                            format!(
                                "remote open failed: {}",
                                crate::commands::sftp::sftp_error_detail(e)
                            )
                        })?;
                        // Stage into `<local>.part` (same directory as the
                        // final file, so the completion rename is atomic on
                        // the same filesystem, never a cross-volume move).
                        let lpart = part_path(&local);
                        let offset = match resume {
                            Some(ResumeMode::Resume) if size != u64::MAX => {
                                match local_part_offset(&lpart, size).await {
                                    Ok(off) => off,
                                    Err(note) => {
                                        log::info!("[sshspan-sftp] download {remote}: {note}");
                                        0
                                    }
                                }
                            }
                            _ => 0,
                        };
                        let mut lf = if offset > 0 {
                            if let Err(e) = discard_exact(&mut rf, offset).await {
                                return Err(format!("resume seek on remote failed: {e}"));
                            }
                            tokio::fs::OpenOptions::new()
                                .append(true)
                                .open(&lpart)
                                .await
                                .map_err(|e| format!("local open failed: {e}"))?
                        } else {
                            // Fresh start: replaces a leftover .part (the
                            // Overwrite mode's "delete/ignore the .part").
                            tokio::fs::File::create(&lpart)
                                .await
                                .map_err(|e| format!("local create failed: {e}"))?
                        };
                        copy_with_progress(
                            &app,
                            job_id,
                            &mut rf,
                            &mut lf,
                            cancel.clone(),
                            Some(size.saturating_sub(offset)),
                            offset,
                        )
                        .await?;
                        lf.flush()
                            .await
                            .map_err(|e| format!("local flush failed: {e}"))?;
                        lf.sync_all()
                            .await
                            .map_err(|e| format!("local fsync failed: {e}"))?;
                        drop(lf);
                        tokio::fs::rename(&lpart, &local)
                            .await
                            .map_err(|e| format!("final rename failed: {e}"))?;
                        // Preserve-timestamps on DOWNLOADS is NOT applied here:
                        // the remote mtime would have to be written onto the
                        // LOCAL file, and std has no portable mtime setter
                        // (Windows needs SetFileTime; adding a crate for it is
                        // out of scope). The renderer can apply it later via
                        // the sftp_set_mtime IPC command for non-queue flows;
                        // queue downloads keep the local file's fresh mtime.
                    }
                    JobKind::ServerCopy => unreachable!("handled above"),
                }
                Ok(())
            }
            .await
        }
    };

    match result {
        Ok(()) => finish_job(&app, job_id, JobState::Done, None),
        Err(e) if e == "cancelled" => finish_job(&app, job_id, JobState::Cancelled, None),
        Err(e) => finish_job(&app, job_id, JobState::Failed, Some(e)),
    }
    let _ = size;
}

/// Cancel one job (active jobs abort at their next chunk; queued flip state).
pub fn cancel_job<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, job_id: u64) {
    let q = app.state::<TransferQueue>();
    let mut guard = q.jobs.lock().unwrap();
    if let Some(j) = guard.iter_mut().find(|j| j.id == job_id) {
        if let Some(c) = &j.cancel {
            c.store(true, Ordering::SeqCst);
        }
        if j.state == JobState::Queued {
            j.state = JobState::Cancelled;
        }
    }
    drop(guard);
    drop(q);
    emit_queue(app);
}

/// Re-queue a failed/cancelled job.
pub fn retry_job<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, job_id: u64) {
    let q = app.state::<TransferQueue>();
    {
        let mut guard = q.jobs.lock().unwrap();
        if let Some(j) = guard.iter_mut().find(|j| j.id == job_id) {
            if matches!(j.state, JobState::Failed | JobState::Cancelled) {
                j.state = JobState::Queued;
                j.error = None;
                // bytes_done resets, but a leftover `.part` is deliberately
                // NOT deleted: with Resume mode the retried job continues
                // from it. Cleanup of stale `.part` files is the user's /
                // clear_finished's concern, not retry's.
                j.bytes_done = 0;
                j.cancel = None;
            }
        }
    }
    drop(q);
    emit_queue(app);
    dispatch(app);
}

/// Remove Done/Failed/Cancelled jobs from the list.
pub fn clear_finished<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>) {
    let q = app.state::<TransferQueue>();
    q.jobs.lock().unwrap().retain(|j| {
        !matches!(
            j.state,
            JobState::Done | JobState::Failed | JobState::Cancelled
        )
    });
    drop(q);
    emit_queue(app);
}

/// Cancel everything belonging to a session (disconnect/lock). A
/// ServerCopy job belongs to BOTH its source and target sessions.
pub fn cancel_for_session<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, session_id: &str) {
    let q = app.state::<TransferQueue>();
    {
        let mut guard = q.jobs.lock().unwrap();
        for j in guard.iter_mut() {
            let owns =
                j.session_id == session_id || j.target_session_id.as_deref() == Some(session_id);
            if owns && matches!(j.state, JobState::Queued | JobState::Active) {
                if let Some(c) = &j.cancel {
                    c.store(true, Ordering::SeqCst);
                }
                if j.state == JobState::Queued {
                    j.state = JobState::Cancelled;
                }
            }
        }
    }
    drop(q);
    emit_queue(app);
}

/// True when the session has active or queued jobs (as source OR as the
/// target of a server copy).
pub fn session_busy<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, session_id: &str) -> bool {
    app.state::<TransferQueue>()
        .jobs
        .lock()
        .unwrap()
        .iter()
        .any(|j| {
            (j.session_id == session_id || j.target_session_id.as_deref() == Some(session_id))
                && matches!(j.state, JobState::Queued | JobState::Active)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_path_appends_suffix_in_same_directory() {
        assert_eq!(part_path("/srv/x/file.bin"), "/srv/x/file.bin.part");
        assert_eq!(part_path(r"C:\Users\a\doc.txt"), r"C:\Users\a\doc.txt.part");
        // Idempotence guard: a .part path derives to .part.part on purpose
        // (each retry stages its own name); the assertion just pins the rule.
        assert_eq!(part_path("/tmp/a.part"), "/tmp/a.part.part");
    }

    #[test]
    fn alignment_allows_strict_prefix_only() {
        // Missing/empty partial → fresh start.
        assert_eq!(part_alignment(0, 500), Ok(0));
        // Strict prefix → resume at that offset.
        assert_eq!(part_alignment(300, 500), Ok(300));
        // Equal or larger partial → stale, must fall back to Overwrite.
        assert!(part_alignment(500, 500).is_err());
        assert!(part_alignment(700, 500).is_err());
        // Unknown total (the u64::MAX sentinel) is unverifiable → Overwrite.
        assert!(part_alignment(300, u64::MAX).is_err());
    }

    #[tokio::test]
    async fn discard_exact_skips_and_reports_eof() {
        let data = vec![7u8; 100 * 1024]; // > one 32 KiB buffer
        let mut r = std::io::Cursor::new(data.clone());
        // Discarding the whole stream is fine (n bytes, then the caller
        // copies 0 more).
        assert_eq!(discard_exact(&mut r, data.len() as u64).await.unwrap(), 100 * 1024);
        // Discarding past EOF fails with the position in the message.
        let mut r2 = std::io::Cursor::new(vec![1u8; 10]);
        let err = discard_exact(&mut r2, 11).await.unwrap_err();
        assert!(err.contains("EOF at 10 of 11"), "unexpected message: {err}");
    }
}
