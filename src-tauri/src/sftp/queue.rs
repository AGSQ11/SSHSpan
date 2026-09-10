//! Background transfer queue for SFTP uploads/downloads.
//!
//! FileZilla's model: one session browses, others transfer. Each queued job
//! asks the SSH session actor for a fresh SFTP channel (via the existing
//! `sftp_tx` oneshot), so browsing stays responsive during transfers.
//! Progress is streamed to the renderer as `sftp-queue` Tauri events.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{Emitter, Manager};
use tokio::io::AsyncWriteExt;

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

/// Fetch the live SFTP channel-count setting (1..=4, default 2).
fn parallel_limit<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> usize {
    app.state::<crate::AppState>()
        .db
        .get_config("setting.sftpParallel")
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|n| n.clamp(1, 4))
        .unwrap_or(2)
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

    for (id, session_id, kind, local, remote, size, target) in to_start {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            run_job(app, gen, id, session_id, kind, local, remote, size, target).await;
        });
    }
}

/// Ask the SSH session actor for a fresh SFTP channel (browse session stays
/// untouched — each transfer gets its own channel over the same connection).
async fn open_transfer_channel<R: tauri::Runtime>(
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
    let mut buf = vec![0u8; 32 * 1024];
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
async fn run_server_copy<RT: tauri::Runtime>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    source_session: &str,
    source_remote: &str,
    target: &ServerCopyTarget,
    cancel: Arc<AtomicBool>,
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
    let mut rf = target_sftp.create(&target.remote_path).await.map_err(|e| {
        let d = crate::commands::sftp::sftp_error_detail(e);
        log::error!("[sshspan-sftp] sendto leg2 create {}: {d}", target.remote_path);
        format!("target create: {d}")
    })?;
    // Progress = second half of the overall copy.
    copy_with_progress(
        app,
        job_id,
        &mut lf,
        &mut rf,
        cancel.clone(),
        Some(size),
        size,
    )
    .await
    .map_err(|e| {
        log::error!("[sshspan-sftp] sendto leg2 write {} (size {size}): {e}", target.remote_path);
        format!("target write: {e}")
    })?;
    rf.close().await.map_err(|e| format!("close failed: {e}"))?;
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
            run_server_copy(&app, job_id, &session_id, &remote, &target, cancel).await
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
                        let mut rf = sftp
                            .create(&remote)
                            .await
                            .map_err(|e| format!("remote open failed: {e}"))?;
                        copy_with_progress(&app, job_id, &mut lf, &mut rf, cancel.clone(), None, 0)
                            .await?;
                        rf.close().await.map_err(|e| format!("close failed: {e}"))?;
                    }
                    JobKind::Download => {
                        let mut rf = sftp.open(&remote).await.map_err(|e| {
                            format!(
                                "remote open failed: {}",
                                crate::commands::sftp::sftp_error_detail(e)
                            )
                        })?;
                        // Clamp reads to the file size so the final chunk never
                        // crosses EOF (see copy_with_progress doc comment).
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
                        // well-behaved servers).
                        let size = size.unwrap_or(u64::MAX);
                        let mut lf = tokio::fs::File::create(&local)
                            .await
                            .map_err(|e| format!("local create failed: {e}"))?;
                        copy_with_progress(
                            &app,
                            job_id,
                            &mut rf,
                            &mut lf,
                            cancel.clone(),
                            Some(size),
                            0,
                        )
                        .await?;
                        lf.flush()
                            .await
                            .map_err(|e| format!("local flush failed: {e}"))?;
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
