//! Background transfer queue for SFTP uploads/downloads.
//!
//! FileZilla's model: one session browses, others transfer. Each queued job
//! asks the SSH session actor for a fresh SFTP channel (via the existing
//! `sftp_tx` oneshot), so browsing stays responsive during transfers.
//! Progress is streamed to the renderer as `sftp-queue` Tauri events.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::AsyncWriteExt;

use crate::ssh_client::SessionRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JobKind {
    Upload,
    Download,
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
pub fn emit_queue(app: &AppHandle) {
    let q = app.state::<TransferQueue>();
    let jobs = q.snapshot();
    let _ = app.emit("sftp-queue", serde_json::json!({ "jobs": jobs }));
}

/// Fetch the live SFTP channel-count setting (1..=4, default 2).
fn parallel_limit(app: &AppHandle) -> usize {
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
}

/// Add jobs and kick the dispatcher. `items` are fully-expanded file pairs
/// (directories were expanded by the caller).
pub fn enqueue(app: &AppHandle, items: Vec<QueuedItem>) {
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
pub fn dispatch(app: &AppHandle) {
    let q = app.state::<TransferQueue>();
    let limit = parallel_limit(app);

    let to_start: Vec<(u64, String, JobKind, String, String, u64)> = {
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
                started.push((
                    j.id,
                    j.session_id.clone(),
                    j.kind,
                    j.local_path.clone(),
                    j.remote_path.clone(),
                    j.size,
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

    for (id, session_id, kind, local, remote, size) in to_start {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            run_job(app, gen, id, session_id, kind, local, remote, size).await;
        });
    }
}

/// Ask the SSH session actor for a fresh SFTP channel (browse session stays
/// untouched — each transfer gets its own channel over the same connection).
async fn open_transfer_channel(
    app: &AppHandle,
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
/// transfer on the last chunk.
async fn copy_with_progress<R, W>(
    app: &AppHandle,
    job_id: u64,
    reader: &mut R,
    writer: &mut W,
    cancel: Arc<AtomicBool>,
    max_read: Option<u64>,
) -> Result<u64, String>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        let n = reader
            .read(&mut buf[..want])
            .await
            .map_err(|e| e.to_string())?;
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
            update_progress(app, job_id, done, Some(speed));
            last_emit = now;
            last_bytes = done;
        }
    }
    writer.flush().await.map_err(|e| e.to_string())?;
    writer.shutdown().await.map_err(|e| e.to_string())?;
    Ok(done)
}

fn update_progress(app: &AppHandle, job_id: u64, bytes_done: u64, speed: Option<f64>) {
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
fn finish_job(app: &AppHandle, job_id: u64, state: JobState, error: Option<String>) {
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

async fn run_job(
    app: AppHandle,
    _gen: u64,
    job_id: u64,
    session_id: String,
    kind: JobKind,
    local: String,
    remote: String,
    size: u64,
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

    let result: Result<(), String> = async {
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
                copy_with_progress(&app, job_id, &mut lf, &mut rf, cancel.clone(), None).await?;
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
                    .size
                    .unwrap_or(0);
                let mut lf = tokio::fs::File::create(&local)
                    .await
                    .map_err(|e| format!("local create failed: {e}"))?;
                copy_with_progress(&app, job_id, &mut rf, &mut lf, cancel.clone(), Some(size))
                    .await?;
                lf.flush()
                    .await
                    .map_err(|e| format!("local flush failed: {e}"))?;
            }
        }
        Ok(())
    }
    .await;

    match result {
        Ok(()) => finish_job(&app, job_id, JobState::Done, None),
        Err(e) if e == "cancelled" => finish_job(&app, job_id, JobState::Cancelled, None),
        Err(e) => finish_job(&app, job_id, JobState::Failed, Some(e)),
    }
    let _ = size;
}

/// Cancel one job (active jobs abort at their next chunk; queued flip state).
pub fn cancel_job(app: &AppHandle, job_id: u64) {
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
pub fn retry_job(app: &AppHandle, job_id: u64) {
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
pub fn clear_finished(app: &AppHandle) {
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

/// Cancel everything belonging to a session (disconnect/lock).
pub fn cancel_for_session(app: &AppHandle, session_id: &str) {
    let q = app.state::<TransferQueue>();
    {
        let mut guard = q.jobs.lock().unwrap();
        for j in guard.iter_mut() {
            if j.session_id == session_id && matches!(j.state, JobState::Queued | JobState::Active)
            {
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

/// True when the session has active or queued jobs.
pub fn session_busy(app: &AppHandle, session_id: &str) -> bool {
    app.state::<TransferQueue>()
        .jobs
        .lock()
        .unwrap()
        .iter()
        .any(|j| {
            j.session_id == session_id && matches!(j.state, JobState::Queued | JobState::Active)
        })
}
