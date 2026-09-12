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

impl JobKind {
    /// Stable string form for the `transfer_queue.kind` column — matches the
    /// enum's own `#[serde(rename_all = "camelCase")]` wire spelling so the
    /// DB row and `emit_queue`'s JSON never disagree.
    fn as_db_str(self) -> &'static str {
        match self {
            JobKind::Upload => "upload",
            JobKind::Download => "download",
            JobKind::ServerCopy => "serverCopy",
        }
    }

    fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "upload" => Some(JobKind::Upload),
            "download" => Some(JobKind::Download),
            "serverCopy" => Some(JobKind::ServerCopy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JobState {
    Queued,
    Active,
    /// Suspended by the user (or restored from a previous run — see
    /// `restore_pending`) with its position intact: an Active job's `.part`
    /// is left exactly where it was, a Queued job (including one sitting out
    /// an auto-retry backoff) is simply parked. Never started by `dispatch`;
    /// only `resume_job`/`resume_all` move a job out of this state.
    Paused,
    Done,
    Failed,
    Cancelled,
}

impl JobState {
    /// Stable string form for the `transfer_queue.state` column — matches
    /// the enum's own camelCase wire spelling.
    fn as_db_str(self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Active => "active",
            JobState::Paused => "paused",
            JobState::Done => "done",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }
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

    /// Stable string form for the `transfer_queue.resume` column — round-
    /// trips through [`ResumeMode::from_str_loose`].
    fn as_db_str(self) -> &'static str {
        match self {
            ResumeMode::Overwrite => "overwrite",
            ResumeMode::Resume => "resume",
            ResumeMode::Ask => "ask",
        }
    }
}

/// Staging suffix for in-flight transfers. Transfers write `<dest>.part` and
/// rename to `<dest>` only after a full flush, so a crash/cancel leaves a
/// resumable partial instead of a corrupt "complete" file.
pub const PART_SUFFIX: &str = ".part";

/// Sentinel error strings `run_job` matches on to tell "the worker stopped
/// itself because a flag was raised" apart from a genuine transfer failure.
/// Every fallible copy step in this file returns a `String`, so a sentinel
/// value (rather than a richer error type) is what keeps that distinction
/// without a wider refactor of every `?`-using call site — see
/// `classify_error`'s doc comment for the same tradeoff applied to
/// retry/terminal classification.
const CANCELLED_SENTINEL: &str = "cancelled";
/// Distinct from `CANCELLED_SENTINEL`: a paused job's `.part` must survive
/// and its position must be preserved (see `JobState::Paused`), so `run_job`
/// must never treat the two the same way.
const PAUSED_SENTINEL: &str = "paused";

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
        return Err("source size unknown; cannot verify .part alignment — starting over".into());
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
    /// Pause flag shared with the active worker — deliberately separate from
    /// `cancel`: a cancelled job's `.part` is abandoned (cleanup is the
    /// user's/`clear_finished`'s concern), while a paused job's `.part` is
    /// the whole point of pausing, so the two must never share one flag.
    /// `None` while Queued/Done/Failed/Cancelled; set by `dispatch` the
    /// moment a job goes Active, mirroring `cancel`.
    #[serde(skip)]
    pub pause: Option<Arc<AtomicBool>>,
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
    /// Automatic-retry counter (distinct from a user clicking Retry, which
    /// resets this to 0): incremented each time `handle_job_failure`
    /// re-queues a retryable failure. Auto-retry stops once this reaches
    /// `MAX_AUTO_RETRIES` and the job lands in `Failed` with the last error.
    pub attempts: u32,
    /// When set, the earliest instant `dispatch` may start this Queued job —
    /// the backoff timer for an in-flight auto-retry. `None` means eligible
    /// immediately (a freshly enqueued job, or one resumed by the user).
    /// A `SystemTime` (not `Instant`) so it round-trips through
    /// `emit_queue`'s JSON and survives a restore from `restore_pending`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<std::time::SystemTime>,
    /// Opt-in post-transfer SHA-256 check (`setting.sftpVerifyTransfers`),
    /// stamped from the setting at enqueue time so every job in a batch is
    /// consistent even if the setting changes mid-batch. `None` behaves as
    /// `Some(false)` (off) — kept optional so a restored job whose persisted
    /// row predates this column still reconstructs cleanly via
    /// `restore_pending`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<bool>,
    /// Last time this job's `bytes_done` was written to the `transfer_queue`
    /// table (see `update_progress`). Progress ticks arrive many times a
    /// second; persisting every one would hammer the disk for no benefit; a
    /// crash between two persisted points just re-downloads/re-uploads a
    /// little more on the next resume, which is cheap. Not part of the wire
    /// format — purely internal bookkeeping.
    #[serde(skip)]
    last_persist_at: Option<std::time::Instant>,
}

impl TransferJob {
    /// Cumulative byte total the workers report against, i.e. what
    /// `bytes_done` reaches when the job completes. A ServerCopy moves the
    /// data TWICE (leg 1: source → local staging, leg 2: staging → target),
    /// and its progress is reported cumulatively across both legs, so its
    /// total is 2× the source size; plain transfers total the source size.
    /// The renderer maps `bytesDone / progressTotal` onto the bar (for
    /// serverCopy it computes 2×size itself, sftp.js "totalUnits").
    fn progress_total(&self) -> u64 {
        match self.kind {
            JobKind::ServerCopy => self.size.saturating_mul(2),
            _ => self.size,
        }
    }

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
            "attempts": self.attempts,
            // Millis-since-epoch (or null) rather than SystemTime's default
            // {secs_since_epoch, nanos_since_epoch} shape — a plain number is
            // what a renderer countdown wants, and it can't go negative or
            // fail to serialize the way a pre-epoch SystemTime subtraction
            // could.
            "retryAt": self.retry_at.and_then(system_time_to_millis),
            "verify": self.verify.unwrap_or(false),
        })
    }

    /// Snapshot the persisted subset of this job as a `transfer_queue` row
    /// (see `db::QueueJobRow`). `session_id`/`target_session_id` are stored
    /// as-is even though they're only valid for the run that created them —
    /// turning a stale one into a "needs reconnect" job is `restore_pending`'s
    /// job on the NEXT startup, not this method's.
    fn to_row(&self) -> crate::db::QueueJobRow {
        crate::db::QueueJobRow {
            id: self.id as i64,
            kind: self.kind.as_db_str().to_string(),
            session_id: self.session_id.clone(),
            server_name: self.server_name.clone(),
            local_path: self.local_path.clone(),
            remote_path: self.remote_path.clone(),
            size: self.size as i64,
            bytes_done: self.bytes_done as i64,
            state: self.state.as_db_str().to_string(),
            error: self.error.clone(),
            resume: self.resume.map(|r| r.as_db_str().to_string()),
            preserve_ts: self.preserve_ts,
            target_session_id: self.target_session_id.clone(),
            target_server_name: self.target_server_name.clone(),
            target_remote_path: self.target_remote_path.clone(),
            attempts: self.attempts as i64,
            verify: self.verify,
        }
    }
}

/// Milliseconds since the Unix epoch, or `None` for a `SystemTime` that
/// somehow predates it (never happens in practice — `retry_at` is always
/// `SystemTime::now() + a few seconds` — but `duration_since` is fallible and
/// this file avoids `unwrap()` on anything not statically known-infallible).
fn system_time_to_millis(t: std::time::SystemTime) -> Option<u64> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

/// Token-bucket state backing the global bandwidth throttle (see
/// [`TransferQueue::throttle_bandwidth`]). Kept as plain data so the pacing
/// arithmetic ([`rate_bucket_step`]) is a pure function, testable without a
/// clock or a tokio runtime.
struct RateBucket {
    /// Bytes currently available to spend without sleeping. Starts at 0
    /// (not a full bucket) so a freshly lowered cap can't be blown through by
    /// a burst credit nobody paced against; it fills in at the configured
    /// rate as transfers run.
    tokens: f64,
    last_refill: std::time::Instant,
}

impl Default for RateBucket {
    fn default() -> Self {
        Self {
            tokens: 0.0,
            last_refill: std::time::Instant::now(),
        }
    }
}

/// Global queue state (Tauri-managed).
pub struct TransferQueue {
    jobs: Mutex<Vec<TransferJob>>,
    next_id: AtomicU64,
    /// Generation counter — dispatcher restart when jobs are added.
    generation: AtomicU64,
    /// Shared bytes/sec cap for every worker combined (0 = unlimited). Lives
    /// here rather than as its own Tauri-managed state so lib.rs's existing
    /// `app.manage(TransferQueue::new())` call needs no changes; read fresh
    /// on every chunk so [`set_rate_limit`] takes effect on already-running
    /// transfers, not just newly started ones.
    rate_bps: AtomicU64,
    rate_bucket: Mutex<RateBucket>,
}

impl Default for TransferQueue {
    fn default() -> Self {
        Self {
            jobs: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            rate_bps: AtomicU64::new(0),
            rate_bucket: Mutex::new(RateBucket::default()),
        }
    }
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

    /// Pace one chunk against the shared cap, sleeping only when this call
    /// pushed the bucket into deficit. The `rate_bucket` mutex is a plain
    /// `std::sync::Mutex` and is held only for the synchronous arithmetic in
    /// [`rate_bucket_step`] — never across the `.await` below — so a
    /// concurrent [`set_rate_limit`] or another worker's chunk is never
    /// blocked behind a sleeping one.
    async fn throttle_bandwidth(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let cap = self.rate_bps.load(Ordering::SeqCst);
        if cap == 0 {
            return; // unlimited — the common case, skip the lock entirely
        }
        let wait = {
            let mut bucket = self.rate_bucket.lock().unwrap();
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            bucket.last_refill = now;
            let (after, wait) = rate_bucket_step(bucket.tokens, elapsed, cap, bytes);
            bucket.tokens = after;
            wait
        };
        if let Some(d) = wait {
            tokio::time::sleep(d).await;
        }
    }
}

/// Pure token-bucket arithmetic: given the tokens on hand, the time elapsed
/// since the last refill, the bytes/sec cap, and the bytes about to be
/// spent, returns the updated token balance and — if spending would drive it
/// negative — how long to sleep to work the debt off at the current rate.
/// `cap_bps == 0` (unlimited) always returns `(tokens, None)` unchanged.
/// Refill is capped at one second's worth of tokens so a long idle gap (a
/// paused job, a queue with nothing to send) can't bank an unbounded burst
/// credit for later — the cap is a running average, not a once-a-while
/// allowance.
fn rate_bucket_step(
    tokens: f64,
    elapsed_secs: f64,
    cap_bps: u64,
    bytes: u64,
) -> (f64, Option<std::time::Duration>) {
    if cap_bps == 0 {
        return (tokens, None);
    }
    let cap = cap_bps as f64;
    let refilled = (tokens + elapsed_secs.max(0.0) * cap).min(cap);
    let after = refilled - bytes as f64;
    if after >= 0.0 {
        (after, None)
    } else {
        (
            after,
            Some(std::time::Duration::from_secs_f64(-after / cap)),
        )
    }
}

/// Emit the full queue state to the renderer.
pub fn emit_queue<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let q = app.state::<TransferQueue>();
    let jobs = q.snapshot();
    let _ = app.emit("sftp-queue", serde_json::json!({ "jobs": jobs }));
}

// ─── queue persistence (`transfer_queue` table) ────────────────────────────
//
// Best-effort throughout: the in-memory `TransferQueue` is always the source
// of truth for a running app, so a DB write failure here is logged and
// swallowed exactly like the tolerant SETSTAT calls elsewhere in this file —
// it must never fail (or roll back) the transfer it's shadowing. Persistence
// only exists to survive a restart (see `restore_pending`).

/// Upsert one job's persisted row. Called on every meaningful state
/// transition (enqueue, dispatch → Active, pause/resume, cancel/retry,
/// completion) and, throttled, on progress — never anywhere hotter than that.
fn persist_job<R: tauri::Runtime>(app: &tauri::AppHandle<R>, row: crate::db::QueueJobRow) {
    let id = row.id;
    if let Err(e) = app.state::<crate::AppState>().db.upsert_queue_job(&row) {
        log::warn!("[sshspan-sftp] queue persistence: upsert job {id} failed: {e}");
    }
}

/// Mirror `clear_finished`'s in-memory retain: drop every persisted
/// Done/Failed/Cancelled row.
fn persist_clear_finished<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Err(e) = app
        .state::<crate::AppState>()
        .db
        .delete_finished_queue_jobs()
    {
        log::warn!("[sshspan-sftp] queue persistence: clear finished failed: {e}");
    }
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

/// Fetch whether opt-in post-transfer SHA-256 verification is on
/// (`setting.sftpVerifyTransfers`). Off unless the value is exactly "true"
/// or "1" (case-insensitive) — verification re-reads every byte on both
/// ends, so anything unrecognized must fail closed to "off", not "on".
fn verify_enabled<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> bool {
    app.state::<crate::AppState>()
        .db
        .get_config("setting.sftpVerifyTransfers")
        .ok()
        .flatten()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false)
}

/// Fetch the shared bandwidth cap in bytes/sec (`setting.sftpMaxBps`); 0 (or
/// an absent/unparseable value) means unlimited. Same settings-read pattern
/// as [`parallel_limit`]; the live value workers actually pace against lives
/// on `TransferQueue::rate_bps` (see [`set_rate_limit`]), not re-read from
/// the DB on every chunk.
fn rate_limit_bps<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> u64 {
    app.state::<crate::AppState>()
        .db
        .get_config("setting.sftpMaxBps")
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Change the shared bandwidth cap live, without touching any in-flight
/// transfer: every worker reads `rate_bps` fresh on every chunk (see
/// [`TransferQueue::throttle_bandwidth`]), so a raise, a drop, or a change to
/// 0 (unlimited) takes effect the very next chunk any of them copies — never
/// a restart, and never a wait on anything that could deadlock. Also
/// persists the choice as `setting.sftpMaxBps` so it survives a restart
/// (read back into `rate_bps` by [`restore_pending`] at the next startup).
pub fn set_rate_limit<R: tauri::Runtime>(app: &tauri::AppHandle<R>, bytes_per_sec: u64) {
    app.state::<TransferQueue>()
        .rate_bps
        .store(bytes_per_sec, Ordering::SeqCst);
    if let Err(e) = app
        .state::<crate::AppState>()
        .db
        .set_config("setting.sftpMaxBps", &bytes_per_sec.to_string())
    {
        log::warn!("[sshspan-sftp] set_rate_limit: persisting setting failed: {e}");
    }
}

/// One fully-expanded transfer to enqueue.
///
/// Deliberately does NOT carry a `verify` field: every construction site
/// (`commands/sftp.rs`'s `expand_upload`/`expand_download`/
/// `expand_server_copy`/`sftp_server_copy`) builds this struct with an
/// exhaustive field list and no `..Default::default()`, so adding a required
/// field here would be a breaking change to code outside this file. Instead
/// [`enqueue`] stamps every job in a batch from the global
/// `setting.sftpVerifyTransfers` setting directly (the same pattern
/// `parallel_limit` uses for `sftpParallel`) — see `verify_enabled`.
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
    let verify = verify_enabled(app);
    let mut new_rows = Vec::new();
    {
        let mut guard = q.jobs.lock().unwrap();
        for item in items {
            let id = q.next_id.fetch_add(1, Ordering::SeqCst);
            let job = TransferJob {
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
                pause: None,
                started_at: None,
                target_session_id: item.target.as_ref().map(|t| t.session_id.clone()),
                target_server_name: item.target.as_ref().map(|t| t.server_name.clone()),
                target_remote_path: item.target.as_ref().map(|t| t.remote_path.clone()),
                resume: item.resume,
                preserve_ts: item.preserve_ts,
                attempts: 0,
                retry_at: None,
                verify: Some(verify),
                last_persist_at: None,
            };
            new_rows.push(job.to_row());
            guard.push(job);
        }
    }
    q.generation.fetch_add(1, Ordering::SeqCst);
    drop(q);
    for row in new_rows {
        persist_job(app, row);
    }
    emit_queue(app);
    dispatch(app);
}

/// Whether `dispatch` may start this job right now: it must be Queued, and
/// if it's mid-backoff from an auto-retry (`retry_at` set by
/// `handle_job_failure`), that instant must have passed. Paused jobs never
/// match — pulling this predicate out as a free function of plain data (no
/// `TransferQueue`/`AppHandle`) makes "dispatch skips a paused job" and "a
/// backoff still counting down is skipped too" unit-testable without a live
/// Tauri app.
fn is_dispatchable(job: &TransferJob, now: std::time::SystemTime) -> bool {
    job.state == JobState::Queued && job.retry_at.is_none_or(|t| t <= now)
}

/// Spawn workers for queued jobs while fewer than the limit are active.
/// Cheap to call repeatedly: each call checks state under the lock and only
/// spawns when there is work and capacity.
pub fn dispatch<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let q = app.state::<TransferQueue>();
    let limit = parallel_limit(app);

    let mut persisted_rows = Vec::new();
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
        bool,
    )> = {
        let mut guard = q.jobs.lock().unwrap();
        let active = guard.iter().filter(|j| j.state == JobState::Active).count();
        let mut capacity = limit.saturating_sub(active);
        let mut started = Vec::new();
        if capacity == 0 {
            return;
        }
        let now = std::time::SystemTime::now();
        for j in guard.iter_mut() {
            if capacity == 0 {
                break;
            }
            if is_dispatchable(j, now) {
                j.state = JobState::Active;
                j.cancel = Some(Arc::new(AtomicBool::new(false)));
                j.pause = Some(Arc::new(AtomicBool::new(false)));
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
                    j.verify.unwrap_or(false),
                ));
                persisted_rows.push(j.to_row());
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

    for row in persisted_rows {
        persist_job(app, row);
    }

    for (id, session_id, kind, local, remote, size, target, resume, preserve_ts, verify) in to_start
    {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            run_job(
                app,
                gen,
                id,
                session_id,
                kind,
                local,
                remote,
                size,
                target,
                resume,
                preserve_ts,
                verify,
            )
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
///
/// Also the single choke point for the global bandwidth throttle: every job
/// kind's every leg calls this to move bytes, so pacing here (via
/// `TransferQueue::throttle_bandwidth`) caps all of them without needing a
/// separate check in each caller.
#[allow(clippy::too_many_arguments)]
async fn copy_with_progress<RT, R, W>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    reader: &mut R,
    writer: &mut W,
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
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
            return Err(CANCELLED_SENTINEL.into());
        }
        // Checked at the same chunk boundary as cancel, right before the
        // next read: an Active job's `.part` (or partial ServerCopy leg) is
        // left exactly where it stands, never truncated or rewound.
        if pause.load(Ordering::SeqCst) {
            return Err(PAUSED_SENTINEL.into());
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

        // Global bandwidth pacing: a no-op (no lock taken) when unlimited.
        app.state::<TransferQueue>()
            .throttle_bandwidth(n as u64)
            .await;

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

/// How often a job's `bytes_done` is written to the `transfer_queue` table.
/// Progress ticks fire every ~200ms (see `copy_with_progress`); persisting
/// every one would be a DB write several times a second per active transfer
/// for no real benefit — a crash between two persisted points just costs a
/// few more seconds of re-transfer on the next resume.
const PROGRESS_PERSIST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);

fn update_progress<RT: tauri::Runtime>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    bytes_done: u64,
    speed: Option<f64>,
) {
    let q = app.state::<TransferQueue>();
    let (job_json, persist_row) = {
        let mut guard = q.jobs.lock().unwrap();
        match guard.iter_mut().find(|j| j.id == job_id) {
            Some(j) => {
                j.bytes_done = bytes_done;
                let now = std::time::Instant::now();
                let due = j
                    .last_persist_at
                    .is_none_or(|t| now.duration_since(t) >= PROGRESS_PERSIST_INTERVAL);
                let row = if due {
                    j.last_persist_at = Some(now);
                    Some(j.to_row())
                } else {
                    None
                };
                (Some(j.snapshot(speed)), row)
            }
            None => (None, None),
        }
    };
    drop(q);
    if let Some(job) = job_json {
        let _ = app.emit("sftp-queue", serde_json::json!({ "jobs": [job] }));
    }
    if let Some(row) = persist_row {
        persist_job(app, row);
    }
}

/// Set a job's resting state — a terminal one (Done/Failed/Cancelled) or the
/// Paused suspension — and emit it. Also used for Paused because pausing
/// frees the job's concurrency slot exactly like a terminal state does; the
/// `state == Done` special case below is the only place the two are treated
/// differently.
fn finish_job<RT: tauri::Runtime>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    state: JobState,
    error: Option<String>,
) {
    let q = app.state::<TransferQueue>();
    let (job_json, row) = {
        let mut guard = q.jobs.lock().unwrap();
        match guard.iter_mut().find(|j| j.id == job_id) {
            Some(j) => {
                j.state = state;
                j.error = error;
                if state == JobState::Done {
                    // Completed bytes = the job's full progress total. For a
                    // ServerCopy that is 2× the source size (both legs done) —
                    // normalizing to `size` here left every finished Send-to
                    // row at a half-filled bar.
                    j.bytes_done = j.progress_total();
                }
                (Some(j.snapshot(None)), Some(j.to_row()))
            }
            None => (None, None),
        }
    };
    if let Some(job) = job_json {
        let _ = app.emit("sftp-queue", serde_json::json!({ "jobs": [job] }));
    }
    drop(q);
    if let Some(row) = row {
        persist_job(app, row);
    }
    // Something finished (or paused) — try to start the next queued job.
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
#[allow(clippy::too_many_arguments)]
async fn read_via_session<RT: tauri::Runtime>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    sftp: &russh_sftp::client::SftpSession,
    source_remote: &str,
    stage: &std::path::Path,
    size: u64,
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut rf = sftp
        .open(source_remote)
        .await
        .map_err(|e| crate::commands::sftp::sftp_error_detail(e))?;
    // Truncate the staging file (the failed fresh-channel attempt may have
    // left a partial write) before re-reading into it.
    let mut lf = tokio::fs::File::create(stage)
        .await
        .map_err(|e| format!("local recreate failed: {e}"))?;
    copy_with_progress(app, job_id, &mut rf, &mut lf, cancel, pause, Some(size), 0).await?;
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
#[allow(clippy::too_many_arguments)]
async fn run_server_copy<RT: tauri::Runtime>(
    app: &tauri::AppHandle<RT>,
    job_id: u64,
    source_session: &str,
    source_remote: &str,
    target: &ServerCopyTarget,
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    resume: Option<ResumeMode>,
    preserve_ts: bool,
    verify: bool,
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
    let sftp = open_transfer_channel(app, source_session)
        .await
        .map_err(|e| {
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
    // Single-file Send-to jobs are enqueued with size 0 ("stat'd by the
    // worker") — write the stat'd size back into the job record so the queue
    // row gets a real progress denominator (the worker's own clamp below
    // needs it too).
    if let Some(real) = size {
        let q = app.state::<TransferQueue>();
        let mut guard = q.jobs.lock().unwrap();
        if let Some(j) = guard.iter_mut().find(|j| j.id == job_id) {
            if j.size == 0 {
                j.size = real;
            }
        }
        drop(guard);
    }
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
    let fresh_result = copy_with_progress(
        app,
        job_id,
        &mut rf,
        &mut lf,
        cancel.clone(),
        pause.clone(),
        Some(size),
        0,
    )
    .await;
    if let Err(fresh_err) = fresh_result {
        // A user-requested stop, not a genuine read failure: clean up and
        // return the bare sentinel so `run_job` recognizes it. The
        // diagnostic/fallback path below exists to tell "this server
        // read-blocks fresh channels" apart from "the read pattern itself is
        // broken" — it must never fire just because the user paused or
        // cancelled mid-read (retrying via the interactive session at that
        // point would ignore the request and keep transferring).
        if fresh_err == CANCELLED_SENTINEL || fresh_err == PAUSED_SENTINEL {
            let _ = lf.flush().await;
            drop(lf);
            if let Err(e) = rf.close().await {
                log::debug!("[sshspan-sftp] sendto leg1 close after {fresh_err}: {e}");
            }
            drop(sftp);
            return Err(fresh_err);
        }
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
            log::warn!("[sshspan-sftp] close of failed fresh handle for {source_remote}: {e}");
        }
        // 3. Drop the fresh channel's SFTP session entirely.
        drop(sftp);

        let interactive = app.state::<crate::sftp::SftpRegistry>().get(source_session);
        match interactive {
            Some(isftp) => {
                match read_via_session(
                    app,
                    job_id,
                    &isftp,
                    source_remote,
                    &stage,
                    size,
                    cancel.clone(),
                    pause.clone(),
                )
                .await
                {
                    Ok(()) => {
                        log::warn!(
                            "[sshspan-sftp] sendto leg1 succeeded via INTERACTIVE browse session \
                             (fresh channel is read-blocked on this server)"
                        );
                        // Fall through to leg 2 with the staged file in place.
                    }
                    Err(ie) if ie == CANCELLED_SENTINEL || ie == PAUSED_SENTINEL => {
                        return Err(ie);
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
            log::warn!("[sshspan-sftp] close after copy of {source_remote}: {e}");
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
    let mut rf = target_sftp
        .open_with_flags(
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
        pause.clone(),
        Some(size.saturating_sub(offset)),
        size + offset,
    )
    .await
    .map_err(|e| {
        // A user-requested stop must reach `run_job` as the bare sentinel
        // (see the matching leg-1 guard above) — wrapping it into a
        // "target write: …" message would hide the pause/cancel from the
        // state-transition match and land the job in Failed instead.
        if e == CANCELLED_SENTINEL || e == PAUSED_SENTINEL {
            return e;
        }
        log::error!(
            "[sshspan-sftp] sendto leg2 write {} (size {size}): {e}",
            tpart
        );
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
                return Err(format!(
                    "target close failed ({e}); staged stat also failed: {se}"
                ));
            }
        }
    }
    // Some servers refuse rename-over-an-existing-file; the .part is fully
    // uploaded at this point, so removing the final name first is a safe retry.
    if let Err(e) = target_sftp.rename(&tpart, &target.remote_path).await {
        let d = crate::commands::sftp::sftp_error_detail(e);
        if target_sftp.remove_file(&target.remote_path).await.is_ok()
            && target_sftp
                .rename(&tpart, &target.remote_path)
                .await
                .is_ok()
        {
            return Ok(());
        }
        log::error!(
            "[sshspan-sftp] sendto leg2 rename {tpart} -> {}: {d}",
            target.remote_path
        );
        return Err(format!("final rename failed: {d}"));
    }
    // Opt-in verification (`setting.sftpVerifyTransfers`): hash both remote
    // ends and compare before trusting the copy. The source channel was
    // already closed after leg 1, so this reopens a fresh one purely for the
    // hash — cheap next to re-reading the whole file, which is what a
    // mismatch would otherwise cost the user in a silent later discovery.
    // A mismatch removes the target file: the copy must not sit there
    // looking successful when it isn't.
    if verify {
        let source_hash = match open_transfer_channel(app, source_session).await {
            Ok(verify_sftp) => {
                crate::commands::sftp::remote_sha256(
                    &verify_sftp,
                    source_remote,
                    Some(cancel.as_ref()),
                )
                .await
            }
            Err(e) => Err(crate::commands::CmdError(format!(
                "reopening source for verification: {e}"
            ))),
        };
        let target_hash = crate::commands::sftp::remote_sha256(
            &target_sftp,
            &target.remote_path,
            Some(cancel.as_ref()),
        )
        .await;
        match (source_hash, target_hash) {
            (Ok(sh), Ok(th)) if sh == th => {}
            (Ok(sh), Ok(th)) => {
                let _ = target_sftp.remove_file(&target.remote_path).await;
                return Err(format!(
                    "checksum mismatch: source {sh} != target {th} (copy removed)"
                ));
            }
            (Err(e), _) => {
                return Err(format!("checksum mismatch: could not hash source: {e}"));
            }
            (_, Err(e)) => {
                return Err(format!("checksum mismatch: could not hash target: {e}"));
            }
        }
    }
    // Preserve timestamps (after the rename finalizes the destination): stat
    // the STAGED file (its data equals the remote source) and push its mtime
    // onto the target. Best-effort setstat.
    if preserve_ts {
        apply_preserved_mtime(&target_sftp, &stage, &target.remote_path).await;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
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
    verify: bool,
) {
    let (cancel, pause) = {
        let q = app.state::<TransferQueue>();
        let guard = q.jobs.lock().unwrap();
        match guard.iter().find(|j| j.id == job_id) {
            Some(j) => (j.cancel.clone(), j.pause.clone()),
            None => (None, None),
        }
    };
    let (Some(cancel), Some(pause)) = (cancel, pause) else {
        finish_job(&app, job_id, JobState::Failed, Some("job vanished".into()));
        return;
    };

    let result: Result<(), String> = match (kind, target) {
        (JobKind::ServerCopy, Some(target)) => {
            run_server_copy(
                &app,
                job_id,
                &session_id,
                &remote,
                &target,
                cancel,
                pause,
                resume,
                preserve_ts,
                verify,
            )
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
                            pause.clone(),
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
                        // Opt-in verification: hash the local source and the
                        // now-renamed remote destination and compare. A
                        // mismatch removes the remote file rather than
                        // leaving a corrupt upload that looks complete.
                        if verify {
                            let local_hash =
                                local_sha256(std::path::Path::new(&local), cancel.clone()).await;
                            let remote_hash = crate::commands::sftp::remote_sha256(
                                &sftp,
                                &remote,
                                Some(cancel.as_ref()),
                            )
                            .await;
                            match (local_hash, remote_hash) {
                                (Ok(lh), Ok(rh)) if lh == rh => {}
                                (Ok(lh), Ok(rh)) => {
                                    let _ = sftp.remove_file(&remote).await;
                                    return Err(format!(
                                        "checksum mismatch: local {lh} != remote {rh} (upload removed)"
                                    ));
                                }
                                (Err(e), _) => {
                                    return Err(format!(
                                        "checksum mismatch: could not hash local file: {e}"
                                    ));
                                }
                                (_, Err(e)) => {
                                    return Err(format!(
                                        "checksum mismatch: could not hash remote file: {e}"
                                    ));
                                }
                            }
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
                            pause.clone(),
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
                        // Opt-in verification: hash the now-renamed local
                        // file and the remote source and compare. A mismatch
                        // removes the local file rather than leaving a
                        // corrupt download that looks complete.
                        if verify {
                            let local_hash =
                                local_sha256(std::path::Path::new(&local), cancel.clone()).await;
                            let remote_hash = crate::commands::sftp::remote_sha256(
                                &sftp,
                                &remote,
                                Some(cancel.as_ref()),
                            )
                            .await;
                            match (remote_hash, local_hash) {
                                (Ok(rh), Ok(lh)) if rh == lh => {}
                                (Ok(rh), Ok(lh)) => {
                                    let _ = tokio::fs::remove_file(&local).await;
                                    return Err(format!(
                                        "checksum mismatch: remote {rh} != local {lh} (download removed)"
                                    ));
                                }
                                (Err(e), _) => {
                                    return Err(format!(
                                        "checksum mismatch: could not hash remote file: {e}"
                                    ));
                                }
                                (_, Err(e)) => {
                                    return Err(format!(
                                        "checksum mismatch: could not hash local file: {e}"
                                    ));
                                }
                            }
                        }
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
        Err(e) if e == CANCELLED_SENTINEL => finish_job(&app, job_id, JobState::Cancelled, None),
        Err(e) if e == PAUSED_SENTINEL => finish_job(&app, job_id, JobState::Paused, None),
        Err(e) => handle_job_failure(&app, job_id, e),
    }
    let _ = size;
}

/// Stream a local file through SHA-256 in the same 256 KiB chunk size as
/// `copy_with_progress`, so verifying even a very large transfer never holds
/// more than one chunk in memory. Checked against `cancel` between chunks so
/// a cancel raised mid-verification doesn't hang shutdown behind hashing a
/// huge file.
async fn local_sha256(path: &std::path::Path, cancel: Arc<AtomicBool>) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("open for hashing failed: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(CANCELLED_SENTINEL.into());
        }
        let n = f
            .read(&mut buf)
            .await
            .map_err(|e| format!("read for hashing failed: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Classification of a transfer failure for the auto-retry policy (see
/// [`handle_job_failure`]): whether the exact same operation stands a
/// reasonable chance of succeeding on a fresh attempt (a network blip, a
/// closed pipe, a timeout) versus a structural problem that retrying cannot
/// fix (permission denied, a missing file, a full disk, an unsupported
/// operation). Conservative by design: an error this function doesn't
/// recognize is `Terminal`, so auto-retry can never turn an actionable
/// failure into a silent multi-minute stall in an unattended batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorClass {
    Retryable,
    Terminal,
}

/// Classify a failure by its already-rendered message. Every fallible step
/// in this file reaches its caller as a `String` (the
/// `.map_err(|e| format!(...))` convention used throughout `run_job` /
/// `run_server_copy`), and that rendered text already carries the
/// OS-level/SFTP-protocol wording — `std::io::Error`'s `Display` and
/// `sftp_error_detail`'s output both surface it in the message itself — so
/// matching on the final string here recognizes the same failures a
/// typed-error classification would, without a wider refactor of every
/// fallible call site's return type. Case-insensitive; a message containing
/// both a terminal and a retryable phrase is treated as terminal (the
/// stronger signal to trust when the two disagree).
fn classify_error(msg: &str) -> ErrorClass {
    let m = msg.to_ascii_lowercase();
    const TERMINAL: &[&str] = &[
        "permission denied",
        "access denied",
        "no such file",
        "not found",
        "quota",
        "disk full",
        "no space left",
        "invalid handle",
        "unsupported",
        "not supported",
        "already exists",
        "not a directory",
        "is a directory",
        "checksum mismatch",
    ];
    const RETRYABLE: &[&str] = &[
        "connection reset",
        "connection closed",
        "connection aborted",
        "broken pipe",
        "timed out",
        "timeout",
        "temporarily unavailable",
        "temporary failure",
        "unexpected eof",
        "eof at",
    ];
    if TERMINAL.iter().any(|k| m.contains(k)) {
        return ErrorClass::Terminal;
    }
    if RETRYABLE.iter().any(|k| m.contains(k)) {
        return ErrorClass::Retryable;
    }
    ErrorClass::Terminal
}

/// Auto-retry ceiling: after this many automatic attempts a retryable
/// failure still gives up and lands the job in `Failed` — an unattended
/// batch must eventually surface a real, persistent problem instead of
/// retrying forever.
const MAX_AUTO_RETRIES: u32 = 3;

/// Exponential backoff schedule for auto-retry: the Nth retry (1-based, i.e.
/// the value `attempts` holds right after incrementing) waits `2^N` seconds
/// — 2s, 4s, 8s for N = 1, 2, 3.
fn backoff_delay(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(2u64.saturating_pow(attempt))
}

/// Handle a job failure that is neither a pause nor a cancel: classify it
/// and either schedule an automatic retry with exponential backoff or land
/// the job in `Failed` with the real error, exactly as before auto-retry
/// existed. Mirrors `finish_job`'s lock-compute-then-emit discipline.
///
/// Guards against a race between this failure and a pause/cancel request
/// that arrived while the attempt was in flight: the worker may hit a real
/// I/O error before it next checks the flag, so the CURRENT flag state (not
/// just the sentinel this attempt happened to return) decides whether the
/// job is actually cancelled/paused rather than genuinely failed — auto-retry
/// must never resurrect a job the user just stopped.
fn handle_job_failure<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, job_id: u64, error: String) {
    let q = app.state::<TransferQueue>();
    let row = {
        let mut guard = q.jobs.lock().unwrap();
        let Some(j) = guard.iter_mut().find(|j| j.id == job_id) else {
            return;
        };
        let cancelled = j.cancel.as_ref().is_some_and(|c| c.load(Ordering::SeqCst));
        let paused = j.pause.as_ref().is_some_and(|p| p.load(Ordering::SeqCst));
        if cancelled {
            j.state = JobState::Cancelled;
        } else if paused {
            j.state = JobState::Paused;
        } else {
            let retryable =
                classify_error(&error) == ErrorClass::Retryable && j.attempts < MAX_AUTO_RETRIES;
            if retryable {
                j.attempts += 1;
                let delay = backoff_delay(j.attempts);
                j.state = JobState::Queued;
                j.retry_at = Some(std::time::SystemTime::now() + delay);
                j.error = Some(format!(
                    "{error} — retrying ({}/{MAX_AUTO_RETRIES})",
                    j.attempts
                ));
                j.cancel = None;
                j.pause = None;
                // Nudge the dispatcher once the backoff elapses so an
                // otherwise-idle queue doesn't wait on some unrelated event
                // to notice the job is due. `retry_at` (checked by
                // `is_dispatchable`) remains the actual source of truth, so a
                // missed or early wakeup here can't start the job too soon —
                // worst case it waits for the next incidental `dispatch`
                // call, which a busy queue has plenty of anyway.
                let app2 = app.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(delay).await;
                    dispatch(&app2);
                });
            } else {
                j.state = JobState::Failed;
                j.error = Some(error);
            }
        }
        j.to_row()
    };
    drop(q);
    persist_job(app, row);
    emit_queue(app);
    // A retry frees no slot (the job stays Queued/counted-not-Active only
    // once dispatched again), but Failed/Cancelled/Paused all do — cheap to
    // call unconditionally, same as `finish_job`.
    dispatch(app);
}

/// Cancel one job (active jobs abort at their next chunk; queued flip state).
pub fn cancel_job<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, job_id: u64) {
    let q = app.state::<TransferQueue>();
    let row = {
        let mut guard = q.jobs.lock().unwrap();
        match guard.iter_mut().find(|j| j.id == job_id) {
            Some(j) => {
                if let Some(c) = &j.cancel {
                    c.store(true, Ordering::SeqCst);
                }
                if j.state == JobState::Queued {
                    j.state = JobState::Cancelled;
                }
                Some(j.to_row())
            }
            None => None,
        }
    };
    drop(q);
    if let Some(row) = row {
        persist_job(app, row);
    }
    emit_queue(app);
}

/// Re-queue a failed/cancelled job. A user-initiated retry is a fresh start
/// for the auto-retry counter too: `attempts` resets to 0 and any pending
/// backoff (`retry_at`) is cleared, distinguishing this from
/// `handle_job_failure`'s automatic re-queue.
pub fn retry_job<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, job_id: u64) {
    let q = app.state::<TransferQueue>();
    let row = {
        let mut guard = q.jobs.lock().unwrap();
        match guard.iter_mut().find(|j| j.id == job_id) {
            Some(j) if matches!(j.state, JobState::Failed | JobState::Cancelled) => {
                j.state = JobState::Queued;
                j.error = None;
                // bytes_done resets, but a leftover `.part` is deliberately
                // NOT deleted: with Resume mode the retried job continues
                // from it. Cleanup of stale `.part` files is the user's /
                // clear_finished's concern, not retry's.
                j.bytes_done = 0;
                j.cancel = None;
                j.pause = None;
                j.attempts = 0;
                j.retry_at = None;
                Some(j.to_row())
            }
            _ => None,
        }
    };
    drop(q);
    if let Some(row) = row {
        persist_job(app, row);
    }
    emit_queue(app);
    dispatch(app);
}

/// Remove Done/Failed/Cancelled jobs from the list (and their persisted
/// rows, so a restart's `restore_pending` doesn't resurrect them).
pub fn clear_finished<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>) {
    let q = app.state::<TransferQueue>();
    q.jobs.lock().unwrap().retain(|j| {
        !matches!(
            j.state,
            JobState::Done | JobState::Failed | JobState::Cancelled
        )
    });
    drop(q);
    persist_clear_finished(app);
    emit_queue(app);
}

/// Cancel everything belonging to a session (disconnect/lock). A
/// ServerCopy job belongs to BOTH its source and target sessions.
pub fn cancel_for_session<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, session_id: &str) {
    let q = app.state::<TransferQueue>();
    let mut rows = Vec::new();
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
                rows.push(j.to_row());
            }
        }
    }
    drop(q);
    for row in rows {
        persist_job(app, row);
    }
    emit_queue(app);
}

/// Pause one job. An Active job winds down at its next chunk boundary — only
/// the flag is raised here; `copy_with_progress` observes it and `run_job`
/// finalizes the state to `Paused` once the worker actually exits, leaving
/// its `.part` (or partial ServerCopy leg) exactly where it stood. A Queued
/// job (including one sitting out an auto-retry backoff) has no worker to
/// observe a flag, so it is paused immediately. Any other state
/// (Done/Failed/Cancelled/already Paused) is left untouched.
pub fn pause_job<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, job_id: u64) {
    let q = app.state::<TransferQueue>();
    let row = {
        let mut guard = q.jobs.lock().unwrap();
        let Some(j) = guard.iter_mut().find(|j| j.id == job_id) else {
            return;
        };
        match j.state {
            JobState::Active => {
                if let Some(p) = &j.pause {
                    p.store(true, Ordering::SeqCst);
                }
                None
            }
            JobState::Queued => {
                j.state = JobState::Paused;
                j.retry_at = None;
                Some(j.to_row())
            }
            _ => return,
        }
    };
    drop(q);
    if let Some(row) = row {
        persist_job(app, row);
    }
    emit_queue(app);
}

/// Resume one paused job: `Paused` → `Queued`, then kick the dispatcher.
/// Forces `ResumeMode::Resume` regardless of how the job was originally
/// queued — the whole point of pausing is that its `.part` survives, so the
/// resumed attempt must continue from it rather than restart from
/// `Overwrite`/`Ask` semantics. Any state other than `Paused` is a no-op.
pub fn resume_job<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, job_id: u64) {
    let q = app.state::<TransferQueue>();
    let row = {
        let mut guard = q.jobs.lock().unwrap();
        match guard.iter_mut().find(|j| j.id == job_id) {
            Some(j) if j.state == JobState::Paused => {
                j.state = JobState::Queued;
                j.error = None;
                j.retry_at = None;
                j.resume = Some(ResumeMode::Resume);
                Some(j.to_row())
            }
            _ => None,
        }
    };
    drop(q);
    if let Some(row) = row {
        persist_job(app, row);
    }
    emit_queue(app);
    dispatch(app);
}

/// Pause every Active/Queued job — see [`pause_job`] for the per-state
/// behavior applied to each.
pub fn pause_all<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>) {
    let q = app.state::<TransferQueue>();
    let mut rows = Vec::new();
    {
        let mut guard = q.jobs.lock().unwrap();
        for j in guard.iter_mut() {
            match j.state {
                JobState::Active => {
                    if let Some(p) = &j.pause {
                        p.store(true, Ordering::SeqCst);
                    }
                }
                JobState::Queued => {
                    j.state = JobState::Paused;
                    j.retry_at = None;
                    rows.push(j.to_row());
                }
                _ => {}
            }
        }
    }
    drop(q);
    for row in rows {
        persist_job(app, row);
    }
    emit_queue(app);
}

/// Resume every Paused job — see [`resume_job`] for the forced-`Resume`
/// rationale applied to each.
pub fn resume_all<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>) {
    let q = app.state::<TransferQueue>();
    let mut rows = Vec::new();
    {
        let mut guard = q.jobs.lock().unwrap();
        for j in guard.iter_mut() {
            if j.state == JobState::Paused {
                j.state = JobState::Queued;
                j.error = None;
                j.retry_at = None;
                j.resume = Some(ResumeMode::Resume);
                rows.push(j.to_row());
            }
        }
    }
    drop(q);
    for row in rows {
        persist_job(app, row);
    }
    emit_queue(app);
    dispatch(app);
}

/// Reload jobs left `Queued`/`Active`/`Paused` from a previous run and bring
/// them back as `Paused` — never auto-started. The previous run's SSH
/// sessions no longer exist (a new run has fresh, differently-numbered
/// ones), so silently reconnecting and resuming writes at startup would
/// surprise a user who never asked for it; surfacing the job as Paused with
/// an explicit "needs reconnect" error lets them resume it deliberately
/// (`resume_job`) once they've reopened the right connection. Returns the
/// number of jobs restored.
///
/// Must be called once at startup, AFTER both `AppState` (the DB) and
/// `TransferQueue` are managed — see lib.rs's `setup()`. Also seeds the
/// shared bandwidth cap from `setting.sftpMaxBps`: `TransferQueue::new()`
/// runs before the DB exists, so this is the first opportunity to read it.
pub fn restore_pending<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> usize {
    app.state::<TransferQueue>()
        .rate_bps
        .store(rate_limit_bps(app), Ordering::SeqCst);

    let rows = match app.state::<crate::AppState>().db.list_pending_queue_jobs() {
        Ok(rows) => rows,
        Err(e) => {
            log::warn!("[sshspan-sftp] queue restore: list failed: {e}");
            return 0;
        }
    };
    if rows.is_empty() {
        return 0;
    }

    let q = app.state::<TransferQueue>();
    let mut restored_rows = Vec::new();
    {
        let mut guard = q.jobs.lock().unwrap();
        let mut max_id = q.next_id.load(Ordering::SeqCst);
        for row in rows {
            let id = row.id.max(0) as u64;
            max_id = max_id.max(id + 1);
            let Some(kind) = JobKind::from_db_str(&row.kind) else {
                log::warn!(
                    "[sshspan-sftp] queue restore: job {id} has unknown kind {:?}, skipping",
                    row.kind
                );
                continue;
            };
            let job = TransferJob {
                id,
                kind,
                session_id: row.session_id,
                server_name: row.server_name.clone(),
                local_path: row.local_path,
                remote_path: row.remote_path,
                size: row.size.max(0) as u64,
                bytes_done: row.bytes_done.max(0) as u64,
                state: JobState::Paused,
                error: Some(format!(
                    "Session closed before restart — reconnect to \"{}\" and resume.",
                    row.server_name
                )),
                cancel: None,
                pause: None,
                started_at: None,
                target_session_id: row.target_session_id,
                target_server_name: row.target_server_name,
                target_remote_path: row.target_remote_path,
                resume: row.resume.as_deref().map(ResumeMode::from_str_loose),
                preserve_ts: row.preserve_ts,
                attempts: row.attempts.max(0) as u32,
                retry_at: None,
                verify: row.verify,
                last_persist_at: None,
            };
            restored_rows.push(job.to_row());
            guard.push(job);
        }
        q.next_id.store(max_id, Ordering::SeqCst);
    }
    drop(q);

    let n = restored_rows.len();
    for row in restored_rows {
        // Normalize the persisted rows to the restored Paused state/error so
        // a second restart doesn't need to re-derive it.
        persist_job(app, row);
    }
    if n > 0 {
        emit_queue(app);
    }
    n
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
        assert_eq!(
            discard_exact(&mut r, data.len() as u64).await.unwrap(),
            100 * 1024
        );
        // Discarding past EOF fails with the position in the message.
        let mut r2 = std::io::Cursor::new(vec![1u8; 10]);
        let err = discard_exact(&mut r2, 11).await.unwrap_err();
        assert!(err.contains("EOF at 10 of 11"), "unexpected message: {err}");
    }

    /// Minimal `TransferJob` for tests that only care about a couple of
    /// fields (state/retry_at) — every field still needs a value since this
    /// struct is never constructed outside `sftp::queue` (see `QueuedItem`'s
    /// doc comment), so there's no `Default` impl to lean on elsewhere.
    fn test_job(id: u64, state: JobState) -> TransferJob {
        TransferJob {
            id,
            kind: JobKind::Upload,
            session_id: "s1".into(),
            server_name: "srv".into(),
            local_path: "/local/a".into(),
            remote_path: "/remote/a".into(),
            size: 100,
            bytes_done: 0,
            state,
            error: None,
            cancel: None,
            pause: None,
            started_at: None,
            target_session_id: None,
            target_server_name: None,
            target_remote_path: None,
            resume: None,
            preserve_ts: None,
            attempts: 0,
            retry_at: None,
            verify: None,
            last_persist_at: None,
        }
    }

    #[test]
    fn classify_error_recognizes_retryable_phrases() {
        // The task's own examples, plus the shapes std::io::Error /
        // sftp_error_detail actually render for them.
        for msg in [
            "Connection reset by peer (os error 104)",
            "connection closed",
            "Broken pipe (os error 32)",
            "Operation timed out (os error 110)",
            "read for hashing failed: timeout",
            "temporary failure in name resolution",
            "unexpected EOF at 10 of 11 skipped bytes",
        ] {
            assert_eq!(
                classify_error(msg),
                ErrorClass::Retryable,
                "expected retryable: {msg:?}"
            );
        }
    }

    #[test]
    fn classify_error_recognizes_terminal_phrases() {
        for msg in [
            "Permission denied (code 3)",
            "SFTP server returned no such file",
            "disk full",
            "quota exceeded",
            "invalid handle",
            "unsupported operation",
            "checksum mismatch: local abc != remote def (upload removed)",
        ] {
            assert_eq!(
                classify_error(msg),
                ErrorClass::Terminal,
                "expected terminal: {msg:?}"
            );
        }
    }

    #[test]
    fn classify_error_defaults_unrecognized_to_terminal() {
        // Conservative by design: an error this function has never seen
        // before must not be auto-retried.
        assert_eq!(
            classify_error("some brand new SFTP extension error nobody has seen"),
            ErrorClass::Terminal
        );
    }

    #[test]
    fn classify_error_terminal_wins_when_both_match() {
        assert_eq!(
            classify_error("no such file (connection reset while retrying)"),
            ErrorClass::Terminal
        );
    }

    #[test]
    fn backoff_schedule_is_2_4_8_seconds() {
        assert_eq!(backoff_delay(1), std::time::Duration::from_secs(2));
        assert_eq!(backoff_delay(2), std::time::Duration::from_secs(4));
        assert_eq!(backoff_delay(3), std::time::Duration::from_secs(8));
    }

    #[test]
    fn rate_bucket_step_unlimited_never_waits() {
        let (after, wait) = rate_bucket_step(0.0, 10.0, 0, 10_000_000);
        assert_eq!(after, 0.0);
        assert!(wait.is_none());
    }

    #[test]
    fn rate_bucket_step_empty_bucket_waits_proportionally() {
        // 256 KiB at a 1,000,000 B/s cap from a freshly-created (empty)
        // bucket: no time has elapsed to refill, so the whole chunk is debt.
        let bytes = 256 * 1024u64;
        let (after, wait) = rate_bucket_step(0.0, 0.0, 1_000_000, bytes);
        assert!(after < 0.0);
        let wait = wait.expect("an empty bucket must wait for a nonzero chunk");
        let expected = bytes as f64 / 1_000_000.0;
        assert!(
            (wait.as_secs_f64() - expected).abs() < 1e-9,
            "expected ~{expected}s, got {:?}",
            wait
        );
    }

    #[test]
    fn rate_bucket_step_refill_lets_a_small_chunk_through_free() {
        // A full bucket (tokens == cap) can absorb a chunk smaller than the
        // cap with no wait at all.
        let (after, wait) = rate_bucket_step(1_000_000.0, 0.0, 1_000_000, 1_000);
        assert_eq!(after, 999_000.0);
        assert!(wait.is_none());
    }

    #[test]
    fn rate_bucket_step_refill_caps_at_one_second() {
        // A long idle gap (e.g. a paused job) must not bank an unbounded
        // burst credit — refill never exceeds one second's worth of the cap.
        let (after, wait) = rate_bucket_step(0.0, 1000.0, 1_000_000, 0);
        assert_eq!(after, 1_000_000.0);
        assert!(wait.is_none());
    }

    #[test]
    fn dispatch_skips_paused_and_pending_backoff_jobs() {
        let now = std::time::SystemTime::now();
        assert!(!is_dispatchable(&test_job(1, JobState::Paused), now));
        assert!(!is_dispatchable(&test_job(2, JobState::Active), now));
        assert!(!is_dispatchable(&test_job(3, JobState::Done), now));
        assert!(!is_dispatchable(&test_job(4, JobState::Failed), now));
        assert!(!is_dispatchable(&test_job(5, JobState::Cancelled), now));

        // A freshly enqueued Queued job (no retry_at) is eligible right away.
        assert!(is_dispatchable(&test_job(6, JobState::Queued), now));

        // A Queued job mid-backoff is skipped until its retry_at passes.
        let mut retrying = test_job(7, JobState::Queued);
        retrying.retry_at = Some(now + std::time::Duration::from_secs(2));
        assert!(!is_dispatchable(&retrying, now));
        assert!(is_dispatchable(
            &retrying,
            now + std::time::Duration::from_secs(3)
        ));
    }
}
