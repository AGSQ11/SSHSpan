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
    /// Stable string form for the `transfer_queue.kind` column - matches the
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
    /// Suspended by the user (or restored from a previous run - see
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
    /// Stable string form for the `transfer_queue.state` column - matches
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
/// - `Overwrite` - truncate and start from byte 0 (the pre-resume behavior).
/// - `Resume` - continue a partial destination when its size aligns with
///   the source (a larger or size-unknown partial falls back to Overwrite).
/// - `Ask` - the UI layer resolves this to a concrete choice before
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

    /// Stable string form for the `transfer_queue.resume` column - round-
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
/// without a wider refactor of every `?`-using call site - see
/// `classify_error`'s doc comment for the same tradeoff applied to
/// retry/terminal classification.
const CANCELLED_SENTINEL: &str = "cancelled";
/// Distinct from `CANCELLED_SENTINEL`: a paused job's `.part` must survive
/// and its position must be preserved (see `JobState::Paused`), so `run_job`
/// must never treat the two the same way.
const PAUSED_SENTINEL: &str = "paused";

/// Start of the error `copy_chunks` returns when its source ENDED BEFORE the
/// expected size (A7-18). Like the sentinels above it is matched on by text -
/// through [`is_incomplete_transfer`], so the producer and the consumers share
/// one definition.
const INCOMPLETE_TRANSFER: &str = "incomplete transfer";

fn incomplete_transfer_error(done: u64, expected: u64) -> String {
    format!("{INCOMPLETE_TRANSFER}: got {done} of {expected} bytes")
}

fn is_incomplete_transfer(err: &str) -> bool {
    err.starts_with(INCOMPLETE_TRANSFER)
}

/// Whether a failed first leg of a server-to-server copy should be retried on
/// the interactive browse channel. That retry exists for servers that
/// read-block FRESH channels, so it fits a failing read - and nothing else: a
/// user's pause/cancel must be honoured, and a source that simply ENDED EARLY
/// (a file truncated or rotated mid-copy) would only be re-read from the start
/// over the other channel to end early again.
fn leg1_retries_on_interactive_channel(err: &str) -> bool {
    err != CANCELLED_SENTINEL && err != PAUSED_SENTINEL && !is_incomplete_transfer(err)
}

/// Derive the `.part` staging path for a destination. The staging file stays
/// in the destination's own directory so the final rename is a same-directory
/// (atomic on POSIX, MoveFileEx-like on Windows) operation, never a
/// cross-volume move.
pub fn part_path(dest: &str) -> String {
    format!("{dest}{PART_SUFFIX}")
}

/// The directories above `remote_path`, outermost first - exactly the levels
/// [`ensure_remote_dir`] has to make sure exist before a file can be opened
/// there. `/srv/up/a/file.txt` → `/srv`, `/srv/up`, `/srv/up/a`; a path with
/// no directory part yields nothing. Relative paths stay relative (they
/// resolve against the SFTP session's start directory), so `a/b/f` yields `a`,
/// `a/b` rather than `/a`, `/a/b`.
fn remote_parent_chain(remote_path: &str) -> Vec<String> {
    let Some((parent, _file)) = remote_path.rsplit_once('/') else {
        return Vec::new();
    };
    let mut chain = Vec::new();
    let mut cur = if remote_path.starts_with('/') {
        String::from("/")
    } else {
        String::new()
    };
    for seg in parent.split('/').filter(|s| !s.is_empty()) {
        if !(cur.is_empty() || cur.ends_with('/')) {
            cur.push('/');
        }
        cur.push_str(seg);
        chain.push(cur.clone());
    }
    chain
}

/// Best-effort ensure the parent directory of `remote_path` exists on the
/// target SFTP server, creating each missing level. Errors are logged and
/// swallowed - the subsequent open will surface a real failure if the dir is
/// genuinely not creatable. Used so a folder Send-to AND a folder upload can
/// place nested files under directories that don't exist yet on the target:
/// an SFTP server does not create missing parents on open, and the upload
/// expansion enqueues one job per FILE (A7-09 - without this every file of an
/// uploaded folder failed with "No such file").
async fn ensure_remote_dir(sftp: &russh_sftp::client::SftpSession, remote_path: &str) {
    // Walk down from the outermost level, creating each missing component.
    for cur in remote_parent_chain(remote_path) {
        match sftp.metadata(&cur).await {
            Ok(md) if md.is_dir() => continue,
            // No file-type bits: this server does not say what the entry is,
            // so it is walked through - every existing folder of such a
            // server used to look like "not a directory" and stop the walk at
            // the first level. If it is not a folder, the next mkdir or the
            // final open reports that.
            Ok(md) if md.permissions.is_none_or(|mode| mode & 0o170000 == 0) => continue,
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
        return Err("source size unknown; cannot verify .part alignment - starting over".into());
    }
    if part_len >= total {
        return Err(format!(
            ".part ({part_len} B) is not smaller than the source ({total} B) - starting over"
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
        Ok(_) => Err(format!("{lpart} exists but is not a file - starting over")),
        Err(_) => Ok(0),
    }
}

/// Resume offset for a REMOTE `.part` (upload direction, incl. the
/// server-copy target leg). A missing `.part` yields Ok(0). Only a REGULAR
/// file is continued: it is examined with LSTAT, never STAT - STAT follows a
/// link planted at `<remote>.part`, and the upload was then appended to the
/// link's target.
async fn remote_part_offset(
    sftp: &russh_sftp::client::SftpSession,
    rpart: &str,
    total: u64,
) -> Result<u64, String> {
    if sftp.symlink_metadata(rpart).await.is_err() {
        return Ok(0);
    }
    match crate::commands::sftp::regular_file_attrs(sftp, rpart, None).await {
        Ok(md) => match md.size {
            Some(len) => part_alignment(len, total),
            None => Err(format!("size of {rpart} unknown - starting over")),
        },
        Err(why) => Err(format!("{why} - starting over")),
    }
}

/// Rename a COMPLETE remote file `from` onto `to`, replacing whatever is at
/// `to`. SFTP v3 says RENAME must fail when the target exists and OpenSSH's
/// sftp-server follows that, so on a failed rename the target is removed and
/// the rename retried. The removal only happens while `from` is still there:
/// if it vanished (or the failure was a dropped connection) deleting the old
/// target would lose data for nothing. Shared by the upload leg, the
/// server-to-server leg and the edit-and-sync upload so none of them can
/// forget the retry - or, as two of them did, return early from it and skip
/// the verification and timestamp steps that follow.
///
/// `from` must be a REGULAR file, checked with LSTAT before anything is
/// renamed or removed: a temporary file swapped for a symbolic link (in a
/// folder others can write to) used to pass - STAT follows the link - and the
/// retry then deleted the real `to` and put the link in its place. A
/// residual window remains between that check and the RENAME (SFTP v3 has no
/// check-and-rename); the names are unpredictable or created exclusively, so
/// something has to be swapped in during it.
///
/// The error is the first rename's failure, rendered for the user.
///
/// `written`: the bytes just written to `from`, when known - on a server
/// that leaves the type bits out it is how `from` is recognised as the file
/// that was written (see [`crate::commands::sftp::regular_file_attrs`]).
pub(crate) async fn rename_over(
    sftp: &russh_sftp::client::SftpSession,
    from: &str,
    to: &str,
    written: Option<u64>,
) -> Result<(), String> {
    crate::commands::sftp::regular_file_attrs(sftp, from, written)
        .await
        .map_err(|why| format!("{why}, so {to} was left as it was"))?;
    let first = match sftp.rename(from, to).await {
        Ok(()) => return Ok(()),
        Err(e) => crate::commands::sftp::sftp_error_detail(e),
    };
    if crate::commands::sftp::regular_file_attrs(sftp, from, written)
        .await
        .is_ok()
        && sftp.remove_file(to).await.is_ok()
        && sftp.rename(from, to).await.is_ok()
    {
        return Ok(());
    }
    Err(first)
}

/// Everything an upload needs settled before its first byte, returning the
/// `.part` path to write and the offset to continue from (0 = start fresh):
/// the destination directory must exist, and the resume offset is decided
/// against whatever `.part` an earlier attempt left - only a regular file is
/// continued (see [`remote_part_offset`]). Starting from 0 removes a stale
/// `.part` when it is a regular file, a symbolic link (REMOVE never follows a
/// link, so a planted link goes and its target is never touched) or of a type
/// the server does not tell (REMOVE cannot remove a folder either: such a
/// `.part` used to block every later upload); a folder or a special file is
/// left, and the exclusive create in [`open_upload_part`] then says that
/// something is in the way.
///
/// The expansion of a folder upload enqueues one job per FILE and never
/// touches the server, and an SFTP server does not create missing parents on
/// open - so without making the directory here every file of an uploaded
/// folder failed with "No such file" (A7-09).
async fn prepare_upload(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    local_size: u64,
    resume: Option<ResumeMode>,
) -> (String, u64) {
    let rpart = part_path(remote);
    ensure_remote_dir(sftp, remote).await;
    let offset = match resume {
        Some(ResumeMode::Resume) => match remote_part_offset(sftp, &rpart, local_size).await {
            Ok(off) => off,
            Err(note) => {
                log::info!("[sshspan-sftp] upload {remote}: {note}");
                0
            }
        },
        _ => 0,
    };
    if offset == 0 {
        use crate::commands::sftp::{lstat_kind, EntryKind};
        if let Some(EntryKind::File | EntryKind::Symlink | EntryKind::Unknown) =
            lstat_kind(sftp, &rpart).await
        {
            if let Err(e) = sftp.remove_file(&rpart).await {
                log::debug!("[sshspan-sftp] upload pre-clean of {rpart}: {e}");
            }
        }
    }
    (rpart, offset)
}

/// The error for a `.part` that cannot be safely created or continued.
fn part_in_the_way(rpart: &str) -> String {
    format!(
        "A temporary file is in the way: {rpart} exists on the server and is not a partial \
         upload SSHSpan can continue or replace. Move or delete it, then retry."
    )
}

/// Bytes before the resume point that are read back from a `.part` and
/// compared with the source before it is continued.
const RESUME_CHECK_BYTES: u64 = 64 * 1024;

/// Open the `.part` an upload writes, and leave the source `local` at the
/// offset the upload goes on from - returned with the file: `offset`, or 0
/// when that `.part` could not be continued and was replaced.
///
/// A fresh one (`offset` 0) is created EXCLUSIVELY (CREATE|EXCL): an existing
/// name - a link or file someone planted after the pre-clean, or anything the
/// pre-clean would not remove - fails the open instead of being truncated or
/// written through. A continued one is opened READ|WRITE|APPEND, and before
/// anything is written its FSTAT size (of the file actually opened) must be
/// `offset` AND the last `min(offset, 64 KiB)` bytes before it, read back
/// through that very handle, must be the source's bytes at the same offsets.
/// The size alone used to decide, and whoever planted the `.part` controls
/// it: a `.part` the size of a victim file, swapped for a link to the victim
/// between the LSTAT and the OPEN, had the upload appended to the victim
/// (and a `.part` of other content was continued into a corrupt file). One
/// that fails either check is not this upload's: it is removed (REMOVE never
/// follows a link) and the upload starts over, exclusively.
async fn open_upload_part<L>(
    sftp: &russh_sftp::client::SftpSession,
    rpart: &str,
    offset: u64,
    local: &mut L,
) -> Result<(russh_sftp::client::fs::File, u64), String>
where
    L: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    use crate::commands::sftp::sftp_error_detail;
    if offset > 0 {
        let mut file = sftp
            .open_with_flags(
                rpart,
                OpenFlags::READ | OpenFlags::WRITE | OpenFlags::APPEND,
            )
            .await
            .map_err(sftp_error_detail)?;
        let size_ok = matches!(file.metadata().await, Ok(md) if md.size == Some(offset));
        if size_ok && continues_source(&mut file, local, offset).await {
            return Ok((file, offset));
        }
        let _ = file.close().await;
        log::warn!("[sshspan-sftp] {rpart} is not this file's partial upload - starting over");
        if let Err(e) = sftp.remove_file(rpart).await {
            log::debug!("[sshspan-sftp] could not remove {rpart}: {e}");
        }
    }
    local
        .seek(SeekFrom::Start(0))
        .await
        .map_err(|e| format!("local seek failed: {e}"))?;
    match sftp
        .open_with_flags(
            rpart,
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
        )
        .await
    {
        Ok(file) => Ok((file, 0)),
        Err(_) if sftp.symlink_metadata(rpart).await.is_ok() => Err(part_in_the_way(rpart)),
        Err(e) => Err(sftp_error_detail(e)),
    }
}

/// Whether the `min(offset, RESUME_CHECK_BYTES)` bytes before `offset` are
/// the same in the opened remote `.part` and in the local source. Leaves
/// both at `offset` when they are.
async fn continues_source<L>(
    remote: &mut russh_sftp::client::fs::File,
    local: &mut L,
    offset: u64,
) -> bool
where
    L: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    use tokio::io::AsyncReadExt;
    let len = offset.min(RESUME_CHECK_BYTES);
    let start = offset - len;
    let mut theirs = vec![0u8; len as usize];
    let mut ours = vec![0u8; len as usize];
    let remote_read = async {
        remote.seek(SeekFrom::Start(start)).await?;
        remote.read_exact(&mut theirs).await.map(drop)
    }
    .await;
    let local_read = async {
        local.seek(SeekFrom::Start(start)).await?;
        local.read_exact(&mut ours).await.map(drop)
    }
    .await;
    remote_read.is_ok() && local_read.is_ok() && theirs == ours
}

/// Position an open remote file at `offset` for a resumed download WITHOUT
/// reading the part that is already on disk (A7-35). russh-sftp's `File`
/// implements `AsyncSeek`, and `SeekFrom::Start` is a free local assignment:
/// every later read just asks the server for that offset. (The code used to
/// read-and-discard the prefix on the false belief that the crate cannot
/// seek - re-transferring it all, ignoring pause, cancel and the bandwidth
/// cap, with the job frozen at its old progress meanwhile.)
async fn seek_remote<S: tokio::io::AsyncSeek + Unpin>(
    file: &mut S,
    offset: u64,
) -> Result<(), String> {
    file.seek(SeekFrom::Start(offset))
        .await
        .map(|_| ())
        .map_err(|e| format!("resume seek on remote failed: {e}"))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferJob {
    pub id: u64,
    pub kind: JobKind,
    pub session_id: String,
    pub server_name: String,
    /// Saved-server id the job's `session_id` was opened for, stamped by
    /// `enqueue` from the session registry. Session ids are per-run, so this is
    /// what lets a Paused/restored job be matched to a RECONNECTED session of
    /// the same server (see `rebind_job`). `None` for jobs persisted before the
    /// field existed - those can only be cancelled or re-queued by hand.
    pub server_id: Option<String>,
    pub local_path: String,
    pub remote_path: String,
    pub size: u64,
    pub bytes_done: u64,
    pub state: JobState,
    pub error: Option<String>,
    /// Cancel flag shared with the active worker.
    #[serde(skip)]
    pub cancel: Option<Arc<AtomicBool>>,
    /// Pause flag shared with the active worker - deliberately separate from
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
    /// ServerCopy only: saved-server id of the target session (see
    /// `server_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_server_id: Option<String>,
    /// ServerCopy only: absolute remote destination path on the target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_remote_path: Option<String>,
    /// How to treat an existing destination / leftover `.part` (None =
    /// Overwrite, the pre-resume behavior).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume: Option<ResumeMode>,
    /// Preserve timestamps (FileZilla "Preserve timestamps of transferred
    /// files"): after a successful transfer, carry the source mtime over to
    /// the destination - onto the REMOTE file via setstat after an upload /
    /// server-copy target leg, onto the LOCAL file via `File::set_modified`
    /// after a download. Additive Option so construction sites that don't care
    /// keep compiling (default false).
    #[serde(skip)]
    pub preserve_ts: Option<bool>,
    /// Automatic-retry counter (distinct from a user clicking Retry, which
    /// resets this to 0): incremented each time `handle_job_failure`
    /// re-queues a retryable failure. Auto-retry stops once this reaches
    /// `MAX_AUTO_RETRIES` and the job lands in `Failed` with the last error.
    pub attempts: u32,
    /// When set, the earliest instant `dispatch` may start this Queued job -
    /// the backoff timer for an in-flight auto-retry. `None` means eligible
    /// immediately (a freshly enqueued job, or one resumed by the user).
    /// A `SystemTime` (not `Instant`) so it round-trips through
    /// `emit_queue`'s JSON and survives a restore from `restore_pending`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<std::time::SystemTime>,
    /// Opt-in post-transfer SHA-256 check (`setting.sftpVerifyTransfers`),
    /// stamped from the setting at enqueue time so every job in a batch is
    /// consistent even if the setting changes mid-batch. `None` behaves as
    /// `Some(false)` (off) - kept optional so a restored job whose persisted
    /// row predates this column still reconstructs cleanly via
    /// `restore_pending`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<bool>,
    /// Last time this job's `bytes_done` was written to the `transfer_queue`
    /// table (see `update_progress`). Progress ticks arrive many times a
    /// second; persisting every one would hammer the disk for no benefit; a
    /// crash between two persisted points just re-downloads/re-uploads a
    /// little more on the next resume, which is cheap. Not part of the wire
    /// format - purely internal bookkeeping.
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
            "serverId": self.server_id,
            "localPath": self.local_path,
            "remotePath": self.remote_path,
            "size": self.size,
            "bytesDone": self.bytes_done,
            "state": self.state,
            "error": self.error,
            "speed": speed,
            "targetSessionId": self.target_session_id,
            "targetServerName": self.target_server_name,
            "targetServerId": self.target_server_id,
            "targetRemotePath": self.target_remote_path,
            "resume": self.resume,
            "attempts": self.attempts,
            // Millis-since-epoch (or null) rather than SystemTime's default
            // {secs_since_epoch, nanos_since_epoch} shape - a plain number is
            // what a renderer countdown wants, and it can't go negative or
            // fail to serialize the way a pre-epoch SystemTime subtraction
            // could.
            "retryAt": self.retry_at.and_then(system_time_to_millis),
            "verify": self.verify.unwrap_or(false),
        })
    }

    /// Snapshot the persisted subset of this job as a `transfer_queue` row
    /// (see `db::QueueJobRow`). `session_id`/`target_session_id` are stored
    /// as-is even though they're only valid for the run that created them -
    /// turning a stale one into a "needs reconnect" job is `restore_pending`'s
    /// job on the NEXT startup, not this method's. The saved-server ids are
    /// stored alongside precisely because they outlive the run: they are what
    /// `rebind_job` matches a reconnected session against.
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
            server_id: self.server_id.clone(),
            target_server_id: self.target_server_id.clone(),
        }
    }
}

/// Milliseconds since the Unix epoch, or `None` for a `SystemTime` that
/// somehow predates it (never happens in practice - `retry_at` is always
/// `SystemTime::now() + a few seconds` - but `duration_since` is fallible and
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
    /// Generation counter - dispatcher restart when jobs are added.
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
    /// [`rate_bucket_step`] - never across the `.await` below - so a
    /// concurrent [`set_rate_limit`] or another worker's chunk is never
    /// blocked behind a sleeping one.
    async fn throttle_bandwidth(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let cap = self.rate_bps.load(Ordering::SeqCst);
        if cap == 0 {
            return; // unlimited - the common case, skip the lock entirely
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
/// spent, returns the updated token balance and - if spending would drive it
/// negative - how long to sleep to work the debt off at the current rate.
/// `cap_bps == 0` (unlimited) always returns `(tokens, None)` unchanged.
/// Refill is capped at one second's worth of tokens so a long idle gap (a
/// paused job, a queue with nothing to send) can't bank an unbounded burst
/// credit for later - the cap is a running average, not a once-a-while
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
// swallowed exactly like the tolerant SETSTAT calls elsewhere in this file -
// it must never fail (or roll back) the transfer it's shadowing. Persistence
// only exists to survive a restart (see `restore_pending`).

/// Upsert one job's persisted row. Called on every meaningful state
/// transition (enqueue, dispatch → Active, pause/resume, cancel/retry,
/// completion) and, throttled, on progress - never anywhere hotter than that.
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
/// or "1" (case-insensitive) - verification re-reads every byte on both
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
/// 0 (unlimited) takes effect the very next chunk any of them copies - never
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
/// `parallel_limit` uses for `sftpParallel`) - see `verify_enabled`.
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
    /// Keep the source mtime on the destination (default false): the remote
    /// file's on an upload / server-copy target leg, the local file's on a
    /// download.
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
    // Remember which SAVED SERVER each session belongs to: the session ids die
    // with the connection, the server ids are what a reconnected session is
    // matched on (A7-17). Looked up BEFORE the queue lock is taken, so the
    // session-registry lock is never held inside it.
    let server_ids = {
        let registry = app.state::<Arc<SessionRegistry>>();
        endpoint_server_ids(&items, |session| registry.server_id_of(session))
    };
    let mut new_rows = Vec::new();
    {
        let mut guard = q.jobs.lock().unwrap();
        for (item, (server_id, target_server_id)) in items.into_iter().zip(server_ids) {
            let id = q.next_id.fetch_add(1, Ordering::SeqCst);
            let job = new_job(id, item, server_id, target_server_id, verify);
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

/// The saved-server id of each item's session and, for a server copy, of its
/// target session - what [`enqueue`] stamps on the new jobs. `server_id_of` is
/// the session registry's lookup (a parameter so the mapping is testable).
fn endpoint_server_ids(
    items: &[QueuedItem],
    server_id_of: impl Fn(&str) -> Option<String>,
) -> Vec<(Option<String>, Option<String>)> {
    items
        .iter()
        .map(|item| {
            (
                server_id_of(&item.session_id),
                item.target
                    .as_ref()
                    .and_then(|t| server_id_of(&t.session_id)),
            )
        })
        .collect()
}

/// A freshly queued job for `item`, carrying the saved-server ids its
/// endpoints were looked up as.
fn new_job(
    id: u64,
    item: QueuedItem,
    server_id: Option<String>,
    target_server_id: Option<String>,
    verify: bool,
) -> TransferJob {
    TransferJob {
        id,
        kind: item.kind,
        session_id: item.session_id,
        server_name: item.server_name,
        server_id,
        target_server_id,
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
    }
}

/// Whether `dispatch` may start this job right now: it must be Queued, and
/// if it's mid-backoff from an auto-retry (`retry_at` set by
/// `handle_job_failure`), that instant must have passed. Paused jobs never
/// match - pulling this predicate out as a free function of plain data (no
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
/// untouched - each transfer gets its own channel over the same connection).
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
/// the final read never crosses EOF - some SFTP servers answer such reads
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
    copy_chunks(
        reader,
        writer,
        &cancel,
        &pause,
        max_read,
        progress_offset,
        |position, speed| update_progress(app, job_id, position, Some(speed)),
        |bytes| async move {
            // Global bandwidth pacing: a no-op (no lock taken) when unlimited.
            app.state::<TransferQueue>().throttle_bandwidth(bytes).await
        },
    )
    .await
}

/// The copy loop behind [`copy_with_progress`], with everything that needs a
/// Tauri app (progress events, the shared bandwidth bucket) passed in as
/// closures so the loop itself - clamping, pause/cancel, short-copy detection -
/// can be unit-tested against in-memory readers and writers.
///
/// `on_progress(position, bytes_per_sec)` fires about every 200 ms with the
/// job-relative position (`progress_offset` + bytes copied here);
/// `throttle(bytes)` is awaited after every chunk.
#[allow(clippy::too_many_arguments)]
async fn copy_chunks<R, W, P, T, TF>(
    reader: &mut R,
    writer: &mut W,
    cancel: &AtomicBool,
    pause: &AtomicBool,
    max_read: Option<u64>,
    progress_offset: u64,
    mut on_progress: P,
    throttle: T,
) -> Result<u64, String>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    P: FnMut(u64, f64),
    T: Fn(u64) -> TF,
    TF: std::future::Future<Output = ()>,
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
        // saturating: an unknown-size leg 2 passes `u64::MAX` as its offset.
        let off = progress_offset.saturating_add(done);
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

        throttle(n as u64).await;

        let now = std::time::Instant::now();
        if last_emit.elapsed().as_millis() >= 200 {
            let dt = now.duration_since(last_emit).as_secs_f64();
            if dt > 0.0 {
                speed = (done - last_bytes) as f64 / dt;
            }
            on_progress(progress_offset.saturating_add(done), speed);
            last_emit = now;
            last_bytes = done;
        }
    }
    writer.flush().await.map_err(|e| e.to_string())?;
    // russh-sftp 2.4.0 File: poll_shutdown drains pending write ACKs and
    // sends the SFTP CLOSE. It keeps no "already closed" guard, so a
    // caller-side `rf.close()` AFTER this sends a SECOND CLOSE for a handle
    // the server has already released, and the server answers that with a
    // failure (pinned by `sftp::testkit`'s double-close test). That is why the
    // callers treat a failed close after a completed copy as non-fatal and
    // check the staged size instead.
    writer.shutdown().await.map_err(|e| e.to_string())?;
    // Short-copy detection (A7-18): hitting EOF before `max_read` bytes means
    // the source ended early - a remote file truncated or rotated mid-download,
    // a server answering an early EOF, a local file that shrank during an
    // upload. This used to return `Ok(done)` and the callers went on to rename
    // the `.part` into place and finish the job as Done with a short file and
    // no warning. Checked AFTER the flush so what did arrive is on disk and a
    // later Resume can continue from it; `u64::MAX` is the "size unknown"
    // sentinel, where reading until EOF is the only option.
    if let Some(expected) = max_read {
        if expected != u64::MAX && done < expected {
            return Err(incomplete_transfer_error(done, expected));
        }
    }
    Ok(done)
}

/// How often a job's `bytes_done` is written to the `transfer_queue` table.
/// Progress ticks fire every ~200ms (see `copy_with_progress`); persisting
/// every one would be a DB write several times a second per active transfer
/// for no real benefit - a crash between two persisted points just costs a
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

/// Set a job's resting state - a terminal one (Done/Failed/Cancelled) or the
/// Paused suspension - and emit it. Also used for Paused because pausing
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
                    // ServerCopy that is 2× the source size (both legs done) -
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
    // Something finished (or paused) - try to start the next queued job.
    dispatch(app);
}

/// Deletes a staged temp file when dropped (best-effort). Guarantees the
/// staging file never outlives the job: success, failure, cancel, and
/// worker panic all drop the guard, so the file is removed on every exit
/// path (FileZilla removes the temp file once the transfer is cleared).
struct StageGuard(std::path::PathBuf);

/// Core setstat: push `secs` as mtime (and atime) onto a remote path.
/// Tolerant - some servers refuse SETSTAT, which must never fail a
/// completed transfer.
async fn set_remote_mtime(sftp: &russh_sftp::client::SftpSession, dest_remote: &str, secs: u32) {
    let mut attrs = russh_sftp::protocol::FileAttributes::default();
    attrs.mtime = Some(secs);
    attrs.atime = Some(secs);
    match sftp.set_metadata(dest_remote, attrs).await {
        Ok(()) => log::info!("[sshspan-sftp] preserved mtime {secs} on {dest_remote}"),
        Err(e) => log::warn!(
            "[sshspan-sftp] setstat mtime on {dest_remote} refused ({e}) - \
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
            "[sshspan-sftp] could not read source mtime {}: {e} - timestamps not preserved",
            source_local.display()
        ),
    }
}

/// The remote mtime worth stamping onto a downloaded file: `None` when the
/// server did not send one, and also for `0`, which servers that fill in
/// "dummy" attributes send for "unknown" - stamping 1970 onto a file would be
/// worse than leaving its fresh timestamp.
fn preservable_mtime(remote_mtime: Option<u32>) -> Option<u32> {
    remote_mtime.filter(|&secs| secs != 0)
}

/// Set a finished local file's modification time to `secs` (Unix seconds) -
/// the download half of "preserve timestamps". `File::set_modified` is stable
/// and portable (Windows `SetFileTime`, Unix `futimens`), which is what the
/// old "std has no portable mtime setter" note got wrong. The file is opened
/// for write (Windows needs write access for `SetFileTime`) but not truncated.
fn set_local_mtime(path: &std::path::Path, secs: u32) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(secs)))
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
    let mut lf = crate::sftp::create_transfer_file(std::path::Path::new(stage))
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
/// session. Never touches the interactive SftpRegistry sessions - both legs
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
    // worker") - write the stat'd size back into the job record so the queue
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
        // Two failures that are not "this server read-blocks fresh channels"
        // (see `leg1_retries_on_interactive_channel`): a user-requested stop,
        // and a source that ENDED EARLY. Clean up and return - the
        // diagnostic/fallback path below exists to tell a read-blocked channel
        // apart from "the read pattern itself is broken", so it must never
        // fire just because the user paused or cancelled mid-read (retrying
        // via the interactive session at that point would ignore the request
        // and keep transferring), nor re-read the whole file only to end early
        // again.
        if !leg1_retries_on_interactive_channel(&fresh_err) {
            let _ = lf.flush().await;
            drop(lf);
            if let Err(e) = rf.close().await {
                log::debug!("[sshspan-sftp] sendto leg1 close after {fresh_err}: {e}");
            }
            drop(sftp);
            // A stop reaches `run_job` as the bare sentinel, which it matches
            // on; a source that ended early is a genuine failure and says so.
            return Err(if is_incomplete_transfer(&fresh_err) {
                log::warn!(
                    "[sshspan-sftp] sendto leg1 source {source_remote} ended early: {fresh_err}"
                );
                format!("source read: {fresh_err} (stat size {size})")
            } else {
                fresh_err
            });
        }
        // DIAGNOSTIC + FALLBACK: the fresh transfer channel failed the read.
        // Retry the identical clamped read on the interactive browse session -
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
    // rather than a truncated "complete" file on the target. Resume only the
    // TARGET leg (the local staging file above is always rebuilt from scratch
    // by leg 1 - it is removed on every exit path). The same preparation as
    // an upload: the destination's parent folders are made (a folder Send-to
    // expands into nested per-file jobs, and the server does not create
    // missing parents on open), and the `.part` is checked before it is
    // continued or replaced.
    let (tpart, offset) = prepare_upload(&target_sftp, &target.remote_path, size, resume).await;
    // Leaves `lf` at the offset the upload goes on from (0 when the `.part`
    // was not this copy's and was replaced).
    let (mut rf, offset) = open_upload_part(&target_sftp, &tpart, offset, &mut lf)
        .await
        .map_err(|d| {
            log::error!("[sshspan-sftp] sendto leg2 open {tpart}: {d}");
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
        // (see the matching leg-1 guard above) - wrapping it into a
        // "target write: ..." message would hide the pause/cancel from the
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
    // the data is missing - leg-1 read-close and download_to already treat this
    // as benign. Verify the .part actually landed (size matches what we wrote)
    // before trusting it for the rename, so we never rename an empty file.
    if let Err(e) = rf.close().await {
        let expected = size;
        match target_sftp.symlink_metadata(&tpart).await {
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
    // uploaded at this point, so removing the final name first is a safe retry
    // (`rename_over`). Not an early return: verification and timestamps below
    // must run on that path too.
    let written = (size != u64::MAX).then_some(size);
    if let Err(d) = rename_over(&target_sftp, &tpart, &target.remote_path, written).await {
        log::error!(
            "[sshspan-sftp] sendto leg2 rename {tpart} -> {}: {d}",
            target.remote_path
        );
        return Err(format!("final rename failed: {d}"));
    }
    // Opt-in verification (`setting.sftpVerifyTransfers`): hash both remote
    // ends and compare before trusting the copy. The source channel was
    // already closed after leg 1, so this reopens a fresh one purely for the
    // hash - cheap next to re-reading the whole file, which is what a
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
        verify_copy(source_hash, &target_sftp, &target.remote_path, &cancel).await?;
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
                        let (rpart, offset) =
                            prepare_upload(&sftp, &remote, lsize, resume).await;
                        // Leaves `lf` at the offset the upload goes on from
                        // (0 when the `.part` was not this upload's).
                        let (mut rf, offset) = open_upload_part(&sftp, &rpart, offset, &mut lf)
                            .await
                            .map_err(|d| format!("remote open failed: {d}"))?;
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
                            match sftp.symlink_metadata(&rpart).await {
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
                        // Some servers refuse rename-over-an-existing file; the
                        // .part is complete here, so `rename_over` removing the
                        // final name first is a safe retry. Falling through
                        // (not returning) keeps the verification and timestamp
                        // steps below running on that path too.
                        rename_over(&sftp, &rpart, &remote, Some(lsize))
                            .await
                            .map_err(|d| format!("final rename failed: {d}"))?;
                        // Opt-in verification ([`verify_upload`]).
                        if verify {
                            verify_upload(&sftp, std::path::Path::new(&local), &remote, &cancel)
                                .await?;
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
                        // The write deny-list on the final path, again, before
                        // anything is opened: the job may run long after it
                        // was queued (resumed after a reconnect, restored
                        // after a restart), and nothing may be written into
                        // `~/.ssh`, a Startup folder, a shell rc file or
                        // SSHSpan's own folders (A6-02). Filesystem work, so
                        // on a blocking thread; a check that cannot run
                        // refuses.
                        let refused = {
                            let local = local.clone();
                            tokio::task::spawn_blocking(move || {
                                crate::commands::sftp::local_write_refusal(std::path::Path::new(
                                    &local,
                                ))
                            })
                            .await
                            .unwrap_or_else(|e| {
                                Some(format!("the local path could not be checked ({e})"))
                            })
                        };
                        if let Some(why) = refused {
                            return Err(format!("{local}: {why}"));
                        }
                        // Stat first: the size clamp and resume-alignment
                        // check both rely on it, and the mtime is what
                        // "preserve timestamps" stamps onto the finished file.
                        let remote_md = sftp.metadata(&remote).await.map_err(|e| {
                            format!(
                                "remote stat failed: {}",
                                crate::commands::sftp::sftp_error_detail(e)
                            )
                        })?;
                        let size = remote_md.size;
                        let remote_mtime = remote_md.mtime;
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
                        // Decide the REAL resume offset against the exact
                        // object we will append to, then open it without
                        // following a planted symlink.
                        //
                        // The `offset` above came from `local_part_offset`,
                        // which uses `metadata()` - that FOLLOWS a symlink at
                        // `dest/name.part`, so a planted link to a nonzero
                        // victim file would report the VICTIM's length and
                        // pass the alignment check, after which a plain
                        // `append(true).open()` would write remote bytes into
                        // the victim. `open_transfer_file_append` lstat-checks
                        // and opens with O_NOFOLLOW (Unix) so the append can
                        // never resolve through a link. If the existing
                        // `.part` is a link, a non-file, or its true length
                        // disagrees with the aligned offset, we fall back to a
                        // fresh download (offset 0).
                        let mut effective_offset = offset;
                        let mut lf = if offset > 0 {
                            match crate::sftp::open_transfer_file_append(std::path::Path::new(&lpart))
                                .await
                            {
                                Ok((file, md)) if md.len() == offset => {
                                    // Genuine resumable partial: continue where
                                    // it ended, without re-reading the prefix.
                                    seek_remote(&mut rf, offset).await?;
                                    file
                                }
                                Ok((_, md)) => {
                                    log::info!(
                                        "[sshspan-sftp] download {remote}: .part length {} != aligned offset {offset}; starting over",
                                        md.len()
                                    );
                                    effective_offset = 0;
                                    crate::sftp::create_transfer_file(std::path::Path::new(&lpart))
                                        .await
                                        .map_err(|e| format!("local create failed: {e}"))?
                                }
                                Err(e) => {
                                    log::info!(
                                        "[sshspan-sftp] download {remote}: unsafe .part ({e}); starting over"
                                    );
                                    effective_offset = 0;
                                    crate::sftp::create_transfer_file(std::path::Path::new(&lpart))
                                        .await
                                        .map_err(|e| format!("local create failed: {e}"))?
                                }
                            }
                        } else {
                            // Fresh start: replaces a leftover .part (the
                            // Overwrite mode's "delete/ignore the .part").
                            crate::sftp::create_transfer_file(std::path::Path::new(&lpart))
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
                            Some(size.saturating_sub(effective_offset)),
                            effective_offset,
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
                        // Opt-in verification ([`verify_download`]).
                        if verify {
                            verify_download(&sftp, &remote, std::path::Path::new(&local), &cancel)
                                .await?;
                        }
                        // Preserve timestamps (A7-36), after the rename and any
                        // verification so nothing later touches the file: stamp
                        // the REMOTE mtime onto the finished local file.
                        // `File::set_modified` is portable, so this needs no
                        // crate. Best-effort like the upload side - a refused
                        // timestamp must never fail a completed download.
                        if preserve_ts {
                            if let Some(secs) = preservable_mtime(remote_mtime) {
                                let target = std::path::PathBuf::from(&local);
                                match tokio::task::spawn_blocking(move || {
                                    set_local_mtime(&target, secs)
                                })
                                .await
                                {
                                    Ok(Ok(())) => log::info!(
                                        "[sshspan-sftp] preserved mtime {secs} on {local}"
                                    ),
                                    Ok(Err(e)) => log::warn!(
                                        "[sshspan-sftp] could not preserve mtime on {local}: {e}"
                                    ),
                                    Err(e) => log::warn!(
                                        "[sshspan-sftp] mtime task for {local} failed: {e}"
                                    ),
                                }
                            }
                        }
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

/// An upload's opt-in verification (`setting.sftpVerifyTransfers`), after
/// the rename: hash the local source and the remote destination and compare.
/// A mismatch removes the remote file rather than leaving a corrupt upload
/// that looks complete.
async fn verify_upload(
    sftp: &russh_sftp::client::SftpSession,
    local: &std::path::Path,
    remote: &str,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    let local_hash = local_sha256(local, cancel.clone()).await;
    let remote_hash =
        crate::commands::sftp::remote_sha256(sftp, remote, Some(cancel.as_ref())).await;
    match (local_hash, remote_hash) {
        (Ok(lh), Ok(rh)) if lh == rh => Ok(()),
        (Ok(lh), Ok(rh)) => {
            let _ = sftp.remove_file(remote).await;
            Err(format!(
                "checksum mismatch: local {lh} != remote {rh} (upload removed)"
            ))
        }
        (Err(e), _) => Err(format!("checksum mismatch: could not hash local file: {e}")),
        (_, Err(e)) => Err(format!(
            "checksum mismatch: could not hash remote file: {e}"
        )),
    }
}

/// A download's opt-in verification, after the rename: hash the local file
/// and the remote source and compare. A mismatch removes the local file
/// rather than leaving a corrupt download that looks complete.
async fn verify_download(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    local: &std::path::Path,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    let local_hash = local_sha256(local, cancel.clone()).await;
    let remote_hash =
        crate::commands::sftp::remote_sha256(sftp, remote, Some(cancel.as_ref())).await;
    match (remote_hash, local_hash) {
        (Ok(rh), Ok(lh)) if rh == lh => Ok(()),
        (Ok(rh), Ok(lh)) => {
            let _ = tokio::fs::remove_file(local).await;
            Err(format!(
                "checksum mismatch: remote {rh} != local {lh} (download removed)"
            ))
        }
        (Err(e), _) => Err(format!(
            "checksum mismatch: could not hash remote file: {e}"
        )),
        (_, Err(e)) => Err(format!("checksum mismatch: could not hash local file: {e}")),
    }
}

/// A server-to-server copy's opt-in verification: the source's hash (from
/// its own channel) against the target's. A mismatch removes the target
/// file: the copy must not sit there looking successful when it isn't.
async fn verify_copy(
    source_hash: Result<String, crate::commands::CmdError>,
    target_sftp: &russh_sftp::client::SftpSession,
    target_remote: &str,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    let target_hash =
        crate::commands::sftp::remote_sha256(target_sftp, target_remote, Some(cancel.as_ref()))
            .await;
    match (source_hash, target_hash) {
        (Ok(sh), Ok(th)) if sh == th => Ok(()),
        (Ok(sh), Ok(th)) => {
            let _ = target_sftp.remove_file(target_remote).await;
            Err(format!(
                "checksum mismatch: source {sh} != target {th} (copy removed)"
            ))
        }
        (Err(e), _) => Err(format!("checksum mismatch: could not hash source: {e}")),
        (_, Err(e)) => Err(format!("checksum mismatch: could not hash target: {e}")),
    }
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
/// OS-level/SFTP-protocol wording - `std::io::Error`'s `Display` and
/// `sftp_error_detail`'s output both surface it in the message itself - so
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
/// failure still gives up and lands the job in `Failed` - an unattended
/// batch must eventually surface a real, persistent problem instead of
/// retrying forever.
const MAX_AUTO_RETRIES: u32 = 3;

/// Exponential backoff schedule for auto-retry: the Nth retry (1-based, i.e.
/// the value `attempts` holds right after incrementing) waits `2^N` seconds
/// - 2s, 4s, 8s for N = 1, 2, 3.
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
/// job is actually cancelled/paused rather than genuinely failed - auto-retry
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
                    "{error} - retrying ({}/{MAX_AUTO_RETRIES})",
                    j.attempts
                ));
                j.cancel = None;
                j.pause = None;
                // Nudge the dispatcher once the backoff elapses so an
                // otherwise-idle queue doesn't wait on some unrelated event
                // to notice the job is due. `retry_at` (checked by
                // `is_dispatchable`) remains the actual source of truth, so a
                // missed or early wakeup here can't start the job too soon -
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
    // once dispatched again), but Failed/Cancelled/Paused all do - cheap to
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
                // Queued and Paused both have no worker to wind down, so the
                // transition happens here; an Active job is finalized by its
                // worker when it notices the flag. Paused matters especially
                // for a job restored from a previous run whose session is
                // gone: resume cannot start it, so without this it could
                // never leave the queue at all.
                if matches!(j.state, JobState::Queued | JobState::Paused) {
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

/// Failed/Cancelled → Queued. A user-initiated retry is a fresh start for the
/// auto-retry counter too: `attempts` resets to 0 and any pending backoff
/// (`retry_at`) is cleared, distinguishing this from `handle_job_failure`'s
/// automatic re-queue. A job whose session died is first re-pointed at a
/// reconnected session of the same saved server (see [`rebind_job`]); if there
/// is none it stays as it is with a reconnect note, since a retry could only
/// fail again with "Session closed.".
fn retry_failed(j: &mut TransferJob, live: &[LiveSession]) {
    if rebind_job(j, live) == Rebind::NeedsReconnect {
        j.error = Some(reconnect_note(&j.server_name, "retry"));
        return;
    }
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
}

/// Paused → Queued, forcing `ResumeMode::Resume` (the whole point of pausing
/// is that the `.part` survives, so the resumed attempt must continue from it
/// rather than restart from `Overwrite`/`Ask` semantics). A job whose session
/// died is first re-pointed at a reconnected session of the same saved server
/// (see [`rebind_job`]); if there is none it stays Paused with a reconnect
/// note instead of being started only to fail with "Session closed.".
fn resume_paused(j: &mut TransferJob, live: &[LiveSession]) {
    if rebind_job(j, live) == Rebind::NeedsReconnect {
        j.error = Some(reconnect_note(&j.server_name, "resume"));
        return;
    }
    j.state = JobState::Queued;
    j.error = None;
    j.retry_at = None;
    j.resume = Some(ResumeMode::Resume);
}

/// Re-queue a failed/cancelled job - see [`retry_failed`].
pub fn retry_job<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, job_id: u64) {
    let live = live_sessions(app);
    let q = app.state::<TransferQueue>();
    let row = {
        let mut guard = q.jobs.lock().unwrap();
        match guard.iter_mut().find(|j| j.id == job_id) {
            Some(j) if matches!(j.state, JobState::Failed | JobState::Cancelled) => {
                retry_failed(j, &live);
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

// ─── rebinding to reconnected sessions (A7-17) ──────────────────────────────
//
// A job names the SSH SESSION it runs on, and a session id is minted per
// connection. After a drop, a vault lock or an app restart the id is dead for
// good, so a paused/restored job pointing at it could never be resumed even
// after the user reconnected. Each job therefore also carries the id of the
// SAVED SERVER its session belonged to, and resume/retry re-point it at the
// newest live session of that same server.
//
// (This replaces `cancel_for_session`, which nothing ever called and whose
// "cancel everything on disconnect" meaning is the opposite of what the
// persistence feature promises: a dropped connection pauses nothing, fails
// the in-flight attempts, and leaves the rest resumable after reconnect.)

/// A live SSH session as far as rebinding queued transfers is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveSession {
    session_id: String,
    server_id: String,
    started_at_ms: i64,
}

/// Snapshot of the live sessions. Callers take it BEFORE they lock the queue
/// (`resume_job`, `resume_all`, `retry_job`; `enqueue` does the same for its
/// server-id lookup), so the session-registry lock is never held inside the
/// queue lock.
fn live_sessions<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Vec<LiveSession> {
    app.state::<Arc<SessionRegistry>>()
        .live_server_sessions()
        .into_iter()
        .map(|(session_id, server_id, started_at_ms)| LiveSession {
            session_id,
            server_id,
            started_at_ms,
        })
        .collect()
}

/// Whether a job can reach its server(s) right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rebind {
    /// Every endpoint has a live session (possibly just assigned).
    Ready,
    /// An endpoint's session is gone and no live session of the same saved
    /// server exists (or the job predates `server_id`), so nothing can be
    /// started until the user reconnects.
    NeedsReconnect,
}

/// Where one endpoint of a job should run now: the current session while it is
/// still live, otherwise the NEWEST live session of the same saved server
/// (never another server's - a transfer must not silently move hosts),
/// otherwise nowhere.
fn rebind_endpoint(current: &str, server_id: Option<&str>, live: &[LiveSession]) -> Option<String> {
    if live.iter().any(|s| s.session_id == current) {
        return Some(current.to_string());
    }
    let server_id = server_id?;
    live.iter()
        .filter(|s| s.server_id == server_id)
        .max_by_key(|s| s.started_at_ms)
        .map(|s| s.session_id.clone())
}

/// Point `job` at live sessions (see [`rebind_endpoint`]; a ServerCopy has two
/// endpoints and needs both). Mutates the job only on [`Rebind::Ready`].
fn rebind_job(job: &mut TransferJob, live: &[LiveSession]) -> Rebind {
    let source = rebind_endpoint(&job.session_id, job.server_id.as_deref(), live);
    let target = match job.target_session_id.as_deref() {
        Some(t) => rebind_endpoint(t, job.target_server_id.as_deref(), live).map(Some),
        None => Some(None),
    };
    match (source, target) {
        (Some(source), Some(target)) => {
            job.session_id = source;
            if target.is_some() {
                job.target_session_id = target;
            }
            Rebind::Ready
        }
        _ => Rebind::NeedsReconnect,
    }
}

/// The note a paused/failed job carries while it waits for its server to come
/// back; `then` finishes the sentence ("resume", "retry").
fn reconnect_note(server_name: &str, then: &str) -> String {
    format!("Reconnect to \"{server_name}\" to {then}.")
}

/// Pause one job. An Active job winds down at its next chunk boundary - only
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

/// Resume one paused job: `Paused` → `Queued` (see [`resume_paused`]), then
/// kick the dispatcher. Any state other than `Paused` is a no-op.
pub fn resume_job<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>, job_id: u64) {
    let live = live_sessions(app);
    let q = app.state::<TransferQueue>();
    let row = {
        let mut guard = q.jobs.lock().unwrap();
        match guard.iter_mut().find(|j| j.id == job_id) {
            Some(j) if j.state == JobState::Paused => {
                resume_paused(j, &live);
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

/// Pause every Active/Queued job - see [`pause_job`] for the per-state
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

/// Resume every Paused job - see [`resume_paused`] for the forced-`Resume`
/// rationale and the reconnect handling applied to each: jobs whose server is
/// not connected stay Paused (with a note), so this is safe to call blindly.
pub fn resume_all<RT: tauri::Runtime>(app: &tauri::AppHandle<RT>) {
    let live = live_sessions(app);
    let q = app.state::<TransferQueue>();
    let mut rows = Vec::new();
    {
        let mut guard = q.jobs.lock().unwrap();
        for j in guard.iter_mut() {
            if j.state == JobState::Paused {
                resume_paused(j, &live);
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

/// Rebuild a job from its persisted row as a PAUSED job carrying a "needs
/// reconnect" note. Pure (no app needed) so the row ↔ job mapping - above all
/// that the saved-server ids survive, which is what makes the job resumable
/// after a reconnect - is unit-testable. `Err` says why a row cannot be
/// restored.
fn job_from_row(row: crate::db::QueueJobRow) -> Result<TransferJob, String> {
    let Some(kind) = JobKind::from_db_str(&row.kind) else {
        return Err(format!("has unknown kind {:?}", row.kind));
    };
    Ok(TransferJob {
        id: row.id.max(0) as u64,
        kind,
        session_id: row.session_id,
        server_name: row.server_name.clone(),
        server_id: row.server_id,
        local_path: row.local_path,
        remote_path: row.remote_path,
        size: row.size.max(0) as u64,
        bytes_done: row.bytes_done.max(0) as u64,
        state: JobState::Paused,
        error: Some(format!(
            "Session closed before restart - reconnect to \"{}\" and resume.",
            row.server_name
        )),
        cancel: None,
        pause: None,
        started_at: None,
        target_session_id: row.target_session_id,
        target_server_name: row.target_server_name,
        target_server_id: row.target_server_id,
        target_remote_path: row.target_remote_path,
        resume: row.resume.as_deref().map(ResumeMode::from_str_loose),
        preserve_ts: row.preserve_ts,
        attempts: row.attempts.max(0) as u32,
        retry_at: None,
        verify: row.verify,
        last_persist_at: None,
    })
}

/// Reload jobs left `Queued`/`Active`/`Paused` from a previous run and bring
/// them back as `Paused` - never auto-started. The previous run's SSH
/// sessions no longer exist (a new run has fresh, differently-numbered
/// ones), so silently reconnecting and resuming writes at startup would
/// surprise a user who never asked for it; surfacing the job as Paused with
/// an explicit "needs reconnect" error lets them resume it deliberately
/// (`resume_job`) once they've reopened the right connection - `resume_job`
/// then re-points the job at that new session by its persisted saved-server id
/// (see `rebind_job`). Returns the number of jobs restored.
///
/// Must be called once at startup, AFTER both `AppState` (the DB) and
/// `TransferQueue` are managed - see lib.rs's `setup()`. Also seeds the
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
            let job = match job_from_row(row) {
                Ok(job) => job,
                Err(why) => {
                    log::warn!("[sshspan-sftp] queue restore: job {id} {why}, skipping");
                    continue;
                }
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

    // ── resume by seeking (A7-35) ────────────────────────────────────────────

    /// Against a real russh-sftp client: after `seek_remote` the next read
    /// returns the bytes from `offset` on, and ONLY those cross the wire. The
    /// old read-and-discard loop moved the whole prefix first - resuming a
    /// 10 GB download at 9.9 GB transferred 9.9 GB again before the first new
    /// byte.
    #[cfg(unix)]
    #[tokio::test]
    async fn resume_seeks_the_remote_instead_of_rereading_the_prefix() {
        use tokio::io::AsyncReadExt;
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        let data: Vec<u8> = (0..=250u8).cycle().take(1_000_000).collect();
        fx.write("/big.bin", &data);

        let mut rf = sftp.open("/big.bin").await.unwrap();
        seek_remote(&mut rf, 900_000).await.unwrap();
        let mut rest = Vec::new();
        rf.read_to_end(&mut rest).await.unwrap();

        // (`assert!`, not `assert_eq!`: a failure must not dump a megabyte.)
        assert!(
            rest == data[900_000..],
            "read the wrong bytes after seeking"
        );
        assert_eq!(
            fx.knobs.lock().unwrap().bytes_read,
            100_000,
            "only the missing suffix may be read from the server"
        );
    }

    // ── replacing a remote file (rename over an existing one) ────────────────

    /// OpenSSH refuses RENAME onto an existing file. The queue's final step
    /// must still replace it - and must say so only when the new content is
    /// really in place.
    #[cfg(unix)]
    #[tokio::test]
    async fn rename_over_replaces_an_existing_file_despite_the_sftp_v3_rule() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/final.bin", b"old");
        fx.write("/d/final.bin.part", b"new content");

        rename_over(&sftp, "/d/final.bin.part", "/d/final.bin", None)
            .await
            .expect("rename over an existing file");

        assert_eq!(fx.read("/d/final.bin"), b"new content");
        assert!(!fx.exists("/d/final.bin.part"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rename_over_into_a_free_name_is_a_single_plain_rename() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/final.bin.part", b"data");

        rename_over(&sftp, "/d/final.bin.part", "/d/final.bin", None)
            .await
            .unwrap();

        assert_eq!(fx.read("/d/final.bin"), b"data");
        assert_eq!(fx.ops(), vec!["rename /d/final.bin.part /d/final.bin"]);
    }

    /// The retry deletes the old target, so it must never run when the file
    /// that was supposed to replace it is not there - that would turn one
    /// failed rename into lost data.
    #[cfg(unix)]
    #[tokio::test]
    async fn rename_over_never_deletes_the_target_when_the_source_is_gone() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/final.bin", b"precious");

        let err = rename_over(&sftp, "/d/missing.part", "/d/final.bin", None)
            .await
            .expect_err("nothing to rename");

        assert!(!err.is_empty());
        assert_eq!(fx.read("/d/final.bin"), b"precious");
        assert!(
            !fx.ops().iter().any(|op| op.starts_with("remove")),
            "target must not be removed: {:?}",
            fx.ops()
        );
    }

    // ── remote parent directories (A7-09) ────────────────────────────────────

    /// A7-09 end to end through the upload preparation: a folder upload
    /// enqueues one job per FILE and never makes the directories, so the first
    /// file of `/up/a/b/` must create the whole chain - the server refuses to
    /// open `/up/a/b/f.bin.part` otherwise, which is what failed every file of
    /// an uploaded folder with "No such file".
    #[cfg(unix)]
    #[tokio::test]
    async fn upload_preparation_creates_the_missing_remote_directories() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;

        let (rpart, offset) =
            prepare_upload(&sftp, "/up/a/b/f.bin", 10, Some(ResumeMode::Resume)).await;

        assert_eq!((rpart.as_str(), offset), ("/up/a/b/f.bin.part", 0));
        assert!(fx.path("/up/a/b").is_dir());
        // ...and the part file can now actually be opened for writing.
        sftp.open_with_flags(
            &rpart,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await
        .expect("destination directory exists");
        // Existing directories are left alone: the second job of the same
        // folder must not fail on a mkdir of something that is already there.
        prepare_upload(&sftp, "/up/a/b/g.bin", 10, None).await;
        assert!(fx.path("/up/a/b").is_dir());
    }

    /// The resume decision made against an earlier attempt's `.part`: a strict
    /// prefix continues, anything else (or any non-Resume mode) starts over and
    /// clears the stale partial.
    #[cfg(unix)]
    #[tokio::test]
    async fn upload_preparation_resumes_a_matching_part_and_clears_a_stale_one() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/f.bin.part", b"0123");

        // 4 of 10 bytes already there: continue at 4.
        let (_, offset) = prepare_upload(&sftp, "/d/f.bin", 10, Some(ResumeMode::Resume)).await;
        assert_eq!(offset, 4);
        assert!(fx.exists("/d/f.bin.part"), "a resumable part is kept");

        // The source is now SHORTER than the part: it cannot be a prefix.
        let (_, offset) = prepare_upload(&sftp, "/d/f.bin", 3, Some(ResumeMode::Resume)).await;
        assert_eq!(offset, 0);
        assert!(!fx.exists("/d/f.bin.part"), "a stale part is removed");

        // Overwrite never resumes, even when the part would fit.
        fx.write("/d/f.bin.part", b"0123");
        let (_, offset) = prepare_upload(&sftp, "/d/f.bin", 10, Some(ResumeMode::Overwrite)).await;
        assert_eq!(offset, 0);
        assert!(!fx.exists("/d/f.bin.part"));
    }

    /// `ensure_remote_dir` itself, creating outermost first and tolerating
    /// directories that already exist or are created concurrently.
    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_remote_dir_creates_each_level_once_outermost_first() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.mkdir("/srv/up");

        ensure_remote_dir(&sftp, "/srv/up/a/b/file.txt").await;

        assert!(fx.path("/srv/up/a/b").is_dir());
        // Only the missing levels were created, in order.
        assert_eq!(fx.ops(), vec!["mkdir /srv/up/a", "mkdir /srv/up/a/b"]);
        // Idempotent.
        ensure_remote_dir(&sftp, "/srv/up/a/b/other.txt").await;
        assert_eq!(fx.ops().len(), 2);
        // A file in the way stops the walk without panicking.
        fx.write("/srv/blocker", b"x");
        ensure_remote_dir(&sftp, "/srv/blocker/deeper/f.txt").await;
        assert!(!fx.exists("/srv/blocker/deeper"));
    }

    // ── A `.part` someone else planted ──────────────

    /// Upload `bytes` to `remote` the way the upload leg does (prepare, open,
    /// write, close, rename) and return the `.part` offset it went on from.
    #[cfg(unix)]
    async fn upload_via_part(
        sftp: &russh_sftp::client::SftpSession,
        remote: &str,
        bytes: &[u8],
        resume: ResumeMode,
    ) -> Result<u64, String> {
        use tokio::io::AsyncWriteExt;
        let (rpart, offset) = prepare_upload(sftp, remote, bytes.len() as u64, Some(resume)).await;
        let mut local = std::io::Cursor::new(bytes.to_vec());
        let (mut rf, offset) = open_upload_part(sftp, &rpart, offset, &mut local).await?;
        assert_eq!(local.position(), offset, "the source is left at the offset");
        rf.write_all(&bytes[offset as usize..])
            .await
            .map_err(|e| e.to_string())?;
        rf.shutdown().await.map_err(|e| e.to_string())?;
        rename_over(sftp, &rpart, remote, Some(bytes.len() as u64)).await?;
        Ok(offset)
    }

    /// A link planted at `<remote>.part`: Resume used to STAT it - following
    /// the link - and append the upload to the link's TARGET, and the rename
    /// then put the link in place of the upload. The link is never written
    /// through, in either mode; the upload starts over.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_a_planted_part_link_is_never_written_through() {
        for resume in [ResumeMode::Resume, ResumeMode::Overwrite] {
            let (sftp, fx) = crate::sftp::testkit::serve().await;
            fx.write("/victim", b"victim data");
            fx.mkdir("/up");
            fx.symlink("../victim", "/up/f.bin.part");
            let payload = vec![b'u'; 100];

            let offset = upload_via_part(&sftp, "/up/f.bin", &payload, resume)
                .await
                .unwrap_or_else(|e| panic!("{resume:?}: {e}"));

            assert_eq!(offset, 0, "{resume:?}: a link is never resumed");
            assert_eq!(fx.read("/victim"), b"victim data", "{resume:?}");
            assert_eq!(fx.read("/up/f.bin"), payload, "{resume:?}");
            assert!(
                !std::fs::symlink_metadata(fx.path("/up/f.bin"))
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{resume:?}: the upload must be a regular file"
            );
        }
    }

    /// On a server that leaves the type bits out, a `.part` that is a link is
    /// told apart by READLINK and not resumed; a real one still is.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_an_untyped_part_is_resumed_only_when_it_is_not_a_link() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/real.bin.part", b"0123");
        fx.write("/victim", b"0123");
        fx.symlink("../victim", "/d/link.bin.part");
        fx.knobs.lock().unwrap().untyped_modes = true;

        let (_, real) = prepare_upload(&sftp, "/d/real.bin", 10, Some(ResumeMode::Resume)).await;
        let (_, link) = prepare_upload(&sftp, "/d/link.bin", 10, Some(ResumeMode::Resume)).await;

        assert_eq!(real, 4, "a regular .part is continued");
        assert_eq!(link, 0, "a link is not");
        assert_eq!(fx.read("/victim"), b"0123");
    }

    /// `rename_over` checked `from` with STAT - which follows a link - before it
    /// deleted the target: a `.part` swapped for a link replaced the user's file
    /// with that link. `from` must be the regular file that was written.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix1_rename_over_never_puts_a_link_in_place_of_the_target() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/final.bin", b"precious");
        fx.write("/elsewhere", b"attacker");
        fx.symlink("../elsewhere", "/d/final.bin.part");

        let err = rename_over(&sftp, "/d/final.bin.part", "/d/final.bin", None)
            .await
            .expect_err("a link is not renamed into place");

        assert!(err.contains("not a regular file"), "{err}");
        assert_eq!(fx.read("/d/final.bin"), b"precious");
        assert!(!std::fs::symlink_metadata(fx.path("/d/final.bin"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(
            !fx.ops().iter().any(|op| op == "remove /d/final.bin"),
            "{:?}",
            fx.ops()
        );
    }

    // ── Uploads to servers without type bits, and `.part` files ─────────────

    /// On a server that leaves the type bits out and answers "list
    /// this folder" on a file with "permission denied", the `.part` could not
    /// be proven to be a file: every upload failed (it worked before the
    /// rename checked for a regular file), and the unknown `.part` then
    /// blocked the next upload - the pre-clean left it and the exclusive
    /// create failed. A `.part` that is not a link and holds exactly the
    /// bytes just written is accepted, and a stale one of unknown type is
    /// removed.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix2_uploads_work_when_the_folder_probe_on_a_file_is_refused() {
        use russh_sftp::protocol::StatusCode;
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        {
            let mut knobs = fx.knobs.lock().unwrap();
            knobs.untyped_modes = true;
            knobs.opendir_file_status = Some(StatusCode::PermissionDenied);
        }
        fx.write("/d/f.bin", b"old");

        let first = upload_via_part(&sftp, "/d/f.bin", b"new content", ResumeMode::Overwrite).await;
        assert!(first.is_ok(), "{first:?}");
        assert_eq!(fx.read("/d/f.bin"), b"new content");

        fx.write("/d/f.bin.part", b"stale");
        let second = upload_via_part(&sftp, "/d/f.bin", b"newer", ResumeMode::Overwrite).await;
        assert!(second.is_ok(), "{second:?}");
        assert_eq!(fx.read("/d/f.bin"), b"newer");
        assert!(!fx.exists("/d/f.bin.part"));
    }

    /// A resumed `.part` was protected only by its size,
    /// which whoever planted it controls - a regular `.part` the size of a
    /// victim file, swapped for a link to the victim between our LSTAT and
    /// our OPEN, had the upload appended to the victim. The bytes before the
    /// resume point are read back through the opened handle and compared
    /// with the source first; on a mismatch the `.part` goes and the upload
    /// starts over, exclusively.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix2_a_resumed_part_swapped_for_a_link_is_not_appended_to() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/victim", b"VICTIMDATA");
        fx.write("/d/f.bin.part", b"0123456789");
        fx.knobs.lock().unwrap().swap_for_link_on_open =
            Some(("/d/f.bin.part".into(), "victim".into()));

        let offset = upload_via_part(
            &sftp,
            "/d/f.bin",
            b"0123456789abcdefghij",
            ResumeMode::Resume,
        )
        .await;

        assert_eq!(fx.read("/d/victim"), b"VICTIMDATA", "{offset:?}");
        assert_eq!(offset, Ok(0));
        assert_eq!(fx.read("/d/f.bin"), b"0123456789abcdefghij");
    }

    /// A `.part` whose bytes are not the start of this source (the
    /// local file changed since, or the `.part` is someone else's) was
    /// continued anyway - a corrupt file that passes the size check. It is
    /// started over now; a genuine partial upload is still continued.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_fix2_a_part_that_is_not_this_upload_is_started_over() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.write("/d/f.bin.part", b"XXXXXXXXXX");
        let offset = upload_via_part(
            &sftp,
            "/d/f.bin",
            b"0123456789abcdefghij",
            ResumeMode::Resume,
        )
        .await;
        assert_eq!(offset, Ok(0));
        assert_eq!(fx.read("/d/f.bin"), b"0123456789abcdefghij");

        fx.write("/d/g.bin.part", b"0123456789");
        let offset = upload_via_part(
            &sftp,
            "/d/g.bin",
            b"0123456789abcdefghij",
            ResumeMode::Resume,
        )
        .await;
        assert_eq!(offset, Ok(10));
        assert_eq!(fx.read("/d/g.bin"), b"0123456789abcdefghij");
    }

    /// On a server whose attributes carry no file type, every
    /// existing folder looked like "exists but is not a directory", so the
    /// walk gave up at the first level and the upload of a nested file failed
    /// with "No such file". An entry of unknown type is walked through; the
    /// open that follows reports a real obstacle.
    #[cfg(unix)]
    #[tokio::test]
    async fn ru6a_ensure_remote_dir_walks_through_folders_of_an_untyped_server() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        fx.mkdir("/srv/up");
        fx.write("/srv/blocker", b"x");
        fx.knobs.lock().unwrap().untyped_modes = true;

        ensure_remote_dir(&sftp, "/srv/up/a/b/file.txt").await;

        assert!(fx.path("/srv/up/a/b").is_dir(), "{:?}", fx.ops());
        // A file in the way still stops it, without a panic.
        ensure_remote_dir(&sftp, "/srv/blocker/deeper/f.txt").await;
        assert!(!fx.exists("/srv/blocker/deeper"));
    }

    /// `enqueue` stamps every job with
    /// the saved server of its session - and a server copy with its target's
    /// too - and the row it persists keeps them.
    #[test]
    fn ru6a_queued_jobs_carry_the_saved_server_of_each_endpoint() {
        let download = QueuedItem::simple(
            JobKind::Download,
            "s1".into(),
            "Alpha".into(),
            "/local/a".into(),
            "/remote/a".into(),
            1,
        );
        let mut copy = QueuedItem::simple(
            JobKind::ServerCopy,
            "s1".into(),
            "Alpha".into(),
            String::new(),
            "/remote/b".into(),
            2,
        );
        copy.target = Some(ServerCopyTarget {
            session_id: "s2".into(),
            server_name: "Beta".into(),
            remote_path: "/dest/b".into(),
        });
        let orphan = QueuedItem::simple(
            JobKind::Upload,
            "gone".into(),
            "Gamma".into(),
            "/local/c".into(),
            "/remote/c".into(),
            3,
        );
        let items = vec![download, copy, orphan];
        let lookup = |session: &str| match session {
            "s1" => Some("srv-a".to_string()),
            "s2" => Some("srv-b".to_string()),
            _ => None,
        };

        let ids = endpoint_server_ids(&items, lookup);
        assert_eq!(
            ids,
            vec![
                (Some("srv-a".to_string()), None),
                (Some("srv-a".to_string()), Some("srv-b".to_string())),
                (None, None),
            ]
        );
        let jobs: Vec<TransferJob> = items
            .into_iter()
            .zip(ids)
            .enumerate()
            .map(|(i, (item, (server, target)))| new_job(i as u64, item, server, target, true))
            .collect();
        assert_eq!(jobs[1].server_id.as_deref(), Some("srv-a"));
        assert_eq!(jobs[1].target_server_id.as_deref(), Some("srv-b"));
        assert_eq!(jobs[1].target_session_id.as_deref(), Some("s2"));
        assert!(jobs
            .iter()
            .all(|j| j.state == JobState::Queued && j.verify == Some(true)));
        let row = jobs[1].to_row();
        assert_eq!(
            (row.server_id.as_deref(), row.target_server_id.as_deref()),
            (Some("srv-a"), Some("srv-b"))
        );
        assert_eq!(jobs[2].to_row().server_id, None);
    }

    /// The levels `ensure_remote_dir` has to create before an upload can open
    /// `<dir>/<file>.part`: every directory above the file, outermost first.
    #[test]
    fn remote_parent_chain_lists_every_level_outermost_first() {
        assert_eq!(
            remote_parent_chain("/srv/up/a/b/file.txt"),
            vec!["/srv", "/srv/up", "/srv/up/a", "/srv/up/a/b"]
        );
        // A file directly under the root has nothing to create.
        assert!(remote_parent_chain("/file.txt").is_empty());
        assert!(remote_parent_chain("/").is_empty());
        assert!(remote_parent_chain("").is_empty());
        assert!(remote_parent_chain("file.txt").is_empty());
        // Empty segments from doubled slashes collapse.
        assert_eq!(remote_parent_chain("//srv//x/f"), vec!["/srv", "/srv/x"]);
    }

    /// Relative remote paths resolve against the session's start directory, so
    /// the chain must stay relative: the old walk prefixed `/` and would have
    /// created `/a/b` instead of `a/b`.
    #[test]
    fn remote_parent_chain_keeps_relative_paths_relative() {
        assert_eq!(remote_parent_chain("a/b/f"), vec!["a", "a/b"]);
        assert_eq!(remote_parent_chain("a/f"), vec!["a"]);
    }

    // ── preserve timestamps on downloads (A7-36) ─────────────────────────────

    #[test]
    fn preservable_mtime_ignores_missing_and_zero() {
        assert_eq!(preservable_mtime(Some(1_600_000_000)), Some(1_600_000_000));
        assert_eq!(preservable_mtime(None), None);
        assert_eq!(preservable_mtime(Some(0)), None);
    }

    #[test]
    fn set_local_mtime_stamps_a_finished_file() {
        let dir = std::env::temp_dir().join(format!("sshspan-mtime-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f.bin");
        std::fs::write(&file, b"payload").unwrap();

        set_local_mtime(&file, 1_600_000_000).expect("set mtime");

        let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
        assert_eq!(
            modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1_600_000_000
        );
        // Only the timestamp changed.
        assert_eq!(std::fs::read(&file).unwrap(), b"payload");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_local_mtime_reports_a_missing_file() {
        let missing = std::env::temp_dir().join(format!("sshspan-nope-{}", uuid::Uuid::new_v4()));
        assert!(set_local_mtime(&missing, 1_600_000_000).is_err());
    }

    // ── copy loop: short-copy detection (A7-18) ──────────────────────────────

    /// Drive `copy_chunks` over an in-memory source with no progress sink and
    /// no throttle, returning the result and what reached the writer.
    async fn run_copy(
        source: Vec<u8>,
        max_read: Option<u64>,
        cancel: bool,
        pause: bool,
    ) -> (Result<u64, String>, Vec<u8>) {
        let mut reader = std::io::Cursor::new(source);
        let mut sink: Vec<u8> = Vec::new();
        let result = copy_chunks(
            &mut reader,
            &mut sink,
            &AtomicBool::new(cancel),
            &AtomicBool::new(pause),
            max_read,
            0,
            |_, _| {},
            |_| async {},
        )
        .await;
        (result, sink)
    }

    #[tokio::test]
    async fn copy_chunks_copies_a_complete_source() {
        let data: Vec<u8> = (0..=255u8).cycle().take(600 * 1024).collect(); // > 2 chunks
        let (result, sink) = run_copy(data.clone(), Some(data.len() as u64), false, false).await;
        assert_eq!(result, Ok(data.len() as u64));
        assert_eq!(sink, data);
    }

    /// Reads are clamped to the expected size (the EOF-crossing-read defence):
    /// a source LONGER than expected is not an error, the surplus is simply not
    /// requested.
    #[tokio::test]
    async fn copy_chunks_clamps_reads_to_the_expected_size() {
        let (result, sink) = run_copy(vec![9u8; 100], Some(40), false, false).await;
        assert_eq!(result, Ok(40));
        assert_eq!(sink.len(), 40);
    }

    /// A7-18: the source hit EOF before the expected number of bytes - a remote
    /// file truncated/rotated mid-download, a server answering early EOF, a
    /// local file that shrank during an upload. That used to return `Ok` and
    /// the job finished as Done with a short destination and no warning.
    #[tokio::test]
    async fn copy_chunks_reports_an_early_eof_as_incomplete() {
        let (result, sink) = run_copy(vec![7u8; 10], Some(100), false, false).await;
        let err = result.expect_err("a short copy must not look like success");
        assert!(
            err.starts_with("incomplete transfer"),
            "unexpected message: {err}"
        );
        assert!(err.contains("10 of 100"), "unexpected message: {err}");
        // What did arrive is still flushed, so a Resume can continue from it.
        assert_eq!(sink.len(), 10);
    }

    /// A source that ended EARLY is not a read-blocked channel: the Send-to
    /// leg must not respond by re-reading the whole file over the interactive
    /// channel (which would just end early again). The decision is made on the
    /// REAL error `copy_chunks` produces, so a rewording cannot silently break it.
    #[tokio::test]
    async fn an_early_eof_is_not_retried_on_the_interactive_channel() {
        let (result, _) = run_copy(vec![7u8; 10], Some(100), false, false).await;
        let err = result.expect_err("a short copy");

        assert!(is_incomplete_transfer(&err), "{err}");
        assert!(
            !leg1_retries_on_interactive_channel(&err),
            "an early EOF must stop the leg, not trigger a full re-read: {err}"
        );
    }

    /// What the fallback is FOR keeps working: a rejected read (the server
    /// failing a read on the fresh channel) is retried on the browse channel;
    /// a user's pause/cancel never is.
    #[test]
    fn read_failures_still_retry_on_the_interactive_channel() {
        for msg in [
            "SFTP server returned Failure (code 4) with no further detail (at offset 0, len 262144)",
            "Permission denied (code 3): no (at offset 4096, len 262144)",
        ] {
            assert!(leg1_retries_on_interactive_channel(msg), "{msg}");
        }
        assert!(!leg1_retries_on_interactive_channel(CANCELLED_SENTINEL));
        assert!(!leg1_retries_on_interactive_channel(PAUSED_SENTINEL));
    }

    /// `u64::MAX` is the "remote size unknown" sentinel: reading until a real
    /// EOF is the only option there, so a short source is not an error.
    #[tokio::test]
    async fn copy_chunks_does_not_check_an_unknown_size() {
        let (result, sink) = run_copy(vec![1u8; 10], Some(u64::MAX), false, false).await;
        assert_eq!(result, Ok(10));
        assert_eq!(sink.len(), 10);
    }

    /// The pause/cancel sentinels still win over everything else (the
    /// completeness check must not turn a user-requested stop into a failure).
    #[tokio::test]
    async fn copy_chunks_honours_cancel_and_pause() {
        let (result, sink) = run_copy(vec![1u8; 10], Some(10), true, false).await;
        assert_eq!(result, Err(CANCELLED_SENTINEL.to_string()));
        assert!(sink.is_empty());
        let (result, sink) = run_copy(vec![1u8; 10], Some(10), false, true).await;
        assert_eq!(result, Err(PAUSED_SENTINEL.to_string()));
        assert!(sink.is_empty());
    }

    /// Minimal `TransferJob` for tests that only care about a couple of
    /// fields (state/retry_at) - every field still needs a value since this
    /// struct is never constructed outside `sftp::queue` (see `QueuedItem`'s
    /// doc comment), so there's no `Default` impl to lean on elsewhere.
    fn test_job(id: u64, state: JobState) -> TransferJob {
        TransferJob {
            id,
            kind: JobKind::Upload,
            session_id: "s1".into(),
            server_name: "srv".into(),
            server_id: Some("server-1".into()),
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
            target_server_id: None,
            target_remote_path: None,
            resume: None,
            preserve_ts: None,
            attempts: 0,
            retry_at: None,
            verify: None,
            last_persist_at: None,
        }
    }

    // ── rebinding to reconnected sessions (A7-17) ────────────────────────────

    fn live(session: &str, server: &str, started_at_ms: i64) -> LiveSession {
        LiveSession {
            session_id: session.into(),
            server_id: server.into(),
            started_at_ms,
        }
    }

    /// A restored job must come back with the saved-server ids it was queued
    /// with: they are the ONLY thing that outlives the dead session ids, so a
    /// row that lost them would make "reconnect and resume" impossible.
    #[test]
    fn restored_jobs_keep_their_server_ids_and_come_back_paused() {
        let mut job = test_job(7, JobState::Active);
        job.kind = JobKind::ServerCopy;
        job.target_session_id = Some("t1".into());
        job.target_server_name = Some("tgt".into());
        job.target_server_id = Some("server-2".into());
        job.target_remote_path = Some("/dest".into());

        let restored = job_from_row(job.to_row()).expect("restorable row");

        assert_eq!(restored.id, 7);
        assert_eq!(restored.state, JobState::Paused, "never auto-started");
        assert_eq!(restored.server_id.as_deref(), Some("server-1"));
        assert_eq!(restored.target_server_id.as_deref(), Some("server-2"));
        assert!(restored
            .error
            .as_deref()
            .is_some_and(|e| e.contains("reconnect to \"srv\"")));
    }

    #[test]
    fn unknown_row_kinds_are_not_restored() {
        let mut row = test_job(1, JobState::Queued).to_row();
        row.kind = "mystery".into();
        assert!(job_from_row(row).is_err());
    }

    #[test]
    fn rebind_keeps_a_session_that_is_still_live() {
        let mut job = test_job(1, JobState::Paused);
        let live = [live("s1", "server-1", 10), live("s9", "server-1", 99)];
        assert_eq!(rebind_job(&mut job, &live), Rebind::Ready);
        // Two tabs to one server: the job stays on ITS session, not the newer.
        assert_eq!(job.session_id, "s1");
    }

    #[test]
    fn rebind_moves_a_dead_session_to_the_newest_live_one_of_the_same_server() {
        let mut job = test_job(1, JobState::Paused);
        job.session_id = "dead".into();
        let live = [
            live("old", "server-1", 10),
            live("new", "server-1", 20),
            live("elsewhere", "server-2", 30),
        ];
        assert_eq!(rebind_job(&mut job, &live), Rebind::Ready);
        assert_eq!(job.session_id, "new");
    }

    /// A transfer must never silently move to a different host.
    #[test]
    fn rebind_never_crosses_servers() {
        let mut job = test_job(1, JobState::Paused);
        job.session_id = "dead".into();
        let live = [live("other", "server-2", 10)];
        assert_eq!(rebind_job(&mut job, &live), Rebind::NeedsReconnect);
        assert_eq!(job.session_id, "dead", "a failed rebind changes nothing");
    }

    /// Jobs persisted before `server_id` existed cannot be matched to anything
    /// but their own (long dead) session.
    #[test]
    fn rebind_needs_a_server_id_to_match_on() {
        let mut job = test_job(1, JobState::Paused);
        job.session_id = "dead".into();
        job.server_id = None;
        let live = [live("s2", "server-1", 10)];
        assert_eq!(rebind_job(&mut job, &live), Rebind::NeedsReconnect);
        assert_eq!(rebind_job(&mut job, &[]), Rebind::NeedsReconnect);
    }

    /// A server-to-server copy has two endpoints and needs BOTH, matched
    /// independently by their own server ids.
    #[test]
    fn rebind_covers_both_ends_of_a_server_copy() {
        let mut job = test_job(1, JobState::Paused);
        job.kind = JobKind::ServerCopy;
        job.session_id = "src-dead".into();
        job.target_session_id = Some("tgt-dead".into());
        job.target_server_id = Some("server-2".into());

        // Only the source server is back: nothing changes.
        let only_source = [live("src-new", "server-1", 10)];
        assert_eq!(rebind_job(&mut job, &only_source), Rebind::NeedsReconnect);
        assert_eq!(job.session_id, "src-dead");
        assert_eq!(job.target_session_id.as_deref(), Some("tgt-dead"));

        // Both are back: both ends move.
        let both = [
            live("src-new", "server-1", 10),
            live("tgt-new", "server-2", 11),
        ];
        assert_eq!(rebind_job(&mut job, &both), Rebind::Ready);
        assert_eq!(job.session_id, "src-new");
        assert_eq!(job.target_session_id.as_deref(), Some("tgt-new"));
    }

    /// The end-to-end behaviour A7-17 is about: pause → connection drops →
    /// reconnect → Resume must continue the transfer on the NEW session.
    #[test]
    fn resume_continues_a_paused_job_on_the_reconnected_session() {
        let mut job = test_job(1, JobState::Paused);
        job.session_id = "dead".into();
        job.resume = Some(ResumeMode::Overwrite);
        job.error = Some("Session closed before restart - reconnect.".into());

        resume_paused(&mut job, &[live("fresh", "server-1", 5)]);

        assert_eq!(job.state, JobState::Queued);
        assert_eq!(job.session_id, "fresh");
        assert_eq!(job.resume, Some(ResumeMode::Resume), "continue the .part");
        assert_eq!(job.error, None);
    }

    /// With nothing to reconnect to, Resume must NOT start the job (it could
    /// only fail with "Session closed.", losing the helpful note) - it stays
    /// Paused and says what to do. This also makes "Resume all" safe to call
    /// without first working out which servers are connected.
    #[test]
    fn resume_leaves_a_job_paused_while_its_server_is_not_connected() {
        let mut job = test_job(1, JobState::Paused);
        job.session_id = "dead".into();

        resume_paused(&mut job, &[live("other", "server-2", 5)]);

        assert_eq!(job.state, JobState::Paused);
        assert_eq!(job.session_id, "dead");
        assert_eq!(
            job.error.as_deref(),
            Some("Reconnect to \"srv\" to resume.")
        );
    }

    #[test]
    fn retry_rebinds_a_failed_job_after_a_reconnect() {
        let mut job = test_job(1, JobState::Failed);
        job.session_id = "dead".into();
        job.error = Some("Session closed.".into());
        job.attempts = 3;
        job.bytes_done = 50;

        retry_failed(&mut job, &[live("fresh", "server-1", 5)]);

        assert_eq!(job.state, JobState::Queued);
        assert_eq!(job.session_id, "fresh");
        assert_eq!(
            (job.error.as_deref(), job.attempts, job.bytes_done),
            (None, 0, 0)
        );
    }

    #[test]
    fn retry_keeps_a_failed_job_failed_while_its_server_is_not_connected() {
        let mut job = test_job(1, JobState::Failed);
        job.session_id = "dead".into();
        job.error = Some("Session closed.".into());

        retry_failed(&mut job, &[]);

        assert_eq!(job.state, JobState::Failed);
        assert_eq!(job.error.as_deref(), Some("Reconnect to \"srv\" to retry."));
    }

    /// A failure unrelated to the session (the server said no) on a session
    /// that is still alive retries exactly as before.
    #[test]
    fn retry_on_a_live_session_just_requeues() {
        let mut job = test_job(1, JobState::Failed);
        job.error = Some("Permission denied".into());

        retry_failed(&mut job, &[live("s1", "server-1", 5)]);

        assert_eq!(job.state, JobState::Queued);
        assert_eq!(job.session_id, "s1");
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
        // burst credit - refill never exceeds one second's worth of the cap.
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

    /// With transfer verification on, a copy from or to a
    /// server that reports no sizes was compared against the hash of an
    /// EMPTY remote file - a "checksum mismatch" for every good copy, which
    /// the verification then deleted. The queue's own checks now pass for a
    /// good download and a good upload, and both copies are kept.
    #[cfg(unix)]
    #[tokio::test]
    async fn rw_b6_a_good_copy_on_a_server_without_sizes_verifies() {
        let (sftp, fx) = crate::sftp::testkit::serve().await;
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 256) as u8).collect();
        fx.write("/copy.bin", &payload);
        fx.knobs.lock().unwrap().strip_size_mtime = true;
        let local =
            std::env::temp_dir().join(format!("sshspan-rw-verify-{}", uuid::Uuid::new_v4()));
        std::fs::write(&local, &payload).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let downloaded = verify_download(&sftp, "/copy.bin", &local, &cancel).await;
        let kept_locally = local.exists();
        let uploaded = verify_upload(&sftp, &local, "/copy.bin", &cancel).await;
        let _ = std::fs::remove_file(&local);
        assert_eq!(downloaded, Ok(()), "a good download is not a mismatch");
        assert!(kept_locally, "the good download is kept");
        assert_eq!(uploaded, Ok(()), "a good upload is not a mismatch");
        assert!(fx.exists("/copy.bin"), "the good upload is kept");
    }
}
