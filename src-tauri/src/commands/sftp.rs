//! SFTP IPC commands: directory listing, file ops, download/upload, and the
//! "open with system editor" flow (temp download + watch + auto re-upload).

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use notify::Watcher;
use tauri::{AppHandle, Manager};

use std::sync::Arc as StdArc;

use crate::sftp::{edit_temp_dir, EditRegistry, EditWatch, KeepaliveRegistry, SftpRegistry};
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
    let mut remote_file = sftp
        .open(&remote)
        .await
        .map_err(|e| CmdError(format!("open failed: {e}")))?;
    let mut local_file = tokio::fs::File::create(&local)
        .await
        .map_err(|e| CmdError(e.to_string()))?;
    tokio::io::copy(&mut remote_file, &mut local_file)
        .await
        .map_err(|e| CmdError(format!("download failed: {e}")))?;
    // Await the SFTP CLOSE response so a completed transfer is not reported
    // while the remote handle is still being flushed/closed.
    remote_file
        .close()
        .await
        .map_err(|e| CmdError(format!("download close failed: {e}")))?;
    Ok(serde_json::json!({ "ok": true, "local": local }))
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
    let local = edit_temp_dir().join(format!(
        "{}-{file_name}",
        &session_id[..8.min(session_id.len())]
    ));

    let mut remote_file = sftp
        .open(&remote)
        .await
        .map_err(|e| CmdError(format!("open failed: {e}")))?;
    let mut local_file = tokio::fs::File::create(&local)
        .await
        .map_err(|e| CmdError(e.to_string()))?;
    tokio::io::copy(&mut remote_file, &mut local_file)
        .await
        .map_err(|e| CmdError(format!("download failed: {e}")))?;
    drop(local_file);
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
        out.push(QueuedItem {
            kind: JobKind::Upload,
            session_id: session_id.clone(),
            server_name: server_name.clone(),
            local_path: local.display().to_string(),
            remote_path: remote,
            size: md.len(),
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
        expand_upload(child, rname, session_id.clone(), server_name.clone(), out);
    }
}

/// Expand a remote directory into download jobs (recursive); a file becomes one.
fn expand_download(
    sftp: Arc<russh_sftp::client::SftpSession>,
    remote: String,
    local_dir: PathBuf,
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
            let name = remote.rsplit('/').next().unwrap_or("file");
            out.push(QueuedItem {
                kind: JobKind::Download,
                session_id,
                server_name,
                local_path: local_dir.join(name).display().to_string(),
                remote_path: remote,
                size: md.size.unwrap_or(0),
            });
            return Ok(out);
        }
        let dir_name = remote.rsplit('/').next().unwrap_or("dir");
        let target_dir = local_dir.join(dir_name);
        let _ = tokio::fs::create_dir_all(&target_dir).await;
        let mut entries = sftp
            .read_dir(&remote)
            .await
            .map_err(|e| format!("list {remote}: {e}"))?;
        while let Some(entry) = entries.next() {
            let name = entry.file_name().to_string();
            let child_remote = format!("{}/{}", remote.trim_end_matches('/'), name);
            out = expand_download(
                sftp.clone(),
                child_remote,
                target_dir.clone(),
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
                    dest.clone(),
                    session_id.clone(),
                    server_name.clone(),
                    jobs,
                )
                .await
                .map_err(CmdError)?;
            }
        }
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
#[tauri::command]
pub fn sftp_stage_path(name: String) -> CmdResult<serde_json::Value> {
    let safe: String = name
        .chars()
        .map(|c| if c == '/' || c == 92 as char { '_' } else { c })
        .collect();
    Ok(serde_json::json!({ "path": edit_temp_dir().join(safe).display().to_string() }))
}
