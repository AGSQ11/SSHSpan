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

use crate::sftp::{edit_temp_dir, EditRegistry, EditWatch, SftpRegistry};
use crate::ssh_client::SessionRegistry;

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
    app.state::<SftpRegistry>().remove(&session_id);
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
