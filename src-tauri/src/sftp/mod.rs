//! SFTP over the live SSH session. Each tab's SFTP session is stored here,
//! keyed by the tab's SSH session id, alongside a registry of "open with
//! system editor" watches that re-upload files when the local copy changes.

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
        Self { sessions: Mutex::new(HashMap::new()) }
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
        Self { watches: Mutex::new(HashMap::new()) }
    }
    pub fn get(&self, key: &str) -> Option<Arc<std::sync::atomic::AtomicBool>> {
        self.watches.lock().unwrap().get(key).map(|w| w.stopped.clone())
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
        for (_, w) in guard.iter_mut() {
            w.stopped.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = w.watcher.take(); // dropped = stopped
        }
        guard.clear();
    }
    pub fn stop_all_for_session(&self, session_id: &str) {
        let mut guard = self.watches.lock().unwrap();
        let keys: Vec<String> = guard.iter()
            .filter(|(_, w)| w.session_id == session_id)
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            if let Some(w) = guard.get_mut(&k) {
                w.stopped.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = w.watcher.take(); // dropped = stopped
            }
            guard.remove(&k);
        }
    }
}

/// Default temp dir for edited remote files.
pub fn edit_temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("sshspan-edit");
    let _ = std::fs::create_dir_all(&dir);
    dir
}
