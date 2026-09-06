//! Dev-only SSH server for local end-to-end testing (NOT shipped in installers).
//!
//!   cargo run --example dev-sshd
//!
//! Lives under examples/ (not src/bin/) deliberately: any file placed in
//! src/bin/ becomes a Cargo binary target that `tauri build` also compiles,
//! and Tauri's bundler once picked this one instead of the real app as "the"
//! binary to package into the installer. `cargo build`/`tauri build` never
//! build examples/ unless explicitly asked, so this can't happen again.
//!
//! Listens on 127.0.0.1:2222. Accepts ANY user with password "testpass".
//! Shell channels echo (with a prompt); the "sftp" subsystem serves a real
//! filesystem rooted at %TEMP%/sshspan-dev-root (created with sample files).

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{File, FileAttributes, Handle, Name, Status, StatusCode, Version};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

fn root_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("sshspan-dev-root");
    let _ = std::fs::create_dir_all(dir.join("subdir"));
    if !dir.join("hello.txt").exists() {
        let _ = std::fs::write(dir.join("hello.txt"), b"hello from dev-sshd\n");
        let _ = std::fs::write(dir.join("subdir/nested.txt"), b"nested file\n");
    }
    dir
}

fn to_abs(root: &Path, p: &str) -> PathBuf {
    let p = p.replace('\\', "/");
    let rel = p.strip_prefix('/').unwrap_or(&p);
    let joined = root.join(rel);
    // prevent escaping the root
    if joined.starts_with(root) { joined } else { root.to_path_buf() }
}

#[derive(Clone)]
struct SshServer;

impl russh::server::Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        SshSession::default()
    }
}

#[derive(Clone, Default)]
struct SshSession {
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    // `Handler` methods run on separate clones of this struct dispatched
    // concurrently per channel (subsystem_request blocks its clone for the
    // whole sftp session), so `data()` can be invoked for the sftp channel's
    // raw protocol bytes on a DIFFERENT clone while the subsystem handler is
    // still awaiting `russh_sftp::server::run(...)`. Track which channel ids
    // are SFTP subsystems so `data()` never echoes onto them (that would
    // corrupt the binary SFTP framing with echoed text).
    sftp_channels: Arc<Mutex<std::collections::HashSet<ChannelId>>>,
}

impl SshSession {
    async fn take_channel(&mut self, channel_id: ChannelId) -> Channel<Msg> {
        let mut chans = self.channels.lock().await;
        chans.remove(&channel_id).unwrap()
    }
}

impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        if password == "testpass" { Ok(Auth::Accept) } else { Ok(Auth::reject()) }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut chans = self.channels.lock().await;
        chans.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"dev-sshd ready. Type anything (echo mode).\r\ndev-sshd$ ".as_ref())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Never echo onto an SFTP subsystem channel — this handler can be
        // invoked concurrently with the blocked subsystem_request (see the
        // struct doc comment), and echoing raw SFTP protocol bytes back
        // would corrupt the binary framing.
        if self.sftp_channels.lock().await.contains(&channel) {
            return Ok(());
        }
        // Echo mode: translate CR to CRLF for a terminal-friendly echo.
        let mut out: Vec<u8> = Vec::new();
        for &b in data {
            if b == b'\r' {
                out.extend_from_slice(b"\r\n");
            } else {
                out.push(b);
            }
        }
        session.data(channel, out)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            self.sftp_channels.lock().await.insert(channel_id);
            let channel = self.take_channel(channel_id).await;
            let sftp = FsSftp::new(root_dir());
            session.channel_success(channel_id)?;
            russh_sftp::server::run(channel.into_stream(), sftp).await;
        } else {
            session.channel_failure(channel_id)?;
        }
        Ok(())
    }
}

/// Filesystem-backed SFTP v3 handler rooted at a directory.
struct FsSftp {
    root: PathBuf,
    dir_entries: Option<Vec<File>>,
    handles: HashMap<String, PathBuf>, // handle string -> file path
    write_handles: HashMap<String, std::fs::File>,
    next_handle: u32,
}

impl FsSftp {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            dir_entries: None,
            handles: HashMap::new(),
            write_handles: HashMap::new(),
            next_handle: 1,
        }
    }
    fn abs(&self, p: &str) -> PathBuf { to_abs(&self.root, p) }
    fn virt(&self, p: &Path) -> String {
        let rel = p.strip_prefix(&self.root).unwrap_or(p);
        format!("/{}", rel.display())
    }
}

impl russh_sftp::server::Handler for FsSftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, version: u32, _extensions: HashMap<String, String>) -> Result<Version, Self::Error> {
        eprintln!("[dev-sshd] sftp init v{version}");
        Ok(Version::new())
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        eprintln!("[dev-sshd] close ENTER id={id} handle={handle}");
        self.handles.remove(&handle);
        self.write_handles.remove(&handle);
        eprintln!("[dev-sshd] close EXIT id={id}");
        Ok(Status { id, status_code: StatusCode::Ok, error_message: "Ok".to_string(), language_tag: "en-US".to_string() })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let abs = self.abs(&path);
        let mut files = Vec::new();
        match std::fs::read_dir(&abs) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let is_dir = e.path().is_dir();
                    let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                    let mtime = e.metadata().ok().and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as u32)
                        .unwrap_or(0);
                    let mut attrs = FileAttributes::dummy();
                    attrs.size = Some(size);
                    attrs.mtime = Some(mtime);
                    attrs.permissions = Some(if is_dir { 0o040755 } else { 0o100644 });
                    files.push(File::new(e.file_name().to_string_lossy().as_ref(), attrs));
                }
            }
            Err(_) => return Err(StatusCode::NoSuchFile),
        }
        self.dir_entries = Some(files);
        Ok(Handle { id, handle: path })
    }

    async fn readdir(&mut self, id: u32, _handle: String) -> Result<Name, Self::Error> {
        match self.dir_entries.take() {
            Some(files) => Ok(Name { id, files }),
            None => Err(StatusCode::Eof),
        }
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let abs = self.abs(&path);
        let exists = abs.exists();
        let virt = if exists { self.virt(&abs) } else { path.clone() };
        Ok(Name { id, files: vec![File::dummy(&virt)] })
    }

    async fn mkdir(&mut self, id: u32, path: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        std::fs::create_dir_all(self.abs(&path)).map_err(|_| StatusCode::Failure)?;
        Ok(Status { id, status_code: StatusCode::Ok, error_message: "Ok".to_string(), language_tag: "en-US".to_string() })
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(self.abs(&path)).map_err(|_| StatusCode::Failure)?;
        Ok(Status { id, status_code: StatusCode::Ok, error_message: "Ok".to_string(), language_tag: "en-US".to_string() })
    }

    async fn remove(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_file(self.abs(&path)).map_err(|_| StatusCode::Failure)?;
        Ok(Status { id, status_code: StatusCode::Ok, error_message: "Ok".to_string(), language_tag: "en-US".to_string() })
    }

    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        std::fs::rename(self.abs(&oldpath), self.abs(&newpath)).map_err(|_| StatusCode::Failure)?;
        Ok(Status { id, status_code: StatusCode::Ok, error_message: "Ok".to_string(), language_tag: "en-US".to_string() })
    }

    async fn open(
        &mut self,
        id: u32,
        path: String,
        pflags: russh_sftp::protocol::OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        eprintln!("[dev-sshd] open ENTER id={id} path={path} flags={pflags:?}");
        let abs = self.abs(&path);
        let h = format!("h{}", self.next_handle);
        self.next_handle += 1;
        if pflags.contains(russh_sftp::protocol::OpenFlags::WRITE) {
            eprintln!("[dev-sshd] open: opening for write...");
            let f = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
                .open(&abs).map_err(|e| { eprintln!("[dev-sshd] open write FAILED: {e}"); StatusCode::Failure })?;
            eprintln!("[dev-sshd] open: write handle ok");
            self.write_handles.insert(h.clone(), f);
        }
        self.handles.insert(h.clone(), abs);
        eprintln!("[dev-sshd] open EXIT id={id} handle={h}");
        Ok(Handle { id, handle: h })
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<russh_sftp::protocol::Data, Self::Error> {
        use std::io::{Read, Seek, SeekFrom};
        eprintln!("[dev-sshd] read ENTER id={id} handle={handle} offset={offset} len={len}");
        let Some(path) = self.handles.get(&handle) else { eprintln!("[dev-sshd] read: no such handle"); return Err(StatusCode::Failure) };
        let mut f = std::fs::File::open(path).map_err(|e| { eprintln!("[dev-sshd] read: open FAILED: {e}"); StatusCode::Failure })?;
        f.seek(SeekFrom::Start(offset)).map_err(|_| StatusCode::Failure)?;
        let mut buf = vec![0u8; len as usize];
        let n = f.read(&mut buf).map_err(|_| StatusCode::Failure)?;
        buf.truncate(n);
        eprintln!("[dev-sshd] read EXIT id={id} n={n}");
        Ok(russh_sftp::protocol::Data { id, data: buf })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        use std::io::{Seek, SeekFrom, Write};
        eprintln!("[dev-sshd] write ENTER id={id} handle={handle} offset={offset} len={}", data.len());
        let Some(f) = self.write_handles.get_mut(&handle) else { eprintln!("[dev-sshd] write: no such handle"); return Err(StatusCode::Failure) };
        f.seek(SeekFrom::Start(offset)).map_err(|_| StatusCode::Failure)?;
        f.write_all(&data).map_err(|_| StatusCode::Failure)?;
        eprintln!("[dev-sshd] write EXIT id={id}");
        Ok(Status { id, status_code: StatusCode::Ok, error_message: "Ok".to_string(), language_tag: "en-US".to_string() })
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    let root = root_dir();
    eprintln!("[dev-sshd] serving sftp root: {}", root.display());
    // Host key: generate once into a temp file via ssh-keygen (avoids a rand
    // version dependency in this dev-only binary).
    let key_path = std::env::temp_dir().join("sshspan-dev-sshd-key");
    if !key_path.exists() {
        let _ = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f"])
            .arg(&key_path)
            .output();
    }
    let host_key = russh::keys::load_secret_key(key_path.display().to_string(), None)
        .expect("host key");

    let config = russh::server::Config {
        auth_rejection_time: std::time::Duration::from_secs(0),
        keys: vec![host_key],
        ..Default::default()
    };

    eprintln!("[dev-sshd] listening on 127.0.0.1:2222 (any user / password: testpass)");
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap()
        .block_on(async {
            let mut server = SshServer;
            let _ = server.run_on_address(Arc::new(config), ("127.0.0.1", 2222)).await;
        });
}