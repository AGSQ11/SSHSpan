//! In-process SFTP server for unit tests: a real [`SftpSession`] talking to a
//! filesystem-backed handler over an in-memory duplex stream. No SSH, no
//! sockets, no Tauri app - which is what lets the code that walks, copies and
//! edits remote files be tested against the actual russh-sftp client (seek
//! semantics, READDIR attributes, rename rules) rather than a mock of it.
//!
//! Unix only: the handler relies on symlinks and mode bits, and the dev-sshd
//! example it was modelled on stays the tool for manual end-to-end runs.
//!
//! The server behaves like OpenSSH's sftp-server where it matters to this
//! app: READDIR/LSTAT report the entry itself (a symlink is a symlink),
//! STAT follows links, `mkdir` is single-level and fails on an existing
//! directory, and RENAME refuses to replace an existing file (the SFTP v3
//! rule that forces the "remove, then rename" retry in the queue).

use std::collections::HashMap;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};

/// Fault injection and accounting, shared between a test and its server.
#[derive(Default)]
pub struct Knobs {
    /// Refuse RENAME onto an existing file, like OpenSSH's sftp-server.
    pub rename_refuses_existing: bool,
    /// Pretend regular files end at this offset: a read at or past it gets
    /// EOF (a file truncated or rotated while it was being downloaded).
    pub read_eof_at: Option<u64>,
    /// Answer a read at or past this offset with a failure status (the
    /// transfer dying part-way through).
    pub read_fail_at: Option<u64>,
    /// Fail a WRITE at or past this offset.
    pub write_fail_at: Option<u64>,
    /// Server paths (spelled as the client sends them) whose OPENDIR is refused
    /// with "permission denied" - a folder the user may not list.
    pub unlistable: Vec<String>,
    /// Refuse REMOVE of any path containing this text ("permission denied") -
    /// a temp file the server will not let the client clean up.
    pub fail_remove_containing: Option<String>,
    /// Payload bytes served by READ so far - proves a resume did not read the
    /// already-downloaded prefix again.
    pub bytes_read: u64,
    /// Every mutating request in arrival order (`open <path> <flags>`,
    /// `rename <from> <to>`, `remove <path>`, `mkdir <path>`,
    /// `setstat <path>`), so a test can assert HOW a file was replaced.
    pub ops: Vec<String>,
    /// Report permission bits WITHOUT the file-type bits in every attribute
    /// set (READDIR, STAT, LSTAT, FSTAT) - a server that does not say what an
    /// entry is.
    pub untyped_modes: bool,
    /// Server paths whose LSTAT is refused ("permission denied").
    pub lstat_refused: Vec<String>,
    /// Server paths whose STAT is refused ("permission denied").
    pub stat_refused: Vec<String>,
    /// Emulate Win32-OpenSSH: do not delete a file while OUR SFTP handle on it
    /// is open. Also records CLOSEs so a test proves their order.
    pub refuse_remove_open: bool,
    /// Refuse this many REMOVEs with PermissionDenied, then allow them (another
    /// process briefly holds the file without delete sharing).
    pub remove_refusals_left: usize,
    /// `(path, link target)`: when the handle opened on `path` is closed, the
    /// file is replaced by a symbolic link to `link target` - another user of a
    /// shared folder swapping the file between our CLOSE and our RENAME.
    pub swap_for_link_on_close: Option<(String, String)>,
    /// Answer READLINK on anything with this status (a server whose READLINK
    /// does not work), instead of the target / BadMessage.
    pub readlink_status: Option<StatusCode>,
    /// Server paths whose REALPATH answers this path instead of resolving.
    pub realpath_override: Vec<(String, String)>,
    /// REALPATH calls answered so far.
    pub realpath_calls: u64,
    /// Refuse this many STATs ("permission denied"), then answer them.
    pub stat_refusals_left: usize,
    /// Report attributes WITHOUT size and modification time (a server that
    /// says neither).
    pub strip_size_mtime: bool,
    /// Server paths (exact) whose REMOVE is refused ("permission denied").
    pub remove_refused: Vec<String>,
    /// Answer OPENDIR on anything that is not a folder with this status
    /// instead of "failure" (a server whose folder probe on a file says
    /// "permission denied", say).
    pub opendir_file_status: Option<StatusCode>,
    /// `(path, link target)`, once: when an OPEN of `path` arrives, the file
    /// there is first replaced by a symbolic link to `link target` - someone
    /// swapping it between our LSTAT and our OPEN.
    pub swap_for_link_on_open: Option<(String, String)>,
}

/// What a test holds on to besides the client session.
pub struct Fixture {
    /// The directory the server treats as `/`.
    pub root: PathBuf,
    pub knobs: Arc<Mutex<Knobs>>,
}

impl Fixture {
    /// The real path behind a server path such as `/a/b.txt`.
    pub fn path(&self, virt: &str) -> PathBuf {
        self.root.join(virt.trim_start_matches('/'))
    }

    pub fn write(&self, virt: &str, bytes: &[u8]) {
        let p = self.path(virt);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    pub fn read(&self, virt: &str) -> Vec<u8> {
        std::fs::read(self.path(virt)).unwrap()
    }

    pub fn mkdir(&self, virt: &str) {
        std::fs::create_dir_all(self.path(virt)).unwrap();
    }

    /// Create `virt` as a symlink to `target` (verbatim, may dangle).
    pub fn symlink(&self, target: &str, virt: &str) {
        let p = self.path(virt);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, p).unwrap();
    }

    pub fn mode(&self, virt: &str) -> u32 {
        std::fs::metadata(self.path(virt)).unwrap().mode() & 0o7777
    }

    pub fn exists(&self, virt: &str) -> bool {
        std::fs::symlink_metadata(self.path(virt)).is_ok()
    }

    /// The mutating requests seen so far.
    pub fn ops(&self) -> Vec<String> {
        self.knobs.lock().unwrap().ops.clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Start a server over a fresh temp directory and connect a client to it. Must
/// run inside a tokio runtime (`#[tokio::test]`).
pub async fn serve() -> (SftpSession, Fixture) {
    let root = std::env::temp_dir().join(format!("sshspan-sftp-fixture-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(&root).unwrap();
    let knobs = Arc::new(Mutex::new(Knobs {
        rename_refuses_existing: true,
        ..Knobs::default()
    }));
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    russh_sftp::server::run(
        server_io,
        FsHandler {
            root: root.clone(),
            knobs: knobs.clone(),
            handles: HashMap::new(),
            next: 1,
        },
    )
    .await;
    let sftp = SftpSession::new(client_io)
        .await
        .expect("sftp handshake with the test server");
    (sftp, Fixture { root, knobs })
}

enum Open {
    File { file: std::fs::File, path: String },
    Dir { entries: Vec<File>, sent: bool },
}

struct FsHandler {
    root: PathBuf,
    knobs: Arc<Mutex<Knobs>>,
    handles: HashMap<String, Open>,
    next: u32,
}

fn status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_string(),
        language_tag: "en-US".to_string(),
    }
}

fn io_status(e: &std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

impl FsHandler {
    fn real(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    fn log(&self, op: String) {
        self.knobs.lock().unwrap().ops.push(op);
    }

    fn entry(&self, path: &Path, name: &str) -> Option<File> {
        // lstat: the entry itself, never a link's target.
        let md = std::fs::symlink_metadata(path).ok()?;
        Some(File::new(name, self.attrs(&md)))
    }

    /// Attributes as this server reports them (see `Knobs::untyped_modes`).
    fn attrs(&self, md: &std::fs::Metadata) -> FileAttributes {
        let mut attrs = FileAttributes::from(md);
        let knobs = self.knobs.lock().unwrap();
        if knobs.untyped_modes {
            attrs.permissions = attrs.permissions.map(|mode| mode & 0o7777);
        }
        if knobs.strip_size_mtime {
            // SFTP v3 carries atime and mtime under ONE flag: leaving atime in
            // would make the client see mtime 0, not "no time".
            attrs.size = None;
            attrs.atime = None;
            attrs.mtime = None;
        }
        attrs
    }
}

impl russh_sftp::server::Handler for FsHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.log(format!("open {filename} {pflags:?}"));
        let path = self.real(&filename);
        let swap = {
            let mut knobs = self.knobs.lock().unwrap();
            match &knobs.swap_for_link_on_open {
                Some((at, _)) if at == &filename => knobs.swap_for_link_on_open.take(),
                _ => None,
            }
        };
        if let Some((_, target)) = swap {
            let _ = std::fs::remove_file(&path);
            std::os::unix::fs::symlink(target, &path).unwrap();
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(pflags.contains(OpenFlags::READ));
        if pflags.contains(OpenFlags::APPEND) {
            opts.append(true);
        } else {
            opts.write(pflags.contains(OpenFlags::WRITE));
        }
        // SSH_FXF_EXCL is O_EXCL in OpenSSH's sftp-server: CREATE|EXCL fails on
        // ANY existing name - a symbolic link included, dangling or not.
        if pflags.contains(OpenFlags::CREATE) && pflags.contains(OpenFlags::EXCLUDE) {
            opts.create_new(true);
        } else {
            opts.create(pflags.contains(OpenFlags::CREATE));
        }
        opts.truncate(pflags.contains(OpenFlags::TRUNCATE));
        let file = opts.open(&path).map_err(|e| io_status(&e))?;
        let handle = format!("h{}", self.next);
        self.next += 1;
        self.handles.insert(
            handle.clone(),
            Open::File {
                file,
                path: filename,
            },
        );
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        // An unknown handle (a second CLOSE of the same one) is a failure,
        // exactly as OpenSSH answers it.
        let opened = self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        if self.knobs.lock().unwrap().refuse_remove_open {
            if let Open::File { path, .. } = &opened {
                self.log(format!("close {path}"));
            }
        }
        let swap = match &opened {
            Open::File { path, .. } => {
                let knobs = self.knobs.lock().unwrap();
                knobs
                    .swap_for_link_on_close
                    .as_ref()
                    .filter(|(at, _)| at == path)
                    .cloned()
            }
            Open::Dir { .. } => None,
        };
        drop(opened);
        if let Some((at, target)) = swap {
            let real = self.real(&at);
            let _ = std::fs::remove_file(&real);
            std::os::unix::fs::symlink(target, real).unwrap();
        }
        Ok(status(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let (eof_at, fail_at) = {
            let k = self.knobs.lock().unwrap();
            (k.read_eof_at, k.read_fail_at)
        };
        if fail_at.is_some_and(|at| offset >= at) {
            return Err(StatusCode::Failure);
        }
        let Some(Open::File { file, .. }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let mut want = len as u64;
        if let Some(at) = eof_at {
            if offset >= at {
                return Err(StatusCode::Eof);
            }
            want = want.min(at - offset);
        }
        let mut buf = vec![0u8; want as usize];
        let n = file.read_at(&mut buf, offset).map_err(|e| io_status(&e))?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        self.knobs.lock().unwrap().bytes_read += n as u64;
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        if self
            .knobs
            .lock()
            .unwrap()
            .write_fail_at
            .is_some_and(|at| offset >= at)
        {
            return Err(StatusCode::Failure);
        }
        let Some(Open::File { file, .. }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        file.write_all_at(&data, offset)
            .map_err(|e| io_status(&e))?;
        Ok(status(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        if self.knobs.lock().unwrap().lstat_refused.contains(&path) {
            return Err(StatusCode::PermissionDenied);
        }
        let md = std::fs::symlink_metadata(self.real(&path)).map_err(|e| io_status(&e))?;
        Ok(Attrs {
            id,
            attrs: self.attrs(&md),
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        {
            let mut knobs = self.knobs.lock().unwrap();
            if knobs.stat_refused.contains(&path) {
                return Err(StatusCode::PermissionDenied);
            }
            if knobs.stat_refusals_left > 0 {
                knobs.stat_refusals_left -= 1;
                return Err(StatusCode::PermissionDenied);
            }
        }
        let md = std::fs::metadata(self.real(&path)).map_err(|e| io_status(&e))?;
        Ok(Attrs {
            id,
            attrs: self.attrs(&md),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(Open::File { file, .. }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let md = file.metadata().map_err(|e| io_status(&e))?;
        Ok(Attrs {
            id,
            attrs: self.attrs(&md),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.log(format!("setstat {path}"));
        let real = self.real(&path);
        if let Some(mode) = attrs.permissions {
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(mode & 0o7777))
                .map_err(|e| io_status(&e))?;
        }
        if let Some(mtime) = attrs.mtime {
            let f = std::fs::File::open(&real).map_err(|e| io_status(&e))?;
            f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime.into()))
                .map_err(|e| io_status(&e))?;
        }
        Ok(status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if self.knobs.lock().unwrap().unlistable.contains(&path) {
            return Err(StatusCode::PermissionDenied);
        }
        let real = self.real(&path);
        if let Some(code) = self.knobs.lock().unwrap().opendir_file_status {
            if !real.is_dir() {
                return Err(code);
            }
        }
        let mut entries = Vec::new();
        for e in std::fs::read_dir(&real)
            .map_err(|e| io_status(&e))?
            .flatten()
        {
            if let Some(f) = self.entry(&e.path(), &e.file_name().to_string_lossy()) {
                entries.push(f);
            }
        }
        let handle = format!("d{}", self.next);
        self.next += 1;
        self.handles.insert(
            handle.clone(),
            Open::Dir {
                entries,
                sent: false,
            },
        );
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        match self.handles.get_mut(&handle) {
            Some(Open::Dir { entries, sent }) if !*sent => {
                *sent = true;
                Ok(Name {
                    id,
                    files: std::mem::take(entries),
                })
            }
            _ => Err(StatusCode::Eof),
        }
    }

    /// READLINK, as OpenSSH's sftp-server answers it: the link's target, or
    /// for anything that is not a link readlink(2)'s EINVAL, which
    /// `errno_to_portable` maps to SSH_FX_BAD_MESSAGE.
    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        if let Some(code) = self.knobs.lock().unwrap().readlink_status {
            return Err(code);
        }
        let target = std::fs::read_link(self.real(&path)).map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidInput => StatusCode::BadMessage,
            _ => io_status(&e),
        })?;
        Ok(Name {
            id,
            files: vec![File::dummy(target.to_string_lossy())],
        })
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let answer = {
            let mut knobs = self.knobs.lock().unwrap();
            knobs.realpath_calls += 1;
            knobs
                .realpath_override
                .iter()
                .find(|(at, _)| at == &path)
                .map(|(_, answer)| answer.clone())
        };
        if let Some(answer) = answer {
            return Ok(Name {
                id,
                files: vec![File::dummy(answer)],
            });
        }
        let real = self.real(&path);
        let canon = std::fs::canonicalize(&real).unwrap_or(real);
        let virt = match canon.strip_prefix(&self.root) {
            Ok(rel) => format!("/{}", rel.display()),
            Err(_) => "/".to_string(),
        };
        Ok(Name {
            id,
            files: vec![File::dummy(virt)],
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.log(format!("mkdir {path}"));
        std::fs::create_dir(self.real(&path)).map_err(|e| io_status(&e))?;
        Ok(status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(self.real(&path)).map_err(|e| io_status(&e))?;
        Ok(status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        self.log(format!("remove {filename}"));
        let refuse_open = self.knobs.lock().unwrap().refuse_remove_open;
        if refuse_open
            && self
                .handles
                .values()
                .any(|h| matches!(h, Open::File { path, .. } if path == &filename))
        {
            return Err(StatusCode::PermissionDenied);
        }
        {
            let mut knobs = self.knobs.lock().unwrap();
            if knobs.remove_refusals_left > 0 {
                knobs.remove_refusals_left -= 1;
                return Err(StatusCode::PermissionDenied);
            }
            if knobs.remove_refused.contains(&filename) {
                return Err(StatusCode::PermissionDenied);
            }
        }
        if self
            .knobs
            .lock()
            .unwrap()
            .fail_remove_containing
            .as_deref()
            .is_some_and(|needle| filename.contains(needle))
        {
            return Err(StatusCode::PermissionDenied);
        }
        std::fs::remove_file(self.real(&filename)).map_err(|e| io_status(&e))?;
        Ok(status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        self.log(format!("rename {oldpath} {newpath}"));
        let to = self.real(&newpath);
        if self.knobs.lock().unwrap().rename_refuses_existing
            && std::fs::symlink_metadata(&to).is_ok()
        {
            return Err(StatusCode::Failure);
        }
        std::fs::rename(self.real(&oldpath), to).map_err(|e| io_status(&e))?;
        Ok(status(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::FileType;

    /// The harness itself: READDIR reports links as links, STAT follows them,
    /// and a file can be created, read back and replaced the way the app does.
    #[tokio::test]
    async fn server_reports_entries_like_openssh() {
        let (sftp, fx) = serve().await;
        fx.write("/d/file.txt", b"hello");
        fx.symlink("file.txt", "/d/link");
        fx.symlink("/nowhere", "/d/dangling");

        let mut seen: Vec<(String, FileType)> = sftp
            .read_dir("/d")
            .await
            .unwrap()
            .map(|e| (e.file_name(), e.file_type()))
            .collect();
        seen.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            seen,
            vec![
                ("dangling".to_string(), FileType::Symlink),
                ("file.txt".to_string(), FileType::File),
                ("link".to_string(), FileType::Symlink),
            ]
        );
        // STAT follows the link; a dangling one fails.
        assert_eq!(
            sftp.metadata("/d/link").await.unwrap().file_type(),
            FileType::File
        );
        assert!(sftp.metadata("/d/dangling").await.is_err());
    }

    /// Characterises russh-sftp 2.4: `shutdown()` sends the CLOSE, and a
    /// `close()` after it sends ANOTHER one (the file keeps no "already
    /// closed" guard), which the server answers with a failure. This is why
    /// callers that shut a file down must not also `close()` it - and why the
    /// queue's tolerant-close paths exist.
    #[tokio::test]
    async fn a_second_close_after_shutdown_is_answered_with_a_failure() {
        use tokio::io::AsyncWriteExt;
        let (sftp, fx) = serve().await;
        let mut f = sftp.create("/x").await.unwrap();
        f.write_all(b"abc").await.unwrap();
        f.shutdown().await.expect("first close");
        assert!(
            f.close().await.is_err(),
            "second CLOSE is for an unknown handle"
        );
        assert_eq!(fx.read("/x"), b"abc", "the data landed regardless");
    }

    /// OpenSSH refuses RENAME onto an existing file - the rule the queue's
    /// "remove the final name, then rename" retry exists for.
    #[tokio::test]
    async fn rename_refuses_to_replace_an_existing_file() {
        let (sftp, fx) = serve().await;
        fx.write("/a", b"new");
        fx.write("/b", b"old");
        assert!(sftp.rename("/a", "/b").await.is_err());
        assert_eq!(fx.read("/b"), b"old");
        sftp.remove_file("/b").await.unwrap();
        sftp.rename("/a", "/b").await.unwrap();
        assert_eq!(fx.read("/b"), b"new");
    }
}
