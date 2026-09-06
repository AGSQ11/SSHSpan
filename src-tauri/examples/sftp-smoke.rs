//! Minimal russh/russh-sftp regression test: connect to dev-sshd, open SFTP,
//! list dir, download a file, then upload+re-read a new file on the SAME
//! sftp session. Requires `cargo run --example dev-sshd` running first.
//!
//!   cargo run --example sftp-smoke
//!
//! Lives under examples/, not src/bin/ — see the comment in dev-sshd.rs.

use russh::client::{self, Handle};
use russh::keys::PrivateKey;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

struct H;
impl client::Handler for H {
    type Error = anyhow::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    let config = Arc::new(client::Config::default());
    let mut session: Handle<H> = client::connect(config, ("127.0.0.1", 2222), H).await?;
    let ok = session.authenticate_password("tester", "testpass").await?;
    println!("auth: {:?}", ok);

    let ch = session.channel_open_session().await?;
    ch.request_subsystem(true, "sftp").await?;
    let sftp = russh_sftp::client::SftpSession::new(ch.into_stream()).await?;
    println!("sftp init ok, cwd={:?}", sftp.canonicalize(".").await?);

    let entries: Vec<_> = sftp.read_dir(".").await?.collect();
    println!(
        "list: {:?}",
        entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );

    println!("opening hello.txt for read...");
    let mut f = sftp.open("hello.txt").await?;
    let mut buf = String::new();
    f.read_to_string(&mut buf).await?;
    println!("read {} bytes: {:?}", buf.len(), buf);
    drop(f);
    println!("read cycle done, now trying a SECOND open (write)...");

    let t0 = std::time::Instant::now();
    let mut wf = sftp.create("smoke-upload.txt").await?;
    println!("create() returned after {:?}", t0.elapsed());
    use tokio::io::AsyncWriteExt;
    wf.write_all(b"smoke test upload\n").await?;
    println!("write_all done after {:?}, now close()...", t0.elapsed());
    wf.close().await?;
    println!("close() done after {:?}", t0.elapsed());

    println!("now a THIRD open (read again)...");
    let t1 = std::time::Instant::now();
    let mut f2 = sftp.open("smoke-upload.txt").await?;
    let mut buf2 = String::new();
    f2.read_to_string(&mut buf2).await?;
    println!("third open+read after {:?}: {:?}", t1.elapsed(), buf2);

    println!("ALL OK");
    Ok(())
}
