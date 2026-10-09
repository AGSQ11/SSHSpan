//! SSH key deployment and agent integration
//! Replaces sshConfigService.js deployment logic and parts of sshspan.js

use crate::config::{SshConfigService, SshHostConfig};
use anyhow::Result;
use std::fs;
use std::path::PathBuf;

/// Write secret bytes to `path` under owner-only permissions from the first
/// byte: 0600 on Unix, a current-user-only ACL on Windows.
///
/// SECURITY: `OpenOptions::mode()` applies at CREATION ONLY. Opening an
/// existing file with `.create(true).truncate(true).mode(0o600)` keeps that
/// file's old mode, so the key is written under it and the chmod that follows
/// closes the door after the horse has gone. Reproduced: a pre-existing 0644
/// file stays 0644 for the whole write and only becomes 0600 afterwards.
///
/// Remove any existing file first and `create_new`: on Unix it is created
/// with mode 0600; on Windows it is created EMPTY, its ACL restricted, and
/// only THEN written through the same open handle. A restriction failure
/// removes the empty file and propagates the error, never leaving readable
/// secret bytes behind. `create_new` also means we never write through a
/// symlink an attacker planted at the target.
pub fn write_secret_file(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    write_secret_file_restricted(path, contents, |p| {
        #[cfg(windows)]
        restrict_windows_file(&p.to_path_buf())?;
        #[cfg(not(windows))]
        let _ = p;
        Ok(())
    })
}

/// The shared write path, with the permission-restriction step separated so a
/// test can assert it runs on an EMPTY file before any bytes are written.
fn write_secret_file_restricted(
    path: &std::path::Path,
    contents: &[u8],
    restrict: impl FnOnce(&std::path::Path) -> Result<()>,
) -> Result<()> {
    use std::io::Write as _;

    // Replace rather than truncate: truncating an existing file inherits its
    // mode and its inode (and follows a symlink), which is the whole bug.
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::anyhow!("Could not replace {}: {e}", path.display())),
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    // Windows: share nothing while the file is ours. Until icacls has
    // restricted the ACL the file is under the inherited one, and no other
    // process may open it for reading, writing or deleting in that window
    // (or while the bytes go in). icacls itself only needs READ_CONTROL and
    // WRITE_DAC, which sharing does not govern.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(0);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| anyhow::anyhow!("Could not create {}: {e}", path.display()))?;

    // Restrict while the file is still EMPTY. The bytes go in afterwards
    // through the handle opened above, so the path is never reopened (and
    // cannot be swapped) in between.
    if let Err(e) = restrict(path) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(anyhow::anyhow!(
            "Could not restrict permissions on {}: {e}",
            path.display()
        ));
    }

    let written = file
        .write_all(contents)
        .and_then(|()| file.flush())
        .map_err(|e| anyhow::anyhow!("Could not write {}: {e}", path.display()));
    drop(file);
    if let Err(e) = written {
        let _ = fs::remove_file(path);
        return Err(e);
    }

    Ok(())
}

pub struct SshService;

impl SshService {
    /// Deploy a private key to ~/.ssh/ and update SSH config
    pub fn deploy_key(
        key_name: &str,
        private_key_pem: &str,
        public_key: &str,
        host_alias: Option<&str>,
        hostname: Option<&str>,
        user: Option<&str>,
        port: Option<u16>,
        strict_host_key: Option<bool>,
    ) -> Result<DeployResult> {
        let ssh_dir = get_ssh_dir()?;
        fs::create_dir_all(&ssh_dir)?;

        // Determine key filename
        let key_filename = format!("sshspan_{}", sanitize_filename(key_name));
        let private_path = ssh_dir.join(&key_filename);
        let public_path = ssh_dir.join(format!("{}.pub", key_filename));

        // Private key: written through the shared helper so the very first
        // byte lands in a file created at 0600. The previous code opened with
        // .create(true).truncate(true).mode(0o600), which on a RE-DEPLOY over
        // an existing key kept that file's old mode for the whole write and
        // only chmod'd afterwards - the comment claimed "0600 from the FIRST
        // byte on disk", and it was not. On Windows the helper fails closed if
        // the current-user-only ACL cannot be applied.
        write_secret_file(&private_path, private_key_pem.as_bytes()).map_err(|e| {
            let _ = fs::remove_file(&public_path);
            e
        })?;

        // Write public key
        fs::write(&public_path, public_key)?;

        // Update SSH config
        let config_service = SshConfigService::new()?;
        let mut config = config_service.read()?;

        // The alias is used both as the `Host` pattern and as the key for
        // matching an existing stanza below. Legacy vaults may hold names
        // that can't be a single Host token (e.g. containing spaces) —
        // derive a sanitized alias once and use it for both, so a re-deploy
        // of the same key updates the same stanza instead of creating a new
        // one each time. New names are already validated at every create
        // entry point; this is the compatibility path.
        let host = match host_alias {
            Some(alias) if crate::crypto::keys::validate_key_name(alias).is_ok() => {
                alias.to_string()
            }
            Some(alias) => crate::crypto::keys::sanitize_key_name(alias),
            None if crate::crypto::keys::validate_key_name(key_name).is_ok() => {
                key_name.to_string()
            }
            None => crate::crypto::keys::sanitize_key_name(key_name),
        };

        // Check if host already exists. An existing match is a legitimate
        // update (re-deploy of the same key): the alias can only come from a
        // validated key name or the sanitize mapping above, both of which
        // are single Host tokens, so a match cannot hijack an unrelated
        // stanza the user didn't already associate with this key.
        if let Some(existing) = config.hosts.iter_mut().find(|h| h.host == host) {
            existing.identity_file = Some(private_path.to_string_lossy().to_string());
            existing.identities_only = Some(true);
            if let Some(strict) = strict_host_key {
                existing.extra.insert(
                    "stricthostkeychecking".to_string(),
                    if strict {
                        "yes".to_string()
                    } else {
                        "no".to_string()
                    },
                );
            }
            if let Some(h) = hostname {
                existing.hostname = Some(h.to_string());
            }
            if let Some(u) = user {
                existing.user = Some(u.to_string());
            }
            if let Some(p) = port {
                existing.port = Some(p);
            }
        } else {
            config.hosts.push(SshHostConfig {
                host: host.to_string(),
                hostname: hostname.map(|s| s.to_string()),
                user: user.map(|s| s.to_string()),
                port,
                identity_file: Some(private_path.to_string_lossy().to_string()),
                identities_only: Some(true),
                forward_agent: Some(false),
                proxy_jump: None,
                extra: {
                    let mut extra = std::collections::HashMap::new();
                    if let Some(strict) = strict_host_key {
                        extra.insert(
                            "stricthostkeychecking".to_string(),
                            if strict {
                                "yes".to_string()
                            } else {
                                "no".to_string()
                            },
                        );
                    }
                    extra
                },
            });
        }

        config_service.write(&config)?;

        Ok(DeployResult {
            private_key_path: private_path.to_string_lossy().to_string(),
            public_key_path: public_path.to_string_lossy().to_string(),
            host_alias: host.to_string(),
            config_updated: true,
        })
    }

    /// Remove a deployed key
    pub fn remove_key(key_name: &str, host_alias: Option<&str>) -> Result<()> {
        let ssh_dir = get_ssh_dir()?;
        let key_filename = format!("sshspan_{}", sanitize_filename(key_name));
        let private_path = ssh_dir.join(&key_filename);
        let public_path = ssh_dir.join(format!("{}.pub", key_filename));

        // Remove key files
        if private_path.exists() {
            fs::remove_file(&private_path)?;
        }
        if public_path.exists() {
            fs::remove_file(&public_path)?;
        }

        // Update SSH config
        if let Some(host) = host_alias {
            let config_service = SshConfigService::new()?;
            let mut config = config_service.read()?;
            config.hosts.retain(|h| h.host != host);
            config_service.write(&config)?;
        }

        Ok(())
    }

    /// List all deployed keys
    pub fn list_deployed_keys() -> Result<Vec<DeployedKeyInfo>> {
        let ssh_dir = get_ssh_dir()?;

        if !ssh_dir.exists() {
            return Ok(Vec::new());
        }

        let mut keys = Vec::new();

        for entry in fs::read_dir(&ssh_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map_or(false, |ext| ext == "pub") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if stem.starts_with("sshspan_") {
                        let key_name = &stem[8..]; // Remove "sshspan_" prefix
                        let private_path = ssh_dir.join(stem);

                        keys.push(DeployedKeyInfo {
                            name: key_name.to_string(),
                            private_key_path: private_path.to_string_lossy().to_string(),
                            public_key_path: path.to_string_lossy().to_string(),
                            exists: private_path.exists(),
                        });
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Get SSH config hosts
    pub fn get_config_hosts() -> Result<Vec<SshHostConfig>> {
        let config_service = SshConfigService::new()?;
        let config = config_service.read()?;
        Ok(config.hosts)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeployResult {
    pub private_key_path: String,
    pub public_key_path: String,
    pub host_alias: String,
    pub config_updated: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeployedKeyInfo {
    pub name: String,
    pub private_key_path: String,
    pub public_key_path: String,
    pub exists: bool,
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn get_ssh_dir() -> Result<PathBuf> {
    if let Some(home) = dirs::home_dir() {
        Ok(home.join(".ssh"))
    } else {
        anyhow::bail!("Could not determine home directory")
    }
}

/// `%SystemRoot%\System32\<name>`, falling back to `C:\Windows` when the
/// variable is missing.
///
/// Absolute on purpose (A6-13): a bare `Command::new("icacls")` is resolved
/// through the application's own directory before System32, and a per-user
/// install lives in a user-writable directory - an `icacls.exe` planted
/// beside SSHSpan.exe would have run instead of the real one and could have
/// "succeeded" without restricting anything.
#[cfg(windows)]
fn system32_exe(name: &str) -> PathBuf {
    let root = std::env::var("SystemRoot")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| r"C:\Windows".to_string());
    PathBuf::from(root).join("System32").join(name)
}

/// The current user's SID from `whoami /user /fo csv /nh` output, i.e. the
/// last field of the last line (`"domain\user","S-1-5-21-..."`). Taken from
/// the end because an account name may itself contain a comma, and checked
/// for SID shape so nothing else is ever handed to icacls as an account.
#[cfg(any(windows, test))]
fn parse_whoami_sid(csv: &str) -> Option<String> {
    let line = csv.lines().rev().find(|l| !l.trim().is_empty())?;
    let sid = line.rsplit(',').next()?.trim().trim_matches('"');
    let well_formed = sid.starts_with("S-1-")
        && sid.len() > 4
        && sid[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-');
    well_formed.then(|| sid.to_string())
}

/// Leave `path` with exactly one ACE: full control for the current user.
///
/// ONE icacls call does both halves - `/inheritance:r /grant:r *<SID>:F`.
/// The old code ran `/inheritance:r` on its own first and then granted the
/// user by a bare SID, which icacls rejects ("No mapping between account
/// names and security IDs was done."): a SID must carry the `*` prefix. So
/// every secret write on Windows (deploy, private-key export, backup export,
/// audit CSV export) failed after inheritance had already been stripped
/// (A7-01). In a single invocation a rejected grant cannot leave the file
/// with an empty DACL, and `write_secret_file` removes the file on any error.
///
/// Both children are started with `CREATE_NO_WINDOW`: SSHSpan is a
/// GUI-subsystem process, so without it Windows opens a console window for
/// each console program it runs and every secret write flashed them (A7-43).
#[cfg(windows)]
pub(crate) fn restrict_windows_file(path: &PathBuf) -> Result<()> {
    use std::os::windows::process::CommandExt as _;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let whoami = Command::new(system32_exe("whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !whoami.status.success() {
        anyhow::bail!("whoami /user failed with status {}", whoami.status);
    }
    let Some(sid) = parse_whoami_sid(&String::from_utf8_lossy(&whoami.stdout)) else {
        anyhow::bail!("could not parse the current user SID from whoami output");
    };

    let icacls = Command::new(system32_exe("icacls.exe"))
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("*{sid}:F"))
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !icacls.status.success() {
        // icacls reports some failures on stdout and others on stderr.
        let detail = [&icacls.stderr, &icacls.stdout]
            .iter()
            .map(|b| String::from_utf8_lossy(b).trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        anyhow::bail!("icacls failed ({}): {detail}", icacls.status);
    }

    Ok(())
}

#[cfg(test)]
mod secret_write_tests {
    use super::*;

    /// Windows's inherited ACL must never cover secret bytes - restrict the
    /// empty file, then write. The same write path is driven with a
    /// restriction callback here so the test can observe exactly when it is
    /// called, without mocking the filesystem.
    #[test]
    fn secret_file_is_empty_until_permissions_are_restricted() {
        let dir = std::env::temp_dir().join(format!("sshspan-restrict-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.pem");
        let result = write_secret_file_restricted(&path, b"SECRET", |p| {
            // Metadata, not a read: on Windows the file is held with no
            // sharing, so only access that sharing does not govern works.
            assert_eq!(
                fs::metadata(p).unwrap().len(),
                0,
                "no secret bytes before the restriction"
            );
            Ok(())
        });
        let bytes = fs::read(&path);
        let _ = fs::remove_dir_all(&dir);
        result.unwrap();
        assert_eq!(bytes.unwrap(), b"SECRET");
    }

    /// Fail closed while the file is still empty: a permission-restriction
    /// failure removes it and never writes the secret.
    #[test]
    fn failed_permission_restriction_writes_no_secret_and_removes_the_file() {
        let dir =
            std::env::temp_dir().join(format!("sshspan-restrict-fail-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.pem");
        let result = write_secret_file_restricted(&path, b"SECRET", |p| {
            assert_eq!(fs::metadata(p).unwrap().len(), 0);
            anyhow::bail!("restriction refused")
        });
        let exists = path.exists();
        let _ = fs::remove_dir_all(&dir);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("restriction refused"));
        assert!(!exists, "the empty file must be removed on failure");
    }

    /// REGRESSION: the old sequence was
    ///   OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
    ///   -> write -> chmod 0600
    /// `mode()` applies at CREATION only, so overwriting an existing 0644 file
    /// wrote the private key under 0644 and only tightened it afterwards. Both
    /// the export and deploy paths carried this, with comments claiming "0600
    /// from the first byte".
    #[cfg(unix)]
    #[test]
    fn write_secret_file_is_0600_even_over_a_permissive_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "sshspan-secret-{}.pem",
            uuid::Uuid::new_v4().simple()
        ));

        // A pre-existing, world-readable file at the target - the "replace?"
        // case in a save dialog, or a re-deploy over an older key.
        fs::write(&path, b"stale").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_secret_file(&path, b"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be 0600, got {mode:o}");
        assert_eq!(
            fs::read(&path).unwrap(),
            b"-----BEGIN OPENSSH PRIVATE KEY-----"
        );
        let _ = fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_secret_file_creates_at_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "sshspan-secret-new-{}.pem",
            uuid::Uuid::new_v4().simple()
        ));
        write_secret_file(&path, b"key").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new secret file must be 0600, got {mode:o}");
        let _ = fs::remove_file(&path);
    }

    /// A symlink planted at the destination must not be written through:
    /// create_new fails rather than following it to the target.
    #[cfg(unix)]
    #[test]
    fn write_secret_file_does_not_follow_a_planted_symlink() {
        let dir =
            std::env::temp_dir().join(format!("sshspan-symlink-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        fs::write(&victim, b"original").unwrap();
        let link = dir.join("key.pem");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        // remove_file unlinks the symlink itself, then create_new makes a real
        // file - the victim must be untouched.
        write_secret_file(&link, b"secret").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"original");
        assert!(!fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(&dir);
    }

    /// `whoami /user /fo csv /nh` parsing: the SID is the last field of the
    /// last line, with or without a header line, and nothing that is not
    /// SID-shaped comes back (it would be handed to icacls as an account).
    #[test]
    fn whoami_sid_parser_takes_the_last_sid_shaped_field() {
        let sid = "S-1-5-21-62050738-523915034-210444172-1001";
        let row = format!("\"ryzen-main\\andrei\",\"{sid}\"\r\n");
        assert_eq!(parse_whoami_sid(&row).as_deref(), Some(sid));
        let with_header = format!("\"User Name\",\"SID\"\r\n{row}");
        assert_eq!(parse_whoami_sid(&with_header).as_deref(), Some(sid));
        // A comma inside the account name does not shift the field.
        let comma = format!("\"corp\\smith, john\",\"{sid}\"");
        assert_eq!(parse_whoami_sid(&comma).as_deref(), Some(sid));
        assert_eq!(parse_whoami_sid("\"User Name\",\"SID\""), None);
        assert_eq!(parse_whoami_sid(""), None);
        assert_eq!(parse_whoami_sid("\"x\",\"S-1-5 & calc\""), None);
        assert_eq!(parse_whoami_sid("\"x\",\"S-1-\""), None);
    }

    /// REGRESSION (A7-01): on Windows every secret write failed. The grant
    /// named the user by a bare SID (`icacls /grant:r S-1-5-21-...:F`), which
    /// icacls rejects ("No mapping between account names and security IDs was
    /// done.") - it only takes a SID with a `*` prefix - and it ran after
    /// inheritance had already been stripped in a separate call. Deploy,
    /// private-key export, backup export and the audit CSV export all died
    /// there. The write must succeed and leave exactly one ACE: full control
    /// for the current user, nothing inherited.
    #[cfg(windows)]
    #[test]
    fn write_secret_file_leaves_one_full_control_ace_for_the_current_user() {
        // Resolved here rather than through the code under test, so the test
        // does not trust the path logic it is checking.
        let system32 = std::path::PathBuf::from(
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()),
        )
        .join("System32");
        let dir =
            std::env::temp_dir().join(format!("sshspan-acl-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.pem");

        let written = write_secret_file(&path, b"-----BEGIN OPENSSH PRIVATE KEY-----");
        let listing = std::process::Command::new(system32.join("icacls.exe"))
            .arg(&path)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string());
        let me = std::process::Command::new(system32.join("whoami.exe"))
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        let _ = fs::remove_dir_all(&dir);

        written.expect("a secret write must succeed on Windows");
        let listing = listing.expect("icacls must run");
        let me = me.expect("whoami must run");
        // `icacls <file>` prints "<file> <ACE>", one more indented ACE per
        // line, then a blank line and a summary.
        let aces: Vec<String> = listing
            .lines()
            .take_while(|l| !l.trim().is_empty())
            .enumerate()
            .map(|(i, l)| {
                let l = if i == 0 {
                    l.strip_prefix(&path.display().to_string())
                        .unwrap_or_else(|| panic!("unexpected icacls output: {listing}"))
                } else {
                    l
                };
                l.trim().to_string()
            })
            .collect();
        assert_eq!(
            aces.len(),
            1,
            "exactly one ACE expected, icacls said: {listing}"
        );
        assert!(
            aces[0].eq_ignore_ascii_case(&format!("{me}:(F)")),
            "the only ACE must be full control for {me}, not inherited; got {:?}",
            aces[0]
        );
    }
}
