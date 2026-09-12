//! SSH key deployment and agent integration
//! Replaces sshConfigService.js deployment logic and parts of sshspan.js

use crate::config::{SshConfigService, SshHostConfig};
use anyhow::Result;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

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

        // Write the private key with restrictive permissions from the FIRST
        // byte on disk: creating it via fs::write (umask default, typically
        // 0644) and chmodding afterwards leaves a window where the key is
        // world-readable to anything watching ~/.ssh. mode(0o600) applies at
        // create time on Unix; the explicit chmod below stays as a reassert
        // for pre-existing files (re-deploy over an older key).
        use std::io::Write as _;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut private_file = opts.open(&private_path)?;
        private_file.write_all(private_key_pem.as_bytes())?;
        private_file.flush()?;
        drop(private_file);

        // Set permissions: 600 on Unix, handle Windows ACL
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&private_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&private_path, perms)?;
        }

        #[cfg(windows)]
        {
            // Use icacls to restrict to current user. A FAILED restriction is
            // not survivable for a private key: fail the deploy and remove
            // the file rather than leave readable key material behind.
            if let Err(e) = restrict_windows_file(&private_path) {
                let _ = fs::remove_file(&private_path);
                let _ = fs::remove_file(&public_path);
                return Err(anyhow::anyhow!(
                    "Could not restrict private-key file permissions: {e}"
                ));
            }
        }

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

#[cfg(windows)]
pub(crate) fn restrict_windows_file(path: &PathBuf) -> Result<()> {
    use std::process::Command;

    // Get current user SID
    let output = Command::new("whoami")
        .arg("/user")
        .arg("/fo")
        .arg("csv")
        .output()?;

    if !output.status.success() {
        anyhow::bail!("whoami /user failed with status {}", output.status);
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = output_str.lines().collect();

    let sid = if lines.len() >= 2 {
        let parts: Vec<&str> = lines[1].split(',').collect();
        if parts.len() >= 2 {
            Some(parts[1].trim_matches('"').to_string())
        } else {
            None
        }
    } else {
        None
    };
    let Some(sid) = sid else {
        anyhow::bail!("could not parse the current user SID from whoami output");
    };

    // Remove inheritance and set explicit permissions. Both steps must
    // actually succeed — a silently-skipped restriction leaves the private
    // key under the default (inherited) ACL.
    let remove_inheritance = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .output()?;
    if !remove_inheritance.status.success() {
        anyhow::bail!(
            "icacls /inheritance:r failed: {}",
            String::from_utf8_lossy(&remove_inheritance.stderr).trim()
        );
    }

    let grant = Command::new("icacls")
        .arg(path)
        .arg("/grant:r")
        .arg(format!("{}:F", sid))
        .output()?;
    if !grant.status.success() {
        anyhow::bail!(
            "icacls /grant:r failed: {}",
            String::from_utf8_lossy(&grant.stderr).trim()
        );
    }

    Ok(())
}
