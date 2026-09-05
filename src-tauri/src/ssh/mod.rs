//! SSH key deployment and agent integration
//! Replaces sshConfigService.js deployment logic and parts of sshspan.js

use std::path::PathBuf;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use anyhow::Result;
use crate::config::{SshConfigService, SshHostConfig};

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
    ) -> Result<DeployResult> {
        let ssh_dir = get_ssh_dir()?;
        fs::create_dir_all(&ssh_dir)?;

        // Determine key filename
        let key_filename = format!("sshspan_{}", sanitize_filename(key_name));
        let private_path = ssh_dir.join(&key_filename);
        let public_path = ssh_dir.join(format!("{}.pub", key_filename));

        // Write private key
        fs::write(&private_path, private_key_pem)?;
        
        // Set permissions: 600 on Unix, handle Windows ACL
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&private_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&private_path, perms)?;
        }
        
        #[cfg(windows)]
        {
            // Use icacls to restrict to current user
            restrict_windows_file(&private_path)?;
        }

        // Write public key
        fs::write(&public_path, public_key)?;

        // Update SSH config
        let config_service = SshConfigService::new()?;
        let mut config = config_service.read()?;

        let host = host_alias.unwrap_or(key_name);
        
        // Check if host already exists
        if let Some(existing) = config.hosts.iter_mut().find(|h| h.host == host) {
            existing.identity_file = Some(private_path.to_string_lossy().to_string());
            existing.identities_only = Some(true);
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
                extra: std::collections::HashMap::new(),
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
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
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
fn restrict_windows_file(path: &PathBuf) -> Result<()> {
    use std::process::Command;
    
    // Get current user SID
    let output = Command::new("whoami")
        .arg("/user")
        .arg("/fo")
        .arg("csv")
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = output_str.lines().collect();
    
    if lines.len() >= 2 {
        let parts: Vec<&str> = lines[1].split(',').collect();
        if parts.len() >= 2 {
            let sid = parts[1].trim_matches('"');
            
            // Remove inheritance and set explicit permissions
            let _ = Command::new("icacls")
                .arg(path)
                .arg("/inheritance:r")
                .output();
            
            let _ = Command::new("icacls")
                .arg(path)
                .arg("/grant:r")
                .arg(format!("{}:F", sid))
                .output();
        }
    }
    
    Ok(())
}