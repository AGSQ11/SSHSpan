//! SSH config file management
//! Replaces sshConfigService.js

use std::path::PathBuf;
use std::fs;
use directories::ProjectDirs;
use anyhow::Result;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SshHostConfig {
    pub host: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub identities_only: Option<bool>,
    pub forward_agent: Option<bool>,
    pub proxy_jump: Option<String>,
    pub extra: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SshConfig {
    pub hosts: Vec<SshHostConfig>,
}

impl SshConfig {
    pub fn parse(content: &str) -> Self {
        let mut hosts = Vec::new();
        let mut current_host: Option<SshHostConfig> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, whitespace).collect();
            if parts.len() < 2 {
                continue;
            }

            let keyword = parts[0].to_lowercase();
            let value = parts[1].trim();

            match keyword.as_str() {
                "host" => {
                    if let Some(host) = current_host.take() {
                        hosts.push(host);
                    }
                    current_host = Some(SshHostConfig {
                        host: value.to_string(),
                        hostname: None,
                        user: None,
                        port: None,
                        identity_file: None,
                        identities_only: None,
                        forward_agent: None,
                        proxy_jump: None,
                        extra: std::collections::HashMap::new(),
                    });
                }
                "hostname" => {
                    if let Some(ref mut h) = current_host {
                        h.hostname = Some(value.to_string());
                    }
                }
                "user" => {
                    if let Some(ref mut h) = current_host {
                        h.user = Some(value.to_string());
                    }
                }
                "port" => {
                    if let Some(ref mut h) = current_host {
                        h.port = value.parse().ok();
                    }
                }
                "identityfile" => {
                    if let Some(ref mut h) = current_host {
                        h.identity_file = Some(expand_tilde(value));
                    }
                }
                "identitiesonly" => {
                    if let Some(ref mut h) = current_host {
                        h.identities_only = Some(value.eq_ignore_ascii_case("yes"));
                    }
                }
                "forwardagent" => {
                    if let Some(ref mut h) = current_host {
                        h.forward_agent = Some(value.eq_ignore_ascii_case("yes"));
                    }
                }
                "proxyjump" => {
                    if let Some(ref mut h) = current_host {
                        h.proxy_jump = Some(value.to_string());
                    }
                }
                _ => {
                    if let Some(ref mut h) = current_host {
                        h.extra.insert(keyword, value.to_string());
                    }
                }
            }
        }

        if let Some(host) = current_host {
            hosts.push(host);
        }

        Self { hosts }
    }

    pub fn to_config_string(&self) -> String {
        let mut output = String::new();
        
        for host in &self.hosts {
            output.push_str(&format!("Host {}\n", host.host));
            
            if let Some(v) = &host.hostname {
                output.push_str(&format!("    HostName {}\n", v));
            }
            if let Some(v) = &host.user {
                output.push_str(&format!("    User {}\n", v));
            }
            if let Some(v) = host.port {
                output.push_str(&format!("    Port {}\n", v));
            }
            if let Some(v) = &host.identity_file {
                output.push_str(&format!("    IdentityFile {}\n", v));
            }
            if let Some(v) = host.identities_only {
                output.push_str(&format!("    IdentitiesOnly {}\n", if v { "yes" } else { "no" }));
            }
            if let Some(v) = host.forward_agent {
                output.push_str(&format!("    ForwardAgent {}\n", if v { "yes" } else { "no" }));
            }
            if let Some(v) = &host.proxy_jump {
                output.push_str(&format!("    ProxyJump {}\n", v));
            }
            
            for (k, v) in &host.extra {
                output.push_str(&format!("    {} {}\n", k, v));
            }
            
            output.push('\n');
        }

        output
    }
}

fn whitespace(c: char) -> bool {
    c.is_whitespace()
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = dirs::home_dir() {
            return path.replacen("~", &home.to_string_lossy(), 1);
        }
    }
    path.to_string()
}

pub struct SshConfigService {
    config_path: PathBuf,
}

impl SshConfigService {
    pub fn new() -> Result<Self> {
        let config_path = get_ssh_config_path()?;
        Ok(Self { config_path })
    }

    pub fn read(&self) -> Result<SshConfig> {
        if !self.config_path.exists() {
            return Ok(SshConfig { hosts: Vec::new() });
        }
        let content = fs::read_to_string(&self.config_path)?;
        Ok(SshConfig::parse(&content))
    }

    pub fn write(&self, config: &SshConfig) -> Result<()> {
        let content = config.to_config_string();
        
        // Ensure .ssh directory exists
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write atomically
        let temp_path = self.config_path.with_extension("tmp");
        fs::write(&temp_path, content)?;
        fs::rename(&temp_path, &self.config_path)?;

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.config_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&self.config_path, perms)?;
        }

        Ok(())
    }

    pub fn add_host(&self, host: SshHostConfig) -> Result<()> {
        let mut config = self.read()?;
        config.hosts.push(host);
        self.write(&config)
    }

    pub fn remove_host(&self, host_pattern: &str) -> Result<()> {
        let mut config = self.read()?;
        config.hosts.retain(|h| h.host != host_pattern);
        self.write(&config)
    }

    pub fn get_deployable_keys(&self) -> Vec<String> {
        self.read()
            .map(|c| c.hosts.iter()
                .filter_map(|h| h.identity_file.clone())
                .collect())
            .unwrap_or_default()
    }
}

fn get_ssh_config_path() -> Result<PathBuf> {
    if let Some(dirs) = ProjectDirs::from("org", "sshspan", "SSHSpan") {
        Ok(dirs.config_dir().join("ssh").join("config"))
    } else if let Some(home) = dirs::home_dir() {
        Ok(home.join(".ssh").join("config"))
    } else {
        anyhow::bail!("Could not determine SSH config path")
    }
}

pub fn get_ssh_dir() -> Result<PathBuf> {
    if let Some(home) = dirs::home_dir() {
        Ok(home.join(".ssh"))
    } else {
        anyhow::bail!("Could not determine home directory")
    }
}