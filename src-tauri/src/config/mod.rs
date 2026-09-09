//! SSH config file management
//! Replaces sshConfigService.js

use anyhow::Result;
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

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
        // Defense-in-depth for the config sink: every interpolated value goes
        // through sanitize_config_value so a newline/carriage-return can never
        // break out of its directive line and inject a new Host/directive.
        // Entry-point name validation should keep these out already; this
        // guards against legacy stored values and hand-edited structs.
        let sv = sanitize_config_value;

        let mut output = String::new();

        for host in &self.hosts {
            output.push_str(&format!("Host {}\n", sv(&host.host)));

            if let Some(v) = &host.hostname {
                output.push_str(&format!("    HostName {}\n", sv(v)));
            }
            if let Some(v) = &host.user {
                output.push_str(&format!("    User {}\n", sv(v)));
            }
            if let Some(v) = host.port {
                output.push_str(&format!("    Port {}\n", v));
            }
            if let Some(v) = &host.identity_file {
                output.push_str(&format!("    IdentityFile {}\n", sv(v)));
            }
            if let Some(v) = host.identities_only {
                output.push_str(&format!(
                    "    IdentitiesOnly {}\n",
                    if v { "yes" } else { "no" }
                ));
            }
            if let Some(v) = host.forward_agent {
                output.push_str(&format!(
                    "    ForwardAgent {}\n",
                    if v { "yes" } else { "no" }
                ));
            }
            if let Some(v) = &host.proxy_jump {
                output.push_str(&format!("    ProxyJump {}\n", sv(v)));
            }

            for (k, v) in &host.extra {
                output.push_str(&format!("    {} {}\n", sv(k), sv(v)));
            }

            output.push('\n');
        }

        output
    }
}

/// Make a value safe to interpolate into a single ssh_config directive line:
/// any control character (newline, carriage return, tab, NUL, …) is replaced
/// with `_`. Values that are already clean pass through unchanged.
fn sanitize_config_value(value: &str) -> String {
    if value.chars().any(|c| c.is_control()) {
        value
            .chars()
            .map(|c| if c.is_control() { '_' } else { c })
            .collect()
    } else {
        value.to_string()
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
            .map(|c| {
                c.hosts
                    .iter()
                    .filter_map(|h| h.identity_file.clone())
                    .collect()
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn host_with(host: &str, hostname: &str, identity: &str) -> SshConfig {
        let mut extra = std::collections::HashMap::new();
        extra.insert("ProxyCommand".to_string(), "ssh -W %h:%p jumphost".to_string());
        SshConfig {
            hosts: vec![SshHostConfig {
                host: host.to_string(),
                hostname: Some(hostname.to_string()),
                user: Some("root".to_string()),
                port: Some(22),
                identity_file: Some(identity.to_string()),
                identities_only: Some(true),
                forward_agent: Some(false),
                proxy_jump: None,
                extra,
            }],
        }
    }

    #[test]
    fn to_config_string_rejects_config_injection_in_values() {
        // A key named to inject a new Host stanza must not be able to break
        // out of its directive lines.
        let config = host_with(
            "x\nHost *\n ProxyCommand evil",
            "evil\nProxyCommand pwned",
            "/home/u/.ssh/sshspan_x\nProxyCommand evil",
        );
        let out = config.to_config_string();

        // The output must not contain raw newlines inside interpolated
        // values: every line must parse as a single directive.
        for line in out.lines() {
            let t = line.trim();
            assert!(
                t.is_empty()
                    || t.starts_with('#')
                    || t.starts_with("Host ")
                    || line.starts_with("    "),
                "line {line:?} must stay a well-formed config line"
            );
        }
        // No injected directive can survive: the payload's newlines are gone.
        assert!(!out.contains("\nHost *\n"), "injected Host stanza must not survive");
        assert!(
            !out.contains("\nProxyCommand evil"),
            "injected ProxyCommand must not survive"
        );
        // Sanitized (control chars -> '_') values are still present.
        assert!(out.contains("Host x_Host *_ ProxyCommand evil"));
        assert!(out.contains("HostName evil_ProxyCommand pwned"));
    }

    #[test]
    fn to_config_string_clean_values_pass_through_unchanged() {
        let config = host_with("deploy-key-1", "github.com", "/home/u/.ssh/sshspan_deploy-key-1");
        let out = config.to_config_string();
        assert!(out.contains("Host deploy-key-1\n"));
        assert!(out.contains("    HostName github.com\n"));
        assert!(out.contains("    IdentityFile /home/u/.ssh/sshspan_deploy-key-1\n"));
        assert!(out.contains("    ProxyCommand ssh -W %h:%p jumphost\n"));
    }

    #[test]
    fn sanitize_config_value_handles_all_control_chars() {
        assert_eq!(sanitize_config_value("clean"), "clean");
        assert_eq!(sanitize_config_value("a\u{0}b"), "a_b");
        assert_eq!(sanitize_config_value("a\tb\rc\nd"), "a_b_c_d");
    }
}
