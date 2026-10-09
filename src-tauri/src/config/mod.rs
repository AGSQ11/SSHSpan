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
                        h.hostname = Some(config_word(value));
                    }
                }
                "user" => {
                    if let Some(ref mut h) = current_host {
                        h.user = Some(config_word(value));
                    }
                }
                "port" => {
                    if let Some(ref mut h) = current_host {
                        h.port = value.parse().ok();
                    }
                }
                "identityfile" => {
                    if let Some(ref mut h) = current_host {
                        h.identity_file = Some(expand_tilde(&config_word(value)));
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

            // Single-argument directives are quoted when ssh would otherwise
            // split or misread them (a space in a Windows profile path ended
            // every ssh command once the file was Included). The Host line
            // and the `extra` directives can hold several arguments on
            // purpose, so they are written as they are.
            if let Some(v) = &host.hostname {
                output.push_str(&format!("    HostName {}\n", quote_config_word(&sv(v))));
            }
            if let Some(v) = &host.user {
                output.push_str(&format!("    User {}\n", quote_config_word(&sv(v))));
            }
            if let Some(v) = host.port {
                output.push_str(&format!("    Port {}\n", v));
            }
            if let Some(v) = &host.identity_file {
                output.push_str(&format!("    IdentityFile {}\n", quote_config_word(&sv(v))));
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

            // Sorted: the deploy preview shows this text and the deploy later
            // writes it from another HashMap, whose order is random per
            // instance - the same config must always serialize the same (R3).
            let mut extra: Vec<(&String, &String)> = host.extra.iter().collect();
            extra.sort();
            for (k, v) in extra {
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

/// One ssh_config argument, quoted when ssh would otherwise split or misread
/// it: whitespace, a quote or a backslash anywhere, or a leading `#` (which
/// starts a comment). Inside double quotes ssh_config unescapes `\\`, `\"`
/// and `\'` (OpenSSH's `argv_split`), so `\` and `"` are escaped; [`config_word`]
/// is the inverse. Ordinary values are left exactly as they are.
fn quote_config_word(value: &str) -> String {
    let plain = !value.is_empty()
        && !value.starts_with('#')
        && !value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\'));
    if plain {
        value.to_string()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// The value of a single-argument directive as ssh reads it (OpenSSH's
/// `argv_split`): quotes and the escapes `\\`, `\"`, `\'` - and `\ ` outside
/// quotes - are processed, and a `#` that starts a word ends the line. A value
/// that does not come to exactly one argument, or has an unterminated quote,
/// is kept as written.
fn config_word(value: &str) -> String {
    match split_config_args(value) {
        Some(mut args) if args.len() == 1 => args.remove(0),
        _ => value.to_string(),
    }
}

/// OpenSSH's `argv_split` for one line; `None` for an unterminated quote.
fn split_config_args(line: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = line.chars().collect();
    let mut args = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ' ' || chars[i] == '\t' {
            i += 1;
            continue;
        }
        if chars[i] == '#' {
            break;
        }
        let mut arg = String::new();
        let mut quote: Option<char> = None;
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' {
                match chars.get(i + 1) {
                    Some(&next)
                        if matches!(next, '\'' | '"' | '\\')
                            || (quote.is_none() && next == ' ') =>
                    {
                        arg.push(next);
                        i += 2;
                    }
                    _ => {
                        arg.push(c);
                        i += 1;
                    }
                }
                continue;
            }
            match quote {
                None if c == ' ' || c == '\t' => break,
                None if c == '"' || c == '\'' => quote = Some(c),
                Some(q) if c == q => quote = None,
                _ => arg.push(c),
            }
            i += 1;
        }
        if quote.is_some() {
            return None;
        }
        args.push(arg);
    }
    Some(args)
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
    /// SSHSpan's managed config file ([`ssh_config_path`]).
    pub fn new() -> Result<Self> {
        let config_path = ssh_config_path()?;
        Ok(Self { config_path })
    }

    /// A config file at an explicit path - the deploy code takes its target
    /// directories as parameters so tests can use a temp dir.
    pub fn at(config_path: PathBuf) -> Self {
        Self { config_path }
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
}

pub fn ssh_config_path() -> Result<PathBuf> {
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
        extra.insert(
            "ProxyCommand".to_string(),
            "ssh -W %h:%p jumphost".to_string(),
        );
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
        assert!(
            !out.contains("\nHost *\n"),
            "injected Host stanza must not survive"
        );
        assert!(
            !out.contains("\nProxyCommand evil"),
            "injected ProxyCommand must not survive"
        );
        // Sanitized (control chars -> '_') values are still present; a
        // single-argument value with a space in it is written quoted.
        assert!(out.contains("Host x_Host *_ ProxyCommand evil"));
        assert!(out.contains("HostName \"evil_ProxyCommand pwned\""));
    }

    #[test]
    fn to_config_string_clean_values_pass_through_unchanged() {
        let config = host_with(
            "deploy-key-1",
            "github.com",
            "/home/u/.ssh/sshspan_deploy-key-1",
        );
        let out = config.to_config_string();
        assert!(out.contains("Host deploy-key-1\n"));
        assert!(out.contains("    HostName github.com\n"));
        assert!(out.contains("    IdentityFile /home/u/.ssh/sshspan_deploy-key-1\n"));
        assert!(out.contains("    ProxyCommand ssh -W %h:%p jumphost\n"));
    }

    /// R3: the deploy preview shows the serializer's output and the deploy
    /// writes it later from a different `HashMap` - extra directives must
    /// come out in one stable order or the preview is not what is written.
    #[test]
    fn to_config_string_orders_extra_directives_stably() {
        let mut config = host_with("h", "example.com", "/k");
        config.hosts[0].extra.clear();
        for k in [
            "zeta", "alpha", "mike", "bravo", "yankee", "delta", "kilo", "echo",
        ] {
            config.hosts[0].extra.insert(k.to_string(), "v".to_string());
        }
        let out = config.to_config_string();
        let extras: Vec<&str> = out
            .lines()
            .filter_map(|l| l.trim().strip_suffix(" v"))
            .collect();
        assert_eq!(
            extras,
            vec!["alpha", "bravo", "delta", "echo", "kilo", "mike", "yankee", "zeta"]
        );
    }

    /// RU3 fix 1: a value with whitespace, quotes, a backslash or a leading
    /// `#` is written quoted and escaped the way ssh_config reads it back - an
    /// unquoted `IdentityFile /home/John Smith/...` stopped every ssh command
    /// once the managed file was Included ("extra arguments at end of
    /// line") - and `parse` undoes it exactly, which undeploy relies on.
    #[test]
    fn single_value_directives_are_quoted_when_needed_and_parse_back() {
        let tricky = [
            "/home/John Smith/.ssh/sshspan_web",
            r#"C:\Users\Bob "B" O'Neil\.ssh\sshspan_x"#,
            r"C:\Users\bob\.ssh\sshspan_y",
            "#leading-hash",
        ];
        for value in tricky {
            let mut config = host_with("h", "example.com", value);
            config.hosts[0].extra.clear();
            config.hosts[0].user = Some(value.to_string());
            config.hosts[0].hostname = Some(value.to_string());
            let out = config.to_config_string();
            for keyword in ["IdentityFile", "User", "HostName"] {
                let line = out
                    .lines()
                    .find(|l| l.trim_start().starts_with(&format!("{keyword} ")))
                    .unwrap();
                let arg = line.trim_start()[keyword.len() + 1..].to_string();
                assert!(arg.starts_with('"') && arg.ends_with('"'), "{line}");
            }
            let back = SshConfig::parse(&out);
            assert_eq!(back.hosts[0].identity_file.as_deref(), Some(value), "{out}");
            assert_eq!(back.hosts[0].user.as_deref(), Some(value), "{out}");
            assert_eq!(back.hosts[0].hostname.as_deref(), Some(value), "{out}");
        }
        // Ordinary values are left exactly as they were.
        let plain = host_with("deploy-key-1", "github.com", "/home/u/.ssh/sshspan_x");
        let out = plain.to_config_string();
        assert!(
            out.contains("    IdentityFile /home/u/.ssh/sshspan_x\n"),
            "{out}"
        );
        assert!(out.contains("    User root\n"));
    }

    #[test]
    fn sanitize_config_value_handles_all_control_chars() {
        assert_eq!(sanitize_config_value("clean"), "clean");
        assert_eq!(sanitize_config_value("a\u{0}b"), "a_b");
        assert_eq!(sanitize_config_value("a\tb\rc\nd"), "a_b_c_d");
    }
}
