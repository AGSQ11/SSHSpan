//! SSH config file management
//! Replaces sshConfigService.js

use anyhow::Result;
use directories::ProjectDirs;
use std::fs;
use std::path::{Component, Path, PathBuf};

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
    /// SSHSpan's managed config, read the way ssh reads it: a keyword ends
    /// at ` \t\r\n` or `=` (so `Host=x` and `Host = x` are Host lines), and
    /// every `Match` block - like a `Host` or `Match` line with no argument,
    /// or one ssh cannot read (`Host\u{a0}x`) - ends the stanza before it.
    /// The lines of such a block apply to no host, so they are dropped like
    /// lines before the first `Host`: they used to be filed into the stanza
    /// before, and the next rewrite of the file gave that host their
    /// settings.
    pub fn parse(content: &str) -> Self {
        let mut hosts = Vec::new();
        let mut current_host: Option<SshHostConfig> = None;

        for line in content.lines() {
            let line = config_line(line);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let directive = split_keyword(line);
            let host_line = matches!(&directive, Some((keyword, _)) if keyword == "host");
            if !host_line && names_a_block(line) {
                if let Some(host) = current_host.take() {
                    hosts.push(host);
                }
                continue;
            }
            let Some((keyword, value)) = directive else {
                continue;
            };

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
///
/// A backslash alone is enough to force the quotes, and every `\` is then
/// written as `\\`. That is right for OpenSSH 8.7 and later, whose parser
/// (`argv_split`) unescapes it. OpenSSH older than 8.7 does not process escapes
/// inside quotes and reads `\\` as two backslashes - a Windows path such as
/// an IdentityFile under `C:\Users\...`, or a `DOMAIN\user` User, then comes
/// out with every separator doubled there.
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

/// The characters OpenSSH's config parser splits words on (its `WHITESPACE`,
/// ` \t\r\n`). Any other space - `\u{a0}`, `\u{3000}` - is part of a word.
fn is_config_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// One line of an ssh_config as OpenSSH sees it: trailing ` \t\r\n` and form
/// feeds cut, leading ` \t\r\n` skipped - and nothing else (`str::trim` also
/// took `\u{a0}` away, so `\u{a0}Host a` was read as a Host line ssh refuses).
fn config_line(raw: &str) -> &str {
    raw.trim_end_matches(|c: char| is_config_space(c) || c == '\u{c}')
        .trim_start_matches(is_config_space)
}

/// Whether `line` reads as a `Host` or `Match` line to a person - its first
/// word, split at ANY whitespace or `=`, is one of them - whatever ssh makes
/// of it. A line that does but is not one to ssh (no argument, `Host\u{a0}x`)
/// still starts a block: one that applies to nothing, so the lines under it
/// do not land in the block before it (after `Host *`: every host). OpenSSH
/// 8.7 and later refuse such a file; older ones read a bare `Host` as
/// matching nothing.
fn names_a_block(line: &str) -> bool {
    let word = line
        .trim_start()
        .split(|c: char| c.is_whitespace() || c == '=')
        .next()
        .unwrap_or("");
    word.eq_ignore_ascii_case("host") || word.eq_ignore_ascii_case("match")
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

// ─── The user's own ssh config, read-only (R4) ──────────────────────────────

/// A config file is never read past this many bytes.
const USER_CONFIG_MAX_BYTES: u64 = 1 << 20;
/// `Include` brings in at most this many files in total.
const USER_CONFIG_MAX_INCLUDES: usize = 64;
/// All the wildcards of all the `Include` lines of one read look at no more
/// than this many directory entries together.
const USER_CONFIG_MAX_SCANNED: usize = 10_000;
/// At most this many hosts are offered.
const USER_CONFIG_MAX_HOSTS: usize = 1000;

/// The user's own ssh config, `~/.ssh/config` (where OpenSSH looks on
/// Windows too) - not SSHSpan's managed file ([`ssh_config_path`]).
pub fn user_ssh_config_path() -> Result<PathBuf> {
    Ok(get_ssh_dir()?.join("config"))
}

/// The hosts the user's ssh config at `path` defines, for the server
/// dialog's import (R4, A2-43 / A7-26). Read-only, and nothing in it is run
/// or looked up:
/// - one entry per literal `Host` name; a pattern with `*`, `?` or `!` names
///   no host and is skipped, and so are `Match` blocks - their criteria
///   (`exec` among them) are never evaluated, so their settings apply to
///   nothing here (`Match all`, which matches everything, is the exception);
/// - an entry's values are the ones `ssh <name>` would use: the first value
///   obtained wins, taken from every block whose patterns match the name;
/// - `Include` is followed one level - from this file only, and only where it
///   is unconditional (before any Host/Match block, under `Host *` or
///   `Match all`). Relative paths are under `~/.ssh`, `~` is the home
///   directory, wildcards are expanded in lexical order;
/// - bounded by the `USER_CONFIG_MAX_*` limits.
///
/// A missing file is an empty list, not an error.
pub fn read_user_ssh_config(path: &Path) -> Result<Vec<SshHostConfig>> {
    let home = dirs::home_dir();
    let ssh_dir = match &home {
        Some(home) => home.join(".ssh"),
        None => path.parent().map(Path::to_path_buf).unwrap_or_default(),
    };
    read_user_ssh_config_in(path, &ssh_dir, home.as_deref())
}

/// [`read_user_ssh_config`] with `~/.ssh` and `~` given, so tests can use a
/// temp dir.
fn read_user_ssh_config_in(
    path: &Path,
    ssh_dir: &Path,
    home: Option<&Path>,
) -> Result<Vec<SshHostConfig>> {
    read_user_ssh_config_with(path, ssh_dir, home, USER_CONFIG_MAX_SCANNED)
}

/// [`read_user_ssh_config_in`] with the directory-entry budget given.
fn read_user_ssh_config_with(
    path: &Path,
    ssh_dir: &Path,
    home: Option<&Path>,
    scan_budget: usize,
) -> Result<Vec<SshHostConfig>> {
    let Some(text) = read_config_text(path)? else {
        return Ok(Vec::new());
    };
    let mut reader = UserConfigReader {
        ssh_dir,
        home,
        blocks: Vec::new(),
        included: 0,
        scan_budget,
    };
    reader.parse(&text, true, Scope::All);
    Ok(reader.hosts())
}

/// The text of a config file, refused past `USER_CONFIG_MAX_BYTES`: at most
/// one byte more than the cap is ever read, whatever size the file claimed
/// or grows to while it is read.
fn read_capped(reader: impl std::io::Read) -> Result<String> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    reader
        .take(USER_CONFIG_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > USER_CONFIG_MAX_BYTES {
        anyhow::bail!("{}", too_large());
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Why a config file over the size cap is not read.
fn too_large() -> String {
    format!("it is larger than {} MiB", USER_CONFIG_MAX_BYTES >> 20)
}

/// One config file's text (bytes that are not UTF-8 become U+FFFD); `None`
/// when the file does not exist. The errors do not repeat the path: callers
/// say "Could not read <path>: <reason>".
pub(crate) fn read_config_text(path: &Path) -> Result<Option<String>> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !meta.is_file() {
        anyhow::bail!("it is not a regular file");
    }
    if meta.len() > USER_CONFIG_MAX_BYTES {
        anyhow::bail!("{}", too_large());
    }
    let text = read_capped(fs::File::open(path)?)?;
    Ok(Some(text))
}

/// Which hosts a block of the config applies to.
#[derive(Clone)]
enum Scope {
    /// Every host: the lines before the first Host/Match, or `Match all`.
    All,
    /// A `Host` line's patterns, as written.
    Hosts(Vec<String>),
    /// A `Match` block other than `Match all`: never evaluated.
    Skipped,
}

impl Scope {
    /// An `Include` here would be read for every host.
    fn unconditional(&self) -> bool {
        match self {
            Scope::All => true,
            Scope::Hosts(patterns) => patterns.len() == 1 && patterns[0] == "*",
            Scope::Skipped => false,
        }
    }

    /// OpenSSH's Host matching: some pattern matches and no negated one does.
    fn applies_to(&self, alias: &str) -> bool {
        match self {
            Scope::All => true,
            Scope::Skipped => false,
            Scope::Hosts(patterns) => {
                let mut matched = false;
                for pattern in patterns {
                    match pattern.strip_prefix('!') {
                        Some(negated) if wildcard_match(negated, alias, false) => return false,
                        Some(_) => {}
                        None => matched |= wildcard_match(pattern, alias, false),
                    }
                }
                matched
            }
        }
    }
}

/// A run of directives with the scope they apply to.
struct Block {
    scope: Scope,
    directives: Vec<(String, Vec<String>)>,
}

struct UserConfigReader<'a> {
    ssh_dir: &'a Path,
    home: Option<&'a Path>,
    blocks: Vec<Block>,
    included: usize,
    /// Directory entries the `Include` wildcards may still look at.
    scan_budget: usize,
}

impl UserConfigReader<'_> {
    /// Parse one file into blocks, starting in `scope` (an included file
    /// starts where its `Include` line was).
    fn parse(&mut self, text: &str, main_file: bool, scope: Scope) {
        self.blocks.push(Block {
            scope,
            directives: Vec::new(),
        });
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        for line in text.lines() {
            let line = config_line(line);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let directive = split_keyword(line);
            let block_line = matches!(&directive, Some((k, _)) if k == "host" || k == "match");
            // A `Host` or `Match` line ssh does not read as one - no argument,
            // or `Host\u{a0}x` - still starts a block, one that applies to
            // nothing (see [`names_a_block`]).
            if !block_line && names_a_block(line) {
                self.blocks.push(Block {
                    scope: Scope::Skipped,
                    directives: Vec::new(),
                });
                continue;
            }
            let Some((keyword, rest)) = directive else {
                continue;
            };
            // ProxyCommand is a shell command line, not ssh_config words.
            let args = if keyword == "proxycommand" {
                vec![rest.to_string()]
            } else {
                match split_config_args(rest) {
                    Some(args) if !args.is_empty() => args,
                    // A Host or Match line that cannot be parsed still starts
                    // a block - one that applies to nothing - so the
                    // directives under it go with it instead of landing in
                    // the block before (after `Host *`: every host).
                    _ if keyword == "host" || keyword == "match" => {
                        self.blocks.push(Block {
                            scope: Scope::Skipped,
                            directives: Vec::new(),
                        });
                        continue;
                    }
                    _ => continue,
                }
            };
            match keyword.as_str() {
                "host" => self.blocks.push(Block {
                    scope: Scope::Hosts(args),
                    directives: Vec::new(),
                }),
                "match" => {
                    let all = args.len() == 1 && args[0].eq_ignore_ascii_case("all");
                    self.blocks.push(Block {
                        scope: if all { Scope::All } else { Scope::Skipped },
                        directives: Vec::new(),
                    });
                }
                "include" => {
                    let scope = self.current_scope();
                    if main_file && scope.unconditional() {
                        for pattern in &args {
                            self.include(pattern, &scope);
                        }
                        // The including file goes on where it was.
                        self.blocks.push(Block {
                            scope,
                            directives: Vec::new(),
                        });
                    }
                }
                _ => {
                    if let Some(block) = self.blocks.last_mut() {
                        block.directives.push((keyword, args));
                    }
                }
            }
        }
    }

    fn current_scope(&self) -> Scope {
        self.blocks
            .last()
            .map(|b| b.scope.clone())
            .unwrap_or(Scope::All)
    }

    fn include(&mut self, pattern: &str, scope: &Scope) {
        let path = match self.expand_home(pattern) {
            path if path.is_absolute() => path,
            relative => self.ssh_dir.join(relative),
        };
        for file in expand_include_glob(&path, &mut self.scan_budget) {
            if self.included >= USER_CONFIG_MAX_INCLUDES {
                return;
            }
            // An unreadable or oversized include is skipped, not fatal.
            if let Ok(Some(text)) = read_config_text(&file) {
                self.included += 1;
                self.parse(&text, false, scope.clone());
            }
        }
    }

    /// `~` and `~/...` under the home directory; anything else as written.
    fn expand_home(&self, value: &str) -> PathBuf {
        match (value.strip_prefix('~'), self.home) {
            (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with(['/', '\\']) => rest
                .split(['/', '\\'])
                .filter(|part| !part.is_empty())
                .fold(home.to_path_buf(), |path, part| path.join(part)),
            _ => PathBuf::from(value),
        }
    }

    /// One entry per literal Host name, in order of first appearance.
    fn hosts(&self) -> Vec<SshHostConfig> {
        self.literal_aliases()
            .into_iter()
            .map(|alias| self.resolve(alias))
            .collect()
    }

    /// The literal Host names, each once, in order of first appearance, at
    /// most `USER_CONFIG_MAX_HOSTS`. A set answers "seen already?" - the old
    /// `Vec::contains` made this quadratic in the number of names (a 1 MiB
    /// file holds over 100 000), and the scan stops once the cap is reached.
    fn literal_aliases(&self) -> Vec<&str> {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut aliases: Vec<&str> = Vec::new();
        for block in &self.blocks {
            let Scope::Hosts(patterns) = &block.scope else {
                continue;
            };
            for pattern in patterns {
                let literal = !pattern.is_empty() && !pattern.contains(['*', '?', '!']);
                if literal && seen.insert(pattern.as_str()) {
                    aliases.push(pattern.as_str());
                    if aliases.len() == USER_CONFIG_MAX_HOSTS {
                        return aliases;
                    }
                }
            }
        }
        aliases
    }

    /// What `ssh <alias>` would use: the first value obtained wins.
    fn resolve(&self, alias: &str) -> SshHostConfig {
        fn first<T>(slot: &mut Option<T>, value: impl FnOnce() -> T) {
            if slot.is_none() {
                *slot = Some(value());
            }
        }
        let not_none = |v: &str| (!v.eq_ignore_ascii_case("none")).then(|| v.to_string());
        let (mut hostname, mut user, mut port, mut identity_file) = (None, None, None, None);
        let (mut identities_only, mut forward_agent) = (None, None);
        let (mut proxy_jump, mut proxy_command) = (None, None);
        for block in self.blocks.iter().filter(|b| b.scope.applies_to(alias)) {
            for (keyword, args) in &block.directives {
                let value = args[0].as_str();
                match keyword.as_str() {
                    "hostname" => first(&mut hostname, || expand_hostname(value, alias)),
                    "user" => first(&mut user, || value.to_string()),
                    "port" => first(&mut port, || value.parse::<u16>().ok().filter(|p| *p > 0)),
                    "identityfile" => first(&mut identity_file, || {
                        self.expand_home(value).to_string_lossy().into_owned()
                    }),
                    "identitiesonly" => first(&mut identities_only, || {
                        value.eq_ignore_ascii_case("yes") || value.eq_ignore_ascii_case("true")
                    }),
                    "forwardagent" => first(&mut forward_agent, || {
                        !(value.eq_ignore_ascii_case("no") || value.eq_ignore_ascii_case("false"))
                    }),
                    "proxyjump" => first(&mut proxy_jump, || not_none(value)),
                    "proxycommand" => first(&mut proxy_command, || not_none(value)),
                    _ => {}
                }
            }
        }
        let mut extra = std::collections::HashMap::new();
        if let Some(command) = proxy_command.flatten() {
            extra.insert("proxycommand".to_string(), command);
        }
        SshHostConfig {
            host: alias.to_string(),
            hostname,
            user,
            port: port.flatten(),
            identity_file,
            identities_only,
            forward_agent,
            proxy_jump: proxy_jump.flatten(),
            extra,
        }
    }
}

/// A directive line split like OpenSSH's `strdelim`: the keyword (lower
/// case) ends at ` \t\r\n` or `=` - no other whitespace (`Host\u{a0}a` is one
/// unknown keyword to ssh, not a Host line) - then one `=` may follow. A
/// keyword with nothing after it is no directive. `line` is a
/// [`config_line`].
fn split_keyword(line: &str) -> Option<(String, &str)> {
    let end = line.find(|c: char| is_config_space(c) || c == '=')?;
    let rest = line[end..].trim_start_matches(is_config_space);
    let rest = rest
        .strip_prefix('=')
        .unwrap_or(rest)
        .trim_start_matches(is_config_space);
    if rest.is_empty() {
        return None;
    }
    Some((line[..end].to_ascii_lowercase(), rest))
}

/// One `Host` line of an ssh_config file, as the deploy preview reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostLine {
    /// 1-based line number in the file.
    pub line: usize,
    /// The line as written, trimmed.
    pub text: String,
    /// Its patterns as ssh splits them; `None` when ssh cannot split the line
    /// at all (an unbalanced quote - `Host bob's-key` - stops ssh from reading
    /// the file).
    pub patterns: Option<Vec<String>>,
    /// The `IdentityFile`s set in its block, as written (unquoted).
    pub identity_files: Vec<String>,
}

/// Every `Host` line of an ssh_config text, with its line number and the
/// `IdentityFile`s of its block (up to the next Host or Match line).
pub(crate) fn host_lines(text: &str) -> Vec<HostLine> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut found: Vec<HostLine> = Vec::new();
    let mut in_host_block = false;
    for (i, raw) in text.lines().enumerate() {
        let line = config_line(raw);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let directive = split_keyword(line);
        match directive {
            Some((keyword, rest)) if keyword == "host" => {
                found.push(HostLine {
                    line: i + 1,
                    text: line.to_string(),
                    patterns: split_config_args(rest).filter(|args| !args.is_empty()),
                    identity_files: Vec::new(),
                });
                in_host_block = true;
            }
            _ if names_a_block(line) => in_host_block = false,
            Some((keyword, rest)) if keyword == "identityfile" && in_host_block => {
                if let Some(block) = found.last_mut() {
                    block.identity_files.push(config_word(rest));
                }
            }
            _ => {}
        }
    }
    found
}

/// `HostName`'s two tokens: `%h` is the alias, `%%` a percent sign.
fn expand_hostname(value: &str, alias: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(alias),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// The files an `Include` argument names, expanded as `glob(3)` would:
/// wildcards (`*`, `?`, `[...]`) in any component, a leading dot matched only
/// by a pattern that starts with one, results in lexical order. Every
/// directory entry looked at is taken from `budget`, shared by the whole read
/// (`USER_CONFIG_MAX_SCANNED`); at most `USER_CONFIG_MAX_INCLUDES` files.
fn expand_include_glob(path: &Path, budget: &mut usize) -> Vec<PathBuf> {
    let mut found = vec![PathBuf::new()];
    for component in path.components() {
        let part = component.as_os_str();
        let pattern = part.to_string_lossy();
        let wild = matches!(component, Component::Normal(_)) && pattern.contains(['*', '?', '[']);
        if !wild {
            for path in &mut found {
                path.push(part);
            }
            continue;
        }
        let mut next = Vec::new();
        for dir in &found {
            if *budget == 0 {
                break;
            }
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            for entry in entries {
                if *budget == 0 {
                    break;
                }
                *budget -= 1;
                let Ok(entry) = entry else {
                    continue;
                };
                let name = entry.file_name();
                let text = name.to_string_lossy();
                if text.starts_with('.') && !pattern.starts_with('.') {
                    continue;
                }
                if wildcard_match(&pattern, &text, true) {
                    next.push(dir.join(&name));
                }
            }
        }
        found = next;
    }
    let mut files: Vec<PathBuf> = found.into_iter().filter(|p| p.is_file()).collect();
    files.sort_by(|a, b| a.as_os_str().cmp(b.as_os_str()));
    files.truncate(USER_CONFIG_MAX_INCLUDES);
    files
}

/// `*` (any run), `?` (one character) and - when `classes` - `[...]` sets
/// with ranges and `!`/`^` negation. Host patterns use only `*` and `?`, as
/// in OpenSSH's `match_pattern`; Include paths use the `glob(3)` sets too.
fn wildcard_match(pattern: &str, text: &str, classes: bool) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    // Where the last `*` was, and how much text it has taken so far.
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        let step = match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
                continue;
            }
            Some('?') => Some(pi + 1),
            Some('[') if classes => match class_match(&p[pi..], t[ti]) {
                Some((true, len)) => Some(pi + len),
                Some((false, _)) => None,
                // No closing bracket: a literal `[`.
                None => (t[ti] == '[').then_some(pi + 1),
            },
            Some(&c) => (c == t[ti]).then_some(pi + 1),
            None => None,
        };
        match (step, star) {
            (Some(next), _) => {
                pi = next;
                ti += 1;
            }
            (None, Some((star_pi, star_ti))) => {
                pi = star_pi + 1;
                ti = star_ti + 1;
                star = Some((star_pi, star_ti + 1));
            }
            (None, None) => return false,
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// A `[...]` set at the start of `p` against `c`: whether it matched and how
/// many pattern characters it used; `None` when the set is not closed.
fn class_match(p: &[char], c: char) -> Option<(bool, usize)> {
    let mut i = 1;
    let negated = matches!(p.get(i), Some('!' | '^'));
    if negated {
        i += 1;
    }
    let mut matched = false;
    let start = i;
    while i < p.len() {
        if p[i] == ']' && i > start {
            return Some((matched != negated, i + 1));
        }
        if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|&end| end != ']') {
            matched |= p[i] <= c && c <= p[i + 2];
            i += 3;
        } else {
            matched |= p[i] == c;
            i += 1;
        }
    }
    None
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

    /// RU6a item 8: a bare `Host` line in the managed file ends the stanza
    /// before it. Its lines used to be filed into that stanza, so a deploy's
    /// rewrite of the file applied them to the previous host.
    #[test]
    fn ru6a_the_managed_parser_keeps_a_bare_host_block_apart() {
        let text = "Host a\n    User alice\nHost\n    HostName evil.example\n    User mallory\n\
                    Host b\n    HostName b.example\n";
        let parsed = SshConfig::parse(text);
        let a = parsed.hosts.iter().find(|h| h.host == "a").unwrap();
        assert_eq!(a.hostname, None, "{parsed:?}");
        assert_eq!(a.user.as_deref(), Some("alice"), "{parsed:?}");
        let b = parsed.hosts.iter().find(|h| h.host == "b").unwrap();
        assert_eq!(b.hostname.as_deref(), Some("b.example"));
        // A rewrite keeps it that way.
        let out = parsed.to_config_string();
        let back = SshConfig::parse(&out);
        let a = back.hosts.iter().find(|h| h.host == "a").unwrap();
        assert_eq!(
            (a.hostname.as_deref(), a.user.as_deref()),
            (None, Some("alice")),
            "{out}"
        );
    }

    /// RU6a item 11: the deploy preview lists `Host` lines with their line
    /// numbers - including one ssh cannot even split (`Host bob's-key`).
    #[test]
    fn ru6a_host_lines_come_with_line_numbers_even_when_ssh_cannot_split_them() {
        let text = "# comment\nHost web\n  HostName x\nhost bob's-key\nMatch all\n\
                    Host=a b\n  Host inner\nHostName not-a-host-line\n";
        let lines = host_lines(text);
        let got: Vec<(usize, &str, Option<Vec<&str>>)> = lines
            .iter()
            .map(|l| {
                (
                    l.line,
                    l.text.as_str(),
                    l.patterns
                        .as_ref()
                        .map(|p| p.iter().map(String::as_str).collect()),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (2, "Host web", Some(vec!["web"])),
                (4, "host bob's-key", None),
                (6, "Host=a b", Some(vec!["a", "b"])),
                (7, "Host inner", Some(vec!["inner"])),
            ]
        );
    }
}

/// RU4 / R4: the import reads the user's own ssh config - fixture files in a
/// temp dir stand in for `~` and `~/.ssh`.
#[cfg(test)]
mod ru4_user_config_tests {
    use super::*;
    use std::path::Path;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("sshspan-ru4-config-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(root.join(".ssh")).unwrap();
            Self { root }
        }

        fn ssh_dir(&self) -> PathBuf {
            self.root.join(".ssh")
        }

        fn write(&self, rel: &str, text: &str) -> PathBuf {
            let path = self.ssh_dir().join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, text).unwrap();
            path
        }

        fn read(&self) -> Vec<SshHostConfig> {
            read_user_ssh_config_in(
                &self.ssh_dir().join("config"),
                &self.ssh_dir(),
                Some(&self.root),
            )
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn names(hosts: &[SshHostConfig]) -> Vec<&str> {
        hosts.iter().map(|h| h.host.as_str()).collect()
    }

    fn host<'a>(hosts: &'a [SshHostConfig], alias: &str) -> &'a SshHostConfig {
        hosts
            .iter()
            .find(|h| h.host == alias)
            .unwrap_or_else(|| panic!("{alias} missing from {:?}", names(hosts)))
    }

    const MAIN: &str = "\u{feff}# A comment, then a byte-order mark the editor left\n\
        Include conf.d/*.conf extra.conf ~/.ssh/home.conf /does/not/exist.conf\n\
        Host a\n\
        \x20   HostName a.example.com\n\
        \x20   Port=2201\n\
        \x20   IdentityFile \"~/.ssh/id a\"\n\
        \x20   IdentityFile ~/.ssh/second\n\
        Host web*.example.com ?x !neg\n\
        \x20   HostName never\n\
        Match host a exec \"touch /tmp/sshspan-ru4-must-not-run\"\n\
        \x20   User match-user\n\
        \x20   Include match.conf\n\
        Host b c\n\
        \x20   HostName %h.corp.example\n\
        \x20   Include host-only.conf\n\
        Host a\n\
        \x20   User late-a\n\
        \x20   HostName ignored-later\n\
        Host * !c\n\
        \x20   User star-user\n\
        \x20   Port 2299\n";

    fn main_fixture() -> Fixture {
        let f = Fixture::new();
        f.write("config", MAIN);
        f.write(
            "conf.d/10-first.conf",
            "Host inc1\n  HostName inc1.example\n  Include nested.conf\n",
        );
        f.write("conf.d/20-second.conf", "Host inc2\n  User second\n");
        f.write("conf.d/.hidden.conf", "Host hidden\n");
        f.write("conf.d/notes.txt", "Host txt\n");
        f.write("extra.conf", "Host extra\n");
        f.write("home.conf", "Host home\n");
        f.write("nested.conf", "Host nested\n");
        f.write("match.conf", "Host from-match\n");
        f.write("host-only.conf", "Host from-host-block\n");
        f
    }

    #[test]
    fn ru4_missing_user_config_is_an_empty_list_not_an_error() {
        let f = Fixture::new();
        assert!(f.read().is_empty());
    }

    /// Literal hosts only, in order of appearance: wildcard and negated
    /// patterns and `Match` blocks are skipped, `Include` is followed one
    /// level (relative to `~/.ssh`, `~` expanded, globs in lexical order,
    /// hidden files only when asked for), never from inside a Host or Match
    /// block, never from an included file.
    #[test]
    fn ru4_imports_literal_hosts_and_follows_include_one_level() {
        let f = main_fixture();
        let hosts = f.read();
        assert_eq!(
            names(&hosts),
            ["inc1", "inc2", "extra", "home", "a", "b", "c"]
        );
        assert!(!Path::new("/tmp/sshspan-ru4-must-not-run").exists());
    }

    /// Values as `ssh <alias>` would use them: the first value obtained wins,
    /// from every Host block whose patterns match (`*`, `?`, `!`), `%h` in
    /// HostName is the alias, `~` in IdentityFile is the home directory.
    #[test]
    fn ru4_resolves_values_like_openssh_first_match_wins() {
        let f = main_fixture();
        let hosts = f.read();
        let a = host(&hosts, "a");
        assert_eq!(a.hostname.as_deref(), Some("a.example.com"));
        assert_eq!(a.port, Some(2201));
        assert_eq!(a.user.as_deref(), Some("late-a"));
        let id_a = f.root.join(".ssh").join("id a");
        assert_eq!(a.identity_file.as_deref(), Some(id_a.to_str().unwrap()));
        assert_eq!(
            host(&hosts, "b").hostname.as_deref(),
            Some("b.corp.example")
        );
        assert_eq!(host(&hosts, "b").user.as_deref(), Some("star-user"));
        assert_eq!(host(&hosts, "b").port, Some(2299));
        let c = host(&hosts, "c");
        assert_eq!(c.hostname.as_deref(), Some("c.corp.example"));
        assert_eq!(
            (c.user.as_deref(), c.port),
            (None, None),
            "`Host * !c` excludes c"
        );
        assert_eq!(
            host(&hosts, "inc1").hostname.as_deref(),
            Some("inc1.example")
        );
        assert_eq!(host(&hosts, "inc2").user.as_deref(), Some("second"));
        assert_eq!(host(&hosts, "extra").user.as_deref(), Some("star-user"));
    }

    /// The renderer warns about directives SSHSpan does not implement, so
    /// they must survive the import, including a ProxyCommand whose shell
    /// quoting is not ssh_config quoting.
    #[test]
    fn ru4_keeps_markers_for_unsupported_proxy_and_agent_directives() {
        let f = Fixture::new();
        f.write(
            "config",
            "Host jump\n  ProxyJump bastion\n  ForwardAgent yes\n\
             Host cmd\n  ProxyCommand sh -c 'nc %h %p\n\
             Host none\n  ProxyJump none\n  ForwardAgent no\n  ProxyCommand none\n",
        );
        let hosts = f.read();
        let jump = host(&hosts, "jump");
        assert_eq!(jump.proxy_jump.as_deref(), Some("bastion"));
        assert_eq!(jump.forward_agent, Some(true));
        assert_eq!(
            host(&hosts, "cmd")
                .extra
                .get("proxycommand")
                .map(String::as_str),
            Some("sh -c 'nc %h %p")
        );
        let none = host(&hosts, "none");
        assert_eq!(none.proxy_jump, None);
        assert_eq!(none.forward_agent, Some(false));
        assert!(none.extra.is_empty());
    }

    /// `Match all` matches everything, so an `Include` after it is followed;
    /// any other `Match` block is skipped.
    #[test]
    fn ru4_match_all_is_unconditional() {
        let f = Fixture::new();
        f.write(
            "config",
            "Host x\n  User x-user\nMatch all\nInclude late.conf\nUser everyone\n",
        );
        f.write("late.conf", "Host late\n");
        let hosts = f.read();
        assert_eq!(names(&hosts), ["x", "late"]);
        assert_eq!(host(&hosts, "late").user.as_deref(), Some("everyone"));
    }

    /// Bounded: a glob brings in at most the cap of files, oversized files
    /// are skipped, and bytes that are not UTF-8 do not stop the read.
    #[test]
    fn ru4_include_is_bounded_and_tolerates_odd_files() {
        let f = Fixture::new();
        f.write(
            "config",
            "Include latin1.conf\nInclude big.conf\nInclude many/*\n",
        );
        for i in 0..(USER_CONFIG_MAX_INCLUDES + 10) {
            f.write(&format!("many/{i:03}.conf"), &format!("Host many{i:03}\n"));
        }
        let mut big = String::from("Host big\n");
        big.push_str(&"# padding\n".repeat((USER_CONFIG_MAX_BYTES as usize / 10) + 10));
        f.write("big.conf", &big);
        fs::write(
            f.ssh_dir().join("latin1.conf"),
            b"Host latin1\n  User caf\xe9\n",
        )
        .unwrap();
        let hosts = f.read();
        let many = hosts.iter().filter(|h| h.host.starts_with("many")).count();
        assert!(many <= USER_CONFIG_MAX_INCLUDES, "{many} files included");
        assert!(!names(&hosts).contains(&"big"));
        assert_eq!(host(&hosts, "latin1").user.as_deref(), Some("caf\u{FFFD}"));
    }

    /// Review fix 7: the size cap holds for what is actually read, not for
    /// what the file's metadata claimed a moment earlier.
    #[test]
    fn ru4_config_reads_stop_at_the_size_cap() {
        struct Counting<R>(R, std::rc::Rc<std::cell::Cell<u64>>);
        impl<R: std::io::Read> std::io::Read for Counting<R> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.read(buf)?;
                self.1.set(self.1.get() + n as u64);
                Ok(n)
            }
        }
        use std::io::Read as _;
        let read = std::rc::Rc::new(std::cell::Cell::new(0));
        let huge = std::io::repeat(b'#').take(USER_CONFIG_MAX_BYTES * 4);
        assert!(read_capped(Counting(huge, read.clone())).is_err());
        assert!(
            read.get() <= USER_CONFIG_MAX_BYTES + 1,
            "read {} bytes",
            read.get()
        );
        let small = Counting(&b"Host a\n"[..], read.clone());
        assert_eq!(read_capped(small).unwrap(), "Host a\n");
    }

    /// Review fix 6: every wildcard in every `Include` draws on one budget
    /// of directory entries for the whole read, not a fresh one per folder.
    #[test]
    fn ru4_include_globs_share_one_scan_budget() {
        let f = Fixture::new();
        f.write("config", "Include */x*.conf\n");
        for dir in ["a", "b"] {
            for i in 0..5 {
                f.write(&format!("{dir}/x{i}.conf"), &format!("Host {dir}{i}\n"));
            }
        }
        let all = f.read();
        assert_eq!(all.len(), 10, "{:?}", names(&all));
        let budget = 6;
        let hosts = read_user_ssh_config_with(
            &f.ssh_dir().join("config"),
            &f.ssh_dir(),
            Some(&f.root),
            budget,
        )
        .unwrap();
        assert!(hosts.len() <= budget, "{:?}", names(&hosts));
        assert!(hosts.len() < all.len(), "{:?}", names(&hosts));
    }

    /// Review fix 8: a `Host` (or `Match`) line ssh_config cannot parse
    /// starts a block that applies to nothing - its directives used to land
    /// in the block before it (after `Host *`: every imported host).
    #[test]
    fn ru4_an_unparseable_host_line_takes_its_directives_with_it() {
        let f = Fixture::new();
        f.write(
            "config",
            "Host ok\n  User ok-user\nHost *\n  Port 2222\n\
             Host \"broken\n  HostName evil.example\n  User injected\n\
             Match host \"broken\n  IdentityFile /evil/key\n\
             Host later\n",
        );
        let hosts = f.read();
        assert_eq!(names(&hosts), ["ok", "later"]);
        for h in &hosts {
            assert_eq!(h.hostname, None, "{}", h.host);
            assert_eq!(h.identity_file, None, "{}", h.host);
            assert_eq!(h.port, Some(2222), "{}", h.host);
        }
        assert_eq!(host(&hosts, "ok").user.as_deref(), Some("ok-user"));
        assert_eq!(host(&hosts, "later").user, None);
    }

    /// RU6a item 8: a `Host` or `Match` line with NO argument (`Host`,
    /// `Match`, `Host =`) starts a block that applies to nothing. Its lines
    /// used to land in the block before it - after `Host *`: every host.
    #[test]
    fn ru6a_a_bare_host_or_match_line_takes_its_directives_with_it() {
        let f = Fixture::new();
        f.write(
            "config",
            "Host ok\n  User ok-user\nHost *\n  Port 2222\n\
             Host\n  HostName evil.example\n  User injected\n\
             Match\n  IdentityFile /evil/key\n\
             Host =\n  ProxyJump evil-jump\n\
             host\n  ForwardAgent yes\n\
             Host later\n",
        );
        let hosts = f.read();
        assert_eq!(names(&hosts), ["ok", "later"]);
        for h in &hosts {
            assert_eq!(h.hostname, None, "{}", h.host);
            assert_eq!(h.identity_file, None, "{}", h.host);
            assert_eq!(h.proxy_jump, None, "{}", h.host);
            assert_eq!(h.forward_agent, None, "{}", h.host);
            assert_eq!(h.port, Some(2222), "{}", h.host);
        }
        assert_eq!(host(&hosts, "ok").user.as_deref(), Some("ok-user"));
        assert_eq!(host(&hosts, "later").user, None);
    }

    /// RU6a item 8: collecting the literal names used `Vec::contains` for
    /// every pattern - quadratic in the number of names, and it only cut the
    /// list to the cap at the end. A config of many short names (a 1 MiB
    /// file holds over 100 000) made the import hang. A set, and the scan
    /// stops at the cap.
    #[test]
    fn ru6a_imported_aliases_are_deduplicated_with_a_set_and_stop_at_the_cap() {
        let reader = |patterns: Vec<String>| UserConfigReader {
            ssh_dir: Path::new("/"),
            home: None,
            blocks: vec![Block {
                scope: Scope::Hosts(patterns),
                directives: Vec::new(),
            }],
            included: 0,
            scan_budget: 0,
        };
        let bound = std::time::Duration::from_secs(3);

        // Fewer names than the cap, each repeated many times.
        let distinct: Vec<String> = (0..USER_CONFIG_MAX_HOSTS - 1)
            .map(|i| format!("h{i}"))
            .collect();
        let mut repeated = Vec::with_capacity(distinct.len() * 301);
        for _ in 0..301 {
            repeated.extend(distinct.iter().cloned());
        }
        let r = reader(repeated);
        let started = std::time::Instant::now();
        let aliases = r.literal_aliases();
        let took = started.elapsed();
        assert!(
            aliases
                .iter()
                .copied()
                .eq(distinct.iter().map(String::as_str)),
            "each name once, in order of first appearance"
        );
        assert!(took < bound, "repeated names took {took:?}");

        // Far more distinct names than the cap: the first ones, cut at the cap.
        let many: Vec<String> = (0..60_000).map(|i| format!("n{i}")).collect();
        let r = reader(many.clone());
        let started = std::time::Instant::now();
        let aliases = r.literal_aliases();
        let took = started.elapsed();
        assert_eq!(aliases.len(), USER_CONFIG_MAX_HOSTS);
        assert!(aliases
            .iter()
            .copied()
            .eq(many[..USER_CONFIG_MAX_HOSTS].iter().map(String::as_str)));
        assert!(took < bound, "60 000 names took {took:?}");
    }

    /// RU6a item 10: the caller says "Could not read <path>: <reason>", so the
    /// reason must not repeat the path ("Could not read /x: /x is larger
    /// than ...").
    #[test]
    fn ru6a_an_unreadable_config_names_its_path_once() {
        let f = Fixture::new();
        let mut big = String::from("Host big\n");
        big.push_str(&"# padding\n".repeat((USER_CONFIG_MAX_BYTES as usize / 10) + 10));
        let path = f.write("config", &big);
        let dir = f.ssh_dir().join("a-folder");
        fs::create_dir_all(&dir).unwrap();
        for target in [&path, &dir] {
            let err = read_user_ssh_config_in(target, &f.ssh_dir(), Some(&f.root))
                .unwrap_err()
                .to_string();
            // What `ssh_config_list_hosts` shows.
            let shown = format!("Could not read {}: {err}", target.display());
            assert_eq!(
                shown.matches(&target.display().to_string()).count(),
                1,
                "{shown}"
            );
        }
        let err = read_user_ssh_config_in(&path, &f.ssh_dir(), Some(&f.root))
            .unwrap_err()
            .to_string();
        assert!(err.contains("1 MiB"), "{err}");
    }

    /// The parser agrees with OpenSSH itself (`ssh -G`) on every imported
    /// host. Skipped when no ssh client is installed; Unix only.
    #[cfg(unix)]
    #[test]
    fn ru4_resolved_values_agree_with_ssh_g() {
        if std::process::Command::new("ssh")
            .arg("-V")
            .output()
            .is_err()
        {
            eprintln!("skipped: no ssh client on PATH");
            return;
        }
        let f = Fixture::new();
        let dir = f.ssh_dir();
        let d = dir.display();
        // Absolute include paths: `ssh -F` resolves relative ones against the
        // running user's real ~/.ssh. No `Match exec`: ssh would run it.
        let text = MAIN
            .replace('\u{feff}', "")
            .replace(
                "Include conf.d/*.conf extra.conf ~/.ssh/home.conf /does/not/exist.conf",
                &format!("Include \"{d}/conf.d/*.conf\""),
            )
            .replace("\"~/.ssh/id a\"", &format!("\"{d}/id a\""))
            .replace("~/.ssh/second", &format!("{d}/second"))
            .replace(
                "Match host a exec \"touch /tmp/sshspan-ru4-must-not-run\"",
                "Match host never.invalid",
            )
            .replace("    Include match.conf\n", "")
            .replace("    Include host-only.conf\n", "");
        let main = f.write("config", &text);
        f.write(
            "conf.d/10-first.conf",
            "Host inc1\n  HostName inc1.example\n",
        );
        f.write("conf.d/20-second.conf", "Host inc2\n  User second\n");
        let hosts = f.read();
        assert_eq!(names(&hosts), ["inc1", "inc2", "a", "b", "c"]);
        let mut problems = Vec::new();
        for h in &hosts {
            let out = std::process::Command::new("ssh")
                .arg("-G")
                .arg("-F")
                .arg(&main)
                .arg(&h.host)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut wanted = vec![
                format!("hostname {}", h.hostname.as_deref().unwrap_or(&h.host)),
                format!("port {}", h.port.unwrap_or(22)),
            ];
            if let Some(user) = &h.user {
                wanted.push(format!("user {user}"));
            }
            if let Some(id) = &h.identity_file {
                wanted.push(format!("identityfile {id}"));
            }
            for w in wanted {
                if !out.status.success() || !stdout.lines().any(|l| l == w) {
                    problems.push(format!(
                        "{}: ssh -G lacks {w:?} ({})",
                        h.host,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
            }
        }
        assert!(problems.is_empty(), "{}\n{text}", problems.join("\n"));

        // RU6a item 8: a bare `Host` / `Match` line. OpenSSH 8.7 and later
        // refuse the whole file ("no argument after keyword"); older ones take
        // the bare `Host` as a block that matches nothing. Either way ssh never
        // applies the lines under it to another host - and neither may the
        // import, which reads around the bad line instead of refusing the file.
        for bare in ["Host", "Match"] {
            let text = format!("Host *\n  Port 2222\n{bare}\n  HostName leaked.example\nHost a\n");
            let cfg = f.write("bare.conf", &text);
            let out = std::process::Command::new("ssh")
                .arg("-G")
                .arg("-F")
                .arg(&cfg)
                .arg("a")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                !out.status.success() || !stdout.lines().any(|l| l == "hostname leaked.example"),
                "ssh -G applied the bare {bare} block to another host:\n{stdout}"
            );
            let hosts = read_user_ssh_config_in(&cfg, &dir, Some(&f.root)).unwrap();
            assert_eq!(names(&hosts), ["a"], "{bare}");
            assert_eq!(host(&hosts, "a").hostname, None, "{bare}: {text}");
            assert_eq!(host(&hosts, "a").port, Some(2222), "{bare}");
        }
    }

    /// RU6a fix round 1, item 11: OpenSSH ends a keyword at ` \t\r\n` or `=`
    /// only, and trims a line of those (and trailing form feeds) only.
    /// `Host\u{a0}a` was imported as host `a` while `ssh -G` refuses the
    /// file: such a line is no Host line now - it starts a block that
    /// applies to nothing, like any Host line ssh cannot read - and the
    /// deploy preview and the managed config read it the same way.
    #[test]
    fn ru6a_fix1_only_ascii_whitespace_ends_a_keyword() {
        let f = Fixture::new();
        f.write(
            "config",
            "Host\u{a0}nbsp\n  User x\n\u{a0}Host lead\n  User y\nHost\u{3000}ideo\n\
             Host\ttab\r\n  User t\nHost=eq\nHost ff\u{c}\n",
        );
        let hosts = f.read();
        assert_eq!(names(&hosts), ["tab", "eq", "ff"]);
        assert_eq!(host(&hosts, "tab").user.as_deref(), Some("t"));
        assert_eq!(host(&hosts, "eq").user, None);

        let lines: Vec<String> = host_lines("Host\u{a0}a\nHost b\n")
            .into_iter()
            .map(|l| l.text)
            .collect();
        assert_eq!(lines, ["Host b"]);

        let managed = SshConfig::parse("Host a\n  User alice\nHost\u{a0}b\n  User bob\n");
        let names: Vec<(&str, Option<&str>)> = managed
            .hosts
            .iter()
            .map(|h| (h.host.as_str(), h.user.as_deref()))
            .collect();
        assert_eq!(names, [("a", Some("alice"))]);
    }

    /// RU6a fix round 1, item 14: the managed-config parser filed the lines
    /// after `Match <criteria>` into the Host before it (`Host a / User alice
    /// / Match host b / HostName evil.example` gave host `a` that HostName -
    /// written back to it on the next save) and skipped `Host=x`. A Match
    /// line ends the stanza (its lines apply to no host), and `Host=x` /
    /// `Host = x` are read like the user-config reader reads them.
    #[test]
    fn ru6a_fix1_the_managed_parser_ends_a_host_at_match_and_reads_host_equals() {
        let config = SshConfig::parse(
            "Host a\n  User alice\nMatch host b\n  HostName evil.example\n\
             Host=c\n  User carol\nHost = d\n  Port 22\n",
        );
        let names: Vec<&str> = config.hosts.iter().map(|h| h.host.as_str()).collect();
        assert_eq!(names, ["a", "c", "d"]);
        let a = &config.hosts[0];
        assert_eq!(
            (a.user.as_deref(), a.hostname.as_deref()),
            (Some("alice"), None)
        );
        assert!(a.extra.is_empty(), "{:?}", a.extra);
        assert_eq!(config.hosts[1].user.as_deref(), Some("carol"));
        assert_eq!(config.hosts[2].port, Some(22));
    }
}
