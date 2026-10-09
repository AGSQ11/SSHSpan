//! SSH key deployment and agent integration
//! Replaces sshConfigService.js deployment logic and parts of sshspan.js

use crate::config::{SshConfig, SshConfigService, SshHostConfig};
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

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

/// Where a deploy writes: the directory the key files go to (`~/.ssh`) and
/// SSHSpan's managed ssh_config file. They are parameters rather than lookups
/// so tests deploy into a temp dir instead of the real `~/.ssh` (A7-56); the
/// commands pass [`DeployTarget::user_default`].
#[derive(Debug, Clone)]
pub struct DeployTarget {
    pub ssh_dir: PathBuf,
    pub config_path: PathBuf,
}

impl DeployTarget {
    pub fn new(ssh_dir: impl Into<PathBuf>, config_path: impl Into<PathBuf>) -> Self {
        Self {
            ssh_dir: ssh_dir.into(),
            config_path: config_path.into(),
        }
    }

    /// `~/.ssh` and the managed config file the app really uses.
    pub fn user_default() -> Result<Self> {
        Ok(Self::new(
            crate::config::get_ssh_dir()?,
            crate::config::ssh_config_path()?,
        ))
    }

    /// The line a user adds to `~/.ssh/config` so OpenSSH reads the managed
    /// file (A5-05) - SSHSpan never edits `~/.ssh/config` itself. Quoted, so a
    /// path with spaces survives ssh_config's word splitting, with `\` and `"`
    /// escaped the way ssh_config unescapes them and `%` doubled (Include
    /// expands `%` tokens); on Windows the separators are written as `/`,
    /// which Win32-OpenSSH accepts and which keeps the path clear of that
    /// escape handling.
    pub fn include_line(&self) -> String {
        let path = self.config_path.display().to_string();
        #[cfg(windows)]
        let path = path.replace('\\', "/");
        format!(
            "Include \"{}\"",
            literal_percent(&path)
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        )
    }
}

/// `value` with every `%` doubled: IdentityFile, HostName and Include expand
/// `%` tokens, and an unknown one (`%/` in a path) makes ssh give up on the
/// host. The paths and host names a deploy writes are meant literally.
fn literal_percent(value: &str) -> String {
    value.replace('%', "%%")
}

/// Whether an IdentityFile value from the managed config names `path` -
/// written by this version (`%` doubled) or an earlier one (not).
fn identity_names(identity_file: &str, path: &Path) -> bool {
    same_path(Path::new(identity_file), path)
        || same_path(Path::new(&identity_file.replace("%%", "%")), path)
}

/// The Host fields the deploy sheet collects, written into every stanza a
/// deploy writes (ruling R3). They used to be dropped: the stanza had no
/// HostName, User or Port whatever the sheet showed (A7-04 / A2-05).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeployHostFields {
    /// The `Host` alias - see [`SshService::plan_deploy`] for how it is used.
    pub host_alias: Option<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub strict_host_key: Option<bool>,
}

/// Longest HostName / User a deploy writes (a DNS name is at most 253).
const MAX_HOST_FIELD_CHARS: usize = 255;

impl DeployHostFields {
    /// Trim each field (blank means absent) and check the ones written
    /// verbatim. HostName and User must be one word: a space adds arguments
    /// ssh_config rejects, a quote opens a quoted string ("invalid quotes" -
    /// fatal for every ssh command once the managed file is Included) and a
    /// leading `#` turns the rest of the line into a comment. The port cannot
    /// be 0. The alias may not contain `*`, `?` or `!` - they would make it a
    /// pattern matching other hosts (`Host *` with `StrictHostKeyChecking no`
    /// would apply to every host); anything else unusual in it is replaced
    /// (see [`SshService::plan_deploy`]).
    pub fn parse(
        host_alias: Option<String>,
        hostname: Option<String>,
        user: Option<String>,
        port: Option<u16>,
        strict_host_key: Option<bool>,
    ) -> std::result::Result<Self, String> {
        fn present(value: Option<String>) -> Option<String> {
            value
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        }
        fn one_word(label: &str, value: &str) -> std::result::Result<(), String> {
            if value.starts_with('#')
                || value
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\'')
            {
                return Err(format!(
                    "{label} must be a single word without spaces, quotes or control characters, and must not start with #."
                ));
            }
            if value.chars().count() > MAX_HOST_FIELD_CHARS {
                return Err(format!(
                    "{label} is too long (at most {MAX_HOST_FIELD_CHARS} characters)."
                ));
            }
            Ok(())
        }
        let host_alias = present(host_alias);
        if host_alias
            .as_deref()
            .is_some_and(|a| a.contains(['*', '?', '!']))
        {
            return Err(
                "Host alias cannot contain *, ? or ! - in ssh_config they make it a pattern that matches other hosts."
                    .into(),
            );
        }
        let hostname = present(hostname);
        let user = present(user);
        if let Some(h) = &hostname {
            one_word("HostName", h)?;
        }
        if let Some(u) = &user {
            one_word("User", u)?;
        }
        if port == Some(0) {
            return Err("Port must be between 1 and 65535.".into());
        }
        Ok(Self {
            host_alias,
            hostname,
            user,
            port,
            strict_host_key,
        })
    }
}

/// A vault key in a deploy request.
#[derive(Debug, Clone)]
pub struct DeployKey {
    pub id: String,
    pub name: String,
    /// Where the vault records this key as deployed, if anywhere.
    pub deploy_path: Option<String>,
}

/// A key's recorded deployment, for the collision check.
#[derive(Debug, Clone)]
pub struct RecordedDeployment {
    pub id: String,
    pub name: String,
    pub path: String,
}

/// One key as a deploy would write it - what the preview shows.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedKey {
    pub id: String,
    pub name: String,
    /// The `Host` alias of its stanza.
    pub alias: String,
    /// The private key file, `<ssh dir>/sshspan_<sanitized name>`.
    pub file: String,
    pub pub_file: String,
    /// The file - or its `.pub` - exists and is not this key's recorded
    /// deployment.
    pub overwrites_file: bool,
    /// The file is another key's recorded deployment, or an earlier key of
    /// the same deploy is written there.
    pub owned_by_other_key: bool,
    /// The managed config already has a stanza with this alias, and it points
    /// at another key's recorded deployment.
    pub alias_owned_by_other_key: bool,
    /// Why the deploy will refuse this key, if it will - the exact message
    /// [`SshService::apply_deploy`] reports for it.
    pub refusal: Option<String>,
}

/// The result of [`SshService::plan_deploy`]: every key's file, alias and
/// verdict, and the managed config the stanzas merge into.
#[derive(Debug, Clone)]
pub struct DeployPlan {
    pub target: DeployTarget,
    pub fields: DeployHostFields,
    pub keys: Vec<PlannedKey>,
    /// The managed config as it was read when planning.
    base: SshConfig,
}

impl DeployPlan {
    /// The stanzas the deploy writes for the keys it does not refuse, exactly
    /// as it writes them - same merge, same serializer. This is the preview
    /// text; on a fresh managed config it is the whole file.
    pub fn config_text(&self) -> String {
        let deployable: Vec<&PlannedKey> =
            self.keys.iter().filter(|k| k.refusal.is_none()).collect();
        let config = self.with_stanzas(&deployable);
        let hosts = deployable
            .iter()
            .filter_map(|k| config.hosts.iter().find(|h| h.host == k.alias))
            .cloned()
            .collect();
        SshConfig { hosts }.to_config_string()
    }

    /// See [`DeployTarget::include_line`].
    pub fn include_line(&self) -> String {
        self.target.include_line()
    }

    /// The base config with a stanza merged in for each of `keys`.
    fn with_stanzas(&self, keys: &[&PlannedKey]) -> SshConfig {
        let mut config = self.base.clone();
        for key in keys {
            merge_stanza(&mut config, &key.alias, &key.file, &self.fields);
        }
        config
    }
}

/// Key material for one planned key.
pub struct DeployFiles {
    /// The OpenSSH private key text (passphrase-protected or not).
    pub private_key: zeroize::Zeroizing<String>,
    /// The `authorized_keys` line, written as `<file>.pub`.
    pub public_key: String,
}

/// A key the deploy wrote.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployedKey {
    pub id: String,
    pub name: String,
    pub alias: String,
    pub file: String,
    pub pub_file: String,
}

/// A key the deploy did not write, and why.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeployError {
    pub id: String,
    pub name: String,
    pub error: String,
}

/// What [`SshService::apply_deploy`] did.
#[derive(Debug, Default)]
pub struct DeployOutcome {
    pub deployed: Vec<DeployedKey>,
    pub errors: Vec<DeployError>,
    /// Problems that did not stop a key from being written (the managed
    /// config could not be updated).
    pub warnings: Vec<String>,
}

/// What [`SshService::remove_key`] removed.
#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovedDeployment {
    /// Files deleted.
    pub removed: Vec<String>,
    /// Aliases of the managed-config stanzas removed with them.
    pub removed_hosts: Vec<String>,
    /// What could not be cleaned up. Never the key file itself: when that
    /// stays, removal fails instead.
    pub warnings: Vec<String>,
}

pub struct SshService;

impl SshService {
    /// Work out what deploying `keys` would write, without writing anything
    /// (ruling R3): the preview shows this plan and
    /// [`SshService::apply_deploy`] carries it out, so the two cannot drift.
    ///
    /// Files are `<ssh_dir>/sshspan_<sanitized name>` (+ `.pub`). The alias
    /// of a key's stanza is the requested alias for a one-key deploy,
    /// `<alias>-<key name>` when several keys are deployed, and the key name
    /// when no alias is given - each part passed through [`safe_alias`], so an
    /// alias holds only letters, digits, `.`, `_` and `-` (ssh_config reads
    /// quotes, `\`, a leading `#` and `*?!` specially). A later key whose
    /// alias is already taken in the same deploy gets `-2`, `-3`, ...
    ///
    /// A key is refused (`refusal`) when its file is another key's recorded
    /// deployment, is written by an earlier key of the same deploy, or exists
    /// (it or its `.pub`) without being this key's recorded deployment: the
    /// file-name sanitiser is lossy, and `a.b` used to overwrite `a_b`'s
    /// private key without a word (A2-46 / A7-59). Re-deploying a key over its
    /// own file is fine. It is also refused when the managed config's stanza
    /// for its alias points at another key's recorded deployment - that
    /// stanza used to be re-pointed silently, leaving the other key
    /// "deployed" with no stanza.
    pub fn plan_deploy(
        target: &DeployTarget,
        keys: &[DeployKey],
        recorded: &[RecordedDeployment],
        fields: &DeployHostFields,
    ) -> Result<DeployPlan> {
        let base = SshConfigService::at(target.config_path.clone()).read()?;
        let several = keys.len() > 1;
        let mut planned: Vec<PlannedKey> = Vec::with_capacity(keys.len());
        let mut aliases_taken: Vec<String> = Vec::new();
        for key in keys {
            let stem = format!("sshspan_{}", sanitize_filename(&key.name));
            let file = target.ssh_dir.join(&stem);
            let pub_file = target.ssh_dir.join(format!("{stem}.pub"));
            let file_text = file.display().to_string();
            let own_record = key
                .deploy_path
                .as_deref()
                .is_some_and(|p| same_path(Path::new(p), &file));
            let earlier = planned
                .iter()
                .find(|p| p.refusal.is_none() && same_path(Path::new(&p.file), &file))
                .map(|p| p.name.clone());
            let owner = recorded
                .iter()
                .find(|r| r.id != key.id && same_path(Path::new(&r.path), &file));
            // A stray `.pub` is not overwritten either.
            let existing = [&file, &pub_file]
                .into_iter()
                .find(|p| !own_record && fs::symlink_metadata(p).is_ok());
            let overwrites_file = existing.is_some();
            let mut refusal = if let Some(other) = &earlier {
                Some(format!(
                    "Not deployed: \"{other}\" and \"{}\" would both be written to {file_text}. Rename one of them and deploy it again.",
                    key.name
                ))
            } else if let Some(owner) = owner {
                Some(format!(
                    "Not deployed: {file_text} is the deployed key file of \"{}\" - deploying \"{}\" would overwrite it. Rename one of the keys, or remove the other key's deployed copy first.",
                    owner.name, key.name
                ))
            } else if let Some(path) = existing {
                Some(format!(
                    "Not deployed: {} already exists and was not written by SSHSpan for \"{}\". Move or delete that file first if it should be replaced.",
                    path.display(),
                    key.name
                ))
            } else {
                None
            };
            let alias = alias_for(fields.host_alias.as_deref(), &key.name, several);
            let mut alias_owned_by_other_key = false;
            let alias = if refusal.is_none() {
                let alias = distinct_alias(alias, &mut aliases_taken);
                let alias_owner = base
                    .hosts
                    .iter()
                    .find(|h| h.host == alias)
                    .and_then(|h| h.identity_file.as_deref())
                    .and_then(|identity| {
                        recorded.iter().find(|r| {
                            r.id != key.id && identity_names(identity, Path::new(&r.path))
                        })
                    });
                if let Some(other) = alias_owner {
                    alias_owned_by_other_key = true;
                    refusal = Some(format!(
                        "Not deployed: the Host alias \"{alias}\" already points at the deployed key \"{}\" ({}). Choose another alias, or remove that key's deployed copy first.",
                        other.name, other.path
                    ));
                    aliases_taken.retain(|taken| *taken != alias.to_lowercase());
                }
                alias
            } else {
                alias
            };
            planned.push(PlannedKey {
                id: key.id.clone(),
                name: key.name.clone(),
                alias,
                file: file_text,
                pub_file: pub_file.display().to_string(),
                overwrites_file,
                owned_by_other_key: earlier.is_some() || owner.is_some(),
                alias_owned_by_other_key,
                refusal,
            });
        }
        Ok(DeployPlan {
            target: target.clone(),
            fields: fields.clone(),
            keys: planned,
            base,
        })
    }

    /// Carry out a plan. For every key it does not refuse, `material` is asked
    /// for the key's files (the commands unseal the key there, so a refused
    /// key is never decrypted), they are written - the private key through
    /// [`write_secret_file`]: owner-only from the first byte, fail-closed on
    /// Windows - and finally the managed config is written once, with a
    /// stanza for each key that was written, by the merge and serializer the
    /// preview used. A key that is refused or fails is reported and skipped;
    /// the others still deploy.
    pub fn apply_deploy(
        plan: &DeployPlan,
        mut material: impl FnMut(&PlannedKey) -> std::result::Result<DeployFiles, String>,
    ) -> DeployOutcome {
        let mut outcome = DeployOutcome::default();
        let mut written: Vec<&PlannedKey> = Vec::new();
        let dir_ready = fs::create_dir_all(&plan.target.ssh_dir)
            .map_err(|e| format!("Could not create {}: {e}", plan.target.ssh_dir.display()));
        for key in &plan.keys {
            let result = match (&key.refusal, &dir_ready) {
                (Some(refusal), _) => Err(refusal.clone()),
                (None, Err(e)) => Err(e.clone()),
                (None, Ok(())) => material(key).and_then(|files| write_key_files(key, &files)),
            };
            match result {
                Ok(()) => {
                    written.push(key);
                    outcome.deployed.push(DeployedKey {
                        id: key.id.clone(),
                        name: key.name.clone(),
                        alias: key.alias.clone(),
                        file: key.file.clone(),
                        pub_file: key.pub_file.clone(),
                    });
                }
                Err(error) => outcome.errors.push(DeployError {
                    id: key.id.clone(),
                    name: key.name.clone(),
                    error,
                }),
            }
        }
        if !written.is_empty() {
            let config = plan.with_stanzas(&written);
            if let Err(e) = SshConfigService::at(plan.target.config_path.clone()).write(&config) {
                outcome.warnings.push(format!(
                    "The key files were written, but {} could not be updated: {e}",
                    plan.target.config_path.display()
                ));
            }
        }
        outcome
    }

    /// Undo one deployment (A7-22): delete the private key file and its
    /// `.pub`, and every managed-config stanza whose IdentityFile is that key
    /// file (the alias is the user's choice, so it is not derived from the key
    /// name). Files already gone are fine. If the private key file cannot be
    /// deleted nothing else is touched and the error says so - the caller
    /// keeps the key marked as deployed; problems with the `.pub` or the
    /// config only produce warnings. Callers check
    /// [`SshService::is_managed_deploy_path`] first.
    pub fn remove_key(
        target: &DeployTarget,
        deploy_path: &str,
    ) -> std::result::Result<RemovedDeployment, String> {
        let mut done = RemovedDeployment::default();
        match fs::remove_file(deploy_path) {
            Ok(()) => done.removed.push(deploy_path.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "Could not remove {deploy_path}: {e}. The key is still marked as deployed."
                ))
            }
        }
        let public = format!("{deploy_path}.pub");
        match fs::remove_file(&public) {
            Ok(()) => done.removed.push(public),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => done
                .warnings
                .push(format!("Could not remove {public}: {e}")),
        }
        let service = SshConfigService::at(target.config_path.clone());
        match service.read() {
            Ok(mut config) => {
                let (gone, kept): (Vec<SshHostConfig>, Vec<SshHostConfig>) =
                    config.hosts.into_iter().partition(|h| {
                        h.identity_file
                            .as_deref()
                            .is_some_and(|f| identity_names(f, Path::new(deploy_path)))
                    });
                config.hosts = kept;
                if !gone.is_empty() {
                    match service.write(&config) {
                        Ok(()) => done.removed_hosts = gone.into_iter().map(|h| h.host).collect(),
                        Err(e) => done.warnings.push(format!(
                            "Could not update {}: {e}",
                            target.config_path.display()
                        )),
                    }
                }
            }
            Err(e) => done.warnings.push(format!(
                "Could not read {}: {e}",
                target.config_path.display()
            )),
        }
        Ok(done)
    }

    /// Whether `deploy_path` is a file a deploy writes: a `sshspan_*` file
    /// directly in the managed SSH directory. Only those are ever deleted on
    /// undeploy - a recorded path is not trusted on its own (a backup
    /// restored before F9, or a hand-edited database, could point it at the
    /// user's own `id_ed25519`, which used to pass because it is inside
    /// `~/.ssh`).
    pub fn is_managed_deploy_path(target: &DeployTarget, deploy_path: &str) -> bool {
        let path = Path::new(deploy_path);
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return false;
        };
        if !name.to_string_lossy().starts_with("sshspan_") {
            return false;
        }
        let canonical = |p: &Path| dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        same_path(&canonical(parent), &canonical(&target.ssh_dir))
    }
}

/// Write one key's private file (owner-only) and its `.pub`; a failure
/// leaves neither behind.
fn write_key_files(key: &PlannedKey, files: &DeployFiles) -> std::result::Result<(), String> {
    let private = Path::new(&key.file);
    let public = Path::new(&key.pub_file);
    write_secret_file(private, files.private_key.as_bytes()).map_err(|e| {
        let _ = fs::remove_file(public);
        e.to_string()
    })?;
    fs::write(public, &files.public_key).map_err(|e| {
        let _ = fs::remove_file(private);
        format!("Could not write {}: {e}", public.display())
    })
}

/// The `Host` alias for one key - the rule in [`SshService::plan_deploy`].
fn alias_for(requested: Option<&str>, key_name: &str, several: bool) -> String {
    match requested {
        Some(alias) if several => format!("{}-{}", safe_alias(alias), safe_alias(key_name)),
        Some(alias) => safe_alias(alias),
        None => safe_alias(key_name),
    }
}

/// A Host alias ssh_config takes literally: letters, digits, `.`, `_` and
/// `-` - every other character becomes `-` - not starting with `-` or `.`
/// (`ssh -x` reads an option), never empty. Key names may hold anything
/// printable, and the old rule (any valid key name) let `'`, `"`, `\`, a
/// leading `#` and the pattern characters `*?!` into the Host line: "invalid
/// quotes" stops every ssh command once the file is Included, and `Host *`
/// matches every host.
fn safe_alias(raw: &str) -> String {
    let mapped: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    match mapped.trim_start_matches(['-', '.']) {
        "" => "key".to_string(),
        alias => alias.to_string(),
    }
}

/// `alias`, or `alias-2`, `alias-3`, ... - the first one not yet taken in
/// this deploy (compared without case), which is then recorded as taken.
fn distinct_alias(alias: String, taken: &mut Vec<String>) -> String {
    let mut candidate = alias.clone();
    let mut n = 2;
    while taken.contains(&candidate.to_lowercase()) {
        candidate = format!("{alias}-{n}");
        n += 1;
    }
    taken.push(candidate.to_lowercase());
    candidate
}

/// Point the stanza for `alias` at `identity_file` with the requested
/// fields: an existing stanza of that alias (an earlier deploy) is updated
/// in place - fields not given keep their value - otherwise one is added.
/// The key file path and the host name are meant literally, so their `%`
/// signs are doubled ([`literal_percent`]); the serializer quotes them when
/// needed.
fn merge_stanza(
    config: &mut SshConfig,
    alias: &str,
    identity_file: &str,
    fields: &DeployHostFields,
) {
    let identity_file = literal_percent(identity_file);
    let hostname = fields.hostname.as_deref().map(literal_percent);
    let strict = fields
        .strict_host_key
        .map(|strict| if strict { "yes" } else { "no" }.to_string());
    if let Some(existing) = config.hosts.iter_mut().find(|h| h.host == alias) {
        existing.identity_file = Some(identity_file);
        existing.identities_only = Some(true);
        if let Some(value) = strict {
            existing
                .extra
                .insert("stricthostkeychecking".to_string(), value);
        }
        if let Some(h) = hostname {
            existing.hostname = Some(h);
        }
        if let Some(u) = &fields.user {
            existing.user = Some(u.clone());
        }
        if let Some(p) = fields.port {
            existing.port = Some(p);
        }
    } else {
        let mut extra = std::collections::HashMap::new();
        if let Some(value) = strict {
            extra.insert("stricthostkeychecking".to_string(), value);
        }
        config.hosts.push(SshHostConfig {
            host: alias.to_string(),
            hostname,
            user: fields.user.clone(),
            port: fields.port,
            identity_file: Some(identity_file),
            identities_only: Some(true),
            forward_agent: Some(false),
            proxy_jump: None,
            extra,
        });
    }
}

/// Whether two paths name the same file for a deploy: on Windows names are
/// case-insensitive and either separator works.
fn same_path(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        let fold = |p: &Path| p.to_string_lossy().replace('/', "\\").to_lowercase();
        fold(a) == fold(b)
    }
    #[cfg(not(windows))]
    {
        a == b
    }
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
mod deploy_tests {
    use super::*;

    /// A throwaway `~/.ssh` and managed config file, removed on drop - the
    /// deploy code never sees the real home directory in a test (A7-56).
    struct Scratch {
        root: PathBuf,
        target: DeployTarget,
    }

    impl Scratch {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "sshspan-deploy-{tag}-{}",
                uuid::Uuid::new_v4().simple()
            ));
            let target = DeployTarget::new(
                root.join("home").join(".ssh"),
                root.join("app-config").join("ssh").join("config"),
            );
            Self { root, target }
        }
        fn file(&self, name: &str) -> PathBuf {
            self.target.ssh_dir.join(name)
        }
        fn config(&self) -> String {
            fs::read_to_string(&self.target.config_path).unwrap_or_default()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn key(id: &str, name: &str) -> DeployKey {
        DeployKey {
            id: id.into(),
            name: name.into(),
            deploy_path: None,
        }
    }

    fn fields(alias: Option<&str>) -> DeployHostFields {
        DeployHostFields::parse(alias.map(String::from), None, None, None, None).unwrap()
    }

    /// Stand-in key material, so the file contents say which key wrote them.
    fn material(planned: &PlannedKey) -> Result<DeployFiles, String> {
        Ok(DeployFiles {
            private_key: zeroize::Zeroizing::new(format!("PRIVATE {}", planned.id)),
            public_key: format!("ssh-ed25519 AAAAC3Nza {}", planned.id),
        })
    }

    fn plan(s: &Scratch, keys: &[DeployKey], f: &DeployHostFields) -> DeployPlan {
        SshService::plan_deploy(&s.target, keys, &[], f).unwrap()
    }

    #[test]
    fn plan_names_files_and_aliases_by_the_documented_rule() {
        let s = Scratch::new("aliases");
        let one = plan(&s, &[key("k1", "web")], &fields(Some("prod")));
        assert_eq!(one.keys[0].alias, "prod");
        assert_eq!(
            one.keys[0].file,
            s.file("sshspan_web").display().to_string()
        );
        assert_eq!(
            one.keys[0].pub_file,
            s.file("sshspan_web.pub").display().to_string()
        );
        // Not a single Host token: sanitized, as for legacy key names.
        let spaced = plan(&s, &[key("k1", "web")], &fields(Some("my prod")));
        assert_eq!(spaced.keys[0].alias, "my-prod");
        let several = plan(
            &s,
            &[key("k1", "web"), key("k2", "db")],
            &fields(Some("prod")),
        );
        let aliases: Vec<&str> = several.keys.iter().map(|k| k.alias.as_str()).collect();
        assert_eq!(aliases, vec!["prod-web", "prod-db"]);
        let unnamed = plan(&s, &[key("k1", "web"), key("k2", "old key")], &fields(None));
        let aliases: Vec<&str> = unnamed.keys.iter().map(|k| k.alias.as_str()).collect();
        assert_eq!(aliases, vec!["web", "old-key"]);
        assert!(unnamed.keys.iter().all(|k| k.refusal.is_none()));
    }

    /// Two different files whose keys sanitize to one Host alias get
    /// distinct stanzas instead of one silently replacing the other.
    #[test]
    fn plan_keeps_aliases_distinct_within_one_deploy() {
        let s = Scratch::new("alias-dupes");
        let p = plan(&s, &[key("k1", "a b"), key("k2", "a-b")], &fields(None));
        assert_ne!(p.keys[0].file, p.keys[1].file);
        let aliases: Vec<&str> = p.keys.iter().map(|k| k.alias.as_str()).collect();
        assert_eq!(aliases, vec!["a-b", "a-b-2"]);
    }

    /// R3: the preview's text is exactly what the deploy writes, HostName /
    /// User / Port included.
    #[test]
    fn config_text_is_exactly_what_apply_writes() {
        let s = Scratch::new("config-text");
        let f = DeployHostFields::parse(
            Some("prod".into()),
            Some("web.example.com".into()),
            Some("deploy".into()),
            Some(2222),
            Some(true),
        )
        .unwrap();
        let p = plan(&s, &[key("k1", "web"), key("k2", "db")], &f);
        let preview = p.config_text();
        let outcome = SshService::apply_deploy(&p, material);
        assert!(outcome.errors.is_empty() && outcome.warnings.is_empty());
        assert_eq!(s.config(), preview);
        for line in [
            "Host prod-web\n",
            "Host prod-db\n",
            "    HostName web.example.com\n",
            "    User deploy\n",
            "    Port 2222\n",
            "    IdentitiesOnly yes\n",
            "    stricthostkeychecking yes\n",
        ] {
            assert!(preview.contains(line), "missing {line:?} in\n{preview}");
        }
        // Compared parsed: on Windows the path is written quoted and escaped.
        let parsed = SshConfig::parse(&preview);
        assert_eq!(
            parsed.hosts[0].identity_file,
            Some(s.file("sshspan_web").display().to_string())
        );
        assert_eq!(
            fs::read_to_string(s.file("sshspan_web")).unwrap(),
            "PRIVATE k1"
        );
        assert_eq!(
            fs::read_to_string(s.file("sshspan_db.pub")).unwrap(),
            "ssh-ed25519 AAAAC3Nza k2"
        );
    }

    #[cfg(unix)]
    #[test]
    fn apply_writes_the_private_key_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("mode");
        let p = plan(&s, &[key("k1", "web")], &fields(None));
        SshService::apply_deploy(&p, material);
        let mode = fs::metadata(s.file("sshspan_web"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// A2-46 / A7-59: `a.b` and `a_b` both sanitize to `sshspan_a_b`; the
    /// second must be refused, not written over the first.
    #[test]
    fn keys_that_share_a_file_name_collide_and_apply_refuses_the_second() {
        let s = Scratch::new("batch-collision");
        let p = plan(&s, &[key("k1", "a.b"), key("k2", "a_b")], &fields(None));
        assert!(p.keys[0].refusal.is_none());
        assert!(p.keys[1].owned_by_other_key);
        let refusal = p.keys[1]
            .refusal
            .clone()
            .expect("the second key is refused");
        assert!(refusal.contains("\"a.b\""), "{refusal}");
        assert!(!p.config_text().contains("Host a_b"));
        let outcome = SshService::apply_deploy(&p, material);
        assert_eq!(outcome.deployed.len(), 1);
        assert_eq!(outcome.deployed[0].id, "k1");
        assert_eq!(outcome.errors.len(), 1);
        assert_eq!(outcome.errors[0].id, "k2");
        assert_eq!(outcome.errors[0].error, refusal);
        assert_eq!(
            fs::read_to_string(s.file("sshspan_a_b")).unwrap(),
            "PRIVATE k1"
        );
        assert!(!s.config().contains("Host a_b"));
    }

    #[test]
    fn another_keys_recorded_deploy_path_is_refused() {
        let s = Scratch::new("recorded");
        fs::create_dir_all(&s.target.ssh_dir).unwrap();
        fs::write(s.file("sshspan_a_b"), "OLD KEY").unwrap();
        let recorded = [RecordedDeployment {
            id: "k-old".into(),
            name: "a.b".into(),
            path: s.file("sshspan_a_b").display().to_string(),
        }];
        let p = SshService::plan_deploy(&s.target, &[key("k2", "a_b")], &recorded, &fields(None))
            .unwrap();
        assert!(p.keys[0].owned_by_other_key);
        assert!(p.keys[0].overwrites_file);
        let outcome = SshService::apply_deploy(&p, material);
        assert!(outcome.deployed.is_empty());
        assert_eq!(
            fs::read_to_string(s.file("sshspan_a_b")).unwrap(),
            "OLD KEY"
        );
    }

    /// A file SSHSpan did not record for this key is refused; re-deploying a
    /// key over its own recorded file is not.
    #[test]
    fn a_foreign_file_is_refused_but_a_redeploy_over_the_keys_own_file_is_not() {
        let s = Scratch::new("foreign");
        fs::create_dir_all(&s.target.ssh_dir).unwrap();
        fs::write(s.file("sshspan_web"), "FOREIGN").unwrap();
        let p = plan(&s, &[key("k1", "web")], &fields(None));
        assert!(p.keys[0].overwrites_file && !p.keys[0].owned_by_other_key);
        assert!(p.keys[0].refusal.is_some());
        let outcome = SshService::apply_deploy(&p, material);
        assert_eq!(outcome.errors.len(), 1);
        assert_eq!(
            fs::read_to_string(s.file("sshspan_web")).unwrap(),
            "FOREIGN"
        );

        let mut own = key("k1", "web");
        own.deploy_path = Some(s.file("sshspan_web").display().to_string());
        let p = plan(&s, &[own], &fields(None));
        assert!(!p.keys[0].overwrites_file && p.keys[0].refusal.is_none());
        let outcome = SshService::apply_deploy(&p, material);
        assert_eq!(outcome.deployed.len(), 1);
        assert_eq!(
            fs::read_to_string(s.file("sshspan_web")).unwrap(),
            "PRIVATE k1"
        );
    }

    /// Other stanzas in the managed file survive; an existing stanza for the
    /// same alias is updated in place, and the preview shows that update.
    #[test]
    fn apply_keeps_other_stanzas_and_updates_an_existing_alias_in_place() {
        let s = Scratch::new("merge");
        fs::create_dir_all(s.target.config_path.parent().unwrap()).unwrap();
        fs::write(
            &s.target.config_path,
            "Host other\n    HostName other.example\n\nHost prod\n    HostName old.example\n    IdentityFile /old/key\n",
        )
        .unwrap();
        let f =
            DeployHostFields::parse(Some("prod".into()), None, Some("deploy".into()), None, None)
                .unwrap();
        let p = plan(&s, &[key("k1", "web")], &f);
        let preview = p.config_text();
        assert!(preview.contains("HostName old.example"), "{preview}");
        SshService::apply_deploy(&p, material);
        let written = s.config();
        assert!(
            written.starts_with("Host other\n    HostName other.example\n"),
            "{written}"
        );
        assert!(written.contains(&preview), "{written}");
        assert!(!written.contains("/old/key"));
        assert_eq!(written.matches("Host prod\n").count(), 1);
    }

    #[test]
    fn host_fields_are_trimmed_and_checked() {
        let f = DeployHostFields::parse(
            Some("  ".into()),
            Some(" web.example ".into()),
            Some("deploy".into()),
            Some(22),
            Some(false),
        )
        .unwrap();
        assert_eq!(f.host_alias, None);
        assert_eq!(f.hostname.as_deref(), Some("web.example"));
        for (hostname, user, port) in [
            (Some("web example"), None, None),
            (None, Some("de\nploy"), None),
            (None, Some("a\"b"), None),
            (None, None, Some(0u16)),
        ] {
            assert!(
                DeployHostFields::parse(
                    None,
                    hostname.map(String::from),
                    user.map(String::from),
                    port,
                    None
                )
                .is_err(),
                "{hostname:?} {user:?} {port:?}"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn include_line_quotes_the_managed_config_path() {
        let t = DeployTarget::new("/x", "/home/me/My Configs/ssh/config");
        assert_eq!(
            t.include_line(),
            "Include \"/home/me/My Configs/ssh/config\""
        );
        let odd = DeployTarget::new("/x", "/tmp/a\\b\"c/config");
        assert_eq!(odd.include_line(), "Include \"/tmp/a\\\\b\\\"c/config\"");
    }

    #[cfg(windows)]
    #[test]
    fn include_line_uses_forward_slashes_on_windows() {
        let t = DeployTarget::new(
            r"C:\x",
            r"C:\Users\Me Too\AppData\Roaming\sshspan\config\ssh\config",
        );
        assert_eq!(
            t.include_line(),
            "Include \"C:/Users/Me Too/AppData/Roaming/sshspan/config/ssh/config\""
        );
    }

    // ── RU3 fix 1: nothing a deploy writes may stop ssh from parsing ──

    /// Key names the vault accepts can hold characters ssh_config reads as
    /// quotes, escapes, comments or patterns (`Host bob's-key` -> "invalid
    /// quotes", which ends every ssh command once the file is Included;
    /// `Host *` matches every host). Aliases use letters, digits, `.`, `_` and
    /// `-` only, and never start with `-` (ssh would read an option).
    #[test]
    fn aliases_use_only_characters_ssh_config_takes_literally() {
        let s = Scratch::new("alias-chars");
        let names = [
            "bob's-key",
            "a\"b",
            "x\\y",
            "#hash",
            "web*prod",
            "who?",
            "!neg",
            "me@laptop",
            "-x",
        ];
        let keys: Vec<DeployKey> = names
            .iter()
            .enumerate()
            .map(|(i, n)| key(&format!("k{i}"), n))
            .collect();
        let p = plan(&s, &keys, &fields(None));
        for planned in &p.keys {
            assert!(
                !planned.alias.is_empty()
                    && !planned.alias.starts_with('-')
                    && planned
                        .alias
                        .chars()
                        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-')),
                "{:?} -> {:?}",
                planned.name,
                planned.alias
            );
        }
        assert_eq!(p.keys[0].alias, "bob-s-key");
        assert_eq!(p.keys[4].alias, "web-prod");
        let several = plan(
            &s,
            &[key("k1", "a'b"), key("k2", "c")],
            &fields(Some("my prod")),
        );
        assert_eq!(several.keys[0].alias, "my-prod-a-b");
    }

    /// A Host alias the user types is refused when it would be a pattern.
    #[test]
    fn a_host_alias_with_pattern_characters_is_refused() {
        for alias in ["*", "web*", "?x", "!prod", "a b*"] {
            let err = DeployHostFields::parse(Some(alias.into()), None, None, None, None)
                .expect_err(alias);
            assert!(err.contains("*, ? or !"), "{alias}: {err}");
        }
        assert!(
            DeployHostFields::parse(Some("prod.example".into()), None, None, None, None).is_ok()
        );
    }

    #[test]
    fn host_name_and_user_refuse_quotes_and_a_leading_hash() {
        for (hostname, user) in [
            (Some("a'b"), None),
            (Some("#host"), None),
            (None, Some("o'neil")),
            (None, Some("#root")),
        ] {
            assert!(
                DeployHostFields::parse(
                    None,
                    hostname.map(String::from),
                    user.map(String::from),
                    None,
                    None
                )
                .is_err(),
                "{hostname:?} {user:?}"
            );
        }
        // A Windows domain user keeps its backslash (it is quoted on write).
        let f = DeployHostFields::parse(None, None, Some(r"CORP\bob".into()), None, None).unwrap();
        assert_eq!(f.user.as_deref(), Some(r"CORP\bob"));
    }

    /// `%` starts a token in IdentityFile, HostName and Include; the paths
    /// and host names a deploy writes are taken literally.
    #[test]
    fn percent_signs_are_written_literally() {
        let s = Scratch {
            target: DeployTarget::new(
                std::env::temp_dir().join("sshspan 100%").join(".ssh"),
                std::env::temp_dir().join("cfg 100%").join("config"),
            ),
            root: std::env::temp_dir().join(format!(
                "sshspan-deploy-percent-{}",
                uuid::Uuid::new_v4().simple()
            )),
        };
        let f =
            DeployHostFields::parse(None, Some("fe80::1%eth0".into()), None, None, None).unwrap();
        let p = plan(&s, &[key("k1", "web")], &f);
        let text = p.config_text();
        assert!(text.contains("    HostName fe80::1%%eth0\n"), "{text}");
        assert!(text.contains("sshspan 100%%"), "{text}");
        assert!(s.target.include_line().contains("cfg 100%%"));
    }

    /// Minor 2: an existing stanza with the requested alias that points at
    /// ANOTHER key's deployed file is not silently re-pointed.
    #[test]
    fn an_alias_that_points_at_another_keys_deployment_is_refused() {
        let s = Scratch::new("alias-takeover");
        let other = s.file("sshspan_old").display().to_string();
        fs::create_dir_all(s.target.config_path.parent().unwrap()).unwrap();
        fs::write(
            &s.target.config_path,
            format!("Host prod\n    HostName old.example\n    IdentityFile {other}\n"),
        )
        .unwrap();
        let recorded = [RecordedDeployment {
            id: "k-old".into(),
            name: "old".into(),
            path: other.clone(),
        }];
        let p = SshService::plan_deploy(
            &s.target,
            &[key("k1", "web")],
            &recorded,
            &fields(Some("prod")),
        )
        .unwrap();
        assert!(p.keys[0].alias_owned_by_other_key);
        let refusal = p.keys[0].refusal.clone().expect("refused");
        assert!(
            refusal.contains("\"prod\"") && refusal.contains("\"old\""),
            "{refusal}"
        );
        let outcome = SshService::apply_deploy(&p, material);
        assert!(outcome.deployed.is_empty());
        assert!(
            s.config().contains(&other),
            "the other key's stanza is untouched"
        );

        // The same key re-deployed under its own alias is fine.
        let recorded = [RecordedDeployment {
            id: "k1".into(),
            name: "web".into(),
            path: other.clone(),
        }];
        let p = SshService::plan_deploy(
            &s.target,
            &[key("k1", "web")],
            &recorded,
            &fields(Some("prod")),
        )
        .unwrap();
        assert!(!p.keys[0].alias_owned_by_other_key);
    }

    /// Minor 7: a stray `sshspan_<name>.pub` that is not this key's is not
    /// overwritten either.
    #[test]
    fn a_foreign_public_key_file_is_refused_too() {
        let s = Scratch::new("foreign-pub");
        fs::create_dir_all(&s.target.ssh_dir).unwrap();
        fs::write(s.file("sshspan_web.pub"), "ssh-ed25519 AAAA someone-else").unwrap();
        let p = plan(&s, &[key("k1", "web")], &fields(None));
        assert!(p.keys[0].overwrites_file);
        assert!(p.keys[0].refusal.as_deref().unwrap_or("").contains(".pub"));
        SshService::apply_deploy(&p, material);
        assert_eq!(
            fs::read_to_string(s.file("sshspan_web.pub")).unwrap(),
            "ssh-ed25519 AAAA someone-else"
        );
    }

    /// A7-22: undeploy removes both files and every stanza that points at
    /// the key file, and leaves the rest of the managed config alone.
    #[test]
    fn remove_key_deletes_the_files_and_the_stanzas_that_use_them() {
        let s = Scratch::new("remove");
        let p = plan(&s, &[key("k1", "web"), key("k2", "db")], &fields(None));
        SshService::apply_deploy(&p, material);
        let web = s.file("sshspan_web").display().to_string();
        let removed = SshService::remove_key(&s.target, &web).unwrap();
        assert_eq!(removed.removed, vec![web.clone(), format!("{web}.pub")]);
        assert_eq!(removed.removed_hosts, vec!["web".to_string()]);
        assert!(removed.warnings.is_empty());
        assert!(!s.file("sshspan_web").exists() && !s.file("sshspan_web.pub").exists());
        let config = s.config();
        assert!(
            !config.contains("Host web\n") && config.contains("Host db\n"),
            "{config}"
        );
    }

    /// A private key file that cannot be removed is reported and nothing else
    /// changes - the caller keeps the key marked as deployed.
    #[test]
    fn remove_key_reports_a_private_file_it_cannot_delete() {
        let s = Scratch::new("remove-fails");
        let p = plan(&s, &[key("k1", "web")], &fields(None));
        SshService::apply_deploy(&p, material);
        let web = s.file("sshspan_web");
        fs::remove_file(&web).unwrap();
        fs::create_dir(&web).unwrap(); // remove_file cannot delete a directory
        let err = SshService::remove_key(&s.target, &web.display().to_string()).unwrap_err();
        assert!(err.contains(&web.display().to_string()), "{err}");
        assert!(
            s.file("sshspan_web.pub").exists(),
            "nothing else was touched"
        );
        assert!(s.config().contains("Host web\n"));
    }

    #[test]
    fn only_sshspan_files_directly_in_the_ssh_dir_are_managed() {
        let s = Scratch::new("managed");
        fs::create_dir_all(s.target.ssh_dir.join("sub")).unwrap();
        let managed =
            |p: PathBuf| SshService::is_managed_deploy_path(&s.target, &p.display().to_string());
        assert!(managed(s.file("sshspan_web")));
        assert!(!managed(s.file("id_ed25519")), "the user's own key");
        assert!(!managed(s.target.ssh_dir.join("sub").join("sshspan_web")));
        assert!(!managed(s.root.join("sshspan_web")));
    }
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
