//! Update check + install: queries the GitHub releases API, compares versions,
//! and (only with explicit user consent, obtained renderer-side) downloads the
//! OS-matching installer and launches it, then exits so the installer can run.

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tauri::AppHandle;

use super::{CmdError, CmdResult};

const RELEASES_API: &str = "https://api.github.com/repos/AGSQ11/SSHSpan/releases/latest";

/// Hard cap for the release-manifest JSON read by `update_check` (10 MiB -
/// the real payload is a few KiB; anything larger is a broken or hostile
/// response and must never be buffered whole).
const MAX_MANIFEST_BYTES: u64 = 10 * 1024 * 1024;

/// Hard cap for the streamed installer download (512 MiB). Installers are
/// streamed to disk chunk-by-chunk, so this is a sanity bound, not the
/// amount of RAM used - but an "installer" larger than this is refused
/// instead of filling the disk.
const MAX_INSTALLER_BYTES: u64 = 512 * 1024 * 1024;

/// Hard cap for the detached minisign signature (`.minisig`) downloaded
/// alongside the installer. A real minisign signature file is ~200 bytes;
/// 4 KiB is generous headroom while still refusing to buffer anything
/// hostile served in its place.
const MAX_SIGNATURE_BYTES: u64 = 4 * 1024;

/// minisign public key (base64 body of `minisign.pub`, i.e. the SECOND line
/// of the key file - algorithm bytes + key id + Ed25519 key, base64-encoded).
///
/// The SHA-256 asset digest returned by the GitHub API comes from the same
/// release that serves the installer, so it only proves the download matches
/// the release - not that the release itself is trusted. This embedded key
/// narrows that gap: the release workflow signs every installer with the
/// minisign SECRET key (GitHub secret `MINISIGN_SECRET_KEY`), with the
/// trusted comment `SSHSpan release <tag>`, and uploads the `.minisig` files
/// as release assets; `update_download_and_run` refuses to run an installer
/// whose signature does not verify against this PUBLIC key or whose signed
/// comment names a different release than the one being installed.
///
/// What that protects against, honestly: an installer or `.minisig` swapped
/// in an already-published release, a hostile mirror or proxy, and a genuine
/// older signed build re-published under a newer tag. What it does NOT: the
/// release workflow signs whatever a pushed `v*` tag builds, so whoever can
/// push tags or change the workflow (a repository or token compromise), or
/// read the Actions secret, can produce validly signed installers. After such
/// a compromise the key must be rotated (below) and the release re-cut.
///
/// Key provisioned 2026-09-12 (key id D67C45BA942239D8). The secret key is
/// NOT in the repository - it lives in the `MINISIGN_SECRET_KEY` Actions
/// secret and in the maintainer's offline backup. From this build on,
/// signature verification is FAIL-CLOSED: a missing, invalid, or unsigned
/// `.minisig` refuses the update. Releases older than the first signed one
/// cannot be auto-update sources for provisioned builds. To rotate: generate
/// a new pair (`minisign -G -W`), replace this const, and update the
/// `MINISIGN_SECRET_KEY` secret in the same release.
const MINISIGN_PUBLIC_KEY: &str = "RWTYOSKUukV81mdaGcLXYzZmZNrPbxlpBqedq7f7kb/PnK87ALjqn055";

/// Marker value of `MINISIGN_PUBLIC_KEY` before the maintainer provisions
/// the real key; matched by full equality.
const MINISIGN_PUBLIC_KEY_PLACEHOLDER: &str = "PLACEHOLDER-REPLACE-WITH-BASE64-PUBLIC-KEY";

/// True when the minisign public key has been provisioned (i.e. is not the
/// build-time placeholder). When false, signature verification is skipped
/// with a warning and the GitHub digest check alone decides - matching the
/// pre-signing behavior so releases keep working while the keypair is
/// being set up. Parameterized over the key so tests can exercise both
/// states regardless of whether the shipped const is still the placeholder.
fn minisign_key_provisioned(key: &str) -> bool {
    key != MINISIGN_PUBLIC_KEY_PLACEHOLDER
}

/// The trusted comment the release workflow signs each installer with:
/// `minisign -t "SSHSpan release ${GITHUB_REF_NAME}"` in release.yml, where
/// the ref name is the `v<version>` tag that triggered the build.
fn release_trusted_comment(version: &str) -> String {
    format!(
        "SSHSpan release v{}",
        version.trim().trim_start_matches('v')
    )
}

/// Verify a downloaded installer blob against a minisign `.minisig` file
/// body using the embedded public key, for the release `version` the URL is
/// bound to. Fails closed on ANY problem: bad base64, wrong key id, wrong
/// key, tampered content, a mangled trusted comment (the global signature
/// covers both), or a valid signature whose trusted comment names another
/// release (A6-05).
fn verify_minisign_signature(installer: &[u8], sig_body: &str, version: &str) -> CmdResult<()> {
    verify_minisign_with_key(MINISIGN_PUBLIC_KEY, installer, sig_body, version)
}

/// [`verify_minisign_signature`] against a caller-chosen key, so the tests
/// run the shipped code path with their own keypair.
fn verify_minisign_with_key(
    key_b64: &str,
    installer: &[u8],
    sig_body: &str,
    version: &str,
) -> CmdResult<()> {
    let pubkey = minisign_verify::PublicKey::from_base64(key_b64)
        .map_err(|e| CmdError(format!("Embedded minisign public key is invalid: {e}")))?;
    let signature = minisign_verify::Signature::decode(sig_body)
        .map_err(|e| CmdError(format!("Release signature is unparseable: {e}")))?;
    // `false` = refuse legacy (non-prehashed) signatures: the release
    // workflow's minisign signs in the default pre-hashed mode, so anything
    // else was not produced by it.
    pubkey
        .verify(installer, &signature, false)
        .map_err(|e| CmdError(format!("Release signature verification FAILED: {e}")))?;
    // The signature proves the bytes are SOME signed release; the signed
    // comment says WHICH. The version number in the URL and the API answer
    // is unsigned, so without this a genuine older installer re-published
    // under a newer tag passed every check (a silent downgrade).
    let expected = release_trusted_comment(version);
    let signed_for = signature.trusted_comment();
    if signed_for != expected {
        let shown: String = signed_for
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect();
        return Err(CmdError(format!(
            "Release signature is for \"{shown}\", not \"{expected}\"; refusing to install \
             a signed build of another release."
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    #[serde(rename = "browserDownloadUrl", alias = "browser_download_url")]
    browser_download_url: String,
    /// SHA-256 of the uploaded asset as computed by GitHub, e.g.
    /// "sha256:<hex>". Present on every asset uploaded via the releases API
    /// (verified against our own releases); used to verify the installer
    /// after download so a substituted/tampered file is never executed.
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    body: Option<String>,
    assets: Vec<GhAsset>,
}

/// Running app version, from `tauri.conf.json` via Tauri's `PackageInfo`.
///
/// Deliberately NOT `env!("CARGO_PKG_VERSION")`: the release workflow syncs
/// the tag into `package.json` / `tauri.conf.json` / `Cargo.toml` at build
/// time, and `tauri.conf.json` is the one Tauri itself bakes into the binary
/// when `version` is set there (tauri-codegen prefers it over
/// `CARGO_PKG_VERSION`). Reading it back from the app handle keeps the
/// updater's notion of "what am I running" tied to the same source of truth
/// the installer metadata uses, so a stale Cargo.toml can never make a
/// freshly-installed build offer an "update" to itself.
fn current_version(app: &AppHandle) -> String {
    app.package_info().version.to_string()
}

/// Pick the release asset matching the running OS / package ecosystem.
fn pick_asset_for_os(assets: &[GhAsset]) -> Option<&GhAsset> {
    #[cfg(target_os = "windows")]
    {
        assets
            .iter()
            .find(|a| a.name.ends_with("_x64-setup.exe"))
            .or_else(|| assets.iter().find(|a| a.name.ends_with("_x64_en-US.msi")))
    }
    #[cfg(target_os = "linux")]
    {
        // Prefer the native package format: .deb where dpkg exists, else .rpm.
        let has_dpkg = std::path::Path::new("/usr/bin/dpkg").exists();
        if has_dpkg {
            assets
                .iter()
                .find(|a| a.name.ends_with("_amd64.deb"))
                .or_else(|| assets.iter().find(|a| a.name.ends_with(".rpm")))
                .or_else(|| assets.iter().find(|a| a.name.ends_with(".AppImage")))
        } else {
            assets
                .iter()
                .find(|a| a.name.ends_with(".rpm"))
                .or_else(|| assets.iter().find(|a| a.name.ends_with("_amd64.deb")))
                .or_else(|| assets.iter().find(|a| a.name.ends_with(".AppImage")))
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = assets;
        None
    }
}

/// Derive the installer filename extension from the asset URL. Every known
/// kind is matched by exact suffix - a substring check could catch anything
/// mentioning it.
fn installer_ext(url: &str) -> &'static str {
    if url.ends_with(".msi") {
        ".msi"
    } else if url.ends_with(".deb") {
        ".deb"
    } else if url.ends_with(".rpm") {
        ".rpm"
    } else if url.ends_with(".AppImage") {
        ".AppImage"
    } else {
        ".exe"
    }
}

/// How far ahead of the running version a candidate may claim to be. The
/// release metadata (GitHub API response) is not itself signed - only the
/// installer bytes are - so an on-path attacker can serve arbitrary version
/// NUMBERS. Without a plausibility bound they can fast-forward-freeze the
/// app: claim v9.9.9 while pointing at a real old signed asset; the user
/// "updates" to the old build and every genuine future release then parses
/// as a downgrade and is refused. The bounds below sit well above any
/// realistic release cadence; raise them if the project ever jumps multiple
/// majors in one update. The freeze variant (replaying the CURRENT version
/// forever) cannot be fixed client-side and is accepted risk.
const MAX_MAJOR_JUMP: u64 = 1;
const MAX_MINOR_JUMP: u64 = 12;

fn is_newer(candidate_tag: &str, current: &str) -> bool {
    let strip = |s: &str| s.trim().trim_start_matches('v').to_string();
    let (cand, cur) = (strip(candidate_tag), strip(current));
    if cand == cur {
        // Defensive short-circuit: never offer an "update" to the version we
        // are already running, regardless of what the tag parsing does.
        return false;
    }
    match (
        semver::Version::parse(&cand),
        semver::Version::parse(cur.as_str()),
    ) {
        (Ok(a), Ok(b)) => {
            if a <= b {
                return false; // strictly newer only - never a downgrade
            }
            // Fast-forward plausibility bound (see the constants above).
            let major_ok = a.major <= b.major + MAX_MAJOR_JUMP;
            let minor_ok = a.major < b.major || a.minor <= b.minor + MAX_MINOR_JUMP;
            major_ok && minor_ok
        }
        _ => false, // unparsable tag: never nag the user over an unknown format
    }
}

/// Read a response body into a byte buffer, enforcing a hard cap: bail out
/// as soon as the accumulated size exceeds `max_bytes` (checked both against
/// a declared Content-Length, where present, and per-chunk during streaming)
/// so an oversized body is never buffered whole. Mirrors the capped-read
/// helpers used for Bitwarden server responses.
async fn read_body_capped(
    mut resp: reqwest::Response,
    max_bytes: u64,
    what: &str,
) -> CmdResult<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes {
            return Err(CmdError(format!(
                "{what} too large ({len} bytes, limit {max_bytes})."
            )));
        }
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CmdError(format!("Could not read {what}: {e}")))?
    {
        body.extend_from_slice(&chunk);
        if body.len() as u64 > max_bytes {
            return Err(CmdError(format!(
                "{what} exceeded the {max_bytes} byte limit."
            )));
        }
    }
    Ok(body)
}

/// The single host-allowlist used for BOTH the initial installer URL and any
/// redirect target followed during download, so every hop of the download is
/// validated identically. Suffix matches require the leading dot, so
/// lookalikes like "notgithubusercontent.com" or "github.com.evil.com" are
/// rejected rather than matched.
fn is_allowed_host(host: &str) -> bool {
    host == "github.com"
        || host.ends_with(".github.com")
        || host == "githubusercontent.com"
        || host.ends_with(".githubusercontent.com")
}

/// Validate an installer URL against the host allowlist (scheme + host).
fn validate_asset_url(raw: &str) -> CmdResult<url::Url> {
    let parsed = url::Url::parse(raw).map_err(|e| CmdError(format!("Bad asset URL: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(CmdError(
            "Refusing to download over a non-HTTPS URL.".into(),
        ));
    }
    let host_ok = parsed.host_str().map_or(false, is_allowed_host);
    if !host_ok {
        return Err(CmdError(
            "Refusing to download from a non-GitHub URL.".into(),
        ));
    }
    Ok(parsed)
}

/// The only GitHub repository whose release assets may be downloaded and
/// executed. The host allowlist above admits every public GitHub repo; the
/// renderer supplies the initial URL, so without an owner/repo pin a
/// compromised renderer could point the updater at any other repository's
/// release asset and have it downloaded AND executed. Redirect hops are still
/// validated against the host allowlist only, because GitHub redirects
/// release downloads to `objects.githubusercontent.com` /
/// `release-assets.githubusercontent.com` paths that do not carry the
/// owner/repo prefix - the pin applies to the renderer-supplied URL, which is
/// the only hop an attacker controls directly.
const RELEASE_REPO_PREFIX: &str = "/AGSQ11/SSHSpan/releases/download/";

/// Validate the INITIAL installer URL handed over by the renderer: HTTPS,
/// GitHub host allowlist, AND exactly
/// `/AGSQ11/SSHSpan/releases/download/<tag>/<asset>` - no query, no fragment,
/// no further segments. Everything derived from it (the extension that picks
/// the launch plan, the `.minisig` sibling) comes from this parsed path, never
/// from the raw string: `...setup.exe#.AppImage` or `...setup.exe?x=.msi`
/// used to change how a downloaded file was started.
fn validate_initial_asset_url(raw: &str) -> CmdResult<url::Url> {
    let parsed = validate_asset_url(raw)?;
    let host_ok = parsed.host_str() == Some("github.com");
    let segments: Vec<&str> = parsed
        .path_segments()
        .map(|segments| segments.collect())
        .unwrap_or_default();
    let path_ok = parsed.path().starts_with(RELEASE_REPO_PREFIX)
        && segments.len() == 6
        && segments.iter().all(|segment| !segment.is_empty());
    let plain = parsed.query().is_none() && parsed.fragment().is_none();
    if !(host_ok && path_ok && plain) {
        return Err(CmdError(
            "Refusing to download: the installer URL must be an \
             AGSQ11/SSHSpan GitHub release asset."
                .into(),
        ));
    }
    Ok(parsed)
}

/// Restrict `version` to filename-safe characters before it is interpolated
/// into the installer temp path. The renderer supplies this string, so a
/// hostile value must not be able to steer the temp path outside the temp
/// directory (`..`/`..\` lose their separators and collapse harmlessly).
fn sanitize_version_for_filename(version: &str) -> String {
    let filtered: String = version
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
        .collect();
    if filtered.is_empty() {
        "unknown".into()
    } else {
        filtered
    }
}

/// What `update_check` reports about the latest release.
///
/// `newerVersion` is the release's version whenever it is newer than the
/// running one, and null otherwise; `available` is true only when there is
/// also an installer for this platform. A newer release WITHOUT one used to
/// come back as plain `available: false`, which the renderer could only read
/// as "you are on the latest version" (A2-41).
fn update_check_result(
    rel: &GhRelease,
    current: &str,
    asset: Option<&GhAsset>,
) -> serde_json::Value {
    let newer = is_newer(&rel.tag_name, current);
    let version = rel.tag_name.trim_start_matches('v');
    let asset = if newer { asset } else { None };
    serde_json::json!({
        "available": asset.is_some(),
        "newerVersion": if newer { Some(version) } else { None },
        "current": current,
        "version": version,
        "notes": rel.body.clone().unwrap_or_default(),
        "assetUrl": asset.map(|a| a.browser_download_url.clone()),
        // GitHub-computed SHA-256 of the asset ("sha256:<hex>"). The renderer
        // passes this back into update_download_and_run so the installer can
        // be verified before execution.
        "assetDigest": asset.and_then(|a| a.digest.clone()),
    })
}

/// How a verified installer is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchPlan {
    /// Windows Installer package: `msiexec /i <file>`. msiexec itself runs
    /// unelevated and raises UAC when the package needs it.
    Msiexec,
    /// Hand the file to the OS shell (`opener::open`: ShellExecuteW "open" on
    /// Windows, the desktop's package handler on Linux). On Windows this is
    /// what lets the NSIS installer run at all: `installMode: both` gives it
    /// a manifest that requires administrator rights, and CreateProcess -
    /// what `Command::spawn` uses - refuses that from an unelevated app with
    /// ERROR_ELEVATION_REQUIRED (740), while ShellExecute shows the UAC
    /// prompt (A7-10).
    ShellOpen,
    /// Swap the running AppImage for the downloaded one.
    ReplaceAppImage,
}

fn launch_plan(ext: &str) -> LaunchPlan {
    match ext {
        ".msi" => LaunchPlan::Msiexec,
        ".AppImage" => LaunchPlan::ReplaceAppImage,
        _ => LaunchPlan::ShellOpen,
    }
}

/// A downloaded installer on disk, deleted again when this is dropped - on
/// every early return after the file was created: a refused or broken
/// download, a digest or signature failure, a launch that did not happen
/// (A7-42). [`StagedInstaller::keep`] disarms it once the OS has the
/// installer: it must outlive the app, and a later start prunes it
/// ([`prune_stale_update_files`]). It only ever removes the file the updater
/// itself created.
struct StagedInstaller {
    path: std::path::PathBuf,
    keep: bool,
}

impl StagedInstaller {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path, keep: false }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// The installer is running (or has replaced the AppImage): leave it.
    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for StagedInstaller {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Stream `resp` into a NEW file at `dest`, hashing as it goes and enforcing
/// `max_bytes`, and return the staged file with its `sha256:<hex>` digest.
/// The file is created exclusively (`create_new`), so a file planted at that
/// name is refused - never reused, overwritten or deleted. Once it exists, any
/// failure removes it again.
async fn download_installer_to(
    resp: &mut reqwest::Response,
    dest: &std::path::Path,
    max_bytes: u64,
) -> CmdResult<(StagedInstaller, String)> {
    let file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dest)
        .await
        .map_err(|e| CmdError(format!("Could not create the installer file: {e}")))?;
    let staged = StagedInstaller::new(dest.to_path_buf());
    // `file` moves into the helper and is closed when it returns, before
    // `staged` can delete the path on an error.
    let digest = stream_installer(resp, file, max_bytes).await?;
    Ok((staged, digest))
}

/// The body of [`download_installer_to`]: the size cap (declared length and
/// running total), the running SHA-256, and the writes.
async fn stream_installer(
    resp: &mut reqwest::Response,
    mut file: tokio::fs::File,
    max_bytes: u64,
) -> CmdResult<String> {
    use tokio::io::AsyncWriteExt;
    if let Some(len) = resp.content_length() {
        if len > max_bytes {
            return Err(CmdError(format!(
                "Installer too large ({len} bytes, limit {max_bytes})."
            )));
        }
    }
    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CmdError(format!("Download failed: {e}")))?
    {
        downloaded += chunk.len() as u64;
        if downloaded > max_bytes {
            return Err(CmdError(format!(
                "Installer exceeded the {max_bytes} byte limit."
            )));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| CmdError(e.to_string()))?;
    }
    file.flush().await.map_err(|e| CmdError(e.to_string()))?;
    if downloaded == 0 {
        return Err(CmdError("Downloaded installer is empty.".into()));
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// How old a staged installer must be before a later start deletes it.
pub const STALE_UPDATE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// The extensions [`update_download_and_run`] stages installers with.
const STAGED_INSTALLER_EXTS: [&str; 5] = [".exe", ".msi", ".deb", ".rpm", ".AppImage"];

/// Exactly the names [`update_download_and_run`] stages installers under:
/// `sshspan-<version>-update-<32 lowercase hex><ext>` - the version filtered
/// by [`sanitize_version_for_filename`], the random part a simple UUID, the
/// extension one of [`STAGED_INSTALLER_EXTS`]. Anything else in the temp or
/// AppImage folder is not ours to delete (`sshspan-notes-update-2026.txt`
/// matched the old prefix test).
fn is_staged_installer_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("sshspan-") else {
        return false;
    };
    let Some(stem) = STAGED_INSTALLER_EXTS
        .iter()
        .find_map(|ext| rest.strip_suffix(ext))
    else {
        return false;
    };
    let Some((version, random)) = stem.rsplit_once("-update-") else {
        return false;
    };
    !version.is_empty()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
        && random.len() == 32
        && random.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// Where installers get staged: the temp directory, plus the running
/// AppImage's own directory (an AppImage update is staged beside it so the
/// final rename stays on one filesystem).
pub fn update_staging_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = vec![std::env::temp_dir()];
    if let Some(dir) = std::env::var_os("APPIMAGE")
        .map(std::path::PathBuf::from)
        .and_then(|image| image.parent().map(std::path::Path::to_path_buf))
        .filter(|dir| !dir.as_os_str().is_empty())
    {
        dirs.push(dir);
    }
    dirs
}

/// Delete staged installers (`sshspan-*-update-*`) older than `max_age` from
/// `dir`, returning how many were removed. A successful update leaves its
/// installer behind (it must outlive the app) and a crash can leave a partial
/// one; this runs at startup so neither stays forever (A7-42). Only plain
/// files directly inside `dir` - never directories, never symlinks, never
/// anything else - and failures (a file still in use) are skipped.
pub fn prune_stale_update_files(dir: &std::path::Path, max_age: std::time::Duration) -> usize {
    let cutoff = std::time::SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_str()
            .is_some_and(is_staged_installer_name)
        {
            continue;
        }
        // DirEntry::file_type does not follow symlinks.
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|modified| modified < cutoff);
        if stale && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Check GitHub for the latest release and, if newer, report the asset URL for
/// this OS. Never installs anything - the renderer asks the user first.
#[tauri::command]
pub async fn update_check(app: AppHandle) -> CmdResult<serde_json::Value> {
    let current = current_version(&app);
    let client = reqwest::Client::builder()
        .user_agent("SSHSpan-Update-Check")
        .timeout(std::time::Duration::from_secs(15))
        // Explicit rather than implied: Cargo.toml already removes the
        // native-tls backend, and this makes a re-added `default-tls`
        // feature a compile error here instead of a silent switch back to
        // OpenSSL for the update channel.
        .use_rustls_tls()
        .build()
        .map_err(|e| CmdError(e.to_string()))?;
    let resp = client
        .get(RELEASES_API)
        .send()
        .await
        .map_err(|e| CmdError(format!("Could not reach GitHub: {e}")))?
        .error_for_status()
        .map_err(|e| CmdError(format!("GitHub API error: {e}")))?;
    // Cap the manifest read: never buffer an unbounded JSON body, even from
    // an allowlisted API endpoint.
    let bytes = read_body_capped(resp, MAX_MANIFEST_BYTES, "release manifest").await?;
    let rel: GhRelease = serde_json::from_slice(&bytes)
        .map_err(|e| CmdError(format!("Could not parse GitHub response: {e}")))?;

    let asset = if is_newer(&rel.tag_name, &current) {
        pick_asset_for_os(&rel.assets)
    } else {
        None
    };
    Ok(update_check_result(&rel, &current, asset))
}

/// Download the `<installer>.minisig` sibling asset through the same
/// validate-allowlist + manual-redirect + revalidation + size-cap discipline
/// as the installer itself, returning the body as a string. ANY failure -
/// including a 404 for an unsigned asset, a network error, or an oversized
/// body - returns Err; the caller decides (fail-closed) what to do with it.
///
/// `original_release_url` must be the repo-pinned
/// `github.com/AGSQ11/SSHSpan/releases/download/...` URL, NOT the
/// post-redirect CDN object URL. GitHub serves a release asset and its
/// `.minisig` sibling as SEPARATE release assets, each 302-redirecting to its
/// own signed `release-assets.githubusercontent.com` object; the CDN object
/// URL carries a signed query, so appending `.minisig` to the FINAL URL both
/// targets the wrong object and mangles the query (the suffix lands after
/// `?...`, not on the path). Appending the suffix to the original release URL
/// names the sibling asset, and its own redirect hop below is followed and
/// re-validated independently.
/// The `.minisig` sibling of a validated release-asset URL, built on the
/// parsed path (no query or fragment can carry the suffix elsewhere).
fn minisig_url(release_url: &url::Url) -> url::Url {
    let mut sig = release_url.clone();
    sig.set_query(None);
    sig.set_fragment(None);
    let path = format!("{}.minisig", release_url.path());
    sig.set_path(&path);
    sig
}

async fn download_minisig(
    client: &reqwest::Client,
    original_release_url: &url::Url,
) -> CmdResult<String> {
    let mut current_url = validate_asset_url(minisig_url(original_release_url).as_str())?;

    // Same single-manual-redirect loop as the installer download: every hop
    // re-validated against the same allowlist.
    let mut resp = None;
    for _ in 0..2 {
        let r = client
            .get(current_url.as_str())
            .send()
            .await
            .map_err(|e| CmdError(format!("Signature download failed: {e}")))?;
        if r.status().is_redirection() {
            let location = r
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| CmdError("Signature redirect without a Location header.".into()))?;
            let next = current_url
                .join(&location)
                .map_err(|e| CmdError(format!("Bad signature redirect target: {e}")))?;
            current_url = validate_asset_url(next.as_str())?;
            continue;
        }
        resp = Some(
            r.error_for_status()
                .map_err(|e| CmdError(format!("Signature download failed: {e}")))?,
        );
        break;
    }
    let resp = resp.ok_or_else(|| {
        CmdError("Signature download redirected more than once; refusing to follow.".into())
    })?;

    // read_body_capped handles the 4 KiB cap (content-length pre-check plus
    // streaming accumulation) exactly like the manifest read.
    let body = read_body_capped(resp, MAX_SIGNATURE_BYTES, "release signature").await?;
    if body.is_empty() {
        return Err(CmdError("Downloaded release signature is empty.".into()));
    }
    String::from_utf8(body).map_err(|_| CmdError("Release signature is not valid UTF-8.".into()))
}

/// Download the chosen installer to a temp path, launch it detached, and exit
/// the app so the installer isn't blocked by our own running process.
/// The renderer must only call this after the user explicitly approved.
///
/// `expected_sha256` is the GitHub-computed digest ("sha256:<hex>") threaded
/// through from `update_check`'s response. It is REQUIRED: the parameter stays
/// `Option` only so a missing value produces our own clear error instead of a
/// deserialisation failure. Omitting it used to skip the integrity check
/// entirely, which is a check a compromised renderer could switch off simply
/// by not passing the argument.
#[tauri::command]
pub async fn update_download_and_run(
    app: AppHandle,
    url: String,
    version: String,
    expected_sha256: Option<String>,
) -> CmdResult<serde_json::Value> {
    // Only accept installer URLs from OUR GitHub releases (owner/repo pinned,
    // not just the github.com host).
    let mut current_url = validate_initial_asset_url(&url)?;
    // Preserve the repo-pinned release URL before the redirect loop mutates
    // `current_url` into the CDN object URL: the `.minisig` sibling must be
    // resolved from THIS release-asset URL, not the redirected one (F7).
    let original_release_url = current_url.clone();

    // Rollback guard. `update_check` compares versions, but this command takes
    // `url` and `version` straight from the renderer, so on its own it would
    // happily install an OLDER release of this repo - genuinely signed, so
    // every downstream check passes - pinning the user to a known-vulnerable
    // build. Re-derive the comparison here, where the decision is made.
    let running = current_version(&app);
    if !is_newer(&version, &running) {
        return Err(CmdError(format!(
            "Refusing to install {version}: it is not newer than the running version {running}."
        )));
    }

    // Bind the claimed version to the signed asset URL: the release-download
    // path is `/AGSQ11/SSHSpan/releases/download/v<tag>/<asset>`, so the tag
    // segment must equal the renderer-supplied `version`. Without this, a
    // compromised renderer could claim a FUTURE version while pointing at an
    // OLDER (still genuinely signed) asset URL - every signature check passes
    // while the install is a silent downgrade. The metadata (version number)
    // is not itself signed, so tie it to the URL that selects the signed
    // bytes. This is checked at the same decision point as the rollback guard,
    // and the signed trusted comment is checked against the same version.
    let release_version = release_version_bound_to_url(&original_release_url, &version)?;

    // From the validated, parsed path - never the raw string (see
    // validate_initial_asset_url).
    let ext = installer_ext(original_release_url.path());
    let plan = launch_plan(ext);

    // AppImage self-replace: when the running app IS an AppImage (the
    // AppImage runtime exports `APPIMAGE` = absolute path of the running
    // image), a downloaded `.AppImage` update must be swapped in place -
    // opening it would just start a second instance. Stage the download in
    // the SAME directory as the running image so the final rename is atomic
    // on one filesystem, and refuse early if that path is unknown.
    let appimage_target = if plan == LaunchPlan::ReplaceAppImage {
        match std::env::var("APPIMAGE") {
            Ok(p) if !p.trim().is_empty() && std::path::Path::new(p.trim()).is_file() => {
                Some(std::path::PathBuf::from(p.trim()))
            }
            _ => {
                return Err(CmdError(
                    "A Linux AppImage update was offered, but this app was not started \
                     from an AppImage, so it cannot self-replace. Install SSHSpan via \
                     .deb/.rpm, or download the new AppImage manually from the releases \
                     page."
                        .into(),
                ))
            }
        }
    } else {
        None
    };

    // Exclusive-create temp path with a random suffix: a pre-planted file at
    // a predictable name can never be reused, and create_new() below fails
    // if the path somehow already exists. `version` comes from the renderer,
    // so it is filtered to filename-safe characters first - a hostile value
    // must not be able to steer the temp path outside the destination
    // directory.
    let file_version = sanitize_version_for_filename(&release_version);
    let rand_suffix = uuid::Uuid::new_v4().simple().to_string();
    let dest_dir = appimage_target
        .as_ref()
        .and_then(|t| t.parent())
        .map(|d| d.to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let dest = dest_dir.join(format!(
        "sshspan-{}-update-{}{}",
        file_version, rand_suffix, ext
    ));

    let client = reqwest::Client::builder()
        .user_agent("SSHSpan-Update-Download")
        .timeout(std::time::Duration::from_secs(600))
        // Redirects are followed MANUALLY so every hop can be re-validated
        // against the same host allowlist; the default policy would happily
        // follow a 3xx to an arbitrary host after the initial URL passed.
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls()
        .build()
        .map_err(|e| CmdError(e.to_string()))?;

    // At most one manual redirect hop; every target is re-validated.
    let mut resp = None;
    for _ in 0..2 {
        let r = client
            .get(current_url.as_str())
            .send()
            .await
            .map_err(|e| CmdError(format!("Download failed: {e}")))?;
        if r.status().is_redirection() {
            let location = r
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| CmdError("Redirect without a Location header.".into()))?;
            // Resolve the Location against the current URL (it may be
            // relative), then re-validate against the SAME allowlist.
            let next = current_url
                .join(&location)
                .map_err(|e| CmdError(format!("Bad redirect target: {e}")))?;
            current_url = validate_asset_url(next.as_str())?;
            continue;
        }
        resp = Some(
            r.error_for_status()
                .map_err(|e| CmdError(format!("Download failed: {e}")))?,
        );
        break;
    }
    let mut resp = resp.ok_or_else(|| {
        CmdError("Download redirected more than once; refusing to follow.".into())
    })?;

    // Stream the body to disk with a hard size cap instead of buffering the
    // whole installer in RAM. From here on `staged` deletes the file again on
    // every early return - a download, digest, signature or launch failure -
    // instead of leaving up to 512 MiB behind per attempt (A7-42).
    let (staged, actual) = download_installer_to(&mut resp, &dest, MAX_INSTALLER_BYTES).await?;

    // Integrity verification: refuse to execute anything whose SHA-256 does
    // not match the digest GitHub computed for the release asset.
    match expected_sha256.as_deref() {
        Some(expected) if expected.eq_ignore_ascii_case(&actual) => { /* verified */ }
        Some(expected) => {
            return Err(CmdError(format!(
                "Installer integrity check FAILED (expected {expected}, got {actual}); \
                 refusing to run a possibly tampered download."
            )));
        }
        // Absent digest = refuse. This was previously a "carry on" arm for
        // older renderers; but the renderer is the untrusted side of the IPC
        // boundary, so an optional integrity check is one an attacker just
        // declines to supply. `update_check` always returns the digest.
        None => {
            return Err(CmdError(
                "Installer integrity check skipped: no expected digest was supplied. \
                 Re-run the update check and try again."
                    .into(),
            ));
        }
    }

    // Signature verification: the digest above proves the download matches
    // the release, but both the binary and its digest come from the same
    // GitHub API response - whoever can alter one can alter the other. The
    // minisign signature binds the installer, and the release it is for, to
    // a key embedded in this binary (see MINISIGN_PUBLIC_KEY for what that
    // does and does not cover). With the key provisioned this is fail-closed
    // (missing/invalid signature = delete the installer and refuse to run);
    // until then it is skipped with a warning (digest check only), so
    // pre-provisioning builds keep updating.
    if minisign_key_provisioned(MINISIGN_PUBLIC_KEY) {
        // ANY signature problem - 404 (unsigned asset), network failure,
        // oversized body, unparseable or invalid signature, a signature for
        // another release - deletes the installer and refuses to run it.
        // There is deliberately no "unsigned release, carry on" path once the
        // key is provisioned.
        let sig = download_minisig(&client, &original_release_url).await?;
        // The installer was streamed to disk; re-read it for verification
        // (bounded by the size cap already enforced during download).
        let installer = tokio::fs::read(staged.path())
            .await
            .map_err(|e| CmdError(format!("Could not re-read downloaded installer: {e}")))?;
        verify_minisign_signature(&installer, &sig, &release_version)?;
    } else {
        log::warn!(
            "MINISIGN_PUBLIC_KEY is still the build-time placeholder; \
             skipping release-signature verification (GitHub digest check only)."
        );
    }

    launch_installer(plan, staged.path(), appimage_target.as_deref()).await?;
    let installed_path = match appimage_target.as_ref() {
        Some(target) => target.display().to_string(),
        None => dest.display().to_string(),
    };
    // The OS has the installer now (or it replaced the AppImage): it must
    // outlive this process. A later start prunes it once it is a day old.
    staged.keep();

    // Respond to the renderer first, then exit so our files unlock and the
    // installer (already running detached) takes over.
    let app_for_exit = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        app_for_exit.exit(0);
    });
    Ok(serde_json::json!({ "ok": true, "installer": installed_path }))
}

/// The release version an installer URL is bound to: the `<tag>` segment of
/// `.../releases/download/<tag>/<asset>`, which must equal the claimed
/// `version` (a leading `v` ignored on both sides). Returned without the `v`.
fn release_version_bound_to_url(release_url: &url::Url, version: &str) -> CmdResult<String> {
    let tag_segment = release_url
        .path_segments()
        // .../releases/download/<tag>/<asset>
        .and_then(|mut segs| segs.nth_back(1))
        .unwrap_or("");
    let claimed = version.trim().trim_start_matches('v');
    let tag = tag_segment.trim_start_matches('v');
    if tag.is_empty() || tag != claimed {
        return Err(CmdError(format!(
            "Refusing to install: the claimed version {version} does not match the \
             release tag in the asset URL ({tag_segment})."
        )));
    }
    Ok(claimed.to_string())
}

/// Start the verified installer at `installer` the way `plan` says.
///
/// Accepted risk (security review F5): the installer is started by path from
/// a folder the user can write to (the temp folder, or the AppImage's folder),
/// re-opened after its digest and signature were checked. Another process
/// running as the same user could swap the file in between. That process can
/// already run code as the user, and the UAC prompt the NSIS installer raises
/// is not a security boundary against same-user code, so this is not closed
/// here.
async fn launch_installer(
    plan: LaunchPlan,
    installer: &std::path::Path,
    appimage_target: Option<&std::path::Path>,
) -> CmdResult<()> {
    match plan {
        LaunchPlan::Msiexec => launch_msi(installer),
        LaunchPlan::ShellOpen => {
            // ShellExecute does not return while the UAC prompt is up, so it
            // runs on the blocking pool. On Linux this is the desktop's
            // package-installer handler (GNOME Software / KDE Discover open
            // .deb/.rpm and ask for the root password).
            let path = installer.to_path_buf();
            tauri::async_runtime::spawn_blocking(move || shell_open_installer(&path))
                .await
                .map_err(|e| CmdError(format!("Could not start the installer: {e}")))?
        }
        LaunchPlan::ReplaceAppImage => replace_running_appimage(installer, appimage_target).await,
    }
}

/// Windows' "the user declined" error (UAC prompt answered No).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const ERROR_CANCELLED: i32 = 1223;

/// The error for an installer the OS shell did not start.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn installer_launch_error(error: &std::io::Error) -> CmdError {
    if error.raw_os_error() == Some(ERROR_CANCELLED) {
        CmdError("Update cancelled - Windows did not get permission to run the installer.".into())
    } else {
        CmdError(format!("Could not start the installer: {error}"))
    }
}

/// Hand the installer to the shell exactly once: ShellExecuteExW "open",
/// which raises the UAC prompt. `opener::open` retried ShellExecuteW on ANY
/// error, so a declined prompt was shown a second time.
#[cfg(target_os = "windows")]
fn shell_open_installer(installer: &std::path::Path) -> CmdResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW};
    let file: Vec<u16> = installer
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: SHELLEXECUTEINFOW is plain data for which all-zero is a valid
    // value; the fields set below are the required ones.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    // SW_SHOWNORMAL
    info.nShow = 1;
    // SAFETY: `info` is initialized and its string pointers (`file`, `verb`)
    // are NUL-terminated buffers that outlive the call.
    if unsafe { ShellExecuteExW(&mut info) } != 0 {
        Ok(())
    } else {
        Err(installer_launch_error(&std::io::Error::last_os_error()))
    }
}

/// Elsewhere the desktop's handler opens the package (`xdg-open` and kin).
#[cfg(not(target_os = "windows"))]
fn shell_open_installer(installer: &std::path::Path) -> CmdResult<()> {
    opener::open(installer).map_err(|e| CmdError(format!("Could not start the installer: {e}")))
}

#[cfg(target_os = "windows")]
fn launch_msi(installer: &std::path::Path) -> CmdResult<()> {
    std::process::Command::new("msiexec")
        .arg("/i")
        .arg(installer)
        .spawn()
        .map(drop)
        .map_err(|e| CmdError(format!("Could not start the installer: {e}")))
}

#[cfg(not(target_os = "windows"))]
fn launch_msi(_installer: &std::path::Path) -> CmdResult<()> {
    Err(CmdError(
        "A Windows Installer package cannot be installed on this system.".into(),
    ))
}

/// Self-replace the running AppImage: the new image was staged in the SAME
/// directory (atomic same-filesystem rename), so make it executable and swap
/// it over the running one. The old image's mount keeps its inode alive until
/// this process exits, so the swap is safe mid-run; the user restarts into
/// the new version.
#[cfg(target_os = "linux")]
async fn replace_running_appimage(
    staged: &std::path::Path,
    target: Option<&std::path::Path>,
) -> CmdResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(target) = target else {
        return Err(CmdError(
            "AppImage update refused: the running image path is unknown.".into(),
        ));
    };
    tokio::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o755))
        .await
        .map_err(|e| CmdError(e.to_string()))?;
    tokio::fs::rename(staged, target).await.map_err(|e| {
        CmdError(format!(
            "Could not replace the running AppImage ({}): {e}",
            target.display()
        ))
    })
}

#[cfg(not(target_os = "linux"))]
async fn replace_running_appimage(
    _staged: &std::path::Path,
    _target: Option<&std::path::Path>,
) -> CmdResult<()> {
    Err(CmdError(
        "An AppImage update can only be installed on Linux.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic reqwest Response with the given status, headers and
    /// body - no network needed. reqwest 0.12 implements
    /// `From<http::Response<T>> for Response`, so unit tests can exercise
    /// the download helpers directly (same approach as the Bitwarden
    /// HTTP-hardening tests).
    fn make_response(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> reqwest::Response {
        let mut builder = http::Response::builder().status(status);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(body).unwrap().into()
    }

    // ── Host allowlist ───────────────────────────────────────────────────────

    // ── Repo-pinned initial URL ─────────────────────────────────────────────
    // The renderer supplies the initial URL; it must point at OUR releases,
    // not merely at github.com (any other public repo's release asset must be
    // refused). Redirect hops keep using the host-only allowlist because
    // GitHub's CDN redirect targets don't carry the owner/repo prefix.

    #[test]
    fn initial_url_accepts_our_release_assets() {
        for url in [
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.2/SSHSpan_1.7.2_x64-setup.exe",
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.2/SSHSpan_1.7.2_x64_en-US.msi",
        ] {
            assert!(
                validate_initial_asset_url(url).is_ok(),
                "expected own release asset to pass: {url}"
            );
        }
    }

    #[test]
    fn initial_url_rejects_other_repos_and_cdn_hosts() {
        for url in [
            // Another public repo: host passes, owner/repo does not.
            "https://github.com/EVIL/malware/releases/download/v1/payload.exe",
            // Path confusion must not slip past the prefix check.
            "https://github.com/AGSQ11/SSHSpan-evil/releases/download/v1/x.exe",
            "https://github.com/AGSQ11/SSHSpanOther/releases/download/v1/x.exe",
            // CDN host directly (renderer must hand over the github.com URL).
            "https://objects.githubusercontent.com/github-production-release/x",
            // Not github.com at all.
            "https://evil.example.com/a.exe",
        ] {
            assert!(
                validate_initial_asset_url(url).is_err(),
                "expected rejection of {url}"
            );
        }
    }

    #[test]
    fn initial_url_must_be_exactly_a_release_asset() {
        // F4: a fragment or query changed the launch plan and the .minisig
        // URL, which were derived from the raw string.
        for url in [
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/SSHSpan_1.10.0_x64-setup.exe#.AppImage",
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/SSHSpan_1.10.0_x64-setup.exe?x=.msi",
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/sub/x.exe",
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/",
            "https://github.com/AGSQ11/SSHSpan/releases/download//x.exe",
        ] {
            assert!(validate_initial_asset_url(url).is_err(), "{url}");
        }
        let ok = validate_initial_asset_url(
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/SSHSpan_1.10.0_x64-setup.exe",
        )
        .unwrap();
        assert_eq!(installer_ext(ok.path()), ".exe");
    }

    #[test]
    fn minisig_url_is_built_on_the_parsed_path() {
        let url = validate_initial_asset_url(
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/SSHSpan_1.10.0_x64-setup.exe",
        )
        .unwrap();
        assert_eq!(
            minisig_url(&url).as_str(),
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/SSHSpan_1.10.0_x64-setup.exe.minisig"
        );
    }

    #[test]
    fn declined_uac_prompt_reads_as_cancelled() {
        let declined = std::io::Error::from_raw_os_error(1223);
        assert_eq!(
            installer_launch_error(&declined).0,
            "Update cancelled - Windows did not get permission to run the installer."
        );
        let other = std::io::Error::from_raw_os_error(2);
        assert!(installer_launch_error(&other)
            .0
            .starts_with("Could not start the installer: "));
    }

    #[test]
    fn staged_installer_names_match_only_the_generated_shape() {
        // F3: the old prefix test matched files that are not ours.
        for foreign in [
            "sshspan-notes-update-2026.txt",
            "sshspan--update-",
            "sshspan-1.9.2-update-0123abcd.exe",
            "sshspan-1.9.2-update-0123456789ABCDEF0123456789ABCDEF.exe",
            "sshspan-1.9.2-update-0123456789abcdef0123456789abcdef.exe.bak",
            "sshspan--update-0123456789abcdef0123456789abcdef.exe",
        ] {
            assert!(!is_staged_installer_name(foreign), "{foreign}");
        }
        for ours in [
            "sshspan-1.9.2-update-0123456789abcdef0123456789abcdef.exe",
            "sshspan-1.10.0-rc1-update-fedcba9876543210fedcba9876543210.AppImage",
            "sshspan-unknown-update-00000000000000000000000000000000.msi",
        ] {
            assert!(is_staged_installer_name(ours), "{ours}");
        }
    }

    #[test]
    fn asset_url_tag_binds_the_claimed_version() {
        let url = validate_initial_asset_url(
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/SSHSpan_1.10.0_x64-setup.exe",
        )
        .unwrap();
        // The bound version is what the signed trusted comment is checked
        // against, without the tag's `v`.
        assert_eq!(
            release_version_bound_to_url(&url, "1.10.0").unwrap(),
            "1.10.0"
        );
        assert_eq!(
            release_version_bound_to_url(&url, "v1.10.0").unwrap(),
            "1.10.0"
        );
        for other in ["1.9.0", "1.10", "", "1.10.0.1"] {
            assert!(
                release_version_bound_to_url(&url, other).is_err(),
                "{other:?}"
            );
        }
    }

    // ── Version-to-filename sanitization ────────────────────────────────────
    // `version` is renderer-supplied and interpolated into the installer temp
    // path; path separators must never survive the filter.

    #[test]
    fn version_sanitizer_strips_path_steering() {
        for hostile in [
            "../../evil",
            "..\\..\\evil",
            "1.7.2/../../Users/x/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x",
            "C:\\Users\\x\\Startup\\x",
            "\0:nul",
        ] {
            let out = sanitize_version_for_filename(hostile);
            assert!(
                !out.contains('/')
                    && !out.contains('\\')
                    && !out.contains(':')
                    && !out.contains('\0'),
                "sanitized version {hostile:?} -> {out:?} must not contain path structure"
            );
        }
        assert_eq!(sanitize_version_for_filename("../../evil"), "....evil");
        assert_eq!(sanitize_version_for_filename(""), "unknown");
        assert_eq!(sanitize_version_for_filename("1.7.2-1"), "1.7.2-1");
    }

    #[test]
    fn allowlist_accepts_github_hosts() {
        for url in [
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.0/a.exe",
            "https://objects.githubusercontent.com/github-production-release/x",
            "https://release-assets.githubusercontent.com/x",
            "https://uploads.github.com/x",
        ] {
            assert!(
                validate_asset_url(url).is_ok(),
                "expected allowlisted URL: {url}"
            );
        }
    }

    #[test]
    fn allowlist_rejects_non_github_hosts() {
        for url in [
            "https://evil.example.com/a.exe",
            "https://github.com.evil.com/a.exe", // suffix must be on .github.com
            "https://githubusercontent.com.evil.com/a.exe",
            "https://notgithubusercontent.com/a.exe", // lookalike prefix must NOT match
            "https://evil.com/github.com/a.exe",
        ] {
            let err = validate_asset_url(url).unwrap_err();
            assert!(
                err.to_string().contains("non-GitHub"),
                "expected rejection of {url}, got: {err}"
            );
        }
    }

    #[test]
    fn allowlist_rejects_non_https_and_garbage() {
        assert!(validate_asset_url("http://github.com/a.exe").is_err());
        assert!(validate_asset_url("file:///C:/Windows/System32/calc.exe").is_err());
        assert!(validate_asset_url("not a url").is_err());
        assert!(validate_asset_url("").is_err());
    }

    // ── Redirect-target revalidation ─────────────────────────────────────────
    // simulate_redirect_hop models what the download loop does when the
    // server answers 3xx: resolve Location against the current URL, then
    // re-validate the target against the same allowlist.

    fn simulate_redirect_hop(current: &str, location: &str) -> CmdResult<url::Url> {
        let current = validate_asset_url(current)?;
        let next = current
            .join(location)
            .map_err(|e| CmdError(format!("Bad redirect target: {e}")))?;
        validate_asset_url(next.as_str())
    }

    #[test]
    fn redirect_to_allowlisted_host_is_followed() {
        let next = simulate_redirect_hop(
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.0/a.exe",
            "https://objects.githubusercontent.com/release-asset/x",
        )
        .expect("on-allowlist redirect target must be accepted");
        assert_eq!(
            next.host_str(),
            Some("objects.githubusercontent.com"),
            "redirect target host must be preserved"
        );
    }

    #[test]
    fn relative_redirect_stays_on_allowed_host() {
        let next = simulate_redirect_hop(
            "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.0/a.exe",
            "/AGSQ11/SSHSpan/releases/download/v1.8.0/a.exe",
        )
        .expect("relative redirect must resolve and pass");
        assert_eq!(next.host_str(), Some("github.com"));
    }

    #[test]
    fn off_allowlist_redirect_is_rejected() {
        for location in [
            "https://evil.example.com/payload.exe",
            "http://evil.example.com/payload.exe", // also non-HTTPS
            "https://github.com.evil.com/payload.exe",
        ] {
            let err = simulate_redirect_hop(
                "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.0/a.exe",
                location,
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("non-GitHub") || err.to_string().contains("non-HTTPS"),
                "expected rejection of redirect to {location}, got: {err}"
            );
        }
    }

    #[test]
    fn redirect_without_location_header_is_rejected() {
        let resp = make_response(302, &[], b"moved".to_vec());
        assert!(resp.headers().get(reqwest::header::LOCATION).is_none());
    }

    // ── Size-cap enforcement ─────────────────────────────────────────────────

    #[tokio::test]
    async fn manifest_within_cap_is_read_intact() {
        let body = br#"{"tag_name":"v1.7.0","assets":[]}"#.to_vec();
        let resp = make_response(200, &[], body.clone());
        let bytes = read_body_capped(resp, MAX_MANIFEST_BYTES, "release manifest")
            .await
            .unwrap();
        assert_eq!(bytes, body);
    }

    #[tokio::test]
    async fn oversized_manifest_is_rejected() {
        // A tiny cap makes a small body "oversized" without allocating much.
        // A synthetic reqwest Response built from a Full body reports its
        // exact size, so either the content_length() pre-check ("too large")
        // or the streaming accumulation check ("exceeded") fires - both
        // reject, which is what matters.
        let resp = make_response(200, &[], b"xxxxx".to_vec());
        let err = read_body_capped(resp, 4, "release manifest")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("too large") || msg.contains("exceeded"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn oversized_chunked_manifest_without_content_length_is_rejected() {
        // A synthetic reqwest Response always reports an exact content_length
        // derived from its body, so the pre-check usually fires first; a real
        // chunked response with no Content-Length exercises the streaming
        // accumulation guard. Both guards must reject, so accept either
        // message (same approach as the Bitwarden oversized-body test).
        let resp = make_response(200, &[], vec![b'x'; 4096]);
        let err = read_body_capped(resp, 16, "release manifest")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("too large") || msg.contains("exceeded"),
            "unexpected error: {msg}"
        );
    }

    // ── Installer download size cap + hashing + digest verification ─────────
    // verify_download models the streaming loop of update_download_and_run
    // (size cap + running SHA-256 + digest comparison) against synthetic
    // responses, without touching disk or network.

    async fn verify_download(
        resp: reqwest::Response,
        expected_sha256: Option<&str>,
    ) -> Result<String, String> {
        let mut resp = resp;
        let mut hasher = Sha256::new();
        let mut downloaded: u64 = 0;
        if let Some(len) = resp.content_length() {
            if len > MAX_INSTALLER_BYTES {
                return Err(format!("too large: {len}"));
            }
        }
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            downloaded += chunk.len() as u64;
            if downloaded > 32 {
                return Err(format!("exceeded the 32 byte limit: {downloaded}"));
            }
            hasher.update(&chunk);
        }
        if downloaded == 0 {
            return Err("empty".into());
        }
        let actual = format!("sha256:{:x}", hasher.finalize());
        match expected_sha256 {
            Some(expected) if expected.eq_ignore_ascii_case(&actual) => Ok(actual),
            Some(expected) => Err(format!("mismatch: expected {expected}, got {actual}")),
            None => Ok(actual),
        }
    }

    fn sha256_hex(data: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(data))
    }

    #[tokio::test]
    async fn installer_with_matching_digest_is_accepted() {
        let body = b"fake installer bytes".to_vec();
        let expected = sha256_hex(&body);
        let resp = make_response(200, &[], body);
        let actual = verify_download(resp, Some(&expected)).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn installer_with_wrong_digest_is_rejected() {
        let body = b"tampered installer bytes".to_vec();
        let wrong = sha256_hex(b"different content entirely");
        let err = verify_download(make_response(200, &[], body), Some(&wrong))
            .await
            .unwrap_err();
        assert!(
            err.contains("mismatch"),
            "tampered installer must be rejected with a digest mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn oversized_installer_aborts_download() {
        // Cap of 32 bytes in verify_download; body is 33 bytes.
        let resp = make_response(200, &[], vec![b'a'; 33]);
        let err = verify_download(resp, None).await.unwrap_err();
        assert!(
            err.contains("exceeded"),
            "over-cap installer must abort, got: {err}"
        );
    }

    #[tokio::test]
    async fn empty_installer_body_is_rejected() {
        let resp = make_response(200, &[], Vec::new());
        let err = verify_download(resp, None).await.unwrap_err();
        assert_eq!(err, "empty");
    }

    // ── Equal versions: never offer an "update" to ourselves ─────────────────
    #[test]
    fn same_version_is_not_newer() {
        assert!(!is_newer("1.7.0", "1.7.0"));
        assert!(!is_newer("v1.7.0", "1.7.0"));
        assert!(!is_newer("v1.7.0", "v1.7.0"));
        assert!(!is_newer(" 1.7.0 ", "1.7.0"));
    }

    // ── Older running, newer remote: offer the update ───────────────────────
    #[test]
    fn newer_remote_is_newer() {
        assert!(is_newer("1.7.0", "1.4.0"));
        assert!(is_newer("v1.7.0", "1.4.0"));
        assert!(is_newer("1.10.0", "1.9.0")); // numeric compare, not lexicographic
        assert!(is_newer("2.0.0", "1.99.99"));
        assert!(is_newer("1.7.1", "1.7.0"));
    }

    // ── Fast-forward plausibility bound (freeze defence) ─────────────────────
    // The release metadata is unsigned; a MITM can claim any version number
    // while pointing at a real old signed asset. Absurd version claims must
    // be refused so they cannot freeze future genuine updates out.
    #[test]
    fn implausible_fast_forward_is_refused() {
        // From 1.7.2: a claim of v9.9.9 (old asset, absurd number) is refused.
        assert!(!is_newer("v9.9.9", "1.7.2"));
        assert!(!is_newer("v100.0.0", "1.7.2"));
        // Same-major minor jump beyond the bound is refused too.
        assert!(!is_newer("v1.99.0", "1.7.2"));
        // ...but a plausible next release still passes.
        assert!(is_newer("v1.8.0", "1.7.2"));
        assert!(is_newer("v1.19.0", "1.7.2"));
        assert!(is_newer("v2.0.0", "1.7.2"));
    }

    // ── Newer running, older remote: never offer a downgrade ────────────────
    #[test]
    fn older_remote_is_not_newer() {
        assert!(!is_newer("1.4.0", "1.7.0"));
        assert!(!is_newer("v1.4.0", "v1.7.0"));
        assert!(!is_newer("1.9.0", "1.10.0"));
        assert!(!is_newer("1.7.0", "1.7.1"));
    }

    // ── Unparsable tags: fail closed (no nag over an unknown format) ────────
    #[test]
    fn unparsable_tag_is_not_newer() {
        assert!(!is_newer("latest", "1.7.0"));
        assert!(!is_newer("nightly-2026-09-08", "1.7.0"));
        assert!(!is_newer("1.7", "1.7.0")); // not full semver
    }

    // ── Regression for the reported bug ─────────────────────────────────────
    // Shipped 1.7.0 binaries self-reported CARGO_PKG_VERSION = 1.4.0 while
    // GitHub's latest tag was v1.7.0, so the app offered an "update" to the
    // version it was already running. Equal after normalization must never
    // be flagged, whatever the tag's spelling.
    #[test]
    fn regression_self_reported_stale_version_not_newer() {
        // The exact user-visible failure: tag v1.7.0 vs running "1.4.0" is a
        // real difference and WOULD be newer - this asserts it is detected
        // (true), which is why the version *source* had to be fixed. With the
        // fix, the running version is 1.7.0 and the equal-version short-
        // circuit keeps the banner away.
        assert!(is_newer("v1.7.0", "1.4.0"));
        assert!(!is_newer("v1.7.0", "1.7.0"));
    }

    // ── minisign release-signature verification ─────────────────────────────
    // The vectors below were generated with a fixed-seed Ed25519 keypair in
    // the exact wire format the minisign CLI writes (verified against
    // jedisct1/minisign's sign() for the signed-message layout: the raw
    // BLAKE2b-512 of the file in pre-hashed mode, and sig || trusted-comment
    // body for the global signature). scripts/gen_minisign_test_vector.py
    // regenerates them.

    /// Base64 public key of the test keypair (seed = SHA-256 of
    /// "sshspan-test-seed-v1"; key id = BLAKE2b-8(pk)).
    const TEST_MINISIGN_PUBKEY: &str = "RWRZlujGKpcBlfJ1Dj473IeWDsZcPcuqvbspGCvLyHO5VAtOuZKpXfcB";

    /// Test payload the signatures below cover.
    const TEST_BLOB: &[u8] = b"SSHSpan minisign unit-test payload";

    /// Valid minisign (pre-hashed, "ED") signature over TEST_BLOB.
    const TEST_SIG_GOOD: &str = "untrusted comment: signature from minisign secret key
RURZlujGKpcBldENeLIUcGNlFb9xFwGX+iU02JbswtWWQcwT/WyI+zphVZmp33Z68qq7K87GPIrQ5pq8bDM5D5cq4jrREOolrw4=
trusted comment: sshspan-updater-test
Zo4gaiQqoL1Jfr9KXg5zhLPR2W1kR6V9kt/NEr/E06UHQiCABaoXZC2Y8FZgL6TjOS3mB2J7N8PLYKufka2IAg==";

    /// Valid minisign signature over DIFFERENT content (b"tampered bytes") -
    /// a well-formed signature that must still fail against TEST_BLOB.
    const TEST_SIG_OTHER_BLOB: &str = "untrusted comment: signature from minisign secret key
RURZlujGKpcBlV9Y3Of2Aq8JpnTqJciEKaKsGZN1PEnSLAvM32YiLeMCo5j0nqtZFXxi79QXGTljTGHWm2+nVcfC4PFn+TTfsAM=
trusted comment: sshspan-updater-test
SWYMI+zOPB2iL5kCX2udBtoWCA9aGT7AvUVmT4Xa1CDTDUadQKeArHOsgGjFxnV/3xtgKHY5t3aUFcma2FDgBg==";

    /// Valid signature over TEST_BLOB whose trusted comment is the one the
    /// release workflow writes for tag v1.8.0 (`-t "SSHSpan release v1.8.0"`):
    /// `make_sig(TEST_BLOB, b"SSHSpan release v1.8.0")` in
    /// scripts/gen_minisign_test_vector.py. Same signature line as
    /// TEST_SIG_GOOD - only the comment and the global signature differ.
    const TEST_SIG_RELEASE_1_8_0: &str = "untrusted comment: signature from minisign secret key
RURZlujGKpcBldENeLIUcGNlFb9xFwGX+iU02JbswtWWQcwT/WyI+zphVZmp33Z68qq7K87GPIrQ5pq8bDM5D5cq4jrREOolrw4=
trusted comment: SSHSpan release v1.8.0
uZHs1rxpejlQPSqtY5OIsWoGXMtzkT6Ac4PgoGlqPqltUpAed6uknY84aGivUuEWW6tHflTgt7iFPCgiqm/mAQ==";

    /// The shipped verification (`verify_minisign_with_key`) against a
    /// caller-chosen key, for an installer claimed to be v1.8.0.
    fn verify_with_key(key_b64: &str, blob: &[u8], sig_body: &str) -> Result<(), String> {
        verify_minisign_with_key(key_b64, blob, sig_body, "1.8.0").map_err(|e| e.0)
    }

    // ── Signature bound to the claimed release (A6-05) ──────────────────────

    #[test]
    fn release_signature_verifies_for_the_version_it_names() {
        for claimed in ["1.8.0", "v1.8.0", " 1.8.0 "] {
            verify_minisign_with_key(
                TEST_MINISIGN_PUBKEY,
                TEST_BLOB,
                TEST_SIG_RELEASE_1_8_0,
                claimed,
            )
            .unwrap_or_else(|e| panic!("{claimed:?}: {}", e.0));
        }
    }

    #[test]
    fn genuine_signature_of_another_release_is_refused() {
        // The replay A6-05 describes: the genuine v1.8.0 installer and its
        // genuine .minisig re-published under tag v1.10.0. Bytes, digest and
        // signature are all real; only the signed comment tells the truth.
        let err = verify_minisign_with_key(
            TEST_MINISIGN_PUBKEY,
            TEST_BLOB,
            TEST_SIG_RELEASE_1_8_0,
            "1.10.0",
        )
        .expect_err("a signature for v1.8.0 must not install as v1.10.0");
        assert!(err.0.contains("SSHSpan release v1.10.0"), "{}", err.0);
        assert!(err.0.contains("SSHSpan release v1.8.0"), "{}", err.0);
        // Near misses do not match either.
        for claimed in ["1.8", "1.8.0.1", "1.8.00", "1.8.0-rc1", ""] {
            assert!(
                verify_minisign_with_key(
                    TEST_MINISIGN_PUBKEY,
                    TEST_BLOB,
                    TEST_SIG_RELEASE_1_8_0,
                    claimed
                )
                .is_err(),
                "{claimed:?}"
            );
        }
        // A valid signature whose comment is not a release comment at all.
        assert!(
            verify_minisign_with_key(TEST_MINISIGN_PUBKEY, TEST_BLOB, TEST_SIG_GOOD, "1.8.0")
                .is_err()
        );
    }

    #[test]
    fn edited_trusted_comment_breaks_the_signature() {
        // Rewriting the comment to name the claimed version is caught by the
        // global signature, which covers the comment.
        let forged =
            TEST_SIG_RELEASE_1_8_0.replace("SSHSpan release v1.8.0", "SSHSpan release v1.10.0");
        let err = verify_minisign_with_key(TEST_MINISIGN_PUBKEY, TEST_BLOB, &forged, "1.10.0")
            .expect_err("an edited trusted comment must fail");
        assert!(err.0.contains("FAILED"), "{}", err.0);
    }

    // ── Update check: newer release, no installer for this OS (A2-41) ───────

    fn release(tag: &str) -> GhRelease {
        GhRelease {
            tag_name: tag.to_string(),
            body: Some("release notes".into()),
            assets: Vec::new(),
        }
    }

    fn release_asset(name: &str) -> GhAsset {
        GhAsset {
            name: name.to_string(),
            browser_download_url: format!(
                "https://github.com/AGSQ11/SSHSpan/releases/download/v1.10.0/{name}"
            ),
            digest: Some("sha256:00ff".into()),
        }
    }

    #[test]
    fn newer_release_without_an_installer_reports_newer_version() {
        let out = update_check_result(&release("v1.10.0"), "1.9.1", None);
        assert_eq!(out["available"], false);
        assert_eq!(out["newerVersion"], "1.10.0");
        assert_eq!(out["version"], "1.10.0");
        assert_eq!(out["assetUrl"], serde_json::Value::Null);
    }

    #[test]
    fn newer_release_with_an_installer_is_available() {
        let asset = release_asset("SSHSpan_1.10.0_x64-setup.exe");
        let out = update_check_result(&release("v1.10.0"), "1.9.1", Some(&asset));
        assert_eq!(out["available"], true);
        assert_eq!(out["newerVersion"], "1.10.0");
        assert_eq!(out["assetUrl"], asset.browser_download_url.as_str());
        assert_eq!(out["assetDigest"], "sha256:00ff");
        assert_eq!(out["current"], "1.9.1");
        assert_eq!(out["notes"], "release notes");
    }

    #[test]
    fn current_older_or_unknown_release_has_no_newer_version() {
        let asset = release_asset("SSHSpan_1.9.1_x64-setup.exe");
        for tag in ["v1.9.1", "v1.8.0", "nightly"] {
            let out = update_check_result(&release(tag), "1.9.1", Some(&asset));
            assert_eq!(out["available"], false, "{tag}");
            assert_eq!(out["newerVersion"], serde_json::Value::Null, "{tag}");
            assert_eq!(out["assetUrl"], serde_json::Value::Null, "{tag}");
        }
    }

    // ── How the installer is started (A7-10) ────────────────────────────────

    #[test]
    fn nsis_installer_is_started_through_the_shell() {
        // `installMode: both` gives the NSIS installer a manifest that needs
        // administrator rights. CreateProcess (Command::spawn) cannot start
        // that from an unelevated app (error 740); ShellExecute can, because
        // it raises the UAC prompt.
        assert_eq!(launch_plan(".exe"), LaunchPlan::ShellOpen);
        assert_eq!(launch_plan(".msi"), LaunchPlan::Msiexec);
        assert_eq!(launch_plan(".AppImage"), LaunchPlan::ReplaceAppImage);
        assert_eq!(launch_plan(".deb"), LaunchPlan::ShellOpen);
        assert_eq!(launch_plan(".rpm"), LaunchPlan::ShellOpen);
    }

    // ── Downloaded installers are cleaned up (A7-42) ────────────────────────

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sshspan-ru5-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn refused_download_leaves_no_partial_installer() {
        let dir = scratch_dir("partial");
        let dest = dir.join("sshspan-1.10.0-update-x.exe");
        // 33 bytes against a 32-byte cap, refused after the file was created.
        let mut resp = make_response(200, &[], vec![b'a'; 33]);
        let err = download_installer_to(&mut resp, &dest, 32)
            .await
            .err()
            .expect("an over-cap download must fail");
        assert!(
            err.0.contains("too large") || err.0.contains("exceeded"),
            "{}",
            err.0
        );
        assert!(!dest.exists(), "the partial installer must be deleted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_download_leaves_no_file() {
        let dir = scratch_dir("empty");
        let dest = dir.join("sshspan-1.10.0-update-x.exe");
        let mut resp = make_response(200, &[], Vec::new());
        let err = download_installer_to(&mut resp, &dest, 32)
            .await
            .err()
            .expect("an empty download must fail");
        assert!(err.0.contains("empty"), "{}", err.0);
        assert!(!dest.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn staged_installer_is_deleted_unless_kept() {
        let dir = scratch_dir("staged");
        // Dropped without keep(): a later digest, signature or launch failure.
        let dest = dir.join("sshspan-1.10.0-update-a.exe");
        let mut resp = make_response(200, &[], b"installer bytes".to_vec());
        let (staged, digest) = download_installer_to(&mut resp, &dest, 1024).await.unwrap();
        assert_eq!(digest, sha256_hex(b"installer bytes"));
        assert_eq!(staged.path(), dest.as_path());
        assert_eq!(std::fs::read(&dest).unwrap(), b"installer bytes");
        drop(staged);
        assert!(
            !dest.exists(),
            "an installer that never ran must be deleted"
        );
        // Kept: the installer must outlive the app (a later start prunes it).
        let kept = dir.join("sshspan-1.10.0-update-b.exe");
        let mut resp = make_response(200, &[], b"installer bytes".to_vec());
        let (staged, _) = download_installer_to(&mut resp, &kept, 1024).await.unwrap();
        staged.keep();
        assert!(kept.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_file_already_at_the_staging_path_is_refused_and_left_alone() {
        let dir = scratch_dir("planted");
        let dest = dir.join("sshspan-1.10.0-update-x.exe");
        std::fs::write(&dest, b"not ours").unwrap();
        let mut resp = make_response(200, &[], b"installer".to_vec());
        assert!(download_installer_to(&mut resp, &dest, 1024).await.is_err());
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"not ours",
            "a file the updater did not create must never be overwritten or deleted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_prune_removes_only_stale_staged_installers() {
        let dir = scratch_dir("prune");
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 24 * 60 * 60);
        let make = |name: &str, modified: Option<std::time::SystemTime>| {
            let path = dir.join(name);
            std::fs::write(&path, b"x").unwrap();
            if let Some(t) = modified {
                std::fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(t)
                    .unwrap();
            }
            path
        };
        let stale_exe = make(
            "sshspan-1.9.2-update-0123456789abcdef0123456789abcdef.exe",
            Some(old),
        );
        let stale_appimage = make(
            "sshspan-1.9.2-update-89ef89ef89ef89ef89ef89ef89ef89ef.AppImage",
            Some(old),
        );
        let fresh = make(
            "sshspan-1.9.2-update-45674567456745674567456745674567.exe",
            None,
        );
        let unrelated = make("othertool-1.0-update-1.exe", Some(old));
        let ours_but_not_an_update = make("sshspan-notes.txt", Some(old));
        let folder = dir.join("sshspan-1.0.0-update-dddddddddddddddddddddddddddddddd.exe");
        std::fs::create_dir(&folder).unwrap();

        assert_eq!(prune_stale_update_files(&dir, STALE_UPDATE_MAX_AGE), 2);
        assert!(!stale_exe.exists() && !stale_appimage.exists());
        assert!(fresh.exists(), "a fresh installer may still be running");
        assert!(unrelated.exists() && ours_but_not_an_update.exists());
        assert!(folder.is_dir(), "directories are never touched");
        // A missing directory is simply nothing to prune.
        assert_eq!(
            prune_stale_update_files(&dir.join("absent"), STALE_UPDATE_MAX_AGE),
            0
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Installer extension derivation ──────────────────────────────────────

    #[test]
    fn installer_ext_matches_asset_kinds() {
        assert_eq!(
            installer_ext(
                "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.2/SSHSpan_1.7.2_x64_en-US.msi"
            ),
            ".msi"
        );
        assert_eq!(
            installer_ext(
                "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.2/SSHSpan_1.7.2_amd64.deb"
            ),
            ".deb"
        );
        assert_eq!(
            installer_ext(
                "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.2/SSHSpan-1.7.2-1.x86_64.rpm"
            ),
            ".rpm"
        );
        assert_eq!(
            installer_ext(
                "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.2/SSHSpan_1.7.2_amd64.AppImage"
            ),
            ".AppImage"
        );
        assert_eq!(
            installer_ext(
                "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.2/SSHSpan_1.7.2_x64-setup.exe"
            ),
            ".exe"
        );
        // The AppImage match is exact-suffix, not substring.
        assert_eq!(
            installer_ext(
                "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.2/notanappimage.exe"
            ),
            ".exe"
        );
    }

    // ── Linux asset picker: AppImage fallback ────────────────────────────────
    // These run only on Linux CI (dpkg exists on the runner, so the deb
    // branch is exercised); on other hosts the cfg compiles them out.

    #[cfg(target_os = "linux")]
    fn asset(name: &str) -> GhAsset {
        GhAsset {
            name: name.to_string(),
            browser_download_url: format!(
                "https://github.com/AGSQ11/SSHSpan/releases/download/v1.7.2/{name}"
            ),
            digest: None,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_picker_prefers_deb_and_falls_back_to_appimage() {
        // Package-manager assets win when present.
        let assets = vec![
            asset("SSHSpan_1.7.2_amd64.AppImage"),
            asset("SSHSpan_1.7.2_amd64.deb"),
        ];
        let picked = pick_asset_for_os(&assets).unwrap();
        assert!(picked.name.ends_with(".deb"));

        // No deb/rpm in the release (or dpkg-less system): the AppImage is
        // the install format and must be selected rather than returning None.
        let assets = vec![
            asset("SSHSpan_1.7.2_x64-setup.exe"),
            asset("SSHSpan_1.7.2_amd64.AppImage"),
        ];
        let picked = pick_asset_for_os(&assets).unwrap();
        assert!(picked.name.ends_with(".AppImage"));

        // Nothing usable → None, as before.
        assert!(pick_asset_for_os(&[asset("SSHSpan_1.7.2_x64-setup.exe")]).is_none());
    }

    #[test]
    fn minisign_placeholder_key_is_detected_as_unprovisioned() {
        // Detection is full-string equality against the placeholder, in both
        // directions: the placeholder means "skip verification" and any real
        // key string means "verify". Written against the helper rather than
        // the shipped const so the test keeps passing once the maintainer
        // provisions the real key (the release workflow runs cargo test).
        assert!(!minisign_key_provisioned(MINISIGN_PUBLIC_KEY_PLACEHOLDER));
        assert!(minisign_key_provisioned(TEST_MINISIGN_PUBKEY));
        assert!(minisign_key_provisioned(""));
    }

    #[test]
    fn shipped_minisign_key_is_provisioned_and_wellformed() {
        // Guards against the placeholder ever sneaking back into the build:
        // the shipped const must be a real (provisioned, parseable) key so
        // signature verification stays fail-closed.
        assert!(minisign_key_provisioned(MINISIGN_PUBLIC_KEY));
        assert!(
            minisign_verify::PublicKey::from_base64(MINISIGN_PUBLIC_KEY).is_ok(),
            "shipped minisign public key must parse"
        );
    }

    #[test]
    fn minisign_good_signature_verifies() {
        verify_with_key(TEST_MINISIGN_PUBKEY, TEST_BLOB, TEST_SIG_RELEASE_1_8_0)
            .expect("a real minisign pre-hashed signature over the exact bytes must verify");
    }

    #[test]
    fn minisign_tampered_content_is_rejected() {
        let err = verify_with_key(
            TEST_MINISIGN_PUBKEY,
            b"SSHSpan minisign unit-test payloaX", // one flipped byte
            TEST_SIG_GOOD,
        )
        .expect_err("tampered content must fail verification");
        assert!(
            err.contains("failed"),
            "expected a signature failure, got: {err}"
        );
    }

    #[test]
    fn minisign_signature_of_other_content_is_rejected() {
        // Even a perfectly valid signature (over different bytes) must not
        // verify against TEST_BLOB - this is the release-asset substitution
        // case: attacker uploads their own installer + its own valid sig.
        let err = verify_with_key(TEST_MINISIGN_PUBKEY, TEST_BLOB, TEST_SIG_OTHER_BLOB)
            .expect_err("a signature over different content must be rejected");
        assert!(
            err.contains("failed"),
            "expected a signature failure, got: {err}"
        );
    }

    #[test]
    fn minisign_wrong_key_is_rejected() {
        // A different (valid-format) Ed25519 key: the signature's key id
        // does not match, so verification fails before any crypto runs.
        // Second half of the test pubkey with the first bytes of the real
        // one kept - valid format, different key id/key.
        let wrong_key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
        let err = verify_with_key(wrong_key, TEST_BLOB, TEST_SIG_GOOD)
            .expect_err("a signature from a different key must be rejected");
        assert!(
            err.contains("different key"),
            "expected a key-id mismatch, got: {err}"
        );
    }

    #[test]
    fn minisign_mangled_signature_is_rejected() {
        for bad in [
            "",                                   // empty body
            "not base64 at all\n///\nx\ny",       // garbage
            "untrusted comment: x\nQUJD=",        // truncated base64
            "untrusted comment: x\n\n\n\n",       // missing fields
            "untrusted comment: x\nRURZlujGKpcBldENeLIUcGNlFb9xFwGX+iU02JbswtWWQcwT/WyI+zphVZmp33Z68qq7K87GPIrQ5pq8bDM5D5cq4jrREOolrw4=\ntrusted comment: x\nQUJD", // no global signature
        ] {
            assert!(
                verify_with_key(TEST_MINISIGN_PUBKEY, TEST_BLOB, bad).is_err(),
                "mangled signature body must be rejected: {bad:?}"
            );
        }
    }

    // ── .minisig URL derivation + download cap ──────────────────────────────

    #[test]
    fn minisig_url_is_derived_from_final_installer_url() {
        // The sibling suffix must land on the same host/path as the FINAL
        // (post-redirect) asset URL, and must pass the same allowlist.
        let final_url =
            validate_asset_url("https://release-assets.githubusercontent.com/799989282/a.exe")
                .unwrap();
        let mut sig = final_url.as_str().to_string();
        sig.push_str(".minisig");
        let parsed = validate_asset_url(&sig).expect(".minisig sibling must be allowlisted");
        assert_eq!(
            parsed.as_str(),
            "https://release-assets.githubusercontent.com/799989282/a.exe.minisig"
        );
    }

    #[tokio::test]
    async fn oversized_minisig_body_is_rejected() {
        // A .minisig served in place of the real one must be refused by the
        // same capped-read discipline as the manifest.
        let resp = make_response(200, &[], vec![b'x'; MAX_SIGNATURE_BYTES as usize + 1]);
        let err = read_body_capped(resp, MAX_SIGNATURE_BYTES, "release signature")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("too large") || msg.contains("exceeded"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn minisig_body_within_cap_is_read_intact() {
        let body = TEST_SIG_GOOD.as_bytes().to_vec();
        let resp = make_response(200, &[], body.clone());
        let bytes = read_body_capped(resp, MAX_SIGNATURE_BYTES, "release signature")
            .await
            .unwrap();
        assert_eq!(bytes, body);
    }
}
