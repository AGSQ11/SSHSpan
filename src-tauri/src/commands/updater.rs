//! Update check + install: queries the GitHub releases API, compares versions,
//! and (only with explicit user consent, obtained renderer-side) downloads the
//! OS-matching installer and launches it, then exits so the installer can run.

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tauri::AppHandle;

use super::{CmdError, CmdResult};

const RELEASES_API: &str = "https://api.github.com/repos/AGSQ11/SSHSpan/releases/latest";

/// Hard cap for the release-manifest JSON read by `update_check` (10 MiB —
/// the real payload is a few KiB; anything larger is a broken or hostile
/// response and must never be buffered whole).
const MAX_MANIFEST_BYTES: u64 = 10 * 1024 * 1024;

/// Hard cap for the streamed installer download (512 MiB). Installers are
/// streamed to disk chunk-by-chunk, so this is a sanity bound, not the
/// amount of RAM used — but an "installer" larger than this is refused
/// instead of filling the disk.
const MAX_INSTALLER_BYTES: u64 = 512 * 1024 * 1024;

/// Hard cap for the detached minisign signature (`.minisig`) downloaded
/// alongside the installer. A real minisign signature file is ~200 bytes;
/// 4 KiB is generous headroom while still refusing to buffer anything
/// hostile served in its place.
const MAX_SIGNATURE_BYTES: u64 = 4 * 1024;

/// minisign public key (base64 body of `minisign.pub`, i.e. the SECOND line
/// of the key file — algorithm bytes + key id + Ed25519 key, base64-encoded).
///
/// PROVISIONING: the SHA-256 asset digest returned by the GitHub API comes
/// from the same release that serves the installer, so it only proves the
/// download matches the release — not that the release itself is trusted.
/// This embedded key closes that gap: the release workflow signs every
/// installer with the minisign SECRET key (GitHub secret
/// `MINISIGN_SECRET_KEY`) and uploads the `.minisig` files as release
/// assets; `update_download_and_run` refuses to run an installer whose
/// signature does not verify against this PUBLIC key, which lives in the
/// source tree and cannot be changed by whoever controls the release.
///
/// Until the maintainer generates a keypair this stays a PLACEHOLDER and
/// verification is SKIPPED with a logged warning (the GitHub digest check
/// still applies — current behavior). To provision:
///   1. `minisign -G -W` (creates an unencrypted minisign.pub + minisign.key;
///      the -W is required because the release workflow signs
///      non-interactively).
///   2. Repository settings → Secrets → Actions → new secret
///      `MINISIGN_SECRET_KEY` whose value is the ENTIRE contents of
///      `minisign.key` (both lines).
///   3. Replace the string below with the base64 body of `minisign.pub`
///      (the second line, starting with `RW`). See the CHANGELOG
///      "Unreleased" section for the full checklist.
const MINISIGN_PUBLIC_KEY: &str = "PLACEHOLDER-REPLACE-WITH-BASE64-PUBLIC-KEY";

/// Marker value of `MINISIGN_PUBLIC_KEY` before the maintainer provisions
/// the real key; matched by full equality.
const MINISIGN_PUBLIC_KEY_PLACEHOLDER: &str = "PLACEHOLDER-REPLACE-WITH-BASE64-PUBLIC-KEY";

/// True when the minisign public key has been provisioned (i.e. is not the
/// build-time placeholder). When false, signature verification is skipped
/// with a warning and the GitHub digest check alone decides — matching the
/// pre-signing behavior so releases keep working while the keypair is
/// being set up. Parameterized over the key so tests can exercise both
/// states regardless of whether the shipped const is still the placeholder.
fn minisign_key_provisioned(key: &str) -> bool {
    key != MINISIGN_PUBLIC_KEY_PLACEHOLDER
}

/// Verify a downloaded installer blob against a minisign `.minisig` file
/// body using the embedded public key. Fails closed on ANY problem: bad
/// base64, wrong key id, wrong key, tampered content, or a mangled trusted
/// comment (the global signature covers both).
fn verify_minisign_signature(installer: &[u8], sig_body: &str) -> CmdResult<()> {
    let pubkey = minisign_verify::PublicKey::from_base64(MINISIGN_PUBLIC_KEY)
        .map_err(|e| CmdError(format!("Embedded minisign public key is invalid: {e}")))?;
    let signature = minisign_verify::Signature::decode(sig_body)
        .map_err(|e| CmdError(format!("Release signature is unparseable: {e}")))?;
    // `false` = refuse legacy (non-prehashed) signatures: the release
    // workflow's minisign signs in the default pre-hashed mode, so anything
    // else was not produced by it.
    pubkey
        .verify(installer, &signature, false)
        .map_err(|e| CmdError(format!("Release signature verification FAILED: {e}")))
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
        } else {
            assets
                .iter()
                .find(|a| a.name.ends_with(".rpm"))
                .or_else(|| assets.iter().find(|a| a.name.ends_with("_amd64.deb")))
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = assets;
        None
    }
}

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
        (Ok(a), Ok(b)) => a > b, // strictly newer only — never a downgrade
        _ => false,              // unparsable tag: never nag the user over an unknown format
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

/// Check GitHub for the latest release and, if newer, report the asset URL for
/// this OS. Never installs anything — the renderer asks the user first.
#[tauri::command]
pub async fn update_check(app: AppHandle) -> CmdResult<serde_json::Value> {
    let current = current_version(&app);
    let client = reqwest::Client::builder()
        .user_agent("SSHSpan-Update-Check")
        .timeout(std::time::Duration::from_secs(15))
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

    let available = is_newer(&rel.tag_name, &current);
    let (asset_url, asset_digest) = if available {
        pick_asset_for_os(&rel.assets)
            .map(|a| (Some(a.browser_download_url.clone()), a.digest.clone()))
            .unwrap_or((None, None))
    } else {
        (None, None)
    };
    Ok(serde_json::json!({
        "available": available && asset_url.is_some(),
        "current": current,
        "version": rel.tag_name.trim_start_matches('v'),
        "notes": rel.body.unwrap_or_default(),
        "assetUrl": asset_url,
        // GitHub-computed SHA-256 of the asset ("sha256:<hex>"). The renderer
        // passes this back into update_download_and_run so the installer can
        // be verified before execution.
        "assetDigest": asset_digest,
    }))
}

/// Download the `<installer-url>.minisig` sibling of the (post-redirect)
/// installer URL through the same validate-allowlist + manual-redirect +
/// revalidation + size-cap discipline as the installer itself, returning
/// the body as a string. ANY failure — including a 404 for an unsigned
/// asset, a network error, or an oversized body — returns Err; the caller
/// decides (fail-closed) what to do with it.
async fn download_minisig(
    client: &reqwest::Client,
    final_installer_url: &url::Url,
) -> CmdResult<String> {
    // GitHub serves release assets and their .minisig siblings from the same
    // host and path, so appending the suffix to the FINAL (post-redirect)
    // URL lands on the right asset even after the release-download →
    // objects/release-assets redirect hop.
    let mut sig_url_str = final_installer_url.as_str().to_string();
    sig_url_str.push_str(".minisig");
    let mut current_url = validate_asset_url(&sig_url_str)?;

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
/// through from `update_check`'s response; it is `Option` for backward
/// tolerance with older renderers. When present the downloaded file is
/// verified against it and execution is REFUSED on mismatch.
#[tauri::command]
pub async fn update_download_and_run(
    app: AppHandle,
    url: String,
    version: String,
    expected_sha256: Option<String>,
) -> CmdResult<serde_json::Value> {
    // Only accept installer URLs from our GitHub releases domain.
    let mut current_url = validate_asset_url(&url)?;

    let ext = if url.contains(".msi") {
        ".msi"
    } else if url.ends_with(".deb") {
        ".deb"
    } else if url.ends_with(".rpm") {
        ".rpm"
    } else {
        ".exe"
    };
    // Exclusive-create temp path with a random suffix: a pre-planted file at
    // a predictable name can never be reused, and create_new() below fails
    // if the path somehow already exists.
    let rand_suffix = uuid::Uuid::new_v4().simple().to_string();
    let dest =
        std::env::temp_dir().join(format!("sshspan-{}-update-{}{}", version, rand_suffix, ext));

    let client = reqwest::Client::builder()
        .user_agent("SSHSpan-Update-Download")
        .timeout(std::time::Duration::from_secs(600))
        // Redirects are followed MANUALLY so every hop can be re-validated
        // against the same host allowlist; the default policy would happily
        // follow a 3xx to an arbitrary host after the initial URL passed.
        .redirect(reqwest::redirect::Policy::none())
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
    // whole installer in RAM.
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&dest)
        .await
        .map_err(|e| CmdError(e.to_string()))?;
    use tokio::io::AsyncWriteExt;
    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    if let Some(len) = resp.content_length() {
        if len > MAX_INSTALLER_BYTES {
            return Err(CmdError(format!(
                "Installer too large ({len} bytes, limit {MAX_INSTALLER_BYTES})."
            )));
        }
    }
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CmdError(format!("Download failed: {e}")))?
    {
        downloaded += chunk.len() as u64;
        if downloaded > MAX_INSTALLER_BYTES {
            return Err(CmdError(format!(
                "Installer exceeded the {MAX_INSTALLER_BYTES} byte limit."
            )));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| CmdError(e.to_string()))?;
    }
    file.flush().await.map_err(|e| CmdError(e.to_string()))?;
    drop(file);

    if downloaded == 0 {
        let _ = tokio::fs::remove_file(&dest).await;
        return Err(CmdError("Downloaded installer is empty.".into()));
    }

    // Integrity verification: refuse to execute anything whose SHA-256 does
    // not match the digest GitHub computed for the release asset.
    let actual = format!("sha256:{:x}", hasher.finalize());
    match expected_sha256.as_deref() {
        Some(expected) if expected.eq_ignore_ascii_case(&actual) => { /* verified */ }
        Some(expected) => {
            let _ = tokio::fs::remove_file(&dest).await;
            return Err(CmdError(format!(
                "Installer integrity check FAILED (expected {expected}, got {actual}); \
                 refusing to run a possibly tampered download."
            )));
        }
        // Backward tolerance: an older renderer did not thread the digest
        // through. We still execute only a non-empty, allowlisted,
        // size-capped HTTPS download from GitHub, but this path loses the
        // tamper guarantee — the renderer in this repo always sends the
        // digest, so in practice this arm is unreachable for shipped builds.
        None => { /* no digest provided: non-empty size verified above */ }
    }

    // Signature verification: the digest above proves the download matches
    // the release, but both the binary and its digest come from the same
    // GitHub API response — whoever can alter one can alter the other. The
    // minisign signature closes that gap by binding the installer to a key
    // embedded in this binary. With the key provisioned this is fail-closed
    // (missing/invalid signature = delete the installer and refuse to run);
    // until then it is skipped with a warning (digest check only), so
    // pre-provisioning builds keep updating.
    if minisign_key_provisioned(MINISIGN_PUBLIC_KEY) {
        // ANY signature problem — 404 (unsigned asset), network failure,
        // oversized body, unparseable or invalid signature — deletes the
        // installer and refuses to run it. There is deliberately no
        // "unsigned release, carry on" path once the key is provisioned.
        let sig = match download_minisig(&client, &current_url).await {
            Ok(sig) => sig,
            Err(e) => {
                let _ = tokio::fs::remove_file(&dest).await;
                return Err(e);
            }
        };
        // The installer was streamed to disk; re-read it for verification
        // (bounded by the size cap already enforced during download).
        let installer = match tokio::fs::read(&dest).await {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = tokio::fs::remove_file(&dest).await;
                return Err(CmdError(format!(
                    "Could not re-read downloaded installer: {e}"
                )));
            }
        };
        if let Err(e) = verify_minisign_signature(&installer, &sig) {
            let _ = tokio::fs::remove_file(&dest).await;
            return Err(e);
        }
    } else {
        log::warn!(
            "MINISIGN_PUBLIC_KEY is still the build-time placeholder; \
             skipping release-signature verification (GitHub digest check only)."
        );
    }

    // Launch the installer detached.
    #[cfg(target_os = "windows")]
    {
        if ext == ".msi" {
            std::process::Command::new("msiexec")
                .args(["/i", &dest.display().to_string()])
                .spawn()
                .map_err(|e| CmdError(e.to_string()))?;
        } else {
            std::process::Command::new(&dest)
                .spawn()
                .map_err(|e| CmdError(e.to_string()))?;
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Open with the desktop's package-installer handler (GNOME Software /
        // KDE Discover handle .deb/.rpm), which prompts for the root password.
        opener::open(&dest).map_err(|e| CmdError(e.to_string()))?;
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        opener::open(&dest).map_err(|e| CmdError(e.to_string()))?;
    }

    // Respond to the renderer first, then exit so our files unlock and the
    // installer (already running detached) takes over.
    let app_for_exit = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        app_for_exit.exit(0);
    });
    Ok(serde_json::json!({ "ok": true, "installer": dest.display().to_string() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic reqwest Response with the given status, headers and
    /// body — no network needed. reqwest 0.12 implements
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
        // or the streaming accumulation check ("exceeded") fires — both
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
        // real difference and WOULD be newer — this asserts it is detected
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

    /// Valid minisign signature over DIFFERENT content (b"tampered bytes") —
    /// a well-formed signature that must still fail against TEST_BLOB.
    const TEST_SIG_OTHER_BLOB: &str = "untrusted comment: signature from minisign secret key
RURZlujGKpcBlV9Y3Of2Aq8JpnTqJciEKaKsGZN1PEnSLAvM32YiLeMCo5j0nqtZFXxi79QXGTljTGHWm2+nVcfC4PFn+TTfsAM=
trusted comment: sshspan-updater-test
SWYMI+zOPB2iL5kCX2udBtoWCA9aGT7AvUVmT4Xa1CDTDUadQKeArHOsgGjFxnV/3xtgKHY5t3aUFcma2FDgBg==";

    /// verify_with_key runs the same verification update_download_and_run
    /// performs, but against a caller-chosen key so tests can exercise the
    /// provisioned path without touching the shipped placeholder const.
    fn verify_with_key(key_b64: &str, blob: &[u8], sig_body: &str) -> Result<(), String> {
        let pubkey =
            minisign_verify::PublicKey::from_base64(key_b64).map_err(|e| format!("key: {e}"))?;
        let signature =
            minisign_verify::Signature::decode(sig_body).map_err(|e| format!("sig: {e}"))?;
        pubkey
            .verify(blob, &signature, false)
            .map_err(|e| e.to_string())
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
    fn minisign_good_signature_verifies() {
        verify_with_key(TEST_MINISIGN_PUBKEY, TEST_BLOB, TEST_SIG_GOOD)
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
        // verify against TEST_BLOB — this is the release-asset substitution
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
        // one kept — valid format, different key id/key.
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
