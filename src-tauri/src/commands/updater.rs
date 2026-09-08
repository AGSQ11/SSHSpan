//! Update check + install: queries the GitHub releases API, compares versions,
//! and (only with explicit user consent, obtained renderer-side) downloads the
//! OS-matching installer and launches it, then exits so the installer can run.

use serde::Deserialize;
use tauri::AppHandle;

use super::{CmdError, CmdResult};

const RELEASES_API: &str = "https://api.github.com/repos/AGSQ11/SSHSpan/releases/latest";

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    #[serde(rename = "browserDownloadUrl", alias = "browser_download_url")]
    browser_download_url: String,
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
    let rel: GhRelease = client
        .get(RELEASES_API)
        .send()
        .await
        .map_err(|e| CmdError(format!("Could not reach GitHub: {e}")))?
        .error_for_status()
        .map_err(|e| CmdError(format!("GitHub API error: {e}")))?
        .json()
        .await
        .map_err(|e| CmdError(format!("Could not parse GitHub response: {e}")))?;

    let available = is_newer(&rel.tag_name, &current);
    let asset_url = if available {
        pick_asset_for_os(&rel.assets).map(|a| a.browser_download_url.clone())
    } else {
        None
    };
    Ok(serde_json::json!({
        "available": available && asset_url.is_some(),
        "current": current,
        "version": rel.tag_name.trim_start_matches('v'),
        "notes": rel.body.unwrap_or_default(),
        "assetUrl": asset_url,
    }))
}

/// Download the chosen installer to a temp path, launch it detached, and exit
/// the app so the installer isn't blocked by our own running process.
/// The renderer must only call this after the user explicitly approved.
#[tauri::command]
pub async fn update_download_and_run(
    app: AppHandle,
    url: String,
    version: String,
) -> CmdResult<serde_json::Value> {
    // Only accept installer URLs from our GitHub releases domain.
    let parsed = url::Url::parse(&url).map_err(|e| CmdError(format!("Bad asset URL: {e}")))?;
    let host_ok = parsed.host_str().map_or(false, |h| {
        h == "github.com" || h.ends_with(".github.com") || h.ends_with("githubusercontent.com")
    });
    if !host_ok {
        return Err(CmdError(
            "Refusing to download from a non-GitHub URL.".into(),
        ));
    }

    let ext = if url.contains(".msi") {
        ".msi"
    } else if url.ends_with(".deb") {
        ".deb"
    } else if url.ends_with(".rpm") {
        ".rpm"
    } else {
        ".exe"
    };
    let dest = std::env::temp_dir().join(format!("sshspan-{}-update{}", version, ext));

    let client = reqwest::Client::builder()
        .user_agent("SSHSpan-Update-Download")
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .map_err(|e| CmdError(e.to_string()))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CmdError(format!("Download failed: {e}")))?
        .error_for_status()
        .map_err(|e| CmdError(format!("Download failed: {e}")))?;
    let mut file = tokio::fs::File::create(&dest)
        .await
        .map_err(|e| CmdError(e.to_string()))?;
    use tokio::io::AsyncWriteExt;
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| CmdError(format!("Download failed: {e}")))?;
    file.write_all(&bytes)
        .await
        .map_err(|e| CmdError(e.to_string()))?;
    drop(file);

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
    use super::is_newer;

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
}
