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

fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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
    match (
        semver::Version::parse(&cand),
        semver::Version::parse(cur.as_str()),
    ) {
        (Ok(a), Ok(b)) => a > b,
        _ => cand != cur, // unparsable tags: only flag a genuine difference
    }
}

/// Check GitHub for the latest release and, if newer, report the asset URL for
/// this OS. Never installs anything — the renderer asks the user first.
#[tauri::command]
pub async fn update_check() -> CmdResult<serde_json::Value> {
    let current = current_version();
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

    let available = is_newer(&rel.tag_name, current);
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
