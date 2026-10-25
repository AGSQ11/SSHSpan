//! SSHSpan - Cross-platform SSH Key Manager
//! Tauri v2 library entry point

pub mod assistant;
pub mod bitwarden;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod db;
pub mod putty_sessions;
pub mod sftp;
pub mod ssh;
pub mod ssh_client;

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
};

use commands::server::*;
use commands::sftp::*;
use commands::terminal::*;
use commands::updater::*;
use commands::*;
use db::Database;
use sftp::{EditRegistry, KeepaliveRegistry, SftpRegistry};
use ssh_client::SessionRegistry;

/// Application state shared across commands
pub struct AppState {
    pub db: Database,
}

impl AppState {
    pub fn new(app: &tauri::AppHandle) -> anyhow::Result<Self> {
        let db = Database::new(app)?;
        Ok(Self { db })
    }
}

/// Initialize the Tauri application
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let state = match AppState::new(app.handle()) {
                Ok(state) => state,
                Err(e) => {
                    // No state is managed: the window stays hidden, commands
                    // are refused (see `refuse_after_failed_startup`) and the
                    // app exits when the user closes the dialog.
                    report_startup_failure(app.handle(), &e);
                    return Ok(());
                }
            };
            app.manage(state);

            // Vault password lives in memory only; cleared on lock / quit
            app.manage(VaultPasswordStore::new());
            // Save-dialog-approved write targets (system_write_text_file gate)
            app.manage(commands::DialogPathStore::new());
            // Master-password guess backoff (unlock / change-password)
            app.manage(commands::UnlockThrottle::new());
            // Renderer liveness signal for the backend idle auto-lock
            app.manage(commands::ActivityTracker::new());
            // Vault generation: bumped on lock so pending operations abort
            app.manage(commands::VaultGeneration::new());
            // Master-password change vs. every other write of sealed data
            app.manage(commands::VaultRotationLock::new());
            // One native credential question (MCP credential, assistant API
            // key move, Bitwarden sync destination) at a time, app-wide, and
            // per kind the 30-second wait after a "no"
            app.manage(commands::CredentialQuestions::new());
            // Per-tab AI access levels; in-memory, cleared on vault lock
            app.manage(assistant::AssistantLevels::new());
            // Live MCP sessions + connect statuses; torn down on vault lock
            // (HTTP DELETE with Mcp-Session-Id where a session exists)
            app.manage(assistant::mcp::McpState::new());

            // Live SSH terminal sessions; cleared on vault lock
            app.manage(std::sync::Arc::new(SessionRegistry::new()));
            app.manage(SftpRegistry::new());
            app.manage(EditRegistry::new());
            app.manage(KeepaliveRegistry::new());
            app.manage(crate::sftp::queue::TransferQueue::new());

            // Bring back transfers a previous run left unfinished. They come
            // back Paused, never running: the SSH sessions they were bound to
            // died with that run, and silently reconnecting to write files at
            // startup is not something the user asked for. Must run after both
            // the DB state and the queue are managed.
            let restored = crate::sftp::queue::restore_pending(app.handle());
            if restored > 0 {
                log::info!("[sshspan-sftp] restored {restored} unfinished transfer(s) as paused");
            }

            // Backend-enforced idle auto-lock: covers the case where the
            // renderer cannot lock the vault itself (hung/crashed webview).
            commands::spawn_auto_lock_watchdog(app.handle().clone());

            // Installers a previous update left behind (they must outlive the
            // app that launches them) or a crash left half-written (A7-42).
            // Off the startup path: the temp directory can be large.
            std::thread::spawn(|| {
                for dir in update_staging_dirs() {
                    let removed = prune_stale_update_files(&dir, STALE_UPDATE_MAX_AGE);
                    if removed > 0 {
                        log::info!(
                            "[sshspan-update] removed {removed} stale installer(s) from {}",
                            dir.display()
                        );
                    }
                }
            });

            // A tray that cannot be created is not fatal: the app runs, and
            // closing the window quits instead of hiding into a tray that is
            // not there (A7-37).
            if let Err(e) = create_tray(app.handle()) {
                log::warn!("[sshspan] could not create the tray icon: {e}");
                TRAY_AVAILABLE.store(false, std::sync::atomic::Ordering::SeqCst);
            }

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
            }

            Ok(())
        })
        .invoke_handler(refuse_after_failed_startup(tauri::generate_handler![
            // App lifecycle (rulings R11 / R12)
            app_quit,
            app_info,
            // Vault commands
            vault_create,
            vault_unlock,
            vault_lock,
            vault_change_password,
            vault_status,
            // Backups are written and read by Rust behind native dialogs. The
            // commands that moved the sealed vault through the webview
            // (`vault_backup_create` / `vault_backup_restore`, and
            // `vault_export` / `vault_import`) were removed (A6-03).
            vault_backup_export_to_file,
            vault_backup_restore_from_file,
            // Key commands. `key_generate` and `key_fingerprint` were removed:
            // nothing in the renderer called them (keys are created by
            // `key_create_with_categories`; fingerprints come with `key_list`),
            // and an unused command is IPC surface only a compromised renderer
            // could reach (A8-16).
            key_import,
            key_export,
            key_export_to_file,
            key_delete,
            key_rename,
            key_list,
            key_get,
            key_deploy,
            key_deploy_preview,
            key_remove_deployed,
            // Category commands
            category_list,
            category_create,
            category_rename,
            category_reparent,
            category_set_order,
            category_delete,
            // Key ↔ category bridge
            key_set_categories,
            key_create_with_categories,
            // SSH Config commands. `ssh_config_read` and `ssh_config_write`
            // were removed (no renderer caller, A8-16; `ssh_config_write` let
            // a caller write any directive - ProxyCommand included - into the
            // managed config, which only `key_deploy` writes).
            ssh_config_list_hosts,
            // Saved server CRUD
            server_list,
            server_save,
            // PuTTY's saved sessions, to save as servers (Windows; refused
            // elsewhere with a message saying so)
            putty_list_sessions,
            server_delete,
            // Connect / interactive SSH terminal
            terminal_connect,
            terminal_send,
            terminal_resize,
            terminal_disconnect,
            // `terminal_keepalive` was removed: no renderer caller (A8-16);
            // keepalives are sent at the SSH protocol level.
            terminal_list,
            server_test,
            known_hosts_list,
            known_hosts_forget,
            // Renderer liveness heartbeat (backend idle auto-lock input)
            heartbeat,
            // `sftp_upload`, `sftp_stage_path`, `sftp_file_sha256` and
            // `sftp_set_mtime` were removed: nothing in the renderer called
            // them (uploads go through the queue, which does its own staging,
            // verification and timestamps), and an unused command is IPC
            // surface that only a compromised renderer could reach.
            sftp_open,
            sftp_list_dir,
            sftp_resolve_link,
            sftp_dir_size,
            sftp_mkdir,
            sftp_remove,
            sftp_rename,
            sftp_download,
            sftp_open_for_edit,
            sftp_close_edit,
            sftp_edit_resolve,
            sftp_chmod,
            sftp_get_permissions,
            sftp_touch,
            sftp_fs_info,
            sftp_keepalive_start,
            sftp_queue_add,
            sftp_queue_list,
            sftp_queue_cancel,
            sftp_queue_retry,
            sftp_queue_pause,
            sftp_queue_resume,
            sftp_queue_pause_all,
            sftp_queue_resume_all,
            sftp_queue_set_rate_limit,
            sftp_queue_clear_finished,
            sftp_server_copy,
            sftp_search,
            sftp_search_cancel,
            sftp_bookmarks_list,
            sftp_bookmarks_save,
            sftp_local_list,
            sftp_local_mkdir,
            sftp_local_rename,
            sftp_local_remove,
            sftp_local_open_folder,
            sftp_close,
            // Bitwarden commands
            bitwarden_get_config,
            bitwarden_save_config,
            bitwarden_test_connection,
            bitwarden_sync,
            bitwarden_allow_sync,
            // AI assistant commands
            assistant::assistant_get_config,
            assistant::assistant_save_config,
            assistant::assistant_test_connection,
            assistant::assistant_chat,
            assistant::assistant_set_level,
            assistant::assistant_get_level,
            assistant::assistant_exec,
            assistant::assistant_type_text,
            // MCP (Model Context Protocol) commands
            assistant::mcp::mcp_list_servers,
            assistant::mcp::mcp_save_server,
            assistant::mcp::mcp_remove_server,
            assistant::mcp::mcp_test_connection,
            assistant::mcp::mcp_set_tool_state,
            assistant::mcp::mcp_call_tool,
            // Settings commands
            settings_get,
            system_paths,
            settings_set,
            // Audit log commands
            audit_list,
            audit_clear,
            // System commands
            system_open_external,
            system_open_url,
            system_select_file,
            system_pick_file_path,
            system_pick_files,
            system_pick_save_path,
            system_write_text_file,
            update_check,
            update_download_and_run,
        ]))
        // Closing the window hides it to the tray instead of exiting, which is
        // what the tray has always implied (it offers Show and Quit, and until
        // now the X button silently killed the process and the tray with it).
        // The vault deliberately stays unlocked: hiding is not a security
        // boundary, and the tray's "Lock Vault" and the idle auto-lock are the
        // controls for that. Quit (the tray's, or `app_quit` from the window)
        // sets QUITTING first so this handler lets the exit proceed. The first
        // hide of a run emits `window-hidden-to-tray`, so the renderer can tell
        // the user where the app went (R11 / A5-24). Without a tray there is
        // nothing to come back from, so the close goes through and quits.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let ordering = std::sync::atomic::Ordering::SeqCst;
                if QUITTING.load(ordering) || !TRAY_AVAILABLE.load(ordering) {
                    return;
                }
                api.prevent_close();
                let _ = window.hide();
                if first_time(&HIDE_NOTICE_SENT) {
                    let _ = window.emit("window-hidden-to-tray", ());
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        // Lifecycle teardown: every exit - the tray's Quit, `app_quit`, the
        // updater handing over to an installer, closing a tray-less window -
        // runs the vault lock path (`lock_vault_internal`): live sessions
        // killed, SFTP and edit registries cleared (staged copies of remote
        // files deleted), the transfer queue paused, MCP sessions torn down,
        // the master password cleared and `vault.lock` audited (A6-09 / A7-47
        // / A8-23) - and the MCP session teardowns still running (each
        // unseals its own credential, then sends its DELETE) are waited for,
        // 2 s at most, instead of being cut off. Tauri v2's
        // desktop run loop does NOT expose OS suspend/lock events
        // (WindowEvent::Suspended/Resumed are mobile-only), so an OS suspend
        // that leaves the process alive is not covered; that would need a
        // platform-specific crate.
        .run(|app_handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                exit_teardown(app_handle);
            }
        });
}

/// True once a real quit is under way, so the window-close handler can tell
/// "the user clicked X" (hide to tray) from "the app is exiting" (let it
/// through). Set by [`request_quit`]; without it `prevent_close()` would also
/// swallow a Quit and the app could never be exited.
static QUITTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// False when the tray icon could not be created: closing the window then
/// quits instead of hiding the app where it cannot be found again.
static TRAY_AVAILABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Set by the first hide-to-tray of this run (`window-hidden-to-tray` is
/// emitted once per run).
static HIDE_NOTICE_SENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set by the first exit teardown, so it runs once per run.
static EXIT_TEARDOWN_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set when setup failed: no state is managed, so commands are refused.
static STARTUP_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True the first time it is called for `flag`, false every time after.
fn first_time(flag: &std::sync::atomic::AtomicBool) -> bool {
    !flag.swap(true, std::sync::atomic::Ordering::SeqCst)
}

/// Exit the app the way the tray's Quit always has: mark the exit as
/// deliberate BEFORE asking to exit, so the close handler does not hide the
/// window instead. The exit itself runs the vault lock teardown
/// ([`exit_teardown`]).
fn request_quit(app: &tauri::AppHandle) {
    QUITTING.store(true, std::sync::atomic::Ordering::SeqCst);
    app.exit(0);
}

/// Quit from the window (ruling R11: Ctrl+Q, the palette, the vault menu) -
/// the same path as the tray's Quit. Closing the window only hides it, and on
/// desktops without a visible tray there was no way to exit at all (A7-37).
#[tauri::command]
fn app_quit(app: tauri::AppHandle) -> Result<serde_json::Value, commands::CmdError> {
    request_quit(&app);
    Ok(serde_json::json!({ "ok": true }))
}

/// How long an exit waits at most for the MCP session DELETEs still running:
/// long enough for a server that answers, short enough that a hung one never
/// holds the exit.
const EXIT_TEARDOWN_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// The teardown for an exit: the vault lock path, once, and only when there
/// is something to tear down - after a completed setup (a failed one manages
/// no state) and while the vault is unlocked (a lock already tore everything
/// down). Then the MCP session teardowns that lock started - and any still
/// running from an earlier lock or a server edit - are waited for,
/// [`EXIT_TEARDOWN_BUDGET`] at most, the unsealing of their credentials
/// included (the lock path no longer does it before returning): they used
/// to be started and forgotten, so the exit could cut them off and leave the
/// sessions open on the servers.
fn exit_teardown(app: &tauri::AppHandle) {
    let unlocked = app
        .try_state::<commands::VaultPasswordStore>()
        .is_some_and(|store| store.is_set());
    if unlocked && first_time(&EXIT_TEARDOWN_DONE) {
        commands::lock_vault_internal(app);
    }
    if let Some(mcp) = app.try_state::<assistant::mcp::McpState>() {
        finish_mcp_teardowns(&mcp, EXIT_TEARDOWN_BUDGET);
    }
}

/// Wait for the MCP session teardowns `mcp` still tracks, `budget` at most.
/// False when some were still running as it ran out: the exit cuts those off.
/// Runs on the main thread (the exit's event), outside the async runtime.
fn finish_mcp_teardowns(mcp: &assistant::mcp::McpState, budget: std::time::Duration) -> bool {
    let pending = mcp.take_teardowns();
    if pending.is_empty() {
        return true;
    }
    let finished =
        tauri::async_runtime::block_on(assistant::mcp::wait_for_teardowns(pending, budget));
    if !finished {
        log::warn!(
            "[sshspan] exit: MCP session teardowns still running after {} s were cut off",
            budget.as_secs()
        );
    }
    finished
}

/// While setup has failed nothing is managed, and a command would panic on
/// the missing state - taking the error dialog down with it. Refuse them.
fn refuse_after_failed_startup<F>(
    handler: F,
) -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static
where
    F: Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static,
{
    move |invoke| {
        if STARTUP_FAILED.load(std::sync::atomic::Ordering::SeqCst) {
            invoke
                .resolver
                .reject("SSHSpan could not start - see the error message.");
            return true;
        }
        handler(invoke)
    }
}

/// Tell the user why SSHSpan cannot start, then exit when the dialog closes
/// (A7-31). Tauri turns a setup error into a panic while the window is still
/// hidden (and, in release builds on Windows, with no console), so the app
/// used to vanish without a word on every launch. Non-blocking `show`: setup
/// runs on the main thread, where a blocking dialog would deadlock.
fn report_startup_failure(app: &tauri::AppHandle, error: &anyhow::Error) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
    STARTUP_FAILED.store(true, std::sync::atomic::Ordering::SeqCst);
    log::error!("[sshspan] startup failed: {error:#}");
    let db_path = db::get_db_path(app).ok();
    let handle = app.clone();
    app.dialog()
        .message(startup_failure_message(error, db_path.as_deref()))
        .title("SSHSpan cannot start")
        .kind(MessageDialogKind::Error)
        .show(move |_| handle.exit(1));
}

/// The startup error dialog's text: the cause and where the database is.
fn startup_failure_message(error: &anyhow::Error, db_path: Option<&std::path::Path>) -> String {
    let location = db_path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "unknown (the app data folder could not be determined)".to_string());
    format!(
        "SSHSpan could not open its vault database, so it cannot start.\n\n\
         Cause: {error:#}\n\n\
         Database: {location}\n\n\
         Check that the folder exists and is writable, that no other program has \
         the file open and that the disk is not full. SSHSpan will close now."
    )
}

/// Create system tray with menu
fn create_tray(app: &tauri::AppHandle) -> anyhow::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show, &lock, &quit])?;

    let _tray = TrayIconBuilder::with_id("main-tray")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| {
            let window = app.get_webview_window("main").unwrap();
            match event.id().as_ref() {
                "show" => {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
                "lock" => {
                    // Enforce the lock in the BACKEND, not by asking the
                    // renderer: a hung or compromised webview could otherwise
                    // ignore `vault-lock-requested` and leave the vault
                    // unsealed. `lock_vault_internal` kills sessions, stops
                    // watches, clears the in-memory password and bumps the
                    // vault generation; the emit afterwards is only so a
                    // healthy renderer updates its UI.
                    crate::commands::lock_vault_internal(app);
                    let _ = window.emit("vault-lock-requested", "");
                }
                "quit" => request_quit(app),
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hide_notice_is_sent_once_per_run() {
        let flag = std::sync::atomic::AtomicBool::new(false);
        assert!(first_time(&flag));
        assert!(!first_time(&flag));
        assert!(!first_time(&flag));
    }

    /// The exit waits for the MCP session DELETEs still running -
    /// and never longer than its budget. (The budgets that a passing run
    /// never reaches are wide for a loaded machine; the hung teardown runs
    /// 30 s, so a wait that ignored its budget still fails the 20 s bound.)
    #[test]
    fn the_exit_waits_for_mcp_teardowns_but_never_past_its_budget() {
        use std::time::{Duration, Instant};
        let mcp = assistant::mcp::McpState::new();
        assert!(
            finish_mcp_teardowns(&mcp, Duration::from_secs(30)),
            "nothing to wait for"
        );
        // One that answers is waited for.
        let (done, finished) = std::sync::mpsc::channel();
        mcp.track_teardowns(vec![tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = done.send(());
        })]);
        assert!(finish_mcp_teardowns(&mcp, Duration::from_secs(30)));
        assert!(finished.try_recv().is_ok(), "the teardown had finished");
        // One that hangs is cut off at the budget.
        mcp.track_teardowns(vec![tauri::async_runtime::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        })]);
        let started = Instant::now();
        assert!(!finish_mcp_teardowns(&mcp, Duration::from_millis(300)));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_secs(20),
            "{waited:?}"
        );
        assert!(mcp.take_teardowns().is_empty(), "each is waited for once");
    }

    #[test]
    fn startup_failure_message_names_the_cause_and_the_database() {
        let error = anyhow::anyhow!("disk I/O error").context("could not migrate the vault");
        let message = startup_failure_message(
            &error,
            Some(std::path::Path::new(
                "/home/u/.local/share/sshspan/sshspan.db",
            )),
        );
        assert!(message.contains("could not migrate the vault"), "{message}");
        assert!(message.contains("disk I/O error"), "{message}");
        assert!(
            message.contains("/home/u/.local/share/sshspan/sshspan.db"),
            "{message}"
        );
        let unknown = startup_failure_message(&error, None);
        assert!(unknown.contains("unknown"), "{unknown}");
    }
}
