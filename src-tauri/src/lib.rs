//! SSHSpan - Cross-platform SSH Key Manager
//! Tauri v2 library entry point

pub mod bitwarden;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod db;
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
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_sql::Builder::default().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let state = AppState::new(app.handle())?;
            app.manage(state);

            // Vault password lives in memory only; cleared on lock / quit
            app.manage(VaultPasswordStore::new());
            // Save-dialog-approved write targets (system_write_text_file gate)
            app.manage(commands::DialogPathStore::new());
            // Master-password guess backoff (unlock / change-password)
            app.manage(commands::UnlockThrottle::new());

            // Live SSH terminal sessions; cleared on vault lock
            app.manage(std::sync::Arc::new(SessionRegistry::new()));
            app.manage(SftpRegistry::new());
            app.manage(EditRegistry::new());
            app.manage(KeepaliveRegistry::new());
            app.manage(crate::sftp::queue::TransferQueue::new());

            create_tray(app.handle())?;

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Vault commands
            vault_create,
            vault_unlock,
            vault_lock,
            vault_change_password,
            vault_status,
            vault_export,
            vault_import,
            vault_backup_create,
            vault_backup_restore,
            // Key commands
            key_generate,
            key_import,
            key_export,
            key_export_to_file,
            key_delete,
            key_list,
            key_get,
            key_fingerprint,
            key_deploy,
            key_remove_deployed,
            // Category commands
            category_list,
            category_create,
            category_rename,
            category_reparent,
            category_delete,
            // Key ↔ category bridge
            key_set_categories,
            key_create_with_categories,
            // SSH Config commands
            ssh_config_read,
            ssh_config_write,
            ssh_config_list_hosts,
            // Saved server CRUD
            server_list,
            server_save,
            server_delete,
            // Connect / interactive SSH terminal
            terminal_connect,
            terminal_send,
            terminal_resize,
            terminal_disconnect,
            terminal_keepalive,
            terminal_list,
            server_test,
            known_hosts_list,
            known_hosts_check,
            known_hosts_forget,
            sftp_open,
            sftp_list_dir,
            sftp_resolve_link,
            sftp_dir_size,
            sftp_file_sha256,
            sftp_mkdir,
            sftp_remove,
            sftp_rename,
            sftp_set_mtime,
            sftp_download,
            sftp_upload,
            sftp_open_for_edit,
            sftp_close_edit,
            sftp_chmod,
            sftp_get_permissions,
            sftp_touch,
            sftp_fs_info,
            sftp_keepalive_start,
            sftp_queue_add,
            sftp_queue_list,
            sftp_queue_cancel,
            sftp_queue_retry,
            sftp_queue_clear_finished,
            sftp_server_copy,
            sftp_search,
            sftp_bookmarks_list,
            sftp_bookmarks_save,
            sftp_local_list,
            sftp_close,
            sftp_stage_path,
            // Bitwarden commands
            bitwarden_get_config,
            bitwarden_save_config,
            bitwarden_test_connection,
            bitwarden_sync,
            // Settings commands
            settings_get,
            settings_set,
            // Audit log commands
            audit_list,
            // System commands
            system_open_external,
            system_open_url,
            system_show_item_in_folder,
            system_select_file,
            system_pick_save_path,
            system_write_text_file,
            update_check,
            update_download_and_run,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        // Best-effort lifecycle teardown: Tauri v2's desktop run loop does NOT
        // expose OS suspend/lock events (WindowEvent::Suspended/Resumed are
        // mobile-only).  We therefore reuse the existing `vault_lock` teardown
        // when the app is about to exit.  This clears the in-memory master
        // password and stops live sessions, but it cannot cover an OS suspend
        // that leaves the process alive.  A true OS-suspend handler would need a
        // platform-specific crate (e.g. `windows` on Win32) and is out of scope
        // for this fix.
        .run(|_app_handle, event| match event {
            tauri::RunEvent::ExitRequested { .. } => {
                let _ = _app_handle
                    .state::<crate::commands::VaultPasswordStore>()
                    .clear();
                _app_handle
                    .state::<std::sync::Arc<crate::ssh_client::SessionRegistry>>()
                    .kill_all();
            }
            _ => {}
        });
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
                    let _ = window.emit("vault-lock-requested", "");
                }
                "quit" => {
                    app.exit(0);
                }
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
