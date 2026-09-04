//! SSHSpan - Cross-platform SSH Key Manager
//! Tauri v2 library entry point

pub mod commands;
pub mod crypto;
pub mod db;
pub mod bitwarden;
pub mod ssh;
pub mod config;
pub mod ssh_client;

use tauri::{
    Emitter,
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent, MouseButton},
    Manager,
};

use commands::*;
use commands::server::*;
use commands::terminal::*;
use db::Database;
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
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
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

            // Live SSH terminal sessions; cleared on vault lock
            app.manage(std::sync::Arc::new(SessionRegistry::new()));

            create_tray(app.handle())?;
            

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Vault commands
            vault_create, vault_unlock, vault_lock, vault_change_password,
            vault_status, vault_export, vault_import,
            // Key commands
            key_generate, key_import, key_export, key_delete, key_list,
            key_get, key_fingerprint, key_deploy, key_remove_deployed,
            // Category commands
            category_list, category_create, category_rename, category_reparent, category_delete,
            // Key ↔ category bridge
            key_set_categories, key_create_with_categories,
            // SSH Config commands
            ssh_config_read, ssh_config_write, ssh_config_list_hosts,
            // Saved server CRUD
            server_list, server_save, server_delete,
            // Connect / interactive SSH terminal
            terminal_connect, terminal_send, terminal_resize, terminal_disconnect, terminal_list,
            server_test, known_hosts_list, known_hosts_forget,
            // Bitwarden commands
            bitwarden_get_config, bitwarden_save_config, bitwarden_test_connection, bitwarden_sync,
            // Settings commands
            settings_get, settings_set,
            // Audit log commands
            audit_list,
            // System commands
            system_open_external, system_show_item_in_folder, system_select_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
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
            if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event {
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

