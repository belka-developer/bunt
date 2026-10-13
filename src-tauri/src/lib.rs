//! Бунт: оболочка приложения.
//!
//! Здесь живёт всё, что нельзя сделать из веб-интерфейса: проверка и установка
//! обновлений из GitHub Releases, значок в трее, запуск одного экземпляра.
//! Запуск запретов (winws), служба и компоненты появятся позже.

mod integrity;
mod modules;
mod settings;
mod fptn;
mod wg;
mod dns;
mod vless;
mod vcredist;
mod telegram;
mod zapret;

use serde::Serialize;
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};
use tauri_plugin_updater::UpdaterExt;

#[derive(Serialize)]
struct AppInfo {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct UpdateInfo {
    available: bool,
    current: String,
    latest: Option<String>,
    notes: Option<String>,
}

#[derive(Serialize, Clone)]
struct Progress {
    downloaded: u64,
    total: Option<u64>,
}

/// Название и установленная версия приложения.
#[tauri::command]
fn app_info(app: AppHandle) -> AppInfo {
    AppInfo {
        name: app.package_info().name.clone(),
        version: app.package_info().version.to_string(),
    }
}

/// Проверяет, есть ли на GitHub новая версия. Ничего не скачивает.
#[tauri::command]
async fn check_update(app: AppHandle) -> Result<UpdateInfo, String> {
    let current = app.package_info().version.to_string();
    let updater = app.updater().map_err(|e| e.to_string())?;
    let update = updater.check().await.map_err(|e| e.to_string())?;

    Ok(match update {
        Some(u) => UpdateInfo {
            available: true,
            current,
            latest: Some(u.version.clone()),
            notes: u.body.clone(),
        },
        None => UpdateInfo {
            available: false,
            current,
            latest: None,
            notes: None,
        },
    })
}

/// Скачивает новую версию, проверяет подпись и запускает установщик.
/// Вызывается только по нажатию пользователя. Прогресс уходит в интерфейс событиями.
#[tauri::command]
async fn install_update(app: AppHandle) -> Result<(), String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let update = updater
        .check()
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Обновлений нет".to_string())?;

    let mut downloaded: u64 = 0;
    let progress_app = app.clone();
    let done_app = app.clone();

    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let _ = progress_app.emit("update-progress", Progress { downloaded, total });
            },
            move || {
                let _ = done_app.emit("update-installing", ());
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    app.restart();
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Пункт меню трея с состоянием запрета Discord (текст меняется из интерфейса).
struct TrayItems {
    discord: Mutex<Option<MenuItem<tauri::Wry>>>,
}

/// Открывает Бунт на нужной вкладке.
fn go_page(app: &AppHandle, page: &str) {
    show_main(app);
    let _ = app.emit("navigate", page);
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Открыть Бунт", true, None::<&str>)?;
    let discord = MenuItem::with_id(app, "go:discord", "Запрет Discord и YouTube", true, None::<&str>)?;
    let telegram = MenuItem::with_id(app, "go:telegram", "Запрет Telegram", true, None::<&str>)?;
    let vless = MenuItem::with_id(app, "go:vless", "VLESS", true, None::<&str>)?;
    let dns = MenuItem::with_id(app, "go:dns", "DNS", true, None::<&str>)?;
    let fptn = MenuItem::with_id(app, "go:fptn", "FPTN", true, None::<&str>)?;
    let wg = MenuItem::with_id(app, "go:wg", "WireGuard / AmneziaWG", true, None::<&str>)?;
    let updates = MenuItem::with_id(app, "go:updates", "Обновления", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "go:settings", "Настройки", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let elevate = MenuItem::with_id(app, "elevate", "Дать Бунту права администратора", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[&open, &sep1, &discord, &telegram, &vless, &wg, &dns, &fptn, &sep2, &updates, &settings, &quit],
    )?;
    // Без прав администратора запрет работать не будет: в меню трея появляется пункт, который это исправляет
    if !settings::is_admin_sync() {
        menu.insert(&elevate, 1)?;
    }
    *app.state::<TrayItems>().discord.lock().unwrap() = Some(discord);

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Бунт")
        .on_menu_event(|app, event| {
            let id = event.id.as_ref();
            if id == "open" {
                show_main(app);
            } else if id == "elevate" {
                show_main(app);
                let _ = app.emit("navigate", "home");
                tauri::async_runtime::spawn(async { let _ = settings::relaunch_as_admin().await; });
            } else if id == "quit" {
                app.exit(0);
            } else if let Some(page) = id.strip_prefix("go:") {
                go_page(app, page);
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// Интерфейс сообщает, включён ли запрет, и подпись пункта в трее меняется.
#[tauri::command]
fn tray_set_discord(state: tauri::State<'_, TrayItems>, on: bool) {
    if let Some(item) = state.discord.lock().unwrap().as_ref() {
        let _ = item.set_text(if on { "Запрет Discord и YouTube · включён" } else { "Запрет Discord и YouTube · выключен" });
    }
}

pub fn run() {
    // После перезапуска от администратора закрываем старый экземпляр
    settings::takeover_from_args();
    tauri::Builder::default()
        .manage(zapret::Zapret::default())
        .manage(settings::SettingsState(Mutex::new(settings::Settings::default())))
        .manage(TrayItems { discord: Mutex::new(None) })
        // Второй запуск просто поднимает уже открытое окно.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main(app);
        }))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            app_info,
            check_update,
            install_update,
            modules::installed_components,
            modules::modules_dir,
            modules::latest_component,
            modules::install_component,
            modules::uninstall_component,
            modules::release_notes,
            settings::settings_get,
            settings::settings_set,
            integrity::integrity_check,
            integrity::integrity_verify_online,
            settings::open_url,
            settings::autostart_exists,
            settings::is_admin,
            settings::relaunch_as_admin,
            tray_set_discord,
            zapret::zapret_strategies,
            zapret::zapret_start,
            zapret::zapret_stop,
            zapret::zapret_status,
            zapret::zapret_foreign,
            zapret::zapret_take_over,
            telegram::telegram_status,
            telegram::telegram_start,
            telegram::telegram_stop,
            telegram::telegram_config_set,
            telegram::telegram_new_secret,
            telegram::telegram_config_reset,
            telegram::telegram_set_autostart,
            telegram::telegram_foreign,
            telegram::telegram_take_over,
            fptn::fptn_status,
            fptn::fptn_connect,
            fptn::fptn_disconnect,
            fptn::fptn_repair,
            fptn::fptn_config_set,
            fptn::fptn_config_reset,
            fptn::fptn_clear_token,
            fptn::fptn_adapter,
            fptn::fptn_log,
            fptn::fptn_foreign,
            fptn::fptn_take_over,
            wg::wg_status,
            wg::wg_connect,
            wg::wg_disconnect,
            wg::wg_repair,
            wg::wg_import,
            wg::wg_delete,
            wg::wg_profile_view,
            wg::wg_select,
            wg::wg_config_set,
            wg::wg_adapter,
            wg::wg_log,
            dns::dns_status,
            dns::dns_apply,
            dns::dns_reset,
            dns::dns_ping,
            vless::vless_status,
            vless::vless_connect,
            vless::vless_disconnect,
            vless::vless_repair,
            vless::vless_import,
            vless::vless_delete,
            vless::vless_select,
            vless::vless_config_set,
            vless::vless_profile_view,
            vless::vless_ping,
            vless::vless_processes,
            vless::vless_log,
            vless::vless_sub_add,
            vless::vless_sub_refresh,
            vless::vless_sub_remove
        ])
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            let tray = window.state::<settings::SettingsState>().0.lock().unwrap().tray;
            match event {
                // Закрытие окна прячет Бунт в трей (выход есть в меню трея)
                tauri::WindowEvent::CloseRequested { api, .. } if tray => {
                    api.prevent_close();
                    let _ = window.hide();
                }
                // Сворачивание тоже уводит в трей
                tauri::WindowEvent::Resized(_) if tray && window.is_minimized().unwrap_or(false) => {
                    let _ = window.hide();
                }
                _ => {}
            }
        })
        .setup(|app| {
            let s = settings::load(app.handle());
            *app.state::<settings::SettingsState>().0.lock().unwrap() = s;
            setup_tray(app)?;
            // С параметром --hidden (автозапуск) окно не показываем, Бунт сидит в трее
            if !std::env::args().any(|a| a == "--hidden") {
                show_main(app.handle());
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("не удалось запустить Бунт")
        .run(|app, event| {
            // При выходе останавливаем запущенный запрет, чтобы winws не остался висеть.
            if let tauri::RunEvent::Exit = event {
                app.state::<zapret::Zapret>().stop();
                telegram::stop();
                fptn::shutdown();
                wg::shutdown();
                vless::shutdown();
            }
        });
}
