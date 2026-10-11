//! Бунт: оболочка приложения.
//!
//! Здесь живёт всё, что нельзя сделать из веб-интерфейса: проверка и установка
//! обновлений из GitHub Releases, значок в трее, запуск одного экземпляра.
//! Запуск запретов (winws), служба и компоненты появятся позже.

mod modules;
mod settings;
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
    let telegram = MenuItem::with_id(app, "go:telegram", "Запрет Telegram · скоро", false, None::<&str>)?;
    let vless = MenuItem::with_id(app, "go:vless", "VLESS · скоро", false, None::<&str>)?;
    let wg = MenuItem::with_id(app, "go:wg", "WireGuard · скоро", false, None::<&str>)?;
    let updates = MenuItem::with_id(app, "go:updates", "Обновления", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "go:settings", "Настройки", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[&open, &sep1, &discord, &telegram, &vless, &wg, &sep2, &updates, &settings, &quit],
    )?;
    *app.state::<TrayItems>().discord.lock().unwrap() = Some(discord);

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Бунт")
        .on_menu_event(|app, event| {
            let id = event.id.as_ref();
            if id == "open" {
                show_main(app);
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
            modules::release_notes,
            settings::settings_get,
            settings::settings_set,
            settings::open_url,
            tray_set_discord,
            zapret::zapret_strategies,
            zapret::zapret_start,
            zapret::zapret_stop,
            zapret::zapret_status,
            zapret::zapret_foreign,
            zapret::zapret_take_over
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
            }
        });
}
