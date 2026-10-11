//! Бунт: оболочка приложения.
//!
//! Здесь живёт всё, что нельзя сделать из веб-интерфейса: проверка и установка
//! обновлений из GitHub Releases, значок в трее, запуск одного экземпляра.
//! Запуск запретов (winws), служба и компоненты появятся позже.

mod modules;
mod zapret;

use serde::Serialize;
use tauri::{
    menu::{Menu, MenuItem},
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

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Открыть", true, None::<&str>)?;
    let check = MenuItem::with_id(app, "check", "Проверить обновления", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &check, &quit])?;

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Бунт")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "check" => {
                show_main(app);
                let _ = app.emit("tray-check-update", ());
            }
            "quit" => app.exit(0),
            _ => {}
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

pub fn run() {
    tauri::Builder::default()
        .manage(zapret::Zapret::default())
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
            zapret::zapret_strategies,
            zapret::zapret_start,
            zapret::zapret_stop,
            zapret::zapret_status
        ])
        .setup(|app| {
            setup_tray(app)?;
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
