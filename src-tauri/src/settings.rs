//! Настройки Бунта, автозапуск и открытие ссылок.
//!
//! Настройки лежат в `%APPDATA%\\dev.belka.bunt\\settings.json`.
//! Автозапуск сделан записью в разделе Run реестра текущего пользователя: она видна в
//! «Автозагрузке» диспетчера задач. Бунт стартует без прав администратора и предлагает их дать.

use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, sync::Mutex};
use tauri::{AppHandle, Manager};

#[cfg(windows)]
use std::{os::windows::process::CommandExt, process::Command};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Settings {
    pub autostart: bool,
    /// Закрытие и сворачивание окна прячет Бунт в трей
    pub tray: bool,
    pub notify: bool,
    pub autoupdate: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { autostart: false, tray: true, notify: true, autoupdate: true }
    }
}

pub struct SettingsState(pub Mutex<Settings>);

fn file(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_config_dir().ok().map(|d| d.join("settings.json"))
}

pub fn load(app: &AppHandle) -> Settings {
    file(app)
        .and_then(|f| fs::read_to_string(f).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(app: &AppHandle, s: &Settings) -> Result<(), String> {
    let f = file(app).ok_or("Нет папки настроек")?;
    if let Some(dir) = f.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(f, serde_json::to_string_pretty(s).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

#[cfg_attr(not(windows), allow(dead_code))]
#[cfg(windows)]
pub(crate) fn run_hidden(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

#[cfg(windows)]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(windows)]
fn autostart_present() -> bool {
    run_hidden("reg", &["query", RUN_KEY, "/v", "Bunt"]).is_some()
}

/// Старые версии (0.1.5) ставили автозапуск задачей планировщика. Убираем её, чтобы Бунт не запускался дважды.
#[cfg(windows)]
fn remove_old_task() {
    if run_hidden("schtasks", &["/Query", "/TN", "Bunt"]).is_some() {
        let _ = run_hidden("schtasks", &["/Delete", "/TN", "Bunt", "/F"]);
    }
}

/// Автозапуск: запись в разделе Run текущего пользователя, она видна в «Автозагрузке» диспетчера задач.
/// Бунт стартует без прав администратора и сам предлагает их дать.
fn apply_autostart(on: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        remove_old_task();
        if on {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let value = format!("\"{}\" --hidden", exe.display());
            run_hidden("reg", &["add", RUN_KEY, "/v", "Bunt", "/t", "REG_SZ", "/d", &value, "/f"])
                .map(|_| ())
                .ok_or_else(|| "Не удалось записать автозапуск в реестр".to_string())
        } else if autostart_present() {
            run_hidden("reg", &["delete", RUN_KEY, "/v", "Bunt", "/f"])
                .map(|_| ())
                .ok_or_else(|| "Не удалось убрать автозапуск из реестра".to_string())
        } else {
            Ok(())
        }
    }
    #[cfg(not(windows))]
    {
        let _ = on;
        Ok(())
    }
}

/// Запись должна указывать на текущий exe (путь мог измениться при переустановке).
fn reconcile(s: &Settings) {
    if s.autostart {
        let _ = apply_autostart(true);
    } else {
        #[cfg(windows)]
        remove_old_task();
    }
}

/// Запущен ли Бунт с правами администратора.
pub fn is_admin_sync() -> bool {
    #[cfg(windows)]
    {
        // Уровень целостности «High» (S-1-16-12288) есть только у запущенных от администратора
        run_hidden("whoami", &["/groups"]).map(|o| o.contains("S-1-16-12288")).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[tauri::command]
pub async fn is_admin() -> Result<bool, String> {
    Ok(is_admin_sync())
}

/// Перезапускает Бунт от имени администратора. Новый экземпляр после подтверждения UAC
/// закрывает старый (`--takeover`). Если подтверждение отклонить, старый продолжает работать.
#[tauri::command]
pub async fn relaunch_as_admin() -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let path = exe.display().to_string().replace('\'', "''");
        let script = format!(
            "Start-Process -FilePath '{path}' -ArgumentList '--takeover','{}' -Verb RunAs",
            std::process::id()
        );
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Вызывается при старте: если запущены с `--takeover PID`, закрывает старый (неадминистраторский) экземпляр.
pub fn takeover_from_args() {
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        let Some(i) = args.iter().position(|a| a == "--takeover") else { return };
        let Some(pid) = args.get(i + 1).filter(|p| p.chars().all(|c| c.is_ascii_digit())) else { return };
        let Ok(exe) = std::env::current_exe() else { return };
        let Some(name) = exe.file_name().map(|n| n.to_string_lossy().to_string()) else { return };
        // Убеждаемся, что по этому PID действительно наш exe, а не посторонний процесс
        let filter_pid = format!("PID eq {pid}");
        let filter_img = format!("IMAGENAME eq {name}");
        let listed = run_hidden("tasklist", &["/FI", &filter_pid, "/FI", &filter_img, "/NH"]).unwrap_or_default();
        if listed.to_lowercase().contains(&name.to_lowercase()) {
            let _ = run_hidden("taskkill", &["/PID", pid, "/F"]);
            std::thread::sleep(std::time::Duration::from_millis(800));
        }
    }
}

#[tauri::command]
pub async fn settings_get(state: tauri::State<'_, SettingsState>) -> Result<Settings, String> {
    let s = state.0.lock().unwrap().clone();
    reconcile(&s);
    Ok(s)
}

#[tauri::command]
pub async fn settings_set(
    app: AppHandle,
    state: tauri::State<'_, SettingsState>,
    settings: Settings,
) -> Result<Settings, String> {
    let old = state.0.lock().unwrap().clone();
    let mut new = settings;
    let mut error = None;
    if new.autostart != old.autostart {
        if let Err(e) = apply_autostart(new.autostart) {
            new.autostart = old.autostart;
            error = Some(e);
        }
    }
    save(&app, &new)?;
    *state.0.lock().unwrap() = new.clone();
    match error {
        Some(e) => Err(e),
        None => Ok(new),
    }
}

/// Есть ли запись автозапуска в реестре.
#[tauri::command]
pub async fn autostart_exists() -> Result<bool, String> {
    #[cfg(windows)]
    {
        Ok(autostart_present())
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

/// Открывает в браузере только известные ссылки проекта.
#[tauri::command]
pub fn open_url(url: String) -> Result<(), String> {
    const ALLOWED: [&str; 3] = [
        "https://github.com/belka-developer/bunt",
        "https://github.com/belka-developer/bunt#readme",
        "https://discord.gg/dw65R5Mvft",
    ];
    let ok = ALLOWED.contains(&url.as_str())
        || url.starts_with("https://github.com/belka-developer/bunt/")
        || url.starts_with("https://github.com/Flowseal/zapret-discord-youtube/")
        || url.starts_with("https://github.com/Flowseal/tg-ws-proxy/")
        || url.starts_with("https://github.com/fptn-project/fptn/");
    if !ok {
        return Err("Эту ссылку открыть нельзя".into());
    }
    launch(&url)
}

/// Открывает адрес в браузере по умолчанию. Проверка, что адрес разрешён, лежит на вызывающем.
pub(crate) fn launch(url: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        Command::new("explorer")
            .arg(url)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(windows))]
    let _ = url;
    Ok(())
}
