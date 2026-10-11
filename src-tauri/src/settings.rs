//! Настройки Бунта, автозапуск и открытие ссылок.
//!
//! Настройки лежат в `%APPDATA%\\dev.belka.bunt\\settings.json`.
//! Автозапуск сделан задачей планировщика Windows с повышенными правами: так Бунт
//! стартует при входе в систему без окна UAC (Бунту нужны права администратора).

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
const TASK: &str = "Bunt";

#[cfg(windows)]
fn schtasks(args: &[&str]) -> bool {
    Command::new("schtasks")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn task_exists() -> bool {
    schtasks(&["/Query", "/TN", TASK])
}

#[cfg(windows)]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(windows)]
fn create_task() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Запуск Бунта при входе в Windows</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-32-545</GroupId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
      <Arguments>--hidden</Arguments>
    </Exec>
  </Actions>
</Task>"#,
        xml_escape(&exe.display().to_string())
    );
    // schtasks читает XML в UTF-16 с BOM
    let mut bytes: Vec<u8> = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let tmp = std::env::temp_dir().join("bunt-autostart.xml");
    fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    let ok = schtasks(&["/Create", "/TN", TASK, "/XML", &tmp.display().to_string(), "/F"]);
    let _ = fs::remove_file(&tmp);
    if ok { Ok(()) } else { Err("Не удалось создать задачу автозапуска. Запустите Бунт от имени администратора.".into()) }
}

fn apply_autostart(on: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        if on {
            create_task()
        } else if task_exists() {
            if schtasks(&["/Delete", "/TN", TASK, "/F"]) { Ok(()) } else { Err("Не удалось удалить задачу автозапуска".into()) }
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

/// Задача должна указывать на текущий exe (путь мог измениться при переустановке).
fn reconcile(s: &Settings) {
    if s.autostart {
        let _ = apply_autostart(true);
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

/// Есть ли задача автозапуска в планировщике заданий Windows.
#[tauri::command]
pub async fn autostart_exists() -> Result<bool, String> {
    #[cfg(windows)]
    {
        Ok(task_exists())
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
        || url.starts_with("https://github.com/Flowseal/zapret-discord-youtube/");
    if !ok {
        return Err("Эту ссылку открыть нельзя".into());
    }
    #[cfg(windows)]
    {
        Command::new("explorer")
            .arg(&url)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
