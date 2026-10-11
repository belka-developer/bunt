//! Запрет для Telegram: локальный MTProto-прокси `tg-ws-proxy` (Flowseal, лицензия MIT).
//!
//! В релизе лежит один `TgWsProxy_windows.exe`. Бунт кладёт его в `modules\telegram\<версия>`,
//! готовит рядом портативный конфиг (`TgWsProxy_data\config.json`) и запускает без окна настроек.
//! Права администратора для работы не нужны.

use std::{
    collections::hash_map::RandomState,
    fs,
    hash::{BuildHasher, Hasher},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Имя exe внутри папки компонента.
pub(crate) const EXE: &str = "TgWsProxy.exe";
/// Портативные данные прокси (конфиг, лог). Лежат рядом с exe.
pub(crate) const DATA: &str = "TgWsProxy_data";
const PROC: &str = "TgWsProxy";
const DEFAULT_PORT: u16 = 1443;

/// Имя файла в релизе под архитектуру этого компьютера.
pub(crate) fn release_asset_name() -> &'static str {
    if cfg!(target_arch = "aarch64") { "TgWsProxy_windows_arm64.exe" } else { "TgWsProxy_windows.exe" }
}

fn random_secret() -> String {
    let mut out = String::new();
    for _ in 0..2 {
        // RandomState засевается ОС, для локального прокси этого достаточно
        let mut h = RandomState::new().build_hasher();
        h.write_u64(std::process::id() as u64);
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

fn our_pids() -> Vec<u32> {
    crate::zapret::list_procs(PROC).into_iter().filter(|(_, p)| crate::zapret::is_ours(p)).map(|(id, _)| id).collect()
}

fn foreign() -> Vec<String> {
    crate::zapret::list_procs(PROC).into_iter().filter(|(_, p)| !crate::zapret::is_ours(p)).map(|(_, p)| p).collect()
}

/// Останавливает прокси Бунта (чужие копии не трогаем).
pub fn stop() {
    for pid in our_pids() {
        crate::zapret::kill_pid(pid);
    }
}

pub(crate) fn running() -> bool {
    !our_pids().is_empty()
}

fn flag_path() -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join("telegram.json"))
}

pub(crate) fn set_enabled(on: bool) {
    if let Ok(p) = flag_path() {
        let _ = fs::write(p, serde_json::json!({ "enabled": on }).to_string());
    }
}

fn is_enabled() -> bool {
    flag_path()
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("enabled").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

fn config_path(dir: &Path) -> PathBuf {
    dir.join(DATA).join("config.json")
}

fn read_config(dir: &Path) -> serde_json::Value {
    fs::read_to_string(config_path(dir)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| serde_json::json!({}))
}

/// Готовит папку данных: конфиг по умолчанию и отметку, что приветственное окно уже показано.
/// Существующий конфиг не трогаем, кроме выключения самообновления: версиями управляет Бунт.
pub(crate) fn prepare(dir: &Path) -> Result<(), String> {
    let data = dir.join(DATA);
    fs::create_dir_all(&data).map_err(|e| format!("Не удалось создать {}: {e}", data.display()))?;
    let _ = fs::write(data.join(".first_run_done_mtproto"), b"");
    let mut cfg = read_config(dir);
    let obj = cfg.as_object_mut().ok_or("Конфиг прокси повреждён")?;
    obj.entry("host").or_insert(serde_json::json!("127.0.0.1"));
    obj.entry("port").or_insert(serde_json::json!(DEFAULT_PORT));
    if obj.get("secret").and_then(|s| s.as_str()).map(|s| s.len() != 32).unwrap_or(true) {
        obj.insert("secret".into(), serde_json::json!(random_secret()));
    }
    obj.insert("check_updates".into(), serde_json::json!(false));
    obj.insert("autostart".into(), serde_json::json!(false));
    fs::write(config_path(dir), serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?)
        .map_err(|e| format!("Не удалось записать конфиг: {e}"))
}

/// Читает данные прокси (порт, секрет) прежней версии, без логов.
pub(crate) fn read_data(from: Option<&Path>) -> Vec<(String, Vec<u8>)> {
    let Some(from) = from else { return Vec::new() };
    let Ok(rd) = fs::read_dir(from.join(DATA)) else { return Vec::new() };
    rd.flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if e.path().is_file() && !name.contains(".log") { Some((name, fs::read(e.path()).ok()?)) } else { None }
        })
        .collect()
}

pub(crate) fn restore_data(to: &Path, files: &[(String, Vec<u8>)]) {
    if files.is_empty() {
        return;
    }
    let d = to.join(DATA);
    let _ = fs::create_dir_all(&d);
    for (name, bytes) in files {
        let _ = fs::write(d.join(name), bytes);
    }
}

fn tail(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().rev().take(4).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

fn start_blocking() -> Result<(), String> {
    let dir = crate::modules::active_dir("telegram")?;
    let exe = dir.join(EXE);
    if !exe.is_file() {
        return Err("Файлы компонента не найдены. Переустановите его.".into());
    }
    if running() {
        return Ok(());
    }
    if !foreign().is_empty() {
        return Err("Уже запущен другой TgWsProxy (не из Бунта). Закройте его в трее и повторите.".into());
    }
    prepare(&dir)?;
    let mut cmd = Command::new(&exe);
    cmd.arg("--portable").current_dir(&dir).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.spawn().map_err(|e| format!("Не удалось запустить прокси: {e}"))?;
    // onefile-exe распаковывается секунду-две: ждём, пока процесс не закрепится
    for _ in 0..12 {
        std::thread::sleep(Duration::from_millis(500));
        if running() {
            std::thread::sleep(Duration::from_millis(800));
            if running() {
                return Ok(());
            }
            break;
        }
    }
    let log = tail(&dir.join(DATA).join("proxy.log"));
    Err(if log.is_empty() { "Прокси сразу закрылся. Возможно, порт занят.".into() } else { format!("Прокси сразу закрылся: {log}") })
}

#[derive(serde::Serialize)]
pub struct Status {
    running: bool,
    enabled: bool,
    port: u16,
    link: String,
}

fn status_now() -> Status {
    let (port, link) = match crate::modules::active_dir("telegram") {
        Ok(dir) => {
            let cfg = read_config(&dir);
            let port = cfg.get("port").and_then(|p| p.as_u64()).unwrap_or(DEFAULT_PORT as u64) as u16;
            let host = match cfg.get("host").and_then(|h| h.as_str()) {
                Some("0.0.0.0") | None | Some("") => "127.0.0.1".to_string(),
                Some(h) => h.to_string(),
            };
            let secret = cfg.get("secret").and_then(|s| s.as_str()).unwrap_or("");
            let link = if cfg.get("no_secure").and_then(|b| b.as_bool()).unwrap_or(false) {
                format!("tg://socks?server={host}&port={port}")
            } else if secret.is_empty() {
                String::new()
            } else {
                format!("tg://proxy?server={host}&port={port}&secret=dd{secret}")
            };
            (port, link)
        }
        Err(_) => (DEFAULT_PORT, String::new()),
    };
    Status { running: running(), enabled: is_enabled(), port, link }
}

/// Запущен ли прокси, порт и ссылка для Telegram. Конфиг создаётся при первом обращении.
#[tauri::command]
pub async fn telegram_status() -> Result<Status, String> {
    tauri::async_runtime::spawn_blocking(|| {
        if let Ok(dir) = crate::modules::active_dir("telegram") {
            let _ = prepare(&dir);
        }
        status_now()
    })
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn telegram_start() -> Result<Status, String> {
    tauri::async_runtime::spawn_blocking(|| {
        start_blocking()?;
        set_enabled(true);
        Ok(status_now())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn telegram_stop() -> Result<Status, String> {
    tauri::async_runtime::spawn_blocking(|| {
        stop();
        set_enabled(false);
        status_now()
    })
    .await
    .map_err(|e| e.to_string())
}

/// Меняет порт прокси. Если он работает, перезапускает его.
#[tauri::command]
pub async fn telegram_set_port(port: u16) -> Result<Status, String> {
    if port < 1024 {
        return Err("Порт должен быть от 1024 до 65535.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let dir = crate::modules::active_dir("telegram")?;
        prepare(&dir)?;
        let mut cfg = read_config(&dir);
        cfg["port"] = serde_json::json!(port);
        fs::write(config_path(&dir), serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        if running() {
            stop();
            std::thread::sleep(Duration::from_millis(800));
            start_blocking()?;
        }
        Ok(status_now())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_32_hex_and_differs() {
        let (a, b) = (random_secret(), random_secret());
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn prepare_keeps_port_and_secret() {
        let d = std::env::temp_dir().join(format!("bunt-tg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        prepare(&d).unwrap();
        let first = read_config(&d);
        assert_eq!(first["port"], 1443);
        assert_eq!(first["check_updates"], false);
        let mut c = first.clone();
        c["port"] = serde_json::json!(2000);
        fs::write(config_path(&d), c.to_string()).unwrap();
        prepare(&d).unwrap();
        let second = read_config(&d);
        assert_eq!(second["port"], 2000);
        assert_eq!(second["secret"], first["secret"]);
        let _ = fs::remove_dir_all(&d);
    }
}
