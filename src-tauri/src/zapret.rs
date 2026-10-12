//! Запуск запрета для Discord и YouTube.
//!
//! Каждая стратегия Flowseal это bat-файл с одной командой запуска `winws.exe`.
//! Бунт читает этот файл из установленной версии, подставляет пути и запускает
//! `winws.exe` сам, без cmd и без окна. Поэтому работают все стратегии, в том числе
//! новые, а отдельной конвертации в другой формат не нужно.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Default)]
pub struct Zapret(Mutex<Option<Child>>);

impl Zapret {
    /// Останавливает запущенный запрет. Вызывается и при выходе из приложения.
    pub fn stop(&self) {
        if let Some(mut child) = self.0.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // winws, оставшийся от прошлого запуска Бунта (например, при обновлении)
        for pid in our_pids() {
            kill_pid(pid);
        }
    }
}

/// Разбирает bat-файл стратегии в список аргументов для winws.exe.
pub fn parse_bat(text: &str, bin: &str, lists: &str, game_tcp: &str, game_udp: &str) -> Result<Vec<String>, String> {
    let text = text.trim_start_matches('\u{feff}');
    let mut collected = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim_end();
        if !inside {
            let lower = line.to_lowercase();
            if let Some(pos) = lower.find("winws.exe") {
                inside = true;
                collected.push_str(&line[pos + "winws.exe".len()..]);
            } else {
                continue;
            }
        } else {
            collected.push(' ');
            collected.push_str(line);
        }
        if collected.ends_with('^') {
            collected.pop();
        } else {
            break;
        }
    }
    if !inside {
        return Err("В файле стратегии нет запуска winws.exe".into());
    }

    let mut s = collected.trim_start_matches('"').to_string();
    for (name, value) in [("%BIN%", bin), ("%LISTS%", lists), ("%GameFilterTCP%", game_tcp), ("%GameFilterUDP%", game_udp)] {
        s = replace_ci(&s, name, value);
    }
    if s.contains('%') {
        return Err("В стратегии осталась неизвестная переменная. Обновите Бунт.".into());
    }
    Ok(split_args(&s))
}

fn replace_ci(s: &str, from: &str, to: &str) -> String {
    let (ls, lf) = (s.to_lowercase(), from.to_lowercase());
    // Нижний регистр может менять длину только у редких символов; в bat-файлах их нет.
    if ls.len() != s.len() {
        return s.replace(from, to);
    }
    let mut out = String::new();
    let mut i = 0;
    while let Some(pos) = ls[i..].find(&lf) {
        out.push_str(&s[i..i + pos]);
        out.push_str(to);
        i += pos + from.len();
    }
    out.push_str(&s[i..]);
    out
}

/// Делит строку по пробелам, как cmd: кавычки группируют и убираются.
fn split_args(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut has = false;
    for c in s.chars() {
        match c {
            '"' => { quoted = !quoted; has = true; }
            c if c.is_whitespace() && !quoted => {
                if has { args.push(std::mem::take(&mut cur)); has = false; }
            }
            c => { cur.push(c); has = true; }
        }
    }
    if has { args.push(cur); }
    args
}

fn write_if_missing(path: &Path, text: &str) {
    if !path.exists() {
        let _ = fs::write(path, text);
    }
}

fn prepare_lists(dir: &Path, ipset: &str) -> Result<(), String> {
    let lists = dir.join("lists");
    fs::create_dir_all(&lists).map_err(|e| e.to_string())?;
    write_if_missing(&lists.join("ipset-exclude-user.txt"), "203.0.113.113/32\n");
    write_if_missing(&lists.join("list-general-user.txt"), "# Never leave this file empty\ndomain.example.abc\n");
    write_if_missing(&lists.join("list-exclude-user.txt"), "domain.example.abc\n");
    let target = lists.join("ipset-all.txt");
    match ipset {
        "any" => fs::write(&target, "").map_err(|e| e.to_string())?,
        "loaded" => {
            let backup = lists.join("ipset-all.txt.backup");
            if backup.exists() {
                fs::copy(&backup, &target).map_err(|e| e.to_string())?;
            }
        }
        _ => fs::write(&target, "203.0.113.113/32\n").map_err(|e| e.to_string())?,
    }
    Ok(())
}

/// Все запущенные winws.exe: (PID, путь к файлу).
fn list_winws() -> Vec<(u32, String)> {
    list_procs("winws")
}

/// Запущенные процессы с этим именем (без .exe): (PID, путь к файлу).
pub(crate) fn list_procs(name: &str) -> Vec<(u32, String)> {
    #[cfg(windows)]
    {
        let script = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Process {name} -ErrorAction SilentlyContinue | ForEach-Object {{ \"$($_.Id)|$($_.Path)\" }}");
        if let Ok(o) = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script.as_str()])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            return String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| {
                    let (id, path) = l.trim().split_once('|')?;
                    Some((id.parse().ok()?, path.to_string()))
                })
                .collect();
        }
    }
    let _ = name;
    Vec::new()
}

fn norm(p: &str) -> String {
    p.replace('/', "\\").to_lowercase()
}

/// Запущен ли этот winws из папки modules Бунта.
pub(crate) fn is_ours(path: &str) -> bool {
    match crate::modules::modules_root() {
        Ok(root) => norm(path).starts_with(&norm(&root.display().to_string())),
        Err(_) => false,
    }
}

/// PID процессов winws.exe из нашей папки (чужие, например от службы Flowseal, не трогаем).
fn our_pids() -> Vec<u32> {
    list_winws().into_iter().filter(|(_, p)| is_ours(p)).map(|(id, _)| id).collect()
}

#[cfg(windows)]
fn sc(args: &[&str]) -> Option<String> {
    Command::new("sc")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}
#[cfg(not(windows))]
fn sc(_args: &[&str]) -> Option<String> {
    None
}

fn service_exists(name: &str) -> bool {
    sc(&["query", name]).is_some()
}

pub(crate) fn kill_pid(pid: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
    #[cfg(not(windows))]
    let _ = pid;
}

fn foreign_winws() -> Vec<String> {
    list_winws().into_iter().filter(|(_, p)| !is_ours(p)).map(|(_, p)| p).collect()
}

fn tail(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().rev().take(4).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

/// Названия стратегий установленной версии: все `general*.bat`.
#[tauri::command]
pub fn zapret_strategies() -> Result<Vec<String>, String> {
    let dir = crate::modules::active_dir("discord")?;
    let mut names: Vec<String> = fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("general") && n.to_lowercase().ends_with(".bat"))
        .map(|n| n[..n.len() - 4].to_string())
        .collect();
    names.sort();
    Ok(names)
}

/// Запускает winws со стратегией. `game`: disabled | all | tcp | udp. `ipset`: none | loaded | any.
#[tauri::command]
pub async fn zapret_start(
    state: tauri::State<'_, Zapret>,
    strategy: String,
    game: String,
    ipset: String,
) -> Result<(), String> {
    if strategy.contains(['/', '\\']) || strategy.contains("..") || !strategy.starts_with("general") {
        return Err("Неверное имя стратегии".into());
    }
    if !crate::settings::is_admin_sync() {
        return Err("Нужны права администратора. Нажмите «Дать права» в верхней части окна Бунта.".into());
    }
    state.stop();
    if !foreign_winws().is_empty() || service_exists("zapret") {
        return Err("Запрет уже запущен не из Бунта (служба zapret или другой winws.exe). Остановите его, и Бунт сможет запустить свой.".into());
    }

    let dir: PathBuf = crate::modules::active_dir("discord")?;
    let bat = fs::read_to_string(dir.join(format!("{strategy}.bat")))
        .map_err(|_| format!("Не найден файл стратегии {strategy}.bat"))?;
    prepare_lists(&dir, &ipset)?;

    let bin = format!("{}\\", dir.join("bin").display());
    let lists = format!("{}\\", dir.join("lists").display());
    let (tcp, udp) = match game.as_str() {
        "all" => ("1024-65535", "1024-65535"),
        "tcp" => ("1024-65535", "12"),
        "udp" => ("12", "1024-65535"),
        _ => ("12", "12"),
    };
    let args = parse_bat(&bat, &bin, &lists, tcp, udp)?;

    let log_path = dir.join("winws.log");
    let log = fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let log2 = log.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(dir.join("bin").join("winws.exe"));
    cmd.args(&args)
        .current_dir(dir.join("bin"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log2));
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let mut child = cmd.spawn().map_err(|e| format!("Не удалось запустить winws.exe: {e}"))?;

    // Если winws сразу завершился, это ошибка (нет прав, антивирус, неверные параметры).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    if let Ok(Some(status)) = child.try_wait() {
        let info = tail(&log_path);
        return Err(format!("winws.exe сразу завершился ({status}). {info}"));
    }
    *state.0.lock().unwrap() = Some(child);
    if let Ok(root) = crate::modules::modules_root() {
        let last = serde_json::json!({ "strategy": strategy, "game": game, "ipset": ipset, "enabled": true });
        let _ = fs::write(root.join("zapret.json"), last.to_string());
    }
    Ok(())
}

/// Запоминает, включил ли пользователь запрет: при следующем запуске Бунта он поднимется сам.
pub(crate) fn set_enabled(on: bool) {
    let Ok(root) = crate::modules::modules_root() else { return };
    let path = root.join("zapret.json");
    let mut v: serde_json::Value = fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    v["enabled"] = serde_json::Value::Bool(on);
    let _ = fs::write(path, v.to_string());
}

/// Останавливает запрет.
#[tauri::command]
pub async fn zapret_stop(state: tauri::State<'_, Zapret>) -> Result<(), String> {
    state.stop();
    set_enabled(false);
    Ok(())
}

#[derive(serde::Serialize)]
pub struct Status {
    running: bool,
    /// Пользователь оставил запрет включённым при последнем выходе
    enabled: bool,
    strategy: Option<String>,
    game: Option<String>,
    ipset: Option<String>,
}

/// Работает ли winws из папки Бунта и с какими настройками он был запущен.
/// Нужно при старте: после обновления Бунта запрет продолжает работать, и интерфейс должен это показать.
#[tauri::command]
pub async fn zapret_status(state: tauri::State<'_, Zapret>) -> Result<Status, String> {
    let own = {
        let mut guard = state.0.lock().unwrap();
        match guard.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    };
    let running = own || !our_pids().is_empty();
    let last: serde_json::Value = crate::modules::modules_root()
        .ok()
        .and_then(|r| fs::read_to_string(r.join("zapret.json")).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let get = |k: &str| last.get(k).and_then(|v| v.as_str()).map(String::from);
    Ok(Status { running, enabled: last.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false), strategy: get("strategy"), game: get("game"), ipset: get("ipset") })
}

#[derive(serde::Serialize)]
pub struct Foreign {
    /// Установлена служба zapret (Flowseal)
    service: bool,
    /// Пути к чужим winws.exe
    procs: Vec<String>,
}

/// Запущен ли запрет не из Бунта: служба zapret или winws.exe из другой папки.
#[tauri::command]
pub async fn zapret_foreign() -> Result<Foreign, String> {
    Ok(Foreign { service: service_exists("zapret"), procs: foreign_winws() })
}

/// Останавливает чужой запрет: службу zapret (с удалением, чтобы не вернулась после перезагрузки),
/// чужие winws.exe и остатки драйвера WinDivert. Файлы Flowseal на диске не трогает.
#[tauri::command]
pub async fn zapret_take_over(state: tauri::State<'_, Zapret>) -> Result<(), String> {
    state.stop();
    if service_exists("zapret") {
        let _ = sc(&["stop", "zapret"]);
        for _ in 0..10 {
            match sc(&["query", "zapret"]) {
                Some(s) if !s.contains("STOPPED") => std::thread::sleep(Duration::from_millis(500)),
                _ => break,
            }
        }
        let _ = sc(&["delete", "zapret"]);
    }
    for (pid, path) in list_winws() {
        if !is_ours(&path) {
            kill_pid(pid);
        }
    }
    std::thread::sleep(Duration::from_millis(600));
    if !foreign_winws().is_empty() {
        return Err("Не удалось остановить чужой winws.exe. Закройте его вручную.".into());
    }
    for name in ["WinDivert", "WinDivert14"] {
        if service_exists(name) {
            let _ = sc(&["stop", name]);
            let _ = sc(&["delete", name]);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flowseal_bat() {
        let Ok(text) = fs::read_to_string("/home/claude/flowseal/zdy/general (ALT2).bat") else { return };
        let args = parse_bat(&text, "C:\\P F\\bin\\", "C:\\P F\\lists\\", "12", "12").unwrap();
        assert!(args[0].starts_with("--wf-tcp=80,443"));
        assert!(args[0].ends_with(",12"));
        assert!(args.iter().any(|a| a == "--hostlist=C:\\P F\\lists\\list-general.txt"));
        assert!(args.iter().any(|a| a == "--new"));
        assert!(!args.iter().any(|a| a.contains('%') || a.contains('^') || a.contains('"')));
        println!("{} аргументов", args.len());
    }

    #[test]
    fn every_strategy_parses() {
        let Ok(rd) = fs::read_dir("/home/claude/flowseal/zdy") else { return };
        let mut n = 0;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("general") && name.ends_with(".bat") {
                let text = fs::read_to_string(e.path()).unwrap();
                parse_bat(&text, "B\\", "L\\", "12", "12").unwrap_or_else(|er| panic!("{name}: {er}"));
                n += 1;
            }
        }
        assert!(n >= 20, "найдено только {n}");
    }
}
