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

fn winws_running() -> bool {
    #[cfg(windows)]
    {
        let out = Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq winws.exe", "/NH"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if let Ok(o) = out {
            return String::from_utf8_lossy(&o.stdout).to_lowercase().contains("winws.exe");
        }
    }
    false
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
    state.stop();
    if winws_running() {
        return Err("winws.exe уже запущен (возможно, служба Flowseal или другой запуск). Остановите его и повторите.".into());
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
    Ok(())
}

/// Останавливает запрет.
#[tauri::command]
pub fn zapret_stop(state: tauri::State<'_, Zapret>) {
    state.stop();
}

/// Работает ли запущенный Бунтом winws.
#[tauri::command]
pub fn zapret_running(state: tauri::State<'_, Zapret>) -> bool {
    let mut guard = state.0.lock().unwrap();
    match guard.as_mut() {
        Some(c) => matches!(c.try_wait(), Ok(None)),
        None => false,
    }
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
