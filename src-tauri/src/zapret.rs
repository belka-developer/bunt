//! Запуск запрета для Discord и YouTube.
//!
//! Каждая стратегия Flowseal это bat-файл с одной командой запуска `winws.exe`.
//! Бунт читает этот файл из установленной версии, подставляет пути и запускает
//! `winws.exe` сам, без cmd и без окна. Поэтому работают все стратегии, в том числе
//! новые, а отдельной конвертации в другой формат не нужно.

use tauri::Emitter;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{atomic::{AtomicBool, Ordering}, Mutex},
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

    /// Полностью выключает запрет из папки Бунта перед удалением или заменой файлов: процесс winws, служба zapret
    /// (если её поставили из этой папки через service.bat) и драйвер WinDivert, который держит файлы открытыми.
    /// Чужие службы и драйверы, указывающие в другие папки, не трогает.
    pub fn remove_ours(&self) {
        self.stop();
        if service_exists("zapret") && service_binary("zapret").map(|p| is_ours(&p)).unwrap_or(false) {
            stop_service("zapret");
            let _ = sc(&["delete", "zapret"]);
        }
        for _ in 0..10 {
            let pids = our_pids();
            if pids.is_empty() {
                break;
            }
            for pid in pids {
                kill_pid(pid);
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        for name in ["WinDivert", "WinDivert14"] {
            if service_exists(name) && service_binary(name).map(|p| is_ours(&p)).unwrap_or(false) {
                stop_service(name);
                let _ = sc(&["delete", name]);
            }
        }
    }
}

/// Путь к файлу службы из `sc qc`: без кавычек и префикса `\??\`, который есть у драйверов.
pub(crate) fn service_binary(name: &str) -> Option<String> {
    let text = sc(&["qc", name])?;
    parse_binary_path(&text)
}

pub(crate) fn parse_binary_path(text: &str) -> Option<String> {
    let line = text.lines().find(|l| l.contains("BINARY_PATH_NAME"))?;
    let v = line.split_once(':')?.1.trim();
    let v = v.trim_start_matches('"');
    let v = v.trim_start_matches("\\??\\");
    // у служб после пути идут аргументы: берём путь до .exe или .sys
    let low = v.to_lowercase();
    let end = [".exe", ".sys"].iter().filter_map(|e| low.find(e).map(|i| i + e.len())).min().unwrap_or(v.len());
    Some(v[..end].to_string())
}

/// Останавливает службу и ждёт, пока она остановится (до пяти секунд).
fn stop_service(name: &str) {
    let _ = sc(&["stop", name]);
    for _ in 0..10 {
        match sc(&["query", name]) {
            Some(s) if !s.contains("STOPPED") => std::thread::sleep(Duration::from_millis(500)),
            _ => break,
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

pub(crate) fn write_if_missing(path: &Path, text: &str) {
    if !path.exists() {
        let _ = fs::write(path, text);
    }
}

pub(crate) fn prepare_lists(dir: &Path, ipset: &str) -> Result<(), String> {
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
pub(crate) fn our_pids() -> Vec<u32> {
    list_winws().into_iter().filter(|(_, p)| is_ours(p)).map(|(id, _)| id).collect()
}

#[cfg(windows)]
pub(crate) fn sc(args: &[&str]) -> Option<String> {
    Command::new("sc")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}
#[cfg(not(windows))]
pub(crate) fn sc(_args: &[&str]) -> Option<String> {
    None
}

pub(crate) fn service_exists(name: &str) -> bool {
    sc(&["query", name]).is_some()
}

/// Служба zapret, поставленная Бунтом из своей папки.
pub(crate) fn our_service() -> bool {
    service_exists("zapret") && service_binary("zapret").map(|p| is_ours(&p)).unwrap_or(false)
}

/// Служба zapret, которую поставили не из Бунта (например, service.bat из Flowseal).
pub(crate) fn foreign_service() -> bool {
    service_exists("zapret") && !our_service()
}

/// Что подставить в `%GameFilterTCP%` и `%GameFilterUDP%`: порт 12 означает «не трогать».
pub(crate) fn game_ports(game: &str, p: &Ports) -> (String, String) {
    match game {
        "all" => (p.tcp.clone(), p.udp.clone()),
        "tcp" => (p.tcp.clone(), "12".into()),
        "udp" => ("12".into(), p.udp.clone()),
        _ => ("12".into(), "12".into()),
    }
}

/// Порты для Game Filter: числа и диапазоны через запятую, например `1024-65535` или `3478,50000-50100`.
pub fn valid_ports(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 120 {
        return false;
    }
    s.split(',').all(|part| {
        let port = |x: &str| x.parse::<u32>().map(|n| (1..=65535).contains(&n)).unwrap_or(false);
        match part.split_once('-') {
            Some((a, b)) => port(a) && port(b) && a.parse::<u32>().unwrap() <= b.parse::<u32>().unwrap(),
            None => port(part),
        }
    })
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

pub(crate) fn foreign_winws() -> Vec<String> {
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
    game_tcp: Option<String>,
    game_udp: Option<String>,
) -> Result<(), String> {
    let ports = Ports::new(game_tcp, game_udp);
    start_inner(&state, &strategy, &game, &ipset, &ports).await
}

/// Порты Game Filter: отдельно TCP и UDP.
#[derive(Clone)]
pub struct Ports {
    tcp: String,
    udp: String,
}

impl Ports {
    pub fn new(tcp: Option<String>, udp: Option<String>) -> Self {
        let ok = |v: Option<String>| v.map(|x| x.trim().to_string()).filter(|x| valid_ports(x)).unwrap_or_else(|| "1024-65535".into());
        Ports { tcp: ok(tcp), udp: ok(udp) }
    }
}

async fn start_inner(state: &Zapret, strategy: &str, game: &str, ipset: &str, ports: &Ports) -> Result<(), String> {
    if strategy.contains(['/', '\\']) || strategy.contains("..") || !strategy.starts_with("general") {
        return Err("Неверное имя стратегии".into());
    }
    if !crate::settings::is_admin_sync() {
        return Err("Нужны права администратора. Нажмите «Дать права» в верхней части окна Бунта.".into());
    }
    if our_service() {
        // Служба сама держит winws. Выключенную можно запустить, а стратегию службы меняют переустановкой.
        if !our_pids().is_empty() {
            return Err("Запрет работает как служба Windows. Чтобы сменить стратегию или настройки, нажмите «Переустановить» в блоке «Служба Windows».".into());
        }
        let _ = sc(&["start", "zapret"]);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        return if our_pids().is_empty() { Err("Служба zapret не запустилась".into()) } else { Ok(()) };
    }
    state.stop();
    if !foreign_winws().is_empty() || foreign_service() {
        return Err("Запрет уже запущен не из Бунта (служба zapret или другой winws.exe). Остановите его, и Бунт сможет запустить свой.".into());
    }

    let dir: PathBuf = crate::modules::active_dir("discord")?;
    let bat = fs::read_to_string(dir.join(format!("{strategy}.bat")))
        .map_err(|_| format!("Не найден файл стратегии {strategy}.bat"))?;
    prepare_lists(&dir, ipset)?;
    crate::zapret_tools::apply_saved_fakes(&dir);

    let bin = format!("{}\\", dir.join("bin").display());
    let lists = format!("{}\\", dir.join("lists").display());
    let (tcp, udp) = game_ports(game, ports);
    let args = parse_bat(&bat, &bin, &lists, &tcp, &udp)?;

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
        let mut last: serde_json::Value = fs::read_to_string(root.join("zapret.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| serde_json::json!({}));
        last["strategy"] = strategy.into();
        last["game"] = game.into();
        last["ipset"] = ipset.into();
        last["game_tcp"] = ports.tcp.clone().into();
        last["game_udp"] = ports.udp.clone().into();
        last["enabled"] = true.into();
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
    if our_service() {
        // Службу не удаляем: она снова запустится вместе с Windows
        let _ = sc(&["stop", "zapret"]);
        for _ in 0..10 {
            if our_pids().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
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
    game_tcp: Option<String>,
    game_udp: Option<String>,
    /// Запрет установлен службой Windows из папки Бунта
    service: bool,
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
    Ok(Status { running, enabled: last.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false), strategy: get("strategy"), game: get("game"), ipset: get("ipset"), game_tcp: get("game_tcp"), game_udp: get("game_udp"), service: our_service() })
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
    Ok(Foreign { service: foreign_service(), procs: foreign_winws() })
}

/// Останавливает чужой запрет: службу zapret (с удалением, чтобы не вернулась после перезагрузки),
/// чужие winws.exe и остатки драйвера WinDivert. Файлы Flowseal на диске не трогает.
#[tauri::command]
pub async fn zapret_take_over(state: tauri::State<'_, Zapret>) -> Result<(), String> {
    state.stop();
    if foreign_service() {
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

// ───────────────────────── Проверка стратегий и сервисов ─────────────────────────

/// Что проверяем: (id, название, хост). Достаточно получить любой HTTPS-ответ: если DPI режет соединение,
/// рукопожатие TLS не завершится и запрос упадёт по таймауту или сбросу.
const TARGETS: [(&str, &str, &str); 6] = [
    ("discord", "Discord", "discord.com"),
    ("gateway", "Discord: чат и голос", "gateway.discord.gg"),
    ("cdn", "Discord: картинки", "cdn.discordapp.com"),
    ("youtube", "YouTube", "www.youtube.com"),
    ("ytimg", "YouTube: превью", "i.ytimg.com"),
    ("video", "YouTube: видео", "redirector.googlevideo.com"),
];

static BUSY: AtomicBool = AtomicBool::new(false);
static CANCEL: AtomicBool = AtomicBool::new(false);

#[derive(serde::Serialize, Clone, Debug, PartialEq)]
pub struct Check {
    id: String,
    label: String,
    host: String,
    ok: bool,
    ms: Option<u64>,
}

async fn probe_one(client: &reqwest::Client, id: String, label: String, host: String) -> Check {
    let t = std::time::Instant::now();
    let ok = client.get(format!("https://{host}/")).send().await.is_ok();
    let ms = t.elapsed().as_millis() as u64;
    Check { id, label, host, ok, ms: if ok { Some(ms) } else { None } }
}

/// Все адреса для проверки: встроенные и добавленные пользователем.
fn all_targets() -> Vec<(String, String, String)> {
    let mut v: Vec<(String, String, String)> = TARGETS.iter().map(|&(a, b, c)| (a.to_string(), b.to_string(), c.to_string())).collect();
    for h in crate::zapret_tools::custom_targets() {
        v.push((format!("custom:{h}"), h.clone(), h));
    }
    v
}

/// Проверяет все сервисы одновременно. Системный прокси не используем: проверяем сам канал.
async fn probe_all() -> Result<Vec<Check>, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(6))
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(futures_util::future::join_all(all_targets().into_iter().map(|(id, label, host)| probe_one(&client, id, label, host))).await)
}

fn failed_checks() -> Vec<Check> {
    all_targets().into_iter().map(|(id, label, host)| Check { id, label, host, ok: false, ms: None }).collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn results_path() -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join("zapret-test.json"))
}

fn component_version() -> String {
    crate::modules::active_dir("discord")
        .ok()
        .and_then(|d| d.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_default()
}

/// Добавляет результат стратегии в сохранённые. Если версия компонента сменилась, старые результаты неактуальны.
fn merge_store(old: serde_json::Value, version: &str, at: u64, name: &str, checks: &[Check], error: Option<&str>) -> serde_json::Value {
    let mut results = if old.get("version").and_then(|v| v.as_str()) == Some(version) {
        old.get("results").cloned().unwrap_or_else(|| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    results[name] = serde_json::json!({ "at": at, "checks": checks, "error": error });
    serde_json::json!({ "version": version, "results": results })
}

fn save_result(name: &str, checks: &[Check], error: Option<&str>) {
    let Ok(path) = results_path() else { return };
    let old = fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let v = merge_store(old, &component_version(), now_secs(), name, checks, error);
    let _ = fs::write(path, v.to_string());
}

/// Сохранённые результаты проверки для установленной версии (пусто, если версия другая).
#[tauri::command]
pub fn zapret_results() -> serde_json::Value {
    let v: serde_json::Value = results_path()
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if v.get("version").and_then(|x| x.as_str()) == Some(component_version().as_str()) {
        v
    } else {
        serde_json::json!({ "version": component_version(), "results": {} })
    }
}

#[derive(serde::Serialize)]
pub struct Probe {
    /// Какая стратегия сейчас работает; пусто, если запрет выключен
    strategy: Option<String>,
    checks: Vec<Check>,
    at: u64,
}

/// Быстрая проверка доступности сервисов через текущий канал. Если запрет работает, результат
/// запоминается за его стратегией.
#[tauri::command]
pub async fn zapret_probe(state: tauri::State<'_, Zapret>) -> Result<Probe, String> {
    if BUSY.load(Ordering::SeqCst) {
        return Err("Сейчас идёт проверка стратегий".into());
    }
    let own = {
        let mut g = state.0.lock().unwrap();
        g.as_mut().map(|c| matches!(c.try_wait(), Ok(None))).unwrap_or(false)
    };
    let running = own || !our_pids().is_empty();
    let strategy = if running {
        results_last().and_then(|l| l.get("strategy").and_then(|v| v.as_str()).map(String::from))
    } else {
        None
    };
    let checks = probe_all().await?;
    if let Some(name) = &strategy {
        save_result(name, &checks, None);
    }
    Ok(Probe { strategy, checks, at: now_secs() })
}

fn results_last() -> Option<serde_json::Value> {
    let root = crate::modules::modules_root().ok()?;
    serde_json::from_str(&fs::read_to_string(root.join("zapret.json")).ok()?).ok()
}

#[derive(serde::Serialize, Clone)]
struct TestProgress {
    index: usize,
    total: usize,
    name: String,
    /// start: запускаем стратегию, done: получен результат
    phase: &'static str,
    ok_count: Option<usize>,
}

/// Проверяет стратегии по очереди: запускает, ждёт, опрашивает сервисы. Если `stop_on_full`, останавливается на
/// первой, где доступно всё. После проверки возвращает запрет в прежнее состояние (был включён, работает дальше
/// с прежней стратегией; был выключен, остаётся выключенным).
#[tauri::command]
pub async fn zapret_test(
    app: tauri::AppHandle,
    state: tauri::State<'_, Zapret>,
    strategies: Vec<String>,
    game: String,
    ipset: String,
    stop_on_full: bool,
    game_tcp: Option<String>,
    game_udp: Option<String>,
) -> Result<serde_json::Value, String> {
    if !crate::settings::is_admin_sync() {
        return Err("Нужны права администратора. Нажмите «Дать права» в верхней части окна Бунта.".into());
    }
    if BUSY.swap(true, Ordering::SeqCst) {
        return Err("Проверка уже идёт".into());
    }
    CANCEL.store(false, Ordering::SeqCst);
    let ports = Ports::new(game_tcp, game_udp);
    let result = run_test(&app, &state, &strategies, &game, &ipset, &ports, stop_on_full).await;
    BUSY.store(false, Ordering::SeqCst);
    result?;
    Ok(zapret_results())
}

async fn run_test(
    app: &tauri::AppHandle,
    state: &Zapret,
    strategies: &[String],
    game: &str,
    ipset: &str,
    ports: &Ports,
    stop_on_full: bool,
) -> Result<(), String> {
    if our_service() {
        return Err("Запрет установлен как служба Windows. Удалите службу в блоке «Служба Windows», чтобы проверять стратегии.".into());
    }
    if !foreign_winws().is_empty() || foreign_service() {
        return Err("Запрет уже запущен не из Бунта (служба zapret или другой winws.exe). Остановите его, и Бунт сможет проверить стратегии.".into());
    }
    let prev_raw = crate::modules::modules_root().ok().and_then(|r| fs::read_to_string(r.join("zapret.json")).ok());
    let prev: serde_json::Value = prev_raw.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default();
    let was_running = {
        let own = state.0.lock().unwrap().as_mut().map(|c| matches!(c.try_wait(), Ok(None))).unwrap_or(false);
        own || !our_pids().is_empty()
    };

    let total = strategies.len();
    for (i, name) in strategies.iter().enumerate() {
        if CANCEL.load(Ordering::SeqCst) {
            break;
        }
        let _ = app.emit("zapret-test", TestProgress { index: i, total, name: name.clone(), phase: "start", ok_count: None });
        let (checks, error) = match start_inner(state, name, game, ipset, ports).await {
            Ok(()) => {
                tokio::time::sleep(Duration::from_millis(800)).await;
                match probe_all().await {
                    Ok(c) => (c, None),
                    Err(e) => (failed_checks(), Some(e)),
                }
            }
            Err(e) => (failed_checks(), Some(e)),
        };
        state.stop();
        let ok_count = checks.iter().filter(|c| c.ok).count();
        save_result(name, &checks, error.as_deref());
        let _ = app.emit("zapret-test", TestProgress { index: i, total, name: name.clone(), phase: "done", ok_count: Some(ok_count) });
        if stop_on_full && ok_count == checks.len() {
            break;
        }
    }

    // Возвращаем как было.
    state.stop();
    if let Ok(root) = crate::modules::modules_root() {
        let path = root.join("zapret.json");
        match &prev_raw {
            Some(raw) => {
                let _ = fs::write(&path, raw);
            }
            None => {
                let _ = fs::remove_file(&path);
            }
        }
    }
    if was_running {
        let s = |k: &str, d: &str| prev.get(k).and_then(|v| v.as_str()).unwrap_or(d).to_string();
        let strategy = s("strategy", "");
        if !strategy.is_empty() {
            let _ = start_inner(state, &strategy, &s("game", "disabled"), &s("ipset", "none"), &Ports::new(Some(s("game_tcp", "")), Some(s("game_udp", "")))).await;
        }
    }
    Ok(())
}

/// Прерывает проверку стратегий после текущей.
#[tauri::command]
pub fn zapret_test_cancel() {
    CANCEL.store(true, Ordering::SeqCst);
}

// ───────────────────────── Автопроверка по расписанию ─────────────────────────

/// Настройка автопроверки: через сколько часов проверять (0 выключено) и когда проверяли в последний раз.
#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Debug, PartialEq)]
pub struct ScanCfg {
    #[serde(default)]
    hours: u64,
    #[serde(default)]
    last: u64,
}

fn scan_path() -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join("zapret-scan.json"))
}

#[tauri::command]
pub fn zapret_scan_get() -> ScanCfg {
    scan_path().ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Сохраняет то, что передано: интервал в часах (не больше 30 суток) и/или время последней проверки.
#[tauri::command]
pub fn zapret_scan_set(hours: Option<u64>, last: Option<u64>) -> Result<ScanCfg, String> {
    let mut cfg = zapret_scan_get();
    if let Some(h) = hours {
        cfg.hours = h.min(720);
    }
    if let Some(l) = last {
        cfg.last = l;
    }
    fs::write(scan_path()?, serde_json::to_string(&cfg).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_paths() {
        let svc = "SERVICE_NAME: zapret\r\n        BINARY_PATH_NAME   : \"C:\\Program Files\\Bunt\\modules\\discord\\1.2\\bin\\winws.exe\" --wf-tcp=80\r\n";
        assert_eq!(parse_binary_path(svc).unwrap(), "C:\\Program Files\\Bunt\\modules\\discord\\1.2\\bin\\winws.exe");
        let drv = "        BINARY_PATH_NAME   : \\??\\C:\\x\\bin\\WinDivert64.sys\r\n";
        assert_eq!(parse_binary_path(drv).unwrap(), "C:\\x\\bin\\WinDivert64.sys");
        assert!(parse_binary_path("nothing").is_none());
    }

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

    #[test]
    fn merge_keeps_same_version_only() {
        let c = vec![Check { id: "discord".into(), label: "Discord".into(), host: "discord.com".into(), ok: true, ms: Some(80) }];
        let a = merge_store(serde_json::Value::Null, "1.0", 10, "general", &c, None);
        let b = merge_store(a.clone(), "1.0", 20, "general (ALT)", &c, None);
        assert_eq!(b["results"].as_object().unwrap().len(), 2);
        assert_eq!(b["results"]["general"]["at"], 10);
        let n = merge_store(b, "2.0", 30, "general", &c, Some("ошибка"));
        assert_eq!(n["results"].as_object().unwrap().len(), 1);
        assert_eq!(n["results"]["general"]["error"], "ошибка");
        assert_eq!(n["version"], "2.0");
    }

    #[test]
    fn targets_are_unique() {
        let mut ids: Vec<_> = TARGETS.iter().map(|t| t.0).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), TARGETS.len());
        assert_eq!(failed_checks().len(), 6);
    }

    #[test]
    fn scan_cfg_defaults_and_partial_json() {
        assert_eq!(ScanCfg::default(), ScanCfg { hours: 0, last: 0 });
        let c: ScanCfg = serde_json::from_str("{\"hours\":6}").unwrap();
        assert_eq!(c, ScanCfg { hours: 6, last: 0 });
    }
}
