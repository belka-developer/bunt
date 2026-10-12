//! WireGuard и AmneziaWG: профили .conf и туннели через клиент AmneziaWG.
//!
//! Клиент AmneziaWG (amnezia-vpn/amneziawg-windows-client) понимает и обычные конфиги WireGuard, и конфиги с
//! обфускацией (Jc, S1, H1 и другие), поэтому Бунту нужен один движок. Бунт распаковывает его MSI в
//! `modules\wg\<версия>\` и запускает туннель как службу Windows: `amneziawg.exe /installtunnelservice <файл>`.
//! Остановка: `/uninstalltunnelservice <имя>`.
//!
//! Что делает Бунт сверх этого:
//! * запоминает шлюз и DNS физических адаптеров до подключения, после отключения убирает следы туннеля
//!   (маршруты, DNS), без «сброса сети» Windows;
//! * ставит службе запуск «вручную», иначе Windows подняла бы туннель при загрузке без Бунта;
//! * не даёт запускать профили со сценариями PostUp и PreDown, которые выполняются от имени системы;
//! * управляет виртуальным адаптером: включить, отключить, удалить;
//! * трогает только свои службы (путь к exe внутри `modules`), чужие туннели WireGuard остаются как были.
//!
//! Раскладка: `modules\wg\<версия>\` клиент, `modules\wg\data\profiles\<имя>.conf` профили,
//! `modules\wg\data\config.json` настройки, `session.json` состояние сессии, `wg.log` журнал Бунта.

use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::Command,
    time::Duration,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(crate) const EXE: &str = "amneziawg.exe";
pub(crate) const TOOL: &str = "awg.exe";

/// Ключи AmneziaWG в разделе [Interface]
const AWG_KEYS: &[&str] = &[
    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime",
];
/// Ключи, которые запускают программы от имени системы
const SCRIPT_KEYS: &[&str] = &["preup", "postup", "predown", "postdown"];

fn root() -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join("wg"))
}
pub(crate) fn data_dir() -> Result<PathBuf, String> {
    Ok(root()?.join("data"))
}
fn profiles_dir() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("profiles"))
}
fn config_file() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("config.json"))
}
fn session_file() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("session.json"))
}
fn log_file() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("wg.log"))
}
/// Имена в папке компонента, которые не являются версиями.
pub(crate) fn is_service_dir(name: &str) -> bool {
    name == "data"
}

fn wlog(msg: &str) {
    if let (Ok(d), Ok(f)) = (data_dir(), log_file()) {
        let _ = fs::create_dir_all(d);
        let old = fs::read_to_string(&f).unwrap_or_default();
        let lines: Vec<&str> = old.lines().collect();
        let keep = lines[lines.len().saturating_sub(300)..].join("\n");
        let _ = fs::write(&f, if keep.is_empty() { format!("{msg}\n") } else { format!("{keep}\n{msg}\n") });
    }
}

// ───────── настройки ─────────

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// Выбранный профиль
    pub active: String,
    /// Подключать выбранный профиль при запуске Бунта
    pub autoconnect: bool,
    /// Не отключать туннель при выходе из Бунта
    pub keep_on_exit: bool,
    /// Вместо 0.0.0.0/0 передавать клиенту две половины 0.0.0.0/1 и 128.0.0.0/1: трафик всё равно идёт через
    /// туннель, но клиент не включает «выключатель» (брандмауэр, который режет всё, кроме туннеля). Так не ломаются
    /// Radmin VPN, Hamachi и доступ к локальной сети.
    pub split_default: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { active: String::new(), autoconnect: false, keep_on_exit: false, split_default: true }
    }
}

pub(crate) fn load_config() -> Config {
    config_file().ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_config(c: &Config) -> Result<(), String> {
    fs::create_dir_all(data_dir()?).map_err(|e| e.to_string())?;
    fs::write(config_file()?, serde_json::to_string_pretty(c).map_err(|e| e.to_string())?).map_err(|e| format!("Не удалось сохранить настройки: {e}"))
}

// ───────── профили ─────────

/// Допустимое имя туннеля: оно же имя адаптера Windows (до 15 знаков).
pub(crate) fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 15 && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '=' | '+' | '.' | '-'))
}

pub(crate) fn sanitize_name(n: &str) -> String {
    let base = n.trim().trim_end_matches(".conf").trim_end_matches(".CONF");
    let s: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '=' | '+' | '.' | '-') { c } else { '-' })
        .collect();
    let s = s.trim_matches('-').to_string();
    let s: String = s.chars().take(15).collect();
    if s.is_empty() { "tunnel".to_string() } else { s }
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Profile {
    pub name: String,
    pub endpoint: String,
    pub address: String,
    pub dns: String,
    pub allowed: String,
    /// В конфиге есть параметры обфускации AmneziaWG
    pub awg: bool,
    /// Весь трафик идёт через туннель (0.0.0.0/0)
    pub full_tunnel: bool,
    pub peers: usize,
    #[serde(skip)]
    pub tun_ip: String,
}

fn is_key(v: &str) -> bool {
    v.len() == 44 && v.ends_with('=') && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
}

fn valid_cidr(s: &str) -> bool {
    let mut it = s.splitn(2, '/');
    let ip = it.next().unwrap_or("");
    let ok_ip = ip.parse::<IpAddr>();
    match (ok_ip, it.next()) {
        (Ok(a), Some(p)) => p.parse::<u8>().map(|n| n <= if a.is_ipv4() { 32 } else { 128 }).unwrap_or(false),
        (Ok(_), None) => true,
        _ => false,
    }
}

fn valid_endpoint(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && s.contains(':') && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

fn list(v: &str) -> Vec<String> {
    v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

/// Разбор и проверка конфига. Ключи наружу не отдаются.
pub(crate) fn parse_conf(name: &str, text: &str) -> Result<Profile, String> {
    let text = text.trim_start_matches('\u{feff}');
    if text.len() > 64 * 1024 {
        return Err("Файл слишком большой для конфига WireGuard.".into());
    }
    if text.contains('\0') {
        return Err("В файле есть недопустимые символы.".into());
    }
    #[derive(PartialEq, Clone, Copy)]
    enum Sec {
        None,
        Iface,
        Peer,
    }
    let mut sec = Sec::None;
    let mut p = Profile { name: name.to_string(), ..Profile::default() };
    let mut has_priv = false;
    let mut peer_key = false;
    let mut peer_open = false;
    let mut endpoints: Vec<String> = Vec::new();
    let mut allowed: Vec<String> = Vec::new();
    let finish_peer = |open: bool, key: bool| -> Result<(), String> {
        if open && !key {
            Err("В одном из разделов [Peer] нет PublicKey.".to_string())
        } else {
            Ok(())
        }
    };
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let l = line.to_lowercase();
            if l == "[interface]" {
                finish_peer(peer_open, peer_key)?;
                peer_open = false;
                sec = Sec::Iface;
            } else if l == "[peer]" {
                finish_peer(peer_open, peer_key)?;
                peer_open = true;
                peer_key = false;
                p.peers += 1;
                sec = Sec::Peer;
            } else {
                return Err(format!("Неизвестный раздел {line}."));
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("Не понял строку: {}", line.chars().take(40).collect::<String>()));
        };
        let k = k.trim().to_lowercase();
        let v = v.trim();
        if SCRIPT_KEYS.contains(&k.as_str()) {
            return Err("В профиле есть сценарии PreUp, PostUp, PreDown или PostDown. Бунт не запускает их: они выполняются от имени системы. Удалите эти строки.".into());
        }
        match sec {
            Sec::None => return Err("Строки вне разделов [Interface] и [Peer].".into()),
            Sec::Iface => match k.as_str() {
                "privatekey" => {
                    if !is_key(v) {
                        return Err("PrivateKey выглядит неверно (нужно 44 знака base64).".into());
                    }
                    has_priv = true;
                }
                "address" => {
                    let items = list(v);
                    if items.is_empty() || !items.iter().all(|a| valid_cidr(a)) {
                        return Err("Address указан неверно.".into());
                    }
                    p.address = items.join(", ");
                    p.tun_ip = items.iter().filter_map(|a| a.split('/').next().and_then(|i| i.parse::<Ipv4Addr>().ok())).map(|a| a.to_string()).next().unwrap_or_default();
                }
                "dns" => {
                    if !v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | ',' | ' ' | '-')) {
                        return Err("DNS указан неверно.".into());
                    }
                    p.dns = list(v).join(", ");
                }
                "mtu" => {
                    let n: u32 = v.parse().map_err(|_| "MTU должен быть числом.".to_string())?;
                    if !(576..=1500).contains(&n) {
                        return Err("MTU должен быть от 576 до 1500.".into());
                    }
                }
                "listenport" => {
                    v.parse::<u16>().map_err(|_| "ListenPort указан неверно.".to_string())?;
                }
                other => {
                    if AWG_KEYS.contains(&other) {
                        p.awg = true;
                    }
                    if v.chars().any(|c| c.is_control()) {
                        return Err(format!("Недопустимое значение у {k}."));
                    }
                }
            },
            Sec::Peer => match k.as_str() {
                "publickey" => {
                    if !is_key(v) {
                        return Err("PublicKey выглядит неверно (нужно 44 знака base64).".into());
                    }
                    peer_key = true;
                }
                "presharedkey" => {
                    if !is_key(v) {
                        return Err("PresharedKey выглядит неверно.".into());
                    }
                }
                "endpoint" => {
                    if !valid_endpoint(v) {
                        return Err("Endpoint указан неверно (нужен вид адрес:порт).".into());
                    }
                    endpoints.push(v.to_string());
                }
                "allowedips" => {
                    let items = list(v);
                    if items.is_empty() || !items.iter().all(|a| valid_cidr(a)) {
                        return Err("AllowedIPs указан неверно.".into());
                    }
                    allowed.extend(items);
                }
                "persistentkeepalive" => {
                    if v != "off" {
                        v.parse::<u16>().map_err(|_| "PersistentKeepalive указан неверно.".to_string())?;
                    }
                }
                _ => {
                    if v.chars().any(|c| c.is_control()) {
                        return Err(format!("Недопустимое значение у {k}."));
                    }
                }
            },
        }
    }
    finish_peer(peer_open, peer_key)?;
    if !has_priv {
        return Err("В [Interface] нет PrivateKey.".into());
    }
    if p.address.is_empty() {
        return Err("В [Interface] нет Address.".into());
    }
    if p.peers == 0 {
        return Err("В конфиге нет раздела [Peer].".into());
    }
    p.endpoint = endpoints.first().cloned().unwrap_or_default();
    p.full_tunnel = allowed.iter().any(|a| a == "0.0.0.0/0" || a == "::/0");
    p.allowed = allowed.join(", ");
    Ok(p)
}

/// Текст конфига с замазанными ключами: его можно показывать в интерфейсе.
pub(crate) fn mask_conf(text: &str) -> String {
    text.trim_start_matches('\u{feff}')
        .lines()
        .map(|l| {
            let key = l.split('=').next().unwrap_or("").trim().to_lowercase();
            if key == "privatekey" || key == "presharedkey" {
                format!("{} = ••••••••", l.split('=').next().unwrap_or("").trim())
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn run_dir() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("run"))
}

/// Заменяет в AllowedIPs «всё» на две половины адресного пространства. Остальные записи не трогает.
pub(crate) fn soften_allowed(text: &str) -> String {
    text.lines()
        .map(|l| {
            let Some((k, v)) = l.split_once('=') else { return l.to_string() };
            if !k.trim().eq_ignore_ascii_case("allowedips") {
                return l.to_string();
            }
            let mut out: Vec<String> = Vec::new();
            for item in v.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
                match item {
                    "0.0.0.0/0" => {
                        out.push("0.0.0.0/1".into());
                        out.push("128.0.0.0/1".into());
                    }
                    "::/0" => {
                        out.push("::/1".into());
                        out.push("8000::/1".into());
                    }
                    other => out.push(other.to_string()),
                }
            }
            format!("{} = {}", k.trim(), out.join(", "))
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Рабочая копия конфига без ключей-«выключателей». Живёт, пока включён туннель.
fn effective_conf(name: &str, text: &str, split: bool) -> Result<PathBuf, String> {
    let src = conf_path(name)?;
    if !split {
        return Ok(src);
    }
    let dir = run_dir()?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{name}.conf"));
    fs::write(&path, soften_allowed(text.trim_start_matches('\u{feff}'))).map_err(|e| format!("Не удалось подготовить конфиг: {e}"))?;
    lock_down(&path);
    Ok(path)
}

fn clean_run() {
    if let Ok(d) = run_dir() {
        let _ = fs::remove_dir_all(d);
    }
}

fn conf_path(name: &str) -> Result<PathBuf, String> {
    if !valid_name(name) {
        return Err("Неверное имя профиля.".into());
    }
    Ok(profiles_dir()?.join(format!("{name}.conf")))
}

fn read_profile(name: &str) -> Result<(Profile, String), String> {
    let text = fs::read_to_string(conf_path(name)?).map_err(|_| format!("Профиль {name} не найден."))?;
    Ok((parse_conf(name, &text)?, text))
}

/// Закрывает файл с ключами от обычных пользователей: читать могут только система и администраторы.
fn lock_down(path: &std::path::Path) {
    #[cfg(windows)]
    {
        let _ = Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
    #[cfg(not(windows))]
    let _ = path;
}

fn list_profiles() -> Vec<Profile> {
    let Ok(dir) = profiles_dir() else { return Vec::new() };
    let mut out: Vec<Profile> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    let name = n.strip_suffix(".conf")?.to_string();
                    if !valid_name(&name) {
                        return None;
                    }
                    let text = fs::read_to_string(e.path()).ok()?;
                    Some(parse_conf(&name, &text).unwrap_or(Profile { name, endpoint: "Профиль повреждён".into(), ..Profile::default() }))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

// ───────── PowerShell и процессы ─────────

fn ps(script: &str) -> Option<String> {
    crate::fptn::ps(script)
}

/// Запускает программу скрыто и возвращает код выхода и весь вывод.
fn run(program: &std::path::Path, args: &[&str]) -> Option<(i32, String)> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some((out.status.code().unwrap_or(-1), text.trim().to_string()))
}

fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// Службы туннелей, которые запущены именно нашим exe: (имя туннеля, имя службы, состояние).
fn ours_tunnels(exe: &std::path::Path) -> Vec<(String, String, String)> {
    let exe_l = ps_quote(&exe.to_string_lossy().to_lowercase());
    let script = format!(
        "Get-CimInstance Win32_Service | Where-Object {{ $_.Name -like '*Tunnel$*' -and $_.PathName -and $_.PathName.ToLower().Contains('{exe_l}') }} | ForEach-Object {{ $_.Name + '|' + $_.State }}"
    );
    parse_services(&ps(&script).unwrap_or_default())
}

pub(crate) fn parse_services(text: &str) -> Vec<(String, String, String)> {
    text.lines()
        .filter_map(|l| {
            let (svc, state) = l.trim().split_once('|')?;
            let (_, tun) = svc.split_once('$')?;
            if tun.is_empty() || !valid_name(tun) {
                return None;
            }
            Some((tun.to_string(), svc.to_string(), state.trim().to_string()))
        })
        .collect()
}

fn is_running_state(s: &str) -> bool {
    matches!(s, "Running" | "Start Pending" | "StartPending")
}

// ───────── сессия ─────────

#[derive(Serialize, Deserialize, Default, Clone)]
struct Session {
    active: bool,
    name: String,
    tun_ip: String,
    gateway: String,
    adapters: Vec<crate::fptn::AdapterDns>,
}

fn read_session() -> Session {
    session_file().ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn write_session(s: &Session) {
    if let (Ok(dir), Ok(f)) = (data_dir(), session_file()) {
        let _ = fs::create_dir_all(dir);
        let _ = fs::write(f, serde_json::to_string(s).unwrap_or_default());
    }
}

/// Убирает за туннелем маршруты и DNS и возвращает короткий отчёт.
fn repair(remove_adapter: bool) -> Result<String, String> {
    let sess = read_session();
    let name = if valid_name(&sess.name) { sess.name.clone() } else { load_config().active };
    if !valid_name(&name) {
        return Err("Не знаю, за каким туннелем убирать: профиль не выбран.".into());
    }
    // Если адрес туннеля неизвестен, подставляем безопасный: он не совпадёт ни с одним маршрутом
    let tun_ip = if sess.tun_ip.parse::<Ipv4Addr>().map(|a| !a.is_unspecified()).unwrap_or(false) {
        sess.tun_ip.clone()
    } else {
        read_profile(&name).map(|(p, _)| p.tun_ip).ok().filter(|i| i.parse::<Ipv4Addr>().map(|a| !a.is_unspecified()).unwrap_or(false)).unwrap_or_else(|| "255.255.255.255".to_string())
    };
    // Метрика-2 правило FPTN для WireGuard не нужно: службе не передаётся шлюз
    let script = crate::fptn::repair_script(&tun_ip, &name, "", &sess.adapters, remove_adapter);
    let out = ps(&script).ok_or("Не удалось выполнить очистку сети (PowerShell)")?;
    let mut s = sess;
    s.active = false;
    write_session(&s);
    let rep = out.find('{').and_then(|i| serde_json::from_str::<serde_json::Value>(out[i..].trim()).ok());
    Ok(match rep {
        Some(v) => {
            let gw = v.get("gateway").and_then(|x| x.as_str()).unwrap_or("");
            let al = v.get("alias").and_then(|x| x.as_str()).unwrap_or("");
            if gw.is_empty() {
                "Следы туннеля убраны, но основной шлюз не найден: проверьте кабель или Wi-Fi.".to_string()
            } else {
                format!("Сеть восстановлена: основной шлюз {gw} ({al}).")
            }
        }
        None => "Следы туннеля убраны.".to_string(),
    })
}

// ───────── подключение ─────────

fn exe_path() -> Result<PathBuf, String> {
    let exe = crate::modules::active_dir("wg")?.join(EXE);
    if !exe.is_file() {
        return Err("Не найден amneziawg.exe. Переустановите компонент.".into());
    }
    Ok(exe)
}

fn adapter_exists(name: &str) -> bool {
    let n = ps_quote(name);
    ps(&format!("if(Get-NetAdapter -Name '{n}' -ErrorAction SilentlyContinue){{ 'yes' }}")).map(|o| o.contains("yes")).unwrap_or(false)
}

/// Останавливает и удаляет службы туннелей Бунта. Без нашего exe ничего не трогает: чужие службы остаются.
fn stop_tunnels(exe: Option<&std::path::Path>) {
    let Some(exe) = exe else { return };
    stop_tunnels_inner(exe);
    clean_run();
}

fn stop_tunnels_inner(exe: &std::path::Path) {
    for (tun, svc, _) in ours_tunnels(exe) {
        let _ = run(exe, &["/uninstalltunnelservice", &tun]);
        let gone = || !ours_tunnels(exe).iter().any(|(_, s, _)| *s == svc);
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(500));
            if gone() {
                break;
            }
        }
        // Если штатное удаление не сработало, добиваем через sc
        if !gone() {
            let _ = run(std::path::Path::new("sc.exe"), &["stop", &svc]);
            std::thread::sleep(Duration::from_millis(1500));
            let _ = run(std::path::Path::new("sc.exe"), &["delete", &svc]);
        }
    }
}

fn connect_blocking(name: &str) -> Result<(), String> {
    crate::fptn::require_admin()?;
    if !valid_name(name) {
        return Err("Неверное имя профиля.".into());
    }
    let exe = exe_path()?;
    let (prof, text) = read_profile(name)?;
    let cur = ours_tunnels(&exe);
    if cur.iter().any(|(t, _, s)| t == name && is_running_state(s)) {
        return Ok(());
    }
    // Одновременно работает один туннель Бунта: два полных туннеля подрались бы за маршруты
    if cur.iter().any(|(_, _, s)| is_running_state(s)) {
        wlog("Другой туннель включён: отключаю его перед запуском нового.");
        disconnect_blocking()?;
    }
    if read_session().active {
        let _ = repair(true);
    }
    let pr = crate::fptn::probe().unwrap_or_default();
    let sess = Session {
        active: true,
        name: name.to_string(),
        tun_ip: prof.tun_ip.clone(),
        gateway: pr.gateway.clone(),
        adapters: pr.adapters.clone(),
    };
    write_session(&sess);
    wlog(&format!("Подключаю профиль {name} ({}).", if prof.awg { "AmneziaWG" } else { "WireGuard" }));
    let split = load_config().split_default && prof.full_tunnel;
    let conf = effective_conf(name, &text, split)?;
    if split {
        wlog("Весь трафик пойдёт через туннель двумя половинами (0.0.0.0/1 и 128.0.0.0/1): остальной трафик и Radmin VPN не блокируются.");
    }
    let conf_s = conf.to_string_lossy().to_string();
    let (code, out) = run(&exe, &["/installtunnelservice", &conf_s]).ok_or("Не удалось запустить amneziawg.exe.")?;
    if code != 0 {
        wlog(&format!("installtunnelservice: код {code}: {out}"));
        stop_tunnels(Some(&exe));
        let _ = repair(true);
        return Err(format!("Не удалось создать службу туннеля (код {code}). {}", if out.is_empty() { "Подробностей нет." } else { out.as_str() }));
    }
    // Служба по умолчанию запускается вместе с Windows: переводим на ручной запуск
    let mut up = false;
    for i in 0..60 {
        std::thread::sleep(Duration::from_millis(500));
        let now = ours_tunnels(&exe);
        if let Some((_, svc, state)) = now.iter().find(|(t, _, _)| t == name) {
            if i == 0 || i % 4 == 0 {
                let _ = run(std::path::Path::new("sc.exe"), &["config", svc, "start=", "demand"]);
            }
            if is_running_state(state) && state == "Running" && adapter_exists(name) {
                up = true;
                break;
            }
            if state == "Stopped" && i > 4 {
                break;
            }
        }
    }
    if !up {
        wlog("Туннель не поднялся.");
        stop_tunnels(Some(&exe));
        let _ = repair(true);
        return Err("Туннель не запустился. Проверьте ключи и адрес сервера в профиле; сеть возвращена в исходное состояние.".into());
    }
    wlog("Туннель поднят.");
    Ok(())
}

fn disconnect_blocking() -> Result<String, String> {
    let exe = exe_path().ok();
    stop_tunnels(exe.as_deref());
    std::thread::sleep(Duration::from_millis(700));
    wlog("Туннель остановлен.");
    repair(true).or_else(|e| if read_session().name.is_empty() && load_config().active.is_empty() { Ok("Туннель отключён.".to_string()) } else { Err(e) })
}

/// Полная остановка: при установке, обновлении и удалении компонента.
pub fn stop_all() {
    let active = exe_path().map(|e| ours_tunnels(&e).iter().any(|(_, _, s)| is_running_state(s))).unwrap_or(false);
    if active || read_session().active {
        let _ = disconnect_blocking();
    }
}

/// Вызывается при выходе из Бунта.
pub fn shutdown() {
    if load_config().keep_on_exit {
        return;
    }
    stop_all();
}

// ───────── адаптер и статистика ─────────

#[derive(Serialize, Default)]
pub struct Adapter {
    exists: bool,
    status: String,
    description: String,
}

fn adapter_now(name: &str) -> Adapter {
    if !valid_name(name) {
        return Adapter::default();
    }
    let n = ps_quote(name);
    let script = format!("$a=Get-NetAdapter -Name '{n}' -ErrorAction SilentlyContinue; if($a){{ [pscustomobject]@{{status=[string]$a.Status;description=[string]$a.InterfaceDescription}} | ConvertTo-Json -Compress }}");
    let Some(out) = ps(&script) else { return Adapter::default() };
    let Some(i) = out.find('{') else { return Adapter::default() };
    let v: serde_json::Value = serde_json::from_str(out[i..].trim()).unwrap_or_default();
    Adapter {
        exists: true,
        status: v.get("status").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        description: v.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    }
}

#[derive(Serialize, Default, Clone, Debug, PartialEq)]
pub struct Stats {
    /// Секунд с последнего рукопожатия, None: рукопожатия не было
    pub handshake_ago: Option<u64>,
    pub rx: u64,
    pub tx: u64,
}

/// Разбор `awg show <имя> dump`: первая строка про интерфейс, дальше по строке на пира.
pub(crate) fn parse_dump(text: &str, now_unix: u64) -> Stats {
    let mut st = Stats::default();
    for (i, l) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 7 {
            continue;
        }
        let hs: u64 = f[4].parse().unwrap_or(0);
        if hs > 0 {
            let ago = now_unix.saturating_sub(hs);
            st.handshake_ago = Some(st.handshake_ago.map(|x| x.min(ago)).unwrap_or(ago));
        }
        st.rx += f[5].parse::<u64>().unwrap_or(0);
        st.tx += f[6].parse::<u64>().unwrap_or(0);
    }
    st
}

fn stats_now(name: &str) -> Stats {
    let (Ok(dir), true) = (crate::modules::active_dir("wg"), valid_name(name)) else { return Stats::default() };
    let tool = dir.join(TOOL);
    if !tool.is_file() {
        return Stats::default();
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    run(&tool, &["show", name, "dump"]).filter(|(c, _)| *c == 0).map(|(_, t)| parse_dump(&t, now)).unwrap_or_default()
}

// ───────── команды ─────────

#[derive(Serialize)]
pub struct Info {
    running: bool,
    /// Имя включённого туннеля
    tunnel: String,
    /// Прошлая сессия не закрыта: сеть могла остаться изменённой
    dirty: bool,
    profiles: Vec<Profile>,
    config: Config,
    adapter: Adapter,
    stats: Stats,
}

fn info(with_adapter: bool) -> Info {
    let config = load_config();
    let tunnel = exe_path().ok().and_then(|e| ours_tunnels(&e).into_iter().find(|(_, _, s)| is_running_state(s)).map(|(t, _, _)| t)).unwrap_or_default();
    let running = !tunnel.is_empty();
    let watch = if running { tunnel.clone() } else { config.active.clone() };
    Info {
        running,
        dirty: !running && read_session().active,
        profiles: list_profiles(),
        adapter: if with_adapter && cfg!(windows) { adapter_now(&watch) } else { Adapter::default() },
        stats: if running && cfg!(windows) { stats_now(&tunnel) } else { Stats::default() },
        tunnel,
        config,
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn wg_status() -> Result<Info, String> {
    blocking(|| Ok(info(true))).await
}

#[tauri::command]
pub async fn wg_connect(name: String) -> Result<Info, String> {
    blocking(move || {
        connect_blocking(&name)?;
        let mut c = load_config();
        if c.active != name {
            c.active = name;
            let _ = save_config(&c);
        }
        Ok(info(true))
    })
    .await
}

#[derive(Serialize)]
pub struct Done {
    message: String,
    info: Info,
}

#[tauri::command]
pub async fn wg_disconnect() -> Result<Done, String> {
    blocking(|| {
        crate::fptn::require_admin()?;
        let message = disconnect_blocking()?;
        Ok(Done { message, info: info(true) })
    })
    .await
}

/// Ручной ремонт сети: следы туннеля убираются без сброса сети Windows.
#[tauri::command]
pub async fn wg_repair() -> Result<Done, String> {
    blocking(|| {
        crate::fptn::require_admin()?;
        if info(false).running {
            return Err("Туннель включён. Сначала отключите его.".into());
        }
        let message = repair(true)?;
        Ok(Done { message, info: info(true) })
    })
    .await
}

/// Добавляет профиль из текста .conf. Ключи остаются на диске и в интерфейс не возвращаются.
#[tauri::command]
pub async fn wg_import(name: String, text: String, replace: bool) -> Result<Info, String> {
    blocking(move || {
        let name = sanitize_name(&name);
        parse_conf(&name, &text)?;
        let path = conf_path(&name)?;
        if path.exists() {
            if !replace {
                return Err(format!("EXISTS: профиль «{name}» уже есть."));
            }
            if info(false).tunnel == name {
                return Err("Этот профиль сейчас включён. Сначала отключите его.".into());
            }
        }
        fs::create_dir_all(profiles_dir()?).map_err(|e| e.to_string())?;
        let body = text.trim_start_matches('\u{feff}').replace("\r\n", "\n").replace('\n', "\r\n");
        fs::write(&path, body).map_err(|e| format!("Не удалось сохранить профиль: {e}"))?;
        lock_down(&path);
        let mut c = load_config();
        if c.active.is_empty() || !conf_path(&c.active).map(|p| p.exists()).unwrap_or(false) {
            c.active = name.clone();
            save_config(&c)?;
        }
        wlog(&format!("Профиль {name} добавлен."));
        Ok(info(true))
    })
    .await
}

#[tauri::command]
pub async fn wg_delete(name: String) -> Result<Info, String> {
    blocking(move || {
        let path = conf_path(&name)?;
        if info(false).tunnel == name {
            return Err("Профиль включён. Сначала отключите его.".into());
        }
        fs::remove_file(&path).map_err(|e| format!("Не удалось удалить профиль: {e}"))?;
        let mut c = load_config();
        if c.active == name {
            c.active = list_profiles().first().map(|p| p.name.clone()).unwrap_or_default();
            save_config(&c)?;
        }
        wlog(&format!("Профиль {name} удалён."));
        Ok(info(true))
    })
    .await
}

/// Конфиг профиля с замазанными ключами.
#[tauri::command]
pub async fn wg_profile_view(name: String) -> Result<String, String> {
    blocking(move || {
        let (_, text) = read_profile(&name)?;
        Ok(mask_conf(&text))
    })
    .await
}

#[tauri::command]
pub async fn wg_select(name: String) -> Result<Info, String> {
    blocking(move || {
        conf_path(&name)?;
        let mut c = load_config();
        c.active = name;
        save_config(&c)?;
        Ok(info(true))
    })
    .await
}

#[tauri::command]
pub async fn wg_config_set(config: Config) -> Result<Info, String> {
    blocking(move || {
        let mut c = config;
        let old = load_config();
        if !c.active.is_empty() && !conf_path(&c.active).map(|p| p.exists()).unwrap_or(false) {
            c.active = old.active;
        }
        save_config(&c)?;
        Ok(info(true))
    })
    .await
}

/// Включить, отключить или удалить виртуальный адаптер туннеля (только его).
#[tauri::command]
pub async fn wg_adapter(action: String) -> Result<Info, String> {
    blocking(move || {
        crate::fptn::require_admin()?;
        let st = info(false);
        let name = if st.running { st.tunnel.clone() } else { st.config.active.clone() };
        if !valid_name(&name) {
            return Err("Профиль не выбран.".into());
        }
        let n = ps_quote(&name);
        let script = match action.as_str() {
            "enable" => format!("Enable-NetAdapter -Name '{n}' -Confirm:$false -ErrorAction Stop"),
            "disable" => format!("Disable-NetAdapter -Name '{n}' -Confirm:$false -ErrorAction Stop"),
            "remove" => {
                if st.running {
                    return Err("Туннель включён. Сначала отключите его.".into());
                }
                format!("$a=Get-NetAdapter -Name '{n}' -ErrorAction Stop; if($a.PnPDeviceID){{ pnputil /remove-device $a.PnPDeviceID }}")
            }
            _ => return Err("Неизвестное действие.".into()),
        };
        let wrapped = format!("try {{ {script} }} catch {{ 'ERR: ' + $_.Exception.Message }}");
        let out = ps(&wrapped).unwrap_or_default();
        if let Some(e) = out.lines().find(|l| l.starts_with("ERR: ")) {
            return Err(e.trim_start_matches("ERR: ").to_string());
        }
        std::thread::sleep(Duration::from_millis(600));
        Ok(info(true))
    })
    .await
}

#[tauri::command]
pub async fn wg_log() -> Result<String, String> {
    blocking(|| {
        let t = log_file().ok().and_then(|p| fs::read_to_string(p).ok()).unwrap_or_default();
        let lines: Vec<&str> = t.lines().filter(|l| !l.trim().is_empty()).collect();
        Ok(lines[lines.len().saturating_sub(60)..].join("\n"))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const P: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn conf(extra_iface: &str, extra_peer: &str) -> String {
        format!("[Interface]\nPrivateKey = {K}\nAddress = 10.8.0.2/32, fd00::2/128\nDNS = 1.1.1.1, 8.8.8.8\n{extra_iface}\n[Peer]\nPublicKey = {P}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n{extra_peer}\n")
    }

    #[test]
    fn parses_plain_wireguard() {
        let p = parse_conf("home", &conf("", "PersistentKeepalive = 25")).unwrap();
        assert_eq!(p.endpoint, "vpn.example.com:51820");
        assert_eq!(p.tun_ip, "10.8.0.2");
        assert_eq!(p.dns, "1.1.1.1, 8.8.8.8");
        assert!(p.full_tunnel && !p.awg);
        assert_eq!(p.peers, 1);
    }

    #[test]
    fn detects_amnezia_params() {
        let p = parse_conf("awg", &conf("Jc = 5\nJmin = 10\nJmax = 50\nS1 = 60\nS2 = 90\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4", "")).unwrap();
        assert!(p.awg);
        let p = parse_conf("awg2", &conf("I1 = <b 0xf6ab3267fa><c><t>", "")).unwrap();
        assert!(p.awg);
    }

    #[test]
    fn rejects_scripts_and_garbage() {
        assert!(parse_conf("x", &conf("PostUp = calc.exe", "")).unwrap_err().contains("PostUp"));
        assert!(parse_conf("x", &conf("preup=cmd", "")).is_err());
        assert!(parse_conf("x", "").is_err());
        assert!(parse_conf("x", "[Interface]\nPrivateKey = short\n").is_err());
        assert!(parse_conf("x", &conf("", "").replace("vpn.example.com:51820", "bad host;calc")).is_err());
        assert!(parse_conf("x", &conf("", "").replace("0.0.0.0/0", "10.0.0.0/99")).is_err());
        assert!(parse_conf("x", &conf("", "").replace("[Peer]", "[Pear]")).is_err());
        assert!(parse_conf("x", &conf("MTU = 50", "")).is_err());
        // без Address
        assert!(parse_conf("x", &conf("", "").replace("Address = 10.8.0.2/32, fd00::2/128\n", "")).is_err());
    }

    #[test]
    fn softens_default_route() {
        let t = "[Peer]\nPublicKey = x\nallowedips = 0.0.0.0/0, ::/0, 10.0.0.0/8\nEndpoint = a:1\n";
        let o = soften_allowed(t);
        assert!(o.contains("allowedips = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1, 10.0.0.0/8"));
        assert!(o.contains("PublicKey = x") && o.contains("Endpoint = a:1"));
        assert!(!o.contains("0.0.0.0/0") && !o.contains("::/0"));
        // уже разрезанные и частные записи остаются как есть
        assert_eq!(soften_allowed("AllowedIPs = 192.168.0.0/16"), "AllowedIPs = 192.168.0.0/16");
        assert!(Config::default().split_default);
    }

    #[test]
    fn split_tunnel_is_not_full() {
        let p = parse_conf("x", &conf("", "").replace("0.0.0.0/0, ::/0", "10.0.0.0/8")).unwrap();
        assert!(!p.full_tunnel);
    }

    #[test]
    fn names() {
        assert!(valid_name("wg-home") && valid_name("a.b_c=1+2"));
        assert!(!valid_name("") && !valid_name("a b") && !valid_name("a'b") && !valid_name("0123456789abcdef"));
        assert_eq!(sanitize_name("My VPN.conf"), "My-VPN");
        assert_eq!(sanitize_name("моя сеть"), "tunnel");
        assert_eq!(sanitize_name("averyveryverylongprofilename"), "averyveryverylo");
    }

    #[test]
    fn mask_hides_keys_only() {
        let m = mask_conf(&conf("", ""));
        assert!(!m.contains(K) && m.contains("PrivateKey = ••••••••") && m.contains(P) && m.contains("vpn.example.com"));
    }

    #[test]
    fn dump_parsing() {
        let d = format!("{K}\t{P}\t51820\toff\n{P}\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t1000\t500\t700\t25\n");
        let s = parse_dump(&d, 1030);
        assert_eq!(s, Stats { handshake_ago: Some(30), rx: 500, tx: 700 });
        assert_eq!(parse_dump("x\n", 5), Stats::default());
        let none = format!("{K}\t{P}\t51820\toff\n{P}\t(none)\t-\t0.0.0.0/0\t0\t0\t0\toff\n");
        assert_eq!(parse_dump(&none, 5).handshake_ago, None);
    }

    #[test]
    fn service_parsing() {
        let t = "AmneziaWGTunnel$wg-home|Running\r\nWireGuardTunnel$office|Stopped\r\nnonsense\r\nX$bad name|Running\r\n";
        let v = parse_services(t);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], ("wg-home".to_string(), "AmneziaWGTunnel$wg-home".to_string(), "Running".to_string()));
        assert_eq!(v[1].2, "Stopped");
    }
}
