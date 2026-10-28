//! Остальные возможности Flowseal, которые есть в его service.bat: свои и базовые списки, обновление ipset,
//! замена фейков, записи hosts, диагностика, свои сайты для проверки и служба Windows.

use crate::zapret::{self, Zapret};
use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(windows)]
use std::{os::windows::process::CommandExt, process::Command};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const NEED_ADMIN: &str = "Нужны права администратора. Нажмите «Дать права» в верхней части окна Бунта.";

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn root_file(name: &str) -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join(name))
}

fn read_json(path: &Path) -> serde_json::Value {
    fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| serde_json::json!({}))
}

/// Мелкие настройки раздела: когда обновляли ipset, какие фейки выбраны, какой стратегией установлена служба.
fn meta() -> serde_json::Value {
    root_file("zapret-lists.json").map(|p| read_json(&p)).unwrap_or_else(|_| serde_json::json!({}))
}

fn set_meta(key: &str, value: serde_json::Value) {
    let Ok(path) = root_file("zapret-lists.json") else { return };
    let mut m = read_json(&path);
    m[key] = value;
    let _ = fs::write(path, m.to_string());
}

/// Скачивает текст: сначала из основного адреса, потом из запасного (GitHub raw в России часто недоступен).
async fn download(urls: &[&str]) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .user_agent("Bunt")
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let mut last = String::from("нет адресов");
    for url in urls {
        match client.get(*url).send().await.and_then(|r| r.error_for_status()) {
            Ok(r) => match r.text().await {
                Ok(t) if t.len() <= 5_000_000 => return Ok(t),
                Ok(_) => last = "файл слишком большой".into(),
                Err(e) => last = e.to_string(),
            },
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("Не удалось скачать файл ({last}). Если GitHub не открывается, включите запрет и повторите."))
}

// ───────────────────────── Списки ─────────────────────────

/// key, файл, название, подсказка, можно ли править
const LISTS: [(&str, &str, &str, &str, bool); 8] = [
    ("general", "list-general-user.txt", "Свои домены", "Домены для обхода, по одному на строку. Поддомены учитываются автоматически.", true),
    ("exclude", "list-exclude-user.txt", "Исключения доменов", "Домены, которые не нужно обрабатывать, даже если они попадают под другие списки.", true),
    ("ipset", "ipset-all.txt.backup", "IP и подсети для режима loaded", "Адреса и подсети, которые обрабатывает режим IPSet loaded. Обновить список из репозитория можно кнопкой «Обновить».", true),
    ("ipsetEx", "ipset-exclude-user.txt", "Исключения IP", "Адреса и подсети, которые не нужно обрабатывать.", true),
    ("base_general", "list-general.txt", "Домены из репозитория", "Базовый список Flowseal. Его заменяет обновление компонента, поэтому свои домены добавляйте в «Свои домены».", false),
    ("base_google", "list-google.txt", "Домены Google из репозитория", "Базовый список Flowseal для YouTube и сервисов Google. Только просмотр.", false),
    ("base_exclude", "list-exclude.txt", "Исключения из репозитория", "Домены, которые Flowseal исключает из обработки. Только просмотр.", false),
    ("base_ipsetEx", "ipset-exclude.txt", "Исключения IP из репозитория", "Сети, которые Flowseal исключает из обработки. Только просмотр.", false),
];

const PLACEHOLDER_DOMAIN: &str = "domain.example.abc";
const PLACEHOLDER_IP: &str = "203.0.113.113/32";

fn active_dir() -> Result<PathBuf, String> {
    crate::modules::active_dir("discord")
}

/// Строки списка без пустых и комментариев.
fn entries(text: &str) -> Vec<&str> {
    text.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
}

fn valid_ip_line(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, prefix)) => match (ip.parse::<IpAddr>(), prefix.parse::<u8>()) {
            (Ok(IpAddr::V4(_)), Ok(p)) => p <= 32,
            (Ok(IpAddr::V6(_)), Ok(p)) => p <= 128,
            _ => false,
        },
        None => s.parse::<IpAddr>().is_ok(),
    }
}

fn valid_domain_line(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && !s.contains(char::is_whitespace) && !s.contains(['/', '\\', '"', '%', '^', '&'])
}

/// Приводит текст списка к виду, который понимает winws, и проверяет строки.
fn normalize_list(key: &str, text: &str) -> Result<String, String> {
    let text = text.trim_start_matches('\u{feff}');
    let is_ip = key == "ipset" || key == "ipsetEx";
    let mut out: Vec<String> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            out.push(line.to_string());
            continue;
        }
        let ok = if is_ip { valid_ip_line(line) } else { valid_domain_line(line) };
        if !ok {
            return Err(format!("Строка {}: «{}» не подходит для этого списка.", n + 1, line.chars().take(60).collect::<String>()));
        }
        out.push(line.to_string());
    }
    // winws не любит пустые списки: Flowseal кладёт в них заглушку.
    if entries(&out.join("\n")).is_empty() && key != "ipset" {
        out.push(if is_ip { PLACEHOLDER_IP } else { PLACEHOLDER_DOMAIN }.to_string());
    }
    while out.last().map(|l| l.is_empty()).unwrap_or(false) {
        out.pop();
    }
    Ok(out.join("\n") + "\n")
}

/// Список «loaded» хранится в `ipset-all.txt.backup`. Если его нет, а в ipset-all.txt лежит настоящий список, берём его.
fn ensure_backup(dir: &Path) {
    let lists = dir.join("lists");
    let (target, backup) = (lists.join("ipset-all.txt"), lists.join("ipset-all.txt.backup"));
    if backup.exists() {
        return;
    }
    if let Ok(t) = fs::read_to_string(&target) {
        let e = entries(&t);
        if !e.is_empty() && !e.contains(&PLACEHOLDER_IP) {
            let _ = fs::write(&backup, t);
        }
    }
}

#[derive(serde::Serialize)]
pub struct ListInfo {
    key: &'static str,
    file: &'static str,
    title: &'static str,
    hint: &'static str,
    editable: bool,
    text: String,
    count: usize,
}

#[derive(serde::Serialize)]
pub struct ListsReply {
    lists: Vec<ListInfo>,
    ipset_updated: Option<u64>,
}

#[tauri::command]
pub async fn zapret_lists() -> Result<ListsReply, String> {
    let dir = active_dir()?;
    let lists = dir.join("lists");
    let _ = zapret::prepare_lists(&dir, "none");
    ensure_backup(&dir);
    let infos = LISTS
        .iter()
        .map(|&(key, file, title, hint, editable)| {
            let text = fs::read_to_string(lists.join(file)).unwrap_or_default();
            let count = entries(&text).iter().filter(|l| **l != PLACEHOLDER_DOMAIN && **l != PLACEHOLDER_IP).count();
            ListInfo { key, file, title, hint, editable, text, count }
        })
        .collect();
    Ok(ListsReply { lists: infos, ipset_updated: meta().get("ipset_updated").and_then(|v| v.as_u64()) })
}

#[tauri::command]
pub async fn zapret_list_save(key: String, text: String) -> Result<String, String> {
    let Some(&(_, file, _, _, true)) = LISTS.iter().find(|l| l.0 == key) else {
        return Err("Этот список нельзя менять".into());
    };
    if text.len() > 1_000_000 {
        return Err("Список слишком большой".into());
    }
    let clean = normalize_list(&key, &text)?;
    let lists = active_dir()?.join("lists");
    fs::create_dir_all(&lists).map_err(|e| e.to_string())?;
    fs::write(lists.join(file), &clean).map_err(|e| e.to_string())?;
    Ok(clean)
}

// ───────────────────────── Обновление ipset ─────────────────────────

const IPSET_URLS: [&str; 2] = [
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/ipset-service.txt",
    "https://cdn.jsdelivr.net/gh/Flowseal/zapret-discord-youtube@main/.service/ipset-service.txt",
];

/// Проверяет скачанный список: только адреса и подсети, хотя бы один.
fn check_ipset(text: &str) -> Result<usize, String> {
    let e = entries(text);
    if e.is_empty() {
        return Err("Скачанный список пустой".into());
    }
    if let Some(bad) = e.iter().find(|l| !valid_ip_line(l)) {
        return Err(format!("В скачанном списке есть строка, которая не похожа на адрес: «{}»", bad.chars().take(60).collect::<String>()));
    }
    Ok(e.len())
}

#[derive(serde::Serialize)]
pub struct IpsetReply {
    count: usize,
    at: u64,
}

/// Скачивает свежий список IP и кладёт его в файл режима loaded. Применится при следующем запуске запрета.
#[tauri::command]
pub async fn zapret_ipset_update() -> Result<IpsetReply, String> {
    let dir = active_dir()?;
    let text = download(&IPSET_URLS).await?;
    let count = check_ipset(&text)?;
    let lists = dir.join("lists");
    fs::create_dir_all(&lists).map_err(|e| e.to_string())?;
    fs::write(lists.join("ipset-all.txt.backup"), text.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())?;
    let at = now_secs();
    set_meta("ipset_updated", at.into());
    Ok(IpsetReply { count, at })
}

// ───────────────────────── Фейки ─────────────────────────

const ACTIVE: [(&str, &str, &str); 2] = [("discord", "ACTIVE_DISCORD_UDP.bin", "fake_discord"), ("game", "ACTIVE_GAME_UDP.bin", "fake_game")];

fn is_active_name(n: &str) -> bool {
    n.to_lowercase().starts_with("active_")
}

/// Файлы-образцы в папке bin: всё `*.bin`, кроме ACTIVE_*.
fn fake_files(bin: &Path) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = fs::read_dir(bin)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let name = e.file_name().into_string().ok()?;
                    let stem = name.strip_suffix(".bin").or_else(|| name.strip_suffix(".BIN"))?.to_string();
                    if is_active_name(&name) {
                        return None;
                    }
                    Some((stem, e.metadata().map(|m| m.len()).unwrap_or(0)))
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

#[derive(serde::Serialize)]
pub struct Fake {
    name: String,
    bytes: u64,
}

#[derive(serde::Serialize)]
pub struct FakesReply {
    fakes: Vec<Fake>,
    discord: Option<String>,
    game: Option<String>,
}

fn file_hash(p: &Path) -> Option<String> {
    crate::integrity::hash_file(p).ok()
}

#[tauri::command]
pub async fn zapret_fakes() -> Result<FakesReply, String> {
    let bin = active_dir()?.join("bin");
    let files = fake_files(&bin);
    let hashes: Vec<(String, Option<String>)> = files.iter().map(|(n, _)| (n.clone(), file_hash(&bin.join(format!("{n}.bin"))))).collect();
    let current = |active: &str| -> Option<String> {
        let h = file_hash(&bin.join(active))?;
        hashes.iter().find(|(_, x)| x.as_deref() == Some(h.as_str())).map(|(n, _)| n.clone())
    };
    Ok(FakesReply {
        fakes: files.iter().map(|(n, b)| Fake { name: n.clone(), bytes: *b }).collect(),
        discord: current(ACTIVE[0].1),
        game: current(ACTIVE[1].1),
    })
}

fn copy_fake(bin: &Path, name: &str, active: &str) -> Result<(), String> {
    if name.contains(['/', '\\']) || name.contains("..") || is_active_name(name) {
        return Err("Неверное имя файла".into());
    }
    let src = bin.join(format!("{name}.bin"));
    if !src.is_file() {
        return Err(format!("Файл {name}.bin не найден"));
    }
    fs::copy(&src, bin.join(active)).map(|_| ()).map_err(|e| format!("Не удалось заменить {active}: {e}"))
}

/// Заменяет `ACTIVE_DISCORD_UDP.bin` (target = discord) или `ACTIVE_GAME_UDP.bin` (target = game) выбранным образцом.
#[tauri::command]
pub async fn zapret_fake_set(target: String, name: String) -> Result<FakesReply, String> {
    let Some(&(_, active, key)) = ACTIVE.iter().find(|a| a.0 == target) else {
        return Err("Неизвестная цель".into());
    };
    copy_fake(&active_dir()?.join("bin"), &name, active)?;
    set_meta(key, name.into());
    zapret_fakes().await
}

/// Перед запуском возвращает выбранные пользователем фейки на место: обновление компонента их сбрасывает.
pub(crate) fn apply_saved_fakes(dir: &Path) {
    let m = meta();
    let bin = dir.join("bin");
    for (_, active, key) in ACTIVE {
        let Some(name) = m.get(key).and_then(|v| v.as_str()) else { continue };
        let src = bin.join(format!("{name}.bin"));
        if src.is_file() && file_hash(&src) != file_hash(&bin.join(active)) {
            let _ = copy_fake(&bin, name, active);
        }
    }
}

// ───────────────────────── hosts ─────────────────────────

const HOSTS_URLS: [&str; 2] = [
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts",
    "https://cdn.jsdelivr.net/gh/Flowseal/zapret-discord-youtube@main/.service/hosts",
];
const MARK_START: &str = "# >>> Бунт: записи Flowseal. Блок можно удалить в разделе «Запрет Discord»";
const MARK_END: &str = "# <<< Бунт";

pub(crate) fn hosts_path() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join("drivers").join("etc").join("hosts")
}

/// Разбирает скачанный файл: оставляет только строки «IP имя [имя…]». Любая другая строка это ошибка.
fn parse_hosts(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (n, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let ip = parts.next().unwrap_or("");
        let names: Vec<&str> = parts.collect();
        let name_ok = |h: &str| !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
        if ip.parse::<IpAddr>().is_err() || names.is_empty() || !names.iter().all(|h| name_ok(h)) {
            return Err(format!("Строка {} не похожа на запись hosts: «{}»", n + 1, line.chars().take(60).collect::<String>()));
        }
        out.push(format!("{ip} {}", names.join(" ")));
    }
    if out.is_empty() {
        return Err("В файле нет записей".into());
    }
    if out.len() > 1000 {
        return Err("Слишком много записей".into());
    }
    Ok(out)
}

/// Убирает блок Бунта из текста hosts.
pub(crate) fn strip_block(text: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if line.trim() == MARK_START {
            inside = true;
            continue;
        }
        if inside {
            if line.trim() == MARK_END {
                inside = false;
            }
            continue;
        }
        out.push(line);
    }
    while out.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        out.pop();
    }
    out.join("\r\n")
}

fn with_block(text: &str, entries: &[String]) -> String {
    let base = strip_block(text);
    let mut s = base;
    if !s.is_empty() {
        s.push_str("\r\n\r\n");
    }
    s.push_str(MARK_START);
    for e in entries {
        s.push_str("\r\n");
        s.push_str(e);
    }
    s.push_str("\r\n");
    s.push_str(MARK_END);
    s.push_str("\r\n");
    s
}

/// Строки вне блока Бунта, где сказано про YouTube: они ломают открытие сайта.
fn youtube_lines(text: &str) -> Vec<String> {
    strip_block(text)
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with('#') && (l.contains("youtube.com") || l.contains("youtu.be")))
        .map(String::from)
        .collect()
}

#[derive(serde::Serialize)]
pub struct HostsStatus {
    installed: bool,
    entries: usize,
    youtube: Vec<String>,
}

fn block_entries(text: &str) -> usize {
    let mut inside = false;
    let mut n = 0;
    for line in text.lines() {
        if line.trim() == MARK_START {
            inside = true;
        } else if line.trim() == MARK_END {
            inside = false;
        } else if inside && !line.trim().is_empty() && !line.trim().starts_with('#') {
            n += 1;
        }
    }
    n
}

#[tauri::command]
pub async fn zapret_hosts_status() -> Result<HostsStatus, String> {
    let text = fs::read_to_string(hosts_path()).unwrap_or_default();
    let n = block_entries(&text);
    Ok(HostsStatus { installed: n > 0, entries: n, youtube: youtube_lines(&text) })
}

/// Скачивает записи, чтобы показать их пользователю до записи в hosts.
#[tauri::command]
pub async fn zapret_hosts_preview() -> Result<Vec<String>, String> {
    parse_hosts(&download(&HOSTS_URLS).await?)
}

fn write_hosts(text: &str) -> Result<(), String> {
    if !crate::settings::is_admin_sync() {
        return Err(NEED_ADMIN.into());
    }
    let path = hosts_path();
    if let Ok(root) = crate::modules::modules_root() {
        let backup = root.join("hosts.backup");
        if !backup.exists() {
            let _ = fs::copy(&path, backup);
        }
    }
    fs::write(&path, text).map_err(|e| format!("Не удалось записать hosts: {e}. Возможно, файл защищён антивирусом."))?;
    let _ = crate::fptn::ps("Clear-DnsClientCache");
    Ok(())
}

/// Записывает показанные пользователю строки в hosts отдельным блоком. Строки проверяются ещё раз.
#[tauri::command]
pub async fn zapret_hosts_apply(lines: Vec<String>) -> Result<HostsStatus, String> {
    let entries = parse_hosts(&lines.join("\n"))?;
    let text = fs::read_to_string(hosts_path()).unwrap_or_default();
    write_hosts(&with_block(&text, &entries))?;
    zapret_hosts_status().await
}

#[tauri::command]
pub async fn zapret_hosts_remove() -> Result<HostsStatus, String> {
    let text = fs::read_to_string(hosts_path()).unwrap_or_default();
    let mut s = strip_block(&text);
    if !s.is_empty() {
        s.push_str("\r\n");
    }
    write_hosts(&s)?;
    zapret_hosts_status().await
}

// ───────────────────────── Диагностика ─────────────────────────

#[derive(Default, Debug)]
struct Facts {
    bfe: Option<bool>,
    proxy: Option<String>,
    tcp_timestamps: Option<bool>,
    adguard: bool,
    killer: Vec<String>,
    intel: Vec<String>,
    checkpoint: Vec<String>,
    smartbyte: Vec<String>,
    vpn: Vec<String>,
    doh: Option<bool>,
    path: String,
    windivert_sys: bool,
    hosts_youtube: Vec<String>,
    foreign_winws: Vec<String>,
    foreign_service: bool,
    windivert_foreign: bool,
    other_bypass: Vec<String>,
}

const DIAG_SCRIPT: &str = r#"
$bfe = Get-Service BFE -ErrorAction SilentlyContinue
Write-Output ('bfe|' + $(if ($bfe -and $bfe.Status -eq 'Running') { '1' } else { '0' }))
$ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
if ($ie -and $ie.ProxyEnable -eq 1) { Write-Output ('proxy|' + $ie.ProxyServer) }
try { $t = (Get-NetTCPSetting -SettingName Internet -ErrorAction Stop).Timestamps; Write-Output ('tcpts|' + $(if ($t -eq 'Enabled') { '1' } else { '0' })) } catch {}
if (Get-Process AdguardSvc -ErrorAction SilentlyContinue) { Write-Output 'adguard|1' }
$svc = @(Get-Service -ErrorAction SilentlyContinue)
function Names($f) { ($svc | Where-Object $f | ForEach-Object { $_.DisplayName }) -join ';' }
$k = Names { $_.Name -match 'Killer' -or $_.DisplayName -match 'Killer' }; if ($k) { Write-Output ('killer|' + $k) }
$i = Names { $_.DisplayName -match 'Intel' -and $_.DisplayName -match 'Connectivity' -and $_.DisplayName -match 'Network' }; if ($i) { Write-Output ('intel|' + $i) }
$c = Names { $_.Name -match 'TracSrvWrapper|EPWD' }; if ($c) { Write-Output ('checkpoint|' + $c) }
$s = Names { $_.Name -match 'SmartByte' -or $_.DisplayName -match 'SmartByte' }; if ($s) { Write-Output ('smartbyte|' + $s) }
$v = Names { ($_.Name -match 'VPN' -or $_.DisplayName -match 'VPN') -and $_.Status -eq 'Running' }; if ($v) { Write-Output ('vpn|' + $v) }
try {
  $d = @(Get-ChildItem -Recurse -Path 'HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters' -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object { $_.DohFlags -gt 0 }).Count
  Write-Output ('doh|' + $(if ($d -gt 0) { '1' } else { '0' }))
} catch {}
"#;

fn split_names(v: &str) -> Vec<String> {
    v.split(';').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// Разбирает вывод скрипта диагностики: строки вида `ключ|значение`.
fn parse_facts(out: &str, f: &mut Facts) {
    for line in out.lines() {
        let Some((k, v)) = line.trim().split_once('|') else { continue };
        match k {
            "bfe" => f.bfe = Some(v == "1"),
            "proxy" => f.proxy = Some(v.to_string()),
            "tcpts" => f.tcp_timestamps = Some(v == "1"),
            "adguard" => f.adguard = v == "1",
            "killer" => f.killer = split_names(v),
            "intel" => f.intel = split_names(v),
            "checkpoint" => f.checkpoint = split_names(v),
            "smartbyte" => f.smartbyte = split_names(v),
            "vpn" => f.vpn = split_names(v),
            "doh" => f.doh = Some(v == "1"),
            _ => {}
        }
    }
}

#[derive(serde::Serialize, Debug, PartialEq)]
pub struct Diag {
    id: &'static str,
    /// ok | warn | bad
    level: &'static str,
    title: String,
    detail: String,
    /// Что можно исправить кнопкой
    fix: Option<&'static str>,
}

fn d(id: &'static str, level: &'static str, title: &str, detail: &str) -> Diag {
    Diag { id, level, title: title.into(), detail: detail.into(), fix: None }
}

fn diagnose(f: &Facts) -> Vec<Diag> {
    let mut v = Vec::new();
    match f.bfe {
        Some(true) => v.push(d("bfe", "ok", "Служба фильтрации (BFE) работает", "")),
        Some(false) => v.push(d("bfe", "bad", "Служба Base Filtering Engine не запущена", "Она нужна запрету: без неё WinDivert не работает. Запустите её в services.msc.")),
        None => {}
    }
    match &f.proxy {
        Some(p) => v.push(d("proxy", "warn", "Включён системный прокси", &format!("Адрес: {p}. Убедитесь, что он нужен. Если вы его не настраивали, выключите его в параметрах Windows.")))
        ,
        None => v.push(d("proxy", "ok", "Системный прокси не используется", "")),
    }
    match f.tcp_timestamps {
        Some(true) => v.push(d("tcpts", "ok", "Метки времени TCP включены", "")),
        Some(false) => {
            let mut x = d("tcpts", "warn", "Метки времени TCP выключены", "Многие стратегии используют их (параметр fooling=ts). Включите их кнопкой.");
            x.fix = Some("tcpts");
            v.push(x);
        }
        None => {}
    }
    let conflict = |id: &'static str, found: &[String], name: &str, how: &str| -> Diag {
        if found.is_empty() {
            d(id, "ok", &format!("{name}: не найден"), "")
        } else {
            d(id, "bad", &format!("Найден {name}"), &format!("{} Службы: {}.", how, found.join(", ")))
        }
    };
    v.push(if f.adguard {
        d("adguard", "bad", "Найден процесс Adguard", "Adguard может мешать Discord. Закройте его или отключите фильтрацию HTTPS.")
    } else {
        d("adguard", "ok", "Adguard: не найден", "")
    });
    v.push(conflict("killer", &f.killer, "Killer Network", "Службы Killer конфликтуют с запретом. Отключите их в services.msc."));
    v.push(conflict("intel", &f.intel, "Intel Connectivity Network Service", "Эта служба конфликтует с запретом. Отключите её в services.msc."));
    v.push(conflict("checkpoint", &f.checkpoint, "Check Point", "Check Point конфликтует с запретом. Попробуйте удалить его."));
    v.push(conflict("smartbyte", &f.smartbyte, "SmartByte", "SmartByte конфликтует с запретом. Удалите его или отключите в services.msc."));
    if f.vpn.is_empty() {
        v.push(d("vpn", "ok", "VPN-службы не работают", ""));
    } else {
        v.push(d("vpn", "warn", "Работают службы VPN", &format!("{}. Часть VPN конфликтует с запретом, на время подбора стратегии их лучше выключить.", f.vpn.join(", "))));
    }
    match f.doh {
        Some(true) => v.push(d("doh", "ok", "Защищённый DNS настроен", "")),
        Some(false) => v.push(d("doh", "warn", "Защищённый DNS не настроен", "YouTube и Discord могут не открываться с DNS провайдера. На вкладке DNS выберите сервер и включите DoH (нужна Windows 11) или настройте защищённый DNS в браузере.")),
        None => {}
    }
    if f.path.chars().any(|c| ('а'..='я').contains(&c.to_ascii_lowercase()) || ('А'..='Я').contains(&c) || c == 'ё' || c == 'Ё') {
        v.push(d("cyr", "warn", "В пути до Бунта есть кириллица", &format!("{}. Если обход не работает, переустановите Бунт в папку без русских букв, например C:\\Bunt.", f.path)));
    } else {
        v.push(d("cyr", "ok", "В пути до Бунта нет кириллицы", ""));
    }
    if f.path.to_lowercase().contains("onedrive") {
        v.push(d("onedrive", "warn", "Бунт лежит в папке OneDrive", "OneDrive может блокировать файлы запрета. Перенесите Бунт в папку вне OneDrive."));
    }
    if f.windivert_sys {
        v.push(d("windivert", "ok", "Драйвер WinDivert на месте", ""));
    } else {
        v.push(d("windivert", "bad", "Нет файла WinDivert64.sys", "Скорее всего его удалил антивирус. Добавьте папку Бунта в исключения и переустановите компонент."));
    }
    if f.hosts_youtube.is_empty() {
        v.push(d("hosts_yt", "ok", "В hosts нет записей про YouTube", ""));
    } else {
        v.push(d("hosts_yt", "warn", "В hosts есть записи про YouTube", &format!("Они могут сломать открытие сайта: {}. Удалите их из файла hosts.", f.hosts_youtube.iter().take(3).cloned().collect::<Vec<_>>().join("; "))));
    }
    if f.foreign_winws.is_empty() && !f.foreign_service {
        v.push(d("foreign", "ok", "Чужого запрета не найдено", ""));
    } else {
        let mut what: Vec<String> = f.foreign_winws.clone();
        if f.foreign_service {
            what.push("служба zapret".into());
        }
        v.push(d("foreign", "bad", "Работает запрет не из Бунта", &format!("{}. Бунт может остановить его при запуске.", what.join(", "))));
    }
    if f.windivert_foreign {
        v.push(d("windivert_foreign", "bad", "Драйвер WinDivert запущен из другой папки", "Остатки другого запрета мешают запуску. Бунт уберёт их при остановке чужого запрета."));
    }
    if !f.other_bypass.is_empty() {
        v.push(d("other", "warn", "Работают другие обходы блокировок", &format!("{}. Они мешают друг другу, оставьте один.", f.other_bypass.join(", "))));
    }
    v
}

#[tauri::command]
pub async fn zapret_diagnose() -> Result<Vec<Diag>, String> {
    let mut f = Facts::default();
    if let Some(out) = crate::fptn::ps(DIAG_SCRIPT) {
        parse_facts(&out, &mut f);
    }
    let dir = active_dir().ok();
    f.path = dir.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
    f.windivert_sys = dir.as_ref().map(|p| p.join("bin").join("WinDivert64.sys").is_file()).unwrap_or(true);
    f.hosts_youtube = youtube_lines(&fs::read_to_string(hosts_path()).unwrap_or_default());
    f.foreign_winws = zapret::foreign_winws();
    f.foreign_service = zapret::foreign_service();
    f.windivert_foreign = zapret::service_exists("WinDivert") && zapret::service_binary("WinDivert").map(|p| !zapret::is_ours(&p)).unwrap_or(false);
    for name in ["goodbyedpi", "ciadpi", "byedpi", "spoofdpi"] {
        if !zapret::list_procs(name).is_empty() {
            f.other_bypass.push(format!("{name}.exe"));
        }
    }
    Ok(diagnose(&f))
}

/// Исправляет то, что можно исправить одной командой.
#[tauri::command]
pub async fn zapret_diag_fix(id: String) -> Result<(), String> {
    if id != "tcpts" {
        return Err("Это нельзя исправить автоматически".into());
    }
    if !crate::settings::is_admin_sync() {
        return Err(NEED_ADMIN.into());
    }
    #[cfg(windows)]
    {
        let ok = Command::new("netsh")
            .args(["interface", "tcp", "set", "global", "timestamps=enabled"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            return Err("Не удалось включить метки времени TCP".into());
        }
    }
    Ok(())
}

/// Версии Discord: (название, процесс, папка в %APPDATA%).
const DISCORDS: [(&str, &str, &str); 4] = [
    ("Discord", "Discord.exe", "discord"),
    ("Discord PTB", "DiscordPTB.exe", "discordptb"),
    ("Discord Canary", "DiscordCanary.exe", "discordcanary"),
    ("Discord Development", "DiscordDevelopment.exe", "discorddevelopment"),
];

/// Закрывает Discord и чистит его кэш (Cache, Code Cache, GPUCache). Возвращает названия очищенных версий.
#[tauri::command]
pub async fn zapret_clear_discord_cache() -> Result<Vec<String>, String> {
    let appdata = std::env::var("APPDATA").map_err(|_| "Не найдена папка AppData".to_string())?;
    let mut done = Vec::new();
    for (name, process, folder) in DISCORDS {
        let base = Path::new(&appdata).join(folder);
        if !base.is_dir() {
            continue;
        }
        #[cfg(windows)]
        {
            let _ = Command::new("taskkill").args(["/IM", process, "/F"]).creation_flags(CREATE_NO_WINDOW).output();
        }
        #[cfg(not(windows))]
        let _ = process;
        std::thread::sleep(Duration::from_millis(400));
        for sub in ["Cache", "Code Cache", "GPUCache"] {
            let p = base.join(sub);
            if p.is_dir() {
                fs::remove_dir_all(&p).map_err(|e| format!("Не удалось очистить {name}: {e}. Закройте Discord и повторите."))?;
            }
        }
        done.push(name.to_string());
    }
    if done.is_empty() {
        return Err("Discord не найден".into());
    }
    Ok(done)
}

// ───────────────────────── Свои сайты для проверки ─────────────────────────

/// Приводит ввод к имени хоста: убирает схему и путь, проверяет символы.
fn normalize_host(s: &str) -> Option<String> {
    let mut h = s.trim().to_lowercase();
    for p in ["https://", "http://"] {
        if let Some(r) = h.strip_prefix(p) {
            h = r.to_string();
        }
    }
    let h = h.split(['/', '?', '#']).next().unwrap_or("").trim_end_matches('.').to_string();
    let labels: Vec<&str> = h.split('.').collect();
    let ok = h.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if ok { Some(h) } else { None }
}

pub(crate) fn custom_targets() -> Vec<String> {
    root_file("zapret-targets.json")
        .map(|p| read_json(&p))
        .ok()
        .and_then(|v| v.get("hosts").and_then(|h| h.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()))
        .unwrap_or_default()
}

#[tauri::command]
pub fn zapret_targets_get() -> Vec<String> {
    custom_targets()
}

#[tauri::command]
pub fn zapret_targets_set(hosts: Vec<String>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for h in hosts {
        if h.trim().is_empty() {
            continue;
        }
        let n = normalize_host(&h).ok_or_else(|| format!("«{}» не похоже на адрес сайта", h.trim().chars().take(60).collect::<String>()))?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    if out.len() > 20 {
        return Err("Можно добавить не больше 20 сайтов".into());
    }
    fs::write(root_file("zapret-targets.json")?, serde_json::json!({ "hosts": out }).to_string()).map_err(|e| e.to_string())?;
    Ok(out)
}

// ───────────────────────── Служба Windows ─────────────────────────

/// Оборачивает аргумент для командной строки службы: `--ключ="значение с пробелами"`.
fn quote_arg(a: &str) -> String {
    if !a.contains([' ', '\t']) {
        return a.to_string();
    }
    match a.split_once('=') {
        Some((k, v)) if k.starts_with("--") => format!("{k}=\"{v}\""),
        _ => format!("\"{a}\""),
    }
}

/// Командная строка службы: путь к winws.exe в кавычках и аргументы.
fn bin_path(exe: &str, args: &[String]) -> String {
    let mut s = format!("\"{exe}\"");
    for a in args {
        s.push(' ');
        s.push_str(&quote_arg(a));
    }
    s
}

#[derive(serde::Serialize)]
pub struct ServiceStatus {
    /// Служба zapret, поставленная Бунтом
    installed: bool,
    running: bool,
    strategy: Option<String>,
    /// Служба zapret, поставленная не из Бунта
    foreign: bool,
}

fn service_running() -> bool {
    zapret::sc(&["query", "zapret"]).map(|s| s.contains("RUNNING")).unwrap_or(false)
}

#[tauri::command]
pub async fn zapret_service_status() -> Result<ServiceStatus, String> {
    let installed = zapret::our_service();
    Ok(ServiceStatus {
        installed,
        running: installed && service_running(),
        strategy: if installed { meta().get("service_strategy").and_then(|v| v.as_str()).map(String::from) } else { None },
        foreign: zapret::foreign_service(),
    })
}

/// Ставит запрет службой Windows: он стартует вместе с системой, без Бунта. Служба называется zapret, как у Flowseal.
#[tauri::command]
pub async fn zapret_service_install(
    state: tauri::State<'_, Zapret>,
    strategy: String,
    game: String,
    ipset: String,
    game_tcp: Option<String>,
    game_udp: Option<String>,
) -> Result<ServiceStatus, String> {
    if strategy.contains(['/', '\\']) || strategy.contains("..") || !strategy.starts_with("general") {
        return Err("Неверное имя стратегии".into());
    }
    if !crate::settings::is_admin_sync() {
        return Err(NEED_ADMIN.into());
    }
    if zapret::foreign_service() || !zapret::foreign_winws().is_empty() {
        return Err("Запрет уже запущен не из Бунта. Остановите его, и службу можно будет поставить.".into());
    }
    if zapret::our_service() {
        state.remove_ours();
    } else {
        state.stop();
    }
    let dir = active_dir()?;
    let bat = fs::read_to_string(dir.join(format!("{strategy}.bat"))).map_err(|_| format!("Не найден файл стратегии {strategy}.bat"))?;
    zapret::prepare_lists(&dir, &ipset)?;
    apply_saved_fakes(&dir);
    let ports = zapret::Ports::new(game_tcp, game_udp);
    let (tcp, udp) = zapret::game_ports(&game, &ports);
    let bin = format!("{}\\", dir.join("bin").display());
    let lists = format!("{}\\", dir.join("lists").display());
    let args = zapret::parse_bat(&bat, &bin, &lists, &tcp, &udp)?;
    let path = bin_path(&dir.join("bin").join("winws.exe").display().to_string(), &args);

    let created = zapret::sc(&["create", "zapret", "binPath=", &path, "DisplayName=", "zapret", "start=", "auto"]);
    if created.is_none() {
        return Err("Не удалось создать службу. Проверьте, что Бунт запущен от администратора.".into());
    }
    let _ = zapret::sc(&["description", "zapret", "Zapret DPI bypass, поставлено Бунтом"]);
    #[cfg(windows)]
    {
        let _ = Command::new("reg")
            .args(["add", "HKLM\\System\\CurrentControlSet\\Services\\zapret", "/v", "zapret-discord-youtube", "/t", "REG_SZ", "/d", &strategy, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
    let _ = zapret::sc(&["start", "zapret"]);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    if !service_running() {
        let _ = zapret::sc(&["delete", "zapret"]);
        return Err("Служба создана, но не запустилась, поэтому я её удалил. Проверьте стратегию на обычном запуске и права администратора.".into());
    }
    set_meta("service_strategy", strategy.clone().into());
    zapret::set_enabled(false);
    zapret_service_status().await
}

/// Удаляет службу zapret, остановив её и драйвер WinDivert из папки Бунта.
#[tauri::command]
pub async fn zapret_service_remove(state: tauri::State<'_, Zapret>) -> Result<ServiceStatus, String> {
    if !crate::settings::is_admin_sync() {
        return Err(NEED_ADMIN.into());
    }
    if zapret::foreign_service() {
        return Err("Эту службу поставили не из Бунта. Используйте «Остановить чужой запрет».".into());
    }
    state.remove_ours();
    zapret_service_status().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_lines() {
        for ok in ["1.2.3.4", "10.0.0.0/8", "2001:db8::/32", "::1"] {
            assert!(valid_ip_line(ok), "{ok}");
        }
        for bad in ["", "1.2.3", "1.2.3.4/33", "example.com", "1.2.3.4/x", "2001:db8::/129"] {
            assert!(!valid_ip_line(bad), "{bad}");
        }
    }

    #[test]
    fn normalizes_lists() {
        assert_eq!(normalize_list("general", "").unwrap(), format!("{PLACEHOLDER_DOMAIN}\n"));
        assert_eq!(normalize_list("ipsetEx", "# x\n").unwrap(), format!("# x\n{PLACEHOLDER_IP}\n"));
        assert_eq!(normalize_list("general", "\u{feff}a.com  \n\nb.org\n\n\n").unwrap(), "a.com\n\nb.org\n");
        assert!(normalize_list("general", "bad domain").is_err());
        assert!(normalize_list("ipset", "1.2.3.4\nnot-an-ip").unwrap_err().contains("Строка 2"));
        // пустой список loaded допустим: это режим «ничего не обрабатывать»
        assert_eq!(normalize_list("ipset", "").unwrap(), "\n");
    }

    #[test]
    fn ipset_download_check() {
        assert_eq!(check_ipset("# c\n1.1.1.0/24\n2.2.2.2\n").unwrap(), 2);
        assert!(check_ipset("<html>").is_err());
        assert!(check_ipset("# only comment").is_err());
    }

    #[test]
    fn hosts_parse_and_block() {
        let e = parse_hosts("# c\n1.2.3.4 a.example.com b.example.com\n\n::1  v6.example.com\n").unwrap();
        assert_eq!(e, vec!["1.2.3.4 a.example.com b.example.com", "::1 v6.example.com"]);
        assert!(parse_hosts("1.2.3.4").is_err());
        assert!(parse_hosts("evil.com 1.2.3.4").is_err());
        assert!(parse_hosts("1.2.3.4 a.com; rm -rf").is_err());
        assert!(parse_hosts("# nothing").is_err());

        let original = "127.0.0.1 localhost\r\n";
        let with = with_block(original, &e);
        assert!(with.contains(MARK_START) && with.contains("1.2.3.4 a.example.com"));
        assert_eq!(block_entries(&with), 2);
        // повторная запись не дублирует блок
        assert_eq!(with_block(&with, &e), with);
        // удаление возвращает исходный текст
        assert_eq!(strip_block(&with), "127.0.0.1 localhost");
    }

    #[test]
    fn youtube_entries_outside_block_only() {
        let text = format!("1.1.1.1 youtube.com\n# 2.2.2.2 youtu.be\n{MARK_START}\n3.3.3.3 youtube.com\n{MARK_END}\n");
        assert_eq!(youtube_lines(&text), vec!["1.1.1.1 youtube.com"]);
    }

    #[test]
    fn service_command_line() {
        assert_eq!(quote_arg("--wf-tcp=80,443"), "--wf-tcp=80,443");
        assert_eq!(quote_arg("--hostlist=C:\\P F\\lists\\a.txt"), "--hostlist=\"C:\\P F\\lists\\a.txt\"");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        let s = bin_path("C:\\P F\\bin\\winws.exe", &["--new".into(), "--ipset=C:\\P F\\x.txt".into()]);
        assert_eq!(s, "\"C:\\P F\\bin\\winws.exe\" --new --ipset=\"C:\\P F\\x.txt\"");
    }

    #[test]
    fn hosts_for_custom_targets() {
        assert_eq!(normalize_host("https://Example.com/path?q=1").as_deref(), Some("example.com"));
        assert_eq!(normalize_host(" rutracker.org. ").as_deref(), Some("rutracker.org"));
        for bad in ["", "localhost", "a b.com", "-a.com", "a..com", "exa$mple.com"] {
            assert!(normalize_host(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn diagnostics_parse_and_judge() {
        let mut f = Facts::default();
        parse_facts("bfe|1\nproxy|127.0.0.1:8080\ntcpts|0\nadguard|1\nkiller|Killer Network Service;Killer Wifi\nvpn|MyVPN\ndoh|0\njunk\n", &mut f);
        f.path = "C:\\Users\\Иван\\OneDrive\\Bunt".into();
        f.windivert_sys = true;
        f.hosts_youtube = vec!["1.1.1.1 youtube.com".into()];
        let r = diagnose(&f);
        let level = |id: &str| r.iter().find(|x| x.id == id).map(|x| x.level);
        assert_eq!(level("bfe"), Some("ok"));
        assert_eq!(level("proxy"), Some("warn"));
        assert_eq!(level("tcpts"), Some("warn"));
        assert_eq!(r.iter().find(|x| x.id == "tcpts").unwrap().fix, Some("tcpts"));
        assert_eq!(level("adguard"), Some("bad"));
        assert_eq!(level("killer"), Some("bad"));
        assert_eq!(level("intel"), Some("ok"));
        assert_eq!(level("vpn"), Some("warn"));
        assert_eq!(level("doh"), Some("warn"));
        assert_eq!(level("cyr"), Some("warn"));
        assert_eq!(level("onedrive"), Some("warn"));
        assert_eq!(level("hosts_yt"), Some("warn"));
        assert_eq!(level("foreign"), Some("ok"));

        let clean = Facts { bfe: Some(true), tcp_timestamps: Some(true), doh: Some(true), path: "C:\\Bunt".into(), windivert_sys: true, ..Default::default() };
        assert!(diagnose(&clean).iter().all(|x| x.level == "ok"));
    }
}
