//! Проверка целостности компонентов.
//!
//! При установке Бунт записывает SHA-256 каждого файла компонента в `.bunt-manifest.json`
//! рядом с файлами. Проверка сравнивает файлы на диске с этим списком и смотрит цифровые
//! подписи у драйвера и исполняемого файла. Это защита от порчи файлов и случайных правок:
//! злоумышленник с правами администратора может подменить и сам список.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

#[cfg(windows)]
use std::{os::windows::process::CommandExt, process::Command};

const MANIFEST: &str = ".bunt-manifest.json";

/// Файлы, которые меняются при обычной работе, в хеши не входят.
fn skipped(rel: &str) -> bool {
    let r = rel.replace('\\', "/").to_lowercase();
    r == MANIFEST || r == "winws.log" || r == "lists/ipset-all.txt" || r.ends_with("-user.txt")
}

fn hash_file(path: &Path) -> Result<String, String> {
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
    title: String,
    /// ok | warn | bad | info
    state: String,
    note: Option<String>,
}

fn item(title: &str, state: &str, note: Option<String>) -> Item {
    Item { title: title.to_string(), state: state.to_string(), note }
}

fn names(list: &[String]) -> String {
    let shown: Vec<&str> = list.iter().take(3).map(|s| s.as_str()).collect();
    let more = if list.len() > 3 { format!(" и ещё {}", list.len() - 3) } else { String::new() };
    format!("{}{}", shown.join(", "), more)
}

/// Сверка файлов компонента с записанными при установке хешами.
fn check_files(label: &str, dir: &Path) -> Vec<Item> {
    let title = format!("{label}: хеши файлов");
    let current = match hash_dir(dir) {
        Ok(c) => c,
        Err(e) => return vec![item(&title, "bad", Some(format!("Не удалось прочитать файлы: {e}")))],
    };
    let manifest = dir.join(MANIFEST);
    let saved: Option<BTreeMap<String, String>> = fs::read_to_string(&manifest)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| serde_json::from_value(v.get("files")?.clone()).ok());

    let Some(saved) = saved else {
        let _ = write_manifest(dir);
        return vec![item(
            &title,
            "info",
            Some("Список хешей создан сейчас по текущим файлам (компонент поставлен до появления проверки). Дальше проверка сравнивает файлы с ним. Для полной уверенности переустановите компонент.".into()),
        )];
    };

    let changed: Vec<String> = saved.iter().filter(|(k, v)| current.get(*k).map(|c| c != *v).unwrap_or(false)).map(|(k, _)| k.clone()).collect();
    let missing: Vec<String> = saved.keys().filter(|k| !current.contains_key(*k)).cloned().collect();
    let added: Vec<String> = current.keys().filter(|k| !saved.contains_key(*k)).cloned().collect();

    let mut out = Vec::new();
    if changed.is_empty() && missing.is_empty() {
        out.push(item(&title, "ok", Some(format!("Проверено файлов: {}. Всё совпадает с установкой.", saved.len()))));
    } else {
        let mut parts = Vec::new();
        if !changed.is_empty() {
            parts.push(format!("изменены: {}", names(&changed)));
        }
        if !missing.is_empty() {
            parts.push(format!("пропали: {}", names(&missing)));
        }
        out.push(item(&title, "bad", Some(format!("{}. Переустановите компонент.", parts.join("; ")))));
    }
    if !added.is_empty() {
        out.push(item(&format!("{label}: лишние файлы"), "warn", Some(format!("Появились файлы, которых не было при установке: {}.", names(&added)))));
    }
    out
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

fn run_check() -> Vec<Item> {
    let mut out = Vec::new();
    match crate::modules::active_dir("discord") {
        Ok(dir) => {
            let label = "Запрет Discord и YouTube";
            out.extend(check_files(label, &dir));
            for (file, rel) in [("winws.exe", "bin/winws.exe"), ("WinDivert64.sys", "bin/WinDivert64.sys")] {
                if let Some(i) = check_signature(label, file, &dir.join(rel)) {
                    out.push(i);
                }
            }
        }
        Err(_) => out.push(item("Компоненты", "info", Some("Нет установленных компонентов для проверки.".into()))),
    }
    out
}

/// Проверка целостности установленных компонентов.
#[tauri::command]
pub async fn integrity_check() -> Result<Vec<Item>, String> {
    tauri::async_runtime::spawn_blocking(run_check).await.map_err(|e| e.to_string())
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
        assert_eq!(r[1].state, "warn");

        // без списка хешей: создаётся эталон и сообщается об этом
        fs::remove_file(dir.join(MANIFEST)).unwrap();
        let r = check_files("T", &dir);
        assert_eq!(r[0].state, "info");
        assert!(dir.join(MANIFEST).exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
