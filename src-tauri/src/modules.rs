//! Компоненты (запреты и другие утилиты) лежат в папке `modules` рядом с exe Бунта:
//!
//! ```text
//! <папка Бунта>\modules\state.json              какая версия каждого компонента активна
//! <папка Бунта>\modules\discord\<версия>\...    файлы компонента
//! <папка Бунта>\modules\.staging\               временная папка загрузки
//! ```
//!
//! Новая версия ставится рядом со старой, ничего не перезаписывается.

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use tauri::{AppHandle, Emitter};

/// Источники компонентов: id → (владелец, репозиторий).
fn source(id: &str) -> Result<(&'static str, &'static str), String> {
    match id {
        "discord" => Ok(("Flowseal", "zapret-discord-youtube")),
        _ => Err(format!("Неизвестный компонент: {id}")),
    }
}

pub fn modules_root() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or("Не удалось определить папку Бунта")?;
    Ok(dir.join("modules"))
}

type State = BTreeMap<String, String>;

fn read_state(root: &Path) -> State {
    fs::read_to_string(root.join("state.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_state(root: &Path, state: &State) -> Result<(), String> {
    let text = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    let tmp = root.join("state.json.tmp");
    fs::write(&tmp, text).map_err(|e| e.to_string())?;
    fs::rename(&tmp, root.join("state.json")).map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    zipball_url: Option<String>,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: Option<u64>,
    /// GitHub отдаёт хеш вида "sha256:..."
    digest: Option<String>,
}

#[derive(Serialize)]
pub struct Latest {
    version: String,
    size: Option<u64>,
}

#[derive(Serialize, Clone)]
struct Progress {
    id: String,
    downloaded: u64,
    total: Option<u64>,
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(concat!("Bunt/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

async fn fetch_release(id: &str) -> Result<Release, String> {
    let (owner, repo) = source(id)?;
    fetch_release_of(owner, repo).await
}

async fn fetch_release_of(owner: &str, repo: &str) -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
    let resp = client()?
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("Нет связи с GitHub: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GitHub ответил: {}", resp.status()));
    }
    resp.json().await.map_err(|e| format!("Непонятный ответ GitHub: {e}"))
}

fn clean_version(tag: &str) -> String {
    tag.trim_start_matches(['v', 'V']).to_string()
}

/// Берём версию из тега и защищаем путь: имя папки не должно содержать ничего лишнего.
fn safe_dir_name(v: &str) -> Result<String, String> {
    if !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) && v != ".." {
        Ok(v.to_string())
    } else {
        Err(format!("Странная версия в релизе: {v}"))
    }
}

/// Какие компоненты установлены: id → версия. Запись в state.json без папки игнорируется.
#[tauri::command]
pub fn installed_components() -> Result<State, String> {
    let root = modules_root()?;
    Ok(read_state(&root)
        .into_iter()
        .filter(|(id, v)| root.join(id).join(v).is_dir())
        .collect())
}

/// Папка, куда Бунт кладёт компоненты. Показывается пользователю в интерфейсе.
#[tauri::command]
pub fn modules_dir() -> Result<String, String> {
    Ok(modules_root()?.display().to_string())
}

/// Последняя версия компонента на GitHub. Ничего не скачивает.
#[tauri::command]
pub async fn latest_component(id: String) -> Result<Latest, String> {
    let rel = fetch_release(&id).await?;
    let asset = rel.assets.iter().find(|a| a.name.to_lowercase().ends_with(".zip"));
    Ok(Latest {
        version: clean_version(&rel.tag_name),
        size: asset.and_then(|a| a.size),
    })
}

/// Скачивает последний релиз, проверяет хеш и кладёт в `modules\<id>\<версия>`.
#[tauri::command]
pub async fn install_component(app: AppHandle, id: String) -> Result<String, String> {
    let rel = fetch_release(&id).await?;
    let version = safe_dir_name(&clean_version(&rel.tag_name))?;
    let root = modules_root()?;
    let target = root.join(&id).join(&version);
    if target.is_dir() {
        let mut state = read_state(&root);
        state.insert(id, version.clone());
        write_state(&root, &state)?;
        return Ok(version);
    }

    let (url, digest) = match rel.assets.iter().find(|a| a.name.to_lowercase().ends_with(".zip")) {
        Some(a) => (a.browser_download_url.clone(), a.digest.clone()),
        None => (rel.zipball_url.clone().ok_or("В релизе нет архива")?, None),
    };

    let staging = root.join(".staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|e| format!("Нет прав на запись в {}: {e}", staging.display()))?;
    let result = download_and_place(&app, &id, &url, digest.as_deref(), &staging, &target).await;
    let _ = fs::remove_dir_all(&staging);
    result?;

    let mut state = read_state(&root);
    state.insert(id, version.clone());
    write_state(&root, &state)?;
    Ok(version)
}

async fn download_and_place(
    app: &AppHandle,
    id: &str,
    url: &str,
    digest: Option<&str>,
    staging: &Path,
    target: &Path,
) -> Result<(), String> {
    let resp = client()?.get(url).send().await.map_err(|e| format!("Не удалось скачать: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Скачивание: GitHub ответил {}", resp.status()));
    }
    let total = resp.content_length();
    let zip_path = staging.join("download.zip");
    let mut file = fs::File::create(&zip_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut downloaded = 0u64;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Обрыв загрузки: {e}"))?;
        hasher.update(&chunk);
        file.write_all(&chunk).map_err(|e| e.to_string())?;
        downloaded += chunk.len() as u64;
        let _ = app.emit("module-progress", Progress { id: id.to_string(), downloaded, total });
    }
    drop(file);

    if let Some(expected) = digest.and_then(|d| d.strip_prefix("sha256:")) {
        let actual = hex::encode(hasher.finalize());
        if !actual.eq_ignore_ascii_case(expected) {
            return Err("Хеш скачанного архива не совпал с GitHub. Установка отменена.".into());
        }
    }

    let unpacked = staging.join("unpacked");
    extract_zip(&zip_path, &unpacked)?;

    // Если всё лежит в одной вложенной папке (так делает zipball), поднимаем её содержимое.
    let mut root_dir = unpacked.clone();
    let entries: Vec<_> = fs::read_dir(&unpacked).map_err(|e| e.to_string())?.flatten().collect();
    if entries.len() == 1 && entries[0].path().is_dir() {
        root_dir = entries[0].path();
    }

    fs::create_dir_all(target.parent().ok_or("Неверный путь")?).map_err(|e| e.to_string())?;
    fs::rename(&root_dir, target).map_err(|e| format!("Не удалось переместить файлы: {e}"))?;
    // Запоминаем хеши файлов, по ним потом работает проверка целостности
    let _ = crate::integrity::write_manifest(target);
    Ok(())
}

fn extract_zip(zip_path: &Path, out: &Path) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(fs::File::open(zip_path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("Архив повреждён: {e}"))?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        // enclosed_name отбрасывает пути с «..» и абсолютные пути
        let Some(rel) = entry.enclosed_name() else {
            return Err("В архиве небезопасный путь. Установка отменена.".into());
        };
        let dest = out.join(rel);
        if entry.is_dir() {
            fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
        } else {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut f = fs::File::create(&dest).map_err(|e| e.to_string())?;
            io::copy(&mut entry, &mut f).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Папка активной версии компонента (`modules\<id>\<версия>`).
pub fn active_dir(id: &str) -> Result<PathBuf, String> {
    let root = modules_root()?;
    let version = read_state(&root).get(id).cloned().ok_or("Компонент не установлен")?;
    let dir = root.join(id).join(version);
    if dir.is_dir() { Ok(dir) } else { Err("Файлы компонента не найдены. Установите его заново.".into()) }
}

#[derive(Serialize)]
pub struct Notes {
    version: String,
    body: String,
    url: String,
    published: Option<String>,
}

/// Описание последнего релиза («что нового»): для самого Бунта и для компонентов.
#[tauri::command]
pub async fn release_notes(id: String) -> Result<Notes, String> {
    let (owner, repo) = match id.as_str() {
        "app" => ("belka-developer", "bunt"),
        other => source(other)?,
    };
    let rel = fetch_release_of(owner, repo).await?;
    Ok(Notes {
        version: clean_version(&rel.tag_name),
        body: rel.body.unwrap_or_default(),
        url: rel.html_url.unwrap_or_else(|| format!("https://github.com/{owner}/{repo}/releases")),
        published: rel.published_at,
    })
}
