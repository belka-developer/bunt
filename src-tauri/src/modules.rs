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
pub(crate) fn source(id: &str) -> Result<(&'static str, &'static str), String> {
    match id {
        "discord" => Ok(("Flowseal", "zapret-discord-youtube")),
        "telegram" => Ok(("Flowseal", "tg-ws-proxy")),
        "fptn" => Ok(("fptn-project", "fptn")),
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

#[derive(Deserialize, Clone)]
pub(crate) struct Release {
    pub(crate) tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    zipball_url: Option<String>,
    #[serde(default)]
    pub(crate) assets: Vec<Asset>,
}

#[derive(Deserialize, Clone)]
pub(crate) struct Asset {
    pub(crate) name: String,
    pub(crate) browser_download_url: String,
    pub(crate) size: Option<u64>,
    /// GitHub отдаёт хеш вида "sha256:..."
    pub(crate) digest: Option<String>,
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
    /// Что сейчас происходит (для компонентов с несколькими этапами установки)
    stage: Option<String>,
}

pub(crate) fn progress(app: &AppHandle, id: &str, downloaded: u64, total: u64, stage: &str) {
    let _ = app.emit("module-progress", Progress { id: id.to_string(), downloaded, total: Some(total), stage: Some(stage.to_string()) });
}

pub(crate) fn client() -> Result<reqwest::Client, String> {
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
    fetch_release_url(owner, repo, None).await
}

/// Релиз с конкретным тегом (нужен, чтобы сверить установленную версию с оригиналом).
pub(crate) async fn fetch_release_tag(id: &str, tag: &str) -> Result<Release, String> {
    let (owner, repo) = source(id)?;
    fetch_release_url(owner, repo, Some(tag)).await
}

fn archive_url(owner: &str, repo: &str, tag: &str) -> String {
    format!("https://github.com/{owner}/{repo}/archive/refs/tags/{tag}.zip")
}

fn cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, Release)>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, Release)>>> = std::sync::OnceLock::new();
    C.get_or_init(Default::default)
}

/// Релиз через API GitHub. Ответы кэшируются на 10 минут: лимит API без входа всего 60 запросов в час на адрес,
/// а Бунт спрашивает один и тот же релиз для версии, описания и проверок. Если лимит исчерпан (403),
/// тег берётся с обычной страницы релиза, а файлы качаются по прямой ссылке, это лимитом не считается.
async fn fetch_release_url(owner: &str, repo: &str, tag: Option<&str>) -> Result<Release, String> {
    let key = format!("{owner}/{repo}/{}", tag.unwrap_or("latest"));
    if let Some((at, rel)) = cache().lock().unwrap().get(&key) {
        if at.elapsed() < std::time::Duration::from_secs(600) {
            return Ok(rel.clone());
        }
    }
    let url = match tag {
        Some(t) => format!("https://api.github.com/repos/{owner}/{repo}/releases/tags/{t}"),
        None => format!("https://api.github.com/repos/{owner}/{repo}/releases/latest"),
    };
    let resp = client()?
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("Нет связи с GitHub: {e}"))?;
    let status = resp.status();
    let rel = if status.is_success() {
        let mut rel: Release = resp.json().await.map_err(|e| format!("Непонятный ответ GitHub: {e}"))?;
        // архив с обычного адреса вместо API, чтобы скачивание не тратило лимит
        rel.zipball_url = Some(archive_url(owner, repo, &rel.tag_name));
        rel
    } else if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        fallback_release(owner, repo, tag).await.map_err(|e| format!("GitHub ограничил число запросов (403), попробуйте позже ({e})"))?
    } else {
        return Err(format!("GitHub ответил: {status}"));
    };
    cache().lock().unwrap().insert(key, (std::time::Instant::now(), rel.clone()));
    Ok(rel)
}

/// Релиз без API: тег из перенаправления страницы /releases/latest и архив по прямой ссылке.
async fn fallback_release(owner: &str, repo: &str, tag: Option<&str>) -> Result<Release, String> {
    let tag = match tag {
        Some(t) => t.to_string(),
        None => {
            let resp = client()?
                .get(format!("https://github.com/{owner}/{repo}/releases/latest"))
                .send()
                .await
                .map_err(|e| format!("Нет связи с GitHub: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("страница релиза: {}", resp.status()));
            }
            let path = resp.url().path().to_string();
            path.rsplit_once("/tag/").map(|x| x.1.trim_end_matches('/').to_string()).filter(|t| !t.is_empty()).ok_or("релизов нет")?
        }
    };
    Ok(Release {
        zipball_url: Some(archive_url(owner, repo, &tag)),
        html_url: Some(format!("https://github.com/{owner}/{repo}/releases/tag/{tag}")),
        tag_name: tag,
        body: None,
        published_at: None,
        assets: Vec::new(),
    })
}

/// Архив релиза и его хеш, если GitHub его отдаёт.
pub(crate) fn pick_archive(rel: &Release) -> Result<(String, Option<String>), String> {
    match rel.assets.iter().find(|a| a.name.to_lowercase().ends_with(".zip")) {
        Some(a) => Ok((a.browser_download_url.clone(), a.digest.clone())),
        None => Ok((rel.zipball_url.clone().ok_or("В релизе нет архива")?, None)),
    }
}

pub(crate) async fn download_bytes(url: &str) -> Result<Vec<u8>, String> {
    let resp = client()?.get(url).send().await.map_err(|e| format!("Не удалось скачать: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Скачивание: GitHub ответил {}", resp.status()));
    }
    resp.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("Обрыв загрузки: {e}"))
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

/// Пользовательские списки (`lists/*-user.txt`) сохраняются при обновлении и переустановке.
fn read_user_lists(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let Ok(rd) = fs::read_dir(dir.join("lists")) else { return Vec::new() };
    rd.flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with("-user.txt") { Some((name, fs::read(e.path()).ok()?)) } else { None }
        })
        .collect()
}

fn restore_user_lists(dir: &Path, lists: &[(String, Vec<u8>)]) {
    if lists.is_empty() {
        return;
    }
    let d = dir.join("lists");
    let _ = fs::create_dir_all(&d);
    for (name, bytes) in lists {
        let _ = fs::write(d.join(name), bytes);
    }
}

/// Скачивает последний релиз, проверяет хеш и кладёт в `modules\<id>\<версия>`.
/// `force`: переустановка, даже если эта версия уже стоит. Работающий winws останавливается.
#[tauri::command]
pub async fn install_component(
    app: AppHandle,
    state: tauri::State<'_, crate::zapret::Zapret>,
    id: String,
    force: Option<bool>,
) -> Result<String, String> {
    let force = force.unwrap_or(false);
    let rel = fetch_release(&id).await?;
    let version = safe_dir_name(&clean_version(&rel.tag_name))?;
    let root = modules_root()?;
    let target = root.join(&id).join(&version);
    // Первая сборка Telegram ставила exe: такая папка без исходников прокси не годится
    let broken = id == "telegram" && target.is_dir() && !target.join("proxy").is_dir();
    if target.is_dir() && !force && !broken {
        let mut st = read_state(&root);
        st.insert(id, version.clone());
        write_state(&root, &st)?;
        return Ok(version);
    }

    if id == "fptn" {
        return install_fptn(&app, &rel, &version, &root, &target).await;
    }
    let (url, digest) = pick_archive(&rel)?;
    let staging = root.join(".staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|e| format!("Нет прав на запись в {}: {e}", staging.display()))?;

    let result: Result<(), String> = async {
        let root_dir = download_and_extract(&app, &id, &url, digest.as_deref(), &staging).await?;
        if id == "telegram" {
            // Python и библиотеки для запуска прокси без окна
            crate::telegram::ensure_runtime(&app).await?;
            progress(&app, "telegram", 97, 100, "Записываем файлы");
        }
        // Файлы заняты работающим процессом: останавливаем его прямо перед заменой
        if id == "telegram" {
            crate::telegram::stop();
        } else {
            state.stop();
        }
        // Свои списки берём из заменяемой папки или из предыдущей активной версии
        let previous = read_state(&root).get(&id).map(|v| root.join(&id).join(v));
        let saved = if target.is_dir() {
            read_user_lists(&target)
        } else {
            previous.as_deref().map(read_user_lists).unwrap_or_default()
        };
        if target.is_dir() {
            fs::remove_dir_all(&target).map_err(|e| format!("Не удалось удалить старые файлы: {e}"))?;
        }
        fs::create_dir_all(target.parent().ok_or("Неверный путь")?).map_err(|e| e.to_string())?;
        fs::rename(&root_dir, &target).map_err(|e| format!("Не удалось переместить файлы: {e}"))?;
        restore_user_lists(&target, &saved);
        // Хеши файлов, по ним работает быстрая проверка целостности
        let _ = crate::integrity::write_manifest(&target);
        Ok(())
    }
    .await;
    let _ = fs::remove_dir_all(&staging);
    result?;

    let mut st = read_state(&root);
    st.insert(id.clone(), version.clone());
    write_state(&root, &st)?;
    // Старые версии больше не нужны
    if let Ok(rd) = fs::read_dir(root.join(&id)) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n != version.as_str() && !(id == "telegram" && crate::telegram::is_service_dir(&n)) && !(id == "fptn" && crate::fptn::is_service_dir(&n)) {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
    Ok(version)
}

/// Удаляет компонент целиком: останавливает запрет и стирает папку с файлами и своими списками.
#[tauri::command]
pub async fn uninstall_component(state: tauri::State<'_, crate::zapret::Zapret>, id: String) -> Result<(), String> {
    source(&id)?;
    if id == "fptn" {
        // Остановить клиент, убрать маршруты и адаптер, запустить штатный деинсталлятор, затем стереть папку
        let _ = tauri::async_runtime::spawn_blocking(crate::fptn::shutdown).await;
        if let Ok(dir) = active_dir("fptn") {
            run_fptn_uninstaller(&dir);
        }
    } else if id == "telegram" {
        crate::telegram::stop();
        crate::telegram::set_enabled(false);
    } else {
        state.stop();
        crate::zapret::set_enabled(false);
    }
    let root = modules_root()?;
    let dir = root.join(&id);
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("Не удалось удалить файлы (их держит другая программа?): {e}"))?;
    }
    let mut st = read_state(&root);
    st.remove(&id);
    write_state(&root, &st)
}

/// Скачивает архив, проверяет хеш и распаковывает во временную папку. Возвращает папку с файлами.
async fn download_and_extract(
    app: &AppHandle,
    id: &str,
    url: &str,
    digest: Option<&str>,
    staging: &Path,
) -> Result<PathBuf, String> {
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
        // У Telegram загрузка файлов это первая пятая часть установки (дальше ставится Python), у FPTN три пятых
        let part = match id {
            "telegram" => Some((20, "Скачиваем файлы прокси")),
            "fptn" => Some((60, "Скачиваем установщик FPTN")),
            _ => None,
        };
        if let Some((share, label)) = part {
            if let Some(t) = total.filter(|t| *t > 0) {
                progress(app, id, downloaded * share / t, 100, label);
            }
        } else {
            let _ = app.emit("module-progress", Progress { id: id.to_string(), downloaded, total, stage: None });
        }
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
    let entries: Vec<_> = fs::read_dir(&unpacked).map_err(|e| e.to_string())?.flatten().collect();
    Ok(if entries.len() == 1 && entries[0].path().is_dir() { entries[0].path() } else { unpacked })
}

pub(crate) fn extract_zip(zip_path: &Path, out: &Path) -> Result<(), String> {
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

// ───────── FPTN: официальный установщик Inno Setup ─────────

fn find_installer(dir: &Path) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().map(|x| x.eq_ignore_ascii_case("exe")).unwrap_or(false) {
                return Some(p);
            }
        }
    }
    None
}

/// Убирает окна и процессы, которые установщик запускает после себя (клиент FPTN с треем).
#[cfg_attr(not(windows), allow(dead_code))]
fn kill_fptn_in(dir: &Path) {
    for name in ["fptn-client", "fptn-client-cli"] {
        for (pid, path) in crate::zapret::list_procs(name) {
            if path.to_lowercase().replace('/', "\\").starts_with(&dir.display().to_string().to_lowercase().replace('/', "\\")) {
                crate::zapret::kill_pid(pid);
            }
        }
    }
}

fn run_fptn_uninstaller(dir: &Path) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let un = dir.join("unins000.exe");
        if un.is_file() {
            let _ = std::process::Command::new(un)
                .args(["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"])
                .creation_flags(0x0800_0000)
                .status();
        }
    }
    #[cfg(not(windows))]
    let _ = dir;
}

/// FPTN распространяется установщиком. Бунт запускает его тихо сразу в `modules\fptn\<версия>`,
/// без ярлыков, и убирает автозапуск клиента, который установщик пытается открыть.
async fn install_fptn(app: &AppHandle, rel: &Release, version: &str, root: &Path, target: &Path) -> Result<String, String> {
    if !cfg!(windows) {
        return Err("FPTN ставится только в Windows.".into());
    }
    if !crate::settings::is_admin_sync() {
        return Err("Для установки FPTN нужны права администратора.".into());
    }
    let asset = rel
        .assets
        .iter()
        .find(|a| a.name.to_lowercase().starts_with("fptnclientinstaller") && a.name.to_lowercase().ends_with(".zip"))
        .ok_or("В релизе не нашёлся установщик Windows (GitHub мог ограничить запросы, повторите позже).")?;
    let staging = root.join(".staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|e| format!("Нет прав на запись в {}: {e}", staging.display()))?;

    let result: Result<(), String> = async {
        let unpacked = download_and_extract(app, "fptn", &asset.browser_download_url, asset.digest.as_deref(), &staging).await?;
        let installer = find_installer(&unpacked).ok_or("В архиве нет установщика .exe")?;
        progress(app, "fptn", 65, 100, "Останавливаем клиент");
        let _ = tauri::async_runtime::spawn_blocking(crate::fptn::shutdown).await;
        if target.is_dir() {
            fs::remove_dir_all(target).map_err(|e| format!("Не удалось удалить старые файлы: {e}"))?;
        }
        fs::create_dir_all(target.parent().ok_or("Неверный путь")?).map_err(|e| e.to_string())?;
        progress(app, "fptn", 70, 100, "Устанавливаем FPTN (около минуты)");
        let target_s = target.display().to_string();
        let t2 = target.to_path_buf();
        tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                let status = std::process::Command::new(&installer)
                    .args(["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/NOICONS", "/SP-"])
                    .raw_arg(format!("/DIR=\"{target_s}\""))
                    .creation_flags(0x0800_0000)
                    .status()
                    .map_err(|e| format!("Не удалось запустить установщик: {e}"))?;
                // Установщик в конце открывает клиент с треем: он нам не нужен
                std::thread::sleep(std::time::Duration::from_secs(3));
                kill_fptn_in(&t2);
                if !status.success() {
                    return Err(format!("Установщик FPTN завершился с кодом {}", status.code().unwrap_or(-1)));
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (installer, target_s, t2);
            }
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())??;
        if !target.join(crate::fptn::CLI).is_file() {
            let _ = fs::remove_dir_all(target);
            return Err("После установки не нашёлся fptn-client-cli.exe".into());
        }
        progress(app, "fptn", 95, 100, "Записываем хеши файлов");
        let _ = crate::integrity::write_manifest(target);
        Ok(())
    }
    .await;
    let _ = fs::remove_dir_all(&staging);
    result?;

    let mut st = read_state(root);
    st.insert("fptn".into(), version.to_string());
    write_state(root, &st)?;
    if let Ok(rd) = fs::read_dir(root.join("fptn")) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n != version && !crate::fptn::is_service_dir(&n) {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
    Ok(version.to_string())
}
