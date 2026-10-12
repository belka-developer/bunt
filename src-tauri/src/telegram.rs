//! Запрет для Telegram: локальный MTProto-прокси `tg-ws-proxy` (Flowseal, лицензия MIT).
//!
//! Бунт не запускает трей-приложение из релиза, а ставит исходники прокси и запускает их
//! в терминальном режиме (`python -m proxy.tg_ws_proxy`) без окна. Python берётся
//! встраиваемый (embeddable) с python.org и лежит в самой папке Бунта. Раскладка:
//!
//! ```text
//! modules\telegram\<версия>\   исходники прокси (zip релиза)
//! modules\telegram\runtime\    встроенный Python и библиотеки
//! modules\telegram\data\       config.json, proxy.log (переживают обновление)
//! ```
//!
//! Права администратора не нужны.

use serde::{Deserialize, Serialize};
use std::{
    collections::hash_map::RandomState,
    fs,
    hash::{BuildHasher, Hasher},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use tauri::AppHandle;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const PY_VERSION: &str = "3.11.9";
const GET_PIP: &str = "https://bootstrap.pypa.io/get-pip.py";

fn embed_url() -> String {
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
    format!("https://www.python.org/ftp/python/{PY_VERSION}/python-{PY_VERSION}-embed-{arch}.zip")
}

fn telegram_root() -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join("telegram"))
}
fn runtime_dir() -> Result<PathBuf, String> {
    Ok(telegram_root()?.join("runtime"))
}
fn data_dir() -> Result<PathBuf, String> {
    Ok(telegram_root()?.join("data"))
}
fn python_exe() -> Result<PathBuf, String> {
    Ok(runtime_dir()?.join("python.exe"))
}
pub(crate) fn runtime_python() -> Option<PathBuf> {
    python_exe().ok().filter(|p| p.is_file())
}
/// Имена в папке компонента, которые не являются версиями и не удаляются при обновлении.
pub(crate) fn is_service_dir(name: &str) -> bool {
    name == "runtime" || name == "data"
}

/// Все настройки прокси, как в окне настроек оригинального приложения.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    pub host: String,
    pub port: u16,
    /// 32 символа hex
    pub secret: String,
    /// По одной строке `DC:IP`
    pub dc_ip: String,
    pub verbose: bool,
    pub buf_kb: u32,
    pub pool_size: u32,
    pub log_max_mb: u32,
    pub cfproxy: bool,
    pub h2: bool,
    pub cf_domain_on: bool,
    pub cf_domain: String,
    pub cf_worker_on: bool,
    pub cf_worker: String,
    pub force_test_dc: bool,
    pub no_secure: bool,
    pub fake_tls_domain: String,
    /// Запускать прокси при старте Бунта (и Бунт при старте Windows, это включает интерфейс)
    pub autostart: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: "127.0.0.1".into(),
            port: 1443,
            secret: String::new(),
            dc_ip: "2:149.154.167.220\n4:149.154.167.220".into(),
            verbose: false,
            buf_kb: 256,
            pool_size: 4,
            log_max_mb: 5,
            cfproxy: true,
            h2: true,
            cf_domain_on: false,
            cf_domain: String::new(),
            cf_worker_on: false,
            cf_worker: String::new(),
            force_test_dc: false,
            no_secure: false,
            fake_tls_domain: String::new(),
            autostart: false,
        }
    }
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

fn domains(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in text.split(|c: char| c == ',' || c == ';' || c.is_whitespace()).filter(|d| !d.is_empty()) {
        if !out.iter().any(|x| x.eq_ignore_ascii_case(d)) {
            out.push(d.to_string());
        }
    }
    out
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty() && d.len() <= 253 && d.contains('.') && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn dc_lines(text: &str) -> Vec<String> {
    text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
}

/// Проверяет настройки и возвращает понятную ошибку.
pub(crate) fn validate(c: &Config) -> Result<(), String> {
    if c.host.parse::<std::net::IpAddr>().is_err() {
        return Err("Адрес прослушивания должен быть IP-адресом, например 127.0.0.1.".into());
    }
    if c.port < 1024 {
        return Err("Порт должен быть от 1024 до 65535.".into());
    }
    if c.secret.len() != 32 || !c.secret.chars().all(|x| x.is_ascii_hexdigit()) {
        return Err("Секрет должен состоять из 32 символов 0-9 и a-f.".into());
    }
    for l in dc_lines(&c.dc_ip) {
        let ok = l.split_once(':').map(|(d, ip)| d.parse::<u32>().is_ok() && ip.parse::<std::net::Ipv4Addr>().is_ok()).unwrap_or(false);
        if !ok {
            return Err(format!("Неверная строка DC: «{l}». Нужен формат номер:IPv4, например 2:149.154.167.220."));
        }
    }
    if c.buf_kb < 4 || c.buf_kb > 65536 {
        return Err("Размер буфера: от 4 до 65536 КБ.".into());
    }
    if c.pool_size > 64 {
        return Err("Размер пула: от 0 до 64.".into());
    }
    if c.log_max_mb < 1 || c.log_max_mb > 1024 {
        return Err("Размер лога: от 1 до 1024 МБ.".into());
    }
    for (on, text, name) in [(c.cf_domain_on, &c.cf_domain, "Свой домен Cloudflare"), (c.cf_worker_on, &c.cf_worker, "Домен Cloudflare Worker")] {
        if on {
            let list = domains(text);
            if list.is_empty() {
                return Err(format!("{name}: укажите домен или выключите пункт."));
            }
            if let Some(bad) = list.iter().find(|d| !valid_domain(d)) {
                return Err(format!("{name}: «{bad}» не похоже на домен."));
            }
        }
    }
    let f = c.fake_tls_domain.trim();
    if !f.is_empty() && !valid_domain(f) {
        return Err("Домен Fake TLS: укажите обычный домен, например example.com.".into());
    }
    Ok(())
}

fn config_file() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("config.json"))
}

/// Читает настройки; недостающие поля берутся по умолчанию, секрет создаётся при первом обращении.
pub(crate) fn load_config() -> Config {
    let mut c: Config = config_file()
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if c.secret.len() != 32 || !c.secret.chars().all(|x| x.is_ascii_hexdigit()) {
        c.secret = random_secret();
    }
    c
}

fn save_config(c: &Config) -> Result<(), String> {
    let dir = data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| format!("Не удалось создать {}: {e}", dir.display()))?;
    fs::write(config_file()?, serde_json::to_string_pretty(c).map_err(|e| e.to_string())?).map_err(|e| format!("Не удалось записать настройки: {e}"))
}

/// Аргументы командной строки прокси по настройкам.
pub(crate) fn build_args(c: &Config, log_file: &Path) -> Vec<String> {
    let mut a: Vec<String> = vec!["-m".into(), "proxy.tg_ws_proxy".into()];
    let mut push = |k: &str, v: Option<String>| {
        a.push(k.to_string());
        if let Some(v) = v {
            a.push(v);
        }
    };
    push("--host", Some(c.host.clone()));
    push("--port", Some(c.port.to_string()));
    push("--secret", Some(c.secret.clone()));
    let dcs = dc_lines(&c.dc_ip);
    if dcs.is_empty() {
        push("--dc-ip", None);
    }
    for d in dcs {
        push("--dc-ip", Some(d));
    }
    if c.verbose {
        push("-v", None);
    }
    push("--buf-kb", Some(c.buf_kb.to_string()));
    push("--pool-size", Some(c.pool_size.to_string()));
    push("--log-file", Some(log_file.display().to_string()));
    push("--log-max-mb", Some(c.log_max_mb.to_string()));
    if !c.cfproxy {
        push("--no-cfproxy", None);
    }
    if !c.h2 {
        push("--no-h2", None);
    }
    if c.cf_domain_on {
        for d in domains(&c.cf_domain) {
            push("--cfproxy-domain", Some(d));
        }
    }
    if c.cf_worker_on {
        for d in domains(&c.cf_worker) {
            push("--cfproxy-worker-domain", Some(d));
        }
    }
    if c.no_secure {
        push("--no-secure", None);
    }
    if !c.fake_tls_domain.trim().is_empty() {
        push("--fake-tls-domain", Some(c.fake_tls_domain.trim().to_string()));
    }
    if c.force_test_dc {
        push("--force-test-dc", None);
    }
    a
}

/// Ссылка для Telegram: обычная (dd) или с Fake TLS (ee).
pub(crate) fn link(c: &Config) -> String {
    let host = match c.host.as_str() {
        "0.0.0.0" | "::" | "" => "127.0.0.1",
        h => h,
    };
    let f = c.fake_tls_domain.trim();
    let secret = if f.is_empty() { format!("dd{}", c.secret) } else { format!("ee{}{}", c.secret, hex::encode(f.as_bytes())) };
    format!("tg://proxy?server={host}&port={}&secret={secret}", c.port)
}

// ───────── процесс ─────────

fn our_pids() -> Vec<u32> {
    crate::zapret::list_procs("python").into_iter().filter(|(_, p)| crate::zapret::is_ours(p)).map(|(id, _)| id).collect()
}

/// Останавливает прокси Бунта (чужие python не трогаем).
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

fn tail(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().rev().filter(|l| !l.trim().is_empty()).take(4).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

/// Файл python311._pth: у встраиваемого Python это единственный источник путей поиска модулей.
fn write_pth(src: Option<&Path>) -> Result<(), String> {
    let rt = runtime_dir()?;
    let stem = format!("python{}", PY_VERSION.split('.').take(2).collect::<Vec<_>>().join(""));
    let mut text = format!("{stem}.zip\n.\nLib\\site-packages\n");
    if let Some(s) = src {
        text.push_str(&s.display().to_string());
        text.push('\n');
    }
    text.push_str("import site\n");
    fs::write(rt.join(format!("{stem}._pth")), text).map_err(|e| format!("Не удалось настроить Python: {e}"))
}

fn start_blocking() -> Result<(), String> {
    let dir = crate::modules::active_dir("telegram")?;
    let py = runtime_python().ok_or("Не найден встроенный Python. Переустановите компонент.")?;
    if !dir.join("proxy").is_dir() {
        return Err("Файлы прокси не найдены. Переустановите компонент.".into());
    }
    if running() {
        return Ok(());
    }
    let cfg = load_config();
    validate(&cfg)?;
    save_config(&cfg)?;
    write_pth(Some(&dir))?;
    let data = data_dir()?;
    let log = data.join("proxy.log");
    let err_log = data.join("stderr.log");
    let _ = fs::remove_file(&err_log);
    let errf = fs::File::create(&err_log).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&py);
    cmd.args(build_args(&cfg, &log))
        .current_dir(&dir)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONIOENCODING", "utf-8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(errf));
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let mut child = cmd.spawn().map_err(|e| format!("Не удалось запустить прокси: {e}"))?;
    // Если порт занят или настройки неверны, прокси завершается за первые секунды
    for _ in 0..6 {
        std::thread::sleep(Duration::from_millis(500));
        if let Ok(Some(code)) = child.try_wait() {
            let msg = tail(&err_log);
            let msg = if msg.is_empty() { tail(&log) } else { msg };
            return Err(format!("Прокси закрылся (код {code}){}", if msg.is_empty() { String::new() } else { format!(": {msg}") }));
        }
    }
    Ok(())
}

// ───────── установка встроенного Python ─────────

fn run_py(py: &Path, args: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new(py);
    // Рабочая папка Бунта может быть любой (например, System32): относительные пути от неё не годятся
    cmd.args(args).current_dir(py.parent().unwrap_or(Path::new("."))).env("PYTHONDONTWRITEBYTECODE", "1").env("PIP_DISABLE_PIP_VERSION_CHECK", "1").stdin(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().map_err(|e| format!("Не удалось запустить Python: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    let last: Vec<&str> = text.lines().rev().filter(|l| !l.trim().is_empty()).take(3).collect();
    Err(last.into_iter().rev().collect::<Vec<_>>().join(" | "))
}

/// Python и pip на чистой системе иногда спотыкаются при первом запуске (сеть, антивирус): три попытки.
fn run_py_retry(py: &Path, args: &[&str]) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 1..=3u64 {
        match run_py(py, args) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_secs(3 * attempt));
        }
    }
    Err(last)
}

fn runtime_ready() -> bool {
    match runtime_python() {
        Some(py) => run_py(&py, &["-c", "import httpx, h2, certifi"]).is_ok(),
        None => false,
    }
}

/// Ставит встроенный Python и библиотеки прокси, если их ещё нет. Этапы показываются полосой загрузки.
pub(crate) async fn ensure_runtime(app: &AppHandle) -> Result<(), String> {
    if tauri::async_runtime::spawn_blocking(runtime_ready).await.map_err(|e| e.to_string())? {
        return Ok(());
    }
    let rt = runtime_dir()?;
    let _ = fs::remove_dir_all(&rt);
    fs::create_dir_all(&rt).map_err(|e| format!("Нет прав на запись в {}: {e}", rt.display()))?;
    let result: Result<(), String> = async {
        crate::modules::progress(app, "telegram", 22, 100, "Скачиваем Python");
        let zip = crate::modules::download_bytes(&embed_url()).await.map_err(|e| format!("Python: {e}"))?;
        let zip_path = rt.join("python-embed.zip");
        fs::write(&zip_path, &zip).map_err(|e| e.to_string())?;
        crate::modules::extract_zip(&zip_path, &rt)?;
        let _ = fs::remove_file(&zip_path);
        write_pth(None)?;
        crate::modules::progress(app, "telegram", 40, 100, "Скачиваем pip");
        let gp = crate::modules::download_bytes(GET_PIP).await.map_err(|e| format!("pip: {e}"))?;
        let gp_path = rt.join("get-pip.py").display().to_string();
        fs::write(&gp_path, &gp).map_err(|e| e.to_string())?;
        crate::modules::progress(app, "telegram", 50, 100, "Устанавливаем pip");
        let py = python_exe()?;
        let app2 = app.clone();
        tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
            run_py_retry(&py, &[&gp_path, "--no-warn-script-location"]).map_err(|e| format!("Не удалось установить pip: {e}"))?;
            crate::modules::progress(&app2, "telegram", 65, 100, "Устанавливаем библиотеки");
            run_py_retry(&py, &["-m", "pip", "install", "--no-warn-script-location", "--only-binary=:all:", "--retries", "5", "--timeout", "30", "httpx[http2]==0.28.1", "certifi"])
                .map_err(|e| format!("Не удалось установить библиотеки: {e}"))?;
            crate::modules::progress(&app2, "telegram", 90, 100, "Ускоряем шифрование");
            // cryptography ускоряет шифрование; без неё прокси работает на встроенной замене
            let _ = run_py_retry(&py, &["-m", "pip", "install", "--no-warn-script-location", "--only-binary=:all:", "--retries", "5", "--timeout", "30", "cryptography"]);
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())??;
        let _ = fs::remove_file(rt.join("get-pip.py"));
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_dir_all(&rt);
    }
    result
}

// ───────── команды ─────────

#[derive(Serialize)]
pub struct Info {
    running: bool,
    enabled: bool,
    link: String,
    config: Config,
}

fn info() -> Info {
    let config = load_config();
    Info { running: running(), enabled: is_enabled(), link: link(&config), config }
}

#[tauri::command]
pub async fn telegram_status() -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(|| {
        if crate::modules::active_dir("telegram").is_ok() {
            let _ = save_config(&load_config());
        }
        info()
    })
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn telegram_start() -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(|| {
        start_blocking()?;
        set_enabled(true);
        Ok(info())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn telegram_stop() -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(|| {
        stop();
        set_enabled(false);
        info()
    })
    .await
    .map_err(|e| e.to_string())
}

fn restart_if_running() -> Result<(), String> {
    if running() {
        stop();
        std::thread::sleep(Duration::from_millis(800));
        start_blocking()?;
    }
    Ok(())
}

/// Сохраняет настройки. Если прокси работает, перезапускает его с новыми.
#[tauri::command]
pub async fn telegram_config_set(config: Config) -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut c = config;
        c.fake_tls_domain = c.fake_tls_domain.trim().to_string();
        validate(&c)?;
        save_config(&c)?;
        restart_if_running()?;
        Ok(info())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Новый секрет (старая ссылка в Telegram перестанет работать).
#[tauri::command]
pub async fn telegram_new_secret() -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let mut c = load_config();
        c.secret = random_secret();
        save_config(&c)?;
        restart_if_running()?;
        Ok(info())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Включает или выключает запуск прокси вместе с Бунтом. Остальные настройки и работающий прокси не трогает.
#[tauri::command]
pub async fn telegram_set_autostart(on: bool) -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut c = load_config();
        c.autostart = on;
        save_config(&c)?;
        Ok(info())
    })
    .await
    .map_err(|e| e.to_string())?
}

// ───────── прокси, запущенный не из Бунта ─────────

#[derive(Serialize)]
pub struct Foreign {
    /// Описание чужих процессов (путь к exe или командная строка)
    procs: Vec<String>,
    /// Есть запись автозапуска оригинального приложения (Run, TgWsProxy)
    autostart: bool,
}

#[cfg_attr(not(windows), allow(dead_code))]
const FOREIGN_AUTOSTART_VALUE: &str = "TgWsProxy";

/// Чужие копии прокси: трей-приложение TgWsProxy*.exe и консольный python с модулем tg_ws_proxy вне папки Бунта.
fn foreign_list() -> Vec<(u32, String)> {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut out: Vec<(u32, String)> = crate::zapret::list_procs("TgWsProxy*").into_iter().filter(|(_, p)| !crate::zapret::is_ours(p)).collect();
    #[cfg(windows)]
    {
        let script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-CimInstance Win32_Process -Filter \"Name like 'python%'\" | Where-Object { $_.CommandLine -match 'tg_ws_proxy' } | ForEach-Object { \"$($_.ProcessId)|$($_.ExecutablePath)\" }";
        if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]).creation_flags(CREATE_NO_WINDOW).output() {
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                if let Some((id, path)) = l.trim().split_once('|') {
                    if let Ok(id) = id.parse::<u32>() {
                        if !crate::zapret::is_ours(path) {
                            out.push((id, format!("python: {path}")));
                        }
                    }
                }
            }
        }
    }
    out
}

fn foreign_autostart() -> bool {
    #[cfg(windows)]
    {
        return crate::settings::run_hidden("reg", &["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", FOREIGN_AUTOSTART_VALUE]).is_some();
    }
    #[cfg(not(windows))]
    false
}

/// Запущен ли Telegram-прокси не из Бунта (и прописан ли он в автозагрузке).
#[tauri::command]
pub async fn telegram_foreign() -> Result<Foreign, String> {
    tauri::async_runtime::spawn_blocking(|| Foreign { procs: foreign_list().into_iter().map(|(_, p)| p).collect(), autostart: foreign_autostart() })
        .await
        .map_err(|e| e.to_string())
}

/// Останавливает чужой прокси. `remove_autostart`: заодно убрать его из автозагрузки Windows (файлы на диске не трогаем).
#[tauri::command]
pub async fn telegram_take_over(remove_autostart: bool) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        for (pid, _) in foreign_list() {
            crate::zapret::kill_pid(pid);
        }
        if remove_autostart && foreign_autostart() {
            #[cfg(windows)]
            {
                crate::settings::run_hidden("reg", &["delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", FOREIGN_AUTOSTART_VALUE, "/f"])
                    .ok_or("Не удалось убрать прокси из автозагрузки")?;
            }
        }
        std::thread::sleep(Duration::from_millis(600));
        if !foreign_list().is_empty() {
            return Err("Не удалось остановить чужой прокси. Закройте его в трее вручную.".into());
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Возвращает настройки по умолчанию, секрет остаётся прежним.
#[tauri::command]
pub async fn telegram_config_reset() -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let secret = load_config().secret;
        save_config(&Config { secret, ..Config::default() })?;
        restart_if_running()?;
        Ok(info())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config { secret: "00112233445566778899aabbccddeeff".into(), ..Config::default() }
    }

    #[test]
    fn secret_is_32_hex_and_differs() {
        let (a, b) = (random_secret(), random_secret());
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn default_args_match_cli() {
        let a = build_args(&cfg(), Path::new("p.log"));
        let s = a.join(" ");
        assert!(s.starts_with("-m proxy.tg_ws_proxy --host 127.0.0.1 --port 1443 --secret 0011"));
        assert!(s.contains("--dc-ip 2:149.154.167.220 --dc-ip 4:149.154.167.220"));
        assert!(!s.contains("--no-cfproxy") && !s.contains("--no-h2") && !s.contains("-v "));
    }

    #[test]
    fn switches_become_flags() {
        let c = Config {
            verbose: true, cfproxy: false, h2: false, no_secure: true, force_test_dc: true,
            cf_domain_on: true, cf_domain: "a.example.com, b.example.com".into(),
            cf_worker_on: true, cf_worker: "w.example.com".into(),
            fake_tls_domain: "example.com".into(), dc_ip: String::new(), ..cfg()
        };
        validate(&c).unwrap();
        let a = build_args(&c, Path::new("p.log"));
        for f in ["-v", "--no-cfproxy", "--no-h2", "--no-secure", "--force-test-dc"] {
            assert!(a.iter().any(|x| x == f), "{f}");
        }
        assert_eq!(a.iter().filter(|x| *x == "--cfproxy-domain").count(), 2);
        assert!(a.windows(2).any(|w| w[0] == "--cfproxy-worker-domain" && w[1] == "w.example.com"));
        assert!(a.windows(2).any(|w| w[0] == "--dc-ip" && w[1].starts_with('-')));
    }

    #[test]
    fn validation_rejects_bad_values() {
        assert!(validate(&Config { port: 80, ..cfg() }).is_err());
        assert!(validate(&Config { secret: "zz".into(), ..cfg() }).is_err());
        assert!(validate(&Config { dc_ip: "2:999.1.1.1".into(), ..cfg() }).is_err());
        assert!(validate(&Config { host: "localhost".into(), ..cfg() }).is_err());
        assert!(validate(&Config { cf_domain_on: true, ..cfg() }).is_err());
        assert!(validate(&cfg()).is_ok());
    }

    #[test]
    fn links() {
        assert!(link(&cfg()).ends_with("&secret=dd00112233445566778899aabbccddeeff"));
        let c = Config { fake_tls_domain: "a.io".into(), ..cfg() };
        assert!(link(&c).ends_with("&secret=ee00112233445566778899aabbccddeeff612e696f"));
    }
}
