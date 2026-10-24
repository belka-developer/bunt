//! Настройки Бунта, автозапуск и открытие ссылок.
//!
//! Настройки лежат в `%APPDATA%\\dev.belka.bunt\\settings.json`.
//! Автозапуск сделан записью в разделе Run реестра текущего пользователя: она видна в
//! «Автозагрузке» диспетчера задач. Бунт стартует без прав администратора и предлагает их дать.
//! Для тех, кому это неудобно, есть второй вариант: задача планировщика Windows «при входе» с наивысшими
//! правами. Она запускает Бунт сразу от администратора и без запроса UAC. Включить и выключить её можно только
//! из Бунта с правами администратора, а при удалении программы установщик её убирает.

use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, sync::Mutex};
use tauri::{AppHandle, Manager};

#[cfg(windows)]
use std::{os::windows::process::CommandExt, process::Command};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Settings {
    pub autostart: bool,
    /// Автозапуск с правами администратора (задача планировщика). Заменяет обычный автозапуск
    pub autostart_admin: bool,
    /// Закрытие и сворачивание окна прячет Бунт в трей
    pub tray: bool,
    pub notify: bool,
    pub autoupdate: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { autostart: false, autostart_admin: false, tray: true, notify: true, autoupdate: true }
    }
}

pub struct SettingsState(pub Mutex<Settings>);

fn file(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_config_dir().ok().map(|d| d.join("settings.json"))
}

pub fn load(app: &AppHandle) -> Settings {
    file(app)
        .and_then(|f| fs::read_to_string(f).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(app: &AppHandle, s: &Settings) -> Result<(), String> {
    let f = file(app).ok_or("Нет папки настроек")?;
    if let Some(dir) = f.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(f, serde_json::to_string_pretty(s).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

#[cfg_attr(not(windows), allow(dead_code))]
#[cfg(windows)]
pub(crate) fn run_hidden(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

#[cfg(windows)]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(windows)]
fn autostart_present() -> bool {
    run_hidden("reg", &["query", RUN_KEY, "/v", "Bunt"]).is_some()
}

/// Старые версии (0.1.5) ставили автозапуск задачей планировщика. Убираем её, чтобы Бунт не запускался дважды.
#[cfg(windows)]
fn remove_old_task() {
    if run_hidden("schtasks", &["/Query", "/TN", "Bunt"]).is_some() {
        let _ = run_hidden("schtasks", &["/Delete", "/TN", "Bunt", "/F"]);
    }
}

/// Автозапуск: запись в разделе Run текущего пользователя, она видна в «Автозагрузке» диспетчера задач.
/// Бунт стартует без прав администратора и сам предлагает их дать.
fn apply_autostart(on: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        remove_old_task();
        if on {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let value = format!("\"{}\" --hidden", exe.display());
            run_hidden("reg", &["add", RUN_KEY, "/v", "Bunt", "/t", "REG_SZ", "/d", &value, "/f"])
                .map(|_| ())
                .ok_or_else(|| "Не удалось записать автозапуск в реестр".to_string())
        } else if autostart_present() {
            run_hidden("reg", &["delete", RUN_KEY, "/v", "Bunt", "/f"])
                .map(|_| ())
                .ok_or_else(|| "Не удалось убрать автозапуск из реестра".to_string())
        } else {
            Ok(())
        }
    }
    #[cfg(not(windows))]
    {
        let _ = on;
        Ok(())
    }
}

/// Имя задачи планировщика для автозапуска с правами администратора.
#[cfg_attr(not(windows), allow(dead_code))]
const TASK_NAME: &str = "Bunt-AdminAutostart";

/// Скрипт создания задачи. Нужны явные настройки: по умолчанию планировщик не запускает задачу от батареи
/// и убивает её через 72 часа, а Бунт должен работать сколько угодно.
#[cfg_attr(not(windows), allow(dead_code))]
fn task_create_script(exe: &str) -> String {
    let exe = exe.replace('\'', "''");
    format!(
        "$me=[Security.Principal.WindowsIdentity]::GetCurrent().Name; \
$a=New-ScheduledTaskAction -Execute '{exe}' -Argument '--hidden'; \
$t=New-ScheduledTaskTrigger -AtLogOn -User $me; $t.Delay='PT5S'; \
$p=New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Highest; \
$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable; \
Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a -Trigger $t -Principal $p -Settings $s -Description 'Запуск Бунта при входе в Windows с правами администратора. Создана Бунтом и удаляется вместе с программой.' -Force | Out-Null; \
if(Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue){{'ok'}}"
    )
}

#[cfg_attr(not(windows), allow(dead_code))]
fn task_remove_script() -> String {
    format!(
        "Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false -ErrorAction SilentlyContinue; \
if(-not (Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue)){{'ok'}}"
    )
}

/// Путь к exe из задачи или `None`, если задачи нет. Читать задачу надёжно получается только с правами администратора.
#[cfg(windows)]
fn task_exe() -> Option<String> {
    let script = format!(
        "$x=Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue; if($x){{ ($x.Actions | ForEach-Object {{ $_.Execute }}) -join '|' }}"
    );
    crate::fptn::ps(&script).map(|o| o.trim().to_string()).filter(|o| !o.is_empty())
}

/// Включает или выключает автозапуск с правами администратора. Создавать и удалять задачу может только администратор.
fn apply_autostart_admin(on: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        if !is_admin_sync() {
            return Err("Нужны права администратора. Нажмите «Дать права» вверху окна.".into());
        }
        if on {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let out = crate::fptn::ps(&task_create_script(&exe.display().to_string())).unwrap_or_default();
            if !out.trim().ends_with("ok") {
                return Err("Не удалось создать задачу в планировщике Windows".into());
            }
            // обычный автозапуск заменяется: иначе Бунт стартовал бы дважды, и первым мог бы оказаться вариант без прав
            apply_autostart(false)
        } else {
            let out = crate::fptn::ps(&task_remove_script()).unwrap_or_default();
            if out.trim().ends_with("ok") {
                Ok(())
            } else {
                Err("Не удалось удалить задачу из планировщика Windows".into())
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = on;
        Ok(())
    }
}

/// Запись должна указывать на текущий exe (путь мог измениться при переустановке).
fn reconcile(s: &Settings) {
    if s.autostart_admin {
        // Задачу можно проверить и починить только с правами администратора. Обычный автозапуск не трогаем и не создаём.
        #[cfg(windows)]
        if is_admin_sync() {
            let exe = std::env::current_exe().map(|e| e.display().to_string().to_lowercase()).unwrap_or_default();
            if task_exe().map(|t| t.to_lowercase() != exe).unwrap_or(true) {
                let _ = apply_autostart_admin(true);
            }
        }
    } else if s.autostart {
        let _ = apply_autostart(true);
    } else {
        #[cfg(windows)]
        remove_old_task();
    }
}

/// Запущен ли Бунт с правами администратора.
pub fn is_admin_sync() -> bool {
    #[cfg(windows)]
    {
        // Уровень целостности «High» (S-1-16-12288) есть только у запущенных от администратора
        run_hidden("whoami", &["/groups"]).map(|o| o.contains("S-1-16-12288")).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[tauri::command]
pub async fn is_admin() -> Result<bool, String> {
    Ok(is_admin_sync())
}

/// Перезапускает Бунт от имени администратора. Новый экземпляр после подтверждения UAC
/// закрывает старый (`--takeover`). Если подтверждение отклонить, старый продолжает работать.
#[tauri::command]
pub async fn relaunch_as_admin() -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let path = exe.display().to_string().replace('\'', "''");
        let script = format!(
            "Start-Process -FilePath '{path}' -ArgumentList '--takeover','{}' -Verb RunAs",
            std::process::id()
        );
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Вызывается при старте: если запущены с `--takeover PID`, закрывает старый (неадминистраторский) экземпляр.
pub fn takeover_from_args() {
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        let Some(i) = args.iter().position(|a| a == "--takeover") else { return };
        let Some(pid) = args.get(i + 1).filter(|p| p.chars().all(|c| c.is_ascii_digit())) else { return };
        let Ok(exe) = std::env::current_exe() else { return };
        let Some(name) = exe.file_name().map(|n| n.to_string_lossy().to_string()) else { return };
        // Убеждаемся, что по этому PID действительно наш exe, а не посторонний процесс
        let filter_pid = format!("PID eq {pid}");
        let filter_img = format!("IMAGENAME eq {name}");
        let listed = run_hidden("tasklist", &["/FI", &filter_pid, "/FI", &filter_img, "/NH"]).unwrap_or_default();
        if listed.to_lowercase().contains(&name.to_lowercase()) {
            let _ = run_hidden("taskkill", &["/PID", pid, "/F"]);
            std::thread::sleep(std::time::Duration::from_millis(800));
        }
    }
}

#[tauri::command]
pub async fn settings_get(state: tauri::State<'_, SettingsState>) -> Result<Settings, String> {
    let s = state.0.lock().unwrap().clone();
    reconcile(&s);
    Ok(s)
}

#[tauri::command]
pub async fn settings_set(
    app: AppHandle,
    state: tauri::State<'_, SettingsState>,
    settings: Settings,
) -> Result<Settings, String> {
    let old = state.0.lock().unwrap().clone();
    let mut new = settings;
    let mut error = None;
    if new.autostart_admin != old.autostart_admin {
        match apply_autostart_admin(new.autostart_admin) {
            Ok(()) => {
                if new.autostart_admin {
                    new.autostart = false;
                }
            }
            Err(e) => {
                new.autostart_admin = old.autostart_admin;
                new.autostart = old.autostart;
                error = Some(e);
            }
        }
    } else if new.autostart && new.autostart_admin {
        new.autostart = false;
        error = Some("Сейчас включён автозапуск с правами администратора, он заменяет обычный. Выключите его, если нужен обычный.".to_string());
    }
    if error.is_none() && new.autostart != old.autostart {
        if let Err(e) = apply_autostart(new.autostart) {
            new.autostart = old.autostart;
            error = Some(e);
        }
    }
    save(&app, &new)?;
    *state.0.lock().unwrap() = new.clone();
    match error {
        Some(e) => Err(e),
        None => Ok(new),
    }
}

/// Есть ли запись автозапуска в реестре.
#[tauri::command]
pub async fn autostart_exists() -> Result<bool, String> {
    #[cfg(windows)]
    {
        Ok(autostart_present())
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

/// Есть ли задача автозапуска с правами администратора. `None`: без прав администратора это не проверить.
#[tauri::command]
pub async fn autostart_task() -> Result<Option<bool>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        #[cfg(windows)]
        {
            if is_admin_sync() {
                Ok(Some(task_exe().is_some()))
            } else {
                Ok(None)
            }
        }
        #[cfg(not(windows))]
        {
            Ok(None)
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Открывает в браузере только известные ссылки проекта.
#[tauri::command]
pub fn open_url(url: String) -> Result<(), String> {
    const ALLOWED: [&str; 3] = [
        "https://github.com/belka-developer/bunt",
        "https://github.com/belka-developer/bunt#readme",
        "https://discord.gg/dw65R5Mvft",
    ];
    let ok = ALLOWED.contains(&url.as_str())
        || url.starts_with("https://github.com/belka-developer/bunt/")
        || url.starts_with("https://github.com/Flowseal/zapret-discord-youtube/")
        || url.starts_with("https://github.com/Flowseal/tg-ws-proxy/")
        || url.starts_with("https://github.com/fptn-project/fptn/");
    if !ok {
        return Err("Эту ссылку открыть нельзя".into());
    }
    launch(&url)
}

/// Открывает адрес в браузере по умолчанию. Проверка, что адрес разрешён, лежит на вызывающем.
pub(crate) fn launch(url: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        Command::new("explorer")
            .arg(url)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(windows))]
    let _ = url;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_script_has_safe_settings() {
        let t = task_create_script(r"C:\Program Files\Bunt\Bunt.exe");
        assert!(t.contains("-RunLevel Highest") && t.contains("-AtLogOn") && t.contains("'--hidden'"));
        // без этих настроек задачу убило бы через 72 часа, а на ноутбуке от батареи она вообще не стартовала бы
        assert!(t.contains("-ExecutionTimeLimit ([TimeSpan]::Zero)") && t.contains("-AllowStartIfOnBatteries") && t.contains("-DontStopIfGoingOnBatteries"));
        assert!(t.contains("-MultipleInstances IgnoreNew") && t.contains(TASK_NAME));
        assert!(t.contains(r"-Execute 'C:\Program Files\Bunt\Bunt.exe'"));
    }

    #[test]
    fn task_script_escapes_quotes_in_path() {
        let t = task_create_script("C:\\O'Neil\\Bunt.exe");
        assert!(t.contains("-Execute 'C:\\O''Neil\\Bunt.exe'"));
    }

    #[test]
    fn task_remove_script_checks_result() {
        let r = task_remove_script();
        assert!(r.contains("Unregister-ScheduledTask") && r.contains(TASK_NAME) && r.contains("'ok'"));
    }

    #[test]
    fn old_settings_files_still_load() {
        let s: Settings = serde_json::from_str(r#"{"autostart":true,"tray":false}"#).unwrap();
        assert!(s.autostart && !s.autostart_admin && !s.tray && s.notify && s.autoupdate);
    }
}
