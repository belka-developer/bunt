//! Microsoft Visual C++ Redistributable при установке FPTN.
//!
//! Установщик FPTN при каждом запуске открывает окно `vc_redist.exe`, даже если пакет уже стоит. Бунт следит за
//! этим процессом, пока идёт установка: если в системе уже есть такая или более новая версия, окно закрывается
//! сразу; если пакета нет или он старее, Бунт ставит его сам, без окон (`/install /quiet /norestart`).

#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::Duration,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Версия вида 14.38.33135 в виде чисел для сравнения.
pub(crate) fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let t = s.trim().trim_start_matches(['v', 'V']);
    let mut it = t.split('.').map(|x| x.trim().parse::<u32>());
    let a = it.next()?.ok()?;
    let b = it.next()?.ok()?;
    let c = it.next()?.ok()?;
    Some((a, b, c))
}

/// Нужно ли ставить пакет: его нет или установленный старее того, что лежит в установщике.
pub(crate) fn needs_install(installed: Option<&str>, bundled: Option<&str>) -> bool {
    match (installed.and_then(parse_version), bundled.and_then(parse_version)) {
        (None, _) => true,
        // версию в установщике прочитать не удалось, а пакет в системе есть: не трогаем
        (Some(_), None) => false,
        (Some(have), Some(need)) => have < need,
    }
}

/// Версия установленного пакета (64-разрядный, ветка 14.x), если он есть.
fn installed_version() -> Option<String> {
    #[cfg(windows)]
    {
        let out = Command::new("reg")
            .args(["query", r"HKLM\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let mut installed = false;
        let mut version = None;
        for l in text.lines() {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 3 && parts[0].eq_ignore_ascii_case("Installed") {
                installed = parts[2] == "0x1";
            }
            if parts.len() >= 3 && parts[0].eq_ignore_ascii_case("Version") {
                version = Some(parts[2].to_string());
            }
        }
        if installed { version } else { None }
    }
    #[cfg(not(windows))]
    None
}

/// Версия пакета, который лежит в установщике.
fn file_version(path: &Path) -> Option<String> {
    let p = path.display().to_string().replace('\'', "''");
    crate::fptn::ps(&format!("(Get-Item -LiteralPath '{p}').VersionInfo.ProductVersion")).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[cfg(windows)]
fn vc_pids() -> Vec<u32> {
    let Ok(o) = Command::new("tasklist").args(["/FI", "IMAGENAME eq vc_redist*", "/FO", "CSV", "/NH"]).creation_flags(CREATE_NO_WINDOW).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter(|l| l.starts_with('"'))
        .filter_map(|l| l.split("\",\"").nth(1)?.trim_matches('"').parse().ok())
        .collect()
}

#[cfg(windows)]
fn kill_vc() {
    let _ = Command::new("taskkill").args(["/IM", "vc_redist*", "/T", "/F"]).creation_flags(CREATE_NO_WINDOW).output();
}

/// Следит за окном vc_redist, пока выполняется установка FPTN.
pub(crate) struct Watch {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

pub(crate) fn watch(staging: PathBuf) -> Watch {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let handle = std::thread::spawn(move || {
        #[cfg(windows)]
        {
            let mut handled = false;
            while !flag.load(Ordering::Relaxed) {
                if !handled && !vc_pids().is_empty() {
                    handled = true;
                    // путь запускающего процесса берём до закрытия окна, копию кладём к себе: временную папку установщик сотрёт
                    let src = crate::zapret::list_procs("vc_redist*").into_iter().map(|(_, p)| p).find(|p| !p.is_empty());
                    let copy = src.as_ref().and_then(|p| {
                        let dst = staging.join("vc_redist.exe");
                        std::fs::copy(p, &dst).ok().map(|_| dst)
                    });
                    kill_vc();
                    let need = match &copy {
                        Some(c) => needs_install(installed_version().as_deref(), file_version(c).as_deref()),
                        None => installed_version().is_none(),
                    };
                    if need {
                        if let Some(c) = copy {
                            let _ = Command::new(&c).args(["/install", "/quiet", "/norestart"]).creation_flags(CREATE_NO_WINDOW).status();
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(120));
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (&flag, &staging);
        }
    });
    Watch { stop, handle: Some(handle) }
}

impl Watch {
    /// Останавливает слежение и ждёт, пока закончится тихая установка пакета, если она шла.
    pub(crate) fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v14.38.33135.00"), Some((14, 38, 33135)));
        assert_eq!(parse_version("14.44.35211.0"), Some((14, 44, 35211)));
        assert_eq!(parse_version("abc"), None);
    }

    #[test]
    fn decides_install() {
        assert!(needs_install(None, Some("14.44.35211.0")));
        assert!(needs_install(Some("v14.29.30133.00"), Some("14.44.35211.0")));
        assert!(!needs_install(Some("v14.44.35211.00"), Some("14.44.35211.0")));
        assert!(!needs_install(Some("v14.50.36000.00"), Some("14.44.35211.0")));
        assert!(!needs_install(Some("v14.38.33135.00"), None));
    }
}
