//! Прокси Telegram для телефона в той же сети: QR-код, временная страница со ссылкой и правило брандмауэра.
//!
//! Страница нужна, потому что вручную переписывать ссылку и секрет на телефоне неудобно. Она поднимается только на время,
//! пока открыт QR-код (до 10 минут), потому что в ней виден секрет прокси.

use serde::Serialize;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

/// Порт временной страницы. Он открывается в брандмауэре вместе с портом прокси.
pub const PAGE_PORT: u16 = 14444;
const SHARE_SECS: u64 = 600;
const RULE: &str = "Бунт: прокси Telegram";

fn is_loopback_host(h: &str) -> bool {
    matches!(h.trim(), "127.0.0.1" | "localhost" | "::1" | "")
}

/// Адрес этого компьютера в локальной сети: тот, с которого система отправляет пакеты наружу. Ничего не отправляется.
fn lan_ip() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

/// QR-код в виде SVG: чёрный на белом при любой теме, чтобы телефон его читал.
pub fn qr_svg(text: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| format!("Не удалось построить QR-код: {e}"))?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(176, 176)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Страница для телефона: кнопка подключения, копирование ссылки и отдельных полей для ручной настройки.
fn page_html(server: &str, port: u16, secret: &str) -> String {
    let query = format!("server={server}&port={port}&secret={secret}");
    let tg = esc(&format!("tg://proxy?{query}"));
    let web = esc(&format!("https://t.me/proxy?{query}"));
    let (server, port, secret) = (esc(server), port.to_string(), esc(secret));
    format!(
        r#"<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Прокси для Telegram</title>
<style>
:root{{color-scheme:light dark}}
body{{margin:0;font:16px/1.45 system-ui,sans-serif;background:#0d1b22;color:#e8f1f4;padding:20px}}
main{{max-width:520px;margin:0 auto;display:grid;gap:14px}}
h1{{font-size:21px;margin:0}} p{{margin:0;color:#9db3bb}}
.btn{{display:block;width:100%;box-sizing:border-box;padding:15px;border:0;border-radius:12px;font:600 16px system-ui,sans-serif;text-align:center;text-decoration:none;cursor:pointer}}
.go{{background:#2fe3a5;color:#04251a}} .alt{{background:#17303b;color:#e8f1f4}}
.f{{background:#12262f;border-radius:12px;padding:12px 14px;display:grid;gap:6px}}
.f small{{color:#9db3bb}} .f code{{word-break:break-all;font:14px ui-monospace,monospace}}
.f button{{justify-self:start;border:0;border-radius:8px;padding:7px 12px;background:#17303b;color:#e8f1f4;font:14px system-ui,sans-serif}}
#ok{{min-height:20px;color:#2fe3a5}}
</style></head><body><main>
<h1>Прокси для Telegram</h1>
<p>Нажмите «Подключить», Telegram предложит добавить прокси. Если не открылся, скопируйте ссылку и вставьте её в любой чат.</p>
<a class="btn go" href="{web}">Подключить в Telegram</a>
<button class="btn alt" data-c="{tg}">Скопировать ссылку</button>
<div id="ok"></div>
<p>Или заполните вручную: тип MTProto.</p>
<div class="f"><small>Сервер</small><code>{server}</code><button data-c="{server}">Копировать</button></div>
<div class="f"><small>Порт</small><code>{port}</code><button data-c="{port}">Копировать</button></div>
<div class="f"><small>Секрет</small><code>{secret}</code><button data-c="{secret}">Копировать</button></div>
</main><script>
function copy(t){{var a=document.createElement('textarea');a.value=t;a.setAttribute('readonly','');a.style.cssText='position:fixed;top:0;opacity:0';document.body.appendChild(a);a.select();a.setSelectionRange(0,t.length);var ok=false;try{{ok=document.execCommand('copy')}}catch(e){{}}document.body.removeChild(a);return ok}}
document.addEventListener('click',function(e){{var b=e.target.closest('[data-c]');if(!b)return;var ok=copy(b.dataset.c);document.getElementById('ok').textContent=ok?'Скопировано':'Не удалось скопировать, выделите текст вручную'}});
</script></body></html>"#
    )
}

fn respond(mut s: std::net::TcpStream, html: &str) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
    let mut buf = [0u8; 2048];
    let n = s.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or("");
    let ok = first.starts_with("GET / ") || first.starts_with("GET /?");
    let (status, body) = if ok { ("200 OK", html) } else { ("404 Not Found", "Не найдено") };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body.as_bytes());
}

/// Отдаёт страницу, пока не выставлен `stop` или не прошёл срок.
fn serve(listener: TcpListener, html: String, stop: Arc<AtomicBool>, secs: u64) {
    let _ = listener.set_nonblocking(true);
    let end = Instant::now() + Duration::from_secs(secs);
    while !stop.load(Ordering::SeqCst) && Instant::now() < end {
        match listener.accept() {
            Ok((s, _)) => {
                let _ = s.set_nonblocking(false);
                respond(s, &html);
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

struct Share {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

static SHARE: Mutex<Option<Share>> = Mutex::new(None);

fn stop_share() {
    if let Some(mut sh) = SHARE.lock().unwrap().take() {
        sh.stop.store(true, Ordering::SeqCst);
        if let Some(t) = sh.thread.take() {
            let _ = t.join();
        }
    }
}

#[derive(Serialize)]
pub struct ShareInfo {
    /// Адрес временной страницы, он зашит в QR-код
    url: String,
    svg: String,
    /// Адрес компьютера в сети, который увидит телефон
    ip: String,
    running: bool,
    expires_secs: u64,
}

/// Запускает временную страницу и возвращает QR-код на неё.
#[tauri::command]
pub async fn telegram_share_start() -> Result<ShareInfo, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let c = crate::telegram::load_config();
        if is_loopback_host(&c.host) {
            return Err("Сначала включите «Доступ из локальной сети» и примените настройки: сейчас прокси слышит только этот компьютер.".into());
        }
        let ip = match c.host.parse::<IpAddr>() {
            Ok(h) if !h.is_unspecified() => h.to_string(),
            _ => lan_ip().map(|i| i.to_string()).ok_or("Не удалось определить адрес компьютера в локальной сети. Проверьте подключение к роутеру.")?,
        };
        // секрет с учётом Fake TLS берём из готовой ссылки, чтобы формат был тот же, что в окне
        let link = crate::telegram::link(&crate::telegram::Config { host: ip.clone(), ..c.clone() });
        let secret = link.rsplit("secret=").next().unwrap_or("").to_string();
        stop_share();
        let listener = TcpListener::bind(("0.0.0.0", PAGE_PORT))
            .map_err(|e| format!("Не удалось открыть страницу на порту {PAGE_PORT}: {e}. Возможно, порт занят."))?;
        let url = format!("http://{ip}:{PAGE_PORT}/");
        let svg = qr_svg(&url)?;
        let html = page_html(&ip, c.port, &secret);
        let stop = Arc::new(AtomicBool::new(false));
        let st2 = stop.clone();
        let thread = std::thread::spawn(move || serve(listener, html, st2, SHARE_SECS));
        *SHARE.lock().unwrap() = Some(Share { stop, thread: Some(thread) });
        Ok(ShareInfo { url, svg, ip, running: crate::telegram::running(), expires_secs: SHARE_SECS })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn telegram_share_stop() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(stop_share).await.map_err(|e| e.to_string())
}

// ───────────────────────── Брандмауэр ─────────────────────────

fn open_script(port: u16) -> String {
    format!(
        "Remove-NetFirewallRule -DisplayName '{RULE}' -ErrorAction SilentlyContinue; \
         New-NetFirewallRule -DisplayName '{RULE}' -Direction Inbound -Action Allow -Protocol TCP -LocalPort {port},{PAGE_PORT} \
         -RemoteAddress LocalSubnet -Profile Any | Out-Null; Write-Output 'done'"
    )
}

fn close_script() -> String {
    format!("Remove-NetFirewallRule -DisplayName '{RULE}' -ErrorAction SilentlyContinue; Write-Output 'done'")
}

fn status_script() -> String {
    format!(
        "$r = Get-NetFirewallRule -DisplayName '{RULE}' -ErrorAction SilentlyContinue | Select-Object -First 1; \
         if ($r) {{ $p = ($r | Get-NetFirewallPortFilter).LocalPort -join ','; Write-Output ('rule|' + $r.Enabled + '|' + $p) }} else {{ Write-Output 'none' }}"
    )
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Firewall {
    /// Правило есть, включено и открывает текущий порт прокси
    open: bool,
    /// Правило есть, но порт в нём устарел
    stale: bool,
}

fn parse_firewall(out: &str, port: u16) -> Firewall {
    let Some(line) = out.lines().map(|l| l.trim()).find(|l| l.starts_with("rule|")) else {
        return Firewall { open: false, stale: false };
    };
    let mut parts = line.split('|').skip(1);
    let enabled = parts.next().map(|e| e.eq_ignore_ascii_case("true")).unwrap_or(false);
    let ports: Vec<&str> = parts.next().unwrap_or("").split(',').map(|p| p.trim()).collect();
    let has = ports.contains(&port.to_string().as_str());
    Firewall { open: enabled && has, stale: enabled && !has }
}

#[tauri::command]
pub async fn telegram_firewall_status() -> Result<Firewall, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let port = crate::telegram::load_config().port;
        let out = crate::fptn::ps(&status_script()).unwrap_or_default();
        Ok(parse_firewall(&out, port))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Открывает или закрывает порт прокси для устройств в той же локальной сети. Нужны права администратора.
#[tauri::command]
pub async fn telegram_firewall_set(open: bool) -> Result<Firewall, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if !crate::settings::is_admin_sync() {
            return Err("Нужны права администратора. Нажмите «Дать права» в верхней части окна Бунта.".to_string());
        }
        let port = crate::telegram::load_config().port;
        let script = if open { open_script(port) } else { close_script() };
        let out = crate::fptn::ps(&script).unwrap_or_default();
        if !out.contains("done") {
            return Err("Не удалось изменить правило брандмауэра".into());
        }
        let out = crate::fptn::ps(&status_script()).unwrap_or_default();
        Ok(parse_firewall(&out, port))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_is_svg() {
        let svg = qr_svg("http://192.168.1.5:14444/").unwrap();
        assert!(svg.contains("<svg") && svg.contains("#ffffff") && svg.contains("#000000"));
    }

    #[test]
    fn page_has_links_and_escapes() {
        let h = page_html("192.168.1.5", 1443, "dd00112233445566778899aabbccddeeff");
        assert!(h.contains("https://t.me/proxy?server=192.168.1.5&amp;port=1443&amp;secret=dd0011"));
        assert!(h.contains("data-c=\"tg://proxy?server=192.168.1.5&amp;port=1443"));
        assert!(h.contains("<code>1443</code>"));
        let evil = page_html("<script>", 1, "x\"y");
        assert!(!evil.contains("<script>alert") && evil.contains("&lt;script&gt;") && evil.contains("x&quot;y"));
    }

    #[test]
    fn serves_page_and_404() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let t = std::thread::spawn(move || serve(l, "<b>hi</b>".into(), st, 30));
        let get = |path: &str| {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        let ok = get("/");
        assert!(ok.starts_with("HTTP/1.1 200") && ok.ends_with("<b>hi</b>") && ok.contains("Cache-Control: no-store"));
        assert!(get("/secret").starts_with("HTTP/1.1 404"));
        assert!(get("/?x=1").starts_with("HTTP/1.1 200"));
        stop.store(true, Ordering::SeqCst);
        t.join().unwrap();
    }

    #[test]
    fn share_stops_on_time() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let t = std::time::Instant::now();
        serve(l, String::new(), Arc::new(AtomicBool::new(false)), 0);
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn firewall_scripts_and_parse() {
        let s = open_script(1443);
        assert!(s.contains("-LocalPort 1443,14444") && s.contains("LocalSubnet") && s.contains(RULE));
        assert!(close_script().contains("Remove-NetFirewallRule"));
        assert_eq!(parse_firewall("none\n", 1443), Firewall { open: false, stale: false });
        assert_eq!(parse_firewall("rule|True|1443,14444\n", 1443), Firewall { open: true, stale: false });
        assert_eq!(parse_firewall("rule|True|2000,14444\n", 1443), Firewall { open: false, stale: true });
        assert_eq!(parse_firewall("rule|False|1443,14444\n", 1443), Firewall { open: false, stale: false });
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_host("127.0.0.1") && is_loopback_host("localhost"));
        assert!(!is_loopback_host("0.0.0.0") && !is_loopback_host("192.168.1.5"));
    }
}
