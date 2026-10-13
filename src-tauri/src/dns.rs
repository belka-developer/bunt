//! DNS: быстрая смена DNS-серверов физических адаптеров Windows.
//!
//! Бунт ничего не ставит: он меняет адреса DNS у сетевых адаптеров (`Set-DnsClientServerAddress`), как это
//! делают в «Свойствах адаптера». Перед первой сменой запоминает прежние настройки, чтобы их можно было
//! вернуть. Пока включён FPTN или WireGuard, DNS не трогаем: они управляют им сами.
//!
//! Состояние лежит в `modules\dns.json`: последние настройки и снимок прежнего DNS.

use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, SocketAddr, UdpSocket},
    path::PathBuf,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Готовый набор серверов. Единственный источник правды: интерфейс получает список из `dns_status`.
#[derive(Serialize, Clone, Copy)]
pub(crate) struct Preset {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) desc: &'static str,
    pub(crate) v4: [&'static str; 2],
    pub(crate) v6: [&'static str; 2],
    /// Адрес DoH-шаблона (для шифрованного DNS в Windows 11), если у провайдера он есть
    pub(crate) doh: Option<&'static str>,
}

pub(crate) const PRESETS: &[Preset] = &[
    Preset { id: "cloudflare", name: "Cloudflare", desc: "Быстрый и приватный", v4: ["1.1.1.1", "1.0.0.1"], v6: ["2606:4700:4700::1111", "2606:4700:4700::1001"], doh: Some("https://cloudflare-dns.com/dns-query") },
    Preset { id: "google", name: "Google", desc: "Привычный и стабильный", v4: ["8.8.8.8", "8.8.4.4"], v6: ["2001:4860:4860::8888", "2001:4860:4860::8844"], doh: Some("https://dns.google/dns-query") },
    Preset { id: "quad9", name: "Quad9", desc: "Блокирует вредоносные сайты", v4: ["9.9.9.9", "149.112.112.112"], v6: ["2620:fe::fe", "2620:fe::9"], doh: Some("https://dns.quad9.net/dns-query") },
    Preset { id: "adguard", name: "AdGuard", desc: "Без рекламы и трекеров", v4: ["94.140.14.14", "94.140.15.15"], v6: ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"], doh: Some("https://dns.adguard-dns.com/dns-query") },
    Preset { id: "yandex", name: "Яндекс DNS", desc: "Быстрый в России", v4: ["77.88.8.8", "77.88.8.1"], v6: ["2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"], doh: None },
    Preset { id: "opendns", name: "OpenDNS", desc: "Cisco, с фильтрацией опасных сайтов", v4: ["208.67.222.222", "208.67.220.220"], v6: ["2620:119:35::35", "2620:119:53::53"], doh: Some("https://doh.opendns.com/dns-query") },
    Preset { id: "comss", name: "Comss.one", desc: "Помогает открывать заблокированные сайты", v4: ["83.220.169.155", "212.109.195.93"], v6: ["", ""], doh: Some("https://dns.comss.one/dns-query") },
];

fn preset(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub(crate) struct Config {
    pub(crate) last: String,
    pub(crate) custom: [String; 2],
    pub(crate) ipv6: bool,
    pub(crate) doh: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { last: String::new(), custom: [String::new(), String::new()], ipv6: true, doh: false }
    }
}

/// Адаптер с его DNS.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub(crate) struct Adapter {
    pub(crate) index: u32,
    pub(crate) name: String,
    pub(crate) desc: String,
    pub(crate) v4: Vec<String>,
    pub(crate) v6: Vec<String>,
    /// Адреса заданы вручную (а не получены от роутера)
    pub(crate) stat: bool,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Stored {
    config: Config,
    snapshot: Option<Vec<Adapter>>,
}

#[derive(Serialize, Default)]
pub(crate) struct Info {
    presets: Vec<Preset>,
    adapters: Vec<Adapter>,
    /// id пресета, `auto` (адреса от роутера), `custom`, `mixed` (на адаптерах по-разному) или пусто
    active: String,
    has_snapshot: bool,
    config: Config,
    vpn: bool,
    doh_supported: bool,
}

#[derive(Serialize)]
pub(crate) struct Done {
    info: Info,
    message: String,
}

#[derive(Deserialize)]
pub(crate) struct ApplyReq {
    /// id пресета или `custom`
    preset: String,
    #[serde(default)]
    custom: Vec<String>,
    /// Индексы адаптеров; пусто: все активные физические
    #[serde(default)]
    adapters: Vec<u32>,
    #[serde(default)]
    ipv6: bool,
    #[serde(default)]
    doh: bool,
}

#[derive(Serialize)]
pub(crate) struct Ping {
    id: String,
    ms: Option<u32>,
}

// ───────── хранение ─────────

fn store_file() -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join("dns.json"))
}

fn load() -> Stored {
    store_file().ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save(s: &Stored) -> Result<(), String> {
    let p = store_file()?;
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    fs::write(p, serde_json::to_string_pretty(s).map_err(|e| e.to_string())?).map_err(|e| format!("Не удалось сохранить настройки DNS: {e}"))
}

// ───────── проверка адресов ─────────

/// Допустимый адрес DNS-сервера: обычный одиночный IP, не «пустой», не петля и не рассылка.
pub(crate) fn valid_ip(s: &str) -> Option<IpAddr> {
    let ip: IpAddr = s.trim().parse().ok()?;
    let bad = match ip {
        IpAddr::V4(a) => a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_unspecified() || a.is_loopback() || a.is_multicast(),
    };
    if bad { None } else { Some(ip) }
}

/// Разбирает введённые вручную адреса. Пустые поля пропускаются, но хотя бы один адрес нужен.
pub(crate) fn parse_custom(list: &[String]) -> Result<Vec<IpAddr>, String> {
    let mut out: Vec<IpAddr> = Vec::new();
    for raw in list {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        let ip = valid_ip(t).ok_or_else(|| format!("«{t}» не похож на адрес DNS-сервера. Пример: 1.1.1.1"))?;
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    if out.is_empty() {
        return Err("Введите хотя бы один адрес DNS-сервера.".into());
    }
    if out.len() > 4 {
        return Err("Слишком много адресов: достаточно двух.".into());
    }
    Ok(out)
}

/// Адреса пресета: IPv4 всегда, IPv6 по желанию.
fn preset_addrs(p: &Preset, ipv6: bool) -> Vec<String> {
    let mut v: Vec<String> = p.v4.iter().map(|s| s.to_string()).collect();
    if ipv6 {
        v.extend(p.v6.iter().filter(|s| !s.is_empty()).map(|s| s.to_string()));
    }
    v
}

// ───────── PowerShell ─────────

fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

fn ps_list(addrs: &[String]) -> String {
    addrs.iter().map(|a| format!("'{}'", ps_quote(a))).collect::<Vec<_>>().join(",")
}

/// Разбор ответа скрипта состояния: (сборка Windows, адаптеры).
pub(crate) fn parse_status(text: &str) -> (u32, Vec<Adapter>) {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Raw {
        build: u32,
        ad: serde_json::Value,
    }
    let raw: Raw = serde_json::from_str(text.trim().trim_start_matches('\u{feff}')).unwrap_or_default();
    let list = match raw.ad {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(o) => vec![serde_json::Value::Object(o)],
        _ => Vec::new(),
    };
    let one = |v: &serde_json::Value, k: &str| -> Vec<String> {
        match v.get(k) {
            Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
            Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.clone()],
            _ => Vec::new(),
        }
    };
    let ads = list
        .iter()
        .filter_map(|v| {
            let index = v.get("index").and_then(|x| x.as_u64())? as u32;
            Some(Adapter {
                index,
                name: v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                desc: v.get("desc").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                v4: one(v, "v4"),
                v6: one(v, "v6"),
                stat: v.get("stat").and_then(|x| x.as_bool()).unwrap_or(false),
            })
        })
        .collect();
    (raw.build, ads)
}

const STATUS_SCRIPT: &str = r#"
$out = @()
foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
  $i = $a.ifIndex
  $v4 = @((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
  $v6 = @((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses | Where-Object { $_ -notlike 'fec0:*' })
  $g = $a.InterfaceGuid
  $n4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -ErrorAction SilentlyContinue).NameServer
  $n6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$g" -ErrorAction SilentlyContinue).NameServer
  $out += [pscustomobject]@{ index = [int]$i; name = [string]$a.Name; desc = [string]$a.InterfaceDescription; v4 = $v4; v6 = $v6; stat = [bool]($n4 -or $n6) }
}
[pscustomobject]@{ build = [int][Environment]::OSVersion.Version.Build; ad = @($out) } | ConvertTo-Json -Compress -Depth 5
"#;

fn read_system() -> (u32, Vec<Adapter>) {
    match crate::fptn::ps(STATUS_SCRIPT) {
        Some(t) => parse_status(&t),
        None => (0, Vec::new()),
    }
}

/// Что сейчас стоит на адаптерах.
pub(crate) fn detect(ads: &[Adapter]) -> String {
    if ads.is_empty() {
        return String::new();
    }
    let kind = |a: &Adapter| -> String {
        if !a.stat {
            return "auto".into();
        }
        let norm: Vec<String> = a.v4.iter().map(|s| s.to_lowercase()).collect();
        for p in PRESETS {
            let mut want: Vec<String> = p.v4.iter().map(|s| s.to_string()).collect();
            let mut got = norm.clone();
            want.sort();
            got.sort();
            if want == got {
                return p.id.to_string();
            }
        }
        "custom".into()
    };
    let first = kind(&ads[0]);
    if ads.iter().all(|a| kind(a) == first) { first } else { "mixed".into() }
}

fn info(read_sys: bool) -> Info {
    let st = load();
    let (build, ads) = if read_sys { read_system() } else { (0, Vec::new()) };
    Info {
        presets: PRESETS.to_vec(),
        active: detect(&ads),
        adapters: ads,
        has_snapshot: st.snapshot.is_some(),
        config: st.config,
        vpn: crate::fptn::is_running() || crate::wg::is_running(),
        doh_supported: build >= 22000,
    }
}

fn flush() {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("ipconfig").arg("/flushdns").creation_flags(CREATE_NO_WINDOW).output();
    }
}

/// Результаты скрипта вида `ok|индекс` и `err|индекс|текст`: (успешно, ошибки).
pub(crate) fn parse_results(text: &str) -> (usize, Vec<String>) {
    let mut ok = 0;
    let mut errs = Vec::new();
    for line in text.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
        if line.starts_with("ok|") {
            ok += 1;
        } else if let Some(rest) = line.strip_prefix("err|") {
            errs.push(rest.replace('|', ": "));
        }
    }
    (ok, errs)
}

fn require_free() -> Result<(), String> {
    crate::fptn::require_admin()?;
    if crate::fptn::is_running() || crate::wg::is_running() {
        return Err("Сейчас включён VPN (FPTN или WireGuard): он сам управляет DNS. Отключите его, затем меняйте DNS.".into());
    }
    Ok(())
}

fn finish(ok: usize, errs: Vec<String>, done: String) -> Result<String, String> {
    if ok == 0 && !errs.is_empty() {
        return Err(format!("Windows не применила DNS: {}", errs.join("; ")));
    }
    flush();
    if errs.is_empty() { Ok(done) } else { Ok(format!("{done} Не вышло на части адаптеров: {}", errs.join("; "))) }
}

// ───────── действия ─────────

fn apply_blocking(req: ApplyReq) -> Result<Done, String> {
    require_free()?;
    let (build, ads) = read_system();
    if ads.is_empty() {
        return Err("Не найдено активных сетевых адаптеров. Подключитесь к сети и повторите.".into());
    }
    let targets: Vec<&Adapter> = if req.adapters.is_empty() { ads.iter().collect() } else { ads.iter().filter(|a| req.adapters.contains(&a.index)).collect() };
    if targets.is_empty() {
        return Err("Выбранные адаптеры больше не активны. Обновите список.".into());
    }
    let (addrs, label, doh_url, doh_ips): (Vec<String>, String, Option<&str>, Vec<String>) = if req.preset == "custom" {
        let ips = parse_custom(&req.custom)?;
        let v: Vec<String> = ips.iter().filter(|i| i.is_ipv4() || req.ipv6).map(|i| i.to_string()).collect();
        if v.is_empty() {
            return Err("Введите хотя бы один адрес IPv4 или включите IPv6.".into());
        }
        (v, "свои адреса".into(), None, Vec::new())
    } else {
        let p = preset(&req.preset).ok_or("Неизвестный набор DNS.")?;
        (preset_addrs(p, req.ipv6), p.name.to_string(), p.doh, p.v4.iter().map(|s| s.to_string()).collect())
    };

    let mut st = load();
    if st.snapshot.is_none() {
        st.snapshot = Some(ads.clone());
    }
    st.config.last = req.preset.clone();
    st.config.ipv6 = req.ipv6;
    st.config.doh = req.doh;
    if req.preset == "custom" {
        let mut c = [String::new(), String::new()];
        for (i, s) in req.custom.iter().take(2).enumerate() {
            c[i] = s.trim().to_string();
        }
        st.config.custom = c;
    }
    save(&st)?;

    let list = ps_list(&addrs);
    let mut script = String::from("$ErrorActionPreference='Stop'\n");
    for a in &targets {
        script.push_str(&format!(
            "try {{ Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses @({list}); 'ok|{}' }} catch {{ ('err|{}|' + ($_.Exception.Message -replace '[\\r\\n|]+',' ')) }}\n",
            a.index, a.index, a.index
        ));
    }
    let doh_on = req.doh && build >= 22000 && doh_url.is_some();
    if doh_on {
        let url = ps_quote(doh_url.unwrap_or(""));
        for ip in &doh_ips {
            script.push_str(&format!(
                "try {{ if (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {{ if (-not (Get-DnsClientDohServerAddress -ServerAddress '{ip}' -ErrorAction SilentlyContinue)) {{ Add-DnsClientDohServerAddress -ServerAddress '{ip}' -DohTemplate '{url}' -AllowFallbackToUdp $true -AutoUpgrade $true | Out-Null }} }} }} catch {{ }}\n"
            ));
        }
    }
    let out = crate::fptn::ps(&script).unwrap_or_default();
    let (ok, errs) = parse_results(&out);
    let msg = finish(ok, errs, format!("DNS: {label}. Применено к адаптерам: {ok}."))?;
    Ok(Done { info: info(true), message: if doh_on { format!("{msg} Шифрование DoH включено.") } else { msg } })
}

fn reset_blocking(mode: &str) -> Result<Done, String> {
    require_free()?;
    let (_, ads) = read_system();
    let mut st = load();
    let mut script = String::from("$ErrorActionPreference='Stop'\n");
    let label;
    if mode == "restore" {
        let snap = st.snapshot.clone().ok_or("Прежних настроек нет: Бунт ещё не менял DNS.")?;
        for a in &snap {
            let n = ps_quote(&a.name);
            let set = if a.stat {
                let mut all = a.v4.clone();
                all.extend(a.v6.clone());
                format!("Set-DnsClientServerAddress -InterfaceAlias '{n}' -ServerAddresses @({})", ps_list(&all))
            } else {
                format!("Set-DnsClientServerAddress -InterfaceAlias '{n}' -ResetServerAddresses")
            };
            script.push_str(&format!("try {{ {set}; 'ok|{}' }} catch {{ ('err|{n}|' + ($_.Exception.Message -replace '[\\r\\n|]+',' ')) }}\n", a.index));
        }
        label = "возвращены прежние настройки";
    } else {
        if ads.is_empty() {
            return Err("Не найдено активных сетевых адаптеров.".into());
        }
        for a in &ads {
            script.push_str(&format!(
                "try {{ Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses; 'ok|{}' }} catch {{ ('err|{}|' + ($_.Exception.Message -replace '[\\r\\n|]+',' ')) }}\n",
                a.index, a.index, a.index
            ));
        }
        label = "автоматически от роутера";
    }
    let out = crate::fptn::ps(&script).unwrap_or_default();
    let (ok, errs) = parse_results(&out);
    let msg = finish(ok, errs, format!("DNS {label}."))?;
    if mode == "restore" {
        st.snapshot = None;
    }
    st.config.last = String::new();
    save(&st)?;
    Ok(Done { info: info(true), message: msg })
}

// ───────── замер скорости ─────────

/// Пакет запроса A-записи для имени.
pub(crate) fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut p = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        let l = label.as_bytes();
        p.push(l.len().min(63) as u8);
        p.extend_from_slice(&l[..l.len().min(63)]);
    }
    p.extend_from_slice(&[0, 0, 1, 0, 1]);
    p
}

/// Ответ нашему запросу: тот же id и бит ответа.
pub(crate) fn is_reply(id: u16, buf: &[u8]) -> bool {
    buf.len() >= 12 && buf[0] == (id >> 8) as u8 && buf[1] == id as u8 && buf[2] & 0x80 != 0
}

/// Время одного запроса к серверу.
pub(crate) fn rtt(server: SocketAddr, name: &str, id: u16, timeout: Duration) -> Option<Duration> {
    let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    sock.connect(server).ok()?;
    let q = build_query(id, name);
    let t = Instant::now();
    sock.send(&q).ok()?;
    let mut buf = [0u8; 512];
    loop {
        let n = sock.recv(&mut buf).ok()?;
        if is_reply(id, &buf[..n]) {
            return Some(t.elapsed());
        }
        if t.elapsed() > timeout {
            return None;
        }
    }
}

/// Медиана по успешным замерам (мс).
pub(crate) fn median(mut v: Vec<u32>) -> Option<u32> {
    if v.is_empty() {
        return None;
    }
    v.sort();
    Some(v[v.len() / 2])
}

fn ping_blocking() -> Vec<Ping> {
    const NAMES: [&str; 3] = ["www.microsoft.com", "www.wikipedia.org", "www.apple.com"];
    let handles: Vec<_> = PRESETS
        .iter()
        .map(|p| {
            let id = p.id.to_string();
            let addr: Option<IpAddr> = p.v4[0].parse().ok();
            std::thread::spawn(move || {
                let ms = addr.and_then(|ip| {
                    let samples: Vec<u32> = NAMES
                        .iter()
                        .enumerate()
                        .filter_map(|(i, n)| rtt(SocketAddr::new(ip, 53), n, 0x4200 + i as u16, Duration::from_millis(1500)))
                        .map(|d| d.as_millis() as u32)
                        .collect();
                    median(samples)
                });
                Ping { id, ms }
            })
        })
        .collect();
    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

// ───────── команды ─────────

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn dns_status() -> Result<Info, String> {
    blocking(|| Ok(info(true))).await
}

#[tauri::command]
pub async fn dns_apply(req: ApplyReq) -> Result<Done, String> {
    blocking(move || apply_blocking(req)).await
}

/// `auto`: адреса от роутера; `restore`: вернуть то, что было до Бунта.
#[tauri::command]
pub async fn dns_reset(mode: String) -> Result<Done, String> {
    blocking(move || reset_blocking(&mode)).await
}

#[tauri::command]
pub async fn dns_ping() -> Result<Vec<Ping>, String> {
    blocking(|| Ok(ping_blocking())).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_valid() {
        let mut ids = std::collections::HashSet::new();
        for p in PRESETS {
            assert!(ids.insert(p.id), "дубликат {}", p.id);
            for a in p.v4 {
                assert!(matches!(valid_ip(a), Some(IpAddr::V4(_))), "{} {}", p.id, a);
            }
            for a in p.v6.iter().filter(|s| !s.is_empty()) {
                assert!(matches!(valid_ip(a), Some(IpAddr::V6(_))), "{} {}", p.id, a);
            }
            if let Some(u) = p.doh {
                assert!(u.starts_with("https://"));
            }
        }
        assert!(preset("cloudflare").is_some() && preset("nope").is_none());
    }

    #[test]
    fn ip_validation() {
        assert!(valid_ip("1.1.1.1").is_some());
        assert!(valid_ip(" 192.168.1.1 ").is_some());
        assert!(valid_ip("2606:4700:4700::1111").is_some());
        for bad in ["", "0.0.0.0", "127.0.0.1", "255.255.255.255", "224.0.0.1", "::", "::1", "1.1.1", "1.1.1.1; calc", "a.b.c.d", "1.1.1.1/24", "'x"] {
            assert!(valid_ip(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn custom_list() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(parse_custom(&v(&["1.1.1.1", "", "1.1.1.1", "8.8.8.8"])).unwrap().len(), 2);
        assert!(parse_custom(&v(&["", " "])).is_err());
        assert!(parse_custom(&v(&["1.1.1.1", "evil'; Remove-Item"])).is_err());
        assert!(parse_custom(&v(&["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"])).is_err());
    }

    #[test]
    fn addrs_with_and_without_v6() {
        let p = preset("google").unwrap();
        assert_eq!(preset_addrs(p, false), vec!["8.8.8.8", "8.8.4.4"]);
        assert_eq!(preset_addrs(p, true).len(), 4);
        assert_eq!(preset_addrs(preset("comss").unwrap(), true).len(), 2);
    }

    #[test]
    fn ps_quoting() {
        assert_eq!(ps_list(&["a".into(), "b'c".into()]), "'a','b''c'");
    }

    #[test]
    fn status_parsing() {
        let two = r#"{"build":22631,"ad":[{"index":5,"name":"Ethernet","desc":"Intel","v4":["1.1.1.1","1.0.0.1"],"v6":[],"stat":true},{"index":9,"name":"Wi-Fi","desc":"","v4":"192.168.1.1","v6":["fe80::1"],"stat":false}]}"#;
        let (b, a) = parse_status(two);
        assert_eq!(b, 22631);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].v4, vec!["1.1.1.1", "1.0.0.1"]);
        assert_eq!(a[1].v4, vec!["192.168.1.1"]);
        assert!(a[0].stat && !a[1].stat);
        // PowerShell сворачивает одиночный элемент в объект
        let one = r#"{"build":19045,"ad":{"index":3,"name":"Eth","v4":["8.8.8.8"],"v6":[],"stat":true}}"#;
        assert_eq!(parse_status(one).1.len(), 1);
        assert_eq!(parse_status("\u{feff}{\"build\":1,\"ad\":[]}").1.len(), 0);
        assert_eq!(parse_status("мусор").1.len(), 0);
    }

    #[test]
    fn detection() {
        let ad = |stat: bool, v4: &[&str]| Adapter { index: 1, name: "e".into(), v4: v4.iter().map(|s| s.to_string()).collect(), stat, ..Default::default() };
        assert_eq!(detect(&[]), "");
        assert_eq!(detect(&[ad(false, &["192.168.1.1"])]), "auto");
        assert_eq!(detect(&[ad(true, &["1.0.0.1", "1.1.1.1"])]), "cloudflare");
        assert_eq!(detect(&[ad(true, &["1.1.1.1", "1.0.0.1"]), ad(true, &["1.1.1.1", "1.0.0.1"])]), "cloudflare");
        assert_eq!(detect(&[ad(true, &["10.0.0.1"])]), "custom");
        assert_eq!(detect(&[ad(true, &["8.8.8.8", "8.8.4.4"]), ad(false, &[])]), "mixed");
    }

    #[test]
    fn results_parsing() {
        let (ok, errs) = parse_results("ok|5\r\nerr|9|Нет доступа\nok|7\n");
        assert_eq!(ok, 2);
        assert_eq!(errs, vec!["9: Нет доступа"]);
    }

    #[test]
    fn query_packet() {
        let q = build_query(0x1234, "www.a.com");
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&q[12..], &[3, b'w', b'w', b'w', 1, b'a', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        assert!(!is_reply(0x1234, &q));
        let mut r = q.clone();
        r[2] |= 0x80;
        assert!(is_reply(0x1234, &r));
        assert!(!is_reply(0x1235, &r));
    }

    #[test]
    fn median_works() {
        assert_eq!(median(vec![]), None);
        assert_eq!(median(vec![30, 10, 20]), Some(20));
        assert_eq!(median(vec![5]), Some(5));
    }

    #[test]
    fn rtt_against_local_server() {
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, from)) = srv.recv_from(&mut buf) {
                let mut r = buf[..n].to_vec();
                r[2] |= 0x80;
                let _ = srv.send_to(&r, from);
            }
        });
        let d = rtt(addr, "example.com", 0x77, Duration::from_millis(1500));
        assert!(d.is_some());
        // сервера нет: таймаут
        let dead = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(rtt(dead.local_addr().unwrap(), "example.com", 1, Duration::from_millis(150)).is_none());
    }
}
