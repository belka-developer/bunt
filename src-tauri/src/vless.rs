//! VLESS: ссылки vless://, подписки и ядро Xray-core.
//!
//! Бунт ставит Xray-core (XTLS/Xray-core) в `modules\vless\<версия>\`, ничего не устанавливая в систему, и
//! запускает `xray.exe run` скрыто. Конфиг Бунт собирает сам из выбранного профиля и правил:
//! * режим «TUN»: виртуальный адаптер wintun, через ядро идёт весь трафик (нужны права администратора);
//! * режим «системный прокси»: локальные SOCKS и HTTP, в Windows включается системный прокси;
//! * правила по приложениям (`process`), доменам (`domain:`, `full:`, `regexp:`, `geosite:`) и сетям (`ip`):
//!   через VLESS, напрямую или заблокировать; остальное идёт по правилу «по умолчанию».
//!
//! Перед подключением запоминаются шлюз и DNS физических адаптеров и прежний системный прокси; после отключения
//! или сбоя Бунт возвращает их, не сбрасывая сеть Windows.
//!
//! Раскладка: `modules\vless\<версия>\` ядро, `modules\vless\data\profiles.json` профили (с ключами, закрыты для
//! обычных пользователей), `config.json` настройки, `session.json` состояние сессии, `run\config.json` рабочий
//! конфиг (удаляется при отключении), `vless.log` журнал Бунта, `xray.log` вывод ядра.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(crate) const EXE: &str = "xray.exe";
const TUN_NAME: &str = "BuntVLESS";
const TUN_IP: &str = "198.18.0.1";

static CHILD: Mutex<Option<Child>> = Mutex::new(None);

fn root() -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join("vless"))
}
pub(crate) fn data_dir() -> Result<PathBuf, String> {
    Ok(root()?.join("data"))
}
fn file(name: &str) -> Result<PathBuf, String> {
    Ok(data_dir()?.join(name))
}
fn run_dir() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("run"))
}

/// Имена в папке компонента, которые не являются версиями.
pub(crate) fn is_service_dir(name: &str) -> bool {
    name == "data"
}

fn vlog(msg: &str) {
    if let (Ok(d), Ok(f)) = (data_dir(), file("vless.log")) {
        let _ = fs::create_dir_all(d);
        let old = fs::read_to_string(&f).unwrap_or_default();
        let lines: Vec<&str> = old.lines().collect();
        let keep = lines[lines.len().saturating_sub(300)..].join("\n");
        let _ = fs::write(&f, if keep.is_empty() { format!("{msg}\n") } else { format!("{keep}\n{msg}\n") });
    }
}

fn ps(script: &str) -> Option<String> {
    crate::fptn::ps(script)
}

fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// Закрывает файл с ключами от обычных пользователей.
fn lock_down(path: &Path) {
    #[cfg(windows)]
    {
        let _ = Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
    #[cfg(not(windows))]
    let _ = path;
}

/// Подписан ли файл компанией WireGuard (так подписан wintun.dll).
pub(crate) fn signed_by_wireguard(path: &Path) -> bool {
    let p = ps_quote(&path.to_string_lossy());
    ps(&format!("$s=Get-AuthenticodeSignature -LiteralPath '{p}'; if($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -like '*WireGuard*'){{ 'yes' }}"))
        .map(|o| o.contains("yes"))
        .unwrap_or(false)
}

// ───────── настройки ─────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Rule {
    /// `app`, `domain` или `ip`
    pub kind: String,
    pub value: String,
    /// `proxy`, `direct` или `block`
    pub action: String,
}

impl Default for Rule {
    fn default() -> Self {
        Rule { kind: "domain".into(), value: String::new(), action: "direct".into() }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Sub {
    pub id: String,
    pub name: String,
    pub url: String,
    /// Когда обновлялась (unix-секунды)
    pub updated: u64,
    pub count: usize,
    /// Трафик из заголовка `subscription-userinfo` (байты). `total` = 0: лимита нет или он неизвестен
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    /// Когда подписка заканчивается (unix-секунды), 0: бессрочная или неизвестно
    pub expire: u64,
    /// Была ли в ответе строка с трафиком вообще
    pub has_usage: bool,
    /// Страница подписки и поддержка из заголовков
    pub web: String,
    pub support: String,
    pub announce: String,
    /// Как часто сервис просит обновлять подписку (часы), 0: не указано
    pub interval: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// Выбранный профиль (id)
    pub active: String,
    /// `tun` или `proxy`
    pub mode: String,
    pub socks_port: u16,
    pub http_port: u16,
    /// Что делать с трафиком, который не подошёл ни под одно правило: `proxy` или `direct`
    pub default_action: String,
    /// Локальная сеть и адреса домашних устройств всегда напрямую
    pub bypass_lan: bool,
    /// DNS на адаптере TUN (запросы идут через ядро)
    pub dns: Vec<String>,
    pub rules: Vec<Rule>,
    pub subs: Vec<Sub>,
    /// Сам обновлять подписки, когда подходит срок (если VLESS с их сервером не включён)
    pub sub_auto: bool,
    pub autoconnect: bool,
    pub keep_on_exit: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            active: String::new(),
            mode: "tun".into(),
            socks_port: 10808,
            http_port: 10809,
            default_action: "proxy".into(),
            bypass_lan: true,
            dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            rules: Vec::new(),
            subs: Vec::new(),
            sub_auto: true,
            autoconnect: false,
            keep_on_exit: false,
        }
    }
}

pub(crate) fn load_config() -> Config {
    file("config.json").ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_config(c: &Config) -> Result<(), String> {
    fs::create_dir_all(data_dir()?).map_err(|e| e.to_string())?;
    fs::write(file("config.json")?, serde_json::to_string_pretty(c).map_err(|e| e.to_string())?).map_err(|e| format!("Не удалось сохранить настройки: {e}"))
}

const MAX_RULES: usize = 300;

fn has_ctrl(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

/// Проверка одного правила. Возвращает приведённое к норме правило.
pub(crate) fn sanitize_rule(r: &Rule) -> Result<Rule, String> {
    let kind = r.kind.trim().to_string();
    let action = r.action.trim().to_string();
    if !matches!(kind.as_str(), "app" | "domain" | "ip") {
        return Err("Неизвестный тип правила.".into());
    }
    if !matches!(action.as_str(), "proxy" | "direct" | "block") {
        return Err("Неизвестное действие правила.".into());
    }
    let value = r.value.trim().to_string();
    if value.is_empty() {
        return Err("В правиле не указано значение.".into());
    }
    if value.chars().count() > 200 || has_ctrl(&value) {
        return Err(format!("Неверное значение правила: «{}».", value.chars().take(40).collect::<String>()));
    }
    match kind.as_str() {
        "app" => {
            if value.contains('"') || value.contains('*') || value.contains('?') || value.contains('<') || value.contains('>') || value.contains('|') {
                return Err(format!("В имени приложения «{value}» недопустимые знаки."));
            }
        }
        "domain" => {
            if value.chars().any(|c| c.is_whitespace()) {
                return Err(format!("В домене «{value}» нельзя пробелы."));
            }
        }
        _ => {
            let ok = value.starts_with("geoip:") && value.len() > 6 && value[6..].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '!'))
                || is_cidr(&value);
            if !ok {
                return Err(format!("«{value}» не похоже на адрес или сеть. Пример: 10.0.0.0/8 или geoip:ru"));
            }
        }
    }
    Ok(Rule { kind, value, action })
}

fn is_cidr(s: &str) -> bool {
    let (ip, len) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else { return false };
    match len {
        None => true,
        Some(l) => l.parse::<u8>().map(|n| n <= if addr.is_ipv4() { 32 } else { 128 }).unwrap_or(false),
    }
}

/// Приводит настройки от интерфейса к безопасному виду. Профили выбора и подписки берутся из сохранённых.
pub(crate) fn sanitize_config(inc: &Config, stored: &Config) -> Result<Config, String> {
    let mode = if inc.mode == "proxy" { "proxy" } else { "tun" };
    if inc.socks_port < 1024 || inc.http_port < 1024 || inc.socks_port == inc.http_port {
        return Err("Порты SOCKS и HTTP должны быть разными и не меньше 1024.".into());
    }
    if inc.rules.len() > MAX_RULES {
        return Err(format!("Правил слишком много: не больше {MAX_RULES}."));
    }
    let mut rules: Vec<Rule> = Vec::new();
    for r in &inc.rules {
        let n = sanitize_rule(r)?;
        if !rules.contains(&n) {
            rules.push(n);
        }
    }
    let mut dns: Vec<String> = Vec::new();
    for d in &inc.dns {
        let t = d.trim();
        if t.is_empty() {
            continue;
        }
        if crate::dns::valid_ip(t).is_none() {
            return Err(format!("«{t}» не похож на адрес DNS-сервера."));
        }
        if !dns.contains(&t.to_string()) {
            dns.push(t.to_string());
        }
    }
    if dns.len() > 4 {
        return Err("DNS-серверов слишком много: достаточно двух.".into());
    }
    Ok(Config {
        active: stored.active.clone(),
        subs: stored.subs.clone(),
        sub_auto: inc.sub_auto,
        mode: mode.into(),
        socks_port: inc.socks_port,
        http_port: inc.http_port,
        default_action: if inc.default_action == "direct" { "direct".into() } else { "proxy".into() },
        bypass_lan: inc.bypass_lan,
        dns,
        rules,
        autoconnect: inc.autoconnect,
        keep_on_exit: inc.keep_on_exit,
    })
}

// ───────── ссылки vless:// ─────────

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Node {
    pub(crate) name: String,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) uuid: String,
    pub(crate) encryption: String,
    pub(crate) flow: String,
    pub(crate) network: String,
    pub(crate) security: String,
    pub(crate) sni: String,
    pub(crate) fp: String,
    pub(crate) pbk: String,
    pub(crate) sid: String,
    pub(crate) spx: String,
    pub(crate) pqv: String,
    pub(crate) alpn: String,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) service: String,
    pub(crate) mode: String,
    pub(crate) header: String,
    pub(crate) extra: String,
}

pub(crate) fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn is_uuid(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5 && [8, 4, 4, 4, 12].iter().zip(&p).all(|(n, x)| x.len() == *n && x.chars().all(|c| c.is_ascii_hexdigit()))
}

fn clean_name(s: &str) -> String {
    let t: String = s.chars().filter(|c| !c.is_control()).collect();
    let t = t.trim();
    t.chars().take(60).collect()
}

pub(crate) fn parse_link(link: &str) -> Result<Node, String> {
    let l = link.trim();
    let rest = l.strip_prefix("vless://").ok_or("Это не ссылка vless://")?;
    let (rest, frag) = rest.split_once('#').unwrap_or((rest, ""));
    let (main, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (user, hostport) = main.rsplit_once('@').ok_or("В ссылке нет адреса сервера (после @).")?;
    let uuid = percent_decode(user);
    if !is_uuid(&uuid) {
        return Err("Идентификатор пользователя в ссылке не похож на UUID.".into());
    }
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, p) = r.split_once(']').ok_or("Неверный адрес IPv6 в ссылке.")?;
        (h.to_string(), p.strip_prefix(':').unwrap_or("").to_string())
    } else {
        let (h, p) = hostport.rsplit_once(':').ok_or("В ссылке нет порта.")?;
        (h.to_string(), p.to_string())
    };
    let port: u16 = port.parse().ok().filter(|p| *p > 0).ok_or("Неверный порт в ссылке.")?;
    if host.is_empty() || host.len() > 253 || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')) {
        return Err("Неверный адрес сервера в ссылке.".into());
    }
    let mut q = std::collections::HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        q.insert(k.to_lowercase(), percent_decode(v));
    }
    let g = |k: &str| q.get(k).cloned().unwrap_or_default();
    let network = match g("type").to_lowercase().as_str() {
        "" | "tcp" | "raw" => "tcp".to_string(),
        "ws" => "ws".into(),
        "grpc" => "grpc".into(),
        "httpupgrade" => "httpupgrade".into(),
        "xhttp" | "splithttp" => "xhttp".into(),
        other => return Err(format!("Транспорт «{other}» не поддерживается. Бунт понимает tcp, ws, grpc, httpupgrade и xhttp.")),
    };
    let security = match g("security").to_lowercase().as_str() {
        "" | "none" => "none".to_string(),
        "tls" => "tls".into(),
        "reality" => "reality".into(),
        other => return Err(format!("Защита «{other}» не поддерживается. Бунт понимает none, tls и reality.")),
    };
    let flow = g("flow");
    if !matches!(flow.as_str(), "" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443") {
        return Err(format!("Поток «{flow}» не поддерживается."));
    }
    let encryption = if g("encryption").is_empty() { "none".to_string() } else { g("encryption") };
    if has_ctrl(&encryption) || encryption.contains('"') {
        return Err("Неверное значение encryption.".into());
    }
    let pbk = g("pbk");
    if security == "reality" && pbk.is_empty() {
        return Err("Для Reality в ссылке нужен публичный ключ (pbk).".into());
    }
    let name = clean_name(&percent_decode(frag));
    Ok(Node {
        name: if name.is_empty() { format!("{host}:{port}") } else { name },
        address: host,
        port,
        uuid,
        encryption,
        flow,
        network,
        security,
        sni: g("sni"),
        fp: if g("fp").is_empty() { "chrome".into() } else { g("fp") },
        pbk,
        sid: g("sid"),
        spx: g("spx"),
        pqv: g("pqv"),
        alpn: g("alpn"),
        host: g("host"),
        path: g("path"),
        service: g("servicename"),
        mode: g("mode"),
        header: g("headertype"),
        extra: g("extra"),
    })
}

// ───────── профили и подписки ─────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
struct Stored {
    id: String,
    name: String,
    link: String,
    /// id подписки или пусто для добавленных вручную
    sub: String,
}

/// Что видит интерфейс. Ссылка и ключи наружу не уходят.
#[derive(Serialize, Clone, Debug, Default)]
pub struct Profile {
    id: String,
    name: String,
    /// Название без флагов-эмодзи (Windows рисует их буквами)
    label: String,
    /// Код страны для флага (файл в `ui/flags`), пусто если страна не узнана
    code: String,
    sub: String,
    address: String,
    port: u16,
    network: String,
    security: String,
    flow: String,
    ok: bool,
    error: String,
}

fn link_id(link: &str) -> String {
    hex::encode(&Sha256::digest(link.trim().as_bytes())[..5])
}

fn read_profiles() -> Vec<Stored> {
    file("profiles.json").ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn write_profiles(list: &[Stored]) -> Result<(), String> {
    fs::create_dir_all(data_dir()?).map_err(|e| e.to_string())?;
    let f = file("profiles.json")?;
    fs::write(&f, serde_json::to_string(list).map_err(|e| e.to_string())?).map_err(|e| format!("Не удалось сохранить профили: {e}"))?;
    lock_down(&f);
    Ok(())
}

fn view(s: &Stored) -> Profile {
    match parse_link(&s.link) {
        Ok(n) => Profile {
            id: s.id.clone(),
            name: s.name.clone(),
            label: super::geo::label(&s.name),
            code: super::geo::code_for(&s.name, ""),
            sub: s.sub.clone(),
            address: n.address,
            port: n.port,
            network: n.network,
            security: n.security,
            flow: n.flow,
            ok: true,
            error: String::new(),
        },
        Err(e) => Profile { id: s.id.clone(), name: s.name.clone(), label: super::geo::label(&s.name), code: super::geo::code_for(&s.name, ""), sub: s.sub.clone(), error: e, ..Profile::default() },
    }
}

fn list_profiles() -> Vec<Profile> {
    read_profiles().iter().map(view).collect()
}

/// Содержимое подписки или вставленного текста: ссылки vless:// и число пропущенных строк.
pub(crate) fn parse_bundle(text: &str) -> (Vec<String>, usize) {
    use base64::Engine;
    let t = text.trim().trim_start_matches('\u{feff}');
    let plain = if t.contains("://") {
        t.to_string()
    } else {
        let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect::<String>().trim_end_matches('=').to_string();
        let e = base64::engine::general_purpose::STANDARD_NO_PAD.decode(compact.as_bytes()).or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(compact.as_bytes()));
        e.ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default()
    };
    let mut links = Vec::new();
    let mut skipped = 0;
    for line in plain.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
        if line.to_lowercase().starts_with("vless://") {
            links.push(line.to_string());
        } else {
            skipped += 1;
        }
    }
    (links, skipped)
}

/// Добавляет ссылки в список. Возвращает (добавлено, уже было, с ошибкой).
fn merge_links(links: &[String], sub: &str) -> Result<(usize, usize, usize), String> {
    let mut list = read_profiles();
    let (mut added, mut dup, mut bad) = (0, 0, 0);
    for l in links {
        match parse_link(l) {
            Ok(n) => {
                let id = link_id(l);
                if list.iter().any(|s| s.id == id) {
                    dup += 1;
                } else {
                    list.push(Stored { id, name: n.name, link: l.trim().to_string(), sub: sub.to_string() });
                    added += 1;
                }
            }
            Err(e) => {
                vlog(&format!("Ссылка пропущена: {e}"));
                bad += 1;
            }
        }
    }
    write_profiles(&list)?;
    Ok((added, dup, bad))
}

// ───────── конфиг Xray ─────────

fn tidy_app(v: &str) -> String {
    if v.contains('/') || v.contains('\\') {
        v.replace('\\', "/")
    } else if v.to_lowercase().ends_with(".exe") {
        v[..v.len() - 4].to_string()
    } else {
        v.to_string()
    }
}

fn tidy_domain(v: &str) -> String {
    let known = ["domain:", "full:", "regexp:", "geosite:", "keyword:", "dotless:", "ext:"];
    if known.iter().any(|k| v.starts_with(k)) {
        v.to_string()
    } else {
        format!("domain:{}", v.trim_start_matches("*.").trim_start_matches('.'))
    }
}

fn tag_of(action: &str) -> &'static str {
    match action {
        "direct" => "direct",
        "block" => "block",
        _ => "proxy",
    }
}

/// Правила маршрутизации Xray: свои процессы напрямую, локальная сеть, правила пользователя, затем «по умолчанию».
pub(crate) fn build_rules(cfg: &Config) -> Vec<Value> {
    let mut rules: Vec<Value> = vec![json!({ "type": "field", "process": ["self/"], "outboundTag": "direct" })];
    if cfg.bypass_lan {
        rules.push(json!({ "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" }));
    }
    for r in &cfg.rules {
        let tag = tag_of(&r.action);
        rules.push(match r.kind.as_str() {
            "app" => json!({ "type": "field", "process": [tidy_app(&r.value)], "outboundTag": tag }),
            "ip" => json!({ "type": "field", "ip": [r.value], "outboundTag": tag }),
            _ => json!({ "type": "field", "domain": [tidy_domain(&r.value)], "outboundTag": tag }),
        });
    }
    rules.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": tag_of(&cfg.default_action) }));
    rules
}

fn stream_settings(n: &Node) -> Value {
    let mut s = json!({ "network": n.network, "security": n.security });
    let host_or_sni = if n.sni.is_empty() { n.address.clone() } else { n.sni.clone() };
    match n.security.as_str() {
        "tls" => {
            let mut t = json!({ "serverName": host_or_sni, "fingerprint": n.fp });
            if !n.alpn.is_empty() {
                t["alpn"] = json!(n.alpn.split(',').map(|a| a.trim()).filter(|a| !a.is_empty()).collect::<Vec<_>>());
            }
            s["tlsSettings"] = t;
        }
        "reality" => {
            let mut r = json!({ "serverName": n.sni, "fingerprint": n.fp, "publicKey": n.pbk, "shortId": n.sid, "spiderX": n.spx });
            if !n.pqv.is_empty() {
                r["mldsa65Verify"] = json!(n.pqv);
            }
            s["realitySettings"] = r;
        }
        _ => {}
    }
    let path = if n.path.is_empty() { "/".to_string() } else { n.path.clone() };
    match n.network.as_str() {
        "ws" => {
            let mut w = json!({ "path": path });
            if !n.host.is_empty() {
                w["headers"] = json!({ "Host": n.host });
            }
            s["wsSettings"] = w;
        }
        "grpc" => s["grpcSettings"] = json!({ "serviceName": n.service, "multiMode": n.mode == "multi" }),
        "httpupgrade" => {
            let mut w = json!({ "path": path });
            if !n.host.is_empty() {
                w["host"] = json!(n.host);
            }
            s["httpupgradeSettings"] = w;
        }
        "xhttp" => {
            let mut w = json!({ "path": path, "mode": if n.mode.is_empty() { "auto" } else { n.mode.as_str() } });
            if !n.host.is_empty() {
                w["host"] = json!(n.host);
            }
            if let Ok(e) = serde_json::from_str::<Value>(&n.extra) {
                if e.is_object() {
                    w["extra"] = e;
                }
            }
            s["xhttpSettings"] = w;
        }
        _ => {
            if n.header == "http" {
                let mut req = json!({ "path": [path] });
                if !n.host.is_empty() {
                    req["headers"] = json!({ "Host": [n.host] });
                }
                s["tcpSettings"] = json!({ "header": { "type": "http", "request": req } });
            }
        }
    }
    s
}

/// Полный конфиг ядра. `addr`: адрес сервера, уже превращённый в IP (ядру не нужен DNS, чтобы дозвониться).
pub(crate) fn build_config(n: &Node, addr: &str, cfg: &Config, tun: bool) -> Value {
    let sniff = json!({ "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true });
    let inbounds = if tun {
        json!([{
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": TUN_NAME,
                "mtu": 1500,
                "gateway": [format!("{TUN_IP}/30")],
                "dns": cfg.dns,
                "autoSystemRoutingTable": ["0.0.0.0/1", "128.0.0.0/1"],
                "autoOutboundsInterface": "auto"
            },
            "sniffing": sniff
        }])
    } else {
        json!([
            { "tag": "socks-in", "listen": "127.0.0.1", "port": cfg.socks_port, "protocol": "socks", "settings": { "udp": true, "auth": "noauth" }, "sniffing": sniff },
            { "tag": "http-in", "listen": "127.0.0.1", "port": cfg.http_port, "protocol": "http", "sniffing": sniff }
        ])
    };
    let mut user = json!({ "id": n.uuid, "encryption": n.encryption });
    if !n.flow.is_empty() {
        user["flow"] = json!(n.flow);
    }
    let mut stream = stream_settings(n);
    if n.address != addr && n.security == "tls" {
        // Адрес заменён на IP, но имя для сертификата остаётся прежним
        if stream["tlsSettings"]["serverName"].as_str().unwrap_or("").is_empty() {
            stream["tlsSettings"]["serverName"] = json!(n.address);
        }
    }
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": inbounds,
        "outbounds": [
            { "tag": "proxy", "protocol": "vless", "settings": { "vnext": [{ "address": addr, "port": n.port, "users": [user] }] }, "streamSettings": stream },
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" }
        ],
        "routing": { "domainStrategy": "AsIs", "rules": build_rules(cfg) }
    })
}

/// Превращает адрес сервера в IP. Если это уже IP, возвращает его же.
fn resolve(host: &str, port: u16) -> Result<String, String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(|e| format!("Не удалось найти адрес сервера {host}: {e}"))?.collect();
    addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).map(|a| a.ip().to_string()).ok_or_else(|| format!("Не удалось найти адрес сервера {host}."))
}

// ───────── сессия ─────────

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct ProxyPrev {
    enable: u32,
    server: Option<String>,
    overr: Option<String>,
    ours: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Session {
    active: bool,
    tun: bool,
    gateway: String,
    adapters: Vec<crate::fptn::AdapterDns>,
    proxy: Option<ProxyPrev>,
}

fn read_session() -> Session {
    file("session.json").ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn write_session(s: &Session) {
    if let (Ok(dir), Ok(f)) = (data_dir(), file("session.json")) {
        let _ = fs::create_dir_all(dir);
        let _ = fs::write(f, serde_json::to_string(s).unwrap_or_default());
    }
}

// ───────── системный прокси Windows ─────────

const INET_KEY: &str = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const NOTIFY: &str = "Add-Type -Namespace B -Name W -MemberDefinition '[System.Runtime.InteropServices.DllImport(\"wininet.dll\")] public static extern bool InternetSetOption(System.IntPtr h,int o,System.IntPtr b,int l);'; [B.W]::InternetSetOption([System.IntPtr]::Zero,39,[System.IntPtr]::Zero,0) | Out-Null; [B.W]::InternetSetOption([System.IntPtr]::Zero,37,[System.IntPtr]::Zero,0) | Out-Null";

fn read_proxy() -> Option<ProxyPrev> {
    let script = format!(
        "$p=Get-ItemProperty '{INET_KEY}'; [pscustomobject]@{{enable=[int]$p.ProxyEnable;server=$p.ProxyServer;overr=$p.ProxyOverride}} | ConvertTo-Json -Compress"
    );
    let out = ps(&script)?;
    let v: Value = serde_json::from_str(out[out.find('{')?..].trim()).ok()?;
    Some(ProxyPrev {
        enable: v.get("enable").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        server: v.get("server").and_then(|x| x.as_str()).map(|s| s.to_string()),
        overr: v.get("overr").and_then(|x| x.as_str()).map(|s| s.to_string()),
        ours: String::new(),
    })
}

fn proxy_value(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

fn set_proxy_script(port: u16) -> String {
    format!(
        "Set-ItemProperty '{INET_KEY}' ProxyServer '{}'; Set-ItemProperty '{INET_KEY}' ProxyOverride '<local>;localhost;127.*;10.*;192.168.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*'; Set-ItemProperty '{INET_KEY}' ProxyEnable 1 -Type DWord; {NOTIFY}",
        proxy_value(port)
    )
}

/// Возвращает прежний системный прокси, если за это время его не сменили вручную.
fn restore_proxy_script(prev: &ProxyPrev) -> String {
    let mut s = format!("$p=Get-ItemProperty '{INET_KEY}'; if([string]$p.ProxyServer -eq '{}'){{ ", ps_quote(&prev.ours));
    match &prev.server {
        Some(v) => s += &format!("Set-ItemProperty '{INET_KEY}' ProxyServer '{}'; ", ps_quote(v)),
        None => s += &format!("Remove-ItemProperty '{INET_KEY}' ProxyServer -ErrorAction SilentlyContinue; "),
    }
    match &prev.overr {
        Some(v) => s += &format!("Set-ItemProperty '{INET_KEY}' ProxyOverride '{}'; ", ps_quote(v)),
        None => s += &format!("Remove-ItemProperty '{INET_KEY}' ProxyOverride -ErrorAction SilentlyContinue; "),
    }
    s += &format!("Set-ItemProperty '{INET_KEY}' ProxyEnable {} -Type DWord }}; {NOTIFY}", prev.enable.min(1));
    s
}

/// Убирает за ядром: системный прокси и, в режиме TUN, маршруты, DNS и адаптер.
fn repair() -> Result<String, String> {
    let sess = read_session();
    let mut notes: Vec<String> = Vec::new();
    if let Some(prev) = &sess.proxy {
        let _ = ps(&restore_proxy_script(prev));
        notes.push("системный прокси возвращён".into());
    }
    let mut msg = String::new();
    if sess.tun {
        let gw = if sess.gateway.parse::<std::net::Ipv4Addr>().is_ok() { sess.gateway.clone() } else { String::new() };
        let script = crate::fptn::repair_script(TUN_IP, TUN_NAME, &gw, &sess.adapters, true);
        let out = ps(&script).ok_or("Не удалось выполнить очистку сети (PowerShell)")?;
        let rep = out.find('{').and_then(|i| serde_json::from_str::<Value>(out[i..].trim()).ok());
        msg = match rep.as_ref().and_then(|v| v.get("gateway")).and_then(|x| x.as_str()) {
            Some(g) if !g.is_empty() => format!("Сеть восстановлена: основной шлюз {g}."),
            Some(_) => "Следы TUN убраны, но основной шлюз не найден: проверьте кабель или Wi-Fi.".into(),
            None => "Следы TUN убраны.".into(),
        };
    }
    let mut s = sess;
    s.active = false;
    s.proxy = None;
    write_session(&s);
    clean_run();
    if msg.is_empty() {
        msg = if notes.is_empty() { "VLESS отключён.".into() } else { format!("VLESS отключён: {}.", notes.join(", ")) };
    }
    Ok(msg)
}

fn clean_run() {
    if let Ok(d) = run_dir() {
        let _ = fs::remove_dir_all(d);
    }
}

// ───────── процесс ─────────

fn our_pids() -> Vec<u32> {
    crate::zapret::list_procs("xray").into_iter().filter(|(_, p)| crate::zapret::is_ours(p)).map(|(id, _)| id).collect()
}

pub(crate) fn is_running() -> bool {
    running()
}

fn running() -> bool {
    let own = {
        let mut g = CHILD.lock().unwrap();
        match g.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    };
    own || !our_pids().is_empty()
}

fn stop_process() {
    if let Some(mut c) = CHILD.lock().unwrap().take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    for pid in our_pids() {
        crate::zapret::kill_pid(pid);
    }
}

fn exe_path() -> Result<PathBuf, String> {
    let exe = crate::modules::active_dir("vless")?.join(EXE);
    if !exe.is_file() {
        return Err("Не найден xray.exe. Переустановите компонент.".into());
    }
    Ok(exe)
}

fn adapter_exists() -> bool {
    ps(&format!("if(Get-NetAdapter -Name '{TUN_NAME}' -ErrorAction SilentlyContinue){{ 'yes' }}")).map(|o| o.contains("yes")).unwrap_or(false)
}

fn port_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn tail_lines(text: &str, n: usize) -> String {
    let l: Vec<&str> = text.lines().collect();
    l[l.len().saturating_sub(n)..].join("\n")
}

/// Последняя понятная ошибка из вывода ядра.
pub(crate) fn last_error(text: &str) -> String {
    text.lines()
        .rev()
        .find(|l| {
            let t = l.to_lowercase();
            t.contains("failed") || t.contains("error") || t.contains("panic") || t.contains("invalid")
        })
        .map(|l| l.trim().chars().take(300).collect())
        .unwrap_or_default()
}

fn connect_blocking(id: &str) -> Result<(), String> {
    let mut cfg = load_config();
    let tun = cfg.mode != "proxy";
    if tun {
        crate::fptn::require_admin()?;
    }
    // Два VPN сразу делят маршруты и ломают сеть: второй не включаем
    if crate::fptn::is_running() {
        return Err("FPTN сейчас включён. Отключите его, прежде чем включать VLESS: два VPN сразу ломают маршруты.".into());
    }
    if crate::wg::is_running() {
        return Err("WireGuard / AmneziaWG сейчас включён. Отключите его, прежде чем включать VLESS: два VPN сразу ломают маршруты.".into());
    }
    let exe = exe_path()?;
    if running() {
        return Ok(());
    }
    let stored = read_profiles().into_iter().find(|s| s.id == id).ok_or("Профиль не найден.")?;
    let node = parse_link(&stored.link)?;
    if !tun && (!port_free(cfg.socks_port) || !port_free(cfg.http_port)) {
        return Err(format!("Порт {} или {} уже занят другой программой. Измените порты в настройках раздела.", cfg.socks_port, cfg.http_port));
    }
    if read_session().active {
        let _ = repair();
    }
    let addr = resolve(&node.address, node.port)?;
    let pr = if tun { crate::fptn::probe().ok() } else { None };
    let prev = if tun { None } else { read_proxy().map(|mut p| { p.ours = proxy_value(cfg.http_port); p }) };
    write_session(&Session {
        active: true,
        tun,
        gateway: pr.as_ref().map(|p| p.gateway.clone()).unwrap_or_default(),
        adapters: pr.as_ref().map(|p| p.adapters.clone()).unwrap_or_default(),
        proxy: prev.clone(),
    });
    cfg.active = id.to_string();
    vlog(&format!("Подключаю «{}» ({}:{}, {}, {}), режим {}.", stored.name, node.address, node.port, node.network, node.security, if tun { "TUN" } else { "системный прокси" }));

    let fail = |msg: String| -> String {
        stop_process();
        let _ = repair();
        msg
    };
    let rdir = run_dir()?;
    fs::create_dir_all(&rdir).map_err(|e| e.to_string())?;
    let conf = rdir.join("config.json");
    fs::write(&conf, serde_json::to_string_pretty(&build_config(&node, &addr, &cfg, tun)).map_err(|e| e.to_string())?).map_err(|e| format!("Не удалось записать конфиг: {e}"))?;
    lock_down(&rdir);
    let dir = exe.parent().map(|p| p.to_path_buf()).unwrap_or_default();

    // Проверка конфига до запуска: понятная ошибка вместо молчаливого вылета
    let mut test = Command::new(&exe);
    test.args(["run", "-test", "-config"]).arg(&conf).current_dir(&dir).env("XRAY_LOCATION_ASSET", &dir);
    #[cfg(windows)]
    test.creation_flags(CREATE_NO_WINDOW);
    let t = test.output().map_err(|e| fail(format!("Не удалось запустить xray.exe: {e}")))?;
    if !t.status.success() {
        let mut txt = String::from_utf8_lossy(&t.stdout).to_string();
        txt.push_str(&String::from_utf8_lossy(&t.stderr));
        let why = last_error(&txt);
        vlog(&format!("Проверка конфига: {}", tail_lines(&txt, 8)));
        return Err(fail(format!("Ядро не приняло конфиг: {}", if why.is_empty() { "подробности в журнале".to_string() } else { why })));
    }

    fs::create_dir_all(data_dir()?).map_err(|e| e.to_string())?;
    let logf = fs::File::create(file("xray.log")?).map_err(|e| e.to_string())?;
    let errf = logf.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&exe);
    cmd.args(["run", "-config"]).arg(&conf).current_dir(&dir).env("XRAY_LOCATION_ASSET", &dir).stdin(Stdio::null()).stdout(Stdio::from(logf)).stderr(Stdio::from(errf));
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let child = cmd.spawn().map_err(|e| fail(format!("Не удалось запустить Xray: {e}")))?;
    *CHILD.lock().unwrap() = Some(child);

    let started = Instant::now();
    let mut ready = false;
    while started.elapsed() < Duration::from_secs(25) {
        std::thread::sleep(Duration::from_millis(500));
        let exited = {
            let mut g = CHILD.lock().unwrap();
            matches!(g.as_mut().map(|c| c.try_wait()), Some(Ok(Some(_))))
        };
        if exited {
            let log = fs::read_to_string(file("xray.log")?).unwrap_or_default();
            let why = last_error(&log);
            return Err(fail(if why.is_empty() { "Xray завершился сразу после запуска. Подробности в журнале.".into() } else { format!("Xray завершился: {why}") }));
        }
        let up = if tun { adapter_exists() } else { TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], cfg.socks_port)), Duration::from_millis(300)).is_ok() };
        if up {
            ready = true;
            break;
        }
    }
    if !ready {
        let log = fs::read_to_string(file("xray.log")?).unwrap_or_default();
        let why = last_error(&log);
        return Err(fail(format!("Xray не поднялся за 25 секунд.{}", if why.is_empty() { String::new() } else { format!(" {why}") })));
    }
    // Ядро могло упасть сразу после старта (нет wintun.dll, нет прав на адаптер)
    std::thread::sleep(Duration::from_millis(1200));
    if !running() {
        let log = fs::read_to_string(file("xray.log")?).unwrap_or_default();
        let why = last_error(&log);
        return Err(fail(if why.is_empty() { "Xray остановился сразу после запуска.".into() } else { format!("Xray остановился: {why}") }));
    }
    if !tun {
        let _ = ps(&set_proxy_script(cfg.http_port));
        vlog(&format!("Системный прокси включён: {}.", proxy_value(cfg.http_port)));
    }
    save_config(&cfg)?;
    vlog("VLESS подключён.");
    Ok(())
}

fn disconnect_blocking() -> Result<String, String> {
    stop_process();
    std::thread::sleep(Duration::from_millis(700));
    vlog("Ядро остановлено.");
    repair()
}

/// Полная остановка: при установке, обновлении и удалении компонента.
pub fn stop_all() {
    if running() || read_session().active {
        let _ = disconnect_blocking();
    }
}

/// Вызывается при выходе из Бунта.
pub fn shutdown() {
    if load_config().keep_on_exit {
        return;
    }
    stop_all();
}

// ───────── пинг и список процессов ─────────

#[derive(Serialize, Debug, PartialEq)]
pub struct Proc {
    name: String,
    path: String,
}

/// Разбор строк `имя|путь`: по одной записи на имя процесса, без системных папок.
pub(crate) fn parse_procs(text: &str) -> Vec<Proc> {
    let mut out: Vec<Proc> = Vec::new();
    for l in text.lines() {
        let Some((n, p)) = l.trim().split_once('|') else { continue };
        let (n, p) = (n.trim(), p.trim());
        if n.is_empty() || p.is_empty() || has_ctrl(n) || has_ctrl(p) {
            continue;
        }
        let low = p.to_lowercase().replace('/', "\\");
        if low.starts_with("c:\\windows\\") || low.contains("\\windowsapps\\microsoft.") {
            continue;
        }
        if !out.iter().any(|x| x.name == n) {
            out.push(Proc { name: n.to_string(), path: p.to_string() });
        }
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

fn procs_blocking() -> Vec<Proc> {
    ps("Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | ForEach-Object { $_.ProcessName + '|' + $_.Path }").map(|t| parse_procs(&t)).unwrap_or_default()
}

// ───────── команды ─────────

#[derive(Serialize)]
pub struct Info {
    running: bool,
    /// Режим работающего ядра
    tun: bool,
    /// Прошлая сессия не закрыта: сеть или системный прокси могли остаться изменёнными
    dirty: bool,
    profiles: Vec<Profile>,
    config: Config,
    #[serde(rename = "adapter")]
    adapter_up: bool,
}

#[derive(Serialize)]
pub struct Done {
    info: Info,
    message: String,
}

fn info() -> Info {
    let config = load_config();
    let running = running();
    let sess = read_session();
    Info {
        running,
        tun: if running { config.mode != "proxy" } else { false },
        dirty: !running && sess.active,
        profiles: list_profiles(),
        adapter_up: running && config.mode != "proxy" && cfg!(windows) && adapter_exists(),
        config,
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn vless_status() -> Result<Info, String> {
    blocking(|| Ok(info())).await
}

#[tauri::command]
pub async fn vless_connect(id: String) -> Result<Info, String> {
    blocking(move || {
        connect_blocking(&id)?;
        Ok(info())
    })
    .await
}

#[tauri::command]
pub async fn vless_disconnect() -> Result<Done, String> {
    blocking(|| {
        let message = disconnect_blocking()?;
        Ok(Done { info: info(), message })
    })
    .await
}

#[tauri::command]
pub async fn vless_repair() -> Result<Done, String> {
    blocking(|| {
        if running() {
            return Err("VLESS сейчас включён: сначала отключите его.".into());
        }
        let message = repair()?;
        Ok(Done { info: info(), message })
    })
    .await
}

#[derive(Serialize)]
pub struct Imported {
    info: Info,
    message: String,
}

fn report(added: usize, dup: usize, bad: usize, skipped: usize) -> String {
    let mut m = format!("Добавлено профилей: {added}.");
    if dup > 0 {
        m += &format!(" Уже были: {dup}.");
    }
    if bad > 0 {
        m += &format!(" Не удалось прочитать: {bad}.");
    }
    if skipped > 0 {
        m += &format!(" Пропущено строк других протоколов: {skipped}.");
    }
    m
}

/// Ссылки vless:// или текст подписки (в том числе в base64).
#[tauri::command]
pub async fn vless_import(text: String) -> Result<Imported, String> {
    blocking(move || {
        let (links, skipped) = parse_bundle(&text);
        if links.is_empty() {
            return Err("Не нашёл ссылок vless://. Вставьте ссылку целиком, например vless://…".into());
        }
        let (added, dup, bad) = merge_links(&links, "")?;
        if added + dup == 0 {
            return Err("Ни одну ссылку не удалось прочитать. Подробности в журнале.".into());
        }
        let mut c = load_config();
        if c.active.is_empty() || !read_profiles().iter().any(|s| s.id == c.active) {
            if let Some(f) = read_profiles().first() {
                c.active = f.id.clone();
                let _ = save_config(&c);
            }
        }
        Ok(Imported { info: info(), message: report(added, dup, bad, skipped) })
    })
    .await
}

#[tauri::command]
pub async fn vless_delete(ids: Vec<String>) -> Result<Info, String> {
    blocking(move || {
        let cfg = load_config();
        if running() && ids.contains(&cfg.active) {
            return Err("Этот профиль сейчас используется: сначала отключите VLESS.".into());
        }
        let list: Vec<Stored> = read_profiles().into_iter().filter(|s| !ids.contains(&s.id)).collect();
        write_profiles(&list)?;
        let mut c = cfg;
        if !list.iter().any(|s| s.id == c.active) {
            c.active = list.first().map(|s| s.id.clone()).unwrap_or_default();
            save_config(&c)?;
        }
        Ok(info())
    })
    .await
}

#[tauri::command]
pub async fn vless_select(id: String) -> Result<Info, String> {
    blocking(move || {
        if !read_profiles().iter().any(|s| s.id == id) {
            return Err("Профиль не найден.".into());
        }
        let mut c = load_config();
        c.active = id;
        save_config(&c)?;
        Ok(info())
    })
    .await
}

#[tauri::command]
pub async fn vless_config_set(config: Config) -> Result<Info, String> {
    blocking(move || {
        let c = sanitize_config(&config, &load_config())?;
        save_config(&c)?;
        Ok(info())
    })
    .await
}

/// Описание профиля без ключей.
#[tauri::command]
pub async fn vless_profile_view(id: String) -> Result<String, String> {
    blocking(move || {
        let s = read_profiles().into_iter().find(|s| s.id == id).ok_or("Профиль не найден.")?;
        let n = parse_link(&s.link)?;
        let mut t = format!("Имя: {}\nСервер: {}:{}\nТранспорт: {}\nЗащита: {}\n", s.name, n.address, n.port, n.network, n.security);
        if !n.flow.is_empty() {
            t += &format!("Поток: {}\n", n.flow);
        }
        if !n.sni.is_empty() {
            t += &format!("SNI: {}\n", n.sni);
        }
        if n.security == "reality" || n.security == "tls" {
            t += &format!("Отпечаток: {}\n", n.fp);
        }
        if !n.host.is_empty() {
            t += &format!("Host: {}\n", n.host);
        }
        if !n.path.is_empty() {
            t += &format!("Путь: {}\n", n.path);
        }
        if !n.service.is_empty() {
            t += &format!("Служба gRPC: {}\n", n.service);
        }
        t += "UUID и ключи скрыты.";
        Ok(t)
    })
    .await
}

/// Пинг одного сервера: время установки TCP-соединения, лучший из двух замеров. `None`: нет ответа.
#[tauri::command]
pub async fn vless_ping_one(id: String) -> Result<Option<u32>, String> {
    blocking(move || {
        let s = read_profiles().into_iter().find(|s| s.id == id).ok_or("Такого сервера нет.")?;
        Ok(parse_link(&s.link).ok().and_then(|n| crate::fptn::tcp_ping(&n.address, n.port)))
    })
    .await
}

#[tauri::command]
pub async fn vless_processes() -> Result<Vec<Proc>, String> {
    blocking(|| Ok(procs_blocking())).await
}

#[tauri::command]
pub async fn vless_log() -> Result<String, String> {
    blocking(|| {
        let ours = file("vless.log").ok().and_then(|p| fs::read_to_string(p).ok()).unwrap_or_default();
        let core = file("xray.log").ok().and_then(|p| fs::read_to_string(p).ok()).unwrap_or_default();
        Ok(format!("{}\n\n— ядро Xray —\n{}", tail_lines(&ours, 60), tail_lines(&core, 60)).trim().to_string())
    })
    .await
}

// ───────── подписки ─────────

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Что сервис подписки сообщает в заголовках ответа.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct SubMeta {
    pub(crate) title: String,
    pub(crate) upload: u64,
    pub(crate) download: u64,
    pub(crate) total: u64,
    pub(crate) expire: u64,
    pub(crate) has_usage: bool,
    pub(crate) web: String,
    pub(crate) support: String,
    pub(crate) announce: String,
    pub(crate) interval: u64,
}

/// `upload=1; download=2; total=3; expire=4` (значения иногда дробные).
fn parse_userinfo(s: &str) -> Option<(u64, u64, u64, u64)> {
    let (mut up, mut down, mut total, mut exp) = (0, 0, 0, 0);
    let mut any = false;
    for part in s.split(';') {
        let Some((k, v)) = part.split_once('=') else { continue };
        let Some(n) = v.trim().parse::<f64>().ok().filter(|x| x.is_finite() && *x >= 0.0) else { continue };
        let n = n as u64;
        match k.trim().to_ascii_lowercase().as_str() {
            "upload" => up = n,
            "download" => down = n,
            "total" => total = n,
            "expire" => exp = n,
            _ => continue,
        }
        any = true;
    }
    any.then_some((up, down, total, exp))
}

/// Текст из заголовка: `base64:…` раскодируется, остальное остаётся как есть.
fn header_text(v: &str) -> String {
    use base64::Engine;
    let t = v.trim();
    if let Some(b) = t.strip_prefix("base64:") {
        let b: String = b.trim().chars().filter(|c| !c.is_whitespace() && *c != '=').collect();
        for eng in [&base64::engine::general_purpose::STANDARD_NO_PAD, &base64::engine::general_purpose::URL_SAFE_NO_PAD] {
            if let Ok(raw) = eng.decode(b.as_bytes()) {
                if let Ok(s) = String::from_utf8(raw) {
                    return clean_name(&s);
                }
            }
        }
        return String::new();
    }
    clean_name(&percent_decode(t))
}

fn header_url(v: &str) -> String {
    let t = v.trim();
    if valid_sub_url(t) { t.to_string() } else { String::new() }
}

/// Разбор заголовков. `get` отдаёт значение заголовка по имени в нижнем регистре.
pub(crate) fn parse_meta(get: impl Fn(&str) -> Option<String>) -> SubMeta {
    let mut m = SubMeta::default();
    if let Some((u, d, t, e)) = get("subscription-userinfo").as_deref().and_then(parse_userinfo) {
        m.upload = u;
        m.download = d;
        m.total = t;
        m.expire = e;
        m.has_usage = true;
    }
    m.title = get("profile-title").map(|v| header_text(&v)).unwrap_or_default();
    m.web = get("profile-web-page-url").map(|v| header_url(&v)).unwrap_or_default();
    m.support = get("support-url").map(|v| header_url(&v)).unwrap_or_default();
    m.announce = get("announce").map(|v| header_text(&v)).unwrap_or_default();
    m.interval = get("profile-update-interval").and_then(|v| v.trim().parse::<u64>().ok()).filter(|h| (1..=720).contains(h)).unwrap_or(0);
    m
}

async fn fetch_sub(url: &str) -> Result<(String, SubMeta), String> {
    let resp = crate::modules::client()?.get(url).send().await.map_err(|e| format!("Не удалось скачать подписку: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Подписка: сервер ответил {}", resp.status()));
    }
    let meta = parse_meta(|name| resp.headers().get(name).map(|v| String::from_utf8_lossy(v.as_bytes()).to_string()));
    let bytes = resp.bytes().await.map_err(|e| format!("Обрыв загрузки подписки: {e}"))?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("Подписка слишком большая.".into());
    }
    Ok((String::from_utf8_lossy(&bytes).to_string(), meta))
}

fn fill_meta(sub: &mut Sub, m: &SubMeta) {
    sub.upload = m.upload;
    sub.download = m.download;
    sub.total = m.total;
    sub.expire = m.expire;
    sub.has_usage = m.has_usage;
    sub.web = m.web.clone();
    sub.support = m.support.clone();
    sub.announce = m.announce.clone();
    sub.interval = m.interval;
}

/// Имя сервера из адреса подписки: `https://sub.example.com/x` → `sub.example.com`.
fn url_host(u: &str) -> String {
    let t = u.split("://").nth(1).unwrap_or(u);
    let t = t.split(['/', '?', '#']).next().unwrap_or("");
    let t = t.rsplit('@').next().unwrap_or(t);
    t.split(':').next().unwrap_or("").to_string()
}

/// Заменяет профили подписки свежими. Свои профили и выбор сохраняются.
fn apply_sub(sub_id: &str, links: &[String]) -> Result<(usize, usize), String> {
    let old: Vec<Stored> = read_profiles();
    let mut list: Vec<Stored> = old.iter().filter(|s| s.sub != sub_id).cloned().collect();
    let mut count = 0;
    for l in links {
        if let Ok(n) = parse_link(l) {
            let id = link_id(l);
            if !list.iter().any(|s| s.id == id) {
                list.push(Stored { id, name: n.name, link: l.trim().to_string(), sub: sub_id.to_string() });
                count += 1;
            }
        }
    }
    let removed = old.iter().filter(|s| s.sub == sub_id && !list.iter().any(|n| n.id == s.id)).count();
    write_profiles(&list)?;
    let mut c = load_config();
    if !list.iter().any(|s| s.id == c.active) {
        c.active = list.first().map(|s| s.id.clone()).unwrap_or_default();
        save_config(&c)?;
    }
    Ok((count, removed))
}

fn valid_sub_url(u: &str) -> bool {
    (u.starts_with("https://") || u.starts_with("http://")) && u.len() < 2000 && !u.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[tauri::command]
pub async fn vless_sub_add(name: String, url: String) -> Result<Imported, String> {
    let url = url.trim().to_string();
    if !valid_sub_url(&url) {
        return Err("Адрес подписки должен начинаться с https://".into());
    }
    let (text, meta) = fetch_sub(&url).await?;
    blocking(move || {
        let (links, skipped) = parse_bundle(&text);
        if links.is_empty() {
            return Err("В подписке нет ссылок vless://. Другие протоколы Бунт пока не понимает.".into());
        }
        let mut c = load_config();
        let id = link_id(&url);
        if c.subs.iter().any(|s| s.id == id) {
            return Err("Эта подписка уже добавлена. Обновите её кнопкой.".into());
        }
        let (count, _) = apply_sub(&id, &links)?;
        let mut nm = clean_name(&name);
        if nm.is_empty() {
            nm = meta.title.clone();
        }
        if nm.is_empty() {
            nm = clean_name(&url_host(&url));
        }
        c = load_config();
        let mut sub = Sub { id, name: if nm.is_empty() { "Подписка".into() } else { nm }, url, updated: now(), count, ..Sub::default() };
        fill_meta(&mut sub, &meta);
        c.subs.push(sub);
        save_config(&c)?;
        Ok(Imported { info: info(), message: format!("Подписка добавлена. {}", report(count, 0, 0, skipped)) })
    })
    .await
}

#[tauri::command]
pub async fn vless_sub_refresh(id: String) -> Result<Imported, String> {
    let url = load_config().subs.into_iter().find(|s| s.id == id).map(|s| s.url).ok_or("Подписка не найдена.")?;
    let (text, meta) = fetch_sub(&url).await?;
    blocking(move || {
        let (links, skipped) = parse_bundle(&text);
        if links.is_empty() {
            return Err("В обновлённой подписке нет ссылок vless://. Старые профили оставлены.".into());
        }
        if running() && read_profiles().iter().any(|s| s.sub == id && s.id == load_config().active) {
            // Работающий профиль не трогаем: после отключения обновление применится
            return Err("Профиль этой подписки сейчас включён. Отключите VLESS и обновите подписку.".into());
        }
        let (count, removed) = apply_sub(&id, &links)?;
        let mut c = load_config();
        if let Some(s) = c.subs.iter_mut().find(|s| s.id == id) {
            s.updated = now();
            s.count = count;
            fill_meta(s, &meta);
        }
        save_config(&c)?;
        let mut m = format!("Подписка обновлена: профилей {count}.");
        if removed > 0 {
            m += &format!(" Убрано пропавших: {removed}.");
        }
        if skipped > 0 {
            m += &format!(" Пропущено строк других протоколов: {skipped}.");
        }
        Ok(Imported { info: info(), message: m })
    })
    .await
}

/// Открывает в браузере страницу подписки или поддержки из заголовков подписки. Адрес берётся из сохранённых данных, а не от окна.
#[tauri::command]
pub async fn vless_sub_open(id: String, what: String) -> Result<(), String> {
    blocking(move || {
        let sub = load_config().subs.into_iter().find(|s| s.id == id).ok_or("Подписка не найдена.")?;
        let url = if what == "support" { sub.support } else { sub.web };
        if !valid_sub_url(&url) {
            return Err("У подписки нет такой ссылки.".into());
        }
        crate::settings::launch(&url)
    })
    .await
}

#[tauri::command]
pub async fn vless_sub_remove(id: String) -> Result<Info, String> {
    blocking(move || {
        let cfg = load_config();
        if running() && read_profiles().iter().any(|s| s.sub == id && s.id == cfg.active) {
            return Err("Профиль этой подписки сейчас включён. Сначала отключите VLESS.".into());
        }
        let list: Vec<Stored> = read_profiles().into_iter().filter(|s| s.sub != id).collect();
        write_profiles(&list)?;
        let mut c = cfg;
        c.subs.retain(|s| s.id != id);
        if !list.iter().any(|s| s.id == c.active) {
            c.active = list.first().map(|s| s.id.clone()).unwrap_or_default();
        }
        save_config(&c)?;
        Ok(info())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "11111111-2222-3333-4444-555555555555";

    fn link(q: &str) -> String {
        format!("vless://{UUID}@example.com:443?{q}#My%20Server")
    }

    #[test]
    fn subscription_headers() {
        use std::collections::HashMap;
        let mut h: HashMap<&str, &str> = HashMap::new();
        h.insert("subscription-userinfo", "upload=455727941; download=6174315083.5; total=1073741824000; expire=2218532293");
        h.insert("profile-title", "base64:0KLQtdGB0YI=");
        h.insert("profile-web-page-url", "https://panel.example.com/sub/abc");
        h.insert("support-url", "javascript:alert(1)");
        h.insert("profile-update-interval", "12");
        let m = parse_meta(|k| h.get(k).map(|v| v.to_string()));
        assert_eq!((m.upload, m.download, m.total, m.expire, m.has_usage), (455727941, 6174315083, 1073741824000, 2218532293, true));
        assert_eq!(m.title, "Тест");
        assert_eq!(m.web, "https://panel.example.com/sub/abc");
        assert_eq!(m.support, "");
        assert_eq!(m.interval, 12);
        let none = parse_meta(|_| None);
        assert!(!none.has_usage && none.total == 0 && none.title.is_empty());
        assert_eq!(parse_userinfo("total=0"), Some((0, 0, 0, 0)));
        assert_eq!(parse_userinfo("мусор"), None);
        assert_eq!(url_host("https://user@sub.example.com:8443/x?y=1"), "sub.example.com");
    }

    #[test]
    fn parses_reality_link() {
        let n = parse_link(&link("type=tcp&security=reality&pbk=KEY&fp=firefox&sni=google.com&sid=ab12&spx=%2F&flow=xtls-rprx-vision&encryption=none")).unwrap();
        assert_eq!(n.name, "My Server");
        assert_eq!((n.address.as_str(), n.port, n.uuid.as_str()), ("example.com", 443, UUID));
        assert_eq!((n.network.as_str(), n.security.as_str(), n.flow.as_str()), ("tcp", "reality", "xtls-rprx-vision"));
        assert_eq!((n.pbk.as_str(), n.fp.as_str(), n.sni.as_str(), n.sid.as_str(), n.spx.as_str()), ("KEY", "firefox", "google.com", "ab12", "/"));
    }

    #[test]
    fn parses_defaults_and_ipv6() {
        let n = parse_link(&format!("vless://{UUID}@[2001:db8::1]:8443")).unwrap();
        assert_eq!((n.address.as_str(), n.port, n.network.as_str(), n.security.as_str(), n.encryption.as_str()), ("2001:db8::1", 8443, "tcp", "none", "none"));
        assert_eq!(n.name, "2001:db8::1:8443");
        let n = parse_link(&link("type=splithttp&security=tls&path=%2Fx&host=h.com")).unwrap();
        assert_eq!(n.network, "xhttp");
    }

    #[test]
    fn rejects_bad_links() {
        for bad in [
            "vmess://abc",
            "vless://@host:1",
            "vless://not-a-uuid@host:443",
            &format!("vless://{UUID}@host"),
            &format!("vless://{UUID}@host:0"),
            &format!("vless://{UUID}@host:99999"),
            &format!("vless://{UUID}@ho st:443"),
            &format!("vless://{UUID}@host:443?type=kcp"),
            &format!("vless://{UUID}@host:443?security=reality"),
            &format!("vless://{UUID}@host:443?flow=evil"),
            &format!("vless://{UUID}@host:443?security=xtls"),
        ] {
            assert!(parse_link(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b%2Fc"), "a b/c");
        assert_eq!(percent_decode("%D0%B1%D1%83%D0%BD%D1%82"), "бунт");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("a+b"), "a+b");
    }

    #[test]
    fn bundles() {
        use base64::Engine;
        let a = link("security=none");
        let b = format!("vless://{UUID}@other.org:80");
        let plain = format!("{a}\n\n{b}\nvmess://xxx\ntrojan://yyy\n");
        let (l, s) = parse_bundle(&plain);
        assert_eq!((l.len(), s), (2, 2));
        let enc = base64::engine::general_purpose::STANDARD.encode(&plain);
        let (l2, s2) = parse_bundle(&enc);
        assert_eq!((l2.len(), s2), (2, 2));
        let url_enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&plain);
        assert_eq!(parse_bundle(&format!("{url_enc}\n")).0.len(), 2);
        assert_eq!(parse_bundle("мусор").0.len(), 0);
        assert_eq!(parse_bundle("").0.len(), 0);
    }

    #[test]
    fn ids_are_stable() {
        let a = link("security=none");
        assert_eq!(link_id(&a), link_id(&format!("  {a}\n")));
        assert_ne!(link_id(&a), link_id(&link("security=tls")));
        assert_eq!(link_id(&a).len(), 10);
    }

    #[test]
    fn rule_sanitizing() {
        let r = |k: &str, v: &str, a: &str| Rule { kind: k.into(), value: v.into(), action: a.into() };
        assert!(sanitize_rule(&r("domain", "example.com", "direct")).is_ok());
        assert!(sanitize_rule(&r("domain", "geosite:google", "proxy")).is_ok());
        assert!(sanitize_rule(&r("app", "chrome.exe", "proxy")).is_ok());
        assert!(sanitize_rule(&r("app", "C:\\Program Files\\App\\app.exe", "block")).is_ok());
        assert!(sanitize_rule(&r("ip", "10.0.0.0/8", "direct")).is_ok());
        assert!(sanitize_rule(&r("ip", "geoip:ru", "direct")).is_ok());
        assert!(sanitize_rule(&r("ip", "2001:db8::/32", "direct")).is_ok());
        for bad in [r("x", "a", "proxy"), r("domain", "a", "x"), r("domain", "", "proxy"), r("domain", "a b", "proxy"), r("ip", "10.0.0.0/99", "proxy"), r("ip", "evil", "proxy"), r("app", "a\"b", "proxy"), r("domain", "a\nb", "proxy")] {
            assert!(sanitize_rule(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(sanitize_rule(&r(" domain ", " a.com ", " proxy ")).unwrap().value, "a.com");
    }

    #[test]
    fn config_sanitizing() {
        let stored = Config { active: "keep".into(), subs: vec![Sub { id: "s".into(), ..Sub::default() }], ..Config::default() };
        let mut inc = Config { mode: "weird".into(), active: "hack".into(), subs: vec![], ..Config::default() };
        inc.rules = vec![Rule { kind: "domain".into(), value: "a.com".into(), action: "direct".into() }; 3];
        inc.dns = vec!["1.1.1.1".into(), " ".into(), "1.1.1.1".into()];
        let c = sanitize_config(&inc, &stored).unwrap();
        assert_eq!((c.mode.as_str(), c.active.as_str(), c.subs.len(), c.rules.len(), c.dns.len()), ("tun", "keep", 1, 1, 1));
        inc.socks_port = 80;
        assert!(sanitize_config(&inc, &stored).is_err());
        inc.socks_port = 5000;
        inc.http_port = 5000;
        assert!(sanitize_config(&inc, &stored).is_err());
        inc.http_port = 5001;
        inc.dns = vec!["evil".into()];
        assert!(sanitize_config(&inc, &stored).is_err());
        inc.dns = vec![];
        inc.rules = (0..400).map(|i| Rule { kind: "domain".into(), value: format!("a{i}.com"), action: "proxy".into() }).collect();
        assert!(sanitize_config(&inc, &stored).is_err());
    }

    #[test]
    fn xray_rules() {
        let mut cfg = Config::default();
        cfg.rules = vec![
            Rule { kind: "app".into(), value: "Discord.exe".into(), action: "proxy".into() },
            Rule { kind: "app".into(), value: "C:\\Games\\x\\game.exe".into(), action: "direct".into() },
            Rule { kind: "domain".into(), value: "*.example.com".into(), action: "direct".into() },
            Rule { kind: "domain".into(), value: "full:a.b".into(), action: "block".into() },
            Rule { kind: "ip".into(), value: "geoip:ru".into(), action: "direct".into() },
        ];
        let r = build_rules(&cfg);
        assert_eq!(r[0]["process"][0], "self/");
        assert_eq!(r[1]["ip"][0], "geoip:private");
        assert_eq!((r[2]["process"][0].as_str(), r[2]["outboundTag"].as_str()), (Some("Discord"), Some("proxy")));
        assert_eq!(r[3]["process"][0], "C:/Games/x/game.exe");
        assert_eq!(r[4]["domain"][0], "domain:example.com");
        assert_eq!((r[5]["domain"][0].as_str(), r[5]["outboundTag"].as_str()), (Some("full:a.b"), Some("block")));
        assert_eq!(r[6]["ip"][0], "geoip:ru");
        assert_eq!(r.last().unwrap()["outboundTag"], "proxy");
        cfg.default_action = "direct".into();
        cfg.bypass_lan = false;
        let r = build_rules(&cfg);
        assert_eq!(r.last().unwrap()["outboundTag"], "direct");
        assert!(!r.iter().any(|x| x.get("ip").map(|i| i[0] == "geoip:private").unwrap_or(false)));
    }

    #[test]
    fn tun_and_proxy_configs() {
        let n = parse_link(&link("type=tcp&security=reality&pbk=KEY&fp=chrome&sni=google.com&sid=ab&flow=xtls-rprx-vision")).unwrap();
        let cfg = Config::default();
        let t = build_config(&n, "1.2.3.4", &cfg, true);
        assert_eq!(t["inbounds"][0]["protocol"], "tun");
        assert_eq!(t["inbounds"][0]["settings"]["name"], TUN_NAME);
        assert_eq!(t["inbounds"][0]["settings"]["autoOutboundsInterface"], "auto");
        assert_eq!(t["inbounds"][0]["sniffing"]["routeOnly"], true);
        let o = &t["outbounds"][0];
        assert_eq!(o["settings"]["vnext"][0]["address"], "1.2.3.4");
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(o["streamSettings"]["realitySettings"]["publicKey"], "KEY");
        assert_eq!(o["streamSettings"]["realitySettings"]["serverName"], "google.com");
        let p = build_config(&n, "1.2.3.4", &cfg, false);
        assert_eq!(p["inbounds"].as_array().unwrap().len(), 2);
        assert_eq!((p["inbounds"][0]["protocol"].as_str(), p["inbounds"][0]["listen"].as_str()), (Some("socks"), Some("127.0.0.1")));
        assert_eq!(p["inbounds"][1]["port"], cfg.http_port);
    }

    #[test]
    fn transports() {
        let ws = parse_link(&link("type=ws&security=tls&path=%2Fws&host=cdn.com&sni=cdn.com&alpn=h2,http%2F1.1")).unwrap();
        let s = stream_settings(&ws);
        assert_eq!(s["wsSettings"]["path"], "/ws");
        assert_eq!(s["wsSettings"]["headers"]["Host"], "cdn.com");
        assert_eq!(s["tlsSettings"]["alpn"][1], "http/1.1");
        let g = stream_settings(&parse_link(&link("type=grpc&security=tls&serviceName=svc&mode=multi")).unwrap());
        assert_eq!((g["grpcSettings"]["serviceName"].as_str(), g["grpcSettings"]["multiMode"].as_bool()), (Some("svc"), Some(true)));
        let x = stream_settings(&parse_link(&link("type=xhttp&security=tls&path=%2Fx&extra=%7B%22a%22%3A1%7D")).unwrap());
        assert_eq!((x["xhttpSettings"]["mode"].as_str(), x["xhttpSettings"]["extra"]["a"].as_i64()), (Some("auto"), Some(1)));
        let bad = stream_settings(&parse_link(&link("type=xhttp&security=tls&extra=notjson")).unwrap());
        assert!(bad["xhttpSettings"].get("extra").is_none());
        let h = stream_settings(&parse_link(&link("type=tcp&headerType=http&host=a.com&path=%2Fp")).unwrap());
        assert_eq!(h["tcpSettings"]["header"]["request"]["path"][0], "/p");
        // без sni для TLS берётся адрес сервера
        let t = stream_settings(&parse_link(&link("security=tls")).unwrap());
        assert_eq!(t["tlsSettings"]["serverName"], "example.com");
    }

    #[test]
    fn proxy_scripts() {
        assert!(set_proxy_script(10809).contains("ProxyServer '127.0.0.1:10809'"));
        let prev = ProxyPrev { enable: 1, server: Some("corp:8080".into()), overr: None, ours: "127.0.0.1:10809".into() };
        let s = restore_proxy_script(&prev);
        assert!(s.contains("-eq '127.0.0.1:10809'") && s.contains("ProxyServer 'corp:8080'") && s.contains("Remove-ItemProperty") && s.contains("ProxyEnable 1"));
        let off = restore_proxy_script(&ProxyPrev { enable: 0, server: None, overr: None, ours: "x".into() });
        assert!(off.contains("ProxyEnable 0") && !off.contains("Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' ProxyServer"));
        // кавычки в чужом значении не ломают скрипт
        let q = restore_proxy_script(&ProxyPrev { enable: 1, server: Some("a'b".into()), overr: None, ours: "o".into() });
        assert!(q.contains("'a''b'"));
    }

    #[test]
    fn process_list() {
        let t = "chrome|C:\\Program Files\\Google\\Chrome\\chrome.exe\nchrome|C:\\other\\chrome.exe\nsvchost|C:\\Windows\\System32\\svchost.exe\nDiscord|C:\\Users\\a\\Discord.exe\nbroken line\n|C:\\x.exe\n";
        let p = parse_procs(t);
        assert_eq!(p.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), vec!["chrome", "Discord"]);
        assert!(p[0].path.contains("Google"));
    }

    #[test]
    fn cidr_check() {
        assert!(is_cidr("1.2.3.4") && is_cidr("1.2.3.0/24") && is_cidr("::1/128"));
        assert!(!is_cidr("1.2.3.4/33") && !is_cidr("a/8") && !is_cidr("1.2.3.4/"));
    }

    #[test]
    fn error_extraction() {
        let log = "Xray 26.3 started\n2026/10/13 [Warning] x\nXray: failed to load config: invalid geosite tag\n";
        assert!(last_error(log).contains("geosite"));
        assert_eq!(last_error("all fine"), "");
    }

    #[test]
    fn resolves_literal_ip() {
        assert_eq!(resolve("1.2.3.4", 1).unwrap(), "1.2.3.4");
        assert_eq!(resolve("::1", 1).unwrap(), "::1");
    }
}
