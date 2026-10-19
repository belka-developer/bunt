//! FPTN: запуск клиента `fptn-client-cli.exe` с защитой сети.
//!
//! Бунт ставит официальный клиент FPTN в `modules\fptn\<версия>` и запускает его консольную
//! версию без окна. Главная задача Бунта здесь не дать FPTN сломать сеть:
//!
//! * до подключения запоминается состояние сети (основной шлюз физического адаптера, DNS);
//! * после отключения, сбоя или выхода из Бунта убираются маршруты FPTN, возвращается DNS,
//!   при желании удаляется виртуальный адаптер, всё без «сброса сети» Windows;
//! * если Бунт был закрыт аварийно и сессия осталась «грязной», сеть чинится при следующем запуске;
//! * виртуальным адаптером можно управлять: включить, отключить, удалить.
//!
//! Раскладка: `modules\fptn\<версия>\` клиент, `modules\fptn\data\` настройки, лог и состояние сессии.

use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{Ipv4Addr, TcpStream, ToSocketAddrs},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(crate) const CLI: &str = "fptn-client-cli.exe";
const CLI_PROC: &str = "fptn-client-cli";
const READY_MARK: &str = "Routing setup completed successfully";

pub(crate) const BYPASS_METHODS: &[&str] = &[
    "obfuscation",
    "sni-spoofing-chrome-149", "sni-spoofing-chrome-148", "sni-spoofing-chrome-147", "sni-spoofing-chrome-146", "sni-spoofing-chrome-145",
    "sni-spoofing-firefox-151", "sni-spoofing-firefox-150", "sni-spoofing-firefox-149",
    "sni-spoofing-yandex-26-4", "sni-spoofing-yandex-26-3", "sni-spoofing-yandex-25", "sni-spoofing-yandex-24",
    "sni-spoofing-safari-26-5", "sni-spoofing-safari-26-4",
];
const STRATEGIES: &[&str] = &["rolling-tunnel", "dual-rolling-tunnel", "triple-rolling-tunnel"];

static CHILD: Mutex<Option<Child>> = Mutex::new(None);

fn root() -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join("fptn"))
}
pub(crate) fn data_dir() -> Result<PathBuf, String> {
    Ok(root()?.join("data"))
}
/// Имена в папке компонента, которые не являются версиями.
pub(crate) fn is_service_dir(name: &str) -> bool {
    name == "data"
}
fn config_file() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("config.json"))
}
fn session_file() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("session.json"))
}
fn log_file() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("fptn.log"))
}
fn flag_file() -> Result<PathBuf, String> {
    Ok(crate::modules::modules_root()?.join("fptn.json"))
}

// ───────── настройки ─────────

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// Токен доступа. В интерфейс не отдаётся, только подсказка (`token_hint`).
    pub token: String,
    pub bypass_method: String,
    pub strategy: String,
    pub sni: String,
    pub mtu: u32,
    /// Имена серверов через запятую; пусто: любой
    pub preferred_server: String,
    /// Имя виртуального адаптера в Windows. Бунт управляет только им.
    pub tun_name: String,
    pub tun_ip: String,
    pub exclude_networks: String,
    pub include_networks: String,
    pub split: bool,
    pub split_mode: String,
    pub split_domains: String,
    pub adblock: bool,
    /// Свой список блокируемых доменов; пусто: список клиента по умолчанию
    pub blacklist: String,
    /// Бунт сам находит шлюз физического адаптера (в обход Radmin, Hamachi, VPN и виртуальных машин)
    pub auto_gateway: bool,
    /// Удалять виртуальный адаптер после отключения
    pub remove_adapter: bool,
    /// Подключаться при запуске Бунта
    pub autostart: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            token: String::new(),
            bypass_method: "sni-spoofing-yandex-26-4".into(),
            strategy: "rolling-tunnel".into(),
            sni: "google.com".into(),
            mtu: 1420,
            preferred_server: String::new(),
            tun_name: "FPTN".into(),
            tun_ip: "10.0.0.1".into(),
            exclude_networks: "10.0.0.0/8,192.168.0.0/16".into(),
            include_networks: String::new(),
            split: false,
            split_mode: "exclude".into(),
            split_domains: String::new(),
            adblock: true,
            blacklist: String::new(),
            auto_gateway: true,
            remove_adapter: true,
            autostart: false,
        }
    }
}

fn list(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c == ';' || c.is_whitespace()).filter(|s| !s.is_empty()).map(String::from).collect()
}

fn valid_net(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, p)) => ip.parse::<Ipv4Addr>().is_ok() && p.parse::<u8>().map(|n| n <= 32).unwrap_or(false),
        None => s.parse::<Ipv4Addr>().is_ok(),
    }
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty() && d.len() <= 253 && d.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
}

pub(crate) fn validate(c: &Config) -> Result<(), String> {
    if !BYPASS_METHODS.contains(&c.bypass_method.as_str()) {
        return Err("Неизвестный метод обхода.".into());
    }
    if !STRATEGIES.contains(&c.strategy.as_str()) {
        return Err("Неизвестная стратегия соединения.".into());
    }
    if !valid_domain(&c.sni) {
        return Err("SNI: укажите домен, например google.com.".into());
    }
    if !(576..=65535).contains(&c.mtu) {
        return Err("MTU: от 576 до 65535.".into());
    }
    let n = c.tun_name.trim();
    if n.is_empty() || n.len() > 32 || !n.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
        return Err("Имя адаптера: до 32 символов, латиница, цифры, - и _.".into());
    }
    if c.tun_ip.parse::<Ipv4Addr>().is_err() {
        return Err("Адрес адаптера должен быть IPv4, например 10.0.0.1.".into());
    }
    for (title, text) in [("Исключаемые сети", &c.exclude_networks), ("Сети через VPN", &c.include_networks)] {
        if let Some(bad) = list(text).iter().find(|s| !valid_net(s)) {
            return Err(format!("{title}: «{bad}» не похоже на сеть. Пример: 192.168.0.0/16."));
        }
    }
    if c.split_mode != "exclude" && c.split_mode != "include" {
        return Err("Режим раздельного туннеля: exclude или include.".into());
    }
    for (title, text) in [("Домены раздельного туннеля", &c.split_domains), ("Чёрный список", &c.blacklist)] {
        if let Some(bad) = list(text).iter().find(|s| !valid_domain(s)) {
            return Err(format!("{title}: «{bad}» не похоже на домен."));
        }
    }
    if c.preferred_server.chars().any(|ch| ch.is_control()) || c.preferred_server.len() > 200 {
        return Err("Предпочитаемый сервер: недопустимые символы.".into());
    }
    if c.token.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err("В токене не должно быть пробелов и переносов строк.".into());
    }
    Ok(())
}

pub(crate) fn load_config() -> Config {
    config_file().ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_config(c: &Config) -> Result<(), String> {
    let dir = data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| format!("Не удалось создать {}: {e}", dir.display()))?;
    fs::write(config_file()?, serde_json::to_string_pretty(c).map_err(|e| e.to_string())?).map_err(|e| format!("Не удалось записать настройки: {e}"))
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub(crate) struct ServerEntry {
    name: String,
    /// Название для показа: без флагов-эмодзи, которые Windows рисует буквами
    label: String,
    /// Код страны для флага (файл в `ui/flags`), пусто если страна не узнана
    code: String,
    host: String,
    port: u16,
}

/// Разбор токена так же, как клиент FPTN: `fptnb:` + base64(brotli(JSON)) или `fptn:` + base64(JSON).
/// Наружу отдаются только имена и адреса серверов, логин и пароль остаются внутри.
pub(crate) fn parse_token(token: &str) -> Result<Vec<ServerEntry>, String> {
    use base64::Engine;
    let t = token.trim();
    if t.is_empty() {
        return Ok(Vec::new());
    }
    let brotli = t.starts_with("fptnb:") || t.starts_with("fptnb//");
    let mut body = t.to_string();
    for p in ["fptnb:", "fptnb//", "fptn://", "fptn:"] {
        body = body.replace(p, "");
    }
    body.retain(|c| !c.is_whitespace() && c != '=');
    let body = body.replace('-', "+").replace('_', "/");
    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(body.as_bytes())
        .map_err(|e| format!("токен повреждён (base64): {e}"))?;
    let json_bytes = if brotli {
        use std::io::Read;
        let mut out = Vec::new();
        brotli_decompressor::Decompressor::new(&raw[..], 4096)
            .take(8 * 1024 * 1024)
            .read_to_end(&mut out)
            .map_err(|e| format!("токен повреждён (brotli): {e}"))?;
        out
    } else {
        raw
    };
    let v: serde_json::Value = serde_json::from_slice(&json_bytes).map_err(|e| format!("в токене не JSON: {e}"))?;
    let list = v.get("servers").and_then(|x| x.as_array()).ok_or("в токене нет списка серверов")?;
    let mut out = Vec::new();
    for sv in list {
        let name = sv.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let host = sv.get("host").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let port = sv.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
        if !name.is_empty() {
            let hint = ["country_code", "countryCode", "country", "code"]
                .iter()
                .find_map(|k| sv.get(*k).and_then(|x| x.as_str()))
                .unwrap_or("");
            out.push(ServerEntry { label: super::geo::label(&name), code: super::geo::code_for(&name, hint), name, host, port });
        }
    }
    if out.is_empty() {
        return Err("список серверов в токене пуст".into());
    }
    Ok(out)
}

fn token_hint(t: &str) -> String {
    let chars: Vec<char> = t.chars().collect();
    if chars.is_empty() {
        String::new()
    } else if chars.len() <= 12 {
        "••••".into()
    } else {
        format!("{}…{}", chars[..5].iter().collect::<String>(), chars[chars.len() - 4..].iter().collect::<String>())
    }
}

/// Аргументы клиента. Токен идёт отдельным аргументом без оболочки, так что кавычки не нужны.
pub(crate) fn build_args(c: &Config, gateway: Option<(&str, &str)>) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    let mut kv = |k: &str, v: String| {
        a.push(k.to_string());
        a.push(v);
    };
    kv("--access-token", c.token.clone());
    kv("--tun-interface-name", c.tun_name.trim().to_string());
    kv("--tun-interface-ip", c.tun_ip.clone());
    kv("--sni", c.sni.clone());
    kv("--mtu-size", c.mtu.to_string());
    kv("--bypass-method", c.bypass_method.clone());
    kv("--connection-strategy", c.strategy.clone());
    let ex = list(&c.exclude_networks).join(",");
    kv("--exclude-tunnel-networks", ex);
    let inc = list(&c.include_networks).join(",");
    if !inc.is_empty() {
        kv("--include-tunnel-networks", inc);
    }
    kv("--enable-ad-block", c.adblock.to_string());
    kv("--enable-split-tunnel", c.split.to_string());
    kv("--split-tunnel-mode", c.split_mode.clone());
    let sd = list(&c.split_domains).join(",");
    if !sd.is_empty() {
        kv("--split-tunnel-domains", sd);
    }
    let bl = list(&c.blacklist).join(",");
    if !bl.is_empty() {
        kv("--blacklist-domains", bl);
    }
    if !c.preferred_server.trim().is_empty() {
        kv("--preferred-server", c.preferred_server.trim().to_string());
    }
    if let Some((gw, iface)) = gateway {
        kv("--gateway-ip", gw.to_string());
        kv("--out-network-interface", iface.to_string());
    }
    a
}

// ───────── PowerShell ─────────

#[cfg_attr(not(windows), allow(dead_code))]
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for ch in data.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if ch.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if ch.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Запускает скрипт PowerShell скрыто. Скрипт передаётся закодированным: никаких проблем с кавычками.
pub(crate) fn ps(script: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let full = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; {script}");
        let utf16: Vec<u8> = full.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", base64(&utf16).as_str()])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;
        return Some(String::from_utf8_lossy(&out.stdout).to_string());
    }
    #[cfg(not(windows))]
    {
        let _ = script;
        None
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct AdapterDns {
    pub(crate) alias: String,
    pub(crate) index: u32,
    /// Статические DNS из реестра, пусто: адреса приходят по DHCP
    pub(crate) ns: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct Probe {
    pub(crate) gateway: String,
    pub(crate) alias: String,
    pub(crate) index: u32,
    pub(crate) adapters: Vec<AdapterDns>,
}

/// Находит основной шлюз среди физических адаптеров (Ethernet, Wi-Fi): виртуальные Radmin, Hamachi, VPN,
/// Hyper-V и Wintun в выбор не попадают. Заодно запоминает статические DNS этих адаптеров.
pub(crate) fn probe() -> Result<Probe, String> {
    let script = r#"
$ErrorActionPreference='SilentlyContinue'
$phys=@(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
$idx=@($phys | ForEach-Object { $_.ifIndex })
$best=$null;$bm=[int]::MaxValue
foreach($r in (Get-NetRoute -DestinationPrefix '0.0.0.0/0')){
  if(($idx -contains $r.ifIndex) -and $r.NextHop -ne '0.0.0.0'){
    $im=(Get-NetIPInterface -InterfaceIndex $r.ifIndex -AddressFamily IPv4).InterfaceMetric
    $m=[int]$r.RouteMetric+[int]$im
    if($m -lt $bm){$bm=$m;$best=$r}
  }
}
$ad=@()
foreach($a in $phys){
  $p=Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+$a.InterfaceGuid)
  $ns=''; if($p){$ns=[string]$p.NameServer}
  $ad+=[pscustomobject]@{alias=[string]$a.Name;index=[int]$a.ifIndex;ns=$ns}
}
[pscustomobject]@{gateway=[string]$best.NextHop;alias=[string]$best.InterfaceAlias;index=[int]$best.ifIndex;adapters=$ad} | ConvertTo-Json -Compress -Depth 4
"#;
    let out = ps(script).ok_or("Не удалось опросить сеть (PowerShell)")?;
    parse_probe(&out)
}

pub(crate) fn parse_probe(text: &str) -> Result<Probe, String> {
    let start = text.find('{').ok_or("Пустой ответ при опросе сети")?;
    let v: serde_json::Value = serde_json::from_str(text[start..].trim()).map_err(|e| format!("Непонятный ответ при опросе сети: {e}"))?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let adapters = match v.get("adapters") {
        Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| serde_json::from_value::<AdapterDns>(x.clone()).ok()).collect(),
        Some(o @ serde_json::Value::Object(_)) => serde_json::from_value::<AdapterDns>(o.clone()).ok().into_iter().collect(),
        _ => Vec::new(),
    };
    Ok(Probe { gateway: s("gateway"), alias: s("alias"), index: v.get("index").and_then(|x| x.as_u64()).unwrap_or(0) as u32, adapters })
}

fn safe_ns(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | ',' | ' '))
}

/// Сценарий очистки: маршруты FPTN, DNS, адаптер, кэш DNS. Все значения проверены заранее.
pub(crate) fn repair_script(tun_ip: &str, tun_name: &str, gateway: &str, adapters: &[AdapterDns], remove_adapter: bool) -> String {
    let mut s = String::from("$ErrorActionPreference='SilentlyContinue'\n");
    s += &format!("Get-NetRoute | Where-Object {{ $_.NextHop -eq '{tun_ip}' }} | Remove-NetRoute -Confirm:$false\n");
    s += &format!("Get-NetRoute -InterfaceAlias '{tun_name}' | Remove-NetRoute -Confirm:$false\n");
    if !gateway.is_empty() {
        // FPTN добавляет свои маршруты через физический шлюз с метрикой 2: хост сервера, исключённые сети, домены раздельного туннеля
        s += &format!("Get-NetRoute | Where-Object {{ $_.NextHop -eq '{gateway}' -and $_.RouteMetric -eq 2 -and $_.DestinationPrefix -ne '0.0.0.0/0' }} | Remove-NetRoute -Confirm:$false\n");
    }
    for a in adapters.iter().filter(|a| safe_ns(&a.ns)) {
        let servers: Vec<String> = a.ns.split(|c: char| c == ',' || c == ' ').filter(|x| !x.is_empty()).map(|x| format!("'{x}'")).collect();
        s += &format!("$p=Get-ItemProperty ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\'+(Get-NetAdapter -InterfaceIndex {i}).InterfaceGuid); $cur=''; if($p){{$cur=[string]$p.NameServer}}\n", i = a.index);
        if servers.is_empty() {
            s += &format!("if($cur -ne ''){{ Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses }}\n", a.index);
        } else {
            s += &format!("if($cur -ne '{}'){{ Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses ({}) }}\n", a.ns, a.index, servers.join(","));
        }
    }
    if remove_adapter {
        s += &format!("$a=Get-NetAdapter -Name '{tun_name}'; if($a -and $a.PnPDeviceID){{ pnputil /remove-device $a.PnPDeviceID | Out-Null }}\n");
    }
    s += "ipconfig /flushdns | Out-Null\n";
    s += "$d=Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1\n";
    s += "[pscustomobject]@{gateway=[string]$d.NextHop;alias=[string]$d.InterfaceAlias} | ConvertTo-Json -Compress\n";
    s
}

// ───────── сессия ─────────

#[derive(Serialize, Deserialize, Default, Clone)]
struct Session {
    active: bool,
    tun_name: String,
    tun_ip: String,
    gateway: String,
    adapters: Vec<AdapterDns>,
}

fn read_session() -> Session {
    session_file().ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn write_session(s: &Session) {
    if let (Ok(dir), Ok(f)) = (data_dir(), session_file()) {
        let _ = fs::create_dir_all(dir);
        let _ = fs::write(f, serde_json::to_string(s).unwrap_or_default());
    }
}

fn set_enabled(on: bool) {
    if let Ok(p) = flag_file() {
        let _ = fs::write(p, serde_json::json!({ "enabled": on }).to_string());
    }
}

fn is_enabled() -> bool {
    flag_file()
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("enabled").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

// ───────── процесс ─────────

fn our_pids() -> Vec<u32> {
    crate::zapret::list_procs(CLI_PROC).into_iter().filter(|(_, p)| crate::zapret::is_ours(p)).map(|(id, _)| id).collect()
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

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            if it.peek() == Some(&'[') {
                for n in it.by_ref() {
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn read_log() -> String {
    log_file().ok().and_then(|p| fs::read(p).ok()).map(|b| strip_ansi(&String::from_utf8_lossy(&b))).unwrap_or_default()
}

fn log_tail(n: usize) -> String {
    let t = read_log();
    let lines: Vec<&str> = t.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn last_error(t: &str) -> String {
    t.lines().rev().find(|l| l.contains("error") || l.contains("ERROR") || l.contains("Error")).map(|l| l.trim().to_string()).unwrap_or_default()
}

/// Останавливает клиент FPTN Бунта.
pub fn stop_process() {
    if let Some(mut c) = CHILD.lock().unwrap().take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    for pid in our_pids() {
        crate::zapret::kill_pid(pid);
    }
}

/// Убирает за FPTN: маршруты, DNS, при необходимости адаптер. Возвращает короткий отчёт.
fn repair(remove_adapter: bool) -> Result<String, String> {
    let cfg = load_config();
    let sess = read_session();
    let tun_name = if sess.tun_name.is_empty() { cfg.tun_name.trim().to_string() } else { sess.tun_name.clone() };
    let tun_ip = if sess.tun_ip.is_empty() { cfg.tun_ip.clone() } else { sess.tun_ip.clone() };
    if tun_ip.parse::<Ipv4Addr>().is_err() || !tun_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("Неверные имя или адрес адаптера в сохранённой сессии.".into());
    }
    let gateway = if sess.gateway.parse::<Ipv4Addr>().is_ok() {
        sess.gateway.clone()
    } else {
        probe().map(|p| p.gateway).unwrap_or_default().parse::<Ipv4Addr>().map(|a| a.to_string()).unwrap_or_default()
    };
    let script = repair_script(&tun_ip, &tun_name, &gateway, &sess.adapters, remove_adapter);
    let out = ps(&script).ok_or("Не удалось выполнить очистку сети (PowerShell)")?;
    let mut s = sess;
    s.active = false;
    write_session(&s);
    let rep = out.find('{').and_then(|i| serde_json::from_str::<serde_json::Value>(out[i..].trim()).ok());
    Ok(match rep {
        Some(v) => {
            let gw = v.get("gateway").and_then(|x| x.as_str()).unwrap_or("");
            let al = v.get("alias").and_then(|x| x.as_str()).unwrap_or("");
            if gw.is_empty() {
                "Маршруты FPTN убраны, но основной шлюз не найден: проверьте кабель или Wi-Fi.".to_string()
            } else {
                format!("Сеть восстановлена: основной шлюз {gw} ({al}).")
            }
        }
        None => "Маршруты FPTN убраны.".to_string(),
    })
}

pub(crate) fn require_admin() -> Result<(), String> {
    if crate::settings::is_admin_sync() { Ok(()) } else { Err("Нужны права администратора: виртуальный адаптер и маршруты меняются только с ними.".into()) }
}

fn connect_blocking() -> Result<(), String> {
    require_admin()?;
    // Два VPN сразу делят маршруты и ломают сеть: второй не включаем
    if crate::wg::is_running() {
        return Err("WireGuard / AmneziaWG сейчас включён. Отключите его, прежде чем включать FPTN: два VPN сразу ломают маршруты.".into());
    }
    if crate::vless::is_running() {
        return Err("VLESS сейчас включён. Отключите его, прежде чем включать FPTN: два VPN сразу ломают маршруты.".into());
    }
    let dir = crate::modules::active_dir("fptn")?;
    let exe = dir.join(CLI);
    if !exe.is_file() {
        return Err("Не найден fptn-client-cli.exe. Переустановите компонент.".into());
    }
    if running() {
        return Ok(());
    }
    let cfg = load_config();
    validate(&cfg)?;
    if cfg.token.trim().is_empty() {
        return Err("Добавьте токен доступа (его выдаёт Telegram-бот FPTN).".into());
    }
    // Остатки прошлой сессии (аварийное закрытие) убираем до подключения
    if read_session().active {
        let _ = repair(true);
    }
    let pr = if cfg.auto_gateway {
        let p = probe()?;
        if p.gateway.parse::<Ipv4Addr>().is_err() || p.alias.is_empty() {
            return Err("Не найден основной шлюз физического адаптера. Проверьте, что интернет работает без FPTN.".into());
        }
        Some(p)
    } else {
        None
    };
    let sess = Session {
        active: true,
        tun_name: cfg.tun_name.trim().to_string(),
        tun_ip: cfg.tun_ip.clone(),
        gateway: pr.as_ref().map(|p| p.gateway.clone()).unwrap_or_default(),
        adapters: pr.as_ref().map(|p| p.adapters.clone()).unwrap_or_default(),
    };
    write_session(&sess);
    fs::create_dir_all(data_dir()?).map_err(|e| e.to_string())?;
    let logf = fs::File::create(log_file()?).map_err(|e| e.to_string())?;
    let errf = logf.try_clone().map_err(|e| e.to_string())?;
    let gw = pr.as_ref().map(|p| (p.gateway.as_str(), p.alias.as_str()));
    let mut cmd = Command::new(&exe);
    cmd.args(build_args(&cfg, gw)).current_dir(&dir).stdin(Stdio::null()).stdout(Stdio::from(logf)).stderr(Stdio::from(errf));
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let child = cmd.spawn().map_err(|e| format!("Не удалось запустить FPTN: {e}"))?;
    *CHILD.lock().unwrap() = Some(child);

    for _ in 0..80 {
        std::thread::sleep(Duration::from_millis(500));
        let exited = {
            let mut g = CHILD.lock().unwrap();
            matches!(g.as_mut().map(|c| c.try_wait()), Some(Ok(Some(_))))
        };
        let log = read_log();
        if exited {
            let why = last_error(&log);
            stop_process();
            let _ = repair(cfg.remove_adapter);
            return Err(if why.is_empty() { "FPTN завершился сразу после запуска. Подробности в логе.".into() } else { format!("FPTN завершился: {why}") });
        }
        if log.contains(READY_MARK) {
            std::thread::sleep(Duration::from_millis(1200));
            return Ok(());
        }
    }
    stop_process();
    let _ = repair(cfg.remove_adapter);
    Err("FPTN не подключился за 40 секунд. Сеть возвращена в исходное состояние, подробности в логе.".into())
}

/// Отключение: остановка клиента и обязательная очистка сети.
fn disconnect_blocking() -> Result<String, String> {
    stop_process();
    set_enabled(false);
    let cfg = load_config();
    // Дать системе закрыть адаптер, иначе pnputil не удалит его
    std::thread::sleep(Duration::from_millis(700));
    repair(cfg.remove_adapter)
}

/// Вызывается при выходе из Бунта.
pub fn shutdown() {
    if running() || read_session().active {
        let _ = disconnect_blocking();
    }
}

// ───────── адаптер ─────────

#[derive(Serialize, Default)]
pub struct Adapter {
    exists: bool,
    /// Up, Disabled, Disconnected…
    status: String,
    description: String,
}

fn adapter_now() -> Adapter {
    let cfg = load_config();
    let name = cfg.tun_name.trim().to_string();
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || name.is_empty() {
        return Adapter::default();
    }
    let script = format!("$a=Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue; if($a){{ [pscustomobject]@{{status=[string]$a.Status;description=[string]$a.InterfaceDescription}} | ConvertTo-Json -Compress }}");
    let Some(out) = ps(&script) else { return Adapter::default() };
    let Some(i) = out.find('{') else { return Adapter::default() };
    let v: serde_json::Value = serde_json::from_str(out[i..].trim()).unwrap_or_default();
    Adapter {
        exists: true,
        status: v.get("status").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        description: v.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    }
}

// ───────── чужие копии ─────────

#[derive(Serialize)]
pub struct Foreign {
    procs: Vec<String>,
    /// Записи автозагрузки (Run) с fptn
    autostart: Vec<String>,
}

fn foreign_procs() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for name in ["fptn-client", CLI_PROC] {
        out.extend(crate::zapret::list_procs(name).into_iter().filter(|(_, p)| !crate::zapret::is_ours(p)));
    }
    out
}

#[cfg_attr(not(windows), allow(dead_code))]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

/// Имена значений в Run, в имени или команде которых есть fptn.
fn foreign_autostart() -> Vec<String> {
    #[cfg(windows)]
    {
        if let Ok(o) = Command::new("reg").args(["query", RUN_KEY]).creation_flags(CREATE_NO_WINDOW).output() {
            return parse_run_entries(&String::from_utf8_lossy(&o.stdout));
        }
    }
    Vec::new()
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_run_entries(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| l.to_lowercase().contains("fptn"))
        .filter_map(|l| l.split_whitespace().next().map(String::from))
        .filter(|n| !n.starts_with("HKEY") && n.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .collect()
}

// ───────── команды ─────────

#[derive(Serialize)]
pub struct Info {
    running: bool,
    connected: bool,
    /// Автоподключение при запуске Бунта или включено при выходе
    enabled: bool,
    /// Прошлая сессия не была закрыта: сеть могла остаться в изменённом виде
    dirty: bool,
    token_set: bool,
    token_hint: String,
    servers: Vec<ServerEntry>,
    token_error: String,
    config: Config,
    adapter: Adapter,
}

fn info(with_adapter: bool) -> Info {
    let mut config = load_config();
    let hint = token_hint(&config.token);
    let token_set = !config.token.is_empty();
    let (servers, token_error) = match parse_token(&config.token) {
        Ok(v) => (v, String::new()),
        Err(e) => (Vec::new(), e),
    };
    config.token.clear();
    let run = running();
    Info {
        running: run,
        connected: run && read_log().contains(READY_MARK),
        enabled: is_enabled(),
        dirty: !run && read_session().active,
        token_set,
        token_hint: hint,
        servers,
        token_error,
        config,
        adapter: if with_adapter && cfg!(windows) { adapter_now() } else { Adapter::default() },
    }
}

/// Время установки TCP-соединения с сервером в миллисекундах: лучший из двух замеров.
/// `None`, если сервер не ответил за 2,5 секунды.
pub(crate) fn tcp_ping(host: &str, port: u16) -> Option<u32> {
    let addr = (host, port).to_socket_addrs().ok()?.next()?;
    let mut best: Option<u32> = None;
    for _ in 0..2 {
        let t = Instant::now();
        if TcpStream::connect_timeout(&addr, Duration::from_millis(2500)).is_ok() {
            let ms = t.elapsed().as_millis().max(1) as u32;
            best = Some(best.map_or(ms, |b| b.min(ms)));
        } else if best.is_none() {
            return None;
        }
    }
    best
}

/// Пинг одного сервера из токена по имени. Адрес берётся из сохранённого токена, а не от окна.
#[tauri::command]
pub async fn fptn_ping(name: String) -> Result<Option<u32>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let servers = parse_token(&load_config().token)?;
        let s = servers.iter().find(|s| s.name == name).ok_or("такого сервера нет в токене")?;
        if s.host.is_empty() || s.port == 0 {
            return Ok(None);
        }
        Ok(tcp_ping(&s.host, s.port))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn fptn_status() -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(|| info(true)).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fptn_connect() -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(|| {
        connect_blocking()?;
        set_enabled(true);
        Ok(info(true))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
pub struct Done {
    message: String,
    info: Info,
}

#[tauri::command]
pub async fn fptn_disconnect() -> Result<Done, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let message = disconnect_blocking()?;
        Ok(Done { message, info: info(true) })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Ручной ремонт сети: убирает маршруты и DNS FPTN без сброса сети Windows.
#[tauri::command]
pub async fn fptn_repair() -> Result<Done, String> {
    tauri::async_runtime::spawn_blocking(|| {
        require_admin()?;
        if running() {
            return Err("FPTN подключён. Сначала отключите его.".into());
        }
        let message = repair(load_config().remove_adapter)?;
        Ok(Done { message, info: info(true) })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Сохраняет настройки. Пустой токен в запросе значит «оставить прежний».
#[tauri::command]
pub async fn fptn_config_set(config: Config) -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut c = config;
        let old = load_config();
        c.token = c.token.trim().to_string();
        if c.token.is_empty() {
            c.token = old.token;
        }
        c.tun_name = c.tun_name.trim().to_string();
        validate(&c)?;
        if running() && (c.tun_name != old.tun_name) {
            return Err("Имя адаптера меняется только при отключённом FPTN.".into());
        }
        save_config(&c)?;
        Ok(info(true))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn fptn_clear_token() -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let mut c = load_config();
        c.token.clear();
        save_config(&c)?;
        Ok(info(true))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn fptn_config_reset() -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let token = load_config().token;
        save_config(&Config { token, ..Config::default() })?;
        Ok(info(true))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Включить, отключить или удалить виртуальный адаптер FPTN (только его, чужие адаптеры не трогаются).
#[tauri::command]
pub async fn fptn_adapter(action: String) -> Result<Info, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_admin()?;
        let name = load_config().tun_name.trim().to_string();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("Неверное имя адаптера в настройках.".into());
        }
        let script = match action.as_str() {
            "enable" => format!("Enable-NetAdapter -Name '{name}' -Confirm:$false -ErrorAction Stop"),
            "disable" => format!("Disable-NetAdapter -Name '{name}' -Confirm:$false -ErrorAction Stop"),
            "remove" => {
                if running() {
                    return Err("FPTN подключён. Сначала отключите его.".into());
                }
                format!("$a=Get-NetAdapter -Name '{name}' -ErrorAction Stop; if($a.PnPDeviceID){{ pnputil /remove-device $a.PnPDeviceID }}")
            }
            _ => return Err("Неизвестное действие.".into()),
        };
        // Ошибки PowerShell показываем пользователю, поэтому ловим их и печатаем текст
        let wrapped = format!("try {{ {script} }} catch {{ 'ERR: ' + $_.Exception.Message }}");
        let out = ps(&wrapped).unwrap_or_default();
        if let Some(e) = out.lines().find(|l| l.starts_with("ERR: ")) {
            return Err(e.trim_start_matches("ERR: ").to_string());
        }
        std::thread::sleep(Duration::from_millis(600));
        Ok(info(true))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Последние строки лога клиента.
#[tauri::command]
pub async fn fptn_log() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(|| log_tail(60)).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fptn_foreign() -> Result<Foreign, String> {
    tauri::async_runtime::spawn_blocking(|| Foreign { procs: foreign_procs().into_iter().map(|(_, p)| p).collect(), autostart: foreign_autostart() })
        .await
        .map_err(|e| e.to_string())
}

/// Останавливает чужой FPTN (GUI или консоль) и по желанию убирает его из автозагрузки.
#[tauri::command]
pub async fn fptn_take_over(remove_autostart: bool) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        for (pid, _) in foreign_procs() {
            crate::zapret::kill_pid(pid);
        }
        if remove_autostart {
            #[cfg(windows)]
            {
                for name in foreign_autostart() {
                    let _ = Command::new("reg").args(["delete", RUN_KEY, "/v", name.as_str(), "/f"]).creation_flags(CREATE_NO_WINDOW).output();
                }
            }
        }
        std::thread::sleep(Duration::from_millis(700));
        if !foreign_procs().is_empty() {
            return Err("Не удалось закрыть чужой FPTN. Закройте его в трее вручную.".into());
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config { token: "fptn:abc123".into(), ..Config::default() }
    }

    #[test]
    fn default_args() {
        let a = build_args(&cfg(), Some(("192.168.1.1", "Ethernet")));
        let s = a.join(" ");
        assert!(s.starts_with("--access-token fptn:abc123 --tun-interface-name FPTN --tun-interface-ip 10.0.0.1 --sni google.com --mtu-size 1420"));
        assert!(s.contains("--bypass-method sni-spoofing-yandex-26-4 --connection-strategy rolling-tunnel"));
        assert!(s.contains("--exclude-tunnel-networks 10.0.0.0/8,192.168.0.0/16"));
        assert!(s.contains("--enable-ad-block true --enable-split-tunnel false --split-tunnel-mode exclude"));
        assert!(s.ends_with("--gateway-ip 192.168.1.1 --out-network-interface Ethernet"));
        assert!(!s.contains("--include-tunnel-networks") && !s.contains("--preferred-server"));
    }

    #[test]
    fn optional_args_and_lists() {
        let c = Config {
            include_networks: "172.16.0.0/12, 1.2.3.4".into(),
            split: true, split_mode: "include".into(), split_domains: "a.com b.org".into(),
            blacklist: "x.ru,y.ru".into(), preferred_server: "Fin, Ger".into(), ..cfg()
        };
        validate(&c).unwrap();
        let s = build_args(&c, None).join(" ");
        assert!(s.contains("--include-tunnel-networks 172.16.0.0/12,1.2.3.4"));
        assert!(s.contains("--split-tunnel-domains a.com,b.org") && s.contains("--blacklist-domains x.ru,y.ru"));
        assert!(s.contains("--preferred-server Fin, Ger") && !s.contains("--gateway-ip"));
    }

    #[test]
    fn validation() {
        assert!(validate(&cfg()).is_ok());
        assert!(validate(&Config { mtu: 100, ..cfg() }).is_err());
        assert!(validate(&Config { bypass_method: "x".into(), ..cfg() }).is_err());
        assert!(validate(&Config { tun_name: "a'; calc; '".into(), ..cfg() }).is_err());
        assert!(validate(&Config { tun_ip: "10.0.0".into(), ..cfg() }).is_err());
        assert!(validate(&Config { exclude_networks: "10.0.0.0/33".into(), ..cfg() }).is_err());
        assert!(validate(&Config { token: "a b".into(), ..cfg() }).is_err());
        assert!(validate(&Config { split_domains: "bad_domain!".into(), ..cfg() }).is_err());
    }

    #[test]
    fn parse_plain_token() {
        use base64::Engine;
        let j = r#"{"version":1,"service_name":"x","username":"u","password":"SECRET","servers":[{"name":"Finland","host":"1.2.3.4","port":443,"md5_fingerprint":"ab"},{"name":"Germany","host":"5.6.7.8","port":443,"md5_fingerprint":"cd"}]}"#;
        let t = format!("fptn:{}", base64::engine::general_purpose::STANDARD.encode(j));
        let s = parse_token(&t).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].name, "Finland");
        assert_eq!(s[1].host, "5.6.7.8");
        assert!(parse_token("").unwrap().is_empty());
        assert!(parse_token("fptn:!!!").is_err());
    }

    #[test]
    fn parse_real_token_from_env() {
        if let Ok(t) = std::env::var("FPTN_TEST_TOKEN") {
            let s = parse_token(&t).unwrap();
            eprintln!("servers: {:?}", s.iter().map(|x| x.name.clone()).collect::<Vec<_>>());
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn token_hint_hides_most() {
        let h = token_hint("fptn:ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert!(h.starts_with("fptn:") && h.ends_with("WXYZ") && !h.contains("KLMN"));
        assert_eq!(token_hint(""), "");
        assert_eq!(token_hint("short"), "••••");
    }

    #[test]
    fn base64_matches_known() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
        assert_eq!(base64(b""), "");
    }

    #[test]
    fn parses_probe() {
        let one = r#"{"gateway":"192.168.1.1","alias":"Ethernet","index":5,"adapters":{"alias":"Ethernet","index":5,"ns":""}}"#;
        let p = parse_probe(one).unwrap();
        assert_eq!((p.gateway.as_str(), p.index, p.adapters.len()), ("192.168.1.1", 5, 1));
        let two = r#"noise {"gateway":"10.1.1.1","alias":"Wi-Fi","index":9,"adapters":[{"alias":"Wi-Fi","index":9,"ns":"8.8.8.8,1.1.1.1"},{"alias":"Eth","index":3,"ns":""}]}"#;
        let p = parse_probe(two).unwrap();
        assert_eq!(p.adapters.len(), 2);
        assert_eq!(p.adapters[0].ns, "8.8.8.8,1.1.1.1");
        assert!(parse_probe("nothing").is_err());
    }

    #[test]
    fn repair_script_is_scoped() {
        let ad = vec![AdapterDns { alias: "E".into(), index: 5, ns: String::new() }, AdapterDns { alias: "W".into(), index: 9, ns: "8.8.8.8,1.1.1.1".into() }];
        let s = repair_script("10.0.0.1", "FPTN", "192.168.1.1", &ad, true);
        assert!(s.contains("NextHop -eq '10.0.0.1'") && s.contains("-InterfaceAlias 'FPTN'"));
        assert!(s.contains("NextHop -eq '192.168.1.1' -and $_.RouteMetric -eq 2"));
        assert!(s.contains("-InterfaceIndex 5 -ResetServerAddresses") && s.contains("-InterfaceIndex 9 -ServerAddresses ('8.8.8.8','1.1.1.1')"));
        assert!(s.contains("pnputil /remove-device"));
        assert!(!repair_script("10.0.0.1", "FPTN", "", &[], false).contains("pnputil"));
        // не должно быть сброса сети Windows
        assert!(!s.to_lowercase().contains("winsock") && !s.to_lowercase().contains("int ip reset"));
    }

    #[test]
    fn ansi_and_run_entries() {
        assert_eq!(strip_ansi("\u{1b}[32mhello\u{1b}[0m world"), "hello world");
        let reg = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n    Bunt    REG_SZ    \"C:\\Bunt\\bunt.exe\" --hidden\n    FptnClient    REG_SZ    \"C:\\Program Files\\FPTN\\fptn-client.exe\"\n";
        assert_eq!(parse_run_entries(reg), vec!["FptnClient".to_string()]);
    }
}
