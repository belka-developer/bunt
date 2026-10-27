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
//! Движок общий с вкладкой Proxy (`xray_engine.rs`), но у каждой вкладки своя папка, свой процесс, свои профили
//! и настройки: `modules\vless\data\…`.
#![allow(dead_code)]

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

pub(crate) const EXE: &str = "xray.exe";
const ROOT_DIR: &str = "vless";
const TUN_NAME: &str = "BuntVLESS";
const TUN_IP: &str = "198.18.0.1";
const LABEL: &str = "VLESS";
const OTHER_LABEL: &str = "Proxy";
const DEFAULT_MODE: &str = "tun";
const DEFAULT_PORTS: (u16, u16) = (10808, 10809);
const LOG_FILE: &str = "vless.log";

static CHILD: Mutex<Option<Child>> = Mutex::new(None);

/// Режим соседнего экземпляра, если он работает: `Some(true)` TUN, `Some(false)` системный прокси.
fn other_mode() -> Option<bool> {
    crate::proxy::running_mode()
}

include!("xray_engine.rs");


/// Работает ли ядро этого экземпляра и в каком режиме (для проверки конфликтов между вкладками).
pub(crate) fn running_mode() -> Option<bool> {
    if running() { Some(load_config().mode != "proxy") } else { None }
}

#[tauri::command]
pub async fn vless_status() -> Result<Info, String> {
    cmd_vless_status().await
}

#[tauri::command]
pub async fn vless_connect(id: String) -> Result<Info, String> {
    cmd_vless_connect(id).await
}

#[tauri::command]
pub async fn vless_disconnect() -> Result<Done, String> {
    cmd_vless_disconnect().await
}

#[tauri::command]
pub async fn vless_repair() -> Result<Done, String> {
    cmd_vless_repair().await
}

#[tauri::command]
pub async fn vless_import(text: String) -> Result<Imported, String> {
    cmd_vless_import(text).await
}

#[tauri::command]
pub async fn vless_delete(ids: Vec<String>) -> Result<Info, String> {
    cmd_vless_delete(ids).await
}

#[tauri::command]
pub async fn vless_select(id: String) -> Result<Info, String> {
    cmd_vless_select(id).await
}

#[tauri::command]
pub async fn vless_config_set(config: Config) -> Result<Info, String> {
    cmd_vless_config_set(config).await
}

#[tauri::command]
pub async fn vless_profile_view(id: String) -> Result<String, String> {
    cmd_vless_profile_view(id).await
}

#[tauri::command]
pub async fn vless_ping_one(id: String) -> Result<Option<u32>, String> {
    cmd_vless_ping_one(id).await
}

#[tauri::command]
pub async fn vless_processes() -> Result<Vec<Proc>, String> {
    cmd_vless_processes().await
}

#[tauri::command]
pub async fn vless_log() -> Result<String, String> {
    cmd_vless_log().await
}

#[tauri::command]
pub async fn vless_sub_add(name: String, url: String) -> Result<Imported, String> {
    cmd_vless_sub_add(name, url).await
}

#[tauri::command]
pub async fn vless_sub_refresh(id: String) -> Result<Imported, String> {
    cmd_vless_sub_refresh(id).await
}

#[tauri::command]
pub async fn vless_sub_open(id: String, what: String) -> Result<(), String> {
    cmd_vless_sub_open(id, what).await
}

#[tauri::command]
pub async fn vless_sub_remove(id: String) -> Result<Info, String> {
    cmd_vless_sub_remove(id).await
}

