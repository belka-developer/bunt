//! Proxy: обычные прокси SOCKS5, HTTP и HTTPS на отдельном экземпляре ядра Xray-core.
//!
//! Работает независимо от вкладки VLESS: своя установка ядра (`modules\proxy\<версия>\`), свои профили и
//! настройки (`modules\proxy\data\…`), свой процесс и свой виртуальный адаптер. Движок общий (`xray_engine.rs`).
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
const ROOT_DIR: &str = "proxy";
const TUN_NAME: &str = "BuntProxy";
const TUN_IP: &str = "198.19.0.1";
const LABEL: &str = "Proxy";
const OTHER_LABEL: &str = "VLESS";
const DEFAULT_MODE: &str = "proxy";
const DEFAULT_PORTS: (u16, u16) = (10818, 10819);
const LOG_FILE: &str = "proxy.log";

static CHILD: Mutex<Option<Child>> = Mutex::new(None);

/// Режим соседнего экземпляра, если он работает: `Some(true)` TUN, `Some(false)` системный прокси.
fn other_mode() -> Option<bool> {
    crate::vless::running_mode()
}

include!("xray_engine.rs");


/// Работает ли ядро этого экземпляра и в каком режиме (для проверки конфликтов между вкладками).
pub(crate) fn running_mode() -> Option<bool> {
    if running() { Some(load_config().mode != "proxy") } else { None }
}

#[tauri::command]
pub async fn proxy_status() -> Result<Info, String> {
    cmd_vless_status().await
}

#[tauri::command]
pub async fn proxy_connect(id: String) -> Result<Info, String> {
    cmd_vless_connect(id).await
}

#[tauri::command]
pub async fn proxy_disconnect() -> Result<Done, String> {
    cmd_vless_disconnect().await
}

#[tauri::command]
pub async fn proxy_repair() -> Result<Done, String> {
    cmd_vless_repair().await
}

#[tauri::command]
pub async fn proxy_add(text: String) -> Result<Imported, String> {
    cmd_proxy_add(text).await
}

#[tauri::command]
pub async fn proxy_delete(ids: Vec<String>) -> Result<Info, String> {
    cmd_vless_delete(ids).await
}

#[tauri::command]
pub async fn proxy_select(id: String) -> Result<Info, String> {
    cmd_vless_select(id).await
}

#[tauri::command]
pub async fn proxy_config_set(config: Config) -> Result<Info, String> {
    cmd_vless_config_set(config).await
}

#[tauri::command]
pub async fn proxy_profile_view(id: String) -> Result<String, String> {
    cmd_vless_profile_view(id).await
}

#[tauri::command]
pub async fn proxy_ping_one(id: String) -> Result<Option<u32>, String> {
    cmd_vless_ping_one(id).await
}

#[tauri::command]
pub async fn proxy_processes() -> Result<Vec<Proc>, String> {
    cmd_vless_processes().await
}

#[tauri::command]
pub async fn proxy_log() -> Result<String, String> {
    cmd_vless_log().await
}

