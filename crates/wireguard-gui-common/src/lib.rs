//! Shared types and parsing for WireGuard GUI and privileged helper.

mod wg_conf;
mod wg_dump;

pub use wg_conf::{parse_wg_quick_conf, WgQuickConf};
pub use wg_dump::{parse_wg_show_dump, WgDumpInterface, WgDumpPeer};
pub use wg_conf::ParseConfError;

use serde::{Deserialize, Serialize};

/// JSON body for `wireguard-gui-helper create --file <path>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTunnelRequest {
    pub name: String,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    /// When true, ignore `private_key` and generate a new keypair.
    #[serde(default)]
    pub generate_keys: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    pub peer: CreatePeerRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePeerRequest {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub allowed_ips: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatusResponse {
    pub tunnels: Vec<TunnelStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    /// Config basename without `.conf` (wg-quick convention).
    pub name: String,
    pub config_path: String,
    pub has_config_file: bool,
    pub interface_up: bool,
    /// IPv4/IPv6 from live interface if up, else from config.
    pub addresses: Vec<String>,
    pub listen_port: Option<u16>,
    pub dns: Vec<String>,
    #[serde(default)]
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub allowed_ips: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_handshake: Option<u64>,
    #[serde(default)]
    pub transfer_rx: u64,
    #[serde(default)]
    pub transfer_tx: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperErrorResponse {
    pub ok: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl HelperErrorResponse {
    pub fn new(message: impl Into<String>, details: Option<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            details,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleOkResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Validate interface / tunnel name for wg-quick (alphanumeric + underscore).
pub fn validate_tunnel_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 15 {
        return Err("name must be 1–15 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("name may only contain letters, digits, and underscore");
    }
    Ok(())
}
