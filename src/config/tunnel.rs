use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct TunnelConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub vpn: TunnelVpnConfig,
    #[serde(default)]
    pub quic: TunnelQuicConfig,
    #[serde(default)]
    pub mesh: Option<crate::mesh::config::MeshConfig>,
}

impl TunnelConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.vpn.enabled {
            self.vpn.validate()?;
        }
        if self.quic.enabled {
            self.quic.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct TunnelVpnConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_wg_bind")]
    pub bind_address: String,
    #[serde(default = "default_wg_port")]
    pub port: u16,
    #[serde(default = "default_wg_interface")]
    pub interface: String,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub peers: Vec<WireGuardPeerConfig>,
    #[serde(default)]
    pub persistent_keepalive: u16,
}

impl TunnelVpnConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.private_key.is_none() {
            return Err(ConfigValidationError {
                field: "tunnel.vpn.private_key".to_string(),
                message: "WireGuard VPN enabled but no private key provided".to_string(),
            });
        }
        if self.addresses.is_empty() {
            return Err(ConfigValidationError {
                field: "tunnel.vpn.addresses".to_string(),
                message: "WireGuard VPN requires at least one address".to_string(),
            });
        }
        Ok(())
    }
}

fn default_wg_bind() -> String {
    "0.0.0.0".to_string()
}
fn default_wg_port() -> u16 {
    51820
}
fn default_wg_interface() -> String {
    "wg0".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct WireGuardPeerConfig {
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_peer_keepalive")]
    pub persistent_keepalive: u16,
    #[serde(default)]
    pub enabled: bool,
}

fn default_peer_keepalive() -> u16 {
    25
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct TunnelQuicConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_quic_bind")]
    pub bind_address: String,
    #[serde(default = "default_quic_port")]
    pub port: u16,
    #[serde(default = "default_quic_max_idle")]
    pub max_idle_timeout_secs: u64,
    #[serde(default = "default_quic_keepalive")]
    pub keepalive_interval_secs: u64,
    #[serde(default)]
    pub server: TunnelQuicServerConfig,
    #[serde(default)]
    pub client: TunnelQuicClientConfig,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub client_ca: Option<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default = "default_dedicated_worker")]
    pub dedicated_worker: bool,
    #[serde(default = "default_max_streams")]
    pub max_concurrent_streams: u64,
    #[serde(default = "default_max_stream_buffer")]
    pub max_stream_buffer_size: usize,
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    #[serde(default)]
    pub auto_generate_certs: bool,
    #[serde(default)]
    pub cert_domain: Option<String>,
    #[serde(default = "default_udp_tunnel_timeout")]
    pub udp_tunnel_timeout_secs: u64,
    #[serde(default = "default_udp_max_datagram_size")]
    pub udp_max_datagram_size: usize,
    #[serde(default)]
    pub high_throughput_mode: bool,
    #[serde(default = "default_congestion_control")]
    pub congestion_control: String,
    #[serde(default = "default_initial_congestion_window")]
    pub initial_congestion_window: u32,
    #[serde(default = "default_stream_receive_window")]
    pub stream_receive_window: u64,
    #[serde(default = "default_connection_receive_window")]
    pub connection_receive_window: u64,
    #[serde(default)]
    pub tls_passthrough: bool,
}

impl TunnelQuicConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.max_concurrent_streams == 0 {
            return Err(ConfigValidationError {
                field: "tunnel.quic.max_concurrent_streams".to_string(),
                message: "Max concurrent streams must be greater than 0".to_string(),
            });
        }
        match self.congestion_control.as_str() {
            "bbr" | "cubic" | "new_reno" => {}
            _ => {
                return Err(ConfigValidationError {
                    field: "tunnel.quic.congestion_control".to_string(),
                    message: "Congestion control must be 'bbr', 'cubic', or 'new_reno'".to_string(),
                });
            }
        }
        Ok(())
    }
}

fn default_dedicated_worker() -> bool {
    true
}
fn default_max_streams() -> u64 {
    100
}
fn default_max_stream_buffer() -> usize {
    1024 * 1024
}
fn default_max_message_size() -> usize {
    1024 * 1024
}
fn default_udp_tunnel_timeout() -> u64 {
    60
}
fn default_udp_max_datagram_size() -> usize {
    1200
}
fn default_quic_bind() -> String {
    "0.0.0.0".to_string()
}
fn default_quic_port() -> u16 {
    51821
}
fn default_quic_max_idle() -> u64 {
    300
}
fn default_quic_keepalive() -> u64 {
    25
}
fn default_congestion_control() -> String {
    "bbr".to_string()
}
fn default_initial_congestion_window() -> u32 {
    32
}
fn default_stream_receive_window() -> u64 {
    16 * 1024 * 1024
}
fn default_connection_receive_window() -> u64 {
    64 * 1024 * 1024
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum VpnAccessLevel {
    #[default]
    General,
    Admin,
}

impl VpnAccessLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            VpnAccessLevel::Admin => "admin",
            VpnAccessLevel::General => "general",
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct QuicVpnClientConfig {
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub access_level: VpnAccessLevel,
    #[serde(default = "default_client_enabled")]
    pub enabled: bool,
}

impl Default for QuicVpnClientConfig {
    fn default() -> Self {
        Self {
            auth_token: String::new(),
            access_level: VpnAccessLevel::General,
            enabled: true,
        }
    }
}

fn default_client_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct QuicVpnAccessConfig {
    #[serde(default = "default_general_allowed_ports")]
    pub general_allowed_ports: Vec<u16>,
    #[serde(default = "default_general_allowed_ports_udp")]
    pub general_allowed_ports_udp: Vec<u16>,
}

impl Default for QuicVpnAccessConfig {
    fn default() -> Self {
        Self {
            general_allowed_ports: default_general_allowed_ports(),
            general_allowed_ports_udp: default_general_allowed_ports_udp(),
        }
    }
}

fn default_general_allowed_ports() -> Vec<u16> {
    vec![80, 443, 8080, 8443]
}
fn default_general_allowed_ports_udp() -> Vec<u16> {
    vec![53, 443]
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct TunnelQuicServerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub mappings: std::collections::HashMap<String, PortMappingConfig>,
    #[serde(default)]
    pub require_client_cert: bool,
    #[serde(default)]
    pub allow_unauthenticated: bool,
    #[serde(default)]
    pub allow_unauthenticated_confirmation: Option<String>,
    #[serde(default = "default_quic_server_max_connections")]
    pub max_connections: usize,
    #[serde(default)]
    pub clients: std::collections::HashMap<String, QuicVpnClientConfig>,
    #[serde(default)]
    pub vpn_access: QuicVpnAccessConfig,
    #[serde(default = "default_auth_rate_limit_max_attempts")]
    pub auth_rate_limit_max_attempts: usize,
    #[serde(default = "default_auth_rate_limit_window_secs")]
    pub auth_rate_limit_window_secs: u64,
}

impl TunnelQuicServerConfig {
    const ALLOW_UNAUTH_CONFIRMATION: &'static str = "I_UNDERSTAND_THIS_IS_INSECURE_FOR_PRODUCTION";

    pub fn is_allow_unauthenticated_confirmed(&self) -> bool {
        if !self.allow_unauthenticated {
            return false;
        }
        self.allow_unauthenticated_confirmation.as_deref() == Some(Self::ALLOW_UNAUTH_CONFIRMATION)
    }
}

fn default_auth_rate_limit_max_attempts() -> usize {
    3
}
fn default_auth_rate_limit_window_secs() -> u64 {
    60
}
fn default_quic_server_max_connections() -> usize {
    1000
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct PortMappingConfig {
    pub port: u16,
    pub protocol: String,
    pub upstream_host: Option<String>,
    pub upstream_port: Option<u16>,
}

impl Default for PortMappingConfig {
    fn default() -> Self {
        Self {
            port: 80,
            protocol: "tcp".to_string(),
            upstream_host: Some("127.0.0.1".to_string()),
            upstream_port: Some(80),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct TunnelQuicClientConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub mappings: std::collections::HashMap<String, PortMappingConfig>,
    #[serde(default)]
    pub peers: std::collections::HashMap<String, TunnelQuicPeerConfig>,
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
    #[serde(default)]
    pub server_ca: Option<String>,
    #[serde(default)]
    pub verify_server: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct TunnelQuicPeerConfig {
    pub address: String,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default = "default_peer_weight")]
    pub weight: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub upstream_host: Option<String>,
    #[serde(default)]
    pub upstream_port: Option<u16>,
}

impl Default for TunnelQuicPeerConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            auth_token: String::new(),
            weight: 100,
            enabled: true,
            server_name: None,
            upstream_host: None,
            upstream_port: None,
        }
    }
}

fn default_peer_weight() -> u32 {
    100
}
