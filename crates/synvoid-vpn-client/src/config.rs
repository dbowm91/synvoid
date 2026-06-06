use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use synvoid_config::TunnelQuicConfig;
use synvoid_tunnel::wireguard::{WgImplementation, WireGuardConfig, WireGuardPeerConfig};

const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10000;
const DEFAULT_RECONNECT_MAX_ATTEMPTS: u32 = 10;
const DEFAULT_RECONNECT_INITIAL_DELAY_MS: u64 = 1000;
const DEFAULT_RECONNECT_MAX_DELAY_MS: u64 = 60000;
const DEFAULT_RECONNECT_BACKOFF_MULTIPLIER: f32 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    #[default]
    Quic,
    WireGuard,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VpnClientConfig {
    pub enabled: bool,
    #[serde(default)]
    pub transport: TransportType,
    pub server_host: String,
    pub server_port: u16,
    pub server_name: Option<String>,
    pub client_id: String,
    pub auth_token: String,
    pub local_bind_host: String,
    #[serde(default)]
    pub port_mappings: Vec<ClientPortMapping>,
    #[serde(default)]
    pub verify_server: bool,
    #[serde(default)]
    pub server_ca: Option<String>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default)]
    pub reconnect: ReconnectConfig,
    #[serde(default)]
    pub wireguard: Option<WireGuardClientTransportConfig>,
}

fn default_connect_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MS
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WireGuardClientTransportConfig {
    pub private_key: String,
    pub peer_public_key: String,
    pub peer_endpoint: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub implementation: WgImplementation,
}

impl WireGuardClientTransportConfig {
    pub fn new(private_key: &str, peer_public_key: &str, peer_endpoint: &str) -> Self {
        Self {
            private_key: private_key.to_string(),
            peer_public_key: peer_public_key.to_string(),
            peer_endpoint: peer_endpoint.to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            implementation: WgImplementation::Auto,
        }
    }

    pub fn with_allowed_ips(mut self, ips: Vec<&str>) -> Self {
        self.allowed_ips = ips.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_implementation(mut self, impl_type: WgImplementation) -> Self {
        self.implementation = impl_type;
        self
    }

    pub fn to_wireguard_config(&self) -> WireGuardConfig {
        let peer = WireGuardPeerConfig::new(
            &self.peer_public_key,
            self.allowed_ips.iter().map(|s| s.as_str()).collect(),
        )
        .with_endpoint(&self.peer_endpoint);

        WireGuardConfig::new(&self.private_key)
            .with_peer(peer)
            .with_implementation(self.implementation)
    }
}

impl Default for VpnClientConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transport: TransportType::default(),
            server_host: String::new(),
            server_port: 51821,
            server_name: None,
            client_id: String::new(),
            auth_token: String::new(),
            local_bind_host: "127.0.0.1".to_string(),
            port_mappings: Vec::new(),
            verify_server: true,
            server_ca: None,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            reconnect: ReconnectConfig::default(),
            wireguard: None,
        }
    }
}

impl VpnClientConfig {
    pub fn new(server_host: &str, server_port: u16, client_id: &str, auth_token: &str) -> Self {
        Self {
            enabled: true,
            server_host: server_host.to_string(),
            server_port,
            server_name: None,
            client_id: client_id.to_string(),
            auth_token: auth_token.to_string(),
            ..Default::default()
        }
    }

    pub fn with_server_name(mut self, name: &str) -> Self {
        self.server_name = Some(name.to_string());
        self
    }

    pub fn with_local_bind(mut self, host: &str) -> Self {
        self.local_bind_host = host.to_string();
        self
    }

    pub fn with_port_mapping(mut self, mapping: ClientPortMapping) -> Self {
        self.port_mappings.push(mapping);
        self
    }

    pub fn with_tcp_mapping(mut self, local_port: u16, remote_port: u16) -> Self {
        self.port_mappings
            .push(ClientPortMapping::tcp(local_port, remote_port));
        self
    }

    pub fn with_udp_mapping(mut self, local_port: u16, remote_port: u16) -> Self {
        self.port_mappings
            .push(ClientPortMapping::udp(local_port, remote_port));
        self
    }

    pub fn with_verify_server(mut self, verify: bool) -> Self {
        self.verify_server = verify;
        self
    }

    pub fn with_server_ca(mut self, ca_path: &str) -> Self {
        self.server_ca = Some(ca_path.to_string());
        self
    }

    pub fn with_connect_timeout(mut self, timeout_ms: u64) -> Self {
        self.connect_timeout_ms = timeout_ms;
        self
    }

    pub fn with_reconnect(mut self, reconnect: ReconnectConfig) -> Self {
        self.reconnect = reconnect;
        self
    }

    pub fn with_wireguard(mut self, wg_config: WireGuardClientTransportConfig) -> Self {
        self.transport = TransportType::WireGuard;
        self.wireguard = Some(wg_config);
        self
    }

    pub fn with_transport(mut self, transport: TransportType) -> Self {
        self.transport = transport;
        self
    }

    pub fn is_wireguard(&self) -> bool {
        self.transport == TransportType::WireGuard
    }

    pub fn to_quic_config(&self) -> TunnelQuicConfig {
        TunnelQuicConfig {
            enabled: true,
            bind_address: "0.0.0.0".to_string(),
            port: 0,
            max_idle_timeout_secs: 300,
            keepalive_interval_secs: 25,
            server: Default::default(),
            client: synvoid_config::TunnelQuicClientConfig {
                enabled: true,
                client_id: self.client_id.clone(),
                auth_token: self.auth_token.clone(),
                mappings: HashMap::new(),
                peers: HashMap::new(),
                client_cert_path: None,
                client_key_path: None,
                server_ca: self.server_ca.clone(),
                verify_server: self.verify_server,
            },
            cert_path: None,
            key_path: None,
            client_ca: None,
            whitelist: Vec::new(),
            dedicated_worker: false,
            max_concurrent_streams: 100,
            max_stream_buffer_size: 1024 * 1024,
            max_message_size: 1024 * 1024,
            auto_generate_certs: false,
            cert_domain: None,
            udp_tunnel_timeout_secs: 300,
            udp_max_datagram_size: 1200,
            high_throughput_mode: false,
            congestion_control: "bbr".to_string(),
            initial_congestion_window: 32,
            stream_receive_window: 16 * 1024 * 1024,
            connection_receive_window: 64 * 1024 * 1024,
            tls_passthrough: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientPortMapping {
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub upstream_host: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

impl ClientPortMapping {
    pub fn tcp(local_port: u16, remote_port: u16) -> Self {
        Self {
            local_port,
            remote_port,
            protocol: Protocol::Tcp,
            upstream_host: None,
        }
    }

    pub fn udp(local_port: u16, remote_port: u16) -> Self {
        Self {
            local_port,
            remote_port,
            protocol: Protocol::Udp,
            upstream_host: None,
        }
    }

    pub fn with_upstream(mut self, host: &str) -> Self {
        self.upstream_host = Some(host.to_string());
        self
    }

    pub fn identifier(&self) -> String {
        format!("local-{}-{}", self.local_port, self.protocol)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReconnectConfig {
    pub enabled: bool,
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f32,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: DEFAULT_RECONNECT_MAX_ATTEMPTS,
            initial_delay_ms: DEFAULT_RECONNECT_INITIAL_DELAY_MS,
            max_delay_ms: DEFAULT_RECONNECT_MAX_DELAY_MS,
            backoff_multiplier: DEFAULT_RECONNECT_BACKOFF_MULTIPLIER,
        }
    }
}

impl ReconnectConfig {
    pub fn new(enabled: bool, max_attempts: u32) -> Self {
        Self {
            enabled,
            max_attempts,
            ..Default::default()
        }
    }

    pub fn with_delays(mut self, initial_ms: u64, max_ms: u64) -> Self {
        self.initial_delay_ms = initial_ms;
        self.max_delay_ms = max_ms;
        self
    }

    pub fn with_backoff(mut self, multiplier: f32) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }
}
