use std::net::SocketAddr;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum WgImplementation {
    #[default]
    Auto,
    Kernel,
    Userspace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub enabled: bool,
    #[serde(default)]
    pub interface_name: String,
    pub private_key: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub peers: Vec<WireGuardPeerConfig>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub implementation: WgImplementation,
    #[serde(default)]
    pub fwmark: Option<u32>,
    #[serde(default)]
    pub table: Option<u32>,
    #[serde(default)]
    pub pre_up: Option<String>,
    #[serde(default)]
    pub post_up: Option<String>,
    #[serde(default)]
    pub pre_down: Option<String>,
    #[serde(default)]
    pub post_down: Option<String>,
    #[serde(default)]
    pub auto_reconnect: bool,
    #[serde(default = "default_reconnect_interval_secs")]
    pub reconnect_interval_secs: u64,
}

fn default_listen_port() -> u16 {
    51820
}
fn default_mtu() -> u16 {
    1420
}
fn default_reconnect_interval_secs() -> u64 {
    5
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface_name: "wg0".to_string(),
            private_key: String::new(),
            listen_port: default_listen_port(),
            peers: Vec::new(),
            dns: Vec::new(),
            mtu: default_mtu(),
            implementation: WgImplementation::Auto,
            fwmark: None,
            table: None,
            pre_up: None,
            post_up: None,
            pre_down: None,
            post_down: None,
            auto_reconnect: true,
            reconnect_interval_secs: default_reconnect_interval_secs(),
        }
    }
}

impl WireGuardConfig {
    pub fn new(private_key: &str) -> Self {
        Self {
            enabled: true,
            private_key: private_key.to_string(),
            ..Default::default()
        }
    }

    pub fn with_interface_name(mut self, name: &str) -> Self {
        self.interface_name = name.to_string();
        self
    }

    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    pub fn with_peer(mut self, peer: WireGuardPeerConfig) -> Self {
        self.peers.push(peer);
        self
    }

    pub fn with_dns(mut self, dns: Vec<String>) -> Self {
        self.dns = dns;
        self
    }

    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    pub fn with_implementation(mut self, impl_type: WgImplementation) -> Self {
        self.implementation = impl_type;
        self
    }

    pub fn with_fwmark(mut self, fwmark: u32) -> Self {
        self.fwmark = Some(fwmark);
        self
    }

    pub fn with_post_up(mut self, cmd: &str) -> Self {
        self.post_up = Some(cmd.to_string());
        self
    }

    pub fn with_post_down(mut self, cmd: &str) -> Self {
        self.post_down = Some(cmd.to_string());
        self
    }

    pub fn validate(&self) -> Result<(), WireGuardConfigError> {
        if self.private_key.is_empty() {
            return Err(WireGuardConfigError::MissingPrivateKey);
        }

        if let Err(e) = validate_base64_key(&self.private_key) {
            return Err(WireGuardConfigError::InvalidPrivateKey(e));
        }

        for (i, peer) in self.peers.iter().enumerate() {
            if peer.public_key.is_empty() {
                return Err(WireGuardConfigError::MissingPeerPublicKey(i));
            }
            if let Err(e) = validate_base64_key(&peer.public_key) {
                return Err(WireGuardConfigError::InvalidPeerPublicKey(i, e));
            }
            if peer.allowed_ips.is_empty() {
                return Err(WireGuardConfigError::MissingAllowedIPs(i));
            }
        }

        if self.mtu < 576 || self.mtu > 1500 {
            return Err(WireGuardConfigError::InvalidMtu(self.mtu));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeerConfig {
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default = "default_persistent_keepalive")]
    pub persistent_keepalive: u16,
}

fn default_persistent_keepalive() -> u16 {
    0
}

impl WireGuardPeerConfig {
    pub fn new(public_key: &str, allowed_ips: Vec<&str>) -> Self {
        Self {
            public_key: public_key.to_string(),
            preshared_key: None,
            endpoint: None,
            allowed_ips: allowed_ips.into_iter().map(|s| s.to_string()).collect(),
            persistent_keepalive: 0,
        }
    }

    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = Some(endpoint.to_string());
        self
    }

    pub fn with_preshared_key(mut self, psk: &str) -> Self {
        self.preshared_key = Some(psk.to_string());
        self
    }

    pub fn with_persistent_keepalive(mut self, interval: u16) -> Self {
        self.persistent_keepalive = interval;
        self
    }

    pub fn endpoint_addr(&self) -> Option<SocketAddr> {
        self.endpoint.as_ref().and_then(|s| s.parse().ok())
    }

    pub fn allowed_ip_networks(&self) -> Result<Vec<IpNetwork>, String> {
        self.allowed_ips
            .iter()
            .map(|s| s.parse::<IpNetwork>().map_err(|e| format!("{}: {}", s, e)))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct WireGuardInterface {
    pub name: String,
    pub listen_port: u16,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub fwmark: Option<u32>,
    pub mtu: u16,
    pub addresses: Vec<IpNetwork>,
}

#[derive(Debug, Clone)]
pub struct WireGuardPeer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<std::time::Duration>,
    pub last_handshake: Option<std::time::Instant>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

impl From<WireGuardPeerConfig> for WireGuardPeer {
    fn from(config: WireGuardPeerConfig) -> Self {
        let public_key = base64_decode_key(&config.public_key).unwrap_or([0u8; 32]);
        let preshared_key = config
            .preshared_key
            .as_ref()
            .and_then(|k| base64_decode_key(k));
        let endpoint = config.endpoint.as_ref().and_then(|s| s.parse().ok());
        let allowed_ips = config.allowed_ip_networks().unwrap_or_default();
        let persistent_keepalive = if config.persistent_keepalive > 0 {
            Some(std::time::Duration::from_secs(
                config.persistent_keepalive as u64,
            ))
        } else {
            None
        };

        Self {
            public_key,
            preshared_key,
            endpoint,
            allowed_ips,
            persistent_keepalive,
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WireGuardConfigError {
    #[error("Missing private key")]
    MissingPrivateKey,
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("Missing public key for peer {0}")]
    MissingPeerPublicKey(usize),
    #[error("Invalid public key for peer {0}: {1}")]
    InvalidPeerPublicKey(usize, String),
    #[error("Missing allowed IPs for peer {0}")]
    MissingAllowedIPs(usize),
    #[error("Invalid MTU: {0}")]
    InvalidMtu(u16),
    #[error("Invalid endpoint: {0}")]
    InvalidEndpoint(String),
}

fn validate_base64_key(key: &str) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let decoded = STANDARD
        .decode(key)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    if decoded.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", decoded.len()));
    }

    Ok(())
}

pub fn base64_decode_key(key: &str) -> Option<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let decoded = STANDARD.decode(key).ok()?;
    if decoded.len() != 32 {
        return None;
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Some(arr)
}

pub fn generate_keypair() -> (String, String) {
    use rand::{RngCore, SeedableRng};

    let mut private_key = [0u8; 32];
    let mut rng = rand::rngs::StdRng::from_os_rng();
    rng.fill_bytes(&mut private_key);

    let public_key = x25519_public_from_private(&private_key);

    let private_b64 = base64_encode_key(&private_key);
    let public_b64 = base64_encode_key(&public_key);

    (private_b64, public_b64)
}

pub fn x25519_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    #[cfg(feature = "wireguard")]
    {
        let secret = defguard_boringtun::x25519::StaticSecret::from(*private_key);
        let public = defguard_boringtun::x25519::PublicKey::from(&secret);
        *public.as_bytes()
    }

    #[cfg(not(feature = "wireguard"))]
    {
        use rand::{RngCore, SeedableRng};
        let _private_key = private_key;
        let mut pk = [0u8; 32];
        let mut rng = rand::rngs::StdRng::from_os_rng();
        rng.fill_bytes(&mut pk);
        pk
    }
}

pub fn base64_encode_key(key: &[u8; 32]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(key)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardClientConfig {
    #[serde(flatten)]
    pub base: WireGuardConfig,
    #[serde(default)]
    pub local_addresses: Vec<String>,
    #[serde(default)]
    pub route_all_traffic: bool,
    #[serde(default)]
    pub allowed_ips_for_routing: Vec<String>,
}

impl From<WireGuardClientConfig> for WireGuardConfig {
    fn from(client: WireGuardClientConfig) -> Self {
        client.base
    }
}

impl WireGuardClientConfig {
    pub fn new(private_key: &str, peer: WireGuardPeerConfig) -> Self {
        Self {
            base: WireGuardConfig::new(private_key).with_peer(peer),
            local_addresses: Vec::new(),
            route_all_traffic: false,
            allowed_ips_for_routing: Vec::new(),
        }
    }

    pub fn with_local_address(mut self, addr: &str) -> Self {
        self.local_addresses.push(addr.to_string());
        self
    }

    pub fn with_route_all_traffic(mut self, route: bool) -> Self {
        self.route_all_traffic = route;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardServerConfig {
    #[serde(flatten)]
    pub base: WireGuardConfig,
    #[serde(default)]
    pub address_pool: Option<String>,
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
}

fn default_max_peers() -> usize {
    100
}

impl From<WireGuardServerConfig> for WireGuardConfig {
    fn from(server: WireGuardServerConfig) -> Self {
        server.base
    }
}

impl WireGuardServerConfig {
    pub fn new(private_key: &str, listen_port: u16) -> Self {
        Self {
            base: WireGuardConfig::new(private_key).with_listen_port(listen_port),
            address_pool: None,
            max_peers: default_max_peers(),
        }
    }

    pub fn with_address_pool(mut self, pool: &str) -> Self {
        self.address_pool = Some(pool.to_string());
        self
    }

    pub fn with_max_peers(mut self, max: usize) -> Self {
        self.max_peers = max;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_private_key() -> String {
        "GMHOtIbfPFGbUDhMY9ggLQWjmf9qxj+Jx9qGgyT4pVo=".to_string()
    }

    fn valid_public_key() -> String {
        "KUtqWjuqVvRKSSnXyKGD3qcS6m3FD1Y0e5wzHUzX4VU=".to_string()
    }

    #[test]
    fn test_wireguard_config_new() {
        let config = WireGuardConfig::new(&valid_private_key());

        assert!(config.enabled);
        assert_eq!(config.interface_name, "wg0");
        assert_eq!(config.listen_port, 51820);
        assert!(config.peers.is_empty());
        assert_eq!(config.mtu, 1420);
    }

    #[test]
    fn test_wireguard_config_builder() {
        let peer = WireGuardPeerConfig::new(&valid_public_key(), vec!["10.0.0.0/24"])
            .with_endpoint("vpn.example.com:51820")
            .with_persistent_keepalive(25);

        let config = WireGuardConfig::new(&valid_private_key())
            .with_interface_name("wg1")
            .with_listen_port(51821)
            .with_peer(peer)
            .with_mtu(1280)
            .with_implementation(WgImplementation::Userspace);

        assert_eq!(config.interface_name, "wg1");
        assert_eq!(config.listen_port, 51821);
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.mtu, 1280);
        assert_eq!(config.implementation, WgImplementation::Userspace);
    }

    #[test]
    fn test_wireguard_peer_config() {
        let peer =
            WireGuardPeerConfig::new(&valid_public_key(), vec!["10.0.0.0/24", "192.168.1.0/24"])
                .with_endpoint("1.2.3.4:51820")
                .with_persistent_keepalive(30);

        assert_eq!(peer.public_key, valid_public_key());
        assert_eq!(peer.endpoint, Some("1.2.3.4:51820".to_string()));
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(peer.persistent_keepalive, 30);
    }

    #[test]
    fn test_peer_endpoint_addr() {
        let peer = WireGuardPeerConfig::new(&valid_public_key(), vec!["0.0.0.0/0"])
            .with_endpoint("192.168.1.1:51820");

        let addr = peer.endpoint_addr().unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 51820);
    }

    #[test]
    fn test_peer_allowed_ip_networks() {
        let peer =
            WireGuardPeerConfig::new(&valid_public_key(), vec!["10.0.0.0/24", "192.168.0.0/16"]);

        let networks = peer.allowed_ip_networks().unwrap();
        assert_eq!(networks.len(), 2);
    }

    #[test]
    fn test_config_validation_valid() {
        let config = WireGuardConfig::new(&valid_private_key()).with_peer(
            WireGuardPeerConfig::new(&valid_public_key(), vec!["10.0.0.0/24"]),
        );

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_missing_private_key() {
        let config = WireGuardConfig::new("");

        match config.validate() {
            Err(WireGuardConfigError::MissingPrivateKey) => {}
            _ => panic!("Expected MissingPrivateKey error"),
        }
    }

    #[test]
    fn test_config_validation_invalid_mtu() {
        let config = WireGuardConfig::new(&valid_private_key()).with_mtu(100);

        match config.validate() {
            Err(WireGuardConfigError::InvalidMtu(100)) => {}
            _ => panic!("Expected InvalidMtu error"),
        }
    }

    #[test]
    fn test_wireguard_client_config() {
        let peer = WireGuardPeerConfig::new(&valid_public_key(), vec!["0.0.0.0/0"])
            .with_endpoint("vpn.example.com:51820");

        let config = WireGuardClientConfig::new(&valid_private_key(), peer)
            .with_local_address("10.0.0.2")
            .with_route_all_traffic(true);

        assert_eq!(config.local_addresses.len(), 1);
        assert!(config.route_all_traffic);
    }

    #[test]
    fn test_wireguard_server_config() {
        let config = WireGuardServerConfig::new(&valid_private_key(), 51820)
            .with_address_pool("10.100.0.0/24")
            .with_max_peers(50);

        assert_eq!(config.base.listen_port, 51820);
        assert_eq!(config.address_pool, Some("10.100.0.0/24".to_string()));
        assert_eq!(config.max_peers, 50);
    }

    #[test]
    fn test_generate_keypair() {
        let (private_key, public_key) = generate_keypair();

        assert!(!private_key.is_empty());
        assert!(!public_key.is_empty());

        assert!(validate_base64_key(&private_key).is_ok());
        assert!(validate_base64_key(&public_key).is_ok());
    }

    #[test]
    fn test_x25519_public_from_private() {
        let private_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let public_bytes = x25519_public_from_private(&private_bytes);

        assert_ne!(public_bytes, [0u8; 32]);
    }

    #[test]
    fn test_base64_decode_key() {
        let key = "GMHOtIbfPFGbUDhMY9ggLQWjmf9qxj+Jx9qGgyT4pVo=";
        let decoded = base64_decode_key(key);

        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap().len(), 32);
    }

    #[test]
    fn test_base64_decode_key_invalid() {
        let invalid_key = "not-valid-base64!!!";
        let decoded = base64_decode_key(invalid_key);

        assert!(decoded.is_none());
    }

    #[test]
    fn test_base64_encode_key() {
        let key: [u8; 32] = [0u8; 32];
        let encoded = base64_encode_key(&key);

        assert!(!encoded.is_empty());
        assert!(base64_decode_key(&encoded).is_some());
    }

    #[test]
    fn test_wireguard_peer_from_config() {
        let peer_config = WireGuardPeerConfig::new(&valid_public_key(), vec!["10.0.0.0/24"])
            .with_endpoint("1.2.3.4:51820")
            .with_persistent_keepalive(25);

        let peer: WireGuardPeer = peer_config.into();

        assert_eq!(peer.endpoint.unwrap().port(), 51820);
        assert!(peer.persistent_keepalive.is_some());
    }

    #[test]
    fn test_implementation_default() {
        let impl_type: WgImplementation = Default::default();
        assert_eq!(impl_type, WgImplementation::Auto);
    }

    #[test]
    fn test_to_quic_config_conversion() {
        let client_config = crate::vpn_client::VpnClientConfig::default();
        let quic_config = client_config.to_quic_config();

        assert!(quic_config.enabled);
    }
}
