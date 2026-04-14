use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::tunnel::wireguard::config::{WgImplementation, WireGuardConfig, WireGuardPeerConfig};
use crate::tunnel::wireguard::session::{WgPeerSession, WgSessionManager};
use crate::tunnel::wireguard::stats::{WgInterfaceStats, WgPeerStats, WgStatsCollector};

#[test]
fn test_vpn_client_config_wireguard_mode() {
    use crate::vpn_client::{TransportType, VpnClientConfig, WireGuardClientTransportConfig};

    let wg_transport = WireGuardClientTransportConfig::new(
        "GMHOtIbfPFGbUDhMY9ggLQWjmf9qxj+Jx9qGgyT4pVo=",
        "KUtqWjuqVvRKSSnXyKGD3qcS6m3FD1Y0e5wzHUzX4VU=",
        "vpn.example.com:51820",
    )
    .with_allowed_ips(vec!["10.0.0.0/24"])
    .with_implementation(WgImplementation::Userspace);

    let config = VpnClientConfig::default()
        .with_transport(TransportType::WireGuard)
        .with_wireguard(wg_transport);

    assert_eq!(config.transport, TransportType::WireGuard);
    assert!(config.wireguard.is_some());

    let wg_config = config.wireguard.unwrap().to_wireguard_config();
    assert_eq!(wg_config.implementation, WgImplementation::Userspace);
    assert_eq!(wg_config.peers.len(), 1);
}

#[test]
fn test_vpn_client_config_transport_types() {
    use crate::vpn_client::{TransportType, VpnClientConfig};

    let quic_config = VpnClientConfig::default();
    assert_eq!(quic_config.transport, TransportType::Quic);
    assert!(quic_config.wireguard.is_none());

    let wg_config = VpnClientConfig::default().with_transport(TransportType::WireGuard);
    assert_eq!(wg_config.transport, TransportType::WireGuard);
}

#[test]
fn test_wireguard_client_transport_config_to_wireguard_config() {
    use crate::vpn_client::WireGuardClientTransportConfig;

    let wg_transport = WireGuardClientTransportConfig::new(
        "private_key_here",
        "public_key_here",
        "endpoint:51820",
    )
    .with_allowed_ips(vec!["0.0.0.0/1", "192.168.0.0/16"]);

    assert_eq!(wg_transport.private_key, "private_key_here");
    assert_eq!(wg_transport.peer_public_key, "public_key_here");
    assert_eq!(wg_transport.allowed_ips.len(), 2);
}

#[test]
fn test_full_config_flow() {
    let peer = WireGuardPeerConfig::new(
        "KUtqWjuqVvRKSSnXyKGD3qcS6m3FD1Y0e5wzHUzX4VU=",
        vec!["0.0.0.0/0"],
    )
    .with_endpoint("vpn.example.com:51820")
    .with_persistent_keepalive(25);

    let config = WireGuardConfig::new("GMHOtIbfPFGbUDhMY9ggLQWjmf9qxj+Jx9qGgyT4pVo=")
        .with_interface_name("wg0")
        .with_listen_port(51820)
        .with_peer(peer)
        .with_implementation(WgImplementation::Auto);

    assert_eq!(config.interface_name, "wg0");
    assert_eq!(config.listen_port, 51820);
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.implementation, WgImplementation::Auto);

    let validation = config.validate();
    assert!(validation.is_ok());
}

#[test]
fn test_session_lifecycle() {
    let manager = WgSessionManager::new();

    let session1 = WgPeerSession::new(
        "peer1_public_key".to_string(),
        vec!["10.0.0.0/24".to_string()],
    );
    let id1 = session1.id.clone();

    let session2 = WgPeerSession::new(
        "peer2_public_key".to_string(),
        vec!["10.0.1.0/24".to_string()],
    );
    let id2 = session2.id.clone();

    manager.add_session(session1);
    manager.add_session(session2);

    assert_eq!(manager.session_count(), 2);

    manager.update_session(&id1, |s| {
        s.update_handshake();
        s.add_tx_bytes(1000);
        s.add_rx_bytes(500);
    });

    let updated = manager.get_session(&id1).unwrap();
    assert!(updated.is_established());
    assert_eq!(updated.tx_bytes, 1000);
    assert_eq!(updated.rx_bytes, 500);

    manager.remove_session(&id1);
    assert_eq!(manager.session_count(), 1);

    manager.remove_session(&id2);
    assert_eq!(manager.session_count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn test_stats_parsing_multiple_interfaces() {
    use crate::tunnel::wireguard::stats::parse_wg_show_output;

    let output = r#"
interface: wg0
  public key: SERVER_PUB_KEY
  private key: (hidden)
  listening port: 51820

peer: CLIENT1_PUB
  endpoint: 10.0.0.1:51820
  allowed ips: 10.100.0.2/32
  latest handshake: 2 minutes, 15 seconds ago
  transfer: 15.50 MiB received, 8.25 MiB sent

peer: CLIENT2_PUB
  endpoint: 10.0.0.2:51820
  allowed ips: 10.100.0.3/32
  latest handshake: 5 minutes ago
  transfer: 5.00 MiB received, 3.00 MiB sent
"#;

    let interfaces = parse_wg_show_output(output).unwrap();
    assert_eq!(interfaces.len(), 1);

    let iface = &interfaces[0];
    assert_eq!(iface.name, "wg0");
    assert_eq!(iface.listen_port, 51820);
    assert_eq!(iface.peers.len(), 2);

    assert_eq!(iface.total_rx(), 20500000);
    assert_eq!(iface.total_tx(), 11250000);
    assert_eq!(iface.connected_peers(), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn test_stats_parsing_persistent_keepalive() {
    use crate::tunnel::wireguard::stats::parse_wg_show_output;

    let output = r#"
interface: wg0
  public key: ABC
  listening port: 51820

peer: XYZ
  endpoint: 1.2.3.4:51820
  allowed ips: 0.0.0.0/0
  persistent keepalive: every 25 seconds
"#;

    let interfaces = parse_wg_show_output(output).unwrap();
    let peer = &interfaces[0].peers[0];

    assert_eq!(peer.persistent_keepalive, Some(25));
}

#[test]
fn test_interface_stats_helpers() {
    let mut stats = WgInterfaceStats::new("test_wg", "test_pub_key", 51820);

    stats.peers.push(WgPeerStats {
        public_key: "peer1".to_string(),
        endpoint: None,
        allowed_ips: vec!["10.0.0.0/24".to_string()],
        latest_handshake: Some(1000),
        transfer_rx: 1000,
        transfer_tx: 500,
        persistent_keepalive: None,
    });

    stats.peers.push(WgPeerStats {
        public_key: "peer2".to_string(),
        endpoint: None,
        allowed_ips: vec!["10.0.1.0/24".to_string()],
        latest_handshake: Some(2000),
        transfer_rx: 2000,
        transfer_tx: 1000,
        persistent_keepalive: None,
    });

    assert_eq!(stats.total_rx(), 3000);
    assert_eq!(stats.total_tx(), 1500);
    assert_eq!(stats.connected_peers(), 2);

    assert!(stats.peer_by_public_key("peer1").is_some());
    assert!(stats.peer_by_public_key("nonexistent").is_none());
}

#[test]
fn test_implementation_selection() {
    assert_eq!(WgImplementation::Auto, WgImplementation::default());
    assert_ne!(WgImplementation::Kernel, WgImplementation::Userspace);
    assert_ne!(WgImplementation::Auto, WgImplementation::Kernel);
}
