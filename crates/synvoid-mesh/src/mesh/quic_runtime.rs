//! Bridge between `[tunnel.mesh]` and the shared QUIC runtime.
//!
//! Mesh never installed a QUIC runtime: `MeshTransport::set_runtime` had no
//! caller anywhere, so no endpoint was ever bound and every dial failed with
//! `RuntimeNotSet`, while startup still logged "Mesh transport started
//! successfully". This module builds the runtime from the mesh configuration;
//! the composition root installs it before the transport starts.
//!
//! TLS posture follows `[tunnel.mesh.tls]`:
//!
//! * `strict` (the default) verifies peers against `ca_path` and requires the
//!   peer certificate to carry the peer's node id as its SAN. Operator-provided
//!   certificates are mandatory in this mode; auto-generation only produces
//!   self-signed leaves, which cannot satisfy a verified trust store.
//! * `tofu` / `permissive` accept the peer without chain verification. That is
//!   an explicit operator downgrade, which is what the mesh cert manager
//!   already treats it as; it exists so loopback and development topologies can
//!   run without a PKI.

use std::sync::Arc;

use synvoid_config::{TunnelQuicClientConfig, TunnelQuicConfig, TunnelQuicServerConfig};
use synvoid_tunnel::quic::runtime::QuicRuntime;

use super::config::{MeshConfig, MeshTlsMode};

/// Conservative defaults mirrored from `synvoid_config`'s serde defaults.
/// `TunnelQuicConfig` derives `Default`, whose zeros are not valid transport
/// values (a zero stream limit disables streams).
const DEFAULT_MAX_CONCURRENT_STREAMS: u64 = 100;
const DEFAULT_STREAM_BUFFER: usize = 1024 * 1024;
const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const DEFAULT_IDLE_SECS: u64 = 300;
const DEFAULT_KEEPALIVE_SECS: u64 = 25;

/// Whether the configured policy demands verified peer authentication.
pub fn requires_verified_peers(config: &MeshConfig) -> bool {
    matches!(config.tls.effective_mode(), MeshTlsMode::Strict) && config.tls.enforce_mutual_tls
}

/// Build the tunnel-QUIC configuration that carries mesh traffic.
///
/// Mesh and tunnel share the QUIC transport but not its trust configuration:
/// the mesh derives everything from `[tunnel.mesh]` and never reads
/// `[tunnel.quic]`.
pub fn tunnel_config_for_mesh(config: &MeshConfig, listen: bool) -> TunnelQuicConfig {
    let verified = matches!(config.tls.effective_mode(), MeshTlsMode::Strict);
    let node_id = config.node_id();

    TunnelQuicConfig {
        enabled: true,
        bind_address: config
            .bind_address
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string()),
        port: config.port,
        max_idle_timeout_secs: DEFAULT_IDLE_SECS,
        keepalive_interval_secs: DEFAULT_KEEPALIVE_SECS,
        // The endpoint must accept inbound peers (origin side) and dial seeds
        // (edge side), so both halves are enabled.
        server: TunnelQuicServerConfig {
            // Exactly one process per node may own the UDP endpoint: the worker
            // listens (it terminates mesh HTTP), the supervisor dials only.
            enabled: listen,
            // Only meaningful when a client CA is present; the runtime logs a
            // hard misconfiguration warning if this is requested without one.
            require_client_cert: listen && verified && config.tls.enforce_mutual_tls,
            ..Default::default()
        },
        client: TunnelQuicClientConfig {
            enabled: true,
            // quinn rejects a client config that disables server verification
            // ("Server certificate verification must be enabled in current
            // quinn version"), so mesh always verifies peers against
            // `ca_path`. `mode` therefore selects how the mesh cert manager
            // treats peer identity; it cannot disable transport verification.
            verify_server: true,
            // One identity serves inbound and outbound; the mesh cert manager
            // issues a single node certificate.
            client_cert_path: config.tls.cert_path.clone(),
            client_key_path: config.tls.key_path.clone(),
            server_ca: config.tls.ca_path.clone(),
            ..Default::default()
        },
        cert_path: config.tls.cert_path.clone(),
        key_path: config.tls.key_path.clone(),
        // The endpoint uses this CA to verify inbound peer certificates.
        client_ca: config.tls.ca_path.clone(),
        auto_generate_certs: config.tls.auto_generate_certs,
        cert_domain: Some(node_id),
        max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
        max_stream_buffer_size: DEFAULT_STREAM_BUFFER,
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        ..Default::default()
    }
}

/// Construct the mesh QUIC runtime.
///
/// The caller must install it on the transport before startup, otherwise the
/// accept loop is skipped and every dial fails closed.
pub fn create_runtime(config: &MeshConfig, listen: bool) -> Result<Arc<QuicRuntime>, String> {
    let tunnel = tunnel_config_for_mesh(config, listen);
    let runtime = QuicRuntime::new(tunnel)
        .map_err(|error| format!("failed to initialize mesh QUIC runtime: {error}"))?;
    Ok(Arc::new(runtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> MeshConfig {
        serde_json::from_value(serde_json::json!({
            "enabled": true,
            "node_id": "origin-node",
            "role": 4,
            "bind_address": "127.0.0.1",
            "port": 50052
        }))
        .expect("minimal mesh config")
    }

    #[test]
    fn tunnel_config_carries_the_mesh_bind_address_and_port() {
        let config = base_config();
        let tunnel = tunnel_config_for_mesh(&config, true);
        assert_eq!(tunnel.bind_address, "127.0.0.1");
        assert_eq!(tunnel.port, 50052);
        assert!(tunnel.enabled);
        assert!(tunnel.server.enabled, "must accept inbound peers");
        assert!(tunnel.client.enabled, "must dial seeds/peers");
    }

    #[test]
    fn strict_mode_requires_and_verifies_peer_certificates() {
        let mut config = base_config();
        config.tls.mode = Some(MeshTlsMode::Strict);
        let tunnel = tunnel_config_for_mesh(&config, true);
        assert!(tunnel.client.verify_server);
        assert!(tunnel.server.require_client_cert);
        assert!(requires_verified_peers(&config));
    }

    #[test]
    fn permissive_mode_cannot_disable_transport_verification() {
        // quinn refuses a client config without server verification, so the
        // mesh downgrade affects identity handling only, never the wire.
        let mut config = base_config();
        config.tls.mode = Some(MeshTlsMode::Permissive);
        config.tls.auto_generate_certs = true;
        let tunnel = tunnel_config_for_mesh(&config, true);
        assert!(
            tunnel.client.verify_server,
            "server verification is mandatory in this quinn version"
        );
        assert!(!requires_verified_peers(&config));
    }

    #[test]
    fn supervisor_style_runtime_dials_without_listening() {
        let tunnel = tunnel_config_for_mesh(&base_config(), false);
        assert!(
            !tunnel.server.enabled,
            "a second process must not bind the port"
        );
        assert!(tunnel.client.enabled, "it still needs to dial peers");
    }

    #[test]
    fn stream_limits_are_valid_for_the_transport() {
        let tunnel = tunnel_config_for_mesh(&base_config(), true);
        assert!(tunnel.max_concurrent_streams > 0);
        assert!(tunnel.max_stream_buffer_size > 0);
        assert!(tunnel.max_message_size > 0);
    }
}
