#![allow(unused_variables, dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::mesh::config::MeshConfig;
use crate::mesh::protocol::MeshMessage;
use crate::mesh::topology::MeshTopology;
use crate::mesh::transports::{MeshTransportError, MeshTransportTrait, MeshTransportType};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TransportPeerId {
    Quic(String),
    WireGuard(String),
}

impl TransportPeerId {
    pub fn as_str(&self) -> &str {
        match self {
            TransportPeerId::Quic(s) => s,
            TransportPeerId::WireGuard(s) => s,
        }
    }
}

#[derive(Clone)]
pub struct MeshTransportStack {
    config: Arc<MeshConfig>,
    quic_transport: Option<Arc<QuicTransportWrapper>>,
    wireguard_transport: Option<Arc<WireGuardTransportWrapper>>,
    active_transports: Arc<RwLock<HashMap<TransportPeerId, MeshTransportType>>>,
    topology: Arc<MeshTopology>,
}

struct QuicTransportWrapper {
    inner: Arc<crate::mesh::transport::MeshTransport>,
}

struct WireGuardTransportWrapper {
    inner: Arc<crate::mesh::transports::wireguard::WireGuardMeshTransport>,
}

impl MeshTransportStack {
    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
    ) -> Self {
        Self {
            config: config.clone(),
            quic_transport: None,
            wireguard_transport: None,
            active_transports: Arc::new(RwLock::new(HashMap::new())),
            topology,
        }
    }

    pub fn set_quic_transport(&mut self, transport: Arc<crate::mesh::transport::MeshTransport>) {
        self.quic_transport = Some(Arc::new(QuicTransportWrapper { inner: transport }));
    }

    pub fn set_wireguard_transport(&mut self, transport: Arc<crate::mesh::transports::wireguard::WireGuardMeshTransport>) {
        self.wireguard_transport = Some(Arc::new(WireGuardTransportWrapper { inner: transport }));
    }

    pub fn get_peer_transport(&self, peer_id: &str) -> Option<MeshTransportType> {
        let transports = self.active_transports.read();
        transports.get(&TransportPeerId::Quic(peer_id.to_string())).copied()
            .or_else(|| transports.get(&TransportPeerId::WireGuard(peer_id.to_string())).copied())
    }

    pub fn register_peer(&self, peer_id: String, transport_type: MeshTransportType) {
        let key = match transport_type {
            MeshTransportType::Quic => TransportPeerId::Quic(peer_id),
            MeshTransportType::WireGuard => TransportPeerId::WireGuard(peer_id),
        };
        self.active_transports.write().insert(key, transport_type);
    }

    pub fn unregister_peer(&self, peer_id: &str) {
        self.active_transports.write().remove(&TransportPeerId::Quic(peer_id.to_string()));
        self.active_transports.write().remove(&TransportPeerId::WireGuard(peer_id.to_string()));
    }

    pub async fn send_to_peer(
        &self,
        peer_id: &str,
        message: &MeshMessage,
        preferred_transport: Option<MeshTransportType>,
    ) -> Result<(), MeshTransportError> {
        let transport_type = preferred_transport.or_else(|| self.get_peer_transport(peer_id));

        match transport_type {
            Some(MeshTransportType::Quic) => {
                if let Some(ref quic) = self.quic_transport {
                    return quic.inner.send_message_to_peer(peer_id, message).await
                        .map_err(|e| MeshTransportError::SendFailed(e.to_string()));
                }
            }
            Some(MeshTransportType::WireGuard) => {
                if let Some(ref wg) = self.wireguard_transport {
                    return wg.inner.send_stream(peer_id, message).await;
                }
            }
            None => {}
        }

        if let Some(ref quic) = self.quic_transport {
            if quic.inner.peer_connections.contains_key(peer_id) {
                return quic.inner.send_message_to_peer(peer_id, message).await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()));
            }
        }

        if let Some(ref wg) = self.wireguard_transport {
            if wg.inner.is_connected(peer_id) {
                return wg.inner.send_stream(peer_id, message).await;
            }
        }

        Err(MeshTransportError::PeerNotConnected(peer_id.to_string()))
    }

    pub async fn send_datagram_to_peer(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        if let Some(ref quic) = self.quic_transport {
            if quic.inner.peer_connections.contains_key(peer_id) {
                return quic.inner.send_datagram_to_peer(peer_id, message).await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()));
            }
        }

        if let Some(ref wg) = self.wireguard_transport {
            if wg.inner.is_connected(peer_id) {
                return wg.inner.send_datagram(peer_id, message).await;
            }
        }

        Err(MeshTransportError::PeerNotConnected(peer_id.to_string()))
    }

    pub async fn broadcast_datagram(&self, message: &MeshMessage) -> Result<(), MeshTransportError> {
        let mut errors = Vec::new();

        if let Some(ref quic) = self.quic_transport {
            let peers: Vec<String> = quic.inner.peer_connections.iter()
                .map(|e| e.key().clone())
                .collect();
            
            for peer_id in peers {
                if let Err(e) = quic.inner.send_datagram_to_peer(&peer_id, message).await {
                    errors.push(format!("QUIC->{}: {}", peer_id, e));
                }
            }
        }

        if let Some(ref wg) = self.wireguard_transport {
            let peers = wg.inner.get_connected_peers();
            
            for peer_id in peers {
                if let Err(e) = wg.inner.send_datagram(&peer_id, message).await {
                    errors.push(format!("WG->{}: {}", peer_id, e));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(MeshTransportError::SendFailed(errors.join("; ")))
        }
    }

    pub fn get_all_connected_peers(&self) -> Vec<(String, MeshTransportType)> {
        let mut peers = Vec::new();

        if let Some(ref quic) = self.quic_transport {
            for entry in quic.inner.peer_connections.iter() {
                peers.push((entry.key().clone(), MeshTransportType::Quic));
            }
        }

        if let Some(ref wg) = self.wireguard_transport {
            for peer_id in wg.inner.get_connected_peers() {
                if !peers.iter().any(|(p, _)| p == &peer_id) {
                    peers.push((peer_id, MeshTransportType::WireGuard));
                }
            }
        }

        peers
    }

    pub fn is_peer_connected(&self, peer_id: &str) -> bool {
        if let Some(ref quic) = self.quic_transport {
            if quic.inner.peer_connections.contains_key(peer_id) {
                return true;
            }
        }

        if let Some(ref wg) = self.wireguard_transport {
            if wg.inner.is_connected(peer_id) {
                return true;
            }
        }

        false
    }

    pub fn get_peer_address(&self, peer_id: &str) -> Option<String> {
        if let Some(ref quic) = self.quic_transport {
            if let Some(conn) = quic.inner.peer_connections.get(peer_id) {
                return Some(conn.address.clone());
            }
        }

        if let Some(ref wg) = self.wireguard_transport {
            if let Some(addr) = wg.inner.get_peer_address(peer_id) {
                return Some(addr);
            }
        }

        None
    }
}
