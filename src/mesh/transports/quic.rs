#![allow(unused_variables, dead_code)]

use std::sync::Arc;

use crate::mesh::config::MeshConfig;
use crate::mesh::protocol::MeshMessage;
use crate::mesh::topology::MeshTopology;
use crate::mesh::transports::{MeshTransportError, MeshTransportTrait, MeshTransportType};
use crate::mesh::cert::MeshCertManager;
use parking_lot::RwLock;

pub struct QuicMeshTransport {
    inner: Arc<crate::mesh::transport::MeshTransport>,
}

impl QuicMeshTransport {
    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
        routing_manager: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>,
        threat_intel: Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>,
        mesh_signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
        stake_manager: Option<Arc<crate::mesh::dht::StakeManager>>,
        #[cfg(feature = "dns")] dns_registry: Option<Arc<crate::dns::MeshDnsRegistry>>,
    ) -> Self {
        let cert_manager = Arc::new(RwLock::new(MeshCertManager::new(&config)));
        
        #[cfg(feature = "verify-pq")]
        cert_manager.read().verify_post_quantum();
        
        let inner = Arc::new(crate::mesh::transport::MeshTransport::new(
            config,
            topology,
            cert_manager,
            record_store,
            routing_manager,
            threat_intel,
            mesh_signer,
            stake_manager,
            #[cfg(feature = "dns")]
            dns_registry,
        ));
        
        Self { inner }
    }

    pub fn get_inner(&self) -> Arc<crate::mesh::transport::MeshTransport> {
        self.inner.clone()
    }

    pub async fn start(&self) -> Result<(), crate::mesh::transport::MeshTransportError> {
        self.inner.start().await
    }
}

impl MeshTransportTrait for QuicMeshTransport {
    fn transport_type(&self) -> MeshTransportType {
        MeshTransportType::Quic
    }

    fn is_connected(&self, peer_id: &str) -> bool {
        self.inner.peer_connections.contains_key(peer_id)
    }

    fn get_peer_address(&self, peer_id: &str) -> Option<String> {
        self.inner.peer_connections.get(peer_id)
            .map(|p| p.address.clone())
    }

    async fn send_stream(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        self.inner.send_message_to_peer(peer_id, message)
            .await
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))
    }

    async fn send_datagram(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        self.inner.send_datagram_to_peer(peer_id, message)
            .await
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))
    }

    async fn broadcast_datagram(
        &self,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        let peers: Vec<String> = self.inner.peer_connections.iter()
            .map(|e| e.key().clone())
            .collect();
        
        if peers.is_empty() {
            return Ok(());
        }

        let message = message.clone();
        let inner = self.inner.clone();
        
        let send_futures: Vec<_> = peers.iter().map(|peer_id| {
            let message = message.clone();
            let inner = inner.clone();
            async move {
                let transport = Self { inner };
                if let Err(e) = transport.send_datagram(peer_id, &message).await {
                    tracing::warn!("Failed to send broadcast to {}: {}", peer_id, e);
                }
            }
        }).collect();

        futures::future::join_all(send_futures).await;
        
        Ok(())
    }

    fn get_connected_peers(&self) -> Vec<String> {
        self.inner.peer_connections.iter()
            .map(|e| e.key().clone())
            .collect()
    }

    fn local_addresses(&self) -> Vec<String> {
        self.inner.get_bind_addresses()
    }

    fn is_available(&self) -> bool {
        true
    }
}
