#![allow(unused_variables)]

use std::sync::Arc;

use crate::cert::MeshCertManager;
use crate::config::MeshConfig;
use crate::protocol::MeshMessage;
use crate::topology::MeshTopology;
use crate::transports::{MeshTransportError, MeshTransportTrait, MeshTransportType};
use parking_lot::RwLock;

pub struct QuicMeshTransport {
    inner: Arc<crate::transport::MeshTransport>,
}

impl QuicMeshTransport {
    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        record_store: Option<Arc<crate::dht::RecordStoreManager>>,
        routing_manager: Option<Arc<crate::dht::routing::DhtRoutingManager>>,
        threat_intel: Option<Arc<crate::threat_intel::ThreatIntelligenceManager>>,
        mesh_signer: Option<Arc<crate::protocol::MeshMessageSigner>>,
        stake_manager: Option<Arc<crate::dht::StakeManager>>,
        backend_pool: Option<Arc<crate::backend::MeshBackendPool>>,
        #[cfg(feature = "dns")] dns_resolver: Option<Arc<dyn synvoid_dns::resolver::DnsResolver>>,
        #[cfg(feature = "dns")] dns_registry: Option<Arc<synvoid_dns::MeshDnsRegistry>>,
    ) -> Self {
        let cert_manager = Arc::new(RwLock::new(MeshCertManager::new(&config)));

        #[cfg(feature = "verify-pq")]
        cert_manager.read().verify_post_quantum();

        let inner = Arc::new(crate::transport::MeshTransport::new(
            config,
            topology,
            cert_manager,
            record_store,
            routing_manager.clone(),
            threat_intel,
            mesh_signer,
            stake_manager,
            backend_pool,
            #[cfg(feature = "dns")]
            dns_resolver,
            #[cfg(feature = "dns")]
            dns_registry,
        ));

        if let Some(ref rm) = routing_manager {
            rm.set_find_node_transport(inner.clone());
            rm.set_ping_transport(inner.clone());
        }

        Self { inner }
    }

    pub fn get_inner(&self) -> Arc<crate::transport::MeshTransport> {
        self.inner.clone()
    }

    #[cfg(feature = "dns")]
    pub async fn start(&self) -> Result<(), crate::transport::MeshTransportError> {
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
        self.inner
            .peer_connections
            .get(peer_id)
            .map(|p| p.address.clone())
    }

    async fn send_stream(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        self.inner
            .send_message_to_peer(peer_id, message)
            .await
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))
    }

    async fn send_datagram(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        self.inner
            .send_datagram_to_peer(peer_id, message)
            .await
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))
    }

    async fn broadcast_datagram(&self, message: &MeshMessage) -> Result<(), MeshTransportError> {
        let peers: Vec<String> = self
            .inner
            .peer_connections
            .iter()
            .map(|e| e.key().clone())
            .collect();

        if peers.is_empty() {
            return Ok(());
        }

        let message = message.clone();
        let inner = self.inner.clone();

        let send_futures: Vec<_> = peers
            .iter()
            .map(|peer_id| {
                let message = message.clone();
                let inner = inner.clone();
                async move {
                    let transport = Self { inner };
                    if let Err(e) = transport.send_datagram(peer_id, &message).await {
                        tracing::warn!("Failed to send broadcast to {}: {}", peer_id, e);
                    }
                }
            })
            .collect();

        futures::future::join_all(send_futures).await;

        Ok(())
    }

    fn get_connected_peers(&self) -> Vec<String> {
        self.inner
            .peer_connections
            .iter()
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
