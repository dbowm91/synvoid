#![allow(dead_code)] // Reserved for future routing protocol handling

use crate::mesh::transport::{MeshPeerConnection, MeshTransport, MeshTransportError};
use std::time::{Duration, Instant};

use quinn::SendStream;
use rand::Rng;

use crate::mesh::protocol::{MeshMessage, ProviderInfo, RouteQueryResult};
use crate::mesh::topology::MeshTopology;

impl MeshTransport {
    pub(crate) async fn send_route_query_datagram(
        &self,
        peer_id: &str,
        query_id: &str,
        upstream_id: &str,
    ) -> Result<(), MeshTransportError> {
        let sequence = self.config.routing.query_sequence.next();
        let timestamp = MeshMessage::generate_timestamp();
        let nonce = MeshMessage::generate_nonce();
        let query = MeshMessage::RouteQuery {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
            max_hops: self.config.routing.max_hops,
            initiator: self.config.node_id().into(),
            sequence,
            timestamp,
            nonce,
        };

        self.send_datagram_to_peer(peer_id, &query).await
    }

    pub(crate) async fn send_route_query_stream(
        &self,
        peer_id: &str,
        query_id: &str,
        upstream_id: &str,
    ) -> Result<(), MeshTransportError> {
        let peer = self
            .peer_connections
            .get(peer_id)
            .ok_or_else(|| MeshTransportError::PeerNotFound(peer_id.to_string()))?;

        let sequence = self.config.routing.query_sequence.next();
        let timestamp = MeshMessage::generate_timestamp();
        let nonce = MeshMessage::generate_nonce();
        let query = MeshMessage::RouteQuery {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
            max_hops: self.config.routing.max_hops,
            initiator: self.config.node_id().into(),
            sequence,
            timestamp,
            nonce,
        };

        let (mut send_stream, _) = peer
            .connection
            .open_bi()
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let encoded = query
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream
            .write_all(&len)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream
            .write_all(&encoded)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        tracing::debug!("Sent stream route query to peer {}: {}", peer_id, query_id);
        Ok(())
    }

    pub(crate) async fn handle_route_query_datagram(
        &self,
        from_peer: &str,
        query_id: &str,
        upstream_id: &str,
        max_hops: u8,
        initiator: &str,
    ) {
        const MAX_INITIAL_HOPS: u8 = 10;

        tracing::debug!(
            "Received route query datagram: {} -> {} from {}",
            query_id,
            upstream_id,
            from_peer
        );

        if max_hops > MAX_INITIAL_HOPS {
            tracing::warn!(
                "RouteQuery rejected: max_hops {} exceeds limit {} (possible attack from {})",
                max_hops,
                MAX_INITIAL_HOPS,
                from_peer
            );
            return;
        }

        if initiator != from_peer {
            let initiator_exists = self.topology.get_peer(initiator).await.is_some();
            let initiator_in_connections = self.peer_connections.contains_key(initiator);

            if !initiator_exists && !initiator_in_connections {
                tracing::warn!(
                    "RouteQuery rejected: initiator {} not known (from {})",
                    initiator,
                    from_peer
                );
                return;
            }
        }

        let query_key = format!("{}:{}", initiator, query_id);
        if self.is_message_seen(&query_key) {
            tracing::debug!("Duplicate route query ignored: {}", query_key);
            return;
        }
        self.mark_message_seen(&query_key);

        if self.is_global_rate_limit_exceeded() {
            tracing::warn!("Route query rate limited: {}", query_key);
            let not_found = MeshMessage::RouteNotFound {
                query_id: query_id.into(),
                upstream_id: upstream_id.into(),
            };
            let _ = self.send_datagram_to_peer(from_peer, &not_found).await;
            return;
        }

        if let Some((provider, hops)) = self.topology.get_cached_route(upstream_id).await {
            let sequence = self.config.routing.query_sequence.next();
            let timestamp = MeshMessage::generate_timestamp();
            let nonce = MeshMessage::generate_nonce();
            let local = self.topology.get_upstream_info(upstream_id).await;
            let response = MeshMessage::RouteResponse {
                query_id: query_id.into(),
                upstream_id: upstream_id.into(),
                provider_node_id: provider.clone().into(),
                hops,
                ttl_secs: 300,
                signature: vec![],
                sequence,
                timestamp,
                nonce,
                upstream_url: local.as_ref().map(|l| l.upstream_url.clone().into()),
                waf_policy: local.as_ref().and_then(|l| l.waf_policy.clone()),
                priority_tier: local.map(|l| l.priority_tier).unwrap_or(0),
                tier_claim: None,
                org_id: None,
                mesh_name: self.config.mesh_name().map(|s| s.into()),
            };

            if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                tracing::warn!("Failed to send route response to {}: {}", from_peer, e);
            }
            return;
        }

        if self.topology.has_local_upstream(upstream_id).await {
            let sequence = self.config.routing.query_sequence.next();
            let timestamp = MeshMessage::generate_timestamp();
            let nonce = MeshMessage::generate_nonce();
            let local = self.topology.get_upstream_info(upstream_id).await;
            let response = MeshMessage::RouteResponse {
                query_id: query_id.into(),
                upstream_id: upstream_id.into(),
                provider_node_id: self.config.node_id().into(),
                hops: 0,
                ttl_secs: 300,
                signature: vec![],
                sequence,
                timestamp,
                nonce,
                upstream_url: local.as_ref().map(|l| l.upstream_url.clone().into()),
                waf_policy: local.as_ref().and_then(|l| l.waf_policy.clone()),
                priority_tier: local.map(|l| l.priority_tier).unwrap_or(0),
                tier_claim: None,
                org_id: None,
                mesh_name: self.config.mesh_name().map(|s| s.into()),
            };

            if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                tracing::warn!("Failed to send local route response: {} - {}", from_peer, e);
            }
            return;
        }

        if max_hops > 0 {
            const ROUTE_QUERY_FANOUT: usize = 3;

            let peers_to_query: Vec<_> = self
                .peer_connections
                .iter()
                .filter(|e| e.key() != from_peer && e.key() != initiator)
                .take(ROUTE_QUERY_FANOUT)
                .map(|e| e.key().clone())
                .collect();

            if !peers_to_query.is_empty() {
                for peer_id in peers_to_query {
                    let sequence = self.config.routing.query_sequence.next();
                    let timestamp = MeshMessage::generate_timestamp();
                    let nonce = MeshMessage::generate_nonce();
                    let forward_query = MeshMessage::RouteQuery {
                        query_id: query_id.into(),
                        upstream_id: upstream_id.into(),
                        max_hops: max_hops - 1,
                        initiator: initiator.into(),
                        sequence,
                        timestamp,
                        nonce,
                    };

                    if let Err(e) = self.send_datagram_to_peer(&peer_id, &forward_query).await {
                        tracing::debug!("Failed to forward route query to {}: {}", peer_id, e);
                    }
                }
                return;
            }
        }

        let not_found = MeshMessage::RouteNotFound {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &not_found).await {
            tracing::debug!("Failed to send route not found: {}", e);
        }
    }

    pub(crate) async fn handle_route_response(
        &self,
        query_id: &str,
        upstream_id: &str,
        provider_node_id: &str,
        hops: u32,
        ttl_secs: u32,
        upstream_url: Option<crate::mesh::protocol::ArcStr>,
        waf_policy: Option<crate::mesh::protocol::WafPolicy>,
        priority_tier: u32,
        tier_claim: Option<crate::mesh::organization::TierClaim>,
        org_id: Option<crate::mesh::protocol::ArcStr>,
        mesh_name: Option<crate::mesh::protocol::ArcStr>,
    ) {
        tracing::debug!(
            "Received route response: {} -> {} ({} hops)",
            upstream_id,
            provider_node_id,
            hops
        );

        self.topology
            .cache_route(
                upstream_id,
                provider_node_id.to_string(),
                hops as u8,
                Duration::from_secs(ttl_secs as u64),
            )
            .await;

        let provider_info = ProviderInfo {
            node_id: provider_node_id.to_string(),
            upstream_url: upstream_url.map(|s| s.to_string()).unwrap_or_default(),
            waf_policy,
            hops: hops as u8,
            ttl: Duration::from_secs(ttl_secs as u64),
            score: 0.5,
            priority_tier,
            tier_claim,
            org_id: org_id.map(|s| s.to_string()),
            mesh_name: mesh_name.map(|s| s.to_string()),
        };

        let mut pending = self.pending_queries.lock().await;
        pending.add_provider(query_id, provider_info);
    }

    pub(crate) async fn complete_pending_query(&self, query_id: &str, upstream_id: &str) {
        let (providers, sender) = {
            let mut pending = self.pending_queries.lock().await;
            let providers = pending
                .collected_providers
                .remove(query_id)
                .unwrap_or_default();
            let sender = pending.pending.remove(query_id);
            (providers, sender)
        };

        if let Some(sender) = sender {
            if providers.is_empty() {
                let _ = sender.send(RouteQueryResult {
                    query_id: query_id.to_string(),
                    upstream_id: upstream_id.to_string(),
                    providers: vec![],
                    discovered_at: Instant::now(),
                });
            } else {
                let _ = sender.send(RouteQueryResult {
                    query_id: query_id.to_string(),
                    upstream_id: upstream_id.to_string(),
                    providers,
                    discovered_at: Instant::now(),
                });
            }
        }
    }

    pub(crate) async fn handle_route_not_found(&self, query_id: &str, upstream_id: &str) {
        tracing::debug!(
            "Route not found for {} from query {}",
            upstream_id,
            query_id
        );

        if let Some(sender) = self.pending_queries.lock().await.take(query_id) {
            let _ = sender.send(RouteQueryResult {
                query_id: query_id.to_string(),
                upstream_id: upstream_id.to_string(),
                providers: vec![],
                discovered_at: Instant::now(),
            });
        }
    }

    pub(crate) async fn handle_route_query(
        &self,
        send_stream: &mut SendStream,
        query_id: String,
        upstream_id: String,
        max_hops: u8,
        _initiator: String,
        topology: &MeshTopology,
    ) -> Result<(), MeshTransportError> {
        let upstream_id_for_log = upstream_id.clone();
        if let Some(upstream_info) = topology.get_upstream_info(&upstream_id).await {
            if upstream_info.is_local || topology.can_forward_service(&upstream_id) {
                let signature = vec![0u8; 32];
                let sequence = 0;
                let timestamp = MeshMessage::generate_timestamp();
                let nonce = MeshMessage::generate_nonce();
                let response = MeshMessage::RouteResponse {
                    query_id: query_id.into(),
                    upstream_id: upstream_id.into(),
                    provider_node_id: topology.node_id().into(),
                    hops: if upstream_info.is_local { 0 } else { 1 },
                    ttl_secs: 300,
                    signature,
                    sequence,
                    timestamp,
                    nonce,
                    upstream_url: Some(upstream_info.upstream_url.clone().into()),
                    waf_policy: upstream_info.waf_policy.clone(),
                    priority_tier: upstream_info.priority_tier,
                    tier_claim: None,
                    org_id: None,
                    mesh_name: self.config.mesh_name().map(|s| s.into()),
                };

                let encoded = response
                    .encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (encoded.len() as u32).to_be_bytes();
                send_stream
                    .write_all(&len)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                send_stream
                    .write_all(&encoded)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

                tracing::debug!(
                    "Responded to route query for {}: {} (hops: {})",
                    upstream_id_for_log,
                    topology.node_id(),
                    if upstream_info.is_local { 0 } else { 1 }
                );
                return Ok(());
            }
        }

        if max_hops > 1 {
            if let Some((provider, hops)) = topology.get_cached_route(&upstream_id).await {
                let signature = vec![0u8; 32];
                let sequence = 0;
                let timestamp = MeshMessage::generate_timestamp();
                let nonce = MeshMessage::generate_nonce();
                let response = MeshMessage::RouteResponse {
                    query_id: query_id.into(),
                    upstream_id: upstream_id.into(),
                    provider_node_id: provider.into(),
                    hops: hops + 1,
                    ttl_secs: 60,
                    signature,
                    sequence,
                    timestamp,
                    nonce,
                    upstream_url: None,
                    waf_policy: None,
                    priority_tier: 0,
                    tier_claim: None,
                    org_id: None,
                    mesh_name: self.config.mesh_name().map(|s| s.into()),
                };

                let encoded = response
                    .encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (encoded.len() as u32).to_be_bytes();
                send_stream
                    .write_all(&len)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                send_stream
                    .write_all(&encoded)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                return Ok(());
            }
        }

        let not_found = MeshMessage::RouteNotFound {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
        };

        let encoded = not_found
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream
            .write_all(&len)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream
            .write_all(&encoded)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        Ok(())
    }

    pub(crate) async fn wait_for_route_event(
        &self,
        upstream_id: &str,
        _timeout: Duration,
    ) -> Option<RouteQueryResult> {
        // First check if already cached (fast path)
        if let Some(cached) = self.topology.get_cached_route(upstream_id).await {
            return Some(RouteQueryResult {
                query_id: String::new(),
                upstream_id: upstream_id.to_string(),
                providers: vec![ProviderInfo {
                    node_id: cached.0,
                    upstream_url: String::new(),
                    waf_policy: None,
                    hops: cached.1,
                    ttl: Duration::from_secs(300),
                    score: 0.5,
                    priority_tier: 0,
                    tier_claim: None,
                    org_id: None,
                    mesh_name: None,
                }],
                discovered_at: Instant::now(),
            });
        }

        None
    }

    pub(crate) async fn preflight_peer_routes(
        &self,
        peer_id: &str,
    ) -> Result<(), MeshTransportError> {
        // Get frequently used upstreams from topology to request from new peer
        let upstreams_to_query = self.topology.get_frequently_used_upstreams(5).await;

        if upstreams_to_query.is_empty() {
            return Ok(());
        }

        tracing::debug!(
            "Preflight querying {} routes from peer {}",
            upstreams_to_query.len(),
            peer_id
        );

        for upstream_id in upstreams_to_query {
            let query_id = format!(
                "preflight-{}-{}",
                self.config.node_id(),
                uuid::Uuid::new_v4()
            );

            // Create a one-shot channel to receive the response
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending_queries
                .lock()
                .await
                .register(query_id.clone(), tx);

            if self
                .send_route_query_datagram(peer_id, &query_id, &upstream_id)
                .await
                .is_ok()
            {
                // Wait briefly for response (non-blocking)
                if let Ok(Ok(route_result)) =
                    tokio::time::timeout(Duration::from_millis(100), rx).await
                {
                    // Cache the route (already cached by handle_route_response)
                    if let Some(best) = route_result.best_provider() {
                        tracing::debug!(
                            "Preflight cached route for {} -> {}",
                            upstream_id,
                            best.node_id
                        );
                    }
                }
            }

            self.pending_queries.lock().await.take(&query_id);
        }

        Ok(())
    }

    pub(crate) async fn send_route_query_to_peer(
        &self,
        peer: &MeshPeerConnection,
        query_id: &str,
        upstream_id: &str,
    ) -> Result<(), MeshTransportError> {
        let (mut send_stream, _) = peer
            .connection
            .open_bi()
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let sequence = self.config.routing.query_sequence.next();
        let timestamp = MeshMessage::generate_timestamp();
        let nonce = MeshMessage::generate_nonce();
        let query = MeshMessage::RouteQuery {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
            max_hops: self.config.routing.max_hops,
            initiator: self.config.node_id().into(),
            sequence,
            timestamp,
            nonce,
        };

        let encoded = query
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream
            .write_all(&len)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream
            .write_all(&encoded)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        Ok(())
    }

    pub(crate) async fn proactive_cache_warm(&self) {
        if self.peer_connections.is_empty() {
            return;
        }

        // Get the top popular upstreams that aren't already cached
        let popular_upstreams = self.topology.get_frequently_used_upstreams(10).await;

        if popular_upstreams.is_empty() {
            return;
        }

        // Get peers we can query
        let peers: Vec<String> = self
            .peer_connections
            .iter()
            .map(|e| e.key().clone())
            .collect();

        if peers.is_empty() {
            return;
        }

        // For each popular upstream not in cache, query a peer
        for upstream_id in popular_upstreams {
            // Skip if already cached
            if self.topology.get_cached_route(&upstream_id).await.is_some() {
                continue;
            }

            // Query a random peer for this route
            let peer_idx = if peers.len() > 1 {
                let mut rng = rand::rng();
                rng.random_range(0..peers.len())
            } else {
                0
            };
            let peer_id = &peers[peer_idx];

            let query_id = format!("warm-{}-{}", self.config.node_id(), uuid::Uuid::new_v4());
            let (tx, _rx) = tokio::sync::oneshot::channel();
            self.pending_queries
                .lock()
                .await
                .register(query_id.clone(), tx);

            if self
                .send_route_query_stream(peer_id, &query_id, &upstream_id)
                .await
                .is_ok()
            {
                tracing::debug!(
                    "Proactive cache warming: queried {} from {}",
                    upstream_id,
                    peer_id
                );
            }

            // Don't wait for response - let it populate cache in background
            self.pending_queries.lock().await.take(&query_id);
        }
    }
}
