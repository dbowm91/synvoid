use crate::mesh::transport::{
    MeshTransport, MeshTransportError, MAX_BATCH_KEYS, MAX_BLOCK_DURATION_SECS, MAX_MESSAGE_SIZE,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::broadcast;

use crate::mesh::protocol::MeshMessage;
use crate::mesh::topology::{MeshTopology, PeerStatus};

impl MeshTransport {
    pub(crate) async fn send_keepalive_datagram(
        &self,
        peer_id: &str,
    ) -> Result<(), MeshTransportError> {
        self.send_datagram_to_peer(peer_id, &MeshMessage::KeepAlive)
            .await
    }

    pub(crate) async fn start_datagram_handler(
        self: Arc<Self>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Datagram handler stopped");
                    break;
                }
                peer_entry = self.wait_for_peer_datagrams() => {
                    if let Some((peer_id, data)) = peer_entry {
                        let transport = self.clone();
                        tokio::spawn(async move {
                            if let Err(e) = transport.handle_incoming_datagram(&peer_id, data).await {
                                tracing::warn!("Failed to handle datagram from {}: {}", peer_id, e);
                            }
                        });
                    }
                }
            }
        }
    }

    pub(crate) async fn wait_for_peer_datagrams(&self) -> Option<(String, Bytes)> {
        for entry in self.peer_connections.iter() {
            let peer_id = entry.key().clone();
            let connection = &entry.value().connection;

            match connection.read_datagram().await {
                Ok(data) => return Some((peer_id, data)),
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("unsupported") {
                        tracing::debug!("Peer {} does not support datagrams", peer_id);
                    } else if err_str.contains("finished") || err_str.contains("FinRead") {
                        // Peer disconnected, continue
                    } else {
                        tracing::trace!("Datagram read error from {}: {}", peer_id, e);
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(1)).await;
        None
    }

    pub(crate) async fn handle_incoming_datagram(
        &self,
        peer_id: &str,
        data: Bytes,
    ) -> Result<(), MeshTransportError> {
        let msg = match MeshMessage::decode(&data) {
            Some(m) => m,
            None => {
                return Err(MeshTransportError::ReceiveFailed(
                    "Failed to decode message".to_string(),
                ))
            }
        };

        if let Some(msg_id) = msg.message_id() {
            if self.is_message_seen(&msg_id) {
                tracing::debug!("Duplicate message ignored: {}", msg_id);
                return Ok(());
            }
            self.mark_message_seen(&msg_id);
        }

        if self.is_global_rate_limit_exceeded() {
            tracing::warn!("Global mesh rate limit exceeded, dropping message");
            return Ok(());
        }

        match msg {
            MeshMessage::RouteQuery {
                query_id,
                upstream_id,
                max_hops,
                initiator,
                sequence: _,
                timestamp: _,
                nonce: _,
            } => {
                self.handle_route_query_datagram(
                    peer_id,
                    &query_id,
                    &upstream_id,
                    max_hops,
                    &initiator,
                )
                .await;
            }
            MeshMessage::RouteResponse {
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                upstream_url,
                waf_policy,
                priority_tier,
                tier_claim,
                org_id,
                mesh_name,
                ..
            } => {
                self.handle_route_response(
                    &query_id,
                    &upstream_id,
                    &provider_node_id,
                    hops as u32,
                    ttl_secs,
                    upstream_url.clone(),
                    waf_policy.clone(),
                    priority_tier,
                    tier_claim,
                    org_id,
                    mesh_name,
                )
                .await;
                // Send ACK to confirm receipt
                let ack = MeshMessage::RouteResponseAck {
                    query_id: query_id.clone(),
                    upstream_id: upstream_id.clone(),
                    provider_node_id: provider_node_id.clone(),
                };
                let _ = self.send_datagram_to_peer(peer_id, &ack).await;
            }
            MeshMessage::RouteNotFound {
                query_id,
                upstream_id,
            } => {
                self.handle_route_not_found(&query_id, &upstream_id).await;
            }
            MeshMessage::KeepAlive => {
                self.handle_keepalive_datagram(peer_id).await;
            }
            MeshMessage::LookupRequest {
                request_id,
                key,
                lookup_type,
            } => {
                self.handle_lookup_request(peer_id, &request_id, &key, lookup_type)
                    .await;
            }
            MeshMessage::LookupBatchRequest { request_id, keys } => {
                self.handle_lookup_batch_request(peer_id, &request_id, &keys)
                    .await;
            }
            MeshMessage::PeerHealthCheck {
                peer_id: target_peer_id,
                timestamp,
            } => {
                self.handle_peer_health_check(peer_id, &target_peer_id, timestamp)
                    .await;
            }
            MeshMessage::PeerAnnounce {
                node_id,
                address,
                role,
                capabilities,
                announced_at,
            } => {
                self.handle_peer_announce(
                    peer_id,
                    &node_id,
                    &address,
                    role,
                    &capabilities,
                    announced_at,
                )
                .await;
            }
            MeshMessage::PeerGone { node_id, reason } => {
                self.handle_peer_gone(peer_id, &node_id, &reason).await;
            }
            MeshMessage::TopologySyncRequest {
                request_id,
                from_version,
                prefer_delta: _,
            } => {
                self.handle_topology_sync_request(peer_id, &request_id, from_version)
                    .await;
            }
            MeshMessage::SeedListRequest {
                node_id,
                request_full_mesh,
            } => {
                self.handle_seed_list_request(peer_id, &node_id, request_full_mesh)
                    .await;
            }
            MeshMessage::SeedListResponse {
                global_nodes,
                edge_nodes,
                version: _,
                genesis_org_id,
            } => {
                self.handle_seed_list_response(global_nodes, edge_nodes, genesis_org_id)
                    .await;
            }
            MeshMessage::PeerLoadReport {
                node_id,
                active_connections,
                cpu_load_percent,
                memory_percent,
                requests_per_second,
            } => {
                self.handle_peer_load_report(
                    &node_id,
                    active_connections,
                    cpu_load_percent,
                    memory_percent,
                    requests_per_second,
                )
                .await;
            }
            MeshMessage::PeerLoadUpdate {
                node_id,
                load_score,
            } => {
                self.handle_peer_load_update(&node_id, load_score).await;
            }
            MeshMessage::RouteUsageReport {
                upstream_id,
                request_count,
                bytes_transferred,
            } => {
                self.handle_route_usage_report(&upstream_id, request_count, bytes_transferred)
                    .await;
            }
            MeshMessage::UpstreamBlocked {
                mesh_identifier,
                service_id,
                blocked_until,
                reason,
                origin_node_id,
            } => {
                self.handle_upstream_blocked(
                    &mesh_identifier,
                    &service_id,
                    blocked_until,
                    &reason,
                    &origin_node_id,
                )
                .await;
            }
            MeshMessage::BandwidthReport {
                upstream_id,
                bytes_sent,
                bytes_received,
                request_count,
                interval_secs,
                timestamp,
            } => {
                self.handle_bandwidth_report(
                    &upstream_id,
                    bytes_sent,
                    bytes_received,
                    request_count,
                    interval_secs,
                    timestamp,
                )
                .await;
            }
            MeshMessage::OrgRegistrationRequest {
                request_id,
                org_name,
                requesting_node_id,
                requesting_node_pubkey,
                timestamp: _,
                signature: _,
            } => {
                self.handle_org_registration_request(
                    peer_id,
                    &request_id,
                    &org_name,
                    &requesting_node_id,
                    &requesting_node_pubkey,
                )
                .await;
            }
            MeshMessage::OrgRegistrationResponse {
                request_id: _,
                org_id,
                org_name: _,
                approved,
                reason: _,
                initial_tier_key,
                signature: _,
                timestamp: _,
            } => {
                self.handle_org_registration_response(
                    peer_id,
                    &org_id,
                    approved,
                    initial_tier_key.as_ref(),
                )
                .await;
            }
            MeshMessage::UpstreamRegistrationRequest {
                request_id,
                upstream_id,
                upstream_url,
                org_id,
                requesting_node_id,
                timestamp: _,
                signature: _,
            } => {
                self.handle_upstream_registration_request(
                    peer_id,
                    &request_id,
                    &upstream_id,
                    &upstream_url,
                    org_id.as_deref(),
                    &requesting_node_id,
                )
                .await;
            }
            MeshMessage::UpstreamRegistrationResponse {
                request_id: _,
                upstream_id,
                approved,
                rejection_reason,
                global_node_id: _,
                global_node_signature: _,
                timestamp: _,
            } => {
                self.handle_upstream_registration_response(
                    peer_id,
                    &upstream_id,
                    approved,
                    rejection_reason.as_deref(),
                )
                .await;
            }
            MeshMessage::OrgInvitationRequest {
                request_id,
                org_id,
                inviter_node_id,
                invited_node_id,
                invited_node_pubkey: _,
                invitation_token,
                expires_at,
                timestamp: _,
                signature: _,
            } => {
                self.handle_org_invitation_request(
                    peer_id,
                    &request_id,
                    &org_id,
                    &inviter_node_id,
                    &invited_node_id,
                    &invitation_token,
                    expires_at,
                )
                .await;
            }
            MeshMessage::OrgInvitationAccept {
                request_id,
                org_id,
                invited_node_id,
                invitation_token,
                proof_of_key,
                timestamp: _,
                signature: _,
            } => {
                self.handle_org_invitation_accept(
                    peer_id,
                    &request_id,
                    &org_id,
                    &invited_node_id,
                    &invitation_token,
                    &proof_of_key,
                )
                .await;
            }
            MeshMessage::OrgMemberAnnounce {
                org_id,
                member_node_id,
                announced_by,
                joined_at,
                signature: _,
            } => {
                self.handle_org_member_announce(&org_id, &member_node_id, &announced_by, joined_at)
                    .await;
            }
            MeshMessage::TierKeyAnnounce {
                org_id,
                key,
                signature: _,
            } => {
                self.handle_tier_key_announce(&org_id, &key).await;
            }
            MeshMessage::TierKeyRevoke {
                org_id,
                key_id,
                signature: _,
            } => {
                self.handle_tier_key_revoke(&org_id, &key_id).await;
            }
            MeshMessage::GlobalNodeAnnounce {
                node_id,
                public_key,
                action,
                timestamp,
                signature,
                key_exchange_endpoint,
            } => {
                self.handle_global_node_announce(
                    peer_id,
                    &node_id,
                    &public_key,
                    action,
                    timestamp,
                    &signature,
                    key_exchange_endpoint.as_deref(),
                )
                .await;
            }
            MeshMessage::UnspentTierKeyAnnounce {
                org_id,
                tier_keys,
                signature: _,
                timestamp: _,
            } => {
                self.handle_unspent_tier_key_announce(&org_id, &tier_keys)
                    .await;
            }
            MeshMessage::KeySigned {
                session_id,
                key_id,
                mesh_id,
                origin_mesh_id,
                origin_ed25519_pubkey,
                server_x25519_pubkey,
                origin_signature,
                nonce: _,
                timestamp: _,
            } => {
                self.handle_key_signed(
                    peer_id,
                    &session_id,
                    &key_id,
                    &mesh_id,
                    &origin_mesh_id,
                    &origin_ed25519_pubkey,
                    &server_x25519_pubkey,
                    &origin_signature,
                )
                .await;
            }
            MeshMessage::DhtSnapshotRequest {
                request_id,
                node_id,
                from_version,
            } => {
                self.handle_dht_snapshot_request(peer_id, &request_id, &node_id, from_version)
                    .await;
            }
            MeshMessage::DhtSnapshotResponse {
                request_id,
                records,
                version,
                timestamp: _,
                signature: _,
                ..
            } => {
                self.handle_dht_snapshot_response(peer_id, &request_id, records, version)
                    .await;
            }
            MeshMessage::DhtRecordAnnounce {
                request_id: _,
                records,
                write_quorum: _,
                timestamp: _,
                source_node_id,
                signature: _,
                ..
            } => {
                self.handle_dht_record_announce(peer_id, &source_node_id, records)
                    .await;
            }
            MeshMessage::DhtSyncRequest {
                request_id,
                node_id,
                from_version,
            } => {
                self.handle_dht_sync_request(peer_id, &request_id, &node_id, from_version)
                    .await;
            }
            MeshMessage::DhtSyncResponse {
                request_id: _,
                records,
                version: _,
                timestamp: _,
                signature: _,
                ..
            } => {
                self.handle_dht_sync_response(peer_id, records).await;
            }
            MeshMessage::DhtAntiEntropyRequest {
                request_id,
                node_id,
                local_root_hash,
                interested_keys,
                timestamp,
                ..
            } => {
                self.handle_dht_anti_entropy_request(
                    peer_id,
                    &request_id,
                    &node_id,
                    &local_root_hash,
                    &interested_keys,
                    timestamp,
                )
                .await;
            }
            MeshMessage::DhtAntiEntropyResponse {
                request_id: _,
                root_hash: _,
                proof_keys: _,
                proof_hashes: _,
                missing_records,
                timestamp,
                signature,
                ..
            } => {
                self.handle_dht_anti_entropy_response(
                    peer_id,
                    missing_records,
                    timestamp,
                    &signature,
                )
                .await;
            }
            MeshMessage::FindNode {
                request_id,
                target_node_id,
                requester_node_id,
                timestamp: _,
            } => {
                self.handle_find_node(peer_id, &request_id, target_node_id, &requester_node_id)
                    .await;
            }
            MeshMessage::FindNodeResponse {
                request_id: _,
                peers,
                responder_node_id: _,
                timestamp: _,
            } => {
                self.handle_find_node_response(peer_id, peers).await;
            }
            MeshMessage::OriginKeyQuery {
                request_id,
                mesh_id,
                timestamp: _,
            } => {
                self.handle_origin_key_query(peer_id, &request_id, &mesh_id)
                    .await;
            }
            MeshMessage::OriginKeyQueryResponse {
                request_id: _,
                mesh_id,
                public_key,
                timestamp: _,
            } => {
                if let Some(ref pk) = public_key {
                    tracing::debug!("Received origin public key for mesh {}: {}", mesh_id, pk);
                }
            }
            #[cfg(feature = "dns")]
            MeshMessage::NodeShutdown {
                node_id,
                role,
                domains,
                graceful,
                shutdown_at,
                timestamp,
                signature: _,
            } => {
                let domains_vec: Vec<std::sync::Arc<str>> = domains
                    .iter()
                    .map(|d| std::sync::Arc::clone(d.as_arc()))
                    .collect();
                self.handle_node_shutdown(
                    peer_id,
                    &node_id,
                    role,
                    domains_vec.as_slice(),
                    graceful,
                    shutdown_at,
                    timestamp,
                )
                .await;
            }
            #[cfg(not(feature = "dns"))]
            MeshMessage::NodeShutdown { .. } => {
                tracing::debug!("NodeShutdown received but DNS feature not enabled");
            }
            MeshMessage::SiteConfigSync {
                request_id,
                site_id,
                config_version,
                config_json,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => {
                self.handle_site_config_sync(
                    peer_id,
                    &request_id,
                    &site_id,
                    config_version,
                    &config_json,
                    timestamp,
                    &source_node_id,
                    signature.as_ref(),
                    signer_public_key.as_deref(),
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegisterRequest {
                request_id,
                domain,
                origin_node_id,
                challenge_token,
                geo,
                capacity,
                timestamp,
                signature,
            } => {
                self.handle_dns_domain_register_request(
                    peer_id,
                    &request_id,
                    &domain,
                    &origin_node_id,
                    &challenge_token,
                    geo.as_deref(),
                    capacity,
                    timestamp,
                    &signature,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegisterResponse {
                request_id,
                domain,
                origin_node_id,
                verified,
                reason,
                timestamp,
                signature: _,
            } => {
                self.handle_dns_domain_register_response(
                    peer_id,
                    &request_id,
                    &domain,
                    &origin_node_id,
                    verified,
                    &reason,
                    timestamp,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainDeregisterRequest {
                request_id,
                domain,
                origin_node_id,
                reason,
                timestamp,
                signature: _,
            } => {
                self.handle_dns_domain_deregister_request(
                    peer_id,
                    &request_id,
                    &domain,
                    &origin_node_id,
                    &reason,
                    timestamp,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegistered {
                domain,
                origin_node_id,
                verified_by_global_node,
                geo,
                capacity,
                registered_at,
                expires_at,
                signature: _,
            } => {
                self.handle_dns_domain_registered(
                    peer_id,
                    &domain,
                    &origin_node_id,
                    &verified_by_global_node,
                    geo.as_deref(),
                    capacity,
                    registered_at,
                    expires_at,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainDeregistered {
                domain,
                origin_node_id,
                deregistered_by_global_node,
                reason,
                deregistered_at,
                signature: _,
            } => {
                self.handle_dns_domain_deregistered(
                    peer_id,
                    &domain,
                    &origin_node_id,
                    &deregistered_by_global_node,
                    &reason,
                    deregistered_at,
                )
                .await;
            }
            MeshMessage::Ping {
                request_id,
                node_id: _,
                timestamp: _,
            } => {
                self.handle_ping(peer_id, &request_id).await;
            }
            MeshMessage::Pong {
                request_id,
                node_id,
                timestamp: _,
            } => {
                self.handle_pong(peer_id, &request_id, &node_id).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::AnycastNodeRegistration { .. } => {
                tracing::debug!("AnycastNodeRegistration received");
            }
            #[cfg(feature = "dns")]
            MeshMessage::AnycastHealthUpdate {
                node_id,
                anycast_ips,
                healthy,
                latency_ms,
                load_percent,
                timestamp: _,
            } => {
                self.handle_anycast_health_update(
                    peer_id,
                    &node_id,
                    anycast_ips,
                    healthy,
                    latency_ms,
                    load_percent,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::ZoneSyncRequest {
                request_id,
                zone_origin,
                serial,
                requesting_node_id,
                timestamp: _,
            } => {
                self.handle_zone_sync_request(
                    peer_id,
                    &request_id,
                    &zone_origin,
                    serial,
                    &requesting_node_id,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::ZoneSyncResponse {
                request_id,
                zone_origin,
                records_json,
                serial,
                complete,
                timestamp: _,
                origin_signature,
                origin_pubkey,
                previous_serial,
                compressed,
            } => {
                self.handle_zone_sync_response(
                    peer_id,
                    &request_id,
                    &zone_origin,
                    &records_json,
                    serial,
                    complete,
                    &origin_signature,
                    origin_pubkey.as_deref(),
                    previous_serial,
                    compressed,
                )
                .await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::ZoneSyncAck {
                request_id,
                zone_origin,
                serial,
                timestamp: _,
            } => {
                self.handle_zone_sync_ack(peer_id, &request_id, &zone_origin, serial)
                    .await;
            }
            _ => {
                tracing::trace!(
                    "Received unhandled datagram type from {}: {:?}",
                    peer_id,
                    msg
                );
            }
        }

        Ok(())
    }

    pub(crate) async fn handle_keepalive_datagram(&self, peer_id: &str) {
        tracing::trace!("Received keepalive from {}", peer_id);
        if let Some(mut peer) = self.peer_connections.get_mut(peer_id) {
            peer.last_seen = Instant::now();
        }
    }

    pub(crate) async fn handle_lookup_request(
        &self,
        from_peer: &str,
        request_id: &str,
        key: &str,
        lookup_type: crate::mesh::protocol::LookupType,
    ) {
        tracing::debug!(
            "Received lookup request: {} for key {} from {}",
            request_id,
            key,
            from_peer
        );

        let value = match lookup_type {
            crate::mesh::protocol::LookupType::Route => {
                if let Some((provider, hops)) = self.topology.get_cached_route(key).await {
                    Some(format!("{}:{}", provider, hops).into_bytes())
                } else {
                    self.topology
                        .get_upstream_info(key)
                        .await
                        .map(|_local| format!("local:{}", self.config.node_id()).into_bytes())
                }
            }
            crate::mesh::protocol::LookupType::Peer => {
                if let Some(peer) = self.topology.get_peer(key).await {
                    Some(peer.address.clone().into_bytes())
                } else {
                    None
                }
            }
            crate::mesh::protocol::LookupType::KeyValue
            | crate::mesh::protocol::LookupType::Certificate
            | crate::mesh::protocol::LookupType::Config => None,
        };

        let response = MeshMessage::LookupResponse {
            request_id: request_id.into(),
            key: key.into(),
            value: value.clone(),
            found: value.is_some(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send lookup response to {}: {}", from_peer, e);
        }
    }

    pub(crate) async fn handle_lookup_batch_request(
        &self,
        from_peer: &str,
        request_id: &str,
        keys: &[crate::mesh::protocol::ArcStr],
    ) {
        if keys.len() > MAX_BATCH_KEYS {
            tracing::warn!(
                "Batch lookup request from {} rejected: {} keys exceeds limit of {}",
                from_peer,
                keys.len(),
                MAX_BATCH_KEYS
            );
            let response = MeshMessage::Error {
                code: 400,
                message: format!("Too many keys: {} (max {})", keys.len(), MAX_BATCH_KEYS).into(),
            };
            let _ = self.send_datagram_to_peer(from_peer, &response).await;
            return;
        }

        tracing::debug!(
            "Received batch lookup request: {} for {} keys from {}",
            request_id,
            keys.len(),
            from_peer
        );

        let mut results = HashMap::new();

        for key in keys {
            if let Some((provider, _)) = self.topology.get_cached_route(key).await {
                results.insert(
                    key.to_string(),
                    Some(format!("{}:{}", provider, 0).into_bytes()),
                );
            } else if self.topology.has_local_upstream(key).await {
                results.insert(
                    key.to_string(),
                    Some(format!("local:{}", self.config.node_id()).into_bytes()),
                );
            } else {
                results.insert(key.to_string(), None);
            }
        }

        let response = MeshMessage::LookupBatchResponse {
            request_id: request_id.into(),
            results,
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!(
                "Failed to send batch lookup response to {}: {}",
                from_peer,
                e
            );
        }
    }

    pub(crate) async fn handle_peer_health_check(
        &self,
        from_peer: &str,
        target_peer_id: &str,
        _timestamp: u64,
    ) {
        tracing::trace!(
            "Received health check request for {} from {}",
            target_peer_id,
            from_peer
        );

        let status = if let Some(peer) = self.topology.get_peer(target_peer_id).await {
            if peer.is_healthy() {
                crate::mesh::protocol::HealthStatus::Healthy
            } else {
                crate::mesh::protocol::HealthStatus::Degraded
            }
        } else {
            crate::mesh::protocol::HealthStatus::Unknown
        };

        let response = MeshMessage::PeerHealthResponse {
            peer_id: target_peer_id.into(),
            status,
            latency_ms: None,
            timestamp: crate::utils::safe_unix_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send health response to {}: {}", from_peer, e);
        }
    }

    pub(crate) async fn handle_peer_announce(
        &self,
        from_peer: &str,
        node_id: &str,
        address: &str,
        role: crate::mesh::config::MeshNodeRole,
        capabilities: &crate::mesh::protocol::MeshCapabilities,
        _announced_at: u64,
    ) {
        tracing::debug!(
            "Received peer announce: {} ({}) from {}",
            node_id,
            address,
            from_peer
        );

        self.topology
            .add_peer(
                crate::mesh::protocol::MeshPeerInfo {
                    node_id: node_id.to_string(),
                    address: address.to_string(),
                    role,
                    capabilities: capabilities.clone(),
                    is_global: role.is_global(),
                    latency_ms: None,
                    upstreams: vec![],
                    is_trusted: role.is_global(),
                    quic_port: None,
                    wireguard_port: None,
                    advertised_port: None,
                },
                PeerStatus::Healthy,
            )
            .await;

        self.update_threat_intel_global_nodes().await;
    }

    pub(crate) async fn handle_peer_gone(&self, from_peer: &str, node_id: &str, reason: &str) {
        tracing::info!(
            "Peer {} announced departure from {}: {}",
            node_id,
            from_peer,
            reason
        );

        self.topology.remove_peer(node_id).await;

        self.update_threat_intel_global_nodes().await;
    }

    pub(crate) async fn handle_site_config_sync(
        &self,
        _from_peer: &str,
        _request_id: &str,
        site_id: &str,
        config_version: u64,
        config_json: &str,
        timestamp: u64,
        source_node_id: &str,
        signature: &[u8],
        signer_public_key: Option<&str>,
    ) {
        tracing::info!(
            "Received site config sync for site {} version {} from node {}",
            site_id,
            config_version,
            source_node_id
        );

        let is_valid_origin = {
            let origins = self.topology.find_all_origins_for_site(site_id).await;
            origins.contains(&source_node_id.to_string())
        };

        if !is_valid_origin {
            tracing::warn!(
                "Site config sync from {} who is not an origin for site {} - rejecting",
                source_node_id,
                site_id
            );
            return;
        }

        let verified = if !signature.is_empty() {
            let public_key = match signer_public_key {
                Some(pk) => pk,
                None => {
                    tracing::warn!(
                        "Site config sync from {} has signature but no public key - rejecting",
                        source_node_id
                    );
                    return;
                }
            };

            let sign_data = format!(
                "{}:{}:{}:{}",
                site_id,
                config_version,
                config_json.len(),
                timestamp
            );

            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, public_key) {
                Ok(pubkey_bytes) => {
                    let result = crate::integrity::signing::verify_ed25519_raw(
                        &pubkey_bytes,
                        &sign_data,
                        signature,
                    );
                    if result {
                        tracing::info!(
                            "Site config sync signature verified for site {} from {}",
                            site_id,
                            source_node_id
                        );
                    } else {
                        tracing::warn!(
                            "Site config sync signature verification FAILED for site {} from {}",
                            site_id,
                            source_node_id
                        );
                    }
                    result
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to decode public key for site config sync from {}: {}",
                        source_node_id,
                        e
                    );
                    return;
                }
            }
        } else {
            tracing::debug!(
                "Site config sync from {} has no signature - accepting (backward compatible)",
                source_node_id
            );
            true
        };

        if !verified {
            tracing::warn!(
                "Rejected site config sync from {} due to invalid signature",
                source_node_id
            );
            return;
        }

        let tx_to_send = {
            let tx_option = self.site_config_sync_tx.read();
            tx_option.clone()
        };

        if let Some(tx) = tx_to_send {
            let _ = tx
                .send((site_id.to_string(), config_json.to_string()))
                .await;
            tracing::debug!("Sent site config sync to callback handler");
        } else {
            tracing::warn!("No site config sync callback configured");
        }
    }

    pub(crate) async fn handle_topology_sync_request(
        &self,
        from_peer: &str,
        request_id: &str,
        from_version: u64,
    ) {
        tracing::debug!(
            "Received topology sync request: {} from version {} from {}",
            request_id,
            from_version,
            from_peer
        );

        let peers = self.topology.get_all_peers().await;
        let upstreams = self.topology.get_upstream_owners().await;
        let version = self.topology.get_topology_version().await;

        let response = MeshMessage::TopologySyncResponse {
            request_id: request_id.into(),
            peers: peers
                .into_iter()
                .map(|p| crate::mesh::protocol::MeshPeerInfo {
                    node_id: p.node_id,
                    address: p.address,
                    role: p.role,
                    capabilities: p.capabilities,
                    is_global: p.is_global,
                    latency_ms: p.latency_ms,
                    upstreams: p.upstreams.into_iter().collect(),
                    is_trusted: p.role.is_global(),
                    quic_port: p.quic_port,
                    wireguard_port: p.wireguard_port,
                    advertised_port: p.advertised_port,
                })
                .collect(),
            upstreams,
            version,
            is_delta: false,
            removed_peers: vec![],
            removed_upstreams: vec![],
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!(
                "Failed to send topology sync response to {}: {}",
                from_peer,
                e
            );
        }
    }

    pub(crate) async fn handle_seed_list_request(
        &self,
        from_peer: &str,
        _node_id: &str,
        request_full_mesh: bool,
    ) {
        tracing::debug!(
            "Received seed list request from {} (full_mesh: {})",
            from_peer,
            request_full_mesh
        );

        let response = if self.topology.is_global() {
            let global_nodes = self.topology.get_seeded_global_nodes().await;
            let edge_nodes = if request_full_mesh {
                self.topology.get_seeded_edge_nodes().await
            } else {
                Vec::new()
            };

            MeshMessage::SeedListResponse {
                global_nodes,
                edge_nodes,
                version: 1,
                genesis_org_id: Some(self.config.node_identity.genesis_org_id().into()),
            }
        } else {
            MeshMessage::Error {
                code: 403,
                message: "Only global nodes can serve seed lists".into(),
            }
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send seed list response to {}: {}", from_peer, e);
        }
    }

    pub(crate) async fn handle_peer_load_report(
        &self,
        node_id: &str,
        active_connections: u32,
        cpu_load_percent: f32,
        memory_percent: f32,
        _requests_per_second: f32,
    ) {
        tracing::trace!(
            "Received load report from {}: conns={}, cpu={}%, mem={}%",
            node_id,
            active_connections,
            cpu_load_percent,
            memory_percent
        );

        let load_score = ((cpu_load_percent as f64 / 100.0) * 0.6
            + (memory_percent as f64 / 100.0) * 0.4)
            .min(1.0)
            .max(0.0);

        let mut scores = self.topology.peer_scores().write().await;
        if let Some(score) = scores.get_mut(node_id) {
            score.load_score = 1.0 - load_score;
            score.last_updated = Instant::now();
        } else {
            scores.insert(
                node_id.to_string(),
                crate::mesh::topology::PeerScore {
                    node_id: node_id.to_string(),
                    latency_score: 0.5,
                    stability_score: 0.5,
                    load_score: 1.0 - load_score,
                    traffic_score: 0.0,
                    upstream_score: 0.0,
                    total_score: 0.5,
                    last_updated: Instant::now(),
                },
            );
        }
    }

    pub(crate) async fn handle_peer_load_update(&self, node_id: &str, load_score: f64) {
        tracing::trace!(
            "Received load update from {}: score={}",
            node_id,
            load_score
        );

        let mut scores = self.topology.peer_scores().write().await;
        if let Some(score) = scores.get_mut(node_id) {
            score.load_score = 1.0 - load_score;
            score.last_updated = Instant::now();
        }
    }

    pub(crate) async fn handle_route_usage_report(
        &self,
        upstream_id: &str,
        request_count: u64,
        bytes_transferred: u64,
    ) {
        tracing::trace!(
            "Received route usage report for {}: {} requests, {} bytes",
            upstream_id,
            request_count,
            bytes_transferred
        );

        self.topology
            .record_route_usage(upstream_id.to_string(), bytes_transferred)
            .await;

        if let Some(score) = self
            .topology
            .peer_scores()
            .write()
            .await
            .get_mut(upstream_id)
        {
            let usage = self.topology.route_usage().read().await;
            score.traffic_score = usage.get_upstream_score(upstream_id);
        }
    }

    pub(crate) async fn handle_upstream_blocked(
        &self,
        mesh_identifier: &str,
        service_id: &str,
        blocked_until: u64,
        reason: &str,
        origin_node_id: &str,
    ) {
        // blocked_until is Unix timestamp when block expires
        let now_unix = crate::utils::safe_unix_timestamp();

        // Validate: block timestamp not unreasonably far in the future
        let max_allowed = now_unix + MAX_BLOCK_DURATION_SECS;
        if blocked_until > max_allowed {
            tracing::warn!(
                "Received block with timestamp too far in future: {} (current: {}, max: {}). Ignoring.",
                blocked_until, now_unix, max_allowed
            );
            return;
        }

        // Calculate remaining duration, skip if already expired
        let remaining_secs = blocked_until.saturating_sub(now_unix);
        if remaining_secs == 0 {
            tracing::debug!(
                "Received expired block notification for {}.{}, ignoring",
                mesh_identifier,
                service_id
            );
            return;
        }

        let blocked_instant = Instant::now() + Duration::from_secs(remaining_secs);

        tracing::info!(
            "Received upstream blocked notification: {}.{} blocked for {}s (reason: {})",
            mesh_identifier,
            service_id,
            remaining_secs,
            reason
        );

        self.topology
            .block_upstream(
                mesh_identifier,
                service_id,
                blocked_instant,
                reason,
                origin_node_id,
            )
            .await;
    }

    pub(crate) async fn handle_bandwidth_report(
        &self,
        upstream_id: &str,
        bytes_sent: u64,
        bytes_received: u64,
        request_count: u64,
        interval_secs: u64,
        _timestamp: u64,
    ) {
        tracing::trace!(
            "Received bandwidth report for {}: {}B sent, {}B recv, {} reqs in {}s",
            upstream_id,
            bytes_sent,
            bytes_received,
            request_count,
            interval_secs
        );

        self.topology
            .record_route_usage(upstream_id.to_string(), bytes_sent + bytes_received)
            .await;
    }

    pub(crate) async fn send_load_report_to_peers(&self) {
        let active_connections = crate::admin::get_current_connections() as u32;
        let (cpu_load_percent, memory_percent) = crate::admin::get_cpu_memory_usage();
        let requests_per_second = 0.0_f32;

        let load_report = MeshMessage::PeerLoadReport {
            node_id: self.config.node_id().into(),
            active_connections,
            cpu_load_percent,
            memory_percent,
            requests_per_second,
        };

        let peer_ids: Vec<String> = self
            .peer_connections
            .iter()
            .map(|e| e.key().clone())
            .collect();

        for peer_id in peer_ids {
            if let Err(e) = self.send_datagram_to_peer(&peer_id, &load_report).await {
                tracing::debug!("Failed to send load report to {}: {}", peer_id, e);
            }
        }

        tracing::trace!(
            "Sent load report to peers: conns={}, cpu={}%, mem={}%",
            active_connections,
            cpu_load_percent,
            memory_percent
        );
    }

    pub(crate) async fn peer_message_loop(
        &self,
        _session_id: String,
        peer_node_id: String,
        connection: Connection,
        topology: Arc<MeshTopology>,
    ) {
        let topology_for_loop = topology.clone();
        loop {
            tokio::select! {
                result = connection.accept_bi() => {
                    match result {
                        Ok((mut send_stream, mut recv_stream)) => {
                            let topo = topology_for_loop.clone();
                            let transport = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = transport.handle_peer_message(&mut send_stream, &mut recv_stream, &topo).await {
                                    tracing::debug!("Peer message error: {}", e);
                                }
                            });
                        }
                        Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                            tracing::info!("Peer {} disconnected", peer_node_id);
                            topology.update_peer_status(&peer_node_id, PeerStatus::Disconnected).await;
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("Peer {} connection error: {}", peer_node_id, e);
                            topology.update_peer_status(&peer_node_id, PeerStatus::Disconnected).await;
                            break;
                        }
                    }
                }
                _ = connection.closed() => {
                    tracing::info!("Peer {} connection closed", peer_node_id);
                    topology.update_peer_status(&peer_node_id, PeerStatus::Disconnected).await;
                    break;
                }
            }
        }
    }

    pub(crate) async fn handle_peer_message(
        &self,
        send_stream: &mut SendStream,
        recv_stream: &mut RecvStream,
        topology: &MeshTopology,
    ) -> Result<(), MeshTransportError> {
        let mut len_buf = [0u8; 4];
        recv_stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(MeshTransportError::ReceiveFailed(format!(
                "Message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            )));
        }
        let mut data = vec![0u8; len];
        recv_stream
            .read_exact(&mut data)
            .await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;

        let msg = MeshMessage::decode(&data).ok_or_else(|| {
            MeshTransportError::ReceiveFailed("Failed to decode message".to_string())
        })?;

        match msg {
            MeshMessage::RouteQuery {
                query_id,
                upstream_id,
                max_hops,
                initiator,
                sequence: _,
                timestamp: _,
                nonce: _,
            } => {
                self.handle_route_query(
                    send_stream,
                    query_id.to_string(),
                    upstream_id.to_string(),
                    max_hops,
                    initiator.to_string(),
                    topology,
                )
                .await?;
            }
            MeshMessage::RouteResponse {
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                upstream_url: _,
                waf_policy: _,
                priority_tier: _,
                ..
            } => {
                let _ = query_id;
                tracing::debug!(
                    "Got route response: {} -> {} ({} hops)",
                    upstream_id,
                    provider_node_id,
                    hops
                );
                topology
                    .cache_route(
                        &upstream_id,
                        provider_node_id.to_string(),
                        hops,
                        Duration::from_secs(ttl_secs as u64),
                    )
                    .await;
            }
            MeshMessage::RouteNotFound {
                query_id,
                upstream_id,
            } => {
                let _ = query_id;
                tracing::debug!("Route not found: {} from query {}", upstream_id, query_id);
            }
            MeshMessage::UpstreamAnnounce {
                upstream_id,
                action: _,
                signature: _,
            } => {
                tracing::debug!("Upstream announcement: {}", upstream_id);
            }
            MeshMessage::UpstreamUpdate {
                upstream_id,
                info: _,
                signature: _,
            } => {
                tracing::debug!("Upstream update: {}", upstream_id);
            }
            MeshMessage::KeepAlive => {
                let response = MeshMessage::KeepAliveAck
                    .encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (response.len() as u32).to_be_bytes();
                send_stream
                    .write_all(&len)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                send_stream
                    .write_all(&response)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
            }
            MeshMessage::Hello { .. } | MeshMessage::HelloAck { .. } => {
                tracing::warn!("Unexpected handshake message in peer loop");
            }
            _ => {
                tracing::debug!("Unhandled mesh message type");
            }
        }

        Ok(())
    }

    pub(crate) async fn perform_health_check(&self, peer_id: &str) -> Option<u32> {
        let start = Instant::now();

        if let Some(peer) = self.peer_connections.get(peer_id) {
            let result = async {
                let (mut send_stream, mut recv_stream) = peer.connection.open_bi().await?;

                let msg = MeshMessage::PeerHealthCheck {
                    peer_id: self.config.node_id().into(),
                    timestamp: crate::utils::safe_unix_timestamp(),
                };

                let encoded = msg.encode()?;
                let len = (encoded.len() as u32).to_be_bytes();
                send_stream.write_all(&len).await?;
                send_stream.write_all(&encoded).await?;

                let mut len_buf = [0u8; 4];
                recv_stream.read_exact(&mut len_buf).await?;
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_MESSAGE_SIZE {
                    return Err(MeshTransportError::ReceiveFailed(format!(
                        "Health check response too large: {} bytes (max {})",
                        len, MAX_MESSAGE_SIZE
                    )));
                }
                let mut buf = vec![0u8; len];
                recv_stream.read_exact(&mut buf).await?;

                Ok::<_, MeshTransportError>(())
            }
            .await;

            let latency = start.elapsed().as_millis() as u32;

            if result.is_ok() {
                self.topology.record_connection_success(peer_id).await;
                self.topology
                    .update_peer_latency_for_score(peer_id, latency)
                    .await;
                self.topology.update_peer_latency(peer_id, latency).await;
                self.topology
                    .update_peer_status(peer_id, PeerStatus::Healthy)
                    .await;
                tracing::trace!("Health check OK for {}: {}ms", peer_id, latency);
                return Some(latency);
            } else {
                self.topology.record_connection_failure(peer_id).await;
                self.topology
                    .update_peer_status(peer_id, PeerStatus::Unhealthy)
                    .await;
                tracing::warn!("Health check failed for {}: {:?}", peer_id, result.err());
                return None;
            }
        }

        None
    }
}
