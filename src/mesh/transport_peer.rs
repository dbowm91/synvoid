#![allow(dead_code, clippy::redundant_locals)] // Reserved for future peer communication handling

use crate::mesh::transport::{
    MeshTransport, MeshTransportError, MAX_BATCH_KEYS, MAX_BLOCK_DURATION_SECS, MAX_MESSAGE_SIZE,
};
use hex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::broadcast;

use crate::mesh::protocol::{ArcStr, HealthStatus, MeshMessage};

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
        use futures::future;
        use tokio::time::{timeout, Duration};

        const POLL_TIMEOUT_MS: u64 = 100;

        let peers: Vec<(String, quinn::Connection)> = self
            .peer_connections
            .iter()
            .map(|e| (e.key().clone(), e.value().connection.clone()))
            .collect();

        if peers.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
            return None;
        }

        let futures = peers.iter().map(|(peer_id, connection)| async move {
            match timeout(
                Duration::from_millis(POLL_TIMEOUT_MS),
                connection.read_datagram(),
            )
            .await
            {
                Ok(Ok(data)) => Some((peer_id.clone(), data)),
                Ok(Err(e)) => {
                    let err_str = e.to_string();
                    if err_str.contains("unsupported") {
                        tracing::debug!("Peer {} does not support datagrams", peer_id);
                    } else if err_str.contains("finished") || err_str.contains("FinRead") {
                    } else {
                        tracing::trace!("Datagram read error from {}: {}", peer_id, e);
                    }
                    None
                }
                Err(_) => None,
            }
        });

        let results = future::join_all(futures).await;

        for result in results.into_iter().flatten() {
            return Some(result);
        }

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
                signature,
                timestamp,
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
                    timestamp,
                    signature,
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
            MeshMessage::UpstreamVerificationQuery {
                request_id,
                upstream_id,
                querying_node_id,
                timestamp: _,
                provider_node_id,
            } => {
                self.handle_upstream_verification_query(
                    peer_id,
                    &request_id,
                    &upstream_id,
                    &querying_node_id,
                    &provider_node_id,
                )
                .await;
            }
            MeshMessage::UpstreamVerificationResponse {
                request_id,
                upstream_id,
                verified,
                global_node_id,
                global_node_signature: _,
                upstream_url: _,
                org_id: _,
                timestamp: _,
                provider_node_id,
            } => {
                self.handle_upstream_verification_response(
                    peer_id,
                    &request_id,
                    &upstream_id,
                    verified,
                    &global_node_id,
                    &provider_node_id,
                )
                .await;
            }
            MeshMessage::UpstreamOwnershipChallenge {
                request_id,
                upstream_id,
                challenge_type,
                challenge_token,
                global_node_id,
                timestamp,
            } => {
                self.handle_upstream_ownership_challenge(
                    peer_id,
                    &request_id,
                    &upstream_id,
                    &challenge_type,
                    &challenge_token,
                    &global_node_id,
                    timestamp,
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
            MeshMessage::GenesisKeyTransition {
                sequence,
                new_key_fingerprint,
                announced_by,
                timestamp,
                genesis_signature,
            } => {
                self.handle_genesis_key_transition(
                    peer_id,
                    sequence,
                    &new_key_fingerprint,
                    &announced_by,
                    timestamp,
                    &genesis_signature,
                )
                .await;
            }
            MeshMessage::RevokeGlobalNode {
                node_id,
                reason,
                timestamp,
                genesis_signature,
            } => {
                self.handle_revoke_global_node(
                    peer_id,
                    &node_id,
                    &reason,
                    timestamp,
                    &genesis_signature,
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
                signature,
                signer_public_key,
            } => {
                self.handle_dht_snapshot_request(
                    peer_id,
                    &request_id,
                    &node_id,
                    from_version,
                    &signature,
                    &signer_public_key,
                )
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
            MeshMessage::DhtRecordQuery {
                request_id,
                key,
                timestamp: _,
                source_node_id: _,
            } => {
                if let Some(ref record_store) = self.record_store {
                    if let Some(response) =
                        record_store.handle_record_query(&request_id, &key, peer_id)
                    {
                        let _ = self.send_datagram_to_peer(peer_id, &response).await;
                    }
                }
            }
            MeshMessage::DhtRecordResponse {
                request_id,
                key,
                value,
                found,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => {
                if found {
                    let record = crate::mesh::protocol::DhtRecord {
                        key: key.to_string(),
                        value: value.clone(),
                        timestamp,
                        sequence_number: 0,
                        ttl_seconds: 0,
                        source_node_id: source_node_id.to_string(),
                        signature,
                        signer_public_key: Some(signer_public_key),
                        content_hash: {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(&value);
                            hasher.finalize().to_vec()
                        },
                    };
                    let _ = self.complete_dht_query(&request_id, record).await;
                }
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
                let domains_vec: Vec<std::sync::Arc<str>> =
                    domains.iter().map(|d| d.as_arc()).collect();
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
                proxy_cache_preferences,
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
                    proxy_cache_preferences.as_ref(),
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
            MeshMessage::ThreatAnnounce { .. }
            | MeshMessage::ThreatSyncRequest { .. }
            | MeshMessage::ThreatSyncResponse { .. }
            | MeshMessage::ThreatAcknowledgement { .. } => {
                if let Some(ref threat_intel) = self.threat_intel {
                    let peer_role = self
                        .topology
                        .get_peer(peer_id)
                        .await
                        .map(|p| p.role)
                        .unwrap_or(crate::mesh::config::MeshNodeRole::EDGE);
                    if let Some(response) = threat_intel.handle_mesh_message(
                        &msg,
                        peer_id,
                        peer_role,
                        self.mesh_signer.as_ref(),
                    ) {
                        let _ = self.send_datagram_to_peer(peer_id, &response).await;
                    }
                } else {
                    tracing::trace!(
                        "Threat message received but threat intel not enabled: {:?}",
                        msg
                    );
                }
            }
            MeshMessage::YaraRuleAnnounce { .. }
            | MeshMessage::YaraRuleSyncRequest { .. }
            | MeshMessage::YaraRuleSyncResponse { .. }
            | MeshMessage::YaraRuleAcknowledgement { .. }
            | MeshMessage::YaraRuleSubmission { .. }
            | MeshMessage::YaraRuleSubmissionResponse { .. } => {
                if let Some(ref yara_rules) = self.yara_rules {
                    if let Some(response) = yara_rules.handle_mesh_message(&msg, peer_id) {
                        let _ = self.send_datagram_to_peer(peer_id, &response).await;
                    }
                } else {
                    tracing::trace!(
                        "YARA message received but YARA rules not enabled: {:?}",
                        msg
                    );
                }
            }
            MeshMessage::OrgKeySignRequest { .. } | MeshMessage::OrgKeySignResponse { .. } => {
                if let Some(response) = self.org_key_manager.handle_mesh_message(msg).await {
                    let _ = self.send_datagram_to_peer(peer_id, &response).await;
                }
            }
            MeshMessage::QuorumStoreRequest {
                request_id,
                key,
                value,
                ttl_seconds,
                origin_node_id,
                origin_signature,
                action: _,
            } => {
                if let Some(ref record_store) = self.record_store {
                    let record = crate::mesh::protocol::DhtRecord {
                        key: key.to_string(),
                        value: value.clone(),
                        timestamp: crate::mesh::safe_unix_timestamp(),
                        sequence_number: 0,
                        ttl_seconds,
                        source_node_id: origin_node_id.to_string(),
                        signature: origin_signature.clone(),
                        signer_public_key: None,
                        content_hash: {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(&value);
                            hasher.finalize().to_vec()
                        },
                    };

                    if record_store
                        .handle_quorum_store_request(&request_id.to_string(), peer_id, record)
                        .await
                    {
                        tracing::debug!("Quorum store request accepted for key: {}", key);
                    } else {
                        tracing::debug!("Quorum store request rejected for key: {}", key);
                    }
                }
            }
            MeshMessage::QuorumSignatureResponse {
                request_id,
                key: _,
                signature,
            } => {
                if let Some(ref record_store) = self.record_store {
                    let _ = record_store
                        .handle_quorum_signature_response(
                            &request_id.to_string(),
                            peer_id,
                            signature,
                        )
                        .await;
                }
            }
            MeshMessage::QuorumRejectionResponse {
                request_id,
                key: _,
                reason,
                evidence,
            } => {
                if let Some(ref record_store) = self.record_store {
                    record_store
                        .handle_quorum_rejection_response(
                            &request_id.to_string(),
                            peer_id,
                            reason,
                            evidence,
                        )
                        .await;
                }
            }
            MeshMessage::UpstreamAnnounce {
                upstream_id,
                action,
                signature,
                origin_ed25519_pubkey,
                origin_signature,
            } => {
                use crate::mesh::dht::keys::DhtKey;
                use crate::mesh::protocol::AnnounceAction;
                use ed25519_dalek::Verifier;

                let upstream_id_str = upstream_id.to_string();
                let origin_pk_str = origin_ed25519_pubkey.to_string();

                let sign_data = format!("{}:{:?}:{}", upstream_id_str, action, peer_id);

                let signature_valid = if !origin_signature.is_empty()
                    && !origin_ed25519_pubkey.is_empty()
                {
                    let pk_bytes = hex::decode(&origin_pk_str);
                    let sig_bytes: Vec<u8> = origin_signature.clone();
                    if pk_bytes.as_ref().map_or(false, |b| b.len() == 32) && sig_bytes.len() == 64 {
                        let pk_bytes = pk_bytes.unwrap();
                        let mut pk_array = [0u8; 32];
                        pk_array.copy_from_slice(&pk_bytes);

                        let mut sig_array = [0u8; 64];
                        sig_array.copy_from_slice(&sig_bytes);

                        match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
                            Ok(pk) => pk
                                .verify(
                                    sign_data.as_bytes(),
                                    &ed25519_dalek::Signature::from_bytes(&sig_array),
                                )
                                .is_ok(),
                            Err(_) => false,
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !signature_valid {
                    tracing::warn!(
                        "UpstreamAnnounce from {} for {} rejected: invalid origin signature",
                        peer_id,
                        upstream_id_str
                    );
                    return Ok(());
                }

                let key = DhtKey::verified_upstream(&upstream_id_str);
                let key_str = key.as_str();

                match action {
                    AnnounceAction::Add | AnnounceAction::Update => {
                        if let Some(ref record_store) = self.record_store {
                            let origin_node_id = if let Ok(pk_bytes) = hex::decode(&origin_pk_str) {
                                crate::mesh::dht::routing::node_id::NodeId::from_public_key(
                                    &pk_bytes,
                                )
                                .to_string()
                            } else {
                                origin_pk_str.clone()
                            };

                            let verified_upstream = crate::mesh::dht::VerifiedUpstream {
                                upstream_id: upstream_id_str.clone(),
                                origin_node_id,
                                upstream_url: upstream_id_str.clone(),
                                org_id: None,
                                global_node_id: peer_id.to_string(),
                                global_node_signature: signature.clone(),
                                origin_signature: origin_signature.clone(),
                                origin_pubkey: {
                                    use base64::{engine::general_purpose::STANDARD, Engine};
                                    hex::decode(&origin_pk_str)
                                        .ok()
                                        .map(|bytes| STANDARD.encode(&bytes))
                                },
                                registered_at: crate::mesh::safe_unix_timestamp(),
                                expires_at: crate::mesh::safe_unix_timestamp() + 300,
                            };
                            if let Ok(bytes) = serde_json::to_vec(&verified_upstream) {
                                let ttl = 300;
                                record_store.store_and_announce(key_str.to_string(), bytes, ttl);
                                tracing::debug!(
                                    "Stored verified upstream {} in DHT (action: {:?})",
                                    upstream_id_str,
                                    action
                                );
                            }
                        }
                    }
                    AnnounceAction::Remove => {
                        tracing::debug!(
                            "Upstream {} announced removed (expires via TTL)",
                            upstream_id_str
                        );
                    }
                }
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
                    dns_serving_healthy: false,
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

        let was_global = {
            if let Some(peer) = self.topology.get_peer(node_id).await {
                peer.role.is_global()
            } else {
                false
            }
        };

        self.topology.remove_peer(node_id).await;

        if was_global {
            tracing::info!("Global node {} departed, triggering DHT rebalance", node_id);
            if let Some(ref record_store) = self.record_store {
                record_store.rebalance_after_departure(node_id).await;
            }
        }

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
        proxy_cache_preferences: Option<&crate::mesh::protocol::ProxyCachePreferences>,
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

        if signature.is_empty() {
            tracing::warn!(
                "Site config sync from {} has no signature - rejecting",
                source_node_id
            );
            return;
        }

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

        let verified =
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
                    false
                }
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
                .send((
                    site_id.to_string(),
                    config_json.to_string(),
                    proxy_cache_preferences.cloned(),
                ))
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
                    dns_serving_healthy: false,
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
            .clamp(0.0, 1.0);

        let mut scores = self.topology.peer_scores().write().await;
        if let Some(score) = scores.get_mut(node_id) {
            score.load_score = 1.0 - load_score;
            score.last_updated = crate::mesh::safe_unix_timestamp();
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
                    last_updated: crate::mesh::safe_unix_timestamp(),
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
            score.last_updated = crate::mesh::safe_unix_timestamp();
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

    pub(crate) async fn handle_upstream_verification_query(
        &self,
        peer_id: &str,
        request_id: &str,
        upstream_id: &str,
        querying_node_id: &str,
        provider_node_id: &str,
    ) {
        tracing::info!(
            "Received upstream verification query for {} (provider: {}) from node {} (request_id: {})",
            upstream_id,
            provider_node_id,
            querying_node_id,
            request_id
        );

        let upstream_info = self.topology.get_upstream_info(upstream_id).await;

        let (verified, upstream_url) = match upstream_info {
            Some(info) => {
                let url = info.upstream_url.clone();
                match self.verify_upstream_reachability(&url).await {
                    Ok(_) => (true, url),
                    Err(e) => {
                        tracing::warn!("Upstream {} verification failed: {}", upstream_id, e);
                        (false, url)
                    }
                }
            }
            None => {
                tracing::warn!("Upstream {} not found for verification", upstream_id);
                (false, String::new())
            }
        };

        let timestamp = crate::utils::safe_unix_timestamp();
        let signable_content = format!(
            "{}:{}:{}:{}:{}:{}",
            request_id, upstream_id, verified, querying_node_id, timestamp, provider_node_id
        );
        let global_node_signature = self
            .mesh_signer
            .as_ref()
            .map(|signer| signer.sign(signable_content.as_bytes()));

        let response = MeshMessage::UpstreamVerificationResponse {
            request_id: request_id.into(),
            upstream_id: upstream_id.into(),
            verified,
            global_node_id: querying_node_id.into(),
            global_node_signature,
            upstream_url: upstream_url.into(),
            org_id: None,
            timestamp,
            provider_node_id: provider_node_id.into(),
        };

        if let Err(e) = self.send_message_to_peer(peer_id, &response).await {
            tracing::warn!("Failed to send verification response to {}: {}", peer_id, e);
        }
    }

    async fn verify_upstream_reachability(&self, upstream_url: &str) -> Result<(), String> {
        use std::time::Duration;

        let url = url::Url::parse(upstream_url).map_err(|e| format!("Invalid URL: {}", e))?;

        let host = url.host_str().ok_or("No host in URL")?;
        let port = url.port().unwrap_or(80);
        let addr = format!("{}:{}", host, port);

        let connect_timeout = Duration::from_secs(5);
        let _read_timeout = Duration::from_secs(5);

        match tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("Connection failed: {}", e)),
            Err(_) => Err("Connection timed out".to_string()),
        }
    }

    pub(crate) async fn handle_upstream_verification_response(
        &self,
        peer_id: &str,
        request_id: &str,
        upstream_id: &str,
        verified: bool,
        _global_node_id: &str,
        provider_node_id: &str,
    ) {
        tracing::info!(
            "Received verification response for {} (provider: {}) from node {}: verified={} (request_id: {})",
            upstream_id,
            provider_node_id,
            peer_id,
            verified,
            request_id
        );

        if let Some(ref verification_mgr) = self.get_verification_manager() {
            verification_mgr.record_verification_result(
                upstream_id,
                provider_node_id,
                peer_id,
                verified,
            );
        }
    }

    pub(crate) fn get_verification_manager(
        &self,
    ) -> Option<Arc<crate::mesh::verification::VerificationTaskManager>> {
        self.verification_manager.read().clone()
    }

    pub(crate) async fn handle_upstream_ownership_challenge(
        &self,
        peer_id: &str,
        request_id: &str,
        upstream_id: &str,
        challenge_type: &crate::mesh::protocol::OwnershipChallengeType,
        challenge_token: &str,
        global_node_id: &str,
        timestamp: u64,
    ) {
        tracing::info!(
            "Received upstream ownership challenge for {} from global node {} (request_id: {})",
            upstream_id,
            global_node_id,
            request_id
        );

        if let Err(e) = self
            .verify_challenge_signature(request_id, global_node_id, timestamp, challenge_token)
            .await
        {
            tracing::warn!(
                "Challenge signature verification failed from global node {}: {}",
                global_node_id,
                e
            );
            return;
        }

        tracing::debug!(
            "Challenge signature verified for global node {}",
            global_node_id
        );

        match challenge_type {
            crate::mesh::protocol::OwnershipChallengeType::Dns01 {
                domain,
                txt_record_name,
                txt_record_value,
            } => {
                tracing::info!(
                    "DNS-01 challenge for domain {}: storing TXT record {} = {} for mesh DNS serving",
                    domain,
                    txt_record_name,
                    txt_record_value
                );

                self.store_dns01_challenge(
                    txt_record_name.clone(),
                    domain.clone(),
                    txt_record_value.clone(),
                    upstream_id.to_string(),
                );

                let proof = crate::mesh::protocol::OwnershipChallengeProof::Dns01 {
                    txt_record_value: txt_record_value.clone(),
                };

                let response = MeshMessage::UpstreamChallengeProof {
                    request_id: request_id.into(),
                    upstream_id: upstream_id.into(),
                    challenge_proof: proof,
                    origin_node_id: self.config.node_id().into(),
                    timestamp: crate::mesh::safe_unix_timestamp(),
                };

                if let Err(e) = self.send_datagram_to_peer(peer_id, &response).await {
                    tracing::warn!("Failed to send challenge proof to {}: {}", peer_id, e);
                }
            }
            crate::mesh::protocol::OwnershipChallengeType::Http01 {
                token,
                key_authorization,
            } => {
                tracing::info!(
                    "HTTP-01 challenge: storing key authorization for token {} at /.well-known/malu-challenge/{}",
                    token,
                    token
                );

                self.store_http01_challenge(
                    token.clone(),
                    key_authorization.clone(),
                    upstream_id.to_string(),
                );

                let proof = crate::mesh::protocol::OwnershipChallengeProof::Http01 {
                    key_authorization: key_authorization.clone(),
                };

                let response = MeshMessage::UpstreamChallengeProof {
                    request_id: request_id.into(),
                    upstream_id: upstream_id.into(),
                    challenge_proof: proof,
                    origin_node_id: self.config.node_id().into(),
                    timestamp: crate::mesh::safe_unix_timestamp(),
                };

                if let Err(e) = self.send_datagram_to_peer(peer_id, &response).await {
                    tracing::warn!("Failed to send challenge proof to {}: {}", peer_id, e);
                }
            }
        }
    }

    async fn verify_challenge_signature(
        &self,
        request_id: &str,
        global_node_id: &str,
        timestamp: u64,
        challenge_token: &str,
    ) -> Result<(), String> {
        if challenge_token.is_empty() {
            return Err("Empty challenge token".to_string());
        }

        if let Some(signature_hex) = challenge_token.strip_prefix("signed:") {
            let signature_bytes =
                hex::decode(signature_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;

            if signature_bytes.len() != 64 {
                return Err(format!(
                    "Invalid signature length: expected 64, got {}",
                    signature_bytes.len()
                ));
            }

            let cert_manager = self.cert_manager.read();
            let public_key_bytes = cert_manager
                .get_global_node_key(global_node_id)
                .ok_or_else(|| format!("No public key found for global node {}", global_node_id))?;

            let signable = format!("{}:{}:{}", request_id, global_node_id, timestamp);

            if crate::mesh::cert::verify_ed25519(&signable, &signature_bytes, &public_key_bytes) {
                tracing::debug!(
                    "Challenge signature verified for global node {}",
                    global_node_id
                );
                Ok(())
            } else {
                Err(format!(
                    "Signature verification failed for global node {}",
                    global_node_id
                ))
            }
        } else {
            Err("Unsupported challenge token format - expected 'signed:' prefix".to_string())
        }
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
        let peer_node_id_for_loop = peer_node_id.clone();
        loop {
            tokio::select! {
                result = connection.accept_bi() => {
                    match result {
                        Ok((mut send_stream, mut recv_stream)) => {
                            let topo = topology_for_loop.clone();
                            let transport = self.clone();
                            let peer_id = peer_node_id_for_loop.clone();
                            tokio::spawn(async move {
                                if let Err(e) = transport.handle_peer_message(&mut send_stream, &mut recv_stream, &topo, peer_id).await {
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
        peer_node_id: String,
    ) -> Result<(), MeshTransportError> {
        let mut first_byte = [0u8; 1];
        recv_stream
            .read_exact(&mut first_byte)
            .await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;

        let http_methods = [
            b'G', // GET
            b'P', // POST, PUT, PATCH
            b'H', // HTTP/
            b'D', // DELETE
            b'O', // OPTIONS
            b'T', // TRACE
            b'C', // CONNECT
        ];

        if http_methods.contains(&first_byte[0]) {
            let mut remainder = String::new();
            let mut total_header_buf = vec![first_byte[0]];

            let mut reader = tokio::io::BufReader::with_capacity(4096, recv_stream);
            use tokio::io::AsyncReadExt;
            reader
                .read_to_string(&mut remainder)
                .await
                .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
            total_header_buf.extend_from_slice(remainder.as_bytes());

            let http_data = total_header_buf.clone();
            let header_str = String::from_utf8_lossy(&total_header_buf);

            return self
                .handle_http_proxy_stream(
                    &header_str,
                    http_data,
                    send_stream,
                    topology,
                    peer_node_id,
                )
                .await;
        }

        let mut len_buf = [0u8; 3];
        recv_stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;

        let full_len_buf = [first_byte[0], len_buf[0], len_buf[1], len_buf[2]];
        let len = u32::from_be_bytes(full_len_buf) as usize;
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
            MeshMessage::SessionRotate {
                session_id,
                peer_id,
                key_version,
                peer_entropy,
                timestamp: _,
            } => {
                tracing::debug!(
                    "Received SessionRotate for session {} from peer {} (key_version={})",
                    session_id,
                    peer_id,
                    key_version,
                );
                if let Some(ref session_mgr) = self.mlkem_session_manager {
                    if let Err(e) =
                        session_mgr.apply_peer_rotation(&session_id, key_version, &peer_entropy)
                    {
                        tracing::warn!("Failed to apply peer session rotation: {}", e);
                    } else {
                        let ack = MeshMessage::SessionRotateAck {
                            session_id,
                            peer_id: self.config.node_id().into(),
                            key_version,
                            peer_entropy: Vec::new(),
                            timestamp: crate::utils::current_timestamp(),
                        };
                        let encoded = ack
                            .encode()
                            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                        let len = (encoded.len() as u32).to_be_bytes();
                        let _ = send_stream.write_all(&len).await;
                        let _ = send_stream.write_all(&encoded).await;
                    }
                }
            }
            MeshMessage::SessionRotateAck {
                session_id,
                peer_id: _,
                key_version: _,
                peer_entropy,
                timestamp: _,
            } => {
                tracing::debug!("Received SessionRotateAck for session {}", session_id);
                if let Some(ref session_mgr) = self.mlkem_session_manager {
                    if let Err(e) = session_mgr.finalize_rotation(&session_id, &peer_entropy) {
                        tracing::warn!("Failed to finalize session rotation: {}", e);
                    }
                }
            }
            MeshMessage::Ping {
                request_id,
                node_id: _,
                timestamp: _,
            } => {
                let response = MeshMessage::Pong {
                    request_id,
                    node_id: self.config.node_id().into(),
                    timestamp: crate::utils::safe_unix_timestamp(),
                };
                let encoded = response
                    .encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (encoded.len() as u32).to_be_bytes();
                let _ = send_stream.write_all(&len).await;
                let _ = send_stream.write_all(&encoded).await;
            }
            MeshMessage::Pong {
                request_id: _,
                node_id: _,
                timestamp: _,
            } => {
                tracing::trace!("Received Pong via stream");
            }
            MeshMessage::PeerHealthResponse {
                peer_id: _,
                status: _,
                latency_ms,
                timestamp: _,
            } => {
                if let Some(latency) = latency_ms {
                    tracing::trace!("Peer health response: latency={}ms", latency);
                }
            }
            MeshMessage::MeshAck {
                original_message_id: _,
                status: _,
                timestamp: _,
            } => {
                tracing::trace!("Received MeshAck via stream");
            }
            MeshMessage::RouteResponseAck {
                query_id,
                upstream_id: _,
                provider_node_id: _,
            } => {
                tracing::debug!("Route response ack for query {}", query_id);
            }
            MeshMessage::RouteRejected {
                query_id,
                upstream_id: _,
                reason: _,
                alternatives: _,
            } => {
                tracing::debug!("Route rejected for query {}", query_id);
            }
            MeshMessage::PeerHealthCheck {
                peer_id: _,
                timestamp: _,
            } => {
                let response = MeshMessage::PeerHealthResponse {
                    peer_id: self.config.node_id().into(),
                    status: HealthStatus::Healthy,
                    latency_ms: None,
                    timestamp: crate::utils::safe_unix_timestamp(),
                };
                let encoded = response
                    .encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (encoded.len() as u32).to_be_bytes();
                let _ = send_stream.write_all(&len).await;
                let _ = send_stream.write_all(&encoded).await;
            }
            MeshMessage::ServerlessFunctionAnnounce(announce) => {
                tracing::debug!(
                    "Received serverless function announce: {} v{}",
                    announce.function_name,
                    announce.version
                );
                self.handle_serverless_function_announce(announce).await;
            }
            MeshMessage::ServerlessInvokeRequest(req) => {
                tracing::debug!(
                    "Received serverless invoke request: {} from {}",
                    req.function_name,
                    req.caller_node_id
                );
                self.handle_serverless_invoke_request(&req).await?;
            }
            MeshMessage::ServerlessInvokeResponse(response) => {
                tracing::debug!(
                    "Received ServerlessInvokeResponse from {}: success={}, function={}",
                    response.caller_node_id,
                    response.success,
                    response.function_name
                );
                self.handle_serverless_invoke_response(&response).await?;
            }
            MeshMessage::RaftCommitNotification {
                leader_id: _,
                commit_index: _,
                namespace,
                key_id,
                timestamp: _,
            } => {
                tracing::debug!(
                    "Received RaftCommitNotification for namespace {:?} key {}",
                    namespace,
                    key_id
                );
                if let Some(ref edge_replica) = *self.edge_replica_manager.read() {
                    if let Some(ref rclient) = self.org_key_manager.get_raft_client() {
                        let erm = edge_replica.clone();
                        let rclient = rclient.clone();
                        let ns = namespace.clone();
                        let key = key_id.clone();
                        tokio::spawn(async move {
                            match rclient.query_leader_for_record(ns.clone(), &key).await {
                                Ok(Some(data)) => {
                                    if let Err(e) = erm.update_from_notification(&ns, &key, &data) {
                                        tracing::error!("Failed to update edge replica: {}", e);
                                    } else {
                                        tracing::info!(
                                            "Edge replica updated for {:?} key {}",
                                            ns,
                                            key
                                        );
                                    }
                                }
                                Ok(None) => {
                                    if let Err(e) = erm.delete_from_notification(&ns, &key) {
                                        tracing::error!(
                                            "Failed to delete from edge replica: {}",
                                            e
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Failed to query leader for record: {}", e);
                                }
                            }
                        });
                    }
                }
            }
            MeshMessage::Raft {
                target_node_id,
                payload,
            } => {
                tracing::debug!(
                    "Received Raft message for target {} via stream",
                    target_node_id
                );
                self.handle_raft_message(target_node_id.to_string(), payload, send_stream)
                    .await?;
            }
            _ => {
                tracing::trace!("Stream peer handler: unhandled message type received via stream");
            }
        }

        Ok(())
    }

    pub(crate) async fn handle_serverless_function_announce(
        &self,
        announce: crate::mesh::protocol::ServerlessFunctionAnnounce,
    ) {
        let Some(record_store) = self.record_store.clone() else {
            tracing::warn!("Serverless function announce received but no record store available");
            return;
        };

        let key = crate::mesh::dht::keys::DhtKey::serverless_function(&announce.function_name);
        let key_str = key.as_str();

        let value = serde_json::json!({
            "function_name": announce.function_name,
            "version": announce.version,
            "checksum": announce.checksum,
            "routes": announce.routes,
            "allowed_methods": announce.allowed_methods,
            "memory_mb": announce.memory_mb,
            "timeout_seconds": announce.timeout_seconds,
            "priority": announce.priority,
            "announced_at": chrono::Utc::now().timestamp(),
        });

        if let Ok(bytes) = serde_json::to_vec(&value) {
            let ttl = 3600;
            if record_store.store_and_announce(key_str.to_string(), bytes, ttl) {
                tracing::debug!(
                    "Stored serverless function {} in DHT with TTL {}s",
                    announce.function_name,
                    ttl
                );
            } else {
                tracing::warn!(
                    "Failed to store serverless function {} in DHT",
                    announce.function_name
                );
            }
        }
    }

    pub(crate) async fn handle_serverless_invoke_request(
        &self,
        req: &crate::mesh::protocol::ServerlessInvokeRequest,
    ) -> Result<(), MeshTransportError> {
        use crate::serverless::manager::CallerContext;
        use std::time::Instant;

        let start = Instant::now();

        let sm = {
            let guard = self.serverless_manager.read();
            guard.clone()
        };

        let Some(serverless_manager) = sm else {
            tracing::warn!(
                "ServerlessInvokeRequest for '{}' but serverless manager not available",
                req.function_name
            );
            return Ok(());
        };

        let caller = CallerContext {
            node_id: req.caller_node_id.clone(),
            role: crate::mesh::config::MeshNodeRole::EDGE,
            org_id: None,
            tier: None,
            is_local: false,
        };

        let function_name = req.function_name.clone();
        let result = serverless_manager
            .invoke_for_mesh(
                &function_name,
                "POST",
                "/",
                &http::HeaderMap::new(),
                None,
                caller,
            )
            .await;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        let (success, response_data, error_message) = match result {
            Ok(response) => {
                tracing::debug!(
                    "Serverless invoke '{}' completed: status={}, {}ms",
                    function_name,
                    response.status_code,
                    execution_time_ms
                );
                let body_vec = response.body.to_vec();
                (true, body_vec, String::new())
            }
            Err(e) => {
                tracing::warn!("Serverless invoke '{}' failed: {}", function_name, e);
                (false, Vec::new(), e.to_string())
            }
        };

        let response_msg = MeshMessage::ServerlessInvokeResponse(
            crate::mesh::protocol::ServerlessInvokeResponse {
                function_name,
                caller_node_id: req.caller_node_id.clone(),
                timestamp: crate::utils::safe_unix_timestamp(),
                response_data,
                success,
                error_message,
                execution_time_ms,
                response_signature: Vec::new(),
            },
        );

        if let Err(e) = self
            .send_message_to_peer(&req.caller_node_id, &response_msg)
            .await
        {
            tracing::warn!(
                "Failed to send ServerlessInvokeResponse to {}: {}",
                req.caller_node_id,
                e
            );
        }

        Ok(())
    }

    pub(crate) async fn handle_serverless_invoke_response(
        &self,
        response: &crate::mesh::protocol::ServerlessInvokeResponse,
    ) -> Result<(), MeshTransportError> {
        let mut pending = self.pending_serverless_invocations.lock().await;
        let key = format!("{}:{}", response.function_name, response.caller_node_id);
        if let Some(sender) = pending.remove(&key) {
            tracing::debug!(
                "Delivering serverless invocation response for '{}' to waiting caller",
                response.function_name
            );
            let _ = sender.send(response.clone());
        } else {
            tracing::warn!(
                "Received ServerlessInvokeResponse for '{}' but no pending invocation found",
                response.function_name
            );
        }
        Ok(())
    }

    pub(crate) async fn handle_raft_message(
        &self,
        target_node_id: String,
        payload: crate::mesh::protocol::RaftPayload,
        send_stream: &mut quinn::SendStream,
    ) -> Result<(), MeshTransportError> {
        let local_node_id = self.config.node_id();
        if target_node_id != local_node_id {
            tracing::warn!(
                "Received Raft message for node {} but local node is {} - forwarding not implemented",
                target_node_id,
                local_node_id
            );
            return Ok(());
        }

        let instance = {
            let guard = self.raft_instance.read();
            guard.clone()
        };

        let response_data = match payload.msg_type {
            crate::mesh::protocol::RaftMsgType::ClientProposal => {
                let request_id = payload.request_id.clone();
                let command: crate::mesh::raft::state_machine::RaftCommand =
                    match postcard::from_bytes(&payload.data) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("Failed to deserialize Raft command: {}", e);
                            return Ok(());
                        }
                    };

                if let Some(ref inst) = instance {
                    if !inst.is_leader().await {
                        let leader_hint = inst.get_leader_id().await.map(|id| id.to_string());
                        let response = crate::mesh::protocol::MeshMessage::NotLeader {
                            request_id: ArcStr::from(request_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                            leader_node_id: leader_hint.map(ArcStr::from),
                            current_term: None,
                        };
                        Some(
                            response.encode().map_err(|e| {
                                MeshTransportError::SendFailed(format!("{:?}", e))
                            })?,
                        )
                    } else {
                        match inst.client_write(command).await {
                            Ok(commit_index) => {
                                let response =
                                    crate::mesh::protocol::MeshMessage::ConsistentReadResponse {
                                        request_id: ArcStr::from(request_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                                        value: Some(commit_index.to_le_bytes().to_vec()),
                                        leader_node_id: Some(ArcStr::from(local_node_id.to_string())),
                                        timestamp: crate::utils::safe_unix_timestamp(),
                                    };
                                Some(
                                    response.encode().map_err(|e| {
                                        MeshTransportError::SendFailed(format!("{:?}", e))
                                    })?,
                                )
                            }
                            Err(e) => {
                                tracing::warn!("Raft client_write failed: {}", e);
                                None
                            }
                        }
                    }
                } else {
                    tracing::warn!("Received Raft message but no Raft instance available");
                    None
                }
            }
            crate::mesh::protocol::RaftMsgType::AppendEntries => {
                let _request_id = payload.request_id.clone();
                let rpc: openraft::raft::AppendEntriesRequest<crate::mesh::raft::state_machine::GlobalRegistryTypeConfig> =
                    match postcard::from_bytes(&payload.data) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("Failed to deserialize AppendEntries request: {}", e);
                            return Ok(());
                        }
                    };

                if let Some(ref inst) = instance {
                    match inst.raft_append_entries(rpc).await {
                        Ok(resp) => {
                            let encoded = postcard::to_stdvec(&resp).map_err(|e| {
                                MeshTransportError::SendFailed(format!("Serialize error: {}", e))
                            })?;
                            Some(encoded)
                        }
                        Err(e) => {
                            tracing::warn!("Raft append_entries failed: {}", e);
                            None
                        }
                    }
                } else {
                    tracing::warn!("Received AppendEntries but no Raft instance available");
                    None
                }
            }
            crate::mesh::protocol::RaftMsgType::VoteRequest => {
                let _request_id = payload.request_id.clone();
                let rpc: openraft::raft::VoteRequest<crate::mesh::raft::state_machine::GlobalRegistryTypeConfig> =
                    match postcard::from_bytes(&payload.data) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("Failed to deserialize VoteRequest: {}", e);
                            return Ok(());
                        }
                    };

                if let Some(ref inst) = instance {
                    match inst.raft_vote(rpc).await {
                        Ok(resp) => {
                            let encoded = postcard::to_stdvec(&resp).map_err(|e| {
                                MeshTransportError::SendFailed(format!("Serialize error: {}", e))
                            })?;
                            Some(encoded)
                        }
                        Err(e) => {
                            tracing::warn!("Raft vote failed: {}", e);
                            None
                        }
                    }
                } else {
                    tracing::warn!("Received VoteRequest but no Raft instance available");
                    None
                }
            }
            _ => {
                tracing::warn!("Unhandled Raft message type: {:?}", payload.msg_type);
                None
            }
        };

        if let Some(data) = response_data {
            let len = (data.len() as u32).to_be_bytes();
            send_stream
                .write_all(&len)
                .await
                .map_err(|e| MeshTransportError::SendFailed(format!("Write failed: {}", e)))?;
            send_stream
                .write_all(&data)
                .await
                .map_err(|e| MeshTransportError::SendFailed(format!("Write failed: {}", e)))?;
        }

        Ok(())
    }

    pub(crate) async fn perform_health_check(&self, peer_id: &str) -> Option<u32> {
        let start = Instant::now();

        if let Some(peer) = self.peer_connections.get(peer_id) {
            let result = async {
                let (mut send_stream, mut recv_stream) = {
                    let mut pool = peer.stream_pool.lock().await;
                    pool.acquire().await
                }
                .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

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

                {
                    let mut pool = peer.stream_pool.lock().await;
                    pool.release((send_stream, recv_stream));
                }

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

    async fn handle_http_proxy_stream(
        &self,
        header_str: &str,
        http_data: Vec<u8>,
        send_stream: &mut SendStream,
        topology: &MeshTopology,
        peer_node_id: String,
    ) -> Result<(), MeshTransportError> {
        let host = self.extract_host_from_http(&http_data);
        let upstream_id = match host {
            Some(h) => format!("http://{}", h),
            None => {
                return Err(MeshTransportError::ReceiveFailed(
                    "No Host header found in HTTP request".to_string(),
                ));
            }
        };

        let upstream_info = topology.get_upstream_info(&upstream_id).await;
        let backend_url = match upstream_info {
            Some(info) => info.upstream_url,
            None => {
                tracing::debug!("No local backend found for {}", upstream_id);
                let not_found = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(not_found)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        };

        if let Some(token) = header_str.strip_prefix("GET /.well-known/acme-challenge/") {
            let token = token.trim();
            if !token.is_empty() && !token.contains('\r') && !token.contains('\n') {
                if let Some(key_authz) = self.get_http01_challenge(token) {
                    tracing::debug!(
                        "ACME HTTP-01 challenge served from mesh for token {}",
                        token
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                        key_authz.len(),
                        key_authz
                    );
                    send_stream
                        .write_all(resp.as_bytes())
                        .await
                        .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                    let _ = send_stream.finish();
                    return Ok(());
                }
            }
        }

        if upstream_id.starts_with("serverless_function:") {
            return self
                .handle_serverless_proxy_stream(&upstream_id, &http_data, send_stream, peer_node_id)
                .await;
        }

        let parsed_url = match url::Url::parse(&backend_url) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("Failed to parse backend URL {}: {}", backend_url, e);
                let error_resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(error_resp)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        };

        let host_str = parsed_url.host_str().unwrap_or("127.0.0.1");
        let port = parsed_url.port().unwrap_or(80);

        if let Ok(ip) = host_str.parse::<std::net::IpAddr>() {
            if crate::proxy::headers::is_private_ip(&ip) {
                tracing::warn!(
                    "SSRF prevention: rejecting connection to private IP {} via mesh proxy",
                    ip
                );
                let forbidden = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(forbidden)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        } else {
            match tokio::net::lookup_host(format!("{}:{}", host_str, port)).await {
                Ok(ips) => {
                    for ip in ips {
                        let ip_addr = ip.ip();
                        if crate::proxy::headers::is_private_ip(&ip_addr) {
                            tracing::warn!(
                                "SSRF prevention: rejecting connection to private IP {} resolved from domain {} via mesh proxy",
                                ip_addr,
                                host_str
                            );
                            let forbidden = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                            send_stream
                                .write_all(forbidden)
                                .await
                                .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                            let _ = send_stream.finish();
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to resolve domain {} for SSRF check: {}",
                        host_str,
                        e
                    );
                }
            }
        }

        let addr = format!("{}:{}", host_str, port);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut backend_conn = match TcpStream::connect(&addr).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to connect to backend {}: {}", addr, e);
                let bad_gateway = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(bad_gateway)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        };

        backend_conn
            .write_all(&http_data)
            .await
            .map_err(|e| MeshTransportError::SendFailed(format!("Backend write failed: {}", e)))?;

        let mut full_response = Vec::new();
        let mut resp_buf = vec![0u8; 65536];
        loop {
            let n = backend_conn.read(&mut resp_buf).await.map_err(|e| {
                MeshTransportError::ReceiveFailed(format!("Backend read failed: {}", e))
            })?;
            if n == 0 {
                break;
            }
            full_response.extend_from_slice(&resp_buf[..n]);
        }

        let (transformed_response, did_transform) = match self
            .apply_response_transforms(&full_response, &upstream_id)
            .await
        {
            Ok((resp, transformed)) => (resp, transformed),
            Err(e) => {
                tracing::warn!("Transform error for {}: {}", upstream_id, e);
                (full_response, false)
            }
        };

        send_stream
            .write_all(&transformed_response)
            .await
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;

        if did_transform {
            tracing::debug!("Sent transformed response for {}", upstream_id);
        }

        let _ = send_stream.finish();

        Ok(())
    }

    fn extract_host_from_http(&self, http_data: &[u8]) -> Option<String> {
        let header_str = match String::from_utf8(http_data.to_vec()) {
            Ok(s) => s,
            Err(_) => return None,
        };

        for line in header_str.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("host:") {
                let host_part = line
                    .split(':')
                    .skip(1)
                    .collect::<String>()
                    .trim()
                    .to_string();
                return Some(host_part);
            }
        }
        None
    }

    fn extract_path_from_http(&self, http_data: &[u8]) -> String {
        let header_str = match String::from_utf8(http_data.to_vec()) {
            Ok(s) => s,
            Err(_) => return "/".to_string(),
        };

        for line in header_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("GET ")
                || trimmed.starts_with("POST ")
                || trimmed.starts_with("PUT ")
                || trimmed.starts_with("PATCH ")
                || trimmed.starts_with("DELETE ")
                || trimmed.starts_with("OPTIONS ")
                || trimmed.starts_with("HEAD ")
                || trimmed.starts_with("TRACE ")
                || trimmed.starts_with("CONNECT ")
            {
                if let Some(second_space) = trimmed.find(' ') {
                    if let Some(third_space) = trimmed[second_space + 1..].find(' ') {
                        return trimmed[second_space + 1..second_space + 1 + third_space]
                            .to_string();
                    }
                }
            }
        }
        "/".to_string()
    }

    fn extract_method_from_http(&self, http_data: &[u8]) -> Option<String> {
        let header_str = match String::from_utf8(http_data.to_vec()) {
            Ok(s) => s,
            Err(_) => return None,
        };

        for line in header_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("GET ")
                || trimmed.starts_with("POST ")
                || trimmed.starts_with("PUT ")
                || trimmed.starts_with("PATCH ")
                || trimmed.starts_with("DELETE ")
                || trimmed.starts_with("OPTIONS ")
                || trimmed.starts_with("HEAD ")
                || trimmed.starts_with("TRACE ")
                || trimmed.starts_with("CONNECT ")
            {
                if let Some(space) = trimmed.find(' ') {
                    return Some(trimmed[..space].to_string());
                }
            }
        }
        None
    }

    async fn apply_response_transforms(
        &self,
        response: &[u8],
        upstream_id: &str,
    ) -> Result<(Vec<u8>, bool), MeshTransportError> {
        let Some(record_store) = &self.record_store else {
            return Ok((response.to_vec(), false));
        };

        let response_str = match String::from_utf8(response.to_vec()) {
            Ok(s) => s,
            Err(_) => return Ok((response.to_vec(), false)),
        };

        let header_end_pos = response_str.find("\r\n\r\n").map(|p| p + 4);
        let Some(header_end) = header_end_pos else {
            return Ok((response.to_vec(), false));
        };

        let headers_section = &response_str[..header_end];
        let body_start = header_end;

        let content_type = self
            .extract_content_type_from_headers(headers_section)
            .unwrap_or_default();

        let transformable = content_type.contains("text/html")
            || content_type.contains("text/css")
            || content_type.contains("javascript")
            || content_type.contains("image/svg");

        if !transformable {
            return Ok((response.to_vec(), false));
        }

        let minification_key = format!("upstream_minification:{}", upstream_id);
        let min_config: Option<serde_json::Value> = record_store
            .get_record(&minification_key)
            .and_then(|r| serde_json::from_slice(&r.value).ok());

        let min_enabled = min_config
            .as_ref()
            .and_then(|c| c.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !min_enabled {
            return Ok((response.to_vec(), false));
        }

        let enable_html = min_config
            .as_ref()
            .and_then(|c| c.get("enable_html"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let enable_css = min_config
            .as_ref()
            .and_then(|c| c.get("enable_css"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let enable_js = min_config
            .as_ref()
            .and_then(|c| c.get("enable_js"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let body = &response[body_start..];
        let body_str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return Ok((response.to_vec(), false)),
        };

        let generator = crate::static_files::minifier::MinifierGenerator::new();
        let mut minified_body = body_str.to_string();

        if content_type.contains("text/html") && enable_html {
            if let Ok(minified) = generator.minify_html(body_str) {
                minified_body = minified;
            }
        } else if content_type.contains("text/css") && enable_css {
            if let Ok(minified) = generator.minify_css(body_str) {
                minified_body = minified;
            }
        } else if (content_type.contains("javascript") || content_type.contains("js")) && enable_js
        {
            if let Ok(minified) = generator.minify_js(body_str) {
                minified_body = minified;
            }
        }

        let new_body_len = minified_body.len();

        let mut new_headers = String::new();
        for line in headers_section.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("content-length:") {
                new_headers.push_str(&format!("Content-Length: {}\r\n", new_body_len));
            } else if !line_lower.starts_with("transfer-encoding:") {
                new_headers.push_str(line);
                new_headers.push_str("\r\n");
            }
        }
        new_headers.push_str("\r\n");

        let mut new_response = new_headers.into_bytes();
        new_response.extend_from_slice(minified_body.as_bytes());

        tracing::debug!(
            "Applied minification to {}: {} -> {} bytes",
            upstream_id,
            body.len(),
            new_body_len
        );

        Ok((new_response, true))
    }

    fn extract_content_type_from_headers(&self, headers: &str) -> Option<String> {
        for line in headers.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("content-type:") {
                return Some(
                    line.split(':')
                        .skip(1)
                        .collect::<String>()
                        .trim()
                        .to_string(),
                );
            }
        }
        None
    }

    async fn handle_serverless_proxy_stream(
        &self,
        upstream_id: &str,
        http_data: &[u8],
        send_stream: &mut SendStream,
        peer_node_id: String,
    ) -> Result<(), MeshTransportError> {
        let function_name = upstream_id
            .strip_prefix("serverless_function:")
            .unwrap_or(upstream_id);

        let serverless_manager_opt = {
            let sm_guard = self.serverless_manager.read();
            sm_guard.as_ref().cloned()
        };

        let Some(serverless_manager) = serverless_manager_opt else {
            tracing::warn!("Serverless proxy request but no serverless manager configured");
            let not_found = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            send_stream
                .write_all(not_found)
                .await
                .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
            let _ = send_stream.finish();
            return Ok(());
        };

        let peer_role = self
            .topology
            .get_peer(&peer_node_id)
            .await
            .map(|p| p.role)
            .unwrap_or(crate::mesh::config::MeshNodeRole::EDGE);

        let caller = crate::serverless::manager::CallerContext::mesh(peer_node_id, peer_role);

        let method = self.extract_method_from_http(http_data);
        let path = self.extract_path_from_http(http_data);

        let method = method.unwrap_or_else(|| "GET".to_string());

        let header_str = match String::from_utf8(http_data.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                let error_resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                send_stream
                    .write_all(error_resp)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
                return Ok(());
            }
        };

        let mut headers = http::HeaderMap::new();
        for line in header_str.lines() {
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                if let Ok(header_name) = name.parse::<http::header::HeaderName>() {
                    if let Ok(header_value) = value.parse::<http::header::HeaderValue>() {
                        headers.insert(header_name, header_value);
                    }
                }
            }
        }

        let body_offset = header_str
            .find("\r\n\r\n")
            .map(|p| p + 4)
            .unwrap_or(header_str.len());
        let body = if body_offset < http_data.len() {
            Some(bytes::Bytes::copy_from_slice(&http_data[body_offset..]))
        } else {
            None
        };

        match serverless_manager
            .invoke_for_mesh(function_name, &method, &path, &headers, body, caller)
            .await
        {
            Ok(response) => {
                let status_line = format!("HTTP/1.1 {} \r\n", response.status_code);
                let mut response_bytes = status_line.into_bytes();

                for (name, value) in response.headers.iter() {
                    response_bytes.extend_from_slice(name.as_str().as_bytes());
                    response_bytes.extend_from_slice(b": ");
                    response_bytes.extend_from_slice(value.as_bytes());
                    response_bytes.extend_from_slice(b"\r\n");
                }
                response_bytes.extend_from_slice(b"\r\n");
                response_bytes.extend_from_slice(&response.body);

                send_stream
                    .write_all(&response_bytes)
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();

                tracing::debug!(
                    "Serverless function '{}' responded with {} in {}ms",
                    function_name,
                    response.status_code,
                    response.execution_time_ms
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Serverless function '{}' invocation failed: {}",
                    function_name,
                    e
                );
                let error_body = format!("Serverless error: {}", e);
                let error_resp = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    error_body.len(),
                    error_body
                );
                send_stream
                    .write_all(error_resp.as_bytes())
                    .await
                    .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;
                let _ = send_stream.finish();
            }
        }

        Ok(())
    }
}
