#![allow(dead_code)] // Reserved for future DHT protocol handling

use crate::mesh::transport::MeshTransport;

impl MeshTransport {
    pub(crate) async fn handle_dht_snapshot_request(
        &self,
        from_peer: &str,
        request_id: &str,
        _node_id: &str,
        from_version: u64,
    ) {
        tracing::debug!(
            "Received DHT snapshot request from {} (from_version: {})",
            from_peer,
            from_version
        );

        if let Some(ref record_store) = self.record_store {
            if let Some(response) = record_store.create_snapshot_response(request_id, from_version)
            {
                if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                    tracing::warn!(
                        "Failed to send DHT snapshot response to {}: {}",
                        from_peer,
                        e
                    );
                } else {
                    tracing::debug!("Sent DHT snapshot response to {}", from_peer);
                }
            }
        } else {
            tracing::debug!("No record store available for DHT snapshot");
        }
    }

    pub(crate) async fn handle_dht_snapshot_response(
        &self,
        from_peer: &str,
        _request_id: &str,
        records: Vec<crate::mesh::protocol::DhtRecord>,
        version: u64,
    ) {
        tracing::debug!(
            "Received DHT snapshot response from {} ({} records, version: {})",
            from_peer,
            records.len(),
            version
        );

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            let applied = record_store.verify_and_apply_snapshot(records, version, signer);
            tracing::info!(
                "Applied {} records from DHT snapshot (version: {})",
                applied,
                version
            );
        }
    }

    pub(crate) async fn handle_dht_record_announce(
        &self,
        from_peer: &str,
        source_node_id: &str,
        records: Vec<crate::mesh::protocol::DhtRecord>,
    ) {
        tracing::debug!(
            "Received DHT record announce from {} ({} records)",
            from_peer,
            records.len()
        );

        let rep_score = self
            .topology
            .get_peer_audit_reputation(from_peer)
            .await
            .map(|rep| (rep * 100.0) as i64)
            .unwrap_or(0);

        let min_reputation = self.get_effective_write_threshold(from_peer).await;

        if min_reputation > 0 && rep_score < min_reputation {
            tracing::debug!(
                "Rejecting DHT record announce from {}: reputation {} below threshold {}",
                from_peer,
                rep_score,
                min_reputation
            );
            return;
        }

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            record_store.handle_record_announce(records, source_node_id, rep_score, signer);
        }
    }

    pub(crate) async fn handle_dht_sync_request(
        &self,
        from_peer: &str,
        request_id: &str,
        node_id: &str,
        from_version: u64,
    ) {
        tracing::debug!(
            "Received DHT sync request from {} (node: {}, from_version: {})",
            from_peer,
            node_id,
            from_version
        );

        if let Some(ref record_store) = self.record_store {
            if let Some(response) = record_store.create_sync_response(request_id, from_version) {
                if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                    tracing::warn!("Failed to send DHT sync response: {}", e);
                }
            }
        }
    }

    pub(crate) async fn handle_dht_sync_response(
        &self,
        from_peer: &str,
        records: Vec<crate::mesh::protocol::DhtRecord>,
    ) {
        tracing::debug!(
            "Received DHT sync response from {} ({} records)",
            from_peer,
            records.len()
        );

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            record_store.handle_sync_response_verified(records, from_peer, signer);
        }
    }

    pub(crate) async fn handle_dht_anti_entropy_request(
        &self,
        from_peer: &str,
        request_id: &str,
        _node_id: &str,
        local_root_hash: &[u8],
        interested_keys: &[String],
        _timestamp: u64,
    ) {
        tracing::debug!(
            "Received DHT anti-entropy request from {} ({} interested keys)",
            from_peer,
            interested_keys.len()
        );

        if let Some(ref record_store) = self.record_store {
            if let Some(response) = record_store.handle_anti_entropy_request(
                request_id,
                local_root_hash,
                interested_keys,
                from_peer,
            ) {
                if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                    tracing::warn!(
                        "Failed to send DHT anti-entropy response to {}: {}",
                        from_peer,
                        e
                    );
                }
            }
        }
    }

    pub(crate) async fn get_effective_read_threshold(&self, _peer_id: &str) -> i64 {
        if let Some(override_val) = self
            .config
            .dht
            .as_ref()
            .and_then(|d| d.manual_threshold_override)
        {
            return override_val;
        }

        if let Some(ref record_store) = self.record_store {
            if let Some(policy) = record_store.get_network_policy() {
                let max = self
                    .config
                    .dht
                    .as_ref()
                    .map(|d| d.max_reputation_threshold)
                    .unwrap_or(80);
                return policy.min_reputation_for_read.clamp(0, max);
            }
        }

        self.config
            .dht
            .as_ref()
            .map(|d| d.min_reputation_for_dht_read)
            .unwrap_or(10)
    }

    pub(crate) async fn get_effective_write_threshold(&self, _peer_id: &str) -> i64 {
        if let Some(override_val) = self
            .config
            .dht
            .as_ref()
            .and_then(|d| d.manual_threshold_override)
        {
            return override_val;
        }

        if let Some(ref record_store) = self.record_store {
            if let Some(policy) = record_store.get_network_policy() {
                let max = self
                    .config
                    .dht
                    .as_ref()
                    .map(|d| d.max_reputation_threshold)
                    .unwrap_or(80);
                return policy.min_reputation_for_write.clamp(0, max);
            }
        }

        self.config
            .dht
            .as_ref()
            .map(|d| d.min_reputation_for_dht_write)
            .unwrap_or(30)
    }

    pub(crate) async fn handle_dht_anti_entropy_response(
        &self,
        from_peer: &str,
        missing_records: Vec<crate::mesh::protocol::DhtRecord>,
        _timestamp: u64,
        signature: &[u8],
    ) {
        tracing::debug!(
            "Received DHT anti-entropy response from {} ({} missing records)",
            from_peer,
            missing_records.len()
        );

        if missing_records.is_empty() {
            return;
        }

        if !signature.is_empty() {
            tracing::debug!("DHT anti-entropy response from {} has signature", from_peer);
        }

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            record_store.handle_anti_entropy_response_verified(missing_records, from_peer, signer);
            record_store.compute_merkle_tree();
        }
    }

    pub(crate) async fn handle_find_node(
        &self,
        from_peer: &str,
        request_id: &str,
        target_node_id: Vec<u8>,
        _requester_node_id: &str,
    ) {
        tracing::debug!(
            "Received FindNode from {} for target of length {}",
            from_peer,
            target_node_id.len()
        );

        let min_reputation = self.get_effective_read_threshold(from_peer).await;

        if min_reputation > 0 {
            if let Some(rep) = self.topology.get_peer_audit_reputation(from_peer).await {
                let rep_score = (rep * 100.0) as i64;
                if rep_score < min_reputation {
                    tracing::debug!(
                        "Rejecting FindNode from {}: reputation {} below threshold {}",
                        from_peer,
                        rep_score,
                        min_reputation
                    );
                    return;
                }
            } else {
                tracing::debug!(
                    "Rejecting FindNode from {}: unknown peer (no reputation)",
                    from_peer
                );
                return;
            }
        }

        let Some(ref routing_manager) = self.routing_manager else {
            tracing::trace!("FindNode received but routing not enabled");
            return;
        };

        let target_id = match crate::mesh::dht::routing::NodeId::from_bytes(&target_node_id) {
            Some(id) => id,
            None => {
                tracing::warn!("Invalid target_node_id in FindNode from {}", from_peer);
                return;
            }
        };

        let closest_peers = routing_manager
            .find_closest_to_node_id(&target_id, 20)
            .await;

        let response = crate::mesh::protocol::MeshMessage::FindNodeResponse {
            request_id: request_id.into(),
            peers: closest_peers,
            responder_node_id: self.config.node_id().into(),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send FindNodeResponse to {}: {}", from_peer, e);
        }
    }

    pub(crate) async fn handle_find_node_response(
        &self,
        from_peer: &str,
        peers: Vec<crate::mesh::dht::routing::PeerContact>,
    ) {
        tracing::debug!(
            "Received FindNodeResponse from {} with {} peers",
            from_peer,
            peers.len()
        );

        let Some(ref routing_manager) = self.routing_manager else {
            return;
        };

        for peer in peers {
            if peer.node_id_string == self.config.node_id() {
                continue;
            }

            routing_manager
                .add_peer(
                    peer.node_id_string.clone(),
                    peer.address,
                    peer.port,
                    if peer.is_global {
                        crate::mesh::config::MeshNodeRole::GLOBAL
                    } else {
                        crate::mesh::config::MeshNodeRole::EDGE
                    },
                    peer.latency_ms,
                    peer.is_trusted,
                    peer.geo,
                    peer.pow_nonce,
                    peer.public_key,
                )
                .await;
        }
    }

    pub(crate) async fn dht_cache_resync(&self) {
        if self.topology.is_global() {
            return;
        }

        if let Some(ref record_store) = self.record_store {
            if !record_store.should_resync() {
                return;
            }

            // Get connected global nodes
            let global_nodes: Vec<String> = self
                .peer_connections
                .iter()
                .filter(|e| e.value().role.is_global())
                .map(|e| e.key().clone())
                .collect();

            if global_nodes.is_empty() {
                tracing::debug!("No global nodes connected for DHT resync");
                return;
            }

            if let Some(request) = record_store.create_snapshot_request() {
                let peer_id = &global_nodes[0];
                tracing::info!("DHT cache stale, requesting resync from {}", peer_id);

                if let Err(e) = self.send_datagram_to_peer(peer_id, &request).await {
                    tracing::warn!("Failed to request DHT resync from {}: {}", peer_id, e);
                }
            }
        }
    }
}
