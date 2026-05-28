use super::*;

const MAX_RECORDS_PER_ANNOUNCE: usize = 100;

impl RecordStoreManager {
    async fn get_sender_reputation(
        &self,
        from_node: &str,
        _signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> i64 {
        let topology_opt = {
            let routing = self.routing_state.read();
            routing.topology.clone()
        };

        if let Some(ref topology) = topology_opt {
            if let Some(peer) = topology.get_peer(from_node).await {
                let reputation = peer.audit_reputation();
                return (reputation * 100.0) as i64;
            }
        }

        let stake_opt = {
            let routing = self.routing_state.read();
            routing.stake_manager.clone()
        };

        if let Some(ref stake_mgr) = stake_opt {
            let stake = stake_mgr.get_stake_weight(from_node);
            return (stake * 100.0) as i64;
        }

        50
    }

    pub async fn handle_mesh_message(
        &self,
        message: &MeshMessage,
        from_node: &str,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> Option<MeshMessage> {
        let timestamp = match message {
            MeshMessage::DhtRecordAnnounce { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtRecordQuery { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtRecordResponse { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtSyncResponse { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtAntiEntropyRequest { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtAntiEntropyResponse { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtRecordPush { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtRecordPushAck { timestamp, .. } => Some(*timestamp),
            _ => None,
        };

        if let Some(ts) = timestamp {
            if !validate_message_timestamp(ts) {
                tracing::warn!(
                    "DHT message rejected: timestamp {} outside acceptable window",
                    ts
                );
                return None;
            }
        }

        if self.is_rate_limited(from_node) {
            tracing::warn!("DHT message rejected: rate limited peer {}", from_node);
            return None;
        }

        match message {
            MeshMessage::DhtRecordAnnounce {
                request_id: _,
                records,
                write_quorum: _,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => {
                tracing::debug!(
                    "Received DhtRecordAnnounce from {} with {} records",
                    from_node,
                    records.len()
                );

                if records.len() > MAX_RECORDS_PER_ANNOUNCE {
                    tracing::warn!(
                        "DhtRecordAnnounce rejected from {}: {} records exceeds limit of {}",
                        from_node,
                        records.len(),
                        MAX_RECORDS_PER_ANNOUNCE
                    );
                    return None;
                }

                if let Some(signer) = signer {
                    if !signature.is_empty() {
                        let content = format!(
                            "{},{},{},{}",
                            source_node_id,
                            records.len(),
                            self.node_role.bits(),
                            timestamp
                        );
                        let pk_bytes = if signer_public_key.as_ref().map_or(true, |s| s.is_empty())
                        {
                            Vec::new()
                        } else {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(signer_public_key.as_ref().unwrap())
                                .unwrap_or_default()
                        };
                        if !signer
                            .verify_auto_async(content.as_bytes(), signature, &pk_bytes)
                            .await
                        {
                            tracing::warn!(
                                "DhtRecordAnnounce signature verification failed from {}",
                                from_node
                            );
                            return None;
                        }
                    }
                }

                let reputation = self.get_sender_reputation(from_node, signer).await;
                self.handle_record_announce(records.clone(), from_node, reputation, signer);
                None
            }
            MeshMessage::DhtRecordQuery {
                request_id,
                key,
                timestamp: _,
                source_node_id: _,
            } => {
                tracing::debug!(
                    "Received DhtRecordQuery from {} for key: {}",
                    from_node,
                    key
                );
                self.handle_record_query(request_id, key, from_node)
            }
            MeshMessage::DhtRecordResponse {
                request_id: _,
                key: _,
                value: _,
                found: _,
                timestamp: _,
                source_node_id: _,
                signature: _,
                signer_public_key: _,
            } => {
                tracing::debug!("Received DhtRecordResponse from {}", from_node);
                None
            }
            MeshMessage::DhtSyncRequest {
                request_id,
                node_id: _,
                from_version,
            } => {
                tracing::debug!(
                    "Received DhtSyncRequest from {} (version: {})",
                    from_node,
                    from_version
                );
                self.handle_sync_request(request_id, from_node, *from_version)
            }
            MeshMessage::DhtSyncResponse {
                request_id: _,
                records,
                version: _,
                timestamp: _,
                signature: _,
                signer_public_key: _,
            } => {
                tracing::debug!(
                    "Received DhtSyncResponse from {} with {} records",
                    from_node,
                    records.len()
                );
                self.handle_sync_response(records.clone(), from_node);
                None
            }
            MeshMessage::DhtAntiEntropyRequest {
                request_id,
                node_id,
                local_root_hash,
                interested_keys,
                timestamp: _,
                ..
            } => {
                tracing::debug!(
                    "Received DhtAntiEntropyRequest from {} for {} keys",
                    from_node,
                    interested_keys.len()
                );
                self.handle_anti_entropy_request(
                    request_id,
                    local_root_hash,
                    interested_keys,
                    from_node,
                )
            }
            MeshMessage::DhtAntiEntropyResponse {
                request_id: _,
                root_hash: _,
                proof_keys: _,
                proof_hashes: _,
                missing_records,
                timestamp: _,
                signature: _,
                signer_public_key: _,
            } => {
                tracing::debug!(
                    "Received DhtAntiEntropyResponse from {} with {} records",
                    from_node,
                    missing_records.len()
                );
                std::mem::drop(self.handle_anti_entropy_response(message, from_node));
                None
            }
            MeshMessage::DhtRecordPush {
                request_id,
                records,
                hop_count,
                seen_node_ids,
                timestamp: _,
                signer_public_key: _,
            } => {
                tracing::debug!(
                    "Received DhtRecordPush from {} with {} records, hop {}",
                    from_node,
                    records.len(),
                    hop_count
                );

                if seen_node_ids.contains(&self.node_id) {
                    tracing::debug!("DhtRecordPush already seen, skipping");
                    return None;
                }

                let reputation = self.get_sender_reputation(from_node, signer).await;

                let ingress_ctx = crate::mesh::dht::signed::DhtRecordIngressContext::new_remote(
                    from_node.to_string(),
                    from_node.to_string(),
                    crate::mesh::dht::signed::SourceClassification::Unknown,
                    crate::mesh::dht::signed::IngressPath::Push,
                );

                for record in records {
                    self.store_record_from_ingress(record.clone(), &ingress_ctx, reputation);
                    self.init_propagation_state(&record.key);
                }
                self.compute_merkle_tree();

                if *hop_count < 5 {
                    let new_seen_ids: Vec<String> = seen_node_ids
                        .iter()
                        .chain(std::iter::once(&self.node_id))
                        .cloned()
                        .collect();

                    let ack = MeshMessage::DhtRecordPushAck {
                        request_id: format!("{}-ack", request_id).into(),
                        original_request_id: request_id.clone(),
                        node_id: self.node_id.clone().into(),
                        accepted: true,
                        missing_keys: Vec::new(),
                        timestamp: MeshMessage::generate_timestamp(),
                    };

                    Some(ack)
                } else {
                    None
                }
            }
            MeshMessage::DhtRecordPushAck {
                request_id: _,
                original_request_id,
                node_id,
                accepted,
                missing_keys: _,
                timestamp: _,
            } => {
                tracing::debug!(
                    "Received DhtRecordPushAck from {} for {}: accepted={}",
                    node_id,
                    original_request_id,
                    accepted
                );

                if *accepted {
                    self.record_propagation_ack(original_request_id);
                }
                None
            }
            _ => None,
        }
    }

    pub fn compute_merkle_tree(&self) {
        let tree = {
            let rs = self.record_state.read();
            let mut record_map = HashMap::new();
            for (key, entry) in rs.records.iter() {
                record_map.insert(key.clone(), entry.record.value.clone());
            }
            MerkleTree::from_records(&record_map)
        };

        let mut rs = self.record_state.write();
        rs.merkle_tree = Some(tree);
    }

    pub fn update_merkle_incremental(&self, key: &str, value: &[u8]) {
        let mut rs = self.record_state.write();
        match rs.merkle_tree.as_mut() {
            Some(tree) => {
                tree.insert_or_update(key.to_string(), value);
            }
            None => {
                let mut record_map = HashMap::new();
                for (k, entry) in rs.records.iter() {
                    record_map.insert(k.clone(), entry.record.value.clone());
                }
                record_map.insert(key.to_string(), value.to_vec());
                rs.merkle_tree = Some(MerkleTree::from_records(&record_map));
            }
        }
    }

    pub fn remove_merkle_key(&self, key: &str) {
        let mut rs = self.record_state.write();
        if let Some(tree) = rs.merkle_tree.as_mut() {
            tree.remove_key(key);
        }
    }

    pub fn get_merkle_root_hash(&self) -> Option<Vec<u8>> {
        let rs = self.record_state.read();
        rs.merkle_tree.as_ref().and_then(|t| t.root_hash())
    }

    pub fn generate_merkle_proof(
        &self,
        keys: &[String],
    ) -> Option<crate::mesh::dht::merkle::MerkleProof> {
        let rs = self.record_state.read();
        rs.merkle_tree.as_ref().and_then(|t| t.generate_proof(keys))
    }

    pub fn get_records_for_keys(&self, keys: &[String]) -> Vec<DhtRecord> {
        let rs = self.record_state.read();
        keys.iter()
            .filter_map(|k| rs.records.get(k).map(|e| e.record.clone()))
            .collect()
    }

    pub fn handle_anti_entropy_request(
        &self,
        request_id: &str,
        local_root_hash: &[u8],
        interested_keys: &[String],
        from_node: &str,
    ) -> Option<MeshMessage> {
        if !self.config.enabled {
            return None;
        }

        let my_root_hash = self.get_merkle_root_hash();

        if my_root_hash.as_deref() == Some(local_root_hash) {
            tracing::debug!(
                "DHT anti-entropy: {} has same root hash as {}",
                from_node,
                self.node_id
            );
            return Some(MeshMessage::DhtAntiEntropyResponse {
                request_id: request_id.into(),
                root_hash: local_root_hash.to_vec(),
                proof_keys: interested_keys.to_vec(),
                proof_hashes: Vec::new(),
                missing_records: Vec::new(),
                timestamp: MeshMessage::generate_timestamp(),
                signature: Vec::new(),
                signer_public_key: None,
            });
        }

        let (records, proof) = {
            let rs = self.record_state.read();
            let recs = self.get_records_for_keys(interested_keys);
            let proof = rs
                .merkle_tree
                .as_ref()
                .and_then(|t| t.generate_proof(interested_keys));
            (recs, proof)
        };

        let proof_keys: Vec<String> = proof
            .as_ref()
            .map(|p| p.queried_keys.clone())
            .unwrap_or_default();
        let proof_hashes: Vec<Vec<u8>> = proof
            .as_ref()
            .map(|p| p.proof_nodes.iter().map(|n| n.hash.clone()).collect())
            .unwrap_or_default();

        let mut signature = Vec::new();
        let mut signer_public_key = None;
        let timestamp = MeshMessage::generate_timestamp();
        let root_hash_value = my_root_hash.unwrap_or_default();

        {
            let rs = self.record_state.read();
            if let Some(ref signer) = rs.mesh_signer {
                let record_set_digest =
                    crate::mesh::dht::signed::compute_record_set_digest(&records);
                let content = crate::mesh::dht::signed::get_anti_entropy_response_signable_content(
                    request_id,
                    &self.node_id,
                    &root_hash_value,
                    records.len(),
                    timestamp,
                    &record_set_digest,
                );
                signature = signer.sign(&content);
                signer_public_key = Some(signer.get_public_key());
            }
        }

        tracing::debug!(
            "DHT anti-entropy: responding to {} with {} records (hash mismatch)",
            from_node,
            records.len()
        );

        Some(MeshMessage::DhtAntiEntropyResponse {
            request_id: request_id.into(),
            root_hash: root_hash_value,
            proof_keys,
            proof_hashes,
            missing_records: records,
            timestamp,
            signature,
            signer_public_key,
        })
    }

    pub async fn handle_anti_entropy_response(&self, response: &MeshMessage, from_node: &str) {
        if !self.config.enabled {
            return;
        }

        let MeshMessage::DhtAntiEntropyResponse {
            request_id: _,
            root_hash: _,
            proof_keys: _,
            proof_hashes: _,
            missing_records,
            timestamp: _,
            signature: _,
            signer_public_key: _,
        } = response
        else {
            return;
        };

        if missing_records.is_empty() {
            tracing::debug!("DHT anti-entropy: no missing records from {}", from_node);
            return;
        }

        let mut stored_count = 0;
        let reputation = self.get_sender_reputation(from_node, None).await;

        let ingress_ctx = crate::mesh::dht::signed::DhtRecordIngressContext::new_remote(
            from_node.to_string(),
            from_node.to_string(),
            crate::mesh::dht::signed::SourceClassification::Unknown,
            crate::mesh::dht::signed::IngressPath::AntiEntropy,
        );

        for record in missing_records {
            if self.store_record_from_ingress(record.clone(), &ingress_ctx, reputation) {
                stored_count += 1;
            }
        }

        self.compute_merkle_tree();

        tracing::info!(
            "DHT anti-entropy: stored {} records from {}",
            stored_count,
            from_node
        );
    }

    pub fn start_background_tasks(&self) {
        let self_arc = Arc::new(self.clone());
        self_arc.start_recovery_worker();

        let config = self.config.clone();
        let node_id = self.node_id.clone();
        let node_role = self.node_role;
        let initial_interval = self.config.initial_sync_interval_secs;
        let replication_factor = self.config.replication_factor;
        let self_arc = Arc::new(self.clone());
        let merkle_self = Arc::downgrade(&self_arc);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            let mut last_sync = Instant::now();

            loop {
                interval.tick().await;

                if !config.enabled || !node_role.is_global() {
                    continue;
                }

                if let Some(record_store) = merkle_self.upgrade() {
                    record_store.cleanup_expired();
                }

                if last_sync.elapsed().as_secs() > initial_interval {
                    tracing::debug!("DHT sync interval reached");
                    last_sync = Instant::now();

                    if let Some(record_store) = merkle_self.upgrade() {
                        let _ =
                            Self::run_anti_entropy_cycle(&record_store, replication_factor).await;
                    }
                }
            }
        });

        let integrity_self = Arc::downgrade(&Arc::new(self.clone()));
        let integrity_config = self.config.clone();
        let integrity_role = self.node_role;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));

            loop {
                interval.tick().await;

                if !integrity_config.enabled || !integrity_role.is_global() {
                    continue;
                }

                if let Some(record_store) = integrity_self.upgrade() {
                    let old_root = record_store.get_merkle_root_hash();
                    record_store.compute_merkle_tree();
                    let new_root = record_store.get_merkle_root_hash();
                    if old_root != new_root {
                        tracing::warn!(
                            "Merkle Integrity Worker: root hash drift detected, rebuilt tree"
                        );
                    } else {
                        tracing::debug!("Merkle Integrity Worker: tree verified, no drift");
                    }
                }
            }
        });
    }

    pub async fn rebalance_after_departure(&self, departed_node_id: &str) {
        if !self.config.enabled || !self.node_role.is_global() {
            return;
        }

        let routing_manager = self.routing_state.read().routing_manager.clone();
        let Some(rm) = routing_manager else {
            return;
        };

        let transport_opt = self.routing_state.read().transport.clone();
        let Some(transport) = transport_opt else {
            return;
        };

        let replication_factor = self.config.replication_factor;
        let write_quorum = self.config.write_quorum as usize;

        let records_to_rebalance: Vec<(String, DhtRecord)> = {
            let rs = self.record_state.read();
            rs.records
                .iter()
                .into_iter()
                .filter(|(_, entry)| entry.local_origin)
                .map(|(k, v)| (k.clone(), v.record.clone()))
                .collect()
        };

        if records_to_rebalance.is_empty() {
            tracing::debug!(
                "No local records to rebalance after departure of {}",
                departed_node_id
            );
            return;
        }

        tracing::info!(
            "DHT rebalance triggered after departure of {}: re-announcing {} records",
            departed_node_id,
            records_to_rebalance.len()
        );

        let signer_public_key = {
            let rs = self.record_state.read();
            rs.mesh_signer.as_ref().map(|s| s.get_public_key())
        };

        for (key, record) in records_to_rebalance {
            let target_geo = None;
            let closest_peers = rm
                .find_closest_peers_hybrid(&key, target_geo, replication_factor)
                .await;

            if closest_peers.is_empty() {
                tracing::warn!("DHT rebalance: no peers found for key {}", &key);
                continue;
            }

            let request_id = format!("rebalance-{}-{}", &key, uuid::Uuid::new_v4());
            let announce = MeshMessage::DhtRecordAnnounce {
                request_id: request_id.into(),
                records: vec![record.clone()],
                write_quorum: self.config.write_quorum,
                timestamp: MeshMessage::generate_timestamp(),
                source_node_id: self.node_id.clone().into(),
                signature: Vec::new(),
                signer_public_key: signer_public_key.clone(),
            };

            let mut success_count = 0;
            for peer in closest_peers {
                if peer.node_id_string == self.node_id {
                    continue;
                }

                if transport
                    .send_datagram_to_peer(&peer.node_id_string, &announce)
                    .await
                    .is_ok()
                {
                    success_count += 1;
                    crate::metrics::record_dht_announce_sent();
                } else {
                    crate::metrics::record_dht_announce_failed();
                }
            }

            if success_count < write_quorum {
                tracing::warn!(
                    "DHT rebalance: write quorum not met for {} ({}/{})",
                    &key,
                    success_count,
                    write_quorum
                );
            }
        }
    }

    async fn run_anti_entropy_cycle(
        record_store: &Arc<RecordStoreManager>,
        replication_factor: usize,
    ) {
        let transport = match record_store.routing_state.read().transport.clone() {
            Some(t) => t,
            None => return,
        };

        let topology = transport.get_topology();
        let peers = topology.get_global_nodes_as_peer_info().await;

        if peers.is_empty() {
            return;
        }

        let my_root_hash = match record_store.get_merkle_root_hash() {
            Some(h) => h,
            None => return,
        };

        let node_id = record_store.node_id.clone();

        let peer_count = peers.len().min(replication_factor);
        let selected_peers: Vec<_> = peers.into_iter().take(peer_count).collect();

        let signer_public_key = {
            let rs = record_store.record_state.read();
            rs.mesh_signer.as_ref().map(|s| s.get_public_key())
        };

        let transport_clone = transport.clone();

        let anti_entropy_futures: Vec<_> = selected_peers
            .iter()
            .map(|peer| {
                let request_id = MeshMessage::generate_nonce().to_string();

                let interested_keys: Vec<String> = {
                    let rs = record_store.record_state.read();
                    let mut entries: Vec<_> = rs
                        .records
                        .iter()
                        .into_iter()
                        .map(|(k, v)| (k, v.version))
                        .collect();
                    entries.sort_by(|a, b| b.1.cmp(&a.1));
                    entries.into_iter().take(100).map(|(k, _)| k).collect()
                };

                let request = MeshMessage::DhtAntiEntropyRequest {
                    request_id: request_id.into(),
                    node_id: node_id.clone().into(),
                    local_root_hash: my_root_hash.clone(),
                    interested_keys,
                    timestamp: MeshMessage::generate_timestamp(),
                    signer_public_key: signer_public_key.clone(),
                };

                let transport = transport_clone.clone();
                async move {
                    if let Err(e) = transport
                        .send_datagram_to_peer(&peer.node_id, &request)
                        .await
                    {
                        tracing::debug!(
                            "DHT anti-entropy request to {} failed: {}",
                            peer.node_id,
                            e
                        );
                    } else {
                        tracing::debug!("DHT anti-entropy request sent to {}", peer.node_id);
                    }
                }
            })
            .collect();

        futures::future::join_all(anti_entropy_futures).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_record_status_default_is_live() {
        let status = crate::mesh::protocol::DhtRecordStatus::default();
        assert_eq!(status, crate::mesh::protocol::DhtRecordStatus::Live);
    }

    #[test]
    fn test_dht_record_status_round_trip_is_live() {
        let status = crate::mesh::protocol::DhtRecordStatus::from_u8(1);
        assert_eq!(status, crate::mesh::protocol::DhtRecordStatus::Live);
    }

    #[test]
    fn test_quorum_signature_proto_from_quorum_signature() {
        let sig = crate::mesh::dht::quorum::QuorumSignature {
            node_id: "node1".to_string(),
            signature: vec![1, 2, 3],
            timestamp: 12345,
            signer_public_key: Some("test_pk".to_string()),
        };
        let proto: crate::mesh::protocol::QuorumSignatureProto = (&sig).into();
        assert_eq!(proto.node_id, "node1");
        assert_eq!(proto.signature, vec![1, 2, 3]);
        assert_eq!(proto.timestamp, 12345);
        assert_eq!(proto.signer_public_key, Some("test_pk".to_string()));
    }
}
