use super::*;

impl RecordStoreManager {
    pub fn create_sync_request(&self) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        Some(MeshMessage::DhtSyncRequest {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            node_id: self.node_id.clone().into(),
            from_version: *self.local_version.read(),
        })
    }

    pub fn create_sync_response(&self, request_id: &str, from_version: u64) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let records = self.get_records_for_sync(from_version);

        let mut signature = Vec::new();
        let mut signer_public_key = String::new();
        
        let mesh_signer = self.mesh_signer.read();
        if let Some(ref signer) = *mesh_signer {
            let timestamp = MeshMessage::generate_timestamp();
            let content = format!(
                "{},{},{},{}",
                request_id,
                *self.local_version.read(),
                records.len(),
                timestamp
            );
            signature = signer.sign(&content);
            signer_public_key = signer.get_public_key();
        }

        Some(MeshMessage::DhtSyncResponse {
            request_id: request_id.into(),
            records,
            version: *self.local_version.read(),
            timestamp: MeshMessage::generate_timestamp(),
            signature,
            signer_public_key,
        })
    }

    pub fn create_snapshot_request(&self) -> Option<MeshMessage> {
        if !self.config.enabled || self.is_global_node() {
            return None;
        }

        Some(MeshMessage::DhtSnapshotRequest {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            node_id: self.node_id.clone().into(),
            from_version: *self.local_version.read(),
        })
    }

    pub fn create_snapshot_response(&self, request_id: &str, from_version: u64) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let records: Vec<DhtRecord> = self.get_all_records()
            .into_iter()
            .filter(|r| {
                let dht_key = DhtKey::from_str(&r.key);
                dht_key.is_public()
            })
            .collect();

        let mut signature = Vec::new();
        let mut signer_public_key = String::new();
        
        let mesh_signer = self.mesh_signer.read();
        if let Some(ref signer) = *mesh_signer {
            let timestamp = MeshMessage::generate_timestamp();
            let content = format!(
                "{},{},{},{}",
                request_id,
                *self.local_version.read(),
                records.len(),
                timestamp
            );
            signature = signer.sign(&content);
            signer_public_key = signer.get_public_key();
        }

        Some(MeshMessage::DhtSnapshotResponse {
            request_id: request_id.into(),
            records,
            version: *self.local_version.read(),
            timestamp: MeshMessage::generate_timestamp(),
            signature,
            signer_public_key,
        })
    }

    pub fn apply_snapshot(&self, records: Vec<DhtRecord>, version: u64, is_verified: bool) -> usize {
        if !self.config.enabled || self.is_global_node() {
            return 0;
        }

        let reputation = if is_verified { 100 } else { 0 };
        let mut applied = 0;
        for record in records {
            if self.store_record(record, reputation) {
                applied += 1;
            }
        }

        *self.last_snapshot_version.write() = version;
        self.record_successful_sync();
        
        self.compute_merkle_tree();

        tracing::info!("Applied DHT snapshot: {} records cached (version: {})", applied, version);
        applied
    }

    pub fn verify_and_apply_snapshot(
        &self,
        records: Vec<DhtRecord>,
        version: u64,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> usize {
        if !self.config.enabled || self.is_global_node() {
            return 0;
        }

        let record_signer = self.record_signer.read();
        let Some(ref verifier) = *record_signer else {
            tracing::warn!("No record signer configured, rejecting unsigned records");
            return 0;
        };

        let signer_public_key = signer.map(|s| s.get_public_key());
        let mut applied = 0;
        
        for record in records {
            let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
                key: record.key.clone(),
                value: record.value.clone(),
                publisher_id: record.source_node_id.clone(),
                signature: record.signature.clone(),
                created_at: record.timestamp,
                expires_at: Some(record.timestamp + record.ttl_seconds),
                record_type: crate::mesh::dht::signed::SignedRecordType::Organization,
                sequence_number: 0,
                source_node_id: record.source_node_id.clone(),
                ttl_seconds: record.ttl_seconds,
                signer_public_key: record.signer_public_key.clone(),
            };
            
            let verified = if signer_public_key.as_ref().map(|pk| !pk.is_empty()).unwrap_or(false) {
                if let Some(ref pk) = signer_public_key {
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    signer.as_ref()
                        .map(|s| s.verify(signed_record.get_signable_content().as_str(), &signed_record.signature, &pk_bytes))
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                verifier.verify(&signed_record)
            };
            
            if verified {
                if self.store_record(record, 100) {
                    applied += 1;
                }
            } else {
                let record_key = record.key.clone();
                tracing::warn!("Failed to verify record {} in snapshot", record_key);
            }
        }

        *self.last_snapshot_version.write() = version;
        self.record_successful_sync();
        
        self.compute_merkle_tree();

        tracing::info!("Verified and applied DHT snapshot: {} records (version: {})", applied, version);
        applied
    }

    pub fn should_resync(&self) -> bool {
        if !self.config.enabled || self.is_global_node() {
            return false;
        }

        let now = Instant::now();
        let last_sync = *self.last_sync.read();
        let current_interval = *self.current_sync_interval.read();
        now.duration_since(last_sync) > Duration::from_secs(current_interval)
    }

    pub fn record_successful_sync(&self) {
        if !self.config.enabled || self.is_global_node() {
            return;
        }

        *self.last_sync.write() = Instant::now();
        *self.initial_sync_completed.write() = true;

        let current = *self.current_sync_interval.read();
        let max_interval = self.config.max_sync_interval_secs;
        
        if current < max_interval {
            let new_interval = (current * 2).min(max_interval);
            *self.current_sync_interval.write() = new_interval;
            tracing::info!("DHT sync interval increased to {}s (max: {}s)", new_interval, max_interval);
        }
    }

    pub fn reset_sync_interval(&self) {
        if !self.config.enabled || self.is_global_node() {
            return;
        }

        let initial = self.config.initial_sync_interval_secs;
        *self.current_sync_interval.write() = initial;
        tracing::debug!("DHT sync interval reset to {}s", initial);
    }

    pub fn get_current_sync_interval(&self) -> u64 {
        *self.current_sync_interval.read()
    }

    pub fn get_last_snapshot_version(&self) -> u64 {
        *self.last_snapshot_version.read()
    }

    pub fn handle_record_announce(
        &self,
        records: Vec<DhtRecord>,
        from_node: &str,
        source_reputation: i64,
        _signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) {
        if !self.config.enabled {
            return;
        }

        let mut stored_count = 0;
        let mut skipped_count = 0;
        
        for record in records {
            if !self.verify_origin_permission(&record, from_node) {
                tracing::debug!(
                    "Rejected record announce from {}: not an origin for record key {}",
                    from_node,
                    record.key
                );
                skipped_count += 1;
                continue;
            }

            if self.is_global_node() || self.can_cache_on_edge(&record.key) {
                if self.store_record(record, source_reputation) {
                    stored_count += 1;
                }
            } else {
                skipped_count += 1;
            }
        }

        tracing::debug!(
            "Applied DHT record announce from {}: {} stored, {} skipped (edge node)",
            from_node,
            stored_count,
            skipped_count
        );
    }

    fn verify_origin_permission(&self, record: &DhtRecord, announcer: &str) -> bool {
        let dht_key = crate::mesh::dht::keys::DhtKey::from_str(&record.key);
        
        if let Some(record_type) = dht_key.to_signed_record_type() {
            if !record_type.requires_origin_node() {
                return true;
            }
        } else {
            return true;
        }

        if self.is_global_node() {
            return true;
        }

        let topology = self.topology.read();
        if let Some(ref topo) = *topology {
            let site_scope = dht_key.site_scope();
            if let Some(site) = site_scope {
                if let Some(origin_id) = topo.find_origin_by_site_sync(&site) {
                    return origin_id == announcer;
                }
            }
        }

        false
    }

    pub fn handle_record_query(
        &self,
        request_id: &str,
        key: &str,
        from_node: &str,
    ) -> Option<MeshMessage> {
        if !self.config.enabled {
            return None;
        }

        if let Some(ref stake_mgr) = *self.stake_manager.read() {
            if !stake_mgr.can_read_dht(from_node) {
                tracing::debug!(
                    "DHT query rejected: node {} has insufficient stake to read",
                    from_node
                );
                return None;
            }
        }

        let record = self.get_record(key);

        let mut signature = Vec::new();
        let mut signer_public_key = String::new();
        
        let mesh_signer = self.mesh_signer.read();
        if let Some(ref signer) = *mesh_signer {
            if let Some(ref rec) = record {
                let timestamp = MeshMessage::generate_timestamp();
                let content = format!(
                    "{},{},{},{},{}",
                    request_id,
                    key,
                    rec.timestamp,
                    self.node_id,
                    timestamp
                );
                signature = signer.sign(&content);
                signer_public_key = signer.get_public_key();
            }
        }

        Some(MeshMessage::DhtRecordResponse {
            request_id: request_id.into(),
            key: key.into(),
            value: record.as_ref().map(|r| r.value.clone()).unwrap_or_default(),
            found: record.is_some(),
            timestamp: MeshMessage::generate_timestamp(),
            source_node_id: self.node_id.clone().into(),
            signature,
            signer_public_key,
        })
    }

    pub fn handle_sync_request(
        &self,
        request_id: &str,
        _from_node: &str,
        from_version: u64,
    ) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        self.create_sync_response(request_id, from_version)
    }

    pub fn handle_sync_response(
        &self,
        records: Vec<DhtRecord>,
        _from_node: &str,
    ) {
        if !self.config.enabled || !self.is_global_node() {
            return;
        }

        self.apply_sync(records);
    }

    pub fn handle_sync_response_verified(
        &self,
        records: Vec<DhtRecord>,
        _from_node: &str,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) {
        if !self.config.enabled || !self.is_global_node() {
            return;
        }

        let record_signer = self.record_signer.read();
        let Some(ref verifier) = *record_signer else {
            tracing::warn!("No record signer configured, rejecting sync response");
            return;
        };

        let signer_public_key = signer.map(|s| s.get_public_key());
        let mut verified_records = Vec::new();
        
        for record in records {
            let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
                key: record.key.clone(),
                value: record.value.clone(),
                publisher_id: record.source_node_id.clone(),
                signature: record.signature.clone(),
                created_at: record.timestamp,
                expires_at: Some(record.timestamp + record.ttl_seconds),
                record_type: crate::mesh::dht::signed::SignedRecordType::Organization,
                sequence_number: 0,
                source_node_id: record.source_node_id.clone(),
                ttl_seconds: record.ttl_seconds,
                signer_public_key: record.signer_public_key.clone(),
            };
            
            let verified = if signer_public_key.as_ref().map(|pk| !pk.is_empty()).unwrap_or(false) {
                if let Some(ref pk) = signer_public_key {
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    signer.as_ref()
                        .map(|s| s.verify(signed_record.get_signable_content().as_str(), &signed_record.signature, &pk_bytes))
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                verifier.verify(&signed_record)
            };
            
            if verified {
                verified_records.push(record);
            } else {
                tracing::warn!("Failed to verify record {} in sync response", record.key);
            }
        }

        self.apply_sync(verified_records);
    }

    pub fn handle_anti_entropy_response_verified(
        &self,
        records: Vec<DhtRecord>,
        from_node: &str,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) {
        if !self.config.enabled || !self.is_global_node() {
            return;
        }

        let record_signer = self.record_signer.read();
        let Some(ref verifier) = *record_signer else {
            tracing::warn!("No record signer configured, rejecting anti-entropy response");
            return;
        };

        let signer_public_key = signer.map(|s| s.get_public_key());
        
        let mut accepted_count = 0;
        let mut rejected_count = 0;
        
        for record in records {
            if record.signature.is_empty() {
                tracing::debug!("Rejecting record {} from {}: no signature", record.key, from_node);
                rejected_count += 1;
                continue;
            }

            let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
                key: record.key.clone(),
                value: record.value.clone(),
                publisher_id: record.source_node_id.clone(),
                signature: record.signature.clone(),
                created_at: record.timestamp,
                expires_at: Some(record.timestamp + record.ttl_seconds),
                record_type: crate::mesh::dht::signed::SignedRecordType::Organization,
                sequence_number: 0,
                source_node_id: record.source_node_id.clone(),
                ttl_seconds: record.ttl_seconds,
                signer_public_key: record.signer_public_key.clone(),
            };
            
            let verified = if signer_public_key.as_ref().map(|pk| !pk.is_empty()).unwrap_or(false) {
                if let Some(ref pk) = signer_public_key {
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    signer.as_ref()
                        .map(|s| s.verify(signed_record.get_signable_content().as_str(), &signed_record.signature, &pk_bytes))
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                verifier.verify(&signed_record)
            };
            
            if !verified {
                tracing::debug!("Rejecting record {} from {}: invalid signature", record.key, from_node);
                rejected_count += 1;
                
                if let Some(ref stake_mgr) = *self.stake_manager.read() {
                    stake_mgr.submit_global_slash_vote(
                        record.source_node_id.clone(),
                        crate::mesh::dht::stake::SlashReason::InvalidRecordSignature,
                    );
                }
                continue;
            }
            
            let record_key = record.key.clone();
            
            if self.store_record(record, 100) {
                tracing::debug!("Stored record {} from {} (verified)", record_key, from_node);
                accepted_count += 1;
            }
        }
        
        if rejected_count > 0 {
            tracing::info!("Anti-entropy from {}: {} accepted, {} rejected", from_node, accepted_count, rejected_count);
        }

        self.compute_merkle_tree();
    }

    pub async fn broadcast_pending_records(&self) {
        if !self.config.enabled || !self.is_global_node() {
            return;
        }

        self.announce_records_via_kademlia().await;
    }

    async fn announce_records_via_kademlia(&self) {
        let Some(message) = self.create_record_announce() else {
            return;
        };

        let routing_manager = self.routing_manager.read().clone();
        let Some(rm) = routing_manager else {
            tracing::warn!("No routing manager available for Kademlia announce");
            return;
        };

        let transport_opt = self.transport.read().clone();
        let Some(transport) = transport_opt else {
            return;
        };

        let replication_factor = self.config.replication_factor;
        
        // Use None for target_geo - we're announcing from our location,
        // so we'll get our regional hubs first via the hybrid lookup
        let target_geo = None;
        
        let peers = rm.find_closest_peers_hybrid(&self.node_id, target_geo, replication_factor).await;
        
        if peers.is_empty() {
            tracing::debug!("No peers found for record announce");
            return;
        }

        let mut success_count = 0;
        let mut fail_count = 0;

        for peer in peers {
            if peer.node_id_string == self.node_id {
                continue;
            }

            if let Err(e) = transport.send_datagram_to_peer(&peer.node_id_string, &message).await {
                fail_count += 1;
                tracing::debug!("Failed to announce to peer {}: {}", peer.node_id_string, e);
            } else {
                success_count += 1;
            }
        }

        tracing::debug!("Kademlia DHT record announce: {} sent, {} failed", success_count, fail_count);
    }

    pub async fn query_record_iterative(&self, key: &str) -> Option<DhtRecord> {
        if !self.config.enabled {
            return None;
        }

        let local_record = self.get_record(key);
        if local_record.is_some() {
            return local_record;
        }

        let routing_manager = self.routing_manager.read().clone();
        let Some(rm) = routing_manager else {
            return None;
        };

        let transport_opt = self.transport.read().clone();
        let Some(transport) = transport_opt else {
            return None;
        };

        let dht_key = crate::mesh::dht::keys::DhtKey::from_str(key);
        
        if dht_key.is_privileged() && !rm.can_respond_to_privileged() {
            tracing::debug!("Query for privileged key {} requires global node", key);
            return None;
        }

        let target_geo = None;
        let closest_peers = rm.find_closest_peers_hybrid(key, target_geo, 8).await;
        
        if closest_peers.is_empty() {
            return None;
        }

        let mut queried_peers: Vec<String> = Vec::new();
        
        for peer in closest_peers {
            if peer.node_id_string == self.node_id {
                continue;
            }

            if queried_peers.contains(&peer.node_id_string) {
                continue;
            }
            queried_peers.push(peer.node_id_string.clone());

            let request_id = format!("query-{}-{}", key, uuid::Uuid::new_v4());
            let query = MeshMessage::DhtRecordQuery {
                request_id: request_id.into(),
                key: key.into(),
                timestamp: MeshMessage::generate_timestamp(),
                source_node_id: self.node_id.clone().into(),
            };

            if transport.send_datagram_to_peer(&peer.node_id_string, &query).await.is_ok() {
                tracing::debug!("Sent DHT record query for {} to peer {}", key, peer.node_id_string);
            }
        }

        None
    }

    pub async fn announce_record_to_closest(&self, record: &DhtRecord, replication_factor: usize) -> usize {
        if !self.config.enabled || !self.is_global_node() {
            return 0;
        }

        let routing_manager = self.routing_manager.read().clone();
        let Some(rm) = routing_manager else {
            return 0;
        };

        let transport_opt = self.transport.read().clone();
        let Some(transport) = transport_opt else {
            return 0;
        };

        let target_geo = None;
        let closest_peers = rm.find_closest_peers_hybrid(&record.key, target_geo, replication_factor).await;
        
        if closest_peers.is_empty() {
            return 0;
        }

        let request_id = format!("announce-{}-{}", record.key, uuid::Uuid::new_v4());
        
        let signer_public_key = {
            let mesh_signer = self.mesh_signer.read();
            mesh_signer.as_ref().map(|s| s.get_public_key()).unwrap_or_default()
        };
        
        let announce = MeshMessage::DhtRecordAnnounce {
            request_id: request_id.into(),
            records: vec![record.clone()],
            write_quorum: self.config.write_quorum,
            timestamp: MeshMessage::generate_timestamp(),
            source_node_id: self.node_id.clone().into(),
            signature: Vec::new(),
            signer_public_key,
        };

        let mut success_count = 0;
        
        for peer in closest_peers {
            if peer.node_id_string == self.node_id {
                continue;
            }

            if transport.send_datagram_to_peer(&peer.node_id_string, &announce).await.is_ok() {
                success_count += 1;
            }
        }

        let write_quorum = self.config.write_quorum as usize;
        if success_count >= write_quorum {
            counter!("maluwaf.dht.quorum.achieved", "type" => "write").increment(1);
            tracing::debug!("DHT write quorum achieved for {}: {}/{} peers", record.key, success_count, write_quorum);
        } else {
            counter!("maluwaf.dht.quorum.failed", "type" => "write").increment(1);
            tracing::debug!("DHT write quorum NOT achieved for {}: {}/{} peers", record.key, success_count, write_quorum);
        }
        
        tracing::debug!("Announced record {} to {} peers", record.key, success_count);
        success_count
    }

    pub fn init_propagation_state(&self, key: &str) {
        let mut states = self.propagation_states.write();
        if !states.contains_key(key) {
            states.insert(key.to_string(), PropagationState {
                key: key.to_string(),
                ack_count: 0,
                attempted_peers: Vec::new(),
                completed: false,
                last_update: Instant::now(),
            });
        }
    }

    pub fn record_propagation_attempt(&self, key: &str, peer_id: &str) {
        let mut states = self.propagation_states.write();
        if let Some(state) = states.get_mut(key) {
            if !state.attempted_peers.contains(&peer_id.to_string()) {
                state.attempted_peers.push(peer_id.to_string());
                state.last_update = Instant::now();
            }
        }
    }

    pub fn record_propagation_ack(&self, key: &str) -> bool {
        let mut states = self.propagation_states.write();
        if let Some(state) = states.get_mut(key) {
            state.ack_count += 1;
            state.last_update = Instant::now();
            
            if state.ack_count >= self.convergence_threshold {
                state.completed = true;
                tracing::debug!("DHT propagation converged for key {} after {} acks", key, state.ack_count);
                return true;
            }
        }
        false
    }

    pub fn is_propagation_complete(&self, key: &str) -> bool {
        let states = self.propagation_states.read();
        states.get(key).map(|s| s.completed).unwrap_or(false)
    }

    pub fn get_propagation_state(&self, key: &str) -> Option<PropagationState> {
        let states = self.propagation_states.read();
        states.get(key).cloned()
    }

    pub fn cleanup_stale_propagation_states(&self, max_age_secs: u64) {
        let mut states = self.propagation_states.write();
        let now = Instant::now();
        states.retain(|_, state| {
            now.duration_since(state.last_update).as_secs() < max_age_secs
        });
    }

    pub fn get_pending_propagations(&self) -> Vec<String> {
        let states = self.propagation_states.read();
        states
            .values()
            .filter(|s| !s.completed)
            .map(|s| s.key.clone())
            .collect()
    }
}
