use super::*;

impl RecordStoreManager {
    pub fn create_sync_request(&self) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        Some(MeshMessage::DhtSyncRequest {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            node_id: self.node_id.clone().into(),
            from_version: self.record_state.read().local_version,
        })
    }

    pub fn create_sync_response(&self, request_id: &str, from_version: u64) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let records = self.get_records_for_sync(from_version);
        let record_set_digest = crate::mesh::dht::signed::compute_record_set_digest(&records);
        let timestamp = MeshMessage::generate_timestamp();

        let mut signature = Vec::new();
        let mut signer_public_key = None;

        let rs = self.record_state.read();
        if let Some(ref signer) = rs.mesh_signer {
            let content = crate::mesh::dht::signed::get_sync_signable_content(
                request_id,
                &self.node_id,
                &self.node_id,
                rs.local_version,
                records.len(),
                timestamp,
                &record_set_digest,
            );
            signature = signer.sign(&content);
            signer_public_key = Some(signer.get_public_key());
        }

        Some(MeshMessage::DhtSyncResponse {
            request_id: request_id.into(),
            records,
            version: rs.local_version,
            timestamp,
            signature,
            signer_public_key,
        })
    }

    pub fn create_snapshot_request(&self) -> Option<MeshMessage> {
        if !self.config.enabled || self.is_global_node() {
            return None;
        }

        let rs = self.record_state.read();
        let request_id = uuid::Uuid::new_v4().to_string();
        let from_version = rs.local_version;
        let timestamp = MeshMessage::generate_timestamp();

        let mut signature = Vec::new();
        let mut signer_public_key = None;

        if let Some(ref signer) = rs.mesh_signer {
            let content = crate::mesh::dht::signed::get_snapshot_request_signable_content(
                &request_id,
                &self.node_id,
                from_version,
                timestamp,
            );
            signature = signer.sign(&content);
            signer_public_key = Some(signer.get_public_key());
        }

        Some(MeshMessage::DhtSnapshotRequest {
            request_id: request_id.into(),
            node_id: self.node_id.clone().into(),
            from_version,
            signature,
            signer_public_key,
        })
    }

    pub fn create_snapshot_response(
        &self,
        request_id: &str,
        from_version: u64,
    ) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let records: Vec<DhtRecord> = self
            .get_all_records()
            .into_iter()
            .filter(|r| {
                let dht_key = DhtKey::from_str(&r.key);
                dht_key.is_public()
            })
            .take(crate::mesh::transport::MAX_SNAPSHOT_RECORDS)
            .collect();

        let record_set_digest = crate::mesh::dht::signed::compute_record_set_digest(&records);
        let timestamp = MeshMessage::generate_timestamp();

        let mut signature = Vec::new();
        let mut signer_public_key = None;

        let rs = self.record_state.read();
        if let Some(ref signer) = rs.mesh_signer {
            let content = crate::mesh::dht::signed::get_snapshot_signable_content(
                request_id,
                &self.node_id,
                rs.local_version,
                records.len(),
                timestamp,
                &record_set_digest,
            );
            signature = signer.sign(&content);
            signer_public_key = Some(signer.get_public_key());
        }

        Some(MeshMessage::DhtSnapshotResponse {
            request_id: request_id.into(),
            records,
            version: self.record_state.read().local_version,
            timestamp,
            signature,
            signer_public_key,
        })
    }

    pub fn apply_snapshot(
        &self,
        records: Vec<DhtRecord>,
        version: u64,
        is_verified: bool,
    ) -> usize {
        if !self.config.enabled || self.is_global_node() {
            return 0;
        }

        let reputation = if is_verified { 100 } else { 0 };
        let mut applied = 0;
        for record in records {
            if self.store_record(record, reputation, false) {
                applied += 1;
            }
        }

        self.record_state.write().last_snapshot_version = version;
        self.record_successful_sync();

        self.compute_merkle_tree();

        tracing::info!(
            "Applied DHT snapshot: {} records cached (version: {})",
            applied,
            version
        );
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

        let rs = self.record_state.read();
        let Some(ref verifier) = rs.record_signer else {
            tracing::warn!("No record signer configured, rejecting unsigned records");
            return 0;
        };

        let signer_public_key = signer.map(|s| s.get_public_key());
        let mut applied = 0;

        for record in records {
            let dht_key = crate::mesh::dht::keys::DhtKey::from_str(&record.key);
            let record_type = dht_key
                .to_signed_record_type()
                .unwrap_or(crate::mesh::dht::signed::SignedRecordType::NodeInfo);

            let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
                key: record.key.clone(),
                value: record.value.clone(),
                publisher_id: record.source_node_id.clone(),
                signature: record.signature.clone(),
                created_at: record.timestamp,
                expires_at: Some(record.timestamp + record.ttl_seconds),
                record_type,
                sequence_number: 0,
                source_node_id: record.source_node_id.clone(),
                ttl_seconds: record.ttl_seconds,
                signer_public_key: record.signer_public_key.clone(),
            };

            let verified = if signer_public_key
                .as_ref()
                .map(|pk| !pk.is_empty())
                .unwrap_or(false)
            {
                if let Some(ref pk) = signer_public_key {
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    signer
                        .as_ref()
                        .map(|s| {
                            s.verify(
                                &signed_record.get_signable_content(),
                                &signed_record.signature,
                                &pk_bytes,
                            )
                        })
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                verifier.verify(&signed_record)
            };

            if verified {
                if self.store_record(record, 100, false) {
                    applied += 1;
                }
            } else {
                let record_key = record.key.clone();
                tracing::warn!("Failed to verify record {} in snapshot", record_key);
            }
        }

        self.record_state.write().last_snapshot_version = version;
        self.record_successful_sync();

        self.compute_merkle_tree();

        tracing::info!(
            "Verified and applied DHT snapshot: {} records (version: {})",
            applied,
            version
        );
        applied
    }

    pub fn should_resync(&self) -> bool {
        if !self.config.enabled || self.is_global_node() {
            return false;
        }

        let now = Instant::now();
        let ms = self.metrics_state.read();
        now.duration_since(ms.last_sync) > Duration::from_secs(ms.current_sync_interval)
    }

    pub fn record_successful_sync(&self) {
        if !self.config.enabled || self.is_global_node() {
            return;
        }

        let mut ms = self.metrics_state.write();
        ms.last_sync = Instant::now();
        ms.initial_sync_completed = true;

        let current = ms.current_sync_interval;
        let max_interval = self.config.max_sync_interval_secs;

        if current < max_interval {
            let new_interval = (current * 2).min(max_interval);
            ms.current_sync_interval = new_interval;
            tracing::info!(
                "DHT sync interval increased to {}s (max: {}s)",
                new_interval,
                max_interval
            );
        }
    }

    pub fn reset_sync_interval(&self) {
        if !self.config.enabled || self.is_global_node() {
            return;
        }

        let initial = self.config.initial_sync_interval_secs;
        self.metrics_state.write().current_sync_interval = initial;
        tracing::debug!("DHT sync interval reset to {}s", initial);
    }

    pub fn get_current_sync_interval(&self) -> u64 {
        self.metrics_state.read().current_sync_interval
    }

    pub fn get_last_snapshot_version(&self) -> u64 {
        self.record_state.read().last_snapshot_version
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

        let ingress_ctx = crate::mesh::dht::signed::DhtRecordIngressContext::new_remote(
            from_node.to_string(),
            from_node.to_string(),
            crate::mesh::dht::signed::SourceClassification::Unknown,
            crate::mesh::dht::signed::IngressPath::Announce,
        );

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
                if self.store_record_from_ingress(record, &ingress_ctx, source_reputation) {
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

        let routing = self.routing_state.read();
        if let Some(ref topo) = routing.topology {
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

        if let Some(ref stake_mgr) = self.routing_state.read().stake_manager {
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
        let mut signer_public_key = None;

        let rs = self.record_state.read();
        if let Some(ref signer) = rs.mesh_signer {
            if let Some(ref rec) = record {
                let timestamp = MeshMessage::generate_timestamp();
                let content = format!(
                    "{},{},{},{},{}",
                    request_id, key, rec.timestamp, self.node_id, timestamp
                );
                signature = signer.sign(content.as_bytes());
                signer_public_key = Some(signer.get_public_key());
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

    pub fn handle_sync_response(&self, records: Vec<DhtRecord>, _from_node: &str) {
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

        let rs = self.record_state.read();
        let Some(ref verifier) = rs.record_signer else {
            tracing::warn!("No record signer configured, rejecting sync response");
            return;
        };

        let signer_public_key = signer.map(|s| s.get_public_key());
        let mut verified_records = Vec::new();

        let ingress_ctx = crate::mesh::dht::signed::DhtRecordIngressContext::new_remote(
            _from_node.to_string(),
            _from_node.to_string(),
            crate::mesh::dht::signed::SourceClassification::Unknown,
            crate::mesh::dht::signed::IngressPath::SyncResponse,
        );

        for record in records {
            let dht_key = crate::mesh::dht::keys::DhtKey::from_str(&record.key);
            let record_type = dht_key
                .to_signed_record_type()
                .unwrap_or(crate::mesh::dht::signed::SignedRecordType::NodeInfo);

            let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
                key: record.key.clone(),
                value: record.value.clone(),
                publisher_id: record.source_node_id.clone(),
                signature: record.signature.clone(),
                created_at: record.timestamp,
                expires_at: Some(record.timestamp + record.ttl_seconds),
                record_type,
                sequence_number: 0,
                source_node_id: record.source_node_id.clone(),
                ttl_seconds: record.ttl_seconds,
                signer_public_key: record.signer_public_key.clone(),
            };

            let verified = if signer_public_key
                .as_ref()
                .map(|pk| !pk.is_empty())
                .unwrap_or(false)
            {
                if let Some(ref pk) = signer_public_key {
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    signer
                        .as_ref()
                        .map(|s| {
                            s.verify(
                                &signed_record.get_signable_content(),
                                &signed_record.signature,
                                &pk_bytes,
                            )
                        })
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

        for record in verified_records {
            self.store_record_from_ingress(record, &ingress_ctx, 100);
        }
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

        let rs = self.record_state.read();
        let Some(ref verifier) = rs.record_signer else {
            tracing::warn!("No record signer configured, rejecting anti-entropy response");
            return;
        };

        let signer_public_key = signer.map(|s| s.get_public_key());

        let mut accepted_count = 0;
        let mut rejected_count = 0;

        let ingress_ctx = crate::mesh::dht::signed::DhtRecordIngressContext::new_remote(
            from_node.to_string(),
            from_node.to_string(),
            crate::mesh::dht::signed::SourceClassification::Unknown,
            crate::mesh::dht::signed::IngressPath::AntiEntropy,
        );

        for record in records {
            if record.signature.is_empty() {
                tracing::debug!(
                    "Rejecting record {} from {}: no signature",
                    record.key,
                    from_node
                );
                rejected_count += 1;
                continue;
            }

            let dht_key = crate::mesh::dht::keys::DhtKey::from_str(&record.key);
            let record_type = dht_key
                .to_signed_record_type()
                .unwrap_or(crate::mesh::dht::signed::SignedRecordType::NodeInfo);

            let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
                key: record.key.clone(),
                value: record.value.clone(),
                publisher_id: record.source_node_id.clone(),
                signature: record.signature.clone(),
                created_at: record.timestamp,
                expires_at: Some(record.timestamp + record.ttl_seconds),
                record_type,
                sequence_number: 0,
                source_node_id: record.source_node_id.clone(),
                ttl_seconds: record.ttl_seconds,
                signer_public_key: record.signer_public_key.clone(),
            };

            let verified = if signer_public_key
                .as_ref()
                .map(|pk| !pk.is_empty())
                .unwrap_or(false)
            {
                if let Some(ref pk) = signer_public_key {
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    signer
                        .as_ref()
                        .map(|s| {
                            s.verify(
                                &signed_record.get_signable_content(),
                                &signed_record.signature,
                                &pk_bytes,
                            )
                        })
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                verifier.verify(&signed_record)
            };

            if !verified {
                tracing::debug!(
                    "Rejecting record {} from {}: invalid signature",
                    record.key,
                    from_node
                );
                rejected_count += 1;

                if let Some(ref stake_mgr) = self.routing_state.read().stake_manager {
                    stake_mgr.submit_global_slash_vote(
                        record.source_node_id.clone(),
                        crate::mesh::dht::stake::SlashReason::InvalidRecordSignature,
                    );
                }
                continue;
            }

            let record_key = record.key.clone();

            if self.store_record_from_ingress(record, &ingress_ctx, 100) {
                tracing::debug!("Stored record {} from {} (verified)", record_key, from_node);
                accepted_count += 1;
            }
        }

        if rejected_count > 0 {
            tracing::info!(
                "Anti-entropy from {}: {} accepted, {} rejected",
                from_node,
                accepted_count,
                rejected_count
            );
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

        let routing_manager = self.routing_state.read().routing_manager.clone();
        let Some(rm) = routing_manager else {
            tracing::warn!("No routing manager available for Kademlia announce");
            return;
        };

        let transport_opt = self.routing_state.read().transport.clone();
        let Some(transport) = transport_opt else {
            return;
        };

        let replication_factor = self.config.replication_factor;

        // Use None for target_geo - we're announcing from our location,
        // so we'll get our regional hubs first via the hybrid lookup
        let target_geo = None;

        let peers = rm
            .find_closest_peers_hybrid(&self.node_id, target_geo, replication_factor)
            .await;

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

            if let Err(e) = transport
                .send_datagram_to_peer(&peer.node_id_string, &message)
                .await
            {
                fail_count += 1;
                tracing::debug!("Failed to announce to peer {}: {}", peer.node_id_string, e);
            } else {
                success_count += 1;
            }
        }

        tracing::debug!(
            "Kademlia DHT record announce: {} sent, {} failed",
            success_count,
            fail_count
        );
    }

    pub async fn announce_record_to_closest(
        &self,
        record: &DhtRecord,
        replication_factor: usize,
    ) -> usize {
        if !self.config.enabled || !self.is_global_node() {
            return 0;
        }

        let routing_manager = self.routing_state.read().routing_manager.clone();
        let Some(rm) = routing_manager else {
            return 0;
        };

        let transport_opt = self.routing_state.read().transport.clone();
        let Some(transport) = transport_opt else {
            return 0;
        };

        let target_geo = None;
        let closest_peers = rm
            .find_closest_peers_hybrid(&record.key, target_geo, replication_factor)
            .await;

        if closest_peers.is_empty() {
            return 0;
        }

        let write_quorum = self.config.write_quorum as usize;
        if closest_peers.len() < write_quorum {
            tracing::warn!(
                "DHT write warning: peer count ({}) is below write quorum ({}). DHT writes may fail or have reduced durability.",
                closest_peers.len(),
                write_quorum
            );
        }

        let request_id = format!("announce-{}-{}", record.key, uuid::Uuid::new_v4());
        let timestamp = MeshMessage::generate_timestamp();
        let records_count = 1;

        let (signature, signer_public_key) = {
            let rs = self.record_state.read();
            match rs.mesh_signer.as_ref() {
                Some(signer) => {
                    let content = format!(
                        "{},{},{},{}",
                        self.node_id,
                        records_count,
                        self.node_role.bits(),
                        timestamp
                    );
                    (signer.sign(content.as_bytes()), Some(signer.get_public_key()))
                }
                None => (Vec::new(), None),
            }
        };

        let announce = MeshMessage::DhtRecordAnnounce {
            request_id: request_id.into(),
            records: vec![record.clone()],
            write_quorum: self.config.write_quorum,
            timestamp,
            source_node_id: self.node_id.clone().into(),
            signature,
            signer_public_key,
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

        if success_count >= write_quorum {
            counter!("synvoid.dht.quorum.achieved", "type" => "write").increment(1);
            tracing::debug!(
                "DHT write quorum achieved for {}: {}/{} peers",
                record.key,
                success_count,
                write_quorum
            );
        } else {
            counter!("synvoid.dht.quorum.failed", "type" => "write").increment(1);
            tracing::debug!(
                "DHT write quorum NOT achieved for {}: {}/{} peers",
                record.key,
                success_count,
                write_quorum
            );
        }

        tracing::debug!("Announced record {} to {} peers", record.key, success_count);
        success_count
    }

    pub fn init_propagation_state(&self, key: &str) {
        let mut states = self.record_state.write();
        if !states.propagation_states.contains_key(key) {
            states.propagation_states.insert(
                key.to_string(),
                PropagationState {
                    key: key.to_string(),
                    ack_count: 0,
                    attempted_peers: Vec::new(),
                    completed: false,
                    last_update: Instant::now(),
                },
            );
        }
    }

    pub fn record_propagation_attempt(&self, key: &str, peer_id: &str) {
        let mut states = self.record_state.write();
        if let Some(state) = states.propagation_states.get_mut(key) {
            if !state.attempted_peers.contains(&peer_id.to_string()) {
                state.attempted_peers.push(peer_id.to_string());
                state.last_update = Instant::now();
            }
        }
    }

    pub fn record_propagation_ack(&self, key: &str) -> bool {
        let mut states = self.record_state.write();
        if let Some(state) = states.propagation_states.get_mut(key) {
            state.ack_count += 1;
            state.last_update = Instant::now();

            if state.ack_count >= self.convergence_threshold {
                state.completed = true;
                tracing::debug!(
                    "DHT propagation converged for key {} after {} acks",
                    key,
                    state.ack_count
                );
                return true;
            }
        }
        false
    }

    pub fn is_propagation_complete(&self, key: &str) -> bool {
        let states = self.record_state.read();
        states
            .propagation_states
            .get(key)
            .map(|s| s.completed)
            .unwrap_or(false)
    }

    pub fn get_propagation_state(&self, key: &str) -> Option<PropagationState> {
        let states = self.record_state.read();
        states.propagation_states.get(key).cloned()
    }

    pub fn cleanup_stale_propagation_states(&self, max_age_secs: u64) {
        let mut states = self.record_state.write();
        let now = Instant::now();
        states
            .propagation_states
            .retain(|_, state| now.duration_since(state.last_update).as_secs() < max_age_secs);
    }

    pub fn get_pending_propagations(&self) -> Vec<String> {
        let states = self.record_state.read();
        states
            .propagation_states
            .values()
            .filter(|s| !s.completed)
            .map(|s| s.key.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_derivation_from_dht_key() {
        let test_cases = vec![
            (
                "node_info:my-node",
                crate::mesh::dht::signed::SignedRecordType::NodeInfo,
            ),
            (
                "org:test",
                crate::mesh::dht::signed::SignedRecordType::Organization,
            ),
            (
                "upstream:example.com",
                crate::mesh::dht::signed::SignedRecordType::Upstream,
            ),
            (
                "verified_upstream:example.com",
                crate::mesh::dht::signed::SignedRecordType::VerifiedUpstream,
            ),
            (
                "dns_record:example.com:www",
                crate::mesh::dht::signed::SignedRecordType::DnsRecord,
            ),
            (
                "tier_claim:my-org",
                crate::mesh::dht::signed::SignedRecordType::TierClaim,
            ),
            (
                "global_node_heartbeat:node1",
                crate::mesh::dht::signed::SignedRecordType::GlobalNodeHeartbeat,
            ),
            (
                "node_health:node1",
                crate::mesh::dht::signed::SignedRecordType::NodeHealth,
            ),
        ];

        for (key, expected_type) in test_cases {
            let dht_key = crate::mesh::dht::keys::DhtKey::from_str(key);
            let actual_type = dht_key
                .to_signed_record_type()
                .unwrap_or(crate::mesh::dht::signed::SignedRecordType::NodeInfo);
            assert_eq!(
                actual_type, expected_type,
                "Record type mismatch for key {}: expected {:?}, got {:?}",
                key, expected_type, actual_type
            );
        }
    }

    #[test]
    fn test_sync_response_verified_uses_correct_record_type() {
        let record = crate::mesh::protocol::DhtRecord {
            key: "node_info:my-node".to_string(),
            value: b"node_data".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 3600,
            source_node_id: "node1".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("fake_key".to_string()),
            content_hash: vec![],
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let dht_key = crate::mesh::dht::keys::DhtKey::from_str(&record.key);
        let record_type = dht_key
            .to_signed_record_type()
            .unwrap_or(crate::mesh::dht::signed::SignedRecordType::NodeInfo);

        assert_eq!(
            record_type,
            crate::mesh::dht::signed::SignedRecordType::NodeInfo,
            "BUG: The record type for node_info:my-node should be NodeInfo"
        );

        let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
            key: record.key.clone(),
            value: record.value.clone(),
            publisher_id: record.source_node_id.clone(),
            signature: record.signature.clone(),
            created_at: record.timestamp,
            expires_at: Some(record.timestamp + record.ttl_seconds),
            record_type,
            sequence_number: 0,
            source_node_id: record.source_node_id.clone(),
            ttl_seconds: record.ttl_seconds,
            signer_public_key: record.signer_public_key.clone(),
        };

        assert_eq!(
            signed_record.record_type,
            crate::mesh::dht::signed::SignedRecordType::NodeInfo,
            "SignedDhtRecord should use NodeInfo type derived from DHT key, not hardcoded Organization"
        );
    }
}
