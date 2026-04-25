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
                        let pk_bytes = if signer_public_key.is_empty() {
                            Vec::new()
                        } else {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(signer_public_key)
                                .unwrap_or_default()
                        };
                        if !signer.verify(content.as_bytes(), signature, &pk_bytes) {
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
                for record in records {
                    self.store_record(record.clone(), reputation);
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
                signer_public_key: String::new(),
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
        let mut signer_public_key = String::new();

        {
            let rs = self.record_state.read();
            if let Some(ref signer) = rs.mesh_signer {
                let timestamp = MeshMessage::generate_timestamp();
                let content = format!(
                    "{},{},{},{},{}",
                    request_id,
                    proof_keys.len(),
                    records.len(),
                    self.node_role.bits(),
                    timestamp
                );
                signature = signer.sign(content.as_bytes());
                signer_public_key = signer.get_public_key();
            }
        }

        tracing::debug!(
            "DHT anti-entropy: responding to {} with {} records (hash mismatch)",
            from_node,
            records.len()
        );

        Some(MeshMessage::DhtAntiEntropyResponse {
            request_id: request_id.into(),
            root_hash: my_root_hash.unwrap_or_default(),
            proof_keys,
            proof_hashes,
            missing_records: records,
            timestamp: MeshMessage::generate_timestamp(),
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

        for record in missing_records {
            if self.store_record(record.clone(), reputation) {
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

        let quorum_self = Arc::downgrade(&Arc::new(self.clone()));
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));

            loop {
                interval.tick().await;

                if let Some(record_store) = quorum_self.upgrade() {
                    let qm = {
                        if let Some(qm) = record_store.quorum_manager().try_read() {
                            qm.clone()
                        } else {
                            None
                        }
                    };
                    if let Some(qm) = qm {
                        qm.cleanup_old_entries(300).await;
                    }
                }
            }
        });
    }

    pub async fn start_quorum_request(
        &self,
        key: String,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> Option<String> {
        let quorum_manager_opt = {
            let qm = self.quorum_manager.read();
            qm.clone()
        };

        let Some(quorum_manager) = quorum_manager_opt else {
            tracing::warn!("No quorum manager configured");
            return None;
        };

        let topology_opt = {
            let routing = self.routing_state.read();
            routing.topology.clone()
        };

        let Some(topology) = topology_opt else {
            tracing::warn!("No topology available for quorum request");
            return None;
        };

        let transport_opt = {
            let routing = self.routing_state.read();
            routing.transport.clone()
        };

        let Some(transport) = transport_opt else {
            tracing::warn!("No transport available for quorum request");
            return None;
        };

        let global_nodes = topology.get_global_nodes_as_peer_info().await;
        if global_nodes.is_empty() {
            tracing::warn!("No global nodes available for quorum request");
            return None;
        }

        let (origin_signature, signer_public_key) = {
            let rs = self.record_state.read();
            if let Some(ref signer) = rs.mesh_signer {
                #[derive(serde::Serialize)]
                struct Signable<'a> {
                    key: &'a str,
                    value: &'a [u8],
                    timestamp: u64,
                }
                let signed_content = crate::serialization::serialize(&Signable {
                    key: &key,
                    value: &value,
                    timestamp: crate::mesh::safe_unix_timestamp(),
                })
                .unwrap_or_default();

                let signature = signer.sign(&signed_content);
                let pk = signer.get_public_key();
                (signature, pk)
            } else {
                (Vec::new(), String::new())
            }
        };

        let request_id = format!("quorum-{}-{}", key, uuid::Uuid::new_v4());

        let quorum_request = crate::mesh::dht::quorum::QuorumRequest::new(
            request_id.clone(),
            key.clone(),
            value.clone(),
            ttl_seconds,
            self.node_id.clone(),
            origin_signature.clone(),
            &global_nodes
                .iter()
                .map(|p| p.node_id.clone())
                .collect::<Vec<_>>(),
        );

        quorum_manager.start_request(quorum_request).await;

        let quorum_msg = MeshMessage::QuorumStoreRequest {
            request_id: request_id.clone().into(),
            key: key.clone().into(),
            value,
            ttl_seconds,
            origin_node_id: self.node_id.clone().into(),
            origin_signature,
            action: crate::mesh::protocol::AnnounceAction::Add,
        };

        for peer in &global_nodes {
            if peer.node_id == self.node_id {
                continue;
            }

            if let Err(e) = transport
                .send_datagram_to_peer(&peer.node_id, &quorum_msg)
                .await
            {
                tracing::warn!("Failed to send quorum request to {}: {}", peer.node_id, e);
            }
        }

        tracing::info!(
            "Started quorum request {} for key {} with {} global nodes",
            request_id,
            key,
            global_nodes.len()
        );

        Some(request_id)
    }

    pub async fn handle_quorum_store_request(
        &self,
        request_id: &str,
        from_node_id: &str,
        record: crate::mesh::protocol::DhtRecord,
    ) -> bool {
        let quorum_manager_opt = {
            let qm = self.quorum_manager.read();
            qm.clone()
        };

        let Some(quorum_manager) = quorum_manager_opt else {
            tracing::warn!("No quorum manager configured for handling quorum store request");
            return false;
        };

        let topology_opt = {
            let routing = self.routing_state.read();
            routing.topology.clone()
        };

        let Some(topology) = topology_opt else {
            tracing::warn!("No topology available for handling quorum store request");
            return false;
        };

        let transport_opt = {
            let routing = self.routing_state.read();
            routing.transport.clone()
        };

        let Some(transport) = transport_opt else {
            tracing::warn!("No transport available for handling quorum store request");
            return false;
        };

        let signature_valid = {
            let rs = self.record_state.read();
            if let Some(ref verifier) = rs.record_signer {
                let signed_record = crate::mesh::dht::SignedDhtRecord {
                    key: record.key.clone(),
                    value: record.value.clone(),
                    publisher_id: record.source_node_id.clone(),
                    signature: record.signature.clone(),
                    created_at: record.timestamp,
                    expires_at: Some(record.timestamp + record.ttl_seconds),
                    record_type: crate::mesh::dht::SignedRecordType::NodeInfo,
                    sequence_number: record.sequence_number,
                    source_node_id: record.source_node_id.clone(),
                    ttl_seconds: record.ttl_seconds,
                    signer_public_key: record.signer_public_key.clone(),
                };
                verifier.verify(&signed_record)
            } else {
                false
            }
        };

        if !signature_valid {
            tracing::warn!(
                "Rejecting quorum store request from {} - invalid signature",
                from_node_id
            );
            let rejection = MeshMessage::QuorumRejectionResponse {
                request_id: request_id.into(),
                key: record.key.clone().into(),
                reason: "unauthorized".into(),
                evidence: None,
            };
            let _ = transport
                .send_datagram_to_peer(from_node_id, &rejection)
                .await;
            return false;
        }

        let signer_public_key = record.signer_public_key.as_ref();
        let is_authorized = if let Some(signer_pk) = signer_public_key {
            let cert_manager = {
                let routing = self.routing_state.read();
                routing.transport.as_ref().map(|t| t.cert_manager.clone())
            };
            if let Some(cert_mgr) = cert_manager {
                let authorized = cert_mgr.read().is_global_node_authorized(signer_pk);
                if !authorized {
                    tracing::warn!(
                        "Rejecting quorum store request from {} - signer not in authorized global node list",
                        from_node_id
                    );
                    let rejection = MeshMessage::QuorumRejectionResponse {
                        request_id: request_id.into(),
                        key: record.key.clone().into(),
                        reason: "unauthorized".into(),
                        evidence: Some(format!("signer_public_key: {}", signer_pk).into_bytes()),
                    };
                    let _ = transport
                        .send_datagram_to_peer(from_node_id, &rejection)
                        .await;
                }
                authorized
            } else {
                tracing::warn!("No cert manager available for authorization check");
                false
            }
        } else {
            tracing::warn!(
                "Rejecting quorum store request from {} - no signer public key",
                from_node_id
            );
            let rejection = MeshMessage::QuorumRejectionResponse {
                request_id: request_id.into(),
                key: record.key.clone().into(),
                reason: "unauthorized".into(),
                evidence: None,
            };
            let _ = transport
                .send_datagram_to_peer(from_node_id, &rejection)
                .await;
            false
        };

        if !is_authorized {
            return false;
        }

        let (signature, signer_public_key) = {
            let rs = self.record_state.read();
            if let Some(ref signer) = rs.mesh_signer {
                #[derive(serde::Serialize)]
                struct Signable<'a> {
                    key: &'a str,
                    value: &'a [u8],
                    timestamp: u64,
                }
                let signed_content = crate::serialization::serialize(&Signable {
                    key: &record.key,
                    value: record.value.as_slice(),
                    timestamp: crate::mesh::safe_unix_timestamp(),
                })
                .unwrap_or_default();

                let sig = signer.sign(&signed_content);
                let pk = signer.get_public_key();
                (sig, pk)
            } else {
                (Vec::new(), String::new())
            }
        };

        let global_nodes = topology.get_global_nodes().await;
        if global_nodes.is_empty() {
            tracing::warn!("No global nodes available for quorum - rejecting store request");
            return false;
        }
        if global_nodes.len() < 3 {
            tracing::warn!(
                "Fewer than 3 global nodes ({}) for quorum - auto-approving with reduced fault tolerance",
                global_nodes.len()
            );
        }

        quorum_manager
            .add_signature(request_id, self.node_id.clone(), signature.clone())
            .await;

        let response = MeshMessage::QuorumSignatureResponse {
            request_id: request_id.into(),
            key: record.key.clone().into(),
            signature,
        };
        let _ = transport
            .send_datagram_to_peer(from_node_id, &response)
            .await;

        tracing::debug!(
            "Sent quorum signature for request {} to {}",
            request_id,
            from_node_id
        );

        true
    }

    pub async fn store_record_after_quorum(
        &self,
        record: &crate::mesh::protocol::DhtRecord,
    ) -> bool {
        let mut rs = self.record_state.write();
        let version = rs.local_version;
        rs.records.insert(
            record.key.clone(),
            crate::mesh::dht::record_store::DhtRecordEntry {
                record: record.clone(),
                local_origin: true,
                version,
            },
        );
        rs.local_version += 1;
        tracing::debug!("Stored record after quorum: {}", record.key);
        true
    }

    pub async fn handle_quorum_signature_response(
        &self,
        request_id: &str,
        node_id: &str,
        signature: Vec<u8>,
    ) -> bool {
        let manager_opt = {
            let qm = self.quorum_manager.read();
            (*qm).clone()
        };
        if let Some(manager) = manager_opt {
            manager
                .add_signature(request_id, node_id.to_string(), signature)
                .await
        } else {
            false
        }
    }

    pub async fn handle_quorum_rejection_response(
        &self,
        request_id: &str,
        node_id: &str,
        reason: crate::mesh::protocol::ArcStr,
        evidence: Option<Vec<u8>>,
    ) {
        let reason_str = reason.to_string();
        let rejection_reason: crate::mesh::dht::quorum::RejectionReason =
            reason_str.parse().unwrap_or_else(|_| {
                crate::mesh::dht::quorum::RejectionReason::Unknown(reason_str.to_string())
            });

        let manager_opt = {
            let qm = self.quorum_manager.read();
            (*qm).clone()
        };
        if let Some(manager) = manager_opt {
            manager
                .add_rejection(request_id, node_id.to_string(), rejection_reason, evidence)
                .await;
        }
    }

    pub async fn check_quorum_completion(
        &self,
        request_id: &str,
    ) -> Option<crate::mesh::dht::quorum::QuorumResult> {
        let manager_opt = {
            let qm = self.quorum_manager.read();
            (*qm).clone()
        };
        if let Some(manager) = manager_opt {
            if let Some(request) = manager.get_request(request_id).await {
                let topology_opt = {
                    let routing = self.routing_state.read();
                    routing.topology.clone()
                };

                if let Some(topology) = topology_opt {
                    let global_nodes = topology.get_global_nodes().await;
                    let total = global_nodes.len();

                    if request.threshold_met(total) {
                        if request.has_rejections() {
                            return Some(crate::mesh::dht::quorum::QuorumResult::Rejected {
                                rejection: request.rejections.first().cloned().unwrap(),
                                verified: false,
                            });
                        }

                        return Some(crate::mesh::dht::quorum::QuorumResult::Approved(
                            request.signatures.clone(),
                        ));
                    }

                    if request.deadline_passed() {
                        return Some(crate::mesh::dht::quorum::QuorumResult::Timeout {
                            signatures_collected: request.signatures.clone(),
                            threshold: crate::mesh::dht::quorum::QuorumRequest::required_signatures(
                                total,
                            ),
                        });
                    }
                }
            }
        }
        None
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
            rs.mesh_signer
                .as_ref()
                .map(|s| s.get_public_key())
                .unwrap_or_default()
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
            rs.mesh_signer
                .as_ref()
                .map(|s| s.get_public_key())
                .unwrap_or_default()
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
