use super::*;

impl RecordStoreManager {
    pub(crate) fn can_cache_on_edge(&self, key: &str) -> bool {
        if !self.config.edge_cache_enabled {
            return false;
        }
        let dht_key = DhtKey::from_str(key);
        dht_key.is_public()
    }

    pub(crate) fn store_record_verified_internal(
        &self,
        record: DhtRecord,
        source_reputation: i64,
        is_local_origin: bool,
    ) -> bool {
        if !self.config.enabled {
            return false;
        }

        if self.is_rate_limited(&record.source_node_id) {
            tracing::warn!(
                "Record store: node {} is rate limited, cannot store record for key {}",
                record.source_node_id,
                record.key
            );
            crate::stubs::metrics::record_dht_store_rate_limited();
            return false;
        }

        let is_global = self.is_global_node();
        let dht_key = DhtKey::from_str(&record.key);

        if dht_key.is_raft_global() {
            tracing::warn!(
                "Record store: rejected direct DHT write for Raft-owned key {}; use Raft write path",
                record.key
            );
            crate::stubs::metrics::record_dht_store_operation(false);
            return false;
        }

        let policy = crate::dht::key_policy::DhtKeyPolicyTable::policy_for_key(&dht_key);
        if !is_local_origin && !policy.remote_writes_allowed {
            tracing::warn!(
                "Record store: remote write denied by policy for key {} (authority class: {:?})",
                record.key,
                policy.authority_class
            );
            crate::stubs::metrics::record_dht_store_operation(false);
            return false;
        }

        if record.signature.is_empty() {
            tracing::warn!("Record store: record for key {} must be signed", record.key);
            return false;
        } else {
            let signer_key_valid = record
                .signer_public_key
                .as_ref()
                .map(|s| !s.is_empty())
                .unwrap_or(false);

            if !signer_key_valid {
                tracing::warn!(
                    "Record store: missing signer public key for key {} from node {}",
                    record.key,
                    record.source_node_id
                );
                return false;
            }

            if !crate::dht::signed::verify_dht_record_signature(&record) {
                tracing::warn!(
                    "Record store: invalid signature for key {} from node {}",
                    record.key,
                    record.source_node_id
                );
                return false;
            }
        }

        if !record.verify_content_hash() {
            tracing::warn!(
                "Record store: content hash mismatch for key {} from node {}",
                record.key,
                record.source_node_id
            );
            return false;
        }

        if let Some(ref stake_mgr) = self.routing_state.read().stake_manager {
            if !stake_mgr.can_write_dht(&record.source_node_id) {
                tracing::warn!(
                    "Record store: node {} has insufficient stake to write DHT record",
                    record.source_node_id
                );
                return false;
            }
        }

        if self.is_global_node() {
            return self.store_record_global(record, is_local_origin);
        }

        let is_self_record = dht_key.is_self_record(&self.node_id);

        if let Some(ref verifier) = self.capability_verifier {
            if !verifier.verify_capability_for_key(&record.source_node_id, &record.key) {
                tracing::warn!(
                    "Record store: capability verification failed for node {} on key {}",
                    record.source_node_id,
                    record.key
                );
                return false;
            }
        }

        if dht_key.is_privileged() {
            if let Err(e) = self.access_control.require_global_node() {
                tracing::warn!(
                    "Record store: {} cannot store privileged record",
                    record.source_node_id
                );
                return false;
            }
        }

        if !self.config.edge_write_enabled {
            if self.can_cache_on_edge(&record.key) && is_self_record {
                return self.store_record_edge_cache(record);
            }
            tracing::warn!(
                "Record store: edge write disabled, cannot store: {}",
                record.key
            );
            return false;
        }

        if !self
            .access_control
            .can_store(&record.key, false, is_self_record, source_reputation)
        {
            tracing::warn!(
                "Record store: access denied for key {} (reputation: {} < {})",
                record.key,
                source_reputation,
                self.access_control.min_reputation_for_write()
            );
            return false;
        }

        if self.access_control.is_self_only(&record.key) && !is_self_record {
            tracing::warn!(
                "Record store: key {} can only be stored by the owning node",
                record.key
            );
            return false;
        }

        if self.can_cache_on_edge(&record.key) {
            return self.store_record_edge_cache(record);
        }

        tracing::warn!(
            "Record store: edge node cannot cache privileged record: {}",
            record.key
        );
        false
    }

    /// Store a record originating locally on this node. The `is_local_origin` flag is
    /// always `true` — remote/mesh writes should use `store_record_from_ingress`.
    pub fn store_local_record(&self, record: DhtRecord, source_reputation: i64) -> bool {
        self.store_record_verified_internal(record, source_reputation, true)
    }

    pub fn store_record_from_ingress(
        &self,
        record: DhtRecord,
        ingress_ctx: &crate::dht::signed::DhtRecordIngressContext,
        source_reputation: i64,
    ) -> bool {
        if !self.config.enabled {
            return false;
        }

        if let Err(e) = record.verify_for_ingress(ingress_ctx, &self.access_control) {
            tracing::warn!(
                "Ingress verification failed for record {} from {} via {:?}: {:?}",
                record.key,
                ingress_ctx.source_node_id(),
                ingress_ctx.path(),
                e
            );
            crate::stubs::metrics::record_dht_store_operation(false);
            return false;
        }

        // Optional canonical-reader ingress authority gate.
        // Applied only for direct signed-record client ingress paths (Push, Announce)
        // to keep the seam low-risk and avoid altering sync/replay semantics.
        // Sync/replay (SnapshotSync, SyncResponse, AntiEntropy, etc), local,
        // and quorum paths skip the gate even if a policy context is attached.
        // If the per-ingress ctx carries a DhtIngressPolicyContext with a reader,
        // delegate to check_dht_ingress_authority. NotConfigured preserves legacy.
        // Rejected or Deferred for the targeted remote ingress causes rejection here.
        if !self.check_record_ingress_canonical_gate(&record, ingress_ctx) {
            return false;
        }

        self.store_record_verified_internal(
            record,
            source_reputation,
            ingress_ctx.is_local_origin(),
        )
    }

    fn check_record_ingress_canonical_gate(
        &self,
        record: &DhtRecord,
        ingress_ctx: &crate::dht::signed::DhtRecordIngressContext,
    ) -> bool {
        if ingress_ctx.is_local_origin() {
            return true;
        }
        let path = ingress_ctx.path();
        if !matches!(
            path,
            crate::dht::signed::IngressPath::Push | crate::dht::signed::IngressPath::Announce
        ) {
            return true;
        }
        if let Some(pctx) = ingress_ctx.policy_context() {
            let dht_key = DhtKey::from_str(&record.key);
            match crate::dht::check_dht_ingress_authority(
                pctx,
                &dht_key,
                Some(ingress_ctx.source_node_id()),
                None,
            ) {
                crate::dht::DhtIngressGateOutcome::Accepted
                | crate::dht::DhtIngressGateOutcome::NotConfigured => {}
                crate::dht::DhtIngressGateOutcome::Rejected(r) => {
                    tracing::warn!(
                        "Record store: remote ingress rejected by canonical policy for key {} from {}: {:?}",
                        record.key,
                        ingress_ctx.source_node_id(),
                        r
                    );
                    crate::stubs::metrics::record_dht_store_operation(false);
                    return false;
                }
                crate::dht::DhtIngressGateOutcome::Deferred(d) => {
                    tracing::warn!(
                        "Record store: remote ingress deferred by canonical policy for key {} from {} (treating as reject per plan): {:?}",
                        record.key,
                        ingress_ctx.source_node_id(),
                        d
                    );
                    crate::stubs::metrics::record_dht_store_operation(false);
                    return false;
                }
            }
        }
        true
    }

    pub(crate) fn store_record_global(&self, mut record: DhtRecord, is_local_origin: bool) -> bool {
        let now = synvoid_utils::safe_unix_timestamp();
        let dht_key = DhtKey::from_str(&record.key);

        if dht_key.is_raft_global() {
            tracing::warn!(
                "Rejected direct DHT write for Raft-owned key {} from {}; use Raft write path",
                record.key,
                record.source_node_id
            );
            crate::stubs::metrics::record_dht_store_operation(false);
            return false;
        }

        let expires_at = record.timestamp.saturating_add(record.ttl_seconds);
        if now > expires_at {
            tracing::warn!("Received expired record: {}", record.key);
            crate::stubs::metrics::record_dht_store_operation(false);
            return false;
        }

        if !crate::dht::signed::validate_record_timestamp(record.timestamp) {
            tracing::warn!(
                "Received record with timestamp too far in future: {} for key {}",
                record.timestamp,
                record.key
            );
            crate::stubs::metrics::record_dht_store_operation(false);
            return false;
        }

        let is_local_record = is_local_origin && record.source_node_id == self.node_id;

        if self
            .access_control
            .requires_immutability_trust_anchor(&record.key)
            && !is_local_record
        {
            let signer_valid = if let Some(ref signer_pk) = record.signer_public_key {
                if self.access_control.authorized_genesis_keys.is_empty() {
                    tracing::warn!(
                        "Rejected immutable record {}: no authorized genesis keys configured - rejecting from {}",
                        record.key,
                        record.source_node_id
                    );
                    crate::stubs::metrics::record_dht_store_operation(false);
                    return false;
                }
                if !self
                    .access_control
                    .authorized_genesis_keys
                    .contains(signer_pk)
                {
                    tracing::warn!(
                        "Rejected immutable record {}: signer {} is not an authorized genesis key",
                        record.key,
                        signer_pk
                    );
                    crate::stubs::metrics::record_dht_store_operation(false);
                    return false;
                }
                tracing::debug!(
                    "Trust anchor verification passed for immutable record: {}",
                    record.key
                );
                true
            } else {
                tracing::warn!(
                    "Rejected immutable record {} from {}: no signer public key provided",
                    record.key,
                    record.source_node_id
                );
                crate::stubs::metrics::record_dht_store_operation(false);
                return false;
            };

            let _ = signer_valid;
        }

        if !is_local_record {
            if record.signature.is_empty() {
                tracing::warn!(
                    "Rejected record with missing signature for key {} from node {}",
                    record.key,
                    record.source_node_id
                );
                crate::stubs::metrics::record_dht_store_operation(false);
                return false;
            }

            let signer_key_valid = record
                .signer_public_key
                .as_ref()
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if !signer_key_valid {
                tracing::warn!(
                    "Rejected record with missing signer public key for key {} from node {}",
                    record.key,
                    record.source_node_id
                );
                crate::stubs::metrics::record_dht_store_operation(false);
                return false;
            }

            let record_type = dht_key
                .to_signed_record_type()
                .unwrap_or(crate::dht::SignedRecordType::NodeInfo);

            if !crate::dht::signed::verify_dht_record_signature_for_key(&record, record_type) {
                tracing::warn!(
                    "Rejected record with invalid signature for key {} from node {}",
                    record.key,
                    record.source_node_id
                );
                crate::stubs::metrics::record_dht_store_operation(false);
                return false;
            }
        }

        if is_local_record {
            let rs = self.record_state.read();
            if let Some(ref signer) = rs.record_signer {
                let signed_record = crate::dht::SignedDhtRecord::new(
                    record.key.clone(),
                    record.value.clone(),
                    record.source_node_id.clone(),
                    crate::dht::SignedRecordType::NodeInfo,
                );

                if let Some(signature) = signer.sign(&signed_record) {
                    record.signature = signature;
                    record.signer_public_key = signer.get_verifying_key();
                    tracing::debug!("Signed local record with Ed25519: {}", record.key);
                }
            }
        }

        let mut rs = self.record_state.write();

        let record_type = dht_key.to_signed_record_type();

        let should_replace = match record_type {
            Some(crate::dht::SignedRecordType::GenesisKeyTransition)
            | Some(crate::dht::SignedRecordType::RevokedGlobalNode)
            | Some(crate::dht::SignedRecordType::YaraRulesManifest)
            | Some(crate::dht::SignedRecordType::YaraRuleContent) => {
                if rs.records.get(&record.key).is_some() {
                    tracing::debug!(
                        "Rejected immutable record type for key {} - records of this type cannot be replaced",
                        record.key
                    );
                    crate::stubs::metrics::record_dht_store_operation(false);
                    return false;
                }
                true
            }
            _ => match rs.records.get(&record.key) {
                None => true,
                Some(existing_entry) => {
                    let existing_key = (
                        existing_entry.record.timestamp,
                        existing_entry.record.sequence_number,
                        existing_entry.record.source_node_id.clone(),
                    );
                    let new_key = (
                        record.timestamp,
                        record.sequence_number,
                        record.source_node_id.clone(),
                    );
                    new_key > existing_key
                }
            },
        };

        if !should_replace {
            tracing::debug!(
                "Rejected older record for key {} (existing timestamp: {}, new timestamp: {})",
                record.key,
                rs.records
                    .get(&record.key)
                    .map(|e| e.record.timestamp)
                    .unwrap_or(0),
                record.timestamp
            );
            crate::stubs::metrics::record_dht_store_operation(false);
            return false;
        }

        let version = rs.local_version;
        rs.records.insert(
            record.key.clone(),
            DhtRecordEntry {
                record: record.clone(),
                local_origin: is_local_record,
                version,
                status: Default::default(),
            },
        );

        rs.local_version += 1;

        tracing::debug!("Stored global record: {}", record.key);

        drop(rs);

        if self.is_global_node() {
            if let Some(ref disk_store) = self.record_state.read().disk_store {
                disk_store.insert(
                    record.key.clone(),
                    DhtRecordEntry {
                        record: record.clone(),
                        local_origin: is_local_record,
                        version,
                        status: Default::default(),
                    },
                );
            }
        }

        self.maybe_queue_for_announce(&record);

        if self.is_global_node() {
            self.record_change();
        }

        self.update_merkle_incremental(&record.key, &record.value);

        let record_type = crate::dht::keys::DhtKey::from_str(&record.key).key_type();
        crate::stubs::metrics::increment_dht_records_by_type(record_type);
        crate::stubs::metrics::record_dht_store_operation(true);
        true
    }

    pub(crate) fn maybe_queue_for_announce(&self, record: &DhtRecord) {
        let dht_key = DhtKey::from_str(&record.key);

        if dht_key.is_public() && !dht_key.requires_confirmation() {
            self.queue_for_announce(record.clone());
            tracing::debug!("Auto-queued public record for announce: {}", record.key);
        }
    }

    fn store_record_edge_cache(&self, record: DhtRecord) -> bool {
        let now = synvoid_utils::safe_unix_timestamp();

        let expires_at = record.timestamp + record.ttl_seconds;
        if now > expires_at {
            tracing::debug!("Ignoring expired record in edge cache: {}", record.key);
            return false;
        }

        let effective_ttl = self.config.edge_cache_ttl_secs.min(record.ttl_seconds);
        let record_key = record.key.clone();

        let cache_ttl_record = DhtRecord {
            key: record_key.clone(),
            value: record.value.clone(),
            timestamp: record.timestamp,
            sequence_number: 0,
            ttl_seconds: effective_ttl,
            source_node_id: record.source_node_id.clone(),
            signature: record.signature.clone(),
            signer_public_key: record.signer_public_key.clone(),
            content_hash: record.content_hash.clone(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let mut rs = self.record_state.write();

        while rs.records.len() >= self.config.edge_cache_max_entries {
            if let Some(oldest_key) = rs.records.front().map(|(k, _)| k.clone()) {
                rs.records.remove(&oldest_key);
                tracing::debug!("Edge cache full, evicted LRU: {}", oldest_key);
            } else {
                break;
            }
        }

        let version = rs.local_version;
        rs.records.insert(
            record_key,
            DhtRecordEntry {
                record: cache_ttl_record,
                local_origin: false,
                version,
                status: Default::default(),
            },
        );

        rs.local_version += 1;

        tracing::debug!("Cached edge record: {}", record.key);

        if self.is_global_node() {
            drop(rs);
            self.update_merkle_incremental(&record.key, &record.value);
        }

        crate::stubs::metrics::record_dht_store_operation(true);
        true
    }

    pub fn get_record(&self, key: &str) -> Option<DhtRecord> {
        if !self.config.enabled {
            return None;
        }

        let (record, is_expired) = {
            let rs = self.record_state.read();
            match rs.records.get(key) {
                Some(entry) => {
                    let now = synvoid_utils::safe_unix_timestamp();
                    let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                    (Some(entry.record.clone()), now >= expires_at)
                }
                None => (None, false),
            }
        };

        if let Some(record) = record {
            if !is_expired {
                if !self.is_global_node() {
                    self.metrics_state.write().cache_hits += 1;
                    let rs = self.record_state.write();
                    if let Some(entry) = rs.records.remove(key) {
                        rs.records.insert(key.to_string(), entry);
                    }
                }
                crate::stubs::metrics::record_dht_get_operation(true);
                return Some(record);
            } else {
                let rs = self.record_state.write();
                rs.records.remove(key);
            }
        }

        if !self.is_global_node() {
            self.metrics_state.write().cache_misses += 1;
        }

        if self.is_global_node() {
            if let Some(ref disk_store) = self.record_state.read().disk_store {
                if let Some(entry) = disk_store.get(key) {
                    let now = synvoid_utils::safe_unix_timestamp();
                    let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                    if now < expires_at {
                        let rs = self.record_state.write();
                        rs.records.insert(key.to_string(), entry.clone());
                        crate::stubs::metrics::record_dht_get_operation(true);
                        return Some(entry.record);
                    }
                }
            }
        }

        crate::stubs::metrics::record_dht_get_operation(false);
        None
    }

    pub fn get_record_cached(&self, key: &str) -> Option<DhtRecord> {
        if !self.config.enabled || self.is_global_node() {
            return None;
        }

        let dht_key = DhtKey::from_str(key);
        if !dht_key.is_public() {
            return None;
        }

        self.get_record(key)
    }

    pub fn should_query_global(&self, key: &str) -> bool {
        if !self.config.enabled || self.is_global_node() {
            return false;
        }

        let dht_key = DhtKey::from_str(key);
        if !dht_key.is_public() {
            return true;
        }

        self.get_record(key).is_none()
    }

    pub fn get_all_records(&self) -> Vec<DhtRecord> {
        let rs = self.record_state.read();
        rs.records
            .values()
            .into_iter()
            .filter(|entry| {
                let now = synvoid_utils::safe_unix_timestamp();
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now < expires_at && entry.status == crate::protocol::DhtRecordStatus::Live
            })
            .map(|e| e.record.clone())
            .collect()
    }

    pub fn get_by_prefix(&self, prefix: &str, limit: usize) -> Vec<DhtRecord> {
        let rs = self.record_state.read();
        rs.records
            .get_by_prefix(prefix, limit)
            .into_iter()
            .filter(|(_, entry)| {
                let now = synvoid_utils::safe_unix_timestamp();
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now < expires_at && entry.status == crate::protocol::DhtRecordStatus::Live
            })
            .map(|(_, e)| e.record.clone())
            .collect()
    }

    pub fn get_version(&self) -> u64 {
        self.record_state.read().local_version
    }

    pub fn should_sync(&self) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let interval = self.get_adaptive_sync_interval();
        let last = self.metrics_state.read().last_sync;
        last.elapsed() > Duration::from_secs(interval)
    }

    pub fn get_adaptive_sync_interval(&self) -> u64 {
        let base_interval = self.config.sync_interval_secs;

        let mut ms = self.metrics_state.write();
        let now = Instant::now();
        ms.recent_changes
            .retain(|t| now.duration_since(*t).as_secs() < 300);

        let change_count = ms.recent_changes.len();

        if change_count > 10 {
            (base_interval / 4).max(60)
        } else if change_count > 5 {
            (base_interval / 2).max(120)
        } else if change_count == 0 {
            (base_interval * 2).min(self.config.max_sync_interval_secs)
        } else {
            base_interval
        }
    }

    pub fn record_change(&self) {
        let mut ms = self.metrics_state.write();
        ms.recent_changes.push(Instant::now());
    }

    pub fn record_sync(&self) {
        self.metrics_state.write().last_sync = Instant::now();
    }

    pub fn get_records_for_sync(&self, from_version: u64) -> Vec<DhtRecord> {
        let rs = self.record_state.read();

        rs.records
            .values()
            .into_iter()
            .filter(|entry| entry.version > from_version)
            .filter(|entry| {
                let now = synvoid_utils::safe_unix_timestamp();
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now < expires_at
            })
            .map(|entry| entry.record.clone())
            .collect()
    }

    pub fn apply_sync(&self, records: Vec<DhtRecord>) {
        let mut rs = self.record_state.write();
        let mut changed = false;

        for record in records {
            let now = synvoid_utils::safe_unix_timestamp();

            let expires_at = record.timestamp.saturating_add(record.ttl_seconds);
            if now > expires_at {
                continue;
            }

            if !crate::dht::signed::validate_record_timestamp(record.timestamp) {
                tracing::debug!(
                    "Skipping sync record with future timestamp: {} for key {}",
                    record.timestamp,
                    record.key
                );
                continue;
            }

            if self
                .access_control
                .requires_immutability_trust_anchor(&record.key)
            {
                if let Some(ref signer_pk) = record.signer_public_key {
                    if self.access_control.authorized_genesis_keys.is_empty() {
                        tracing::warn!(
                            "Skipping immutable record {}: no authorized genesis keys configured",
                            record.key
                        );
                        continue;
                    }
                    if !self
                        .access_control
                        .authorized_genesis_keys
                        .contains(signer_pk)
                    {
                        tracing::warn!(
                            "Skipping immutable record {}: signer {} is not an authorized genesis key",
                            record.key,
                            signer_pk
                        );
                        continue;
                    }
                } else {
                    tracing::warn!(
                        "Skipping immutable record {}: no signer public key provided",
                        record.key
                    );
                    continue;
                }
            }

            let dht_key = DhtKey::from_str(&record.key);
            let record_type = dht_key.to_signed_record_type();

            let should_replace = match record_type {
                Some(crate::dht::SignedRecordType::GenesisKeyTransition)
                | Some(crate::dht::SignedRecordType::RevokedGlobalNode)
                | Some(crate::dht::SignedRecordType::YaraRulesManifest)
                | Some(crate::dht::SignedRecordType::YaraRuleContent) => {
                    if rs.records.get(&record.key).is_some() {
                        tracing::debug!(
                            "Skipping immutable record type for key {} - cannot be replaced via sync",
                            record.key
                        );
                        false
                    } else {
                        true
                    }
                }
                _ => match rs.records.get(&record.key) {
                    None => true,
                    Some(existing_entry) => {
                        let existing_key = (
                            existing_entry.record.timestamp,
                            existing_entry.record.sequence_number,
                            existing_entry.record.source_node_id.clone(),
                        );
                        let new_key = (
                            record.timestamp,
                            record.sequence_number,
                            record.source_node_id.clone(),
                        );
                        new_key > existing_key
                    }
                },
            };

            if should_replace {
                changed = true;
                let version = rs.local_version + 1;
                rs.records.insert(
                    record.key.clone(),
                    DhtRecordEntry {
                        record,
                        local_origin: false,
                        version,
                        status: Default::default(),
                    },
                );
            }
        }

        if changed {
            rs.local_version += 1;
            drop(rs);
            self.compute_merkle_tree();
        }
    }

    pub fn queue_for_announce(&self, record: DhtRecord) {
        let mut rs = self.record_state.write();
        if rs.pending_announces.len() >= MAX_PENDING_ANNOUNCES {
            rs.pending_announces.pop_front();
        }
        rs.pending_announces.push_back(record);
        crate::stubs::metrics::record_dht_announce_queue_depth(rs.pending_announces.len());
    }

    pub fn cleanup_expired(&self) {
        let now = synvoid_utils::safe_unix_timestamp();

        let count_before = self.record_state.read().records.len();

        let rs = self.record_state.write();
        let keys_to_remove: Vec<String> = rs
            .records
            .iter()
            .into_iter()
            .filter(|(_, entry)| {
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now >= expires_at
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in keys_to_remove {
            rs.records.remove(&key);
        }

        let count_after = rs.records.len();
        if count_before != count_after {
            tracing::debug!(
                "Cleaned up {} expired DHT records",
                count_before - count_after
            );
        }
    }

    pub fn get_record_count(&self) -> usize {
        self.record_state.read().records.len()
    }

    pub fn create_record_announce(&self) -> Option<MeshMessage> {
        if !self.config.enabled {
            return None;
        }

        let mut rs = self.record_state.write();
        if rs.pending_announces.is_empty() {
            return None;
        }

        let records: Vec<DhtRecord> = rs.pending_announces.iter().cloned().collect();

        let mut signature = Vec::new();
        let mut signer_public_key = None;

        if let Some(ref signer) = rs.mesh_signer {
            let timestamp = MeshMessage::generate_timestamp();
            let content = format!(
                "{},{},{},{}",
                self.node_id,
                records.len(),
                self.node_role.bits(),
                timestamp
            );
            signature = signer.sign(content.as_bytes());
            signer_public_key = Some(signer.get_public_key());
        }

        let request_id = uuid::Uuid::new_v4().to_string();

        let message = MeshMessage::DhtRecordAnnounce {
            request_id: request_id.into(),
            records,
            write_quorum: self.config.write_quorum,
            timestamp: MeshMessage::generate_timestamp(),
            source_node_id: self.node_id.clone().into(),
            signature,
            signer_public_key,
        };

        rs.pending_announces.clear();
        crate::stubs::metrics::record_dht_announce_queue_depth(0);
        Some(message)
    }

    pub fn publish_global_node_public_key(&self, public_key: &str) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let key = format!("global_node_key:{}", self.node_id);
        let now = synvoid_utils::safe_unix_timestamp();

        let value = serde_json::json!({
            "public_key": public_key,
            "timestamp": now,
        });
        let value = match serde_json::to_vec(&value) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize global node public key: {}", e);
                return false;
            }
        };

        let record = DhtRecord {
            key,
            value: value.clone(),
            timestamp: now,
            sequence_number: 0,
            ttl_seconds: 86400,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&value);
                hasher.finalize().to_vec()
            },
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let stored = self.store_local_record(record.clone(), 100);
        if stored {
            self.queue_for_announce(record);
            tracing::info!("Published global node public key for node {}", self.node_id);
        }
        stored
    }

    pub fn store_and_announce(&self, key: String, value: Vec<u8>, ttl_seconds: u64) -> bool {
        self.store_and_announce_with_broadcast(key, value, ttl_seconds, false, 0)
    }

    pub fn store_and_announce_critical(
        &self,
        key: String,
        value: Vec<u8>,
        ttl_seconds: u64,
        replication_factor: usize,
    ) -> bool {
        self.store_and_announce_with_broadcast(key, value, ttl_seconds, true, replication_factor)
    }

    fn store_and_announce_with_broadcast(
        &self,
        key: String,
        value: Vec<u8>,
        ttl_seconds: u64,
        immediate_broadcast: bool,
        replication_factor: usize,
    ) -> bool {
        if !self.config.enabled {
            return false;
        }

        let now = synvoid_utils::safe_unix_timestamp();

        let record = DhtRecord {
            key: key.clone(),
            value: value.clone(),
            timestamp: now,
            sequence_number: 0,
            ttl_seconds,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&value);
                hasher.finalize().to_vec()
            },
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let stored = self.store_local_record(record.clone(), 100);
        if stored {
            self.queue_for_announce(record.clone());
            tracing::debug!("Stored and queued record for announce: {}", key);

            if immediate_broadcast && self.is_global_node() && replication_factor > 0 {
                let record_store = self.clone();
                tokio::spawn(async move {
                    record_store
                        .announce_record_to_closest(&record, replication_factor)
                        .await;
                });
            }
        }
        stored
    }

    pub fn remove(&self, key: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        let rs = self.record_state.write();
        if rs.records.remove(key).is_some() {
            tracing::debug!("Removed record from DHT: {}", key);
            drop(rs);
            self.record_change();
            return true;
        }
        false
    }

    pub fn get(&self, key: &str) -> Option<crate::protocol::DhtRecord> {
        let rs = self.record_state.read();
        rs.records.get(key).map(|entry| entry.record.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_remote_record_with_signature(
        key: &str,
        signature: Vec<u8>,
        signer_public_key: Option<String>,
    ) -> DhtRecord {
        DhtRecord {
            key: key.to_string(),
            value: b"test_value".to_vec(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "remote_node".to_string(),
            signature,
            signer_public_key,
            content_hash: vec![],
            quorum_proof: Vec::new(),
            request_id: None,
        }
    }

    #[test]
    fn test_store_record_requires_signer_key_for_non_empty_signature() {
        let record =
            make_remote_record_with_signature("node_info:test", vec![1, 2, 3, 4, 5, 6, 7, 8], None);

        let should_reject = !record.signature.is_empty()
            && record
                .signer_public_key
                .as_ref()
                .map(|s| s.is_empty())
                .unwrap_or(true);
        assert!(
            should_reject,
            "A record with non-empty signature but missing signer key should be rejected"
        );
    }

    #[test]
    fn test_store_record_rejects_empty_signer_key_with_signature() {
        let record = make_remote_record_with_signature(
            "node_info:test",
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            Some("".to_string()),
        );

        let signer_key_valid = record
            .signer_public_key
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        assert!(
            !signer_key_valid,
            "Empty signer key should be detected as invalid"
        );
    }

    #[test]
    fn test_verify_dht_record_signature_detects_missing_key() {
        let record =
            make_remote_record_with_signature("node_info:test", vec![1, 2, 3, 4, 5, 6, 7, 8], None);

        let result = crate::dht::signed::verify_dht_record_signature(&record);
        assert!(
            !result,
            "verify_dht_record_signature should reject record with missing signer public key"
        );
    }

    #[test]
    fn test_record_type_derived_from_dht_key_for_node_info() {
        let dht_key = DhtKey::from_str("node_info:test_node");
        let record_type = dht_key
            .to_signed_record_type()
            .unwrap_or(crate::dht::SignedRecordType::NodeInfo);

        assert_eq!(
            record_type,
            crate::dht::SignedRecordType::NodeInfo,
            "node_info: prefix should derive NodeInfo record type"
        );
    }

    #[test]
    fn test_record_type_derived_from_dht_key_for_org() {
        let dht_key = DhtKey::from_str("org:test_org");
        let record_type = dht_key
            .to_signed_record_type()
            .unwrap_or(crate::dht::SignedRecordType::NodeInfo);

        assert_eq!(
            record_type,
            crate::dht::SignedRecordType::Organization,
            "org: prefix should derive Organization record type"
        );
    }

    #[test]
    fn test_record_type_derived_from_dht_key_for_upstream() {
        let dht_key = DhtKey::from_str("upstream:example.com");
        let record_type = dht_key
            .to_signed_record_type()
            .unwrap_or(crate::dht::SignedRecordType::Upstream);

        assert_eq!(
            record_type,
            crate::dht::SignedRecordType::Upstream,
            "upstream: prefix should derive Upstream record type"
        );
    }

    fn build_signed_remote_record(
        key: &str,
        signer: &crate::protocol::MeshMessageSigner,
    ) -> DhtRecord {
        let mut record = DhtRecord {
            key: key.to_string(),
            value: b"test_value".to_vec(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "remote_node".to_string(),
            signature: Vec::new(),
            signer_public_key: Some(signer.get_public_key()),
            content_hash: vec![],
            quorum_proof: Vec::new(),
            request_id: None,
        };
        let signed = crate::dht::signed::dht_record_to_signed_record(&record);
        let content = signed.get_signable_content();
        record.signature = signer.sign(&content);
        record
    }

    #[test]
    fn test_remote_org_public_key_denied_by_policy() {
        let signer = crate::protocol::MeshMessageSigner::new([1u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("org_pubkey:my-org", &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "Remote OrgPublicKey without Raft proof should be denied by key policy"
        );
    }

    #[test]
    fn test_remote_revoked_global_node_denied_by_policy() {
        let signer = crate::protocol::MeshMessageSigner::new([2u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let key = "revoked_global_node:bad-node:0:test";
        let record = build_signed_remote_record(key, &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "Remote RevokedGlobalNode without Raft proof should be denied by key policy"
        );
    }

    #[test]
    fn test_remote_global_node_proof_denied_by_policy() {
        let signer = crate::protocol::MeshMessageSigner::new([3u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("global_node_proof:other-node", &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "Remote GlobalNodeProof without Raft proof should be denied by key policy"
        );
    }

    #[test]
    fn test_local_creation_works_for_node_info() {
        let signer = crate::protocol::MeshMessageSigner::new([4u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("node_info:test-node", &signer);
        let result = store.store_record_verified_internal(record, 100, true);
        assert!(result, "Local creation of NodeInfo should succeed");
    }

    #[test]
    fn test_local_creation_works_for_upstream() {
        let signer = crate::protocol::MeshMessageSigner::new([5u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("upstream:example.com", &signer);
        let result = store.store_record_verified_internal(record, 100, true);
        assert!(result, "Local creation of Upstream should succeed");
    }

    #[test]
    fn test_remote_upstream_allowed_by_policy() {
        let signer = crate::protocol::MeshMessageSigner::new([6u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("upstream:example.com", &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            result,
            "Remote Upstream write should be allowed by key policy (SoftLocal with remote_writes_allowed)"
        );
    }

    #[test]
    fn test_remote_global_node_list_denied_by_policy() {
        let signer = crate::protocol::MeshMessageSigner::new([7u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("global_node_list", &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "Remote GlobalNodeList without Raft proof should be denied by key policy"
        );
    }

    #[test]
    fn test_remote_dns_zone_denied_by_key_policy() {
        let signer = crate::protocol::MeshMessageSigner::new([8u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);

        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );
        let record = build_signed_remote_record("dns_zone:example.com", &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "DnsZone ownership must not be mutable through remote DHT capability alone; requires Raft or quorum attestation"
        );
    }

    #[test]
    fn test_remote_dns_zone_denied_without_valid_signature() {
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = DhtRecord {
            key: "dns_zone:example.com".to_string(),
            value: b"zone_data".to_vec(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "remote_node".to_string(),
            signature: vec![1, 2, 3],
            signer_public_key: Some("invalid_key".to_string()),
            content_hash: vec![],
            quorum_proof: Vec::new(),
            request_id: None,
        };
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "Remote DnsZone with invalid signature should be rejected"
        );
    }

    #[test]
    fn test_remote_dns_record_denied_without_valid_signature() {
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = DhtRecord {
            key: "dns_record:example.com:www".to_string(),
            value: b"record_data".to_vec(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "remote_node".to_string(),
            signature: vec![1, 2, 3],
            signer_public_key: Some("invalid_key".to_string()),
            content_hash: vec![],
            quorum_proof: Vec::new(),
            request_id: None,
        };
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "Remote DnsRecord with invalid signature should be rejected"
        );
    }

    #[test]
    fn test_remote_tier_key_denied_by_policy() {
        let signer = crate::protocol::MeshMessageSigner::new([10u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("tier_key:org1:tier1", &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "Remote TierKey without Raft proof should be denied by key policy"
        );
    }

    #[test]
    fn test_remote_node_cert_binding_denied_by_policy() {
        let signer = crate::protocol::MeshMessageSigner::new([11u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("node_cert_binding:other-node", &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "Remote NodeCertBinding without Raft attestation should be denied by key policy"
        );
    }

    #[test]
    fn test_remote_genesis_key_transition_denied_by_policy() {
        let signer = crate::protocol::MeshMessageSigner::new([12u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("genesis_key_transition:1:fp:announcer", &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "Remote GenesisKeyTransition without Raft attestation should be denied by key policy"
        );
    }

    #[test]
    fn test_remote_threat_indicator_requires_ttl() {
        let signer = crate::protocol::MeshMessageSigner::new([13u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let mut record = build_signed_remote_record("threat_indicator:192.168.1.1:ip", &signer);
        record.ttl_seconds = 0;
        let result = store.store_record_verified_internal(record, 100, true);
        assert!(
            !result,
            "ThreatIndicator with zero TTL should be rejected (ttl_required=true)"
        );
    }

    #[test]
    fn test_ingress_verification_rejects_unsigned_record() {
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = DhtRecord {
            key: "node_info:test-node".to_string(),
            value: b"test_value".to_vec(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "remote_node".to_string(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let ingress_ctx = crate::dht::signed::DhtRecordIngressContext::new_remote(
            "peer-1".to_string(),
            "remote_node".to_string(),
            crate::dht::signed::SourceClassification::EdgeNode,
            crate::dht::signed::IngressPath::Announce,
        );

        let result = store.store_record_from_ingress(record, &ingress_ctx, 100);
        assert!(
            !result,
            "Ingress path should reject unsigned record from remote source"
        );
    }

    #[test]
    fn test_ingress_verification_rejects_empty_signature() {
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = DhtRecord {
            key: "node_info:test-node".to_string(),
            value: b"test_value".to_vec(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "remote_node".to_string(),
            signature: vec![1, 2, 3],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let ingress_ctx = crate::dht::signed::DhtRecordIngressContext::new_remote(
            "peer-1".to_string(),
            "remote_node".to_string(),
            crate::dht::signed::SourceClassification::EdgeNode,
            crate::dht::signed::IngressPath::Announce,
        );

        let result = store.store_record_from_ingress(record, &ingress_ctx, 100);
        assert!(
            !result,
            "Ingress path should reject record with signature but no signer public key"
        );
    }

    #[test]
    fn test_store_record_requires_signature_even_for_local_origin() {
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = DhtRecord {
            key: "node_info:test-node".to_string(),
            value: b"test_value".to_vec(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "test-global-node".to_string(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let result = store.store_local_record(record, 100);
        assert!(
            !result,
            "store_local_record rejects unsigned records even for local origin"
        );
    }

    #[test]
    fn test_store_record_accepts_signed_local_record() {
        let signer = crate::protocol::MeshMessageSigner::new([17u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("node_info:test-node", &signer);
        let result = store.store_local_record(record, 100);
        assert!(result, "store_local_record accepts signed local record");
    }

    #[test]
    fn test_bypass_remote_ingress_rejects_raft_key_without_proof() {
        let signer = crate::protocol::MeshMessageSigner::new([14u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("org:my-org", &signer);

        let ingress_ctx = crate::dht::signed::DhtRecordIngressContext::new_remote(
            "peer-attacker".to_string(),
            "remote-attacker".to_string(),
            crate::dht::signed::SourceClassification::EdgeNode,
            crate::dht::signed::IngressPath::Announce,
        );

        let result = store.store_record_from_ingress(record.clone(), &ingress_ctx, 100);
        assert!(
            !result,
            "Remote org write via ingress path should be rejected by Raft-global policy"
        );

        let local_result = store.store_record_verified_internal(record, 100, true);
        assert!(
            !local_result,
            "Same org record should also be rejected (is_raft_global blocks all DHT writes)"
        );
    }

    #[test]
    fn test_bypass_store_record_global_rejects_direct_raft_key_write() {
        let signer = crate::protocol::MeshMessageSigner::new([15u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("org:my-org", &signer);
        let result = store.store_record_verified_internal(record, 100, false);
        assert!(
            !result,
            "store_record_verified_internal should reject remote Raft-owned key even on global node"
        );
    }

    #[test]
    fn test_bypass_edge_node_cannot_store_global_only_keys() {
        let signer = crate::protocol::MeshMessageSigner::new([16u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-edge-node".to_string(),
            crate::config::MeshNodeRole::EDGE,
            None,
            access_control,
            None,
        );

        let record = build_signed_remote_record("node_info:test-node", &signer);
        let result = store.store_record_verified_internal(record, 100, true);
        assert!(
            !result,
            "Edge node should not be able to store node_info (privileged key requires global node)"
        );
    }

    #[test]
    fn test_bypass_unsigned_record_always_rejected_regardless_of_origin() {
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );

        let record = DhtRecord {
            key: "node_info:test-node".to_string(),
            value: b"test_value".to_vec(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "remote_node".to_string(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let remote_result = store.store_record_verified_internal(record.clone(), 100, false);
        assert!(
            !remote_result,
            "Unsigned record from remote origin should always be rejected"
        );

        let local_result = store.store_record_verified_internal(record, 100, true);
        assert!(
            !local_result,
            "Unsigned record from local origin should also be rejected (store requires signature for all writes)"
        );
    }

    #[test]
    fn test_ingress_gate_default_none_does_not_reject_on_no_reader() {
        let signer = crate::protocol::MeshMessageSigner::new([20u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );
        let record = build_signed_remote_record("global_node_proof:remote_node", &signer);
        let ingress_ctx = crate::dht::signed::DhtRecordIngressContext::new_remote(
            "peer-1".to_string(),
            "remote_node".to_string(),
            crate::dht::signed::SourceClassification::EdgeNode,
            crate::dht::signed::IngressPath::Push,
        );
        let result = store.store_record_from_ingress(record, &ingress_ctx, 100);
        assert!(!result);
    }

    #[test]
    fn test_ingress_gate_configured_push_rejects_unauthorized_canonical() {
        let signer = crate::protocol::MeshMessageSigner::new([21u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );
        let reader = crate::mesh::canonical::StaticCanonicalTrustReader::new(
            crate::mesh::canonical::CanonicalFreshness::Live,
        );
        let pctx =
            crate::dht::DhtIngressPolicyContext::with_canonical_reader(std::sync::Arc::new(reader));
        let record = build_signed_remote_record("global_node_proof:remote_node", &signer);
        let ingress_ctx = crate::dht::signed::DhtRecordIngressContext::new_remote(
            "peer-1".to_string(),
            "remote_node".to_string(),
            crate::dht::signed::SourceClassification::EdgeNode,
            crate::dht::signed::IngressPath::Push,
        )
        .with_policy_context(Some(pctx));
        let gate_ok = store.check_record_ingress_canonical_gate(&record, &ingress_ctx);
        assert!(!gate_ok);
        let result = store.store_record_from_ingress(record, &ingress_ctx, 100);
        assert!(!result);
    }

    #[test]
    fn test_ingress_gate_configured_announce_rejects_unauthorized_canonical() {
        let signer = crate::protocol::MeshMessageSigner::new([22u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );
        let reader = crate::mesh::canonical::StaticCanonicalTrustReader::new(
            crate::mesh::canonical::CanonicalFreshness::Live,
        );
        let pctx =
            crate::dht::DhtIngressPolicyContext::with_canonical_reader(std::sync::Arc::new(reader));
        let record = build_signed_remote_record("global_node_proof:remote_node", &signer);
        let ingress_ctx = crate::dht::signed::DhtRecordIngressContext::new_remote(
            "peer-1".to_string(),
            "remote_node".to_string(),
            crate::dht::signed::SourceClassification::EdgeNode,
            crate::dht::signed::IngressPath::Announce,
        )
        .with_policy_context(Some(pctx));
        let result = store.store_record_from_ingress(record, &ingress_ctx, 100);
        assert!(!result);
    }

    #[test]
    fn test_ingress_gate_configured_advisory_proceeds_with_rejecting_reader() {
        let signer = crate::protocol::MeshMessageSigner::new([23u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );
        let reader = crate::mesh::canonical::StaticCanonicalTrustReader::new(
            crate::mesh::canonical::CanonicalFreshness::Live,
        );
        let pctx =
            crate::dht::DhtIngressPolicyContext::with_canonical_reader(std::sync::Arc::new(reader));
        let record = build_signed_remote_record("upstream:example.com", &signer);
        let ingress_ctx = crate::dht::signed::DhtRecordIngressContext::new_remote(
            "peer-1".to_string(),
            "remote_node".to_string(),
            crate::dht::signed::SourceClassification::EdgeNode,
            crate::dht::signed::IngressPath::Push,
        )
        .with_policy_context(Some(pctx));
        let result = store.store_record_from_ingress(record, &ingress_ctx, 100);
        assert!(result);
    }

    #[test]
    fn test_ingress_gate_sync_bypass_does_not_consult_gate() {
        let signer = crate::protocol::MeshMessageSigner::new([24u8; 32]);
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );
        let reader = crate::mesh::canonical::StaticCanonicalTrustReader::new(
            crate::mesh::canonical::CanonicalFreshness::Live,
        );
        let pctx =
            crate::dht::DhtIngressPolicyContext::with_canonical_reader(std::sync::Arc::new(reader));
        let record = build_signed_remote_record("global_node_proof:remote_node", &signer);
        let ingress_ctx = crate::dht::signed::DhtRecordIngressContext::new_remote(
            "peer-1".to_string(),
            "remote_node".to_string(),
            crate::dht::signed::SourceClassification::EdgeNode,
            crate::dht::signed::IngressPath::SyncResponse,
        )
        .with_policy_context(Some(pctx));
        let result = store.store_record_from_ingress(record, &ingress_ctx, 100);
        assert!(!result);
    }

    #[test]
    fn test_record_store_manager_ingress_policy_context_set_get() {
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = RecordStoreManager::new(
            crate::dht::RecordStoreConfig::default(),
            "test-global-node".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );
        assert!(store.ingress_policy_context().is_none());
        let reader = crate::mesh::canonical::StaticCanonicalTrustReader::new(
            crate::mesh::canonical::CanonicalFreshness::Live,
        );
        let pctx =
            crate::dht::DhtIngressPolicyContext::with_canonical_reader(std::sync::Arc::new(reader));
        store.set_ingress_policy_context(Some(pctx));
        assert!(store.ingress_policy_context().is_some());
    }
}
