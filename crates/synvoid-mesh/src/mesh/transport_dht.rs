#![allow(dead_code)]
// SAFETY_REASON: Reserved for future DHT protocol handling

use std::time::{Duration, Instant};

use crate::transport::MeshTransport;
use base64::Engine;
use ed25519_dalek::Verifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DhtSyncAuthMode {
    Signed,
    UnsignedAllowed,
    UnsignedRejected,
}

fn classify_dht_sync_auth_mode(
    signature: &[u8],
    signer_public_key: Option<&str>,
    require_signed_sync_requests: bool,
    unsigned_sync_compat_until_unix: Option<u64>,
    now_unix: u64,
) -> DhtSyncAuthMode {
    let has_auth = !signature.is_empty() && signer_public_key.is_some_and(|s| !s.is_empty());
    if has_auth {
        DhtSyncAuthMode::Signed
    } else if unsigned_sync_compat_until_unix.is_some_and(|deadline| now_unix >= deadline) {
        DhtSyncAuthMode::UnsignedRejected
    } else if require_signed_sync_requests {
        DhtSyncAuthMode::UnsignedRejected
    } else {
        DhtSyncAuthMode::UnsignedAllowed
    }
}

fn verify_dht_sync_request_signature(
    request_id: &str,
    node_id: &str,
    from_version: u64,
    timestamp: u64,
    nonce: &str,
    signature: &[u8],
    signer_public_key: Option<&str>,
) -> bool {
    let Some(signer_public_key) = signer_public_key else {
        return false;
    };
    let content = crate::dht::signed::get_sync_request_signable_content(
        request_id,
        node_id,
        from_version,
        timestamp,
        nonce,
    );
    match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signer_public_key) {
        Ok(pk_bytes) if pk_bytes.len() == 32 && signature.len() == 64 => {
            let mut pk_array = [0u8; 32];
            pk_array.copy_from_slice(&pk_bytes);
            let mut sig_array = [0u8; 64];
            sig_array.copy_from_slice(signature);
            match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
                Ok(pk) => pk
                    .verify(&content, &ed25519_dalek::Signature::from_bytes(&sig_array))
                    .is_ok(),
                Err(_) => false,
            }
        }
        _ => false,
    }
}

fn verify_dht_anti_entropy_request_signature(
    request_id: &str,
    node_id: &str,
    local_root_hash: &[u8],
    timestamp: u64,
    nonce: &str,
    signature: &[u8],
    signer_public_key: Option<&str>,
) -> bool {
    crate::dht::signed::verify_dht_anti_entropy_request_envelope_signature(
        request_id,
        node_id,
        local_root_hash,
        timestamp,
        nonce,
        signature,
        signer_public_key,
    )
}

fn replay_result_reason(replay_result: crate::protocol::ReplayResult) -> &'static str {
    match replay_result {
        crate::protocol::ReplayResult::FutureTimestamp => "future_timestamp",
        crate::protocol::ReplayResult::ExpiredTimestamp => "expired_timestamp",
        crate::protocol::ReplayResult::ReplayDetected => "replay_detected",
        crate::protocol::ReplayResult::Valid => "valid",
    }
}

impl MeshTransport {
    /// Verify that the envelope signer's public key matches the authorized key
    /// for the claimed node identity. Only enforced on global nodes.
    pub(crate) fn verify_signer_node_binding(
        &self,
        claimed_node_id: &str,
        signer_public_key: Option<&str>,
        context: &str,
    ) -> bool {
        if !self.config.role.is_global() {
            return true;
        }
        let Some(pk_str) = signer_public_key else {
            return true;
        };
        if pk_str.is_empty() {
            return true;
        }
        let Ok(pk_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pk_str) else {
            return true;
        };
        let cert_mgr = self.cert_manager.read();
        if let Some(expected_key) = cert_mgr.get_global_node_key(claimed_node_id) {
            if pk_bytes != expected_key {
                tracing::warn!(
                    "{} rejected: signer_public_key does not match authorized key for node {}",
                    context,
                    claimed_node_id
                );
                return false;
            }
        }
        true
    }

    pub(crate) async fn handle_dht_snapshot_request(
        &self,
        from_peer: &str,
        request_id: &str,
        _node_id: &str,
        from_version: u64,
        signature: &[u8],
        signer_public_key: &str,
    ) {
        tracing::debug!(
            "Received DHT snapshot request from {} (from_version: {})",
            from_peer,
            from_version
        );

        let now = Instant::now();
        let window = Duration::from_secs(crate::transport::SNAPSHOT_REQUEST_RATE_LIMIT_WINDOW_SECS);
        {
            let mut times = self.snapshot_request_times.write();
            let peer_times = times.entry(from_peer.to_string()).or_insert_with(Vec::new);
            peer_times.retain(|&t| now.duration_since(t) < window);
            if peer_times.len() >= crate::transport::MAX_SNAPSHOT_REQUESTS_PER_WINDOW {
                tracing::warn!(
                    "DHT snapshot request rate limit exceeded for peer {}",
                    from_peer
                );
                return;
            }
            peer_times.push(now);
        }

        if signature.is_empty() || signer_public_key.is_empty() {
            tracing::warn!(
                "DHT snapshot request from {} rejected: missing signature ({}) or public key ({})",
                from_peer,
                signature.is_empty(),
                signer_public_key.is_empty()
            );
            return;
        }

        if let Some(ref stake_manager) = self.stake_manager {
            if !stake_manager.can_read_dht(signer_public_key) {
                tracing::warn!(
                    "DHT snapshot request from {} rejected: insufficient stake",
                    from_peer
                );
                return;
            }
        }

        let signature_valid = {
            let timestamp = crate::protocol::MeshMessage::generate_timestamp();
            let content = crate::dht::signed::get_snapshot_request_signable_content(
                request_id,
                _node_id,
                from_version,
                timestamp,
            );
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signer_public_key) {
                Ok(pk_bytes) if pk_bytes.len() == 32 && signature.len() == 64 => {
                    let mut pk_array = [0u8; 32];
                    pk_array.copy_from_slice(&pk_bytes);
                    let mut sig_array = [0u8; 64];
                    sig_array.copy_from_slice(signature);
                    match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
                        Ok(pk) => pk
                            .verify(&content, &ed25519_dalek::Signature::from_bytes(&sig_array))
                            .is_ok(),
                        Err(_) => false,
                    }
                }
                _ => false,
            }
        };

        if !signature_valid {
            tracing::warn!(
                "DHT snapshot request from {} rejected: invalid signature",
                from_peer
            );
            return;
        }

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
        request_id: &str,
        records: Vec<crate::protocol::DhtRecord>,
        version: u64,
        timestamp: u64,
        signature: &[u8],
        signer_public_key: &str,
    ) {
        tracing::debug!(
            "Received DHT snapshot response from {} ({} records, version: {})",
            from_peer,
            records.len(),
            version
        );

        if signature.is_empty() || signer_public_key.is_empty() {
            tracing::warn!(
                "DHT snapshot response from {} rejected: missing signature ({}) or public key ({})",
                from_peer,
                signature.is_empty(),
                signer_public_key.is_empty()
            );
            return;
        }

        if !crate::dht::signed::validate_message_timestamp(timestamp) {
            tracing::warn!(
                "DHT snapshot response from {} rejected: timestamp too old or too far in future",
                from_peer
            );
            return;
        }

        let record_set_digest = crate::dht::signed::compute_record_set_digest(&records);

        let signature_valid = {
            let content = crate::dht::signed::get_snapshot_signable_content(
                request_id,
                from_peer,
                version,
                records.len(),
                timestamp,
                &record_set_digest,
            );
            if content.is_empty() {
                false
            } else {
                match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signer_public_key) {
                    Ok(pk_bytes) if pk_bytes.len() == 32 && signature.len() == 64 => {
                        let mut pk_array = [0u8; 32];
                        pk_array.copy_from_slice(&pk_bytes);
                        let mut sig_array = [0u8; 64];
                        sig_array.copy_from_slice(signature);
                        match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
                            Ok(pk) => pk
                                .verify(&content, &ed25519_dalek::Signature::from_bytes(&sig_array))
                                .is_ok(),
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        };

        if !signature_valid {
            tracing::warn!(
                "DHT snapshot response from {} rejected: invalid signature",
                from_peer
            );
            return;
        }

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            let applied =
                record_store.verify_and_apply_snapshot(records, version, signer, from_peer);
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
        records: Vec<crate::protocol::DhtRecord>,
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
        timestamp: u64,
        nonce: &str,
        signature: &[u8],
        signer_public_key: Option<&str>,
    ) {
        tracing::debug!(
            "Received DHT sync request from {} (node: {}, from_version: {})",
            from_peer,
            node_id,
            from_version
        );

        let require_signed_sync_requests = self
            .config
            .dht
            .as_ref()
            .map(|d| d.require_signed_sync_requests)
            .unwrap_or(true);
        let unsigned_sync_compat_until_unix = self
            .config
            .dht
            .as_ref()
            .and_then(|d| d.unsigned_sync_compat_until_unix);
        let now_unix = synvoid_utils::safe_unix_timestamp();
        match classify_dht_sync_auth_mode(
            signature,
            signer_public_key,
            require_signed_sync_requests,
            unsigned_sync_compat_until_unix,
            now_unix,
        ) {
            DhtSyncAuthMode::UnsignedRejected => {
                tracing::warn!(
                    "DHT sync request from {} rejected: unsigned request not allowed (require_signed_sync_requests={}, compat_until={:?}, now={})",
                    from_peer,
                    require_signed_sync_requests,
                    unsigned_sync_compat_until_unix,
                    now_unix
                );
                return;
            }
            DhtSyncAuthMode::UnsignedAllowed => {
                tracing::warn!(
                    "DHT sync request from {} has no auth fields; accepting because mesh.dht.require_signed_sync_requests=false",
                    from_peer
                );
            }
            DhtSyncAuthMode::Signed => {
                if nonce.is_empty() {
                    tracing::warn!(
                        "DHT sync request from {} rejected: nonce is empty",
                        from_peer
                    );
                    return;
                }

                if !crate::dht::signed::validate_message_timestamp(timestamp) {
                    tracing::warn!(
                        "DHT sync request from {} rejected: timestamp too old or too far in future",
                        from_peer
                    );
                    return;
                }

                let replay_state = self
                    .peer_connections
                    .get(from_peer)
                    .map(|conn| conn.replay_protection.clone());
                if let Some(replay_protection) = replay_state {
                    let replay_result = replay_protection
                        .write()
                        .await
                        .check_and_add(nonce, timestamp);
                    if !matches!(replay_result, crate::protocol::ReplayResult::Valid) {
                        tracing::warn!(
                            "DHT sync request from {} rejected: replay protection {}",
                            from_peer,
                            replay_result_reason(replay_result)
                        );
                        return;
                    }
                }

                let signature_valid = verify_dht_sync_request_signature(
                    request_id,
                    node_id,
                    from_version,
                    timestamp,
                    nonce,
                    signature,
                    signer_public_key,
                );

                if !signature_valid {
                    tracing::warn!(
                        "DHT sync request from {} rejected: invalid signature",
                        from_peer
                    );
                    return;
                }

                if !self.verify_signer_node_binding(
                    node_id,
                    signer_public_key,
                    "DHT sync request",
                ) {
                    return;
                }
            }
        }

        // MESH-14: If require_pki_binding, verify node has a cert binding
        if self.config.tls.require_pki_binding {
            if self.cert_manager.read().get_cert_binding(node_id).is_none() {
                tracing::warn!(
                    "DHT sync request from {} rejected: no cert binding for node {} (require_pki_binding=true)",
                    from_peer, node_id
                );
                return;
            }
        }

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
        request_id: &str,
        records: Vec<crate::protocol::DhtRecord>,
        version: u64,
        timestamp: u64,
        signature: &[u8],
        signer_public_key: Option<&str>,
    ) {
        tracing::debug!(
            "Received DHT sync response from {} ({} records, signer: {:?})",
            from_peer,
            records.len(),
            signer_public_key
        );

        if signature.is_empty() || signer_public_key.map_or(true, |s| s.is_empty()) {
            tracing::warn!(
                "DHT sync response from {} rejected: missing signature ({}) or public key ({})",
                from_peer,
                signature.is_empty(),
                signer_public_key.map_or(true, |s| s.is_empty())
            );
            return;
        }

        if !crate::dht::signed::validate_message_timestamp(timestamp) {
            tracing::warn!(
                "DHT sync response from {} rejected: timestamp too old or too far in future",
                from_peer
            );
            return;
        }

        let record_set_digest = crate::dht::signed::compute_record_set_digest(&records);

        let signature_valid = {
            let content = crate::dht::signed::get_sync_signable_content(
                request_id,
                from_peer,
                from_peer,
                version,
                records.len(),
                timestamp,
                &record_set_digest,
            );
            if content.is_empty() {
                false
            } else {
                match base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(signer_public_key.unwrap_or_default())
                {
                    Ok(pk_bytes) if pk_bytes.len() == 32 && signature.len() == 64 => {
                        let mut pk_array = [0u8; 32];
                        pk_array.copy_from_slice(&pk_bytes);
                        let mut sig_array = [0u8; 64];
                        sig_array.copy_from_slice(signature);
                        match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
                            Ok(pk) => pk
                                .verify(&content, &ed25519_dalek::Signature::from_bytes(&sig_array))
                                .is_ok(),
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        };

        if !signature_valid {
            tracing::warn!(
                "DHT sync response from {} rejected: invalid signature",
                from_peer
            );
            return;
        }

        if !self.verify_signer_node_binding(
            from_peer,
            signer_public_key,
            "DHT sync response",
        ) {
            return;
        }

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            record_store.handle_sync_response_verified(records, from_peer, signer);
        }
    }

    pub(crate) async fn handle_dht_anti_entropy_request(
        &self,
        from_peer: &str,
        request_id: &str,
        node_id: &str,
        local_root_hash: &[u8],
        interested_keys: &[String],
        timestamp: u64,
        nonce: &str,
        signature: &[u8],
        signer_public_key: Option<&str>,
    ) {
        tracing::debug!(
            "Received DHT anti-entropy request from {} ({} interested keys)",
            from_peer,
            interested_keys.len()
        );

        if !crate::dht::signed::validate_message_timestamp(timestamp) {
            tracing::warn!(
                "DHT anti-entropy request from {} rejected: timestamp too old or too far in future",
                from_peer
            );
            return;
        }

        let require_signed = self
            .config
            .dht
            .as_ref()
            .map(|d| d.require_signed_anti_entropy_requests)
            .unwrap_or(true);
        let compat_until = self
            .config
            .dht
            .as_ref()
            .and_then(|d| d.unsigned_anti_entropy_compat_until_unix);
        let now_unix = synvoid_utils::safe_unix_timestamp();
        let has_auth = !signature.is_empty()
            && signer_public_key.is_some_and(|s| !s.is_empty())
            && !nonce.is_empty();
        if !has_auth {
            let compat_active = compat_until.is_some_and(|deadline| now_unix < deadline);
            if require_signed && !compat_active {
                tracing::warn!(
                    "DHT anti-entropy request from {} rejected: missing envelope signature/nonce (require_signed_anti_entropy_requests={}, compat_until={:?}, now={})",
                    from_peer,
                    require_signed,
                    compat_until,
                    now_unix
                );
                return;
            }
            tracing::warn!(
                "DHT anti-entropy request from {} accepted without signature (legacy compat window active or signing disabled)",
                from_peer
            );
        } else {
            if !verify_dht_anti_entropy_request_signature(
                request_id,
                node_id,
                local_root_hash,
                timestamp,
                nonce,
                signature,
                signer_public_key,
            ) {
                tracing::warn!(
                    "DHT anti-entropy request from {} rejected: invalid envelope signature",
                    from_peer
                );
                return;
            }

            // Phase 3: Verify signer_public_key matches the claimed node_id
            // against authorized global node keys (binds L2 envelope signer to L4 node identity)
            if !self.verify_signer_node_binding(
                node_id,
                signer_public_key,
                "DHT anti-entropy request",
            ) {
                return;
            }
        }

        let replay_state = self
            .peer_connections
            .get(from_peer)
            .map(|conn| conn.replay_protection.clone());
        if let Some(replay_protection) = replay_state {
            let replay_result = replay_protection
                .write()
                .await
                .check_and_add(nonce, timestamp);
            if !matches!(replay_result, crate::protocol::ReplayResult::Valid) {
                tracing::warn!(
                    "DHT anti-entropy request from {} rejected: replay protection {}",
                    from_peer,
                    replay_result_reason(replay_result)
                );
                return;
            }
        }

        // MESH-14: If require_pki_binding, verify node has a cert binding
        if self.config.tls.require_pki_binding {
            if self.cert_manager.read().get_cert_binding(node_id).is_none() {
                tracing::warn!(
                    "DHT anti-entropy request from {} rejected: no cert binding for node {} (require_pki_binding=true)",
                    from_peer, node_id
                );
                return;
            }
        }

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
        missing_records: Vec<crate::protocol::DhtRecord>,
        timestamp: u64,
        signature: &[u8],
        signer_public_key: Option<&str>,
    ) {
        tracing::debug!(
            "Received DHT anti-entropy response from {} ({} missing records)",
            from_peer,
            missing_records.len()
        );

        if missing_records.is_empty() {
            return;
        }

        if !crate::dht::signed::validate_message_timestamp(timestamp) {
            tracing::warn!(
                "DHT anti-entropy response from {} rejected: timestamp too old or too far in future",
                from_peer
            );
            return;
        }

        if signature.is_empty() {
            tracing::warn!(
                "DHT anti-entropy response from {} rejected: missing envelope signature",
                from_peer
            );
            return;
        }

        if !self.verify_signer_node_binding(
            from_peer,
            signer_public_key,
            "DHT anti-entropy response",
        ) {
            return;
        }

        tracing::debug!(
            "DHT anti-entropy response from {} has valid timestamp and signature",
            from_peer
        );

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

        let target_id = match crate::dht::routing::NodeId::from_bytes(&target_node_id) {
            Some(id) => id,
            None => {
                tracing::warn!("Invalid target_node_id in FindNode from {}", from_peer);
                return;
            }
        };

        let closest_peers = routing_manager
            .find_closest_to_node_id(&target_id, 20)
            .await;

        let response = crate::protocol::MeshMessage::FindNodeResponse {
            request_id: request_id.into(),
            peers: closest_peers,
            responder_node_id: self.config.node_id().into(),
            timestamp: crate::protocol::MeshMessage::generate_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send FindNodeResponse to {}: {}", from_peer, e);
        }
    }

    pub(crate) async fn handle_find_node_response(
        &self,
        from_peer: &str,
        peers: Vec<crate::dht::routing::PeerContact>,
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
                        crate::config::MeshNodeRole::GLOBAL
                    } else {
                        crate::config::MeshNodeRole::EDGE
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
                let mut all_failed = true;
                for peer_id in &global_nodes {
                    tracing::info!("DHT cache stale, requesting resync from {}", peer_id);
                    if self.send_datagram_to_peer(peer_id, &request).await.is_ok() {
                        all_failed = false;
                        break;
                    }
                    tracing::warn!("Failed to request DHT resync from {}", peer_id);
                }
                if all_failed {
                    tracing::warn!("DHT resync failed: all global nodes unreachable");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_dht_sync_auth_mode, replay_result_reason,
        verify_dht_anti_entropy_request_signature, verify_dht_sync_request_signature,
        DhtSyncAuthMode,
    };
    use crate::dht::signed::{
        verify_dht_record_push_envelope_signature_bytes, DhtRecordPushEnvelopeSignable,
    };
    use crate::protocol::MeshMessageSigner;

    #[test]
    fn test_classify_sync_auth_signed_when_signature_and_key_present() {
        let mode = classify_dht_sync_auth_mode(&[1u8; 64], Some("key"), true, None, 100);
        assert_eq!(mode, DhtSyncAuthMode::Signed);
    }

    #[test]
    fn test_classify_sync_auth_unsigned_rejected_when_required() {
        let mode = classify_dht_sync_auth_mode(&[], None, true, None, 100);
        assert_eq!(mode, DhtSyncAuthMode::UnsignedRejected);
    }

    #[test]
    fn test_classify_sync_auth_unsigned_allowed_when_not_required() {
        let mode = classify_dht_sync_auth_mode(&[], None, false, None, 100);
        assert_eq!(mode, DhtSyncAuthMode::UnsignedAllowed);
    }

    #[test]
    fn test_classify_sync_auth_legacy_unsigned_compatibility_mode() {
        let mode = classify_dht_sync_auth_mode(&[], Some(""), false, Some(150), 100);
        assert_eq!(mode, DhtSyncAuthMode::UnsignedAllowed);
    }

    #[test]
    fn test_classify_sync_auth_treats_empty_public_key_as_unsigned() {
        let mode = classify_dht_sync_auth_mode(&[1u8; 64], Some(""), true, None, 100);
        assert_eq!(mode, DhtSyncAuthMode::UnsignedRejected);
    }

    #[test]
    fn test_classify_sync_auth_compat_window_expired_rejects_unsigned() {
        let mode = classify_dht_sync_auth_mode(&[], None, false, Some(100), 101);
        assert_eq!(mode, DhtSyncAuthMode::UnsignedRejected);
    }

    #[test]
    fn test_classify_sync_auth_compat_window_at_deadline_rejects_unsigned() {
        let mode = classify_dht_sync_auth_mode(&[], None, false, Some(100), 100);
        assert_eq!(mode, DhtSyncAuthMode::UnsignedRejected);
    }

    #[test]
    fn test_verify_sync_request_signature_rejects_tampered_signature() {
        let signer = MeshMessageSigner::new([42u8; 32]);
        let request_id = "req-1";
        let node_id = "node-a";
        let from_version = 10;
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "nonce-a";
        let content = crate::dht::signed::get_sync_request_signable_content(
            request_id,
            node_id,
            from_version,
            timestamp,
            nonce,
        );
        let mut signature = signer.sign(&content);
        signature[0] ^= 0x01;
        let valid = verify_dht_sync_request_signature(
            request_id,
            node_id,
            from_version,
            timestamp,
            nonce,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(!valid);
    }

    #[test]
    fn test_verify_sync_request_signature_accepts_valid_signature() {
        let signer = MeshMessageSigner::new([24u8; 32]);
        let request_id = "req-2";
        let node_id = "node-b";
        let from_version = 11;
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "nonce-b";
        let content = crate::dht::signed::get_sync_request_signable_content(
            request_id,
            node_id,
            from_version,
            timestamp,
            nonce,
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_sync_request_signature(
            request_id,
            node_id,
            from_version,
            timestamp,
            nonce,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(valid);
    }

    #[test]
    fn test_replay_result_reason_replay_detected() {
        assert_eq!(
            replay_result_reason(crate::protocol::ReplayResult::ReplayDetected),
            "replay_detected"
        );
    }

    #[test]
    fn test_replay_protection_rejects_duplicate_nonce_at_same_timestamp() {
        let mut replay = crate::protocol::ReplayProtection::new();
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let first = replay.check_and_add("dup-nonce", timestamp);
        let second = replay.check_and_add("dup-nonce", timestamp);
        assert!(matches!(first, crate::protocol::ReplayResult::Valid));
        assert!(matches!(
            second,
            crate::protocol::ReplayResult::ReplayDetected
        ));
    }

    #[test]
    fn test_replay_protection_rejects_expired_timestamp() {
        let mut replay = crate::protocol::ReplayProtection::new();
        let stale = synvoid_utils::safe_unix_timestamp()
            .saturating_sub(crate::protocol::REPLAY_WINDOW_SECS + 1);
        let result = replay.check_and_add("stale-nonce", stale);
        assert!(matches!(
            result,
            crate::protocol::ReplayResult::ExpiredTimestamp
        ));
    }

    #[test]
    fn test_replay_protection_rejects_future_timestamp() {
        let mut replay = crate::protocol::ReplayProtection::new();
        let future = synvoid_utils::safe_unix_timestamp().saturating_add(61);
        let result = replay.check_and_add("future-nonce", future);
        assert!(matches!(
            result,
            crate::protocol::ReplayResult::FutureTimestamp
        ));
    }

    #[test]
    fn test_verify_anti_entropy_request_signature_accepts_valid_signature() {
        let signer = MeshMessageSigner::new([7u8; 32]);
        let request_id = "anti-req-1";
        let node_id = "node-x";
        let local_root_hash: Vec<u8> = vec![1, 2, 3, 4];
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "anti-nonce-1";
        let content = crate::dht::signed::get_anti_entropy_request_signable_content(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_anti_entropy_request_signature(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(valid);
    }

    #[test]
    fn test_verify_anti_entropy_request_signature_rejects_tampered_signature() {
        let signer = MeshMessageSigner::new([8u8; 32]);
        let request_id = "anti-req-2";
        let node_id = "node-y";
        let local_root_hash: Vec<u8> = vec![5, 6, 7, 8];
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "anti-nonce-2";
        let content = crate::dht::signed::get_anti_entropy_request_signable_content(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
        );
        let mut signature = signer.sign(&content);
        signature[0] ^= 0x01;
        let valid = verify_dht_anti_entropy_request_signature(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(!valid);
    }

    #[test]
    fn test_verify_anti_entropy_request_signature_rejects_missing_public_key() {
        let signer = MeshMessageSigner::new([9u8; 32]);
        let request_id = "anti-req-3";
        let node_id = "node-z";
        let local_root_hash: Vec<u8> = vec![9, 9, 9];
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "anti-nonce-3";
        let content = crate::dht::signed::get_anti_entropy_request_signable_content(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_anti_entropy_request_signature(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
            &signature,
            None,
        );
        assert!(!valid, "missing public key must reject");
    }

    #[test]
    fn test_verify_anti_entropy_request_signature_rejects_empty_nonce() {
        let signer = MeshMessageSigner::new([10u8; 32]);
        let request_id = "anti-req-4";
        let node_id = "node-w";
        let local_root_hash: Vec<u8> = vec![0, 0, 0, 1];
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let content = crate::dht::signed::get_anti_entropy_request_signable_content(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            "",
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_anti_entropy_request_signature(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            "",
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(!valid, "empty nonce must reject");
    }

    fn build_dht_record(key: &str, value: &[u8]) -> crate::protocol::DhtRecord {
        crate::protocol::DhtRecord {
            key: key.to_string(),
            value: value.to_vec(),
            timestamp: 1,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node-r".to_string(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        }
    }

    #[test]
    fn test_verify_record_push_envelope_signature_accepts_valid_signature() {
        let signer = MeshMessageSigner::new([11u8; 32]);
        let request_id = "push-req-1";
        let node_id = "node-r";
        let records = vec![build_dht_record("org:test", b"v")];
        let hop_count = 1;
        let nonce = "push-nonce-1";
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let content = crate::dht::signed::get_dht_record_push_envelope_signable_content(
            request_id, node_id, &records, hop_count, nonce, timestamp,
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_record_push_envelope_signature_bytes(
            request_id,
            node_id,
            &records,
            hop_count,
            nonce,
            timestamp,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(valid);
    }

    #[test]
    fn test_verify_record_push_envelope_signature_rejects_tampered_record() {
        let signer = MeshMessageSigner::new([12u8; 32]);
        let request_id = "push-req-2";
        let node_id = "node-r";
        let records = vec![build_dht_record("org:test", b"v")];
        let hop_count = 1;
        let nonce = "push-nonce-2";
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let content = crate::dht::signed::get_dht_record_push_envelope_signable_content(
            request_id, node_id, &records, hop_count, nonce, timestamp,
        );
        let signature = signer.sign(&content);
        let mut tampered = records.clone();
        tampered[0].value = b"tampered".to_vec();
        let valid = verify_dht_record_push_envelope_signature_bytes(
            request_id,
            node_id,
            &tampered,
            hop_count,
            nonce,
            timestamp,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(!valid, "tampered record set must reject");
    }

    #[test]
    fn test_verify_record_push_envelope_signature_rejects_missing_nonce() {
        let signer = MeshMessageSigner::new([13u8; 32]);
        let request_id = "push-req-3";
        let node_id = "node-r";
        let records = vec![build_dht_record("org:test", b"v")];
        let hop_count = 1;
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let content = crate::dht::signed::get_dht_record_push_envelope_signable_content(
            request_id, node_id, &records, hop_count, "", timestamp,
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_record_push_envelope_signature_bytes(
            request_id,
            node_id,
            &records,
            hop_count,
            "",
            timestamp,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(!valid, "missing nonce must reject");
    }

    #[test]
    fn test_verify_record_push_envelope_signature_rejects_missing_signature() {
        let signer = MeshMessageSigner::new([14u8; 32]);
        let request_id = "push-req-4";
        let node_id = "node-r";
        let records = vec![build_dht_record("org:test", b"v")];
        let hop_count = 1;
        let nonce = "push-nonce-4";
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let valid = verify_dht_record_push_envelope_signature_bytes(
            request_id,
            node_id,
            &records,
            hop_count,
            nonce,
            timestamp,
            &[],
            Some(&signer.get_public_key()),
        );
        assert!(!valid, "missing signature must reject");
    }

    #[test]
    fn test_record_push_envelope_signable_content_changes_with_nonce() {
        let request_id = "push-req-5";
        let node_id = "node-r";
        let records = vec![build_dht_record("org:test", b"v")];
        let hop_count = 1;
        let timestamp = 1u64;
        let a = crate::dht::signed::get_dht_record_push_envelope_signable_content(
            request_id, node_id, &records, hop_count, "nonce-a", timestamp,
        );
        let b = crate::dht::signed::get_dht_record_push_envelope_signable_content(
            request_id, node_id, &records, hop_count, "nonce-b", timestamp,
        );
        assert_ne!(
            a, b,
            "different nonces must produce different signable content"
        );
    }

    #[test]
    fn test_dht_record_push_envelope_signable_uses_protocol_version() {
        let request_id = "push-req-6";
        let node_id = "node-r";
        let records = vec![build_dht_record("org:test", b"v")];
        let hop_count = 1;
        let nonce = "nonce-x";
        let timestamp = 1u64;
        let mut record_keys: Vec<&str> = records.iter().map(|r| r.key.as_str()).collect();
        record_keys.sort();
        let record_set_digest = crate::dht::signed::compute_record_set_digest(&records);
        let content = crate::dht::signed::get_dht_record_push_envelope_signable_content(
            request_id, node_id, &records, hop_count, nonce, timestamp,
        );
        let direct = synvoid_utils::serialization::serialize(&DhtRecordPushEnvelopeSignable {
            request_id,
            node_id,
            record_keys,
            record_set_digest: &record_set_digest,
            hop_count,
            nonce,
            timestamp,
            protocol_version: crate::dht::signed::DHT_RECORD_PUSH_PROTOCOL_VERSION,
        })
        .unwrap_or_default();
        assert_eq!(content, direct);
    }

    #[test]
    fn test_verify_anti_entropy_request_signature_rejects_wrong_signer_key() {
        let signer_a = MeshMessageSigner::new([1u8; 32]);
        let signer_b = MeshMessageSigner::new([2u8; 32]);
        let request_id = "anti-req-wrong-key";
        let node_id = "node-x";
        let local_root_hash: Vec<u8> = vec![1, 2, 3, 4];
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "anti-nonce-wrong-key";
        let content = crate::dht::signed::get_anti_entropy_request_signable_content(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
        );
        // Sign with signer_a but verify with signer_b's public key
        let signature = signer_a.sign(&content);
        let valid = verify_dht_anti_entropy_request_signature(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
            &signature,
            Some(&signer_b.get_public_key()),
        );
        assert!(
            !valid,
            "anti-entropy signature must reject when signer_public_key doesn't match actual signer"
        );
    }

    #[test]
    fn test_record_push_envelope_signature_rejects_unsigned_when_required() {
        let valid = verify_dht_record_push_envelope_signature_bytes(
            "push-req-unsigned",
            "node-r",
            &[build_dht_record("org:test", b"v")],
            1,
            "nonce-unsigned",
            synvoid_utils::safe_unix_timestamp(),
            &[],
            None,
        );
        assert!(!valid, "unsigned push must reject when signature is empty");
    }

    #[test]
    fn test_record_push_envelope_signature_rejects_tampered_signature() {
        let signer = MeshMessageSigner::new([20u8; 32]);
        let request_id = "push-req-tamper";
        let node_id = "node-r";
        let records = vec![build_dht_record("org:test", b"v")];
        let hop_count = 1;
        let nonce = "push-nonce-tamper";
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let content = crate::dht::signed::get_dht_record_push_envelope_signable_content(
            request_id, node_id, &records, hop_count, nonce, timestamp,
        );
        let mut signature = signer.sign(&content);
        // Tamper with the signature
        signature[0] ^= 0xFF;
        let valid = verify_dht_record_push_envelope_signature_bytes(
            request_id,
            node_id,
            &records,
            hop_count,
            nonce,
            timestamp,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(!valid, "tampered record push signature must reject");
    }

    #[test]
    fn test_record_push_replay_protection_rejects_duplicate_nonce() {
        let mut replay = crate::protocol::ReplayProtection::new();
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let first = replay.check_and_add("push-replay-nonce", timestamp);
        let second = replay.check_and_add("push-replay-nonce", timestamp);
        assert!(
            matches!(first, crate::protocol::ReplayResult::Valid),
            "first push with nonce should be valid"
        );
        assert!(
            matches!(second, crate::protocol::ReplayResult::ReplayDetected),
            "replayed push nonce must be rejected"
        );
    }

    #[test]
    fn test_record_push_replay_protection_rejects_expired_timestamp() {
        let mut replay = crate::protocol::ReplayProtection::new();
        let stale = synvoid_utils::safe_unix_timestamp()
            .saturating_sub(crate::protocol::REPLAY_WINDOW_SECS + 1);
        let result = replay.check_and_add("push-expired-nonce", stale);
        assert!(
            matches!(result, crate::protocol::ReplayResult::ExpiredTimestamp),
            "push with expired timestamp must reject"
        );
    }

    #[test]
    fn test_verify_sync_request_signature_rejects_wrong_signer_key() {
        let signer_a = MeshMessageSigner::new([30u8; 32]);
        let signer_b = MeshMessageSigner::new([31u8; 32]);
        let request_id = "sync-wrong-key";
        let node_id = "node-a";
        let from_version = 5;
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "nonce-wrong-key";
        let content = crate::dht::signed::get_sync_request_signable_content(
            request_id,
            node_id,
            from_version,
            timestamp,
            nonce,
        );
        let signature = signer_a.sign(&content);
        let valid = verify_dht_sync_request_signature(
            request_id,
            node_id,
            from_version,
            timestamp,
            nonce,
            &signature,
            Some(&signer_b.get_public_key()),
        );
        assert!(
            !valid,
            "sync request signature must reject when signer_public_key doesn't match actual signer"
        );
    }

    #[test]
    fn test_verify_sync_request_signature_rejects_missing_public_key() {
        let signer = MeshMessageSigner::new([32u8; 32]);
        let request_id = "sync-missing-key";
        let node_id = "node-c";
        let from_version = 1;
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "nonce-missing-key";
        let content = crate::dht::signed::get_sync_request_signable_content(
            request_id,
            node_id,
            from_version,
            timestamp,
            nonce,
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_sync_request_signature(
            request_id,
            node_id,
            from_version,
            timestamp,
            nonce,
            &signature,
            None,
        );
        assert!(!valid, "missing public key must reject");
    }

    #[test]
    fn test_verify_sync_request_signature_accepts_empty_nonce() {
        let signer = MeshMessageSigner::new([33u8; 32]);
        let request_id = "sync-empty-nonce";
        let node_id = "node-d";
        let from_version = 1;
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let content = crate::dht::signed::get_sync_request_signable_content(
            request_id,
            node_id,
            from_version,
            timestamp,
            "",
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_sync_request_signature(
            request_id,
            node_id,
            from_version,
            timestamp,
            "",
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(
            valid,
            "empty nonce is valid if signature matches (nonce is part of signed content)"
        );
    }

    #[test]
    fn test_verify_anti_entropy_request_signature_rejects_tampered_root_hash() {
        let signer = MeshMessageSigner::new([34u8; 32]);
        let request_id = "anti-tamper-hash";
        let node_id = "node-e";
        let local_root_hash: Vec<u8> = vec![1, 2, 3, 4];
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "anti-nonce-tamper-hash";
        let content = crate::dht::signed::get_anti_entropy_request_signable_content(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
        );
        let signature = signer.sign(&content);
        let mut tampered_hash = local_root_hash.clone();
        tampered_hash[0] ^= 0xFF;
        let valid = verify_dht_anti_entropy_request_signature(
            request_id,
            node_id,
            &tampered_hash,
            timestamp,
            nonce,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(
            !valid,
            "anti-entropy signature must reject when root_hash is tampered"
        );
    }

    #[test]
    fn test_verify_anti_entropy_request_signature_rejects_empty_public_key() {
        let signer = MeshMessageSigner::new([35u8; 32]);
        let request_id = "anti-empty-key";
        let node_id = "node-f";
        let local_root_hash: Vec<u8> = vec![1, 2, 3, 4];
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let nonce = "anti-nonce-empty-key";
        let content = crate::dht::signed::get_anti_entropy_request_signable_content(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_anti_entropy_request_signature(
            request_id,
            node_id,
            &local_root_hash,
            timestamp,
            nonce,
            &signature,
            Some(""),
        );
        assert!(!valid, "empty public key string must reject");
    }

    #[test]
    fn test_record_push_envelope_signature_rejects_wrong_node_id() {
        let signer = MeshMessageSigner::new([36u8; 32]);
        let request_id = "push-wrong-node";
        let node_id = "node-g";
        let records = vec![build_dht_record("org:test", b"v")];
        let hop_count = 1;
        let nonce = "push-nonce-wrong-node";
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let content = crate::dht::signed::get_dht_record_push_envelope_signable_content(
            request_id, node_id, &records, hop_count, nonce, timestamp,
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_record_push_envelope_signature_bytes(
            request_id,
            "different-node",
            &records,
            hop_count,
            nonce,
            timestamp,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(
            !valid,
            "record push signature must reject when node_id doesn't match signed content"
        );
    }

    #[test]
    fn test_record_push_envelope_signature_rejects_wrong_hop_count() {
        let signer = MeshMessageSigner::new([37u8; 32]);
        let request_id = "push-wrong-hop";
        let node_id = "node-h";
        let records = vec![build_dht_record("org:test", b"v")];
        let hop_count = 1;
        let nonce = "push-nonce-wrong-hop";
        let timestamp = synvoid_utils::safe_unix_timestamp();
        let content = crate::dht::signed::get_dht_record_push_envelope_signable_content(
            request_id, node_id, &records, hop_count, nonce, timestamp,
        );
        let signature = signer.sign(&content);
        let valid = verify_dht_record_push_envelope_signature_bytes(
            request_id,
            node_id,
            &records,
            5,
            nonce,
            timestamp,
            &signature,
            Some(&signer.get_public_key()),
        );
        assert!(
            !valid,
            "record push signature must reject when hop_count doesn't match signed content"
        );
    }

    #[test]
    fn test_sync_request_signable_content_differs_with_different_request_id() {
        let content_a =
            crate::dht::signed::get_sync_request_signable_content("req-1", "node", 0, 100, "nonce");
        let content_b =
            crate::dht::signed::get_sync_request_signable_content("req-2", "node", 0, 100, "nonce");
        assert_ne!(
            content_a, content_b,
            "different request_ids must produce different signable content"
        );
    }

    #[test]
    fn test_sync_request_signable_content_differs_with_different_from_version() {
        let content_a =
            crate::dht::signed::get_sync_request_signable_content("req", "node", 0, 100, "nonce");
        let content_b =
            crate::dht::signed::get_sync_request_signable_content("req", "node", 10, 100, "nonce");
        assert_ne!(
            content_a, content_b,
            "different from_version must produce different signable content"
        );
    }

    #[test]
    fn test_anti_entropy_signable_content_differs_with_different_root_hash() {
        let content_a = crate::dht::signed::get_anti_entropy_request_signable_content(
            "req",
            "node",
            &[1, 2, 3],
            100,
            "nonce",
        );
        let content_b = crate::dht::signed::get_anti_entropy_request_signable_content(
            "req",
            "node",
            &[4, 5, 6],
            100,
            "nonce",
        );
        assert_ne!(
            content_a, content_b,
            "different root hashes must produce different signable content"
        );
    }

    #[test]
    fn test_classify_sync_auth_missing_signature_rejected() {
        let mode = classify_dht_sync_auth_mode(&[], Some("key"), true, None, 100);
        assert_eq!(mode, DhtSyncAuthMode::UnsignedRejected);
    }

    #[test]
    fn test_classify_sync_auth_empty_signature_treated_as_unsigned() {
        let mode = classify_dht_sync_auth_mode(&[], Some("key"), false, None, 100);
        assert_eq!(mode, DhtSyncAuthMode::UnsignedAllowed);
    }
}
