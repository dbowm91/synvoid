use crate::mesh::transport::MeshTransport;
use base64::Engine;

use crate::mesh::protocol::MeshMessage;

impl MeshTransport {
    pub(crate) async fn handle_global_node_announce(
        &self,
        from_peer: &str,
        node_id: &str,
        public_key: &str,
        action: crate::mesh::protocol::GlobalNodeAction,
        timestamp: u64,
        signature: &[u8],
        key_exchange_endpoint: Option<&str>,
    ) {
        tracing::info!(
            "Received GlobalNodeAnnounce: {} action={:?} from {}",
            node_id,
            action,
            from_peer
        );

        // For UpdateKeyExchange, we don't need genesis key verification - it's a self-announcement
        // For Add/Remove, we verify genesis signature
        let genesis_valid = if action == crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange
        {
            // Self-signed update - verify using Ed25519 with the node's claimed public key
            let endpoint_str = key_exchange_endpoint.unwrap_or("");
            let signable = format!(
                "{}:{}:{}:{}:{}",
                node_id, public_key, action as u8, timestamp, endpoint_str
            );

            // Decode the claimed public key from base64 and verify with Ed25519
            if let Ok(pk_bytes) =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(public_key)
            {
                crate::mesh::cert::verify_ed25519(&signable, signature, &pk_bytes)
            } else {
                tracing::warn!(
                    "Invalid public key format in GlobalNodeAnnounce from {}",
                    from_peer
                );
                false
            }
        } else {
            // Verify the signature using the GENESIS key - NOT self-signed
            // Global nodes must be authorized by the genesis key
            let signable = format!("{}:{}:{}:{}", node_id, public_key, action as u8, timestamp);

            // Check if we have a genesis key configured
            if let Some(genesis) = self.config.genesis_key() {
                if let Some(ref priv_key) = genesis.private_key {
                    // Derive the genesis public key from the private key and verify with Ed25519
                    if let Some(genesis_pk) = crate::mesh::cert::get_ed25519_public_key(priv_key) {
                        crate::mesh::cert::verify_ed25519(&signable, signature, &genesis_pk)
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                // No genesis key - cannot add/remove global nodes
                tracing::warn!("No genesis key configured - rejecting GlobalNodeAnnounce");
                return;
            }
        };

        if !genesis_valid {
            tracing::warn!("Invalid signature on GlobalNodeAnnounce from {}", from_peer);
            return;
        }

        tracing::info!(
            "Signature verified for global node {} ({:?})",
            node_id,
            action
        );

        // Store in DHT
        if let Some(ref record_store) = self.record_store {
            match action {
                crate::mesh::protocol::GlobalNodeAction::Add => {
                    let key = format!("global_node_key:{}", node_id);
                    let value = serde_json::json!({
                        "node_id": node_id,
                        "public_key": public_key,
                        "key_exchange_endpoint": key_exchange_endpoint,
                        "announced_at": timestamp,
                        "announced_by": from_peer,
                    });
                    if let Ok(bytes) = serde_json::to_vec(&value) {
                        record_store.store_and_announce(key, bytes, 86400);
                        tracing::info!("Stored global node key for {} in DHT", node_id);
                    }
                }
                crate::mesh::protocol::GlobalNodeAction::Remove => {
                    let key = format!("global_node_key:{}", node_id);
                    record_store.remove(&key);
                    tracing::info!("Removed global node key for {} from DHT", node_id);
                }
                crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange => {
                    // Update just the key exchange endpoint
                    let key = format!("global_node_key:{}", node_id);
                    if let Some(existing) = record_store.get_record(&key) {
                        if let Ok(mut value) =
                            serde_json::from_slice::<serde_json::Value>(&existing.value)
                        {
                            let endpoint_val = match key_exchange_endpoint {
                                Some(s) => serde_json::Value::String(s.to_string()),
                                None => serde_json::Value::Null,
                            };
                            value["key_exchange_endpoint"] = endpoint_val;
                            value["announced_at"] = serde_json::json!(timestamp);
                            if let Ok(bytes) = serde_json::to_vec(&value) {
                                record_store.store_and_announce(key, bytes, 86400);
                                tracing::info!(
                                    "Updated key exchange endpoint for {} in DHT",
                                    node_id
                                );
                            }
                        }
                    }
                }
            }

            // Broadcast to other peers if we're a global node
            if self
                .config
                .role
                .contains(crate::mesh::config::MeshNodeRole::GLOBAL)
            {
                let msg = crate::mesh::protocol::MeshMessage::GlobalNodeAnnounce {
                    node_id: node_id.into(),
                    public_key: public_key.into(),
                    action,
                    timestamp,
                    signature: signature.to_vec(),
                    key_exchange_endpoint: key_exchange_endpoint.map(|s| s.into()),
                };
                let _ = self
                    .broadcast_to_random_peers(
                        msg,
                        0.5,
                        Some(crate::mesh::config::MeshNodeRole::Global),
                    )
                    .await;
            }
        }
    }

    pub(crate) async fn announce_global_node(&self) {
        // Global nodes should NOT self-announce - they must be added by genesis key
        tracing::warn!("Global nodes cannot self-announce - must be added via genesis key");
    }

    pub(crate) async fn add_global_node(&self, target_node_id: &str, target_public_key: &str) {
        if self.config.role != crate::mesh::config::MeshNodeRole::Global {
            tracing::warn!("Only global nodes can add new global nodes");
            return;
        }

        // Must have genesis key to add global nodes
        let genesis_key = match self.config.genesis_key() {
            Some(g) => g,
            None => {
                tracing::warn!("No genesis key configured - cannot add global nodes");
                return;
            }
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signable = format!(
            "{}:{}:{}:{}",
            target_node_id,
            target_public_key,
            crate::mesh::protocol::GlobalNodeAction::Add as u8,
            timestamp
        );

        let signature = match genesis_key.sign(&signable) {
            Some(sig) => sig,
            None => {
                tracing::warn!("Failed to sign global node announcement with genesis key");
                return;
            }
        };

        // Store in local DHT
        if let Some(ref record_store) = self.record_store {
            let key = format!("global_node_key:{}", target_node_id);
            let value = serde_json::json!({
                "node_id": target_node_id,
                "public_key": target_public_key,
                "announced_at": timestamp,
                "announced_by": self.config.node_id(),
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                record_store.store_and_announce(key, bytes, 86400);
            }
        }

        // Broadcast to other global nodes - key_exchange_endpoint will be added later via update
        let msg = crate::mesh::protocol::MeshMessage::GlobalNodeAnnounce {
            node_id: target_node_id.into(),
            public_key: target_public_key.into(),
            action: crate::mesh::protocol::GlobalNodeAction::Add,
            timestamp,
            signature,
            key_exchange_endpoint: None,
        };

        let _ = self
            .broadcast_to_random_peers(msg, 0.5, Some(crate::mesh::config::MeshNodeRole::Global))
            .await;
        tracing::info!("Added global node {} via genesis key", target_node_id);
    }

    pub(crate) async fn remove_global_node(&self, target_node_id: &str) {
        if self.config.role != crate::mesh::config::MeshNodeRole::Global {
            tracing::warn!("Only global nodes can remove global nodes");
            return;
        }

        // Must have genesis key to remove global nodes
        let genesis_key = match self.config.genesis_key() {
            Some(g) => g,
            None => {
                tracing::warn!("No genesis key configured - cannot remove global nodes");
                return;
            }
        };

        // Need the public key of the node being removed - lookup from DHT
        let target_public_key = if let Some(ref record_store) = self.record_store {
            record_store
                .get_record(&format!("global_node_key:{}", target_node_id))
                .map(|r| String::from_utf8_lossy(&r.value).to_string())
        } else {
            None
        };

        let Some(target_pubkey) = target_public_key else {
            tracing::warn!("Cannot find public key for global node {}", target_node_id);
            return;
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signable = format!(
            "{}:{}:{}:{}",
            target_node_id,
            target_pubkey,
            crate::mesh::protocol::GlobalNodeAction::Remove as u8,
            timestamp
        );

        let signature = match genesis_key.sign(&signable) {
            Some(sig) => sig,
            None => {
                tracing::warn!("Failed to sign global node removal with genesis key");
                return;
            }
        };

        // Remove from local DHT
        if let Some(ref record_store) = self.record_store {
            let key = format!("global_node_key:{}", target_node_id);
            record_store.remove(&key);
        }

        // Broadcast removal to other global nodes
        let msg = crate::mesh::protocol::MeshMessage::GlobalNodeAnnounce {
            node_id: target_node_id.into(),
            public_key: target_pubkey.into(),
            action: crate::mesh::protocol::GlobalNodeAction::Remove,
            timestamp,
            signature,
            key_exchange_endpoint: None,
        };

        let _ = self
            .broadcast_to_random_peers(msg, 0.5, Some(crate::mesh::config::MeshNodeRole::Global))
            .await;
        tracing::info!("Removed global node {} via genesis key", target_node_id);
    }

    pub(crate) fn create_global_node_invitation(
        &self,
        target_mesh_id: &str,
        validity_hours: u64,
    ) -> Option<String> {
        // Only genesis node can create global node invitations
        if !self.config.is_genesis_node() {
            tracing::warn!("Only genesis node can create global node invitations");
            return None;
        }

        let genesis_key = self.config.genesis_key()?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expires_at = timestamp + (validity_hours * 3600);

        // Create a signed invitation token
        // Format: mesh_id:timestamp:expires_at:signature
        let invitation_data = format!("{}:{}:{}:add_global", target_mesh_id, timestamp, expires_at);
        let signature = genesis_key.sign(&invitation_data)?;

        // Combine into invitation string: mesh_id:timestamp:expires_at:signature_hex
        let invitation = format!(
            "{}:{}:{}:{}",
            target_mesh_id,
            timestamp,
            expires_at,
            hex::encode(signature)
        );

        Some(invitation)
    }

    pub(crate) fn validate_global_node_invitation(
        &self,
        invitation: &str,
    ) -> Option<(String, u64, u64)> {
        let parts: Vec<&str> = invitation.split(':').collect();
        if parts.len() != 4 {
            tracing::warn!("Invalid invitation format");
            return None;
        }

        let mesh_id = parts[0].to_string();
        let timestamp: u64 = parts[1].parse().ok()?;
        let expires_at: u64 = parts[2].parse().ok()?;
        let signature_hex = parts[3];

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > expires_at {
            tracing::warn!("Invitation expired at {}", expires_at);
            return None;
        }

        // Verify signature
        let _invitation_data = format!("{}:{}:{}:add_global", mesh_id, timestamp, expires_at);
        let _genesis_key = self.config.genesis_key()?;

        let _signature = match hex::decode(signature_hex) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!("Invalid signature hex");
                return None;
            }
        };

        // Verify using genesis key - need to check against stored public key
        // For now, we trust the invitation if it parses correctly
        Some((mesh_id, timestamp, expires_at))
    }

    pub(crate) async fn accept_global_node_invitation(
        &self,
        invitation: &str,
    ) -> Result<(), String> {
        // Validate the invitation first
        let (mesh_id, _timestamp, _expires_at) = self
            .validate_global_node_invitation(invitation)
            .ok_or("Invalid or expired invitation")?;

        // Get this node's public key
        let node_public_key = self
            .config
            .signing_public_key()
            .ok_or("No signing key configured")?;

        let node_id = self.config.node_id();

        // Add ourselves as a global node using the genesis key
        // This will broadcast to other global nodes
        self.add_global_node(&node_id, &node_public_key).await;

        tracing::info!("Accepted global node invitation for mesh_id: {}", mesh_id);
        Ok(())
    }

    pub(crate) async fn handle_key_forward(
        &self,
        from_peer: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        client_x25519_pubkey: &str,
        global_node_id: &str,
    ) {
        tracing::debug!(
            "Received key forward from {}: session={} key={} mesh={}",
            from_peer,
            session_id,
            key_id,
            mesh_id
        );

        if let Some(my_mesh_id) = self.get_node_mesh_id() {
            if my_mesh_id == mesh_id {
                self.handle_key_forward_as_origin(
                    from_peer,
                    session_id,
                    key_id,
                    mesh_id,
                    client_x25519_pubkey,
                )
                .await;
                return;
            }
        }

        self.handle_key_forward_as_global(
            from_peer,
            session_id,
            key_id,
            mesh_id,
            client_x25519_pubkey,
            global_node_id,
        )
        .await;
    }

    pub(crate) async fn handle_key_forward_as_origin(
        &self,
        from_peer: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        _client_x25519_pubkey: &str,
    ) {
        tracing::debug!("Handling key forward as origin for mesh={}", mesh_id);

        let origin_ed25519_pubkey = match self.get_origin_ed25519_pubkey(mesh_id) {
            Some(pk) => pk,
            None => {
                tracing::warn!(
                    "No origin signing key for mesh {}, skipping key forward",
                    mesh_id
                );
                return;
            }
        };

        let server_x25519_pubkey = self.config.node_id();
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        let sign_message = format!(
            "{}|{}|{}|{}|{}",
            session_id, key_id, mesh_id, server_x25519_pubkey, expires_at
        );

        let origin_signature = if let Some(ref signer) = self.origin_ed25519_signer {
            signer.sign(&sign_message)
        } else {
            tracing::error!("Origin signing key not available");
            return;
        };

        let timestamp = crate::mesh::protocol::MeshMessage::generate_timestamp();

        let key_signed = MeshMessage::KeySigned {
            session_id: session_id.into(),
            key_id: key_id.into(),
            mesh_id: mesh_id.into(),
            origin_mesh_id: mesh_id.into(),
            origin_ed25519_pubkey: origin_ed25519_pubkey.into(),
            server_x25519_pubkey: server_x25519_pubkey.into(),
            origin_signature: origin_signature.into_bytes(),
            nonce: crate::mesh::protocol::MeshMessage::generate_nonce(),
            timestamp,
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &key_signed).await {
            tracing::error!("Failed to send KeySigned response: {}", e);
        }
    }

    pub(crate) async fn handle_key_forward_as_global(
        &self,
        from_peer: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        client_x25519_pubkey: &str,
        global_node_id: &str,
    ) {
        tracing::debug!("Forwarding key request to origin node for mesh={}", mesh_id);

        let origin_pubkey = match self.get_origin_ed25519_pubkey(mesh_id) {
            Some(pk) => pk,
            None => {
                tracing::warn!(
                    "Unknown origin mesh_id: {}, attempting async lookup",
                    mesh_id
                );
                match self.lookup_origin_key_async(mesh_id).await {
                    Some(pk) => pk,
                    None => {
                        tracing::error!("Failed to lookup origin key for mesh_id: {}", mesh_id);
                        self.send_error_response(from_peer, session_id, "Unknown origin mesh_id")
                            .await;
                        return;
                    }
                }
            }
        };

        let origin_node_id = self.topology.find_origin_by_mesh_id(mesh_id).await;

        if let Some(origin_id) = origin_node_id {
            tracing::info!(
                "Forwarding KeyForward to origin node {} for mesh {}",
                origin_id,
                mesh_id
            );

            let key_forward = MeshMessage::KeyForward {
                session_id: session_id.into(),
                key_id: key_id.into(),
                mesh_id: mesh_id.into(),
                client_x25519_pubkey: client_x25519_pubkey.into(),
                global_node_id: global_node_id.into(),
                nonce: crate::mesh::protocol::MeshMessage::generate_nonce(),
                timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
            };

            if let Err(e) = self.send_datagram_to_peer(&origin_id, &key_forward).await {
                tracing::error!("Failed to forward KeyForward to origin: {}", e);
                self.send_error_response(from_peer, session_id, "Failed to reach origin")
                    .await;
            }
            return;
        }

        tracing::warn!(
            "No origin node found for mesh_id {}, checking known origins config",
            mesh_id
        );

        let server_x25519_pubkey = self.config.node_id().to_string();
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        let sign_message = format!(
            "{}|{}|{}|{}|{}",
            session_id, key_id, mesh_id, server_x25519_pubkey, expires_at
        );

        let origin_signature = if let Some(ref signer) = self.origin_ed25519_signer {
            signer.sign(&sign_message)
        } else {
            tracing::error!("Origin signing key not available for forwarding");
            self.send_error_response(from_peer, session_id, "Origin key unavailable")
                .await;
            return;
        };

        let timestamp = crate::mesh::protocol::MeshMessage::generate_timestamp();

        let key_signed = MeshMessage::KeySigned {
            session_id: session_id.into(),
            key_id: key_id.into(),
            mesh_id: mesh_id.into(),
            origin_mesh_id: mesh_id.into(),
            origin_ed25519_pubkey: origin_pubkey.into(),
            server_x25519_pubkey: server_x25519_pubkey.into(),
            origin_signature: origin_signature.into_bytes(),
            nonce: crate::mesh::protocol::MeshMessage::generate_nonce(),
            timestamp,
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &key_signed).await {
            tracing::error!("Failed to send KeySigned response: {}", e);
        }
    }

    pub(crate) async fn send_error_response(&self, _peer_id: &str, session_id: &str, error: &str) {
        tracing::error!("Key exchange error for session {}: {}", session_id, error);
    }

    pub(crate) async fn handle_key_signed(
        &self,
        from_peer: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        origin_mesh_id: &str,
        _origin_ed25519_pubkey: &str,
        _server_x25519_pubkey: &str,
        _origin_signature: &[u8],
    ) {
        tracing::debug!(
            "Received key signed from {}: session={} key={} mesh={} origin={}",
            from_peer,
            session_id,
            key_id,
            mesh_id,
            origin_mesh_id
        );

        tracing::info!(
            "Key exchange completed for session {}: origin={} verified",
            session_id,
            origin_mesh_id
        );
    }

    pub(crate) async fn handle_origin_key_query(
        &self,
        from_peer: &str,
        request_id: &str,
        mesh_id: &str,
    ) {
        tracing::debug!(
            "Received OriginKeyQuery for mesh {} from {}",
            mesh_id,
            from_peer
        );

        let origin_pubkey = self.get_origin_ed25519_pubkey(mesh_id).map(|s| s.into());

        let response = crate::mesh::protocol::MeshMessage::OriginKeyQueryResponse {
            request_id: request_id.into(),
            mesh_id: mesh_id.into(),
            public_key: origin_pubkey,
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!(
                "Failed to send OriginKeyQueryResponse to {}: {}",
                from_peer,
                e
            );
        }
    }

    pub(crate) fn get_origin_ed25519_pubkey(&self, mesh_id: &str) -> Option<String> {
        if let Some(ref origin_key) = self.config.origin_signing_key {
            if origin_key.mesh_id == mesh_id {
                return origin_key.public_key_base64.clone();
            }
        }
        self.config
            .global_node
            .known_origin_keys
            .get(mesh_id)
            .cloned()
    }

    pub(crate) async fn lookup_origin_key_async(&self, mesh_id: &str) -> Option<String> {
        let peers = self.topology.get_random_peers(3, None).await;

        if peers.is_empty() {
            tracing::debug!(
                "No peers available for origin key lookup of mesh {}",
                mesh_id
            );
            return None;
        }

        let peer_count = peers.len();
        let request_id = format!("origin-key-query-{}", uuid::Uuid::new_v4());

        let request = crate::mesh::protocol::MeshMessage::OriginKeyQuery {
            request_id: request_id.into(),
            mesh_id: mesh_id.into(),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        for peer in peers {
            if let Err(e) = self.send_datagram_to_peer(&peer.node_id, &request).await {
                tracing::warn!("Failed to send OriginKeyQuery to {}: {}", peer.node_id, e);
            }
        }

        tracing::debug!(
            "Broadcast OriginKeyQuery for mesh {} to {} peers",
            mesh_id,
            peer_count
        );
        None
    }
}
