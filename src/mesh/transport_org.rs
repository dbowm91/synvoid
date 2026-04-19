#![allow(dead_code)]
// SAFETY_REASON: Reserved for future organization protocol handling

use crate::mesh::transport::MeshTransport;

use crate::mesh::tier_key_encryption::derive_transmission_key;

impl MeshTransport {
    pub(crate) async fn handle_org_registration_request(
        &self,
        from_peer: &str,
        request_id: &str,
        org_name: &str,
        requesting_node_id: &str,
        requesting_node_pubkey: &str,
    ) {
        tracing::info!(
            "Received org registration request: {} from node {}",
            org_name,
            requesting_node_id
        );

        if !self.config.role.is_global() {
            tracing::warn!("Received org registration request on non-global node");
            return;
        }

        let org_config = self.config.org_config();
        let validated_name =
            match crate::mesh::sanitize_org_name_with_config(org_name, &org_config.bad_names) {
                Ok(name) => name,
                Err(e) => {
                    tracing::warn!(
                        "Org registration rejected: invalid name '{}': {}",
                        org_name,
                        e
                    );
                    self.send_org_registration_response(
                        from_peer,
                        request_id,
                        "",
                        org_name,
                        false,
                        format!("Invalid org name: {}", e),
                        None,
                    )
                    .await;
                    return;
                }
            };

        // Check for name uniqueness
        let name_exists = {
            let org_mgr = self.org_manager.read();
            org_mgr.org_name_exists(&validated_name)
        };

        if name_exists {
            tracing::warn!(
                "Org registration rejected: name '{}' already exists",
                validated_name
            );
            self.send_org_registration_response(
                from_peer,
                request_id,
                "",
                &validated_name,
                false,
                "Organization name already exists".to_string(),
                None,
            )
            .await;
            return;
        }

        if org_config.auto_approve {
            tracing::info!(
                "Auto-approving organization registration: {}",
                validated_name
            );
            self.auto_approve_organization(
                request_id,
                &validated_name,
                requesting_node_id,
                requesting_node_pubkey,
                from_peer,
            )
            .await;
            return;
        }

        let pending = crate::mesh::organization::OrgPendingRequest::new(
            request_id.to_string(),
            validated_name.clone(),
            requesting_node_id.to_string(),
            requesting_node_pubkey.to_string(),
        );

        let mut org_mgr = self.org_manager.write();
        org_mgr.add_pending_request(pending);

        tracing::warn!(
            "Organization registration pending approval: {} - {}",
            validated_name,
            request_id
        );
    }

    pub(crate) async fn auto_approve_organization(
        &self,
        request_id: &str,
        org_name: &str,
        requesting_node_id: &str,
        _requesting_node_pubkey: &str,
        from_peer: &str,
    ) {
        let org_id = uuid::Uuid::new_v4().to_string();

        let org_key =
            crate::mesh::organization::OrgKey::generate(Some(requesting_node_id.to_string()));

        let mut org = crate::mesh::organization::Organization::new(
            Some(org_id.clone()),
            Some(org_name.to_string()),
        );
        org.set_org_key(org_key.clone());
        org.add_member_node(requesting_node_id.to_string());

        let org_config = self.config.org_config();
        let mut initial_tier_key = None;

        if org_config.default_tier_on_approve > 0 {
            use rand::RngCore;
            let mut key_bytes = vec![0u8; 32];
            rand::rng().fill_bytes(&mut key_bytes);

            let now = crate::utils::safe_unix_timestamp();
            let valid_until = now + (365 * 24 * 60 * 60);

            let tier_key = crate::mesh::organization::TierKey::new(
                org_config.default_tier_on_approve,
                key_bytes,
                now,
                valid_until,
                "auto-approve".to_string(),
            );
            initial_tier_key = Some(tier_key.clone());
            org.tier_keys.push(tier_key);
        }

        {
            let mut org_mgr = self.org_manager.write();
            org_mgr.register_organization(org);
        }

        // Announce org to DHT
        if let Some(ref record_store) = self.record_store {
            let org_data = serde_json::json!({
                "org_id": org_id,
                "name": org_name,
                "registered_at": crate::utils::safe_unix_timestamp(),
            });
            let key = format!("org:{}", org_id);
            if let Ok(value) = serde_json::to_vec(&org_data) {
                record_store.store_and_announce(key, value, 86400 * 7);
                tracing::debug!("Announced org {} to DHT", org_id);
            }

            // Announce tier keys (ONLY if encryption is available)
            if let Some(ref tier_key) = initial_tier_key {
                if let Some(ref enc) = self.tier_key_encryption {
                    if let Ok(encrypted) = enc.encrypt_tier_key_data(
                        &org_id,
                        tier_key.tier,
                        &tier_key.key_id,
                        &tier_key.key,
                    ) {
                        let serialized = crate::mesh::serialize_encrypted_tier_key(&encrypted);
                        let tier_key_dht =
                            format!("encrypted_tier_key:{}:{}", org_id, tier_key.tier);
                        record_store.store_and_announce(tier_key_dht, serialized, 86400 * 30);
                        tracing::debug!("Announced encrypted tier key for org {} to DHT", org_id);
                    }
                } else {
                    tracing::error!(
                        "Cannot announce tier key for org {} - tier key encryption not available",
                        org_id
                    );
                }
            }
        }

        self.send_org_registration_response(
            from_peer,
            request_id,
            &org_id,
            org_name,
            true,
            "Auto-approved".to_string(),
            initial_tier_key.as_ref(),
        )
        .await;

        tracing::info!("Auto-approved organization: {} ({})", org_name, org_id);
    }

    pub(crate) async fn send_org_registration_response(
        &self,
        to_peer: &str,
        request_id: &str,
        org_id: &str,
        org_name: &str,
        approved: bool,
        reason: String,
        tier_key: Option<&crate::mesh::organization::TierKey>,
    ) {
        let timestamp = crate::utils::safe_unix_timestamp();

        let sign_data = format!(
            "{}:{}:{}:{}:{}",
            request_id, org_id, org_name, approved, timestamp
        );

        let signature = if let Some(ref signer) = self.mesh_signer {
            signer.sign(&sign_data).to_vec()
        } else {
            tracing::warn!("No mesh signer available for org registration response");
            Vec::new()
        };

        let initial_tier_key = if let Some(tk) = tier_key {
            if let Some(ref enc) = self.tier_key_encryption {
                if let Some(ref session_mgr) = self.mlkem_session_manager {
                    if let Some(session) = session_mgr.get_by_peer(to_peer) {
                        let transmission_key = derive_transmission_key(&session.session_key);
                        let encrypted_key =
                            enc.encrypt_for_transmission(&tk.key, &transmission_key);
                        Some(crate::mesh::organization::TierKey {
                            key_id: tk.key_id.clone(),
                            tier: tk.tier,
                            key: encrypted_key,
                            valid_from: tk.valid_from,
                            valid_until: tk.valid_until,
                            issued_by: tk.issued_by.clone(),
                            revoked: tk.revoked,
                            revoked_at: tk.revoked_at,
                            bound_to: tk.bound_to.clone(),
                            is_unspent: tk.is_unspent,
                        })
                    } else {
                        tracing::debug!(
                            "No ML-KEM session for peer {}, not sending tier key",
                            to_peer
                        );
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let response = crate::mesh::protocol::MeshMessage::OrgRegistrationResponse {
            request_id: request_id.into(),
            org_id: org_id.into(),
            org_name: org_name.into(),
            approved,
            reason: reason.into(),
            initial_tier_key,
            signature,
            timestamp,
        };

        if let Err(e) = self.send_message_to_peer(to_peer, &response).await {
            tracing::warn!(
                "Failed to send org registration response to {}: {}",
                to_peer,
                e
            );
        }
    }

    pub(crate) async fn handle_org_registration_response(
        &self,
        from_peer: &str,
        org_id: &str,
        approved: bool,
        initial_tier_key: Option<&crate::mesh::organization::TierKey>,
    ) {
        if !approved {
            tracing::warn!("Organization registration rejected for: {}", org_id);
            return;
        }

        tracing::info!(
            "Organization registration approved for {} from node {}",
            org_id,
            from_peer
        );

        let decrypted_tier_key = if let Some(tk) = initial_tier_key {
            if tk.key.len() > 12 {
                let likely_encrypted = tk.key.len() == 32 + 12;
                if likely_encrypted {
                    if let Some(ref session_mgr) = self.mlkem_session_manager {
                        if let Some(session) = session_mgr.get_by_peer(from_peer) {
                            let transmission_key =
                                crate::mesh::tier_key_encryption::derive_transmission_key(
                                    &session.session_key,
                                );
                            let decrypted = self.tier_key_encryption.as_ref().and_then(|enc| {
                                enc.decrypt_for_transmission(&tk.key, &transmission_key)
                                    .ok()
                            });
                            if let Some(decrypted_key) = decrypted {
                                let mut new_tk = tk.clone();
                                new_tk.key = decrypted_key;
                                Some(new_tk)
                            } else {
                                tracing::warn!(
                                    "Failed to decrypt tier key from {}, storing as-is",
                                    from_peer
                                );
                                Some(tk.clone())
                            }
                        } else {
                            tracing::warn!(
                                "No session found for peer {}, cannot decrypt tier key",
                                from_peer
                            );
                            Some(tk.clone())
                        }
                    } else {
                        Some(tk.clone())
                    }
                } else {
                    Some(tk.clone())
                }
            } else {
                Some(tk.clone())
            }
        } else {
            None
        };

        if let Some(ref record_store) = self.record_store {
            let key = format!("org:{}", org_id);
            let value = org_id.as_bytes().to_vec();
            let ttl = 86400 * 7;

            if record_store.store_and_announce(key, value, ttl) {
                tracing::info!("Stored organization in DHT: {}", org_id);
            } else {
                tracing::warn!("Failed to store organization in DHT: {}", org_id);
            }

            if let Some(ref tier_key) = decrypted_tier_key {
                if let Some(ref enc) = self.tier_key_encryption {
                    if let Ok(encrypted) = enc.encrypt_tier_key_data(
                        org_id,
                        tier_key.tier,
                        &tier_key.key_id,
                        &tier_key.key,
                    ) {
                        let serialized = crate::mesh::serialize_encrypted_tier_key(&encrypted);
                        let tier_key_dht =
                            format!("encrypted_tier_key:{}:{}", org_id, tier_key.tier);
                        if record_store.store_and_announce(tier_key_dht, serialized, 86400 * 30) {
                            tracing::info!(
                                "Stored encrypted initial tier key in DHT: {}/{}",
                                org_id,
                                tier_key.tier
                            );
                        }
                    }
                } else {
                    tracing::error!(
                        "Cannot store tier key for org {} - tier key encryption not available",
                        org_id
                    );
                }
            }
        }
    }

    pub(crate) async fn handle_tier_key_announce(
        &self,
        org_id: &str,
        tier_key: &crate::mesh::organization::TierKey,
    ) {
        tracing::debug!(
            "Received TierKeyAnnounce for org {} tier {}",
            org_id,
            tier_key.tier
        );

        if let Some(ref record_store) = self.record_store {
            if let Some(ref enc) = self.tier_key_encryption {
                if let Ok(encrypted) = enc.encrypt_tier_key_data(
                    org_id,
                    tier_key.tier,
                    &tier_key.key_id,
                    &tier_key.key,
                ) {
                    let serialized = crate::mesh::serialize_encrypted_tier_key(&encrypted);
                    let key = format!("encrypted_tier_key:{}:{}", org_id, tier_key.tier);
                    let ttl = 86400 * 30;

                    if record_store.store_and_announce(key, serialized, ttl) {
                        tracing::info!(
                            "Stored encrypted tier key in DHT: {}/{}",
                            org_id,
                            tier_key.tier
                        );
                    } else {
                        tracing::warn!(
                            "Failed to store encrypted tier key in DHT: {}/{}",
                            org_id,
                            tier_key.tier
                        );
                    }
                } else {
                    tracing::warn!(
                        "Failed to encrypt tier key for org {} tier {}",
                        org_id,
                        tier_key.tier
                    );
                }
            } else {
                tracing::error!(
                    "Cannot store tier key for org {} tier {} - tier key encryption not available",
                    org_id,
                    tier_key.tier
                );
            }
        }
    }

    pub(crate) async fn handle_tier_key_revoke(&self, org_id: &str, key_id: &str) {
        tracing::info!("Received TierKeyRevoke for org {} key {}", org_id, key_id);

        let should_broadcast = {
            let org_manager = self.get_org_manager();
            let mut org_mgr = org_manager.write();
            let result = org_mgr.unbind_tier_key(org_id, key_id);
            if result {
                tracing::info!("Unbound tier key {} from org {}", key_id, org_id);
            }
            result
                && self
                    .config
                    .role
                    .contains(crate::mesh::config::MeshNodeRole::GLOBAL)
        };

        if should_broadcast {
            let _ = self.broadcast_unspent_tier_keys(org_id).await;
        }

        if let Some(ref record_store) = self.record_store {
            let key = format!("tier_key:{}:{}", org_id, key_id);
            record_store.remove(&key);
            tracing::info!("Removed tier key from DHT: {}/{}", org_id, key_id);
        }
    }

    pub(crate) async fn handle_unspent_tier_key_announce(
        &self,
        org_id: &str,
        tier_keys: &[crate::mesh::organization::TierKey],
    ) {
        tracing::debug!(
            "Received UnspentTierKeyAnnounce for org {} with {} keys",
            org_id,
            tier_keys.len()
        );

        if !self.config.role.is_global() {
            tracing::debug!("Ignoring UnspentTierKeyAnnounce on non-global node");
            return;
        }

        let unspent_key_ids: Vec<String> = {
            let org_manager = self.get_org_manager();
            let org_mgr = org_manager.read();
            tier_keys
                .iter()
                .filter_map(|key| {
                    org_mgr
                        .get_organization(org_id)
                        .and_then(|org| org.tier_keys.iter().find(|k| k.key_id == key.key_id))
                        .filter(|tier_key| tier_key.is_unspent)
                        .map(|_| key.key_id.clone())
                })
                .collect()
        };

        for key_id in unspent_key_ids {
            tracing::debug!("Tier key {} is now unspent for org {}", key_id, org_id);
        }
    }

    pub(crate) async fn broadcast_unspent_tier_keys(&self, org_id: &str) -> Result<(), String> {
        let (tier_keys, timestamp) = {
            let org_manager = self.get_org_manager();
            let org_mgr = org_manager.read();
            if let Some(unspent_keys) = org_mgr.get_unspent_tier_keys(org_id) {
                if unspent_keys.is_empty() {
                    return Ok(());
                }
                let tier_keys: Vec<_> = unspent_keys.iter().map(|k| (*k).clone()).collect();
                let timestamp = crate::mesh::protocol::MeshMessage::generate_timestamp();
                (tier_keys, timestamp)
            } else {
                return Ok(());
            }
        };

        let sign_data = tier_keys
            .iter()
            .map(|k| format!("{}:{}:{}", k.key_id, k.tier, k.valid_until))
            .collect::<Vec<_>>()
            .join(":");
        let signature = if let Some(ref signer) = self.mesh_signer {
            signer.sign(&sign_data).to_vec()
        } else {
            tracing::warn!("No mesh signer available for tier key announce");
            Vec::new()
        };

        let message = crate::mesh::protocol::MeshMessage::UnspentTierKeyAnnounce {
            org_id: org_id.into(),
            tier_keys,
            signature,
            timestamp,
        };

        let _result = self
            .broadcast_to_random_peers(
                message,
                0.3,
                Some(crate::mesh::config::MeshNodeRole::GLOBAL),
            )
            .await;
        tracing::info!("Broadcast unspent tier keys for org {}", org_id);
        Ok(())
    }

    pub(crate) async fn handle_org_invitation_request(
        &self,
        _from_peer: &str,
        request_id: &str,
        org_id: &str,
        inviter_node_id: &str,
        invited_node_id: &str,
        invitation_token: &str,
        expires_at: u64,
    ) {
        tracing::info!(
            "Received org invitation request: {} -> {} for org {}",
            inviter_node_id,
            invited_node_id,
            org_id
        );

        let invitation = crate::mesh::organization::OrgInvitation::new(
            request_id.to_string(),
            org_id.to_string(),
            inviter_node_id.to_string(),
            invited_node_id.to_string(),
            None,
            invitation_token.to_string(),
            24,
        );

        let mut org_mgr = self.org_manager.write();
        org_mgr.add_invitation(invitation);

        tracing::warn!(
            "Organization invitation stored for node {} (expires at {})",
            invited_node_id,
            expires_at
        );
    }

    pub(crate) async fn handle_org_invitation_accept(
        &self,
        _from_peer: &str,
        _request_id: &str,
        org_id: &str,
        invited_node_id: &str,
        invitation_token: &str,
        proof_of_key: &str,
    ) {
        tracing::info!(
            "Received org invitation accept: {} for org {}",
            invited_node_id,
            org_id
        );

        let org_mgr = self.org_manager.read();
        let invitation = org_mgr.get_invitation(invited_node_id);

        if let Some(inv) = invitation {
            if let Some(ref pubkey_hex) = inv.invited_node_pubkey {
                if let Ok(pubkey_bytes) = hex::decode(pubkey_hex) {
                    let is_valid = crate::mesh::organization::verify_invitation_proof(
                        proof_of_key,
                        invitation_token,
                        org_id,
                        invited_node_id,
                        &pubkey_bytes,
                    );

                    if is_valid {
                        tracing::info!("Invitation proof verified for node {}", invited_node_id);
                    } else {
                        tracing::warn!(
                            "Invitation proof verification failed for node {}",
                            invited_node_id
                        );
                    }
                    return;
                }
            }
        }

        tracing::warn!(
            "Invitation not found or missing pubkey for node {}",
            invited_node_id
        );
    }

    pub(crate) async fn handle_org_member_announce(
        &self,
        org_id: &str,
        member_node_id: &str,
        announced_by: &str,
        _joined_at: u64,
    ) {
        tracing::info!(
            "Received org member announce: {} joined org {} (announced by {})",
            member_node_id,
            org_id,
            announced_by
        );
    }
}
