use subtle::ConstantTimeEq;

use super::*;

impl MeshConfig {
    pub fn with_defaults_if_enabled(mut self) -> Self {
        if self.enabled {
            if self.seeds.is_empty() && self.role.is_edge() && !self.role.is_global() {
                self.seeds = config_defaults::default_global_seeds();
            }
            if self.connection.min_peer_connections == 0 {
                self.connection.min_peer_connections = 3;
            }
            if self.connection.max_peer_connections == 0 {
                self.connection.max_peer_connections = 20;
            }
        }
        self
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn init_origin_signing_key(&mut self) -> Result<(), String> {
        if let Some(ref mut origin_key) = self.origin_signing_key {
            origin_key.load_key()?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate genesis key configuration
        if let Some(ref genesis) = self.genesis_key {
            if genesis.is_first_node && !self.role.is_global() {
                return Err(
                    "genesis_key.is_first_node can only be true for global nodes".to_string(),
                );
            }

            if genesis.private_key_base64.is_none() && !genesis.is_first_node {
                return Err(
                    "genesis_key requires either a private_key_base64 or is_first_node: true"
                        .to_string(),
                );
            }
        }

        // If role is Global, we should have either a genesis key or be the first node
        if self.role.is_global() && self.genesis_key.is_none() {
            tracing::warn!(
                "Global node without genesis key - cannot add/remove other global nodes"
            );
        }

        if let Some(dht) = &self.dht {
            if !dht.require_signed_sync_requests {
                let now = crate::mesh::safe_unix_timestamp();
                match dht.unsigned_sync_compat_until_unix {
                    Some(deadline) if deadline > now => {}
                    Some(deadline) => {
                        return Err(format!(
                            "mesh.dht.require_signed_sync_requests=false compatibility window expired at {} (now={}); set require_signed_sync_requests=true or extend unsigned_sync_compat_until_unix",
                            deadline, now
                        ));
                    }
                    None => {
                        return Err(
                            "mesh.dht.require_signed_sync_requests=false requires a bounded migration window via mesh.dht.unsigned_sync_compat_until_unix"
                                .to_string(),
                        );
                    }
                }
            }

            if !dht.require_signed_anti_entropy_requests {
                let now = crate::mesh::safe_unix_timestamp();
                match dht.unsigned_anti_entropy_compat_until_unix {
                    Some(deadline) if deadline > now => {}
                    Some(deadline) => {
                        return Err(format!(
                            "mesh.dht.require_signed_anti_entropy_requests=false compatibility window expired at {} (now={}); set require_signed_anti_entropy_requests=true or extend unsigned_anti_entropy_compat_until_unix",
                            deadline, now
                        ));
                    }
                    None => {
                        return Err(
                            "mesh.dht.require_signed_anti_entropy_requests=false requires a bounded migration window via mesh.dht.unsigned_anti_entropy_compat_until_unix"
                                .to_string(),
                        );
                    }
                }
            }

            if !dht.require_signed_record_push {
                let now = crate::mesh::safe_unix_timestamp();
                match dht.unsigned_record_push_compat_until_unix {
                    Some(deadline) if deadline > now => {}
                    Some(deadline) => {
                        return Err(format!(
                            "mesh.dht.require_signed_record_push=false compatibility window expired at {} (now={}); set require_signed_record_push=true or extend unsigned_record_push_compat_until_unix",
                            deadline, now
                        ));
                    }
                    None => {
                        return Err(
                            "mesh.dht.require_signed_record_push=false requires a bounded migration window via mesh.dht.unsigned_record_push_compat_until_unix"
                                .to_string(),
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

impl MeshConfig {
    pub fn generate_node_id() -> String {
        format!("mesh-{}", uuid::Uuid::new_v4())
    }

    pub fn node_id(&self) -> String {
        if let Some(ref identity) = self.node_identity.node_id {
            return identity.clone();
        }
        self.node_id.clone().unwrap_or_else(Self::generate_node_id)
    }

    pub fn router_id(&self) -> String {
        self.node_identity.router_id.clone().unwrap_or_else(|| {
            let mut id = [0u8; 32];
            use rand::RngCore;
            rand::rng().fill_bytes(&mut id);
            derive_router_id(&id)
        })
    }

    pub fn load_node_identity(&mut self) -> Result<(), String> {
        if let Some(ref genesis_b64) = self.node_identity.genesis_key_base64 {
            use base64::Engine;
            let genesis_bytes = URL_SAFE_NO_PAD
                .decode(genesis_b64)
                .map_err(|e| format!("Invalid genesis key base64: {}", e))?;

            if genesis_bytes.len() != 32 {
                return Err("Genesis key must be 32 bytes".to_string());
            }

            let mut genesis_key = [0u8; 32];
            genesis_key.copy_from_slice(&genesis_bytes);

            let public_key = crate::mesh::cert::get_ed25519_public_key(&genesis_key)
                .ok_or("Failed to derive public key from genesis key")?;

            let public_key_b64 = URL_SAFE_NO_PAD.encode(&public_key);

            if let Some(ref genesis_config) = self.genesis_key {
                if !genesis_config.is_genesis_key_authorized(&public_key_b64) {
                    return Err("Genesis key is not in the authorized list".to_string());
                }
            }

            self.node_identity
                .derive_signing_key_from_genesis(&genesis_key, &public_key)
        } else {
            self.node_identity.load_or_generate()
        }
    }

    pub fn has_genesis_key(&self) -> bool {
        self.node_identity.genesis_key_base64.is_some()
    }

    pub fn set_genesis_key(&mut self, genesis_key_base64: String) {
        self.node_identity.genesis_key_base64 = Some(genesis_key_base64);
    }

    pub fn load_global_node_keys(&mut self) -> Result<(), String> {
        self.global_node.load_keys()
    }

    pub fn signing_key(&self) -> Option<&[u8]> {
        self.node_identity.private_key.as_deref()
    }

    pub fn signing_public_key(&self) -> Option<String> {
        self.node_identity.public_key_hex()
    }

    pub fn get_cached_pow_nonce(&self) -> Option<u64> {
        let cache = self.cached_pow.read();
        if let Some((nonce, cached_at)) = *cache {
            if cached_at.elapsed().as_secs() < POW_CACHE_TTL_SECS {
                return Some(nonce);
            }
        }
        None
    }

    pub fn set_cached_pow_nonce(&self, nonce: u64) {
        *self.cached_pow.write() = Some((nonce, std::time::Instant::now()));
    }

    pub fn clear_cached_pow_nonce(&self) {
        *self.cached_pow.write() = None;
    }

    pub fn is_pow_cache_valid(&self) -> bool {
        self.get_cached_pow_nonce().is_some()
    }

    pub fn has_signing_key(&self) -> bool {
        self.node_identity.private_key.is_some()
    }

    pub fn load_genesis_key(&mut self) -> Result<(), String> {
        if let Some(ref mut genesis) = self.genesis_key {
            genesis.load()
        } else {
            Ok(())
        }
    }

    pub fn get_quic_port(&self) -> u16 {
        self.quic_port.unwrap_or(self.port)
    }

    pub fn get_advertised_quic_port(&self) -> u16 {
        if self.auto_port {
            self.quic_port.unwrap_or(self.port)
        } else {
            self.port
        }
    }

    pub fn set_quic_port(&mut self, port: u16) {
        self.quic_port = Some(port);
    }

    pub fn generate_random_port(&self) -> u16 {
        use rand::Rng;
        let mut rng = rand::rng();
        let base = if self.role.is_global() { 5000 } else { 60000 };
        base + rng.random_range(0..10000)
    }

    pub fn apply_dht_role_defaults(&mut self) {
        if let Some(ref mut dht) = self.dht {
            if self.role.is_global() && !dht.full_network_view {
                dht.full_network_view = true;
            }
            if self.role.is_edge() && !dht.routing_enabled {
                dht.routing_enabled = true;
            }
        }
    }

    pub fn genesis_key(&self) -> Option<&GenesisKeyConfig> {
        self.genesis_key.as_ref()
    }

    pub fn is_genesis_node(&self) -> bool {
        self.genesis_key
            .as_ref()
            .map(|g| g.is_first_node)
            .unwrap_or(false)
    }

    pub fn verify_genesis_signature(&self, data: &str, signature: &[u8]) -> bool {
        self.genesis_key
            .as_ref()
            .map(|g| g.verify(data, signature))
            .unwrap_or(false)
    }

    pub fn network_id(&self) -> String {
        self.network_id
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }

    pub fn mesh_name(&self) -> Option<&str> {
        self.mesh_name.as_deref()
    }

    pub fn org_config(&self) -> OrgConfig {
        self.org_config.clone().unwrap_or_default()
    }

    pub fn make_mesh_upstream_id(&self, service_id: &str) -> String {
        format!("{}.{}", self.router_id(), service_id)
    }

    pub fn parse_mesh_upstream_id(full_id: &str) -> Option<(&str, &str)> {
        let dot_pos = full_id.find('.')?;
        if dot_pos == 0 || dot_pos == full_id.len() - 1 {
            return None;
        }
        Some((&full_id[..dot_pos], &full_id[dot_pos + 1..]))
    }

    pub fn generate_network_id() -> String {
        format!("net-{}", uuid::Uuid::new_v4())
    }

    pub fn is_global_node(&self) -> bool {
        self.role.is_global()
    }

    pub fn is_global_node_verified(&self) -> bool {
        self.global_node_key.is_some()
    }

    pub fn can_serve_direct(&self) -> bool {
        if self.disable_direct_origin {
            return false;
        }
        if self.role.is_origin() && self.can_serve_origin_direct {
            return true;
        }
        false
    }

    pub fn is_trusted_node(&self) -> bool {
        if self.node_identity.is_trusted {
            return true;
        }
        self.role.is_global() && self.capabilities_enabled
    }

    pub fn is_capabilities_enabled(&self) -> bool {
        self.capabilities_enabled
    }

    pub fn can_grant_trusted(&self) -> bool {
        self.role.is_global() && self.capabilities_enabled
    }

    pub fn should_become_global(&self, genesis_signature: &[u8]) -> bool {
        if let Some(ref genesis_key) = self.genesis_key {
            let data = format!(
                "become-global:{}",
                self.node_id.as_ref().unwrap_or(&String::new())
            );
            genesis_key.verify(&data, genesis_signature)
        } else {
            false
        }
    }

    pub fn verify_global_node_key(&self, key: &str) -> bool {
        if let Some(ref expected_key) = self.global_node_key {
            return bool::from(expected_key.as_bytes().ct_eq(key.as_bytes()));
        }
        false
    }

    pub fn generate_global_node_key() -> Result<String, hkdf::InvalidLength> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let uuid = uuid::Uuid::new_v4();
        let entropy = uuid.as_bytes();
        let hk = Hkdf::<Sha256>::new(None, entropy);
        let mut okm = [0u8; 32];
        hk.expand(b"synvoid-global-node-key", &mut okm)?;
        Ok(hex::encode(okm))
    }

    pub fn cert_rotation_interval(&self) -> Option<std::time::Duration> {
        self.tls
            .cert_rotation_interval_secs
            .map(std::time::Duration::from_secs)
    }

    pub fn is_tls_configured(&self) -> bool {
        self.tls.cert_path.is_some() && self.tls.key_path.is_some()
    }

    pub fn supports_tls_1_3(&self) -> bool {
        self.tls.min_tls_version == "1.3"
    }

    pub fn verify_seed(&self, seed: &MeshSeedNode) -> bool {
        if let Some(ref seed_network) = seed.network_id {
            if let Some(ref our_network) = self.network_id {
                if seed_network != our_network {
                    tracing::warn!(
                        "Seed {} belongs to different network: {} vs {}",
                        seed.address,
                        seed_network,
                        our_network
                    );
                    return false;
                }
            }
        }

        if let Some(ref seed_key) = seed.global_node_key {
            if let Some(ref our_key) = self.global_node_key {
                if seed_key != our_key {
                    tracing::warn!("Seed {} has invalid global node key", seed.address);
                    return false;
                }
            } else if self.is_global_node() {
                tracing::warn!(
                    "Seed {} requires global node key but none configured",
                    seed.address
                );
                return false;
            }
        }

        true
    }

    pub fn get_verified_seeds(&self) -> Vec<MeshSeedNode> {
        if !self.enabled {
            return Vec::new();
        }
        self.seeds
            .iter()
            .filter(|seed| self.verify_seed(seed))
            .cloned()
            .collect()
    }
}
