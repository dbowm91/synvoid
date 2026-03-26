use super::*;

impl MeshConfig {
    pub fn with_defaults_if_enabled(mut self) -> Self {
        if self.enabled {
            if self.seeds.is_empty() && self.role == MeshNodeRole::Edge {
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
            if genesis.is_first_node && self.role != MeshNodeRole::Global {
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
        if self.role == MeshNodeRole::Global && self.genesis_key.is_none() {
            tracing::warn!(
                "Global node without genesis key - cannot add/remove other global nodes"
            );
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
        self.node_identity.load_or_generate()
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

    pub fn get_wireguard_port(&self) -> u16 {
        self.wireguard_port.unwrap_or(self.wireguard.listen_port)
    }

    pub fn get_advertised_quic_port(&self) -> u16 {
        if self.auto_port {
            self.quic_port.unwrap_or(self.port)
        } else {
            self.port
        }
    }

    pub fn get_advertised_wireguard_port(&self) -> Option<u16> {
        if self.auto_port {
            self.wireguard_port.or(Some(self.wireguard.listen_port))
        } else {
            Some(self.wireguard.listen_port)
        }
    }

    pub fn set_quic_port(&mut self, port: u16) {
        self.quic_port = Some(port);
    }

    pub fn set_wireguard_port(&mut self, port: u16) {
        self.wireguard_port = Some(port);
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
            return expected_key == key;
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
        hk.expand(b"maluwaf-global-node-key", &mut okm)?;
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
