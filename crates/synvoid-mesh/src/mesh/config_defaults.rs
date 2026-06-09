use super::*;

pub fn default_mesh_port() -> u16 {
    5001
}

pub fn default_bandwidth_report_interval() -> u64 {
    30
}

pub fn default_stale_cache_ttl_secs() -> u64 {
    60
}

pub fn default_ratelimit_block_advertisement() -> bool {
    true
}

pub fn default_global_seeds() -> Vec<MeshSeedNode> {
    vec![]
}

pub fn default_request_timeout_secs() -> u64 {
    30
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: None,
            role: MeshNodeRole::EDGE,
            network_id: None,
            mesh_name: None,
            global_node_key: None,
            bind_address: None,
            port: default_mesh_port(),
            quic_port: None,
            auto_port: true,
            seeds: Vec::new(),
            peers: Vec::new(),
            local_upstreams: HashMap::new(),
            service_policy: MeshServicePolicy::default(),
            routing: MeshRoutingConfig::default(),
            tls: MeshTlsConfig::default(),
            transport_preference: MeshTransportPreference::Quic,
            connection: MeshConnectionConfig::default(),
            persistence: MeshPersistenceConfig::default(),
            proxy_cache: None,
            upstream_resolution: None,
            threat_intel: ThreatIntelligenceConfig::default(),
            yara_rules: YaraRulesMeshConfig::default(),
            node_identity: NodeIdentityConfig::default(),
            tier_config: TierConfig::default(),
            bandwidth_report_interval_secs: default_bandwidth_report_interval(),
            stale_cache_ttl_secs: default_stale_cache_ttl_secs(),
            ratelimit_block_advertisement: default_ratelimit_block_advertisement(),
            origin_signing_key: None,
            global_node: GlobalNodeConfig::default(),
            genesis_key: None,
            dht: None,
            dht_access_for_edge: None,
            org_config: None,
            can_serve_origin_direct: true,
            disable_direct_origin: false,
            capabilities_enabled: true,
            require_tier_claim: false,
            request_timeout_secs: default_request_timeout_secs(),
            stake: None,
            seed_tofu: None,
            authority_freshness: AuthorityFreshnessConfig::default(),
            cached_pow: Arc::new(RwLock::new(None)),
            mlkem: Some(MeshMlKemConfig::default()),
        }
    }
}
