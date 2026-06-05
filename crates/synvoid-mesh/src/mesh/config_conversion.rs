use super::*;

impl From<MeshMlKemConfig> for crate::session::SessionConfig {
    fn from(config: MeshMlKemConfig) -> Self {
        crate::session::SessionConfig::new(config.session_ttl_secs, config.rotation_interval_secs)
    }
}

impl From<MeshDhtConfig> for crate::dht::DhtConfig {
    fn from(config: MeshDhtConfig) -> Self {
        Self {
            enabled: config.enabled,
            listen_port: config.listen_port,
            bootstrap_nodes: config.bootstrap_nodes,
            write_quorum: config.write_quorum,
            read_quorum: config.read_quorum,
            replication_factor: 20,
            query_timeout: std::time::Duration::from_secs(config.query_timeout_secs),
            bootstrap_timeout: std::time::Duration::from_secs(config.bootstrap_timeout_secs),
            ping_interval: std::time::Duration::from_secs(30),
            record_ttl: Some(std::time::Duration::from_secs(3600)),
            consistency_level: config.consistency_level,
            disk_path: None,
            edge_cache_enabled: config.edge_cache_enabled,
            edge_cache_max_entries: config.edge_cache_max_entries,
            edge_cache_ttl_secs: config.edge_cache_ttl_secs,
            warm_up_on_connect: config.warm_up_on_connect,
            edge_write_enabled: config.edge_write_enabled,
            min_reputation_for_dht_write: config.min_reputation_for_dht_write,
            health_ttl_secs: config.health_ttl_secs,
            load_ttl_secs: config.load_ttl_secs,
            illegal_upstream_terms: config.illegal_upstream_terms,
            initial_sync_interval_secs: config.initial_sync_interval_secs,
            max_sync_interval_secs: config.max_sync_interval_secs,
            fanout_factor: config.fanout_factor,
            convergence_threshold: config.convergence_threshold,
            geo_routing: config.geo_routing,
            regional_hubs: config.regional_hubs,
        }
    }
}
