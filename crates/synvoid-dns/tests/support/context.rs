//! Common test context and DnsServer setup helpers.
//!
//! These functions build `QueryContext` values with sensible defaults
//! (all optional fields `None`).  Tests that need non-default context
//! fields (cache, DNSSEC, update handler, etc.) should construct
//! `QueryContext` directly and may still use [`super::zone::build_test_zone`]
//! for zone creation.
//!
//! No global state is mutated.  All values are returned explicitly.
#![allow(dead_code)]
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::server::{QueryContext, ShardedZoneStore};
use synvoid_dns::zone_trie::ZoneTrie;

/// Set up the default zone store, zone trie, and ECS config for testing.
///
/// Returns `(zones, zone_trie, ecs_config)` where:
/// - `zones` is an `Arc<ShardedZoneStore>` containing the default
///   [`super::zone::build_test_zone`] zone keyed by `"test.local"`.
/// - `zone_trie` is an `Arc<RwLock<ZoneTrie>>` with `"test.local"` inserted.
/// - `ecs_config` is `EcsFilterConfig::default()`.
///
/// Callers keep the returned Arcs alive for the test duration; they
/// must outlive any `QueryContext` built from them.
pub fn setup() -> (
    Arc<ShardedZoneStore>,
    Arc<RwLock<ZoneTrie>>,
    EcsFilterConfig,
) {
    let zone = super::zone::build_test_zone();
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone);
    let mut trie = ZoneTrie::new();
    trie.insert("test.local");
    let zone_trie = Arc::new(RwLock::new(trie));
    let ecs_config = EcsFilterConfig::default();
    (zones, zone_trie, ecs_config)
}

/// Build a `QueryContext` with all optional fields set to `None`.
///
/// This matches the context shape used by the majority of integration
/// tests (authoritative queries, interop, etc.).  Fields you will
/// typically override after construction:
///
/// - `cache` — for cache-hit / serve-stale tests
/// - `update_handler` — for dynamic UPDATE tests
/// - `notify_handler` — for NOTIFY tests
/// - `zone_transfer` — for AXFR/IXFR tests
/// - `dnssec` — for DNSSEC validation tests
/// - `ecs_filter_config` — for ECS filtering tests (already wired to `ecs_filter_config`)
///
/// # Lifetime
///
/// The returned `QueryContext` borrows from `zones`, `zone_trie`, and
/// `ecs_filter_config`.  The caller must keep those values alive at
/// least as long as the context.
pub fn make_ctx<'a>(
    zones: &'a Arc<ShardedZoneStore>,
    zone_trie: &'a Arc<RwLock<ZoneTrie>>,
    ecs_filter_config: &'a EcsFilterConfig,
) -> QueryContext<'a> {
    QueryContext {
        zones,
        zone_trie,
        geoip_lookup: None,
        min_geo_ttl: 0,
        negative_cache_ttl: 300,
        cache: None,
        dnssec: None,
        signer_name: None,
        query_validator: None,
        firewall: None,
        connection_limits: None,
        max_idle_time: None,
        zone_transfer: None,
        ecs_filter_config,
        rate_limiter: None,
        rrl_enabled: false,
        update_handler: None,
        notify_handler: None,
        query_coalescer: None,
        dns64_translator: None,
        acme_dns_challenges: None,
        cookie_server: None,
        #[cfg(feature = "mesh")]
        mesh_registry: None,
    }
}

/// Find an available ephemeral port by binding to port 0.
///
/// Returns the port number.  The bound socket is dropped immediately,
/// releasing the port.  There is an inherent TOCTOU race — another
/// process may claim the port between drop and the server's bind.  In
/// practice this is rare for ephemeral ports.
pub fn ephemeral_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral");
    socket.local_addr().unwrap().port()
}

/// Create a `DnsConfig` for `127.0.0.1` on the given port.
///
/// The returned config has default settings with `cache_enabled` left
/// at its default (true).  Set `config.settings.cache_enabled = false`
/// in tests that need a cold server.
pub fn make_config(port: u16) -> synvoid_config::dns::DnsConfig {
    synvoid_config::dns::DnsConfig {
        bind_address: "127.0.0.1".to_string(),
        port,
        ..Default::default()
    }
}
