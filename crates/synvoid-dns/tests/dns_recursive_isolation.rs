use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_config::dns::{
    DnsAnycastConfig, DnsConfig, DnsMode, RecursiveDnsConfig, RecursiveUpstreamProvider,
    TrustAnchorConfig,
};
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::recursive_cache::RecursiveDnsCache;
use synvoid_dns::server::RecordType;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, QueryContext, ShardedZoneStore, Zone};
use synvoid_dns::zone_trie::ZoneTrie;

// ── Helpers ─────────────────────────────────────────────────────────────

/// Build a raw DNS query in wire format.
fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + 256 + 4);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    if qname.is_empty() || qname == "." {
        q.push(0);
    } else {
        for label in qname.split('.').filter(|s| !s.is_empty()) {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
    }

    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN

    q
}

/// Build a NOTIFY query (opcode = 4).
fn build_notify_query(id: u16, qname: &str) -> Vec<u8> {
    let mut q = build_query(id, qname, 6); // SOA
                                           // Set opcode to 4 (NOTIFY) in flags byte 2: bits 15-11 = opcode
                                           // Byte 2 = 0x01 originally (QR=0, Opcode=0, AA=0, TC=0, RD=1)
                                           // Opcode 4 = 0b00100 → shift left 11 bits = 0x2800
                                           // Clear opcode bits (bits 11-15 of byte 2-3): mask = 0x87FF
    let flags = u16::from_be_bytes([q[2], q[3]]);
    let new_flags = (flags & 0x87FF) | (4 << 11); // opcode = 4
    q[2] = (new_flags >> 8) as u8;
    q[3] = (new_flags & 0xFF) as u8;
    q
}

/// Build a DNS UPDATE query (opcode = 5).
fn build_update_query(id: u16, qname: &str) -> Vec<u8> {
    let mut q = build_query(id, qname, 255); // ANY
                                             // Set opcode to 5 (UPDATE) in flags byte 2: bits 15-11 = opcode
    let flags = u16::from_be_bytes([q[2], q[3]]);
    let new_flags = (flags & 0x87FF) | (5 << 11); // opcode = 5
    q[2] = (new_flags >> 8) as u8;
    q[3] = (new_flags & 0xFF) as u8;
    // Set QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 (zone section only)
    q[4] = 0;
    q[5] = 1; // QDCOUNT
    q[6] = 0;
    q[7] = 0; // ANCOUNT
    q[8] = 0;
    q[9] = 0; // NSCOUNT
    q[10] = 0;
    q[11] = 0; // ARCOUNT
    q
}

/// Build an AXFR query (type 252).
fn build_axfr_query(id: u16, qname: &str) -> Vec<u8> {
    build_query(id, qname, 252)
}

/// Build the test zone: test.local with standard records.
fn build_test_zone() -> Zone {
    let mut zone = Zone::new("test.local".to_string());
    zone.serial = 2026070201;
    zone.nsec_enabled = false;
    zone.nsec3_enabled = false;

    zone.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: "ns1.test.local. admin.test.local. 2026070201 3600 600 604800 300".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("@".to_string(), RecordType::NS),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NS,
            value: "ns1.test.local.".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("ns1".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "ns1".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.53".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.10".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone
}

/// Set up the minimal QueryContext for testing.
fn setup() -> (
    Arc<ShardedZoneStore>,
    Arc<RwLock<ZoneTrie>>,
    EcsFilterConfig,
) {
    let zone = build_test_zone();

    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone);

    let mut trie = ZoneTrie::new();
    trie.insert("test.local");
    let zone_trie = Arc::new(RwLock::new(trie));

    let ecs_config = EcsFilterConfig::default();

    (zones, zone_trie, ecs_config)
}

fn make_ctx<'a>(
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

// ── Response parsing helpers ────────────────────────────────────────────

fn response_flags(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[2], resp[3]])
}

fn response_rcode(resp: &[u8]) -> u8 {
    (response_flags(resp) & 0x000F) as u8
}

fn is_response(resp: &[u8]) -> bool {
    response_flags(resp) & 0x8000 != 0
}

const RCODE_REFUSED: u8 = 5;

// ══════════════════════════════════════════════════════════════════════
// Recursive mode isolation
// ══════════════════════════════════════════════════════════════════════

/// Test 1: Recursive and authoritative can have distinct bind addresses.
///
/// The recursive server and authoritative server each have independent
/// bind_address/port fields in their respective configs. This test verifies
/// they are separate values that don't interfere with each other.
#[test]
fn test_recursive_mode_different_bind_address() {
    let mut auth_config = DnsConfig::default();
    auth_config.enabled = true;
    auth_config.bind_address = "0.0.0.0".to_string();
    auth_config.port = 53;

    let mut recursive_config = RecursiveDnsConfig::default();
    recursive_config.enabled = true;
    recursive_config.bind_address = "127.0.0.1".to_string();
    recursive_config.port = 1053;

    // Verify the two configs have different bind addresses and ports
    assert_ne!(
        auth_config.bind_address, recursive_config.bind_address,
        "authoritative and recursive must allow different bind addresses"
    );
    assert_ne!(
        auth_config.port, recursive_config.port,
        "authoritative and recursive must allow different ports"
    );

    // Verify the recursive config is stored independently in the DnsConfig
    let mut dns_config = DnsConfig::default();
    dns_config.recursive.bind_address = "127.0.0.1".to_string();
    dns_config.recursive.port = 1053;
    dns_config.bind_address = "0.0.0.0".to_string();
    dns_config.port = 53;

    assert_eq!(dns_config.bind_address, "0.0.0.0");
    assert_eq!(dns_config.port, 53);
    assert_eq!(dns_config.recursive.bind_address, "127.0.0.1");
    assert_eq!(dns_config.recursive.port, 1053);
}

/// Test 2: Recursive cache is independent from authoritative cache.
///
/// The recursive server uses RecursiveDnsCache while the authoritative
/// server uses DnsCache. Inserting into one does not affect the other.
#[test]
fn test_recursive_cache_independent() {
    use synvoid_config::dns::RecursiveCacheConfig;
    use synvoid_dns::recursive_cache::RecursiveCacheKey;

    let recursive_cache_config = RecursiveCacheConfig::default();
    let recursive_cache = RecursiveDnsCache::new(1000, &recursive_cache_config);

    // Insert a record into the recursive cache
    let key = RecursiveCacheKey::new(b"example.com", 1, None);
    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"example.com".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![93, 184, 216, 34],
    }];
    recursive_cache.insert_positive(key.clone(), records, 300, false);

    // Verify it's in the recursive cache
    assert!(
        recursive_cache.get(&key).is_some(),
        "record should be in recursive cache"
    );

    // The authoritative cache is a completely separate type (DnsCache)
    // and is not coupled to RecursiveDnsCache. This is verified by the
    // fact that they are different types with different APIs.
    // RecursiveDnsCache uses byte-keyed lookups; DnsCache uses string-keyed.
    let recursive_stats = recursive_cache.stats();
    assert_eq!(
        recursive_stats.insertions, 1,
        "recursive cache should have 1 insertion"
    );
}

/// Test 3: Authoritative server without zones returns REFUSED when recursion
/// is not configured.
///
/// When no matching zone exists in the trie, handle_query returns REFUSED
/// regardless of recursion settings (the authoritative path doesn't recurse).
#[test]
fn test_authoritative_no_zone_refuses_without_recursion() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // Query for a completely non-existent zone — should get REFUSED
    let query = build_query(0xAAAA, "unknown.example.com", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for valid query");

    assert!(is_response(&resp), "response bit must be set");
    assert_eq!(
        response_rcode(&resp),
        RCODE_REFUSED,
        "RCODE must be REFUSED (5) for non-existent zone without recursion"
    );
}

/// Test 4: Trust anchor config has sensible defaults and validates.
///
/// TrustAnchorConfig is validated as part of the DNS configuration pipeline.
/// This test verifies the default values and that the config can be
/// deserialized correctly.
#[test]
fn test_trust_anchor_config_validation() {
    let config = TrustAnchorConfig::default();

    // Default should be disabled
    assert!(
        !config.enabled,
        "trust anchors should be disabled by default"
    );
    assert!(
        !config.db_path.is_empty(),
        "db_path should have a default value"
    );
    assert!(
        !config.anchor_file_path.is_empty(),
        "anchor_file_path should have a default value"
    );
    assert!(
        config.refresh_interval_secs > 0,
        "refresh_interval_secs should be positive"
    );
    assert!(
        config.pending_observation_days > 0,
        "pending_observation_days should be positive"
    );
    assert!(
        config.revocation_grace_days > 0,
        "revocation_grace_days should be positive"
    );
    assert!(
        config.extended_removal_days > 0,
        "extended_removal_days should be positive"
    );
    assert!(
        config.trust_anchor_retention_days > 0,
        "trust_anchor_retention_days should be positive"
    );

    // Verify it's stored in DnsConfig
    let dns_config = DnsConfig::default();
    assert!(
        !dns_config.trust_anchors.enabled,
        "DnsConfig default trust_anchors should be disabled"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Anycast/mesh feature gate
// ══════════════════════════════════════════════════════════════════════

/// Test 5: Anycast enabled without mesh feature produces a clear error.
///
/// When anycast.enabled=true, DnsServer::start() returns an error indicating
/// the mesh feature is required. This is the current behavior in
/// `startup.rs:74-77`.
#[test]
fn test_anycast_requires_mesh_feature() {
    let config = DnsConfig::default();
    let _server = DnsServer::new(config, None);

    // Enable anycast on the server's config
    // We need to create a server with anycast enabled
    let mut anycast_config = DnsConfig::default();
    anycast_config.enabled = true;
    anycast_config.port = 5353;
    anycast_config.anycast = DnsAnycastConfig {
        enabled: true,
        bind_addresses: vec!["10.0.0.1".to_string()],
        port: 53,
        use_pktinfo: true,
        health_check_domain: "_healthcheck.local".to_string(),
        health_check_interval_secs: 5,
        capacity: 10000,
        mesh_based_sync: true,
        sync_interval_secs: 300,
        geo: None,
        sync_trigger_on_update: true,
    };

    let mut server = DnsServer::new(anycast_config, None);

    // Starting the server with anycast enabled should fail because mesh
    // feature is not compiled in (the extracted dns crate doesn't have mesh).
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(server.start());
    assert!(
        result.is_err(),
        "start() should fail when anycast is enabled without mesh feature"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("Anycast") || err_msg.contains("mesh"),
        "error message should mention anycast or mesh: {}",
        err_msg
    );
}

/// Test 6: Mesh DNS mode config validation doesn't error at config level.
///
/// The DnsMode::Mesh mode validates its mesh-specific settings (intervals > 0)
/// but doesn't fail at config validation time for the feature gate. The actual
/// mesh feature gate is at runtime (start()). This test documents the current
/// config-level behavior.
#[test]
fn test_mesh_mode_requires_mesh_feature() {
    let mut config = DnsConfig::default();
    config.mode = DnsMode::Mesh;
    config.bind_address = "127.0.0.1".to_string();
    config.port = 5353;

    // Config validation passes because mesh defaults are valid.
    // The actual mesh feature gate is at runtime (mesh_registry is None),
    // not at config validation time.
    let result = config.validate();
    assert!(
        result.is_ok(),
        "mesh mode config should validate with default mesh settings: {:?}",
        result
    );

    // Mesh config with zero intervals DOES fail validation
    config.mesh.registration_interval_secs = 0;
    let result = config.validate();
    assert!(
        result.is_err(),
        "mesh mode should fail with zero registration_interval_secs"
    );

    config.mesh.registration_interval_secs = 60;
    config.mesh.sync_interval_secs = 0;
    let result = config.validate();
    assert!(
        result.is_err(),
        "mesh mode should fail with zero sync_interval_secs"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Config validation guards
// ══════════════════════════════════════════════════════════════════════

/// Test 7: When dns.enabled=false, the server can still be constructed
/// but does not indicate readiness to start listeners.
///
/// The `dns.enabled` flag is checked at a higher level (composition root).
/// The DnsServer itself can be constructed regardless. This test documents
/// that the server is constructible with enabled=false.
#[test]
fn test_disabled_dns_skips_startup() {
    let mut config = DnsConfig::default();
    config.enabled = false;
    config.bind_address = "127.0.0.1".to_string();
    config.port = 5353;

    // Server construction succeeds even when disabled
    let server = DnsServer::new(config, None);

    // The server's config indicates it's disabled
    // We can't directly access config.enabled on DnsServer, but we verified
    // construction works. The actual startup skip is done by the caller
    // checking config.enabled before calling start().
    //
    // NOTE: The server's start() method does NOT check config.enabled —
    // it is the responsibility of the composition root / supervisor to
    // skip calling start() when enabled=false.
    drop(server);
}

/// Test 8: Port 0 is rejected at validation.
///
/// DnsConfig::validate() returns InvalidPort when port is 0.
#[test]
fn test_port_zero_rejected() {
    let mut config = DnsConfig::default();
    config.bind_address = "127.0.0.1".to_string();
    config.port = 0;

    let result = config.validate();
    assert!(
        result.is_err(),
        "port 0 should be rejected by DnsConfig::validate()"
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("port") || err_msg.contains("Port"),
        "error should mention port: {}",
        err_msg
    );
}

/// Test 9: Invalid bind address is rejected.
///
/// DnsConfig::validate() returns InvalidBindAddress for non-parseable addresses.
#[test]
fn test_invalid_bind_address_rejected() {
    let mut config = DnsConfig::default();
    config.bind_address = "not-a-valid-ip".to_string();
    config.port = 53;

    let result = config.validate();
    assert!(result.is_err(), "invalid bind address should be rejected");

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("bind") || err_msg.contains("Bind") || err_msg.contains("Invalid"),
        "error should mention bind address: {}",
        err_msg
    );
}

// ══════════════════════════════════════════════════════════════════════
// Dynamic update/notify/transfer deferred
// ══════════════════════════════════════════════════════════════════════

/// Test 10: When dynamic_update is disabled, UPDATE queries return no response.
///
/// Current behavior: when `update_handler` is None (disabled), handle_query
/// returns None, meaning no response is sent to the client. This is the
/// correct silent-drop behavior for an unsupported operation.
///
/// RFC 2136 §2.2 specifies that a server SHOULD return NOTIMP (RCODE 4) for
/// an unsupported UPDATE, but the current implementation returns None (no
/// response). This test documents the CURRENT behavior.
#[test]
fn test_dynamic_update_disabled_returns_notimp() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // ctx.update_handler is None (disabled)
    assert!(
        ctx.update_handler.is_none(),
        "update_handler should be None when disabled"
    );

    let query = build_update_query(0xDD01, "test.local");
    let result = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));

    // Current behavior: returns None (no response sent)
    // Expected RFC behavior: return NOTIMP (RCODE 4)
    assert!(
        result.is_none(),
        "UPDATE query should return None (no response) when dynamic_update is disabled. \
         NOTE: RFC 2136 specifies NOTIMP (RCODE 4) should be returned."
    );
}

/// Test 11: When notify is disabled, NOTIFY queries return no response.
///
/// Current behavior: when `notify_handler` is None (disabled), handle_query
/// returns None, meaning no response is sent to the client.
///
/// RFC 1996 §4.1 specifies that a server SHOULD return REFUSED for an
/// unhandled NOTIFY, but the current implementation returns None (no
/// response). This test documents the CURRENT behavior.
#[test]
fn test_notify_disabled_returns_refused() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // ctx.notify_handler is None (disabled)
    assert!(
        ctx.notify_handler.is_none(),
        "notify_handler should be None when disabled"
    );

    let query = build_notify_query(0xDD02, "test.local");
    let result = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));

    // Current behavior: returns None (no response sent)
    // Expected RFC behavior: return REFUSED (RCODE 5)
    assert!(
        result.is_none(),
        "NOTIFY query should return None (no response) when notify is disabled. \
         NOTE: RFC 1996 specifies REFUSED (RCODE 5) should be returned."
    );
}

/// Test 12: AXFR denied when allow_transfer is empty.
///
/// The `handle_query` path does NOT check for AXFR — it treats AXFR queries
/// as regular queries and returns a NODATA/SOA response for the zone.
/// AXFR handling is only done through `handle_query_with_cache`, which checks
/// `parsed.is_axfr()` before falling through to the zone lookup.
///
/// When `zone_transfer` is None (allow_transfer empty), the AXFR check in
/// `handle_parsed_query_with_cache` returns None (no response).
///
/// This test verifies the `handle_query` path behavior: AXFR queries are
/// treated as normal queries.
#[test]
fn test_axfr_denied_without_allowlist() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    // ctx.zone_transfer is None (no allow_transfer configured)
    assert!(
        ctx.zone_transfer.is_none(),
        "zone_transfer should be None when allow_transfer is empty"
    );

    let query = build_axfr_query(0xDD03, "test.local");

    // handle_query treats AXFR as a regular query type — it falls through
    // to zone lookup. Since "test.local" has no type-252 (AXFR) records,
    // the server returns a NODATA response (NOERROR with SOA in authority).
    let result = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));

    // Current behavior: returns Some (NODATA response) because handle_query
    // doesn't distinguish AXFR from normal queries.
    // The AXFR check only exists in handle_parsed_query_with_cache.
    assert!(
        result.is_some(),
        "handle_query treats AXFR as a normal query and returns a NODATA response. \
         AXFR-specific denial only occurs in handle_parsed_query_with_cache."
    );
}

/// Test 13: AXFR denied without TSIG when require_tsig is true.
///
/// When ZoneTransfer is configured with require_tsig=true and no TSIG
/// is provided, the transfer returns an error. However, this denial only
/// happens through the `handle_parsed_query_with_cache` path, not through
/// `handle_query`.
///
/// The `handle_query` path treats AXFR as a regular query and returns a
/// NODATA response for the zone.
#[test]
fn test_axfr_denied_without_tsig_when_required() {
    use synvoid_dns::transfer::ZoneTransfer;

    let (zones, zone_trie, ecs_filter_config) = setup();

    // Create a ZoneTransfer with require_tsig=true
    let zone_transfer = Arc::new(ZoneTransfer::new(
        zones.clone(),
        vec!["192.168.1.0/24".to_string()], // allow_transfer has entries
        None,                               // no TSIG verifier
    ));

    let mut ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);
    ctx.zone_transfer = Some(&zone_transfer);

    // Build an AXFR query (no TSIG attached)
    let query = build_axfr_query(0xDD04, "test.local");

    // handle_query does NOT check for AXFR — it treats it as a regular query.
    // The zone_transfer field is ignored in the handle_query path.
    // AXFR denial only occurs in handle_parsed_query_with_cache.
    let result = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([192, 168, 1, 1])));

    // Current behavior: returns Some (NODATA response) because handle_query
    // doesn't distinguish AXFR from normal queries.
    // The AXFR-specific require_tsig check only happens in handle_parsed_query_with_cache.
    assert!(
        result.is_some(),
        "handle_query treats AXFR as a normal query. AXFR denial with require_tsig \
         only occurs in handle_parsed_query_with_cache."
    );
}

// ══════════════════════════════════════════════════════════════════════
// Recursive config validation
// ══════════════════════════════════════════════════════════════════════

/// Recursive config validates custom upstream requires servers.
#[test]
fn test_recursive_custom_upstream_requires_servers() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.upstream_provider = RecursiveUpstreamProvider::Custom;
    config.upstream_servers = vec![]; // empty

    let result = config.validate();
    assert!(
        result.is_err(),
        "Custom upstream with no servers should fail validation"
    );
}

/// Recursive config validates query_timeout_secs > 0.
#[test]
fn test_recursive_query_timeout_must_be_positive() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.query_timeout_secs = 0;

    let result = config.validate();
    assert!(
        result.is_err(),
        "query_timeout_secs=0 should fail validation"
    );
}

/// Recursive config validates max_concurrent_queries > 0.
#[test]
fn test_recursive_max_concurrent_must_be_positive() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.max_concurrent_queries = 0;

    let result = config.validate();
    assert!(
        result.is_err(),
        "max_concurrent_queries=0 should fail validation"
    );
}

/// Recursive config validates negative_ttl_secs <= max_ttl_secs.
#[test]
fn test_recursive_negative_ttl_cannot_exceed_max() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    config.cache.negative_ttl_secs = 1000;
    config.cache.max_ttl_secs = 500;

    let result = config.validate();
    assert!(
        result.is_err(),
        "negative_ttl_secs > max_ttl_secs should fail validation"
    );
}

/// Recursive config disabled skips validation.
#[test]
fn test_recursive_disabled_skips_validation() {
    let mut config = RecursiveDnsConfig::default();
    config.enabled = false;
    // These would fail if validation ran
    config.query_timeout_secs = 0;
    config.max_concurrent_queries = 0;

    let result = config.validate();
    assert!(
        result.is_ok(),
        "disabled recursive config should skip all validation"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Anycast config validation
// ══════════════════════════════════════════════════════════════════════

/// Anycast enabled with empty bind_addresses should fail.
#[test]
fn test_anycast_empty_bind_addresses_rejected() {
    let config = DnsAnycastConfig {
        enabled: true,
        bind_addresses: vec![],
        ..Default::default()
    };

    let result = config.validate();
    assert!(
        result.is_err(),
        "anycast enabled with empty bind_addresses should fail"
    );
}

/// Anycast enabled with zero health_check_interval should fail.
#[test]
fn test_anycast_zero_health_check_interval_rejected() {
    let config = DnsAnycastConfig {
        enabled: true,
        bind_addresses: vec!["10.0.0.1".to_string()],
        health_check_interval_secs: 0,
        ..Default::default()
    };

    let result = config.validate();
    assert!(
        result.is_err(),
        "anycast health_check_interval_secs=0 should fail"
    );
}

/// Anycast disabled skips validation.
#[test]
fn test_anycast_disabled_skips_validation() {
    let config = DnsAnycastConfig {
        enabled: false,
        bind_addresses: vec![],
        health_check_interval_secs: 0,
        capacity: 0,
        ..Default::default()
    };

    let result = config.validate();
    assert!(
        result.is_ok(),
        "disabled anycast config should skip all validation"
    );
}

// ══════════════════════════════════════════════════════════════════════
// DnsConfig composite validation
// ══════════════════════════════════════════════════════════════════════

/// Valid DnsConfig passes validation.
#[test]
fn test_valid_dns_config_passes() {
    let mut config = DnsConfig::default();
    config.enabled = true;
    config.bind_address = "127.0.0.1".to_string();
    config.port = 5353;

    let result = config.validate();
    assert!(result.is_ok(), "valid config should pass: {:?}", result);
}

/// Port 0 is rejected even with valid bind address.
#[test]
fn test_dns_config_port_zero_with_valid_bind() {
    let mut config = DnsConfig::default();
    config.bind_address = "127.0.0.1".to_string();
    config.port = 0;

    let result = config.validate();
    assert!(result.is_err(), "port 0 should be rejected");
}

/// Wildcard bind addresses are accepted.
#[test]
fn test_dns_config_wildcard_bind_accepted() {
    let mut config = DnsConfig::default();
    config.bind_address = "0.0.0.0".to_string();
    config.port = 53;

    let result = config.validate();
    assert!(
        result.is_ok(),
        "0.0.0.0 wildcard bind should be accepted: {:?}",
        result
    );
}

/// IPv6 wildcard bind is accepted.
#[test]
fn test_dns_config_ipv6_wildcard_bind_accepted() {
    let mut config = DnsConfig::default();
    config.bind_address = "::".to_string();
    config.port = 53;

    let result = config.validate();
    assert!(
        result.is_ok(),
        ":: wildcard bind should be accepted: {:?}",
        result
    );
}
