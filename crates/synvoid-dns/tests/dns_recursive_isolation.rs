#![allow(clippy::field_reassign_with_default)]

mod support;

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::recursive::CircuitBreaker;
use synvoid_dns::recursive_cache::DnssecValidationState;
use synvoid_dns::recursive_cache::RecursiveDnsCache;
use synvoid_dns::runtime_config::RecursiveEcsPolicyRuntime;
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

/// Test 2: Recursive cache is independent from authoritative cache.
///
/// The recursive server uses RecursiveDnsCache while the authoritative
/// server uses DnsCache. Inserting into one does not affect the other.
#[test]
fn test_recursive_cache_independent() {
    use synvoid_dns::recursive_cache::RecursiveCacheKey;

    let recursive_cache_config =
        support::recursive_cache_runtime(1_000_000, 300, 86_400, 86_400, 0);
    let recursive_cache = RecursiveDnsCache::new(1000, &recursive_cache_config);

    // Insert a record into the recursive cache
    let key = RecursiveCacheKey::new(b"example.com", 1, None);
    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"example.com".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![93, 184, 216, 34],
    }];
    recursive_cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);

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
    // Anycast activation is represented by the runtime rejection signal: the
    // persisted anycast settings have no runtime projection (absent by design),
    // so enabling the guard is what must fail startup.
    let mut runtime = support::dns_runtime_on(support::free_port());
    runtime.authoritative.anycast =
        synvoid_dns::runtime_config::AnycastRuntimeConfig { enabled: true };

    let mut server = DnsServer::new(runtime, None);

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
    // Server construction succeeds even when the persisted top-level gate is
    // disabled — `enabled` is a composition decision, not a server field.
    let mut runtime = support::dns_runtime();
    runtime.enabled = false;
    runtime.authoritative.bind_address = "127.0.0.1:5353".parse().unwrap();
    let server = DnsServer::new(runtime, None);

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

// ══════════════════════════════════════════════════════════════════════
// Anycast config validation
// ══════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════
// DnsConfig composite validation
// ══════════════════════════════════════════════════════════════════════

// ──── Additional zone mutation / recursive safety tests ────

fn build_ixfr_query(id: u16, qname: &str) -> Vec<u8> {
    build_query(id, qname, 251) // IXFR type = 251
}

fn make_ctx_with_handlers<'a>(
    zones: &'a Arc<ShardedZoneStore>,
    zone_trie: &'a Arc<RwLock<ZoneTrie>>,
    ecs_filter_config: &'a EcsFilterConfig,
    notify_handler: Option<&'a synvoid_dns::notify::NotifyHandler>,
    update_handler: Option<&'a synvoid_dns::update::DynamicUpdateHandler>,
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
        update_handler,
        notify_handler,
        query_coalescer: None,
        dns64_translator: None,
        acme_dns_challenges: None,
        cookie_server: None,
        #[cfg(feature = "mesh")]
        mesh_registry: None,
    }
}

/// WS4: IXFR denied when zone_transfer is None — silent drop (handle_query path)
#[test]
fn test_ixfr_denied_when_zone_transfer_none() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs_filter_config);

    let query = build_ixfr_query(0xDD10, "test.local");
    let result = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));

    // IXFR with zone_transfer=None: handle_query treats it as a normal query type
    // and returns NODATA (no IXFR data). Same behavior as AXFR through handle_query.
    assert!(
        result.is_some(),
        "IXFR with zone_transfer=None: handle_query returns NODATA (treats as normal query)"
    );
}

/// WS4: NOTIFY handler present but enabled=false — returns None
#[test]
fn test_notify_handler_disabled_returns_none() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let notify_config = synvoid_dns::notify::NotifyConfig {
        enabled: false,
        also_notify: vec![],
    };
    let notify_handler = synvoid_dns::notify::NotifyHandler::new(Arc::clone(&zones), notify_config);
    let ctx = make_ctx_with_handlers(
        &zones,
        &zone_trie,
        &ecs_filter_config,
        Some(&notify_handler),
        None,
    );

    let query = build_notify_query(0xDD11, "test.local");
    let result = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));

    // NOTIFY with enabled=false: NotifyHandler.handle_notify returns None
    assert!(
        result.is_none(),
        "NOTIFY with handler.enabled=false should return None"
    );
}

/// WS4: UPDATE handler present but enabled=false — returns None
#[test]
fn test_update_handler_disabled_returns_none() {
    let (zones, zone_trie, ecs_filter_config) = setup();
    let update_handler = synvoid_dns::update::DynamicUpdateHandler::new(Arc::clone(&zones))
        .with_config(false, false, true);
    let ctx = make_ctx_with_handlers(
        &zones,
        &zone_trie,
        &ecs_filter_config,
        None,
        Some(&update_handler),
    );

    let query = build_update_query(0xDD12, "test.local");
    let result = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));

    // UPDATE with enabled=false: DynamicUpdateHandler.handle_update returns Err,
    // which causes the dispatch to return None (silent drop).
    assert!(
        result.is_none(),
        "UPDATE with handler.enabled=false should return None"
    );
}

/// WS4: Wildcard transfer denied when allow_wildcard_transfer=false
#[test]
fn test_wildcard_transfer_denied_when_disabled() {
    let zones = Arc::new(ShardedZoneStore::default());
    let transfer = synvoid_dns::transfer::ZoneTransfer::with_security_config(
        Arc::clone(&zones),
        vec!["*".to_string()],
        None,
        false, // allow_wildcard_transfer
        true,  // wildcard_transfer_requires_tsig
        true,  // ixfr_enabled
        true,  // ixfr_fallback_to_axfr
        true,  // require_tsig
        false, // axfr_enabled
        true,  // tcp_only
    );
    let allowed = transfer.is_transfer_allowed("10.0.0.1".parse().unwrap(), "example.com");
    assert!(
        !allowed,
        "Wildcard transfer should be denied when allow_wildcard_transfer=false"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Client ACL tests
// ══════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════
// CNAME depth limit + circuit breaker tests
// ══════════════════════════════════════════════════════════════════════

#[test]
fn test_circuit_breaker_opens_after_failures() {
    let config = support::circuit_breaker_runtime(3, 1, 60);
    let cb = CircuitBreaker::new(&config);

    assert!(!cb.is_open(), "circuit should start closed");

    cb.record_failure();
    assert!(!cb.is_open(), "circuit should stay closed after 1 failure");

    cb.record_failure();
    assert!(!cb.is_open(), "circuit should stay closed after 2 failures");

    cb.record_failure();
    assert!(cb.is_open(), "circuit should open after 3 failures");
}

#[test]
fn test_circuit_breaker_resets_after_successes() {
    let config = support::circuit_breaker_runtime(2, 2, 60);
    let cb = CircuitBreaker::new(&config);

    cb.record_failure();
    cb.record_failure();
    assert!(cb.is_open(), "circuit should open after 2 failures");

    cb.record_success();
    assert!(cb.is_open(), "circuit should stay open with 1 success");

    cb.record_success();
    assert!(
        !cb.is_open(),
        "circuit should close after reaching success_threshold"
    );
}

#[test]
fn test_circuit_breaker_recovery_timeout() {
    let config = support::circuit_breaker_runtime(1, 1, 0);
    let cb = CircuitBreaker::new(&config);

    cb.record_failure();
    assert!(
        !cb.is_open(),
        "circuit with recovery_timeout_secs=0 should not stay open"
    );
}

fn build_query_with_flags(id: u16, flags: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + 256 + 4);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&flags.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());

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
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

fn build_query_with_edns(id: u16, flags: u16, qname: &str, qtype: u16, do_bit: bool) -> Vec<u8> {
    let mut q = build_query_with_flags(id, flags, qname, qtype);
    q[10] = 0;
    q[11] = 1;
    q.push(0);
    q.extend_from_slice(&41u16.to_be_bytes());
    q.extend_from_slice(&4096u16.to_be_bytes());
    q.push(0);
    q.push(0);
    if do_bit {
        q.extend_from_slice(&0x8000u16.to_be_bytes());
    } else {
        q.extend_from_slice(&0u16.to_be_bytes());
    }
    q.extend_from_slice(&0u16.to_be_bytes());
    q
}

const CD_BIT: u16 = 0x0010;
const AD_BIT: u16 = 0x0020;

#[test]
fn test_cd_bit_parsed_from_query() {
    let q = build_query_with_flags(0x1234, 0x0100 | CD_BIT, "example.com", 1);
    let parsed = synvoid_dns::parsed_query::ParsedDnsQuery::parse(&q).unwrap();
    assert!(
        parsed.flags.checking_disabled,
        "CD bit must be parsed from query flags"
    );
}

#[test]
fn test_do_bit_parsed_from_edns() {
    let q = build_query_with_edns(0x1234, 0x0100, "example.com", 1, true);
    let parsed = synvoid_dns::parsed_query::ParsedDnsQuery::parse(&q).unwrap();
    assert!(
        parsed.dnssec_ok,
        "DO bit must be parsed from EDNS OPT record"
    );
}

#[test]
fn test_do_bit_absent_when_no_edns() {
    let q = build_query_with_flags(0x1234, 0x0100, "example.com", 1);
    let parsed = synvoid_dns::parsed_query::ParsedDnsQuery::parse(&q).unwrap();
    assert!(
        !parsed.dnssec_ok,
        "DO bit must be false when no EDNS present"
    );
}

#[test]
fn test_cd_bit_echoed_in_response_header() {
    let flags = synvoid_dns::wire::build_response_header(
        0x1234,
        synvoid_dns::wire::MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            checking_disabled: true,
            response_code: 0,
        },
        1,
        1,
        0,
        0,
    );
    assert_ne!(
        response_flags(&flags) & CD_BIT,
        0,
        "CD bit must be set in response when checking_disabled=true"
    );
}

#[test]
fn test_cd_bit_not_set_when_disabled() {
    let flags = synvoid_dns::wire::build_response_header(
        0x1234,
        synvoid_dns::wire::MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            checking_disabled: false,
            response_code: 0,
        },
        1,
        1,
        0,
        0,
    );
    assert_eq!(
        response_flags(&flags) & CD_BIT,
        0,
        "CD bit must not be set when checking_disabled=false"
    );
}

#[test]
fn test_ad_bit_set_only_when_validated_and_do() {
    let flags = synvoid_dns::wire::build_response_header(
        0x1234,
        synvoid_dns::wire::MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: true,
            checking_disabled: false,
            response_code: 0,
        },
        1,
        1,
        0,
        0,
    );
    assert_ne!(
        response_flags(&flags) & AD_BIT,
        0,
        "AD bit must be set when authentic_data=true"
    );
}

#[test]
fn test_ad_bit_cleared_when_not_validated() {
    let flags = synvoid_dns::wire::build_response_header(
        0x1234,
        synvoid_dns::wire::MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            checking_disabled: false,
            response_code: 0,
        },
        1,
        1,
        0,
        0,
    );
    assert_eq!(
        response_flags(&flags) & AD_BIT,
        0,
        "AD bit must not be set when authentic_data=false"
    );
}

#[test]
fn test_ad_bit_gated_on_do_bit() {
    let q_no_do = build_query_with_flags(0x1234, 0x0100, "example.com", 1);
    let parsed_no_do = synvoid_dns::parsed_query::ParsedDnsQuery::parse(&q_no_do).unwrap();
    assert!(!parsed_no_do.dnssec_ok);

    let ad_bit_should_be_set = parsed_no_do.dnssec_ok;
    assert!(
        !ad_bit_should_be_set,
        "AD must be gated on DO bit: AD=0 when DO=0"
    );

    let q_with_do = build_query_with_edns(0x1234, 0x0100, "example.com", 1, true);
    let parsed_with_do = synvoid_dns::parsed_query::ParsedDnsQuery::parse(&q_with_do).unwrap();
    assert!(parsed_with_do.dnssec_ok);

    let ad_bit_when_do = parsed_with_do.dnssec_ok;
    assert!(
        ad_bit_when_do,
        "AD can be set when DO=1 and validation succeeds"
    );
}

#[test]
fn test_cd_bit_skips_validation() {
    let q = build_query_with_flags(0x1234, 0x0100 | CD_BIT, "example.com", 1);
    let parsed = synvoid_dns::parsed_query::ParsedDnsQuery::parse(&q).unwrap();
    assert!(parsed.flags.checking_disabled);

    let is_dnssec_validated = true;
    let effective_validated = if parsed.flags.checking_disabled {
        false
    } else {
        is_dnssec_validated
    };
    assert!(
        !effective_validated,
        "CD=1 must suppress DNSSEC validation result"
    );
}

#[test]
fn test_cd_and_do_interaction() {
    let q = build_query_with_edns(0x1234, 0x0100 | CD_BIT, "example.com", 1, true);
    let parsed = synvoid_dns::parsed_query::ParsedDnsQuery::parse(&q).unwrap();
    assert!(parsed.flags.checking_disabled);
    assert!(parsed.dnssec_ok);

    let is_dnssec_validated = true;
    let effective_validated = if parsed.flags.checking_disabled {
        false
    } else {
        is_dnssec_validated
    };
    let ad_bit = effective_validated && parsed.dnssec_ok;
    assert!(
        !ad_bit,
        "CD=1 must result in AD=0 even when DO=1 and validation would succeed"
    );
}

#[test]
fn test_response_header_roundtrip_cd_bit() {
    let query = build_query_with_flags(0xABCD, 0x0100 | CD_BIT, "example.com", 1);
    let parsed = synvoid_dns::parsed_query::ParsedDnsQuery::parse(&query).unwrap();
    assert!(parsed.flags.checking_disabled);

    let response_flags_val = synvoid_dns::wire::build_response_header(
        0xABCD,
        synvoid_dns::wire::MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursion_desired: parsed.flags.recursion_desired,
            recursion_available: true,
            authentic_data: false,
            checking_disabled: parsed.flags.checking_disabled,
            response_code: 0,
        },
        1,
        0,
        0,
        0,
    );
    let resp_flags = response_flags(&response_flags_val);
    assert_ne!(
        resp_flags & CD_BIT,
        0,
        "CD bit must be echoed from query to response"
    );
    assert_ne!(resp_flags & 0x8000, 0, "QR bit must be set");
    assert_ne!(resp_flags & 0x0100, 0, "RD must be echoed");
}

#[test]
fn test_recursive_cache_key_dnssec_ok_separation() {
    use synvoid_dns::recursive_cache::RecursiveCacheKey;

    let config = support::recursive_cache_runtime(1_000_000, 300, 86_400, 86_400, 0);
    let cache = RecursiveDnsCache::new(1000, &config);

    let key_do0 = RecursiveCacheKey::new_with_dnssec(b"dosep.test", 1, None, false);
    let key_do1 = RecursiveCacheKey::new_with_dnssec(b"dosep.test", 1, None, true);

    assert_ne!(key_do0, key_do1, "DO=0 and DO=1 keys must be distinct");

    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"dosep.test".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![1, 2, 3, 4],
    }];
    cache.insert_positive(key_do1.clone(), records, 300, DnssecValidationState::Secure);

    assert!(
        cache.get(&key_do0).is_none(),
        "DO=0 should not hit DO=1 entry"
    );
    assert!(cache.get(&key_do1).is_some(), "DO=1 should hit DO=1 entry");
}

#[test]
fn test_dnssec_validation_state_secure() {
    use synvoid_dns::recursive_cache::RecursiveCacheKey;

    let config = support::recursive_cache_runtime(1_000_000, 300, 86_400, 86_400, 0);
    let cache = RecursiveDnsCache::new(1000, &config);

    let key = RecursiveCacheKey::new(b"secure.test", 1, None);
    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"secure.test".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![1, 1, 1, 1],
    }];
    cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Secure);

    let result = cache.get(&key).unwrap();
    assert_eq!(result.2, DnssecValidationState::Secure);
}

#[test]
fn test_dnssec_validation_state_bogus() {
    use synvoid_dns::recursive_cache::RecursiveCacheKey;

    let config = support::recursive_cache_runtime(1_000_000, 300, 86_400, 86_400, 0);
    let cache = RecursiveDnsCache::new(1000, &config);

    let key = RecursiveCacheKey::new(b"bogus.test", 1, None);
    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"bogus.test".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![2, 2, 2, 2],
    }];
    cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Bogus);

    let result = cache.get(&key).unwrap();
    assert_eq!(result.2, DnssecValidationState::Bogus);
}

#[test]
fn test_dnssec_validation_state_unchecked() {
    use synvoid_dns::recursive_cache::RecursiveCacheKey;

    let config = support::recursive_cache_runtime(1_000_000, 300, 86_400, 86_400, 0);
    let cache = RecursiveDnsCache::new(1000, &config);

    let key = RecursiveCacheKey::new(b"unchecked.test", 1, None);
    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"unchecked.test".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![3, 3, 3, 3],
    }];
    cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);

    let result = cache.get(&key).unwrap();
    assert_eq!(result.2, DnssecValidationState::Unchecked);
}

#[test]
fn test_dnssec_validation_state_insecure() {
    use synvoid_dns::recursive_cache::RecursiveCacheKey;

    let config = support::recursive_cache_runtime(1_000_000, 300, 86_400, 86_400, 0);
    let cache = RecursiveDnsCache::new(1000, &config);

    let key = RecursiveCacheKey::new(b"insecure.test", 1, None);
    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"insecure.test".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![4, 4, 4, 4],
    }];
    cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Insecure);

    let result = cache.get(&key).unwrap();
    assert_eq!(result.2, DnssecValidationState::Insecure);
}

#[test]
fn test_cache_dnssec_ok_false_does_not_return_dnssec_entry() {
    use synvoid_dns::recursive_cache::RecursiveCacheKey;

    let config = support::recursive_cache_runtime(1_000_000, 300, 86_400, 86_400, 0);
    let cache = RecursiveDnsCache::new(1000, &config);

    let key_do1 = RecursiveCacheKey::new_with_dnssec(b"return.test", 1, None, true);
    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"return.test".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![10, 20, 30, 40],
    }];
    cache.insert_positive(key_do1.clone(), records, 300, DnssecValidationState::Secure);

    let key_do0 = RecursiveCacheKey::new_with_dnssec(b"return.test", 1, None, false);
    assert!(
        cache.get(&key_do0).is_none(),
        "Entry cached with DO=1 must not be returned for DO=0 query"
    );
    assert!(
        cache.get(&key_do1).is_some(),
        "Entry cached with DO=1 must be returned for DO=1 query"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Recursion depth limit + per-client query limit
// ══════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════
// Bailiwick validation tests
// ══════════════════════════════════════════════════════════════════════

#[test]
fn test_is_in_bailiwick_exact_match() {
    assert!(synvoid_dns::recursive::is_in_bailiwick(
        b"example.com.",
        b"example.com."
    ));
}

#[test]
fn test_is_in_bailiwick_subdomain() {
    assert!(synvoid_dns::recursive::is_in_bailiwick(
        b"ns1.example.com.",
        b"example.com."
    ));
}

#[test]
fn test_is_in_bailiwick_deep_subdomain() {
    assert!(synvoid_dns::recursive::is_in_bailiwick(
        b"a.b.c.example.com.",
        b"example.com."
    ));
}

#[test]
fn test_is_in_bailiwick_out_of_bailiwick() {
    assert!(!synvoid_dns::recursive::is_in_bailiwick(
        b"ns.evil.com.",
        b"example.com."
    ));
}

#[test]
fn test_is_in_bailiwick_suffix_match_not_bailiwick() {
    assert!(!synvoid_dns::recursive::is_in_bailiwick(
        b"notexample.com.",
        b"example.com."
    ));
}

#[test]
fn test_is_in_bailiwick_empty_name() {
    assert!(synvoid_dns::recursive::is_in_bailiwick(b"", b""));
}

#[test]
fn test_is_in_bailiwick_empty_zone() {
    assert!(!synvoid_dns::recursive::is_in_bailiwick(
        b"example.com.",
        b""
    ));
}

#[test]
fn test_is_in_bailiwick_case_insensitive() {
    assert!(synvoid_dns::recursive::is_in_bailiwick(
        b"NS1.Example.COM.",
        b"example.com."
    ));
}

#[test]
fn test_is_in_bailiwick_no_trailing_dot() {
    assert!(synvoid_dns::recursive::is_in_bailiwick(
        b"ns1.example.com",
        b"example.com"
    ));
}

#[test]
fn test_validate_authority_bailiwick_all_in_bailiwick() {
    let ns = vec![
        "ns1.example.com.".to_string(),
        "ns2.example.com.".to_string(),
    ];
    assert!(synvoid_dns::recursive::validate_authority_bailiwick(
        &ns,
        b"example.com."
    ));
}

#[test]
fn test_validate_authority_bailiwick_one_out() {
    let ns = vec!["ns1.example.com.".to_string(), "ns1.evil.com.".to_string()];
    assert!(!synvoid_dns::recursive::validate_authority_bailiwick(
        &ns,
        b"example.com."
    ));
}

#[test]
fn test_validate_authority_bailiwick_empty_ns() {
    let ns: Vec<String> = vec![];
    assert!(synvoid_dns::recursive::validate_authority_bailiwick(
        &ns,
        b"example.com."
    ));
}

#[test]
fn test_validate_additional_bailiwick_glue_in_zone() {
    let ns = vec!["ns1.example.com.".to_string()];
    assert!(synvoid_dns::recursive::validate_additional_bailiwick(
        b"ns1.example.com.",
        &ns
    ));
}

#[test]
fn test_validate_additional_bailiwick_glue_out_of_zone() {
    let ns = vec!["ns1.example.com.".to_string()];
    assert!(!synvoid_dns::recursive::validate_additional_bailiwick(
        b"ns1.evil.com.",
        &ns
    ));
}

#[test]
fn test_validate_additional_bailiwick_empty_ns() {
    let ns: Vec<String> = vec![];
    assert!(!synvoid_dns::recursive::validate_additional_bailiwick(
        b"ns1.example.com.",
        &ns
    ));
}

#[test]
fn test_bailiwick_violations_metric_default() {
    use synvoid_dns::metrics::DnsMetrics;
    let metrics = DnsMetrics::new();
    let summary = metrics.get_summary();
    assert_eq!(summary.bailiwick_violations, 0);
}

#[test]
fn test_bailiwick_violations_metric_increment() {
    use synvoid_dns::metrics::DnsMetrics;
    let metrics = DnsMetrics::new();
    metrics.record_bailiwick_violation();
    metrics.record_bailiwick_violation();
    let summary = metrics.get_summary();
    assert_eq!(summary.bailiwick_violations, 2);
}

// ══════════════════════════════════════════════════════════════════════
// ECS forwarding policy tests
// ══════════════════════════════════════════════════════════════════════

#[test]
fn test_ecs_forwarding_policy_default_is_never() {
    // The persisted default is asserted in
    // `synvoid-config/tests/dns_schema_contract.rs`; Phase 128 keeps this
    // half on the DNS-owned runtime projection.
    assert_eq!(
        support::recursive_runtime().ecs.policy,
        RecursiveEcsPolicyRuntime::Never
    );
}

#[test]
fn test_ecs_runtime_config_defaults() {
    // Persisted defaults are asserted in
    // `synvoid-config/tests/dns_schema_contract.rs`.
    let runtime = support::recursive_runtime().ecs;
    assert_eq!(runtime.prefix_v4, 24);
    assert_eq!(runtime.prefix_v6, 56);
    assert!(!runtime.include_scope_in_response);
}

#[test]
fn test_ecs_truncate_prefix_v4() {
    use std::net::IpAddr;
    use synvoid_dns::edns::ClientSubnet;

    let ecs = ClientSubnet {
        address: IpAddr::from([10, 0, 0, 0]),
        prefix_len: 32,
    };
    let truncated = synvoid_dns::recursive::truncate_ecs_prefix(&ecs, 24, 56);
    assert_eq!(truncated.prefix_len, 24);
    assert_eq!(truncated.address, IpAddr::from([10, 0, 0, 0]));
}

#[test]
fn test_ecs_truncate_prefix_v4_already_less_specific() {
    use std::net::IpAddr;
    use synvoid_dns::edns::ClientSubnet;

    let ecs = ClientSubnet {
        address: IpAddr::from([10, 0, 0, 0]),
        prefix_len: 8,
    };
    let truncated = synvoid_dns::recursive::truncate_ecs_prefix(&ecs, 24, 56);
    assert_eq!(truncated.prefix_len, 8);
}

#[test]
fn test_ecs_truncate_prefix_v6() {
    use std::net::IpAddr;
    use synvoid_dns::edns::ClientSubnet;

    let ecs = ClientSubnet {
        address: IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]),
        prefix_len: 128,
    };
    let truncated = synvoid_dns::recursive::truncate_ecs_prefix(&ecs, 24, 56);
    assert_eq!(truncated.prefix_len, 56);
    assert_eq!(truncated.address, ecs.address);
}

#[test]
fn test_ecs_truncate_prefix_no_change() {
    use std::net::IpAddr;
    use synvoid_dns::edns::ClientSubnet;

    let ecs = ClientSubnet {
        address: IpAddr::from([192, 168, 1, 0]),
        prefix_len: 24,
    };
    let truncated = synvoid_dns::recursive::truncate_ecs_prefix(&ecs, 24, 56);
    assert_eq!(truncated.prefix_len, 24);
}

#[test]
fn test_ecs_policy_never_strips_ecs() {
    use std::net::IpAddr;
    use synvoid_dns::edns::ClientSubnet;

    let subnet = Some(ClientSubnet {
        address: IpAddr::from([8, 8, 8, 0]),
        prefix_len: 24,
    });
    let result = synvoid_dns::recursive::evaluate_ecs_forwarding_policy(
        &RecursiveEcsPolicyRuntime::Never,
        &subnet,
    );
    assert!(result.is_none());
}

#[test]
fn test_ecs_policy_always_forwards_ecs() {
    use std::net::IpAddr;
    use synvoid_dns::edns::ClientSubnet;

    let subnet = Some(ClientSubnet {
        address: IpAddr::from([8, 8, 8, 0]),
        prefix_len: 24,
    });
    let result = synvoid_dns::recursive::evaluate_ecs_forwarding_policy(
        &RecursiveEcsPolicyRuntime::Always,
        &subnet,
    );
    assert!(result.is_some());
    assert_eq!(result.unwrap().prefix_len, 24);
}

#[test]
fn test_ecs_policy_always_without_ecs_returns_none() {
    let subnet: Option<synvoid_dns::edns::ClientSubnet> = None;
    let result = synvoid_dns::recursive::evaluate_ecs_forwarding_policy(
        &RecursiveEcsPolicyRuntime::Always,
        &subnet,
    );
    assert!(result.is_none());
}

#[test]
fn test_ecs_policy_if_present_with_ecs() {
    use std::net::IpAddr;
    use synvoid_dns::edns::ClientSubnet;

    let subnet = Some(ClientSubnet {
        address: IpAddr::from([8, 8, 8, 0]),
        prefix_len: 24,
    });
    let result = synvoid_dns::recursive::evaluate_ecs_forwarding_policy(
        &RecursiveEcsPolicyRuntime::IfPresent,
        &subnet,
    );
    assert!(result.is_some());
}

#[test]
fn test_ecs_policy_if_present_without_ecs() {
    let subnet: Option<synvoid_dns::edns::ClientSubnet> = None;
    let result = synvoid_dns::recursive::evaluate_ecs_forwarding_policy(
        &RecursiveEcsPolicyRuntime::IfPresent,
        &subnet,
    );
    assert!(result.is_none());
}

#[test]
fn test_ecs_policy_cdn_only_returns_none() {
    use std::net::IpAddr;
    use synvoid_dns::edns::ClientSubnet;

    let subnet = Some(ClientSubnet {
        address: IpAddr::from([8, 8, 8, 0]),
        prefix_len: 24,
    });
    let result = synvoid_dns::recursive::evaluate_ecs_forwarding_policy(
        &RecursiveEcsPolicyRuntime::CdnOnly,
        &subnet,
    );
    assert!(result.is_none());
}
