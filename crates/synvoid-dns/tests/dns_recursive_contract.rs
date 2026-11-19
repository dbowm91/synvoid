//! Phase 06 recursive-semantics contract.
//!
//! Every case here pins one of R1-R7: an upstream failure is not an absence of
//! records, stale data is only a fallback, the cache key is honest, the
//! firewall and limits are enforced, and an upstream port is honoured.
//!
//! The resolver is injected through the `DnsResolver` trait, so nothing in this
//! file touches the network except loopback sockets this process owns.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use synvoid_dns::firewall::{DnsFirewall, DnsFirewallAction, DnsFirewallRule, DnsFirewallRuleType};
use synvoid_dns::query_coalesce::{CoalesceResult, QueryCoalescer, QueryKey};
use synvoid_dns::recursive::RecursiveDnsServer;
use synvoid_dns::recursive_cache::{
    CacheLookup, CachedRecord, DnssecValidationState, RecursiveCacheKey,
};
use synvoid_dns::resolver::{
    CNameRecord, DnsResolver, IpRecord, MxRecord, NsRecord, PtrRecord, ResolvedRecord,
    ResolverError, ResolverResult, SoaRecord, SrvRecord, TxtRecord, UpstreamRrset,
};
use synvoid_dns::runtime_config::{
    CustomUpstreamEndpoint, RecursiveRuntimeConfig, RecursiveUpstreamRuntime,
};
use synvoid_dns::wire::{
    encode_name, parse_dns_message, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL,
};

mod support;

// ══════════════════════════════════════════════════════════════════════
// Stub resolver
// ══════════════════════════════════════════════════════════════════════

/// What the stub answers for one qtype.
#[derive(Debug, Clone)]
enum Outcome {
    Rrset(UpstreamRrset),
    Failure(Failure),
}

#[derive(Debug, Clone, Copy)]
enum Failure {
    /// A transport timeout: the resolver produced no answer at all.
    Timeout,
    /// A protocol failure (REFUSED upstream, broken connection).
    QueryFailed,
}

/// A resolver whose answers the test configures per qtype.
#[derive(Default)]
struct StubResolver {
    outcomes: Mutex<HashMap<u16, Outcome>>,
    calls: Mutex<Vec<u16>>,
    /// Artificial upstream latency, so a test can hold a per-client slot.
    delay: Mutex<Option<Duration>>,
}

impl StubResolver {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn answer(&self, record_type: u16, rrset: UpstreamRrset) {
        self.outcomes
            .lock()
            .unwrap()
            .insert(record_type, Outcome::Rrset(rrset));
    }

    fn fail(&self, record_type: u16, failure: Failure) {
        self.outcomes
            .lock()
            .unwrap()
            .insert(record_type, Outcome::Failure(failure));
    }

    fn slow(&self, delay: Duration) {
        *self.delay.lock().unwrap() = Some(delay);
    }

    /// Forget every configured answer: subsequent lookups fail.
    fn clear(&self) {
        self.outcomes.lock().unwrap().clear();
    }

    fn calls(&self) -> Vec<u16> {
        self.calls.lock().unwrap().clone()
    }
}

fn a_answer(ip: [u8; 4], ttl: u32) -> UpstreamRrset {
    a_answer_with_validation(ip, ttl, false)
}

fn a_answer_with_validation(ip: [u8; 4], ttl: u32, validated: bool) -> UpstreamRrset {
    UpstreamRrset {
        records: vec![ResolvedRecord::Address {
            ip: IpAddr::from(ip),
            ttl,
        }],
        rcode: 0,
        negative_ttl: None,
        is_dnssec_validated: validated,
    }
}

fn aaaa_answer(ip: std::net::Ipv6Addr, ttl: u32) -> UpstreamRrset {
    UpstreamRrset {
        records: vec![ResolvedRecord::Address {
            ip: IpAddr::V6(ip),
            ttl,
        }],
        rcode: 0,
        negative_ttl: None,
        is_dnssec_validated: false,
    }
}

fn nxdomain(soa_ttl: u32) -> UpstreamRrset {
    UpstreamRrset {
        records: Vec::new(),
        rcode: RCODE_NXDOMAIN,
        negative_ttl: Some(soa_ttl),
        is_dnssec_validated: false,
    }
}

fn nodata(soa_ttl: u32) -> UpstreamRrset {
    UpstreamRrset {
        records: Vec::new(),
        rcode: 0,
        negative_ttl: Some(soa_ttl),
        is_dnssec_validated: false,
    }
}

#[async_trait]
impl DnsResolver for StubResolver {
    async fn lookup_txt(&self, _name: &str) -> ResolverResult<TxtRecord> {
        Ok(TxtRecord {
            values: Vec::new(),
            ttl: None,
        })
    }

    async fn lookup_ns(&self, _name: &str) -> ResolverResult<NsRecord> {
        Ok(NsRecord {
            nameservers: Vec::new(),
            ttl: None,
        })
    }

    async fn lookup_a(&self, _name: &str) -> ResolverResult<Vec<IpAddr>> {
        Ok(Vec::new())
    }

    async fn lookup_ip_with_ttl(&self, _name: &str) -> ResolverResult<IpRecord> {
        Ok(IpRecord {
            addrs: Vec::new(),
            ttl: None,
            is_dnssec_validated: false,
        })
    }

    async fn lookup_mx(&self, _name: &str) -> ResolverResult<Vec<MxRecord>> {
        Ok(Vec::new())
    }

    async fn lookup_soa(&self, _name: &str) -> ResolverResult<Option<SoaRecord>> {
        Ok(None)
    }

    async fn lookup_ptr(&self, _name: &str) -> ResolverResult<Option<PtrRecord>> {
        Ok(None)
    }

    async fn lookup_srv(&self, _name: &str) -> ResolverResult<Vec<SrvRecord>> {
        Ok(Vec::new())
    }

    async fn lookup_cname(&self, _name: &str) -> ResolverResult<Option<CNameRecord>> {
        Ok(None)
    }

    async fn lookup_rrset(&self, _name: &str, record_type: u16) -> ResolverResult<UpstreamRrset> {
        self.calls.lock().unwrap().push(record_type);
        let delay = *self.delay.lock().unwrap();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        match self.outcomes.lock().unwrap().get(&record_type).cloned() {
            Some(Outcome::Rrset(rrset)) => Ok(rrset),
            Some(Outcome::Failure(Failure::Timeout)) => Err(ResolverError::Timeout),
            Some(Outcome::Failure(Failure::QueryFailed)) => {
                Err(ResolverError::QueryFailed("upstream refused".to_string()))
            }
            None => Err(ResolverError::QueryFailed(
                "stub resolver has no answer configured".to_string(),
            )),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// Server harness
// ══════════════════════════════════════════════════════════════════════

struct Harness {
    server: Arc<RecursiveDnsServer>,
    addr: SocketAddr,
    stub: Arc<StubResolver>,
}

/// A port that is free for both the UDP and the TCP listener.
///
/// The sockets are released before the server binds, so this is a prediction;
/// callers that need the TCP listener retry the connection instead of trusting
/// the number.
fn free_udp_tcp_port() -> u16 {
    for _ in 0..64 {
        let Ok(udp) = std::net::UdpSocket::bind("127.0.0.1:0") else {
            continue;
        };
        let port = udp.local_addr().unwrap().port();
        if let Ok(tcp) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            drop(tcp);
            drop(udp);
            return port;
        }
    }
    panic!("could not find a loopback port free for UDP and TCP");
}

impl Harness {
    async fn start() -> Self {
        Self::with(recursive_runtime(), None).await
    }

    async fn with(
        mut config: RecursiveRuntimeConfig,
        firewall: Option<Arc<parking_lot::RwLock<DnsFirewall>>>,
    ) -> Self {
        let stub = StubResolver::new();
        let addr = SocketAddr::from(([127, 0, 0, 1], free_udp_tcp_port()));
        config.bind_address = addr;
        // A test that provokes failures must not trip the breaker and turn the
        // next assertion into a CircuitBreakerOpen.
        config.circuit_breaker.failure_threshold = u32::MAX;

        let server = Arc::new(RecursiveDnsServer::with_resolver(
            config,
            stub.clone(),
            None,
            firewall,
            None,
        ));
        server
            .clone()
            .start()
            .await
            .expect("recursive server start");
        Self { server, addr, stub }
    }

    fn cache(&self) -> &synvoid_dns::recursive_cache::RecursiveDnsCache {
        self.server.cache()
    }
}

/// The recursive runtime a default configuration produces, with a loopback bind.
fn recursive_runtime() -> RecursiveRuntimeConfig {
    support::recursive_runtime()
}

fn blocked_by_qname(name: &str) -> Arc<parking_lot::RwLock<DnsFirewall>> {
    let mut firewall = DnsFirewall::new();
    firewall
        .add_rule(DnsFirewallRule {
            id: "block_test_qname".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::Block,
            target: name.to_string(),
            ttl: 300,
            created_at: 0,
            expires_at: None,
            enabled: true,
        })
        .expect("static rule is installable");
    Arc::new(parking_lot::RwLock::new(firewall))
}

// ══════════════════════════════════════════════════════════════════════
// Wire helpers
// ══════════════════════════════════════════════════════════════════════

/// A recursive query with explicit RD/CD and an optional DO bit.
fn query(id: u16, qname: &str, qtype: u16, cd: bool, do_bit: bool) -> Vec<u8> {
    let mut flags: u16 = 0x0100; // RD
    if cd {
        flags |= 0x0010;
    }

    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&flags.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&u16::from(do_bit).to_be_bytes()); // ARCOUNT
    query.extend_from_slice(&encode_name(qname).expect("valid query name"));
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // IN

    if do_bit {
        // OPT: root owner, type 41, class 4096, TTL 0, DO set, no options.
        query.push(0);
        query.extend_from_slice(&41u16.to_be_bytes());
        query.extend_from_slice(&4096u16.to_be_bytes());
        query.extend_from_slice(&0x0000_8000u32.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
    }

    query
}

fn flags_of(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[2], response[3]])
}

fn rcode_of(response: &[u8]) -> u8 {
    (flags_of(response) & 0x000F) as u8
}

fn ad_bit(response: &[u8]) -> bool {
    flags_of(response) & 0x0020 != 0
}

fn cd_bit(response: &[u8]) -> bool {
    flags_of(response) & 0x0010 != 0
}

fn ancount(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[6], response[7]])
}

/// The response's question section, byte for byte.
fn question_bytes(response: &[u8]) -> Vec<u8> {
    synvoid_dns::wire::question_section(response)
        .expect("response echoes the question")
        .to_vec()
}

/// `(record_type, ttl, rdata)` for each answer record.
fn answers(response: &[u8]) -> Vec<(u16, u32, Vec<u8>)> {
    let message = parse_dns_message(response).expect("response parses");
    message
        .answers
        .iter()
        .map(|record| {
            let mut rdata = Vec::new();
            match &record.data {
                hickory_proto::rr::RData::A(a) => rdata.extend_from_slice(&a.0.octets()),
                hickory_proto::rr::RData::AAAA(aaaa) => rdata.extend_from_slice(&aaaa.0.octets()),
                hickory_proto::rr::RData::CNAME(cname) => {
                    rdata.extend_from_slice(
                        &encode_name(&cname.to_string()).expect("CNAME target is a name"),
                    );
                }
                other => panic!("unexpected answer rdata: {other:?}"),
            }
            (u16::from(record.record_type()), record.ttl, rdata)
        })
        .collect()
}

async fn udp_query(addr: SocketAddr, query: &[u8]) -> Vec<u8> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client");
    socket.send_to(query, addr).await.expect("send query");
    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .expect("recursive server must answer")
        .expect("recv");
    buf.truncate(len);
    buf
}

async fn tcp_query(addr: SocketAddr, query: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // `start()` binds the TCP listener from a spawned task, so the connect is
    // retried rather than raced.
    let mut stream = None;
    for _ in 0..40 {
        if let Ok(connected) = tokio::net::TcpStream::connect(addr).await {
            stream = Some(connected);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut stream = stream.expect("recursive TCP listener must accept");
    stream.set_nodelay(true).ok();
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .expect("write length");
    stream.write_all(query).await.expect("write query");

    let mut length = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut length))
        .await
        .expect("read length")
        .expect("length prefix");
    let mut response = vec![0u8; u16::from_be_bytes(length) as usize];
    stream
        .read_exact(&mut response)
        .await
        .expect("read response");
    response
}

fn cache_key(qname: &str, qtype: u16, cd: bool, do_bit: bool) -> RecursiveCacheKey {
    RecursiveCacheKey::with_flags(qname.as_bytes(), qtype, None, do_bit, cd)
}

// ══════════════════════════════════════════════════════════════════════
// 1. Upstream failure is SERVFAIL, never a cached NODATA
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn upstream_timeout_is_servfail_and_is_not_cached() {
    let harness = Harness::start().await;
    harness.stub.fail(1, Failure::Timeout);

    let first = udp_query(
        harness.addr,
        &query(0x1001, "timeout.test.", 1, false, false),
    )
    .await;
    assert_eq!(rcode_of(&first), RCODE_SERVFAIL, "a timeout is SERVFAIL");
    assert_eq!(ancount(&first), 0);

    let second = udp_query(
        harness.addr,
        &query(0x1002, "timeout.test.", 1, false, false),
    )
    .await;
    assert_eq!(rcode_of(&second), RCODE_SERVFAIL);

    assert_eq!(
        harness.stub.calls(),
        vec![1, 1],
        "a failed lookup must not be negative-cached: the upstream is asked again"
    );
    assert!(
        harness.cache().is_empty(),
        "no entry may be stored for a failed lookup"
    );
}

#[tokio::test]
async fn upstream_refusal_is_servfail_not_nodata() {
    let harness = Harness::start().await;
    harness.stub.fail(1, Failure::QueryFailed);

    let response = udp_query(
        harness.addr,
        &query(0x1003, "refused.test.", 1, false, false),
    )
    .await;
    assert_eq!(
        rcode_of(&response),
        RCODE_SERVFAIL,
        "an upstream REFUSED must not become an empty NOERROR"
    );
    assert_eq!(ancount(&response), 0);
    assert!(harness.cache().is_empty());
}

// ══════════════════════════════════════════════════════════════════════
// 2. NXDOMAIN keeps its rcode and its SOA-derived TTL
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn upstream_nxdomain_is_rcode_3_cached_with_the_soa_ttl() {
    let harness = Harness::start().await;
    harness.stub.answer(1, nxdomain(120));

    let response = udp_query(harness.addr, &query(0x2001, "nxd.test.", 1, false, false)).await;
    assert_eq!(rcode_of(&response), RCODE_NXDOMAIN, "NXDOMAIN survives");
    assert_eq!(ancount(&response), 0);

    match harness
        .cache()
        .lookup(&cache_key("nxd.test.", 1, false, false))
    {
        CacheLookup::Fresh(hit) => {
            assert_eq!(hit.rcode, RCODE_NXDOMAIN, "cached rcode is NXDOMAIN");
            assert!(
                hit.age < Duration::from_secs(5),
                "the entry is fresh, not stale"
            );
        }
        other => panic!("expected a fresh NXDOMAIN entry, got {other:?}"),
    }

    // The entry is reused: the stub has no answer any more, so only the cache
    // can produce the second NXDOMAIN.
    harness.stub.clear();
    let cached = udp_query(harness.addr, &query(0x2002, "nxd.test.", 1, false, false)).await;
    assert_eq!(
        rcode_of(&cached),
        RCODE_NXDOMAIN,
        "cached NXDOMAIN is reused"
    );
    assert_eq!(
        harness.stub.calls(),
        vec![1],
        "the cached NXDOMAIN must not be re-fetched"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 3. Empty NOERROR is NODATA with the SOA TTL
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn empty_noerror_is_nodata_with_the_soa_ttl() {
    let harness = Harness::start().await;
    harness.stub.answer(1, nodata(60));

    let response = udp_query(
        harness.addr,
        &query(0x3001, "nodata.test.", 1, false, false),
    )
    .await;
    assert_eq!(rcode_of(&response), 0, "NODATA is NOERROR");
    assert_eq!(ancount(&response), 0);

    match harness
        .cache()
        .lookup(&cache_key("nodata.test.", 1, false, false))
    {
        CacheLookup::Fresh(hit) => {
            assert_eq!(hit.rcode, 0);
            assert!(hit.records.is_empty());
        }
        other => panic!("expected a fresh NODATA entry, got {other:?}"),
    }

    harness.stub.clear();
    let cached = udp_query(
        harness.addr,
        &query(0x3002, "nodata.test.", 1, false, false),
    )
    .await;
    assert_eq!(rcode_of(&cached), 0);
    assert_eq!(harness.stub.calls(), vec![1], "NODATA is cached");
}

// ══════════════════════════════════════════════════════════════════════
// 4. Stale is a fallback with TTL 30, and it stops at stale_ttl
// ══════════════════════════════════════════════════════════════════════

fn insert_expiring_entry(harness: &Harness, qname: &str, ttl: u32) {
    harness.cache().insert_positive(
        cache_key(qname, 1, false, false),
        vec![CachedRecord {
            name: encode_name(qname).expect("valid name"),
            record_type: 1,
            ttl,
            data: vec![192, 0, 2, 10],
        }],
        ttl,
        DnssecValidationState::Unchecked,
    );
}

#[tokio::test]
async fn expired_entry_plus_upstream_failure_is_stale_with_ttl_30() {
    let harness = Harness::start().await;
    insert_expiring_entry(&harness, "stale.test.", 1);
    harness.stub.fail(1, Failure::Timeout);

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let response = udp_query(harness.addr, &query(0x4001, "stale.test.", 1, false, false)).await;
    assert_eq!(rcode_of(&response), 0, "stale data is served, not SERVFAIL");
    assert_eq!(ancount(&response), 1);
    let records = answers(&response);
    assert_eq!(records[0].1, 30, "RFC 8767 stale TTL is 30");
    assert_eq!(records[0].2, vec![192, 0, 2, 10]);
    assert!(
        harness.cache().stats().stale_hits >= 1,
        "the stale metric must record the fallback"
    );

    // The refresh is scheduled; give it a moment to record that it ran without
    // changing the answer the client already received.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn expired_entry_plus_upstream_success_is_fresh_not_stale() {
    let harness = Harness::start().await;
    insert_expiring_entry(&harness, "refresh.test.", 1);
    harness.stub.answer(1, a_answer([203, 0, 113, 9], 300));

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let response = udp_query(
        harness.addr,
        &query(0x4101, "refresh.test.", 1, false, false),
    )
    .await;
    assert_eq!(rcode_of(&response), 0);
    let records = answers(&response);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1, 300, "the upstream answer, not the stale TTL");
    assert_eq!(
        records[0].2,
        vec![203, 0, 113, 9],
        "the refreshed data, not the expired entry"
    );
    assert!(
        harness.cache().stats().stale_hits >= 1,
        "the expired entry was read as stale before the refresh"
    );
}

#[tokio::test]
async fn entry_beyond_the_stale_window_is_servfail() {
    let mut config = recursive_runtime();
    config.cache.stale_ttl = Duration::from_secs(1);
    config.cache.max_ttl = Duration::from_secs(1);

    let harness = Harness::with(config, None).await;
    insert_expiring_entry(&harness, "aged.test.", 1);
    harness.stub.fail(1, Failure::Timeout);

    tokio::time::sleep(Duration::from_millis(2400)).await;

    let response = udp_query(harness.addr, &query(0x4201, "aged.test.", 1, false, false)).await;
    assert_eq!(
        rcode_of(&response),
        RCODE_SERVFAIL,
        "past stale_ttl there is nothing left to serve"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 5. TTL 0 is not cacheable
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn ttl_zero_answers_are_served_but_not_cached() {
    let harness = Harness::start().await;
    harness.stub.answer(1, a_answer([198, 51, 100, 7], 0));

    let first = udp_query(harness.addr, &query(0x5001, "zero.test.", 1, false, false)).await;
    assert_eq!(rcode_of(&first), 0);
    assert_eq!(answers(&first)[0].1, 0, "the client sees TTL 0");

    assert!(
        harness.cache().is_empty(),
        "a TTL-0 answer must not enter the cache"
    );

    let second = udp_query(harness.addr, &query(0x5002, "zero.test.", 1, false, false)).await;
    assert_eq!(rcode_of(&second), 0);
    assert_eq!(
        harness.stub.calls(),
        vec![1, 1],
        "a TTL-0 answer must be fetched again"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 6. One cache key: CD, case, and the DO bit
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn cd_and_non_cd_queries_do_not_share_a_validation_state() {
    let harness = Harness::start().await;
    harness
        .stub
        .answer(1, a_answer_with_validation([192, 0, 2, 20], 300, true));

    let validated = udp_query(harness.addr, &query(0x6001, "cd.test.", 1, false, true)).await;
    assert_eq!(rcode_of(&validated), 0);
    assert!(
        ad_bit(&validated),
        "a validated answer sets AD when DO is set"
    );

    let unchecked = udp_query(harness.addr, &query(0x6002, "cd.test.", 1, true, true)).await;
    assert_eq!(rcode_of(&unchecked), 0);
    assert!(cd_bit(&unchecked), "CD is echoed");
    assert!(
        !ad_bit(&unchecked),
        "a CD=1 answer must not claim validation"
    );
    assert_eq!(
        harness.stub.calls(),
        vec![1, 1],
        "CD=1 must not read the CD=0 entry"
    );

    let again = udp_query(harness.addr, &query(0x6003, "cd.test.", 1, false, true)).await;
    assert!(ad_bit(&again));
    assert_eq!(
        harness.stub.calls(),
        vec![1, 1],
        "the CD=0 entry is reused for a CD=0 query"
    );
}

#[tokio::test]
async fn mixed_case_qnames_share_one_cache_entry() {
    let harness = Harness::start().await;
    harness.stub.answer(1, a_answer([192, 0, 2, 30], 300));

    let upper = udp_query(harness.addr, &query(0x7001, "MiXeD.test.", 1, false, false)).await;
    let lower = udp_query(harness.addr, &query(0x7002, "mixed.TEST.", 1, false, false)).await;

    assert_eq!(rcode_of(&upper), 0);
    assert_eq!(rcode_of(&lower), 0);
    assert_eq!(
        harness.stub.calls(),
        vec![1],
        "case variants must share one entry"
    );
    assert_eq!(
        question_bytes(&upper),
        question_bytes(&query(0x7001, "MiXeD.test.", 1, false, false))
    );
    assert_eq!(
        question_bytes(&lower),
        question_bytes(&query(0x7002, "mixed.TEST.", 1, false, false)),
        "each response echoes the case the client asked with"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 7. Coalesced waiters keep their own ID and question
// ══════════════════════════════════════════════════════════════════════

/// A printable label for a coalescer result (the type has no `Debug`).
fn coalesce_kind(result: &Option<CoalesceResult>) -> &'static str {
    match result {
        Some(CoalesceResult::Response(_)) => "Response",
        Some(CoalesceResult::QuestionMismatch) => "QuestionMismatch",
        Some(CoalesceResult::NewQuery(_)) => "NewQuery",
        Some(CoalesceResult::Lagged) => "Lagged",
        Some(CoalesceResult::Timeout) => "Timeout",
        None => "None",
    }
}

#[tokio::test]
async fn coalesced_waiters_each_receive_their_own_message_id() {
    let coalescer = Arc::new(QueryCoalescer::with_config(2000, 16, 30));

    let owner_query = query(0xAAAA, "coalesce.test.", 1, false, false);
    let waiter_a = query(0xBBBB, "coalesce.test.", 1, false, false);
    let waiter_b = query(0xCCCC, "coalesce.test.", 1, false, false);
    let key = QueryKey::from_query(&owner_query, None, None).expect("key");

    let owner = coalescer.get_or_wait(key.clone()).await;
    assert!(
        matches!(owner, Some(CoalesceResult::NewQuery(_))),
        "the first client owns the upstream query"
    );

    let waiter_a_task = {
        let coalescer = coalescer.clone();
        let key = key.clone();
        tokio::spawn(async move { coalescer.get_or_wait_for(key, &waiter_a).await })
    };
    let waiter_b_task = {
        let coalescer = coalescer.clone();
        let key = key.clone();
        tokio::spawn(async move { coalescer.get_or_wait_for(key, &waiter_b).await })
    };

    tokio::time::sleep(Duration::from_millis(50)).await;

    // The owner's response body: the query with QR set and one A record.
    let mut shared = owner_query.clone();
    shared[2] |= 0x80;
    shared[6..8].copy_from_slice(&1u16.to_be_bytes());
    shared.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    shared.extend_from_slice(&60u32.to_be_bytes());
    shared.extend_from_slice(&4u16.to_be_bytes());
    shared.extend_from_slice(&[192, 0, 2, 40]);

    coalescer.broadcast_response(key, Arc::new(shared));

    for (task, expected_id) in [(waiter_a_task, 0xBBBBu16), (waiter_b_task, 0xCCCCu16)] {
        let result = task.await.expect("waiter task");
        let Some(CoalesceResult::Response(response)) = result else {
            panic!(
                "waiter must receive the shared response, got {}",
                coalesce_kind(&result)
            );
        };
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]),
            expected_id,
            "each waiter sees its own message ID"
        );
        assert_eq!(
            question_bytes(&response),
            question_bytes(&query(expected_id, "coalesce.test.", 1, false, false)),
            "each waiter sees its own question"
        );
        assert_eq!(ancount(&response), 1);
    }
}

#[tokio::test]
async fn coalescer_never_delivers_a_different_question() {
    let coalescer = Arc::new(QueryCoalescer::with_config(2000, 16, 30));

    let owner_query = query(0x1111, "owner.test.", 1, false, false);
    let key = QueryKey::from_query(&owner_query, None, None).expect("key");
    let _owner = coalescer.get_or_wait(key.clone()).await;

    // A waiter whose key claims one question but whose bytes ask another: the
    // delivery check must reject it rather than hand over a mismatched packet.
    let mismatched = query(0x2222, "other.test.", 1, false, false);
    let waiter = {
        let coalescer = coalescer.clone();
        let key = key.clone();
        tokio::spawn(async move { coalescer.get_or_wait_for(key, &mismatched).await })
    };

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut shared = owner_query.clone();
    shared[2] |= 0x80;
    coalescer.broadcast_response(key, Arc::new(shared));

    let result = waiter.await.expect("waiter task");
    assert!(
        matches!(result, Some(CoalesceResult::QuestionMismatch)),
        "a mismatched question must not be delivered, got {}",
        coalesce_kind(&result)
    );
}

// ══════════════════════════════════════════════════════════════════════
// 8. Firewall parity on the recursive UDP and TCP paths
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn firewall_blocked_qname_is_refused_on_udp_and_tcp() {
    let harness = Harness::with(recursive_runtime(), Some(blocked_by_qname("blocked.test"))).await;
    harness.stub.answer(1, a_answer([192, 0, 2, 50], 300));

    let udp = udp_query(
        harness.addr,
        &query(0x8001, "blocked.test.", 1, false, false),
    )
    .await;
    assert_eq!(
        rcode_of(&udp),
        RCODE_REFUSED,
        "the recursive UDP path must enforce the firewall"
    );
    assert_eq!(ancount(&udp), 0);

    let tcp = tcp_query(
        harness.addr,
        &query(0x8002, "blocked.test.", 1, false, false),
    )
    .await;
    assert_eq!(
        rcode_of(&tcp),
        RCODE_REFUSED,
        "the recursive TCP path must enforce the firewall"
    );

    assert!(
        harness.stub.calls().is_empty(),
        "a blocked qname is refused before any upstream lookup"
    );
}

#[tokio::test]
async fn firewall_does_not_block_an_unlisted_qname() {
    let harness = Harness::with(recursive_runtime(), Some(blocked_by_qname("blocked.test"))).await;
    harness.stub.answer(1, a_answer([192, 0, 2, 60], 300));

    let response = udp_query(
        harness.addr,
        &query(0x8101, "allowed.test.", 1, false, false),
    )
    .await;
    assert_eq!(rcode_of(&response), 0);
    assert_eq!(ancount(&response), 1);
}

// ══════════════════════════════════════════════════════════════════════
// 9. A custom upstream is queried on its configured port
// ══════════════════════════════════════════════════════════════════════

/// A minimal UDP name server that answers every A query with 203.0.113.53.
async fn spawn_stub_upstream() -> (u16, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind stub upstream");
    let port = socket.local_addr().expect("local addr").port();

    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let response = answer_with_a(&buf[..len], [203, 0, 113, 53]);
            if socket.send_to(&response, peer).await.is_err() {
                break;
            }
        }
    });

    (port, handle)
}

/// Echo the question and append one A record for it.
fn answer_with_a(query: &[u8], address: [u8; 4]) -> Vec<u8> {
    let question = synvoid_dns::wire::question_section(query).expect("query has a question");
    let mut response = Vec::with_capacity(12 + question.len() + 16);

    response.extend_from_slice(&query[0..2]); // ID
    response.extend_from_slice(&0x8180u16.to_be_bytes()); // QR, RD, RA, NOERROR
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    response.extend_from_slice(question);

    response.extend_from_slice(&[0xC0, 0x0C]); // owner: pointer to the question
    response.extend_from_slice(&1u16.to_be_bytes()); // A
    response.extend_from_slice(&1u16.to_be_bytes()); // IN
    response.extend_from_slice(&60u32.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&address);

    response
}

#[tokio::test]
async fn custom_upstream_port_is_honoured() {
    let (upstream_port, _upstream) = spawn_stub_upstream().await;

    let mut config = recursive_runtime();
    config.upstream =
        RecursiveUpstreamRuntime::CustomEndpoints(vec![CustomUpstreamEndpoint::Literal {
            ip: IpAddr::from([127, 0, 0, 1]),
            port: upstream_port,
        }]);
    // 0x20 case randomization changes the question case upstream, which the
    // stub does not follow; it is unrelated to port plumbing.
    config.qname_minimization = false;
    config.query_timeout = Duration::from_secs(2);

    let addr = SocketAddr::from(([127, 0, 0, 1], free_udp_tcp_port()));
    config.bind_address = addr;

    let server = Arc::new(
        RecursiveDnsServer::new(config, None, None, None)
            .await
            .expect("a literal upstream endpoint builds a resolver"),
    );
    server.clone().start().await.expect("start");

    let response = udp_query(addr, &query(0x9001, "forwarded.test.", 1, false, false)).await;
    assert_eq!(rcode_of(&response), 0, "the stub upstream answered");
    assert_eq!(
        answers(&response),
        vec![(1, 60, vec![203, 0, 113, 53])],
        "the answer came from the stub listener on its own port, not port 53"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 10. Upstream lists are explicit
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn empty_custom_upstream_list_fails_startup() {
    let mut config = recursive_runtime();
    config.upstream = RecursiveUpstreamRuntime::CustomEndpoints(Vec::new());

    let error = match RecursiveDnsServer::new(config, None, None, None).await {
        Ok(_) => panic!("an empty upstream list must not fall back to the system resolver"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("refusing to fall back"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn hostname_only_upstream_list_fails_startup() {
    let mut config = recursive_runtime();
    config.upstream =
        RecursiveUpstreamRuntime::CustomEndpoints(vec![CustomUpstreamEndpoint::Hostname {
            host: "dns.example.com".to_string(),
            port: 53,
        }]);

    let error = match RecursiveDnsServer::new(config, None, None, None).await {
        Ok(_) => panic!("a hostname without an address must not fall back to the system resolver"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("hostname"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn empty_global_node_list_fails_startup() {
    let mut config = recursive_runtime();
    config.upstream = RecursiveUpstreamRuntime::GlobalNodes;

    let error = match RecursiveDnsServer::new(config, None, None, None).await {
        Ok(_) => panic!("GlobalNodes without nodes must not fall back to the system resolver"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("GlobalNodes"),
        "unexpected error: {error}"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 11. A and AAAA are separate lookups
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn aaaa_returns_aaaa_records_not_a_cached_nodata() {
    let harness = Harness::start().await;
    harness.stub.answer(1, a_answer([192, 0, 2, 70], 300));
    harness.stub.answer(
        28,
        aaaa_answer("2001:db8::70".parse().expect("v6 literal"), 300),
    );

    let v4 = udp_query(harness.addr, &query(0xA001, "dual.test.", 1, false, false)).await;
    assert_eq!(answers(&v4), vec![(1, 300, vec![192, 0, 2, 70])]);

    let v6 = udp_query(harness.addr, &query(0xA002, "dual.test.", 28, false, false)).await;
    assert_eq!(rcode_of(&v6), 0);
    assert_eq!(
        answers(&v6),
        vec![(
            28,
            300,
            "2001:db8::70"
                .parse::<std::net::Ipv6Addr>()
                .expect("v6")
                .octets()
                .to_vec()
        )],
        "AAAA must be a real AAAA answer, not an A-derived NODATA"
    );

    assert_eq!(
        harness.stub.calls(),
        vec![1, 28],
        "A and AAAA are looked up separately"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 12. Configured limits are enforced
// ══════════════════════════════════════════════════════════════════════

fn cname_answer(count: usize) -> UpstreamRrset {
    UpstreamRrset {
        records: (0..count)
            .map(|index| ResolvedRecord::Cname {
                target: format!("hop{index}.chain.test."),
                ttl: 300,
            })
            .collect(),
        rcode: 0,
        negative_ttl: None,
        is_dnssec_validated: false,
    }
}

#[tokio::test]
async fn max_cname_depth_is_enforced() {
    let mut config = recursive_runtime();
    config.max_cname_depth = 2;

    let harness = Harness::with(config, None).await;
    harness.stub.answer(1, cname_answer(3));

    let too_deep = udp_query(harness.addr, &query(0xB001, "deep.test.", 1, false, false)).await;
    assert_eq!(
        rcode_of(&too_deep),
        RCODE_SERVFAIL,
        "a chain longer than max_cname_depth must fail"
    );

    harness.stub.answer(1, cname_answer(2));
    let allowed = udp_query(harness.addr, &query(0xB002, "ok.test.", 1, false, false)).await;
    assert_eq!(
        rcode_of(&allowed),
        0,
        "a chain at the limit is still answered"
    );
    assert_eq!(ancount(&allowed), 2);
}

// ══════════════════════════════════════════════════════════════════════
// 12b. Per-client semaphore exhaustion is REFUSED, never silence
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn per_client_semaphore_exhaustion_is_refused() {
    let mut config = recursive_runtime();
    config.max_per_client_queries = 1;

    let harness = Harness::with(config, None).await;
    harness.stub.answer(1, a_answer([192, 0, 2, 90], 300));
    // Hold the single per-client slot for longer than the 1 s acquire timeout.
    harness.stub.slow(Duration::from_millis(1600));

    let in_flight = {
        let addr = harness.addr;
        tokio::spawn(
            async move { udp_query(addr, &query(0xE001, "slow.test.", 1, false, false)).await },
        )
    };
    // Let the first query take the only slot.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let refused = udp_query(harness.addr, &query(0xE002, "slow.test.", 1, false, false)).await;
    assert_eq!(
        rcode_of(&refused),
        RCODE_REFUSED,
        "a client over its concurrency limit is refused, not dropped"
    );

    let first = in_flight.await.expect("first query task");
    assert_eq!(
        rcode_of(&first),
        0,
        "the query that held the slot is still answered"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 13. Unsupported types are NOTIMP, not an empty NOERROR
// ══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn unsupported_qtype_is_notimp() {
    let harness = Harness::start().await;

    // HTTPS (65) has no recursive lookup.
    let response = udp_query(
        harness.addr,
        &query(0xC001, "https.test.", 65, false, false),
    )
    .await;
    assert_eq!(
        rcode_of(&response),
        4,
        "an unimplemented qtype is NOTIMP, never an empty NOERROR"
    );
    assert!(
        harness.stub.calls().is_empty(),
        "NOTIMP must not be produced by an upstream lookup"
    );
}

#[tokio::test]
async fn non_in_qclass_is_notimp() {
    let harness = Harness::start().await;

    // QCLASS 3 (CHAOS) must not read or write an IN cache entry.
    let mut chaos = query(0xC201, "version.test.", 16, false, false);
    let class_offset = chaos.len() - 2;
    chaos[class_offset..].copy_from_slice(&3u16.to_be_bytes());

    let response = udp_query(harness.addr, &chaos).await;
    assert_eq!(rcode_of(&response), 4, "only class IN is served");
    assert!(
        harness.stub.calls().is_empty(),
        "a non-IN query must not reach the upstream"
    );
}

#[tokio::test]
async fn any_query_is_answered_from_the_cache_only() {
    let harness = Harness::start().await;
    // The cache holds an A entry for this name, but no ANY entry exists.
    harness.stub.answer(1, a_answer([192, 0, 2, 80], 300));
    let _ = udp_query(harness.addr, &query(0xC101, "any.test.", 1, false, false)).await;

    let any = udp_query(harness.addr, &query(0xC102, "any.test.", 255, false, false)).await;
    assert_eq!(
        rcode_of(&any),
        4,
        "ANY is not synthesized: an ANY miss is NOTIMP"
    );
    assert_eq!(
        harness.stub.calls(),
        vec![1],
        "ANY never reaches the upstream"
    );
}

// ══════════════════════════════════════════════════════════════════════
// 14. Trust anchors are static (decision T5)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn static_trust_anchor_file_is_the_only_anchor_source() {
    use std::io::Write;

    let directory = tempfile::TempDir::new().expect("temp dir");
    let anchors = directory.path().join("trusted-key.key");
    let mut file = std::fs::File::create(&anchors).expect("create anchor file");
    // One record per line: hickory's zone-file reader does not fold the
    // parenthesised multi-line form.
    file.write_all(
        br#"; root KSK
. 86400 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
"#,
    )
    .expect("write anchors");
    drop(file);

    let loaded =
        synvoid_dns::load_static_trust_anchors(&anchors).expect("the static anchor file must load");
    assert_eq!(loaded.len(), 1, "one DNSKEY in the file is one anchor");

    let missing = directory.path().join("absent.key");
    assert!(
        synvoid_dns::load_static_trust_anchors(&missing).is_err(),
        "a missing anchor file is reported, not silently defaulted"
    );
}
