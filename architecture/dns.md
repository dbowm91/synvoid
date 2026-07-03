# DNS Module Architecture

## 1. Purpose and Responsibility

The SynVoid DNS module provides a **comprehensive, production-grade DNS server** with support for:

- **Authoritative DNS serving** with zone management
- **Recursive DNS resolution** with caching
- **DNSSEC signing and validation**
- **DNS-over-TLS (DoT)**, **DNS-over-HTTPS (DoH)**, **DNS-over-Quic (DoQ)**
- **Dynamic Updates (RFC 2136)**
- **TSIG-based transaction security**
- **Geo-steering** based on client location and node health
- **Mesh mode** for dynamic registration from edge nodes

The module is located at `src/dns/` and exports a rich set of submodules.

---

## 2. Key Submodules

### 2.1 Core Server

| Submodule | File | Responsibility |
|-----------|------|----------------|
| `server/mod.rs` | `src/dns/server/mod.rs` | Main `DnsServer` struct, zone management, query handling |
| `server/query.rs` | `src/dns/server/query.rs` | Query parsing, validation, cookie checking |
| `server/response.rs` | `src/dns/server/response.rs` | Response building, NXDOMAIN, error responses |
| `server/response_encoder.rs` | `src/dns/server/response_encoder.rs` | Typed wire-format response encoder (`EncodedRecord`, `ResponseEnvelope`, per-record encoders) |
| `server/startup.rs` | `src/dns/server/startup.rs` | Server startup, socket binding |
| `server/zone.rs` | `src/dns/server/zone.rs` | Zone record management |
| `server/dnssec_impl.rs` | `src/dns/server/dnssec_impl.rs` | DNSSEC-signed response handling |
| `server/rate_limit.rs` | `src/dns/server/rate_limit.rs` | Rate limiting (Response Rate Limiting - RRL) |
| `server/sharded_store.rs` | `src/dns/server/sharded_store.rs` | `ShardedZoneStore` for concurrent zone access |

### 2.2 DNSSEC

| Submodule | File | Responsibility |
|-----------|------|----------------|
| `dnssec.rs` | `src/dns/dnssec.rs` | Core types: `Algorithm`, `KeyType`, `ZoneSigningKey`, `Nsec3Config`, `KeyRotationConfig` |
| `dnssec_key_mgmt.rs` | `src/dns/dnssec_key_mgmt.rs` | `DnsSecKeyManager` - key generation, storage |
| `dnssec_signing.rs` | `src/dns/dnssec_signing.rs` | RRSIG creation, NSEC/NSEC3 record generation |
| `dnssec_validation.rs` | `src/dns/dnssec_validation.rs` | Signature verification, canonicalization, DS digest |
| `trust_anchor.rs` | `src/dns/trust_anchor.rs` | RFC 5011 trust anchor state machine |

### 2.3 Resolvers

| Submodule | File | Responsibility |
|-----------|------|----------------|
| `recursive.rs` | `src/dns/recursive.rs` | `RecursiveDnsServer` - recursive resolver server |
| `resolver.rs` | `src/dns/resolver.rs` | `DnsResolver` trait, `HickoryResolver`, `HickoryRecursor` |
| `recursive_cache.rs` | `src/dns/recursive_cache.rs` | `RecursiveDnsCache` - cache for recursive resolver |

### 2.4 Protocol Support

| Submodule | File | Responsibility |
|-----------|------|----------------|
| `doh.rs` | `src/dns/doh.rs` | DNS-over-HTTPS server |
| `dot.rs` | `src/dns/dot.rs` | DNS-over-TLS server |
| `doq.rs` | `src/dns/doq.rs` | DNS-over-Quic server |
| `tsig.rs` | `src/dns/tsig.rs` | TSIG transaction signing and verification |

### 2.5 Security

| Submodule | File | Responsibility |
|-----------|------|----------------|
| `firewall.rs` | `src/dns/firewall.rs` | `DnsFirewall` - query filtering |
| `cookie.rs` | `src/dns/cookie.rs` | DNS Cookie Server (RFC 7873) |
| `limits.rs` | `src/dns/limits.rs` | Connection limits |
| `update.rs` | `src/dns/update.rs` | Dynamic DNS updates (RFC 2136) |
| `notify.rs` | `src/dns/notify.rs` | DNS NOTIFY handling |
| `transfer.rs` | `src/dns/transfer.rs` | Zone transfers (AXFR/IXFR) |

### 2.6 Supporting Modules

| Submodule | File | Responsibility |
|-----------|------|----------------|
| `cache.rs` | `src/dns/cache.rs` | `DnsCache` - authoritative server cache |
| `compression.rs` | `src/dns/compression.rs` | DNS message compression |
| `config.rs` | `src/dns/config.rs` | `DnsSettings` - DNS configuration wrapper with bind address and geoip |
| `edns.rs` | `src/dns/edns.rs` | EDNS(0) option parsing |
| `messages.rs` | `src/dns/messages.rs` | Mesh DNS message types |
| `mesh_dnssec.rs` | `src/dns/mesh_dnssec.rs` | Mesh DNSSEC validation - `MeshDnsSecValidator`, `MeshTrustAnchor` |
| `metrics.rs` | `src/dns/metrics.rs` | DNS metrics |
| `platform.rs` | `src/dns/platform.rs` | `AnycastSocketPlatform` - platform-specific anycast socket support |
| `prefetch.rs` | `src/dns/prefetch.rs` | `DnsPrefetcher` - DNS response prefetching based on query frequency |
| `qname.rs` | `src/dns/qname.rs` | QNAME minimization and rebinding checks |
| `query_coalesce.rs` | `crates/synvoid-dns/src/query_coalesce.rs` | Query coalescing |
| `query_validator.rs` | `src/dns/query_validator.rs` | Query validation |
| `secure_server.rs` | `src/dns/secure_server.rs` | `SecureDnsServerBase` - TLS DNS server base (DoT/DoH/DoQ) |
| `sharded_cache.rs` | `src/dns/sharded_cache.rs` | `ShardedDnsCache` - high-performance sharded DNS cache |
| `store.rs` | `src/dns/store.rs` | `ZoneStore` trait |
| `wire.rs` | `src/dns/wire.rs` | Wire-format DNS parsing/building |
| `zone_file.rs` | `src/dns/zone_file.rs` | Zone file parsing |
| `zone_manager.rs` | `src/dns/zone_manager.rs` | Zone lifecycle management - index rebuilding, record CRUD |
| `zone_trie.rs` | `src/dns/zone_trie.rs` | Zone lookup trie |
| `rpz.rs` | `src/dns/rpz.rs` | Response Policy Zones |
| `dns64.rs` | `src/dns/dns64.rs` | DNS64 translator |
| `anycast.rs` | `src/dns/anycast.rs` | Anycast support |
| `hsm.rs` | `src/dns/hsm.rs` | HSM-backed key management |
| `crypto_rng.rs` | `src/dns/crypto_rng.rs` | Cryptographic RNG |

---

## 3. Major Data Structures and Types

### 3.1 DnsServer (server/mod.rs:447)

```rust
pub struct DnsServer {
    config: Arc<DnsConfig>,
    zones: Arc<ShardedZoneStore>,
    zone_trie: Arc<RwLock<ZoneTrie>>,
    zone_index: Arc<RwLock<Vec<(String, String)>>>,
    zone_index_btree: Arc<RwLock<BTreeMap<String, String>>>,
    zone_index_dirty: Arc<AtomicBool>,
    rate_limiter: Option<Arc<DnsRateLimiter>>,
    query_validator: Option<DnsQueryValidator>,
    firewall: Option<Arc<RwLock<DnsFirewall>>>,
    connection_limits: Arc<ConnectionLimits>,
    #[cfg(feature = "mesh")]
    mesh_registry: Option<Arc<MeshDnsRegistry>>,
    geoip_lookup: Option<Arc<GeoIpManager>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    cache: Option<Arc<DnsCache>>,
    dnssec: Option<Arc<RwLock<DnsSecKeyManager>>>,
    signer_name: Option<String>,
    rrl_enabled: bool,
    cert_resolver: Option<Arc<CertResolver>>,
    dot_server: Option<DotServer>,
    doh_server: Option<DohServer>,
    doq_server: Option<DoqServer>,
    zone_transfer: Option<Arc<ZoneTransfer>>,
    ecs_filter_config: EcsFilterConfig,
    update_handler: Option<DynamicUpdateHandler>,
    notify_handler: Option<NotifyHandler>,
    hsm_manager: Option<HsmManager>,
    query_coalescer: Option<Arc<QueryCoalescer>>,
    anycast_manager: Option<Arc<AnycastSocketManager>>,
    #[cfg(feature = "mesh")]
    mesh_transport: Option<Arc<MeshTransport>>,
    #[cfg(feature = "mesh")]
    zone_sync: Option<Arc<AnycastZoneSync>>,
    recursive_server: Option<Arc<RecursiveDnsServer>>,
    dns64_translator: Option<Dns64Translator>,
    #[cfg(feature = "dns")]
    acme_dns_challenges: Option<Arc<AcmeDnsChallenge>>,
    cookie_server: Option<Arc<DnsCookieServer>>,
}
```

### 3.2 Zone (server/mod.rs:129)

```rust
pub struct Zone {
    pub origin: String,
    pub records: HashMap<(String, RecordType), Vec<DnsZoneRecord>>,
    pub serial: u32,
    pub ksk_key: Option<ZoneSigningKey>,
    pub zsk_key: Option<ZoneSigningKey>,
    pub dnskey_ttl: Option<u32>,
    pub nsec3_enabled: bool,
    pub nsec_enabled: bool,
    pub nsec3param: Option<Nsec3Config>,
    pub history: Vec<ZoneHistory>,
}
```

### 3.3 RecursiveDnsServer (recursive.rs:52)

```rust
pub struct RecursiveDnsServer {
    config: RecursiveDnsConfig,
    resolver: Arc<dyn DnsResolver>,
    cache: RecursiveDnsCache,
    rate_limiter: Option<Arc<DnsRateLimiter>>,
    firewall: Option<Arc<RwLock<DnsFirewall>>>,
    metrics: Option<Arc<DnsMetrics>>,
    query_semaphore: Arc<Semaphore>,
    running: Arc<tokio::sync::RwLock<bool>>,
}
```

### 3.4 TrustAnchorState (trust_anchor.rs:30)

```rust
pub enum TrustAnchorState {
    Valid,      // Fully trusted
    Seen,       // Observed in DNSKEY but not yet validated via CDS
    Pending,    // Validated via CDS, awaiting 30-day observation (RFC 5011)
    Revoked,    // REVOKE bit observed
    Removed,    // Removed from zone
    Missing,    // Was Valid but expired
}
```

### 3.5 Key DNSSEC Types

```rust
// dnssec.rs
pub enum Algorithm { Ed25519, RSA }
pub enum KeyType { KSK, ZSK }
pub enum DsDigestType { Sha1 = 1, Sha256 = 2, Sha384 = 4 }
pub struct ZoneSigningKey {
    pub key_id: String,
    pub algorithm: Algorithm,
    pub key_type: KeyType,
    pub created_at: u64,
    pub expires_at: u64,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub key_tag: u16,
    pub flags: u16,
    pub key_size: Option<u32>,
}
pub struct Nsec3Config {
    pub algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}
pub struct KeyInfo {
    pub key_type: String,
    pub algorithm: String,
    pub key_tag: u16,
    pub created_at: u64,
    pub expires_at: u64,
    pub age_days: u64,
    pub days_until_expiry: Option<u64>,
}
pub struct DnsSecKeyStatus {
    pub ksk: Option<KeyInfo>,
    pub zsk: Option<KeyInfo>,
}
pub struct KeyRotationResult {
    pub ksk_rotated: bool,
    pub zsk_rotated: bool,
    pub ksk_new_key_id: Option<String>,
    pub zsk_new_key_id: Option<String>,
    pub ksk_age_days: Option<u64>,
    pub zsk_age_days: Option<u64>,
    pub ksk_error: Option<String>,
    pub zsk_error: Option<String>,
}
pub struct RolloverState {
    pub ksk_in_rollover: bool,
    pub zsk_in_rollover: bool,
    pub ksk_rollover_started: Option<u64>,
    pub zsk_rollover_started: Option<u64>,
    pub publish_dnssec: bool,
}
// CryptoRngAdapter - wraps getrandom for rand_core 0.6 traits (RSA crate compat)
pub(crate) struct CryptoRngAdapter;
```

### 3.6 DnsResolver Trait (resolver.rs:131)

```rust
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn lookup_txt(&self, name: &str) -> ResolverResult<TxtRecord>;
    async fn lookup_ns(&self, name: &str) -> ResolverResult<NsRecord>;
    async fn lookup_a(&self, name: &str) -> ResolverResult<Vec<IpAddr>>;
    async fn lookup_ip_with_ttl(&self, name: &str) -> ResolverResult<IpRecord>;
    async fn lookup_mx(&self, name: &str) -> ResolverResult<Vec<MxRecord>>;
    async fn lookup_soa(&self, name: &str) -> ResolverResult<Option<SoaRecord>>;
    async fn lookup_ptr(&self, name: &str) -> ResolverResult<Option<PtrRecord>>;
    async fn lookup_srv(&self, name: &str) -> ResolverResult<Vec<SrvRecord>>;
    async fn lookup_cname(&self, name: &str) -> ResolverResult<Option<CNameRecord>>;
}
```

### 3.7 ShardedDnsCache (sharded_cache.rs:22)

```rust
pub struct ShardedDnsCache {
    shards: Arc<Vec<RwLock<Shard>>>,
    max_ttl: Duration,
    min_ttl: Duration,
    max_entry_size: usize,
    max_capacity: usize,
}
```

### 3.8 SecureDnsServerBase (secure_server.rs:21)

```rust
pub struct SecureDnsServerBase<C: DnsServerConfig> {
    pub config: Arc<C>,
    pub cert_resolver: Option<Arc<CertResolver>>,
    pub dns_server: Arc<RwLock<Option<DnsServer>>>,
    pub shutdown_tx: Option<oneshot::Sender<()>>,
}
```

### 3.9 DnsSettings (config.rs:7)

```rust
pub struct DnsSettings {
    pub config: Arc<DnsConfig>,
    pub geoip: Option<Arc<GeoIpManager>>,
    pub bind_address: SocketAddr,
}
```

### 3.10 AuthoritativeLookupOutcome (server/zone.rs)

```rust
/// Result of an authoritative zone lookup (Phase D).
pub enum AuthoritativeLookupOutcome {
    Positive(Vec<DnsZoneRecord>),
    Cname(Vec<DnsZoneRecord>),
    NoData { soa: DnsZoneRecord },
    NxDomain { soa: DnsZoneRecord },
    NoAuthoritativeZone,
}
```

`Zone::lookup_authoritative(name, qtype)` returns this enum. Unsigned negative responses (NODATA/NXDOMAIN) include SOA from the zone. No `.example` synthetic shortcut in production.

### 3.11 Encoder Strictness Types (server/response_encoder.rs)

```rust
/// Record skipped during encoding with reason.
pub struct SkippedRecord {
    pub owner: String,
    pub record_type: u16,
    pub reason: String,
}

/// Aggregated report of encoding outcomes for a response.
pub struct EncodeReport {
    pub total_records: usize,
    pub encoded_records: usize,
    pub skipped: Vec<SkippedRecord>,
}

impl ResponseEnvelope {
    /// Exact wire-length of fully assembled packet.
    pub fn total_wire_len(&self) -> usize;
    /// Build truncated TC response when packet exceeds UDP payload size.
    pub fn build_truncated_tc_response(&self, max_size: usize) -> Vec<u8>;
}

impl EncodedRecord {
    /// Wire-length contribution of this single record.
    pub fn wire_len(&self) -> usize;
}
```

### 3.12 PrefetchConfig (prefetch.rs:9)

```rust
pub struct PrefetchConfig {
    pub enabled: bool,
    pub min_query_count: u32,
    pub prefetch_ttl_threshold: u32,
    pub max_prefetched_names: usize,
}
```

---

## 4. Key APIs and Entry Points

### 4.1 DnsServer Factory

```rust
// server/mod.rs:855
impl DnsServer {
    pub fn new(config: DnsConfig, cert_resolver: Option<Arc<CertResolver>>) -> Self
    #[cfg(feature = "dns")]
    pub fn with_acme_dns_challenges(self, challenges: Arc<AcmeDnsChallenge>) -> Self
    #[cfg(feature = "dns")]
    pub fn with_cookie_server(self, cookie_server: Arc<DnsCookieServer>) -> Self
}
```

### 4.2 RecursiveDnsServer

```rust
// recursive.rs:63
impl RecursiveDnsServer {
    pub async fn new(config: RecursiveDnsConfig, ...) -> RecursiveDnsResult<Self>
    pub async fn new_with_global_nodes(config: RecursiveDnsConfig, global_node_ips: Vec<IpAddr>) -> RecursiveDnsResult<Self>
    pub async fn start(self: Arc<Self>) -> RecursiveDnsResult<()>
    pub fn stop(&self)
    pub async fn is_running(&self) -> bool
    pub fn cache(&self) -> &RecursiveDnsCache
    pub fn cache_stats(&self) -> RecursiveCacheStats
}
```

### 4.3 HickoryRecursor (RFC 5011 support)

```rust
// resolver.rs:629
impl HickoryRecursor {
    pub fn new(root_hints_path: &str, trust_anchor_path: &str, enable_dnssec: bool) -> Result<Self, ResolverError>
    pub async fn start_rfc5011_updates(self: Arc<Self>) -> Result<(), ResolverError>
    pub async fn stop_rfc5011_updates(&self)
    pub fn get_trust_anchor_status(&self) -> Option<TrustAnchorStatus>
    pub async fn lookup_dnskey(&self, name: &str) -> ResolverResult<Vec<DnsKeyRecord>>
    pub async fn lookup_cds(&self, name: &str) -> ResolverResult<Vec<CdsRecord>>
    pub async fn perform_rfc5011_trust_anchor_check(&self, zone: &str) -> ResolverResult<Rfc5011CheckResult>
}
```

### 4.4 TSIG Verification

```rust
// tsig.rs:118
impl TsigVerifier {
    pub fn new(keys_config: Vec<TsigKeyConfig>) -> Result<Self, String>
    pub fn add_key(&self, config: TsigKeyConfig) -> Result<(), String>
    pub fn remove_key(&self, name: &str) -> Option<TsigKey>
    pub fn verify(&self, tsig_record: &[u8], message: &[u8], original_mac: &[u8], ...) -> Result<(), TsigError>
    pub fn sign(&self, key_name: &str, message: &[u8], tsig_error: u16) -> Result<Vec<u8>, TsigError>
}
```

### 4.5 TrustAnchorManager (RFC 5011)

```rust
// trust_anchor.rs:191
impl TrustAnchorManager {
    pub fn new(config: TrustAnchorConfig) -> Self
    pub fn add_anchor(&self, key_id: String, key_tag: u16, algorithm: u8, public_key: Vec<u8>) -> Result<(), String>
    pub fn remove_anchor(&self, key_id: &str) -> Result<(), String>
    pub fn get_anchors(&self) -> Vec<TrustAnchor>
    pub fn get_trusted_anchors(&self) -> Vec<TrustAnchor>
    pub fn observe_dnskey_at_root(&self, key_tag: u16, algorithm: u8, public_key: &[u8], is_revoked: bool) -> Rfc5011Event
    pub fn trust_anchor_check(&self, key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8], current_dnskey_keytags: Option<&[u16]>) -> Rfc5011Event
    pub fn process_rfc5011_updates(&self) -> Vec<Rfc5011Event>
    pub fn load_initial_anchors_from_file(&self, path: &str) -> Result<usize, String>
}
```

### 4.6 DNSSEC Key Management

```rust
// dnssec.rs (re-exports)
pub use dnssec_key_mgmt::DnsSecKeyManager;
pub use dnssec_signing::{sign_data, create_rrsig_record, create_nsec_record, create_nsec3_record, ...};
pub use dnssec_validation::{calculate_key_tag, canonical_rdata, compute_dnskey, compute_ds_digest, ...};
```

---

## 5. How DNS Resolution Works

### 5.1 Authoritative Server Resolution Flow

```
DNS Query Packet
      │
      ▼
┌─────────────────────────────────┐
│ parse_dns_message()             │
│ wire.rs                         │
└─────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────┐
│ DnsQueryValidator              │
│ - query_validator.rs            │
│ - Validates wire format         │
│ - Checks length limits          │
│ - Validates label counts        │
└─────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────┐
│ Rate Limiting (optional)        │
│ server/rate_limit.rs           │
│ - Response Rate Limiting (RRL) │
└─────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────┐
│ DNS Firewall (optional)        │
│ firewall.rs                    │
│ - Subnet blocking              │
│ - Opcode filtering             │
└─────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────┐
│ Cookie Validation (RFC 7873)  │
│ cookie.rs:66-86              │
│ - Constant-time MAC comparison │
└─────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────┐
│ Zone Lookup                     │
│ ShardedZoneStore                │
│ ZoneTrie for efficient search   │
└─────────────────────────────────┘
      │
      ├──[Zone Found]─────────────► Response built with records
      │                           (NXDOMAIN if not found)
      │
      └──[Zone Not Found]─────────► SERVFAIL / forwarded
```

### 5.2 Recursive Resolution Flow

```
Recursive Query (RecursiveDnsServer)
      │
      ▼
┌─────────────────────────────────┐
│ Check RecursiveDnsCache         │
│ recursive_cache.rs              │
│ - Positive/Negative caching     │
│ - Stale-while-revalidate        │
└─────────────────────────────────┘
      │
      ├──[Cache Hit]──────────────► Build cached response
      │                           (sets authentic_data flag if DNSSEC validated)
      │
      └──[Cache Miss]─────────────┐
                                  ▼
                    ┌─────────────────────────────┐
                    │ Resolve via DnsResolver    │
                    │ resolver.rs                │
                    └─────────────────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
   │HickoryRecursor│      │HickoryResolver│      │GlobalNode    │
   │(full recurs.)│      │ (forwarder)  │      │Resolver      │
   │              │      │              │      │              │
   │- Root hints  │      │- Google DNS  │      │- Mesh nodes  │
   │- Trust anchor│      │- Cloudflare  │      │              │
   │- DNSSEC val  │      │- Upstream IPs│      │              │
   │- RFC 5011    │      │              │      │              │
   └──────────────┘      └──────────────┘      └──────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
                    │ Store in cache + respond    │
                    └─────────────────────────────┘
```

### 5.3 HickoryRecursor (True Recursive)

The `HickoryRecursor` performs **full recursive resolution**:
1. Loads root hints from file
2. Follows delegation chain (root → TLD → authoritative)
3. Optionally validates DNSSEC (`enable_dnssec` flag)
4. Optionally performs RFC 5011 trust anchor updates

```rust
// resolver.rs:628 - HickoryRecursor::from_paths()
let recursor = hickory_resolver::recursor::Recursor::new(
    &roots.iter().map(|c| c.ip).collect::<Vec<_>>(),
    dnssec_policy,
    None,
    recursor_opts,
    TokioRuntimeProvider::default(),
)?;
```

### 5.4 HickoryResolver (Forwarder Mode)

The `HickoryResolver` is a **forwarding resolver** that sends queries to configured upstream servers:
- Google DNS: `8.8.8.8`, `8.8.4.4`
- Cloudflare DNS: `1.1.1.1`, `1.0.0.1`
- Custom upstream IPs
- System resolver config

**Note:** Forwarder mode does **NOT** perform DNSSEC validation - `is_dnssec_validated` is always `false`.

---

## 6. DNSSEC Signing/Validation Flow

### 6.1 DNSSEC Signing (Authoritative Server)

```
Zone Authoritative Response
        │
        ▼
┌───────────────────────────────────┐
│ Check if zone has DNSSEC enabled   │
│ Zone has ksk_key + zsk_key       │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│ For each record in response:      │
│ - Create canonical wire format    │
│ - Sign with ZSK using RRSIG       │
│ dnssec_signing.rs:sign_data()    │
│   - Ed25519: ed25519_dalek       │
│   - RSA: rsa crate               │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│ Include in response:              │
│ - DNSKEY record (public keys)    │
│ - RRSIG records                  │
│ - NSEC/NSEC3 (prove NXDOMAIN)    │
│ dnssec_signing.rs:create_nsec*() │
└───────────────────────────────────┘
```

### 6.2 DNSSEC Validation (Recursive Resolver)

```
DNS Response + RRSIG + DNSKEY + DS
        │
        ▼
┌───────────────────────────────────┐
│ RecursiveDnsServer               │
│ .resolve_upstream()              │
│ Uses HickoryRecursor when:       │
│ config.upstream_provider =       │
│   RecursiveUpstreamProvider::    │
│   Recursive                      │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│ Validate chain of trust:         │
│                                   │
│   Validated DNSKEY               │
│         │                        │
│         │ (computed from DNSKEY)│
│         ▼                        │
│   DS record in parent zone       │
│         │ (digest match)        │
│         ▼                        │
│   Trust Anchor (root)            │
│   or RFC 5011 managed key        │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│ Verify RRSIG signatures          │
│ dnssec_validation.rs            │
│ verify_rrsig()                  │
│ - Canonical form of record      │
│ - Ed25519/RSA verification      │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│ Set authentic_data flag in       │
│ DNS response if validated       │
│ (AD bit, RFC 4035)              │
└───────────────────────────────────┘
```

### 6.3 DNSSEC Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `DnsSecKeyManager` | `dnssec_key_mgmt.rs` | Key generation, storage, rollover |
| `sign_data()` | `dnssec_signing.rs` | Ed25519/RSA signing |
| `create_rrsig_record()` | `dnssec_signing.rs` | Build RRSIG record |
| `create_nsec_record()` | `dnssec_signing.rs` | NSEC proof |
| `create_nsec3_record()` | `dnssec_signing.rs` | NSEC3 proof |
| `calculate_key_tag()` | `dnssec_validation.rs` | RFC 4034 key tag |
| `compute_ds_digest()` | `dnssec_validation.rs` | DS digest computation |
| `canonical_rdata()` | `dnssec_validation.rs` | Canonical RDATA |
| `verify_ds_digest()` | `dnssec_validation.rs` | DS digest verification |

### 6.4 RFC 5011 Trust Anchor State Machine

```
                    ┌──────────────────────────────────────────────┐
  trust_point=0     │              trust_point != 0                  │
  (newly configured)│              (previously Valid)                 │
                    │                                              │
                    │      ┌───────┐                               │
                    │      │ Valid │◄──────────────────────────────┐│
                    │      └───┬───┘                               ││
                    │          │                                    ││
                    │          │ (30-day observation, key in DNSKEY)││
                    │          ▼                                    ││
                    │   ┌────────────┐                              ││
                    │   │  Pending   │────promote after 30 days──►  ││
                    │   └────────────┘                              ││
                    │          │                                    ││
                    │          │ (CDS digest verified)               ││
  ┌─────────────┐   │          ▼                                    ││
  │    Seen     │───┼────►┌────────┐                                ││
  │(in DNSKEY)   │   │      │Pending │                                ││
  └─────────────┘   │      └───┬────┘                                ││
                    │          │                                    ││
                    │          │ (observation period complete)      ││
                    │          ▼                                    ││
                    │   (back to Valid──────────────────────────────┘│
                    │          │                                    ││
                    │          │ (REVOKE bit observed)               ││
                    │          ▼                                    ││
                    │   ┌──────────┐                                 ││
                    └──►│ Revoked  │───── 30 days grace period ────► ││
                        └──────────┘                                 ││
                              │                                       ││
                              │ (extended removal period)            ││
                              ▼                                       ││
                        ┌──────────┐                                  ││
                        │ Removed  │───── extended days ────────────► ││
                        └──────────┘                                 ││
                              │                                       ││
                              │ (purge from storage)                  ││
                              ▼                                       ││
                        ┌──────────┐                                  ││
                        │  Missing │◄──── expired, not seen ────────► ││
                        │ ( Valid  │                                  ││
                        │  was 0)  │                                  ││
                        └──────────┘                                  ││
                             │                                        ││
                             │ (re-appears, CDS digest matches)      ││
                             └────────────────────────────────────────┘
```

**Key rule:** Keys with `trust_point == 0` (never Valid) require digest verification via `trust_anchor_check()` before entering Pending.

### 6.5 Supported Algorithms

| Algorithm | Code | DNSSEC Use | Notes |
|-----------|------|-----------|-------|
| Ed25519 | 15 | KSK/ZSK | Recommended, modern |
| RSA SHA-256 | 8 | KSK/ZSK | Legacy compatibility |

### 6.6 TSIG Transaction Security

TSIG (RFC 2845) provides **message authentication** for DNS:

```rust
// tsig.rs - TsigVerifier::verify()
pub fn verify(&self, ..., original_mac: &[u8], ...) -> Result<(), TsigError> {
    // 1. Time check (fudge window)
    let time_diff = time_signed.abs_diff(now);
    if time_diff > fudge_val { return Err(TsigError::TimeInvalid); }

    // 2. Replay check (cache)
    if cache.is_replay(&mac_hash) { return Err(TsigError::ReplayAttack); }

    // 3. Key lookup
    let key = keys.get(key_name)?;

    // 4. MAC verification (constant-time)
    if !bool::from(computed_mac.ct_eq(original_mac)) {
        return Err(TsigError::MacVerificationFailed);
    }

    // 5. Record in replay cache
    cache.insert(mac_hash);
}
```

Supported algorithms: **HMAC-SHA1**, **HMAC-SHA256**, **HMAC-SHA384**, **HMAC-SHA512**

---

## 7. Feature Gates

The DNS module respects the crate-level feature gates:

| Feature | Submodules Included | Notes |
|---------|-------------------|-------|
| `dns` | Full DNS module | Primary DNS feature |
| `mesh` | `mesh_sync`, `anycast_sync`, mesh registry | Mesh mode DNS registration |
| No features | Core DNS (no mesh) | Standalone authoritative server |

### Compilation Profiles

```bash
# Core (minimal)
cargo check --no-default-features

# DNS profile
cargo check --no-default-features --features dns

# Full (DNS + Mesh)
cargo check --no-default-features --features dns,mesh
```

### Feature-conditional Code

```rust
// server/mod.rs
#[cfg(feature = "dns")]
pub(crate) acme_dns_challenges: Option<Arc<crate::tls::AcmeDnsChallenge>>,

#[cfg(feature = "mesh")]
pub mesh_registry: Option<Arc<MeshDnsRegistry>>,

#[cfg(feature = "mesh")]
pub zone_sync: Option<Arc<AnycastZoneSync>>,

// mod.rs
#[cfg(feature = "mesh")]
pub mod anycast_sync;
#[cfg(feature = "mesh")]
pub mod mesh_sync;
```

---

## 8. Key Configuration Types

### 8.1 RecursiveDnsConfig (via config::dns)

```rust
pub struct RecursiveDnsConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub upstream_provider: RecursiveUpstreamProvider,
    pub upstream_servers: Vec<RecursiveUpstreamServer>,
    pub cache: RecursiveCacheConfig,
    pub dnssec_validation: bool,
    pub qname_minimization: bool,
    pub query_timeout_secs: u64,
    pub max_concurrent_queries: usize,
    pub ratelimit: DnsRateLimitConfig,
    pub firewall: DnsFirewallConfig,
    pub root_hints_path: String,
    pub trust_anchor_path: String,
}

pub enum RecursiveUpstreamProvider {
    Recursive,      // Full recursive with DNSSEC
    GlobalNodes,    // Mesh nodes
    Google,         // Google DNS (no DNSSEC)
    Cloudflare,     // Cloudflare DNS (no DNSSEC)
    System,         // System resolver
    Custom,         // Custom upstream IPs
}
```

### 8.2 TrustAnchorConfig

```rust
pub struct TrustAnchorConfig {
    pub enabled: bool,
    pub db_path: String,
    pub anchor_file_path: String,
    pub refresh_interval_secs: u64,
    pub pending_observation_days: u64,      // Default: 30
    pub revocation_grace_days: u64,           // Default: 30
    pub extended_removal_days: u64,           // Default: 60
    pub trust_anchor_retention_days: u64,     // Default: 7
    pub allow_key_rotation: bool,
}
```

---

## 9. Notable Implementation Details

### 9.1 Query Processing Pipeline (server/query.rs)

The authoritative server processes queries through:
1. **Parse** - `wire::parse_dns_message()` → `ParsedDnsQuery` (parse-once, Phase C)
2. **Validate** - `DnsQueryValidator`
3. **Rate limit** - `DnsRateLimiter::check_ip()`
4. **Firewall** - `DnsFirewall::evaluate_query()`
5. **Cookie check** - `DnsCookieServer::validate_cookie()` (RFC 7873)
6. **Zone lookup** - `ShardedZoneStore` + `ZoneTrie`; `Zone::lookup_authoritative()` returns `AuthoritativeLookupOutcome` (Phase D)
7. **Build response** - Records or NXDOMAIN/SERVFAIL; flags derived from `ResponsePolicy` (Phase A)
8. **Truncation** - Byte-size check: `packet.len() > max_size` → `build_truncated_tc_response()` (Phase B)
9. **Coalescing** - Owner broadcasts response to waiters; `cancel_in_flight()` on failure (Phase F)

**Handler entry points** (parse-once, Phase C):
- `handle_parsed_query(ctx, parsed, client_ip)` — UDP and TCP paths
- `handle_parsed_query_with_cache(ctx, parsed, cache, cache_key, client_ip)` — recursive/cached path

### 9.1.1 Response Flag Policy (Phase A)

All authoritative responses derive flags from `ResponsePolicy` via `build_response_flags_with_policy()`:

| Flag | Authoritative | Recursive |
|------|--------------|-----------|
| AA | true | false |
| RA | false | true (if server supports recursion) |
| RD | echoed from query | echoed from query |
| AD | false (even with RRSIGs) | true only if DNSSEC validated |

This prevents authoritative responses from advertising recursion and prevents signing alone from asserting AD.

### 9.2 DNS Cookie Server (RFC 7873)

Cookie validation at `src/dns/server/query.rs:640-658`:
```rust
if let (Some(cs), Some(edns)) = (ctx.cookie_server, &edns_options) {
    if let Some(ref cookie) = edns.cookie {
        if cookie.server_cookie.is_some() {
            cookie_valid = cs.validate_cookie(client_ip, &cookie.client_cookie, server_cookie);
        }
    }
}
```

Uses **constant-time comparison** via `subtle::ConstantTimeEq`.

### 9.3 Response Rate Limiting (RRL)

`server/rate_limit.rs` implements DNS Response Rate Limiting:
- Token bucket algorithm
- IPv4/IPv6 rate limiting
- Whitelist support

### 9.4 Serial Number Management

Zone serial numbers follow RFC 1982 arithmetic:
```rust
// server/mod.rs:185 - increment_serial_rfc1982()
const HALF_RANGE: u32 = 0x80000000;
current.wrapping_add(1)  // Proper wrap-around handling
```

### 9.5 DNS Cache Architecture (Phase 7)

Three cache implementations serve distinct roles. Phase 7 cache semantics and invalidation workstreams added ~31 tests to `cache.rs` (authoritative cache) and ~19 tests to `recursive_cache.rs` (recursive cache), covering cache key dimensions, serve-stale, TTL clamping, negative TTL from SOA, poisoning detection, cache invalidation on zone mutations, and recursive cache TTL overrides (`stale_ttl_secs`, `max_ttl_secs`, `min_ttl_secs` now confirmed wired).

Test workstreams covered:
- **Cache key redesign**: composite fingerprint keys, qclass/DO-bit/transport-class/namespace dimensions
- **Serve-stale policy**: stale entry serving, `max_stale_count` eviction, counter reset on fresh insert
- **Negative TTL**: SOA-derived TTL (`min(SOA_TTL, SOA_MINIMUM)`), clamped to `[0, negative_cache_ttl]`
- **Poisoning detection**: composite fingerprint keys preventing cross-type conflicts
- **Cache invalidation**: zone mutations (load, add, update, delete, clear) trigger `invalidate_zone()`
- **Recursive cache TTL overrides**: `stale_ttl_secs`, `max_ttl_secs`, `min_ttl_secs` now wired from config

#### Authoritative Cache (`cache.rs`)

```rust
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub client_subnet: Option<IpAddr>,
    pub qclass: u16,              // IN=1, CH=3, etc.
    pub dnssec_ok: bool,          // DO bit — affects response shape
    pub transport_class: TransportClass,  // Udp512 | UdpEdns(u16) | Tcp | Http | Quic
    pub namespace: CacheNamespace,        // Authoritative | Recursive
}

pub enum TransportClass {
    Udp512,
    UdpEdns(u16),   // EDNS UDP payload size
    Tcp,
    Http,
    Quic,
}

pub enum CacheNamespace {
    Authoritative,
    Recursive,
}
```

Cache key dimensions ensure entries are not shared across:
- Different qclasses (IN vs CH)
- Different DO bit values (DNSSEC-signed vs unsigned responses)
- Different transport classes (TCP may have larger responses than UDP)
- Authoritative vs recursive namespaces

Case-insensitive qname canonicalization via `CacheKey::canonicalize()`.

#### Recursive Cache (`recursive_cache.rs`)

Separate positive and negative moka caches (negative = 10% capacity). Uses `Vec<u8>` qname and `RecursiveRecordType` enum.

#### Sharded Cache (`sharded_cache.rs`)

16-shard HashMap for high-concurrency scenarios. No fingerprinting or serve-stale support.

### 9.6 TTL and Negative Caching Policy (Phase 7)

**Positive answers:** TTL clamped to `[config_min_ttl, config_max_ttl]`. Moka `time_to_live` enforces `max_ttl_secs` at the cache layer.

**Negative answers (NXDOMAIN):** TTL derived from SOA authority section: `min(SOA_TTL, SOA_MINIMUM)` per RFC 2308, then clamped to `[0, config_negative_cache_ttl]`.

**NODATA responses:** Same SOA-derived TTL as NXDOMAIN.

**SERVFAIL/REFUSED:** Not cached by default (TTL extraction returns 0 for unrecognized RCODEs).

**Malformed responses:** Not cached (TTL extraction fails → TTL=0).

### 9.7 Cache Invalidation (Phase 7)

All zone mutation paths trigger cache invalidation:

| Mutation Path | Trigger | Mechanism |
|---------------|---------|-----------|
| Config zone load | `server/mod.rs` | `cache.invalidate_zone()` on zone reload |
| `add_record()` | `server/zone.rs` | `cache.invalidate_zone()` after record insert |
| Dynamic update (RFC 2136) | `update.rs` | `cache.invalidate_zone()` after zone record modification |
| Zone delete | `server/zone.rs` | `cache.invalidate_zone()` |
| Clear all | `server/zone.rs` | `cache.clear()` |

**Zone transfer note:** `transfer.rs` only serves outbound AXFR/IXFR — no incoming transfer path exists, so no cache invalidation needed.

Invalidation uses the `qname_index` secondary index for O(1) qname lookup (not O(n) scan).

### 9.8 Serve-Stale Policy (Phase 7)

- **Disabled by default** (`serve_stale.enabled = false`).
- When enabled, stale entries are served within `max_stale_secs` window (default 86400s).
- `max_stale_count` bounds total stale entries served per cache instance (counter resets on fresh insert).
- No background revalidation — stale entries are served as-is and removed when they exceed the stale window.
- Config: `ServeStaleConfig { enabled, max_stale_secs, max_stale_count }`.

### 9.9 Cache Poisoning Detection (Phase 7)

Fingerprint-based poisoning detection uses **composite keys** to prevent cross-type conflicts:

```
fingerprint_key = "{qname}|{qtype}|{qclass}|{dnssec_ok}|{namespace}"
```

Previously, fingerprinting was keyed by qname only — A and AAAA records for the same qname would conflict, causing false positive poisoning alerts.

After `confirmation_threshold` (default 3) consistent fingerprints, new fingerprints are allowed (legitimate zone changes).

### 9.10 Cache Metrics (Phase 7)

**Cache-level metrics** (`CacheMetrics`):
- `hits` — fresh cache hits
- `stale_hits` — stale entries served
- `negative_hits` — negative cache hits
- `misses` — cache misses
- `insertions` — entries inserted
- `invalidations` — entries invalidated (by zone/record clear)
- `poisoned_rejections` — entries rejected by poisoning detection
- `size_rejections` — entries rejected due to max_entry_size

**Prometheus export** (`dns_cache_*`):
- `dns_cache_hits_total`, `dns_cache_misses_total`
- `dns_cache_stale_hits_total`, `dns_cache_negative_hits_total`
- `dns_cache_invalidations_total`, `dns_cache_poisoned_rejections_total`
- `dns_cache_hit_rate`

### 9.11 Wire Format Parsing

**Canonical query parser** (`parsed_query.rs`):
```rust
/// One-shot canonical parser for DNS query messages.
/// Replaces 7+ ad-hoc QNAME/QTYPE extraction loops across the codebase.
pub struct ParsedDnsQuery<'a> {
    pub id: u16,
    pub flags: QueryFlags,
    pub qdcount: u16,
    pub qname: String,
    pub qname_end: usize,
    pub qtype: u16,
    pub qclass: u16,
    pub question_end: usize,
    pub has_edns: bool,
    pub dnssec_ok: bool,
    pub raw: &'a [u8],
}
impl<'a> ParsedDnsQuery<'a> {
    pub fn parse(query: &'a [u8]) -> Result<Self, QueryParseError>;
    pub fn is_query(&self) -> bool;
    pub fn is_axfr(&self) -> bool;
    pub fn is_ixfr(&self) -> bool;
    pub fn is_notify(&self) -> bool;
    pub fn is_update(&self) -> bool;
}

/// Response flag policy — derived from parsed query.
pub struct ResponsePolicy {
    pub authoritative: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub checking_disabled_allowed: bool,
}

/// Canonical response flag constructor (replaces magic hex constants).
pub fn build_response_flags(auth: bool, trunc: bool, rd: bool, ra: bool, ad: bool, rcode: u16) -> u16;
pub fn build_response_flags_from_query(parsed: &ParsedDnsQuery, auth: bool, trunc: bool, ra: bool, ad: bool, rcode: u16) -> u16;
pub fn build_response_flags_with_policy(parsed: &ParsedDnsQuery, policy: &ResponsePolicy, trunc: bool, rcode: u16) -> u16;

/// Coalescing key derived from parsed query state.
impl QueryKey {
    pub fn from_parsed(parsed: &ParsedDnsQuery, client_ip: &str, dimensions: ...) -> Self;
}
```

**Low-level wire utilities** (`wire.rs`):
```rust
pub fn parse_dns_message(msg: &[u8]) -> Result<ParsedMessage, WireError>
pub fn parse_query_name(msg: &[u8], pos: usize) -> Option<String>
pub fn build_question(...) -> Vec<u8>
pub fn build_response_header(...) -> Vec<u8>
pub fn build_error_response(...) -> Option<Vec<u8>>
```

### 9.12 Serialization

Trust anchor persistence uses **Postcard** (via `rkyv`) for binary serialization:
```rust
#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
pub struct TrustAnchor { ... }
```

---

## 10. Known Integration Points

| Item | Location | Description |
|------|----------|--------------|
| DNS Cookie wiring | `server/query.rs:645-662` | `validate_cookie()` called for RFC 7873 |
| Query Coalescer | `crates/synvoid-dns/src/query_coalesce.rs:131` | `with_config(max_wait_ms, max_entries, entry_ttl_secs)` |
| DNSSEC validation | `resolver.rs:423` | `HickoryResolver` always returns `is_dnssec_validated: false` |
| GlobalNodeResolver | `resolver_global.rs` | Resolves via mesh global nodes |
| mesh_sync | `anycast_sync.rs` | Mesh-based zone sync |

---

## 11. Milestone 1 Verification Status

Completed 2026-07-03. 390/390 DNS lib tests pass, 30/30 authoritative_negative tests pass.

### 11.1 Behavior Verified

| Area | Status | Details |
|------|--------|---------|
| Positive RR encoding | Verified | `encode_rr` handles A, AAAA, NS, SOA, MX, TXT, CNAME, SRV, CAA, TLSA, DNSKEY, DS, NSEC, NSEC3, RRSIG |
| Parsed query propagation | Verified | `ParsedDnsQuery::parse()` called once at UDP/TCP entry; `&ParsedDnsQuery` passed to all handlers |
| Query coalescing | Verified | `QueryKey` (6 dimensions: name, qtype, qclass, dnssec_ok, edns_udp_size, client_ip); `broadcast_response` on success, `cancel_in_flight` on failure |
| Unsigned negative responses | Verified | NODATA (RCODE=0 + SOA) and NXDOMAIN (RCODE=3 + SOA) include SOA in authority section via `encode_rr` |
| No-zone REFUSED | Verified | Unknown zones return RCODE=5 (REFUSED) |
| Truncation | Verified | Byte-size based (EDNS UDP payload or 512); TC response preserves query ID, RD echo, QDCOUNT=1 |
| AD/RA policy | Verified | Authoritative responses: AA=1, RA=0, AD=false. AD is only set by recursive resolver when `is_dnssec_validated` |
| SOA enforcement | Verified | Zones rejected at load time if SOA missing; runtime SERVFAIL if SOA absent at query time (fail-closed) |
| Signed NXDOMAIN SOA | Verified | `build_nxdomain_response` includes SOA in authority section before NSEC/NSEC3 records |
| DNSSEC NODATA wire encoding | Fixed | SOA RDATA in NODATA responses uses proper wire format (mname/rname via `encode_name` + 5×u32) |

### 11.2 Test Inventory

| Test suite | Count | Location |
|------------|-------|----------|
| DNS lib unit tests | 399 | `crates/synvoid-dns/src/` |
| Authoritative negative integration | 37 | `tests/authoritative_negative.rs` |
| Flag builder unit tests | 28 | `crates/synvoid-dns/src/parsed_query.rs` |
| Response encoder unit tests | ~30 | `crates/synvoid-dns/src/server/response_encoder.rs` |
| Truncation tests | 10 | `crates/synvoid-dns/src/server/response.rs` |
| Limits tests | 7 | `crates/synvoid-dns/src/limits.rs` |
| DNS64 tests | 6 | `crates/synvoid-dns/src/dns64.rs` |

### 11.3 DNSSEC Limitations (Deferred to Milestone 3)

- **Signed NODATA/NXDOMAIN**: The signed negative response path uses `build_nxdomain_response`/`build_nodata_response` which assemble NSEC/NSEC3 + RRSIG records. While these are now routed through `encode_rr` and `ResponseEnvelope`, the DNSSEC denial proof logic is minimal and not production-hardened.
- **NSEC3 closest-encloser**: Not fully implemented; wildcard matching is limited to NSEC3 denial proofs.
- **RFC 5001 / RFC 5155 compliance**: Not audited for full conformance.
- **DNSSEC signing**: Zones can have KSK/ZSK and generate RRSIGs, but key lifecycle, rotation, and failure modes are not hardened.

### 11.4 External Interoperability

External smoke tests (dig/drill/delv against a running server) were not run during this verification pass. They require a live server instance and external DNS client tools. These should be validated in a staging environment before production deployment.

### 11.5 Verification Commands

```bash
cargo test -p synvoid-dns                                    # 399 tests
cargo test -p synvoid-dns --test authoritative_negative      # 37 tests
cargo test -p synvoid-dns -- flag                            # 33 flag tests (5 regression added)
cargo test -p synvoid-dns -- response_encoder                # ~30 encoder tests
cargo check -p synvoid-dns --all-features                    # clean
cargo check --workspace                                      # clean
```

### 11.6 Milestone 1 Closure Summary

Milestone 1 is closed. The authoritative DNS wire/query correctness is verified:

- **399 lib tests + 37 authoritative_negative integration tests** pass.
- All authoritative responses (positive, NODATA, NXDOMAIN, REFUSED, truncated) have correct flags: AA=1, RA=0, AD=0, RD echoed from query.
- Both signed and unsigned negative responses include SOA in the authority section (fail-closed: missing SOA returns SERVFAIL).
- Signed NXDOMAIN now includes SOA before NSEC/NSEC3 denial proofs.
- 5 flag regression tests guard against future reintroduction of AD/RA into authoritative responses.
- 2 SOA fail-closed tests verify SERVFAIL when SOA is absent.
- Duplicate legacy `src/dns/` tree removed (43 dead files, ~25k lines). Canonical path: `crates/synvoid-dns/src/`.

**What Milestone 1 is**: Authoritative wire-format correctness, query parsing, response assembly, SOA inclusion, flag semantics, DNSSEC NODATA/NXDOMAIN denial proof scaffolding, and truncation.

**What Milestone 1 is not**: Full DNSSEC production hardening (NSEC3 closest-encloser, RFC 5001/5155 compliance, key lifecycle), recursive resolver transport, or external interoperability validation. These remain deferred to Milestone 3.

---

## Phase 5: Config-to-Runtime Fidelity

Phase 5 audited every DNS config field and ensured each is either fully implemented, explicitly documented as deferred, or removed. See `architecture/dns_config_runtime_matrix.md` for the complete field inventory.

### Key Changes

1. **serve_stale wiring**: `DnsServer::new()` now uses `DnsCache::with_serve_stale()` when `config.settings.serve_stale.enabled` is true, passing `max_stale_secs` from config.

2. **DNS64 exclude_aaaa_synthesis**: Added `exclude_aaaa_synthesis: bool` to runtime `Dns64Config`. When true, AAAA synthesis is skipped entirely for all clients.

### Deferred Features (Phase 7+)

The following features have config fields but are NOT wired to runtime behavior:

- **RPZ** (`dns.rpz.*`): Requires rule database engine
- **Dynamic Update** (`dns.settings.dynamic_update`): Handler exists but not wired; security-sensitive
- **Notify** (`dns.settings.notify`): Handler exists but not wired
- **Zone Transfer** (`dns.settings.allow_transfer`, `require_tsig`, `allow_wildcard_transfer`, `wildcard_transfer_requires_tsig`): Requires TSIG infrastructure
- **IXFR** (`dns.settings.ixfr_enabled`, `ixfr_history_size`, `ixfr_fallback_to_axfr`): Requires delta encoding
- **Trust Anchors** (`dns.trust_anchors`): Uses system defaults via HickoryRecursor
- **Prefetch** (`dns.prefetch.*`): Requires predictive cache warming
- **Anycast** (`dns.anycast.*`): Requires mesh feature gate
- **QName Privacy** (`dns.settings.qname_privacy`): Logging integration not wired
- **Padding** (`dns.settings.padding`): EDNS padding struct exists but not wired from config

### Test Coverage

Phase 5 added 37+ tests across two integration test files:
- `dns_config_fidelity.rs`: Cache serve_stale, min/max TTL, DNS64 synthesis/disable/custom prefix/exclude, ECS filter, firewall rules
- `dns_recursive_isolation.rs`: Recursive mode bind independence, cache isolation, authoritative REFUSED, anycast/mesh feature gates, config validation guards

