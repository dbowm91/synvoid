//! DNS-owned runtime configuration vocabulary (Phases 125–130).
//!
//! This module is the **single DNS-owned home for runtime configuration
//! values**. Persisted TOML/JSON schema stays in `synvoid-config`; the
//! application-owned adapter (`src/server/dns_runtime_config.rs`) converts
//! validated persisted config into the types below. Nothing here derives
//! `Serialize`/`Deserialize`/`JsonSchema`/`ToSchema`: this is a runtime
//! vocabulary, not a second persisted schema.
//!
//! # Disciplinary rules
//!
//! * Only values with a real runtime consumer appear here. Fields that are
//!   persisted but unsupported, deferred, or unwired are **absent by design**
//!   and are proven absent by `tests/runtime_config_absent_by_design.rs`.
//! * Values are parsed as early as possible (`SocketAddr`, `Duration`,
//!   `PathBuf`, `Ipv6Addr`, `ipnetwork::IpNetwork`, typed action enums) so
//!   malformed input fails at conversion time, not on the request path.
//! * Certificate/TLS material, GeoIP databases, and mesh/DHT handles are
//!   **provider-owned** by composition and are not modeled here. Provider
//!   inversion is explicitly out of scope for Phases 125–130.
//! * DNSSEC private-key custody stays one-way through
//!   [`crate::dnssec`]/`synvoid-dnssec-keystore`; no runtime type here
//!   carries raw private key material.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// Hickory's runtime record type, re-exported so the application adapter can
/// map the persisted record-type enum without taking a direct protocol
/// dependency.
pub use hickory_proto::rr::RecordType;

// ---------------------------------------------------------------------------
// Top-level authoritative runtime configuration
// ---------------------------------------------------------------------------

/// Complete DNS-owned runtime configuration for one server instance.
#[derive(Debug, Clone)]
pub struct DnsRuntimeConfig {
    /// Top-level activation gate (`dns.enabled`). Composition checks this
    /// before building a server at all.
    pub enabled: bool,
    /// Authoritative UDP/TCP bind socket (`dns.bind_address` + `dns.port`),
    /// parsed once at conversion time.
    pub bind_address: SocketAddr,
    /// Response TTL policy.
    pub ttl: TtlRuntimeConfig,
    /// Authoritative answer cache.
    pub cache: CacheRuntimeConfig,
    /// Connection/query/response limits.
    pub limits: LimitsRuntimeConfig,
    /// DNS request rate limiting.
    pub rate_limit: DnsRateLimitRuntimeConfig,
    /// Response-rate limiting.
    pub rrl: RrlRuntimeConfig,
    /// Implemented DNS firewall controls.
    pub firewall: DnsFirewallRuntimeConfig,
    /// EDNS Client Subnet filtering.
    pub ecs: EcsRuntimeConfig,
    /// Duplicate-query coalescing.
    pub query_coalescing: QueryCoalescingRuntimeConfig,
    /// RFC 6147 DNS64 synthesis (`None` when disabled).
    pub dns64: Option<Dns64RuntimeConfig>,
    /// DNS-over-TLS listener runtime.
    pub dot: DotRuntimeConfig,
    /// DNS-over-HTTPS listener runtime.
    pub doh: DohRuntimeConfig,
    /// DNS-over-Quic listener runtime.
    pub doq: DoqRuntimeConfig,
    /// RFC 2136 dynamic update runtime.
    pub dynamic_update: DynamicUpdateRuntimeConfig,
    /// Zone-transfer runtime policy.
    pub zone_transfer: ZoneTransferRuntimeConfig,
    /// Anycast activation guard.
    pub anycast: AnycastRuntimeConfig,
    /// Global DNSSEC policy and key custody wiring.
    pub dnssec: DnssecRuntimeConfig,
    /// Zone input specs (authoritative zone data).
    pub zones: Vec<ZoneSpec>,
    /// Runtime TSIG key material.
    pub tsig_keys: Vec<TsigRuntimeKey>,
    /// Recursive resolver runtime subtree.
    pub recursive: RecursiveRuntimeConfig,
}

impl DnsRuntimeConfig {
    /// Health-derived transport flags. Mirrors the values the health checker
    /// is initialized with, so health state is a pure function of runtime
    /// configuration.
    pub fn is_dot_enabled(&self) -> bool {
        self.dot.enabled
    }

    pub fn is_doh_enabled(&self) -> bool {
        self.doh.enabled
    }

    pub fn is_doq_enabled(&self) -> bool {
        self.doq.enabled
    }

    /// AXFR is always wired in the authoritative transport; the health flag
    /// reflects that a transfer handler exists, not a config toggle.
    pub fn is_axfr_enabled(&self) -> bool {
        true
    }

    pub fn is_ixfr_enabled(&self) -> bool {
        self.zone_transfer.ixfr_enabled
    }

    pub fn is_update_enabled(&self) -> bool {
        self.dynamic_update.enabled
    }

    pub fn is_tsig_required(&self) -> bool {
        self.zone_transfer.require_tsig
    }

    /// Listener socket for an enabled transport.
    ///
    /// Returns `None` when the transport is disabled, which is the only case
    /// in which a transport carries no parsed address.
    pub fn transport_bind(&self, transport: EncryptedTransport) -> Option<SocketAddr> {
        match transport {
            EncryptedTransport::Dot => self.dot.bind_address,
            EncryptedTransport::Doh => self.doh.bind_address,
            EncryptedTransport::Doq => self.doq.bind_address,
        }
    }
}

/// Which encrypted transport to inspect on [`DnsRuntimeConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedTransport {
    Dot,
    Doh,
    Doq,
}

// ---------------------------------------------------------------------------
// TTL / cache
// ---------------------------------------------------------------------------

/// Response TTL policy in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlRuntimeConfig {
    /// Default TTL applied to records served from a zone.
    pub default_ttl: u32,
    /// Floor applied to GeoIP-selected answers.
    pub min_geo_ttl: u32,
    /// TTL used for synthesized/negative authoritative answers.
    pub negative_cache_ttl: u32,
}

/// Authoritative answer cache runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheRuntimeConfig {
    pub enabled: bool,
    /// Maximum entry count.
    pub capacity: usize,
    /// Upper clamp applied to every stored record.
    pub max_ttl: Duration,
    /// Lower clamp applied to every stored record.
    pub min_ttl: Duration,
    /// Serve-stale window; `None` when serve-stale is disabled.
    pub serve_stale: Option<ServeStaleRuntimeConfig>,
}

impl CacheRuntimeConfig {
    /// Upper TTL as a `u32` for consumers with a 32-bit TTL field. Saturates
    /// instead of truncating so an absurd persisted TTL clamps upward rather
    /// than wrapping to a near-zero value.
    pub fn max_ttl_secs_u32(&self) -> u32 {
        u32::try_from(self.max_ttl.as_secs()).unwrap_or(u32::MAX)
    }
}

/// Serve-stale window. The presence of this value *is* the enable flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeStaleRuntimeConfig {
    pub max_stale: Duration,
    pub max_stale_count: usize,
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Connection, query, and response bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitsRuntimeConfig {
    pub max_tcp_connections: usize,
    pub max_concurrent_queries: usize,
    pub max_query_size: usize,
    pub max_response_size: usize,
    pub max_records_per_response: usize,
    pub max_tcp_idle_time: Duration,
    pub max_tcp_query_time: Duration,
    /// Allow the server to shed load instead of failing closed immediately.
    pub enable_graceful_degradation: bool,
    /// Socket receive buffer for both the UDP and TCP authoritative listeners.
    pub udp_buffer_size: usize,
}

// ---------------------------------------------------------------------------
// Rate limiting / RRL
// ---------------------------------------------------------------------------

/// Whether DNS rate limiting uses the shared process limiter or a
/// dedicated per-server limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRateLimitModeRuntime {
    /// Reuse the composition-owned shared limiter.
    Shared,
    /// Build a limiter dedicated to this DNS server.
    Dedicated,
}

/// DNS request rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsRateLimitRuntimeConfig {
    pub mode: DnsRateLimitModeRuntime,
    pub per_second: u64,
}

/// Response-rate limiting. Only the activation flag has a runtime consumer;
/// the response/second, window, max-response, and TTL values are
/// persistence-only and deliberately absent (see the ownership ledger).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrlRuntimeConfig {
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

/// Implemented DNS firewall controls.
///
/// `default_action` and `max_rules` are persisted but have no runtime
/// consumer and are absent by design. Rebinding-protection settings
/// (`enabled`, `min_ttl_for_internal`, `allowed_internal_domains`,
/// `block_short_ttl_internal`) are wired to a real request-path helper
/// rather than to firewall rules, so they are absent here too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsFirewallRuntimeConfig {
    pub enabled: bool,
    /// Install the built-in private/loopback/link-local subnet block rules.
    pub block_internal_ips: bool,
    /// Install the built-in AXFR (opcode 0x2) block rule.
    pub block_zone_transfers: bool,
}

// ---------------------------------------------------------------------------
// EDNS / DNS64 / coalescing
// ---------------------------------------------------------------------------

/// EDNS Client Subnet filtering for the authoritative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcsRuntimeConfig {
    pub enabled: bool,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub allow_private_prefix: bool,
}

/// RFC 6147 DNS64 runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dns64RuntimeConfig {
    /// Well-known prefix `64:ff9b::/96` (or an operator-provided literal).
    pub prefix: Ipv6Addr,
    /// Suppress AAAA synthesis so the AAAA answer passes through unchanged.
    pub exclude_aaaa_synthesis: bool,
}

/// Duplicate in-flight query coalescing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryCoalescingRuntimeConfig {
    pub enabled: bool,
    pub max_wait: Duration,
    pub max_entries: usize,
    pub entry_ttl: Duration,
    /// Background cleanup cadence for expired coalescer entries.
    pub cleanup_interval: Duration,
}

// ---------------------------------------------------------------------------
// Encrypted transports
// ---------------------------------------------------------------------------

/// DoT listener runtime. Certificate material is composition/provider owned
/// (`CertResolver`); persisted `tls_cert_path`/`tls_key_path`/
/// `use_system_cert_store` are therefore absent by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DotRuntimeConfig {
    pub enabled: bool,
    /// Parsed listener socket. `None` exactly when the transport is
    /// disabled, so a disabled transport never carries a fabricated address.
    pub bind_address: Option<SocketAddr>,
}

/// DoH listener runtime.
///
/// Persisted `doh.path` and `doh.json_path` are **not** runtime inputs: the
/// served routes are fixed protocol constants (`/dns-query`, `/`, and the
/// legacy JSON routes), so those persisted fields are absent by design and
/// the matrix records them as unconsumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DohRuntimeConfig {
    pub enabled: bool,
    /// Parsed listener socket. `None` exactly when the transport is disabled.
    pub bind_address: Option<SocketAddr>,
}

/// DoQ listener runtime. ALPN and TLS material stay composition/provider
/// owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoqRuntimeConfig {
    pub enabled: bool,
    /// Parsed listener socket. `None` exactly when the transport is disabled.
    pub bind_address: Option<SocketAddr>,
    pub max_concurrent_streams: u32,
    pub idle_timeout: Duration,
}

// ---------------------------------------------------------------------------
// Update / transfer / anycast
// ---------------------------------------------------------------------------

/// RFC 2136 dynamic update runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicUpdateRuntimeConfig {
    pub enabled: bool,
    /// Accept updates from any source. When `false` the control-plane guard
    /// in the update handler decides.
    pub allow_any: bool,
    pub require_tsig: bool,
    pub max_update_size: usize,
}

/// Zone-transfer runtime policy. The allowlist is parsed into networks at
/// conversion time; wildcard support is a boolean pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneTransferRuntimeConfig {
    pub allow_transfer: Vec<IpNetwork>,
    pub allow_wildcard_transfer: bool,
    pub wildcard_transfer_requires_tsig: bool,
    pub ixfr_enabled: bool,
    pub ixfr_fallback_to_axfr: bool,
    pub require_tsig: bool,
}

/// Anycast activation guard.
///
/// Persisted anycast addresses, intervals, and health-check settings are
/// unsupported: activation fails closed at startup, so no active anycast
/// setting is projected. This type carries the *rejection signal* only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnycastRuntimeConfig {
    /// When `true`, `DnsServer::start()` must fail closed.
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// DNSSEC / HSM / zones / TSIG
// ---------------------------------------------------------------------------

/// DNSSEC algorithm identifiers owned by DNS runtime. The persisted enum is
/// mapped by the application adapter; this type is the runtime vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecAlgorithmRuntime {
    Ed25519,
    Rsa,
}

impl DnssecAlgorithmRuntime {
    /// Wire/canonical name for the algorithm.
    pub fn as_str(&self) -> &'static str {
        match self {
            DnssecAlgorithmRuntime::Ed25519 => "ED25519",
            DnssecAlgorithmRuntime::Rsa => "RSASHA256",
        }
    }
}

/// DNSSEC signing key role. KSK/KSK+ZSK split is a runtime concern; the
/// persisted configuration selects KSK generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecKeyTypeRuntime {
    Ksk,
    Zsk,
}

/// NSEC/NSEC3 denial-of-existence policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnssecDenialPolicyRuntime {
    pub nsec_enabled: bool,
    pub nsec3_enabled: bool,
    /// NSEC3 hash iterations; global default used when a zone does not
    /// override it.
    pub nsec3_iterations: u16,
    /// NSEC3 hash algorithm identifier (1 = SHA-1).
    pub nsec3_algorithm: u8,
}

/// Global DNSSEC runtime policy and custody wiring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnssecRuntimeConfig {
    pub enabled: bool,
    /// Signing domain; also the KSK owner-name suffix.
    pub domain: String,
    /// Sealed-key storage directory owned by `synvoid-dnssec-keystore`.
    pub key_path: PathBuf,
    pub algorithm: DnssecAlgorithmRuntime,
    pub key_type: DnssecKeyTypeRuntime,
    /// RSA modulus size used at key generation.
    pub rsa_key_size: u32,
    pub ksk_key_size: u32,
    pub rollover_interval: Duration,
    pub denial: DnssecDenialPolicyRuntime,
    /// Keystore-owned HSM settings. Constructed by the application adapter so
    /// persisted HSM schema never enters the DNS crate.
    pub hsm: HsmRuntimeConfig,
}

/// HSM backend selector owned by DNS runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmProviderRuntime {
    /// Hardware PKCS#11 token.
    Pkcs11,
    /// Software backend (test/dev only).
    Soft,
}

/// HSM (PKCS#11) activation. Establishment is fail-closed: there is no
/// software fallback for a required hardware token, and the PIN crosses into
/// the keystore crate, which wraps it in a zeroizing secret type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsmRuntimeConfig {
    pub enabled: bool,
    pub provider: HsmProviderRuntime,
    /// PKCS#11 module path.
    pub module_path: String,
    pub slot_id: Option<usize>,
    /// Never logged, never included in conversion errors.
    pub pin: Option<String>,
    pub key_label: Option<String>,
    pub key_id: Option<Vec<u8>>,
    /// Fail-closed establishment: any PKCS#11 failure is returned to the
    /// caller and signed answers are refused.
    pub require_hsm: bool,
}

impl Default for HsmRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: HsmProviderRuntime::Pkcs11,
            module_path: String::new(),
            slot_id: None,
            pin: None,
            key_label: None,
            key_id: None,
            require_hsm: true,
        }
    }
}

/// One authoritative zone, as runtime input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSpec {
    /// Zone origin, normalized by the adapter.
    pub origin: String,
    pub records: Vec<ZoneRecordSpec>,
    /// Per-zone DNSSEC overrides; `None` means "use the global policy".
    pub dnssec: Option<ZoneDnssecSpec>,
}

/// Per-zone DNSSEC override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneDnssecSpec {
    /// When `false`, the global NSEC/NSEC3 policy applies.
    pub enabled: bool,
    pub nsec_enabled: bool,
    pub nsec3_enabled: bool,
    /// `None` falls back to the global `nsec3_iterations`.
    pub nsec3_iterations: Option<u16>,
}

/// One zone record, as runtime input. The persisted record-type enum is
/// mapped to Hickory's `RecordType` by the application adapter so this crate
/// does not duplicate the persistence enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRecordSpec {
    pub name: String,
    pub record_type: RecordType,
    /// Record TTL; `None` means "use the server's default TTL", resolved by
    /// the authoritative zone loader so the fallback stays in one place.
    pub ttl: Option<u32>,
    /// Textual record value; parsing/validation stays in the authoritative
    /// zone loader so validation behavior is unchanged.
    pub value: String,
    pub priority: Option<u32>,
}

// ---------------------------------------------------------------------------
// TSIG
// ---------------------------------------------------------------------------

/// TSIG MAC algorithm identifiers owned by DNS runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithmRuntime {
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithmRuntime {
    /// Canonical TSIG algorithm name (RFC 8945).
    pub fn as_str(&self) -> &'static str {
        match self {
            TsigAlgorithmRuntime::HmacSha256 => "hmac-sha256.",
            TsigAlgorithmRuntime::HmacSha384 => "hmac-sha384.",
            TsigAlgorithmRuntime::HmacSha512 => "hmac-sha512.",
        }
    }

    /// Minimum decoded secret length, in bytes. Enforced at conversion time
    /// so undersized keys never reach the verifier.
    pub const fn min_secret_len(&self) -> usize {
        match self {
            // RFC 8945 recommends at least half the hash output.
            TsigAlgorithmRuntime::HmacSha256 => 16,
            TsigAlgorithmRuntime::HmacSha384 => 24,
            TsigAlgorithmRuntime::HmacSha512 => 32,
        }
    }
}

/// One TSIG key, as runtime input. The secret is already base64-decoded and
/// length-checked by the application adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct TsigRuntimeKey {
    /// Key name (FQDN form, e.g. `transfer-key.`).
    pub name: String,
    /// Decoded shared secret. Never logged.
    pub secret: Vec<u8>,
    pub algorithm: TsigAlgorithmRuntime,
}

impl std::fmt::Debug for TsigRuntimeKey {
    /// Redacts the secret so a stray `{:?}` cannot leak key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsigRuntimeKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Recursive runtime subtree
// ---------------------------------------------------------------------------

/// Parsed IP network used by recursive ACL and transfer allowlists.
///
/// A small owned wrapper avoids exposing `ipnetwork`'s borrowed-string view
/// types in the runtime API while keeping CIDR matching semantics identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNetwork {
    ip: IpAddr,
    prefix_len: u8,
}

impl IpNetwork {
    /// Build a network from an address and prefix length.
    pub const fn new(ip: IpAddr, prefix_len: u8) -> Self {
        Self { ip, prefix_len }
    }

    /// Network base address.
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Prefix length in bits.
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Parse a CIDR (`addr/len`) or a bare address (implicit full-length
    /// prefix) into a network.
    ///
    /// Parsing lives here so the owning crate validates operator input once,
    /// at conversion time, and no caller can lazily build a network on the
    /// request path. Rejects a family mismatch between address and prefix
    /// length and any out-of-range prefix.
    pub fn parse(value: &str) -> Result<Self, IpNetworkParseError> {
        let value = value.trim();
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => {
                let prefix_len: u8 = prefix.trim().parse().map_err(|_| {
                    IpNetworkParseError::new(value, "prefix length is not a valid integer")
                })?;
                (address.trim(), Some(prefix_len))
            }
            None => (value, None),
        };

        let ip: IpAddr = address.parse().map_err(|e| {
            IpNetworkParseError::new(value, &format!("address is not a valid IP literal: {e}"))
        })?;

        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = match prefix {
            Some(len) if len > max_prefix => {
                return Err(IpNetworkParseError::new(
                    value,
                    &format!("prefix length must be between 0 and {max_prefix}"),
                ));
            }
            Some(len) => len,
            None => max_prefix,
        };

        Ok(Self { ip, prefix_len })
    }

    /// `true` when `candidate` falls inside this network.
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.ip, candidate) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                let prefix = self.prefix_len.min(32);
                let mask: u32 = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(network) & mask == u32::from(addr) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                let prefix = self.prefix_len.min(128);
                let mask: u128 = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(network) & mask == u128::from(addr) & mask
            }
            _ => false,
        }
    }
}

/// Recursive client ACL action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecursiveAclActionRuntime {
    /// Anything not matched by the allowlist is rejected.
    Reject,
    /// Anything not matched by the allowlist is served.
    Allow,
}

/// Recursive client ACL: parsed networks plus an explicit action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveClientAclRuntime {
    /// Parsed allowlist. An empty list means "no restriction".
    pub allowed_clients: Vec<IpNetwork>,
    pub action: RecursiveAclActionRuntime,
}

impl RecursiveClientAclRuntime {
    /// Runtime ACL policy. Preserves the persisted semantics exactly:
    /// an empty allowlist allows every client, otherwise a CIDR match allows
    /// and the action decides the fallback.
    pub fn is_client_allowed(&self, client_ip: IpAddr) -> bool {
        if self.allowed_clients.is_empty() {
            return true;
        }
        if self
            .allowed_clients
            .iter()
            .any(|net| net.contains(client_ip))
        {
            return true;
        }
        matches!(self.action, RecursiveAclActionRuntime::Allow)
    }
}

/// Failure to parse a CIDR or bare address into an [`IpNetwork`].
///
/// The message names the offending value but never any secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNetworkParseError {
    value: String,
    reason: String,
}

impl IpNetworkParseError {
    fn new(value: &str, reason: &str) -> Self {
        Self {
            value: value.to_string(),
            reason: reason.to_string(),
        }
    }
}

impl std::fmt::Display for IpNetworkParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "'{}' is not a valid network: {}",
            self.value, self.reason
        )
    }
}

impl std::error::Error for IpNetworkParseError {}

/// Upstream resolution strategy, normalized away from the persisted
/// "System-or-Custom" ambiguity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecursiveUpstreamRuntime {
    /// Use the host resolver configuration.
    System,
    /// Forward to a public Google endpoint (no local DNSSEC validation).
    Google,
    /// Forward to a public Cloudflare endpoint (no local DNSSEC validation).
    Cloudflare,
    /// Forward to the operator-supplied endpoints below.
    CustomEndpoints(Vec<CustomUpstreamEndpoint>),
    /// True recursion from the root using the configured hints/anchor.
    Recursive {
        root_hints: PathBuf,
        trust_anchor: PathBuf,
    },
    /// Forward to mesh-provided global nodes. Retained for parity until
    /// provider inversion.
    GlobalNodes,
}

/// One custom recursive upstream endpoint. A literal IP and a hostname stay
/// distinguishable after conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomUpstreamEndpoint {
    /// Literal address plus port.
    Literal { ip: IpAddr, port: u16 },
    /// Resolved-at-startup hostname plus port.
    Hostname { host: String, port: u16 },
}

/// Recursive cache runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecursiveCacheRuntimeConfig {
    pub capacity: usize,
    pub negative_ttl: Duration,
    pub stale_ttl: Duration,
    pub max_ttl: Duration,
    pub min_ttl: Duration,
}

/// Circuit-breaker runtime thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreakerRuntimeConfig {
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
    pub success_threshold: u32,
}

/// Recursive ECS forwarding policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecursiveEcsPolicyRuntime {
    /// Never forward client subnet.
    Never,
    /// Always forward the configured prefix.
    Always,
    /// Forward only for known CDN ranges.
    CdnOnly,
    /// Forward when the query already carries a subnet.
    IfPresent,
}

/// Recursive ECS runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecursiveEcsRuntimeConfig {
    pub policy: RecursiveEcsPolicyRuntime,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub include_scope_in_response: bool,
}

/// Recursive resolver runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveRuntimeConfig {
    pub enabled: bool,
    /// Parsed recursive listener socket. Never a wildcard address: the
    /// open-resolver guard is enforced during conversion.
    pub bind_address: SocketAddr,
    pub upstream: RecursiveUpstreamRuntime,
    pub cache: RecursiveCacheRuntimeConfig,
    /// Only meaningful for [`RecursiveUpstreamRuntime::Recursive`]; forwarder
    /// modes never perform local DNSSEC validation and must not claim to.
    pub dnssec_validation: bool,
    pub qname_minimization: bool,
    pub query_timeout: Duration,
    pub max_concurrent_queries: usize,
    pub rate_limit: DnsRateLimitRuntimeConfig,
    pub firewall: DnsFirewallRuntimeConfig,
    pub client_acl: Option<RecursiveClientAclRuntime>,
    pub max_cname_depth: u8,
    pub max_recursion_depth: u8,
    pub max_per_client_queries: u32,
    pub circuit_breaker: CircuitBreakerRuntimeConfig,
    pub ecs: RecursiveEcsRuntimeConfig,
    /// `true` when the selected upstream mode performs local DNSSEC
    /// validation. Used to keep the "forwarder does not validate" warning
    /// truthful without re-deriving the mode.
    pub performs_local_dnssec_validation: bool,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// DNS-owned Unix-time helper (Phase 129 Workstream A).
///
/// Returns `0` for pre-epoch clocks instead of panicking, and installs no
/// global clock singleton.
///
/// Phase 129 replaces the `synvoid_core::time` call sites with this helper.
#[allow(dead_code)]
pub(crate) fn dns_unix_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// DNS-owned IPv4 prefix mask (Phase 129 Workstream C).
///
/// `/0` yields `0`; out-of-range lengths are clamped instead of shifting by
/// the full word width (which would panic).
///
/// Phase 129 replaces the `synvoid_core::net::ipv4_prefix_mask` call sites
/// with this helper.
#[allow(dead_code)]
pub(crate) fn dns_ipv4_prefix_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        1..=32 => u32::MAX << (32 - u32::from(prefix)),
        _ => 0,
    }
}

/// Private helper used by the conversion path to normalize an IPv4 literal
/// into a `SocketAddr`-ready form. Kept private to this module so the public
/// runtime API stays small.
#[allow(dead_code)]
pub(crate) fn socket_addr_v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::from((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_network_contains_matches_cidr_semantics() {
        let net = IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 0))));

        let v6 = IpNetwork::new(IpAddr::V6("fc00::".parse().unwrap()), 7);
        assert!(v6.contains(IpAddr::V6("fdff::1".parse().unwrap())));
        assert!(!v6.contains(IpAddr::V6("fe00::1".parse().unwrap())));

        // IPv4 network never matches an IPv6 candidate.
        assert!(!net.contains(IpAddr::V6("::1".parse().unwrap())));
    }

    #[test]
    fn ip_network_zero_prefix_matches_everything_of_the_same_family() {
        let v4 = IpNetwork::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0);
        assert!(v4.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));
        let v6 = IpNetwork::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 0);
        assert!(v6.contains(IpAddr::V6("fe80::1".parse().unwrap())));
    }

    #[test]
    fn ipv4_prefix_mask_edges() {
        assert_eq!(dns_ipv4_prefix_mask(0), 0);
        assert_eq!(dns_ipv4_prefix_mask(32), u32::MAX);
        assert_eq!(dns_ipv4_prefix_mask(31), 0xFFFF_FFFE);
        // Out-of-range must not panic and must clamp to "no bits".
        assert_eq!(dns_ipv4_prefix_mask(33), 0);
        assert_eq!(dns_ipv4_prefix_mask(255), 0);
    }

    #[test]
    fn unix_timestamp_is_not_panicking() {
        assert!(dns_unix_timestamp_secs() > 1_600_000_000);
    }

    #[test]
    fn recursive_acl_preserves_persisted_semantics() {
        let empty = RecursiveClientAclRuntime {
            allowed_clients: Vec::new(),
            action: RecursiveAclActionRuntime::Reject,
        };
        assert!(empty.is_client_allowed(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))));

        let restricted = RecursiveClientAclRuntime {
            allowed_clients: vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)],
            action: RecursiveAclActionRuntime::Reject,
        };
        assert!(restricted.is_client_allowed(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!restricted.is_client_allowed(IpAddr::V4(Ipv4Addr::new(11, 1, 2, 3))));

        let allow_fallback = RecursiveClientAclRuntime {
            allowed_clients: vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)],
            action: RecursiveAclActionRuntime::Allow,
        };
        assert!(allow_fallback.is_client_allowed(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))));
    }

    #[test]
    fn tsig_key_debug_redacts_secret() {
        let key = TsigRuntimeKey {
            name: "k.".to_string(),
            secret: vec![0xAB; 32],
            algorithm: TsigAlgorithmRuntime::HmacSha256,
        };
        let rendered = format!("{key:?}");
        assert!(
            !rendered.contains("171"),
            "debug output must not contain secret bytes"
        );
        assert!(rendered.contains("redacted"));
    }
}
