// Each test binary compiles this module but uses only part of it.
#![allow(dead_code)]

//! DNS-owned runtime configuration fixtures (Phase 126+).
//!
//! After the Phase 126 cutover, `DnsServer::new` takes
//! [`AuthoritativeRuntimeConfig`] and [`DeferredDnsConfig`] — never a
//! persistence DTO. These builders let tests exercise DNS runtime behavior
//! without importing `synvoid-config` just to configure a server.
//!
//! Defaults mirror `synvoid_config::dns::DnsConfig::default()` for every value
//! the authoritative runtime reads, so a fixture with no overrides behaves
//! like a default server. Override exactly the group a test is about.
//!
//! Phase 128 removed the last persisted-shape fixture: this crate no longer
//! links `synvoid-config` at all. Every fixture here is a DNS-owned runtime
//! value.

use std::net::SocketAddr;
use std::time::Duration;

use synvoid_dns::runtime_config::{
    AnycastRuntimeConfig, AuthoritativeRuntimeConfig, CacheRuntimeConfig,
    CircuitBreakerRuntimeConfig, CustomUpstreamEndpoint, DnsFirewallRuntimeConfig,
    DnsRateLimitModeRuntime, DnsRateLimitRuntimeConfig, DnssecRuntimeConfig, DohRuntimeConfig,
    DoqRuntimeConfig, DotRuntimeConfig, DynamicUpdateRuntimeConfig, EcsRuntimeConfig,
    LimitsRuntimeConfig, QueryCoalescingRuntimeConfig, RecursiveCacheRuntimeConfig,
    RecursiveClientAclRuntime, RecursiveEcsPolicyRuntime, RecursiveEcsRuntimeConfig,
    RecursiveRuntimeConfig, RecursiveUpstreamRuntime, RrlRuntimeConfig, ZoneTransferRuntimeConfig,
};

/// Default authoritative runtime configuration, matching
/// `DnsConfig::default()` for every authoritative group.
///
/// Binds `127.0.0.1:0` so a fixture never collides with a real listener; tests
/// that need a concrete port override [`AuthoritativeRuntimeBuilder::port`].
pub fn authoritative_runtime() -> AuthoritativeRuntimeConfig {
    AuthoritativeRuntimeConfig {
        bind_address: SocketAddr::from(([127, 0, 0, 1], 0)),
        ttl: synvoid_dns::runtime_config::TtlRuntimeConfig {
            default_ttl: 300,
            min_geo_ttl: 60,
            negative_cache_ttl: 300,
        },
        cache: CacheRuntimeConfig {
            enabled: true,
            capacity: 10_000,
            max_ttl: Duration::from_secs(3600),
            min_ttl: Duration::from_secs(0),
            serve_stale: None,
        },
        limits: LimitsRuntimeConfig {
            max_tcp_connections: 100,
            max_concurrent_queries: 1000,
            max_query_size: 65_535,
            max_response_size: 65_535,
            max_records_per_response: 100,
            max_tcp_idle_time: Duration::from_secs(30),
            max_tcp_query_time: Duration::from_secs(10),
            enable_graceful_degradation: false,
            udp_buffer_size: 65_535,
        },
        rate_limit: DnsRateLimitRuntimeConfig {
            mode: DnsRateLimitModeRuntime::Shared,
            per_second: 100,
        },
        rrl: RrlRuntimeConfig { enabled: false },
        firewall: synvoid_dns::runtime_config::DnsFirewallRuntimeConfig {
            enabled: false,
            block_internal_ips: true,
            block_zone_transfers: true,
        },
        ecs: EcsRuntimeConfig {
            enabled: false,
            prefix_v4: 24,
            prefix_v6: 48,
            allow_private_prefix: false,
        },
        query_coalescing: QueryCoalescingRuntimeConfig {
            enabled: false,
            max_wait: Duration::from_millis(5),
            max_entries: 1_000,
            entry_ttl: Duration::from_secs(30),
            cleanup_interval: Duration::from_secs(60),
        },
        dns64: None,
        dot: disabled_dot(),
        doh: disabled_doh(),
        doq: disabled_doq(),
        dynamic_update: DynamicUpdateRuntimeConfig {
            enabled: false,
            allow_any: true,
            require_tsig: false,
            max_update_size: 65_535,
        },
        zone_transfer: ZoneTransferRuntimeConfig {
            allow_transfer: Vec::new(),
            allow_wildcard_transfer: false,
            wildcard_transfer_requires_tsig: true,
            ixfr_enabled: true,
            ixfr_fallback_to_axfr: true,
            require_tsig: false,
        },
        anycast: AnycastRuntimeConfig { enabled: false },
    }
}

fn bind(port: u16) -> Option<SocketAddr> {
    Some(SocketAddr::from(([127, 0, 0, 1], port)))
}

/// Bind a bare IP literal, matching the adapter's IPv6-friendly parsing.
pub fn bind_address(address: &str, port: u16) -> Option<SocketAddr> {
    synvoid_dns::runtime_config::parse_bind_address(address, port)
}

pub fn disabled_dot() -> DotRuntimeConfig {
    DotRuntimeConfig {
        enabled: false,
        bind_address: None,
    }
}

pub fn disabled_doh() -> DohRuntimeConfig {
    DohRuntimeConfig {
        enabled: false,
        bind_address: None,
    }
}

pub fn disabled_doq() -> DoqRuntimeConfig {
    DoqRuntimeConfig {
        enabled: false,
        bind_address: None,
        max_concurrent_streams: 100,
        idle_timeout: Duration::from_secs(30),
    }
}

pub fn dot_on(port: u16) -> DotRuntimeConfig {
    DotRuntimeConfig {
        enabled: true,
        bind_address: bind(port),
    }
}

pub fn doh_on(port: u16) -> DohRuntimeConfig {
    DohRuntimeConfig {
        enabled: true,
        bind_address: bind(port),
    }
}

pub fn doq_on(port: u16) -> DoqRuntimeConfig {
    DoqRuntimeConfig {
        enabled: true,
        bind_address: bind(port),
        max_concurrent_streams: 100,
        idle_timeout: Duration::from_secs(30),
    }
}

/// Fluent overrides over [`authoritative_runtime`].
#[derive(Debug, Clone)]
pub struct AuthoritativeRuntimeBuilder {
    config: AuthoritativeRuntimeConfig,
}

impl Default for AuthoritativeRuntimeBuilder {
    fn default() -> Self {
        Self {
            config: authoritative_runtime(),
        }
    }
}

impl AuthoritativeRuntimeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the authoritative bind port. A non-zero port keeps
    /// `configured_bind_addr` fail-fast happy for tests that assert on it.
    pub fn port(mut self, port: u16) -> Self {
        self.config.bind_address = SocketAddr::from(([127, 0, 0, 1], port));
        self
    }

    pub fn cache_enabled(mut self, enabled: bool) -> Self {
        self.config.cache.enabled = enabled;
        self
    }

    pub fn serve_stale(mut self, enabled: bool) -> Self {
        self.config.cache.serve_stale =
            enabled.then_some(synvoid_dns::runtime_config::ServeStaleRuntimeConfig {
                max_stale: Duration::from_secs(30),
                max_stale_count: 10,
            });
        self
    }

    pub fn default_ttl(mut self, ttl: u32) -> Self {
        self.config.ttl.default_ttl = ttl;
        self
    }

    pub fn min_geo_ttl(mut self, ttl: u32) -> Self {
        self.config.ttl.min_geo_ttl = ttl;
        self
    }

    pub fn negative_cache_ttl(mut self, ttl: u32) -> Self {
        self.config.ttl.negative_cache_ttl = ttl;
        self
    }

    /// Dedicated rate limiter (the default fixture uses the shared one).
    pub fn dedicated_rate_limit(mut self, per_second: u64) -> Self {
        self.config.rate_limit = DnsRateLimitRuntimeConfig {
            mode: DnsRateLimitModeRuntime::Dedicated,
            per_second,
        };
        self
    }

    pub fn rrl(mut self, enabled: bool) -> Self {
        self.config.rrl.enabled = enabled;
        self
    }

    pub fn firewall(mut self, enabled: bool) -> Self {
        self.config.firewall.enabled = enabled;
        self
    }

    pub fn ecs(mut self, enabled: bool) -> Self {
        self.config.ecs.enabled = enabled;
        self
    }

    pub fn query_coalescing(mut self, enabled: bool) -> Self {
        self.config.query_coalescing.enabled = enabled;
        self
    }

    pub fn dns64(mut self, prefix: std::net::Ipv6Addr) -> Self {
        self.config.dns64 = Some(synvoid_dns::runtime_config::Dns64RuntimeConfig {
            prefix,
            exclude_aaaa_synthesis: false,
        });
        self
    }

    pub fn dot(mut self, port: u16) -> Self {
        self.config.dot = dot_on(port);
        self
    }

    pub fn doh(mut self, port: u16) -> Self {
        self.config.doh = doh_on(port);
        self
    }

    pub fn doq(mut self, port: u16) -> Self {
        self.config.doq = doq_on(port);
        self
    }

    pub fn update_enabled(mut self, enabled: bool) -> Self {
        self.config.dynamic_update.enabled = enabled;
        self
    }

    pub fn ixfr(mut self, enabled: bool) -> Self {
        self.config.zone_transfer.ixfr_enabled = enabled;
        self
    }

    pub fn require_tsig(mut self, required: bool) -> Self {
        self.config.zone_transfer.require_tsig = required;
        self
    }

    /// Enable the AXFR allowlist (fail-closed in persisted config today, so
    /// tests set it directly on the runtime value).
    pub fn allow_transfer(mut self, networks: &[synvoid_dns::runtime_config::IpNetwork]) -> Self {
        self.config.zone_transfer.allow_transfer = networks.to_vec();
        self
    }

    pub fn build(self) -> AuthoritativeRuntimeConfig {
        self.config
    }
}

/// Recursive runtime for a loopback bind.
///
/// Mirrors `RecursiveDnsConfig::default()` for every value the recursive
/// runtime reads, so a fixture with no overrides behaves like a default
/// recursive server.
pub fn recursive_runtime() -> RecursiveRuntimeConfig {
    RecursiveRuntimeConfig {
        enabled: true,
        bind_address: SocketAddr::from(([127, 0, 0, 1], 0)),
        upstream: RecursiveUpstreamRuntime::System,
        cache: RecursiveCacheRuntimeConfig {
            capacity: 1_000_000,
            negative_ttl: Duration::from_secs(300),
            stale_ttl: Duration::from_secs(86_400),
            max_ttl: Duration::from_secs(86_400),
            min_ttl: Duration::from_secs(0),
        },
        dnssec_validation: true,
        qname_minimization: true,
        query_timeout: Duration::from_secs(5),
        max_concurrent_queries: 10_000,
        rate_limit: DnsRateLimitRuntimeConfig {
            mode: DnsRateLimitModeRuntime::Shared,
            per_second: 100,
        },
        firewall: DnsFirewallRuntimeConfig {
            enabled: false,
            block_internal_ips: true,
            block_zone_transfers: true,
        },
        client_acl: None,
        max_cname_depth: 10,
        max_recursion_depth: 16,
        max_per_client_queries: 100,
        circuit_breaker: CircuitBreakerRuntimeConfig {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(30),
            success_threshold: 2,
        },
        ecs: RecursiveEcsRuntimeConfig {
            policy: RecursiveEcsPolicyRuntime::Never,
            prefix_v4: 24,
            prefix_v6: 56,
            include_scope_in_response: false,
        },
        performs_local_dnssec_validation: false,
    }
}

/// Recursive runtime with a concrete loopback port.
pub fn recursive_runtime_on(port: u16) -> RecursiveRuntimeConfig {
    RecursiveRuntimeConfig {
        bind_address: SocketAddr::from(([127, 0, 0, 1], port)),
        ..recursive_runtime()
    }
}

/// Recursive runtime with the recursive subsystem disabled.
pub fn recursive_disabled() -> RecursiveRuntimeConfig {
    RecursiveRuntimeConfig {
        enabled: false,
        ..recursive_runtime()
    }
}

/// Recursive runtime with an explicit parsed client ACL.
pub fn recursive_with_acl(
    allowed: Vec<synvoid_dns::runtime_config::IpNetwork>,
    action: synvoid_dns::runtime_config::RecursiveAclActionRuntime,
) -> RecursiveRuntimeConfig {
    RecursiveRuntimeConfig {
        client_acl: Some(RecursiveClientAclRuntime {
            allowed_clients: allowed,
            action,
        }),
        ..recursive_runtime()
    }
}

/// Recursive runtime with custom literal upstream endpoints.
pub fn recursive_with_upstreams(endpoints: Vec<CustomUpstreamEndpoint>) -> RecursiveRuntimeConfig {
    RecursiveRuntimeConfig {
        upstream: RecursiveUpstreamRuntime::CustomEndpoints(endpoints),
        ..recursive_runtime()
    }
}

/// Recursive cache runtime with overrides.
pub fn recursive_cache_runtime(
    capacity: usize,
    negative_ttl_secs: u64,
    stale_ttl_secs: u64,
    max_ttl_secs: u64,
    min_ttl_secs: u64,
) -> RecursiveCacheRuntimeConfig {
    RecursiveCacheRuntimeConfig {
        capacity,
        negative_ttl: Duration::from_secs(negative_ttl_secs),
        stale_ttl: Duration::from_secs(stale_ttl_secs),
        max_ttl: Duration::from_secs(max_ttl_secs),
        min_ttl: Duration::from_secs(min_ttl_secs),
    }
}

/// Circuit-breaker runtime with overrides.
pub fn circuit_breaker_runtime(
    failure_threshold: u32,
    success_threshold: u32,
    recovery_timeout_secs: u64,
) -> CircuitBreakerRuntimeConfig {
    CircuitBreakerRuntimeConfig {
        failure_threshold,
        success_threshold,
        recovery_timeout: Duration::from_secs(recovery_timeout_secs),
    }
}

/// Default DNSSEC runtime (signing disabled).
pub fn dnssec_runtime() -> DnssecRuntimeConfig {
    DnssecRuntimeConfig {
        enabled: false,
        domain: "example.com".to_string(),
        key_path: std::path::PathBuf::from("/var/lib/synvoid/dns/keys"),
        algorithm: synvoid_dns::runtime_config::DnssecAlgorithmRuntime::Ed25519,
        key_type: synvoid_dns::runtime_config::DnssecKeyTypeRuntime::Ksk,
        rsa_key_size: 2048,
        ksk_key_size: 2048,
        rollover_interval: Duration::from_secs(90 * 86_400),
        denial: synvoid_dns::runtime_config::DnssecDenialPolicyRuntime {
            nsec_enabled: true,
            nsec3_enabled: false,
            nsec3_iterations: 5,
            nsec3_algorithm: 1,
        },
        hsm: synvoid_dns::runtime_config::HsmRuntimeConfig::default(),
    }
}

/// DNSSEC runtime with signing requested, for key-manager tests.
pub fn dnssec_enabled_runtime(key_path: std::path::PathBuf, domain: &str) -> DnssecRuntimeConfig {
    DnssecRuntimeConfig {
        enabled: true,
        key_path,
        domain: domain.to_string(),
        ..dnssec_runtime()
    }
}

/// A full DNS runtime, the canonical `DnsServer::new` input.
pub fn dns_runtime() -> synvoid_dns::runtime_config::DnsRuntimeConfig {
    synvoid_dns::runtime_config::DnsRuntimeConfig {
        enabled: true,
        authoritative: authoritative_runtime(),
        dnssec: dnssec_runtime(),
        zones: Vec::new(),
        tsig_keys: Vec::new(),
        recursive: recursive_runtime(),
    }
}

/// Ask the OS for an ephemeral loopback UDP port and report the number.
///
/// **This is a prediction, not a reservation.** The socket is released before
/// this function returns, so the port may already be taken by the time a
/// caller binds it. Code that actually starts a listener must use
/// [`start_bound_dns_server`], which verifies the bind instead of trusting
/// this number.
///
/// The prediction is still useful as a starting point, and it is correct for
/// callers that never bind at all (for example a test asserting that startup
/// fails validation before any listener is created).
pub fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

/// `DnsServer::start` prefix for a failed authoritative UDP bind.
pub(crate) const BIND_UDP_PREFIX: &str = "Failed to bind DNS UDP socket:";

/// `DnsServer::start` prefix for a failed authoritative TCP bind.
pub(crate) const BIND_TCP_PREFIX: &str = "Failed to bind DNS TCP socket:";

/// `std::io::Error`'s `AddrInUse` display, on every supported platform:
/// "Address already in use (os error N)".
const ADDR_IN_USE_TEXT: &str = "in use";

/// Attempts allowed before a test reports that it could not win a loopback
/// port. Each attempt asks the OS for a fresh ephemeral port, so eight
/// attempts means eight genuinely different numbers, not one number retried.
const BIND_ATTEMPTS: usize = 8;

/// True when a `DnsServer::start` failure is a lost bind race rather than a
/// real configuration or runtime error.
///
/// `DnsServer::start` reports bind failures as
/// `"Failed to bind DNS {UDP,TCP} socket: {io_error}"`, so a port conflict is
/// the only failure that both carries one of those two prefixes and mentions
/// `AddrInUse`. Every other failure — zero port, unparseable bind address,
/// anycast rejection, recursive init failure — must propagate so a real error
/// is never masked by a retry.
pub(crate) fn is_bind_conflict(message: &str) -> bool {
    let is_bind_failure =
        message.starts_with(BIND_UDP_PREFIX) || message.starts_with(BIND_TCP_PREFIX);
    is_bind_failure && message.contains(ADDR_IN_USE_TEXT)
}

/// A started `DnsServer` together with the loopback port it actually holds.
pub struct BoundServer {
    /// The running server. Call `shutdown_runtime()` when the test is done.
    pub server: synvoid_dns::server::DnsServer,
    /// The port the server is listening on. Dial this, not a predicted one.
    pub port: u16,
}

/// Start a `DnsServer` on a loopback ephemeral port without assuming any port
/// is free.
///
/// `DnsServer::start` binds the authoritative UDP *and* TCP sockets itself, so
/// a held reservation cannot protect the port — releasing it to let the server
/// bind is exactly the race that made the DNS conformance lane intermittently
/// red (Phase 130 F-3). Instead this helper removes the assumption:
///
/// 1. ask the OS for a candidate port ([`free_port`]);
/// 2. let the server perform the real bind;
/// 3. if that bind lost a race with another process, take a new candidate.
///
/// Nothing sleeps, and a conflict is distinguished from a genuine startup error,
/// so a failing test still fails for its own reason. `configure` adjusts the
/// runtime before the bind and is re-applied to every attempt, because the
/// candidate port differs per attempt.
pub async fn start_bound_dns_server<F>(mut configure: F) -> BoundServer
where
    F: FnMut(&mut synvoid_dns::runtime_config::DnsRuntimeConfig),
{
    let mut last_conflict = String::new();

    for _ in 0..BIND_ATTEMPTS {
        let port = free_port();
        let mut runtime = dns_runtime_on(port);
        configure(&mut runtime);

        let mut server = synvoid_dns::server::DnsServer::new(runtime, None, None);
        match server.start().await {
            Ok(()) => {
                return BoundServer { server, port };
            }
            Err(error) if is_bind_conflict(&error) => {
                // Another process owns this port. Nothing was spawned, so the
                // partially bound socket is already closed; take a new one.
                last_conflict = error;
            }
            Err(error) => panic!("DNS server start failed: {error}"),
        }
    }

    panic!(
        "DNS server could not bind a loopback port in {BIND_ATTEMPTS} attempts: {last_conflict}"
    );
}

/// A non-zero authoritative port for tests that never bind a listener.
///
/// `DnsServer::start` rejects port 0 and a server that is never started never
/// binds, so predicting an ephemeral port for such a test buys nothing and
/// reintroduces the assumption Phase 131 removed. 59999 is in the dynamic range
/// and is used only as a value the server must not act on.
pub const UNBOUND_TEST_PORT: u16 = 59999;

/// A whole-DNS runtime bound to a concrete loopback port, for tests that call
/// `DnsServer::start` and then dial the server.
pub fn dns_runtime_on(port: u16) -> synvoid_dns::runtime_config::DnsRuntimeConfig {
    let mut runtime = dns_runtime();
    runtime.authoritative.bind_address = SocketAddr::from(([127, 0, 0, 1], port));
    runtime
}

/// A TSIG runtime key with a 32-byte HMAC-SHA256 secret.
pub fn tsig_key(name: &str) -> synvoid_dns::runtime_config::TsigRuntimeKey {
    synvoid_dns::runtime_config::TsigRuntimeKey {
        name: name.to_string(),
        secret: vec![0x11; 32],
        algorithm: synvoid_dns::runtime_config::TsigAlgorithmRuntime::HmacSha256,
    }
}

/// One zone runtime spec with a single apex SOA record.
pub fn zone_spec(origin: &str) -> synvoid_dns::runtime_config::ZoneSpec {
    synvoid_dns::runtime_config::ZoneSpec {
        origin: origin.to_string(),
        records: vec![synvoid_dns::runtime_config::ZoneRecordSpec {
            name: origin.to_string(),
            record_type: synvoid_dns::runtime_config::RecordType::SOA,
            ttl: Some(300),
            value: format!("ns1.{origin}. admin.{origin}. 1 7200 3600 604800 300"),
            priority: None,
        }],
        dnssec: None,
    }
}
