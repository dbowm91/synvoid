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
//! Two fixtures still need persisted shapes, because Phases 127/128 own them:
//! [`deferred_config`] (recursive/DNSSEC/zones) and [`recursive_persisted`].
//! Those are clearly named so the residual edge stays visible.

use std::net::SocketAddr;
use std::time::Duration;

use synvoid_dns::runtime_config::{
    AnycastRuntimeConfig, AuthoritativeRuntimeConfig, CacheRuntimeConfig, DeferredDnsConfig,
    DnsRateLimitModeRuntime, DnsRateLimitRuntimeConfig, DohRuntimeConfig, DoqRuntimeConfig,
    DotRuntimeConfig, DynamicUpdateRuntimeConfig, EcsRuntimeConfig, LimitsRuntimeConfig,
    QueryCoalescingRuntimeConfig, RrlRuntimeConfig, ZoneTransferRuntimeConfig,
};

/// Serde default for `dns.firewall.max_rules`. See the Phase 125 closeout
/// finding F-1: the derived Rust `Default` disagrees with the serde default.
pub const FIREWALL_MAX_RULES_SERDE_DEFAULT: usize = 1000;

fn firewall() -> synvoid_config::dns::DnsFirewallConfig {
    synvoid_config::dns::DnsFirewallConfig {
        max_rules: FIREWALL_MAX_RULES_SERDE_DEFAULT,
        ..Default::default()
    }
}

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

/// Persisted sections still owned by Phases 127/128, with defaults.
///
/// Delete this fixture (and `DeferredDnsConfig`) in Phase 128.
pub fn deferred_config() -> DeferredDnsConfig {
    DeferredDnsConfig {
        recursive: synvoid_config::dns::RecursiveDnsConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 0,
            ..Default::default()
        },
        dnssec: synvoid_config::dns::DnsSecConfig::default(),
        zones: synvoid_config::dns::DnsZonesConfig::default(),
    }
}

/// Deferred fixture with DNSSEC signing requested, for key-manager tests.
pub fn deferred_dnssec_enabled(key_path: std::path::PathBuf, domain: &str) -> DeferredDnsConfig {
    let mut deferred = deferred_config();
    deferred.dnssec = synvoid_config::dns::DnsSecConfig {
        enabled: true,
        key_path: key_path.to_string_lossy().to_string(),
        domain: domain.to_string(),
        ..Default::default()
    };
    deferred
}

/// Deferred fixture with the recursive subsystem requested.
///
/// Phase 127 converts this to a DNS-owned runtime type; keeping it persisted
/// here is what makes that phase's residual edge explicit.
pub fn deferred_recursive_enabled(port: u16) -> DeferredDnsConfig {
    let mut deferred = deferred_config();
    deferred.recursive = synvoid_config::dns::RecursiveDnsConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port,
        ..Default::default()
    };
    deferred
}

/// Persisted recursive config for tests that drive
/// `RecursiveDnsServer` directly (Phase 127 converts this too).
pub fn recursive_persisted(port: u16) -> synvoid_config::dns::RecursiveDnsConfig {
    synvoid_config::dns::RecursiveDnsConfig {
        bind_address: "127.0.0.1".to_string(),
        port,
        ..Default::default()
    }
}

/// Persisted firewall config that passes the Phase 45 fail-closed contract.
pub fn firewall_persisted() -> synvoid_config::dns::DnsFirewallConfig {
    firewall()
}
