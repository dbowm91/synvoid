//! Canonical persisted-DNS-config → DNS-runtime-config adapter (Phases 125–130).
//!
//! This module is the **single application-owned conversion path** from the
//! persisted `synvoid-config` DNS schema to the DNS-owned runtime vocabulary
//! in [`synvoid_dns::runtime_config`]. It lives in the composition root
//! (`src/server/`) because persisted schema is application policy, not
//! protocol logic.
//!
//! Invariants enforced here:
//!
//! 1. Conversion always runs [`synvoid_config::dns::DnsConfig::validate`]
//!    first, so typed config validation stays the operator-facing failure
//!    boundary.
//! 2. Invalid values are **rejected**, never clamped or defaulted. There is
//!    no silent fallback.
//! 3. Only implemented runtime behavior is mapped. Unsupported/deferred
//!    persisted fields are absent from the runtime DTO by design; the
//!    authoritative disposition lives in
//!    `architecture/dns_config_runtime_matrix.md`.
//! 4. HSM settings are built as keystore-owned
//!    [`synvoid_dnssec_keystore::HsmConfig`] values rather than projecting the
//!    persisted HSM schema into DNS.
//! 5. TSIG secrets are base64-decoded and length-checked here; conversion
//!    errors never carry secret material.
//!
//! `src/dns/` stays a pure re-export facade: no conversion logic belongs
//! there (`tests/dns_runtime_config_guard.rs` enforces this).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use synvoid_config::dns::{
    DnsConfig, DnsRecordEntry, DnsRecordType, DnsSecAlgorithm, DnsZoneEntry, EcsForwardingPolicy,
    HsmProvider, RecursiveClientAcl, RecursiveDnsConfig, RecursiveUpstreamProvider, TsigAlgorithm,
    TsigKeyConfig,
};
use synvoid_dns::runtime_config::{
    AnycastRuntimeConfig, AuthoritativeRuntimeConfig, CacheRuntimeConfig,
    CircuitBreakerRuntimeConfig, CustomUpstreamEndpoint, Dns64RuntimeConfig,
    DnsFirewallRuntimeConfig, DnsRateLimitModeRuntime, DnsRateLimitRuntimeConfig, DnsRuntimeConfig,
    DnssecAlgorithmRuntime, DnssecDenialPolicyRuntime, DnssecKeyTypeRuntime, DnssecRuntimeConfig,
    DohRuntimeConfig, DoqRuntimeConfig, DotRuntimeConfig, DynamicUpdateRuntimeConfig,
    EcsRuntimeConfig, HsmProviderRuntime, HsmRuntimeConfig, IpNetwork, LimitsRuntimeConfig,
    QueryCoalescingRuntimeConfig, RecordType, RecursiveAclActionRuntime,
    RecursiveCacheRuntimeConfig, RecursiveClientAclRuntime, RecursiveEcsPolicyRuntime,
    RecursiveEcsRuntimeConfig, RecursiveRuntimeConfig, RecursiveUpstreamRuntime, RrlRuntimeConfig,
    ServeStaleRuntimeConfig, TsigAlgorithmRuntime, TsigRuntimeKey, TtlRuntimeConfig,
    ZoneDnssecSpec, ZoneRecordSpec, ZoneSpec, ZoneTransferRuntimeConfig,
};
use synvoid_dns::runtime_config_deferred::DeferredDnsConfig;

/// Typed conversion failure. Every variant names the offending persisted
/// path so operators get an actionable message. None of them embed secret
/// material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRuntimeConversionError {
    /// Persisted config failed the canonical `DnsConfig::validate()` gate.
    InvalidPersistedConfig(String),
    /// A persisted value could not be parsed into its runtime type.
    InvalidValue { path: String, reason: String },
    /// A feature that remains unsupported was requested in an active form.
    Unsupported { path: String, reason: String },
}

impl std::fmt::Display for DnsRuntimeConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsRuntimeConversionError::InvalidPersistedConfig(reason) => {
                write!(f, "invalid DNS configuration: {reason}")
            }
            DnsRuntimeConversionError::InvalidValue { path, reason } => {
                write!(f, "invalid DNS configuration value at `{path}`: {reason}")
            }
            DnsRuntimeConversionError::Unsupported { path, reason } => {
                write!(f, "unsupported DNS configuration at `{path}`: {reason}")
            }
        }
    }
}

impl std::error::Error for DnsRuntimeConversionError {}

fn invalid(path: &str, reason: impl Into<String>) -> DnsRuntimeConversionError {
    DnsRuntimeConversionError::InvalidValue {
        path: path.to_string(),
        reason: reason.into(),
    }
}

type Result<T> = std::result::Result<T, DnsRuntimeConversionError>;

/// Convert already-loaded persisted DNS config into DNS-owned runtime values.
///
/// Runs [`DnsConfig::validate()`] first, then projects only implemented
/// behavior. Never clamps, defaults, or silently drops an invalid value.
pub fn dns_runtime_config_from_persisted(config: &DnsConfig) -> Result<DnsRuntimeConfig> {
    // Typed config validation stays the operator-facing failure boundary.
    // Phase 45's fail-closed `Unsupported` rejections keep their typed config
    // path so the message names the exact setting to change.
    if let Err(e) = config.validate() {
        return Err(match e {
            synvoid_config::dns::DnsConfigError::Unsupported { path, reason } => {
                DnsRuntimeConversionError::Unsupported { path, reason }
            }
            other => DnsRuntimeConversionError::InvalidPersistedConfig(other.to_string()),
        });
    }

    let bind_address = parse_bind("dns.bind_address", &config.bind_address, config.port)?;

    let mut dnssec = dnssec_runtime(&config.dnssec)?;

    // HSM settings are constructed keystore-owned so the persisted HSM schema
    // never enters the DNS crate. Establishment stays fail-closed: an enabled
    // HSM must have a library path and, when a hardware token is required, a
    // PIN.
    dnssec.hsm = hsm_runtime(&config.dnssec.hsm)?;

    let authoritative = AuthoritativeRuntimeConfig {
        bind_address,
        ttl: TtlRuntimeConfig {
            default_ttl: config.settings.default_ttl,
            min_geo_ttl: config.settings.min_geo_ttl,
            negative_cache_ttl: config.settings.negative_cache_ttl,
        },
        cache: cache_runtime(&config.settings),
        limits: limits_runtime(&config.limits)?,
        rate_limit: rate_limit_runtime(&config.ratelimit),
        rrl: RrlRuntimeConfig {
            enabled: config.rrl.enabled,
        },
        firewall: firewall_runtime(&config.firewall),
        ecs: EcsRuntimeConfig {
            enabled: config.settings.ecs_filtering.enabled,
            prefix_v4: config.settings.ecs_filtering.prefix_v4,
            prefix_v6: config.settings.ecs_filtering.prefix_v6,
            allow_private_prefix: config.settings.ecs_filtering.allow_private_prefix,
        },
        query_coalescing: QueryCoalescingRuntimeConfig {
            enabled: config.settings.query_coalescing.enabled,
            max_wait: Duration::from_millis(config.settings.query_coalescing.max_wait_ms),
            max_entries: config.settings.query_coalescing.max_entries,
            entry_ttl: Duration::from_secs(config.settings.query_coalescing.entry_ttl_secs),
            cleanup_interval: Duration::from_secs(
                config.settings.query_coalescing.cleanup_interval_secs,
            ),
        },
        dns64: dns64_runtime(&config.dns64)?,
        dot: dot_runtime(&config.dot)?,
        doh: doh_runtime(&config.doh)?,
        doq: doq_runtime(&config.doq)?,
        dynamic_update: dynamic_update_runtime(&config.settings),
        zone_transfer: zone_transfer_runtime(&config.settings)?,
        anycast: AnycastRuntimeConfig {
            enabled: config.anycast.enabled,
        },
    };

    Ok(DnsRuntimeConfig {
        enabled: config.enabled,
        authoritative,
        dnssec,
        zones: zone_specs(&config.zones.items)?,
        tsig_keys: tsig_keys(&config.dnssec.tsig_keys)?,
        recursive: recursive_runtime(&config.recursive)?,
    })
}

/// Phase 126 constructor input for `DnsServer`.
///
/// Produces the authoritative runtime values plus the deferred persisted
/// sections that Phases 127/128 still own. This is the only conversion entry
/// point production uses.
pub fn dns_server_runtime_config_from_persisted(
    config: &DnsConfig,
) -> Result<DnsServerRuntimeConfig> {
    let runtime = dns_runtime_config_from_persisted(config)?;
    Ok(DnsServerRuntimeConfig {
        authoritative: runtime.authoritative,
        deferred: DeferredDnsConfig {
            recursive: config.recursive.clone(),
            dnssec: config.dnssec.clone(),
            zones: config.zones.clone(),
        },
    })
}

/// Canonical Phase 126 `DnsServer` construction input.
#[derive(Debug, Clone)]
pub struct DnsServerRuntimeConfig {
    /// Authoritative server and encrypted-transport runtime values.
    pub authoritative: AuthoritativeRuntimeConfig,
    /// Recursive/DNSSEC/HSM/zone sections still owned by Phases 127/128.
    pub deferred: DeferredDnsConfig,
}

// ---------------------------------------------------------------------------
// Bind parsing
// ---------------------------------------------------------------------------

/// Parse a persisted `bind_address`/port pair into a socket address.
///
/// Mirrors `synvoid_config`'s wildcard allowance (`"0.0.0.0"` / `"::"` stay
/// valid) and keeps the explicit non-zero-port requirement.
fn parse_bind(path: &str, address: &str, port: u16) -> Result<SocketAddr> {
    if port == 0 {
        return Err(invalid(path, "port cannot be zero"));
    }
    let ip: IpAddr = address
        .parse()
        .map_err(|e| invalid(path, format!("'{address}' is not a valid IP address: {e}")))?;
    Ok(SocketAddr::from((ip, port)))
}

// ---------------------------------------------------------------------------
// Authoritative groups
// ---------------------------------------------------------------------------

fn cache_runtime(settings: &synvoid_config::dns::DnsSettingsConfig) -> CacheRuntimeConfig {
    let serve_stale = &settings.serve_stale;
    CacheRuntimeConfig {
        enabled: settings.cache_enabled,
        capacity: settings.cache_size,
        max_ttl: Duration::from_secs(settings.cache_max_ttl),
        min_ttl: Duration::from_secs(settings.cache_min_ttl),
        serve_stale: if serve_stale.enabled {
            Some(ServeStaleRuntimeConfig {
                max_stale: Duration::from_secs(serve_stale.max_stale_secs),
                max_stale_count: serve_stale.max_stale_count,
            })
        } else {
            None
        },
    }
}

fn limits_runtime(limits: &synvoid_config::dns::DnsLimitsConfig) -> Result<LimitsRuntimeConfig> {
    Ok(LimitsRuntimeConfig {
        max_tcp_connections: limits.max_tcp_connections,
        max_concurrent_queries: limits.max_concurrent_queries,
        max_query_size: limits.max_query_size,
        max_response_size: limits.max_response_size,
        max_records_per_response: limits.max_records_per_response,
        max_tcp_idle_time: Duration::from_secs(limits.max_tcp_idle_time_secs),
        max_tcp_query_time: Duration::from_secs(limits.max_tcp_query_time_secs),
        enable_graceful_degradation: limits.enable_graceful_degradation,
        udp_buffer_size: limits.udp_buffer_size,
    })
}

fn rate_limit_runtime(
    rate_limit: &synvoid_config::dns::DnsRateLimitConfig,
) -> DnsRateLimitRuntimeConfig {
    DnsRateLimitRuntimeConfig {
        mode: match rate_limit.mode {
            synvoid_config::dns::DnsRateLimitMode::Shared => DnsRateLimitModeRuntime::Shared,
            synvoid_config::dns::DnsRateLimitMode::Dedicated => DnsRateLimitModeRuntime::Dedicated,
        },
        per_second: rate_limit.per_second,
    }
}

/// Project only the implemented firewall controls.
///
/// `default_action`, `max_rules`, and the rebinding-protection block have no
/// firewall consumer and are absent by design.
fn firewall_runtime(firewall: &synvoid_config::dns::DnsFirewallConfig) -> DnsFirewallRuntimeConfig {
    DnsFirewallRuntimeConfig {
        enabled: firewall.enabled,
        block_internal_ips: firewall.block_internal_ips,
        block_zone_transfers: firewall.block_zone_transfers,
    }
}

/// Project DNS64, rejecting an unparseable prefix instead of warning and
/// silently substituting the well-known prefix.
fn dns64_runtime(dns64: &synvoid_config::dns::Dns64Config) -> Result<Option<Dns64RuntimeConfig>> {
    if !dns64.enabled {
        return Ok(None);
    }
    let prefix = dns64.prefix.parse::<std::net::Ipv6Addr>().map_err(|e| {
        invalid(
            "dns.dns64.prefix",
            format!("'{}' is not an IPv6 address: {e}", dns64.prefix),
        )
    })?;
    Ok(Some(Dns64RuntimeConfig {
        prefix,
        exclude_aaaa_synthesis: dns64.exclude_aaaa_synthesis,
    }))
}

fn dynamic_update_runtime(
    settings: &synvoid_config::dns::DnsSettingsConfig,
) -> DynamicUpdateRuntimeConfig {
    DynamicUpdateRuntimeConfig {
        enabled: settings.dynamic_update.enabled,
        allow_any: settings.dynamic_update.allow_any,
        require_tsig: settings.dynamic_update.require_tsig,
        max_update_size: settings.dynamic_update.max_update_size,
    }
}

fn zone_transfer_runtime(
    settings: &synvoid_config::dns::DnsSettingsConfig,
) -> Result<ZoneTransferRuntimeConfig> {
    Ok(ZoneTransferRuntimeConfig {
        allow_transfer: parse_ip_list("dns.settings.allow_transfer", &settings.allow_transfer)?,
        allow_wildcard_transfer: settings.allow_wildcard_transfer,
        wildcard_transfer_requires_tsig: settings.wildcard_transfer_requires_tsig,
        ixfr_enabled: settings.ixfr_enabled,
        ixfr_fallback_to_axfr: settings.ixfr_fallback_to_axfr,
        require_tsig: settings.require_tsig,
    })
}

// ---------------------------------------------------------------------------
// Encrypted transports
// ---------------------------------------------------------------------------

/// A transport's bind address is a runtime input only when the transport is
/// enabled. A disabled transport carries `None` instead of a fabricated
/// socket, so `enabled == true` always implies a parsed, validated address.
fn transport_bind(
    path: &str,
    enabled: bool,
    address: &str,
    port: u16,
) -> Result<Option<SocketAddr>> {
    if !enabled {
        return Ok(None);
    }
    parse_bind(path, address, port).map(Some)
}

fn dot_runtime(dot: &synvoid_config::dns::DnsDotConfig) -> Result<DotRuntimeConfig> {
    Ok(DotRuntimeConfig {
        enabled: dot.enabled,
        bind_address: transport_bind(
            "dns.dot.bind_address",
            dot.enabled,
            &dot.bind_address,
            dot.port,
        )?,
    })
}

fn doh_runtime(doh: &synvoid_config::dns::DnsDohConfig) -> Result<DohRuntimeConfig> {
    Ok(DohRuntimeConfig {
        enabled: doh.enabled,
        bind_address: transport_bind(
            "dns.doh.bind_address",
            doh.enabled,
            &doh.bind_address,
            doh.port,
        )?,
    })
}

fn doq_runtime(doq: &synvoid_config::dns::DnsDoqConfig) -> Result<DoqRuntimeConfig> {
    Ok(DoqRuntimeConfig {
        enabled: doq.enabled,
        bind_address: transport_bind(
            "dns.doq.bind_address",
            doq.enabled,
            &doq.bind_address,
            doq.port,
        )?,
        max_concurrent_streams: doq.max_concurrent_streams,
        idle_timeout: Duration::from_secs(doq.idle_timeout_secs),
    })
}

// ---------------------------------------------------------------------------
// DNSSEC / HSM
// ---------------------------------------------------------------------------

fn dnssec_runtime(dnssec: &synvoid_config::dns::DnsSecConfig) -> Result<DnssecRuntimeConfig> {
    Ok(DnssecRuntimeConfig {
        enabled: dnssec.enabled,
        domain: dnssec.domain.clone(),
        key_path: PathBuf::from(&dnssec.key_path),
        algorithm: match dnssec.algorithm {
            DnsSecAlgorithm::Ed25519 => DnssecAlgorithmRuntime::Ed25519,
            DnsSecAlgorithm::RsaSha256 => DnssecAlgorithmRuntime::Rsa,
        },
        key_type: DnssecKeyTypeRuntime::Ksk,
        rsa_key_size: dnssec.rsa_key_size,
        ksk_key_size: dnssec.ksk_key_size,
        rollover_interval: Duration::from_secs(
            u64::from(dnssec.rollover_interval_days) * 24 * 60 * 60,
        ),
        denial: DnssecDenialPolicyRuntime {
            nsec_enabled: dnssec.nsec_enabled,
            nsec3_enabled: dnssec.nsec3_enabled,
            nsec3_iterations: dnssec.nsec3_iterations,
            nsec3_algorithm: dnssec.nsec3_algorithm,
        },
        hsm: HsmRuntimeConfig::default(),
    })
}

/// Build DNS-owned HSM runtime values from the persisted HSM section.
///
/// The persisted HSM schema never enters the DNS crate: only these
/// runtime-owned values cross the boundary, and the application adapter maps
/// them to [`synvoid_dnssec_keystore::HsmConfig`] when it constructs the
/// keystore. An enabled PKCS#11 HSM must name a module; establishment stays
/// fail-closed and there is deliberately no software fallback.
fn hsm_runtime(hsm: &synvoid_config::dns::HsmConfig) -> Result<HsmRuntimeConfig> {
    let provider = match hsm.provider {
        HsmProvider::Pkcs11 => HsmProviderRuntime::Pkcs11,
        HsmProvider::Soft => HsmProviderRuntime::Soft,
    };

    if !hsm.enabled {
        return Ok(HsmRuntimeConfig {
            enabled: false,
            provider,
            ..HsmRuntimeConfig::default()
        });
    }

    if provider == HsmProviderRuntime::Pkcs11 && hsm.module_path.trim().is_empty() {
        return Err(invalid(
            "dns.dnssec.hsm.module_path",
            "an enabled PKCS#11 HSM requires an explicit module path",
        ));
    }

    Ok(HsmRuntimeConfig {
        enabled: true,
        provider,
        module_path: hsm.module_path.clone(),
        slot_id: hsm.slot_id,
        // The PIN crosses into the keystore crate, which wraps it in a
        // zeroizing secret type. It is never logged or echoed in errors.
        pin: hsm.pin.clone(),
        key_label: hsm.key_label.clone(),
        key_id: hsm.key_id.as_ref().map(|id| id.as_bytes().to_vec()),
        // PKCS#11 selection requires hardware backing: establishment failures
        // fail closed rather than falling back to software keys.
        require_hsm: provider == HsmProviderRuntime::Pkcs11,
    })
}

// ---------------------------------------------------------------------------
// Zones
// ---------------------------------------------------------------------------

fn zone_specs(zones: &[DnsZoneEntry]) -> Result<Vec<ZoneSpec>> {
    zones.iter().map(zone_spec).collect()
}

fn zone_spec(zone: &DnsZoneEntry) -> Result<ZoneSpec> {
    Ok(ZoneSpec {
        origin: zone.zone.clone(),
        records: zone
            .records
            .iter()
            .map(zone_record_spec)
            .collect::<Result<Vec<_>>>()?,
        dnssec: zone.dnssec.as_ref().map(|dnssec| ZoneDnssecSpec {
            enabled: dnssec.enabled,
            nsec_enabled: dnssec.nsec_enabled,
            nsec3_enabled: dnssec.nsec3_enabled,
            nsec3_iterations: dnssec.nsec3_iterations,
        }),
    })
}

fn zone_record_spec(record: &DnsRecordEntry) -> Result<ZoneRecordSpec> {
    Ok(ZoneRecordSpec {
        name: record.name.clone(),
        record_type: record_type(record.record_type.clone())?,
        ttl: record.ttl,
        value: record.value.clone(),
        priority: record.priority,
    })
}

/// Map the persisted record-type enum onto Hickory's runtime `RecordType`.
///
/// Private-use and reserved codes are preserved numerically so the
/// authoritative loader's behavior is unchanged.
fn record_type(persisted: DnsRecordType) -> Result<RecordType> {
    Ok(match persisted {
        DnsRecordType::A => RecordType::A,
        DnsRecordType::Aaaa => RecordType::AAAA,
        DnsRecordType::CName => RecordType::CNAME,
        DnsRecordType::Mx => RecordType::MX,
        DnsRecordType::Txt => RecordType::TXT,
        DnsRecordType::Ns => RecordType::NS,
        DnsRecordType::Soa => RecordType::SOA,
        DnsRecordType::Srv => RecordType::SRV,
        DnsRecordType::Ptr => RecordType::PTR,
        DnsRecordType::Caa => RecordType::CAA,
        DnsRecordType::Tlsa => RecordType::TLSA,
        DnsRecordType::Svcb => RecordType::SVCB,
        DnsRecordType::Https => RecordType::HTTPS,
        DnsRecordType::Naptr => RecordType::NAPTR,
        DnsRecordType::Sshfp => RecordType::SSHFP,
        DnsRecordType::Uri => RecordType::from(256),
        DnsRecordType::Rp => RecordType::from(17),
        DnsRecordType::Afsdb => RecordType::from(18),
        DnsRecordType::Ds => RecordType::DS,
        DnsRecordType::Other => RecordType::NULL,
    })
}

// ---------------------------------------------------------------------------
// TSIG
// ---------------------------------------------------------------------------

/// Convert persisted TSIG keys into runtime keys.
///
/// Secrets are base64-decoded and length-checked here. Conversion errors
/// carry the key name and algorithm only, never secret bytes.
fn tsig_keys(keys: &[TsigKeyConfig]) -> Result<Vec<TsigRuntimeKey>> {
    keys.iter().map(tsig_key).collect()
}

fn tsig_key(key: &TsigKeyConfig) -> Result<TsigRuntimeKey> {
    let algorithm = match key.algorithm {
        TsigAlgorithm::HmacSha256 => TsigAlgorithmRuntime::HmacSha256,
        TsigAlgorithm::HmacSha384 => TsigAlgorithmRuntime::HmacSha384,
        TsigAlgorithm::HmacSha512 => TsigAlgorithmRuntime::HmacSha512,
    };

    let decoded = BASE64_STANDARD
        .decode(key.secret_base64.as_bytes())
        .map_err(|_| {
            invalid(
                "dns.dnssec.tsig_keys.secret",
                format!(
                    "TSIG key '{}' has a secret that is not valid base64",
                    key.name
                ),
            )
        })?;

    if decoded.len() < algorithm.min_secret_len() {
        return Err(invalid(
            "dns.dnssec.tsig_keys.secret",
            format!(
                "TSIG key '{}' decodes to {} bytes, below the {} byte minimum for {}",
                key.name,
                decoded.len(),
                algorithm.min_secret_len(),
                algorithm.as_str()
            ),
        ));
    }

    Ok(TsigRuntimeKey {
        name: key.name.clone(),
        secret: decoded,
        algorithm,
    })
}

// ---------------------------------------------------------------------------
// Recursive
// ---------------------------------------------------------------------------

fn recursive_runtime(config: &RecursiveDnsConfig) -> Result<RecursiveRuntimeConfig> {
    let upstream = recursive_upstream(config)?;
    let performs_local_dnssec_validation =
        matches!(upstream, RecursiveUpstreamRuntime::Recursive { .. });

    Ok(RecursiveRuntimeConfig {
        enabled: config.enabled,
        bind_address: parse_bind(
            "dns.recursive.bind_address",
            &config.bind_address,
            config.port,
        )?,
        upstream,
        cache: RecursiveCacheRuntimeConfig {
            capacity: config.cache.capacity,
            negative_ttl: Duration::from_secs(config.cache.negative_ttl_secs),
            stale_ttl: Duration::from_secs(config.cache.stale_ttl_secs),
            max_ttl: Duration::from_secs(config.cache.max_ttl_secs),
            min_ttl: Duration::from_secs(config.cache.min_ttl_secs),
        },
        dnssec_validation: config.dnssec_validation,
        qname_minimization: config.qname_minimization,
        query_timeout: Duration::from_secs(config.query_timeout_secs),
        max_concurrent_queries: config.max_concurrent_queries,
        rate_limit: rate_limit_runtime(&config.ratelimit),
        firewall: firewall_runtime(&config.firewall),
        client_acl: config.client_acl.as_ref().map(recursive_acl).transpose()?,
        max_cname_depth: config.max_cname_depth,
        max_recursion_depth: config.max_recursion_depth,
        max_per_client_queries: config.max_per_client_queries,
        circuit_breaker: CircuitBreakerRuntimeConfig {
            failure_threshold: config.circuit_breaker.failure_threshold,
            recovery_timeout: Duration::from_secs(config.circuit_breaker.recovery_timeout_secs),
            success_threshold: config.circuit_breaker.success_threshold,
        },
        ecs: RecursiveEcsRuntimeConfig {
            policy: match config.ecs.forwarding_policy {
                EcsForwardingPolicy::Never => RecursiveEcsPolicyRuntime::Never,
                EcsForwardingPolicy::Always => RecursiveEcsPolicyRuntime::Always,
                EcsForwardingPolicy::CdnOnly => RecursiveEcsPolicyRuntime::CdnOnly,
                EcsForwardingPolicy::IfPresent => RecursiveEcsPolicyRuntime::IfPresent,
            },
            prefix_v4: config.ecs.prefix_v4,
            prefix_v6: config.ecs.prefix_v6,
            include_scope_in_response: config.ecs.include_scope_in_response,
        },
        performs_local_dnssec_validation,
    })
}

/// Normalize the persisted upstream representation into an explicit runtime
/// strategy. A literal IP and a hostname stay distinguishable.
fn recursive_upstream(config: &RecursiveDnsConfig) -> Result<RecursiveUpstreamRuntime> {
    Ok(match config.upstream_provider {
        RecursiveUpstreamProvider::System => {
            if config.upstream_servers.is_empty() {
                RecursiveUpstreamRuntime::System
            } else {
                RecursiveUpstreamRuntime::CustomEndpoints(custom_endpoints(config)?)
            }
        }
        RecursiveUpstreamProvider::Custom => {
            RecursiveUpstreamRuntime::CustomEndpoints(custom_endpoints(config)?)
        }
        RecursiveUpstreamProvider::Google => RecursiveUpstreamRuntime::Google,
        RecursiveUpstreamProvider::Cloudflare => RecursiveUpstreamRuntime::Cloudflare,
        RecursiveUpstreamProvider::Recursive => RecursiveUpstreamRuntime::Recursive {
            root_hints: PathBuf::from(&config.root_hints_path),
            trust_anchor: PathBuf::from(&config.trust_anchor_path),
        },
        RecursiveUpstreamProvider::GlobalNodes => RecursiveUpstreamRuntime::GlobalNodes,
    })
}

fn custom_endpoints(config: &RecursiveDnsConfig) -> Result<Vec<CustomUpstreamEndpoint>> {
    config
        .upstream_servers
        .iter()
        .enumerate()
        .map(|(index, server)| {
            let path = format!("dns.recursive.upstream_servers[{index}]");
            if let Some(ip) = server.ip {
                return Ok(CustomUpstreamEndpoint::Literal {
                    ip,
                    port: server.port,
                });
            }
            if !server.address.is_empty() {
                return Ok(CustomUpstreamEndpoint::Hostname {
                    host: server.address.clone(),
                    port: server.port,
                });
            }
            Err(invalid(
                &path,
                "upstream server must define either an IP address or a hostname",
            ))
        })
        .collect()
}

/// Convert the recursive client ACL, parsing every CIDR up front so an
/// invalid entry cannot be discovered on the request path.
fn recursive_acl(acl: &RecursiveClientAcl) -> Result<RecursiveClientAclRuntime> {
    let action = match acl.action.as_str() {
        "reject" => RecursiveAclActionRuntime::Reject,
        "allow" => RecursiveAclActionRuntime::Allow,
        other => {
            return Err(invalid(
                "dns.recursive.client_acl.action",
                format!("'{other}' is not a supported ACL action (expected 'allow' or 'reject')"),
            ));
        }
    };

    let allowed_clients = parse_ip_list(
        "dns.recursive.client_acl.allowed_clients",
        &acl.allowed_clients,
    )?;

    Ok(RecursiveClientAclRuntime {
        allowed_clients,
        action,
    })
}

// ---------------------------------------------------------------------------
// Shared parsing helpers
// ---------------------------------------------------------------------------

/// Parse a list of CIDR or bare-IP strings into runtime networks.
///
/// Rejects malformed entries instead of skipping them, so a typo cannot
/// silently widen or narrow an allowlist.
fn parse_ip_list(path: &str, entries: &[String]) -> Result<Vec<IpNetwork>> {
    entries
        .iter()
        .map(|entry| {
            IpNetwork::parse(entry)
                .map_err(|e| invalid(path, format!("'{entry}' is not a valid CIDR: {e}")))
        })
        .collect()
}
