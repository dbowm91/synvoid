//! DNS Resolver Module
//!
//! This module provides recursive DNS resolution capabilities using the Hickory DNS library.
//!
//! # Query Name Minimization (RFC 7816)
//!
//! Query Name Minimization is a privacy-enhancing technique that reduces the amount of
//! information leaked to upstream DNS resolvers. Instead of sending the full query name,
//! the resolver sends only the minimal amount of information needed to resolve the query.
//!
//! ## Implementation Status
//!
//! Full QNAME minimization support is natively provided by Hickory DNS 0.26's
//! recursive resolver implementation.
//!
//! Current status: The `HickoryRecursor` performs full QNAME minimization
//! during iterative resolution. `HickoryResolver` (forwarder mode) relies
//! on the upstream recursive resolver for QNAME minimization.
//!
//! ## Benefits
//!
//! - Improved privacy: Upstream resolvers only see minimal domain information
//! - Reduced query traffic: May result in fewer queries to root/TLD servers
//! - RFC 7816 / RFC 9156 compliant: Standardized approach to query privacy
//!
//! ## References
//!
//! - [RFC 9156: DNS Query Name Minimization to Improve Privacy](https://tools.ietf.org/html/rfc9156)
//! - [Hickory DNS Recursor Implementation](https://github.com/hickory-dns/hickory-dns)

use async_trait::async_trait;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::rr::{RData, RecordType};

#[derive(Debug, Clone)]
pub struct TxtRecord {
    pub values: Vec<String>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct NsRecord {
    pub nameservers: Vec<String>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct IpRecord {
    pub addrs: Vec<IpAddr>,
    pub ttl: Option<u32>,
    pub is_dnssec_validated: bool,
}

#[derive(Debug, Clone)]
pub struct MxRecord {
    pub exchange: String,
    pub preference: u16,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SoaRecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct PtrRecord {
    pub domain: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct CNameRecord {
    pub cname: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    #[error("Query failed: {0}")]
    QueryFailed(String),
    #[error("Timeout")]
    Timeout,
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),
    /// The validating upstream rejected the data. This is a lookup failure, not
    /// an absence of records: it must never be cached as NODATA.
    #[error("DNSSEC validation failed: {0}")]
    Bogus(String),
    /// The record type has no upstream lookup in this resolver.
    #[error("unsupported record type: {0}")]
    Unsupported(u16),
}

pub type ResolverResult<T> = Result<T, ResolverError>;

/// One record as the upstream reported it, before the recursive layer encodes
/// it. Names stay in presentation form here: `recursive.rs` is the only place
/// that turns a name into wire bytes, so the one-owner-encoder rule has a
/// single enforcement point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedRecord {
    /// A or AAAA, with the queried record type.
    Address {
        ip: IpAddr,
        ttl: u32,
    },
    Cname {
        target: String,
        ttl: u32,
    },
    Ns {
        target: String,
        ttl: u32,
    },
    Mx {
        exchange: String,
        preference: u16,
        ttl: u32,
    },
    Txt {
        value: String,
        ttl: u32,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
        ttl: u32,
    },
    Ptr {
        target: String,
        ttl: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
        ttl: u32,
    },
    Naptr {
        order: u16,
        preference: u16,
        /// Character-strings carried verbatim (RFC 3403 §4.1).
        flags: Vec<u8>,
        service: Vec<u8>,
        regexp: Vec<u8>,
        replacement: String,
        ttl: u32,
    },
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
        ttl: u32,
    },
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
        ttl: u32,
    },
}

/// One upstream RRset plus the response metadata a recursive answer must echo.
///
/// This is the only resolver result that separates "no records" from "lookup
/// failed": `rcode` carries NXDOMAIN through instead of collapsing it to an
/// empty set, and `negative_ttl` carries the SOA-derived TTL (RFC 2308 §3)
/// instead of the fixed negative-cache default.
#[derive(Debug, Clone, Default)]
pub struct UpstreamRrset {
    /// Records in the order the upstream returned them.
    pub records: Vec<ResolvedRecord>,
    /// NOERROR (0) or NXDOMAIN (3) as reported by the upstream response.
    pub rcode: u8,
    /// `min(SOA TTL, SOA MINIMUM)` when a negative response carried an SOA.
    pub negative_ttl: Option<u32>,
    /// The upstream marked the data as validated (AD bit or secure proof).
    pub is_dnssec_validated: bool,
}

impl UpstreamRrset {
    /// True when upstream answered NOERROR with no records: NODATA, not NXDOMAIN.
    pub fn is_nodata(&self) -> bool {
        self.records.is_empty() && self.rcode == crate::wire::RCODE_NOERROR
    }

    /// True when upstream answered NXDOMAIN (RFC 1035 §4.1.1 RCODE 3).
    pub fn is_nxdomain(&self) -> bool {
        self.rcode == crate::wire::RCODE_NXDOMAIN
    }
}

/// Convert an upstream SOA into the negative TTL of RFC 2308 §3.
///
/// The SOA's own TTL bounds how long the negative answer may be cached, and so
/// does its MINIMUM field; the smaller of the two wins.
fn soa_negative_ttl(record: &hickory_proto::rr::Record) -> Option<u32> {
    match &record.data {
        RData::SOA(soa) => Some(negative_ttl_from_soa(record.ttl, soa)),
        _ => None,
    }
}

/// `min(SOA TTL, SOA MINIMUM)`, the negative-caching TTL of RFC 2308 §3.
fn negative_ttl_from_soa(ttl: u32, soa: &hickory_proto::rr::rdata::SOA) -> u32 {
    ttl.min(soa.minimum)
}

fn ensure_trailing_dot(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

/// DNS resolver trait.
///
/// **Note:** `HickoryResolver` (forwarder mode) does NOT perform DNSSEC validation —
/// `is_dnssec_validated` is always `false` on its returned records.
/// `HickoryRecursor` (recursive mode) performs full DNSSEC validation when `enable_dnssec` is set.
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

    /// Look up one RRset, preserving the rcode and the SOA-derived negative TTL.
    ///
    /// The per-type helpers above cannot express the difference between "the
    /// zone has no such record" and "the lookup failed", and they hard-code the
    /// negative TTL. The recursive server answers from this method so a
    /// SERVFAIL is never cached as NODATA and NXDOMAIN survives to the wire.
    async fn lookup_rrset(&self, name: &str, record_type: u16) -> ResolverResult<UpstreamRrset>;
}

/// Map an upstream `RData` into the resolver-neutral record shape.
///
/// Returns `None` for a type the recursive server does not answer; the caller
/// reports NOTIMP for those instead of a silently empty answer.
pub fn resolved_record(data: &RData, ttl: u32) -> Option<ResolvedRecord> {
    Some(match data {
        RData::A(a) => ResolvedRecord::Address {
            ip: IpAddr::V4(a.0),
            ttl,
        },
        RData::AAAA(aaaa) => ResolvedRecord::Address {
            ip: IpAddr::V6(aaaa.0),
            ttl,
        },
        RData::CNAME(cname) => ResolvedRecord::Cname {
            target: cname.to_string(),
            ttl,
        },
        RData::NS(ns) => ResolvedRecord::Ns {
            target: ns.to_string(),
            ttl,
        },
        RData::MX(mx) => ResolvedRecord::Mx {
            exchange: mx.exchange.to_string(),
            preference: mx.preference,
            ttl,
        },
        RData::TXT(txt) => ResolvedRecord::Txt {
            value: txt.to_string(),
            ttl,
        },
        RData::SOA(soa) => ResolvedRecord::Soa {
            mname: soa.mname.to_string(),
            rname: soa.rname.to_string(),
            serial: soa.serial,
            refresh: soa.refresh,
            retry: soa.retry,
            expire: soa.expire,
            minimum: soa.minimum,
            ttl,
        },
        RData::PTR(ptr) => ResolvedRecord::Ptr {
            target: ptr.to_string(),
            ttl,
        },
        RData::SRV(srv) => ResolvedRecord::Srv {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: srv.target.to_string(),
            ttl,
        },
        RData::NAPTR(naptr) => ResolvedRecord::Naptr {
            order: naptr.order,
            preference: naptr.preference,
            // NAPTR character-strings are opaque bytes (RFC 3403 §4.1); they
            // are carried through verbatim so a non-ASCII service field is
            // not mangled by a lossy detour through `String`.
            flags: naptr.flags.to_vec(),
            service: naptr.services.to_vec(),
            regexp: naptr.regexp.to_vec(),
            replacement: naptr.replacement.to_string(),
            ttl,
        },
        RData::DNSSEC(dnssec) => match dnssec {
            hickory_proto::dnssec::rdata::DNSSECRData::DS(ds) => ResolvedRecord::Ds {
                key_tag: ds.key_tag(),
                algorithm: ds.algorithm().into(),
                digest_type: ds.digest_type().into(),
                digest: ds.digest().to_vec(),
                ttl,
            },
            hickory_proto::dnssec::rdata::DNSSECRData::DNSKEY(dnskey) => {
                use hickory_proto::dnssec::PublicKey;
                ResolvedRecord::Dnskey {
                    flags: dnskey.flags(),
                    // DNSKEY RDATA carries a fixed protocol value (RFC 4034 §2.1).
                    protocol: 3,
                    algorithm: dnskey.public_key().algorithm().into(),
                    public_key: dnskey.public_key().public_bytes().to_vec(),
                    ttl,
                }
            }
            _ => return None,
        },
        _ => return None,
    })
}

/// Keep the records that answer `wanted` at `queried`.
///
/// Records owned by another name (the tail of a CNAME chain, or glue) are
/// dropped: the recursive layer stamps every answer with the queried owner, so
/// keeping them would label a target's record with the alias's name. The CNAME
/// itself is kept, which is what lets the client follow the alias.
fn collect_rrset(
    answers: &[hickory_proto::rr::Record],
    wanted: RecordType,
    queried: &hickory_proto::rr::Name,
) -> Vec<ResolvedRecord> {
    answers
        .iter()
        .filter(|record| record.name == *queried)
        .filter(|record| {
            let record_type = record.record_type();
            record_type == wanted || record_type == RecordType::CNAME
        })
        .filter_map(|record| resolved_record(&record.data, record.ttl))
        .collect()
}

/// The rcode and SOA-derived negative TTL of a `NoRecords` error.
fn no_records_outcome(no_records: &hickory_resolver::net::NoRecords) -> UpstreamRrset {
    let negative_ttl = no_records.negative_ttl.or_else(|| {
        no_records
            .soa
            .as_ref()
            .map(|soa| negative_ttl_from_soa(soa.ttl, &soa.data))
    });
    UpstreamRrset {
        records: Vec::new(),
        rcode: no_records.response_code.low(),
        negative_ttl,
        is_dnssec_validated: false,
    }
}

#[derive(Clone)]
pub struct NoopResolver;

#[async_trait]
impl DnsResolver for NoopResolver {
    async fn lookup_txt(&self, _name: &str) -> ResolverResult<TxtRecord> {
        Ok(TxtRecord {
            values: vec![],
            ttl: None,
        })
    }

    async fn lookup_ns(&self, _name: &str) -> ResolverResult<NsRecord> {
        Ok(NsRecord {
            nameservers: vec![],
            ttl: None,
        })
    }

    async fn lookup_a(&self, _name: &str) -> ResolverResult<Vec<IpAddr>> {
        Ok(vec![])
    }

    async fn lookup_ip_with_ttl(&self, _name: &str) -> ResolverResult<IpRecord> {
        Ok(IpRecord {
            addrs: vec![],
            ttl: None,
            is_dnssec_validated: false,
        })
    }

    async fn lookup_mx(&self, _name: &str) -> ResolverResult<Vec<MxRecord>> {
        Ok(vec![])
    }

    async fn lookup_soa(&self, _name: &str) -> ResolverResult<Option<SoaRecord>> {
        Ok(None)
    }

    async fn lookup_ptr(&self, _name: &str) -> ResolverResult<Option<PtrRecord>> {
        Ok(None)
    }

    async fn lookup_srv(&self, _name: &str) -> ResolverResult<Vec<SrvRecord>> {
        Ok(vec![])
    }

    async fn lookup_cname(&self, _name: &str) -> ResolverResult<Option<CNameRecord>> {
        Ok(None)
    }

    async fn lookup_rrset(&self, _name: &str, record_type: u16) -> ResolverResult<UpstreamRrset> {
        Err(ResolverError::Unsupported(record_type))
    }
}

/// Privacy-oriented forwarder options: bounded attempts, case randomization
/// (0x20) and a per-query timeout.
fn qname_minimization_options(timeout_secs: u64) -> hickory_resolver::config::ResolverOpts {
    let mut opts = hickory_resolver::config::ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(timeout_secs);
    opts.attempts = 3;
    opts
}

pub struct HickoryResolver {
    resolver: hickory_resolver::TokioResolver,
}

/// One forwarder upstream: address plus the port it is served on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UpstreamEndpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl UpstreamEndpoint {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    /// A nameserver that speaks UDP and TCP on `port`.
    ///
    /// `NameServerConfig` carries the address only; the port lives on each
    /// connection, which is why dropping it here made `:5353` unreachable.
    fn name_server_config(self) -> hickory_resolver::config::NameServerConfig {
        // `NameServerConfig` is non-exhaustive and carries the port on each
        // connection, so start from the stock UDP+TCP pair and move both.
        let mut config = hickory_resolver::config::NameServerConfig::udp_and_tcp(self.ip);
        for connection in &mut config.connections {
            connection.port = self.port;
        }
        config
    }
}

impl std::fmt::Display for UpstreamEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

impl HickoryResolver {
    pub fn from_system_config() -> Result<Self, ResolverError> {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| ResolverError::QueryFailed(format!("Failed to create resolver: {}", e)))?
            .build()
            .map_err(|e| ResolverError::QueryFailed(format!("Failed to build resolver: {}", e)))?;
        Ok(Self { resolver })
    }

    pub fn with_upstream_servers(
        upstream_ips: &[IpAddr],
        timeout_secs: u64,
    ) -> Result<Self, ResolverError> {
        let endpoints: Vec<UpstreamEndpoint> = upstream_ips
            .iter()
            .map(|ip| UpstreamEndpoint::new(*ip, 53))
            .collect();
        Self::with_upstream_endpoints(&endpoints, timeout_secs)
    }

    /// Create a forwarder that queries each endpoint on its own port.
    pub fn with_upstream_endpoints(
        upstreams: &[UpstreamEndpoint],
        timeout_secs: u64,
    ) -> Result<Self, ResolverError> {
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(timeout_secs);
        Self::with_upstream_endpoints_and_options(upstreams, Some(opts))
    }

    pub fn with_upstream_servers_and_options(
        upstream_ips: &[IpAddr],
        opts: Option<hickory_resolver::config::ResolverOpts>,
    ) -> Result<Self, ResolverError> {
        let endpoints: Vec<UpstreamEndpoint> = upstream_ips
            .iter()
            .map(|ip| UpstreamEndpoint::new(*ip, 53))
            .collect();
        Self::with_upstream_endpoints_and_options(&endpoints, opts)
    }

    pub fn with_upstream_endpoints_and_options(
        upstreams: &[UpstreamEndpoint],
        opts: Option<hickory_resolver::config::ResolverOpts>,
    ) -> Result<Self, ResolverError> {
        if upstreams.is_empty() {
            return Err(ResolverError::InvalidDomain(
                "No upstream DNS servers provided".to_string(),
            ));
        }

        let name_servers = upstreams
            .iter()
            .map(|endpoint| endpoint.name_server_config())
            .collect();

        let config =
            hickory_resolver::config::ResolverConfig::from_parts(None, vec![], name_servers);

        let mut builder = hickory_resolver::TokioResolver::builder_with_config(
            config,
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        );
        *builder.options_mut() = opts.unwrap_or_default();
        let resolver = builder
            .build()
            .map_err(|e| ResolverError::QueryFailed(format!("Failed to create resolver: {}", e)))?;

        Ok(Self { resolver })
    }

    /// Create a resolver with QNAME minimization enabled (RFC 7816)
    ///
    /// Note: QNAME minimization is a privacy-enhancing feature that requires
    /// a recent version of hickory-resolver (>= 0.25.2). This feature reduces
    /// privacy leakage to upstream resolvers by sending minimal query names
    /// during recursive resolution.
    ///
    /// Note: QNAME minimization is natively performed by HickoryRecursor.
    /// In forwarder mode (HickoryResolver), privacy-friendly options are configured,
    /// and QNAME minimization is typically performed by the upstream recursive resolver.
    pub fn with_qname_minimization(
        upstream_ips: &[IpAddr],
        timeout_secs: u64,
    ) -> Result<Self, ResolverError> {
        let mut opts = qname_minimization_options(timeout_secs);
        opts.case_randomization = true;
        Self::with_upstream_servers_and_options(upstream_ips, Some(opts))
    }

    /// QNAME-minimization options for a port-carrying endpoint list.
    pub fn with_qname_minimization_endpoints(
        upstreams: &[UpstreamEndpoint],
        timeout_secs: u64,
    ) -> Result<Self, ResolverError> {
        let mut opts = qname_minimization_options(timeout_secs);
        opts.case_randomization = true;
        Self::with_upstream_endpoints_and_options(upstreams, Some(opts))
    }

    pub fn with_default_servers() -> Result<Self, ResolverError> {
        Self::with_upstream_servers(
            &[
                IpAddr::from([8, 8, 8, 8]),
                IpAddr::from([8, 8, 4, 4]),
                IpAddr::from([1, 1, 1, 1]),
                IpAddr::from([1, 0, 0, 1]),
            ],
            5,
        )
    }

    pub fn with_google(timeout_secs: u64) -> Result<Self, ResolverError> {
        let name_servers = vec![
            hickory_resolver::config::NameServerConfig::udp_and_tcp(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(8, 8, 8, 8),
            )),
            hickory_resolver::config::NameServerConfig::udp_and_tcp(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(8, 8, 4, 4),
            )),
            hickory_resolver::config::NameServerConfig::udp_and_tcp(std::net::IpAddr::V6(
                std::net::Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            )),
            hickory_resolver::config::NameServerConfig::udp_and_tcp(std::net::IpAddr::V6(
                std::net::Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
            )),
        ];
        let config =
            hickory_resolver::config::ResolverConfig::from_parts(None, vec![], name_servers);
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(timeout_secs);

        let mut builder = hickory_resolver::TokioResolver::builder_with_config(
            config,
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        );
        *builder.options_mut() = opts;
        let resolver = builder
            .build()
            .map_err(|e| ResolverError::QueryFailed(format!("Failed to create resolver: {}", e)))?;

        Ok(Self { resolver })
    }

    pub fn with_cloudflare(timeout_secs: u64) -> Result<Self, ResolverError> {
        let name_servers = vec![
            hickory_resolver::config::NameServerConfig::udp_and_tcp(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1),
            )),
            hickory_resolver::config::NameServerConfig::udp_and_tcp(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(1, 0, 0, 1),
            )),
            hickory_resolver::config::NameServerConfig::udp_and_tcp(std::net::IpAddr::V6(
                std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
            )),
            hickory_resolver::config::NameServerConfig::udp_and_tcp(std::net::IpAddr::V6(
                std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
            )),
        ];
        let config =
            hickory_resolver::config::ResolverConfig::from_parts(None, vec![], name_servers);
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(timeout_secs);

        let mut builder = hickory_resolver::TokioResolver::builder_with_config(
            config,
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        );
        *builder.options_mut() = opts;
        let resolver = builder
            .build()
            .map_err(|e| ResolverError::QueryFailed(format!("Failed to create resolver: {}", e)))?;

        Ok(Self { resolver })
    }
}

impl Clone for HickoryResolver {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
        }
    }
}

#[async_trait]
impl DnsResolver for HickoryResolver {
    async fn lookup_txt(&self, name: &str) -> ResolverResult<TxtRecord> {
        let name = ensure_trailing_dot(name);

        let lookup = self
            .resolver
            .txt_lookup(&name)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("TXT lookup failed: {}", e)))?;

        let values: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|r| {
                if let hickory_proto::rr::RData::TXT(txt) = &r.data {
                    Some(txt.to_string())
                } else {
                    None
                }
            })
            .collect();

        let ttl = Some(60);
        Ok(TxtRecord { values, ttl })
    }

    async fn lookup_ns(&self, name: &str) -> ResolverResult<NsRecord> {
        let name = ensure_trailing_dot(name);

        let lookup = self
            .resolver
            .ns_lookup(&name)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("NS lookup failed: {}", e)))?;

        let nameservers: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|r| {
                if let hickory_proto::rr::RData::NS(ns) = &r.data {
                    Some(ns.to_string())
                } else {
                    None
                }
            })
            .collect();

        let ttl = Some(60);
        Ok(NsRecord { nameservers, ttl })
    }

    async fn lookup_a(&self, name: &str) -> ResolverResult<Vec<IpAddr>> {
        let name = ensure_trailing_dot(name);

        let lookup = self
            .resolver
            .lookup_ip(&name)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("A lookup failed: {}", e)))?;

        Ok(lookup.iter().collect())
    }

    async fn lookup_ip_with_ttl(&self, name: &str) -> ResolverResult<IpRecord> {
        let name = ensure_trailing_dot(name);

        let lookup = self
            .resolver
            .lookup_ip(&name)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("A lookup failed: {}", e)))?;

        let ttl = Some(60);

        // NOTE: DNSSEC validation status is not exposed by hickory-resolver's lookup API.
        // For proper DNSSEC validation, use HickoryRecursor which tracks validation status.
        // See HickoryResolver::lookup_ip_hickory_resolver::recursor() for DNSSEC-aware lookups.
        Ok(IpRecord {
            addrs: lookup.iter().collect(),
            ttl,
            is_dnssec_validated: false,
        })
    }

    async fn lookup_mx(&self, name: &str) -> ResolverResult<Vec<MxRecord>> {
        let name = ensure_trailing_dot(name);

        match self.resolver.lookup(&name, RecordType::MX).await {
            Ok(lookup) => {
                let ttl = Some(
                    lookup
                        .valid_until()
                        .saturating_duration_since(Instant::now())
                        .as_secs() as u32,
                );
                let records: Vec<MxRecord> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| {
                        if let RData::MX(mx) = &record.data {
                            Some(MxRecord {
                                exchange: mx.exchange.to_string(),
                                preference: mx.preference,
                                ttl,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
                Ok(records)
            }
            Err(e) => Err(ResolverError::QueryFailed(format!(
                "MX lookup failed: {}",
                e
            ))),
        }
    }

    async fn lookup_soa(&self, name: &str) -> ResolverResult<Option<SoaRecord>> {
        let name = ensure_trailing_dot(name);

        match self.resolver.lookup(&name, RecordType::SOA).await {
            Ok(lookup) => {
                let ttl = Some(
                    lookup
                        .valid_until()
                        .saturating_duration_since(Instant::now())
                        .as_secs() as u32,
                );
                let soa = lookup.answers().iter().next().and_then(|record| {
                    if let RData::SOA(soa_data) = &record.data {
                        Some(SoaRecord {
                            mname: soa_data.mname.to_string(),
                            rname: soa_data.rname.to_string(),
                            serial: soa_data.serial,
                            refresh: soa_data.refresh,
                            retry: soa_data.retry,
                            expire: soa_data.expire,
                            minimum: soa_data.minimum,
                            ttl,
                        })
                    } else {
                        None
                    }
                });
                Ok(soa)
            }
            Err(_) => Ok(None),
        }
    }

    async fn lookup_ptr(&self, name: &str) -> ResolverResult<Option<PtrRecord>> {
        let name = ensure_trailing_dot(name);

        match self.resolver.lookup(&name, RecordType::PTR).await {
            Ok(lookup) => {
                let ttl = Some(
                    lookup
                        .valid_until()
                        .saturating_duration_since(Instant::now())
                        .as_secs() as u32,
                );
                let ptr = lookup.answers().iter().next().and_then(|record| {
                    if let RData::PTR(ptr_data) = &record.data {
                        Some(PtrRecord {
                            domain: ptr_data.to_string(),
                            ttl,
                        })
                    } else {
                        None
                    }
                });
                Ok(ptr)
            }
            Err(_) => Ok(None),
        }
    }

    async fn lookup_srv(&self, name: &str) -> ResolverResult<Vec<SrvRecord>> {
        let name = ensure_trailing_dot(name);

        match self.resolver.lookup(&name, RecordType::SRV).await {
            Ok(lookup) => {
                let ttl = Some(
                    lookup
                        .valid_until()
                        .saturating_duration_since(Instant::now())
                        .as_secs() as u32,
                );
                let records: Vec<SrvRecord> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| {
                        if let RData::SRV(srv) = &record.data {
                            Some(SrvRecord {
                                priority: srv.priority,
                                weight: srv.weight,
                                port: srv.port,
                                target: srv.target.to_string(),
                                ttl,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
                Ok(records)
            }
            Err(e) => Err(ResolverError::QueryFailed(format!(
                "SRV lookup failed: {}",
                e
            ))),
        }
    }

    async fn lookup_cname(&self, name: &str) -> ResolverResult<Option<CNameRecord>> {
        let name = ensure_trailing_dot(name);

        match self.resolver.lookup(&name, RecordType::CNAME).await {
            Ok(lookup) => {
                let ttl = Some(
                    lookup
                        .valid_until()
                        .saturating_duration_since(Instant::now())
                        .as_secs() as u32,
                );
                let cname = lookup.answers().iter().next().and_then(|record| {
                    if let RData::CNAME(cname_data) = &record.data {
                        Some(CNameRecord {
                            cname: cname_data.to_string(),
                            ttl,
                        })
                    } else {
                        None
                    }
                });
                Ok(cname)
            }
            Err(_) => Ok(None),
        }
    }

    async fn lookup_rrset(&self, name: &str, record_type: u16) -> ResolverResult<UpstreamRrset> {
        use hickory_resolver::net::{DnsError, NetError};

        let name = ensure_trailing_dot(name);
        let wanted = RecordType::from(record_type);
        let queried = match hickory_proto::rr::Name::from_str(&name) {
            Ok(queried) => queried,
            Err(error) => {
                return Err(ResolverError::InvalidDomain(format!(
                    "Invalid domain name {name}: {error}"
                )))
            }
        };

        match self.resolver.lookup(&name, wanted).await {
            Ok(lookup) => {
                let message = lookup.message();
                Ok(UpstreamRrset {
                    records: collect_rrset(lookup.answers(), wanted, &queried),
                    // A successful hickory lookup is always NOERROR: NXDOMAIN
                    // arrives as `NoRecordsFound` below.
                    rcode: message.metadata.response_code.low(),
                    negative_ttl: lookup.authorities().iter().find_map(soa_negative_ttl),
                    is_dnssec_validated: message.metadata.authentic_data,
                })
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
                Ok(no_records_outcome(&no_records))
            }
            Err(NetError::Dns(DnsError::DnssecBogus)) => Err(ResolverError::Bogus(format!(
                "{name} {wanted} failed validation"
            ))),
            Err(error) => Err(ResolverError::QueryFailed(format!(
                "{wanted} lookup for {name} failed: {error}"
            ))),
        }
    }
}

#[derive(Debug, Default)]
struct LookupResult {
    pub ip_addrs: Vec<IpAddr>,
    pub txt_values: Vec<String>,
    pub ns_names: Vec<String>,
    pub mx_records: Vec<MxRecord>,
    pub soa_record: Option<SoaRecord>,
    pub ptr_record: Option<PtrRecord>,
    pub cname_record: Option<CNameRecord>,
    pub srv_records: Vec<SrvRecord>,
    pub ttl: Option<u32>,
    pub is_dnssec_validated: bool,
}

/// Load a static DNSSEC trust-anchor file.
///
/// This is the only supported anchor source (decision T5): the file is read at
/// startup and never modified at runtime. There is no RFC 5011 observation,
/// promotion, or revocation state machine, so a key added to or revoked in the
/// root zone does not change these anchors until the file is replaced and the
/// process restarted.
pub fn load_static_trust_anchors(
    path: &Path,
) -> Result<hickory_proto::dnssec::TrustAnchors, String> {
    hickory_proto::dnssec::TrustAnchors::from_file(path)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Recursion limits handed to hickory's iterative resolver.
///
/// `recursion_limit` is `dns.recursive.max_recursion_depth`. hickory's other
/// knob (`ns_recursion_limit`) bounds nameserver-pool depth, not CNAME chain
/// length, so the configured `max_cname_depth` is enforced by the recursive
/// server itself and is deliberately not mapped onto it.
#[derive(Debug, Clone, Copy)]
pub struct RecursorLimits {
    pub recursion_limit: u8,
}

impl Default for RecursorLimits {
    fn default() -> Self {
        // hickory's own default, for callers that do not configure a limit.
        Self {
            recursion_limit: 24,
        }
    }
}

pub struct HickoryRecursor {
    recursor: Arc<
        hickory_resolver::recursor::Recursor<hickory_resolver::net::runtime::TokioRuntimeProvider>,
    >,
    enable_dnssec: bool,
}

impl Clone for HickoryRecursor {
    fn clone(&self) -> Self {
        Self {
            recursor: self.recursor.clone(),
            enable_dnssec: self.enable_dnssec,
        }
    }
}

impl HickoryRecursor {
    pub fn new(
        root_hints_path: &str,
        trust_anchor_path: &str,
        enable_dnssec: bool,
    ) -> Result<Self, ResolverError> {
        Self::from_paths(
            Path::new(root_hints_path),
            Path::new(trust_anchor_path),
            enable_dnssec,
            RecursorLimits::default(),
        )
    }

    /// Build the recursor, handing hickory the configured recursion limit.
    pub fn from_paths(
        root_hints_path: &Path,
        trust_anchor_path: &Path,
        enable_dnssec: bool,
        limits: RecursorLimits,
    ) -> Result<Self, ResolverError> {
        let root_ips = Self::load_root_hints(root_hints_path)?;

        let dnssec_policy = if enable_dnssec {
            let trust_anchors = Self::build_trust_anchors(trust_anchor_path);
            let mut config = hickory_resolver::recursor::DnssecConfig::default();
            config.trust_anchor = Some(std::sync::Arc::new(trust_anchors));
            hickory_resolver::recursor::DnssecPolicy::ValidateWithStaticKey(config)
        } else {
            hickory_resolver::recursor::DnssecPolicy::SecurityUnaware
        };

        // Case randomization (0x20) helps mitigate spoofing.
        let recursor_opts = hickory_resolver::recursor::RecursorOptions {
            case_randomization: true,
            recursion_limit: limits.recursion_limit,
            ..Default::default()
        };

        let recursor = hickory_resolver::recursor::Recursor::new(
            &root_ips,
            dnssec_policy,
            None,
            recursor_opts,
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .map_err(|e| ResolverError::QueryFailed(format!("Failed to build recursor: {}", e)))?;

        tracing::info!(
            "Created recursive resolver (DNSSEC: {}, trust anchors: {}, recursion_limit: {})",
            if enable_dnssec { "enabled" } else { "disabled" },
            trust_anchor_path.display(),
            limits.recursion_limit
        );

        Ok(Self {
            recursor: Arc::new(recursor),
            enable_dnssec,
        })
    }

    /// Load the static trust-anchor file.
    ///
    /// Anchors are a startup snapshot read from this file; there is no
    /// observation/update state machine (RFC 5011 is not implemented — see
    /// `docs/RFC5011_TRUST_ANCHOR.md`).
    fn build_trust_anchors(path: &Path) -> hickory_proto::dnssec::TrustAnchors {
        match load_static_trust_anchors(path) {
            Ok(anchors) => {
                tracing::info!(
                    "Loaded {} static DNSSEC trust anchors from {}",
                    anchors.len(),
                    path.display()
                );
                anchors
            }
            Err(error) => {
                tracing::warn!(
                    "Failed to load trust anchors from {}, using defaults: {}",
                    path.display(),
                    error
                );
                hickory_proto::dnssec::TrustAnchors::default()
            }
        }
    }

    fn load_root_hints(path: &Path) -> Result<Vec<IpAddr>, ResolverError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ResolverError::QueryFailed(format!("Failed to read root hints: {}", e)))?;
        Self::parse_root_hints(&content)
    }

    fn parse_root_hints(content: &str) -> Result<Vec<IpAddr>, ResolverError> {
        let mut ips = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let qtype = parts.get(2).unwrap_or(&"");
                let qname = parts.first().unwrap_or(&"");

                // Parse both A and AAAA records for root servers
                // Format: "servername. TTL IN A IPv4" or "servername. TTL IN AAAA IPv6"
                if (qtype == &"A" || qtype == &"AAAA") && qname.ends_with(".root-servers.net.") {
                    if let Some(ip_str) = parts.get(3) {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            if !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                    }
                }
            }
        }

        if ips.is_empty() {
            ips = Self::default_root_servers();
        }

        Ok(ips)
    }

    fn default_root_servers() -> Vec<IpAddr> {
        vec![
            IpAddr::from([198, 41, 0, 4]),
            IpAddr::from([199, 9, 14, 201]),
            IpAddr::from([192, 33, 4, 12]),
            IpAddr::from([199, 7, 91, 13]),
            IpAddr::from([192, 203, 230, 5]),
            IpAddr::from([192, 5, 5, 241]),
            IpAddr::from([192, 112, 36, 4]),
            IpAddr::from([198, 97, 190, 53]),
            IpAddr::from([192, 36, 148, 17]),
            IpAddr::from([192, 58, 128, 30]),
            IpAddr::from([193, 0, 14, 129]),
            IpAddr::from([199, 7, 83, 42]),
            IpAddr::from([202, 12, 27, 33]),
        ]
    }

    async fn recursive_lookup(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> ResolverResult<IpRecord> {
        let name = ensure_trailing_dot(name);

        let query_name = hickory_proto::rr::Name::from_str(&name)
            .map_err(|e| ResolverError::InvalidDomain(format!("Invalid domain name: {}", e)))?;

        let query = hickory_proto::op::Query::query(query_name, record_type);

        let lookup = self
            .recursor
            .resolve(query, Instant::now(), self.enable_dnssec)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("Recursive lookup failed: {}", e)))?;

        let ttl = Some(60);

        let mut addrs = Vec::new();
        let mut is_dnssec_validated = false;

        for proven_record in lookup.answers.iter() {
            if lookup.authentic_data {
                is_dnssec_validated = true;
            }
            let record = proven_record;
            match &record.data {
                RData::A(a) => addrs.push(std::net::IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => addrs.push(std::net::IpAddr::V6(aaaa.0)),
                _ => {}
            }
        }

        if addrs.is_empty() {
            for record in lookup.answers.iter() {
                match &record.data {
                    RData::A(a) => addrs.push(std::net::IpAddr::V4(a.0)),
                    RData::AAAA(aaaa) => addrs.push(std::net::IpAddr::V6(aaaa.0)),
                    _ => {}
                }
            }
        }

        Ok(IpRecord {
            addrs,
            ttl,
            is_dnssec_validated,
        })
    }

    async fn recursive_lookup_by_type(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> ResolverResult<LookupResult> {
        let name = ensure_trailing_dot(name);

        let query_name = hickory_proto::rr::Name::from_str(&name)
            .map_err(|e| ResolverError::InvalidDomain(format!("Invalid domain name: {}", e)))?;

        let query = hickory_proto::op::Query::query(query_name, record_type);

        let lookup = self
            .recursor
            .resolve(query, Instant::now(), self.enable_dnssec)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("Recursive lookup failed: {}", e)))?;

        let ttl = Some(60);
        let mut is_dnssec_validated = false;

        let mut result = LookupResult {
            ttl,
            is_dnssec_validated,
            ..Default::default()
        };

        for proven_record in lookup.answers.iter() {
            if lookup.authentic_data {
                is_dnssec_validated = true;
            }
            let record = proven_record;
            Self::add_record_to_result(&record.data, ttl, &mut result);
        }

        if Self::result_is_empty(&result) {
            for record in lookup.answers.iter() {
                Self::add_record_to_result(&record.data, ttl, &mut result);
            }
        }

        result.is_dnssec_validated = is_dnssec_validated;
        Ok(result)
    }

    fn result_is_empty(result: &LookupResult) -> bool {
        result.ip_addrs.is_empty()
            && result.txt_values.is_empty()
            && result.ns_names.is_empty()
            && result.mx_records.is_empty()
            && result.soa_record.is_none()
            && result.ptr_record.is_none()
            && result.cname_record.is_none()
            && result.srv_records.is_empty()
    }

    fn add_record_to_result(rdata: &RData, ttl: Option<u32>, result: &mut LookupResult) {
        match rdata {
            RData::A(a) => {
                result.ip_addrs.push(std::net::IpAddr::V4(a.0));
            }
            RData::AAAA(aaaa) => {
                result.ip_addrs.push(std::net::IpAddr::V6(aaaa.0));
            }
            RData::TXT(txt) => {
                result.txt_values.push(txt.to_string());
            }
            RData::NS(ns) => {
                result.ns_names.push(ns.to_string());
            }
            RData::MX(mx) => {
                result.mx_records.push(MxRecord {
                    exchange: mx.exchange.to_string(),
                    preference: mx.preference,
                    ttl,
                });
            }
            RData::SOA(soa) => {
                result.soa_record = Some(SoaRecord {
                    mname: soa.mname.to_string(),
                    rname: soa.rname.to_string(),
                    serial: soa.serial,
                    refresh: soa.refresh,
                    retry: soa.retry,
                    expire: soa.expire,
                    minimum: soa.minimum,
                    ttl,
                });
            }
            RData::PTR(ptr) => {
                result.ptr_record = Some(PtrRecord {
                    domain: ptr.to_string(),
                    ttl,
                });
            }
            RData::CNAME(cname) => {
                result.cname_record = Some(CNameRecord {
                    cname: cname.to_string(),
                    ttl,
                });
            }
            RData::SRV(srv) => {
                result.srv_records.push(SrvRecord {
                    priority: srv.priority,
                    weight: srv.weight,
                    port: srv.port,
                    target: srv.target.to_string(),
                    ttl,
                });
            }
            _ => {}
        }
    }

    /// Look up one RRset through the iterative resolver, keeping the rcode and
    /// the SOA-derived negative TTL that a recursive answer must echo.
    async fn recursive_rrset(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> ResolverResult<UpstreamRrset> {
        let name = ensure_trailing_dot(name);

        let query_name = hickory_proto::rr::Name::from_str(&name)
            .map_err(|e| ResolverError::InvalidDomain(format!("Invalid domain name: {}", e)))?;

        let queried = query_name.clone();
        let query = hickory_proto::op::Query::query(query_name, record_type);

        let message = self
            .recursor
            .resolve(query, Instant::now(), self.enable_dnssec)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("Recursive lookup failed: {}", e)))?;

        let negative_ttl = message
            .authorities
            .iter()
            .find_map(soa_negative_ttl)
            .or_else(|| message.additionals.iter().find_map(soa_negative_ttl));

        Ok(UpstreamRrset {
            records: collect_rrset(&message.answers, record_type, &queried),
            rcode: message.metadata.response_code.low(),
            negative_ttl,
            is_dnssec_validated: message.metadata.authentic_data,
        })
    }
}

#[async_trait]
impl DnsResolver for HickoryRecursor {
    async fn lookup_txt(&self, name: &str) -> ResolverResult<TxtRecord> {
        match self.recursive_lookup_by_type(name, RecordType::TXT).await {
            Ok(result) => Ok(TxtRecord {
                values: result.txt_values,
                ttl: result.ttl,
            }),
            Err(e) => Err(e),
        }
    }

    async fn lookup_ns(&self, name: &str) -> ResolverResult<NsRecord> {
        match self.recursive_lookup_by_type(name, RecordType::NS).await {
            Ok(result) => Ok(NsRecord {
                nameservers: result.ns_names,
                ttl: result.ttl,
            }),
            Err(e) => Err(e),
        }
    }

    async fn lookup_a(&self, name: &str) -> ResolverResult<Vec<IpAddr>> {
        match self.recursive_lookup(name, RecordType::A).await {
            Ok(ip_record) => Ok(ip_record.addrs),
            Err(e) => Err(e),
        }
    }

    async fn lookup_ip_with_ttl(&self, name: &str) -> ResolverResult<IpRecord> {
        self.recursive_lookup(name, RecordType::A).await
    }

    async fn lookup_mx(&self, name: &str) -> ResolverResult<Vec<MxRecord>> {
        match self.recursive_lookup_by_type(name, RecordType::MX).await {
            Ok(result) => Ok(result.mx_records),
            Err(e) => Err(e),
        }
    }

    async fn lookup_soa(&self, name: &str) -> ResolverResult<Option<SoaRecord>> {
        match self.recursive_lookup_by_type(name, RecordType::SOA).await {
            Ok(result) => Ok(result.soa_record),
            Err(e) => Err(e),
        }
    }

    async fn lookup_ptr(&self, name: &str) -> ResolverResult<Option<PtrRecord>> {
        match self.recursive_lookup_by_type(name, RecordType::PTR).await {
            Ok(result) => Ok(result.ptr_record),
            Err(e) => Err(e),
        }
    }

    async fn lookup_srv(&self, name: &str) -> ResolverResult<Vec<SrvRecord>> {
        match self.recursive_lookup_by_type(name, RecordType::SRV).await {
            Ok(result) => Ok(result.srv_records),
            Err(e) => Err(e),
        }
    }

    async fn lookup_cname(&self, name: &str) -> ResolverResult<Option<CNameRecord>> {
        match self.recursive_lookup_by_type(name, RecordType::CNAME).await {
            Ok(result) => Ok(result.cname_record),
            Err(e) => Err(e),
        }
    }

    async fn lookup_rrset(&self, name: &str, record_type: u16) -> ResolverResult<UpstreamRrset> {
        self.recursive_rrset(name, RecordType::from(record_type))
            .await
    }
}
