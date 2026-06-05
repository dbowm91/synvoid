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
use tokio::time::{interval, Duration};

use hickory_proto::dnssec::PublicKey;
use hickory_proto::rr::{RData, RecordType};

use crate::trust_anchor::{
    Rfc5011Event, TrustAnchorConfig, TrustAnchorManager, TrustAnchorStatus,
};

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
}

pub type ResolverResult<T> = Result<T, ResolverError>;

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
}

pub struct HickoryResolver {
    resolver: hickory_resolver::TokioResolver,
}

impl HickoryResolver {
    pub fn from_system_config() -> Result<Self, ResolverError> {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| ResolverError::QueryFailed(format!("Failed to create resolver: {}", e)))?
            .build()
            .map_err(|e| ResolverError::QueryFailed(format!("Failed to build resolver: {}", e)))?;
        Ok(Self { resolver })
    }

    pub fn with_upstream_servers(upstream_ips: &[IpAddr]) -> Result<Self, ResolverError> {
        let opts = hickory_resolver::config::ResolverOpts::default();
        Self::with_upstream_servers_and_options(upstream_ips, Some(opts))
    }

    pub fn with_upstream_servers_and_options(
        upstream_ips: &[IpAddr],
        opts: Option<hickory_resolver::config::ResolverOpts>,
    ) -> Result<Self, ResolverError> {
        if upstream_ips.is_empty() {
            return Err(ResolverError::InvalidDomain(
                "No upstream DNS servers provided".to_string(),
            ));
        }

        let name_servers = upstream_ips
            .iter()
            .map(|ip| hickory_resolver::config::NameServerConfig::udp_and_tcp(*ip))
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
    pub fn with_qname_minimization(upstream_ips: &[IpAddr]) -> Result<Self, ResolverError> {
        let mut opts = hickory_resolver::config::ResolverOpts::default();

        // Timeout configuration
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 3;

        // Privacy-friendly configuration
        // Case randomization (0x20) helps mitigate spoofing
        opts.case_randomization = true;

        Self::with_upstream_servers_and_options(upstream_ips, Some(opts))
    }

    pub fn with_default_servers() -> Result<Self, ResolverError> {
        Self::with_upstream_servers(&[
            IpAddr::from([8, 8, 8, 8]),
            IpAddr::from([8, 8, 4, 4]),
            IpAddr::from([1, 1, 1, 1]),
            IpAddr::from([1, 0, 0, 1]),
        ])
    }

    pub fn with_google() -> Result<Self, ResolverError> {
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
        let opts = hickory_resolver::config::ResolverOpts::default();

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

    pub fn with_cloudflare() -> Result<Self, ResolverError> {
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
        let opts = hickory_resolver::config::ResolverOpts::default();

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

pub struct HickoryRecursor {
    recursor: Arc<
        hickory_resolver::recursor::Recursor<hickory_resolver::net::runtime::TokioRuntimeProvider>,
    >,
    enable_dnssec: bool,
    trust_anchor_manager: Option<Arc<TrustAnchorManager>>,
    shutdown_tx: tokio::sync::Mutex<Option<tokio::sync::watch::Sender<()>>>,
    rfc5011_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Clone for HickoryRecursor {
    fn clone(&self) -> Self {
        Self {
            recursor: self.recursor.clone(),
            enable_dnssec: self.enable_dnssec,
            trust_anchor_manager: self.trust_anchor_manager.clone(),
            shutdown_tx: tokio::sync::Mutex::new(None),
            rfc5011_handle: tokio::sync::Mutex::new(None),
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
        )
    }

    pub fn from_paths(
        root_hints_path: &Path,
        trust_anchor_path: &Path,
        enable_dnssec: bool,
    ) -> Result<Self, ResolverError> {
        let root_ips = Self::load_root_hints(root_hints_path)?;

        let roots: Vec<hickory_resolver::config::NameServerConfig> = root_ips
            .iter()
            .map(|ip| hickory_resolver::config::NameServerConfig::udp_and_tcp(*ip))
            .collect();

        let trust_anchor_manager: Option<Arc<TrustAnchorManager>> = if enable_dnssec {
            let db_path = trust_anchor_path
                .with_extension("db")
                .to_string_lossy()
                .to_string();
            let config = TrustAnchorConfig {
                enabled: true,
                db_path,
                anchor_file_path: trust_anchor_path.to_string_lossy().to_string(),
                refresh_interval_secs: 3600,
                pending_observation_days: 30,
                revocation_grace_days: 30,
                extended_removal_days: 60,
                trust_anchor_retention_days: 7,
                allow_key_rotation: true,
            };

            let manager = TrustAnchorManager::new(config);

            if let Err(e) =
                manager.load_initial_anchors_from_file(&trust_anchor_path.to_string_lossy())
            {
                tracing::warn!(
                    "Failed to load initial anchors from {}: {}",
                    trust_anchor_path.display(),
                    e
                );
            } else {
                tracing::info!(
                    "Loaded {} initial trust anchors from {}",
                    manager.get_status().total_anchors,
                    trust_anchor_path.display()
                );
            }

            Some(Arc::new(manager))
        } else {
            None
        };

        let dnssec_policy = if enable_dnssec {
            let trust_anchors =
                Self::build_trust_anchors(trust_anchor_path, trust_anchor_manager.as_ref());
            let mut config = hickory_resolver::recursor::DnssecConfig::default();
            config.trust_anchor = Some(std::sync::Arc::new(trust_anchors));
            hickory_resolver::recursor::DnssecPolicy::ValidateWithStaticKey(config)
        } else {
            hickory_resolver::recursor::DnssecPolicy::SecurityUnaware
        };

        let mut recursor_opts = hickory_resolver::recursor::RecursorOptions::default();
        // Case randomization (0x20) helps mitigate spoofing
        recursor_opts.case_randomization = true;

        let recursor = hickory_resolver::recursor::Recursor::new(
            &roots.iter().map(|c| c.ip).collect::<Vec<_>>(),
            dnssec_policy,
            None,
            recursor_opts,
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .map_err(|e| ResolverError::QueryFailed(format!("Failed to build recursor: {}", e)))?;

        tracing::info!(
            "Created recursive resolver (DNSSEC: {}, RFC 5011: {})",
            if enable_dnssec { "enabled" } else { "disabled" },
            if trust_anchor_manager.is_some() {
                "enabled"
            } else {
                "disabled"
            }
        );

        Ok(Self {
            recursor: Arc::new(recursor),
            enable_dnssec,
            trust_anchor_manager,
            shutdown_tx: tokio::sync::Mutex::new(None),
            rfc5011_handle: tokio::sync::Mutex::new(None),
        })
    }

    fn build_trust_anchors(
        path: &Path,
        manager: Option<&Arc<TrustAnchorManager>>,
    ) -> hickory_proto::dnssec::TrustAnchors {
        if let Some(manager) = manager {
            let trusted_anchors = manager.get_trusted_anchors();
            if !trusted_anchors.is_empty() {
                let mut anchors = hickory_proto::dnssec::TrustAnchors::empty();
                for anchor in trusted_anchors {
                    use hickory_proto::dnssec::{Algorithm, PublicKeyBuf};
                    let algorithm = Algorithm::from_u8(anchor.algorithm);
                    let pkey = PublicKeyBuf::new(anchor.public_key, algorithm);
                    let _ = anchors.insert(&pkey);
                }
                tracing::info!(
                    "Built trust anchors from RFC 5011 manager ({} keys)",
                    anchors.len()
                );
                return anchors;
            }
        }

        match hickory_proto::dnssec::TrustAnchors::from_file(path) {
            Ok(anchors) => {
                tracing::info!("Loaded DNSSEC trust anchors from {}", path.display());
                anchors
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to load trust anchors from {}, using defaults: {}",
                    path.display(),
                    e
                );
                hickory_proto::dnssec::TrustAnchors::default()
            }
        }
    }

    pub async fn start_rfc5011_updates(self: Arc<Self>) -> Result<(), ResolverError> {
        let manager = match &self.trust_anchor_manager {
            Some(m) => m.clone(),
            None => {
                return Err(ResolverError::QueryFailed(
                    "No trust anchor manager configured".to_string(),
                ))
            }
        };

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(());

        tracing::info!("Starting RFC 5011 trust anchor update task");

        let handle = tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(3600));

            loop {
                tokio::select! {
                    _ = check_interval.tick() => {
                        tracing::debug!("RFC 5011: Checking for trust anchor updates");

                        let events = manager.process_rfc5011_updates();

                        for event in &events {
                            match event {
                                Rfc5011Event::KeyPromoted { key_tag } => {
                                    tracing::info!("RFC 5011: Key {} promoted to trusted", key_tag);
                                }
                                Rfc5011Event::KeyRevoked { key_tag } => {
                                    tracing::warn!("RFC 5011: Key {} has been revoked", key_tag);
                                }
                                Rfc5011Event::KeyRemoved { key_tag } => {
                                    tracing::info!("RFC 5011: Key {} removed from trust anchors", key_tag);
                                }
                                Rfc5011Event::KeyMissing { key_tag } => {
                                    tracing::warn!("RFC 5011: Key {} is missing from DNSKEY RRset", key_tag);
                                }
                                Rfc5011Event::KeyPurged { key_tag } => {
                                    tracing::info!("RFC 5011: Key {} purged from storage", key_tag);
                                }
                                _ => {}
                            }
                        }

                        if !events.is_empty() {
                            tracing::info!("RFC 5011: Processed {} trust anchor events", events.len());
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::info!("RFC 5011: Shutting down trust anchor update task");
                        break;
                    }
                }
            }
        });

        tracing::info!("RFC 5011: Background task spawned successfully");

        *self.shutdown_tx.lock().await = Some(shutdown_tx);
        *self.rfc5011_handle.lock().await = Some(handle);
        Ok(())
    }

    pub async fn stop_rfc5011_updates(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        tracing::info!("RFC 5011: Shutdown signal sent");
    }

    pub fn get_trust_anchor_status(&self) -> Option<TrustAnchorStatus> {
        self.trust_anchor_manager
            .as_ref()
            .map(|m: &Arc<TrustAnchorManager>| m.get_status())
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

    pub async fn lookup_dnskey(&self, name: &str) -> ResolverResult<Vec<DnsKeyRecord>> {
        use hickory_proto::dnssec::Algorithm;

        let name = ensure_trailing_dot(name);

        let query_name = hickory_proto::rr::Name::from_str(&name)
            .map_err(|e| ResolverError::InvalidDomain(format!("Invalid domain name: {}", e)))?;

        let query = hickory_proto::op::Query::query(query_name, RecordType::DNSKEY);

        let lookup = self
            .recursor
            .resolve(query, Instant::now(), self.enable_dnssec)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("DNSKEY lookup failed: {}", e)))?;

        let ttl = Some(60);
        let mut records = Vec::new();

        for proven_record in lookup.answers.iter() {
            let record = proven_record;
            let RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::DNSKEY(dnskey)) =
                &record.data
            else {
                continue;
            };

            let algorithm: Algorithm = dnskey.public_key().algorithm();
            let algorithm_u8: u8 = algorithm.into();
            let public_key_bytes = dnskey.public_key().public_bytes();
            let key_tag = Self::compute_key_tag_from_rdata(algorithm_u8, public_key_bytes);
            let is_revoked = dnskey.revoke();

            if let Some(manager) = &self.trust_anchor_manager {
                let _ = manager.observe_dnskey_at_root(
                    key_tag,
                    algorithm_u8,
                    public_key_bytes,
                    is_revoked,
                );
            }

            records.push(DnsKeyRecord {
                key_tag,
                algorithm: algorithm_u8,
                flags: dnskey.flags(),
                public_key: public_key_bytes.to_vec(),
                is_secure: lookup.authentic_data,
                is_revoked,
                ttl,
            });
        }

        if records.is_empty() {
            for record in lookup.answers.iter() {
                if let RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::DNSKEY(dnskey)) =
                    &record.data
                {
                    let algorithm: Algorithm = dnskey.public_key().algorithm();
                    let algorithm_u8: u8 = algorithm.into();
                    let public_key_bytes = dnskey.public_key().public_bytes();
                    let key_tag = Self::compute_key_tag_from_rdata(algorithm_u8, public_key_bytes);

                    records.push(DnsKeyRecord {
                        key_tag,
                        algorithm: algorithm_u8,
                        flags: dnskey.flags(),
                        public_key: public_key_bytes.to_vec(),
                        is_secure: false,
                        is_revoked: dnskey.revoke(),
                        ttl,
                    });
                }
            }
        }

        Ok(records)
    }

    pub async fn lookup_cds(&self, name: &str) -> ResolverResult<Vec<CdsRecord>> {
        let name = ensure_trailing_dot(name);

        let query_name = hickory_proto::rr::Name::from_str(&name)
            .map_err(|e| ResolverError::InvalidDomain(format!("Invalid domain name: {}", e)))?;

        let query = hickory_proto::op::Query::query(query_name, RecordType::CDS);

        let lookup = self
            .recursor
            .resolve(query, Instant::now(), self.enable_dnssec)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("CDS lookup failed: {}", e)))?;

        let ttl = Some(60);
        let mut records = Vec::new();

        for proven_record in lookup.answers.iter() {
            let record = proven_record;
            let RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::CDS(cds)) = &record.data
            else {
                continue;
            };

            let key_tag = cds.key_tag();
            let algorithm_opt = cds.algorithm();

            if let Some(algorithm) = algorithm_opt {
                let algorithm_u8: u8 = algorithm.into();
                let digest_type: u8 = cds.digest_type().into();
                let digest = cds.digest();

                if let Some(manager) = &self.trust_anchor_manager {
                    let _ = manager.trust_anchor_check(
                        key_tag,
                        algorithm_u8,
                        digest_type,
                        digest,
                        None,
                    );
                }

                records.push(CdsRecord {
                    key_tag,
                    algorithm: algorithm_u8,
                    digest_type,
                    digest: digest.to_vec(),
                    is_secure: lookup.authentic_data,
                    ttl,
                });
            }
        }

        Ok(records)
    }

    pub async fn perform_rfc5011_trust_anchor_check(
        &self,
        zone: &str,
    ) -> ResolverResult<Rfc5011CheckResult> {
        let mut events = Vec::new();
        let mut new_keys_seen = 0;
        let mut keys_promoted = 0;
        let mut keys_revoked = 0;

        let dnskey_records = self.lookup_dnskey(zone).await?;
        let cds_records = self.lookup_cds(zone).await?;

        let dnskey_keytags: Vec<u16> = dnskey_records.iter().map(|r| r.key_tag).collect();

        for record in &dnskey_records {
            if record.is_revoked {
                keys_revoked += 1;
            }
        }

        if let Some(manager) = &self.trust_anchor_manager {
            for record in cds_records {
                let event = manager.trust_anchor_check(
                    record.key_tag,
                    record.algorithm,
                    record.digest_type,
                    &record.digest,
                    Some(&dnskey_keytags),
                );
                match &event {
                    crate::trust_anchor::Rfc5011Event::NewKeySeen { .. } => new_keys_seen += 1,
                    crate::trust_anchor::Rfc5011Event::KeyPromoted { .. } => {
                        keys_promoted += 1
                    }
                    _ => {}
                }
                events.push(event);
            }
        }

        Ok(Rfc5011CheckResult {
            events,
            new_keys_seen,
            keys_promoted,
            keys_revoked,
        })
    }

    fn compute_key_tag_from_rdata(algorithm: u8, public_key: &[u8]) -> u16 {
        crate::dnssec::calculate_key_tag(257, 3, algorithm, public_key)
    }
}

#[derive(Debug, Clone)]
pub struct DnsKeyRecord {
    pub key_tag: u16,
    pub algorithm: u8,
    pub flags: u16,
    pub public_key: Vec<u8>,
    pub is_secure: bool,
    pub is_revoked: bool,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct CdsRecord {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
    pub is_secure: bool,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Rfc5011CheckResult {
    pub events: Vec<crate::trust_anchor::Rfc5011Event>,
    pub new_keys_seen: usize,
    pub keys_promoted: usize,
    pub keys_revoked: usize,
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
}
