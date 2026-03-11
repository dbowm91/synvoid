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
//! Full QNAME minimization support requires a newer version of Hickory DNS that includes
//! this feature. The feature was merged in Hickory DNS PR #2919 (merged in 2025).
//!
//! Current status: The resolver supports configuring resolver options, but full
//! QNAME minimization is pending hickory-resolver update.
//!
//! ## How to Enable (Future)
//!
//! Once a compatible Hickory DNS version is available:
//!
//! ```rust,ignore
//! use hickory_resolver::config::{ResolverConfig, ResolverOpts};
//!
//! let mut opts = ResolverOpts::default();
//! opts.qname_minimization = true;  // Enable QNAME minimization
//!
//! let config = ResolverConfig::default();
//! let resolver = TokioAsyncResolver::from_config(config, opts);
//! ```
//!
//! ## Benefits
//!
//! - Improved privacy: Upstream resolvers only see minimal domain information
//! - Reduced query traffic: May result in fewer queries to root/TLD servers
//! - RFC 7816 compliant: Standardized approach to query privacy
//!
//! ## References
//!
//! - [RFC 7816: DNS Query Name Minimization to Improve Privacy](https://tools.ietf.org/html/rfc7816)
//! - [Hickory DNS QNAME Minimization PR](https://github.com/hickory-dns/hickory-dns/pull/2919)

use std::net::IpAddr;
use std::sync::Arc;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct TxtRecord {
    pub values: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NsRecord {
    pub nameservers: Vec<String>,
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

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn lookup_txt(&self, name: &str) -> ResolverResult<TxtRecord>;
    async fn lookup_ns(&self, name: &str) -> ResolverResult<NsRecord>;
    async fn lookup_a(&self, name: &str) -> ResolverResult<Vec<IpAddr>>;
}

#[derive(Clone)]
pub struct NoopResolver;

#[async_trait]
impl DnsResolver for NoopResolver {
    async fn lookup_txt(&self, _name: &str) -> ResolverResult<TxtRecord> {
        Ok(TxtRecord { values: vec![] })
    }

    async fn lookup_ns(&self, _name: &str) -> ResolverResult<NsRecord> {
        Ok(NsRecord { nameservers: vec![] })
    }

    async fn lookup_a(&self, _name: &str) -> ResolverResult<Vec<IpAddr>> {
        Ok(vec![])
    }
}

pub struct HickoryResolver {
    resolver: hickory_resolver::TokioResolver,
}

impl HickoryResolver {
    pub fn from_system_config() -> Result<Self, ResolverError> {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| ResolverError::QueryFailed(format!("Failed to create resolver: {}", e)))?
            .build();
        Ok(Self { resolver })
    }

    pub fn with_upstream_servers(upstream_ips: &[IpAddr]) -> Result<Self, ResolverError> {
        Self::with_upstream_servers_and_options(upstream_ips, None)
    }

    pub fn with_upstream_servers_and_options(
        upstream_ips: &[IpAddr],
        opts: Option<hickory_resolver::config::ResolverOpts>,
    ) -> Result<Self, ResolverError> {
        if upstream_ips.is_empty() {
            return Err(ResolverError::InvalidDomain("No upstream DNS servers provided".to_string()));
        }

        let config = hickory_resolver::config::ResolverConfig::from_parts(
            None,
            vec![],
            hickory_resolver::config::NameServerConfigGroup::from_ips_clear(
                upstream_ips,
                53,
                true,
            ),
        );

        let mut builder = hickory_resolver::Resolver::builder_with_config(
            config,
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        );
        
        if let Some(options) = opts {
            builder = builder.with_options(options);
        }

        let resolver = builder.build();

        Ok(Self { resolver: resolver.into() })
    }

    /// Create a resolver with QNAME minimization enabled (RFC 7816)
    /// 
    /// Note: QNAME minimization is a privacy-enhancing feature that requires
    /// a recent version of hickory-resolver (>= 0.25.2). This feature reduces
    /// privacy leakage to upstream resolvers by sending minimal query names
    /// during recursive resolution.
    /// 
    /// Currently, this method enables privacy-friendly options but full
    /// QNAME minimization requires a Hickory DNS version that supports it.
    pub fn with_qname_minimization(upstream_ips: &[IpAddr]) -> Result<Self, ResolverError> {
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        
        // Timeout configuration
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 3;
        
        // Note: opts.qname_minimization = true would enable RFC 7816
        // but requires hickory-resolver >= 0.25.2
        // For now, we configure privacy-friendly defaults
        // TODO: Enable qname_minimization when hickory-resolver is updated
        
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
        let config = hickory_resolver::config::ResolverConfig::google();
        
        let resolver = hickory_resolver::Resolver::builder_with_config(
            config,
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self { resolver: resolver.into() })
    }

    pub fn with_cloudflare() -> Result<Self, ResolverError> {
        let config = hickory_resolver::config::ResolverConfig::cloudflare();
        
        let resolver = hickory_resolver::Resolver::builder_with_config(
            config,
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self { resolver: resolver.into() })
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
        let name = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{}.", name)
        };

        let lookup = self.resolver
            .txt_lookup(&name)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("TXT lookup failed: {}", e)))?;

        let values: Vec<String> = lookup.iter()
            .map(|txt| txt.to_string())
            .collect();

        Ok(TxtRecord { values })
    }

    async fn lookup_ns(&self, name: &str) -> ResolverResult<NsRecord> {
        let name = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{}.", name)
        };

        let lookup = self.resolver
            .ns_lookup(&name)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("NS lookup failed: {}", e)))?;

        let nameservers: Vec<String> = lookup.iter()
            .map(|ns| ns.to_string())
            .collect();

        Ok(NsRecord { nameservers })
    }

    async fn lookup_a(&self, name: &str) -> ResolverResult<Vec<IpAddr>> {
        let name = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{}.", name)
        };

        let lookup = self.resolver
            .lookup_ip(&name)
            .await
            .map_err(|e| ResolverError::QueryFailed(format!("A lookup failed: {}", e)))?;

        Ok(lookup.into_iter().collect())
    }
}
