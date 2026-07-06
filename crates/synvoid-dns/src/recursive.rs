//! Recursive DNS Server
//!
//! This module provides a recursive DNS resolver that can run alongside
//! the authoritative DNS server. It uses the hickory-resolver crate for
//! upstream recursive resolution.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::firewall::DnsFirewall;
use crate::metrics::DnsMetrics;
use crate::parsed_query::ParsedDnsQuery;
use parking_lot::RwLock;
use synvoid_config::dns::RecursiveDnsConfig;

use super::recursive_cache::{
    CachedRecord, DnssecValidationState, RecursiveCacheKey, RecursiveDnsCache,
};
use super::resolver::{MxRecord, SrvRecord};
use super::wire::{
    build_error_response, build_response_header, get_message_id, parse_dns_message, RCODE_REFUSED,
    RCODE_SERVFAIL,
};
use super::{
    server::DnsRateLimiter, DnsResolver, GlobalNodeResolver, HickoryRecursor, HickoryResolver,
};

#[derive(Debug, thiserror::Error)]
pub enum RecursiveDnsError {
    #[error("Upstream resolution failed: {0}")]
    UpstreamFailed(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
    #[error("Rate limited")]
    RateLimited,
    #[error("Firewall blocked")]
    FirewallBlocked,
    #[error("Timeout")]
    Timeout,
    #[error("Invalid query")]
    InvalidQuery,
    #[error("CNAME depth exceeded")]
    DepthExceeded,
    #[error("Circuit breaker open")]
    CircuitBreakerOpen,
}

pub type RecursiveDnsResult<T> = Result<T, RecursiveDnsError>;

pub struct CircuitBreaker {
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: AtomicU64,
    failure_threshold: u32,
    recovery_timeout_secs: u64,
    success_threshold: u32,
}

impl CircuitBreaker {
    pub fn new(config: &synvoid_config::dns::CircuitBreakerConfig) -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
            failure_threshold: config.failure_threshold,
            recovery_timeout_secs: config.recovery_timeout_secs,
            success_threshold: config.success_threshold,
        }
    }

    pub fn is_open(&self) -> bool {
        let failures = self.failure_count.load(Ordering::Relaxed);
        if failures < self.failure_threshold {
            return false;
        }
        let last = self.last_failure_time.load(Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(last) < self.recovery_timeout_secs
    }

    pub fn record_success(&self) {
        let s = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
        if s >= self.success_threshold {
            self.failure_count.store(0, Ordering::Relaxed);
            self.success_count.store(0, Ordering::Relaxed);
        }
    }

    pub fn record_failure(&self) {
        let prior = self.failure_count.fetch_add(1, Ordering::Relaxed);
        self.last_failure_time.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        if prior + 1 >= self.failure_threshold {
            metrics::counter!("dns_recursive_circuit_breaker_opens_total").increment(1);
        }
    }
}

pub struct RecursiveDnsServer {
    config: RecursiveDnsConfig,
    resolver: Arc<dyn DnsResolver>,
    cache: RecursiveDnsCache,
    rate_limiter: Option<Arc<DnsRateLimiter>>,
    firewall: Option<Arc<RwLock<DnsFirewall>>>,
    metrics: Option<Arc<DnsMetrics>>,
    query_semaphore: Arc<Semaphore>,
    running: Arc<tokio::sync::RwLock<bool>>,
    circuit_breaker: Arc<CircuitBreaker>,
    client_semaphores: Arc<Mutex<HashMap<IpAddr, Arc<Semaphore>>>>,
}

impl RecursiveDnsServer {
    pub async fn new(
        config: RecursiveDnsConfig,
        rate_limiter: Option<Arc<DnsRateLimiter>>,
        firewall: Option<Arc<RwLock<DnsFirewall>>>,
        metrics: Option<Arc<DnsMetrics>>,
    ) -> RecursiveDnsResult<Self> {
        Self::new_with_global_nodes(config, rate_limiter, firewall, metrics, vec![]).await
    }

    pub async fn new_with_global_nodes(
        config: RecursiveDnsConfig,
        rate_limiter: Option<Arc<DnsRateLimiter>>,
        firewall: Option<Arc<RwLock<DnsFirewall>>>,
        metrics: Option<Arc<DnsMetrics>>,
        global_node_ips: Vec<IpAddr>,
    ) -> RecursiveDnsResult<Self> {
        let resolver = Self::create_resolver(&config, &global_node_ips)?;
        let cache = RecursiveDnsCache::new(config.cache.capacity, &config.cache);
        let query_semaphore = Arc::new(Semaphore::new(config.max_concurrent_queries));
        let circuit_breaker = Arc::new(CircuitBreaker::new(&config.circuit_breaker));

        Ok(Self {
            config,
            resolver,
            cache,
            rate_limiter,
            firewall,
            metrics,
            query_semaphore,
            running: Arc::new(tokio::sync::RwLock::new(false)),
            circuit_breaker,
            client_semaphores: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn create_resolver(
        config: &RecursiveDnsConfig,
        global_node_ips: &[IpAddr],
    ) -> RecursiveDnsResult<Arc<dyn DnsResolver>> {
        let resolver: Arc<dyn DnsResolver> = match config.upstream_provider {
            synvoid_config::dns::RecursiveUpstreamProvider::Recursive => {
                tracing::info!(
                    "Configuring true recursive resolver with root hints: {}, trust anchor: {}",
                    config.root_hints_path,
                    config.trust_anchor_path
                );
                Arc::new(
                    HickoryRecursor::new(
                        &config.root_hints_path,
                        &config.trust_anchor_path,
                        config.dnssec_validation,
                    )
                    .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                )
            }
            synvoid_config::dns::RecursiveUpstreamProvider::GlobalNodes => {
                tracing::info!(
                    "Configuring GlobalNodes resolver with {} node IPs",
                    global_node_ips.len()
                );
                Arc::new(
                    GlobalNodeResolver::new(global_node_ips.to_vec())
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                )
            }
            synvoid_config::dns::RecursiveUpstreamProvider::Google => {
                tracing::warn!(
                    "Using Google DNS as upstream provider - DNSSEC validation is NOT performed. \
                     Set upstream_provider='Recursive' to enable DNSSEC validation."
                );
                Arc::new(
                    HickoryResolver::with_google(config.query_timeout_secs)
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                )
            }
            synvoid_config::dns::RecursiveUpstreamProvider::Cloudflare => {
                tracing::warn!(
                    "Using Cloudflare DNS as upstream provider - DNSSEC validation is NOT performed. \
                     Set upstream_provider='Recursive' to enable DNSSEC validation."
                );
                Arc::new(
                    HickoryResolver::with_cloudflare(config.query_timeout_secs)
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                )
            }
            synvoid_config::dns::RecursiveUpstreamProvider::System
            | synvoid_config::dns::RecursiveUpstreamProvider::Custom => {
                let upstream_ips = config.upstream_ips();
                if upstream_ips.is_empty() {
                    Arc::new(
                        HickoryResolver::from_system_config()
                            .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                    )
                } else if config.qname_minimization {
                    Arc::new(
                        HickoryResolver::with_qname_minimization(
                            &upstream_ips,
                            config.query_timeout_secs,
                        )
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                    )
                } else {
                    Arc::new(
                        HickoryResolver::with_upstream_servers(
                            &upstream_ips,
                            config.query_timeout_secs,
                        )
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                    )
                }
            }
        };

        Ok(resolver)
    }

    pub async fn start(self: Arc<Self>) -> RecursiveDnsResult<()> {
        {
            let mut running = self.running.write().await;
            if *running {
                return Ok(());
            }
            *running = true;
        }

        let socket = UdpSocket::bind(format!("{}:{}", self.config.bind_address, self.config.port))
            .await
            .map_err(|e| {
                RecursiveDnsError::UpstreamFailed(format!("Failed to bind socket: {}", e))
            })?;

        info!(
            "Starting recursive DNS server on {}:{}",
            self.config.bind_address, self.config.port
        );

        // Warn about DNSSEC limitations in forwarder mode
        if !matches!(
            self.config.upstream_provider,
            synvoid_config::dns::RecursiveUpstreamProvider::Recursive
        ) && self.config.dnssec_validation
        {
            tracing::warn!(
                    "DNSSEC validation is enabled but forwarder mode ({:?}) does not perform validation. \
                    Upstream servers are trusted to validate DNSSEC. For validated lookups, \
                    configure 'recursive' as the upstream provider.",
                    self.config.upstream_provider
                );
        }

        let server = self.clone();
        let socket = Arc::new(socket);
        let socket_clone = socket.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut running = server.running.read().await;

            loop {
                if !*running {
                    break;
                }

                tokio::select! {
                    result = socket_clone.recv_from(&mut buf) => {
                        match result {
                            Ok((len, client_addr)) => {
                                let server = server.clone();
                                let socket = socket_clone.clone();
                                let packet = buf[..len].to_vec();
                                tokio::spawn(async move {
                                    if let Err(e) = server.handle_packet(packet, client_addr, socket).await {
                                        warn!("Error handling recursive query: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Error receiving packet: {}", e);
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }

                running = server.running.read().await;
            }

            info!("Recursive DNS server stopped");
        });

        let tcp_server = self.clone();
        let tcp_addr = format!("{}:{}", self.config.bind_address, self.config.port);
        tokio::spawn(async move {
            if let Err(e) = tcp_server.start_tcp_listener(&tcp_addr).await {
                error!("TCP listener error: {}", e);
            }
        });

        Ok(())
    }

    async fn start_tcp_listener(&self, addr: &str) -> RecursiveDnsResult<()> {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            RecursiveDnsError::UpstreamFailed(format!("Failed to bind TCP socket: {}", e))
        })?;

        info!("Starting recursive DNS TCP server on {}", addr);

        loop {
            let running = *self.running.read().await;
            if !running {
                break;
            }

            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_tcp_connection(stream, client_addr).await {
                            warn!("Error handling TCP query from {}: {}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
                }
            }
        }

        info!("Recursive DNS TCP server stopped");
        Ok(())
    }

    async fn handle_tcp_connection(
        &self,
        mut stream: TcpStream,
        client_addr: SocketAddr,
    ) -> RecursiveDnsResult<()> {
        let _permit = self
            .query_semaphore
            .acquire()
            .await
            .map_err(|_| RecursiveDnsError::RateLimited)?;

        if let Some(metrics) = &self.metrics {
            metrics.record_recursive_query();
        }

        let max_per_client = self.config.max_per_client_queries;
        let client_sem = if max_per_client > 0 {
            let mut map = self.client_semaphores.lock().unwrap();
            Some(
                map.entry(client_addr.ip())
                    .or_insert_with(|| Arc::new(Semaphore::new(max_per_client as usize)))
                    .clone(),
            )
        } else {
            None
        };

        let _client_permit = if let Some(ref sem) = client_sem {
            let permit = tokio::time::timeout(Duration::from_secs(1), sem.acquire())
                .await
                .map_err(|_| RecursiveDnsError::RateLimited)?
                .map_err(|_| RecursiveDnsError::RateLimited)?;
            Some(permit)
        } else {
            None
        };

        let mut length_buf = [0u8; 2];
        stream.read_exact(&mut length_buf).await.map_err(|e| {
            RecursiveDnsError::UpstreamFailed(format!("Failed to read TCP length: {}", e))
        })?;

        let len = u16::from_be_bytes(length_buf) as usize;

        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await.map_err(|e| {
            RecursiveDnsError::UpstreamFailed(format!("Failed to read TCP query: {}", e))
        })?;

        if let Some(metrics) = &self.metrics {
            metrics.record_query_received();
        }

        if let Some(ref acl) = self.config.client_acl {
            if !acl.is_client_allowed(client_addr.ip()) {
                if let Some(response) = build_error_response(&query, RCODE_REFUSED) {
                    let len = response.len() as u16;
                    let mut len_bytes = len.to_be_bytes().to_vec();
                    len_bytes.extend_from_slice(&response);
                    let _ = stream.write_all(&len_bytes).await;
                }
                return Err(RecursiveDnsError::FirewallBlocked);
            }
        }

        if let Some(ref limiter) = self.rate_limiter {
            if limiter.check_ip(client_addr.ip()).is_err() {
                if let Some(metrics) = &self.metrics {
                    metrics.record_rate_limited();
                }
                return Err(RecursiveDnsError::RateLimited);
            }
        }

        if let Some(ref firewall) = self.firewall {
            if let Ok(parsed_q) = ParsedDnsQuery::parse(&query) {
                let fw = firewall.read();
                if let Ok(decision) = fw.evaluate_query(&parsed_q, client_addr.ip(), "") {
                    if decision.action == crate::firewall::DnsFirewallAction::Block {
                        if let Some(metrics) = &self.metrics {
                            metrics.record_firewall_blocked("recursive_tcp");
                        }
                        return Err(RecursiveDnsError::FirewallBlocked);
                    }
                }
            }
        }

        let message_id = get_message_id(&query).unwrap_or(0);

        let parsed = match parse_dns_message(&query) {
            Ok(p) => p,
            Err(_) => return Err(RecursiveDnsError::InvalidQuery),
        };

        if parsed.queries.is_empty() {
            return Err(RecursiveDnsError::InvalidQuery);
        }

        let question = &parsed.queries[0];
        let qname_str = question.name().to_string();
        let qname_bytes = qname_str.as_bytes().to_vec();

        let checking_disabled = parsed.metadata.checking_disabled;
        let dnssec_ok = parsed.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);

        let (response, _) = match self
            .resolve_upstream(
                &qname_bytes,
                question.query_type(),
                message_id,
                checking_disabled,
                dnssec_ok,
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if let Some(servfail) = build_error_response(&query, RCODE_SERVFAIL) {
                    let len = servfail.len() as u16;
                    let mut len_bytes = len.to_be_bytes().to_vec();
                    len_bytes.extend_from_slice(&servfail);
                    let _ = stream.write_all(&len_bytes).await;
                }
                return Err(e);
            }
        };

        let authority_ns = self.collect_authority_ns(&qname_bytes).await;
        if !validate_authority_bailiwick(&authority_ns, &qname_bytes) {
            warn!(
                "Bailiwick violation: authority NS records not in-bailiwick for {}",
                String::from_utf8_lossy(&qname_bytes)
            );
            if let Some(metrics) = &self.metrics {
                metrics.record_bailiwick_violation();
            }
        }

        let len = response.len() as u16;
        let mut len_bytes = len.to_be_bytes().to_vec();
        len_bytes.extend_from_slice(&response);

        stream.write_all(&len_bytes).await.map_err(|e| {
            RecursiveDnsError::UpstreamFailed(format!("Failed to send TCP response: {}", e))
        })?;

        if let Some(metrics) = &self.metrics {
            metrics.record_response_sent("NOERROR");
        }

        Ok(())
    }

    pub fn stop(&self) {
        let running = self.running.clone();
        tokio::spawn(async move {
            let mut r = running.write().await;
            *r = false;
        });
        info!("Stopping recursive DNS server");
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    async fn handle_packet(
        &self,
        packet: Vec<u8>,
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> RecursiveDnsResult<()> {
        let _permit = self
            .query_semaphore
            .acquire()
            .await
            .map_err(|_| RecursiveDnsError::RateLimited)?;

        if let Some(metrics) = &self.metrics {
            metrics.record_recursive_query();
        }

        let max_per_client = self.config.max_per_client_queries;
        if max_per_client > 0 {
            let sem = {
                let mut map = self.client_semaphores.lock().unwrap();
                map.entry(client_addr.ip())
                    .or_insert_with(|| Arc::new(Semaphore::new(max_per_client as usize)))
                    .clone()
            };
            let _client_permit = tokio::time::timeout(Duration::from_secs(1), sem.acquire())
                .await
                .map_err(|_| RecursiveDnsError::RateLimited)?
                .map_err(|_| RecursiveDnsError::RateLimited)?;

            let query = match parse_dns_message(&packet) {
                Ok(q) => q,
                Err(_) => return Err(RecursiveDnsError::InvalidQuery),
            };

            if let Some(metrics) = &self.metrics {
                metrics.record_query_received();
            }

            if let Some(ref acl) = self.config.client_acl {
                if !acl.is_client_allowed(client_addr.ip()) {
                    if let Some(response) = build_error_response(&packet, RCODE_REFUSED) {
                        let _ = socket.send_to(&response, client_addr).await;
                    }
                    return Err(RecursiveDnsError::FirewallBlocked);
                }
            }

            if let Some(ref limiter) = self.rate_limiter {
                if limiter.check_ip(client_addr.ip()).is_err() {
                    if let Some(metrics) = &self.metrics {
                        metrics.record_rate_limited();
                    }
                    return Err(RecursiveDnsError::RateLimited);
                }
            }

            if let Some(ref firewall) = self.firewall {
                if let Ok(parsed_q) = ParsedDnsQuery::parse(&packet) {
                    let fw = firewall.read();
                    if let Ok(decision) = fw.evaluate_query(&parsed_q, client_addr.ip(), "") {
                        if decision.action == crate::firewall::DnsFirewallAction::Block {
                            if let Some(metrics) = &self.metrics {
                                metrics.record_firewall_blocked("recursive");
                            }
                            return Err(RecursiveDnsError::FirewallBlocked);
                        }
                    }
                }
            }

            let message_id = get_message_id(&packet).unwrap_or(0);
            let response = match self.resolve_query(&query, message_id).await {
                Ok(response) => response,
                Err(e) => {
                    if let Some(response) = build_error_response(&packet, RCODE_SERVFAIL) {
                        let _ = socket.send_to(&response, client_addr).await;
                    }
                    return Err(e);
                }
            };

            socket
                .send_to(&response, client_addr)
                .await
                .map_err(|e| RecursiveDnsError::UpstreamFailed(format!("Send failed: {}", e)))?;

            if let Some(metrics) = &self.metrics {
                metrics.record_response_sent("NOERROR");
            }

            return Ok(());
        }

        let query = match parse_dns_message(&packet) {
            Ok(q) => q,
            Err(_) => return Err(RecursiveDnsError::InvalidQuery),
        };

        if let Some(metrics) = &self.metrics {
            metrics.record_query_received();
        }

        if let Some(ref acl) = self.config.client_acl {
            if !acl.is_client_allowed(client_addr.ip()) {
                if let Some(response) = build_error_response(&packet, RCODE_REFUSED) {
                    let _ = socket.send_to(&response, client_addr).await;
                }
                return Err(RecursiveDnsError::FirewallBlocked);
            }
        }

        if let Some(ref limiter) = self.rate_limiter {
            if limiter.check_ip(client_addr.ip()).is_err() {
                if let Some(metrics) = &self.metrics {
                    metrics.record_rate_limited();
                }
                return Err(RecursiveDnsError::RateLimited);
            }
        }

        if let Some(ref firewall) = self.firewall {
            if let Ok(parsed_q) = ParsedDnsQuery::parse(&packet) {
                let fw = firewall.read();
                if let Ok(decision) = fw.evaluate_query(&parsed_q, client_addr.ip(), "") {
                    if decision.action == crate::firewall::DnsFirewallAction::Block {
                        if let Some(metrics) = &self.metrics {
                            metrics.record_firewall_blocked("recursive");
                        }
                        return Err(RecursiveDnsError::FirewallBlocked);
                    }
                }
            }
        }

        let message_id = get_message_id(&packet).unwrap_or(0);
        let response = match self.resolve_query(&query, message_id).await {
            Ok(response) => response,
            Err(e) => {
                if let Some(response) = build_error_response(&packet, RCODE_SERVFAIL) {
                    let _ = socket.send_to(&response, client_addr).await;
                }
                return Err(e);
            }
        };

        socket
            .send_to(&response, client_addr)
            .await
            .map_err(|e| RecursiveDnsError::UpstreamFailed(format!("Send failed: {}", e)))?;

        if let Some(metrics) = &self.metrics {
            metrics.record_response_sent("NOERROR");
        }

        Ok(())
    }

    async fn resolve_query(&self, query: &Message, message_id: u16) -> RecursiveDnsResult<Vec<u8>> {
        self.resolve_query_with_depth(query, message_id, 0).await
    }

    async fn resolve_query_with_depth(
        &self,
        query: &Message,
        message_id: u16,
        recursion_depth: u8,
    ) -> RecursiveDnsResult<Vec<u8>> {
        if query.queries.is_empty() {
            return Err(RecursiveDnsError::InvalidQuery);
        }

        if self.config.max_recursion_depth > 0 && recursion_depth >= self.config.max_recursion_depth
        {
            return Err(RecursiveDnsError::DepthExceeded);
        }

        if self.config.max_cname_depth > 0 && recursion_depth >= self.config.max_cname_depth {
            return Err(RecursiveDnsError::DepthExceeded);
        }

        let question = &query.queries[0];
        let qname_str = question.name().to_string();
        let qname_bytes = qname_str.as_bytes().to_vec();
        let qtype = question.query_type();

        let checking_disabled = query.metadata.checking_disabled;
        let dnssec_ok = query.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);

        debug!("Recursive query for {} (type {:?})", question.name(), qtype);

        let qtype_u16: u16 = qtype.into();
        let cache_key =
            RecursiveCacheKey::new_with_dnssec(&qname_bytes, qtype_u16, None, dnssec_ok);

        if let Some((records, stale, validation_state)) = self.cache.get(&cache_key) {
            if let Some(metrics) = &self.metrics {
                metrics.record_recursive_cache_hit();
                if stale {
                    metrics.record_cache_hit();
                }
            }

            let response = self.build_cached_response(
                &qname_bytes,
                question.query_type(),
                records,
                message_id,
                validation_state,
                checking_disabled,
                dnssec_ok,
            );
            return Ok(response);
        }

        let (response, _validation_state) = self
            .resolve_upstream(
                &qname_bytes,
                question.query_type(),
                message_id,
                checking_disabled,
                dnssec_ok,
            )
            .await?;

        let authority_ns = self.collect_authority_ns(&qname_bytes).await;
        if !validate_authority_bailiwick(&authority_ns, &qname_bytes) {
            warn!(
                "Bailiwick violation: authority NS records not in-bailiwick for {}",
                String::from_utf8_lossy(&qname_bytes)
            );
            if let Some(metrics) = &self.metrics {
                metrics.record_bailiwick_violation();
            }
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_cache_miss();
            metrics.record_recursive_cache_miss();
        }

        Ok(response)
    }

    async fn resolve_upstream(
        &self,
        qname: &[u8],
        qtype: RecordType,
        message_id: u16,
        checking_disabled: bool,
        dnssec_ok: bool,
    ) -> RecursiveDnsResult<(Vec<u8>, DnssecValidationState)> {
        if self.circuit_breaker.is_open() {
            if let Some(metrics) = &self.metrics {
                metrics.record_recursive_upstream_failure();
            }
            return Err(RecursiveDnsError::CircuitBreakerOpen);
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_recursive_upstream_forward();
        }

        let domain = String::from_utf8_lossy(qname).to_string();
        let mut is_dnssec_validated = false;

        let records = match qtype {
            RecordType::A | RecordType::AAAA => {
                match self.resolver.lookup_ip_with_ttl(&domain).await {
                    Ok(ip_record) => {
                        self.circuit_breaker.record_success();
                        is_dnssec_validated = ip_record.is_dnssec_validated;
                        let ttl = ip_record.ttl.unwrap_or(300);
                        ip_record
                            .addrs
                            .into_iter()
                            .filter_map(|ip| {
                                let record_type: u16 = match ip {
                                    std::net::IpAddr::V4(_) => 1,
                                    std::net::IpAddr::V6(_) => 28,
                                };
                                if qtype == RecordType::AAAA && record_type != 28 {
                                    return None;
                                }
                                if qtype == RecordType::A && record_type != 1 {
                                    return None;
                                }
                                Some(CachedRecord {
                                    name: qname.to_vec(),
                                    record_type,
                                    ttl,
                                    data: match ip {
                                        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                                        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                                    },
                                })
                            })
                            .collect()
                    }
                    Err(_) => {
                        self.circuit_breaker.record_failure();
                        Vec::new()
                    }
                }
            }
            RecordType::TXT => match self.resolver.lookup_txt(&domain).await {
                Ok(txt) => {
                    self.circuit_breaker.record_success();
                    txt.values
                        .into_iter()
                        .map(|v| CachedRecord {
                            name: qname.to_vec(),
                            record_type: 16,
                            ttl: txt.ttl.unwrap_or(300),
                            data: v.into_bytes(),
                        })
                        .collect()
                }
                Err(_) => Vec::new(),
            },
            RecordType::NS => match self.resolver.lookup_ns(&domain).await {
                Ok(ns) => {
                    self.circuit_breaker.record_success();
                    ns.nameservers
                        .into_iter()
                        .map(|ns_name| CachedRecord {
                            name: qname.to_vec(),
                            record_type: 2,
                            ttl: ns.ttl.unwrap_or(300),
                            data: ns_name.into_bytes(),
                        })
                        .collect()
                }
                Err(_) => Vec::new(),
            },
            RecordType::MX => match self.resolver.lookup_mx(&domain).await {
                Ok(mx_records) => {
                    self.circuit_breaker.record_success();
                    mx_records
                        .into_iter()
                        .map(|mx: MxRecord| {
                            let mut data = Vec::new();
                            data.extend_from_slice(&mx.preference.to_be_bytes());
                            data.extend_from_slice(mx.exchange.as_bytes());
                            CachedRecord {
                                name: qname.to_vec(),
                                record_type: 15,
                                ttl: mx.ttl.unwrap_or(300),
                                data,
                            }
                        })
                        .collect()
                }
                Err(_) => Vec::new(),
            },
            RecordType::CNAME => match self.resolver.lookup_cname(&domain).await {
                Ok(Some(cname_record)) => {
                    self.circuit_breaker.record_success();
                    let cname_data = encode_domain_to_wire(&cname_record.cname);
                    vec![CachedRecord {
                        name: qname.to_vec(),
                        record_type: 5,
                        ttl: cname_record.ttl.unwrap_or(300),
                        data: cname_data,
                    }]
                }
                Ok(None) => Vec::new(),
                Err(_) => Vec::new(),
            },
            RecordType::SOA => match self.resolver.lookup_soa(&domain).await {
                Ok(Some(soa)) => {
                    self.circuit_breaker.record_success();
                    let ttl = soa.ttl.unwrap_or(300);
                    let mut data = Vec::new();
                    data.extend_from_slice(&encode_domain_to_wire(&soa.mname));
                    data.extend_from_slice(&encode_domain_to_wire(&soa.rname));
                    data.extend_from_slice(&soa.serial.to_be_bytes());
                    data.extend_from_slice(&soa.refresh.to_be_bytes());
                    data.extend_from_slice(&soa.retry.to_be_bytes());
                    data.extend_from_slice(&soa.expire.to_be_bytes());
                    data.extend_from_slice(&soa.minimum.to_be_bytes());
                    vec![CachedRecord {
                        name: qname.to_vec(),
                        record_type: 6,
                        ttl,
                        data,
                    }]
                }
                Ok(None) => Vec::new(),
                Err(_) => Vec::new(),
            },
            RecordType::PTR => match self.resolver.lookup_ptr(&domain).await {
                Ok(Some(ptr)) => {
                    self.circuit_breaker.record_success();
                    let ttl = ptr.ttl.unwrap_or(300);
                    let data = encode_domain_to_wire(&ptr.domain);
                    vec![CachedRecord {
                        name: qname.to_vec(),
                        record_type: 12,
                        ttl,
                        data,
                    }]
                }
                Ok(None) => Vec::new(),
                Err(_) => Vec::new(),
            },
            RecordType::SRV => match self.resolver.lookup_srv(&domain).await {
                Ok(srv_records) => {
                    self.circuit_breaker.record_success();
                    srv_records
                        .into_iter()
                        .map(|srv: SrvRecord| {
                            let mut data = Vec::new();
                            data.extend_from_slice(&srv.priority.to_be_bytes());
                            data.extend_from_slice(&srv.weight.to_be_bytes());
                            data.extend_from_slice(&srv.port.to_be_bytes());
                            data.extend_from_slice(&encode_domain_to_wire(&srv.target));
                            CachedRecord {
                                name: qname.to_vec(),
                                record_type: 33,
                                ttl: srv.ttl.unwrap_or(300),
                                data,
                            }
                        })
                        .collect()
                }
                Err(_) => Vec::new(),
            },
            _ => Vec::new(),
        };

        let qtype_u16: u16 = qtype.into();

        let effective_dnssec_validated = if checking_disabled {
            false
        } else {
            is_dnssec_validated
        };

        let validation_state = to_validation_state(
            effective_dnssec_validated,
            checking_disabled,
            !self.config.dnssec_validation,
        );

        if records.is_empty() {
            let cache_key = RecursiveCacheKey::new_with_dnssec(qname, qtype_u16, None, dnssec_ok);
            self.cache.insert_negative(
                cache_key,
                true,
                self.config.cache.negative_ttl_secs as u32,
                validation_state,
            );

            let flags = crate::wire::MessageFlags {
                is_response: true,
                opcode: 0,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                authentic_data: effective_dnssec_validated && dnssec_ok,
                checking_disabled,
                response_code: 0,
            };

            let question_section = self.build_question_section(qname, qtype_u16);
            let header = build_response_header(message_id, flags, 1, 0, 0, 0);

            let mut response = header;
            response.extend_from_slice(&question_section);
            return Ok((response, validation_state));
        }

        let cache_key = RecursiveCacheKey::new_with_dnssec(qname, qtype_u16, None, dnssec_ok);
        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300);
        self.cache
            .insert_positive(cache_key, records.clone(), min_ttl, validation_state);

        Ok((
            self.build_cached_response(
                qname,
                qtype,
                records,
                message_id,
                validation_state,
                checking_disabled,
                dnssec_ok,
            ),
            validation_state,
        ))
    }

    fn build_cached_response(
        &self,
        qname: &[u8],
        qtype: RecordType,
        records: Vec<CachedRecord>,
        message_id: u16,
        validation_state: DnssecValidationState,
        checking_disabled: bool,
        dnssec_ok: bool,
    ) -> Vec<u8> {
        let effective_dnssec_validated =
            validation_state == DnssecValidationState::Secure && !checking_disabled;
        let ad_bit = effective_dnssec_validated && dnssec_ok;
        let qtype_u16: u16 = qtype.into();

        let qdcount = 1u16;
        let ancount = records.len() as u16;

        let mut response = Vec::new();

        let question_section = self.build_question_section(qname, qtype_u16);
        response.extend_from_slice(&question_section);

        let mut answer_sections = Vec::new();
        for record in &records {
            let answer_section = self.build_answer_record(record);
            answer_sections.push(answer_section);
        }

        let header_size = 12;
        let question_size = question_section.len();
        let answer_size = answer_sections.iter().map(|s| s.len()).sum::<usize>();

        let total_size = header_size + question_size + answer_size;

        if total_size > 512 {
            let max_answer_size = 512 - header_size - question_size;

            let mut final_response = Vec::new();
            let mut added_size = 0;
            let mut truncated_ancount = 0u16;

            for answer in &answer_sections {
                if added_size + answer.len() <= max_answer_size {
                    final_response.extend_from_slice(answer);
                    added_size += answer.len();
                    truncated_ancount += 1;
                } else {
                    break;
                }
            }

            let flags = crate::wire::MessageFlags {
                is_response: true,
                opcode: 0,
                authoritative: false,
                truncated: true,
                recursion_desired: true,
                recursion_available: true,
                authentic_data: ad_bit,
                checking_disabled,
                response_code: 0,
            };

            let header = build_response_header(message_id, flags, qdcount, truncated_ancount, 0, 0);

            let mut full_response = header;
            full_response.extend_from_slice(&question_section);
            full_response.extend_from_slice(&final_response);

            response = full_response;
        } else {
            let flags = crate::wire::MessageFlags {
                is_response: true,
                opcode: 0,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                authentic_data: ad_bit,
                checking_disabled,
                response_code: 0,
            };

            let header = build_response_header(message_id, flags, qdcount, ancount, 0, 0);

            let mut final_response = header;
            final_response.extend_from_slice(&question_section);
            for answer in answer_sections {
                final_response.extend_from_slice(&answer);
            }

            response = final_response;
        }

        response
    }

    fn build_question_section(&self, qname: &[u8], qtype: u16) -> Vec<u8> {
        let mut section = Vec::new();

        if qname.is_empty() || qname == b"." {
            section.push(0);
        } else {
            section.extend_from_slice(qname);
            if !section.ends_with(&[0]) {
                section.push(0);
            }
        }

        section.extend_from_slice(&qtype.to_be_bytes());
        section.extend_from_slice(&1u16.to_be_bytes());

        section
    }

    fn build_answer_record(&self, record: &CachedRecord) -> Vec<u8> {
        let mut section = Vec::new();

        if record.name.is_empty() || record.name == b"." {
            section.push(0);
        } else {
            section.extend_from_slice(&record.name);
            if !section.ends_with(&[0]) {
                section.push(0);
            }
        }

        section.extend_from_slice(&record.record_type.to_be_bytes());
        section.extend_from_slice(&1u16.to_be_bytes());
        section.extend_from_slice(&record.ttl.to_be_bytes());
        section.extend_from_slice(&(record.data.len() as u16).to_be_bytes());
        section.extend_from_slice(&record.data);

        section
    }

    async fn collect_authority_ns(&self, qname: &[u8]) -> Vec<String> {
        let domain = String::from_utf8_lossy(qname).to_string();
        if let Ok(ns) = self.resolver.lookup_ns(&domain).await {
            ns.nameservers
        } else {
            Vec::new()
        }
    }

    pub fn cache(&self) -> &RecursiveDnsCache {
        &self.cache
    }

    pub fn cache_stats(&self) -> super::recursive_cache::RecursiveCacheStats {
        self.cache.stats()
    }
}

impl Clone for RecursiveDnsServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            resolver: self.resolver.clone(),
            cache: self.cache.clone(),
            rate_limiter: self.rate_limiter.clone(),
            firewall: self.firewall.clone(),
            metrics: self.metrics.clone(),
            query_semaphore: self.query_semaphore.clone(),
            running: self.running.clone(),
            circuit_breaker: self.circuit_breaker.clone(),
            client_semaphores: self.client_semaphores.clone(),
        }
    }
}

fn to_validation_state(
    is_validated: bool,
    cd_bit: bool,
    dnssec_disabled: bool,
) -> DnssecValidationState {
    if dnssec_disabled || cd_bit {
        DnssecValidationState::Unchecked
    } else if is_validated {
        DnssecValidationState::Secure
    } else {
        DnssecValidationState::Bogus
    }
}

/// Encode a dotted domain name to DNS wire format (length-prefixed labels, null-terminated).
fn encode_domain_to_wire(domain: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        result.push(0);
        return result;
    }
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len() as u8;
        result.push(len);
        result.extend_from_slice(label.as_bytes());
    }
    result.push(0);
    result
}

pub fn is_in_bailiwick(name: &[u8], zone_origin: &[u8]) -> bool {
    if name.is_empty() || zone_origin.is_empty() {
        return name == zone_origin;
    }
    let name_lower = name.to_ascii_lowercase();
    let zone_lower = zone_origin.to_ascii_lowercase();
    if name_lower == zone_lower {
        return true;
    }
    if name_lower.len() <= zone_lower.len() {
        return false;
    }
    let suffix = &name_lower[name_lower.len() - zone_lower.len()..];
    if suffix != zone_lower {
        return false;
    }
    name_lower[name_lower.len() - zone_lower.len() - 1] == b'.'
}

pub fn validate_authority_bailiwick(authority_ns: &[String], question_name: &[u8]) -> bool {
    for ns in authority_ns {
        let ns_bytes = ns.as_bytes();
        if !is_in_bailiwick(ns_bytes, question_name) && !is_in_bailiwick(question_name, ns_bytes) {
            return false;
        }
    }
    true
}

pub fn validate_additional_bailiwick(additional_name: &[u8], authority_ns: &[String]) -> bool {
    for ns in authority_ns {
        let ns_bytes = ns.as_bytes();
        if is_in_bailiwick(additional_name, ns_bytes) {
            return true;
        }
    }
    false
}

pub fn truncate_ecs_prefix(
    ecs: &crate::edns::ClientSubnet,
    max_prefix_v4: u8,
    max_prefix_v6: u8,
) -> crate::edns::ClientSubnet {
    let max_prefix = match ecs.address {
        std::net::IpAddr::V4(_) => max_prefix_v4,
        std::net::IpAddr::V6(_) => max_prefix_v6,
    };
    crate::edns::ClientSubnet {
        address: ecs.address,
        prefix_len: ecs.prefix_len.min(max_prefix),
    }
}

pub fn evaluate_ecs_forwarding_policy(
    policy: &synvoid_config::dns::EcsForwardingPolicy,
    client_subnet: &Option<crate::edns::ClientSubnet>,
) -> Option<crate::edns::ClientSubnet> {
    match policy {
        synvoid_config::dns::EcsForwardingPolicy::Never => None,
        synvoid_config::dns::EcsForwardingPolicy::Always => client_subnet.clone(),
        synvoid_config::dns::EcsForwardingPolicy::IfPresent => {
            if client_subnet.is_some() {
                client_subnet.clone()
            } else {
                None
            }
        }
        synvoid_config::dns::EcsForwardingPolicy::CdnOnly => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursive_cache::RecursiveRecordType;
    use synvoid_config::dns::RecursiveCacheConfig;

    fn create_test_cache() -> RecursiveDnsCache {
        let config = RecursiveCacheConfig::default();
        RecursiveDnsCache::new(1000, &config)
    }

    fn create_test_record(name: &[u8], record_type: u16, ttl: u32, data: Vec<u8>) -> CachedRecord {
        CachedRecord {
            name: name.to_vec(),
            record_type,
            ttl,
            data,
        }
    }

    #[test]
    fn test_cache_key_creation() {
        let key = RecursiveCacheKey::new(b"example.com", 1, None);
        assert_eq!(key.qname, b"example.com");
        assert_eq!(key.qtype, RecursiveRecordType::A);
        assert!(key.client_subnet.is_none());
        assert!(!key.dnssec_ok);
    }

    #[test]
    fn test_cache_key_with_subnet() {
        use std::net::IpAddr;
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let key = RecursiveCacheKey::new(b"example.com", 1, Some(ip));
        assert_eq!(key.qname, b"example.com");
        assert!(key.client_subnet.is_some());
    }

    #[test]
    fn test_positive_cache_insert_and_get() {
        let cache = create_test_cache();

        let key = RecursiveCacheKey::new(b"example.com", 1, None);
        let records = vec![create_test_record(
            b"example.com",
            1,
            300,
            vec![93, 184, 216, 34],
        )];

        cache.insert_positive(
            key.clone(),
            records.clone(),
            300,
            DnssecValidationState::Unchecked,
        );

        let result = cache.get(&key);
        assert!(result.is_some());
        let (retrieved, stale, validated) = result.unwrap();
        assert_eq!(retrieved.len(), 1);
        assert!(!stale);
        assert_eq!(validated, DnssecValidationState::Unchecked);
    }

    #[test]
    fn test_negative_cache() {
        let cache = create_test_cache();

        let key = RecursiveCacheKey::new(b"nonexistent.com", 1, None);
        cache.insert_negative(key.clone(), true, 300, DnssecValidationState::Unchecked);

        let result = cache.get(&key);
        assert!(result.is_some());
        let (records, _stale, _validated) = result.unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_cache_stats() {
        let cache = create_test_cache();

        let key = RecursiveCacheKey::new(b"example.com", 1, None);
        let records = vec![create_test_record(b"example.com", 1, 300, vec![1, 2, 3, 4])];

        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);

        let stats = cache.stats();
        assert_eq!(stats.insertions, 1);
    }

    #[test]
    fn test_cache_invalidation() {
        let cache = create_test_cache();

        let key1 = RecursiveCacheKey::new(b"example.com", 1, None);
        let key2 = RecursiveCacheKey::new(b"test.com", 1, None);
        let records1 = vec![create_test_record(b"example.com", 1, 300, vec![1, 1, 1, 1])];
        let records2 = vec![create_test_record(b"test.com", 1, 300, vec![2, 2, 2, 2])];

        cache.insert_positive(
            key1.clone(),
            records1,
            300,
            DnssecValidationState::Unchecked,
        );
        cache.insert_positive(
            key2.clone(),
            records2,
            300,
            DnssecValidationState::Unchecked,
        );

        assert!(cache.get(&key1).is_some());
        assert!(cache.get(&key2).is_some());

        cache.invalidate(b"example.com");

        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_some());
    }

    #[test]
    fn test_cache_invalidation_all() {
        let cache = create_test_cache();

        let key1 = RecursiveCacheKey::new(b"example.com", 1, None);
        let key2 = RecursiveCacheKey::new(b"test.com", 1, None);
        let records1 = vec![create_test_record(b"example.com", 1, 300, vec![1, 1, 1, 1])];
        let records2 = vec![create_test_record(b"test.com", 1, 300, vec![2, 2, 2, 2])];

        cache.insert_positive(
            key1.clone(),
            records1,
            300,
            DnssecValidationState::Unchecked,
        );
        cache.insert_positive(
            key2.clone(),
            records2,
            300,
            DnssecValidationState::Unchecked,
        );

        cache.invalidate_all();

        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_none());

        let stats = cache.stats();
        assert!(stats.invalidations >= 1);
    }

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(u16::from(RecursiveRecordType::A), 1);
        assert_eq!(u16::from(RecursiveRecordType::Aaaa), 28);
        assert_eq!(u16::from(RecursiveRecordType::Mx), 15);
        assert_eq!(u16::from(RecursiveRecordType::Txt), 16);
        assert_eq!(u16::from(RecursiveRecordType::Ns), 2);
        assert_eq!(u16::from(RecursiveRecordType::Soa), 6);
        assert_eq!(u16::from(RecursiveRecordType::Ptr), 12);
        assert_eq!(u16::from(RecursiveRecordType::Srv), 33);
        assert_eq!(u16::from(RecursiveRecordType::CName), 5);
        assert_eq!(u16::from(RecursiveRecordType::Any), 255);

        assert_eq!(RecursiveRecordType::from(1), RecursiveRecordType::A);
        assert_eq!(RecursiveRecordType::from(28), RecursiveRecordType::Aaaa);
        assert_eq!(RecursiveRecordType::from(15), RecursiveRecordType::Mx);
    }

    #[test]
    fn test_cached_record_creation() {
        let record = create_test_record(b"test.example.com", 1, 3600, vec![8, 8, 8, 8]);

        assert_eq!(record.name, b"test.example.com");
        assert_eq!(record.record_type, 1);
        assert_eq!(record.ttl, 3600);
        assert_eq!(record.data, vec![8, 8, 8, 8]);
    }

    #[test]
    fn test_cache_len_operations() {
        let cache = create_test_cache();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        let key = RecursiveCacheKey::new(b"example.com", 1, None);
        let records = vec![create_test_record(b"example.com", 1, 300, vec![1, 2, 3, 4])];

        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);

        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.positive_len(), 1);
        assert_eq!(cache.negative_len(), 0);
    }

    #[test]
    fn test_cache_positive_negative_separation() {
        let cache = create_test_cache();

        let key1 = RecursiveCacheKey::new(b"exists.com", 1, None);
        let key2 = RecursiveCacheKey::new(b"notfound.com", 1, None);
        cache.insert_negative(key2.clone(), true, 300, DnssecValidationState::Unchecked);

        let records = vec![create_test_record(b"exists.com", 1, 300, vec![1, 1, 1, 1])];
        cache.insert_positive(key1.clone(), records, 300, DnssecValidationState::Unchecked);

        assert_eq!(cache.positive_len(), 1);
        assert_eq!(cache.negative_len(), 1);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_record_type_u16_conversion() {
        assert_eq!(u16::from(RecordType::A), 1);
        assert_eq!(u16::from(RecordType::AAAA), 28);
        assert_eq!(u16::from(RecordType::MX), 15);
        assert_eq!(u16::from(RecordType::TXT), 16);
        assert_eq!(u16::from(RecordType::NS), 2);
        assert_eq!(u16::from(RecordType::SOA), 6);
        assert_eq!(u16::from(RecordType::PTR), 12);
        assert_eq!(u16::from(RecordType::SRV), 33);
        assert_eq!(u16::from(RecordType::CNAME), 5);
    }

    #[test]
    fn test_build_question_section() {
        let server = create_mock_server();

        let section = server.build_question_section(b"example.com", 1);

        assert!(!section.is_empty());
        assert!(section.ends_with(&[0, 1]));
        assert!(section.len() >= 6);
    }

    #[test]
    fn test_build_question_section_root() {
        let server = create_mock_server();

        let section = server.build_question_section(b".", 1);

        assert_eq!(section, vec![0, 0, 1, 0, 1]);
    }

    #[test]
    fn test_build_answer_record() {
        let server = create_mock_server();

        let record = create_test_record(b"example.com", 1, 300, vec![93, 184, 216, 34]);
        let section = server.build_answer_record(&record);

        assert!(section.len() > 20);
        let section_slice = &section[section.len() - 6..];
        let rdlen = u16::from_be_bytes([section_slice[0], section_slice[1]]);
        assert_eq!(rdlen, 4);
    }

    #[test]
    fn test_cache_invalidation_by_name() {
        let cache = create_test_cache();

        let key_a = RecursiveCacheKey::new(b"example.com", 1, None);
        let key_aaaa = RecursiveCacheKey::new(b"example.com", 28, None);

        let records_a = vec![create_test_record(b"example.com", 1, 300, vec![1, 1, 1, 1])];
        let records_aaaa = vec![create_test_record(
            b"example.com",
            28,
            300,
            vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        )];

        cache.insert_positive(
            key_a.clone(),
            records_a,
            300,
            DnssecValidationState::Unchecked,
        );
        cache.insert_positive(
            key_aaaa.clone(),
            records_aaaa,
            300,
            DnssecValidationState::Unchecked,
        );

        assert_eq!(cache.len(), 2);

        cache.invalidate(b"example.com");

        assert!(cache.get(&key_a).is_none());
        assert!(cache.get(&key_aaaa).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_multiple_qnames_invalidation() {
        let cache = create_test_cache();

        let key1 = RecursiveCacheKey::new(b"example.com", 1, None);
        let key2 = RecursiveCacheKey::new(b"test.com", 1, None);

        cache.insert_positive(
            key1.clone(),
            vec![create_test_record(b"example.com", 1, 300, vec![1, 1, 1, 1])],
            300,
            DnssecValidationState::Unchecked,
        );
        cache.insert_positive(
            key2.clone(),
            vec![create_test_record(b"test.com", 1, 300, vec![2, 2, 2, 2])],
            300,
            DnssecValidationState::Unchecked,
        );

        cache.invalidate(b"example.com");

        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_key_with_record_type() {
        let key_a = RecursiveCacheKey::new(b"example.com", 1, None);
        let key_aaaa = RecursiveCacheKey::new(b"example.com", 28, None);
        let key_mx = RecursiveCacheKey::new(b"example.com", 15, None);

        assert_ne!(key_a, key_aaaa);
        assert_ne!(key_a, key_mx);
        assert_ne!(key_aaaa, key_mx);
    }

    fn create_mock_server() -> RecursiveDnsServer {
        use std::net::IpAddr;

        let upstream_ip: IpAddr = "8.8.8.8".parse().unwrap();

        RecursiveDnsServer {
            config: RecursiveDnsConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port: 0,
                upstream_provider: synvoid_config::dns::RecursiveUpstreamProvider::System,
                upstream_servers: vec![],
                cache: RecursiveCacheConfig::default(),
                dnssec_validation: false,
                qname_minimization: false,
                query_timeout_secs: 5,
                max_concurrent_queries: 100,
                ratelimit: synvoid_config::dns::DnsRateLimitConfig::default(),
                firewall: synvoid_config::dns::DnsFirewallConfig::default(),
                root_hints_path: "".to_string(),
                trust_anchor_path: "".to_string(),
                client_acl: None,
                max_cname_depth: 10,
                max_recursion_depth: 16,
                max_per_client_queries: 100,
                circuit_breaker: synvoid_config::dns::CircuitBreakerConfig::default(),
                ecs: synvoid_config::dns::RecursiveEcsConfig::default(),
            },
            resolver: Arc::new(HickoryResolver::with_upstream_servers(&[upstream_ip], 5).unwrap()),
            cache: create_test_cache(),
            rate_limiter: None,
            firewall: None,
            metrics: None,
            query_semaphore: Arc::new(Semaphore::new(100)),
            running: Arc::new(tokio::sync::RwLock::new(false)),
            circuit_breaker: Arc::new(CircuitBreaker::new(
                &synvoid_config::dns::CircuitBreakerConfig::default(),
            )),
            client_semaphores: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
