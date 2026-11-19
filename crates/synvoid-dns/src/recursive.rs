//! Recursive DNS Server
//!
//! This module provides a recursive DNS resolver that can run alongside
//! the authoritative DNS server. It uses the hickory-resolver crate for
//! upstream recursive resolution.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinEncodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::firewall::DnsFirewall;
use crate::metrics::DnsMetrics;
use crate::parsed_query::ParsedDnsQuery;
use crate::runtime_config::{
    RecursiveEcsPolicyRuntime, RecursiveRuntimeConfig, RecursiveUpstreamRuntime,
};
use parking_lot::RwLock;

use super::recursive_cache::{
    CacheHit, CacheLookup, CachedRecord, DnssecValidationState, RecursiveCacheKey,
    RecursiveDnsCache,
};
use super::resolver::{HickoryRecursor, RecursorLimits, ResolvedRecord, UpstreamEndpoint};
use super::wire::{
    build_response_header, get_message_id, parse_dns_message, RCODE_NOERROR, RCODE_NOTIMP,
    RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL,
};
use super::{server::DnsRateLimiter, DnsResolver, GlobalNodeResolver, HickoryResolver};

/// TTL served with a stale answer. RFC 8767 §4 asks for a short TTL so the
/// client retries soon instead of pinning data the resolver could not refresh.
const STALE_SERVE_TTL: u32 = 30;

/// A resolved answer and the rcode the response must echo.
///
/// This is what separates "no records" (NOERROR/NODATA, NXDOMAIN) from "the
/// lookup failed": only an `AnswerSet` ever reaches the cache.
#[derive(Debug, Clone)]
pub struct AnswerSet {
    pub records: Vec<CachedRecord>,
    /// NOERROR (0) or NXDOMAIN (3).
    pub rcode: u8,
    /// `min(SOA TTL, SOA MINIMUM)` for a negative answer (RFC 2308 §3).
    pub negative_ttl: Option<u32>,
    pub validation_state: DnssecValidationState,
}

impl AnswerSet {
    fn is_negative(&self) -> bool {
        self.records.is_empty()
    }
}

/// Why an upstream lookup did not produce an `AnswerSet`.
///
/// None of these are cacheable: a timeout, a refusal, a broken dependency, or
/// bogus DNSSEC data is not "no such record" and must not become NODATA.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Transport or dependency failure: SERVFAIL.
    #[error("upstream lookup failed: {0}")]
    Upstream(String),
    /// The upstream rejected the data during validation: SERVFAIL.
    #[error("upstream data failed DNSSEC validation: {0}")]
    Bogus(String),
    /// The circuit breaker is open: SERVFAIL until recovery.
    #[error("upstream circuit breaker is open")]
    CircuitBreakerOpen,
    /// The record type has no recursive lookup: NOTIMP.
    #[error("query type {0} is not supported by the recursive resolver")]
    NotImplemented(u16),
    /// The answer chain is deeper than the configured limit: SERVFAIL.
    #[error("CNAME chain exceeds max_cname_depth")]
    DepthExceeded,
}

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

/// The Hickory resolver constructors take whole seconds; runtime values are
/// `Duration`s. Saturate rather than wrap.
fn duration_secs(duration: std::time::Duration) -> u64 {
    duration.as_secs()
}

pub struct CircuitBreaker {
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: AtomicU64,
    failure_threshold: u32,
    recovery_timeout_secs: u64,
    success_threshold: u32,
}

impl CircuitBreaker {
    pub fn new(config: &crate::runtime_config::CircuitBreakerRuntimeConfig) -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
            failure_threshold: config.failure_threshold,
            recovery_timeout_secs: config.recovery_timeout.as_secs(),
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
    config: RecursiveRuntimeConfig,
    resolver: Arc<dyn DnsResolver>,
    cache: RecursiveDnsCache,
    rate_limiter: Option<Arc<DnsRateLimiter>>,
    firewall: Option<Arc<RwLock<DnsFirewall>>>,
    metrics: Option<Arc<DnsMetrics>>,
    query_semaphore: Arc<Semaphore>,
    running: Arc<tokio::sync::RwLock<bool>>,
    circuit_breaker: Arc<CircuitBreaker>,
    client_semaphores: Arc<parking_lot::Mutex<HashMap<IpAddr, ClientSemaphoreEntry>>>,
    /// Keys with a background refresh already in flight, so a stale-hit storm
    /// cannot spawn one upstream query per client.
    refresh_in_flight: Arc<parking_lot::Mutex<HashSet<RecursiveCacheKey>>>,
}

/// One per-client concurrency slot, with the tick it was last used at so
/// exhaustion can evict the least-recently-used client instead of failing
/// closed for a new one.
struct ClientSemaphoreEntry {
    semaphore: Arc<Semaphore>,
    last_used: u64,
}

const MAX_CLIENT_SEMAPHORES: usize = 10_000;

impl RecursiveDnsServer {
    /// The per-client concurrency slot for `client_ip`.
    ///
    /// The table is bounded; when it is full the least-recently-used client is
    /// evicted so a new client is never silently refused admission.
    fn client_semaphore(
        &self,
        client_ip: IpAddr,
        max_per_client: usize,
        tick: u64,
    ) -> Arc<Semaphore> {
        let mut map = self.client_semaphores.lock();
        if let Some(entry) = map.get_mut(&client_ip) {
            entry.last_used = tick;
            return entry.semaphore.clone();
        }

        if map.len() >= MAX_CLIENT_SEMAPHORES {
            if let Some(lru_ip) = map
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(ip, _)| *ip)
            {
                map.remove(&lru_ip);
            }
        }

        let semaphore = Arc::new(Semaphore::new(max_per_client));
        map.insert(
            client_ip,
            ClientSemaphoreEntry {
                semaphore: semaphore.clone(),
                last_used: tick,
            },
        );
        semaphore
    }

    pub async fn new(
        config: RecursiveRuntimeConfig,
        rate_limiter: Option<Arc<DnsRateLimiter>>,
        firewall: Option<Arc<RwLock<DnsFirewall>>>,
        metrics: Option<Arc<DnsMetrics>>,
    ) -> RecursiveDnsResult<Self> {
        Self::new_with_global_nodes(config, rate_limiter, firewall, metrics, vec![]).await
    }

    pub async fn new_with_global_nodes(
        config: RecursiveRuntimeConfig,
        rate_limiter: Option<Arc<DnsRateLimiter>>,
        firewall: Option<Arc<RwLock<DnsFirewall>>>,
        metrics: Option<Arc<DnsMetrics>>,
        global_node_ips: Vec<IpAddr>,
    ) -> RecursiveDnsResult<Self> {
        let resolver = Self::create_resolver(&config, &global_node_ips)?;
        Ok(Self::with_resolver(
            config,
            resolver,
            rate_limiter,
            firewall,
            metrics,
        ))
    }

    /// Build a server around an already-constructed resolver.
    ///
    /// The resolver is a constructor input so a test (or a caller that owns a
    /// different upstream strategy) can inject one without a real network.
    pub fn with_resolver(
        config: RecursiveRuntimeConfig,
        resolver: Arc<dyn DnsResolver>,
        rate_limiter: Option<Arc<DnsRateLimiter>>,
        firewall: Option<Arc<RwLock<DnsFirewall>>>,
        metrics: Option<Arc<DnsMetrics>>,
    ) -> Self {
        let cache = RecursiveDnsCache::new(config.cache.capacity, &config.cache);
        let query_semaphore = Arc::new(Semaphore::new(config.max_concurrent_queries));
        let circuit_breaker = Arc::new(CircuitBreaker::new(&config.circuit_breaker));

        Self {
            config,
            resolver,
            cache,
            rate_limiter,
            firewall,
            metrics,
            query_semaphore,
            running: Arc::new(tokio::sync::RwLock::new(false)),
            circuit_breaker,
            client_semaphores: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            refresh_in_flight: Arc::new(parking_lot::Mutex::new(HashSet::new())),
        }
    }

    fn create_resolver(
        config: &RecursiveRuntimeConfig,
        global_node_ips: &[IpAddr],
    ) -> RecursiveDnsResult<Arc<dyn DnsResolver>> {
        // Every branch either builds an explicit resolver or fails startup.
        // There is no "empty list means the system resolver" path: that is what
        // silently moved an operator's queries to a different server.
        let resolver: Arc<dyn DnsResolver> = match &config.upstream {
            RecursiveUpstreamRuntime::Recursive {
                root_hints,
                trust_anchor,
            } => {
                tracing::info!(
                    "Configuring true recursive resolver with root hints: {}, static trust anchors: {}",
                    root_hints.display(),
                    trust_anchor.display()
                );
                Arc::new(
                    HickoryRecursor::from_paths(
                        root_hints,
                        trust_anchor,
                        config.dnssec_validation,
                        RecursorLimits {
                            recursion_limit: config.max_recursion_depth,
                        },
                    )
                    .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                )
            }
            RecursiveUpstreamRuntime::GlobalNodes => {
                if global_node_ips.is_empty() {
                    return Err(RecursiveDnsError::UpstreamFailed(
                        "upstream_provider = GlobalNodes requires at least one mesh global node; \
                         refusing to fall back to the system resolver"
                            .to_string(),
                    ));
                }
                for ip in global_node_ips {
                    tracing::info!("Recursive upstream: {}:{} (provider: GlobalNodes)", ip, 53);
                }
                Arc::new(
                    GlobalNodeResolver::new(global_node_ips.to_vec())
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                )
            }
            RecursiveUpstreamRuntime::Google => {
                tracing::warn!(
                    "Using Google DNS as upstream provider - DNSSEC validation is NOT performed. \
                     Set upstream_provider='Recursive' to enable DNSSEC validation."
                );
                for ip in [
                    "8.8.8.8",
                    "8.8.4.4",
                    "2001:4860:4860::8888",
                    "2001:4860:4860::8844",
                ] {
                    tracing::info!("Recursive upstream: {}:53 (provider: Google)", ip);
                }
                Arc::new(
                    HickoryResolver::with_google(duration_secs(config.query_timeout))
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                )
            }
            RecursiveUpstreamRuntime::Cloudflare => {
                tracing::warn!(
                    "Using Cloudflare DNS as upstream provider - DNSSEC validation is NOT performed. \
                     Set upstream_provider='Recursive' to enable DNSSEC validation."
                );
                for ip in [
                    "1.1.1.1",
                    "1.0.0.1",
                    "2606:4700:4700::1111",
                    "2606:4700:4700::1001",
                ] {
                    tracing::info!("Recursive upstream: {}:53 (provider: Cloudflare)", ip);
                }
                Arc::new(
                    HickoryResolver::with_cloudflare(duration_secs(config.query_timeout))
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                )
            }
            RecursiveUpstreamRuntime::System => {
                tracing::info!(
                    "Recursive upstream: host resolver configuration (provider: System)"
                );
                Arc::new(
                    HickoryResolver::from_system_config()
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                )
            }
            RecursiveUpstreamRuntime::CustomEndpoints(endpoints) => {
                let mut upstreams = Vec::with_capacity(endpoints.len());
                for endpoint in endpoints {
                    match endpoint {
                        super::runtime_config::CustomUpstreamEndpoint::Literal { ip, port } => {
                            upstreams.push(UpstreamEndpoint::new(*ip, *port));
                        }
                        super::runtime_config::CustomUpstreamEndpoint::Hostname { host, port } => {
                            return Err(RecursiveDnsError::UpstreamFailed(format!(
                                "upstream '{host}:{port}' is a hostname with no resolved address; \
                                 configure its IP address (a hostname-only upstream list is not \
                                 silently replaced by the system resolver)"
                            )));
                        }
                    }
                }
                if upstreams.is_empty() {
                    return Err(RecursiveDnsError::UpstreamFailed(
                        "upstream_provider = Custom requires at least one upstream address; \
                         refusing to fall back to the system resolver"
                            .to_string(),
                    ));
                }
                for upstream in &upstreams {
                    tracing::info!("Recursive upstream: {} (provider: Custom)", upstream);
                }
                if config.qname_minimization {
                    Arc::new(
                        HickoryResolver::with_qname_minimization_endpoints(
                            &upstreams,
                            duration_secs(config.query_timeout),
                        )
                        .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                    )
                } else {
                    Arc::new(
                        HickoryResolver::with_upstream_endpoints(
                            &upstreams,
                            duration_secs(config.query_timeout),
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

        let socket = UdpSocket::bind(self.config.bind_address)
            .await
            .map_err(|e| {
                RecursiveDnsError::UpstreamFailed(format!("Failed to bind socket: {}", e))
            })?;

        info!(
            "Starting recursive DNS server on {}",
            self.config.bind_address
        );

        // Forwarder-mode truthfulness: only true recursion performs local DNSSEC
        // validation. The runtime projection records that fact, so the warning
        // cannot drift away from the resolver that was actually built.
        if self.config.dnssec_validation && !self.config.performs_local_dnssec_validation {
            tracing::warn!(
                "DNSSEC validation is enabled but forwarder mode ({:?}) does not perform validation. \
                Upstream servers are trusted to validate DNSSEC. For validated lookups, \
                configure 'recursive' as the upstream provider.",
                self.config.upstream
            );
        }

        let server = self.clone();
        let socket = Arc::new(socket);
        let socket_clone = socket.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            loop {
                if !*server.running.read().await {
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
            }

            info!("Recursive DNS server stopped");
        });

        let tcp_server = self.clone();
        let tcp_addr = self.config.bind_address;
        tokio::spawn(async move {
            if let Err(e) = tcp_server.start_tcp_listener(tcp_addr).await {
                error!("TCP listener error: {}", e);
            }
        });

        Ok(())
    }

    async fn start_tcp_listener(&self, addr: SocketAddr) -> RecursiveDnsResult<()> {
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

    /// The per-client concurrency slot, or `None` when the client already holds
    /// its full allowance. Callers answer REFUSED rather than dropping.
    async fn client_permit(&self, client_ip: IpAddr) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let max_per_client = self.config.max_per_client_queries as usize;
        if max_per_client == 0 {
            return None;
        }

        let tick = next_client_tick();
        let semaphore = self.client_semaphore(client_ip, max_per_client, tick);
        match tokio::time::timeout(Duration::from_secs(1), semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => Some(permit),
            _ => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_rate_limited();
                }
                None
            }
        }
    }

    /// Client ACL, request rate limit, then firewall policy — in that order,
    /// and always before the cache is consulted so a blocked qname is never
    /// answered from a cached record.
    fn client_policy(&self, packet: &[u8], client_addr: SocketAddr, transport: &str) -> bool {
        if let Some(ref acl) = self.config.client_acl {
            if !acl.is_client_allowed(client_addr.ip()) {
                return false;
            }
        }

        if let Some(ref limiter) = self.rate_limiter {
            if limiter.check_ip(client_addr.ip()).is_err() {
                if let Some(metrics) = &self.metrics {
                    metrics.record_rate_limited();
                }
                return false;
            }
        }

        if let Some(ref firewall) = self.firewall {
            if let Ok(parsed_q) = ParsedDnsQuery::parse(packet) {
                let fw = firewall.read();
                // The qname argument is what a Domain rule matches; passing
                // an empty string here made every qname rule a no-op.
                if let Ok(decision) =
                    fw.evaluate_query(&parsed_q, client_addr.ip(), &parsed_q.qname)
                {
                    if decision.action == crate::firewall::DnsFirewallAction::Block {
                        if let Some(metrics) = &self.metrics {
                            metrics.record_firewall_blocked(transport);
                        }
                        return false;
                    }
                }
            }
        }

        true
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

        let _client_permit = match self.client_permit(client_addr.ip()).await {
            Some(permit) => Some(permit),
            None if self.config.max_per_client_queries > 0 => {
                self.write_tcp_rcode(&mut stream, &query, RCODE_REFUSED)
                    .await;
                return Ok(());
            }
            None => None,
        };

        if !self.client_policy(&query, client_addr, "recursive_tcp") {
            self.write_tcp_rcode(&mut stream, &query, RCODE_REFUSED)
                .await;
            return Ok(());
        }

        let question = match question_parts(&query) {
            Some(parts) => parts,
            None => return Err(RecursiveDnsError::InvalidQuery),
        };

        let parsed = match parse_dns_message(&query) {
            Ok(p) => p,
            Err(_) => return Err(RecursiveDnsError::InvalidQuery),
        };

        let (response, _) = match self.resolve_query(&parsed, question.message_id).await {
            Ok(response) => response,
            Err(e) => {
                let servfail = self.build_rcode_response(
                    question.message_id,
                    &question.qname_wire,
                    question.qtype,
                    RCODE_SERVFAIL,
                    question.checking_disabled,
                    question.dnssec_ok,
                );
                let len = servfail.len() as u16;
                let mut framed = len.to_be_bytes().to_vec();
                framed.extend_from_slice(&servfail);
                if let Err(write_err) = stream.write_all(&framed).await {
                    tracing::warn!("Failed to send SERVFAIL response: {}", write_err);
                }
                return Err(e);
            }
        };

        let authority_ns = self.collect_authority_ns(&question.qname).await;
        if !validate_authority_bailiwick(&authority_ns, question.qname.as_bytes()) {
            warn!(
                "Bailiwick violation: authority NS records not in-bailiwick for {}",
                question.qname
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
            metrics.record_response_sent(rcode_name(&response));
        }

        Ok(())
    }

    /// Write one length-prefixed rcode response on a TCP stream.
    async fn write_tcp_rcode(&self, stream: &mut TcpStream, query: &[u8], rcode: u8) {
        let Some(question) = question_parts(query) else {
            return;
        };
        let response = self.build_rcode_response(
            question.message_id,
            &question.qname_wire,
            question.qtype,
            rcode,
            question.checking_disabled,
            question.dnssec_ok,
        );
        let len = response.len() as u16;
        let mut framed = len.to_be_bytes().to_vec();
        framed.extend_from_slice(&response);
        if let Err(e) = stream.write_all(&framed).await {
            tracing::warn!("Failed to send rcode {} response: {}", rcode, e);
        }
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

        let query = match parse_dns_message(&packet) {
            Ok(q) => q,
            Err(_) => return Err(RecursiveDnsError::InvalidQuery),
        };

        if let Some(metrics) = &self.metrics {
            metrics.record_query_received();
        }

        let question = match question_parts(&packet) {
            Some(parts) => parts,
            None => return Err(RecursiveDnsError::InvalidQuery),
        };

        let _client_permit = match self.client_permit(client_addr.ip()).await {
            Some(permit) => Some(permit),
            None if self.config.max_per_client_queries > 0 => {
                self.send_udp_rcode(&socket, client_addr, &question, RCODE_REFUSED)
                    .await;
                return Ok(());
            }
            None => None,
        };

        if !self.client_policy(&packet, client_addr, "recursive") {
            self.send_udp_rcode(&socket, client_addr, &question, RCODE_REFUSED)
                .await;
            return Ok(());
        }

        let (response, _) = match self.resolve_query(&query, question.message_id).await {
            Ok(response) => response,
            Err(e) => {
                self.send_udp_rcode(&socket, client_addr, &question, RCODE_SERVFAIL)
                    .await;
                return Err(e);
            }
        };

        socket
            .send_to(&response, client_addr)
            .await
            .map_err(|e| RecursiveDnsError::UpstreamFailed(format!("Send failed: {}", e)))?;

        if let Some(metrics) = &self.metrics {
            metrics.record_response_sent(rcode_name(&response));
        }

        Ok(())
    }

    async fn send_udp_rcode(
        &self,
        socket: &UdpSocket,
        client_addr: SocketAddr,
        question: &QuestionParts,
        rcode: u8,
    ) {
        let response = self.build_rcode_response(
            question.message_id,
            &question.qname_wire,
            question.qtype,
            rcode,
            question.checking_disabled,
            question.dnssec_ok,
        );
        let _ = socket.send_to(&response, client_addr).await;
    }

    async fn resolve_query(
        &self,
        query: &Message,
        message_id: u16,
    ) -> RecursiveDnsResult<(Vec<u8>, DnssecValidationState)> {
        if query.queries.is_empty() {
            return Err(RecursiveDnsError::InvalidQuery);
        }

        let question = &query.queries[0];
        // Presentation form is only a resolver and cache input.
        let qname = question.name().to_string();
        // Parsed wire form of the question name: this is what the response
        // echoes and what every cached owner name is built from.
        let qname_wire = question
            .name()
            .to_bytes()
            .map_err(|_| RecursiveDnsError::InvalidQuery)?;
        let qtype = question.query_type();
        let qtype_u16: u16 = qtype.into();

        let checking_disabled = query.metadata.checking_disabled;
        let dnssec_ok = query.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);

        debug!("Recursive query for {} (type {:?})", question.name(), qtype);

        // IN only, matching the authoritative admission gate. A CHAOS/HS query
        // must not enter an IN cache under the same name and type.
        if question.query_class() != hickory_proto::rr::DNSClass::IN {
            return Ok((
                self.build_rcode_response(
                    message_id,
                    &qname_wire,
                    qtype_u16,
                    RCODE_NOTIMP,
                    checking_disabled,
                    dnssec_ok,
                ),
                DnssecValidationState::Unchecked,
            ));
        }

        // No ECS option is parsed from the request, so no subnet is forwarded
        // and the key carries none. When forwarding lands, the subnet actually
        // sent upstream is what belongs in the key.
        let client_subnet = evaluate_ecs_forwarding_policy(&self.config.ecs.policy, &None)
            .map(|subnet| subnet.address);
        let cache_key = RecursiveCacheKey::with_flags(
            qname.as_bytes(),
            qtype_u16,
            client_subnet,
            dnssec_ok,
            checking_disabled,
        );

        // ANY has no upstream lookup of its own: an ANY query is answered from
        // data this resolver already holds, or with NOTIMP.
        if qtype == RecordType::ANY {
            return Ok(match self.cache.lookup(&cache_key) {
                CacheLookup::Fresh(hit) => {
                    if let Some(metrics) = &self.metrics {
                        metrics.record_recursive_cache_hit();
                        metrics.record_cache_hit();
                    }
                    let (response, state) = self.build_cached_answer(
                        message_id,
                        &qname_wire,
                        qtype_u16,
                        hit,
                        checking_disabled,
                        dnssec_ok,
                    );
                    (response, state)
                }
                CacheLookup::Stale(_) | CacheLookup::Miss => (
                    self.build_rcode_response(
                        message_id,
                        &qname_wire,
                        qtype_u16,
                        RCODE_NOTIMP,
                        checking_disabled,
                        dnssec_ok,
                    ),
                    DnssecValidationState::Unchecked,
                ),
            });
        }

        match self.cache.lookup(&cache_key) {
            CacheLookup::Fresh(hit) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_recursive_cache_hit();
                    metrics.record_cache_hit();
                }
                Ok(self.build_cached_answer(
                    message_id,
                    &qname_wire,
                    qtype_u16,
                    hit,
                    checking_disabled,
                    dnssec_ok,
                ))
            }
            CacheLookup::Stale(hit) => {
                // RFC 8767 §3: expired data is a fallback, so the upstream is
                // always tried first.
                match self
                    .resolve_and_cache(&qname, &qname_wire, qtype, checking_disabled, &cache_key)
                    .await
                {
                    Ok(answer) => {
                        if let Some(metrics) = &self.metrics {
                            metrics.record_cache_miss();
                            metrics.record_recursive_cache_miss();
                        }
                        Ok(self.build_answer_set(
                            message_id,
                            &qname_wire,
                            qtype_u16,
                            &answer,
                            checking_disabled,
                            dnssec_ok,
                        ))
                    }
                    Err(error) => {
                        if let Some(metrics) = &self.metrics {
                            metrics.record_cache_stale_hit();
                        }
                        debug!(
                            "Serving stale answer for {} after upstream failure: {}",
                            qname, error
                        );
                        self.schedule_refresh(
                            cache_key,
                            qname,
                            qname_wire.clone(),
                            qtype,
                            checking_disabled,
                        );
                        Ok(self.build_stale_answer(
                            message_id,
                            &qname_wire,
                            qtype_u16,
                            hit,
                            checking_disabled,
                            dnssec_ok,
                        ))
                    }
                }
            }
            CacheLookup::Miss => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_cache_miss();
                    metrics.record_recursive_cache_miss();
                }
                match self
                    .resolve_and_cache(&qname, &qname_wire, qtype, checking_disabled, &cache_key)
                    .await
                {
                    Ok(answer) => Ok(self.build_answer_set(
                        message_id,
                        &qname_wire,
                        qtype_u16,
                        &answer,
                        checking_disabled,
                        dnssec_ok,
                    )),
                    Err(ResolveError::NotImplemented(record_type)) => {
                        debug!(
                            "Recursive resolver does not implement qtype {} for {}",
                            record_type, qname
                        );
                        Ok((
                            self.build_rcode_response(
                                message_id,
                                &qname_wire,
                                qtype_u16,
                                RCODE_NOTIMP,
                                checking_disabled,
                                dnssec_ok,
                            ),
                            DnssecValidationState::Unchecked,
                        ))
                    }
                    Err(error) => Err(match error {
                        ResolveError::DepthExceeded => RecursiveDnsError::DepthExceeded,
                        ResolveError::CircuitBreakerOpen => RecursiveDnsError::CircuitBreakerOpen,
                        other => RecursiveDnsError::UpstreamFailed(other.to_string()),
                    }),
                }
            }
        }
    }

    /// Resolve one query upstream and store it if it is cacheable.
    ///
    /// Only an `AnswerSet` reaches the cache: a `ResolveError` returns before
    /// any insert, so a timeout or a validation failure can never be read back
    /// as NODATA.
    async fn resolve_and_cache(
        &self,
        qname: &str,
        qname_wire: &[u8],
        qtype: RecordType,
        checking_disabled: bool,
        cache_key: &RecursiveCacheKey,
    ) -> Result<AnswerSet, ResolveError> {
        let answer = self
            .resolve_upstream(qname, qname_wire, qtype, checking_disabled)
            .await?;
        self.store_answer(cache_key, &answer);
        Ok(answer)
    }

    fn store_answer(&self, cache_key: &RecursiveCacheKey, answer: &AnswerSet) {
        if answer.is_negative() {
            // Without an SOA there is no negative TTL to honour, so the answer
            // is served but not cached (RFC 2308 §5).
            let negative_ttl = answer.negative_ttl.unwrap_or(0);
            self.cache.insert_negative(
                cache_key.clone(),
                answer.rcode == RCODE_NXDOMAIN,
                negative_ttl,
                answer.validation_state,
            );
            return;
        }

        let ttl = answer.records.iter().map(|r| r.ttl).min().unwrap_or(0);
        self.cache.insert_positive(
            cache_key.clone(),
            answer.records.clone(),
            ttl,
            answer.validation_state,
        );
    }

    /// Refresh an expired entry in the background after a stale answer.
    fn schedule_refresh(
        &self,
        cache_key: RecursiveCacheKey,
        qname: String,
        qname_wire: Vec<u8>,
        qtype: RecordType,
        checking_disabled: bool,
    ) {
        {
            let mut in_flight = self.refresh_in_flight.lock();
            if !in_flight.insert(cache_key.clone()) {
                // One refresh per entry: a stale-hit storm must not fan out
                // into one upstream query per client.
                return;
            }
        }

        let server = self.clone();
        let key = cache_key.clone();
        tokio::spawn(async move {
            let _ = server
                .resolve_and_cache(&qname, &qname_wire, qtype, checking_disabled, &key)
                .await;
            server.refresh_in_flight.lock().remove(&key);
        });
    }

    /// One upstream lookup. `dnssec_ok` is deliberately absent: the DO bit
    /// decides which records the response may carry, not which records the
    /// resolver asks for, and a validating recursor always requests DNSSEC data.
    async fn resolve_upstream(
        &self,
        qname: &str,
        qname_wire: &[u8],
        qtype: RecordType,
        checking_disabled: bool,
    ) -> Result<AnswerSet, ResolveError> {
        if self.circuit_breaker.is_open() {
            if let Some(metrics) = &self.metrics {
                metrics.record_recursive_upstream_failure();
            }
            return Err(ResolveError::CircuitBreakerOpen);
        }

        let qtype_u16: u16 = qtype.into();
        if !is_supported_qtype(qtype_u16) {
            return Err(ResolveError::NotImplemented(qtype_u16));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_recursive_upstream_forward();
        }

        let rrset = match self.resolver.lookup_rrset(qname, qtype_u16).await {
            Ok(rrset) => {
                self.circuit_breaker.record_success();
                rrset
            }
            Err(super::resolver::ResolverError::Unsupported(record_type)) => {
                return Err(ResolveError::NotImplemented(record_type));
            }
            Err(super::resolver::ResolverError::Bogus(reason)) => {
                self.circuit_breaker.record_failure();
                if let Some(metrics) = &self.metrics {
                    metrics.record_recursive_upstream_failure();
                }
                return Err(ResolveError::Bogus(reason));
            }
            Err(error) => {
                self.circuit_breaker.record_failure();
                if let Some(metrics) = &self.metrics {
                    metrics.record_recursive_upstream_failure();
                }
                return Err(ResolveError::Upstream(error.to_string()));
            }
        };

        let records: Vec<CachedRecord> = rrset
            .records
            .iter()
            .filter_map(|record| cached_record(qname_wire, record))
            .collect();

        // A recursive answer may carry aliases; the configured cap applies to
        // the chain the client would have to follow.
        let aliases = records.iter().filter(|r| r.record_type == 5).count();
        if self.config.max_cname_depth > 0 && aliases > usize::from(self.config.max_cname_depth) {
            return Err(ResolveError::DepthExceeded);
        }

        let validation_state = to_validation_state(
            rrset.is_dnssec_validated,
            checking_disabled,
            !self.config.dnssec_validation,
        );

        Ok(AnswerSet {
            records,
            rcode: rrset.rcode,
            negative_ttl: rrset.negative_ttl,
            validation_state,
        })
    }

    fn build_answer_set(
        &self,
        message_id: u16,
        qname_wire: &[u8],
        qtype_u16: u16,
        answer: &AnswerSet,
        checking_disabled: bool,
        dnssec_ok: bool,
    ) -> (Vec<u8>, DnssecValidationState) {
        (
            self.build_response(
                message_id,
                qname_wire,
                qtype_u16,
                answer.records.clone(),
                answer.rcode,
                answer.validation_state,
                checking_disabled,
                dnssec_ok,
            ),
            answer.validation_state,
        )
    }

    fn build_cached_answer(
        &self,
        message_id: u16,
        qname_wire: &[u8],
        qtype_u16: u16,
        hit: CacheHit,
        checking_disabled: bool,
        dnssec_ok: bool,
    ) -> (Vec<u8>, DnssecValidationState) {
        (
            self.build_response(
                message_id,
                qname_wire,
                qtype_u16,
                hit.records,
                hit.rcode,
                hit.validation_state,
                checking_disabled,
                dnssec_ok,
            ),
            hit.validation_state,
        )
    }

    /// Build the stale answer: the cached records with the RFC 8767 TTL.
    fn build_stale_answer(
        &self,
        message_id: u16,
        qname_wire: &[u8],
        qtype_u16: u16,
        hit: CacheHit,
        checking_disabled: bool,
        dnssec_ok: bool,
    ) -> (Vec<u8>, DnssecValidationState) {
        let records = hit
            .records
            .into_iter()
            .map(|record| CachedRecord {
                ttl: STALE_SERVE_TTL,
                ..record
            })
            .collect();
        (
            self.build_response(
                message_id,
                qname_wire,
                qtype_u16,
                records,
                hit.rcode,
                hit.validation_state,
                checking_disabled,
                dnssec_ok,
            ),
            hit.validation_state,
        )
    }

    /// Build a header + question + rcode response with no answer records.
    fn build_rcode_response(
        &self,
        message_id: u16,
        qname_wire: &[u8],
        qtype_u16: u16,
        rcode: u8,
        checking_disabled: bool,
        dnssec_ok: bool,
    ) -> Vec<u8> {
        self.build_response(
            message_id,
            qname_wire,
            qtype_u16,
            Vec::new(),
            rcode,
            DnssecValidationState::Unchecked,
            checking_disabled,
            dnssec_ok,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_response(
        &self,
        message_id: u16,
        qname_wire: &[u8],
        qtype_u16: u16,
        records: Vec<CachedRecord>,
        rcode: u8,
        validation_state: DnssecValidationState,
        checking_disabled: bool,
        dnssec_ok: bool,
    ) -> Vec<u8> {
        let effective_dnssec_validated =
            validation_state == DnssecValidationState::Secure && !checking_disabled;
        let ad_bit = effective_dnssec_validated && dnssec_ok;

        let qdcount = 1u16;
        let ancount = records.len() as u16;

        let question_section = self.build_question_section(qname_wire, qtype_u16);

        let mut answer_sections = Vec::with_capacity(records.len());
        for record in &records {
            answer_sections.push(self.build_answer_record(record));
        }

        let header_size = 12;
        let question_size = question_section.len();
        let answer_size = answer_sections.iter().map(|s| s.len()).sum::<usize>();
        let total_size = header_size + question_size + answer_size;

        let flags_for = |truncated: bool| crate::wire::MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: false,
            truncated,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: ad_bit,
            checking_disabled,
            response_code: rcode,
        };

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

            let mut full_response = build_response_header(
                message_id,
                flags_for(true),
                qdcount,
                truncated_ancount,
                0,
                0,
            );
            full_response.extend_from_slice(&question_section);
            full_response.extend_from_slice(&final_response);
            return full_response;
        }

        let mut final_response =
            build_response_header(message_id, flags_for(false), qdcount, ancount, 0, 0);
        final_response.extend_from_slice(&question_section);
        for answer in answer_sections {
            final_response.extend_from_slice(&answer);
        }

        final_response
    }

    /// Build the question section from an **encoded** wire name.
    ///
    /// `qname_wire` is `wire::encode_owner(relative, origin)` (or the parsed
    /// request name re-emitted as wire bytes). Appending the presentation-form
    /// string here made the first label length read the ASCII `'e'` of
    /// `example.com`, so no client could parse the response.
    fn build_question_section(&self, qname_wire: &[u8], qtype: u16) -> Vec<u8> {
        let mut section = Vec::with_capacity(qname_wire.len() + 5);

        if qname_wire.is_empty() {
            section.push(0);
        } else {
            section.extend_from_slice(qname_wire);
            if !section.ends_with(&[0]) {
                section.push(0);
            }
        }

        section.extend_from_slice(&qtype.to_be_bytes());
        section.extend_from_slice(&1u16.to_be_bytes());

        section
    }

    /// Build an answer record. `record.name` must already be wire bytes.
    fn build_answer_record(&self, record: &CachedRecord) -> Vec<u8> {
        let mut section = Vec::new();

        if record.name.is_empty() {
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

    async fn collect_authority_ns(&self, qname: &str) -> Vec<String> {
        if let Ok(ns) = self.resolver.lookup_ns(qname).await {
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
            refresh_in_flight: self.refresh_in_flight.clone(),
        }
    }
}

/// The question fields a response needs, read straight from the packet.
struct QuestionParts {
    message_id: u16,
    /// Presentation form, for the resolver and the bailiwick check.
    qname: String,
    /// Parsed wire form, for the echoed question and every cached owner.
    qname_wire: Vec<u8>,
    qtype: u16,
    checking_disabled: bool,
    dnssec_ok: bool,
}

fn question_parts(packet: &[u8]) -> Option<QuestionParts> {
    let message = parse_dns_message(packet).ok()?;
    let question = message.queries.first()?;
    Some(QuestionParts {
        message_id: get_message_id(packet).unwrap_or(0),
        qname: question.name().to_string(),
        qname_wire: question.name().to_bytes().ok()?,
        qtype: question.query_type().into(),
        checking_disabled: message.metadata.checking_disabled,
        dnssec_ok: message.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
    })
}

static CLIENT_TICK: AtomicU64 = AtomicU64::new(0);

fn next_client_tick() -> u64 {
    CLIENT_TICK.fetch_add(1, Ordering::Relaxed)
}

/// Record types the recursive resolver answers with a real upstream lookup.
///
/// Everything else is NOTIMP: answering an unimplemented type with an empty
/// NOERROR would tell a client "no such data" when the resolver never asked.
fn is_supported_qtype(record_type: u16) -> bool {
    matches!(
        record_type,
        1     // A
        | 2   // NS
        | 5   // CNAME
        | 6   // SOA
        | 12  // PTR
        | 15  // MX
        | 16  // TXT
        | 28  // AAAA
        | 33  // SRV
        | 35  // NAPTR
        | 43  // DS
        | 48 // DNSKEY
    )
}

/// Encode one resolved record as a cache entry.
///
/// The owner is the queried name in wire form and every name inside RDATA is
/// encoded by the same owner encoder, so no field of the answer can be
/// presentation ASCII.
fn cached_record(qname_wire: &[u8], record: &ResolvedRecord) -> Option<CachedRecord> {
    let (record_type, ttl, data) = match record {
        ResolvedRecord::Address { ip, ttl } => match ip {
            IpAddr::V4(v4) => (1u16, *ttl, v4.octets().to_vec()),
            IpAddr::V6(v6) => (28u16, *ttl, v6.octets().to_vec()),
        },
        ResolvedRecord::Cname { target, ttl } => (5, *ttl, encode_domain_to_wire(target)),
        ResolvedRecord::Ns { target, ttl } => (2, *ttl, encode_domain_to_wire(target)),
        ResolvedRecord::Mx {
            exchange,
            preference,
            ttl,
        } => {
            let mut data = Vec::new();
            data.extend_from_slice(&preference.to_be_bytes());
            data.extend_from_slice(&encode_domain_to_wire(exchange));
            (15, *ttl, data)
        }
        ResolvedRecord::Txt { value, ttl } => (16, *ttl, encode_character_strings(value)),
        ResolvedRecord::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ttl,
        } => {
            let mut data = Vec::new();
            data.extend_from_slice(&encode_domain_to_wire(mname));
            data.extend_from_slice(&encode_domain_to_wire(rname));
            data.extend_from_slice(&serial.to_be_bytes());
            data.extend_from_slice(&(*refresh as u32).to_be_bytes());
            data.extend_from_slice(&(*retry as u32).to_be_bytes());
            data.extend_from_slice(&(*expire as u32).to_be_bytes());
            data.extend_from_slice(&minimum.to_be_bytes());
            (6, *ttl, data)
        }
        ResolvedRecord::Ptr { target, ttl } => (12, *ttl, encode_domain_to_wire(target)),
        ResolvedRecord::Srv {
            priority,
            weight,
            port,
            target,
            ttl,
        } => {
            let mut data = Vec::new();
            data.extend_from_slice(&priority.to_be_bytes());
            data.extend_from_slice(&weight.to_be_bytes());
            data.extend_from_slice(&port.to_be_bytes());
            data.extend_from_slice(&encode_domain_to_wire(target));
            (33, *ttl, data)
        }
        ResolvedRecord::Naptr {
            order,
            preference,
            flags,
            service,
            regexp,
            replacement,
            ttl,
        } => {
            let mut data = Vec::new();
            data.extend_from_slice(&order.to_be_bytes());
            data.extend_from_slice(&preference.to_be_bytes());
            data.extend_from_slice(&encode_character_string(flags));
            data.extend_from_slice(&encode_character_string(service));
            data.extend_from_slice(&encode_character_string(regexp));
            data.extend_from_slice(&encode_domain_to_wire(replacement));
            (35, *ttl, data)
        }
        ResolvedRecord::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
            ttl,
        } => {
            let mut data = Vec::new();
            data.extend_from_slice(&key_tag.to_be_bytes());
            data.push(*algorithm);
            data.push(*digest_type);
            data.extend_from_slice(digest);
            (43, *ttl, data)
        }
        ResolvedRecord::Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
            ttl,
        } => {
            let mut data = Vec::new();
            data.extend_from_slice(&flags.to_be_bytes());
            data.push(*protocol);
            data.push(*algorithm);
            data.extend_from_slice(public_key);
            (48, *ttl, data)
        }
    };

    Some(CachedRecord {
        name: qname_wire.to_vec(),
        record_type,
        ttl,
        data,
    })
}

/// The metric label for a response: its rcode name.
fn rcode_name(response: &[u8]) -> &'static str {
    match response.get(3).map(|byte| byte & 0x0F) {
        Some(RCODE_NOERROR) => "NOERROR",
        Some(RCODE_NXDOMAIN) => "NXDOMAIN",
        Some(RCODE_NOTIMP) => "NOTIMP",
        Some(RCODE_REFUSED) => "REFUSED",
        Some(RCODE_SERVFAIL) => "SERVFAIL",
        _ => "NOERROR",
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

/// Encode a dotted domain name to DNS wire format (length-prefixed labels,
/// null-terminated).
///
/// Delegates to the campaign's single owner encoder so an RDATA name cannot be
/// written with a different set of rules than an owner name. A name the encoder
/// rejects (an upstream sent something malformed) becomes the root rather than
/// a partially-encoded name; the caller never emits an unparseable RDATA field.
fn encode_domain_to_wire(domain: &str) -> Vec<u8> {
    match crate::wire::encode_name(domain) {
        Ok(encoded) => encoded,
        Err(err) => {
            warn!("Refusing to encode malformed RDATA name {domain:?}: {err}");
            vec![0]
        }
    }
}

/// Encode one DNS character-string: a length octet followed by the bytes.
///
/// NAPTR carries three single character-strings (RFC 3403 §4.1), so a value
/// longer than 255 octets is malformed and is truncated rather than split —
/// splitting would turn one field into several and shift every field after it.
fn encode_character_string(value: &[u8]) -> Vec<u8> {
    let len = value.len().min(255);
    let mut encoded = Vec::with_capacity(len + 1);
    encoded.push(len as u8);
    encoded.extend_from_slice(&value[..len]);
    encoded
}

/// Encode a TXT value as one or more DNS character-strings (RFC 1035 §3.3.14).
///
/// Each character-string carries its own length octet and is at most 255
/// octets; a longer value is split, exactly as the authoritative encoder does.
/// Writing the raw bytes (the old behavior) made the first value byte look like
/// a length, so the RDATA did not parse.
fn encode_character_strings(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return vec![0];
    }
    let mut encoded = Vec::with_capacity(bytes.len() + bytes.len() / 255 + 2);
    for chunk in bytes.chunks(255) {
        encoded.push(chunk.len() as u8);
        encoded.extend_from_slice(chunk);
    }
    encoded
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
    policy: &RecursiveEcsPolicyRuntime,
    client_subnet: &Option<crate::edns::ClientSubnet>,
) -> Option<crate::edns::ClientSubnet> {
    match policy {
        RecursiveEcsPolicyRuntime::Never => None,
        RecursiveEcsPolicyRuntime::Always => client_subnet.clone(),
        RecursiveEcsPolicyRuntime::IfPresent => {
            if client_subnet.is_some() {
                client_subnet.clone()
            } else {
                None
            }
        }
        // CDN-range detection is not implemented, so the policy is absent by
        // design rather than silently forwarding (or silently dropping) a
        // client subnet.
        RecursiveEcsPolicyRuntime::CdnOnly => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursive_cache::RecursiveRecordType;

    fn create_test_cache() -> RecursiveDnsCache {
        let config = crate::runtime_config::test_fixtures::recursive_cache_runtime();
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

        let name = crate::wire::encode_owner("www", "example.com").unwrap();
        let section = server.build_question_section(&name, 1);

        // Byte-identical to the owner encoder: the question section is the
        // encoded name followed by QTYPE/QCLASS, never presentation ASCII.
        assert_eq!(
            &section[..name.len()],
            &crate::wire::encode_owner("www.example.com", "").unwrap()[..]
        );
        assert_eq!(&section[name.len()..], &[0x00, 0x01, 0x00, 0x01]);
        assert_eq!(
            crate::wire::parse_query_name(&section, 0).as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn test_build_question_section_root() {
        let server = create_mock_server();

        let section = server.build_question_section(&[0u8], 1);

        assert_eq!(section, vec![0, 0, 1, 0, 1]);
    }

    /// RDATA name fields are wire names, not presentation strings. Before this
    /// was fixed an NS or MX answer carried `ns1.example.com` as ASCII, so the
    /// first byte (`'n'` = 110) was read as a length.
    #[test]
    fn test_rdata_domain_names_are_wire_encoded() {
        let encoded = encode_domain_to_wire("ns1.example.com");
        assert_eq!(
            crate::wire::parse_query_name(&encoded, 0).as_deref(),
            Some("ns1.example.com")
        );
        // A malformed name must not produce a partially encoded field.
        assert_eq!(encode_domain_to_wire("bad..name"), vec![0]);
    }

    /// TXT is a sequence of length-prefixed character-strings. Writing the raw
    /// bytes made the first value byte look like a length.
    #[test]
    fn test_txt_rdata_is_length_prefixed() {
        assert_eq!(encode_character_strings("hello"), b"\x05hello".to_vec());
        assert_eq!(encode_character_strings(""), vec![0]);

        let long = "a".repeat(300);
        let encoded = encode_character_strings(&long);
        assert_eq!(encoded[0], 255);
        assert_eq!(encoded[256], 45);
        assert_eq!(encoded.len(), 2 + 300);
    }

    #[test]
    fn test_build_answer_record() {
        let server = create_mock_server();

        let name = crate::wire::encode_owner("www.example.com", "").unwrap();
        let record = create_test_record(&name, 1, 300, vec![93, 184, 216, 34]);
        let section = server.build_answer_record(&record);

        assert_eq!(
            crate::wire::parse_query_name(&section, 0).as_deref(),
            Some("www.example.com"),
            "answer owner must decode as a wire name"
        );

        assert!(section.len() > 20);
        let section_slice = &section[section.len() - 6..];
        let rdlen = u16::from_be_bytes([section_slice[0], section_slice[1]]);
        assert_eq!(rdlen, 4);
    }

    /// The wire name taken from a parsed request is exactly what
    /// `wire::encode_owner` produces, so the value stored in
    /// `CachedRecord.name` and echoed as the question are the same bytes.
    #[test]
    fn test_parsed_question_name_matches_owner_encoder() {
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234u16.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&crate::wire::encode_owner("WwW", "example.com").unwrap());
        query.extend_from_slice(&1u16.to_be_bytes()); // A
        query.extend_from_slice(&1u16.to_be_bytes()); // IN

        let message = parse_dns_message(&query).expect("query must parse");
        let wire = message.queries[0]
            .name()
            .to_bytes()
            .expect("parsed name must emit as wire bytes");

        // Case and labels survive: no presentation-form round trip.
        assert_eq!(
            wire,
            crate::wire::encode_owner("WwW.example.com", "").unwrap()
        );
        assert_eq!(
            crate::wire::parse_query_name(&wire, 0).as_deref(),
            Some("WwW.example.com")
        );
    }

    /// Explicit invariant on the cache-insert path: `CachedRecord.name` holds an
    /// encoded, absolute wire name (terminating root label, <= 255 octets), not
    /// the dotted presentation form.
    #[test]
    fn test_cached_record_name_is_encoded_wire_name() {
        for (relative, expected) in [
            ("www", "www.example.com"),
            ("a.b", "a.b.example.com"),
            ("@", "example.com"),
        ] {
            let name = crate::wire::encode_owner(relative, "example.com").unwrap();

            assert_eq!(
                name.last(),
                Some(&0u8),
                "CachedRecord.name must be root-terminated: {relative:?}"
            );
            assert!(
                name.len() <= 255,
                "CachedRecord.name must fit the 255-octet name limit"
            );
            assert_ne!(
                name,
                relative.as_bytes().to_vec(),
                "CachedRecord.name must not hold presentation ASCII"
            );
            assert_eq!(
                crate::wire::parse_query_name(&name, 0).as_deref(),
                Some(expected),
                "CachedRecord.name must decode back to the queried FQDN"
            );
        }
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

        let mut config = crate::runtime_config::test_fixtures::recursive_runtime();
        config.query_timeout = std::time::Duration::from_secs(5);
        config.max_concurrent_queries = 100;

        RecursiveDnsServer {
            config,
            resolver: Arc::new(HickoryResolver::with_upstream_servers(&[upstream_ip], 5).unwrap()),
            cache: create_test_cache(),
            rate_limiter: None,
            firewall: None,
            metrics: None,
            query_semaphore: Arc::new(Semaphore::new(100)),
            running: Arc::new(tokio::sync::RwLock::new(false)),
            circuit_breaker: Arc::new(CircuitBreaker::new(
                &crate::runtime_config::test_fixtures::circuit_breaker_runtime(),
            )),
            client_semaphores: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            refresh_in_flight: Arc::new(parking_lot::Mutex::new(HashSet::new())),
        }
    }
}
