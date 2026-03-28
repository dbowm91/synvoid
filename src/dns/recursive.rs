//! Recursive DNS Server
//!
//! This module provides a recursive DNS resolver that can run alongside
//! the authoritative DNS server. It uses the hickory-resolver crate for
//! upstream recursive resolution.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dns_parser::Packet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::dns::RecursiveDnsConfig;
use crate::dns::firewall::DnsFirewall;
use crate::dns::metrics::DnsMetrics;
use parking_lot::RwLock;

use super::recursive_cache::{CachedRecord, RecursiveCacheKey, RecursiveDnsCache};
use super::resolver::{MxRecord, SrvRecord};
use super::wire::{
    build_error_response, build_response_header, get_message_id, parse_dns_message, RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
};
use super::{server::DnsRateLimiter, DnsResolver, HickoryRecursor, HickoryResolver};

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
}

pub type RecursiveDnsResult<T> = Result<T, RecursiveDnsError>;

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

impl RecursiveDnsServer {
    pub async fn new(
        config: RecursiveDnsConfig,
        rate_limiter: Option<Arc<DnsRateLimiter>>,
        firewall: Option<Arc<RwLock<DnsFirewall>>>,
        metrics: Option<Arc<DnsMetrics>>,
    ) -> RecursiveDnsResult<Self> {
        let resolver = Self::create_resolver(&config)?;
        let cache = RecursiveDnsCache::new(config.cache.capacity, &config.cache);
        let query_semaphore = Arc::new(Semaphore::new(config.max_concurrent_queries));

        Ok(Self {
            config,
            resolver,
            cache,
            rate_limiter,
            firewall,
            metrics,
            query_semaphore,
            running: Arc::new(tokio::sync::RwLock::new(false)),
        })
    }

    fn create_resolver(config: &RecursiveDnsConfig) -> RecursiveDnsResult<Arc<dyn DnsResolver>> {
        let resolver: Arc<dyn DnsResolver> = match config.upstream_provider {
            crate::config::dns::RecursiveUpstreamProvider::Recursive => {
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
            crate::config::dns::RecursiveUpstreamProvider::Google => Arc::new(
                HickoryResolver::with_google()
                    .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
            ),
            crate::config::dns::RecursiveUpstreamProvider::Cloudflare => Arc::new(
                HickoryResolver::with_cloudflare()
                    .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
            ),
            crate::config::dns::RecursiveUpstreamProvider::System | _ => {
                let upstream_ips = config.upstream_ips();
                if upstream_ips.is_empty() {
                    Arc::new(
                        HickoryResolver::from_system_config()
                            .map_err(|e| RecursiveDnsError::UpstreamFailed(e.to_string()))?,
                    )
                } else {
                    Arc::new(
                        HickoryResolver::with_upstream_servers(&upstream_ips)
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

        let mut length_buf = [0u8; 2];
        stream.read_exact(&mut length_buf).await.map_err(|e| {
            RecursiveDnsError::UpstreamFailed(format!("Failed to read TCP length: {}", e))
        })?;

        let len = u16::from_be_bytes(length_buf) as usize;

        if len > 65535 {
            return Err(RecursiveDnsError::UpstreamFailed(
                "TCP message too large".to_string(),
            ));
        }

        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await.map_err(|e| {
            RecursiveDnsError::UpstreamFailed(format!("Failed to read TCP query: {}", e))
        })?;

        if let Some(metrics) = &self.metrics {
            metrics.record_query_received();
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
            let mut fw = firewall.write();
            if let Ok(decision) = fw.evaluate_query(&query, client_addr.ip(), "") {
                if decision.action == crate::dns::firewall::DnsFirewallAction::Block {
                    if let Some(metrics) = &self.metrics {
                        metrics.record_firewall_blocked("recursive_tcp");
                    }
                    return Err(RecursiveDnsError::FirewallBlocked);
                }
            }
        }

        let message_id = get_message_id(&query).unwrap_or(0);

        let questions = match parse_dns_message(&query) {
            Ok(p) => p.questions,
            Err(_) => return Err(RecursiveDnsError::InvalidQuery),
        };

        if questions.is_empty() {
            return Err(RecursiveDnsError::InvalidQuery);
        }

        let question = &questions[0];
        let qname_str = question.qname.to_string();
        let qname_bytes = qname_str.as_bytes().to_vec();

        let (response, _) = match self
            .resolve_upstream(&qname_bytes, question.qtype, message_id)
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

        let query = match parse_dns_message(&packet) {
            Ok(q) => q,
            Err(_) => return Err(RecursiveDnsError::InvalidQuery),
        };

        if let Some(metrics) = &self.metrics {
            metrics.record_query_received();
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
            let mut fw = firewall.write();
            if let Ok(decision) = fw.evaluate_query(&packet, client_addr.ip(), "") {
                if decision.action == crate::dns::firewall::DnsFirewallAction::Block {
                    if let Some(metrics) = &self.metrics {
                        metrics.record_firewall_blocked("recursive");
                    }
                    return Err(RecursiveDnsError::FirewallBlocked);
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

    async fn resolve_query(
        &self,
        query: &Packet<'_>,
        message_id: u16,
    ) -> RecursiveDnsResult<Vec<u8>> {
        let questions = &query.questions;
        if questions.is_empty() {
            return Err(RecursiveDnsError::InvalidQuery);
        }

        let question = &questions[0];
        let qname_str = question.qname.to_string();
        let qname_bytes = qname_str.as_bytes().to_vec();
        let qtype = question.qtype;

        debug!("Recursive query for {} (type {:?})", question.qname, qtype);

        let qtype_u16: u16 = match question.qtype {
            dns_parser::QueryType::A => 1,
            dns_parser::QueryType::AAAA => 28,
            dns_parser::QueryType::TXT => 16,
            dns_parser::QueryType::NS => 2,
            dns_parser::QueryType::MX => 15,
            dns_parser::QueryType::CNAME => 5,
            dns_parser::QueryType::SOA => 6,
            dns_parser::QueryType::PTR => 12,
            dns_parser::QueryType::SRV => 33,
            dns_parser::QueryType::All => 255,
            _ => u16::MAX,
        };
        let cache_key = RecursiveCacheKey::new(&qname_bytes, qtype_u16, None);

        if let Some((records, stale, is_dnssec_validated)) = self.cache.get(&cache_key) {
            if let Some(metrics) = &self.metrics {
                if stale {
                    metrics.record_cache_hit();
                }
            }

            let response = self.build_cached_response(
                &qname_bytes,
                question.qtype,
                records,
                message_id,
                is_dnssec_validated,
            );
            return Ok(response);
        }

        let (response, _is_dnssec_validated) = self
            .resolve_upstream(&qname_bytes, question.qtype, message_id)
            .await?;

        if let Some(metrics) = &self.metrics {
            metrics.record_cache_miss();
        }

        Ok(response)
    }

    async fn resolve_upstream(
        &self,
        qname: &[u8],
        qtype: dns_parser::QueryType,
        message_id: u16,
    ) -> RecursiveDnsResult<(Vec<u8>, bool)> {
        let domain = String::from_utf8_lossy(qname).to_string();
        let mut is_dnssec_validated = false;

        let records = match qtype {
            dns_parser::QueryType::A | dns_parser::QueryType::AAAA => {
                match self.resolver.lookup_ip_with_ttl(&domain).await {
                    Ok(ip_record) => {
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
                                if qtype == dns_parser::QueryType::AAAA && record_type != 28 {
                                    return None;
                                }
                                if qtype == dns_parser::QueryType::A && record_type != 1 {
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
                    Err(_) => Vec::new(),
                }
            }
            dns_parser::QueryType::TXT => match self.resolver.lookup_txt(&domain).await {
                Ok(txt) => txt
                    .values
                    .into_iter()
                    .map(|v| CachedRecord {
                        name: qname.to_vec(),
                        record_type: 16,
                        ttl: txt.ttl.unwrap_or(300),
                        data: v.into_bytes(),
                    })
                    .collect(),
                Err(_) => Vec::new(),
            },
            dns_parser::QueryType::NS => match self.resolver.lookup_ns(&domain).await {
                Ok(ns) => ns
                    .nameservers
                    .into_iter()
                    .map(|ns_name| CachedRecord {
                        name: qname.to_vec(),
                        record_type: 2,
                        ttl: ns.ttl.unwrap_or(300),
                        data: ns_name.into_bytes(),
                    })
                    .collect(),
                Err(_) => Vec::new(),
            },
            dns_parser::QueryType::MX => match self.resolver.lookup_mx(&domain).await {
                Ok(mx_records) => mx_records
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
                    .collect(),
                Err(_) => Vec::new(),
            },
            dns_parser::QueryType::CNAME => match self.resolver.lookup_cname(&domain).await {
                Ok(Some(cname_record)) => {
                    let mut cname_bytes = cname_record.cname.into_bytes();
                    if !cname_bytes.is_empty() && cname_bytes.last() != Some(&b'.') {
                        cname_bytes.push(b'.');
                    }
                    vec![CachedRecord {
                        name: qname.to_vec(),
                        record_type: 5,
                        ttl: cname_record.ttl.unwrap_or(300),
                        data: cname_bytes,
                    }]
                }
                Ok(None) => Vec::new(),
                Err(_) => Vec::new(),
            },
            dns_parser::QueryType::SOA => match self.resolver.lookup_soa(&domain).await {
                Ok(Some(soa)) => {
                    let ttl = soa.ttl.unwrap_or(300);
                    let mut data = Vec::new();
                    data.extend_from_slice(soa.mname.as_bytes());
                    data.push(0);
                    data.extend_from_slice(soa.rname.as_bytes());
                    data.push(0);
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
            dns_parser::QueryType::PTR => match self.resolver.lookup_ptr(&domain).await {
                Ok(Some(ptr)) => {
                    let ttl = ptr.ttl.unwrap_or(300);
                    let mut data = ptr.domain.into_bytes();
                    if !data.is_empty() && data.last() != Some(&b'.') {
                        data.push(b'.');
                    }
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
            dns_parser::QueryType::SRV => match self.resolver.lookup_srv(&domain).await {
                Ok(srv_records) => srv_records
                    .into_iter()
                    .map(|srv: SrvRecord| {
                        let mut data = Vec::new();
                        data.extend_from_slice(&srv.priority.to_be_bytes());
                        data.extend_from_slice(&srv.weight.to_be_bytes());
                        data.extend_from_slice(&srv.port.to_be_bytes());
                        let mut target = srv.target.into_bytes();
                        if !target.is_empty() && target.last() != Some(&b'.') {
                            target.push(b'.');
                        }
                        data.extend_from_slice(&target);
                        CachedRecord {
                            name: qname.to_vec(),
                            record_type: 33,
                            ttl: srv.ttl.unwrap_or(300),
                            data,
                        }
                    })
                    .collect(),
                Err(_) => Vec::new(),
            },
            _ => Vec::new(),
        };

        let qtype_u16: u16 = match qtype {
            dns_parser::QueryType::A => 1,
            dns_parser::QueryType::AAAA => 28,
            dns_parser::QueryType::TXT => 16,
            dns_parser::QueryType::NS => 2,
            dns_parser::QueryType::MX => 15,
            dns_parser::QueryType::CNAME => 5,
            dns_parser::QueryType::SOA => 6,
            dns_parser::QueryType::PTR => 12,
            dns_parser::QueryType::SRV => 33,
            dns_parser::QueryType::All => 255,
            _ => 0,
        };

        if records.is_empty() {
            let cache_key = RecursiveCacheKey::new(qname, qtype_u16, None);
            self.cache
                .insert_negative(cache_key, true, self.config.cache.negative_ttl_secs as u32);

            let mut full_query = Vec::new();
            full_query.extend_from_slice(qname);
            full_query.push(0);
            full_query.extend_from_slice(&qtype_u16.to_be_bytes());
            full_query.extend_from_slice(&1u16.to_be_bytes());

            let response = build_error_response(&full_query, RCODE_NXDOMAIN).unwrap_or_default();
            return Ok((response, is_dnssec_validated));
        }

        let cache_key = RecursiveCacheKey::new(qname, qtype_u16, None);
        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300);
        self.cache
            .insert_positive(cache_key, records.clone(), min_ttl, is_dnssec_validated);

        Ok((
            self.build_cached_response(qname, qtype, records, message_id, is_dnssec_validated),
            is_dnssec_validated,
        ))
    }

    fn build_cached_response(
        &self,
        qname: &[u8],
        qtype: dns_parser::QueryType,
        records: Vec<CachedRecord>,
        message_id: u16,
        is_dnssec_validated: bool,
    ) -> Vec<u8> {
        let qtype_u16: u16 = match qtype {
            dns_parser::QueryType::A => 1,
            dns_parser::QueryType::AAAA => 28,
            dns_parser::QueryType::TXT => 16,
            dns_parser::QueryType::NS => 2,
            dns_parser::QueryType::MX => 15,
            dns_parser::QueryType::CNAME => 5,
            dns_parser::QueryType::SOA => 6,
            dns_parser::QueryType::PTR => 12,
            dns_parser::QueryType::SRV => 33,
            dns_parser::QueryType::All => 255,
            _ => 0,
        };

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

            let flags = crate::dns::wire::MessageFlags {
                is_response: true,
                opcode: 0,
                authoritative: false,
                truncated: true,
                recursion_desired: true,
                recursion_available: true,
                authentic_data: is_dnssec_validated,
                response_code: 0,
            };

            let header = build_response_header(message_id, flags, qdcount, truncated_ancount, 0, 0);

            let mut full_response = header;
            full_response.extend_from_slice(&question_section);
            full_response.extend_from_slice(&final_response);

            response = full_response;
        } else {
            let flags = crate::dns::wire::MessageFlags {
                is_response: true,
                opcode: 0,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                authentic_data: is_dnssec_validated,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::dns::RecursiveCacheConfig;
    use crate::dns::recursive_cache::RecursiveRecordType;
    use dns_parser::QueryType;

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

        cache.insert_positive(key.clone(), records.clone(), 300, false);

        let result = cache.get(&key);
        assert!(result.is_some());
        let (retrieved, stale, validated) = result.unwrap();
        assert_eq!(retrieved.len(), 1);
        assert!(!stale);
        assert!(!validated);
    }

    #[test]
    fn test_negative_cache() {
        let cache = create_test_cache();

        let key = RecursiveCacheKey::new(b"nonexistent.com", 1, None);
        cache.insert_negative(key.clone(), true, 300);

        let result = cache.get(&key);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = create_test_cache();

        let key = RecursiveCacheKey::new(b"example.com", 1, None);
        let records = vec![create_test_record(b"example.com", 1, 300, vec![1, 2, 3, 4])];

        cache.insert_positive(key.clone(), records, 300, false);

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

        cache.insert_positive(key1.clone(), records1, 300, false);
        cache.insert_positive(key2.clone(), records2, 300, false);

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

        cache.insert_positive(key1.clone(), records1, 300, false);
        cache.insert_positive(key2.clone(), records2, 300, false);

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

        cache.insert_positive(key.clone(), records, 300, false);

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
        cache.insert_negative(key2.clone(), true, 300);

        let records = vec![create_test_record(b"exists.com", 1, 300, vec![1, 1, 1, 1])];
        cache.insert_positive(key1.clone(), records, 300, false);

        assert_eq!(cache.positive_len(), 1);
        assert_eq!(cache.negative_len(), 1);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_qtype_to_u16() {
        assert_eq!(dns_parser::QueryType::A, QueryType::A);
        assert_eq!(dns_parser::QueryType::AAAA, QueryType::AAAA);
        assert_eq!(dns_parser::QueryType::MX, QueryType::MX);
        assert_eq!(dns_parser::QueryType::TXT, QueryType::TXT);
        assert_eq!(dns_parser::QueryType::NS, QueryType::NS);
        assert_eq!(dns_parser::QueryType::SOA, QueryType::SOA);
        assert_eq!(dns_parser::QueryType::PTR, QueryType::PTR);
        assert_eq!(dns_parser::QueryType::SRV, QueryType::SRV);
        assert_eq!(dns_parser::QueryType::CNAME, QueryType::CNAME);
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

        cache.insert_positive(key_a.clone(), records_a, 300, false);
        cache.insert_positive(key_aaaa.clone(), records_aaaa, 300, false);

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
            false,
        );
        cache.insert_positive(
            key2.clone(),
            vec![create_test_record(b"test.com", 1, 300, vec![2, 2, 2, 2])],
            300,
            false,
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
                upstream_provider: crate::config::dns::RecursiveUpstreamProvider::System,
                upstream_servers: vec![],
                cache: RecursiveCacheConfig::default(),
                dnssec_validation: false,
                qname_minimization: false,
                query_timeout_secs: 5,
                max_concurrent_queries: 100,
                ratelimit: crate::config::dns::DnsRateLimitConfig::default(),
                firewall: crate::config::dns::DnsFirewallConfig::default(),
                root_hints_path: "".to_string(),
                trust_anchor_path: "".to_string(),
            },
            resolver: Arc::new(HickoryResolver::with_upstream_servers(&[upstream_ip]).unwrap()),
            cache: create_test_cache(),
            rate_limiter: None,
            firewall: None,
            metrics: None,
            query_semaphore: Arc::new(Semaphore::new(100)),
            running: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }
}
