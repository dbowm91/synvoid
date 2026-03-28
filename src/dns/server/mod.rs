use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use super::cache::{CacheKey, DnsCache};
use super::compression::DnsMessageCompressor;
use super::dnssec::DnsSecKeyManager;
use super::dnssec::{compute_dnskey, Algorithm};
use super::doh::DohServer;
use super::doq::DoqServer;
use super::dot::DotServer;
use super::edns::{parse_edns_options, EdnsOptions};
use super::mesh_sync::MeshDnsRegistry;
use super::query_validator::DnsQueryValidator;
use super::store::ZoneStore;
use super::wire;
use crate::config::dns::{DnsConfig, DnsRateLimitMode, DnsZoneEntry};
use crate::tls::cert_resolver::CertResolver;

pub use hickory_proto::rr::RecordType;

pub use self::rate_limit::DnsRateLimiter;

mod dnssec_impl;
mod query;
mod rate_limit;
mod response;
mod startup;
mod zone;

pub trait RecordTypeExt {
    fn to_u16(&self) -> u16;
    fn is_signed(&self) -> bool;
    const UNKNOWN: Self;
}

impl RecordTypeExt for RecordType {
    fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::DNSKEY => 48,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::DS => 43,
            RecordType::CDS => 59,
            RecordType::CDNSKEY => 60,
            RecordType::SRV => 33,
            RecordType::OPT => 41,
            RecordType::ANY => 255,
            _ => 0,
        }
    }

    fn is_signed(&self) -> bool {
        !matches!(
            self,
            RecordType::NULL
                | RecordType::DNSKEY
                | RecordType::DS
                | RecordType::RRSIG
                | RecordType::NSEC
                | RecordType::NSEC3
                | RecordType::NSEC3PARAM
                | RecordType::CDS
                | RecordType::CDNSKEY
        )
    }

    const UNKNOWN: Self = RecordType::NULL;
}

impl crate::config::dns::QnamePrivacyConfig {
    pub fn sanitize_qname(&self, qname: &str, zone_origin: &str) -> String {
        if !self.enabled {
            return qname.to_string();
        }

        match self.mode {
            crate::config::dns::QnamePrivacyMode::Full => qname.to_string(),
            crate::config::dns::QnamePrivacyMode::ZoneOnly => {
                let zone = zone_origin.trim_end_matches('.');
                if qname.to_lowercase().ends_with(&format!(".{}", zone)) {
                    let suffix = format!(".{}", zone);
                    qname
                        .strip_suffix(&suffix)
                        .map(|s| {
                            if s.is_empty() {
                                "*".to_string()
                            } else {
                                s.to_string() + &suffix
                            }
                        })
                        .unwrap_or_else(|| qname.to_string())
                } else {
                    "[external]".to_string()
                }
            }
            crate::config::dns::QnamePrivacyMode::Truncate => {
                let parts: Vec<&str> = qname.split('.').collect();
                if parts.len() <= 2 {
                    qname.to_string()
                } else {
                    let keep = parts.len().min(2);
                    let suffix = parts[parts.len() - keep..].join(".");
                    format!("[redacted].{}", suffix)
                }
            }
        }
    }
}

impl DnsServer {
    fn generate_random_salt() -> Vec<u8> {
        super::crypto_rng::random_bytes(16)
    }

    fn generate_random_id() -> u16 {
        super::crypto_rng::random_u16()
    }

    fn parse_soa_serial(soa_value: &str) -> u32 {
        let parts: Vec<&str> = soa_value.split_whitespace().collect();
        if parts.len() >= 3 {
            parts[2].parse::<u32>().unwrap_or(1)
        } else {
            1
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsZoneRecord {
    pub name: String,
    pub record_type: RecordType,
    pub value: String,
    pub ttl: u32,
    pub priority: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DsRecordExport {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
}

#[derive(Debug, Clone)]
pub struct Zone {
    pub origin: String,
    pub records: HashMap<(String, RecordType), Vec<DnsZoneRecord>>,
    pub serial: u32,
    pub ksk_key: Option<super::dnssec::ZoneSigningKey>,
    pub zsk_key: Option<super::dnssec::ZoneSigningKey>,
    pub dnskey_ttl: Option<u32>,
    pub nsec3_enabled: bool,
    pub nsec_enabled: bool,
    pub nsec3param: Option<super::dnssec::Nsec3Config>,
    pub history: Vec<ZoneHistory>,
}

#[derive(Clone, Debug)]
pub struct ZoneHistory {
    pub serial: u32,
    pub records: HashMap<(String, RecordType), Vec<DnsZoneRecord>>,
    pub timestamp: u64,
}

impl Zone {
    pub fn new(origin: String) -> Self {
        Self {
            origin,
            records: HashMap::new(),
            serial: 0,
            ksk_key: None,
            zsk_key: None,
            dnskey_ttl: None,
            nsec3_enabled: false,
            nsec_enabled: false,
            nsec3param: None,
            history: Vec::new(),
        }
    }

    pub fn increment_serial(&mut self) {
        self.increment_serial_with_limit(50);
    }

    pub fn increment_serial_with_limit(&mut self, max_history: usize) {
        let old_serial = self.serial;
        self.serial = Self::increment_serial_rfc1982(old_serial);

        let history_entry = ZoneHistory {
            serial: old_serial,
            records: self.records.clone(),
            timestamp: crate::utils::safe_unix_timestamp(),
        };

        if self.history.len() >= max_history {
            self.history.remove(0);
        }
        self.history.push(history_entry);
    }

    fn increment_serial_rfc1982(current: u32) -> u32 {
        const HALF_RANGE: u32 = 0x80000000;

        let now = crate::utils::safe_unix_timestamp() as u32;

        if current < HALF_RANGE && now >= HALF_RANGE {
            return 1;
        }

        if current == 0 {
            return 1;
        }

        if now > current && now - current < HALF_RANGE {
            return now;
        }

        current.wrapping_add(1)
    }

    pub fn serial_is_more_recent(s1: u32, s2: u32) -> bool {
        const HALF_RANGE: u32 = 0x80000000;

        if s1 == s2 {
            return false;
        }

        let diff = s1.wrapping_sub(s2);
        diff < HALF_RANGE
    }

    pub fn get_previous_version(&self, serial: u32) -> Option<&ZoneHistory> {
        self.history.iter().find(|h| h.serial == serial)
    }
}

#[cfg(test)]
mod zone_tests {
    use super::*;

    #[test]
    fn test_serial_increment_from_zero() {
        let mut zone = Zone::new("example.com".to_string());
        assert_eq!(zone.serial, 0);
        zone.increment_serial();
        assert!(zone.serial > 0);
    }

    #[test]
    fn test_serial_increment_wraps() {
        let mut zone = Zone::new("example.com".to_string());
        zone.serial = 0xFFFFFFFF;
        zone.increment_serial();
        assert!(zone.serial < 0xFFFFFFFF || zone.serial == 1);
    }

    #[test]
    fn test_serial_history() {
        let mut zone = Zone::new("example.com".to_string());
        zone.records.insert(
            ("@".to_string(), RecordType::A),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::A,
                value: "1.2.3.4".to_string(),
                ttl: 3600,
                priority: None,
            }],
        );

        zone.increment_serial();
        assert_eq!(zone.history.len(), 1);

        zone.increment_serial();
        assert_eq!(zone.history.len(), 2);
    }

    #[test]
    fn test_serial_history_limit() {
        let mut zone = Zone::new("example.com".to_string());
        zone.records.insert(
            ("@".to_string(), RecordType::A),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::A,
                value: "1.2.3.4".to_string(),
                ttl: 3600,
                priority: None,
            }],
        );

        for _ in 0..15 {
            zone.increment_serial_with_limit(10);
        }

        assert!(zone.history.len() <= 10);
    }

    #[test]
    fn test_serial_is_more_recent_basic() {
        assert!(Zone::serial_is_more_recent(2, 1));
        assert!(!Zone::serial_is_more_recent(1, 2));
    }

    #[test]
    fn test_serial_is_more_recent_equal() {
        assert!(!Zone::serial_is_more_recent(1, 1));
    }

    #[test]
    fn test_serial_is_more_recent_wrap_around() {
        assert!(Zone::serial_is_more_recent(1, 0xFFFFFFFF));
        assert!(!Zone::serial_is_more_recent(0xFFFFFFFF, 1));
    }
}

#[cfg(test)]
mod nxdomain_tests {
    use super::*;

    #[test]
    fn test_nxdomain_response_basic() {
        let query = build_query(0x1234, "example.com");
        let response = DnsServer::build_simple_nxdomain_response(&query).unwrap();

        assert!(
            response.len() > 12,
            "Response should include question section"
        );

        let id = u16::from_be_bytes([response[0], response[1]]);
        assert_eq!(id, 0x1234);

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(flags & 0x8000 != 0, "QR should be 1 (response)");
        assert!(flags & 0x0400 != 0, "AA should be 1 (authoritative)");
        let rcode = flags & 0x000F;
        assert_eq!(rcode, 3, "RCODE should be 3 (NXDOMAIN)");

        let qdcount = u16::from_be_bytes([response[4], response[5]]);
        assert_eq!(qdcount, 1, "QDCOUNT should be 1 (include question)");

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 0, "ANCOUNT should be 0");

        let nscount = u16::from_be_bytes([response[8], response[9]]);
        assert_eq!(nscount, 0, "NSCOUNT should be 0");

        let arcount = u16::from_be_bytes([response[10], response[11]]);
        assert_eq!(arcount, 0, "ARCOUNT should be 0");

        let qtype =
            u16::from_be_bytes([response[response.len() - 4], response[response.len() - 3]]);
        assert_eq!(qtype, 1, "QTYPE should be A (1)");
        let qclass =
            u16::from_be_bytes([response[response.len() - 2], response[response.len() - 1]]);
        assert_eq!(qclass, 1, "QCLASS should be IN (1)");
    }

    #[test]
    fn test_nxdomain_response_preserves_id() {
        let test_ids = [0x0001, 0x1234, 0xABCD, 0xFFFF];
        for id in test_ids {
            let query = build_query(id, "nonexistent.example.com");
            let response = DnsServer::build_simple_nxdomain_response(&query).unwrap();
            let response_id = u16::from_be_bytes([response[0], response[1]]);
            assert_eq!(response_id, id, "Response ID should match query ID");
        }
    }

    #[test]
    fn test_nxdomain_response_too_short_query() {
        let query = b"too short";
        let response = DnsServer::build_simple_nxdomain_response(query);
        assert!(response.is_none());
    }

    #[test]
    fn test_nxdomain_response_empty_query() {
        let query = Vec::new();
        let response = DnsServer::build_simple_nxdomain_response(&query);
        assert!(response.is_none());
    }

    fn build_query(id: u16, qname: &str) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());

        for part in qname.split('.') {
            query.push(part.len() as u8);
            query.extend_from_slice(part.as_bytes());
        }
        query.push(0);

        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());

        query
    }
}

#[derive(Clone)]
struct DnsHandlerState {
    zones: Arc<RwLock<HashMap<String, Zone>>>,
    zone_trie: Arc<RwLock<super::zone_trie::ZoneTrie>>,
    zone_index: Arc<RwLock<Vec<(String, String)>>>,
    rate_limiter: Option<Arc<DnsRateLimiter>>,
    query_validator: Option<DnsQueryValidator>,
    firewall: Option<Arc<RwLock<super::firewall::DnsFirewall>>>,
    connection_limits: Arc<super::limits::ConnectionLimits>,
    min_geo_ttl: u32,
    negative_cache_ttl: u32,
    cache: Option<Arc<DnsCache>>,
    dnssec: Option<Arc<RwLock<DnsSecKeyManager>>>,
    signer_name: Option<String>,
    rrl_enabled: bool,
    zone_transfer: Option<Arc<super::transfer::ZoneTransfer>>,
    ecs_filter_config: super::edns::EcsFilterConfig,
    update_handler: Option<super::update::DynamicUpdateHandler>,
    notify_handler: Option<super::notify::NotifyHandler>,
    query_coalescer: Option<Arc<super::query_coalesce::QueryCoalescer>>,
}

/// Shared DNS query context to reduce function parameter count.
/// Contains the Arc-wrapped service references needed to handle queries.
pub struct QueryContext<'a> {
    pub zones: &'a Arc<RwLock<HashMap<String, Zone>>>,
    pub zone_trie: &'a Arc<RwLock<super::zone_trie::ZoneTrie>>,
    pub mesh_registry: Option<&'a Arc<MeshDnsRegistry>>,
    pub geoip_lookup: Option<&'a Arc<crate::geoip::GeoIpManager>>,
    pub min_geo_ttl: u32,
    pub negative_cache_ttl: u32,
    pub cache: Option<&'a Arc<DnsCache>>,
    pub dnssec: Option<&'a Arc<RwLock<DnsSecKeyManager>>>,
    pub signer_name: Option<&'a String>,
    pub query_validator: Option<&'a DnsQueryValidator>,
    pub firewall: Option<&'a Arc<RwLock<super::firewall::DnsFirewall>>>,
    pub connection_limits: Option<&'a Arc<super::limits::ConnectionLimits>>,
    pub max_idle_time: Option<std::time::Duration>,
    pub zone_transfer: Option<&'a Arc<super::transfer::ZoneTransfer>>,
    pub ecs_filter_config: &'a super::edns::EcsFilterConfig,
    pub rate_limiter: Option<&'a Arc<DnsRateLimiter>>,
    pub rrl_enabled: bool,
    pub update_handler: Option<&'a super::update::DynamicUpdateHandler>,
    pub notify_handler: Option<&'a super::notify::NotifyHandler>,
    pub query_coalescer: Option<&'a Arc<super::query_coalesce::QueryCoalescer>>,
}

#[allow(dead_code)]
pub struct DnsServer {
    config: Arc<DnsConfig>,
    zones: Arc<RwLock<HashMap<String, Zone>>>,
    zone_trie: Arc<RwLock<super::zone_trie::ZoneTrie>>,
    zone_index: Arc<RwLock<Vec<(String, String)>>>,
    zone_index_btree: Arc<RwLock<BTreeMap<String, String>>>,
    zone_index_dirty: Arc<AtomicBool>,
    rate_limiter: Option<Arc<DnsRateLimiter>>,
    query_validator: Option<DnsQueryValidator>,
    firewall: Option<Arc<RwLock<super::firewall::DnsFirewall>>>,
    connection_limits: Arc<super::limits::ConnectionLimits>,
    mesh_registry: Option<Arc<MeshDnsRegistry>>,
    geoip_lookup: Option<Arc<crate::geoip::GeoIpManager>>,
    #[allow(dead_code)]
    shutdown_tx: Option<oneshot::Sender<()>>,
    cache: Option<Arc<DnsCache>>,
    dnssec: Option<Arc<RwLock<DnsSecKeyManager>>>,
    signer_name: Option<String>,
    rrl_enabled: bool,
    cert_resolver: Option<Arc<CertResolver>>,
    #[allow(dead_code)]
    dot_server: Option<DotServer>,
    #[allow(dead_code)]
    doh_server: Option<DohServer>,
    #[allow(dead_code)]
    doq_server: Option<DoqServer>,
    zone_transfer: Option<Arc<super::transfer::ZoneTransfer>>,
    ecs_filter_config: super::edns::EcsFilterConfig,
    update_handler: Option<super::update::DynamicUpdateHandler>,
    notify_handler: Option<super::notify::NotifyHandler>,
    hsm_manager: Option<super::hsm::HsmManager>,
    query_coalescer: Option<Arc<super::query_coalesce::QueryCoalescer>>,
    anycast_manager: Option<Arc<super::anycast::AnycastSocketManager>>,
    mesh_transport: Option<Arc<crate::mesh::transport::MeshTransport>>,
    zone_sync: Option<Arc<super::anycast_sync::AnycastZoneSync>>,
    #[allow(dead_code)]
    recursive_server: Option<Arc<super::recursive::RecursiveDnsServer>>,
}

impl Clone for DnsServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            zones: self.zones.clone(),
            zone_trie: self.zone_trie.clone(),
            zone_index: self.zone_index.clone(),
            zone_index_btree: self.zone_index_btree.clone(),
            zone_index_dirty: self.zone_index_dirty.clone(),
            rate_limiter: self.rate_limiter.clone(),
            query_validator: self.query_validator.clone(),
            firewall: self.firewall.clone(),
            connection_limits: self.connection_limits.clone(),
            mesh_registry: self.mesh_registry.clone(),
            geoip_lookup: self.geoip_lookup.clone(),
            shutdown_tx: None, // Cannot clone sender
            cache: self.cache.clone(),
            dnssec: self.dnssec.clone(),
            signer_name: self.signer_name.clone(),
            rrl_enabled: self.rrl_enabled,
            cert_resolver: self.cert_resolver.clone(),
            dot_server: None,
            doh_server: None,
            doq_server: None,
            zone_transfer: self.zone_transfer.clone(),
            ecs_filter_config: self.ecs_filter_config.clone(),
            update_handler: self.update_handler.clone(),
            notify_handler: self.notify_handler.clone(),
            hsm_manager: None, // Cannot clone HSM - requires re-initialization
            query_coalescer: self.query_coalescer.clone(),
            anycast_manager: None,  // Cannot clone - requires re-initialization
            mesh_transport: None,   // Cannot clone - requires re-initialization
            zone_sync: None,        // Cannot clone - requires re-initialization
            recursive_server: None, // Cannot clone - requires re-initialization
        }
    }
}

#[cfg(test)]
mod btree_tests {
    use super::*;

    #[test]
    fn test_reverse_domain_simple() {
        assert_eq!(DnsServer::reverse_domain("example.com"), "com.example");
        assert_eq!(
            DnsServer::reverse_domain("www.example.com"),
            "com.example.www"
        );
    }

    #[test]
    fn test_reverse_domain_with_trailing_dot() {
        assert_eq!(DnsServer::reverse_domain("example.com."), "com.example");
        assert_eq!(
            DnsServer::reverse_domain("www.example.com."),
            "com.example.www"
        );
    }

    #[test]
    fn test_reverse_domain_case_insensitive() {
        assert_eq!(DnsServer::reverse_domain("EXAMPLE.COM"), "com.example");
        assert_eq!(
            DnsServer::reverse_domain("WwW.Example.Com"),
            "com.example.www"
        );
    }

    #[test]
    fn test_reverse_domain_single_label() {
        assert_eq!(DnsServer::reverse_domain("localhost"), "localhost");
    }
}

impl DnsServer {
    pub fn new(config: DnsConfig, cert_resolver: Option<Arc<CertResolver>>) -> Self {
        let rate_limiter = match config.ratelimit.mode {
            DnsRateLimitMode::Shared => None,
            DnsRateLimitMode::Dedicated => Some(Arc::new(DnsRateLimiter::new(
                config.ratelimit.per_second,
                config.ratelimit.per_second * 2,
            ))),
        };

        let cache = if config.settings.cache_enabled {
            Some(Arc::new(DnsCache::new(
                config.settings.cache_size,
                config.settings.cache_max_ttl,
                config.settings.cache_min_ttl,
            )))
        } else {
            None
        };

        let (dnssec, signer_name) = if config.dnssec.enabled {
            let key_path = std::path::PathBuf::from(&config.dnssec.key_path);
            let mut manager = DnsSecKeyManager::new(key_path.clone());

            let algorithm = super::dnssec::Algorithm::Ed25519;

            let key_type = super::dnssec::KeyType::KSK;
            let key_name = format!("ksk.{}", config.dnssec.domain);

            if !key_path.exists() {
                if let Err(e) = std::fs::create_dir_all(&key_path) {
                    tracing::error!(
                        "Failed to create DNSSEC key directory {}: {}",
                        key_path.display(),
                        e
                    );
                } else {
                    let rsa_key_size = 2048;
                    let validity_days = 30;
                    if let Err(e) =
                        manager.generate_key(algorithm, key_type, rsa_key_size, validity_days)
                    {
                        tracing::error!("Failed to generate DNSSEC key: {}", e);
                    }
                }
            }

            (Some(Arc::new(RwLock::new(manager))), Some(key_name))
        } else {
            (None, None)
        };

        let hsm_manager = if config.dnssec.enabled || config.dnssec.hsm.enabled {
            let hsm = super::hsm::HsmManager::new();
            if let Err(e) = hsm.initialize(&config.dnssec.hsm) {
                tracing::warn!("Failed to initialize HSM: {}", e);
            }
            Some(hsm)
        } else {
            None
        };

        let query_coalescer = if config.settings.query_coalescing.enabled {
            Some(Arc::new(
                super::query_coalesce::QueryCoalescer::with_config(
                    config.settings.query_coalescing.max_wait_ms,
                    config.settings.query_coalescing.max_entries,
                    config.settings.query_coalescing.entry_ttl_secs,
                ),
            ))
        } else {
            None
        };

        let rrl_enabled = config.rrl.enabled;

        let mesh_registry = None;
        let geoip_lookup = None;

        let query_validator = DnsQueryValidator::from_config(
            config.limits.max_query_size,
            16,
            63,
            255,
            config.limits.max_records_per_response,
            config.limits.max_response_size,
            config.settings.cache_max_ttl as u32,
        );

        let firewall = if config.firewall.enabled {
            let mut fw = super::firewall::DnsFirewall::new();

            if config.firewall.block_internal_ips {
                let rule = super::firewall::DnsFirewallRule {
                    id: "block_internal_ips".to_string(),
                    rule_type: super::firewall::DnsFirewallRuleType::Subnet,
                    action: super::firewall::DnsFirewallAction::Block,
                    target: "10.0.0.0/8".to_string(),
                    ttl: 300,
                    created_at: chrono::Utc::now().timestamp() as u64,
                    expires_at: None,
                    enabled: true,
                };
                let _ = fw.add_rule(rule);

                let rule2 = super::firewall::DnsFirewallRule {
                    id: "block_private_172".to_string(),
                    rule_type: super::firewall::DnsFirewallRuleType::Subnet,
                    action: super::firewall::DnsFirewallAction::Block,
                    target: "172.16.0.0/12".to_string(),
                    ttl: 300,
                    created_at: chrono::Utc::now().timestamp() as u64,
                    expires_at: None,
                    enabled: true,
                };
                let _ = fw.add_rule(rule2);

                let rule3 = super::firewall::DnsFirewallRule {
                    id: "block_private_192".to_string(),
                    rule_type: super::firewall::DnsFirewallRuleType::Subnet,
                    action: super::firewall::DnsFirewallAction::Block,
                    target: "192.168.0.0/16".to_string(),
                    ttl: 300,
                    created_at: chrono::Utc::now().timestamp() as u64,
                    expires_at: None,
                    enabled: true,
                };
                let _ = fw.add_rule(rule3);
            }

            if config.firewall.block_zone_transfers {
                let rule = super::firewall::DnsFirewallRule {
                    id: "block_axfr".to_string(),
                    rule_type: super::firewall::DnsFirewallRuleType::Opcode,
                    action: super::firewall::DnsFirewallAction::Block,
                    target: "0x2".to_string(),
                    ttl: 300,
                    created_at: chrono::Utc::now().timestamp() as u64,
                    expires_at: None,
                    enabled: true,
                };
                let _ = fw.add_rule(rule);
            }

            Some(Arc::new(RwLock::new(fw)))
        } else {
            None
        };

        let connection_limits = Arc::new(super::limits::ConnectionLimits::new(
            config.limits.max_tcp_connections,
            config.limits.max_concurrent_queries,
            config.limits.max_query_size,
            config.limits.max_response_size,
            config.limits.max_records_per_response,
            config.limits.max_tcp_idle_time_secs,
            config.limits.max_tcp_query_time_secs,
        ));

        let ecs_filter_config =
            super::edns::EcsFilterConfig::from_settings(&config.settings.ecs_filtering);

        Self {
            config: Arc::new(config),
            zones: Arc::new(RwLock::new(HashMap::new())),
            zone_trie: Arc::new(RwLock::new(super::zone_trie::ZoneTrie::new())),
            zone_index: Arc::new(RwLock::new(Vec::new())),
            zone_index_btree: Arc::new(RwLock::new(BTreeMap::new())),
            zone_index_dirty: Arc::new(AtomicBool::new(false)),
            rate_limiter,
            query_validator: Some(query_validator),
            firewall,
            connection_limits,
            mesh_registry,
            geoip_lookup,
            shutdown_tx: None,
            cache,
            dnssec,
            signer_name,
            rrl_enabled,
            cert_resolver,
            dot_server: None,
            doh_server: None,
            doq_server: None,
            zone_transfer: None,
            ecs_filter_config,
            update_handler: None,
            notify_handler: None,
            hsm_manager,
            query_coalescer,
            anycast_manager: None,
            mesh_transport: None,
            zone_sync: None,
            recursive_server: None,
        }
    }
}
