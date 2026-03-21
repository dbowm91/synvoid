use std::collections::{HashMap, BTreeMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};


use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use crate::config::dns::{DnsConfig, DnsRateLimitMode, DnsZoneEntry};
use crate::tls::cert_resolver::CertResolver;
use super::cache::{CacheKey, DnsCache};
use super::compression::DnsMessageCompressor;
use super::dnssec::DnsSecKeyManager;
use super::dnssec::{compute_dnskey, Algorithm};
use super::doh::DohServer;
use super::doq::DoqServer;
use super::dot::DotServer;
use super::store::ZoneStore;
use super::mesh_sync::MeshDnsRegistry;
use super::query_validator::DnsQueryValidator;
use super::edns::{parse_edns_options, EdnsOptions};
use super::wire;

pub use hickory_proto::rr::RecordType;

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
                    qname.strip_suffix(&suffix)
                        .map(|s| if s.is_empty() { "*".to_string() } else { s.to_string() + &suffix })
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

    pub(crate) fn build_simple_nxdomain_response(query: &[u8]) -> Option<Arc<Vec<u8>>> {
        use super::wire::{build_response_header, MessageFlags};

        if query.len() < 12 {
            return None;
        }

        let id = wire::get_message_id(query)?;

        let flags = MessageFlags {
            is_response: true,
            opcode: 0,
            authoritative: true,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            response_code: 3, // NXDOMAIN
        };

        let response = build_response_header(id, flags, 0, 0, 0, 0);

        Some(Arc::new(response))
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
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        
        if self.history.len() >= max_history {
            self.history.remove(0);
        }
        self.history.push(history_entry);
    }

    fn increment_serial_rfc1982(current: u32) -> u32 {
        const HALF_RANGE: u32 = 0x80000000;
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        
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
        assert_eq!(zone.serial, 1);
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
        assert_eq!(zone.history[0].serial, 0);
        
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
        
        // Use increment_serial_with_limit with limit of 10
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
        
        assert_eq!(response.len(), 12);
        
        let id = u16::from_be_bytes([response[0], response[1]]);
        assert_eq!(id, 0x1234);
        
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(flags & 0x8000 != 0, "QR should be 1 (response)");
        assert!(flags & 0x0400 != 0, "AA should be 1 (authoritative)");
        let rcode = flags & 0x000F;
        assert_eq!(rcode, 3, "RCODE should be 3 (NXDOMAIN)");
        
        let qdcount = u16::from_be_bytes([response[4], response[5]]);
        assert_eq!(qdcount, 0, "QDCOUNT should be 0");
        
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 0, "ANCOUNT should be 0");
        
        let nscount = u16::from_be_bytes([response[8], response[9]]);
        assert_eq!(nscount, 0, "NSCOUNT should be 0");
        
        let arcount = u16::from_be_bytes([response[10], response[11]]);
        assert_eq!(arcount, 0, "ARCOUNT should be 0");
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

struct TokenBucket {
    tokens: u64,
    max_tokens: u64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: u64, refill_per_second: u64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate: refill_per_second as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        
        let tokens_to_add = (elapsed * self.refill_rate) as u64;
        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.max_tokens);
            self.last_refill = now;
        }
    }
}

use parking_lot::RwLock as PLRwLock;


const MAX_IP_BUCKETS: usize = 100000;
const MAX_RRL_BUCKETS: usize = 100000;
const CLEANUP_INTERVAL_SECS: u64 = 60;
const BUCKET_EXPIRY_SECS: u64 = 300;

struct TimedTokenBucket {
    bucket: TokenBucket,
    last_access: Instant,
}

impl TimedTokenBucket {
    fn new(bucket: TokenBucket) -> Self {
        Self {
            bucket,
            last_access: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.last_access.elapsed().as_secs() > BUCKET_EXPIRY_SECS
    }

    fn try_consume(&mut self) -> bool {
        self.last_access = Instant::now();
        self.bucket.try_consume()
    }

    fn last_access_time(&self) -> Instant {
        self.last_access
    }
}

struct TimedBucketMap<K: Eq + std::hash::Hash + Clone> {
    buckets: std::collections::HashMap<K, TimedTokenBucket>,
    max_buckets: usize,
    cleanup_batch_size: usize,
}

impl<K: Eq + std::hash::Hash + Clone> TimedBucketMap<K> {
    fn new(max_buckets: usize, cleanup_batch_size: usize) -> Self {
        Self {
            buckets: std::collections::HashMap::new(),
            max_buckets,
            cleanup_batch_size,
        }
    }

    fn get_or_insert_with<F: FnOnce() -> TimedTokenBucket>(&mut self, key: &K, f: F) -> &mut TimedTokenBucket {
        self.buckets.entry(key.clone()).or_insert_with(f)
    }

    fn cleanup(&mut self) {
        self.buckets.retain(|_, v| !v.is_expired());
        
        if self.buckets.len() > self.max_buckets {
            let excess = self.buckets.len() - self.max_buckets / 2;
            let mut items: Vec<_> = self.buckets.iter()
                .map(|(k, v)| (k.clone(), v.last_access_time()))
                .collect();
            items.sort_by(|a, b| a.1.cmp(&b.1));
            
            for (key, _) in items.into_iter().take(excess.min(self.cleanup_batch_size)) {
                self.buckets.remove(&key);
            }
        }
    }

    fn is_over_limit(&self, limit: usize) -> bool {
        self.buckets.len() >= limit
    }
}

#[allow(dead_code)]
pub struct DnsRateLimiter {
    global_bucket: PLRwLock<TokenBucket>,
    ip_buckets: PLRwLock<TimedBucketMap<IpAddr>>,
    rrl_buckets: PLRwLock<TimedBucketMap<String>>,
    rrl_source_buckets: PLRwLock<TimedBucketMap<IpAddr>>,
    rrl_threshold: u64,
    rrl_window: Duration,
    last_cleanup: PLRwLock<Instant>,
}

impl DnsRateLimiter {
    pub fn new(per_second: u64, max_burst: u64) -> Self {
        Self {
            global_bucket: PLRwLock::new(TokenBucket::new(max_burst, per_second)),
            ip_buckets: PLRwLock::new(TimedBucketMap::new(MAX_IP_BUCKETS, 1000)),
            rrl_buckets: PLRwLock::new(TimedBucketMap::new(MAX_RRL_BUCKETS, 1000)),
            rrl_source_buckets: PLRwLock::new(TimedBucketMap::new(MAX_RRL_BUCKETS, 1000)),
            rrl_threshold: 100,
            rrl_window: Duration::from_secs(5),
            last_cleanup: PLRwLock::new(Instant::now()),
        }
    }

    fn cleanup_if_needed(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = *self.last_cleanup.read();
            now.duration_since(last).as_secs() >= CLEANUP_INTERVAL_SECS
        };

        if !should_cleanup {
            return;
        }

        self.ip_buckets.write().cleanup();
        self.rrl_buckets.write().cleanup();
        self.rrl_source_buckets.write().cleanup();
        
        *self.last_cleanup.write() = now;
    }

    pub fn check(&self) -> Result<(), ()> {
        if self.global_bucket.write().try_consume() {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<(), ()> {
        if self.check().is_err() {
            return Err(());
        }

        self.cleanup_if_needed();

        let mut buckets = self.ip_buckets.write();
        
        if buckets.is_over_limit(MAX_IP_BUCKETS) {
            return Err(());
        }
        
        let bucket = buckets.get_or_insert_with(&ip, || TimedTokenBucket::new(TokenBucket::new(10, 10)));
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn check_rrl(&self, source_ip: IpAddr) -> Result<(), ()> {
        self.cleanup_if_needed();
        
        let mut buckets = self.rrl_source_buckets.write();
        
        if buckets.is_over_limit(MAX_RRL_BUCKETS) {
            return Err(());
        }
        
        let bucket = buckets.get_or_insert_with(&source_ip, || TimedTokenBucket::new(TokenBucket::new(self.rrl_threshold * 10, self.rrl_threshold)));
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn should_respond(&self, source_ip: IpAddr) -> bool {
        self.cleanup_if_needed();
        
        let mut buckets = self.rrl_source_buckets.write();
        
        if buckets.is_over_limit(MAX_RRL_BUCKETS) {
            return false;
        }
        
        let bucket = buckets.get_or_insert_with(&source_ip, || TimedTokenBucket::new(TokenBucket::new(self.rrl_threshold * 10, self.rrl_threshold)));
        
        if bucket.try_consume() {
            true
        } else {
            tracing::debug!("RRL drop response to {}", source_ip);
            false
        }
    }
}

#[allow(dead_code)]
pub struct DnsServer {
    config: Arc<DnsConfig>,
    zones: Arc<RwLock<HashMap<String, Zone>>>,
    zone_trie: Arc<RwLock<super::zone_trie::ZoneTrie>>,
    zone_index: Arc<RwLock<Vec<(String, String)>>>,
    zone_index_btree: Arc<RwLock<BTreeMap<String, String>>>,
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
            anycast_manager: None, // Cannot clone - requires re-initialization
            mesh_transport: None, // Cannot clone - requires re-initialization
            zone_sync: None, // Cannot clone - requires re-initialization
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
        assert_eq!(DnsServer::reverse_domain("www.example.com"), "com.example.www");
    }

    #[test]
    fn test_reverse_domain_with_trailing_dot() {
        assert_eq!(DnsServer::reverse_domain("example.com."), "com.example");
        assert_eq!(DnsServer::reverse_domain("www.example.com."), "com.example.www");
    }

    #[test]
    fn test_reverse_domain_case_insensitive() {
        assert_eq!(DnsServer::reverse_domain("EXAMPLE.COM"), "com.example");
        assert_eq!(DnsServer::reverse_domain("WwW.Example.Com"), "com.example.www");
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
            DnsRateLimitMode::Dedicated => {
                Some(Arc::new(DnsRateLimiter::new(
                    config.ratelimit.per_second,
                    config.ratelimit.per_second * 2,
                )))
            }
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
                    tracing::error!("Failed to create DNSSEC key directory {}: {}", key_path.display(), e);
                } else {
                    let rsa_key_size = 2048;
                    let validity_days = 30;
                    if let Err(e) = manager.generate_key(algorithm, key_type, rsa_key_size, validity_days) {
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
            Some(Arc::new(super::query_coalesce::QueryCoalescer::with_config(
                config.settings.query_coalescing.max_wait_ms,
                config.settings.query_coalescing.max_entries,
                config.settings.query_coalescing.entry_ttl_secs,
            )))
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

        let ecs_filter_config = super::edns::EcsFilterConfig::from_settings(&config.settings.ecs_filtering);

        Self {
            config: Arc::new(config),
            zones: Arc::new(RwLock::new(HashMap::new())),
            zone_trie: Arc::new(RwLock::new(super::zone_trie::ZoneTrie::new())),
            zone_index: Arc::new(RwLock::new(Vec::new())),
            zone_index_btree: Arc::new(RwLock::new(BTreeMap::new())),
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

    pub fn with_anycast(mut self, manager: super::anycast::AnycastSocketManager) -> Self {
        self.anycast_manager = Some(Arc::new(manager));
        self
    }

    pub fn with_mesh_transport(mut self, transport: Arc<crate::mesh::transport::MeshTransport>) -> Self {
        self.mesh_transport = Some(transport);
        self
    }

    pub fn with_zone_sync(mut self, zone_sync: super::anycast_sync::AnycastZoneSync) -> Self {
        self.zone_sync = Some(Arc::new(zone_sync));
        self
    }

    pub fn with_zone_transfer(mut self, zone_transfer: super::transfer::ZoneTransfer) -> Self {
        self.zone_transfer = Some(Arc::new(zone_transfer));
        self
    }

    pub fn with_zone_transfer_config(
        mut self,
        allowed_transfers: Vec<String>,
        allow_wildcard_transfer: bool,
        wildcard_transfer_requires_tsig: bool,
        ixfr_enabled: bool,
        ixfr_fallback_to_axfr: bool,
        tsig_verifier: Option<Arc<super::tsig::TsigVerifier>>,
    ) -> Self {
        let zone_transfer = super::transfer::ZoneTransfer::with_security_config(
            self.zones.clone(),
            allowed_transfers,
            tsig_verifier,
            allow_wildcard_transfer,
            wildcard_transfer_requires_tsig,
            ixfr_enabled,
            ixfr_fallback_to_axfr,
        );
        self.zone_transfer = Some(Arc::new(zone_transfer));
        self
    }

    pub fn with_notify_handler(mut self, notify_handler: super::notify::NotifyHandler) -> Self {
        self.notify_handler = Some(notify_handler);
        self
    }

    pub fn with_dynamic_update(mut self, enabled: bool, allow_any: bool, require_tsig: bool) -> Self {
        if enabled {
            self.update_handler = Some(super::update::DynamicUpdateHandler::new(self.zones.clone())
                .with_config(enabled, allow_any, require_tsig));
        }
        self
    }

    fn reverse_domain(domain: &str) -> String {
        domain.trim_end_matches('.').to_lowercase().split('.').rev().collect::<Vec<_>>().join(".")
    }

    fn rebuild_zone_index(&self) {
        let zones = self.zones.read();
        let mut index = Vec::new();
        let mut btree_index = BTreeMap::new();
        let mut trie = super::zone_trie::ZoneTrie::new();
        
        for origin in zones.keys() {
            let origin_lower = origin.to_lowercase();
            index.push((origin_lower.clone(), origin.clone()));
            
            let reversed = Self::reverse_domain(&origin_lower);
            btree_index.insert(reversed, origin.clone());
            
            // Insert into the trie for efficient lookup
            trie.insert(&origin_lower);
        }
        index.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        drop(zones);
        
        *self.zone_index.write() = index;
        *self.zone_index_btree.write() = btree_index;
        *self.zone_trie.write() = trie;
    }

    pub fn with_mesh_registry(mut self, registry: Arc<MeshDnsRegistry>) -> Self {
        self.mesh_registry = Some(registry);
        self
    }

    pub fn with_geoip(mut self, geoip: Arc<crate::geoip::GeoIpManager>) -> Self {
        self.geoip_lookup = Some(geoip);
        self
    }

    pub fn load_zones(&self, zone_configs: Vec<DnsZoneEntry>) -> Result<(), String> {
        let mut zones = self.zones.write();
        
        for zone_config in zone_configs {
            let mut zone = Zone::new(zone_config.zone.clone());
            zone.dnskey_ttl = Some(3600);
            
            let zone_dnssec = zone_config.dnssec.as_ref();
            let use_global = zone_dnssec.map(|z| !z.enabled).unwrap_or(true);
            
            if use_global {
                zone.nsec3_enabled = self.config.dnssec.nsec3_enabled;
                zone.nsec_enabled = self.config.dnssec.nsec_enabled;
                zone.nsec3param = if self.config.dnssec.nsec3_enabled {
                    Some(super::dnssec::Nsec3Config::new(self.config.dnssec.nsec3_iterations, Self::generate_random_salt()))
                } else {
                    None
                };
            } else if let Some(dnssec) = zone_dnssec {
                zone.nsec3_enabled = dnssec.nsec3_enabled;
                zone.nsec_enabled = dnssec.nsec_enabled;
                zone.nsec3param = if dnssec.nsec3_enabled {
                    let iterations = dnssec.nsec3_iterations.unwrap_or(self.config.dnssec.nsec3_iterations);
                    Some(super::dnssec::Nsec3Config::new(iterations, Self::generate_random_salt()))
                } else {
                    None
                };
            }

            for record_config in &zone_config.records {
                let record = DnsZoneRecord {
                    name: record_config.name.clone(),
                    record_type: match record_config.record_type {
                        crate::config::dns::DnsRecordType::A => RecordType::A,
                        crate::config::dns::DnsRecordType::Aaaa => RecordType::AAAA,
                        crate::config::dns::DnsRecordType::CName => RecordType::CNAME,
                        crate::config::dns::DnsRecordType::Mx => RecordType::MX,
                        crate::config::dns::DnsRecordType::Txt => RecordType::TXT,
                        crate::config::dns::DnsRecordType::Ns => RecordType::NS,
                        crate::config::dns::DnsRecordType::Soa => RecordType::SOA,
                        crate::config::dns::DnsRecordType::Srv => RecordType::SRV,
                        crate::config::dns::DnsRecordType::Ptr => RecordType::PTR,
                        crate::config::dns::DnsRecordType::Caa => RecordType::CAA,
                        crate::config::dns::DnsRecordType::Tlsa => RecordType::TLSA,
                        crate::config::dns::DnsRecordType::Svcb => RecordType::SVCB,
                        crate::config::dns::DnsRecordType::Https => RecordType::HTTPS,
                        crate::config::dns::DnsRecordType::Naptr => RecordType::NAPTR,
                        crate::config::dns::DnsRecordType::Sshfp => RecordType::SSHFP,
                        crate::config::dns::DnsRecordType::Uri => RecordType::from(256),
                        crate::config::dns::DnsRecordType::Rp => RecordType::from(17),
                        crate::config::dns::DnsRecordType::Afsdb => RecordType::from(18),
                        crate::config::dns::DnsRecordType::Ds => RecordType::DS,
                        crate::config::dns::DnsRecordType::Other => RecordType::NULL,
                    },
                    value: record_config.value.clone(),
                    ttl: record_config.ttl.unwrap_or(self.config.settings.default_ttl),
                    priority: record_config.priority,
                };

                if record.record_type == RecordType::SOA {
                    zone.serial = Self::parse_soa_serial(&record.value);
                }

                let key = (record_config.name.clone(), record.record_type);
                zone.records.entry(key).or_insert_with(Vec::new).push(record);
            }

            if zone.serial == 0 {
                zone.serial = 1;
            }

            tracing::info!("Loaded DNS zone: {} (serial: {})", zone.origin, zone.serial);
            zones.insert(zone.origin.clone(), zone);
        }

        drop(zones);
        self.rebuild_zone_index();

        Ok(())
    }

    pub fn initialize_dnssec(&self) -> Result<(), String> {
        let dnssec = self.dnssec.as_ref().ok_or("DNSSEC not enabled")?;
        let mut manager = dnssec.write();
        
        manager.initialize()?;
        
        if manager.key_signing_key.is_none() {
            let algorithm = self.config.dnssec.algorithm.into();
            manager.generate_key(algorithm, super::dnssec::KeyType::KSK, self.config.dnssec.ksk_key_size, 365)?;
        }
        
        if manager.zone_signing_key.is_none() {
            let algorithm = self.config.dnssec.algorithm.into();
            manager.generate_key(algorithm, super::dnssec::KeyType::ZSK, self.config.dnssec.rsa_key_size, 90)?;
        }
        
        let ksk = manager.key_signing_key.clone();
        let zsk = manager.zone_signing_key.clone();
        
        drop(manager);
        
        let mut zones = self.zones.write();
        for (_, zone) in zones.iter_mut() {
            zone.ksk_key = ksk.clone();
            zone.zsk_key = zsk.clone();
            tracing::info!("Initialized DNSSEC keys for zone: {}", zone.origin);
        }
        
        Ok(())
    }

    pub fn load_zones_from_store(&self, store: &ZoneStore) -> Result<(), String> {
        let stored_zones = store.load_zones()?;
        let mut zones = self.zones.write();
        
        for (origin, zone) in stored_zones {
            tracing::info!("Loaded DNS zone from store: {}", origin);
            zones.insert(origin, zone);
        }
        
        drop(zones);
        self.rebuild_zone_index();

        Ok(())
    }

    pub fn save_zones_to_store(&self, store: &ZoneStore) -> Result<(), String> {
        let zones = self.zones.read();
        
        for (origin, zone) in zones.iter() {
            let records: Vec<(String, RecordType, String, u32, Option<u32>)> = zone.records
                .values()
                .flat_map(|v| v.iter())
                .map(|r| (r.name.clone(), r.record_type.clone(), r.value.clone(), r.ttl, r.priority))
                .collect();
            
            store.save_zone(origin, &records)?;
        }
        
        Ok(())
    }

    pub async fn start(&mut self) -> Result<(), String> {
        if self.config.dnssec.enabled {
            if let Err(e) = self.initialize_dnssec() {
                tracing::warn!("Failed to initialize DNSSEC: {}", e);
            } else {
                tracing::info!("DNSSEC initialized successfully");
                
                Self::start_key_rotation_task(
                    self.dnssec.clone(),
                    86400,
                );
            }
        }

        if self.config.recursive.enabled {
            self.start_recursive_server().await?;
        }

        if let Some(ref coalescer) = self.query_coalescer {
            Self::start_coalescer_cleanup_task(
                Some(coalescer),
                self.config.settings.query_coalescing.cleanup_interval_secs,
            );
        }
        
        if self.config.anycast.enabled {
            self.start_anycast_mode().await?;
        } else {
            self.start_standard_mode().await?;
        }
        
        Ok(())
    }

    async fn start_recursive_server(&mut self) -> Result<(), String> {
        tracing::info!(
            "Starting recursive DNS server on {}:{}",
            self.config.recursive.bind_address,
            self.config.recursive.port
        );

        let rate_limiter = self.rate_limiter.clone();
        let metrics = None;

        let recursive_server = super::recursive::RecursiveDnsServer::new(
            self.config.recursive.clone(),
            rate_limiter,
            None,
            metrics,
        )
        .await
        .map_err(|e| format!("Failed to create recursive DNS server: {}", e))?;

        let server = Arc::new(recursive_server);
        let server_clone = server.clone();
        server_clone.start().await
            .map_err(|e| format!("Failed to start recursive DNS server: {}", e))?;

        self.recursive_server = Some(server);

        Ok(())
    }

    async fn start_anycast_mode(&mut self) -> Result<(), String> {
        let platform = crate::dns::platform::create_platform();
        
        let mut manager = super::anycast::AnycastSocketManager::new(
            &self.config.anycast,
            platform,
        ).await?;

        let node_id = if let Some(ref mesh_registry) = self.mesh_registry {
            mesh_registry.node_id().to_string()
        } else {
            "unknown".to_string()
        };
        
        let geo = self.config.anycast.geo.clone();
        
        let zones_list: Vec<String> = {
            let zones = self.zones.read();
            zones.keys().cloned().collect()
        };

        if let Some(ref mesh_registry) = self.mesh_registry {
            let anycast_ips = manager.get_bound_ips();
            let registration = super::messages::DnsAnycastNodeRegistration {
                node_id: node_id.clone(),
                anycast_ips: anycast_ips.iter().map(|ip| ip.to_string()).collect(),
                geo,
                capacity: self.config.anycast.capacity,
                healthy: true,
                dns_zones: zones_list.clone(),
                certificate_fingerprint: None,
            };
            mesh_registry.register_anycast_node(registration).await?;
        }

        let (health_tx, mut health_rx) = tokio::sync::mpsc::channel::<super::anycast::AnycastHealthUpdate>(100);
        manager.set_health_sender(health_tx);

        let mesh_registry_for_health = self.mesh_registry.clone();
        let node_id_for_health = node_id.clone();
        tokio::spawn(async move {
            while let Some(update) = health_rx.recv().await {
                if let Some(ref registry) = mesh_registry_for_health {
                    let health_update = super::messages::DnsAnycastHealthUpdate {
                        node_id: node_id_for_health.clone(),
                        anycast_ips: vec![update.ip.to_string()],
                        healthy: update.healthy,
                        latency_ms: update.latency_ms.map(|v| v as u32),
                        load_percent: update.error_count.checked_div(update.query_count.max(1)).map(|v| v as u8),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    };
                    let _ = registry.update_anycast_health(health_update).await;
                }
            }
        });

        if self.config.anycast.health_check_interval_secs > 0 {
            let interval = self.config.anycast.health_check_interval_secs;
            manager.start_health_monitor(interval).await;
        }

        let zones_for_sync = self.zones.clone();
        let mut zone_sync = super::anycast_sync::AnycastZoneSync::new(
            node_id.clone(),
            zones_for_sync,
        );

        if let Some(ref transport) = self.mesh_transport {
            zone_sync = zone_sync.with_mesh_transport(transport.clone());
            
            // Set DNS zones on transport for zone sync
            transport.set_dns_zones(self.zones.clone());
        }

        if self.config.anycast.mesh_based_sync {
            let sync_interval = self.config.anycast.sync_interval_secs;
            zone_sync = zone_sync.with_sync_interval(sync_interval);
            zone_sync.start_sync_loop().await;
        }

        self.zone_sync = Some(Arc::new(zone_sync));

        self.anycast_manager = Some(Arc::new(manager));

        self.start_listeners_with_anycast().await?;

        Ok(())
    }

    async fn start_listeners_with_anycast(&mut self) -> Result<(), String> {
        let anycast_manager = self.anycast_manager.as_ref()
            .ok_or("Anycast manager not initialized")?;

        let bound_addresses = anycast_manager.get_bound_addresses();
        
        tracing::info!("Starting anycast DNS on {:?}", bound_addresses);

        let zones = self.zones.clone();
        let zone_trie = self.zone_trie.clone();
        let zone_index = self.zone_index.clone();
        let rate_limiter = self.rate_limiter.clone();
        let mesh_registry = self.mesh_registry.clone();
        let geoip_lookup = self.geoip_lookup.clone();
        let query_validator = self.query_validator.clone();
        let firewall = self.firewall.clone();
        let connection_limits = self.connection_limits.clone();
        let min_geo_ttl = self.config.settings.min_geo_ttl;
        let negative_cache_ttl = self.config.settings.negative_cache_ttl;
        let cache = self.cache.clone();
        let dnssec = self.dnssec.clone();
        let signer_name = self.signer_name.clone();
        let rrl_enabled = self.rrl_enabled;
        let zone_transfer = self.zone_transfer.clone();
        let ecs_filter_config = self.ecs_filter_config.clone();
        let update_handler = self.update_handler.clone();
        let notify_handler = self.notify_handler.clone();
        let query_coalescer = self.query_coalescer.clone();
        let anycast_mgr = anycast_manager.clone();
        let config = self.config.clone();
        
        let (tx_udp, mut rx_udp) = tokio::sync::oneshot::channel::<()>();
        let (tx_tcp, _rx_tcp) = tokio::sync::oneshot::channel::<()>();
        let tx = tx_udp;
        self.shutdown_tx = Some(tx);

        let zones_udp = zones.clone();
        let zone_trie_udp = zone_trie.clone();
        let _zone_index_udp = zone_index.clone();
        let rate_limiter_udp = rate_limiter.clone();
        let query_validator_udp = query_validator.clone();
        let firewall_udp = firewall.clone();
        let mesh_registry_udp = mesh_registry.clone();
        let geoip_lookup_udp = geoip_lookup.clone();
        let cache_udp = cache.clone();
        let dnssec_udp = dnssec.clone();
        let signer_name_udp = signer_name.clone();
        let rrl_enabled_udp = rrl_enabled;
        let zone_transfer_udp = zone_transfer.clone();
        let ecs_filter_config_udp = ecs_filter_config.clone();
        let update_handler_udp = update_handler.clone();
        let notify_handler_udp = notify_handler.clone();
        let query_coalescer_udp = query_coalescer.clone();
        let anycast_udp = anycast_mgr.clone();
        
        let udp_buffer_size = config.limits.udp_buffer_size;

        tokio::spawn(async move {
            let mut buf = vec![0u8; udp_buffer_size];
            
            loop {
                tokio::select! {
                    result = anycast_udp.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src, dest_ip)) => {
                                let client_ip = src.ip();
                                
                                let allowed = if let Some(rl) = &rate_limiter_udp {
                                    rl.check_ip(client_ip).is_ok()
                                } else {
                                    true
                                };
                                
                                if !allowed {
                                    tracing::debug!("Anycast DNS query rate limited for {}", client_ip);
                                    continue;
                                }
                                
                                let query_validator = query_validator_udp.as_ref();
                                if let Some(validator) = query_validator {
                                    if let Err(resp) = validator.validate_query_with_response(&buf[..len]) {
                                        if let Some(response) = resp {
                                            if let Err(e) = anycast_udp.send_to(&response, src, dest_ip).await {
                                                tracing::debug!("Failed to send error response: {}", e);
                                            }
                                        }
                                        continue;
                                    }
                                }
                                
                                let query_name = Self::extract_query_name(&buf[..len]);
                                
                                if let Some(fw) = firewall_udp.as_ref() {
                                    let mut firewall = fw.write();
                                    match firewall.evaluate_query(&buf[..len], client_ip, &query_name) {
                                        Ok(decision) => {
                                            match decision.action {
                                                super::firewall::DnsFirewallAction::Block => {
                                                    tracing::warn!(
                                                        "Anycast DNS query blocked by firewall: rule={} client={} qname={}",
                                                        decision.rule_id,
                                                        client_ip,
                                                        query_name
                                                    );
                                                    continue;
                                                }
                                                _ => {}
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("Firewall evaluation error: {}", e);
                                        }
                                    }
                                }
                                
                                let cache_key = CacheKey::new(
                                    String::new(),
                                    RecordType::NULL,
                                    Some(client_ip),
                                );
                                
                                let dnssec = dnssec_udp.clone();
                                let signer_name = signer_name_udp.clone();
                                
                                let response = if let Some(ref coalescer) = query_coalescer_udp {
                                    let query_key = super::query_coalesce::QueryKey::from_query(&buf[..len], Some(client_ip));
                                    
                                    if let Some(key) = query_key {
                                        match coalescer.get_or_wait(key.clone()) {
                                            Some(super::query_coalesce::CoalesceResult::Response(resp)) => {
                                                Some(resp)
                                            }
                                            Some(super::query_coalesce::CoalesceResult::NewQuery(_)) => {
                                                if let Some(ref c) = cache_udp {
                                                    Self::handle_query_with_cache(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        negative_cache_ttl,
                                                        c,
                                                        cache_key,
                                                        dnssec.as_ref(),
                                                        signer_name.as_ref(),
                                                        Some(client_ip),
                                                        zone_transfer_udp.as_ref(),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                } else {
                                                    Self::handle_query(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        Some(client_ip),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                }
                                            }
                                            None => {
                                                if let Some(ref c) = cache_udp {
                                                    Self::handle_query_with_cache(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        negative_cache_ttl,
                                                        c,
                                                        cache_key,
                                                        dnssec.as_ref(),
                                                        signer_name.as_ref(),
                                                        Some(client_ip),
                                                        zone_transfer_udp.as_ref(),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                } else {
                                                    Self::handle_query(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        Some(client_ip),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                }
                                            }
                                            _ => {
                                                if let Some(ref c) = cache_udp {
                                                    Self::handle_query_with_cache(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        negative_cache_ttl,
                                                        c,
                                                        cache_key,
                                                        dnssec.as_ref(),
                                                        signer_name.as_ref(),
                                                        Some(client_ip),
                                                        zone_transfer_udp.as_ref(),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                } else {
                                                    Self::handle_query(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        Some(client_ip),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                }
                                            }
                                        }
                                    } else {
                                        if let Some(ref c) = cache_udp {
                                            Self::handle_query_with_cache(
                                                &zones_udp,
                                                &zone_trie_udp,
                                                &buf[..len],
                                                mesh_registry_udp.as_ref(),
                                                geoip_lookup_udp.as_ref(),
                                                min_geo_ttl,
                                                negative_cache_ttl,
                                                c,
                                                cache_key,
                                                dnssec.as_ref(),
                                                signer_name.as_ref(),
                                                Some(client_ip),
                                                zone_transfer_udp.as_ref(),
                                                &ecs_filter_config_udp,
update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                } else {
                                                    Self::handle_query(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        Some(client_ip),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                }
                                    }
                                } else if let Some(ref c) = cache_udp {
                                    Self::handle_query_with_cache(
                                        &zones_udp,
                                        &zone_trie_udp,
                                        &buf[..len],
                                        mesh_registry_udp.as_ref(),
                                        geoip_lookup_udp.as_ref(),
                                        min_geo_ttl,
                                        negative_cache_ttl,
                                        c,
                                        cache_key,
                                        dnssec.as_ref(),
                                        signer_name.as_ref(),
                                        Some(client_ip),
                                        zone_transfer_udp.as_ref(),
                                        &ecs_filter_config_udp,
                                        update_handler_udp.as_ref(),
                                        notify_handler_udp.as_ref(),
                                    )
                                } else {
                                    Self::handle_query(
                                        &zones_udp,
                                        &zone_trie_udp,
                                        &buf[..len],
                                        mesh_registry_udp.as_ref(),
                                        geoip_lookup_udp.as_ref(),
                                        min_geo_ttl,
                                        Some(client_ip),
                                        &ecs_filter_config_udp,
                                        update_handler_udp.as_ref(),
                                        notify_handler_udp.as_ref(),
                                    )
                                };
                                
                                if let Some(ref resp) = response {
                                    if rrl_enabled_udp {
                                        if let Some(rl) = rate_limiter_udp.as_ref() {
                                            if !rl.should_respond(client_ip) {
                                                tracing::debug!("Anycast RRL dropping response to {}", client_ip);
                                                continue;
                                            }
                                        }
                                    }
                                    
                                    if let Err(e) = anycast_udp.send_to(resp, src, dest_ip).await {
                                        tracing::debug!("Anycast DNS send error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Anycast recv error: {}", e);
                            }
                        }
                    }
                    _ = &mut rx_udp => {
                        tracing::info!("Anycast DNS server shutting down (UDP)");
                        let _ = tx_tcp.send(());
                        break;
                    }
                }
            }
        });

        tracing::info!("Anycast DNS UDP server started on {:?}", bound_addresses);

        let anycast_mgr_tcp = anycast_manager.clone();
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let mut shutdown_rx = shutdown_tx.subscribe();

        let zones_tcp = zones.clone();
        let zone_trie_tcp = zone_trie.clone();
        let zone_index_tcp = zone_index.clone();
        let rate_limiter_tcp = rate_limiter.clone();
        let query_validator_tcp = query_validator.clone();
        let firewall_tcp = firewall.clone();
        let connection_limits_tcp = connection_limits.clone();
        let mesh_registry_tcp = mesh_registry.clone();
        let geoip_lookup_tcp = geoip_lookup.clone();
        let min_geo_ttl = min_geo_ttl;
        let cache_tcp = cache.clone();
        let dnssec_tcp = dnssec.clone();
        let signer_name_tcp = signer_name.clone();
        let zone_transfer_tcp = zone_transfer.clone();
        let ecs_filter_config_tcp = ecs_filter_config.clone();
        let update_handler_tcp = update_handler.clone();
        let notify_handler_tcp = notify_handler.clone();
        let rrl_enabled_tcp = rrl_enabled;
        let query_coalescer_tcp = query_coalescer.clone();
        
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = anycast_mgr_tcp.accept_tcp() => {
                        match result {
                            Ok(conn) => {
                                let client_ip = conn.peer_addr.ip();
                                let dest_ip = conn.dest_ip;
                                
                                let allowed = if let Some(rl) = &rate_limiter_tcp {
                                    rl.check_ip(client_ip).is_ok()
                                } else {
                                    true
                                };
                                
                                if !allowed {
                                    tracing::debug!("Anycast DNS TCP query rate limited for {}", client_ip);
                                    continue;
                                }
                                
                                let connection_limits = connection_limits_tcp.clone();
                                match connection_limits.try_acquire_connection() {
                                    Ok(_guard) => {}
                                    Err(e) => {
                                        tracing::warn!("Anycast TCP connection rejected by limits: {}", e);
                                        continue;
                                    }
                                }
                                
                                let zones_clone = zones_tcp.clone();
                                let zone_trie_clone = zone_trie_tcp.clone();
                                let zone_index_clone = zone_index_tcp.clone();
                                let mesh_registry_clone = mesh_registry_tcp.clone();
                                let geoip_lookup_clone = geoip_lookup_tcp.clone();
                                let cache_clone = cache_tcp.clone();
                                let dnssec_clone = dnssec_tcp.clone();
                                let signer_name_clone = signer_name_tcp.clone();
                                let query_validator_clone = query_validator_tcp.clone();
                                let firewall_clone = firewall_tcp.clone();
                                let zone_transfer_clone = zone_transfer_tcp.clone();
                                let ecs_filter_clone = ecs_filter_config_tcp.clone();
                                let rate_limiter_clone = rate_limiter_tcp.clone();
                                let update_handler_clone = update_handler_tcp.clone();
                                let notify_handler_clone = notify_handler_tcp.clone();
                                let query_coalescer_clone = query_coalescer_tcp.clone();
                                
                                tokio::spawn(async move {
                                    let max_idle_time = Some(std::time::Duration::from_secs(
                                        connection_limits.max_tcp_idle_time().as_secs()
                                    ));
                                    tracing::debug!("TCP connection from {} to anycast IP {}", client_ip, dest_ip);
                                    if let Err(e) = Self::handle_tcp_query(conn.stream, &zones_clone, &zone_trie_clone, &zone_index_clone, mesh_registry_clone.as_ref(), geoip_lookup_clone.as_ref(), min_geo_ttl, negative_cache_ttl, cache_clone.as_ref(), dnssec_clone.as_ref(), signer_name_clone.as_ref(), query_validator_clone.as_ref(), firewall_clone.as_ref(), Some(&connection_limits), max_idle_time, zone_transfer_clone.as_ref(), &ecs_filter_clone, rate_limiter_clone.as_ref(), rrl_enabled_tcp, update_handler_clone.as_ref(), notify_handler_clone.as_ref(), query_coalescer_clone.as_ref()).await {
                                        tracing::debug!("Anycast TCP DNS error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("Anycast DNS TCP accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("Anycast DNS TCP server shutting down");
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }

    async fn start_standard_mode(&mut self) -> Result<(), String> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], self.config.port));

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DNS UDP socket: {}", e))?;

        let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DNS TCP socket: {}", e))?;

        tracing::info!("DNS server listening on {} (UDP + TCP)", bind_addr);

        let zones = self.zones.clone();
        let zone_index = self.zone_index.clone();
        let rate_limiter = self.rate_limiter.clone();
        let mesh_registry = self.mesh_registry.clone();
        let geoip_lookup = self.geoip_lookup.clone();
        let query_validator = self.query_validator.clone();
        let firewall = self.firewall.clone();
        let connection_limits = self.connection_limits.clone();
        let min_geo_ttl = self.config.settings.min_geo_ttl;
        let negative_cache_ttl = self.config.settings.negative_cache_ttl;
        let cache = self.cache.clone();
        let dnssec = self.dnssec.clone();
        let signer_name = self.signer_name.clone();
        let rrl_enabled = self.rrl_enabled;
        let zone_transfer = self.zone_transfer.clone();
        let ecs_filter_config = self.ecs_filter_config.clone();
        let update_handler = self.update_handler.clone();
        let notify_handler = self.notify_handler.clone();
        let query_coalescer = self.query_coalescer.clone();
        
        let (tx_udp, mut rx_udp) = tokio::sync::oneshot::channel::<()>();
        let (tx_tcp, mut rx_tcp) = tokio::sync::oneshot::channel::<()>();
        let tx = tx_udp;
        self.shutdown_tx = Some(tx);

        let zones_udp = zones.clone();
        let zone_trie_udp = self.zone_trie.clone();
        let _zone_index_udp = zone_index.clone();
        let rate_limiter_udp = rate_limiter.clone();
        let query_validator_udp = query_validator.clone();
        let firewall_udp = firewall.clone();
        let mesh_registry_udp = mesh_registry.clone();
        let geoip_lookup_udp = geoip_lookup.clone();
        let cache_udp = cache.clone();
        let dnssec_udp = dnssec.clone();
        let signer_name_udp = signer_name.clone();
        let rrl_enabled_udp = rrl_enabled;
        let zone_transfer_udp = zone_transfer.clone();
        let ecs_filter_config_udp = ecs_filter_config.clone();
        let update_handler_udp = update_handler.clone();
        let notify_handler_udp = notify_handler.clone();
        let query_coalescer_udp = query_coalescer.clone();
        let udp_buffer_size = self.config.limits.udp_buffer_size;
        
        tokio::spawn(async move {
            let mut buf = vec![0u8; udp_buffer_size];
            
            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                let client_ip = src.ip();
                                
                                let allowed = if let Some(rl) = &rate_limiter_udp {
                                    rl.check_ip(client_ip).is_ok()
                                } else {
                                    true
                                };
                                
                                if !allowed {
                                    tracing::debug!("DNS query rate limited for {}", client_ip);
                                    continue;
                                }
                                
                                // Validate query structure
                                let query_validator = query_validator_udp.as_ref();
                                if let Some(validator) = query_validator {
                                    if let Err(resp) = validator.validate_query_with_response(&buf[..len]) {
                                        if let Some(response) = resp {
                                            if let Err(e) = socket.send_to(&response, &src).await {
                                                tracing::debug!("Failed to send error response: {}", e);
                                            }
                                        }
                                        continue;
                                    }
                                }
                                
                                // Extract query name once for firewall and RRL checks
                                let query_name = Self::extract_query_name(&buf[..len]);
                                
                                // Firewall check
                                if let Some(fw) = firewall_udp.as_ref() {
                                    let mut firewall = fw.write();
                                    match firewall.evaluate_query(&buf[..len], client_ip, &query_name) {
                                        Ok(decision) => {
                                            match decision.action {
                                                super::firewall::DnsFirewallAction::Block => {
                                                    tracing::warn!(
                                                        "DNS query blocked by firewall: rule={} client={} qname={}",
                                                        decision.rule_id,
                                                        client_ip,
                                                        query_name
                                                    );
                                                    continue;
                                                }
                                                _ => {}
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("Firewall evaluation error: {}", e);
                                        }
                                    }
                                }
                                
                                let cache_key = CacheKey::new(
                                    String::new(),
                                    RecordType::NULL,
                                    Some(client_ip),
                                );
                                
                                let dnssec = dnssec_udp.clone();
                                let signer_name = signer_name_udp.clone();
                                let rate_limiter = rate_limiter_udp.clone();
                                let rrl_enabled = rrl_enabled_udp;
                                
                                let response = if let Some(ref coalescer) = query_coalescer_udp {
                                    let query_key = super::query_coalesce::QueryKey::from_query(&buf[..len], Some(client_ip));
                                    
                                    if let Some(key) = query_key {
                                        match coalescer.get_or_wait(key.clone()) {
                                            Some(super::query_coalesce::CoalesceResult::Response(resp)) => {
                                                Some(resp)
                                            }
                                            Some(super::query_coalesce::CoalesceResult::NewQuery(_)) => {
                                                if let Some(ref c) = cache_udp {
                                                    Self::handle_query_with_cache(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        negative_cache_ttl,
                                                        c,
                                                        cache_key,
                                                        dnssec.as_ref(),
                                                        signer_name.as_ref(),
                                                        Some(client_ip),
                                                        zone_transfer_udp.as_ref(),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                } else {
                                                    Self::handle_query(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        Some(client_ip),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                }
                                            }
                                            None => {
                                                if let Some(ref c) = cache_udp {
                                                    Self::handle_query_with_cache(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        negative_cache_ttl,
                                                        c,
                                                        cache_key,
                                                        dnssec.as_ref(),
                                                        signer_name.as_ref(),
                                                        Some(client_ip),
                                                        zone_transfer_udp.as_ref(),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                } else {
                                                    Self::handle_query(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        Some(client_ip),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                }
                                            }
                                            _ => {
                                                if let Some(ref c) = cache_udp {
                                                    Self::handle_query_with_cache(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        negative_cache_ttl,
                                                        c,
                                                        cache_key,
                                                        dnssec.as_ref(),
                                                        signer_name.as_ref(),
                                                        Some(client_ip),
                                                        zone_transfer_udp.as_ref(),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                } else {
                                                    Self::handle_query(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                        mesh_registry_udp.as_ref(),
                                                        geoip_lookup_udp.as_ref(),
                                                        min_geo_ttl,
                                                        Some(client_ip),
                                                        &ecs_filter_config_udp,
                                                        update_handler_udp.as_ref(),
                                                        notify_handler_udp.as_ref(),
                                                    )
                                                }
                                            }
                                        }
                                    } else {
                                        if let Some(ref c) = cache_udp {
                                            Self::handle_query_with_cache(
                                                &zones_udp,
                                                &zone_trie_udp,
                                                &buf[..len],
                                                mesh_registry_udp.as_ref(),
                                                geoip_lookup_udp.as_ref(),
                                                min_geo_ttl,
                                                negative_cache_ttl,
                                                c,
                                                cache_key,
                                                dnssec.as_ref(),
                                                signer_name.as_ref(),
                                                Some(client_ip),
                                                zone_transfer_udp.as_ref(),
                                                &ecs_filter_config_udp,
                                                update_handler_udp.as_ref(),
                                                notify_handler_udp.as_ref(),
                                            )
                                                } else {
                                                    Self::handle_query(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                                mesh_registry_udp.as_ref(),
                                                geoip_lookup_udp.as_ref(),
                                                min_geo_ttl,
                                                Some(client_ip),
                                                &ecs_filter_config_udp,
                                                update_handler_udp.as_ref(),
                                                notify_handler_udp.as_ref(),
                                            )
                                        }
                                    }
                                } else if let Some(ref c) = cache_udp {
                                    Self::handle_query_with_cache(
                                        &zones_udp,
                                        &zone_trie_udp,
                                        &buf[..len],
                                        mesh_registry_udp.as_ref(),
                                        geoip_lookup_udp.as_ref(),
                                        min_geo_ttl,
                                        negative_cache_ttl,
                                        c,
                                        cache_key,
                                        dnssec.as_ref(),
                                        signer_name.as_ref(),
                                        Some(client_ip),
                                        zone_transfer_udp.as_ref(),
                                        &ecs_filter_config_udp,
                                        update_handler_udp.as_ref(),
                                        notify_handler_udp.as_ref(),
                                    )
                                                } else {
                                                    Self::handle_query(
                                                        &zones_udp,
                                                        &zone_trie_udp,
                                                        &buf[..len],
                                        mesh_registry_udp.as_ref(),
                                        geoip_lookup_udp.as_ref(),
                                        min_geo_ttl,
                                        Some(client_ip),
                                        &ecs_filter_config_udp,
                                        update_handler_udp.as_ref(),
                                        notify_handler_udp.as_ref(),
                                    )
                                };
                                if let Some(ref resp) = response {
                                    if rrl_enabled {
                                        if let Some(rl) = rate_limiter.as_ref() {
                                            if !rl.should_respond(client_ip) {
                                                tracing::debug!("RRL dropping response to {}", client_ip);
                                                continue;
                                            }
                                        }
                                    }
                                    
                                    let _ = socket.send_to(resp, src).await;
                                }
                            }
                            Err(e) => {
                                tracing::error!("DNS recv error: {}", e);
                            }
                        }
                    }
                    _ = &mut rx_udp => {
                        tracing::info!("DNS server shutting down (UDP)");
                        let _ = tx_tcp.send(());
                        break;
                    }
                }
            }
        });

        let zones_tcp = zones.clone();
        let zone_trie_tcp = self.zone_trie.clone();
        let zone_index_tcp = zone_index.clone();
        let rate_limiter_tcp = rate_limiter.clone();
        let query_validator_tcp = query_validator.clone();
        let firewall_tcp = firewall.clone();
        let connection_limits_tcp = connection_limits.clone();
        let mesh_registry_tcp = mesh_registry.clone();
        let geoip_lookup_tcp = geoip_lookup.clone();
        let min_geo_ttl = min_geo_ttl;
        let cache_tcp = cache;
        let dnssec_tcp = dnssec;
        let signer_name_tcp = signer_name;
        let zone_transfer_tcp = zone_transfer;
        let ecs_filter_config = self.ecs_filter_config.clone();
        let ecs_filter_config_tcp = ecs_filter_config.clone();
        let update_handler_tcp = self.update_handler.clone();
        let notify_handler_tcp = self.notify_handler.clone();
        let rrl_enabled_tcp = rrl_enabled;
        let udp_buffer_size = self.config.limits.udp_buffer_size;
        let query_coalescer_tcp = query_coalescer.clone();

        tokio::spawn(async move {
            let _buf = vec![0u8; udp_buffer_size];
            
            loop {
                tokio::select! {
                    result = tcp_listener.accept() => {
                        match result {
                            Ok((stream, _src)) => {
                                let client_ip = stream.peer_addr().map(|a| a.ip()).unwrap_or_else(|_| IpAddr::from([0,0,0,0]));
                                
                                let allowed = if let Some(rl) = &rate_limiter_tcp {
                                    rl.check_ip(client_ip).is_ok()
                                } else {
                                    true
                                };
                                
                                if !allowed {
                                    tracing::debug!("DNS TCP query rate limited for {}", client_ip);
                                    continue;
                                }
                                
                                let connection_limits = connection_limits_tcp.clone();
                                match connection_limits.try_acquire_connection() {
                                    Ok(_guard) => {}
                                    Err(e) => {
                                        tracing::warn!("Connection rejected by limits: {}", e);
                                        continue;
                                    }
                                }
                                
                                let zones_clone = zones_tcp.clone();
                                let zone_trie_clone = zone_trie_tcp.clone();
                                let zone_index_clone = zone_index_tcp.clone();
                                let mesh_registry_clone = mesh_registry_tcp.clone();
                                let geoip_lookup_clone = geoip_lookup_tcp.clone();
                                let cache_clone = cache_tcp.clone();
                                let dnssec_clone = dnssec_tcp.clone();
                                let signer_name_clone = signer_name_tcp.clone();
                                let query_validator_clone = query_validator_tcp.clone();
                                let firewall_clone = firewall_tcp.clone();
                                let zone_transfer_clone = zone_transfer_tcp.clone();
                                let ecs_filter_clone = ecs_filter_config_tcp.clone();
                                let rate_limiter_clone = rate_limiter_tcp.clone();
                                let update_handler_clone = update_handler_tcp.clone();
                                let notify_handler_clone = notify_handler_tcp.clone();
                                let query_coalescer_clone = query_coalescer_tcp.clone();
                                
                                tokio::spawn(async move {
                                    let max_idle_time = Some(std::time::Duration::from_secs(
                                        connection_limits.max_tcp_idle_time().as_secs()
                                    ));
                                    if let Err(e) = Self::handle_tcp_query(stream, &zones_clone, &zone_trie_clone, &zone_index_clone, mesh_registry_clone.as_ref(), geoip_lookup_clone.as_ref(), min_geo_ttl, negative_cache_ttl, cache_clone.as_ref(), dnssec_clone.as_ref(), signer_name_clone.as_ref(), query_validator_clone.as_ref(), firewall_clone.as_ref(), Some(&connection_limits), max_idle_time, zone_transfer_clone.as_ref(), &ecs_filter_clone, rate_limiter_clone.as_ref(), rrl_enabled_tcp, update_handler_clone.as_ref(), notify_handler_clone.as_ref(), query_coalescer_clone.as_ref()).await {
                                        tracing::debug!("TCP DNS error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("DNS TCP accept error: {}", e);
                            }
                        }
                    }
                    _ = &mut rx_tcp => {
                        tracing::info!("DNS server shutting down (TCP)");
                        break;
                    }
                }
            }
        });

        if self.config.dot.enabled {
            let mut dot = DotServer::new(self.config.dot.clone(), self.cert_resolver.clone());
            dot.set_dns_server(self.clone());
            if let Err(e) = dot.start().await {
                tracing::warn!("Failed to start DoT server: {}", e);
            } else {
                tracing::info!("DoT server started on port {}", self.config.dot.port);
            }
            self.dot_server = Some(dot);
        }

        if self.config.doh.enabled {
            let mut doh = DohServer::new(self.config.doh.clone(), self.cert_resolver.clone());
            doh.set_dns_server(self.clone());
            if let Err(e) = doh.start().await {
                tracing::warn!("Failed to start DoH server: {}", e);
            } else {
                tracing::info!("DoH server started on port {}", self.config.doh.port);
            }
            self.doh_server = Some(doh);
        }

        if self.config.doq.enabled {
            let mut doq = DoqServer::new(self.config.doq.clone(), self.cert_resolver.clone());
            doq.set_dns_server(self.clone());
            if let Err(e) = doq.start(std::net::SocketAddr::from(([0,0,0,0], self.config.doq.port)), self.clone()).await {
                tracing::warn!("Failed to start DoQ server: {}", e);
            } else {
                tracing::info!("DoQ server started on port {}", self.config.doq.port);
            }
            self.doq_server = Some(doq);
        }

        Ok(())
    }

    async fn handle_tcp_query(
        mut stream: tokio::net::TcpStream,
        zones: &Arc<RwLock<HashMap<String, Zone>>>,
        zone_trie: &Arc<RwLock<super::zone_trie::ZoneTrie>>,
        _zone_index: &Arc<RwLock<Vec<(String, String)>>>,
        mesh_registry: Option<&Arc<MeshDnsRegistry>>,
        geoip_lookup: Option<&Arc<crate::geoip::GeoIpManager>>,
        min_geo_ttl: u32,
        negative_cache_ttl: u32,
        cache: Option<&Arc<DnsCache>>,
        dnssec: Option<&Arc<RwLock<DnsSecKeyManager>>>,
        signer_name: Option<&String>,
        query_validator: Option<&DnsQueryValidator>,
        firewall: Option<&Arc<RwLock<super::firewall::DnsFirewall>>>,
        connection_limits: Option<&Arc<super::limits::ConnectionLimits>>,
        max_idle_time: Option<std::time::Duration>,
        zone_transfer: Option<&Arc<super::transfer::ZoneTransfer>>,
        ecs_filter_config: &super::edns::EcsFilterConfig,
        rate_limiter: Option<&Arc<DnsRateLimiter>>,
        rrl_enabled: bool,
        update_handler: Option<&super::update::DynamicUpdateHandler>,
        notify_handler: Option<&super::notify::NotifyHandler>,
        query_coalescer: Option<&Arc<super::query_coalesce::QueryCoalescer>>,
    ) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};
        
        let client_ip = stream.peer_addr().map(|a| a.ip()).unwrap_or_else(|_| IpAddr::from([0,0,0,0]));
        
        let idle_timeout = max_idle_time.unwrap_or(Duration::from_secs(30));
        
        let mut length_buf = [0u8; 2];
        let read_result = timeout(idle_timeout, stream.read_exact(&mut length_buf)).await;
        
        match read_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("TCP read error: {}", e)),
            Err(_) => {
                tracing::debug!("TCP connection idle timeout for {}", client_ip);
                return Err("Connection idle timeout".to_string());
            }
        }
        
        let len = u16::from_be_bytes([length_buf[0], length_buf[1]]) as usize;
        
        if len > 65535 {
            return Err("DNS query too large".to_string());
        }
        
        let mut query = vec![0u8; len];
        
        let read_result = timeout(idle_timeout, stream.read_exact(&mut query)).await;
        
        match read_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("TCP read error: {}", e)),
            Err(_) => {
                tracing::debug!("TCP query read timeout for {}", client_ip);
                return Err("Query read timeout".to_string());
            }
        }
        
        // Validate query structure
        if let Some(validator) = query_validator {
            if let Err(resp) = validator.validate_query_with_response(&query) {
                if let Some(response) = resp {
                    let len = response.len() as u16;
                    let mut response_buf = len.to_be_bytes().to_vec();
                    response_buf.extend_from_slice(&response);
                    if let Err(e) = stream.write_all(&response_buf).await {
                        tracing::debug!("Failed to send error response: {}", e);
                    }
                }
                tracing::debug!("Invalid DNS TCP query from {}: validation failed", client_ip);
                return Err("Invalid query".to_string());
            }
        }
        
        // Firewall check
        if let Some(fw) = firewall.as_ref() {
            let qname = Self::extract_query_name(&query);
            let mut fw_read = fw.write();
            match fw_read.evaluate_query(&query, client_ip, &qname) {
                Ok(decision) => {
                    match decision.action {
                        super::firewall::DnsFirewallAction::Block => {
                            tracing::warn!(
                                "DNS TCP query blocked by firewall: rule={} client={} qname={}",
                                decision.rule_id,
                                client_ip,
                                qname
                            );
                            return Err("Blocked by firewall".to_string());
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    tracing::warn!("TCP Firewall evaluation error: {}", e);
                }
            }
        }
        
        let cache_key = CacheKey::new(
            String::new(),
            RecordType::NULL,
            Some(client_ip),
        );
        
        let response = if let Some(coalescer) = query_coalescer {
            let query_key = super::query_coalesce::QueryKey::from_query(&query, Some(client_ip));
            
            if let Some(key) = query_key {
                match coalescer.get_or_wait(key.clone()) {
                    Some(super::query_coalesce::CoalesceResult::Response(resp)) => {
                        Some(resp)
                    }
                    Some(super::query_coalesce::CoalesceResult::NewQuery(_)) => {
                        if let Some(c) = cache {
                            Self::handle_query_with_cache(
                                zones,
                                zone_trie,
                                &query,
                                mesh_registry,
                                geoip_lookup,
                                min_geo_ttl,
                                negative_cache_ttl,
                                c,
                                cache_key,
                                dnssec,
                                signer_name,
                                Some(client_ip),
                                zone_transfer,
                                ecs_filter_config,
                                update_handler,
                                notify_handler,
                            )
                        } else {
                            Self::handle_query(
                                zones,
                                zone_trie,
                                &query,
                                mesh_registry,
                                geoip_lookup,
                                min_geo_ttl,
                                Some(client_ip),
                                ecs_filter_config,
                                update_handler,
                                notify_handler,
                            )
                        }
                    }
                    None => {
                        if let Some(c) = cache {
                            Self::handle_query_with_cache(
                                zones,
                                zone_trie,
                                &query,
                                mesh_registry,
                                geoip_lookup,
                                min_geo_ttl,
                                negative_cache_ttl,
                                c,
                                cache_key,
                                dnssec,
                                signer_name,
                                Some(client_ip),
                                zone_transfer,
                                ecs_filter_config,
                                update_handler,
                                notify_handler,
                            )
                        } else {
                            Self::handle_query(
                                zones,
                                zone_trie,
                                &query,
                                mesh_registry,
                                geoip_lookup,
                                min_geo_ttl,
                                Some(client_ip),
                                ecs_filter_config,
                                update_handler,
                                notify_handler,
                            )
                        }
                    }
                    _ => {
                        if let Some(c) = cache {
                            Self::handle_query_with_cache(
                                zones,
                                zone_trie,
                                &query,
                                mesh_registry,
                                geoip_lookup,
                                min_geo_ttl,
                                negative_cache_ttl,
                                c,
                                cache_key,
                                dnssec,
                                signer_name,
                                Some(client_ip),
                                zone_transfer,
                                ecs_filter_config,
                                update_handler,
                                notify_handler,
                            )
                        } else {
                            Self::handle_query(
                                zones,
                                zone_trie,
                                &query,
                                mesh_registry,
                                geoip_lookup,
                                min_geo_ttl,
                                Some(client_ip),
                                ecs_filter_config,
                                update_handler,
                                notify_handler,
                            )
                        }
                    }
                }
            } else {
                if let Some(c) = cache {
                    Self::handle_query_with_cache(
                        zones,
                        zone_trie,
                        &query,
                        mesh_registry,
                        geoip_lookup,
                        min_geo_ttl,
                        negative_cache_ttl,
                        c,
                        cache_key,
                        dnssec,
                        signer_name,
                        Some(client_ip),
                        zone_transfer,
                        ecs_filter_config,
                        update_handler,
                        notify_handler,
                    )
                } else {
                    Self::handle_query(
                        zones,
                        zone_trie,
                        &query,
                        mesh_registry,
                        geoip_lookup,
                        min_geo_ttl,
                        Some(client_ip),
                        ecs_filter_config,
                        update_handler,
                        notify_handler,
                    )
                }
            }
        } else if let Some(c) = cache {
            Self::handle_query_with_cache(
                zones,
                zone_trie,
                &query,
                mesh_registry,
                geoip_lookup,
                min_geo_ttl,
                negative_cache_ttl,
                c,
                cache_key,
                dnssec,
                signer_name,
                Some(client_ip),
                zone_transfer,
                ecs_filter_config,
                update_handler,
                notify_handler,
            )
        } else {
            Self::handle_query(
                zones,
                zone_trie,
                &query,
                mesh_registry,
                geoip_lookup,
                min_geo_ttl,
                Some(client_ip),
                ecs_filter_config,
                update_handler,
                notify_handler,
            )
        };
        
        if let Some(resp) = response {
            // Check if this is a zone transfer (AXFR/IXFR) - need special multi-message handling for TCP
            if let Some(zt) = zone_transfer {
                // Detect zone transfer by checking query type at offset 20
                let query_qtype = if query.len() >= 22 {
                    u16::from_be_bytes([query[20], query[21]])
                } else { 0 };

                if query_qtype == super::transfer::AXFR_QUERY_TYPE {
                    let qname = Self::extract_query_name(&query);
                    let tsig = super::tsig::parse_tsig_from_query(&query, 22);
                    match zt.handle_axfr_request_messages(&qname, client_ip, tsig.as_ref()) {
                        Ok(messages) => {
                            for msg in messages {
                                let len = msg.len() as u16;
                                let mut buf = len.to_be_bytes().to_vec();
                                buf.extend_from_slice(&msg);
                                stream.write_all(&buf).await.map_err(|e| e.to_string())?;
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            tracing::warn!("AXFR multi-message failed: {}", e);
                            return Err(format!("AXFR failed: {}", e));
                        }
                    }
                }
                
                if query_qtype == super::transfer::IXFR_QUERY_TYPE {
                    let qname = Self::extract_query_name(&query);
                    let serial = Self::extract_ixfr_serial(&query);
                    let tsig = super::tsig::parse_tsig_from_query(&query, 22);
                    match zt.handle_ixfr_request_messages(&qname, client_ip, serial, tsig.as_ref()) {
                        Ok(messages) => {
                            for msg in messages {
                                let len = msg.len() as u16;
                                let mut buf = len.to_be_bytes().to_vec();
                                buf.extend_from_slice(&msg);
                                stream.write_all(&buf).await.map_err(|e| e.to_string())?;
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            tracing::warn!("IXFR multi-message failed: {}", e);
                            return Err(format!("IXFR failed: {}", e));
                        }
                    }
                }
            }
            
            // Apply RRL for TCP queries if enabled
            if rrl_enabled {
                if let Some(rl) = rate_limiter {
                    if !rl.should_respond(client_ip) {
                        tracing::debug!("RRL dropping TCP response to {}", client_ip);
                        return Ok(());
                    }
                }
            }
            
            if let Some(limits) = connection_limits {
                if let Err(e) = limits.validate_response_size(resp.len()) {
                    tracing::warn!("Response size {} exceeds limit: {}", resp.len(), e);
                }
            }
            let len = resp.len() as u16;
            let mut response_buf = len.to_be_bytes().to_vec();
            response_buf.extend_from_slice(&resp);
            stream.write_all(&response_buf).await.map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }

    pub fn handle_query_with_cache(
        zones: &Arc<RwLock<HashMap<String, Zone>>>,
        zone_trie: &Arc<RwLock<super::zone_trie::ZoneTrie>>,
        query: &[u8],
        mesh_registry: Option<&Arc<MeshDnsRegistry>>,
        geoip_lookup: Option<&Arc<crate::geoip::GeoIpManager>>,
        min_geo_ttl: u32,
        negative_cache_ttl: u32,
        cache: &Arc<DnsCache>,
        mut cache_key: CacheKey,
        _dnssec: Option<&Arc<RwLock<DnsSecKeyManager>>>,
        _signer_name: Option<&String>,
        client_ip: Option<std::net::IpAddr>,
        zone_transfer: Option<&Arc<super::transfer::ZoneTransfer>>,
        ecs_filter_config: &super::edns::EcsFilterConfig,
        update_handler: Option<&super::update::DynamicUpdateHandler>,
        notify_handler: Option<&super::notify::NotifyHandler>,
    ) -> Option<Arc<Vec<u8>>> {
        if query.len() < 12 {
            return None;
        }

        let flags = u16::from_be_bytes([query[2], query[3]]);
        let opcode = (flags & 0x7800) >> 11;
        
        if opcode as u8 == super::wire::OPCODE_NOTIFY {
            if let Some(handler) = notify_handler {
                if let Some(ip) = client_ip {
                    return handler.handle_notify(query, ip).map(|r| Arc::new(r));
                }
            }
            return None;
        }
        
        if opcode as u8 == super::wire::OPCODE_UPDATE {
            if let Some(handler) = update_handler {
                if let Some(ip) = client_ip {
                    match handler.handle_update(query, ip) {
                        Ok(response) => return Some(Arc::new(response)),
                        Err(_) => return None,
                    }
                }
            }
            return None;
        }

        let mut pos = 12;
        let mut qname = String::new();
        
        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if !qname.is_empty() {
                qname.push('.');
            }
            qname.push_str(&String::from_utf8_lossy(&query[pos + 1..pos + 1 + len]));
            pos += 1 + len;
        }

        if pos + 4 > query.len() {
            return None;
        }
        
        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
        
        if qtype == super::transfer::AXFR_QUERY_TYPE {
            if let (Some(zt), Some(ip)) = (zone_transfer, client_ip) {
                let tsig = super::tsig::parse_tsig_from_query(query, pos + 4);
                match zt.handle_axfr_request(&qname, ip, tsig.as_ref()) {
                    Ok(response) => return Some(Arc::new(response)),
                    Err(e) => {
                        tracing::warn!("AXFR failed: {}", e);
                        return None;
                    }
                }
            }
            return None;
        }
        
        if qtype == super::transfer::IXFR_QUERY_TYPE {
            if let (Some(zt), Some(ip)) = (zone_transfer, client_ip) {
                let serial = Self::extract_ixfr_serial(query);
                let tsig = super::tsig::parse_tsig_from_query(query, pos + 4);
                match zt.handle_ixfr_request(&qname, ip, serial, tsig.as_ref()) {
                    Ok(response) => return Some(Arc::new(response)),
                    Err(e) => {
                        tracing::warn!("IXFR failed: {}", e);
                        return None;
                    }
                }
            }
            return None;
        }
        
        let record_type = RecordType::from(qtype);

        cache_key.qname = qname.clone();
        use super::server::RecordTypeExt;
        cache_key.qtype = record_type.to_u16();

        if let Some(cached) = cache.get(&cache_key) {
            return Some(cached);
        }

        let result = Self::handle_query(
            zones,
            zone_trie,
            query,
            mesh_registry,
            geoip_lookup,
            min_geo_ttl,
            client_ip,
            ecs_filter_config,
            None,
            None,
        );

        if let Some(ref data) = result {
            let ttl = Self::extract_ttl_from_response(data.as_ref(), negative_cache_ttl);
            if ttl > 0 {
                cache.insert(cache_key, data.as_ref().clone(), ttl);
            }
        }

        result
    }

    fn extract_ttl_from_response(response: &[u8], negative_cache_ttl: u32) -> u32 {
        if response.len() < 12 {
            return 0;
        }

        let flags = u16::from_be_bytes([response[2], response[3]]);
        let rcode = flags & 0x000F;
        let ancount = u16::from_be_bytes([response[6], response[7]]);

        if ancount == 0 {
            if rcode == 3 {
                return negative_cache_ttl;
            }
            return 0;
        }

        let mut pos = 12;
        while pos < response.len() {
            let len = response[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            pos += 1 + len;
        }
        pos += 4;

        if pos + 10 > response.len() {
            return 0;
        }

        let record_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        if record_type != 1 && record_type != 28 && record_type != 5 && record_type != 15 && record_type != 16 && record_type != 2 && record_type != 6 && record_type != 33 {
            return 0;
        }
        pos += 2;
        pos += 2;

        u32::from_be_bytes([response[pos], response[pos + 1], response[pos + 2], response[pos + 3]])
    }

    fn extract_ixfr_serial(query: &[u8]) -> Option<u32> {
        if query.len() < 16 {
            return None;
        }

        let mut pos = 12;
        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            pos += 1 + len;
        }

        if pos + 8 > query.len() {
            return None;
        }

        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
        if qtype != super::transfer::IXFR_QUERY_TYPE {
            return None;
        }

        let mut pos = pos + 4;
        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            pos += 1 + len;
        }

        if pos + 4 <= query.len() {
            Some(u32::from_be_bytes([query[pos], query[pos + 1], query[pos + 2], query[pos + 3]]))
        } else {
            None
        }
    }

    fn resolve_from_mesh(
        mesh_registry: &Arc<MeshDnsRegistry>,
        qname: &str,
        client_ip: std::net::IpAddr,
        geoip_lookup: Option<&Arc<crate::geoip::GeoIpManager>>,
        qtype: u16,
    ) -> Option<Vec<DnsZoneRecord>> {
        let domain = qname.trim_end_matches('.');

        if !mesh_registry.has_origin_for_domain(domain) {
            tracing::debug!("No origin nodes registered for domain {}", domain);
            return None;
        }

        let client_geo = if let Some(geoip) = geoip_lookup {
            geoip.get_country_info(client_ip).map(|c| c.code.clone())
        } else {
            None
        };

        let best_edge = mesh_registry.get_best_edge_for_client(
            domain,
            Some(client_ip),
            client_geo.as_deref(),
        );

        best_edge.map(|edge| {
            let record_type = match qtype {
                1 => RecordType::A,
                28 => RecordType::AAAA,
                _ => RecordType::A,
            };

            edge.ip_addresses
                .iter()
                .filter_map(|ip| {
                    let matches_query = match record_type {
                        RecordType::A => ip.parse::<std::net::Ipv4Addr>().is_ok(),
                        RecordType::AAAA => ip.parse::<std::net::Ipv6Addr>().is_ok(),
                        _ => true,
                    };
                    if matches_query {
                        Some(DnsZoneRecord {
                            name: "@".to_string(),
                            record_type,
                            value: ip.clone(),
                            ttl: 60,
                            priority: None,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
    }

    pub fn handle_query(
        zones: &Arc<RwLock<HashMap<String, Zone>>>,
        zone_trie: &Arc<RwLock<super::zone_trie::ZoneTrie>>,
        query: &[u8],
        mesh_registry: Option<&Arc<MeshDnsRegistry>>,
        geoip_lookup: Option<&Arc<crate::geoip::GeoIpManager>>,
        _min_geo_ttl: u32,
        client_ip: Option<std::net::IpAddr>,
        ecs_filter_config: &super::edns::EcsFilterConfig,
        update_handler: Option<&super::update::DynamicUpdateHandler>,
        notify_handler: Option<&super::notify::NotifyHandler>,
    ) -> Option<Arc<Vec<u8>>> {
        use super::server::RecordTypeExt;
        
        if query.len() < 12 {
            return None;
        }

        let flags = u16::from_be_bytes([query[2], query[3]]);
        let opcode = (flags & 0x7800) >> 11;
        
        if opcode as u8 == super::wire::OPCODE_NOTIFY {
            if let Some(handler) = notify_handler {
                if let Some(ip) = client_ip {
                    return handler.handle_notify(query, ip).map(|r| Arc::new(r));
                }
            }
            return None;
        }
        
        if opcode as u8 == super::wire::OPCODE_UPDATE {
            if let Some(handler) = update_handler {
                if let Some(ip) = client_ip {
                    match handler.handle_update(query, ip) {
                        Ok(response) => return Some(Arc::new(response)),
                        Err(_) => return None,
                    }
                }
            }
            return None;
        }

        let qdcount = u16::from_be_bytes([query[4], query[5]]);

        let is_query = (flags & 0x8000) == 0;
        if !is_query || qdcount == 0 {
            return None;
        }

        let mut edns_options = parse_edns_options(query);
        
        if let Some(ref mut edns) = edns_options {
            super::edns::filter_ecs(edns, ecs_filter_config);
        }
        
        let dnssec_ok = edns_options.as_ref().map(|e| e.dnssec_ok).unwrap_or(false);

        let mut pos = 12;
        let mut qname = String::new();
        
        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if !qname.is_empty() {
                qname.push('.');
            }
            qname.push_str(&String::from_utf8_lossy(&query[pos + 1..pos + 1 + len]));
            pos += 1 + len;
        }

        if pos + 4 > query.len() {
            return None;
        }

        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);

        let qname_lower = qname.to_lowercase();
        if qname_lower.ends_with(".example") || qname_lower == "example" {
            return Self::build_simple_nxdomain_response(query);
        }

        let record_type = RecordType::from(qtype);
        
        let zones_guard = zones.read();
        let trie_guard = zone_trie.read();
        
        let qname_lower = qname.to_lowercase();
        
        // Use the trie for efficient zone lookup
        let best_match = trie_guard.find_zone(&qname_lower);
        
        let (origin_str, zone) = match best_match {
            Some(origin) => {
                match zones_guard.get(&origin) {
                    Some(zone) => (origin.clone(), zone),
                    None => return None,
                }
            }
            None => return None,
        };
        
        let origin_canonical = origin_str.clone();
        let origin_lower_for_strip = origin_canonical.trim_end_matches('.').to_lowercase();
        
        // Reuse qname_lower instead of calling to_lowercase again
        let qname_lower_trimmed = qname_lower.trim_end_matches('.').to_string();
        let lookup_name = if qname_lower_trimmed == origin_lower_for_strip || qname.is_empty() || qname == "@" {
            "@".to_string()
        } else {
            let suffix = format!(".{}", origin_lower_for_strip);
            match qname_lower_trimmed.strip_suffix(&suffix) {
                Some(s) => s.to_string(),
                None => qname_lower_trimmed.clone(),
            }
        };

        let key = (lookup_name.clone(), record_type);
        if let Some(records) = zone.records.get(&key) {
            return Some(Self::build_response(&qname, qtype, records, dnssec_ok, edns_options.as_ref(), zone.zsk_key.as_ref(), &origin_canonical));
        }

        if record_type == RecordTypeExt::UNKNOWN || record_type == RecordType::A {
            let cname_key = (lookup_name.clone(), RecordType::CNAME);
            if let Some(cname_records) = zone.records.get(&cname_key) {
                if let Some(cname) = cname_records.first() {
                    let cname_target = cname.value.trim_end_matches('.');
                    let qname_stripped = qname.trim_end_matches('.');
                    if cname_target.eq_ignore_ascii_case(qname_stripped) {
                        tracing::warn!("CNAME loop detected for {}", qname);
                        return None;
                    }
                }
                return Some(Self::build_response(&qname, qtype, cname_records, dnssec_ok, edns_options.as_ref(), zone.zsk_key.as_ref(), &origin_canonical));
            }
        }

        if qtype == 255 {
            let mut all_records = Vec::new();
            let mut seen_cname = false;
            let lookup_name_for_qtype = lookup_name.clone();

            for ((name, _rt), records) in &zone.records {
                if name == &lookup_name_for_qtype || (name == "@" && lookup_name_for_qtype.is_empty()) {
                    for record in records {
                        if record.record_type == RecordType::CNAME {
                            if !seen_cname {
                                all_records.push(record.clone());
                                seen_cname = true;
                            }
                        } else if record.record_type != RecordType::SOA
                            && record.record_type != RecordType::NS
                            && record.record_type != RecordType::DNSKEY
                            && record.record_type != RecordType::DS
                            && record.record_type != RecordType::RRSIG
                            && record.record_type != RecordType::NSEC
                            && record.record_type != RecordType::NSEC3
                            && record.record_type != RecordType::NSEC3PARAM
                        {
                            all_records.push(record.clone());
                        }
                    }
                }
            }

            if !all_records.is_empty() {
                return Some(Self::build_response(&qname, qtype, &all_records, dnssec_ok, edns_options.as_ref(), zone.zsk_key.as_ref(), &origin_canonical));
            }

            if record_type == RecordType::DNSKEY && qname_lower_trimmed == origin_lower_for_strip {
                    let dnskey_records = Self::build_dnskey_records(zone);
                    return Some(Self::build_response(&qname, qtype, &dnskey_records, dnssec_ok, edns_options.as_ref(), zone.ksk_key.as_ref(), &origin_canonical));
                }

                if qtype == 59 && qname_lower_trimmed == origin_lower_for_strip {
                    if let Some(ksk) = &zone.ksk_key {
                        let cds_records = Self::build_cds_records(ksk);
                        return Some(Self::build_response(&qname, qtype, &cds_records, dnssec_ok, edns_options.as_ref(), zone.ksk_key.as_ref(), &origin_canonical));
                    }
                }

                if qtype == 60 && qname_lower_trimmed == origin_lower_for_strip {
                    let cdnskey_records = Self::build_cdnskey_records(zone);
                    return Some(Self::build_response(&qname, qtype, &cdnskey_records, dnssec_ok, edns_options.as_ref(), zone.ksk_key.as_ref(), &origin_canonical));
                }

                if record_type == RecordType::DS && qname_lower_trimmed == origin_lower_for_strip {
                    if let Some(ksk) = &zone.ksk_key {
                        let ds_records = Self::build_ds_records(ksk);
                        return Some(Self::build_response(&qname, qtype, &ds_records, dnssec_ok, edns_options.as_ref(), zone.ksk_key.as_ref(), &origin_canonical));
                    }
                }

                if record_type == RecordType::NSEC3PARAM && qname_lower_trimmed == origin_lower_for_strip {
                    if let Some(nsec3param_record) = Self::build_nsec3param_record(zone) {
                        return Some(Self::build_response(&qname, qtype, &[nsec3param_record], dnssec_ok, edns_options.as_ref(), zone.zsk_key.as_ref(), &origin_canonical));
                    }
                }
        }

        drop(zones_guard);

        if let (Some(registry), Some(ip)) = (mesh_registry, client_ip) {
            if let Some(mesh_records) = Self::resolve_from_mesh(
                registry,
                &qname,
                ip,
                geoip_lookup,
                qtype,
            ) {
                if !mesh_records.is_empty() {
                    tracing::debug!("Resolved {} from mesh network", qname);
                    return Some(Self::build_response(&qname, qtype, &mesh_records, dnssec_ok, edns_options.as_ref(), None, &qname));
                }
            }
        }

        if dnssec_ok {
            if let Some(zones) = zones.try_read() {
                let qname_lower = qname.to_lowercase();
                for (origin, zone) in zones.iter() {
                    let origin_lower = origin.to_lowercase();
                    if qname_lower.ends_with(&origin_lower) || qname_lower == origin_lower {
                        if zone.nsec_enabled {
                            let nsec_records = Self::build_nsec_records(zone, &qname, record_type);
                            if !nsec_records.is_empty() {
                                let zsk = zone.zsk_key.as_ref();
                                return Some(Self::build_nxdomain_response(
                                    &qname,
                                    qtype,
                                    &nsec_records,
                                    dnssec_ok,
                                    edns_options.as_ref(),
                                    zsk,
                                    origin.as_str(),
                                ));
                            }
                        } else if zone.nsec3_enabled {
                            let nsec3_records = Self::build_nsec3_records(zone, &qname, record_type);
                            if !nsec3_records.is_empty() {
                                let zsk = zone.zsk_key.as_ref();
                                return Some(Self::build_nxdomain_response(
                                    &qname,
                                    qtype,
                                    &nsec3_records,
                                    dnssec_ok,
                                    edns_options.as_ref(),
                                    zsk,
                                    origin.as_str(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn build_nxdomain_response(
        qname: &str,
        qtype: u16,
        nsec3_records: &[DnsZoneRecord],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        zsk: Option<&super::dnssec::ZoneSigningKey>,
        signer_name: &str,
    ) -> Arc<Vec<u8>> {
        let mut response = Vec::new();
        
        let response_id = Self::generate_random_id();
        response.extend_from_slice(&response_id.to_be_bytes());
        
        let mut flags = 0x8583u16;
        if dnssec_ok {
            flags |= 0x0020;
        }
        response.extend_from_slice(&flags.to_be_bytes());
        
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&(nsec3_records.len() as u16).to_be_bytes());

        let name_parts: Vec<&str> = if qname.is_empty() || qname == "@" {
            vec![""]
        } else {
            qname.split('.').collect()
        };

        for part in &name_parts {
            if !part.is_empty() {
                response.push((*part).len() as u8);
                response.extend_from_slice(part.as_bytes());
            }
        }
        response.push(0);
        
        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        for nsec_record in nsec3_records {
            let nsec_name_parts: Vec<&str> = nsec_record.name.split('.').collect();
            
            for part in &nsec_name_parts {
                if !part.is_empty() {
                    response.push((*part).len() as u8);
                    response.extend_from_slice(part.as_bytes());
                }
            }
            response.push(0);

            response.extend_from_slice(&50u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&nsec_record.ttl.to_be_bytes());

            if let Ok(nsec_data) = hex::decode(&nsec_record.value) {
                response.extend_from_slice(&(nsec_data.len() as u16).to_be_bytes());
                response.extend_from_slice(&nsec_data);
            }
        }

        if dnssec_ok && !nsec3_records.is_empty() {
            if let Some(key) = zsk {
                for nsec_record in nsec3_records {
                    let rrsig = Self::create_signed_rrsig(nsec_record, signer_name, key);
                    if !rrsig.is_empty() {
                        let nsec_name_parts: Vec<&str> = nsec_record.name.split('.').collect();
                        for part in &nsec_name_parts {
                            if !part.is_empty() {
                                response.push((*part).len() as u8);
                                response.extend_from_slice(part.as_bytes());
                            }
                        }
                        response.push(0);
                        response.extend_from_slice(&46u16.to_be_bytes());
                        response.extend_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&nsec_record.ttl.to_be_bytes());
                        response.extend_from_slice(&(rrsig.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rrsig);
                    }
                }
            }
        }

        if let Some(edns) = edns_options {
            let opt_record = super::edns::EdnsOptions::build_opt_record(edns.udp_payload_size, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        } else if dnssec_ok {
            let opt_record = super::edns::EdnsOptions::build_opt_record(4096, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        }

        Arc::new(response)
    }

    fn build_dnskey_records(zone: &Zone) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();
        
        if let Some(ref ksk) = zone.ksk_key {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DNSKEY,
                value: hex::encode(&ksk.public_key),
                ttl: zone.dnskey_ttl.unwrap_or(3600),
                priority: None,
            });
        }
        
        // Per RFC 4034 Section 2.2, only KSK should be published in DNSKEY set at zone apex.
        // ZSK is used for signing but not exposed in the DNSKEY RRset.
        
        records
    }

    fn build_ds_records(ksk: &super::dnssec::ZoneSigningKey) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();
        
        if let Ok(ds_data) = super::dnssec::create_ds_record(ksk, super::dnssec::DsDigestType::Sha256) {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DS,
                value: hex::encode(&ds_data),
                ttl: 3600,
                priority: None,
            });
        }
        
        records
    }

    fn build_cds_records(ksk: &super::dnssec::ZoneSigningKey) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();
        
        if let Ok(ds_data) = super::dnssec::create_ds_record(ksk, super::dnssec::DsDigestType::Sha256) {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DS,
                value: hex::encode(&ds_data),
                ttl: 3600,
                priority: None,
            });
        }
        
        if let Ok(ds_data_sha1) = super::dnssec::create_ds_record(ksk, super::dnssec::DsDigestType::Sha1) {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DS,
                value: hex::encode(&ds_data_sha1),
                ttl: 3600,
                priority: None,
            });
        }
        
        records
    }

    pub fn export_ds_records(&self, zone_name: &str) -> Result<Vec<DsRecordExport>, String> {
        let zones = self.zones.read();
        let zone = zones.get(zone_name).ok_or("Zone not found")?;
        
        let ksk = zone.ksk_key.as_ref().ok_or("KSK not configured")?;
        
        let mut exports = Vec::new();
        
        for digest_type in &[super::dnssec::DsDigestType::Sha256, super::dnssec::DsDigestType::Sha1] {
            if let Ok(ds_data) = super::dnssec::create_ds_record(ksk, *digest_type) {
                if ds_data.len() >= 4 {
                    let key_tag = u16::from_be_bytes([ds_data[0], ds_data[1]]);
                    let algorithm = ds_data[2];
                    let digest_type_val = ds_data[3];
                    let digest = hex::encode(&ds_data[4..]);
                    
                    exports.push(DsRecordExport {
                        key_tag,
                        algorithm,
                        digest_type: digest_type_val,
                        digest,
                    });
                }
            }
        }
        
        Ok(exports)
    }

    pub fn export_ds_for_parent(&self, zone_name: &str) -> Result<String, String> {
        let exports = self.export_ds_records(zone_name)?;
        
        let mut output = String::new();
        for ds in &exports {
            let digest_name = match ds.digest_type {
                1 => "SHA1",
                2 => "SHA256",
                _ => "UNKNOWN",
            };
            output.push_str(&format!(
                "@ {} IN DS {} {} {} {}\n",
                3600, ds.key_tag, ds.algorithm, digest_name, ds.digest
            ));
        }
        
        Ok(output)
    }

    fn build_cdnskey_records(zone: &Zone) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();
        
        if let Some(ref ksk) = zone.ksk_key {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DNSKEY,
                value: hex::encode(&ksk.public_key),
                ttl: zone.dnskey_ttl.unwrap_or(3600),
                priority: None,
            });
        }
        
        if let Some(ref zsk) = zone.zsk_key {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DNSKEY,
                value: hex::encode(&zsk.public_key),
                ttl: zone.dnskey_ttl.unwrap_or(3600),
                priority: None,
            });
        }
        
        records
    }

    fn build_nsec3_records(zone: &Zone, qname: &str, _qtype: RecordType) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();
        
        let Some(ref nsec3param) = zone.nsec3param else {
            return records;
        };

        let zone_origin = zone.origin.trim_end_matches('.');
        
        let qname_lower = qname.to_lowercase();
        let mut current = qname_lower.as_str();
        
        let mut closest_encloser = String::new();
        let mut found = false;
        
        while let Some(dot_pos) = current.rfind('.') {
            let prefix = &current[..dot_pos];
            let check_name = if prefix.is_empty() {
                zone_origin.to_string()
            } else {
                format!("{}.{}", prefix, zone_origin)
            };
            
            let key_exists = zone.records.keys().any(|(name, rt)| {
                let full_name = if name == "@" || name.is_empty() {
                    zone_origin.to_string()
                } else {
                    format!("{}.{}", name, zone_origin)
                };
                full_name.to_lowercase() == check_name.to_lowercase() && rt.is_signed()
            });
            
            if key_exists {
                closest_encloser = check_name;
                found = true;
                break;
            }
            
            current = prefix;
        }
        
        if !found {
            closest_encloser = zone_origin.to_string();
        }
        
        let closest_hash = super::dnssec::hash_name_nsec3(&closest_encloser, nsec3param);
        let closest_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &closest_hash);
        
        let wildcard_name = format!("*.{}", closest_encloser);
        let wildcard_hash = super::dnssec::hash_name_nsec3(&wildcard_name, nsec3param);
        let wildcard_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &wildcard_hash);
        
        let next_closer_name = qname_lower.trim_end_matches(&closest_encloser);
        let next_closer = if next_closer_name.is_empty() || next_closer_name == "." {
            qname_lower.clone()
        } else {
            next_closer_name.trim_start_matches('.').to_string()
        };
        let _next_closer_hash = super::dnssec::hash_name_nsec3(&next_closer, nsec3param);
        
        let wildcard_types = vec![1, 2, 5, 6, 16, 28, 33];
        
        let wildcard_nsec3 = super::dnssec::create_nsec3_record(&wildcard_hash_b32, &next_closer, nsec3param, &wildcard_types);
        
        let closest_nsec3 = super::dnssec::create_nsec3_record(&closest_hash_b32, &wildcard_hash_b32, nsec3param, &wildcard_types);
        
        records.push(DnsZoneRecord {
            name: wildcard_hash_b32,
            record_type: RecordType::NSEC3,
            value: hex::encode(&wildcard_nsec3),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        });
        
        let closest_hash_b32_for_soa = closest_hash_b32.clone();
        
        records.push(DnsZoneRecord {
            name: closest_hash_b32,
            record_type: RecordType::NSEC3,
            value: hex::encode(&closest_nsec3),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        });
        
        if let Some(soa_record) = zone.records.get(&("@".to_string(), RecordType::SOA)) {
            if let Some(_) = soa_record.first() {
                let soa_hash = super::dnssec::hash_name_nsec3(zone_origin, nsec3param);
                let soa_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &soa_hash);
                
                let soa_types = vec![1, 2, 5, 6, 16, 28, 33];
                let soa_nsec3 = super::dnssec::create_nsec3_record(&soa_hash_b32, &closest_hash_b32_for_soa, nsec3param, &soa_types);
                
                records.push(DnsZoneRecord {
                    name: soa_hash_b32,
                    record_type: RecordType::NSEC3,
                    value: hex::encode(&soa_nsec3),
                    ttl: zone.dnskey_ttl.unwrap_or(3600),
                    priority: None,
                });
            }
        }
        
        records
    }

    fn build_nsec_records(zone: &Zone, qname: &str, qtype: RecordType) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();
        
        let zone_origin = zone.origin.trim_end_matches('.').to_lowercase();
        let qname_lower = qname.to_lowercase().trim_end_matches('.').to_string();
        
        let next_name = super::dnssec::find_next_name_in_zone(zone, &qname_lower)
            .unwrap_or_else(|| zone_origin.clone());
        
        let types = if qname_lower == zone_origin || qname_lower.ends_with(&format!(".{}", zone_origin)) {
            vec![1, 2, 5, 6, 15, 16, 28, 33]
        } else {
            let mut types = vec![1, 2, 5, 6];
            match qtype {
                RecordType::A => types.push(28),
                RecordType::AAAA => types.push(28),
                RecordType::MX => types.push(15),
                RecordType::TXT => types.push(16),
                RecordType::SRV => types.push(33),
                RecordType::CNAME => types.push(5),
                RecordType::NS => types.push(2),
                RecordType::SOA => types.push(6),
                _ => {}
            }
            types
        };
        
        let nsec_rdata = super::dnssec::create_nsec_record(&qname_lower, &next_name, &types);
        
        let owner_name = if qname_lower == zone_origin {
            zone_origin.clone()
        } else {
            qname_lower.clone()
        };
        
        records.push(DnsZoneRecord {
            name: owner_name,
            record_type: RecordType::NSEC,
            value: hex::encode(&nsec_rdata),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        });
        
        records
    }

    #[allow(dead_code)]
    fn build_nsec3_nodata(zone: &Zone, qname: &str, qtype: RecordType) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();
        
        let Some(ref nsec3param) = zone.nsec3param else {
            return records;
        };

        let zone_origin = zone.origin.trim_end_matches('.');
        
        let qname_hash = super::dnssec::hash_name_nsec3(qname, nsec3param);
        let qname_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &qname_hash);
        
        let _types_exists = zone.records.keys().any(|(name, _rt)| {
            let full_name = if name == "@" || name.is_empty() {
                zone_origin.to_string()
            } else {
                format!("{}.{}", name, zone_origin)
            };
            full_name.to_lowercase() == qname.to_lowercase()
        });
        
        let mut types = vec![1, 2, 5, 6];
        
        match qtype {
            RecordType::A => types.push(28),
            RecordType::AAAA => types.push(1),
            RecordType::MX => types.push(15),
            RecordType::TXT => types.push(16),
            RecordType::SRV => types.push(33),
            _ => {}
        }
        
        let next_domain = format!("*.{}", zone_origin);
        
        let nsec3_rdata = super::dnssec::create_nsec3_record(&qname_hash_b32, &next_domain, nsec3param, &types);
        
        records.push(DnsZoneRecord {
            name: qname_hash_b32,
            record_type: RecordType::NSEC3,
            value: hex::encode(&nsec3_rdata),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        });
        
        if let Some(soa_record) = zone.records.get(&("@".to_string(), RecordType::SOA)) {
            if let Some(_) = soa_record.first() {
                let soa_hash = super::dnssec::hash_name_nsec3(zone_origin, nsec3param);
                let soa_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &soa_hash);
                
                let soa_types = vec![1, 2, 5, 6, 16, 28, 33];
                let soa_nsec3 = super::dnssec::create_nsec3_record(&soa_hash_b32, qname, nsec3param, &soa_types);
                
                records.push(DnsZoneRecord {
                    name: soa_hash_b32,
                    record_type: RecordType::NSEC3,
                    value: hex::encode(&soa_nsec3),
                    ttl: zone.dnskey_ttl.unwrap_or(3600),
                    priority: None,
                });
            }
        }
        
        records
    }

    #[allow(dead_code)]
    fn is_nodata(zone: &Zone, qname: &str) -> bool {
        let zone_origin = zone.origin.trim_end_matches('.');
        
        if qname.ends_with(zone_origin) || qname == zone_origin {
            let lookup_name = if qname == zone_origin {
                "@".to_string()
            } else {
                qname.strip_suffix(&format!(".{}", zone_origin))
                    .unwrap_or(qname)
                    .to_string()
            };
            
            let has_records = zone.records.keys().any(|(name, _)| {
                name == &lookup_name || name.is_empty()
            });
            
            return has_records;
        }
        
        false
    }

    fn build_nsec3param_record(zone: &Zone) -> Option<DnsZoneRecord> {
        let Some(ref nsec3param) = zone.nsec3param else {
            return None;
        };
        
        let nsec3param_data = super::dnssec::create_nsec3param_record(nsec3param);
        
        Some(DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NSEC3PARAM,
            value: hex::encode(&nsec3param_data),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        })
    }

    fn build_response(
        qname: &str,
        qtype: u16,
        records: &[DnsZoneRecord],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        zsk: Option<&super::dnssec::ZoneSigningKey>,
        signer_name: &str,
    ) -> Arc<Vec<u8>> {
        let max_response_size = edns_options
            .map(|e| e.udp_payload_size as usize)
            .unwrap_or(512);
        
        let mut response = Vec::new();
        let mut compressor = DnsMessageCompressor::new();
        
        let response_id = Self::generate_random_id();
        response.extend_from_slice(&response_id.to_be_bytes());
        
        let mut qr_aa = 0x8580u16;
        if dnssec_ok {
            qr_aa |= 0x0020;
        }
        response.extend_from_slice(&qr_aa.to_be_bytes());
        
        response.extend_from_slice(&1u16.to_be_bytes());
        let ancount = records.len() as u16;
        response.extend_from_slice(&ancount.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        
        let mut add_count = 0usize;
        if dnssec_ok && !records.is_empty() {
            add_count = records.len();
        }
        response.extend_from_slice(&(add_count as u16).to_be_bytes());

        let qname_for_compression = if qname.is_empty() || qname == "@" {
            String::new()
        } else {
            qname.trim_end_matches('.').to_lowercase()
        };

        let question_name_offset = response.len();
        if !qname_for_compression.is_empty() {
            compressor.add_label(&qname_for_compression, question_name_offset as u16);
        }

        let name_parts: Vec<&str> = if qname.is_empty() || qname == "@" {
            vec![""]
        } else {
            qname.split('.').collect()
        };

        for part in &name_parts {
            response.push((*part).len() as u8);
            response.extend_from_slice(part.as_bytes());
        }
        response.push(0);

        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        for record in records {
            let record_name = if record.name == "@" || record.name.is_empty() {
                qname_for_compression.clone()
            } else {
                record.name.to_lowercase()
            };

            if record_name == qname_for_compression && !qname_for_compression.is_empty() {
                response.push(0xC0 | (question_name_offset >> 8) as u8);
                response.push((question_name_offset & 0xFF) as u8);
            } else {
                compressor.add_label(&record_name, response.len() as u16);
                for part in record_name.split('.') {
                    if !part.is_empty() {
                        response.push(part.len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                }
                response.push(0);
            }

            response.extend_from_slice(&u16::from(record.record_type).to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&record.ttl.to_be_bytes());

            match record.record_type {
                RecordType::A => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv4Addr>() {
                        let bytes: &[u8; 4] = &ip.octets();
                        let len = bytes.len() as u16;
                        response.extend_from_slice(&len.to_be_bytes());
                        response.extend_from_slice(bytes);
                    }
                }
                RecordType::AAAA => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv6Addr>() {
                        let bytes = ip.octets();
                        let len = bytes.len() as u16;
                        response.extend_from_slice(&len.to_be_bytes());
                        response.extend_from_slice(&bytes);
                    }
                }
                RecordType::CNAME | RecordType::NS => {
                    let mut target_parts: Vec<&str> = record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    let mut total_len = 0;
                    for part in &target_parts {
                        total_len += 1 + part.len();
                    }
                    response.extend_from_slice(&(total_len as u16).to_be_bytes());
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                }
                RecordType::TXT => {
                    let txt_value = record.value.as_bytes();
                    let mut offset = 0;
                    while offset < txt_value.len() {
                        let remaining = txt_value.len() - offset;
                        let chunk_len = std::cmp::min(remaining, 255);
                        response.push(chunk_len as u8);
                        response.extend_from_slice(&txt_value[offset..offset + chunk_len]);
                        offset += chunk_len;
                    }
                }
                RecordType::MX => {
                    let priority = record.priority.unwrap_or(10);
                    response.extend_from_slice(&2u16.to_be_bytes());
                    response.extend_from_slice(&priority.to_be_bytes());
                    let mut target_parts: Vec<&str> = record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                }
                RecordType::DNSKEY => {
                    if let Ok(key_bytes) = hex::decode(&record.value) {
                        let dnskey = compute_dnskey(&super::dnssec::ZoneSigningKey {
                            key_id: String::new(),
                            algorithm: Algorithm::Ed25519,
                            key_type: super::dnssec::KeyType::KSK,
                            created_at: 0,
                            expires_at: 0,
                            public_key: key_bytes.clone(),
                            private_key: Vec::new(),
                            key_tag: 0,
                            flags: 257,
                            key_size: None,
                        });
                        response.extend_from_slice(&(dnskey.len() as u16).to_be_bytes());
                        response.extend_from_slice(&dnskey);
                    }
                }
                RecordType::DS => {
                    if let Ok(ds_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(ds_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&ds_bytes);
                    }
                }
                RecordType::PTR => {
                    let mut target_parts: Vec<&str> = record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    let mut total_len = 0;
                    for part in &target_parts {
                        total_len += 1 + part.len();
                    }
                    response.extend_from_slice(&(total_len as u16).to_be_bytes());
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                }
                RecordType::CAA => {
                    let caa_value = record.value.as_bytes();
                    response.extend_from_slice(&(caa_value.len() as u16).to_be_bytes());
                    response.extend_from_slice(caa_value);
                }
                RecordType::TLSA => {
                    let tlsa_value = record.value.as_bytes();
                    response.extend_from_slice(&(tlsa_value.len() as u16).to_be_bytes());
                    response.extend_from_slice(tlsa_value);
                }
                RecordType::SVCB | RecordType::HTTPS => {
                    if let Ok(svcb_data) = Self::parse_svcb_value(&record.value) {
                        response.extend_from_slice(&(svcb_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&svcb_data);
                    }
                }
                RecordType::NAPTR => {
                    if let Ok(naptr_data) = Self::parse_naptr_value(&record.value) {
                        response.extend_from_slice(&(naptr_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&naptr_data);
                    }
                }
                RecordType::SSHFP => {
                    if let Ok(sshfp_data) = Self::parse_sshfp_value(&record.value) {
                        response.extend_from_slice(&(sshfp_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&sshfp_data);
                    }
                }
                _ => continue,
            };
        }

        if dnssec_ok && !records.is_empty() && records[0].record_type != RecordType::DNSKEY {
            if let Some(key) = zsk {
                for record in records {
                    let _rrname_offset = response.len();
                    if !qname_for_compression.is_empty() {
                        response.push(0xC0 | (question_name_offset >> 8) as u8);
                        response.push((question_name_offset & 0xFF) as u8);
                    } else {
                        response.push(0);
                    }
                    
                    let rrsig = Self::create_signed_rrsig(record, signer_name, key);
                    if !rrsig.is_empty() {
                        response.extend_from_slice(&46u16.to_be_bytes());
                        response.extend_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&record.ttl.to_be_bytes());
                        response.extend_from_slice(&(rrsig.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rrsig);
                    }
                }
            }
        }

        if let Some(edns) = edns_options {
            let opt_record = super::edns::EdnsOptions::build_opt_record(edns.udp_payload_size, dnssec_ok);
            if !opt_record.is_empty() {
                response.extend_from_slice(&[0]);
                response.extend_from_slice(&41u16.to_be_bytes());
                response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
                response.extend_from_slice(&opt_record);
            }
        } else if dnssec_ok {
            let opt_record = super::edns::EdnsOptions::build_opt_record(4096, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        }

        if response.len() > max_response_size && max_response_size > 0 {
            return Self::build_truncated_response(qname, qtype, records, dnssec_ok, edns_options, zsk, signer_name);
        }

        Arc::new(response)
    }

    fn build_truncated_response(
        qname: &str,
        qtype: u16,
        records: &[DnsZoneRecord],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        zsk: Option<&super::dnssec::ZoneSigningKey>,
        signer_name: &str,
    ) -> Arc<Vec<u8>> {
        let max_size = edns_options
            .map(|e| e.udp_payload_size as usize)
            .unwrap_or(512);
        
        let mut response = Vec::new();
        
        let response_id = Self::generate_random_id();
        response.extend_from_slice(&response_id.to_be_bytes());
        response.extend_from_slice(&0x8582u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        
        let name_parts: Vec<&str> = if qname.is_empty() || qname == "@" {
            vec![""]
        } else {
            qname.split('.').collect()
        };

        let mut included_records = Vec::new();
        
        for record in records {
            let record_size = Self::estimate_record_size(record, &name_parts);
            
            let rrsig_size = if dnssec_ok && zsk.is_some() && record.record_type.is_signed() {
                let sig_size = zsk.map(|k| match k.algorithm {
                    super::dnssec::Algorithm::Ed25519 => 64,
                    super::dnssec::Algorithm::RSA => 256, // RSA signatures are larger
                }).unwrap_or(64);
                
                2 + name_parts.iter().map(|p| 1 + p.len()).sum::<usize>() + 1 + 2 + 2 + 4 + 8 + 8 + 2 + signer_name.len() + 1 + sig_size
            } else {
                0
            };
            
            if response.len() + record_size + rrsig_size + 20 > max_size {
                break;
            }
            
            included_records.push(record.clone());
        }
        
        let ancount = included_records.len() as u16;
        response.extend_from_slice(&ancount.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        for part in &name_parts {
            if !part.is_empty() {
                response.push((*part).len() as u8);
                response.extend_from_slice(part.as_bytes());
            }
        }
        response.push(0);

        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        for record in &included_records {
            for part in &name_parts {
                if !part.is_empty() {
                    response.push((*part).len() as u8);
                    response.extend_from_slice(part.as_bytes());
                }
            }
            response.push(0);

            response.extend_from_slice(&u16::from(record.record_type).to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&record.ttl.to_be_bytes());

            match record.record_type {
                RecordType::A => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv4Addr>() {
                        let bytes: &[u8; 4] = &ip.octets();
                        response.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(bytes);
                    }
                }
                RecordType::AAAA => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv6Addr>() {
                        let bytes = ip.octets();
                        response.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&bytes);
                    }
                }
                RecordType::CNAME | RecordType::NS => {
                    let mut target_parts: Vec<&str> = record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    let mut total_len = 0;
                    for part in &target_parts {
                        total_len += 1 + part.len();
                    }
                    response.extend_from_slice(&(total_len as u16).to_be_bytes());
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                }
                RecordType::TXT => {
                    let txt_value = record.value.as_bytes();
                    let mut offset = 0;
                    while offset < txt_value.len() {
                        let remaining = txt_value.len() - offset;
                        let chunk_len = std::cmp::min(remaining, 255);
                        response.push(chunk_len as u8);
                        response.extend_from_slice(&txt_value[offset..offset + chunk_len]);
                        offset += chunk_len;
                    }
                }
                RecordType::MX => {
                    let priority = record.priority.unwrap_or(10);
                    response.extend_from_slice(&2u16.to_be_bytes());
                    response.extend_from_slice(&priority.to_be_bytes());
                    let mut target_parts: Vec<&str> = record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                }
                RecordType::SVCB | RecordType::HTTPS => {
                    if let Ok(svcb_data) = Self::parse_svcb_value(&record.value) {
                        response.extend_from_slice(&(svcb_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&svcb_data);
                    }
                }
                RecordType::NAPTR => {
                    if let Ok(naptr_data) = Self::parse_naptr_value(&record.value) {
                        response.extend_from_slice(&(naptr_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&naptr_data);
                    }
                }
                _ => continue,
            };
        }

        if dnssec_ok && !included_records.is_empty() {
            if let Some(key) = zsk {
                for record in &included_records {
                    let rrsig = Self::create_signed_rrsig(record, signer_name, key);
                    if !rrsig.is_empty() && response.len() + rrsig.len() + 12 < max_size {
                        for part in &name_parts {
                            if !part.is_empty() {
                                response.push((*part).len() as u8);
                                response.extend_from_slice(part.as_bytes());
                            }
                        }
                        response.push(0);
                        response.extend_from_slice(&46u16.to_be_bytes());
                        response.extend_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&record.ttl.to_be_bytes());
                        response.extend_from_slice(&(rrsig.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rrsig);
                    }
                }
            }
        }

        if let Some(edns) = edns_options {
            let opt_record = super::edns::EdnsOptions::build_opt_record(edns.udp_payload_size, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        }

        Arc::new(response)
    }

    pub fn parse_svcb_value(value: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("SVCB value must have priority and target".to_string());
        }

        let priority: u16 = parts[0].parse().map_err(|_| "Invalid SVCB priority")?;
        let target = parts[1];

        let mut result = Vec::new();
        result.extend_from_slice(&priority.to_be_bytes());

        if target.ends_with('.') || target == "." {
            let target_parts: Vec<&str> = target.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        } else if target.is_empty() {
            result.push(0);
        } else {
            let target_parts: Vec<&str> = target.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        }

        if parts.len() > 2 {
            let mut params: Vec<(u16, Vec<u8>)> = Vec::new();

            for param in &parts[2..] {
                if let Some((key, val)) = param.split_once('=') {
                    let svcparam_key = match key {
                        "mandatory" => 0,
                        "alpn" => 1,
                        "no-default-alpn" => 2,
                        "port" => 3,
                        "ipv4hint" => 4,
                        "ech" => 5,
                        "ipv6hint" => 6,
                        "dns" => 7,
                        "nhttp" => 8,
                        _ => continue,
                    };

                    let mut encoded = Vec::new();
                    match svcparam_key {
                        0 => {
                            for m in val.split(',') {
                                let m_trimmed = m.trim();
                                let m_key = match m_trimmed {
                                    "alpn" => 1u16,
                                    "no-default-alpn" => 2,
                                    "port" => 3,
                                    "ipv4hint" => 4,
                                    "ech" => 5,
                                    "ipv6hint" => 6,
                                    "dns" => 7,
                                    "nhttp" => 8,
                                    _ => continue,
                                };
                                encoded.extend_from_slice(&m_key.to_be_bytes());
                            }
                        }
                        1 => {
                            for alpn in val.split(',') {
                                let alpn = alpn.trim();
                                encoded.push(alpn.len() as u8);
                                encoded.extend_from_slice(alpn.as_bytes());
                            }
                        }
                        2 => {
                        }
                        3 => {
                            if let Ok(port) = val.parse::<u16>() {
                                encoded.extend_from_slice(&port.to_be_bytes());
                            }
                        }
                        4 => {
                            for ip in val.split(',') {
                                let ip = ip.trim();
                                if let Ok(ipv4) = ip.parse::<std::net::Ipv4Addr>() {
                                    encoded.extend_from_slice(&ipv4.octets());
                                }
                            }
                        }
                        5 => {
                            if let Ok(ech) = hex::decode(val) {
                                encoded.extend_from_slice(&ech);
                            }
                        }
                        6 => {
                            for ip in val.split(',') {
                                let ip = ip.trim();
                                if let Ok(ipv6) = ip.parse::<std::net::Ipv6Addr>() {
                                    encoded.extend_from_slice(&ipv6.octets());
                                }
                            }
                        }
                        7 => {
                            if let Ok(port) = val.parse::<u16>() {
                                encoded.extend_from_slice(&port.to_be_bytes());
                            }
                        }
                        8 => {
                            if let Some((ver, rest)) = val.split_once('/') {
                                encoded.extend_from_slice(ver.as_bytes());
                                if let Ok(port) = rest.parse::<u16>() {
                                    encoded.extend_from_slice(&port.to_be_bytes());
                                }
                            }
                        }
                        _ => {
                            encoded.extend_from_slice(val.as_bytes());
                        }
                    }

                    if !encoded.is_empty() {
                        params.push((svcparam_key, encoded));
                    }
                }
            }

            params.sort_by_key(|(key, _)| *key);

            for (key, encoded) in params {
                result.push((key >> 8) as u8);
                result.push((key & 0xFF) as u8);
                result.push((encoded.len() >> 8) as u8);
                result.push((encoded.len() & 0xFF) as u8);
                result.extend_from_slice(&encoded);
            }
        }

        Ok(result)
    }

    pub fn parse_naptr_value(value: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 5 {
            return Err("NAPTR value must have at least 5 fields: order preference flags service replacement".to_string());
        }

        let order: u16 = parts[0].parse().map_err(|_| "Invalid NAPTR order")?;
        let preference: u16 = parts[1].parse().map_err(|_| "Invalid NAPTR preference")?;
        let flags = parts[2];
        let service = parts[3];
        let replacement = parts[4];

        let mut result = Vec::new();
        result.extend_from_slice(&order.to_be_bytes());
        result.extend_from_slice(&preference.to_be_bytes());

        result.push(flags.len() as u8);
        result.extend_from_slice(flags.as_bytes());

        result.push(service.len() as u8);
        result.extend_from_slice(service.as_bytes());

        let regex = if parts.len() > 5 {
            parts[5]
        } else {
            ""
        };
        result.push(regex.len() as u8);
        result.extend_from_slice(regex.as_bytes());

        if replacement.ends_with('.') || replacement == "." {
            let target_parts: Vec<&str> = replacement.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        } else if replacement.is_empty() {
            result.push(0);
        } else {
            let target_parts: Vec<&str> = replacement.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        }

        Ok(result)
    }

    pub fn parse_sshfp_value(value: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("SSHFP value must have at least 2 fields: algorithm fingerprint".to_string());
        }

        let algorithm: u8 = parts[0].parse().map_err(|_| "Invalid SSHFP algorithm")?;
        let fingerprint_type: u8 = parts[1].parse().map_err(|_| "Invalid SSHFP fingerprint type")?;
        let fingerprint = parts.get(2).unwrap_or(&"");

        if algorithm > 2 {
            return Err("Invalid SSHFP algorithm (must be 0-2)".to_string());
        }
        if fingerprint_type > 2 {
            return Err("Invalid SSHFP fingerprint type (must be 0-2)".to_string());
        }

        let mut result = Vec::new();
        result.push(algorithm);
        result.push(fingerprint_type);

        let fp_bytes = hex::decode(fingerprint.replace(":", "").replace(" ", ""))
            .map_err(|_| "Invalid SSHFP fingerprint (expected hex)")?;
        result.extend_from_slice(&fp_bytes);

        Ok(result)
    }

    pub fn parse_uri_value(value: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 3 {
            return Err("URI value must have at least 3 fields: priority weight target".to_string());
        }

        let priority: u16 = parts[0].parse().map_err(|_| "Invalid URI priority")?;
        let weight: u16 = parts[1].parse().map_err(|_| "Invalid URI weight")?;
        let target = parts[2];

        let mut result = Vec::new();
        result.extend_from_slice(&priority.to_be_bytes());
        result.extend_from_slice(&weight.to_be_bytes());

        if target.ends_with('.') || target == "." {
            let target_parts: Vec<&str> = target.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        } else {
            let target_parts: Vec<&str> = target.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        }

        Ok(result)
    }

    pub fn parse_rp_value(value: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("RP value must have at least 2 fields: mbox dname".to_string());
        }

        let mbox = parts[0];
        let dname = parts[1];

        let mut result = Vec::new();

        if mbox.contains('@') {
            let (local, domain) = mbox.split_once('@').unwrap();
            let mbox_parts: Vec<&str> = domain.split('.').filter(|s| !s.is_empty()).collect();
            result.push(local.len() as u8);
            result.extend_from_slice(local.as_bytes());
            for part in mbox_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
        }
        result.push(0);

        if dname.ends_with('.') || dname == "." {
            let dname_parts: Vec<&str> = dname.split('.').filter(|s| !s.is_empty()).collect();
            for part in dname_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        } else {
            let dname_parts: Vec<&str> = dname.split('.').filter(|s| !s.is_empty()).collect();
            for part in dname_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        }

        Ok(result)
    }

    pub fn parse_afsdb_value(value: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("AFSDB value must have at least 2 fields: subtype hostname".to_string());
        }

        let subtype: u16 = parts[0].parse().map_err(|_| "Invalid AFSDB subtype")?;
        let hostname = parts[1];

        let mut result = Vec::new();
        result.extend_from_slice(&subtype.to_be_bytes());

        if hostname.ends_with('.') || hostname == "." {
            let hostname_parts: Vec<&str> = hostname.split('.').filter(|s| !s.is_empty()).collect();
            for part in hostname_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        } else {
            let hostname_parts: Vec<&str> = hostname.split('.').filter(|s| !s.is_empty()).collect();
            for part in hostname_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        }

        Ok(result)
    }

    fn estimate_record_size(record: &DnsZoneRecord, name_parts: &[&str]) -> usize {
        let name_size = name_parts.iter().map(|p| 1 + p.len()).sum::<usize>() + 1;
        let rdata_size = match record.record_type {
            RecordType::A => 4,
            RecordType::AAAA => 16,
            RecordType::CNAME | RecordType::NS => record.value.split('.').filter(|s| !s.is_empty()).map(|s| 1 + s.len()).sum::<usize>() + 1,
            RecordType::TXT => {
                let len = record.value.len();
                (len / 255) + 1 + len
            },
            RecordType::MX => 2 + record.value.split('.').filter(|s| !s.is_empty()).map(|s| 1 + s.len()).sum::<usize>() + 1,
            _ => record.value.len(),
        };
        name_size + 2 + 2 + 4 + 2 + rdata_size
    }

    fn create_signed_rrsig(record: &DnsZoneRecord, signer_name: &str, key: &super::dnssec::ZoneSigningKey) -> Vec<u8> {
        let labels = super::dnssec::count_labels(&record.name);
        
        let canonical_rdata = super::dnssec::canonical_rdata(
            u16::from(record.record_type),
            &record.value,
            record.priority,
            record.ttl,
        );
        
        let mut canonical_msg = Vec::new();
        
        let name_lower = record.name.to_lowercase();
        let name = name_lower.trim_end_matches('.');
        
        if name.is_empty() {
            canonical_msg.push(0);
        } else {
            for part in name.split('.') {
                if !part.is_empty() {
                    canonical_msg.push(part.len() as u8);
                    canonical_msg.extend_from_slice(part.as_bytes());
                }
            }
            canonical_msg.push(0);
        }
        
        canonical_msg.extend_from_slice(&u16::from(record.record_type).to_be_bytes());
        canonical_msg.extend_from_slice(&1u16.to_be_bytes());
        canonical_msg.extend_from_slice(&record.ttl.to_be_bytes());
        canonical_msg.extend_from_slice(&(canonical_rdata.len() as u16).to_be_bytes());
        canonical_msg.extend_from_slice(&canonical_rdata);
        
        let signature = match super::dnssec::sign_data(&canonical_msg, key) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::warn!("Failed to sign record: {}", e);
                return Vec::new();
            }
        };
        
        let now = chrono::Utc::now().timestamp() as u64;
        let sig_expire = now + (7 * 86400);
        let sig_inception = now - 86400;
        
        let mut rrsig = Vec::new();
        
        rrsig.extend_from_slice(&u16::from(record.record_type).to_be_bytes());
        rrsig.push(key.algorithm.to_u8());
        rrsig.push(labels);
        rrsig.extend_from_slice(&record.ttl.to_be_bytes());
        rrsig.extend_from_slice(&sig_expire.to_be_bytes());
        rrsig.extend_from_slice(&sig_inception.to_be_bytes());
        rrsig.extend_from_slice(&key.key_tag.to_be_bytes());
        
        let signer = signer_name.trim_end_matches('.');
        for part in signer.split('.') {
            if !part.is_empty() {
                rrsig.push(part.len() as u8);
                rrsig.extend_from_slice(part.as_bytes());
            }
        }
        rrsig.push(0);
        
        rrsig.extend_from_slice(&signature);
        
        rrsig
    }

    fn extract_query_name(query: &[u8]) -> String {
        let mut pos = 12;
        let mut qname = String::new();
        
        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                break;
            }
            if !qname.is_empty() {
                qname.push('.');
            }
            let label = String::from_utf8_lossy(&query[pos + 1..pos + 1 + len]);
            qname.push_str(&label);
            pos += 1 + len;
        }
        
        if qname.is_empty() {
            "unknown".to_string()
        } else {
            qname
        }
    }

    #[allow(dead_code)]
    fn build_dnssec_response(
        &self,
        _id: u16,
        _qname: &str,
        _qtype: u16,
        _records: &[DnsZoneRecord],
    ) -> Option<Vec<u8>> {
        // DNSSEC disabled - return None
        None
    }

    pub fn get_zones(&self) -> Arc<RwLock<HashMap<String, Zone>>> {
        self.zones.clone()
    }

    pub fn get_zone_trie(&self) -> Arc<RwLock<super::zone_trie::ZoneTrie>> {
        self.zone_trie.clone()
    }

    pub fn get_zone_index(&self) -> Arc<RwLock<Vec<(String, String)>>> {
        self.zone_index.clone()
    }

    pub fn get_cache(&self) -> Option<Arc<DnsCache>> {
        self.cache.clone()
    }

    pub fn get_dnssec(&self) -> Option<Arc<RwLock<DnsSecKeyManager>>> {
        self.dnssec.clone()
    }

    pub fn get_signer_name(&self) -> Option<String> {
        self.signer_name.clone()
    }

    pub fn get_ecs_filter_config(&self) -> super::edns::EcsFilterConfig {
        self.ecs_filter_config.clone()
    }

    pub fn shutdown(&mut self) {
        if let Some(ref server) = self.recursive_server {
            server.stop();
            tracing::info!("Recursive DNS server stopped");
        }
        
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    pub fn add_record(&self, zone: &str, record: DnsZoneRecord) -> Result<(), String> {
        let mut zones = self.zones.write();
        
        let zone_entry = zones.entry(zone.to_string()).or_insert_with(|| Zone::new(zone.to_string()));

        let key = (record.name.clone(), record.record_type);
        zone_entry.records.entry(key).or_insert_with(Vec::new).push(record);
        
        let zone_origin = zone_entry.origin.clone();
        drop(zones);

        if let Some(ref cache) = self.cache {
            cache.invalidate_zone(&zone_origin);
        }
        
        Ok(())
    }

    pub fn invalidate_cache(&self) {
        if let Some(ref cache) = self.cache {
            cache.clear();
        }
    }

    pub fn cache_stats(&self) -> Option<super::cache::CacheStats> {
        self.cache.as_ref().map(|c| c.stats())
    }

    pub fn start_key_rotation_task(
        dnssec: Option<Arc<RwLock<DnsSecKeyManager>>>,
        interval_secs: u64,
    ) {
        if let Some(dnssec_manager) = dnssec {
            let rotation_interval = Duration::from_secs(interval_secs);
            
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(rotation_interval);
                
                loop {
                    interval.tick().await;
                    
                    let mut manager = dnssec_manager.write();
                    let config = super::dnssec::KeyRotationConfig::default();
                    
                    match manager.check_and_rotate(config) {
                        Ok(result) => {
                            if result.ksk_rotated || result.zsk_rotated {
                                tracing::info!("DNSSEC key rotation completed: {:?}", result);
                            }
                        }
                        Err(e) => {
                            tracing::error!("DNSSEC key rotation check failed: {}", e);
                        }
                    }
                }
            });
            
            tracing::info!("DNSSEC key rotation task started with interval {}s", interval_secs);
        }
    }

    pub fn get_dnssec_status(&self) -> Option<super::dnssec::DnsSecKeyStatus> {
        self.dnssec.as_ref().and_then(|d| {
            let manager = d.read();
            manager.get_key_status().ok()
        })
    }

    pub(crate) fn start_coalescer_cleanup_task(
        coalescer: Option<&Arc<super::query_coalesce::QueryCoalescer>>,
        interval_secs: u64,
    ) {
        if let Some(coalescer) = coalescer {
            let coalescer = coalescer.clone();
            
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
                
                loop {
                    interval.tick().await;
                    
                    let count_before = coalescer.in_flight_count();
                    coalescer.cleanup_stale();
                    let count_after = coalescer.in_flight_count();
                    
                    if count_before != count_after {
                        tracing::debug!(
                            "Query coalescer cleanup: {} -> {} entries",
                            count_before,
                            count_after
                        );
                    }
                }
            });
            
            tracing::info!(
                "Query coalescer cleanup task started with interval {}s",
                interval_secs
            );
        }
    }

    pub fn get_coalescer_metrics(&self) -> Option<super::query_coalesce::QueryCoalescerMetrics> {
        self.query_coalescer.as_ref().map(|c| c.metrics())
    }
}
