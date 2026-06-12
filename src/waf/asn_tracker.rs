//! ASN-based distributed scraper detection.
//!
//! Detects distributed scraping campaigns where many IPs from the same ASN
//! collectively exceed request thresholds that no single IP would trigger.
//! Uses lock-free `AtomicSlidingWindow` counters per ASN and caches IP→ASN
//! lookups to minimize GeoIP overhead.

use crate::block_store::{BlockProvenance, BlockProvenanceKind, BlockStore};
use crate::config::defaults::AsnScrapingConfig;
use crate::geoip::types::AsnInfo;
use crate::geoip::GeoIpManager;
use crate::proxy::WafDecision;
use crate::waf::ratelimit::core::AtomicSlidingWindow;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Per-ASN sliding window state for request counting and unique IP tracking.
struct AsnWindowState {
    per_minute: AtomicSlidingWindow,
    per_5min: AtomicSlidingWindow,
    per_hour: AtomicSlidingWindow,
    unique_ips: DashMap<u32, u64>,
    violation_count: u32,
    last_violation: Option<u64>,
    organization: String,
}

impl AsnWindowState {
    fn new(organization: String) -> Self {
        Self {
            per_minute: AtomicSlidingWindow::new(60, 60),
            per_5min: AtomicSlidingWindow::new(300, 60),
            per_hour: AtomicSlidingWindow::new(3600, 60),
            unique_ips: DashMap::new(),
            violation_count: 0,
            last_violation: None,
            organization,
        }
    }
}

/// Result of an ASN scraping check.
#[derive(Debug)]
pub enum AsnCheckResult {
    Pass,
    Blocked { asn: u32, reason: String },
}

/// ASN-based distributed scraper detector.
///
/// Tracks request volume and unique IP distribution per ASN. When either
/// threshold is exceeded, blocks the requesting IP via `BlockStore` and
/// optionally announces the block to mesh peers.
pub struct AsnTracker {
    asn_windows: DashMap<u32, AsnWindowState>,
    asn_cache: RwLock<lru_time_cache::LruCache<IpAddr, u32>>,
    config: AsnScrapingConfig,
    geoip: Option<Arc<GeoIpManager>>,
    block_store: Option<Arc<BlockStore>>,
    whitelisted_asns: Arc<RwLock<HashSet<u32>>>,
    last_cleanup: parking_lot::Mutex<Instant>,
}

impl AsnTracker {
    pub fn new(
        config: AsnScrapingConfig,
        geoip: Option<Arc<GeoIpManager>>,
        block_store: Option<Arc<BlockStore>>,
    ) -> Self {
        let whitelisted: HashSet<u32> = config.whitelisted_asns.iter().copied().collect();
        Self {
            asn_windows: DashMap::new(),
            asn_cache: RwLock::new(lru_time_cache::LruCache::with_capacity(config.cache_size)),
            config,
            geoip,
            block_store,
            whitelisted_asns: Arc::new(RwLock::new(whitelisted)),
            last_cleanup: parking_lot::Mutex::new(Instant::now()),
        }
    }

    /// Check a request against ASN scraping thresholds.
    ///
    /// Returns `None` if the request passes, or `Some(WafDecision::Drop)` if blocked.
    pub fn check_request(&self, client_ip: IpAddr) -> Option<WafDecision> {
        if !self.config.enabled {
            return None;
        }

        let asn = self.resolve_asn(client_ip)?;
        if self.is_whitelisted(asn) {
            return None;
        }

        let now_ms = crate::utils::current_timestamp() * 1000;
        let truncated_ip = Self::truncate_ip(client_ip);

        let mut entry = self.asn_windows.entry(asn).or_insert_with(|| {
            let org = self
                .geoip
                .as_ref()
                .and_then(|g| g.get_asn_info(client_ip))
                .map(|info| info.organization)
                .unwrap_or_default();
            AsnWindowState::new(org)
        });

        let minute_count = entry.per_minute.increment(now_ms);
        let five_min_count = entry.per_5min.increment(now_ms);
        let hour_count = entry.per_hour.increment(now_ms);

        entry.unique_ips.insert(truncated_ip, now_ms);
        let unique_count = entry.unique_ips.len() as u32;

        let mut violation_reason = None;

        if minute_count > self.config.requests_per_minute as u64 {
            violation_reason = Some(format!("asn_scraping:volume:minute:{}r/m", minute_count));
        } else if five_min_count > self.config.requests_per_5min as u64 {
            violation_reason = Some(format!("asn_scraping:volume:5min:{}r/5m", five_min_count));
        } else if hour_count > self.config.requests_per_hour as u64 {
            violation_reason = Some(format!("asn_scraping:volume:hour:{}r/h", hour_count));
        } else if unique_count > self.config.unique_ips_threshold {
            violation_reason = Some(format!(
                "asn_scraping:distribution:{}unique_ips",
                unique_count
            ));
        }

        if let Some(reason) = violation_reason {
            entry.violation_count += 1;
            entry.last_violation = Some(crate::utils::safe_unix_timestamp());

            let ban_duration = self.calculate_ban_duration(entry.violation_count);

            tracing::warn!(
                asn = asn,
                organization = %entry.organization,
                violations = entry.violation_count,
                ban_duration_secs = ban_duration,
                reason = %reason,
                "ASN scraping violation detected"
            );

            crate::metrics::record_attack_type("AsnScraping");

            if let Some(ref store) = self.block_store {
                store.block_ip_with_provenance(
                    client_ip,
                    "asn_scraping",
                    ban_duration,
                    "global",
                    BlockProvenance {
                        kind: BlockProvenanceKind::LocalAsnTracker,
                        source: Some(format!("asn_{}", asn)),
                    },
                );
            }

            return Some(WafDecision::Drop);
        }

        None
    }

    /// Get ASN info for an IP, using the cache to avoid repeated lookups.
    fn resolve_asn(&self, ip: IpAddr) -> Option<u32> {
        {
            let cache = self.asn_cache.read();
            if let Some(&asn) = cache.peek(&ip) {
                return Some(asn);
            }
        }

        let geoip = self.geoip.as_ref()?;
        let AsnInfo { asn, .. } = geoip.get_asn_info(ip)?;

        let mut cache = self.asn_cache.write();
        cache.insert(ip, asn);
        Some(asn)
    }

    fn is_whitelisted(&self, asn: u32) -> bool {
        self.whitelisted_asns.read().contains(&asn)
    }

    /// Truncate an IP to a /24 (v4) or first 24 bits (v6) for unique IP tracking.
    fn truncate_ip(ip: IpAddr) -> u32 {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                u32::from_be_bytes([octets[0], octets[1], octets[2], 0])
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                ((segments[0] as u32) << 16) | (segments[1] as u32)
            }
        }
    }

    fn calculate_ban_duration(&self, violation_count: u32) -> u64 {
        let base = self.config.ban_duration_secs;
        if violation_count <= 1 {
            base
        } else {
            base * 2u64.saturating_pow(violation_count.saturating_sub(1))
        }
    }

    /// Update the ASN whitelist (used by global nodes via mesh NetworkPolicy).
    pub fn update_whitelist(&self, asns: Vec<u32>) {
        let mut whitelist = self.whitelisted_asns.write();
        *whitelist = asns.into_iter().collect();
        tracing::info!(
            count = whitelist.len(),
            "Updated ASN whitelist from mesh policy"
        );
    }

    /// Periodic cleanup of stale unique IP entries.
    pub fn cleanup_unique_ips(&self) {
        let mut last = self.last_cleanup.lock();
        if last.elapsed() < Duration::from_secs(60) {
            return;
        }
        *last = Instant::now();
        drop(last);

        let window_secs = self.config.unique_ips_window_secs;
        let now_ms = crate::utils::current_timestamp() * 1000;
        let cutoff = now_ms.saturating_sub(window_secs * 1000);

        for entry in self.asn_windows.iter_mut() {
            entry
                .unique_ips
                .retain(|_, &mut first_seen| first_seen > cutoff);
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &AsnScrapingConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AsnScrapingConfig {
        AsnScrapingConfig {
            enabled: true,
            requests_per_minute: 10,
            requests_per_5min: 50,
            requests_per_hour: 200,
            unique_ips_threshold: 5,
            unique_ips_window_secs: 300,
            violations_before_block: 1,
            ban_duration_secs: 60,
            cache_size: 100,
            whitelisted_asns: vec![],
        }
    }

    fn create_tracker(config: AsnScrapingConfig) -> AsnTracker {
        AsnTracker::new(config, None, None)
    }

    #[test]
    fn test_truncate_ipv4() {
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        let truncated = AsnTracker::truncate_ip(ip);
        assert_eq!(truncated, 0xCB_00_71_00); // 203.0.113.0
    }

    #[test]
    fn test_truncate_ipv6() {
        let ip: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let truncated = AsnTracker::truncate_ip(ip);
        assert_eq!(truncated, 0x2001_0DB8);
    }

    #[test]
    fn test_ban_duration_escalation() {
        let tracker = create_tracker(test_config());
        assert_eq!(tracker.calculate_ban_duration(1), 60);
        assert_eq!(tracker.calculate_ban_duration(2), 120);
        assert_eq!(tracker.calculate_ban_duration(3), 240);
        assert_eq!(tracker.calculate_ban_duration(4), 480);
    }

    #[test]
    fn test_whitelist_bypass() {
        let mut config = test_config();
        config.whitelisted_asns = vec![15169];
        let tracker = create_tracker(config);
        assert!(tracker.is_whitelisted(15169));
        assert!(!tracker.is_whitelisted(12345));
    }

    #[test]
    fn test_update_whitelist() {
        let tracker = create_tracker(test_config());
        assert!(!tracker.is_whitelisted(13335));
        tracker.update_whitelist(vec![13335, 8075]);
        assert!(tracker.is_whitelisted(13335));
        assert!(tracker.is_whitelisted(8075));
        assert!(!tracker.is_whitelisted(15169));
    }

    #[test]
    fn test_disabled_tracker_passes() {
        let mut config = test_config();
        config.enabled = false;
        let tracker = create_tracker(config);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(tracker.check_request(ip).is_none());
    }

    #[test]
    fn test_asn_state_creation() {
        let state = AsnWindowState::new("Test Org".to_string());
        assert_eq!(state.organization, "Test Org");
        assert_eq!(state.violation_count, 0);
        assert!(state.last_violation.is_none());
    }
}
