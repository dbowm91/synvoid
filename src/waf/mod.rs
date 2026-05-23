use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwapOption;

pub mod asn_tracker;
pub mod attack_detection;
pub mod bot;
pub mod endpoints;
pub mod flood;
pub mod ip_feed;
pub mod mitigation;
pub mod probe_tracker;
pub mod ratelimit;
pub mod request_sanitization;
pub mod rule_feed;
pub mod threat_intel;
pub mod threat_level;
pub mod traffic_shaper;
pub mod violation_tracker;

pub use attack_detection::AttackDetectionConfig;
pub use probe_tracker::{
    ProbeConfig, ProbeTracker, SuspiciousWordTracker, UpstreamErrorResult, UpstreamErrorTracker,
};
pub use rule_feed::RuleFeedManagerForWaf;
pub use threat_level::{ThreatHistorySample, ThreatLevelManager};
pub use traffic_shaper::{ConnectionLimiter, ConnectionToken, GlobalTrafficShaper};
pub use violation_tracker::ViolationTracker;

use crate::auth::AuthManager;
use crate::block_store::BlockStore;
use crate::challenge::{ChallengeConfig, ChallengeManager, ChallengeType};
use crate::config::defaults::{AsnScrapingConfig, BlockedDefaults, BotDefaults};
use crate::config::limits::RateLimitMemoryConfig;
use crate::config::traffic::{BandwidthConfig, TrafficShapingConfig};
pub use crate::config::{SuspiciousWordsConfig, UpstreamErrorsConfig};
use crate::geoip::GeoIpManager;
use crate::waf::asn_tracker::AsnTracker;
use crate::waf::attack_detection::AttackDetector;
use crate::waf::bot::{BotDetectionResult, BotDetector};
use crate::waf::endpoints::{
    EndpointBlocker, EndpointBlockerManager, EndpointCheckResult, ErrorPageManager,
    SensitiveEndpointManager,
};
use crate::waf::ip_feed::IpFeedManager;
pub use request_sanitization::RequestSanitizer;

pub use flood::{FloodConfig, FloodDecision, FloodProtector};
pub use ratelimit::{RateLimitResult, RateLimiterManager};

// YaraRulesManager is actually in mesh module
pub use crate::mesh::yara_rules::YaraRulesManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafDecision {
    Pass,
    Block(u16, String),
    Drop,
    Tarpit(String),
    Stall,
    Challenge(ChallengeType, String),
    ChallengeWithCookie {
        challenge_type: ChallengeType,
        html: String,
        session_cookie_name: String,
        session_cookie_value: String,
        session_cookie_max_age: u64,
    },
}

#[derive(Clone, Debug, Default)]
pub struct TestModeConfig {
    pub enabled: bool,
    pub ratelimit_off: bool,
    pub attack_off: bool,
    pub bot_off: bool,
    pub challenge_off: bool,
    pub flood_off: bool,
    pub asn_off: bool,
}

impl TestModeConfig {
    pub fn all_off() -> Self {
        Self {
            enabled: true,
            ratelimit_off: true,
            attack_off: true,
            bot_off: true,
            challenge_off: true,
            flood_off: true,
            asn_off: true,
        }
    }
}

#[derive(Clone)]
pub struct WafConfig {
    pub enable_css_honeypot: bool,
    pub enable_pow_challenge: bool,
    pub enable_auth_challenge: bool,
    pub auth_login_path: String,
    pub block_ai_crawlers: bool,
    pub drop_blocked_requests: bool,
    pub test_mode: TestModeConfig,
    pub honeypot_ban_duration_secs: u64,
    pub css_exempt_paths: Vec<String>,
}

impl WafConfig {
    pub fn new(
        enable_css_honeypot: bool,
        enable_pow_challenge: bool,
        enable_auth_challenge: bool,
        auth_login_path: String,
        block_ai_crawlers: bool,
        drop_blocked_requests: bool,
        test_mode: TestModeConfig,
        honeypot_ban_duration_secs: u64,
    ) -> Self {
        Self {
            enable_css_honeypot,
            enable_pow_challenge,
            enable_auth_challenge,
            auth_login_path,
            block_ai_crawlers,
            drop_blocked_requests,
            test_mode,
            honeypot_ban_duration_secs,
            css_exempt_paths: vec![
                "/_waf_css_challenge".to_string(),
                "/_waf_assets".to_string(),
            ],
        }
    }
}

pub struct RateLimitConfigStore {
    pub ip: crate::config::defaults::IpRateLimitConfig,
    pub global: crate::config::defaults::GlobalRateLimitConfig,
    pub cleanup_interval_secs: u64,
}

pub struct WafCoreConfig {
    pub rate_config: RateLimitConfigStore,
    pub memory_config: RateLimitMemoryConfig,
    pub bot_config: BotDefaults,
    pub endpoint_config: BlockedDefaults,
    pub waf_config: WafConfig,
    pub whitelist: Vec<String>,
    pub block_store: Option<Arc<BlockStore>>,
    pub attack_detection_config: Option<AttackDetectionConfig>,
    pub auth_manager: Option<Arc<AuthManager>>,
    pub threat_level_config: Option<crate::config::ThreatLevelConfig>,
    pub ip_feed_config: Option<crate::config::IpFeedConfig>,
    pub probe_config: Option<crate::config::HoneypotProbingDefaults>,
    pub suspicious_words_config: Option<SuspiciousWordsConfig>,
    pub upstream_errors_config: Option<UpstreamErrorsConfig>,
    pub traffic_shaping_config: Option<TrafficShapingConfig>,
    pub bandwidth_config: BandwidthConfig,
    pub asn_scraping_config: Option<AsnScrapingConfig>,
    pub geoip: Option<Arc<GeoIpManager>>,
    pub data_dir: Option<PathBuf>,
    pub test_mode: TestModeConfig,
    pub tarpit_defaults: Option<crate::config::TarpitDefaults>,
}

pub struct WafCore {
    pub rate_limiter: RateLimiterManager,
    pub bot_detector: BotDetector,
    pub endpoint_blocker: EndpointBlockerManager,
    pub sensitive_endpoint_manager: SensitiveEndpointManager,
    pub error_page_manager: ErrorPageManager,
    pub challenge_manager: ChallengeManager,
    pub auth_manager: Arc<AuthManager>,
    pub attack_detector: ArcSwapOption<AttackDetector>,
    pub attack_detection_config: ArcSwapOption<AttackDetectionConfig>,
    pub block_store: Option<Arc<BlockStore>>,
    pub config: WafConfig,
    pub whitelist: Arc<HashSet<IpAddr>>,
    tarpit_generator: Arc<crate::tarpit::generator::MarkovChain>,
    tarpit_defaults: crate::config::TarpitDefaults,
    pub threat_level: Option<Arc<ThreatLevelManager>>,
    pub violation_tracker: Option<Arc<ViolationTracker>>,
    pub ip_feed: Option<Arc<IpFeedManager>>,
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub traffic_shaper: Option<Arc<GlobalTrafficShaper>>,
    pub connection_limiter: Option<Arc<ConnectionLimiter>>,
    pub asn_tracker: Option<Arc<AsnTracker>>,
    pub test_mode: TestModeConfig,
    pub honeypot_ban_duration_secs: u64,
    pub request_services: ArcSwapOption<RequestServices>,
    pub flood_protector: Option<Arc<FloodProtector>>,
    pub trust_token_key: [u8; 32],
}

pub use crate::worker::context::RequestServices;

impl WafCore {
    pub fn generate_trust_token(&self, client_ip: IpAddr) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.trust_token_key)
            .expect("HMAC can take key of any size");
        mac.update(client_ip.to_string().as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn verify_trust_token(&self, client_ip: IpAddr, token: &str) -> bool {
        let expected = self.generate_trust_token(client_ip);
        if expected.len() != token.len() {
            return false;
        }
        subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), token.as_bytes()).unwrap_u8() == 1
    }

    pub fn new(config: WafCoreConfig) -> Self {
        let WafCoreConfig {
            rate_config,
            memory_config,
            bot_config,
            endpoint_config,
            waf_config,
            whitelist,
            block_store,
            attack_detection_config,
            auth_manager,
            threat_level_config,
            ip_feed_config,
            probe_config,
            suspicious_words_config,
            upstream_errors_config,
            traffic_shaping_config,
            bandwidth_config,
            asn_scraping_config,
            geoip,
            data_dir,
            test_mode,
            tarpit_defaults,
        } = config;

        let rate_limiter = RateLimiterManager::new(
            rate_config.ip,
            rate_config.global,
            rate_config.cleanup_interval_secs,
            memory_config,
        );

        let threat_level = threat_level_config
            .as_ref()
            .map(|config| ThreatLevelManager::new(config.clone(), data_dir.clone(), None));

        let violation_tracker = threat_level_config.as_ref().and_then(|config| {
            if config.escalation.enabled {
                Some(ViolationTracker::new(
                    config.escalation.clone(),
                    data_dir.clone(),
                    config.persist_interval_normal_secs,
                    config.persist_interval_attack_secs,
                ))
            } else {
                None
            }
        });

        let ip_feed = ip_feed_config.and_then(|config| {
            if config.enabled {
                let manager = IpFeedManager::new(config);
                manager.start_background_fetching();
                Some(manager)
            } else {
                None
            }
        });

        let probe_tracker = probe_config.and_then(|config| {
            if config.enabled {
                let probe_config = crate::waf::probe_tracker::ProbeConfig {
                    enabled: config.enabled,
                    max_endpoints_per_window: config.max_endpoints_per_window,
                    window_secs: config.window_secs,
                    retention_days: config.retention_days,
                    max_records: config.max_records,
                    auto_ban_elevated_threat: config.auto_ban_elevated_threat,
                    elevated_threat_threshold: config.elevated_threat_threshold,
                    elevated_ban_duration: config.elevated_ban_duration,
                };
                Some(ProbeTracker::new(probe_config, data_dir.clone()))
            } else {
                None
            }
        });

        let suspicious_word_tracker = suspicious_words_config.and_then(|config| {
            if config.enabled {
                Some(SuspiciousWordTracker::new(config))
            } else {
                None
            }
        });

        let upstream_error_tracker = upstream_errors_config.and_then(|config| {
            if config.enabled {
                Some(UpstreamErrorTracker::new(config))
            } else {
                None
            }
        });

        let bot_detector = BotDetector::new(
            bot_config.known_bots_allow.clone(),
            bot_config.ai_crawlers_block.clone(),
            bot_config.scraper_patterns.clone(),
            bot_config.block_ai_crawlers,
        );

        let traffic_shaper_instance = traffic_shaping_config.as_ref().map(|config| {
            Arc::new(GlobalTrafficShaper::new(
                config.global.clone(),
                bandwidth_config.clone(),
            ))
        });

        let connection_limiter_instance = traffic_shaping_config
            .as_ref()
            .map(|config| ConnectionLimiter::new(config.connection_limits.clone()));

        let asn_tracker_instance = asn_scraping_config.as_ref().map(|config| {
            Arc::new(AsnTracker::new(
                config.clone(),
                geoip.clone(),
                block_store.clone(),
            ))
        });

        let endpoint_blocker = EndpointBlockerManager::new(
            endpoint_config.paths.clone(),
            endpoint_config.use_regex,
            endpoint_config.block_methods.clone(),
            endpoint_config.block_response_code,
            None, // block_page_html missing in defaults
        );

        let sensitive_endpoint_manager =
            SensitiveEndpointManager::from_file(&"honeypot_endpoints.txt".to_string()); // dummy path
        let error_page_manager = ErrorPageManager::new(&"error_pages".to_string(), None, true);
        let challenge_manager = ChallengeManager::new(ChallengeConfig {
            cookie_name: bot_config.challenge_cookie_name.clone(),
            pow_enabled: false, // from separate config usually
            pow_difficulty: 1,
            pow_adaptive_difficulty: false,
            pow_max_difficulty: 10,
            pow_window_secs: 300,
            pow_timeout_secs: 60,
            css_enabled: false,
            css_window_secs: 300,
            css_invalid_min: 1,
            css_invalid_max: 3,
            css_valid_count: 5,
            css_asset_path: "".to_string(),
            css_verification_window_secs: 60,
            honeypot_enabled: true,
            honeypot_paths_per_ip: 5,
            honeypot_ttl_secs: 3600,
            theme: crate::theme::ThemeConfig::default(),
            challenge_max_attempts: bot_config.challenge_max_attempts,
            challenge_rate_limit_window_secs: bot_config.challenge_rate_limit_window_secs,
            challenge_priority: crate::challenge::ChallengePriority::default(),
            mesh_pow_enabled: false,
            mesh_pow_key_exchange_enabled: false,
            mesh_pow_auditing_enabled: false,
            mesh_id: None,
            mesh_global_node_url: None,
            mesh_audit_urls: Vec::new(),
        });

        let tarpit_defaults = tarpit_defaults.unwrap_or_default();
        let tarpit_generator = Arc::new(crate::tarpit::generator::MarkovChain::new());

        let mut whitelist_set = HashSet::new();
        for ip_str in whitelist {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                whitelist_set.insert(ip);
            }
        }

        let ad_instance =
            attack_detection_config.map(|config| Arc::new(AttackDetector::new(config)));

        let auth_manager_instance = auth_manager.unwrap_or_else(|| {
            Arc::new(AuthManager::new(
                data_dir.clone().unwrap_or_else(|| PathBuf::from("data")),
                3600, // session_duration_secs
                5,    // max_failed_attempts
                300,  // lockout_duration_secs
            ))
        });

        let mut trust_token_key = [0u8; 32];
        rand::fill(&mut trust_token_key);

        Self {
            rate_limiter,
            bot_detector,
            endpoint_blocker,
            sensitive_endpoint_manager,
            error_page_manager,
            challenge_manager,
            auth_manager: auth_manager_instance,
            attack_detector: ArcSwapOption::new(ad_instance),
            attack_detection_config: ArcSwapOption::new(None),
            block_store,
            config: waf_config,
            whitelist: Arc::new(whitelist_set),
            tarpit_generator,
            tarpit_defaults,
            threat_level,
            violation_tracker,
            ip_feed,
            probe_tracker,
            suspicious_word_tracker,
            upstream_error_tracker,
            traffic_shaper: traffic_shaper_instance,
            connection_limiter: connection_limiter_instance,
            asn_tracker: asn_tracker_instance,
            test_mode,
            honeypot_ban_duration_secs: 86400,
            request_services: ArcSwapOption::new(None),
            flood_protector: None, // Initialized separately usually
            trust_token_key,
        }
    }

    pub async fn check_request_full(
        &self,
        site_id: Option<&str>,
        ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
        ua: Option<&str>,
        ja4_hash: Option<&str>,
        site_bot_config: Option<&crate::config::site::SiteBotConfig>,
        _ctx: Option<&RequestServices>,
    ) -> WafDecision {
        if let Some(decision) = self.check_block_store(ip, site_id) {
            return decision;
        }

        if let Some(decision) = self.check_rate_limits(ip, site_id).await {
            return decision;
        }

        if let Some(decision) = self.check_endpoint_block(path, method) {
            return decision;
        }

        if let Some(decision) = self.check_honeypot(ip, path, method, ua) {
            return decision;
        }

        if let Some(decision) = self.check_bot_protection(ip, path, ua, ja4_hash, site_bot_config) {
            return decision;
        }

        if let Some(ref protector) = self.flood_protector {
            match protector.check_tcp_connection(ip) {
                FloodDecision::RateLimited => {
                    return WafDecision::Block(429, "Rate Limited".to_string())
                }
                FloodDecision::Blackholed => return WafDecision::Drop,
                FloodDecision::Allowed => {}
            }
        }

        // Parallel Attack Detection
        if let Some(ad) = self.attack_detector.load().as_ref() {
            let http_method =
                http::Method::from_bytes(method.as_bytes()).unwrap_or(http::Method::GET);

            let (result, score) = ad
                .check_request(ip, &http_method, path, query, headers, body)
                .await;

            if let Some(res) = result {
                tracing::info!(
                    "Attack detected from {}: {:?} (score: {}) at {}",
                    ip,
                    res.attack_type,
                    score,
                    res.input_location
                );

                if let Some(ref tl) = self.threat_level {
                    tl.record_attack();
                }

                if let Some(ref violation_tracker) = self.violation_tracker {
                    violation_tracker.record_violation(ip, "attack_detected", 3);
                }

                return WafDecision::Block(403, "Attack Detected".to_string());
            }
        }

        WafDecision::Pass
    }

    pub async fn check_request(
        &self,
        site_id: Option<&str>,
        ip: IpAddr,
        method: &str,
        path: &str,
        ua: Option<&str>,
    ) -> WafDecision {
        let headers = http::HeaderMap::new();
        self.check_request_full(
            site_id, ip, method, path, None, &headers, None, ua, None, None, None,
        )
        .await
    }

    async fn check_rate_limits(&self, ip: IpAddr, site_id: Option<&str>) -> Option<WafDecision> {
        let result = self.rate_limiter.check_rate_limit(site_id, ip).await;
        match result {
            RateLimitResult::Allowed => None,
            RateLimitResult::Limited {
                limit_type,
                retry_after_millis,
            } => {
                tracing::info!(
                    "Rate limiting IP {}: {} (site: {:?}, retry after: {}ms)",
                    ip,
                    limit_type,
                    site_id.unwrap_or("global"),
                    retry_after_millis
                );

                let threat_level = self
                    .threat_level
                    .as_ref()
                    .map(|tl| tl.get_level().as_u8())
                    .unwrap_or(1);

                if threat_level >= 2 {
                    if let Some(decision) = self.maybe_escalate_and_block(
                        ip,
                        "rate_limit",
                        threat_level,
                        429,
                        "Too Many Requests",
                    ) {
                        return Some(decision);
                    }
                }

                Some(WafDecision::Block(429, "Too Many Requests".to_string()))
            }
            RateLimitResult::Blackholed => Some(WafDecision::Drop),
        }
    }

    fn check_block_store(&self, ip: IpAddr, site_id: Option<&str>) -> Option<WafDecision> {
        if let Some(ref store) = self.block_store {
            let scope = site_id.unwrap_or("global");
            if let Some(entry) = store.is_blocked(&ip, scope) {
                if self.config.drop_blocked_requests {
                    return Some(WafDecision::Drop);
                }
                return Some(WafDecision::Block(403, entry.reason.clone()));
            }
        }
        None
    }

    fn check_endpoint_block(&self, path: &str, method: &str) -> Option<WafDecision> {
        let result = self.endpoint_blocker.check(path, method);
        match result {
            EndpointCheckResult::Allowed => None,
            EndpointCheckResult::Blocked {
                response_code,
                html,
                ..
            } => Some(WafDecision::Block(response_code, html.unwrap_or_default())),
        }
    }

    fn check_honeypot(
        &self,
        ip: IpAddr,
        path: &str,
        method: &str,
        user_agent: Option<&str>,
    ) -> Option<WafDecision> {
        if let Some(matched) = self.sensitive_endpoint_manager.check(path) {
            tracing::info!(
                "Honeypot hit: IP {} accessed sensitive endpoint {} (matched: {}) (UA: {:?})",
                ip,
                path,
                matched,
                user_agent
            );

            if let Some(ref tl) = self.threat_level {
                tl.record_attack();
            }

            if let Some(decision) = self.maybe_escalate_and_block(
                ip,
                "honeypot_hit",
                4, // Critical threat level for honeypot hits
                403,
                "Access Denied",
            ) {
                return Some(decision);
            }

            return Some(WafDecision::Stall);
        }
        None
    }

    fn check_bot_protection(
        &self,
        client_ip: IpAddr,
        path: &str,
        user_agent: Option<&str>,
        ja4_hash: Option<&str>,
        site_bot_config: Option<&crate::config::site::SiteBotConfig>,
    ) -> Option<WafDecision> {
        let block_ai = site_bot_config.and_then(|c| c.block_ai_crawlers);

        // Use full fingerprinting check (JA3 is None here, JA4 is passed)
        let bot_result = self
            .bot_detector
            .check_with_fingerprints(user_agent, block_ai, None, ja4_hash);

        match bot_result {
            BotDetectionResult::Blocked { reason, .. } => {
                tracing::info!(
                    "Blocking bot from {}: {} - UA: {:?}, JA4: {:?}",
                    client_ip,
                    reason,
                    user_agent,
                    ja4_hash
                );
                crate::metrics::record_attack_type("Bots");
                Some(WafDecision::Block(403, "Forbidden".to_string()))
            }
            BotDetectionResult::Tarpit { reason, .. } => {
                tracing::info!(
                    "Tarpitting scraper from {}: {} - UA: {:?}, JA4: {:?}",
                    client_ip,
                    reason,
                    user_agent,
                    ja4_hash
                );
                Some(WafDecision::Tarpit(path.to_string()))
            }
            BotDetectionResult::Allowed { .. } => {
                // Suspicious if it's a known automated tool but not explicitly blocked
                let is_automated = user_agent.is_some_and(|ua| {
                    let ua_lower = ua.to_lowercase();
                    ua_lower.contains("curl")
                        || ua_lower.contains("postman")
                        || ua_lower.contains("python-requests")
                        || ua_lower.contains("go-http-client")
                });

                if is_automated {
                    let (html, session_id) = self
                        .challenge_manager
                        .generate_challenge_page(&client_ip, Some(path));
                    if let Some(sid) = session_id {
                        return Some(WafDecision::ChallengeWithCookie {
                            challenge_type: self.challenge_manager.get_challenge_type(),
                            html,
                            session_cookie_name: self.challenge_manager.css_session_cookie_name(),
                            session_cookie_value: sid,
                            session_cookie_max_age: self.challenge_manager.css_window_secs(),
                        });
                    } else {
                        return Some(WafDecision::Challenge(
                            self.challenge_manager.get_challenge_type(),
                            html,
                        ));
                    }
                }

                None
            }
        }
    }

    fn maybe_escalate_and_block(
        &self,
        ip: IpAddr,
        reason: &str,
        threat_level: u8,
        code: u16,
        msg: &str,
    ) -> Option<WafDecision> {
        if let Some(ref tracker) = self.violation_tracker {
            if tracker.record_violation(ip, reason, threat_level) > 0 {
                if let Some(ref store) = self.block_store {
                    let duration = self.honeypot_ban_duration_secs;
                    store.block_ip(ip, reason, duration, "global");
                }
                return Some(WafDecision::Block(code, msg.to_string()));
            }
        }
        None
    }

    pub async fn check_honeypot_async(
        &self,
        ip: IpAddr,
        path: &str,
        method: &str,
        user_agent: Option<&str>,
    ) -> Option<WafDecision> {
        self.check_honeypot(ip, path, method, user_agent)
    }

    pub fn check_early(
        &self,
        client_ip: IpAddr,
        _path: &str,
        _cookies: Option<&str>,
        _ua: Option<&str>,
    ) -> WafDecision {
        if let Some(ref store) = self.block_store {
            let scope = "global";
            if let Some(entry) = store.is_blocked(&client_ip, scope) {
                if self.config.drop_blocked_requests {
                    return WafDecision::Drop;
                }
                return WafDecision::Block(403, entry.reason.clone());
            }
        }
        WafDecision::Pass
    }

    pub fn streaming(&self) -> Option<crate::waf::attack_detection::StreamingWafCore> {
        self.attack_detector
            .load()
            .as_ref()
            .map(|ad| ad.clone().streaming())
    }

    pub fn block_ip_for_honeypot(
        &self,
        ip: IpAddr,
        reason: &str,
        duration_secs: u64,
        _scope: &str,
    ) {
        if let Some(ref store) = self.block_store {
            store.block_ip(ip, reason, duration_secs, "global");
        }
    }

    pub fn block_ip_with_threat_intel(
        &self,
        ip: IpAddr,
        reason: &str,
        duration_secs: u64,
        _scope: &str,
    ) {
        if let Some(ref store) = self.block_store {
            store.block_ip(ip, reason, duration_secs, "global");
        }
    }

    pub fn set_flood_protector(&mut self, protector: Arc<FloodProtector>) {
        #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
        {
            if let Some(ebpf) = protector.get_syn_protector().get_ebpf_protector() {
                // If we have an eBPF protector, wrap it in a MitigationProvider and set it
                // We need to be careful with lifetimes and Arcs here.
                // Assuming EbpfSynFloodProtector is Clone or can be wrapped in Arc/Mutex.
                // Since EbpfSynFloodProtector is not easily Clone, we might need to adjust its structure
                // or use a pointer. Given the current structure, we'll use a Mutex-wrapped Arc if available.
                // For now, we'll use the Logging provider as a placeholder if we can't easily bridge them,
                // but the goal is to use EbpfMitigationProvider.
            }
        }
        self.flood_protector = Some(protector);
    }

    pub fn is_over_bandwidth_limit(&self) -> bool {
        if let Some(ref shaper) = self.traffic_shaper {
            let (ingress_over, egress_over) = shaper.is_over_monthly_limit();
            ingress_over || egress_over
        } else {
            false
        }
    }

    pub fn check_dht_threat_lookup(
        &self,
        _ip: IpAddr,
        _threat_intel: Option<&Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>,
    ) -> Option<WafDecision> {
        // Placeholder for DHT lookup
        None
    }

    pub fn record_suspicious_words(
        &self,
        _ip: IpAddr,
        _path: &str,
        _query: Option<&str>,
        _ua: Option<&str>,
    ) {
        // Placeholder
    }

    pub fn start_background_tasks(&self) {
        // Placeholder
    }

    pub fn get_threat_intel(
        &self,
    ) -> Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>> {
        // Phase 3: Relegated to Control Plane (Supervisor).
        None
    }

    pub fn get_upload_validator(&self) -> Option<Arc<crate::upload::UploadValidator>> {
        get_upload_validator()
    }

    pub fn generate_tarpit_response(&self, _path: &str) -> String {
        "Tarpit active".to_string()
    }

    pub fn stream_tarpit(
        &self,
        path: &str,
        user_agent: Option<&str>,
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
        let tarpit_config = crate::tarpit::TarpitConfig {
            enabled: self.tarpit_defaults.enabled,
            max_depth: self.tarpit_defaults.max_depth,
            links_per_page: self.tarpit_defaults.links_per_page,
            response_delay_ms: self.tarpit_defaults.response_delay_ms,
            scraper_patterns: self.tarpit_defaults.scraper_user_agents.clone(),
        };
        let handler = crate::tarpit::TarpitHandler::new(tarpit_config);
        handler.stream_request(path, user_agent)
    }

    pub fn check_request_body(&self, _chunk: &[u8]) -> (bool, Option<WafDecision>) {
        (false, None)
    }

    pub fn reload_attack_detector(&self) -> Result<(), String> {
        // Placeholder
        Ok(())
    }

    pub fn set_request_services(&self, _services: Arc<RequestServices>) {
        // Placeholder
    }
}

pub static UPLOAD_VALIDATOR: std::sync::OnceLock<Arc<crate::upload::UploadValidator>> =
    std::sync::OnceLock::new();

pub fn get_upload_validator() -> Option<Arc<crate::upload::UploadValidator>> {
    UPLOAD_VALIDATOR.get().cloned()
}

pub fn set_upload_validator(validator: Arc<crate::upload::UploadValidator>) {
    let _ = UPLOAD_VALIDATOR.set(validator);
}

pub fn set_threat_intel(_intel: Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>) {
    // Relegated to Control Plane (Supervisor)
}

pub fn set_yara_rules(_rules: Arc<crate::mesh::YaraRulesManager>) {
    // Relegated to Control Plane (Supervisor)
}

pub fn get_yara_rules() -> Option<Arc<crate::mesh::YaraRulesManager>> {
    None
}
