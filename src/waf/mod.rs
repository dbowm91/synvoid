//! WAF (Web Application Firewall) core functionality.
//!
//! This module provides the core WAF engine including:
//! - Rate limiting (per-IP and global)
//! - Bot detection
//! - Attack detection (SQLi, XSS, etc.)
//! - Threat level management
//! - Challenge system (PoW, CSS)
//!
//! # Example
//! ```ignore
//! let waf = WafCore::new(config);
//! let decision = waf.check_request("example_site", client_ip, "GET", "/").await;
//! ```

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

pub use asn_tracker::{AsnCheckResult, AsnTracker};
pub use attack_detection::{
    AttackDetectionConfig, AttackDetectionResult, AttackDetector, AttackType, StreamingWafCore,
};
pub use bot::{BotDetectionResult, BotDetector};
pub use endpoints::{
    EndpointBlockerManager, EndpointCheckResult, ErrorPageManager, SensitiveEndpointManager,
};
pub use flood::{FloodConfig, FloodDecision, FloodProtector};
pub use ip_feed::{IpFeedEntry, IpFeedManager, MultiFeedManager};
pub use probe_tracker::{
    ProbeConfig, ProbeEvent, ProbeRecord, ProbeResult, ProbeStats, ProbeTracker,
    SuspiciousWordRecord, SuspiciousWordStats, SuspiciousWordTracker, UpstreamErrorRecord,
    UpstreamErrorResult, UpstreamErrorStats, UpstreamErrorTracker,
};
pub use ratelimit::{RateLimitConfigStore, RateLimitResult, RateLimiterManager};
pub use request_sanitization::{RequestSanitizer, SanitizedRequest};
pub use rule_feed::{
    get_custom_patterns_for_category, get_global_patterns, get_merged_patterns,
    has_custom_patterns, GlobalRulePatterns, ParsedRules, RuleFeedManager, RuleFeedManagerForWaf,
    RuleFeedResponse, RuleSet,
};
pub use threat_level::{
    BaselineStats, LearningStats, ThreatHistory, ThreatHistoryAll, ThreatHistorySample,
    ThreatLevel, ThreatLevelManager, ThreatMetrics, ThreatScore, ThreatStatus,
};
pub use traffic_shaper::{
    AsyncTokenBucket, BandwidthDirection, BandwidthLimitExceeded, ConnectionLimitError,
    ConnectionLimiter, ConnectionToken, GlobalTrafficShaper, SiteTrafficLimits, SiteTrafficShaper,
};
pub use violation_tracker::{ViolationStats, ViolationTracker};

#[cfg(feature = "mesh")]
pub use crate::mesh::yara_rules::YaraRulesManager;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub request_paths: Vec<String>,
    #[serde(default)]
    pub ips: Vec<IpAddr>,
}

/// WAF decision for a request.
///
/// This enum represents the result of WAF inspection, indicating how the
/// request should be handled.
#[derive(Debug, Clone)]
pub enum WafDecision {
    Block(u16, String),
    Challenge(String),
    ChallengeWithCookie {
        html: String,
        session_cookie_name: String,
        session_cookie_value: String,
        session_cookie_max_age: u64,
    },
    Tarpit(String),
    Pass,
    Drop,
    Stall,
}

use crate::auth::AuthManager;
use crate::block_store::BlockStore;
use crate::challenge::{ChallengeConfig, ChallengeManager, ChallengeResult};
use crate::config::RateLimitMemoryConfig;
#[cfg(feature = "mesh")]
use crate::mesh::protocol::{ThreatSeverity, ThreatType};
#[cfg(feature = "mesh")]
use crate::mesh::threat_intel::ThreatIntelligenceManager;
use crate::theme::ThemeConfig;
use crate::upload::UploadValidator;
use crate::worker::context::RequestServices;

use arc_swap::ArcSwapOption;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

#[cfg(feature = "mesh")]
static THREAT_INTEL: OnceLock<Arc<ThreatIntelligenceManager>> = OnceLock::new();
#[cfg(feature = "mesh")]
static YARA_RULES: OnceLock<Arc<YaraRulesManager>> = OnceLock::new();
static UPLOAD_VALIDATOR: OnceLock<Arc<UploadValidator>> = OnceLock::new();

#[cfg(feature = "mesh")]
#[deprecated(
    since = "0.2.0",
    note = "Use RequestServices context instead of global singleton"
)]
pub fn set_threat_intel(ti: Arc<ThreatIntelligenceManager>) {
    let _ = THREAT_INTEL.set(ti);
}

#[cfg(feature = "mesh")]
#[deprecated(
    since = "0.2.0",
    note = "Use RequestServices context instead of global singleton"
)]
pub fn get_threat_intel() -> Option<Arc<ThreatIntelligenceManager>> {
    THREAT_INTEL.get().cloned()
}

#[cfg(feature = "mesh")]
#[deprecated(
    since = "0.2.0",
    note = "Use RequestServices context instead of global singleton"
)]
pub fn set_yara_rules(yr: Arc<YaraRulesManager>) {
    let _ = YARA_RULES.set(yr);
}

#[cfg(feature = "mesh")]
#[deprecated(
    since = "0.2.0",
    note = "Use RequestServices context instead of global singleton"
)]
pub fn get_yara_rules() -> Option<Arc<YaraRulesManager>> {
    YARA_RULES.get().cloned()
}

#[deprecated(
    since = "0.2.0",
    note = "Use RequestServices context instead of global singleton"
)]
pub fn set_upload_validator(uv: Arc<UploadValidator>) {
    let _ = UPLOAD_VALIDATOR.set(uv);
}

#[deprecated(
    since = "0.2.0",
    note = "Use RequestServices context instead of global singleton"
)]
pub fn get_upload_validator() -> Option<Arc<UploadValidator>> {
    UPLOAD_VALIDATOR.get().cloned()
}
use rand::Rng;
use std::collections::HashSet;

/// Core WAF (Web Application Firewall) engine.
///
/// This is the main entry point for request filtering. It coordinates multiple
/// protection layers including rate limiting, bot detection, attack detection,
/// and challenge systems.
///
/// # Fields
/// * `rate_limiter` - Manages per-IP and global rate limits
/// * `bot_detector` - Identifies and blocks malicious bots
/// * `endpoint_blocker` - Blocks access to sensitive endpoints
/// * `challenge_manager` - Handles PoW and CSS challenges
/// * `attack_detector` - Detects SQL injection, XSS, and other attacks
/// * `block_store` - Manages IP blocklist
///
/// # Example
/// ```ignore
/// let waf = WafCore::new(WafCoreConfig { ... });
/// let decision = waf.check_request_full(
///     "example_site",
///     client_ip,
///     "GET",
///     "/path",
///     Some("query=string"),
///     &headers,
///     body,
///     user_agent,
///     None,
///     None,
/// ).await;
/// ```
pub struct WafCore {
    pub rate_limiter: RateLimiterManager,
    pub bot_detector: BotDetector,
    pub endpoint_blocker: EndpointBlockerManager,
    pub sensitive_endpoint_manager: SensitiveEndpointManager,
    pub error_page_manager: ErrorPageManager,
    pub challenge_manager: ChallengeManager,
    pub auth_manager: Option<Arc<AuthManager>>,
    attack_detector: ArcSwapOption<AttackDetector>,
    attack_detection_config: ArcSwapOption<AttackDetectionConfig>,
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
    test_mode: TestModeConfig,
    honeypot_ban_duration_secs: u64,
    request_services: ArcSwapOption<RequestServices>,
}

#[derive(Clone, Default)]
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

    pub fn from_flags(flags: &[&str]) -> Self {
        let mut config = Self {
            enabled: true,
            ..Self::default()
        };

        for flag in flags {
            match *flag {
                "ratelimit-off" | "ratelimit_off" => config.ratelimit_off = true,
                "attack-off" | "attack_off" => config.attack_off = true,
                "bot-off" | "bot_off" => config.bot_off = true,
                "challenge-off" | "challenge_off" => config.challenge_off = true,
                "flood-off" | "flood_off" => config.flood_off = true,
                "asn-off" | "asn_off" => config.asn_off = true,
                _ => {}
            }
        }
        config
    }

    pub fn disabled_count(&self) -> usize {
        [
            self.ratelimit_off,
            self.attack_off,
            self.bot_off,
            self.challenge_off,
            self.flood_off,
        ]
        .iter()
        .filter(|&&x| x)
        .count()
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

pub struct WafCoreConfig {
    pub rate_config: RateLimitConfigStore,
    pub memory_config: RateLimitMemoryConfig,
    pub bot_config: BotProtectionConfig,
    pub endpoint_config: EndpointBlockerConfig,
    pub waf_config: WafConfig,
    pub whitelist: Vec<String>,
    pub block_store: Option<Arc<BlockStore>>,
    pub attack_detection_config: Option<AttackDetectionConfig>,
    pub auth_manager: Option<Arc<AuthManager>>,
    pub threat_level_config: Option<crate::config::ThreatLevelConfig>,
    pub ip_feed_config: Option<crate::config::IpFeedConfig>,
    pub probe_config: Option<crate::config::HoneypotProbingDefaults>,
    pub suspicious_words_config: Option<crate::config::SuspiciousWordsConfig>,
    pub upstream_errors_config: Option<crate::config::UpstreamErrorsConfig>,
    pub traffic_shaping_config: Option<crate::config::TrafficShapingConfig>,
    pub asn_scraping_config: Option<crate::config::defaults::AsnScrapingConfig>,
    pub geoip: Option<Arc<crate::geoip::GeoIpManager>>,
    pub data_dir: Option<std::path::PathBuf>,
    pub test_mode: TestModeConfig,
    pub tarpit_defaults: Option<crate::config::TarpitDefaults>,
}

impl WafCore {
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
                let probe_config = ProbeConfig {
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
            bot_config.known_bots_allow,
            bot_config.ai_crawlers_block,
            bot_config.scraper_patterns,
            bot_config.block_ai_crawlers,
        );
        let endpoint_blocker = EndpointBlockerManager::new(
            endpoint_config.paths,
            endpoint_config.use_regex,
            endpoint_config.block_methods,
            endpoint_config.block_response_code,
            endpoint_config.block_page_html.clone(),
        );

        // Log warnings for invalid regex patterns
        let invalid_patterns = endpoint_blocker.get_invalid_patterns();
        for pattern in invalid_patterns {
            tracing::warn!(
                "Invalid or unsafe regex pattern in blocked paths: '{}'",
                pattern
            );
        }
        let sensitive_endpoint_manager =
            SensitiveEndpointManager::from_file(&bot_config.honeypot_endpoints_file);
        let error_page_manager = ErrorPageManager::with_theme_and_mode(
            &bot_config.error_pages_directory,
            bot_config.error_pages_custom_directory,
            bot_config.error_pages_enabled,
            &bot_config.error_pages_mode,
            bot_config.theme.clone(),
        );
        let challenge_manager = ChallengeManager::new(ChallengeConfig {
            cookie_name: bot_config.challenge_cookie_name,
            pow_enabled: bot_config.enable_pow_challenge,
            pow_difficulty: bot_config.pow_difficulty,
            pow_window_secs: bot_config.pow_window_secs,
            pow_timeout_secs: bot_config.pow_timeout_secs,
            css_enabled: bot_config.css_enabled,
            css_window_secs: bot_config.css_window_secs,
            css_invalid_min: bot_config.css_invalid_min,
            css_invalid_max: bot_config.css_invalid_max,
            css_valid_count: bot_config.css_valid_count,
            css_asset_path: bot_config.css_asset_path,
            css_verification_window_secs: bot_config.css_verification_window_secs,
            honeypot_enabled: bot_config.honeypot_enabled,
            honeypot_paths_per_ip: bot_config.honeypot_paths_per_ip,
            honeypot_ttl_secs: bot_config.honeypot_ttl_secs,
            theme: bot_config.theme,
            challenge_max_attempts: bot_config.challenge_max_attempts,
            challenge_rate_limit_window_secs: bot_config.challenge_rate_limit_window_secs,
            challenge_priority: bot_config.challenge_priority,
            mesh_pow_enabled: bot_config.mesh_pow_enabled,
            mesh_pow_key_exchange_enabled: bot_config.mesh_pow_key_exchange_enabled,
            mesh_pow_auditing_enabled: bot_config.mesh_pow_auditing_enabled,
            mesh_id: bot_config.mesh_id.clone(),
            mesh_global_node_url: bot_config.mesh_global_node_url.clone(),
            mesh_audit_urls: bot_config.mesh_audit_urls.clone(),
        });

        let tarpit_defaults = tarpit_defaults.unwrap_or_default();
        let tarpit_generator = Arc::new(crate::tarpit::generator::MarkovChain::new());

        let mut whitelist_set = HashSet::new();
        for ip_str in whitelist {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                whitelist_set.insert(ip);
            }
        }

        Self {
            rate_limiter,
            bot_detector,
            endpoint_blocker,
            sensitive_endpoint_manager,
            error_page_manager,
            challenge_manager,
            auth_manager,
            attack_detector: ArcSwapOption::new(attack_detection_config.map(Arc::new)),
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
            traffic_shaper,
            connection_limiter,
            asn_tracker,
            test_mode,
            honeypot_ban_duration_secs: 86400,
            request_services: ArcSwapOption::new(None),
        }
    }

    pub fn update_attack_detection_config(&self, config: AttackDetectionConfig) {
        self.attack_detection_config.store(Some(Arc::new(config)));
    }

    pub fn set_request_services(&self, services: Arc<RequestServices>) {
        self.request_services.store(Some(services));
    }

    /// Check if a request should be allowed.
    ///
    /// This is a convenience method that calls `check_request_full` with
    /// common defaults.
    ///
    /// # Arguments
    /// * `site_id` - Identifier for the site (used for site-specific rules)
    /// * `client_ip` - The client's IP address
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `path` - Request path
    ///
    /// # Returns
    /// `WafDecision` indicating how to handle the request
    pub async fn check_request(
        &self,
        site_id: &str,
        client_ip: IpAddr,
        method: &str,
        path: &str,
    ) -> WafDecision {
        let headers = http::HeaderMap::new();
        self.check_request_full(
            Some(site_id),
            client_ip,
            method,
            path,
            None,
            &headers,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    }

    /// Comprehensive request inspection.
    ///
    /// Runs the request through all active WAF layers:
    /// 1. Whitelist check
    /// 2. Rate limiting
    /// 3. Blockstore check
    /// 4. Endpoint blocking
    /// 5. Bot detection
    /// 6. Attack detection (regex, libinjection)
    /// 7. Challenges (if enabled)
    ///
    /// # Returns
    /// - `Pass` - Request is allowed
    /// - `Block` - Request should be blocked
    /// - `Drop` - Request should be silently dropped
    /// - `Challenge` - Client must complete a challenge
    /// - `Tarpit` - Client receives fake/slow response
    /// - `Stall` - Connection is stalled (honeypot)
    pub async fn check_request_full(
        &self,
        site_id: Option<&str>,
        client_ip: std::net::IpAddr,
        method: &str,
        path: &str,
        query_string: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
        user_agent: Option<&str>,
        ja4_hash: Option<&str>,
        site_bot_config: Option<&crate::config::site::SiteBotConfig>,
        services: Option<Arc<RequestServices>>,
    ) -> WafDecision {
        let services = services.or_else(|| (*self.request_services.load()).clone());

        if self.whitelist.contains(&client_ip) {
            return WafDecision::Pass;
        }

        let ratelimit_start = std::time::Instant::now();
        if let Some(decision) = self.check_rate_limits(client_ip, site_id) {
            crate::metrics::record_waf_check_timing(
                "ratelimit",
                ratelimit_start.elapsed().as_millis() as u64,
            );
            return decision;
        }

        let blockstore_start = std::time::Instant::now();
        if let Some(decision) = self.check_block_store(client_ip, site_id) {
            crate::metrics::record_waf_check_timing(
                "blockstore",
                blockstore_start.elapsed().as_millis() as u64,
            );
            return decision;
        }

        let dht_start = std::time::Instant::now();
        #[cfg(feature = "mesh")]
        if let Some(decision) = self.check_dht_threat_lookup(
            client_ip,
            services.as_ref().and_then(|rs| rs.threat_intel.as_ref()),
        ) {
            crate::metrics::record_waf_check_timing(
                "dht_threat",
                dht_start.elapsed().as_millis() as u64,
            );
            return decision;
        }
        #[cfg(not(feature = "mesh"))]
        let _ = dht_start;

        let endpoint_start = std::time::Instant::now();
        if let Some(decision) = self.check_endpoint_block(path, method) {
            crate::metrics::record_waf_check_timing(
                "endpoint",
                endpoint_start.elapsed().as_millis() as u64,
            );
            return decision;
        }

        self.record_suspicious_words(client_ip, path, query_string, user_agent);

        let honeypot_start = std::time::Instant::now();
        if let Some(decision) = self.check_honeypot(client_ip, path, method, user_agent) {
            crate::metrics::record_waf_check_timing(
                "honeypot",
                honeypot_start.elapsed().as_millis() as u64,
            );
            return decision;
        }

        let bot_start = std::time::Instant::now();
        if let Some(decision) =
            self.check_bot_protection(client_ip, path, user_agent, ja4_hash, site_bot_config)
        {
            crate::metrics::record_waf_check_timing("bot", bot_start.elapsed().as_millis() as u64);
            return decision;
        }

        let attack_start = std::time::Instant::now();
        if let Some(decision) =
            self.check_attack_patterns(client_ip, method, path, query_string, headers, body)
                .await
        {
            crate::metrics::record_waf_check_timing(
                "attack",
                attack_start.elapsed().as_millis() as u64,
            );
            return decision;
        }

        let challenge_start = std::time::Instant::now();
        if let Some(decision) = self.check_challenge(client_ip, path, site_bot_config) {
            crate::metrics::record_waf_check_timing(
                "challenge",
                challenge_start.elapsed().as_millis() as u64,
            );
            return decision;
        }

        WafDecision::Pass
    }

    pub fn check_request_body(&self, body: &[u8]) -> Option<WafDecision> {
        if let Some(attack_detector) = self.attack_detector.load().as_ref() {
            if self.test_mode.enabled && self.test_mode.attack_off {
                return None;
            }

            if let Some(result) = attack_detector.check_body_only(body) {
                metrics::counter!(
                    "synvoid.attack_detected",
                    "type" => result.attack_type.to_string(),
                    "location" => result.input_location.to_string(),
                )
                .increment(1);

                crate::metrics::record_attack_type(&result.attack_type.to_string());

                tracing::warn!(
                    attack_type = %result.attack_type,
                    location = %result.input_location,
                    fingerprint = ?result.fingerprint,
                    pattern = ?result.matched_pattern,
                    "Streaming body attack detected"
                );

                let threat_level = self
                    .threat_level
                    .as_ref()
                    .map(|tl| tl.get_level().as_u8())
                    .unwrap_or(1);

                if threat_level >= 3 {
                    if let Some(decision) = self.maybe_escalate_and_block(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        "streaming_body_attack",
                        threat_level,
                        403,
                        "Attack detected - IP blocked",
                    ) {
                        if let Some(ref tl) = self.threat_level {
                            tl.record_blocked();
                        }
                        return Some(decision);
                    }
                }

                if let Some(ref tl) = self.threat_level {
                    tl.record_attack();
                }

                let action_str = match self.attack_detection_config.load().as_ref() {
                    Some(config) => config.action.clone(),
                    None => "stall".to_string(),
                };

                match action_str.as_str() {
                    "block" => return Some(WafDecision::Block(403, "Forbidden".to_string())),
                    "log" => return None,
                    _ => return Some(WafDecision::Stall),
                }
            }
        }
        None
    }

    fn check_rate_limits(&self, ip: IpAddr, site_id: Option<&str>) -> Option<WafDecision> {
        let result = self.rate_limiter.check_request(ip, site_id);
        match result {
            RateLimitResult::Allowed => None,
            RateLimitResult::Blocked {
                reason,
                retry_after: _,
            } => {
                tracing::info!(
                    "Rate limiting IP {}: {} (site: {:?})",
                    ip,
                    reason,
                    site_id.unwrap_or("global")
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
        }
    }

    fn check_block_store(&self, ip: IpAddr, site_id: Option<&str>) -> Option<WafDecision> {
        if let Some(ref store) = self.block_store {
            let scope = site_id.unwrap_or("global");
            if let Some(entry) = store.is_blocked(&ip, scope) {
                if self.config.drop_blocked_requests {
                    return Some(WafDecision::Drop);
                }
                return Some(WafDecision::Block(403, entry.reason));
            }
        }
        None
    }

    fn check_endpoint_block(&self, path: &str, method: &str) -> Option<WafDecision> {
        let result = self.endpoint_blocker.check_request(path, method);
        match result {
            EndpointCheckResult::Allowed => None,
            EndpointCheckResult::Blocked { code, html } => {
                Some(WafDecision::Block(code, html.unwrap_or_default()))
            }
        }
    }

    fn check_honeypot(
        &self,
        ip: IpAddr,
        path: &str,
        method: &str,
        user_agent: Option<&str>,
    ) -> Option<WafDecision> {
        if self.sensitive_endpoint_manager.is_sensitive_endpoint(path) {
            tracing::info!(
                "Honeypot hit: IP {} accessed sensitive endpoint {} (UA: {:?})",
                ip,
                path,
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
        let bot_result = self.bot_detector.check_request(user_agent, ja4_hash);
        match bot_result {
            BotDetectionResult::Blocked { reason, .. } => {
                tracing::info!(
                    "Blocking bot from {}: {} - UA: {:?}",
                    client_ip,
                    reason,
                    user_agent
                );
                crate::metrics::record_attack_type("Bots");
                Some(WafDecision::Block(403, "Forbidden".to_string()))
            }
            BotDetectionResult::Stall { reason, .. } => {
                tracing::info!(
                    "Blocking bot from {}: {} - UA: {:?}",
                    client_ip,
                    reason,
                    user_agent
                );
                crate::metrics::record_attack_type("Bots");
                Some(WafDecision::Stall)
            }
            BotDetectionResult::Tarpit { reason, .. } => {
                tracing::info!(
                    "Tarpitting scraper from {}: {} - UA: {:?}",
                    client_ip,
                    reason,
                    user_agent
                );
                Some(WafDecision::Tarpit(path.to_string()))
            }
            BotDetectionResult::Allowed { .. } => None,
        }
    }

    async fn check_attack_patterns(
        &self,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        query_string: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> Option<WafDecision> {
        if let Some(attack_detector) = self.attack_detector.load().as_ref() {
            if self.test_mode.enabled && self.test_mode.attack_off {
                return None;
            }

            let detector = attack_detector.clone();
            let method_owned = method.to_string();
            let path_owned = path.to_string();
            let query_owned = query_string.map(|s| s.to_string());
            let headers_owned = headers.clone();
            let body_owned = body.map(|b| b.to_vec());

            let (first_attack_result, anomaly_score) = tokio::task::spawn_blocking(move || {
                let method_enum = match method_owned.as_str() {
                    "GET" => http::Method::GET,
                    "POST" => http::Method::POST,
                    "PUT" => http::Method::PUT,
                    "DELETE" => http::Method::DELETE,
                    "PATCH" => http::Method::PATCH,
                    "HEAD" => http::Method::HEAD,
                    "OPTIONS" => http::Method::OPTIONS,
                    "TRACE" => http::Method::TRACE,
                    "CONNECT" => http::Method::CONNECT,
                    _ => http::Method::GET,
                };

                detector.check_request(
                    &method_enum,
                    &path_owned,
                    query_owned.as_deref(),
                    &headers_owned,
                    body_owned.as_deref(),
                )
            })
            .await
            .unwrap_or_else(|e| {
                tracing::error!("WAF attack detection task panicked: {}", e);
                (None, 0)
            });

            if let Some(result) = first_attack_result {
                metrics::counter!(
                    "synvoid.attack_detected",
                    "type" => result.attack_type.to_string(),
                    "location" => result.input_location.to_string(),
                )
                .increment(1);

                crate::metrics::record_attack_type(&result.attack_type.to_string());

                tracing::warn!(
                    attack_type = %result.attack_type,
                    location = %result.input_location,
                    fingerprint = ?result.fingerprint,
                    pattern = ?result.matched_pattern,
                    "Attack detected - stalling connection"
                );

                let threat_level = self
                    .threat_level
                    .as_ref()
                    .map(|tl| tl.get_level().as_u8())
                    .unwrap_or(1);

                if threat_level >= 3 {
                    if let Some(decision) = self.maybe_escalate_and_block(
                        client_ip,
                        "attack",
                        threat_level,
                        403,
                        "Attack detected - IP blocked",
                    ) {
                        if let Some(ref tl) = self.threat_level {
                            tl.record_blocked();
                        }
                        return Some(decision);
                    }
                }

                if let Some(ref tl) = self.threat_level {
                    tl.record_attack();
                }

                let action_str = match self.attack_detection_config.load().as_ref() {
                    Some(config) => config.action.clone(),
                    None => "stall".to_string(),
                };

                match action_str.as_str() {
                    "block" => return Some(WafDecision::Block(403, "Forbidden".to_string())),
                    "log" => return None,
                    _ => return Some(WafDecision::Stall),
                }
            }

            if let Some(config) = self.attack_detection_config.load().as_ref() {
                if config.anomaly_scoring.enabled {
                    if anomaly_score >= config.anomaly_scoring.threshold {
                        metrics::counter!("synvoid.anomaly_score_threshold_exceeded").increment(1);
                        if let Some(ref tl) = self.threat_level {
                            tl.record_attack();
                        }
                        let action_str = config.action.clone();
                        match action_str.as_str() {
                            "block" => return Some(WafDecision::Block(403, "Forbidden".to_string())),
                            "log" => return None,
                            _ => return Some(WafDecision::Stall),
                        }
                    }
                }
            }
            None
        } else {
            None
        }
    }

    fn check_challenge(
        &self,
        client_ip: IpAddr,
        path: &str,
        site_bot_config: Option<&crate::config::site::SiteBotConfig>,
    ) -> Option<WafDecision> {
        let enable_css_honeypot = site_bot_config
            .and_then(|c| c.enable_css_honeypot)
            .unwrap_or(self.config.enable_css_honeypot);

        if (self.config.enable_pow_challenge || enable_css_honeypot)
            && !self
                .config
                .css_exempt_paths
                .iter()
                .any(|p| path.starts_with(p))
        {
            if self.test_mode.enabled && self.test_mode.challenge_off {
                return None;
            }

            let challenge_result = self.challenge_manager.check_cookie(None);
            match challenge_result {
                ChallengeResult::NotSet | ChallengeResult::Failed => {
                    let (html, session_id) = self
                        .challenge_manager
                        .generate_challenge_page(&client_ip, Some(path));
                    if let Some(sid) = session_id {
                        let session_cookie_name = self.challenge_manager.css_session_cookie_name();
                        let window_secs = self.challenge_manager.css_window_secs();
                        Some(WafDecision::ChallengeWithCookie {
                            html,
                            session_cookie_name,
                            session_cookie_value: sid,
                            session_cookie_max_age: window_secs,
                        })
                    } else {
                        Some(WafDecision::Challenge(html))
                    }
                }
                ChallengeResult::Passed => None,
                ChallengeResult::RateLimited => Some(WafDecision::Pass),
            }
        } else {
            None
        }
    }

    pub fn generate_tarpit_response(&self, path: &str) -> String {
        let mut rng = rand::rng();
        let max_depth = self.tarpit_defaults.max_depth;
        let links_per_page = self.tarpit_defaults.links_per_page;

        self.tarpit_generator.generate_html_page(
            rng.random_range(0..max_depth),
            max_depth,
            links_per_page,
            path,
        )
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
            if tracker.record_violation(ip, reason, threat_level) {
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
}

pub struct RateLimitConfig {
    pub ip: crate::config::IpRateLimitConfig,
    pub global: crate::config::GlobalRateLimitConfig,
    pub cleanup_interval_secs: u64,
}

pub struct BotProtectionConfig {
    pub block_ai_crawlers: bool,
    pub enable_css_honeypot: bool,
    pub enable_pow_challenge: bool,
    pub known_bots_allow: Vec<String>,
    pub ai_crawlers_block: Vec<String>,
    pub scraper_patterns: Vec<String>,
    pub challenge_cookie_name: String,
    pub challenge_window_secs: u64,
    pub pow_difficulty: u8,
    pub pow_timeout_secs: u64,
    pub pow_window_secs: u64,
    pub css_enabled: bool,
    pub css_invalid_min: u32,
    pub css_invalid_max: u32,
    pub css_valid_count: u32,
    pub css_asset_path: String,
    pub css_window_secs: u64,
    pub css_verification_window_secs: u32,
    pub challenge_priority: crate::challenge::ChallengePriority,
    pub challenge_max_attempts: u32,
    pub challenge_rate_limit_window_secs: u64,
    pub honeypot_endpoints_file: String,
    pub honeypot_enabled: bool,
    pub honeypot_paths_per_ip: usize,
    pub honeypot_ttl_secs: u64,
    pub honeypot_ban_duration: String,
    pub error_pages_enabled: bool,
    pub error_pages_mode: String,
    pub error_pages_directory: String,
    pub error_pages_custom_directory: Option<String>,
    pub theme: ThemeConfig,
    pub mesh_pow_enabled: bool,
    pub mesh_pow_key_exchange_enabled: bool,
    pub mesh_pow_auditing_enabled: bool,
    pub mesh_id: Option<String>,
    pub mesh_global_node_url: Option<String>,
    pub mesh_audit_urls: Vec<String>,
}

pub struct EndpointBlockerConfig {
    pub paths: Vec<String>,
    pub use_regex: bool,
    pub block_methods: Vec<String>,
    pub block_response_code: u16,
    pub block_page_html: Option<String>,
}

impl EndpointBlockerConfig {
    pub fn validate(&self) -> Vec<(String, String)> {
        let validation = EndpointBlockerManager::validate_patterns(&self.paths, self.use_regex);
        validation.invalid
    }
}
