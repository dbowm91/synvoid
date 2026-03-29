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
//! let decision = waf.check_request(client_ip, "GET", "/").await;
//! ```

pub mod asn_tracker;
pub mod attack_detection;
pub mod bot;
pub mod endpoints;
pub mod flood;
pub mod ip_feed;
pub mod probe_tracker;
pub mod ratelimit;
pub mod request_sanitization;
pub mod rule_feed;
pub mod threat_level;
pub mod traffic_shaper;
pub mod violation_tracker;

pub use asn_tracker::{AsnCheckResult, AsnTracker};
pub use attack_detection::{
    AttackDetectionConfig, AttackDetectionResult, AttackDetector, AttackType,
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

use crate::auth::AuthManager;
use crate::block_store::BlockStore;
use crate::challenge::{ChallengeConfig, ChallengeManager, ChallengeResult};
use crate::config::RateLimitMemoryConfig;
use crate::mesh::threat_intel::ThreatIntelligenceManager;
use crate::mesh::yara_rules::YaraRulesManager;
use crate::proxy::WafDecision;
use crate::theme::ThemeConfig;

use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;

thread_local! {
    static THREAT_INTEL: RwLock<Option<Arc<ThreatIntelligenceManager>>> = const { RwLock::new(None) };
    static YARA_RULES: RwLock<Option<Arc<YaraRulesManager>>> = const { RwLock::new(None) };
}

pub fn set_threat_intel(ti: Option<Arc<ThreatIntelligenceManager>>) {
    THREAT_INTEL.with(|t| {
        *t.write() = ti;
    });
}

pub fn get_threat_intel() -> Option<Arc<ThreatIntelligenceManager>> {
    THREAT_INTEL.with(|t| t.read().clone())
}

pub fn set_yara_rules(yr: Option<Arc<YaraRulesManager>>) {
    YARA_RULES.with(|y| {
        *y.write() = yr;
    });
}

pub fn get_yara_rules() -> Option<Arc<YaraRulesManager>> {
    YARA_RULES.with(|y| y.read().clone())
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
///     client_ip,
///     "GET",
///     "/path",
///     Some("query=string"),
///     &headers,
///     body,
///     user_agent,
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
    attack_detector: RwLock<Option<Arc<AttackDetector>>>,
    attack_detection_config: Option<AttackDetectionConfig>,
    pub block_store: Option<Arc<BlockStore>>,
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    pub config: WafConfig,
    pub whitelist: Arc<HashSet<IpAddr>>,
    tarpit_generator: Option<Arc<crate::tarpit::generator::MarkovChain>>,
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
        let mut config = Self::default();
        config.enabled = true;

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
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
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
            threat_intel,
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

        let attack_detector = RwLock::new(
            attack_detection_config
                .as_ref()
                .map(|config| Arc::new(AttackDetector::new(config.clone()))),
        );

        let (traffic_shaper, connection_limiter) = if let Some(config) = traffic_shaping_config {
            if config.enabled {
                let shaper = Arc::new(GlobalTrafficShaper::new(
                    config.global.clone(),
                    config.bandwidth.clone(),
                ));
                let conn_limiter = ConnectionLimiter::new(config.connection_limits.clone());
                (Some(shaper), Some(conn_limiter))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let asn_tracker = asn_scraping_config.and_then(|config| {
            if config.enabled {
                Some(Arc::new(AsnTracker::new(
                    config,
                    geoip,
                    block_store.clone(),
                )))
            } else {
                None
            }
        });

        let whitelist_set: HashSet<IpAddr> = whitelist
            .into_iter()
            .filter_map(|ip_str| ip_str.parse().ok())
            .collect();

        let honeypot_ban_duration_secs =
            Self::parse_duration(&bot_config.honeypot_ban_duration).unwrap_or(24 * 60 * 60);

        WafCore {
            rate_limiter,
            bot_detector,
            endpoint_blocker,
            sensitive_endpoint_manager,
            error_page_manager,
            challenge_manager,
            auth_manager,
            attack_detector,
            attack_detection_config,
            block_store,
            threat_intel,
            config: waf_config,
            whitelist: Arc::new(whitelist_set),
            tarpit_generator: Some(Arc::new(crate::tarpit::generator::MarkovChain::new())),
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
            honeypot_ban_duration_secs,
        }
    }

    pub fn set_threat_intel(&mut self, threat_intel: Option<Arc<ThreatIntelligenceManager>>) {
        self.threat_intel = threat_intel;
    }

    fn block_ip_with_threat_intel(
        &self,
        client_ip: IpAddr,
        reason: &str,
        duration: u64,
        scope: &str,
    ) {
        if let Some(ref store) = self.block_store {
            store.block_ip(client_ip, reason, duration, scope);
        }
        if let Some(ref threat_intel) = self.threat_intel {
            threat_intel.announce_local_block(
                client_ip,
                reason.to_string(),
                duration,
                scope.to_string(),
            );
        }
        if let Some(ref threat_intel) = get_threat_intel() {
            threat_intel.announce_local_block(
                client_ip,
                reason.to_string(),
                duration,
                scope.to_string(),
            );
        }
    }

    fn maybe_auto_ban_probe(&self, client_ip: IpAddr, tracker: &ProbeTracker) {
        let config = tracker.get_config();
        if !config.auto_ban_elevated_threat {
            return;
        }
        let threat_level = self
            .threat_level
            .as_ref()
            .map(|tl| tl.get_level().as_u8())
            .unwrap_or(1);
        if threat_level >= config.elevated_threat_threshold {
            tracing::warn!(
                ip = %client_ip,
                threat_level = threat_level,
                ban_duration_secs = config.elevated_ban_duration,
                "Auto-banning probe source due to elevated threat level"
            );
            self.block_ip_with_threat_intel(
                client_ip,
                "probe_auto_ban",
                config.elevated_ban_duration,
                "global",
            );
        }
    }

    fn handle_probe_event(
        &self,
        client_ip: IpAddr,
        path: &str,
        method: &str,
        user_agent: Option<&str>,
    ) -> Option<WafDecision> {
        if let Some(ref tracker) = self.probe_tracker {
            let result = tracker.record_event(
                client_ip,
                path.to_string(),
                method.to_string(),
                user_agent.map(String::from),
            );
            if let ProbeResult::ProbingDetected {
                unique_endpoints,
                event_count,
            } = result
            {
                tracing::warn!(
                    ip = %client_ip,
                    endpoints = ?unique_endpoints,
                    total_events = event_count,
                    "Probing pattern detected - multiple honeypot endpoints accessed"
                );
                self.maybe_auto_ban_probe(client_ip, tracker);
            }
        }
        self.block_ip_with_threat_intel(
            client_ip,
            "honeypot",
            self.honeypot_ban_duration_secs,
            "global",
        );
        Some(WafDecision::Stall)
    }

    fn maybe_escalate_and_block(
        &self,
        client_ip: IpAddr,
        violation_reason: &str,
        threat_level: u8,
        block_status: u16,
        block_message: &str,
    ) -> Option<WafDecision> {
        if let Some(ref tracker) = self.violation_tracker {
            let violation_count =
                tracker.record_violation(client_ip, violation_reason, threat_level);
            let block_threshold = self
                .threat_level
                .as_ref()
                .map(|tl| tl.get_legacy_config().escalation.violations_before_block)
                .unwrap_or(3);
            if violation_count >= block_threshold {
                let ban_duration = self
                    .threat_level
                    .as_ref()
                    .map(|tl| tl.get_base_ban_duration(violation_count))
                    .unwrap_or(3600);
                self.block_ip_with_threat_intel(
                    client_ip,
                    violation_reason,
                    ban_duration,
                    "global",
                );
                tracker.clear_violations(client_ip);
                return Some(WafDecision::Block(block_status, block_message.to_string()));
            }
        }
        None
    }

    pub fn is_over_bandwidth_limit(&self) -> bool {
        if let Some(ref shaper) = self.traffic_shaper {
            let (ingress_over, egress_over) = shaper.is_over_monthly_limit();
            return ingress_over || egress_over;
        }
        false
    }

    pub fn reload_attack_detector(&self) -> Result<(), String> {
        let config = self
            .attack_detection_config
            .as_ref()
            .ok_or("No attack detection config")?;

        let mut new_config = config.clone();

        // Merge custom patterns from config with global rule feed patterns
        // Note: sqli and xss use libinjection and don't support custom_patterns
        macro_rules! merge_patterns {
            ($category:expr, $field:ident) => {
                let patterns = crate::waf::rule_feed::get_custom_patterns_for_category($category);
                if !patterns.is_empty() {
                    new_config.$field.custom_patterns.extend(patterns);
                }
            };
        }

        merge_patterns!("path_traversal", path_traversal);
        merge_patterns!("rfi", rfi);
        merge_patterns!("ssrf", ssrf);
        merge_patterns!("ssti", ssti);
        merge_patterns!("cmd_injection", cmd_injection);
        merge_patterns!("xxe", xxe);
        merge_patterns!("jwt", jwt);
        merge_patterns!("ldap_injection", ldap_injection);
        merge_patterns!("xpath_injection", xpath_injection);
        merge_patterns!("open_redirect", open_redirect);

        *self.attack_detector.write() = Some(Arc::new(AttackDetector::new(new_config)));

        Ok(())
    }

    fn parse_duration(s: &str) -> Option<u64> {
        let s = s.trim();
        let value: u64 = s
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()?;

        let unit = s
            .chars()
            .skip_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .trim()
            .to_lowercase();

        Some(match unit.as_str() {
            "s" | "sec" | "seconds" => value,
            "m" | "min" | "minutes" => value * 60,
            "h" | "hour" | "hours" => value * 60 * 60,
            "d" | "day" | "days" => value * 60 * 60 * 24,
            "" => value,
            _ => return None,
        })
    }

    pub fn test_mode(&self) -> &TestModeConfig {
        &self.test_mode
    }

    /// Early WAF check that runs before full HTTP parsing.
    ///
    /// This performs minimal checks that can be done with just the IP, path, and cookies:
    /// - IP blocklist check
    /// - CSS challenge cookie verification
    ///
    /// Returns `WafDecision::Drop` if the connection should be silently dropped,
    /// `WafDecision::Pass` if it should proceed, or `WafDecision::ChallengeWithCookie`
    /// if a challenge should be presented.
    pub fn check_early(
        &self,
        client_ip: std::net::IpAddr,
        path: &str,
        cookies: Option<&str>,
    ) -> WafDecision {
        if let Some(ref store) = self.block_store {
            if store.is_blocked(&client_ip, "global").is_some() {
                tracing::debug!("Early check: IP {} is blocked", client_ip);
                return WafDecision::Drop;
            }
        }

        if self.config.enable_css_honeypot
            && !self
                .config
                .css_exempt_paths
                .iter()
                .any(|p| path.starts_with(p))
        {
            if self.test_mode.enabled && self.test_mode.challenge_off {
                return WafDecision::Pass;
            }

            let css_cookie = cookies.and_then(|c| {
                let cookie_name = self.challenge_manager.css_session_cookie_name();
                c.split(';')
                    .find(|cookie| cookie.trim().starts_with(&format!("{}=", cookie_name)))
                    .map(|cookie| cookie.trim()[cookie_name.len() + 1..].to_string())
            });

            let verified_cookie = cookies.and_then(|c| {
                let verified_name = self.challenge_manager.css_verified_cookie_name();
                c.split(';')
                    .find(|cookie| cookie.trim().starts_with(&format!("{}=", verified_name)))
                    .map(|_| "verified")
            });

            let cookie_value = verified_cookie.or(css_cookie.as_deref());
            let challenge_result = self.challenge_manager.check_cookie(cookie_value);

            match challenge_result {
                ChallengeResult::NotSet | ChallengeResult::Failed => {
                    let (html, session_id) =
                        self.challenge_manager.generate_challenge_page(&client_ip);
                    if let Some(sid) = session_id {
                        let session_cookie_name = self.challenge_manager.css_session_cookie_name();
                        let window_secs = self.challenge_manager.css_window_secs();
                        return WafDecision::ChallengeWithCookie {
                            html,
                            session_cookie_name,
                            session_cookie_value: sid,
                            session_cookie_max_age: window_secs,
                        };
                    }
                }
                ChallengeResult::Passed => {}
                ChallengeResult::RateLimited => {
                    return WafDecision::Pass;
                }
            }
        }

        WafDecision::Pass
    }

    /// Check a request with minimal information.
    ///
    /// This is a convenience method that calls `check_request_full` with
    /// empty headers and body.
    ///
    /// # Arguments
    /// * `client_ip` - The client's IP address
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `path` - Request path
    /// * `user_agent` - Optional user agent string
    ///
    /// # Returns
    /// A `WafDecision` indicating how to handle the request
    pub async fn check_request(
        &self,
        client_ip: std::net::IpAddr,
        method: &str,
        path: &str,
        user_agent: Option<&str>,
    ) -> WafDecision {
        self.check_request_full(
            client_ip,
            method,
            path,
            None,
            &http::HeaderMap::new(),
            None,
            user_agent,
        )
        .await
    }

    /// Check a request with full inspection.
    ///
    /// This method runs all WAF checks including:
    /// - IP whitelist verification
    /// - IP feed blocklist checks
    /// - Rate limiting (global and per-IP)
    /// - Endpoint blocking
    /// - Honeypot detection
    /// - Bot detection
    /// - Attack detection (SQLi, XSS, etc.)
    /// - Challenge verification
    ///
    /// # Arguments
    /// * `client_ip` - The client's IP address
    /// * `method` - HTTP method
    /// * `path` - Request path
    /// * `query_string` - Optional query string
    /// * `headers` - HTTP headers
    /// * `body` - Optional request body
    /// * `user_agent` - Optional user agent string
    ///
    /// # Returns
    /// A `WafDecision` indicating how to handle the request:
    /// - `Pass` - Request is allowed
    /// - `Block` - Request should be blocked
    /// - `Drop` - Request should be silently dropped
    /// - `Challenge` - Client must complete a challenge
    /// - `Tarpit` - Client receives fake/slow response
    /// - `Stall` - Connection is stalled (honeypot)
    pub async fn check_request_full(
        &self,
        client_ip: std::net::IpAddr,
        method: &str,
        path: &str,
        query_string: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
        user_agent: Option<&str>,
    ) -> WafDecision {
        if let Some(ref tl) = self.threat_level {
            tl.record_request();
        }

        if !self.test_mode.enabled || !self.test_mode.asn_off {
            if let Some(ref tracker) = self.asn_tracker {
                tracker.cleanup_unique_ips();
                if let Some(decision) = tracker.check_request(client_ip) {
                    return decision;
                }
            }
        }

        if let Some(decision) = self.check_rate_limit(client_ip, path).await {
            return decision;
        }

        if let Some(decision) = self.check_ip_feed(client_ip) {
            return decision;
        }

        if let Some(decision) = self.check_endpoint_block(path, method) {
            return decision;
        }

        self.record_suspicious_words(client_ip, path, query_string, user_agent);

        if let Some(decision) = self.check_honeypot(client_ip, path, method, user_agent) {
            return decision;
        }

        if self.whitelist.contains(&client_ip) {
            return WafDecision::Pass;
        }

        if let Some(decision) = self.check_bot_protection(client_ip, path, user_agent) {
            return decision;
        }

        if let Some(decision) =
            self.check_attack_patterns(client_ip, method, path, query_string, headers, body)
        {
            return decision;
        }

        if let Some(decision) = self.check_challenge(client_ip, path) {
            return decision;
        }

        WafDecision::Pass
    }

    async fn check_rate_limit(&self, client_ip: IpAddr, path: &str) -> Option<WafDecision> {
        if !self.test_mode.enabled || !self.test_mode.ratelimit_off {
            if self.rate_limiter.is_in_blackhole() {
                return Some(WafDecision::Drop);
            }

            match self.rate_limiter.check_global() {
                RateLimitResult::Blackholed => return Some(WafDecision::Drop),
                RateLimitResult::Limited { limit_type, .. } => {
                    tracing::debug!("Global rate limited: {}", limit_type);

                    if let Some(ref tl) = self.threat_level {
                        tl.record_blocked();
                    }
                    crate::metrics::record_attack_type("RateLimit");

                    return Some(WafDecision::Block(
                        429,
                        format!("Global rate limit exceeded ({})", limit_type),
                    ));
                }
                RateLimitResult::Allowed => {}
            }

            let _global_permit = self.rate_limiter.acquire_global_connection().await;

            let is_whitelisted = self.whitelist.contains(&client_ip);
            if !is_whitelisted {
                match self.rate_limiter.check_rate_limit(client_ip).await {
                    RateLimitResult::Limited { limit_type, .. } => {
                        tracing::debug!(
                            "Rate limited: {} for {} ({})",
                            limit_type,
                            client_ip,
                            path
                        );

                        if let Some(ref tl) = self.threat_level {
                            tl.record_rate_limit_hit();
                        }
                        crate::metrics::record_attack_type("RateLimit");

                        let threat_level = self
                            .threat_level
                            .as_ref()
                            .map(|tl| tl.get_level().as_u8())
                            .unwrap_or(1);

                        if let Some(decision) = self.maybe_escalate_and_block(
                            client_ip,
                            "rate_limit",
                            threat_level,
                            429,
                            "Too many rate limit violations - IP blocked",
                        ) {
                            return Some(decision);
                        }

                        let body = format!("Rate limit exceeded ({})", limit_type);
                        return Some(WafDecision::Block(429, body));
                    }
                    RateLimitResult::Blackholed => return Some(WafDecision::Drop),
                    RateLimitResult::Allowed => {}
                }
            }
        }

        None
    }

    fn check_ip_feed(&self, client_ip: IpAddr) -> Option<WafDecision> {
        if let Some(ref ip_feed) = self.ip_feed {
            if ip_feed.is_blocked(&client_ip) {
                tracing::info!("Blocking IP from feed: {}", client_ip);
                self.block_ip_with_threat_intel(client_ip, "ip_feed", 0, "global");
                return Some(WafDecision::Drop);
            }
        }
        None
    }

    fn check_endpoint_block(&self, path: &str, method: &str) -> Option<WafDecision> {
        if let EndpointCheckResult::Blocked {
            response_code,
            html,
            ..
        } = self.endpoint_blocker.check(path, method)
        {
            let html = html.unwrap_or_else(|| "Forbidden".to_string());
            return Some(WafDecision::Block(response_code, html));
        }
        None
    }

    fn record_suspicious_words(
        &self,
        client_ip: IpAddr,
        path: &str,
        query_string: Option<&str>,
        user_agent: Option<&str>,
    ) {
        if let Some(ref word_tracker) = self.suspicious_word_tracker {
            if let Some(record) =
                word_tracker.check_and_record(client_ip, path, query_string, user_agent)
            {
                tracing::debug!(
                    ip = %client_ip,
                    word = %record.matched_word,
                    endpoint = %record.endpoint,
                    "Suspicious word detected in request"
                );
            }
        }
    }

    fn check_honeypot(
        &self,
        client_ip: IpAddr,
        path: &str,
        method: &str,
        user_agent: Option<&str>,
    ) -> Option<WafDecision> {
        if let Some(matched) = self.sensitive_endpoint_manager.check(path) {
            tracing::info!(
                "Honeypot endpoint accessed: {} - matched: {}",
                path,
                matched
            );
            return self.handle_probe_event(client_ip, &matched, method, user_agent);
        }

        if self.challenge_manager.is_honeypot_hit(&client_ip, path) {
            tracing::info!("IP-bound honeypot accessed: {} by {}", path, client_ip);
            return self.handle_probe_event(client_ip, path, method, user_agent);
        }

        None
    }

    fn check_bot_protection(
        &self,
        _client_ip: IpAddr,
        path: &str,
        user_agent: Option<&str>,
    ) -> Option<WafDecision> {
        let bot_result = self.bot_detector.check(user_agent);

        if self.test_mode.enabled && self.test_mode.bot_off {
            return None;
        }

        match bot_result {
            BotDetectionResult::Blocked { reason, .. } => {
                tracing::info!("Blocking bot: {} - UA: {:?}", reason, user_agent);
                crate::metrics::record_attack_type("Bots");
                Some(WafDecision::Stall)
            }
            BotDetectionResult::Tarpit { reason, .. } => {
                tracing::info!("Tarpitting scraper: {} - UA: {:?}", reason, user_agent);
                Some(WafDecision::Tarpit(path.to_string()))
            }
            BotDetectionResult::Allowed { .. } => None,
        }
    }

    fn check_attack_patterns(
        &self,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        query_string: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> Option<WafDecision> {
        if let Some(ref attack_detector) = *self.attack_detector.read() {
            let method_enum = match method {
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

            if self.test_mode.enabled && self.test_mode.attack_off {
                return None;
            }

            if let Some(result) =
                attack_detector.check_request(&method_enum, path, query_string, headers, body)
            {
                metrics::counter!(
                    "maluwaf.attack_detected",
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

                return Some(WafDecision::Stall);
            }
        }
        None
    }

    fn check_challenge(&self, client_ip: IpAddr, path: &str) -> Option<WafDecision> {
        if (self.config.enable_pow_challenge || self.config.enable_css_honeypot)
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
                    let (html, session_id) =
                        self.challenge_manager.generate_challenge_page(&client_ip);
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
        if let Some(ref generator) = self.tarpit_generator {
            let mut rng = rand::rng();
            let max_depth = 10;
            let links_per_page = 50;

            generator.generate_html_page(
                rng.random_range(0..max_depth),
                max_depth,
                links_per_page,
                path,
            )
        } else {
            "<html><body>Please wait...</body></html>".to_string()
        }
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
