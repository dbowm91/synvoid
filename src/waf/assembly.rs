//! Phase 04: internal assembly stages for `WafCore::new()`.
//!
//! `WafCore` remains root application composition over the canonical
//! `synvoid-waf` engine. Each `assemble_*` helper builds one coherent service
//! group and returns a narrow bundle. The top-level constructor in `mod.rs`
//! only orchestrates these stages in dependency order. No domain logic moves
//! into `synvoid-waf`; no application services move out.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::defaults::{AsnScrapingConfig, BlockedDefaults, BotDefaults};
use crate::config::limits::RateLimitMemoryConfig;
use crate::config::traffic::{BandwidthConfig, TrafficShapingConfig};
use crate::config::{SuspiciousWordsConfig, UpstreamErrorsConfig};
use crate::geoip::GeoIpManager;
use crate::waf::asn_tracker::AsnTracker;
use crate::waf::attack_detection::{AttackDetectionConfig, AttackDetector};
use crate::waf::bot::BotDetector;
use crate::waf::endpoints::{EndpointBlockerManager, ErrorPageManager, SensitiveEndpointManager};
use crate::waf::ip_feed::IpFeedManager;
use crate::waf::probe_tracker::{ProbeTracker, SuspiciousWordTracker, UpstreamErrorTracker};
use crate::waf::threat_level::ThreatLevelManager;
use crate::waf::traffic_shaper::{ConnectionLimiter, GlobalTrafficShaper};
use crate::waf::violation_tracker::ViolationTracker;
use crate::waf::{RateLimitConfigStore, RateLimiterManager};
use synvoid_auth::AuthManager;
use synvoid_challenge::{ChallengeConfig, ChallengeManager};

/// Detector/policy setup: bot detector + endpoint managers + attack detector.
pub(crate) struct DetectorBundle {
    pub bot_detector: BotDetector,
    pub endpoint_blocker: EndpointBlockerManager,
    pub sensitive_endpoint_manager: SensitiveEndpointManager,
    pub error_page_manager: ErrorPageManager,
    pub challenge_manager: ChallengeManager,
    pub attack_detector: Option<Arc<AttackDetector>>,
}

/// Runtime trackers: threat-level + violation escalation.
pub(crate) struct ThreatBundle {
    pub threat_level: Option<Arc<ThreatLevelManager>>,
    pub violation_tracker: Option<Arc<ViolationTracker>>,
}

/// Threat/rule-feed integration: IP feed + probe/suspicious/upstream trackers.
pub(crate) struct FeedTrackerBundle {
    pub ip_feed: Option<Arc<IpFeedManager>>,
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
}

/// Rate/traffic controls: shaper + connection limiter.
pub(crate) struct TrafficBundle {
    pub traffic_shaper: Option<Arc<GlobalTrafficShaper>>,
    pub connection_limiter: Option<Arc<ConnectionLimiter>>,
    pub asn_tracker: Option<Arc<AsnTracker>>,
}

pub(crate) fn assemble_rate_limiter(
    rate_config: RateLimitConfigStore,
    memory_config: RateLimitMemoryConfig,
) -> RateLimiterManager {
    RateLimiterManager::new(
        rate_config.ip,
        rate_config.global,
        rate_config.cleanup_interval_secs,
        memory_config,
    )
}

pub(crate) fn assemble_threat_services(
    threat_level_config: &Option<crate::config::ThreatLevelConfig>,
    data_dir: &Option<PathBuf>,
) -> ThreatBundle {
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

    ThreatBundle {
        threat_level,
        violation_tracker,
    }
}

pub(crate) fn assemble_feed_trackers(
    ip_feed_config: Option<crate::config::IpFeedConfig>,
    probe_config: Option<crate::config::HoneypotProbingDefaults>,
    suspicious_words_config: Option<SuspiciousWordsConfig>,
    upstream_errors_config: Option<UpstreamErrorsConfig>,
    data_dir: &Option<PathBuf>,
) -> FeedTrackerBundle {
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
            let probe_cfg = crate::waf::probe_tracker::ProbeConfig {
                enabled: config.enabled,
                max_endpoints_per_window: config.max_endpoints_per_window,
                window_secs: config.window_secs,
                retention_days: config.retention_days,
                max_records: config.max_records,
                auto_ban_elevated_threat: config.auto_ban_elevated_threat,
                elevated_threat_threshold: config.elevated_threat_threshold,
                elevated_ban_duration: config.elevated_ban_duration,
            };
            Some(ProbeTracker::new(probe_cfg, data_dir.clone()))
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

    FeedTrackerBundle {
        ip_feed,
        probe_tracker,
        suspicious_word_tracker,
        upstream_error_tracker,
    }
}

pub(crate) fn assemble_traffic_controls(
    traffic_shaping_config: &Option<TrafficShapingConfig>,
    bandwidth_config: &BandwidthConfig,
    asn_scraping_config: &Option<AsnScrapingConfig>,
    geoip: &Option<Arc<GeoIpManager>>,
) -> TrafficBundle {
    let traffic_shaper = traffic_shaping_config.as_ref().map(|config| {
        Arc::new(GlobalTrafficShaper::new(
            config.global.clone(),
            bandwidth_config.clone(),
        ))
    });

    let connection_limiter = traffic_shaping_config
        .as_ref()
        .map(|config| ConnectionLimiter::new(config.connection_limits.clone()));

    let asn_tracker = asn_scraping_config
        .as_ref()
        .map(|config| Arc::new(AsnTracker::new(config.clone(), geoip.clone())));

    TrafficBundle {
        traffic_shaper,
        connection_limiter,
        asn_tracker,
    }
}

pub(crate) fn assemble_detectors(
    bot_config: &BotDefaults,
    endpoint_config: &BlockedDefaults,
    attack_detection_config: Option<AttackDetectionConfig>,
) -> DetectorBundle {
    let bot_detector = BotDetector::new(
        bot_config.known_bots_allow.clone(),
        bot_config.ai_crawlers_block.clone(),
        bot_config.scraper_patterns.clone(),
        bot_config.block_ai_crawlers,
    );

    let endpoint_blocker = EndpointBlockerManager::new(
        endpoint_config.paths.clone(),
        endpoint_config.use_regex,
        endpoint_config.block_methods.clone(),
        endpoint_config.block_response_code,
        None,
    );

    let sensitive_endpoint_manager = SensitiveEndpointManager::from_file("honeypot_endpoints.txt");
    let error_page_manager = ErrorPageManager::new("error_pages", None, true);
    let challenge_manager = ChallengeManager::new(ChallengeConfig {
        cookie_name: bot_config.challenge_cookie_name.clone(),
        pow_enabled: false,
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
        challenge_priority: synvoid_challenge::ChallengePriority::default(),
        mesh_pow_enabled: false,
        mesh_pow_key_exchange_enabled: false,
        mesh_pow_auditing_enabled: false,
        mesh_id: None,
        mesh_global_node_url: None,
        mesh_audit_urls: Vec::new(),
    });

    let attack_detector =
        attack_detection_config.map(|config| Arc::new(AttackDetector::new(config)));

    DetectorBundle {
        bot_detector,
        endpoint_blocker,
        sensitive_endpoint_manager,
        error_page_manager,
        challenge_manager,
        attack_detector,
    }
}

pub(crate) fn assemble_whitelist(whitelist: Vec<String>) -> Arc<HashSet<IpAddr>> {
    let mut set = HashSet::new();
    for ip_str in whitelist {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            set.insert(ip);
        }
    }
    Arc::new(set)
}

pub(crate) fn assemble_auth_manager(
    auth_manager: Option<Arc<AuthManager>>,
    data_dir: &Option<PathBuf>,
) -> Arc<AuthManager> {
    auth_manager.unwrap_or_else(|| {
        Arc::new(AuthManager::new(
            data_dir.clone().unwrap_or_else(|| PathBuf::from("data")),
            3600,
            3,
            300,
        ))
    })
}

/// Generate the 32-byte trust-token HMAC key with an explicit OsRng contract
/// (M-04). Falls back to the thread RNG only if `getrandom` fails.
pub(crate) fn generate_trust_token_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    {
        use rand::{RngCore, TryRngCore};
        if let Err(e) = rand::rngs::OsRng.try_fill_bytes(&mut key) {
            tracing::error!(error = %e, "OsRng failed seeding trust-token key; falling back to thread RNG");
            rand::rng().fill_bytes(&mut key);
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::defaults::{BlockedDefaults, BotDefaults};
    use crate::config::limits::RateLimitMemoryConfig;

    fn empty_probe() -> Option<crate::config::HoneypotProbingDefaults> {
        None
    }

    #[test]
    fn disabled_threat_config_yields_no_services() {
        let bundle = assemble_threat_services(&None, &None);
        assert!(bundle.threat_level.is_none());
        assert!(bundle.violation_tracker.is_none());
    }

    #[test]
    fn enabled_threat_config_yields_threat_level() {
        let cfg = crate::config::ThreatLevelConfig::default();
        let bundle = assemble_threat_services(&Some(cfg), &None);
        assert!(bundle.threat_level.is_some());
        // Violation tracker presence follows escalation.enabled; assert the
        // coupling rather than a fixed expectation.
        let cfg2 = crate::config::ThreatLevelConfig::default();
        let expected_violation = cfg2.escalation.enabled;
        assert_eq!(bundle.violation_tracker.is_some(), expected_violation);
    }

    #[test]
    fn disabled_feeds_yield_no_trackers() {
        let bundle = assemble_feed_trackers(None, empty_probe(), None, None, &None);
        assert!(bundle.ip_feed.is_none());
        assert!(bundle.probe_tracker.is_none());
        assert!(bundle.suspicious_word_tracker.is_none());
        assert!(bundle.upstream_error_tracker.is_none());
    }

    #[test]
    fn disabled_traffic_config_yields_no_controls() {
        let bundle = assemble_traffic_controls(&None, &BandwidthConfig::default(), &None, &None);
        assert!(bundle.traffic_shaper.is_none());
        assert!(bundle.connection_limiter.is_none());
        assert!(bundle.asn_tracker.is_none());
    }

    #[test]
    fn whitelist_parses_valid_and_skips_invalid() {
        let set = assemble_whitelist(vec![
            "127.0.0.1".to_string(),
            "not-an-ip".to_string(),
            "::1".to_string(),
        ]);
        assert_eq!(set.len(), 2);
    }

    #[tokio::test]
    async fn auth_manager_default_builds_without_panic() {
        let mgr = assemble_auth_manager(None, &None);
        // Manager exists; no further assertion on internals.
        let _ = mgr;
    }

    #[test]
    fn trust_key_is_32_bytes() {
        let key = generate_trust_token_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn detectors_build_with_defaults() {
        let bundle = assemble_detectors(&BotDefaults::default(), &BlockedDefaults::default(), None);
        assert!(bundle.attack_detector.is_none());
        let _ = bundle.bot_detector;
    }

    #[test]
    fn detectors_with_attack_config_yield_detector() {
        let bundle = assemble_detectors(
            &BotDefaults::default(),
            &BlockedDefaults::default(),
            Some(AttackDetectionConfig::default()),
        );
        assert!(bundle.attack_detector.is_some());
    }

    #[test]
    fn rate_limiter_builds_with_memory_config() {
        let cfg = crate::config::MainConfig::default_config();
        let store = RateLimitConfigStore {
            ip: cfg.defaults.ratelimit.ip.clone(),
            global: cfg.defaults.ratelimit.global.clone(),
            cleanup_interval_secs: 0,
        };
        let _limiter = assemble_rate_limiter(store, RateLimitMemoryConfig::default());
    }
}
