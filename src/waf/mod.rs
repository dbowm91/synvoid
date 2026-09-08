//! Root WAF application composition over the canonical `synvoid-waf` engine.
//!
//! Ownership: `synvoid-waf` owns reusable request-policy evaluation and detector
//! state (attack detection, bots, endpoints, flood, rate-limit sliding windows,
//! traffic buckets/`ConnectionLimiter`, probe/violation trackers, enforcement
//! adapters, narrow traits). This module owns construction/wiring of
//! runtime-specific services and compatibility adapters (`WafCore`/`AppWaf`).
//! See `architecture/waf_ownership_convergence.md`. Request-path code must
//! consume narrow traits (`WafProcessor`, `WafAccess`, `BlockListStore`),
//! never concrete composition types.
//!
//! Block-store enforcement lives in the worker admission boundary, not in WAF
//! mutation shims. Timed blocks go through `block_ip_with_provenance` with a
//! `BlockProvenanceKind` on the control-plane path.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use http::HeaderMap;
pub use synvoid_block_store::{BlockProvenance, BlockProvenanceKind};
use synvoid_core::enforcement::{
    EnforcementCandidate, EnforcementClass, EnforcementReason, EnforcementSource,
};
use synvoid_waf::enforcement::{
    attack_candidate, bot_candidate, endpoint_candidate, flood_candidate,
};

pub mod adapters;
pub mod asn_tracker;
pub mod attack_detection;
pub mod endpoints;
pub mod flood;
pub mod ip_feed;
pub use synvoid_waf::mitigation;
pub mod probe_tracker;
pub mod ratelimit;
pub mod rule_feed;
pub mod threat_intel;
pub mod threat_level;
pub mod traffic_shaper;
pub mod violation_tracker;

pub mod adapter;

// Re-exports from extracted synvoid-waf crate
pub use synvoid_waf::bot;
pub use synvoid_waf::request_sanitization;

pub use attack_detection::AttackDetectionConfig;
pub use probe_tracker::{
    ProbeConfig, ProbeTracker, SuspiciousWordTracker, UpstreamErrorResult, UpstreamErrorTracker,
};
pub use rule_feed::RuleFeedManagerForWaf;
pub use threat_level::{ThreatHistorySample, ThreatLevelManager};
pub use traffic_shaper::{ConnectionLimiter, ConnectionToken, GlobalTrafficShaper};
pub use violation_tracker::ViolationTracker;

use crate::config::defaults::{AsnScrapingConfig, BlockedDefaults, BotDefaults};
use crate::config::limits::RateLimitMemoryConfig;
use crate::config::traffic::{BandwidthConfig, TrafficShapingConfig};
pub use crate::config::{SuspiciousWordsConfig, UpstreamErrorsConfig};
use crate::geoip::GeoIpManager;
use crate::waf::asn_tracker::AsnTracker;
use crate::waf::attack_detection::AttackDetector;
use crate::waf::bot::{BotDetectionResult, BotDetector};
#[allow(unused_imports)]
use crate::waf::endpoints::{
    EndpointBlockerManager, EndpointCheckResult, ErrorPageManager, SensitiveEndpointManager,
};
use crate::waf::ip_feed::IpFeedManager;
pub use request_sanitization::RequestSanitizer;
use synvoid_auth::AuthManager;
use synvoid_challenge::{ChallengeConfig, ChallengeManager};

pub use flood::{FloodConfig, FloodDecision, FloodProtector};
pub use ratelimit::{RateLimitResult, RateLimiterManager};

#[cfg(feature = "mesh")]
// YaraRulesManager is actually in mesh module
pub use crate::mesh::yara_rules::YaraRulesManager;

pub use synvoid_waf::primitives::{TestModeConfig, WafConfig, WafDecision};

/// One staged policy outcome: the rendered directive plus its canonical
/// candidate for deterministic reduction.
///
/// The directive carries the response payload (status, HTML, cookies); the
/// candidate carries only the transport-neutral class, source, and bounded
/// reason. Reduction selects the winner; dispatch renders the winner's
/// directive.
struct StagedOutcome {
    decision: WafDecision,
    candidate: synvoid_core::enforcement::EnforcementCandidate,
}

impl StagedOutcome {
    fn new(
        decision: WafDecision,
        candidate: synvoid_core::enforcement::EnforcementCandidate,
    ) -> Self {
        Self {
            decision,
            candidate,
        }
    }
}

/// Fold a staged outcome into the running winner with the canonical reducer.
///
/// Allocation-free: the winner is always one of the inputs, so the common
/// allow path (all `None`) never touches the heap.
fn fold_outcome(best: Option<StagedOutcome>, next: Option<StagedOutcome>) -> Option<StagedOutcome> {
    match (best, next) {
        (None, next) => next,
        (best, None) => best,
        (Some(current), Some(candidate)) => {
            let winner = synvoid_core::enforcement::reduce(current.candidate, candidate.candidate);
            if winner == current.candidate {
                Some(current)
            } else {
                Some(candidate)
            }
        }
    }
}

/// Emit the terminal-outcome observability for the reduced winner.
///
/// Source/class/reason labels are frozen bounded codes from the canonical
/// contract — never IPs, URLs, user agents, or rule text. The allow path
/// emits nothing.
fn record_enforcement_outcome(candidate: &synvoid_core::enforcement::EnforcementCandidate) {
    metrics::counter!("synvoid_request_enforcement_source_total", "source" => candidate.source.as_str())
        .increment(1);
    metrics::counter!(
        "synvoid_request_enforcement_reason_total",
        "source" => candidate.source.as_str(),
        "class" => candidate.class.as_str(),
        "reason" => candidate.reason.as_str()
    )
    .increment(1);
}

pub struct RateLimitConfigStore {
    pub ip: crate::config::defaults::IpRateLimitConfig,
    pub global: crate::config::defaults::GlobalRateLimitConfig,
    pub cleanup_interval_secs: u64,
}

/// Composition constructor for [`WafCore`]/[`AppWaf`].
///
/// This is root-owned application wiring, not reusable domain configuration:
/// data-only WAF policy (`waf_config`, `attack_detection_config`, `test_mode`,
/// `whitelist`) plus an explicit dependency bundle of service configs and
/// handles (rate-limit/bot/endpoint/threat/feed/probe/traffic/ASN configs,
/// `auth_manager`, `geoip`, `data_dir`, `tarpit_defaults`). Reusable WAF logic
/// in `synvoid-waf` never touches this type (the crate does not import root).
/// Prefer data-only `synvoid_waf::primitives::{WafConfig, TestModeConfig}` for
/// domain needs. See `architecture/waf_ownership_convergence.md`.
pub struct WafCoreConfig {
    pub rate_config: RateLimitConfigStore,
    pub memory_config: RateLimitMemoryConfig,
    pub bot_config: BotDefaults,
    pub endpoint_config: BlockedDefaults,
    pub waf_config: WafConfig,
    pub whitelist: Vec<String>,
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

/// Root-owned WAF application composition over the canonical `synvoid-waf`
/// domain engine.
///
/// After Phase 19 this type is deliberately composition, not the canonical
/// policy engine: reusable detector/policy state lives in `synvoid-waf` (bot,
/// endpoints, attack detection, flood, sliding windows, traffic buckets,
/// probe/violation trackers, enforcement adapters); this struct wires those
/// together with runtime services (rate-limiter manager, challenge/auth
/// managers, threat-level, feeds, GeoIP, tarpit, traffic shaper, ASN tracker,
/// upload validator, `RequestServices`). Field classification lives in
/// `architecture/waf_ownership_convergence.md`. Request-path code must consume
/// narrow traits (`WafProcessor`, `WafAccess`), never this concrete type.
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
    pub config: WafConfig,
    pub whitelist: Arc<HashSet<IpAddr>>,
    _tarpit_generator: Arc<crate::tarpit::MarkovChain>,
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

/// Root composition alias: `WafCore` is application wiring over `synvoid-waf`.
/// Prefer narrow traits (`WafProcessor`, `WafAccess`) at request-path call
/// sites; use this alias where the composition type itself must be named.
pub type AppWaf = WafCore;
/// Composition-constructor alias for [`WafCoreConfig`].
pub type AppWafConfig = WafCoreConfig;

impl synvoid_proxy::protocol::trait_def::WafCoreBackend for WafCore {}

#[async_trait]
impl synvoid_http::Http3RequestWaf for WafCore {
    async fn check_request_full(
        &self,
        site_id: Option<&str>,
        ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        ua: Option<&str>,
        ja4_hash: Option<&str>,
        site_bot_config: Option<&synvoid_config::site::SiteBotConfig>,
    ) -> synvoid_proxy::WafDecision {
        WafCore::check_request_full(
            self,
            site_id,
            ip,
            method,
            path,
            query,
            headers,
            body,
            ua,
            ja4_hash,
            site_bot_config,
            None,
        )
        .await
    }

    fn generate_tarpit_response(&self, path: &str) -> String {
        WafCore::generate_tarpit_response(self, path)
    }
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
        // M-06: Trust tokens are always 64 hex chars (32-byte HMAC hex). The
        // previous dummy-allocation path added a distinct timing branch for
        // length mismatches. `ct_eq` on slices of different length returns 0
        // without an allocation; the length (64) is public and fixed, so a
        // single constant-time compare is sufficient.
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

        let asn_tracker_instance = asn_scraping_config
            .as_ref()
            .map(|config| Arc::new(AsnTracker::new(config.clone(), geoip.clone())));

        let endpoint_blocker = EndpointBlockerManager::new(
            endpoint_config.paths.clone(),
            endpoint_config.use_regex,
            endpoint_config.block_methods.clone(),
            endpoint_config.block_response_code,
            None, // block_page_html missing in defaults
        );

        let sensitive_endpoint_manager =
            SensitiveEndpointManager::from_file("honeypot_endpoints.txt"); // dummy path
        let error_page_manager = ErrorPageManager::new("error_pages", None, true);
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
            challenge_priority: synvoid_challenge::ChallengePriority::default(),
            mesh_pow_enabled: false,
            mesh_pow_key_exchange_enabled: false,
            mesh_pow_auditing_enabled: false,
            mesh_id: None,
            mesh_global_node_url: None,
            mesh_audit_urls: Vec::new(),
        });

        let tarpit_defaults = tarpit_defaults.unwrap_or_default();
        let tarpit_generator = Arc::new(crate::tarpit::MarkovChain::new());

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
                3,    // max_failed_attempts
                300,  // lockout_duration_secs
            ))
        });

        let mut trust_token_key = [0u8; 32];
        // M-04: Use OsRng (getrandom) for bearer-secret seeding. `rand::fill`
        // uses the thread-local ChaCha12 RNG (seeded via getrandom) — practically
        // OK, but security audit expects an explicit OsRng contract for 32-byte
        // bearer secrets.
        {
            use rand::{RngCore, TryRngCore};
            if let Err(e) = rand::rngs::OsRng.try_fill_bytes(&mut trust_token_key) {
                tracing::error!(error = %e, "OsRng failed seeding trust-token key; falling back to thread RNG");
                rand::rng().fill_bytes(&mut trust_token_key);
            }
        }

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
            config: waf_config,
            whitelist: Arc::new(whitelist_set),
            _tarpit_generator: tarpit_generator,
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

    /// Full request enforcement pipeline.
    ///
    /// Policy is produced in explicit stages and composed with the canonical
    /// reducer (`synvoid_core::enforcement`), so precedence is data + tests
    /// rather than incidental call order. See
    /// `architecture/enforcement_decision_contract.md`.
    ///
    /// Stages:
    ///
    /// 1. cheap local policy checks (rate limit, endpoint policy). Block-store
    ///    admission is checked at the worker composition root before this
    ///    pipeline runs, never here.
    /// 2. challenge/bot/rate/flood candidates (honeypot, bot, flood).
    /// 3. expensive attack/body inspection — skipped when stages 1–2 already
    ///    selected `Drop` or `Block`, which attack inspection (Block-class
    ///    only) cannot outrank. Documented resource-protection short-circuit:
    ///    the interim winner's provenance is retained.
    /// 4. deterministic reduction of all claimed candidates.
    /// 5. response rendering/dispatch from the winner's directive at the HTTP
    ///    dispatch layer.
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
        let mut best: Option<StagedOutcome> = None;

        // Stage 1: cheap local policy checks.
        best = fold_outcome(best, self.check_rate_limits(ip, site_id).await);
        best = fold_outcome(best, self.check_endpoint_block(path, method));

        // Stage 2: challenge/bot/rate/flood candidates.
        best = fold_outcome(best, self.check_honeypot(ip, path, method, ua));
        best = fold_outcome(
            best,
            self.check_bot_protection(ip, path, ua, ja4_hash, site_bot_config),
        );
        best = fold_outcome(best, self.check_flood(ip));

        // Stage 3: expensive attack inspection (skipped on interim Drop/Block).
        let interim_is_denied = matches!(
            best,
            Some(ref outcome)
                if matches!(
                    outcome.candidate.class,
                    synvoid_core::enforcement::EnforcementClass::Drop
                        | synvoid_core::enforcement::EnforcementClass::Block
                )
        );
        if !interim_is_denied {
            best = fold_outcome(
                best,
                self.check_attack(ip, method, path, query, headers, body)
                    .await,
            );
        }

        // Stage 5: deterministic reduction already folded above; observe.
        // Stage 6 (rendering) happens at the dispatch layer.
        match best {
            None => WafDecision::Pass,
            Some(outcome) => {
                record_enforcement_outcome(&outcome.candidate);
                outcome.decision
            }
        }
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

    async fn check_rate_limits(&self, ip: IpAddr, site_id: Option<&str>) -> Option<StagedOutcome> {
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

                let candidate = EnforcementCandidate::new(
                    EnforcementClass::Block,
                    EnforcementSource::RateLimit,
                    EnforcementReason::RateLimited,
                );

                if threat_level >= 2 {
                    if let Some(decision) = self.maybe_escalate_and_block(
                        ip,
                        "rate_limit",
                        threat_level,
                        429,
                        "Too Many Requests",
                    ) {
                        return Some(StagedOutcome::new(decision, candidate));
                    }
                }

                Some(StagedOutcome::new(
                    WafDecision::Block(429, "Too Many Requests".to_string()),
                    candidate,
                ))
            }
            RateLimitResult::Blackholed => Some(StagedOutcome::new(
                WafDecision::Drop,
                EnforcementCandidate::new(
                    EnforcementClass::Drop,
                    EnforcementSource::RateLimit,
                    EnforcementReason::RateLimited,
                ),
            )),
        }
    }

    fn check_endpoint_block(&self, path: &str, method: &str) -> Option<StagedOutcome> {
        let result = self.endpoint_blocker.check(path, method);
        let candidate = endpoint_candidate(&result)?;
        match result {
            EndpointCheckResult::Allowed => None,
            EndpointCheckResult::Blocked {
                response_code,
                html,
                ..
            } => Some(StagedOutcome::new(
                WafDecision::Block(response_code, html.unwrap_or_default()),
                candidate,
            )),
        }
    }

    /// Stage 2 flood candidate. The candidate mapping is single-sourced from
    /// `synvoid_waf::enforcement::flood_candidate`; rendering preserves the
    /// historical 429/`Drop` outcomes.
    fn check_flood(&self, ip: IpAddr) -> Option<StagedOutcome> {
        let protector = self.flood_protector.as_ref()?;
        let flood = protector.check_tcp_connection(ip);
        let candidate = flood_candidate(flood)?;
        let decision = match flood {
            FloodDecision::Allowed => return None,
            FloodDecision::RateLimited => WafDecision::Block(429, "Rate Limited".to_string()),
            FloodDecision::Blackholed => WafDecision::Drop,
        };
        Some(StagedOutcome::new(decision, candidate))
    }

    /// Stage 3 expensive attack inspection. Produces Block-class claims only.
    async fn check_attack(
        &self,
        ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> Option<StagedOutcome> {
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

                return Some(StagedOutcome::new(
                    WafDecision::Block(403, "Attack Detected".to_string()),
                    attack_candidate(&res),
                ));
            }
        }
        None
    }

    fn check_honeypot(
        &self,
        ip: IpAddr,
        path: &str,
        _method: &str,
        user_agent: Option<&str>,
    ) -> Option<StagedOutcome> {
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
                return Some(StagedOutcome::new(
                    decision,
                    EnforcementCandidate::new(
                        EnforcementClass::Block,
                        EnforcementSource::Honeypot,
                        EnforcementReason::HoneypotHit,
                    ),
                ));
            }

            return Some(StagedOutcome::new(
                WafDecision::Stall,
                EnforcementCandidate::new(
                    EnforcementClass::Stall,
                    EnforcementSource::Honeypot,
                    EnforcementReason::HoneypotHit,
                ),
            ));
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
    ) -> Option<StagedOutcome> {
        let block_ai = site_bot_config.and_then(|c| c.block_ai_crawlers);

        // Use full fingerprinting check (JA3 is None here, JA4 is passed)
        let bot_result = self
            .bot_detector
            .check_with_fingerprints(user_agent, block_ai, None, ja4_hash);

        // Canonical candidate is single-sourced from the detector mapping.
        let candidate = bot_candidate(&bot_result);

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
                Some(StagedOutcome::new(
                    WafDecision::Block(403, "Forbidden".to_string()),
                    candidate.expect("blocked bot must yield a candidate"),
                ))
            }
            BotDetectionResult::Tarpit { reason, .. } => {
                tracing::info!(
                    "Tarpitting scraper from {}: {} - UA: {:?}, JA4: {:?}",
                    client_ip,
                    reason,
                    user_agent,
                    ja4_hash
                );
                Some(StagedOutcome::new(
                    WafDecision::Tarpit(path.to_string()),
                    candidate.expect("tarpitted scraper must yield a candidate"),
                ))
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
                    let candidate = EnforcementCandidate::new(
                        EnforcementClass::Challenge,
                        EnforcementSource::BotPolicy,
                        EnforcementReason::ChallengeRequired,
                    );
                    if let Some(sid) = session_id {
                        return Some(StagedOutcome::new(
                            WafDecision::ChallengeWithCookie {
                                challenge_type: self.challenge_manager.get_challenge_type(),
                                html,
                                session_cookie_name: self
                                    .challenge_manager
                                    .css_session_cookie_name(),
                                session_cookie_value: sid,
                                session_cookie_max_age: self.challenge_manager.css_window_secs(),
                            },
                            candidate,
                        ));
                    } else {
                        return Some(StagedOutcome::new(
                            WafDecision::Challenge(
                                self.challenge_manager.get_challenge_type(),
                                html,
                            ),
                            candidate,
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
            .map(|outcome| outcome.decision)
    }

    pub fn streaming(&self) -> Option<crate::waf::attack_detection::StreamingWafCore> {
        self.attack_detector
            .load()
            .as_ref()
            .map(|ad| ad.clone().streaming())
    }

    pub fn set_flood_protector(&mut self, protector: Arc<FloodProtector>) {
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

    /// Deprecated no-op placeholder (Phase 19): suspicious-word recording is not
    /// wired in this composition. No production call site may rely on it.
    pub fn record_suspicious_words(
        &self,
        _ip: IpAddr,
        _path: &str,
        _query: Option<&str>,
        _ua: Option<&str>,
    ) {
        // Placeholder
    }

    /// Deprecated no-op placeholder (Phase 19): WAF composition owns no
    /// background tasks. No production call site may rely on it.
    pub fn start_background_tasks(&self) {
        // Placeholder
    }

    pub fn get_upload_validator(&self) -> Option<Arc<synvoid_upload::UploadValidator>> {
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
            redirect_policy: synvoid_tarpit::config::RedirectPolicy::RelativeOnly,
            admission: synvoid_tarpit::config::AdmissionConfig {
                max_concurrent: self.tarpit_defaults.max_concurrent_sessions,
                max_per_ip: self.tarpit_defaults.max_sessions_per_ip,
            },
            budget: synvoid_tarpit::config::BudgetConfig {
                max_duration_secs: self.tarpit_defaults.max_duration_secs,
                max_chunks: self.tarpit_defaults.max_chunks,
                max_bytes: self.tarpit_defaults.max_bytes,
                max_idle_secs: self.tarpit_defaults.max_idle_secs,
                write_timeout_ms: self.tarpit_defaults.write_timeout_ms,
            },
            fingerprint: synvoid_tarpit::config::FingerprintConfig {
                min_chunk_delay_ms: self.tarpit_defaults.min_chunk_delay_ms,
                max_chunk_delay_ms: self.tarpit_defaults.max_chunk_delay_ms,
                vary_content_type: true,
                vary_status_code: true,
            },
        };
        let handler = crate::tarpit::TarpitHandler::new(tarpit_config);
        handler.stream_request(path, user_agent)
    }

    pub fn check_request_body(&self, _chunk: &[u8]) -> (bool, Option<WafDecision>) {
        (false, None)
    }

    /// Deprecated no-op placeholder (Phase 19): attack-detector reloads go
    /// through the rule-feed/control-plane path. Always returns `Ok`.
    pub fn reload_attack_detector(&self) -> Result<(), String> {
        // Placeholder
        Ok(())
    }

    /// Deprecated no-op placeholder (Phase 19): request services are threaded
    /// through dispatch call sites instead. No production call site may rely
    /// on it.
    pub fn set_request_services(&self, _services: Arc<RequestServices>) {
        // Placeholder
    }
}

impl synvoid_http::request_parse::EarlyWafHooks for WafCore {
    fn verify_trust_token(&self, client_ip: IpAddr, token: &str) -> bool {
        WafCore::verify_trust_token(self, client_ip, token)
    }
}

impl synvoid_http::ChallengePathWaf for WafCore {
    fn generate_challenge_page(
        &self,
        ip: &IpAddr,
        app_path: Option<&str>,
    ) -> (String, Option<String>) {
        self.challenge_manager.generate_challenge_page(ip, app_path)
    }

    fn css_enabled(&self) -> bool {
        self.challenge_manager.css_enabled()
    }

    fn css_session_cookie_name(&self) -> String {
        self.challenge_manager.css_session_cookie_name()
    }

    fn record_css_asset_request(
        &self,
        session_id: &str,
        asset_name: &str,
    ) -> (
        synvoid_challenge::css::AssetRequestResult,
        synvoid_challenge::css::CssAssetAction,
    ) {
        self.challenge_manager
            .record_css_asset_request(session_id, asset_name)
    }

    fn css_verified_cookie_name(&self) -> String {
        self.challenge_manager.css_verified_cookie_name()
    }

    fn css_window_secs(&self) -> u64 {
        self.challenge_manager.css_window_secs()
    }
}

impl synvoid_http::UploadValidationWaf for WafCore {
    fn get_upload_validator(&self) -> Option<Arc<synvoid_upload::UploadValidator>> {
        WafCore::get_upload_validator(self)
    }

    fn render_upload_validation_error_page(
        &self,
        status_code: u16,
        message: Option<&str>,
    ) -> String {
        self.error_page_manager.render_page(status_code, message)
    }
}

impl synvoid_http::RequestBodyWaf for WafCore {
    fn streaming(&self) -> Option<Box<dyn synvoid_http::shared_handler::StreamingWafScanner>> {
        WafCore::streaming(self)
            .map(|s| Box::new(s) as Box<dyn synvoid_http::shared_handler::StreamingWafScanner>)
    }

    fn check_request_body(&self, chunk: &[u8]) -> (bool, Option<synvoid_waf::WafDecision>) {
        WafCore::check_request_body(self, chunk)
    }
}

impl synvoid_http::WafErrorPageRenderer for WafCore {
    fn render_page(&self, status: u16, message: Option<&str>) -> String {
        self.error_page_manager.render_page(status, message)
    }
}

#[async_trait]
impl synvoid_http::BufferedRequestWaf for WafCore {
    fn error_page_theme(&self) -> &crate::theme::ThemeConfig {
        self.error_page_manager.theme()
    }

    fn render_page_with_theme(
        &self,
        status: u16,
        message: Option<&str>,
        override_theme: Option<&crate::theme::ThemeConfig>,
    ) -> String {
        self.error_page_manager
            .render_page_with_theme(status, message, override_theme)
    }

    fn connection_limiter(&self) -> Option<Arc<ConnectionLimiter>> {
        self.connection_limiter.clone()
    }

    fn is_over_bandwidth_limit(&self) -> bool {
        WafCore::is_over_bandwidth_limit(self)
    }

    fn honeypot_ban_duration_secs(&self) -> u64 {
        self.honeypot_ban_duration_secs
    }

    fn stream_tarpit(&self, path: &str, user_agent: Option<&str>) -> synvoid_http::TarpitStream {
        Box::pin(WafCore::stream_tarpit(self, path, user_agent))
    }

    fn generate_tarpit_response(&self, path: &str) -> String {
        WafCore::generate_tarpit_response(self, path)
    }

    async fn check_request_full(
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
    ) -> synvoid_waf::WafDecision {
        WafCore::check_request_full(
            self,
            site_id,
            ip,
            method,
            path,
            query,
            headers,
            body,
            ua,
            ja4_hash,
            site_bot_config,
            None,
        )
        .await
    }

    async fn check_request_full_owned(
        self: Arc<Self>,
        site_id: Option<String>,
        ip: IpAddr,
        method: String,
        path: String,
        query: Option<String>,
        headers: http::HeaderMap,
        body: Option<bytes::Bytes>,
        ua: Option<String>,
        ja4_hash: Option<String>,
        site_bot_config: Option<crate::config::site::SiteBotConfig>,
    ) -> synvoid_waf::WafDecision {
        WafCore::check_request_full(
            &self,
            site_id.as_deref(),
            ip,
            &method,
            &path,
            query.as_deref(),
            &headers,
            body.as_deref(),
            ua.as_deref(),
            ja4_hash.as_deref(),
            site_bot_config.as_ref(),
            None,
        )
        .await
    }
}

impl synvoid_waf::access::WafAccess for WafCore {
    fn connection_limiter(&self) -> Option<Arc<ConnectionLimiter>> {
        self.connection_limiter.clone()
    }

    fn is_over_bandwidth_limit(&self) -> bool {
        WafCore::is_over_bandwidth_limit(self)
    }

    fn streaming(&self) -> Option<Box<dyn synvoid_core::streaming_waf::StreamingWafScanner>> {
        WafCore::streaming(self)
            .map(|s| Box::new(s) as Box<dyn synvoid_core::streaming_waf::StreamingWafScanner>)
    }
}

pub static UPLOAD_VALIDATOR: std::sync::OnceLock<Arc<synvoid_upload::UploadValidator>> =
    std::sync::OnceLock::new();

pub fn get_upload_validator() -> Option<Arc<synvoid_upload::UploadValidator>> {
    UPLOAD_VALIDATOR.get().cloned()
}

pub fn set_upload_validator(validator: Arc<synvoid_upload::UploadValidator>) {
    if UPLOAD_VALIDATOR.set(validator).is_err() {
        tracing::warn!("set_upload_validator ignored: validator already initialized");
    }
}

#[cfg(feature = "mesh")]
pub fn set_threat_intel(_intel: Arc<dyn crate::worker::context::ThreatIntelLookup>) {
    // Relegated to Control Plane (Supervisor)
}

#[cfg(not(feature = "mesh"))]
pub fn set_threat_intel(_intel: Arc<()>) {
    // Relegated to Control Plane (Supervisor)
}

#[cfg(feature = "mesh")]
pub fn set_yara_rules(_rules: Arc<crate::mesh::YaraRulesManager>) {
    // Relegated to Control Plane (Supervisor)
}

#[cfg(not(feature = "mesh"))]
pub fn set_yara_rules(_rules: Arc<()>) {
    // Relegated to Control Plane (Supervisor)
}

#[cfg(feature = "mesh")]
pub fn get_yara_rules() -> Option<Arc<crate::mesh::YaraRulesManager>> {
    None
}

#[cfg(not(feature = "mesh"))]
pub fn get_yara_rules() -> Option<Arc<()>> {
    None
}

#[cfg(test)]
mod enforcement_pipeline_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::config::defaults::{GlobalRateLimitConfig, IpRateLimitConfig};
    use crate::config::limits::RateLimitMemoryConfig;
    use crate::config::traffic::BandwidthConfig;

    const NORMAL_UA: &str =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    fn test_waf_core(ip_rate: IpRateLimitConfig) -> WafCore {
        WafCore::new(WafCoreConfig {
            rate_config: RateLimitConfigStore {
                ip: ip_rate,
                global: GlobalRateLimitConfig {
                    per_second: 10_000,
                    per_minute: 100_000,
                    per_5min: 500_000,
                    max_connections: 10_000,
                },
                cleanup_interval_secs: 0,
            },
            memory_config: RateLimitMemoryConfig::default(),
            bot_config: BotDefaults::default(),
            endpoint_config: BlockedDefaults::default(),
            waf_config: WafConfig::new(
                false,
                false,
                false,
                "/login".to_string(),
                false,
                false,
                TestModeConfig::default(),
                3600,
            ),
            whitelist: Vec::new(),
            attack_detection_config: Some(AttackDetectionConfig::default()),
            auth_manager: None,
            threat_level_config: None,
            ip_feed_config: None,
            probe_config: None,
            suspicious_words_config: None,
            upstream_errors_config: None,
            traffic_shaping_config: None,
            bandwidth_config: BandwidthConfig::default(),
            asn_scraping_config: None,
            geoip: None,
            data_dir: Some(std::env::temp_dir().join("synvoid-enforcement-pipeline-test")),
            test_mode: TestModeConfig::default(),
            tarpit_defaults: None,
        })
    }

    fn permissive_ip_rate() -> IpRateLimitConfig {
        IpRateLimitConfig {
            per_second: 10_000,
            per_minute: 100_000,
            per_5min: 500_000,
            per_10min: 1_000_000,
            per_hour: 5_000_000,
            per_day: 10_000_000,
            burst: 1_000,
        }
    }

    fn headers() -> http::HeaderMap {
        http::HeaderMap::new()
    }

    #[test]
    fn fold_outcome_allow_never_erases_terminal() {
        use synvoid_core::enforcement as e;
        let terminal = StagedOutcome::new(
            WafDecision::Block(429, "limited".to_string()),
            e::EnforcementCandidate::new(
                e::EnforcementClass::Block,
                e::EnforcementSource::RateLimit,
                e::EnforcementReason::RateLimited,
            ),
        );
        // StagedOutcome is not Clone; rebuild the allow-side as None (no
        // claim), which is how the pipeline represents allow.
        let won = fold_outcome(Some(terminal), None).expect("terminal must survive");
        assert!(matches!(won.decision, WafDecision::Block(429, _)));
        assert_eq!(won.candidate.class, e::EnforcementClass::Block);
    }

    #[test]
    fn fold_outcome_higher_precedence_wins_in_either_order() {
        use synvoid_core::enforcement as e;
        let mk = |class| {
            StagedOutcome::new(
                WafDecision::Stall,
                e::EnforcementCandidate::new(
                    class,
                    e::EnforcementSource::Honeypot,
                    e::EnforcementReason::HoneypotHit,
                ),
            )
        };
        // Stall vs Block: Block must win regardless of fold order. Rebuild
        // (StagedOutcome is not Clone) for the reversed fold.
        let fwd = fold_outcome(
            Some(mk(e::EnforcementClass::Stall)),
            Some(mk(e::EnforcementClass::Block)),
        );
        assert_eq!(
            fwd.expect("claim").candidate.class,
            e::EnforcementClass::Block
        );
        let rev = fold_outcome(
            Some(mk(e::EnforcementClass::Block)),
            Some(mk(e::EnforcementClass::Stall)),
        );
        assert_eq!(
            rev.expect("claim").candidate.class,
            e::EnforcementClass::Block
        );
    }

    #[tokio::test]
    async fn flood_drop_outranks_rate_limit_block() {
        // B1: rate-limit Block (429) and flood-blackhole Drop claimed
        // together must reduce to Drop. Legacy call order returned the rate
        // block because it ran first.
        let core = test_waf_core(IpRateLimitConfig {
            per_second: 1,
            per_minute: 10,
            per_5min: 50,
            per_10min: 100,
            per_hour: 500,
            per_day: 1000,
            burst: 0,
        });
        let mut core = core;
        let protector = Arc::new(FloodProtector::new(
            crate::waf::flood::FloodConfig::default(),
        ));
        core.set_flood_protector(protector.clone());

        // First request: rate limiter allows (primes the per-second window).
        let first = core
            .check_request_full(
                None,
                TEST_IP,
                "GET",
                "/",
                None,
                &headers(),
                None,
                Some(NORMAL_UA),
                None,
                None,
                None,
            )
            .await;
        assert!(matches!(first, WafDecision::Pass));

        // Enter flood blackhole: the next request is both rate-limited and
        // flood-blackholed.
        protector.enter_blackhole();
        let second = core
            .check_request_full(
                None,
                TEST_IP,
                "GET",
                "/",
                None,
                &headers(),
                None,
                Some(NORMAL_UA),
                None,
                None,
                None,
            )
            .await;
        assert!(
            matches!(second, WafDecision::Drop),
            "flood Drop must outrank rate-limit Block, got {second:?}"
        );
    }

    #[tokio::test]
    async fn attack_block_outranks_honeypot_stall() {
        // B2: a honeypot hit (Stall) carrying an attack payload (Block) must
        // reduce to Block. Legacy call order returned Stall because the
        // honeypot check ran before attack detection.
        let mut core = test_waf_core(permissive_ip_rate());
        core.sensitive_endpoint_manager =
            SensitiveEndpointManager::new(vec!["/secret-honeypot".to_string()]);

        let decision = core
            .check_request_full(
                None,
                TEST_IP,
                "GET",
                "/secret-honeypot",
                Some("id=1' OR '1'='1"),
                &headers(),
                None,
                Some(NORMAL_UA),
                None,
                None,
                None,
            )
            .await;
        assert!(
            matches!(decision, WafDecision::Block(403, _)),
            "attack Block must outrank honeypot Stall, got {decision:?}"
        );
    }

    #[tokio::test]
    async fn blocked_endpoint_with_attack_payload_keeps_endpoint_block() {
        // Preserved behavior + documented stage-4 skip: an endpoint Block
        // decided in stages 1–3 is final; expensive attack inspection is
        // skipped and the endpoint directive (not "Attack Detected") renders.
        let core = test_waf_core(permissive_ip_rate());
        let decision = core
            .check_request_full(
                None,
                TEST_IP,
                "GET",
                "/.env",
                Some("id=1' OR '1'='1"),
                &headers(),
                None,
                Some(NORMAL_UA),
                None,
                None,
                None,
            )
            .await;
        match decision {
            WafDecision::Block(403, ref msg) => {
                assert_ne!(
                    msg, "Attack Detected",
                    "endpoint directive must render, attack stage skipped"
                );
            }
            other => panic!("expected endpoint 403 block, got {other:?}"),
        }
    }
}
