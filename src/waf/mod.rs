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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use http::HeaderMap;
use lru_time_cache::LruCache;
use parking_lot::Mutex;
pub use synvoid_block_store::{BlockProvenance, BlockProvenanceKind};
use synvoid_core::enforcement::{
    EnforcementCandidate, EnforcementClass, EnforcementReason, EnforcementSource,
};
use synvoid_waf::enforcement::{
    attack_candidate, bot_candidate, endpoint_candidate, flood_candidate,
};

pub mod adapters;
pub mod asn_tracker;
pub mod assembly;
pub mod attack_detection;
pub mod endpoints;
pub mod flood;
pub mod ip_feed;
pub use synvoid_waf::mitigation;
pub mod probe_tracker;
pub mod ratelimit;
pub mod rule_feed;
pub mod site_attack_config;
pub mod threat_intel;
pub mod threat_level;
pub mod traffic_shaper;
pub mod violation_tracker;
#[cfg(feature = "mesh")]
pub mod yara_snapshot;

pub mod adapter;

// Re-exports from extracted synvoid-waf crate
pub use synvoid_waf::bot;
pub use synvoid_waf::request_sanitization;

pub use attack_detection::AttackDetectionConfig;
pub use attack_detection::AttackType;
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
use crate::waf::site_attack_config::{AttackAction, ResolvedAttackPolicy};
pub use request_sanitization::RequestSanitizer;
use synvoid_auth::AuthManager;
use synvoid_challenge::ChallengeManager;

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
    /// Global `[defaults.error_pages]` (directory/mode/enabled). Previously
    /// the manager hard-coded a relative `error_pages` dir and generic mode,
    /// so operator-configured template directories were never loaded.
    pub error_pages: crate::config::defaults::ErrorPagesDefaults,
    /// Initial global block-page theme, converted from `[defaults.theme]`.
    /// Served pages always read the live handle (see `ErrorPageManager`),
    /// so the admin `PUT /theme` takes effect without a restart.
    pub error_page_theme: crate::theme::ThemeConfig,
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
/// Upper bound on per-site detector variants. Each entry owns compiled
/// Aho-Corasick/regex structures, so this is a memory-budget boundary, not a
/// tuning knob. Least-recently-used variants are evicted.
const SITE_DETECTOR_CACHE_CAPACITY: usize = 64;

/// Historical scanner ceiling when no per-request body cap is supplied.
const DEFAULT_WAF_STREAMING_BODY_LIMIT: usize = 10 * 1024 * 1024;

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
    attack_config_generation: AtomicU64,
    site_detector_cache: Mutex<LruCache<u64, Arc<AttackDetector>>>,
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
impl synvoid_http3::Http3RequestWaf for WafCore {
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
        site_attack_config: Option<&synvoid_config::site::SiteAttackDetectionConfig>,
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
            site_attack_config,
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

    /// Phase 04 orchestration: `WafCore::new` wires narrow staged bundles in
    /// dependency order (rate limiter → threat → feeds → traffic → detectors
    /// → whitelist/auth/trust-key). Each stage lives in `assembly`; this
    /// constructor stays at one abstraction level and changes no behavior.
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
            error_pages,
            error_page_theme,
        } = config;

        // Stage 1: rate limiter (no dependencies).
        let rate_limiter = assembly::assemble_rate_limiter(rate_config, memory_config);

        // Stage 2: threat-level + violation escalation.
        let threat_bundle = assembly::assemble_threat_services(&threat_level_config, &data_dir);

        // Stage 3: threat/rule-feed integration trackers.
        let feed_bundle = assembly::assemble_feed_trackers(
            ip_feed_config,
            probe_config,
            suspicious_words_config,
            upstream_errors_config,
            &data_dir,
        );

        // Stage 4: rate/traffic controls + ASN tracker.
        let traffic_bundle = assembly::assemble_traffic_controls(
            &traffic_shaping_config,
            &bandwidth_config,
            &asn_scraping_config,
            &geoip,
        );

        // Stage 5: detector/policy setup (bot, endpoints, challenge, attack).
        let attack_detection_snapshot = attack_detection_config.clone();
        let detectors = assembly::assemble_detectors(
            &bot_config,
            &endpoint_config,
            attack_detection_config,
            &error_pages,
            error_page_theme,
        );

        // Stage 6: render/backends (tarpit, whitelist, auth, trust key).
        let tarpit_defaults = tarpit_defaults.unwrap_or_default();
        let tarpit_generator = Arc::new(crate::tarpit::MarkovChain::new());
        let whitelist_set = assembly::assemble_whitelist(whitelist);
        let auth_manager_instance = assembly::assemble_auth_manager(auth_manager, &data_dir);
        let trust_token_key = assembly::generate_trust_token_key();

        Self {
            rate_limiter,
            bot_detector: detectors.bot_detector,
            endpoint_blocker: detectors.endpoint_blocker,
            sensitive_endpoint_manager: detectors.sensitive_endpoint_manager,
            error_page_manager: detectors.error_page_manager,
            challenge_manager: detectors.challenge_manager,
            auth_manager: auth_manager_instance,
            attack_detector: ArcSwapOption::new(detectors.attack_detector),
            attack_detection_config: ArcSwapOption::new(attack_detection_snapshot.map(Arc::new)),
            attack_config_generation: AtomicU64::new(0),
            site_detector_cache: Mutex::new(LruCache::with_capacity(SITE_DETECTOR_CACHE_CAPACITY)),
            config: waf_config,
            whitelist: whitelist_set,
            _tarpit_generator: tarpit_generator,
            tarpit_defaults,
            threat_level: threat_bundle.threat_level,
            violation_tracker: threat_bundle.violation_tracker,
            ip_feed: feed_bundle.ip_feed,
            probe_tracker: feed_bundle.probe_tracker,
            suspicious_word_tracker: feed_bundle.suspicious_word_tracker,
            upstream_error_tracker: feed_bundle.upstream_error_tracker,
            traffic_shaper: traffic_bundle.traffic_shaper,
            connection_limiter: traffic_bundle.connection_limiter,
            asn_tracker: traffic_bundle.asn_tracker,
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
        site_attack_config: Option<&crate::config::site::SiteAttackDetectionConfig>,
        _ctx: Option<&RequestServices>,
    ) -> WafDecision {
        let mut best: Option<StagedOutcome> = None;

        // Stage 1: cheap local policy checks.
        best = fold_outcome(best, self.check_rate_limits(ip, site_id).await);
        best = fold_outcome(best, self.check_endpoint_block(path, method));

        // Stage 2: challenge/bot/rate/flood candidates.
        best = fold_outcome(best, self.check_honeypot(ip, path, method, ua));
        let (bot_outcome, bot_allowlisted) =
            self.check_bot_protection(ip, path, ua, ja4_hash, site_bot_config);
        best = fold_outcome(best, bot_outcome);
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
            // An explicitly allowlisted client identifies itself in
            // User-Agent by definition; mining that self-identification
            // string for redirect targets is pure false-positive surface
            // (every preview crawler ships a documentation URL in its UA).
            // Path, query and body scanning stay fully active, so a spoofed
            // crawler UA carrying a real attack payload still blocks.
            if bot_allowlisted {
                let mut filtered = headers.clone();
                filtered.remove(http::header::USER_AGENT);
                best = fold_outcome(
                    best,
                    self.check_attack(ip, method, path, query, &filtered, body, site_attack_config)
                        .await,
                );
            } else {
                best = fold_outcome(
                    best,
                    self.check_attack(ip, method, path, query, headers, body, site_attack_config)
                        .await,
                );
            }
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
            site_id, ip, method, path, None, &headers, None, ua, None, None, None, None,
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
        site_attack_config: Option<&crate::config::site::SiteAttackDetectionConfig>,
    ) -> Option<StagedOutcome> {
        let loaded = self.attack_detection_config.load();
        let fallback;
        let global: &AttackDetectionConfig = match loaded.as_ref() {
            Some(cfg) => cfg,
            None => {
                fallback = AttackDetectionConfig::default();
                &fallback
            }
        };

        let generation = self.attack_config_generation.load(Ordering::Relaxed);
        let policy =
            site_attack_config::resolve_attack_policy(site_attack_config, global, path, generation);
        if !policy.enabled {
            return None;
        }

        let Some(ad) = self.detector_for_policy(&policy) else {
            return None;
        };

        let http_method = http::Method::from_bytes(method.as_bytes()).unwrap_or(http::Method::GET);

        // Site-disabled detectors neither report nor score, so a disabled
        // detector cannot mask a lower-priority hit for an enabled one.
        let mut disabled_buf = [AttackType::Sqli; 5];
        let site_disabled =
            site_attack_config::site_disabled_list(site_attack_config, global, &mut disabled_buf);
        let (result, score) = ad
            .check_request_with_site_disabled(
                ip,
                &http_method,
                path,
                query,
                headers,
                body,
                site_disabled,
            )
            .await;

        let res = result?;
        if !site_attack_config::attack_type_enabled(site_attack_config, global, res.attack_type) {
            return None;
        }

        // The body cap is enforced before the detector on the normal request
        // path, but a detector constructed with an explicit lower cap can
        // still report `body_size`. It is a request-body limit, not an attack,
        // so render 413 and do not count it as an attack violation.
        if res
            .fingerprint
            .as_deref()
            .is_some_and(|fingerprint| fingerprint.starts_with("body_size:"))
        {
            tracing::warn!(
                ip = %ip,
                path = %path,
                fingerprint = ?res.fingerprint,
                "request body exceeds the WAF body cap"
            );
            return Some(StagedOutcome::new(
                WafDecision::Block(413, "Payload Too Large".to_string()),
                EnforcementCandidate::new(
                    EnforcementClass::Block,
                    EnforcementSource::StreamingBodyScan,
                    EnforcementReason::BodyTooLarge,
                ),
            ));
        }

        if policy.is_log() {
            tracing::warn!(
                ip = %ip,
                attack_type = ?res.attack_type,
                location = %res.input_location,
                path = %path,
                action = policy.action.as_str(),
                confidence = res.confidence().as_str(),
                "attack-pattern match observed under log-only policy"
            );
            return None;
        }

        tracing::info!(
            "Attack detected from {}: {:?} (score: {}) at {} (action: {}, confidence: {})",
            ip,
            res.attack_type,
            score,
            res.input_location,
            policy.action.as_str(),
            res.confidence().as_str()
        );

        if res.should_record_violation() {
            if let Some(ref tl) = self.threat_level {
                tl.record_attack();
            }

            if let Some(ref violation_tracker) = self.violation_tracker {
                violation_tracker.record_violation(ip, "attack_detected", 3);
            }
        }

        let (decision, candidate) = match policy.action {
            AttackAction::Block => (
                WafDecision::Block(403, "Attack Detected".to_string()),
                attack_candidate(&res),
            ),
            AttackAction::Stall => (
                WafDecision::Stall,
                synvoid_waf::enforcement::attack_candidate_with_class(
                    &res,
                    EnforcementClass::Stall,
                ),
            ),
            AttackAction::Log => unreachable!("log action returned above"),
        };

        Some(StagedOutcome::new(decision, candidate))
    }

    /// Select the immutable detector for a resolved policy.
    ///
    /// The no-override path returns the single global detector. A per-site
    /// policy is built once and cached under a bounded LRU keyed by the policy
    /// fingerprint (which includes the configuration generation).
    fn detector_for_policy(
        &self,
        policy: &ResolvedAttackPolicy<'_>,
    ) -> Option<Arc<AttackDetector>> {
        let Some(fingerprint) = policy.fingerprint else {
            return self.attack_detector.load().as_ref().cloned();
        };

        {
            let mut cache = self.site_detector_cache.lock();
            if let Some(detector) = cache.get(&fingerprint).cloned() {
                metrics::counter!("synvoid_waf_site_detector_cache_hits_total").increment(1);
                return Some(detector);
            }
        }
        metrics::counter!("synvoid_waf_site_detector_cache_misses_total").increment(1);

        // Site variants consume the same global rule-feed patterns as the
        // global detector; reload clears the cache so they are rebuilt.
        let detector_config = config_with_rule_feed_patterns(policy.detector_config.as_ref());
        let detector = Arc::new(AttackDetector::new(detector_config));
        metrics::counter!("synvoid_waf_site_detector_rebuilds_total").increment(1);

        let mut cache = self.site_detector_cache.lock();
        cache.insert(fingerprint, detector.clone());
        metrics::gauge!("synvoid_waf_site_detector_cache_size").set(cache.len() as f64);
        Some(detector)
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
    ) -> (Option<StagedOutcome>, bool) {
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
                (
                    Some(StagedOutcome::new(
                        WafDecision::Block(403, "Forbidden".to_string()),
                        candidate.expect("blocked bot must yield a candidate"),
                    )),
                    false,
                )
            }
            BotDetectionResult::Tarpit { reason, .. } => {
                tracing::info!(
                    "Tarpitting scraper from {}: {} - UA: {:?}, JA4: {:?}",
                    client_ip,
                    reason,
                    user_agent,
                    ja4_hash
                );
                (
                    Some(StagedOutcome::new(
                        WafDecision::Tarpit(path.to_string()),
                        candidate.expect("tarpitted scraper must yield a candidate"),
                    )),
                    false,
                )
            }
            BotDetectionResult::Allowed { reason } => {
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
                        return (
                            Some(StagedOutcome::new(
                                WafDecision::ChallengeWithCookie {
                                    challenge_type: self.challenge_manager.get_challenge_type(),
                                    html,
                                    session_cookie_name: self
                                        .challenge_manager
                                        .css_session_cookie_name(),
                                    session_cookie_value: sid,
                                    session_cookie_max_age: self
                                        .challenge_manager
                                        .css_window_secs(),
                                },
                                candidate,
                            )),
                            false,
                        );
                    } else {
                        return (
                            Some(StagedOutcome::new(
                                WafDecision::Challenge(
                                    self.challenge_manager.get_challenge_type(),
                                    html,
                                ),
                                candidate,
                            )),
                            false,
                        );
                    }
                }

                (None, reason == "known_search_bot")
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
        // The application detector intentionally leaves the body cap to the
        // request pipeline. Scanners built without a per-request site context
        // (HTTP/3 body/upstream paths) use the historical 10 MiB scan ceiling;
        // `streaming_for_path_with_limit` overrides it with the resolved cap.
        self.attack_detector.load().as_ref().map(|ad| {
            ad.clone()
                .streaming_with_fallback_body_limit(DEFAULT_WAF_STREAMING_BODY_LIMIT)
        })
    }

    fn streaming_scanner_for_path(
        &self,
        path: &str,
        site_attack_config: Option<&crate::config::site::SiteAttackDetectionConfig>,
        max_body_size: Option<usize>,
    ) -> Option<Box<dyn synvoid_http::shared_handler::StreamingWafScanner>> {
        let loaded = self.attack_detection_config.load();
        let fallback;
        let global: &AttackDetectionConfig = match loaded.as_ref() {
            Some(cfg) => cfg,
            None => {
                fallback = AttackDetectionConfig::default();
                &fallback
            }
        };

        let generation = self.attack_config_generation.load(Ordering::Relaxed);
        let policy =
            site_attack_config::resolve_attack_policy(site_attack_config, global, path, generation);
        if !policy.enabled {
            return None;
        }

        let detector = self.detector_for_policy(&policy)?;
        let mut core = match max_body_size {
            Some(limit) => detector.streaming_with_body_limit(limit),
            None => detector.streaming_with_fallback_body_limit(DEFAULT_WAF_STREAMING_BODY_LIMIT),
        };
        core.set_log_only(policy.is_log());
        Some(Box::new(core) as Box<dyn synvoid_http::shared_handler::StreamingWafScanner>)
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

    /// Rebuild the global attack detector from the effective configuration and
    /// the current global rule-feed patterns, then invalidate the per-site
    /// detector cache.
    ///
    /// Site variants are rebuilt lazily on their next request. Streaming
    /// scanner settings (`max_request_body_size` and per-path log-only policy)
    /// are preserved because they come from the same configuration snapshot
    /// and request policy resolution.
    pub fn reload_attack_detector(&self) -> Result<(), String> {
        let Some(base) = self.attack_detection_config.load().as_ref().cloned() else {
            return Ok(());
        };

        let merged = config_with_rule_feed_patterns(&base);
        let detector = Arc::new(AttackDetector::new(merged));

        self.attack_detector.store(Some(detector));
        self.attack_config_generation.fetch_add(1, Ordering::SeqCst);

        let mut cache = self.site_detector_cache.lock();
        cache.clear();
        metrics::gauge!("synvoid_waf_site_detector_cache_size").set(0.0);
        drop(cache);
        metrics::counter!("synvoid_waf_detector_reloads_total").increment(1);

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

    fn streaming_for_path(
        &self,
        path: &str,
        site_attack_config: Option<&crate::config::site::SiteAttackDetectionConfig>,
    ) -> Option<Box<dyn synvoid_http::shared_handler::StreamingWafScanner>> {
        self.streaming_scanner_for_path(path, site_attack_config, None)
    }

    fn streaming_for_path_with_limit(
        &self,
        path: &str,
        site_attack_config: Option<&crate::config::site::SiteAttackDetectionConfig>,
        max_body_size: usize,
    ) -> Option<Box<dyn synvoid_http::shared_handler::StreamingWafScanner>> {
        self.streaming_scanner_for_path(path, site_attack_config, Some(max_body_size))
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
    fn error_page_theme(&self) -> Arc<crate::theme::ThemeConfig> {
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
        site_attack_config: Option<&crate::config::site::SiteAttackDetectionConfig>,
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
            site_attack_config,
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
        site_attack_config: Option<crate::config::site::SiteAttackDetectionConfig>,
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
            site_attack_config.as_ref(),
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

fn config_with_rule_feed_patterns(base: &AttackDetectionConfig) -> AttackDetectionConfig {
    fn merge(category: &str, target: &mut Vec<String>) {
        for pattern in crate::waf::rule_feed::get_custom_patterns_for_category(category, None) {
            if !target.iter().any(|existing| existing == &pattern) {
                target.push(pattern);
            }
        }
    }

    let mut config = base.clone();
    merge("sqli", &mut config.sqli.custom_patterns);
    merge("xss", &mut config.xss.custom_patterns);
    merge("cmd_injection", &mut config.cmd_injection.custom_patterns);
    merge("path_traversal", &mut config.path_traversal.custom_patterns);
    merge("ssrf", &mut config.ssrf.custom_patterns);
    merge("ssti", &mut config.ssti.custom_patterns);
    merge("open_redirect", &mut config.open_redirect.custom_patterns);
    merge("xxe", &mut config.xxe.custom_patterns);
    merge("rfi", &mut config.rfi.custom_patterns);
    merge("ldap_injection", &mut config.ldap_injection.custom_patterns);
    merge(
        "xpath_injection",
        &mut config.xpath_injection.custom_patterns,
    );
    merge("jwt", &mut config.jwt.custom_patterns);
    config
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
        test_waf_core_with_attack_config(ip_rate, AttackDetectionConfig::default())
    }

    fn test_waf_core_with_attack_config(
        ip_rate: IpRateLimitConfig,
        attack_detection_config: AttackDetectionConfig,
    ) -> WafCore {
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
            attack_detection_config: Some(attack_detection_config),
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
            error_pages: crate::config::defaults::ErrorPagesDefaults::default(),
            error_page_theme: crate::theme::ThemeConfig::default(),
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

    const FB_UA: &str = "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)";

    fn headers_with_ua(ua: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            ua.parse().expect("test UA must parse"),
        );
        headers
    }

    #[tokio::test]
    async fn allowlisted_bot_ua_with_url_passes_attack_stage() {
        // Every preview crawler ships a documentation URL in its UA; the
        // open-redirect detector mines it and blocks. An explicitly
        // allowlisted client must not be mined for redirect targets in its
        // self-identification string.
        let mut core = test_waf_core(permissive_ip_rate());
        core.bot_detector = BotDetector::new(
            vec!["facebookexternalhit".to_string()],
            Vec::new(),
            Vec::new(),
            false,
        );
        let decision = core
            .check_request_full(
                None,
                TEST_IP,
                "GET",
                "/static/uploads/abc123.jpeg",
                None,
                &headers_with_ua(FB_UA),
                None,
                Some(FB_UA),
                None,
                None,
                None,
                None,
            )
            .await;
        assert!(
            matches!(decision, WafDecision::Pass),
            "allowlisted crawler UA must pass, got {decision:?}"
        );
    }

    #[tokio::test]
    async fn non_allowlisted_ua_with_url_still_blocks() {
        // Same URL-bearing UA shape without an allowlist entry must still
        // block: path/query/body scanning is untouched by the exemption.
        let core = test_waf_core(permissive_ip_rate());
        let ua = "Mozilla/5.0 (compatible; EvilClient/1.0; +http://evil.example/)";
        let decision = core
            .check_request_full(
                None,
                TEST_IP,
                "GET",
                "/static/uploads/abc123.jpeg",
                None,
                &headers_with_ua(ua),
                None,
                Some(ua),
                None,
                None,
                None,
                None,
            )
            .await;
        assert!(
            matches!(decision, WafDecision::Block(403, _)),
            "non-allowlisted UA with URL must block, got {decision:?}"
        );
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

    use crate::config::site::{SiteAttackDetectionConfig, SiteAttackPathRule};
    use synvoid_core::enforcement::{EnforcementClass, EnforcementReason, EnforcementSource};

    fn site_with_action(action: &str) -> SiteAttackDetectionConfig {
        let mut site = SiteAttackDetectionConfig::default();
        site.action = Some(action.to_string());
        site
    }

    fn sqli_query() -> &'static str {
        "id=1' OR '1'='1"
    }

    #[tokio::test]
    async fn default_and_global_action_block() {
        let core = test_waf_core(permissive_ip_rate());
        let outcome = core
            .check_attack(
                TEST_IP,
                "GET",
                "/search",
                Some(sqli_query()),
                &headers(),
                None,
                None,
            )
            .await
            .expect("default action must block");
        assert!(matches!(outcome.decision, WafDecision::Block(403, _)));
        assert_eq!(outcome.candidate.class, EnforcementClass::Block);
        assert_eq!(outcome.candidate.source, EnforcementSource::AttackDetection);
        assert_eq!(outcome.candidate.reason, EnforcementReason::AttackDetected);

        let mut global = AttackDetectionConfig::default();
        global.action = "stall".to_string();
        let core = test_waf_core_with_attack_config(permissive_ip_rate(), global);
        let outcome = core
            .check_attack(
                TEST_IP,
                "GET",
                "/search",
                Some(sqli_query()),
                &headers(),
                None,
                None,
            )
            .await
            .expect("global stall action must stall");
        assert_eq!(outcome.decision, WafDecision::Stall);
        assert_eq!(outcome.candidate.class, EnforcementClass::Stall);
        assert_eq!(outcome.candidate.source, EnforcementSource::AttackDetection);
        assert_eq!(outcome.candidate.reason, EnforcementReason::AttackDetected);
    }

    #[tokio::test]
    async fn site_action_log_observes_without_blocking_or_escalating() {
        let mut core = test_waf_core(permissive_ip_rate());
        core.violation_tracker = Some(ViolationTracker::new(
            crate::config::ThreatLevelEscalation {
                enabled: true,
                violations_before_block: 1,
                violation_window_secs: 300,
                excluded_ips: Vec::new(),
            },
            None,
            60,
            10,
        ));
        let site = site_with_action("log");

        for _ in 0..3 {
            let outcome = core
                .check_attack(
                    TEST_IP,
                    "GET",
                    "/search",
                    Some(sqli_query()),
                    &headers(),
                    None,
                    Some(&site),
                )
                .await;
            assert!(outcome.is_none(), "log action must not block");
        }

        assert_eq!(
            core.violation_tracker
                .as_ref()
                .expect("tracker")
                .check_violations(TEST_IP),
            0,
            "log action must not record violations"
        );
    }

    #[tokio::test]
    async fn site_action_stall_returns_stall_candidate() {
        let core = test_waf_core(permissive_ip_rate());
        let site = site_with_action("stall");
        let outcome = core
            .check_attack(
                TEST_IP,
                "GET",
                "/search",
                Some(sqli_query()),
                &headers(),
                None,
                Some(&site),
            )
            .await
            .expect("stall action must stall");
        assert_eq!(outcome.decision, WafDecision::Stall);
        assert_eq!(outcome.candidate.class, EnforcementClass::Stall);
        assert_eq!(outcome.candidate.source, EnforcementSource::AttackDetection);
        assert_eq!(outcome.candidate.reason, EnforcementReason::AttackDetected);
    }

    #[tokio::test]
    async fn per_path_log_beats_site_block_action() {
        let core = test_waf_core(permissive_ip_rate());
        let mut site = site_with_action("block");
        site.per_path = vec![SiteAttackPathRule {
            path_prefix: "/admin".to_string(),
            action: Some("log".to_string()),
        }];

        let logged = core
            .check_attack(
                TEST_IP,
                "GET",
                "/admin/new",
                Some(sqli_query()),
                &headers(),
                None,
                Some(&site),
            )
            .await;
        assert!(logged.is_none(), "per-path log must beat site block");

        let blocked = core
            .check_attack(
                TEST_IP,
                "GET",
                "/public",
                Some(sqli_query()),
                &headers(),
                None,
                Some(&site),
            )
            .await
            .expect("other paths keep the site block action");
        assert!(matches!(blocked.decision, WafDecision::Block(403, _)));
    }

    #[tokio::test]
    async fn site_paranoia_variant_is_site_scoped() {
        // "http://" keeps the request on the detector path (fast-path prefilter);
        // the SQLi `0x` token is a level-3-only pattern.
        let mut global = AttackDetectionConfig::default();
        global.open_redirect.enabled = false;
        global.rfi.enabled = false;
        let core = test_waf_core_with_attack_config(permissive_ip_rate(), global);
        let mut site = SiteAttackDetectionConfig::default();
        site.paranoia_level = Some(3);
        let query = Some("q=x+http://example.com/0x41");

        let global_result = core
            .check_attack(TEST_IP, "GET", "/files", query, &headers(), None, None)
            .await;
        assert!(
            global_result.is_none(),
            "default paranoia 2 must not match a level-3 pattern"
        );

        let site_result = core
            .check_attack(
                TEST_IP,
                "GET",
                "/files",
                query,
                &headers(),
                None,
                Some(&site),
            )
            .await
            .expect("site paranoia 3 must detect the high pattern");
        assert!(matches!(site_result.decision, WafDecision::Block(403, _)));

        let other_site = SiteAttackDetectionConfig::default();
        let other_result = core
            .check_attack(
                TEST_IP,
                "GET",
                "/files",
                query,
                &headers(),
                None,
                Some(&other_site),
            )
            .await;
        assert!(
            other_result.is_none(),
            "another site must not inherit paranoia 3"
        );
    }

    #[tokio::test]
    async fn site_custom_patterns_are_site_scoped() {
        // The fast-path prefilter needs a token it recognises; the custom
        // pattern itself remains site-only.
        let mut global = AttackDetectionConfig::default();
        global.open_redirect.enabled = false;
        global.rfi.enabled = false;
        let core = test_waf_core_with_attack_config(permissive_ip_rate(), global);
        let mut site = SiteAttackDetectionConfig::default();
        site.sqli.custom_patterns = vec!["http://SITE_ONLY_SQLI_ABC".to_string()];
        let query = Some("q=http://SITE_ONLY_SQLI_ABC");

        let global_result = core
            .check_attack(TEST_IP, "GET", "/search", query, &headers(), None, None)
            .await;
        assert!(
            global_result.is_none(),
            "global detector must not see the site pattern"
        );

        let site_result = core
            .check_attack(
                TEST_IP,
                "GET",
                "/search",
                query,
                &headers(),
                None,
                Some(&site),
            )
            .await
            .expect("site custom pattern must fire");
        assert!(matches!(site_result.decision, WafDecision::Block(403, _)));
    }

    #[tokio::test]
    async fn site_ssrf_override_is_honored() {
        let mut global = AttackDetectionConfig::default();
        global.rfi.enabled = false;
        global.open_redirect.enabled = false;
        global.path_traversal.enabled = false;
        let core = test_waf_core_with_attack_config(permissive_ip_rate(), global);

        let query = Some("target=http://192.168.1.1/secret");
        let global_result = core
            .check_attack(TEST_IP, "GET", "/fetch", query, &headers(), None, None)
            .await
            .expect("global SSRF policy must block private IPs");
        assert!(matches!(global_result.decision, WafDecision::Block(403, _)));

        let mut site = SiteAttackDetectionConfig::default();
        site.ssrf.block_private_ips = Some(false);
        let site_result = core
            .check_attack(
                TEST_IP,
                "GET",
                "/fetch",
                query,
                &headers(),
                None,
                Some(&site),
            )
            .await;
        assert!(
            site_result.is_none(),
            "site block_private_ips = false must be honored"
        );
    }

    #[tokio::test]
    async fn detector_cache_is_bounded_and_invalidated_on_reload() {
        let core = test_waf_core(permissive_ip_rate());

        for index in 0..(SITE_DETECTOR_CACHE_CAPACITY + 6) {
            let mut site = SiteAttackDetectionConfig::default();
            site.sqli.custom_patterns = vec![format!("SITE_CACHE_PATTERN_{index}")];
            let _ = core
                .check_attack(
                    TEST_IP,
                    "GET",
                    "/search",
                    Some("q=benign"),
                    &headers(),
                    None,
                    Some(&site),
                )
                .await;
        }

        assert!(
            core.site_detector_cache.lock().len() <= SITE_DETECTOR_CACHE_CAPACITY,
            "site detector cache must stay bounded"
        );

        core.reload_attack_detector()
            .expect("reload without a rule feed must succeed");
        assert_eq!(core.site_detector_cache.lock().len(), 0);
        assert_eq!(core.attack_config_generation.load(Ordering::SeqCst), 1);
        assert!(core.attack_detector.load().is_some());
    }

    #[tokio::test]
    async fn identical_site_policy_reuses_one_cached_detector() {
        let core = test_waf_core(permissive_ip_rate());
        let mut site = SiteAttackDetectionConfig::default();
        site.paranoia_level = Some(3);

        let _ = core
            .check_attack(
                TEST_IP,
                "GET",
                "/files",
                Some("file=/var/log/syslog"),
                &headers(),
                None,
                Some(&site),
            )
            .await;
        let _ = core
            .check_attack(
                TEST_IP,
                "GET",
                "/files",
                Some("file=/var/log/syslog"),
                &headers(),
                None,
                Some(&site),
            )
            .await;

        assert_eq!(
            core.site_detector_cache.lock().len(),
            1,
            "identical policies share one immutable detector"
        );
    }

    #[tokio::test]
    async fn streaming_scanner_uses_resolved_action() {
        let core = test_waf_core(permissive_ip_rate());
        let log_site = site_with_action("log");
        let mut logged =
            synvoid_http::RequestBodyWaf::streaming_for_path(&core, "/upload", Some(&log_site))
                .expect("streaming scanner");
        assert!(matches!(
            logged.scan_chunk(sqli_query().as_bytes()),
            synvoid_core::streaming_waf::StreamingWafDecision::Continue
        ));

        let block_site = site_with_action("block");
        let mut blocked =
            synvoid_http::RequestBodyWaf::streaming_for_path(&core, "/upload", Some(&block_site))
                .expect("streaming scanner");
        assert!(matches!(
            blocked.scan_chunk(sqli_query().as_bytes()),
            synvoid_core::streaming_waf::StreamingWafDecision::Block(..)
        ));
    }

    #[tokio::test]
    async fn three_benign_header_variants_do_not_escalate() {
        let mut core = test_waf_core(permissive_ip_rate());
        core.violation_tracker = Some(ViolationTracker::new(
            crate::config::ThreatLevelEscalation {
                enabled: true,
                violations_before_block: 3,
                violation_window_secs: 300,
                excluded_ips: Vec::new(),
            },
            None,
            60,
            10,
        ));

        let variants = [
            vec![
                ("accept", "text/html,application/xhtml+xml"),
                ("sec-fetch-dest", "document"),
                ("sec-fetch-mode", "navigate"),
                ("cache-control", "max-age=0"),
                ("referer", "https://example.test/a?b=1&c=2"),
            ],
            vec![
                ("accept", "image/avif,image/webp,*/*"),
                ("sec-fetch-dest", "image"),
                ("if-none-match", "\"abc123\""),
                ("range", "bytes=0-1023"),
                ("origin", "https://example.test"),
            ],
            vec![
                ("accept", "application/json"),
                ("priority", "u=0, i"),
                ("dnt", "1"),
                ("te", "trailers"),
                ("cookie", "session=abc; theme=dark"),
            ],
        ];

        for pairs in variants {
            let mut map = http::HeaderMap::new();
            for (name, value) in pairs {
                map.insert(name, value.parse().expect("header value"));
            }
            let decision = core
                .check_request_full(
                    None,
                    TEST_IP,
                    "GET",
                    "/",
                    None,
                    &map,
                    None,
                    Some(NORMAL_UA),
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            assert!(matches!(decision, WafDecision::Pass));
        }

        assert_eq!(
            core.violation_tracker
                .as_ref()
                .expect("tracker")
                .check_violations(TEST_IP),
            0,
            "benign header variants must not accumulate violations"
        );
    }
}
