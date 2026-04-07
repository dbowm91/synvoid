use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::{watch, Mutex as TokioMutex};

use crate::config::ConfigManager;
use crate::metrics::WorkerMetrics;
use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use crate::process::WorkerId;
use crate::{DrainFlag, RunningFlag};

#[derive(Clone)]
#[allow(dead_code)]
pub(super) struct WorkerState {
    pub(super) worker_id: WorkerId,
    pub(super) metrics: Arc<WorkerMetrics>,
    pub(super) start_time: Instant,
    pub(super) ipc: Arc<TokioMutex<AsyncIpcStream>>,
    pub(super) running: RunningFlag,
    pub(super) draining: DrainFlag,
    pub(super) config_manager: Arc<RwLock<ConfigManager>>,
    #[allow(dead_code)]
    pub(super) config_path: PathBuf,
    pub(super) shutdown_rx: watch::Receiver<bool>,
}

#[allow(dead_code)]
pub(super) fn create_waf(main_config: &crate::config::MainConfig) -> Arc<crate::waf::WafCore> {
    let data_dir = main_config
        .persistence
        .data_dir
        .as_ref()
        .map(std::path::PathBuf::from);

    let waf = crate::waf::WafCore::new(crate::waf::WafCoreConfig {
        rate_config: crate::waf::RateLimitConfigStore {
            ip: main_config.defaults.ratelimit.ip.clone(),
            global: main_config.defaults.ratelimit.global.clone(),
            cleanup_interval_secs: main_config.rate_limit_memory.cleanup_interval_secs,
        },
        memory_config: main_config.rate_limit_memory.clone(),
        bot_config: crate::waf::BotProtectionConfig {
            block_ai_crawlers: main_config.defaults.bot.block_ai_crawlers,
            enable_css_honeypot: main_config.defaults.bot.enable_css_honeypot,
            enable_pow_challenge: main_config.defaults.pow_challenge.enabled,
            known_bots_allow: main_config.defaults.bot.known_bots_allow.clone(),
            ai_crawlers_block: main_config.defaults.bot.ai_crawlers_block.clone(),
            scraper_patterns: Vec::new(),
            challenge_cookie_name: main_config.defaults.bot.challenge_cookie_name.clone(),
            challenge_window_secs: main_config.defaults.bot.challenge_window_secs,
            pow_difficulty: main_config.defaults.pow_challenge.difficulty,
            pow_timeout_secs: main_config.defaults.pow_challenge.timeout_secs,
            pow_window_secs: main_config.defaults.pow_challenge.window_secs,
            css_enabled: main_config.defaults.css_challenge.enabled,
            css_invalid_min: main_config.defaults.css_challenge.invalid_count_min,
            css_invalid_max: main_config.defaults.css_challenge.invalid_count_max,
            css_valid_count: main_config.defaults.css_challenge.valid_count,
            css_asset_path: main_config.defaults.css_challenge.asset_path.clone(),
            css_window_secs: main_config.defaults.css_challenge.challenge_window_secs,
            css_verification_window_secs: main_config
                .defaults
                .css_challenge
                .verification_window_secs,
            challenge_priority: crate::challenge::ChallengePriority::PowThenCss,
            challenge_max_attempts: 3,
            challenge_rate_limit_window_secs: 60,
            honeypot_endpoints_file: main_config.defaults.honeypot.endpoints_file.clone(),
            honeypot_enabled: true,
            honeypot_paths_per_ip: main_config.defaults.honeypot.paths_per_ip,
            honeypot_ttl_secs: main_config.defaults.honeypot.ttl_secs,
            honeypot_ban_duration: main_config.defaults.honeypot.block.ban_duration.clone(),
            error_pages_enabled: main_config.defaults.error_pages.enabled,
            error_pages_mode: "default".to_string(),
            error_pages_directory: main_config.defaults.error_pages.directory.clone(),
            error_pages_custom_directory: None,
            theme: crate::theme::ThemeConfig::from(main_config.defaults.theme.clone()),
            mesh_pow_enabled: false,
            mesh_pow_key_exchange_enabled: false,
            mesh_pow_auditing_enabled: false,
            mesh_id: None,
            mesh_global_node_url: None,
            mesh_audit_urls: Vec::new(),
        },
        endpoint_config: crate::waf::EndpointBlockerConfig {
            paths: main_config.defaults.blocked.paths.clone(),
            use_regex: main_config.defaults.blocked.use_regex,
            block_methods: main_config.defaults.blocked.block_methods.clone(),
            block_response_code: main_config.defaults.blocked.block_response_code,
            block_page_html: None,
        },
        waf_config: crate::waf::WafConfig {
            enable_css_honeypot: main_config.defaults.css_challenge.enabled,
            enable_pow_challenge: main_config.defaults.pow_challenge.enabled,
            enable_auth_challenge: main_config.defaults.auth.enabled,
            auth_login_path: main_config.defaults.auth.login_path.clone(),
            block_ai_crawlers: main_config.defaults.bot.block_ai_crawlers,
            drop_blocked_requests: false,
            test_mode: crate::waf::TestModeConfig::default(),
            honeypot_ban_duration_secs: 86400,
            css_exempt_paths: main_config.defaults.css_challenge.exempt_paths.clone(),
        },
        whitelist: Vec::new(),
        block_store: None,
        attack_detection_config: Some(crate::waf::AttackDetectionConfig::default()),
        auth_manager: None,
        threat_level_config: Some(main_config.threat_level.clone()),
        ip_feed_config: Some(main_config.ip_feeds.clone()),
        probe_config: Some(main_config.defaults.honeypot_probe.clone()),
        suspicious_words_config: Some(main_config.defaults.suspicious_words.clone()),
        upstream_errors_config: Some(main_config.defaults.upstream_errors.clone()),
        traffic_shaping_config: Some(main_config.traffic_shaping.clone()),
        asn_scraping_config: Some(main_config.defaults.asn_scraping.clone()),
        geoip: None,
        data_dir,
        test_mode: crate::waf::TestModeConfig::default(),
    });

    Arc::new(waf)
}
