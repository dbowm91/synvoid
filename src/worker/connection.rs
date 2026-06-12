use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::{watch, Mutex as TokioMutex};

use crate::{DrainFlag, RunningFlag};
use synvoid_config::ConfigManager;
use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;
use synvoid_ipc::WorkerId;
use synvoid_metrics::WorkerMetrics;

#[derive(Clone)]
// SAFETY_REASON: Debugging - stored for introspection
#[allow(dead_code)]
pub(super) struct WorkerState {
    pub(super) worker_id: WorkerId,
    pub(super) metrics: Arc<WorkerMetrics>,
    pub(super) start_time: Instant,
    pub(super) ipc: Arc<TokioMutex<AsyncIpcStream>>,
    pub(super) running: RunningFlag,
    pub(super) draining: DrainFlag,
    pub(super) config_manager: Arc<RwLock<ConfigManager>>,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    pub(super) config_path: PathBuf,
    pub(super) shutdown_rx: watch::Receiver<bool>,
}

// SAFETY_REASON: Debugging - stored for introspection
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
        bot_config: main_config.defaults.bot.clone(),
        endpoint_config: main_config.defaults.blocked.clone(),
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
        attack_detection_config: Some(crate::waf::AttackDetectionConfig::default()),
        auth_manager: None,
        threat_level_config: Some(main_config.threat_level.clone()),
        ip_feed_config: Some(main_config.ip_feeds.clone()),
        probe_config: Some(main_config.defaults.honeypot_probe.clone()),
        suspicious_words_config: Some(main_config.defaults.suspicious_words.clone()),
        upstream_errors_config: Some(main_config.defaults.upstream_errors.clone()),
        traffic_shaping_config: Some(main_config.traffic_shaping.clone()),
        bandwidth_config: main_config.traffic_shaping.bandwidth.clone(),
        asn_scraping_config: Some(main_config.defaults.asn_scraping.clone()),
        geoip: None,
        data_dir,
        test_mode: crate::waf::TestModeConfig::default(),
        tarpit_defaults: Some(main_config.tarpit.clone()),
    });

    Arc::new(waf)
}
