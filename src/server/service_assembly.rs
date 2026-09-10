//! Phase 04: subsystem assembly for `UnifiedServer::run()`.
//!
//! Root-private builders that keep the top-level `run()` orchestration at one
//! abstraction level. Each helper returns a narrow typed bundle, not a
//! bag-of-everything. Initialization order stays visible in `run()`; no new
//! crates, no DI machinery, no public API broadening.

use std::sync::Arc;

use crate::config::MainConfig;
use crate::router::Router;
use crate::waf::WafCore;
use synvoid_http::runtime::HttpRuntimeContext;

use super::plugin_runtime::PluginRuntimeOwner;
use super::runtime_handles::{
    spawn_registered_unit, RuntimeHandleClass, UnifiedServerRuntimeHandles,
};
use crate::metrics::adapter::WorkerMetricsSink;
use crate::metrics::WorkerMetrics;
use crate::router_adapter::RouterRouteResolver;
use crate::waf::adapter::RootWafProcessor;
use crate::worker::drain_adapter::WorkerDrainStateAdapter;
use crate::worker::drain_state::WorkerDrainState;

pub(crate) type AssembledHttpContext = HttpRuntimeContext<
    RootWafProcessor,
    RouterRouteResolver,
    WorkerMetricsSink,
    WorkerDrainStateAdapter,
>;

/// Build the plugin runtime owner from the application plugin config.
///
/// Loads configured WASM plugins, enables hot-reload for the first plugin
/// directory when present, and starts the epoch incrementer. The returned
/// owner must be kept alive until after runtime drain (dropped at the end of
/// `run()`).
pub(crate) fn assemble_plugin_runtime(main_config: &MainConfig) -> PluginRuntimeOwner {
    let mut main_config = main_config.clone();

    if main_config.plugins.migrate_deprecated_native_plugins() {
        tracing::warn!(
            "DEPRECATION: [plugins.native_plugins] is deprecated. \
             Use [plugins.unsafe_native] instead."
        );
    }
    let native_cfg = &main_config.plugins.unsafe_native;
    let runtime_native_config = crate::plugin::UnsafeNativeExtensionConfig {
        enabled: native_cfg.enabled,
        allow_in_production: native_cfg.allow_in_production,
        risk_acknowledgement: native_cfg.risk_acknowledgement.clone(),
        allowed_dirs: native_cfg.allowed_dirs.clone(),
        hot_reload_enabled: native_cfg.hot_reload_enabled,
        ..Default::default()
    };
    crate::plugin::set_global_unsafe_native_config(runtime_native_config);

    if native_cfg.enabled {
        if crate::plugin::is_production_env() {
            if native_cfg.allow_in_production {
                tracing::warn!("Unsafe native extensions: ENABLED in production mode");
            } else {
                tracing::warn!(
                    "Unsafe native extensions: enabled but blocked in production \
                     (allow_in_production=false)"
                );
            }
        } else {
            tracing::info!("Unsafe native extensions: enabled in development mode");
        }
    } else {
        tracing::debug!("Unsafe native extensions: disabled");
    }

    let mut owner = PluginRuntimeOwner::new(Arc::new(crate::plugin::PluginManager::new()));
    owner.load_configured_plugins(&main_config.plugins.wasm.plugins);

    if let Some(plugin_cfg) = main_config.plugins.wasm.plugins.first() {
        let plugin_dir = std::path::Path::new(&plugin_cfg.path)
            .parent()
            .unwrap_or(std::path::Path::new("/opt/synvoid/plugins"))
            .to_path_buf();
        if plugin_dir.is_dir() {
            if let Err(e) = owner.enable_hot_reload_if_configured(&plugin_dir) {
                tracing::debug!("Hot-reload not enabled: {}", e);
            }
        }
    }

    owner.start_epoch_incrementer(std::time::Duration::from_secs(1));

    owner
}

/// Build the request router with the plugin manager attached.
pub(crate) fn assemble_router(
    main_config: &MainConfig,
    sites: std::collections::HashMap<String, crate::config::site::SiteConfig>,
    plugin_manager: Arc<crate::plugin::PluginManager>,
) -> Router {
    Router::new(main_config, sites).with_plugin_manager(plugin_manager)
}

/// Build the shared HTTP runtime context when both metrics and drain state
/// are present. Returns `None` when either is absent (same semantics as the
/// pre-Phase-04 inline block).
pub(crate) fn assemble_http_runtime_context(
    waf: &Arc<WafCore>,
    router: &Arc<Router>,
    metrics: &Option<Arc<WorkerMetrics>>,
    drain: &Option<Arc<WorkerDrainState>>,
) -> Option<AssembledHttpContext> {
    let root_waf = RootWafProcessor::new(waf.clone());
    let route_resolver = RouterRouteResolver::new(router.clone());
    match (metrics, drain) {
        (Some(metrics), Some(drain)) => {
            let metrics_sink = WorkerMetricsSink::new(metrics.clone());
            let drain_adapter = WorkerDrainStateAdapter::new(drain.clone());
            Some(AssembledHttpContext::new(
                Arc::new(root_waf),
                Arc::new(route_resolver),
                Arc::new(metrics_sink),
                Arc::new(drain_adapter),
            ))
        }
        _ => None,
    }
}

/// Register the threat-level auto-scale maintenance task when enabled.
pub(crate) fn spawn_threat_autoscale(
    handles: &mut UnifiedServerRuntimeHandles,
    waf: &Arc<WafCore>,
    shutdown_tx: &tokio::sync::broadcast::Sender<()>,
) {
    let threat_level = waf.threat_level.clone();
    if let Some(ref tl) = threat_level {
        let config = tl.get_legacy_config();
        if config.auto_scale {
            let tl_clone = tl.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();
            spawn_registered_unit(
                handles,
                "threat_level_auto_scale",
                RuntimeHandleClass::Maintenance,
                async move {
                    loop {
                        tokio::select! {
                            _ = shutdown_rx.recv() => break,
                            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                                tl_clone.check_and_scale();
                            }
                        }
                    }
                },
            );
        }
    }
}

/// Start the QUIC tunnel router when configured. Pure startup step extracted
/// so `run()` shows tunnel → maintenance → plugin → router ordering.
pub(crate) async fn start_quic_tunnel(
    tunnel_router: &Option<Arc<tokio::sync::Mutex<crate::tunnel::TunnelRouter>>>,
    tunnel_config: &Option<crate::config::TunnelConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ref router) = tunnel_router {
        if let Some(ref cfg) = tunnel_config {
            if cfg.quic.enabled {
                tracing::info!("Starting QUIC tunnel router for server-WAF mode");
                let mut locked = router.lock().await;
                locked.start().await?;

                tracing::info!(
                    "QUIC tunnel server listening on {}:{}",
                    cfg.quic.bind_address,
                    cfg.quic.port
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MainConfig;

    #[tokio::test]
    async fn assemble_plugin_runtime_with_empty_plugins() {
        let cfg = MainConfig::default_config();
        let owner = assemble_plugin_runtime(&cfg);
        // No configured plugins in defaults; manager exists and epoch runs.
        assert!(owner.manager().wasm_manager().epoch_incrementer_running());
    }

    #[test]
    fn assemble_router_builds_without_panic() {
        let cfg = MainConfig::default_config();
        let mgr = Arc::new(crate::plugin::PluginManager::new());
        let _router = assemble_router(&cfg, std::collections::HashMap::new(), mgr);
    }

    #[tokio::test]
    async fn http_context_absent_without_metrics_or_drain() {
        use crate::config::defaults::{BlockedDefaults, BotDefaults};
        use crate::config::limits::RateLimitMemoryConfig;
        use crate::config::traffic::BandwidthConfig;
        use crate::waf::{RateLimitConfigStore, WafCoreConfig};
        use synvoid_waf::primitives::{TestModeConfig, WafConfig};

        let waf = Arc::new(WafCore::new(WafCoreConfig {
            rate_config: RateLimitConfigStore {
                ip: crate::config::MainConfig::default_config()
                    .defaults
                    .ratelimit
                    .ip
                    .clone(),
                global: crate::config::MainConfig::default_config()
                    .defaults
                    .ratelimit
                    .global
                    .clone(),
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
            attack_detection_config: None,
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
            data_dir: None,
            test_mode: TestModeConfig::default(),
            tarpit_defaults: None,
        }));
        let cfg = MainConfig::default_config();
        let mgr = Arc::new(crate::plugin::PluginManager::new());
        let router = Arc::new(assemble_router(&cfg, std::collections::HashMap::new(), mgr));
        // Neither metrics nor drain present → None (preserves old semantics).
        assert!(assemble_http_runtime_context(&waf, &router, &None, &None).is_none());
    }
}
