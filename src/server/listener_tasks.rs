//! Phase 04: protocol-listener task assembly for `UnifiedServer::run()`.
//!
//! Each `spawn_*` helper registers one subsystem family with
//! `UnifiedServerRuntimeHandles`. The top-level `run()` keeps the visible
//! order: HTTP → HTTPS → HTTP/3 → TCP/UDP pools → DNS → ACME → shutdown/drain.
//! No new crates, no hidden second composition root.

use std::net::SocketAddr;
use std::sync::Arc;

use super::runtime_handles::{
    spawn_registered, spawn_registered_unit, RuntimeHandleClass, UnifiedServerRuntimeHandles,
};
use super::{ServerSharedState, UnifiedServer};

/// Spawn every bound HTTP/HTTPS/HTTP3 listener.
pub(crate) async fn spawn_http_listeners(
    handles: &mut UnifiedServerRuntimeHandles,
    state: &Arc<ServerSharedState>,
    server: &UnifiedServer,
    bound: &[super::listener_binding::BoundHttpListener],
) {
    let cert_resolver = server.cert_resolver.clone();
    let tls_config = server.tls_config.clone();
    let (main_config, http_config) = {
        let cfg = server.config.read().await;
        (cfg.main.clone(), cfg.main.http.clone())
    };

    for listener in bound {
        let plan = listener.plan.clone();
        let id = plan.name().to_string();

        if let Some(std_listener) = listener
            .tcp
            .as_ref()
            .and_then(|socket| socket.try_clone().ok())
        {
            let shutdown_rx = server.shutdown_tx.subscribe();
            let st = state.clone();
            let name = format!("{}:{id}", if plan.tls { "https" } else { "http" });
            let class = RuntimeHandleClass::CriticalServer;
            if plan.tls {
                let Some(resolver) = cert_resolver.clone() else {
                    tracing::error!(listener = %id, "TLS listener has no certificate resolver");
                    continue;
                };
                let tls_cfg = tls_config.clone();
                let http_cfg = http_config.clone();
                let main_cfg = main_config.clone();
                let listener_plan = plan.clone();
                spawn_registered(handles, name, class, async move {
                    UnifiedServer::run_https_server_inner(
                        st,
                        std_listener,
                        listener_plan,
                        resolver,
                        tls_cfg,
                        http_cfg,
                        main_cfg,
                        shutdown_rx,
                    )
                    .await
                });
            } else {
                let http_cfg = http_config.clone();
                let main_cfg = main_config.clone();
                let listener_plan = plan.clone();
                spawn_registered(handles, name, class, async move {
                    UnifiedServer::run_http_server_inner(
                        st,
                        std_listener,
                        listener_plan,
                        http_cfg,
                        main_cfg,
                        shutdown_rx,
                    )
                    .await
                });
            }
        }

        if let Some(std_socket) = listener
            .udp
            .as_ref()
            .and_then(|socket| socket.try_clone().ok())
        {
            let Some(resolver) = cert_resolver.clone() else {
                tracing::error!(listener = %id, "HTTP/3 listener has no certificate resolver");
                continue;
            };
            let shutdown_rx = server.shutdown_tx.subscribe();
            let st = state.clone();
            let h3_cfg = server.http3_config.clone();
            let name = format!("h3:{id}");
            let listener_plan = plan.clone();
            spawn_registered(
                handles,
                name,
                RuntimeHandleClass::ProtocolListener,
                async move {
                    UnifiedServer::run_http3_server_inner(
                        st,
                        std_socket,
                        listener_plan,
                        resolver,
                        h3_cfg,
                        shutdown_rx,
                    )
                    .await
                },
            );
        }
    }
}

/// Spawn the admin HTTP API when `[admin] enabled=true`.
///
/// Serves `create_admin_router` on `bind_address:port` with the standard
/// shutdown receiver, drained via `shutdown_and_join` like every other
/// listener. `enabled=false` (or an unparseable/unbindable address)
/// registers nothing and logs the reason.
pub(crate) async fn spawn_admin_service(
    handles: &mut UnifiedServerRuntimeHandles,
    state: &Arc<ServerSharedState>,
    server: &UnifiedServer,
) {
    let Some(addr) = server.admin_addr else {
        return;
    };

    let admin_config = {
        let cfg = server.config.read().await;
        cfg.main.admin.clone()
    };
    if !admin_config
        .bind_address
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
    {
        tracing::warn!(
            addr = %addr,
            "Admin API bound to a non-loopback address; session cookies follow [admin] secure_cookie"
        );
    }

    let std_listener = match synvoid_platform::socket_bind::bind_tcp_reuse(addr) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(addr = %addr, error = %e, "Admin API failed to bind; control plane disabled");
            return;
        }
    };
    let listener = match tokio::net::TcpListener::from_std(std_listener) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(addr = %addr, error = %e, "Admin API failed to adopt listener; control plane disabled");
            return;
        }
    };

    // `build_admin_state` uses `blocking_read` on the config lock, which
    // panics on a Tokio worker thread. Build it on the blocking pool; the
    // stored `Arc<RwLock<ConfigManager>>` is only read asynchronously later.
    // The same `Arc<AdminState>` feeds the router and the metrics publisher
    // so the panel observes this worker's own traffic and logs.
    let config_for_router = state.config.clone();
    let probe_tracker = server.get_probe_tracker();
    let suspicious_word_tracker = server.get_suspicious_word_tracker();
    let upstream_error_tracker = server.get_upstream_error_tracker();
    let threat_level_manager = server.get_threat_level_manager();
    // Same Arc the worker's ErrorPageManager renders through: the admin
    // PUT /theme stores here, served block pages read here. Hoisted out of
    // the blocking closure (`server` is borrowed, not 'static).
    let error_page_theme = Some(server.get_waf().error_page_manager.theme_handle());
    let admin_token = admin_config.resolve_token();
    let admin_cors = admin_config.cors.clone();
    let admin_rate_limit = admin_config.rate_limit.clone();
    let admin_trusted_proxies = admin_config.trusted_proxies.clone();
    let admin_state = match tokio::task::spawn_blocking(move || {
        crate::admin::build_admin_state(
            config_for_router,
            admin_token,
            probe_tracker,
            suspicious_word_tracker,
            upstream_error_tracker,
            threat_level_manager,
            None,
            error_page_theme,
            #[cfg(feature = "mesh")]
            None,
            #[cfg(feature = "icmp-filter")]
            None,
        )
    })
    .await
    {
        Ok(Some(admin_state)) => admin_state,
        Ok(None) => {
            tracing::error!("Admin API state build failed; control plane disabled");
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "Admin API state build panicked; control plane disabled");
            return;
        }
    };

    // Register the worker-local request-log sink before serving: the
    // HTTP/HTTPS lanes resolve it per request, so records flow even on
    // keep-alive connections accepted before this point.
    let _ = state.request_log_sink.set(admin_state.clone());

    let router = crate::admin::build_router_from_state(
        admin_state.clone(),
        admin_cors,
        admin_rate_limit,
        admin_trusted_proxies.clone(),
    );
    crate::admin::middleware::set_trusted_proxies(admin_trusted_proxies);

    let mut shutdown_rx = server.shutdown_tx.subscribe();
    tracing::info!(addr = %addr, "Starting admin API");
    spawn_registered(
        handles,
        "admin",
        RuntimeHandleClass::ProtocolListener,
        async move {
            // `into_make_service_with_connect_info` is load-bearing: the
            // admin rate limiter and audit log key by client IP from the
            // `ConnectInfo` extension. Plain `axum::serve` never populates
            // it, which collapsed every client into a single global
            // "unknown" bucket (60/min shared across all operators/tabs).
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
            })
            .await
            .map_err(|e| e.to_string())
        },
    );

    spawn_metrics_publisher_service(handles, state, &admin_state, server);
}

/// Publish this worker's own metrics and site stats into its `AdminState`
/// once per second. Every worker (standalone or supervised) runs the same
/// feed over its own `WorkerMetrics` — no cross-process sharing, no second
/// metrics system. Drained via the standard shutdown like every other
/// maintenance task.
pub(crate) fn spawn_metrics_publisher_service(
    handles: &mut UnifiedServerRuntimeHandles,
    state: &Arc<ServerSharedState>,
    admin_state: &Arc<crate::admin::state::AdminState>,
    server: &UnifiedServer,
) {
    let feed = Arc::new(crate::admin::metrics::LocalMetricsFeed {
        metrics: state.metrics.clone(),
        worker_id: state.worker_id.unwrap_or(crate::process::WorkerId(0)),
    });
    let admin_state = admin_state.clone();
    let shutdown_rx = server.shutdown_tx.subscribe();
    spawn_registered_unit(
        handles,
        "admin_metrics_publisher",
        RuntimeHandleClass::Maintenance,
        async move {
            crate::admin::metrics::start_metrics_publisher(admin_state, feed, None, shutdown_rx)
                .await;
        },
    );
}

/// Spawn TCP/UDP pool tasks when present.
pub(crate) fn spawn_aux_pools(handles: &mut UnifiedServerRuntimeHandles, server: &UnifiedServer) {
    if let Some(ref pool) = server.tcp_pool {
        let pool = pool.clone();
        spawn_registered_unit(
            handles,
            "tcp_pool",
            RuntimeHandleClass::ProtocolListener,
            async move { pool.start().await },
        );
    }

    if let Some(ref pool) = server.udp_pool {
        let pool = pool.clone();
        spawn_registered_unit(
            handles,
            "udp_pool",
            RuntimeHandleClass::ProtocolListener,
            async move { pool.start().await },
        );
    }
}

/// Spawn the DNS server when the `dns` feature built it and mesh policy
/// allows it. Returns whether a DNS task was registered.
#[cfg(feature = "dns")]
pub(crate) fn spawn_dns_service(
    handles: &mut UnifiedServerRuntimeHandles,
    server: &UnifiedServer,
) -> bool {
    if let Some(ref dns_server) = server.dns_server {
        #[cfg(feature = "mesh")]
        let is_global = server
            .mesh_transport
            .as_ref()
            .map(|mt| mt.is_global_node())
            .unwrap_or(false);
        #[cfg(not(feature = "mesh"))]
        let is_global = false;
        #[cfg(feature = "mesh")]
        let dns_mesh_mode_only = {
            let topology = server.mesh_transport.as_ref().map(|mt| mt.get_topology());
            if let Some(ref t) = topology {
                let cfg = t.config();
                cfg.dht
                    .as_ref()
                    .map(|d| d.dns_mesh_mode_only)
                    .unwrap_or(true)
            } else {
                true
            }
        };
        #[cfg(not(feature = "mesh"))]
        let dns_mesh_mode_only = true;
        let can_start = !dns_mesh_mode_only || is_global;

        if can_start {
            let dns_server = dns_server.clone();
            spawn_registered(
                handles,
                "dns",
                RuntimeHandleClass::ProtocolListener,
                async move {
                    let mut srv = (*dns_server).clone();
                    srv.start().await.map_err(|e| e.to_string())
                },
            );
            return true;
        }
        tracing::info!("Skipping DNS server: dns_mesh_mode_only=true and node is not global");
    }
    false
}

/// Spawn ACME init/renewal when the `dns` feature built a manager.
#[cfg(feature = "dns")]
pub(crate) fn spawn_acme_service(
    handles: &mut UnifiedServerRuntimeHandles,
    server: &UnifiedServer,
) -> bool {
    if let Some(ref acme_mgr) = *server
        .acme_manager
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
    {
        let acme_clone = acme_mgr.clone();
        let mut shutdown_rx = server.shutdown_tx.subscribe();
        spawn_registered(
            handles,
            "acme_init_renewal",
            RuntimeHandleClass::Maintenance,
            async move {
                tokio::select! {
                    result = acme_clone.init() => {
                        match result {
                            Ok(()) => {
                                acme_clone.spawn_renewal_task();
                                Ok(())
                            }
                            Err(e) => {
                                tracing::error!("Failed to initialize ACME manager: {}", e);
                                Err(e.to_string())
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => Ok(()),
                }
            },
        );
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_classes_are_distinct() {
        assert_ne!(
            RuntimeHandleClass::CriticalServer,
            RuntimeHandleClass::ProtocolListener
        );
        assert_ne!(
            RuntimeHandleClass::Maintenance,
            RuntimeHandleClass::BestEffort
        );
    }
}
