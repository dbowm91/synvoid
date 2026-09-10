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

/// Spawn HTTP/1 listeners (v4 mandatory, v6 optional).
pub(crate) fn spawn_http_listeners(
    handles: &mut UnifiedServerRuntimeHandles,
    state: &Arc<ServerSharedState>,
    shutdown_tx: &tokio::sync::broadcast::Sender<()>,
    http_addr: SocketAddr,
    http_addr_v6: Option<SocketAddr>,
) {
    let shutdown_rx = shutdown_tx.subscribe();
    let st = state.clone();
    spawn_registered(
        handles,
        "http_v4",
        RuntimeHandleClass::CriticalServer,
        async move { UnifiedServer::run_http_server_inner(st, http_addr, shutdown_rx).await },
    );

    if let Some(addr_v6) = http_addr_v6 {
        let shutdown_rx = shutdown_tx.subscribe();
        let st = state.clone();
        spawn_registered(
            handles,
            "http_v6",
            RuntimeHandleClass::ProtocolListener,
            async move {
                tracing::info!("Starting HTTP server on IPv6 {}", addr_v6);
                UnifiedServer::run_http_server_inner(st, addr_v6, shutdown_rx).await
            },
        );
    }
}

/// Spawn HTTPS listeners when TLS + cert resolver are present.
pub(crate) async fn spawn_https_listeners(
    handles: &mut UnifiedServerRuntimeHandles,
    state: &Arc<ServerSharedState>,
    server: &UnifiedServer,
) {
    let cert_resolver = server.cert_resolver.clone();
    let tls_config = server.tls_config.clone();

    if let (Some(addr), Some(resolver)) = (server.https_addr, cert_resolver.clone()) {
        let shutdown_rx = server.shutdown_tx.subscribe();
        let st = state.clone();
        let main_config = {
            let cfg = server.config.read().await;
            cfg.main.clone()
        };
        let http_config = main_config.http.clone();
        let tls_cfg = tls_config.clone();
        spawn_registered(
            handles,
            "https_v4",
            RuntimeHandleClass::CriticalServer,
            async move {
                UnifiedServer::run_https_server_inner(
                    st,
                    addr,
                    resolver,
                    tls_cfg,
                    http_config,
                    main_config,
                    shutdown_rx,
                )
                .await
            },
        );
    }

    if let (Some(addr_v6), Some(resolver)) = (server.https_addr_v6, cert_resolver.clone()) {
        let shutdown_rx = server.shutdown_tx.subscribe();
        let st = state.clone();
        let main_config = {
            let cfg = server.config.read().await;
            cfg.main.clone()
        };
        let http_config = main_config.http.clone();
        let tls_cfg = tls_config.clone();
        spawn_registered(
            handles,
            "https_v6",
            RuntimeHandleClass::ProtocolListener,
            async move {
                tracing::info!("Starting HTTPS server on IPv6 {}", addr_v6);
                UnifiedServer::run_https_server_inner(
                    st,
                    addr_v6,
                    resolver,
                    tls_cfg,
                    http_config,
                    main_config,
                    shutdown_rx,
                )
                .await
            },
        );
    }
}

/// Spawn HTTP/3 listeners when configured.
pub(crate) fn spawn_http3_listeners(
    handles: &mut UnifiedServerRuntimeHandles,
    state: &Arc<ServerSharedState>,
    server: &UnifiedServer,
) {
    let cert_resolver = server.cert_resolver.clone();
    let http3_config = server.http3_config.clone();

    if let (Some(addr), Some(resolver)) = (server.http3_addr, cert_resolver.clone()) {
        let shutdown_rx = server.shutdown_tx.subscribe();
        let st = state.clone();
        let h3_cfg = http3_config.clone();
        spawn_registered(
            handles,
            "http3_v4",
            RuntimeHandleClass::ProtocolListener,
            async move {
                UnifiedServer::run_http3_server_inner(st, addr, resolver, h3_cfg, shutdown_rx).await
            },
        );
    }

    if let (Some(addr_v6), Some(resolver)) = (server.http3_addr_v6, cert_resolver.clone()) {
        let shutdown_rx = server.shutdown_tx.subscribe();
        let st = state.clone();
        let h3_cfg = http3_config.clone();
        spawn_registered(
            handles,
            "http3_v6",
            RuntimeHandleClass::ProtocolListener,
            async move {
                tracing::info!("Starting HTTP/3 server on IPv6 {}", addr_v6);
                UnifiedServer::run_http3_server_inner(st, addr_v6, resolver, h3_cfg, shutdown_rx)
                    .await
            },
        );
    }
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
