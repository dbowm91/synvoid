//! Read-only TCP/UDP listener inventory.
//!
//! The runtime listener definitions live in the top-level `[tcp.protocols.*]`
//! and `[udp.protocols.*]` maps. This surface reports what the pools actually
//! bound in this process and the real active connection/flow counts. There is
//! no create/delete endpoint: mutating a running listener requires a restart
//! (or a deliberate reload feature), and a handler that wrote a site-local
//! config no runtime code consumed was a lie.

use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct TcpUdpListener {
    pub id: String,
    pub transport: String,
    pub port: u16,
    pub protocol: String,
    pub upstream: String,
    pub enabled: bool,
    pub bound: bool,
    pub active_connections: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListListenersResponse {
    pub listeners: Vec<TcpUdpListener>,
}

#[utoipa::path(
    get,
    path = "/tcp-udp/listeners",
    responses(
        (status = 200, description = "Bound TCP/UDP listeners", body = ListListenersResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tcp_udp"
)]
pub async fn list_listeners(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ListListenersResponse>, StatusCode> {
    let mut listeners = Vec::new();

    for listener in crate::tcp::listener::tcp_listener_snapshots() {
        listeners.push(TcpUdpListener {
            id: format!(
                "tcp:{}:{}:{}",
                listener.protocol, listener.bind_address, listener.port
            ),
            transport: "tcp".to_string(),
            port: listener.port,
            protocol: listener.protocol,
            upstream: listener.upstream,
            enabled: true,
            bound: listener.bound,
            active_connections: listener.active_connections,
        });
    }

    for listener in crate::udp::listener::udp_listener_snapshots() {
        listeners.push(TcpUdpListener {
            id: format!(
                "udp:{}:{}:{}",
                listener.protocol, listener.bind_address, listener.port
            ),
            transport: "udp".to_string(),
            port: listener.port,
            protocol: listener.protocol,
            upstream: listener.upstream,
            enabled: true,
            bound: listener.bound,
            active_connections: listener.active_flows,
        });
    }

    listeners.sort_by(|a, b| {
        a.transport
            .cmp(&b.transport)
            .then(a.port.cmp(&b.port))
            .then(a.protocol.cmp(&b.protocol))
    });

    Ok(Json(ListListenersResponse { listeners }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HttpListener {
    pub id: String,
    pub transport: String,
    pub configured_addr: String,
    pub bound_addr: Option<String>,
    pub tls: bool,
    pub http2: bool,
    pub http3: bool,
    pub default_site: Option<String>,
    pub site_count: usize,
    pub state: String,
    pub active_connections: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListHttpListenersResponse {
    pub listeners: Vec<HttpListener>,
}

#[utoipa::path(
    get,
    path = "/http/listeners",
    responses(
        (status = 200, description = "Bound HTTP/HTTPS/HTTP3 listeners", body = ListHttpListenersResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tcp_udp"
)]
pub async fn list_http_listeners(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ListHttpListenersResponse>, StatusCode> {
    let listeners = crate::server::http_listener_snapshots()
        .into_iter()
        .map(|listener| HttpListener {
            id: listener.id,
            transport: listener.transport,
            configured_addr: listener.configured_addr,
            bound_addr: listener.bound_addr,
            tls: listener.tls,
            http2: listener.http2,
            http3: listener.http3,
            default_site: listener.default_site,
            site_count: listener.site_count,
            state: listener.state,
            active_connections: listener.active_connections,
        })
        .collect();
    Ok(Json(ListHttpListenersResponse { listeners }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProtocolInfo {
    pub name: String,
    pub description: String,
    pub supported: bool,
}

#[utoipa::path(
    get,
    path = "/tcp-udp/protocols",
    responses(
        (status = 200, description = "Configured TCP/UDP protocol profiles", body = Vec<ProtocolInfo>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tcp_udp"
)]
pub async fn list_protocols(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<ProtocolInfo>>, StatusCode> {
    let config = state.process.config.read().await;
    let mut protocols = Vec::new();
    for name in config.main.tcp.protocols.keys() {
        protocols.push(ProtocolInfo {
            name: name.clone(),
            description: "TCP protocol profile from [tcp.protocols]".to_string(),
            supported: true,
        });
    }
    for name in config.main.udp.protocols.keys() {
        protocols.push(ProtocolInfo {
            name: name.clone(),
            description: "UDP protocol profile from [udp.protocols]".to_string(),
            supported: true,
        });
    }
    protocols.sort_by(|a, b| a.name.cmp(&b.name));
    protocols.dedup_by(|a, b| a.name == b.name);

    Ok(Json(protocols))
}
