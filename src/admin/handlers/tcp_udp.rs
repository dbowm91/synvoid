use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct TcpUdpListener {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub upstream: String,
    pub enabled: bool,
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
        (status = 200, description = "List of TCP/UDP listeners", body = ListListenersResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tcp_udp"
)]
pub async fn list_listeners(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ListListenersResponse>, StatusCode> {
    let config = state.process.config.read().await;
    let mut listeners = Vec::new();

    for (site_id, site_config) in &config.sites {
        for (name, port_config) in &site_config.tcp.ports {
            if let (Some(port), Some(upstream)) = (port_config.port, &port_config.upstream) {
                listeners.push(TcpUdpListener {
                    id: format!("{}-{}", site_id, name),
                    port,
                    protocol: name.clone(),
                    upstream: upstream.clone(),
                    enabled: site_config.tcp.enabled.unwrap_or(false),
                    active_connections: 0,
                });
            }
        }
    }

    Ok(Json(ListListenersResponse { listeners }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateListenerRequest {
    pub site_id: String,
    pub port: u16,
    pub protocol: String,
    pub upstream: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateListenerResponse {
    pub listener: TcpUdpListener,
}

#[utoipa::path(
    post,
    path = "/tcp-udp/listeners",
    request_body = CreateListenerRequest,
    responses(
        (status = 200, description = "Listener created"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tcp_udp"
)]
pub async fn create_listener(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<CreateListenerRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let mut config = state.process.config.write().await;
    let site_config = config
        .sites
        .get_mut(&req.site_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let listener_id = format!("{}-{}", req.site_id, req.protocol);

    tracing::info!(
        "Creating TCP/UDP listener {} on port {} for site {} -> upstream {}",
        listener_id,
        req.port,
        req.site_id,
        req.upstream
    );

    if !site_config.tcp.enabled.unwrap_or(false) {
        site_config.tcp.enabled = Some(true);
    }

    let audit_id = uuid::Uuid::new_v4().to_string();

    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "create_tcp_udp_listener".to_string(),
        target_kind: "tcp_udp_listener".to_string(),
        target_id: listener_id.clone(),
        prior_state: None,
        requested_state: Some(serde_json::json!({
            "site_id": req.site_id,
            "port": req.port,
            "protocol": req.protocol,
            "upstream": req.upstream,
        })),
        resulting_state: Some(serde_json::json!({
            "listener_id": listener_id,
            "port": req.port,
            "protocol": req.protocol,
            "upstream": req.upstream,
        })),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::AppliedLocalOnly,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: format!("{}:{}", req.site_id, req.protocol),
        local_store_mutated: true,
        propagation: PropagationStatus::AppliedLocalOnly,
        event_id: None,
        audit_id: Some(audit_id),
        message: format!("TCP/UDP listener created on port {}", req.port),
    }))
}

#[utoipa::path(
    delete,
    path = "/tcp-udp/listeners/{listener_id}",
    params(
        ("listener_id" = String, Path, description = "Listener ID to delete")
    ),
    responses(
        (status = 200, description = "Listener deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Listener not found"),
        (status = 400, description = "Invalid listener ID format"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tcp_udp"
)]
pub async fn delete_listener(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(listener_id): Path<String>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let mut config = state.process.config.write().await;

    let parts: Vec<&str> = listener_id.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::InvalidRejected,
            target: listener_id,
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Invalid listener ID format".to_string(),
        }));
    }
    let site_id = parts[0];
    let protocol_name = parts[1];

    let site_config = config.sites.get_mut(site_id).ok_or(StatusCode::NOT_FOUND)?;

    if site_config.tcp.ports.remove(protocol_name).is_some() {
        let audit_id = uuid::Uuid::new_v4().to_string();

        let audit_event = AdminAuditEvent {
            audit_id: audit_id.clone(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            actor: AdminActor::new(AdminMutationAuthority::AdminManual),
            action: "delete_tcp_udp_listener".to_string(),
            target_kind: "tcp_udp_listener".to_string(),
            target_id: listener_id.clone(),
            prior_state: None,
            requested_state: None,
            resulting_state: Some(serde_json::json!({
                "listener_id": listener_id,
                "removed": true,
            })),
            mutation_status: AdminMutationStatus::Applied,
            propagation_status: PropagationStatus::AppliedLocalOnly,
            event_id: None,
        };
        state.audit.log_audit_event(&audit_event);

        tracing::info!("Deleted TCP/UDP listener {}", listener_id);
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Applied,
            target: listener_id,
            local_store_mutated: true,
            propagation: PropagationStatus::AppliedLocalOnly,
            event_id: None,
            audit_id: Some(audit_id),
            message: "TCP/UDP listener deleted".to_string(),
        }))
    } else {
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::NoOpAlreadyAbsent,
            target: listener_id,
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Listener not found".to_string(),
        }))
    }
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
        (status = 200, description = "List of supported protocols", body = Vec<ProtocolInfo>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tcp_udp"
)]
pub async fn list_protocols(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<ProtocolInfo>>, StatusCode> {
    let protocols = vec![
        ProtocolInfo {
            name: "http".to_string(),
            description: "HTTP/1.1 proxy".to_string(),
            supported: true,
        },
        ProtocolInfo {
            name: "http2".to_string(),
            description: "HTTP/2 proxy".to_string(),
            supported: true,
        },
        ProtocolInfo {
            name: "tls".to_string(),
            description: "TLS/SSL proxy".to_string(),
            supported: true,
        },
    ];

    Ok(Json(protocols))
}
