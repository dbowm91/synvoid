#![cfg(feature = "mesh")]

use super::super::state::AdminState;
use super::common::{OptionalAuth, PaginationQuery};
use crate::mesh::client_audit::{AuditReportResponse, ClientAuditReport};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
pub use synvoid_block_store::{BlockProvenance, BlockProvenanceKind, BlocklistEvent};
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    BlockMutationTarget, PropagationStatus,
};
use utoipa::ToSchema;

#[allow(dead_code)]
fn mesh_id_ban_sentinel_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}

#[allow(dead_code)]
fn mesh_id_ban_reason(mesh_id: &str, reason: &str) -> String {
    format!("mesh_id_ban:{mesh_id}:{reason}")
}

#[allow(dead_code)]
fn is_mesh_id_ban_reason(reason: &str, mesh_id: &str) -> bool {
    reason.starts_with(&format!("mesh_id_ban:{mesh_id}:"))
}

#[allow(dead_code)]
fn extract_mesh_id_from_ban_reason(reason: &str) -> Option<String> {
    let prefix = "mesh_id_ban:";
    if let Some(rest) = reason.strip_prefix(prefix) {
        if let Some(colon_pos) = rest.find(':') {
            return Some(rest[..colon_pos].to_string());
        }
    }
    None
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuditReportRequest {
    pub mesh_id: String,
    pub edge_node_id: String,
    pub session_id: Option<String>,
    pub timestamp: i64,
    pub pow_challenge: Option<String>,
    pub pow_nonce: Option<String>,
    pub signature: Option<String>,
    pub signed: Option<bool>,
    pub audit_results: AuditResultsDto,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuditResultsDto {
    pub success: bool,
    pub passed: bool,
    pub results: Vec<NodeProbeResultDto>,
    pub summary: AuditSummaryDto,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NodeProbeResultDto {
    #[serde(rename = "nodeUrl")]
    pub node_url: String,
    #[serde(rename = "upstreamIp")]
    pub upstream_ip: Option<String>,
    #[serde(rename = "routedToAllowedIp")]
    pub routed_to_allowed_ip: bool,
    pub node_id: Option<String>,
    pub success: bool,
    pub error: Option<String>,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuditSummaryDto {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditReportResponseDto {
    pub accepted: bool,
    pub message: String,
    pub reputation_updated: Option<f64>,
    pub quarantined: bool,
    pub quarantine_reason: Option<String>,
    pub new_pow_challenge: Option<String>,
}

impl From<AuditReportResponse> for AuditReportResponseDto {
    fn from(r: AuditReportResponse) -> Self {
        AuditReportResponseDto {
            accepted: r.accepted,
            message: r.message,
            reputation_updated: r.reputation_updated,
            quarantined: r.quarantined,
            quarantine_reason: r.quarantine_reason,
            new_pow_challenge: r.new_pow_challenge,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct MeshNodeInfo {
    pub node_id: String,
    pub role: String,
    pub address: String,
    pub ip_address: Option<String>,
    pub reputation: f64,
    pub last_seen_secs_ago: u64,
    pub connection_status: String,
    pub is_connected: bool,
    pub is_global: bool,
    pub audit_fails: u64,
    pub audit_successes: u64,
    pub audit_reputation: f64,
    pub total_requests: u64,
    pub threats_submitted: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeshNodeListResponse {
    pub nodes: Vec<MeshNodeInfo>,
    pub total: usize,
    pub global_count: usize,
    pub edge_count: usize,
    pub connected_count: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BanIpRequest {
    pub ip: String,
    pub reason: String,
    pub duration_seconds: Option<u64>,
    pub site_scope: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BanMeshIdRequest {
    pub mesh_id: String,
    pub reason: String,
    pub duration_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UnbanRequest {
    pub identifier: String,
    pub ban_type: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BanRecord {
    pub id: String,
    pub ban_type: String,
    pub identifier: String,
    pub reason: String,
    pub blocked_at: u64,
    pub expires_at: Option<u64>,
    pub is_permanent: bool,
    pub site_scope: String,
    pub provenance: String,
    pub provenance_source: Option<String>,
    #[serde(default)]
    pub is_legacy_sentinel: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BanListResponse {
    pub bans: Vec<BanRecord>,
    pub total: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeshAdminStatusResponse {
    pub is_global_node: bool,
    pub node_id: Option<String>,
    pub connected_peers: usize,
    pub global_nodes: usize,
    pub edge_nodes: usize,
    pub genesis_key_configured: bool,
    pub genesis_public_key_fingerprint: Option<String>,
    pub signing_key_derived: bool,
    pub signing_public_key: Option<String>,
    pub quic_0rtt_enabled: bool,
    pub quic_0rtt_warning: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RaftStatusResponse {
    pub node_id: u64,
    pub leader_id: Option<u64>,
    pub term: u64,
    pub last_log_index: u64,
    pub last_applied_index: u64,
    pub membership: Vec<u64>,
    pub is_leader: bool,
    pub state: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DhtStatsResponse {
    pub node_id: String,
    pub total_peers: usize,
    pub bucket_count: usize,
    pub record_count: usize,
    pub pending_announces: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeriveSigningKeyRequest {
    pub genesis_key_base64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeriveSigningKeyResponse {
    pub success: bool,
    pub signing_public_key: Option<String>,
    pub node_id: Option<String>,
    pub message: String,
}

fn extract_ip_from_address(address: &str) -> Option<String> {
    if let Some(at_pos) = address.rfind('@') {
        if let Ok(ip) = address[at_pos + 1..].parse::<IpAddr>() {
            return Some(ip.to_string());
        }
    }
    address.split(':').next().and_then(|s| {
        if s.contains('.') || s.contains(':') {
            if s.parse::<IpAddr>().is_ok() {
                Some(s.to_string())
            } else {
                None
            }
        } else {
            None
        }
    })
}

fn role_to_string(role: crate::mesh::config::MeshNodeRole) -> String {
    if role.is_global() && role.is_edge() {
        "global_edge".to_string()
    } else if role.is_global() && role.is_origin() {
        "global_origin".to_string()
    } else if role.is_edge() && role.is_origin() {
        "edge_origin".to_string()
    } else if role.is_global() {
        "global".to_string()
    } else if role.is_edge() {
        "edge".to_string()
    } else if role.is_origin() {
        "origin".to_string()
    } else {
        "unknown".to_string()
    }
}

#[utoipa::path(
    get,
    path = "/mesh/nodes",
    responses(
        (status = 200, description = "List of mesh nodes", body = MeshNodeListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn list_mesh_nodes(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<PaginationQuery>,
    _auth: OptionalAuth,
) -> Result<Json<MeshNodeListResponse>, StatusCode> {
    let (limit, offset) = query.with_defaults(100, 500);
    let mut all_nodes = Vec::new();
    let mut global_count = 0;
    let mut connected_count = 0;

    let topology_opt = state.mesh.mesh_transport.as_ref().map(|t| t.get_topology());

    if let Some(topology) = topology_opt {
        let peers = topology.get_all_peers().await;
        let now_unix = crate::utils::current_timestamp();

        for peer in peers {
            let is_connected = peer.status == crate::mesh::topology::PeerStatus::Healthy;
            let role_str = role_to_string(peer.role);

            if peer.role.is_global() {
                global_count += 1;
            }
            if is_connected {
                connected_count += 1;
            }

            let last_seen_secs_ago = now_unix.saturating_sub(peer.last_seen);
            let ip_address = extract_ip_from_address(&peer.address);

            all_nodes.push(MeshNodeInfo {
                node_id: peer.node_id.clone(),
                role: role_str,
                address: peer.address.clone(),
                ip_address,
                reputation: 60.0,
                last_seen_secs_ago,
                connection_status: format!("{:?}", peer.status),
                is_connected,
                is_global: peer.is_global,
                audit_fails: peer.audit_failures,
                audit_successes: peer.audit_successes,
                audit_reputation: peer.audit_reputation(),
                total_requests: 0,
                threats_submitted: 0,
            });
        }
    }

    let total = all_nodes.len();
    let edge_count = total.saturating_sub(global_count);

    all_nodes.sort_by(|a, b| match query.search.as_deref() {
        Some(s) if !s.is_empty() => {
            if a.node_id.contains(s) || a.address.contains(s) {
                std::cmp::Ordering::Equal
            } else {
                b.node_id.cmp(&a.node_id)
            }
        }
        _ => a.last_seen_secs_ago.cmp(&b.last_seen_secs_ago),
    });

    let nodes: Vec<MeshNodeInfo> = all_nodes.into_iter().skip(offset).take(limit).collect();

    Ok(Json(MeshNodeListResponse {
        nodes,
        total,
        global_count,
        edge_count,
        connected_count,
    }))
}

#[utoipa::path(
    get,
    path = "/mesh/nodes/{node_id}",
    params(
        ("node_id" = String, Path, description = "Node ID")
    ),
    responses(
        (status = 200, description = "Mesh node details", body = MeshNodeInfo),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Node not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn get_mesh_node(
    State(state): State<Arc<AdminState>>,
    Path(node_id): Path<String>,
    _auth: OptionalAuth,
) -> Result<Json<MeshNodeInfo>, StatusCode> {
    let topology_opt = state.mesh.mesh_transport.as_ref().map(|t| t.get_topology());

    if let Some(topology) = topology_opt {
        if let Some(peer) = topology.get_peer(&node_id).await {
            let is_connected = peer.status == crate::mesh::topology::PeerStatus::Healthy;
            let role_str = role_to_string(peer.role);

            let now_unix = crate::utils::current_timestamp();
            let last_seen_secs_ago = now_unix.saturating_sub(peer.last_seen);

            let address = peer.address.clone();
            let ip_address = extract_ip_from_address(&address);
            let audit_rep = peer.audit_reputation();

            return Ok(Json(MeshNodeInfo {
                node_id: peer.node_id,
                role: role_str,
                address,
                ip_address,
                reputation: 60.0,
                last_seen_secs_ago,
                connection_status: format!("{:?}", peer.status),
                is_connected,
                is_global: peer.is_global,
                audit_fails: peer.audit_failures,
                audit_successes: peer.audit_successes,
                audit_reputation: audit_rep,
                total_requests: 0,
                threats_submitted: 0,
            }));
        }
    }

    Err(StatusCode::NOT_FOUND)
}

#[utoipa::path(
    post,
    path = "/mesh/ban/ip",
    request_body = BanIpRequest,
    responses(
        (status = 200, description = "IP banned successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid IP address"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn ban_ip(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(payload): Json<BanIpRequest>,
) -> Result<Json<AdminMutationResult<BlockMutationTarget>>, StatusCode> {
    let ip: IpAddr = payload.ip.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let reason = if payload.reason.is_empty() {
        "manual_admin_ban".to_string()
    } else {
        payload.reason
    };
    let duration = payload.duration_seconds.unwrap_or(0);
    let site_scope = payload.site_scope.unwrap_or_else(|| "global".to_string());

    if let Some(transport) = &state.mesh.mesh_transport {
        if let Some(threat_intel) = transport.get_threat_intel() {
            let block_store = threat_intel.get_block_store();

            if block_store.block_ip_with_provenance(
                ip,
                &reason,
                duration,
                &site_scope,
                BlockProvenance {
                    kind: BlockProvenanceKind::AdminManual,
                    source: Some("admin_ban_ip".to_string()),
                },
            ) {
                tracing::info!(
                    "Admin banned IP {} for {} seconds (reason: {})",
                    ip,
                    duration,
                    reason
                );

                let mut event = BlocklistEvent::block_ip(
                    &ip.to_string(),
                    &reason,
                    &site_scope,
                    BlockProvenance {
                        kind: BlockProvenanceKind::AdminManual,
                        source: Some("admin_ban_ip".to_string()),
                    },
                    synvoid_utils::safe_unix_timestamp(),
                );
                let event_id = event.generate_event_id();
                event = event.with_event_id(event_id.clone());
                tracing::debug!(target: "blocklist_event", ?event, "Block event emitted");

                let audit_id = uuid::Uuid::new_v4().to_string();

                let audit_event = AdminAuditEvent {
                    audit_id: audit_id.clone(),
                    timestamp: synvoid_utils::safe_unix_timestamp(),
                    actor: AdminActor::new(AdminMutationAuthority::AdminManual),
                    action: "block_ip".to_string(),
                    target_kind: "ip".to_string(),
                    target_id: ip.to_string(),
                    prior_state: None,
                    requested_state: Some(serde_json::json!({
                        "ip": ip.to_string(),
                        "reason": reason,
                        "duration_seconds": duration,
                        "site_scope": site_scope,
                    })),
                    resulting_state: Some(serde_json::json!({
                        "ip": ip.to_string(),
                        "reason": reason,
                        "duration_seconds": duration,
                        "site_scope": site_scope,
                        "is_permanent": duration == 0,
                    })),
                    mutation_status: AdminMutationStatus::Applied,
                    propagation_status: PropagationStatus::QueuedBestEffort,
                    event_id: Some(event_id.clone()),
                };
                state.audit.log_audit_event(&audit_event);

                threat_intel.announce_local_block(ip, reason.clone(), duration, site_scope.clone());

                // Iteration 50: Broadcast block event to workers so they preserve original provenance
                if let Some(ref pm) = state.process.process_manager {
                    let event_json = serde_json::to_string(&event).unwrap_or_default();
                    let pm = pm.clone();
                    let event_id_clone = event_id.clone();
                    tokio::spawn(async move {
                        pm.broadcast_blocklist_event(
                            event_json,
                            "admin_ban_ip".to_string(),
                            event_id_clone,
                        )
                        .await;
                    });
                }

                return Ok(Json(AdminMutationResult {
                    status: AdminMutationStatus::Applied,
                    target: BlockMutationTarget {
                        kind: "ip".to_string(),
                        value: ip.to_string(),
                        site_scope: Some(site_scope),
                    },
                    local_store_mutated: true,
                    propagation: PropagationStatus::QueuedBestEffort,
                    event_id: Some(event_id),
                    audit_id: Some(audit_id),
                    message: format!("IP {} banned successfully", ip),
                }));
            } else {
                return Ok(Json(AdminMutationResult {
                    status: AdminMutationStatus::Failed,
                    target: BlockMutationTarget {
                        kind: "ip".to_string(),
                        value: ip.to_string(),
                        site_scope: Some(site_scope),
                    },
                    local_store_mutated: false,
                    propagation: PropagationStatus::NotApplicable,
                    event_id: None,
                    audit_id: None,
                    message: "Failed to apply block".to_string(),
                }));
            }
        }
    }

    Err(StatusCode::INTERNAL_SERVER_ERROR)
}

#[utoipa::path(
    post,
    path = "/mesh/ban/mesh-id",
    request_body = BanMeshIdRequest,
    responses(
        (status = 200, description = "Mesh ID banned successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn ban_mesh_id(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(payload): Json<BanMeshIdRequest>,
) -> Result<Json<AdminMutationResult<BlockMutationTarget>>, StatusCode> {
    let mesh_id = payload.mesh_id;
    let reason = if payload.reason.is_empty() {
        "manual_admin_ban".to_string()
    } else {
        payload.reason
    };
    let duration = payload.duration_seconds.unwrap_or(0);

    if let Some(transport) = &state.mesh.mesh_transport {
        if let Some(threat_intel) = transport.get_threat_intel() {
            let block_store = threat_intel.get_block_store();

            let blocked = block_store.block_mesh_id_with_provenance(
                &mesh_id,
                &reason,
                duration,
                "global",
                BlockProvenance {
                    kind: BlockProvenanceKind::AdminManual,
                    source: Some("admin_ban_mesh_id".to_string()),
                },
            );

            if blocked || duration == 0 {
                tracing::info!(
                    "Admin banned mesh_id {} for {} seconds (reason: {})",
                    mesh_id,
                    duration,
                    reason
                );

                let mut event = BlocklistEvent::block_mesh_id(
                    &mesh_id,
                    &reason,
                    "global",
                    BlockProvenance {
                        kind: BlockProvenanceKind::AdminManual,
                        source: Some("admin_ban_mesh_id".to_string()),
                    },
                    synvoid_utils::safe_unix_timestamp(),
                );
                let event_id = event.generate_event_id();
                event = event.with_event_id(event_id.clone());
                tracing::debug!(target: "blocklist_event", ?event, "Block event emitted");

                let audit_id = uuid::Uuid::new_v4().to_string();

                let audit_event = AdminAuditEvent {
                    audit_id: audit_id.clone(),
                    timestamp: synvoid_utils::safe_unix_timestamp(),
                    actor: AdminActor::new(AdminMutationAuthority::AdminManual),
                    action: "block_mesh_id".to_string(),
                    target_kind: "mesh_id".to_string(),
                    target_id: mesh_id.to_string(),
                    prior_state: None,
                    requested_state: Some(serde_json::json!({
                        "mesh_id": mesh_id,
                        "reason": reason,
                        "duration_seconds": duration,
                        "site_scope": "global",
                    })),
                    resulting_state: Some(serde_json::json!({
                        "mesh_id": mesh_id,
                        "reason": reason,
                        "duration_seconds": duration,
                        "site_scope": "global",
                        "is_permanent": duration == 0,
                    })),
                    mutation_status: AdminMutationStatus::Applied,
                    propagation_status: PropagationStatus::QueuedBestEffort,
                    event_id: Some(event_id.clone()),
                };
                state.audit.log_audit_event(&audit_event);

                // Iteration 50: Broadcast block event to workers so they preserve original provenance
                if let Some(ref pm) = state.process.process_manager {
                    let event_json = serde_json::to_string(&event).unwrap_or_default();
                    let pm = pm.clone();
                    let event_id_clone = event_id.clone();
                    tokio::spawn(async move {
                        pm.broadcast_blocklist_event(
                            event_json,
                            "admin_ban_mesh_id".to_string(),
                            event_id_clone,
                        )
                        .await;
                    });
                }

                return Ok(Json(AdminMutationResult {
                    status: AdminMutationStatus::Applied,
                    target: BlockMutationTarget {
                        kind: "mesh_id".to_string(),
                        value: mesh_id.clone(),
                        site_scope: Some("global".to_string()),
                    },
                    local_store_mutated: true,
                    propagation: PropagationStatus::QueuedBestEffort,
                    event_id: Some(event_id),
                    audit_id: Some(audit_id),
                    message: format!("Mesh ID {} banned successfully", mesh_id),
                }));
            }

            return Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::Failed,
                target: BlockMutationTarget {
                    kind: "mesh_id".to_string(),
                    value: mesh_id,
                    site_scope: Some("global".to_string()),
                },
                local_store_mutated: false,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: "Failed to apply mesh ID block".to_string(),
            }));
        }
    }

    Err(StatusCode::INTERNAL_SERVER_ERROR)
}

#[utoipa::path(
    delete,
    path = "/mesh/ban",
    params(
        ("identifier" = String, Query, description = "IP address or mesh ID to unban"),
        ("ban_type" = String, Query, description = "Type of ban: 'ip' or 'mesh_id'")
    ),
    responses(
        (status = 200, description = "Unbanned successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn unban(
    State(state): State<Arc<AdminState>>,
    Query(params): Query<UnbanRequest>,
    _auth: OptionalAuth,
) -> Result<Json<AdminMutationResult<BlockMutationTarget>>, StatusCode> {
    let identifier = params.identifier;
    let ban_type = params.ban_type;

    if let Some(transport) = &state.mesh.mesh_transport {
        if let Some(threat_intel) = transport.get_threat_intel() {
            let block_store = threat_intel.get_block_store();

            match ban_type.as_str() {
                "ip" => {
                    if let Ok(ip) = identifier.parse::<IpAddr>() {
                        if block_store.unblock_ip(&ip, "global") {
                            tracing::info!("Admin unbanned IP {}", ip);
                            let mut event = BlocklistEvent::unblock_ip(
                                &ip.to_string(),
                                "global",
                                BlockProvenance {
                                    kind: BlockProvenanceKind::AdminManual,
                                    source: Some("admin_unban_ip".to_string()),
                                },
                                synvoid_utils::safe_unix_timestamp(),
                            );
                            let event_id = event.generate_event_id();
                            event = event.with_event_id(event_id.clone());
                            tracing::debug!(target: "blocklist_event", ?event, "Unblock event emitted");

                            let audit_id = uuid::Uuid::new_v4().to_string();

                            let audit_event = AdminAuditEvent {
                                audit_id: audit_id.clone(),
                                timestamp: synvoid_utils::safe_unix_timestamp(),
                                actor: AdminActor::new(AdminMutationAuthority::AdminManual),
                                action: "unblock_ip".to_string(),
                                target_kind: "ip".to_string(),
                                target_id: ip.to_string(),
                                prior_state: None,
                                requested_state: None,
                                resulting_state: Some(serde_json::json!({
                                    "ip": ip.to_string(),
                                    "site_scope": "global",
                                    "removed": true,
                                })),
                                mutation_status: AdminMutationStatus::Applied,
                                propagation_status: PropagationStatus::QueuedBestEffort,
                                event_id: Some(event_id.clone()),
                            };
                            state.audit.log_audit_event(&audit_event);

                            threat_intel.announce_local_unblock(
                                synvoid_core::block_store::BlockTargetKind::Ip,
                                &ip.to_string(),
                                "global",
                                BlockProvenance {
                                    kind: BlockProvenanceKind::AdminManual,
                                    source: Some("admin_unban_ip".to_string()),
                                },
                            );
                            if let Some(ref pm) = state.process.process_manager {
                                let event_json = serde_json::to_string(&event).unwrap_or_default();
                                let pm = pm.clone();
                                let event_id_clone = event_id.clone();
                                tokio::spawn(async move {
                                    pm.broadcast_blocklist_event(
                                        event_json,
                                        "admin_unban_ip".to_string(),
                                        event_id_clone,
                                    )
                                    .await;
                                });
                            }
                            return Ok(Json(AdminMutationResult {
                                status: AdminMutationStatus::Applied,
                                target: BlockMutationTarget {
                                    kind: "ip".to_string(),
                                    value: ip.to_string(),
                                    site_scope: Some("global".to_string()),
                                },
                                local_store_mutated: true,
                                propagation: PropagationStatus::QueuedBestEffort,
                                event_id: Some(event_id),
                                audit_id: Some(audit_id),
                                message: format!("IP {} unbanned successfully", ip),
                            }));
                        }
                    }
                    return Ok(Json(AdminMutationResult {
                        status: AdminMutationStatus::NoOpAlreadyAbsent,
                        target: BlockMutationTarget {
                            kind: "ip".to_string(),
                            value: identifier.clone(),
                            site_scope: Some("global".to_string()),
                        },
                        local_store_mutated: false,
                        propagation: PropagationStatus::NotApplicable,
                        event_id: None,
                        audit_id: None,
                        message: format!("IP {} was not blocked", identifier),
                    }));
                }
                "mesh_id" => {
                    if block_store.unblock_mesh_id(&identifier, "global") {
                        tracing::info!("Admin unbanned mesh_id {}", identifier);
                        let mut event = BlocklistEvent::unblock_mesh_id(
                            &identifier,
                            "global",
                            BlockProvenance {
                                kind: BlockProvenanceKind::AdminManual,
                                source: Some("admin_unban_mesh_id".to_string()),
                            },
                            synvoid_utils::safe_unix_timestamp(),
                        );
                        let event_id = event.generate_event_id();
                        event = event.with_event_id(event_id.clone());
                        tracing::debug!(target: "blocklist_event", ?event, "Unblock event emitted");

                        let audit_id = uuid::Uuid::new_v4().to_string();

                        let audit_event = AdminAuditEvent {
                            audit_id: audit_id.clone(),
                            timestamp: synvoid_utils::safe_unix_timestamp(),
                            actor: AdminActor::new(AdminMutationAuthority::AdminManual),
                            action: "unblock_mesh_id".to_string(),
                            target_kind: "mesh_id".to_string(),
                            target_id: identifier.clone(),
                            prior_state: None,
                            requested_state: None,
                            resulting_state: Some(serde_json::json!({
                                "mesh_id": identifier,
                                "site_scope": "global",
                                "removed": true,
                            })),
                            mutation_status: AdminMutationStatus::Applied,
                            propagation_status: PropagationStatus::QueuedBestEffort,
                            event_id: Some(event_id.clone()),
                        };
                        state.audit.log_audit_event(&audit_event);

                        threat_intel.announce_local_unblock(
                            synvoid_core::block_store::BlockTargetKind::MeshId,
                            &identifier,
                            "global",
                            BlockProvenance {
                                kind: BlockProvenanceKind::AdminManual,
                                source: Some("admin_unban_mesh_id".to_string()),
                            },
                        );
                        if let Some(ref pm) = state.process.process_manager {
                            let event_json = serde_json::to_string(&event).unwrap_or_default();
                            let pm = pm.clone();
                            let event_id_clone = event_id.clone();
                            tokio::spawn(async move {
                                pm.broadcast_blocklist_event(
                                    event_json,
                                    "admin_unban_mesh_id".to_string(),
                                    event_id_clone,
                                )
                                .await;
                            });
                        }
                        return Ok(Json(AdminMutationResult {
                            status: AdminMutationStatus::Applied,
                            target: BlockMutationTarget {
                                kind: "mesh_id".to_string(),
                                value: identifier.clone(),
                                site_scope: Some("global".to_string()),
                            },
                            local_store_mutated: true,
                            propagation: PropagationStatus::QueuedBestEffort,
                            event_id: Some(event_id),
                            audit_id: Some(audit_id),
                            message: format!("Mesh ID {} unbanned successfully", identifier),
                        }));
                    }
                    return Ok(Json(AdminMutationResult {
                        status: AdminMutationStatus::NoOpAlreadyAbsent,
                        target: BlockMutationTarget {
                            kind: "mesh_id".to_string(),
                            value: identifier.clone(),
                            site_scope: Some("global".to_string()),
                        },
                        local_store_mutated: false,
                        propagation: PropagationStatus::NotApplicable,
                        event_id: None,
                        audit_id: None,
                        message: format!("Mesh ID {} was not blocked", identifier),
                    }));
                }
                _ => {
                    return Ok(Json(AdminMutationResult {
                        status: AdminMutationStatus::InvalidRejected,
                        target: BlockMutationTarget {
                            kind: "unknown".to_string(),
                            value: identifier,
                            site_scope: None,
                        },
                        local_store_mutated: false,
                        propagation: PropagationStatus::NotApplicable,
                        event_id: None,
                        audit_id: None,
                        message: format!("Invalid ban_type: {}", ban_type),
                    }));
                }
            }
        }
    }

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Failed,
        target: BlockMutationTarget {
            kind: "unknown".to_string(),
            value: identifier,
            site_scope: None,
        },
        local_store_mutated: false,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: None,
        message: "Block store not available".to_string(),
    }))
}

#[utoipa::path(
    get,
    path = "/mesh/bans",
    responses(
        (status = 200, description = "List of bans", body = BanListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn list_bans(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<PaginationQuery>,
    _auth: OptionalAuth,
) -> Result<Json<BanListResponse>, StatusCode> {
    let (limit, offset) = query.with_defaults(100, 500);
    let mut bans = Vec::new();

    if let Some(transport) = &state.mesh.mesh_transport {
        if let Some(threat_intel) = transport.get_threat_intel() {
            let block_store = threat_intel.get_block_store();
            let records = block_store.get_all_block_records();

            for record in records {
                let is_permanent = record.ban_expire_seconds == 0;
                let expires_at = if is_permanent {
                    None
                } else {
                    Some(record.blocked_at + record.ban_expire_seconds)
                };

                let (ban_type, id) = match record.target_kind {
                    synvoid_block_store::BlockTargetKind::Ip => {
                        ("ip".to_string(), record.identifier.clone())
                    }
                    synvoid_block_store::BlockTargetKind::MeshId => (
                        "mesh_id".to_string(),
                        format!("mesh_id:{}", record.identifier),
                    ),
                };

                bans.push(BanRecord {
                    id,
                    ban_type,
                    identifier: record.identifier,
                    reason: record.reason,
                    blocked_at: record.blocked_at,
                    expires_at,
                    is_permanent,
                    site_scope: record.site_scope,
                    provenance: format!("{:?}", record.provenance.kind),
                    provenance_source: record.provenance.source,
                    is_legacy_sentinel: false,
                });
            }
        }
    }

    let total = bans.len();

    bans.sort_by_key(|b| std::cmp::Reverse(b.blocked_at));

    let bans: Vec<BanRecord> = bans.into_iter().skip(offset).take(limit).collect();

    Ok(Json(BanListResponse { bans, total }))
}

#[utoipa::path(
    get,
    path = "/mesh/status",
    responses(
        (status = 200, description = "Mesh status", body = MeshAdminStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn get_mesh_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MeshAdminStatusResponse>, StatusCode> {
    let mut is_global_node = false;
    let mut node_id = None;
    let mut connected_peers = 0;
    let mut global_nodes = 0;
    let mut edge_nodes = 0;
    let mut genesis_key_configured = false;
    let mut genesis_public_key_fingerprint = None;
    let mut signing_key_derived = false;
    let mut signing_public_key = None;
    let mut quic_0rtt_enabled = false;
    let mut quic_0rtt_warning = None;

    if let Some(transport) = &state.mesh.mesh_transport {
        is_global_node = transport.is_global_node();
        node_id = transport.get_node_mesh_id();
        connected_peers = transport.connected_peer_count();

        let topology = transport.get_topology();
        let peers = topology.get_all_peers().await;

        for peer in peers {
            if peer.role.is_global() {
                global_nodes += 1;
            } else {
                edge_nodes += 1;
            }
        }

        let config = transport.get_mesh_config();
        genesis_key_configured = config.has_genesis_key();
        signing_key_derived = config.has_signing_key();
        quic_0rtt_enabled = config.tls.quic_enable_0rtt;

        if quic_0rtt_enabled {
            quic_0rtt_warning = Some(
                "QUIC 0-RTT is enabled. 0-RTT is susceptible to replay attacks. \
                Only enable if you understand the risks and have mitigated replay at the application layer."
                    .to_string(),
            );
        }

        if let Some(ref pk) = config.signing_public_key() {
            signing_public_key = Some(format!("{}...", &pk[..16.min(pk.len())]));
        }

        if let Some(genesis) = config.genesis_key() {
            if let Some(ref genesis_pk) = genesis.get_public_key() {
                let mut hasher = Sha256::new();
                hasher.update(genesis_pk.as_bytes());
                let result = hasher.finalize();
                genesis_public_key_fingerprint =
                    Some(format!("sha256:{}...", hex::encode(&result[..8])));
            }
        }
    }

    Ok(Json(MeshAdminStatusResponse {
        is_global_node,
        node_id,
        connected_peers,
        global_nodes,
        edge_nodes,
        genesis_key_configured,
        genesis_public_key_fingerprint,
        signing_key_derived,
        signing_public_key,
        quic_0rtt_enabled,
        quic_0rtt_warning,
    }))
}

#[utoipa::path(
    post,
    path = "/mesh/derive-signing-key",
    request_body = DeriveSigningKeyRequest,
    responses(
        (status = 200, description = "Signing key derived"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn derive_signing_key(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<DeriveSigningKeyRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    use base64::Engine;

    let genesis_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.genesis_key_base64)
        .map_err(|e| {
            tracing::warn!("Invalid genesis key base64: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if genesis_bytes.len() != 32 {
        return Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::InvalidRejected,
            target: "signing_key".to_string(),
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Genesis key must be 32 bytes".to_string(),
        }));
    }

    let mut genesis_key = [0u8; 32];
    genesis_key.copy_from_slice(&genesis_bytes);

    let public_key = crate::mesh::cert::get_ed25519_public_key(&genesis_key).ok_or_else(|| {
        tracing::warn!("Failed to derive public key from genesis key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut node_identity = crate::mesh::NodeIdentityConfig::default();
    if let Err(e) = node_identity.derive_signing_key_from_genesis(&genesis_key, &public_key) {
        return Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Failed,
            target: "signing_key".to_string(),
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: format!("Failed to derive signing key: {}", e),
        }));
    }

    let node_id = node_identity.node_id.clone();

    let audit_id = uuid::Uuid::new_v4().to_string();

    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "derive_signing_key".to_string(),
        target_kind: "signing_key".to_string(),
        target_id: "genesis".to_string(),
        prior_state: None,
        requested_state: Some(serde_json::json!({
            "genesis_key_base64": req.genesis_key_base64,
        })),
        resulting_state: Some(serde_json::json!({
            "signing_public_key_derived": true,
            "node_id": node_id,
        })),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::AppliedLocalOnly,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "signing_key".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::AppliedLocalOnly,
        event_id: None,
        audit_id: Some(audit_id),
        message: format!(
            "Signing key derived successfully.\n\
             Add the following to your config/main.toml to use this genesis key:\n\n\
             [mesh.node_identity]\n\
             genesis_key_base64 = \"{}\"\n\n\
             Then restart the node to start as a global node.",
            req.genesis_key_base64
        ),
    }))
}

#[utoipa::path(
    post,
    path = "/mesh/audit/report",
    request_body = AuditReportRequest,
    responses(
        (status = 200, description = "Audit report submitted"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn submit_audit_report(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<AuditReportRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let mesh_id_for_audit = req.mesh_id.clone();
    let edge_node_id_for_audit = req.edge_node_id.clone();

    let report = ClientAuditReport {
        mesh_id: req.mesh_id,
        edge_node_id: req.edge_node_id,
        session_id: req.session_id,
        timestamp: req.timestamp,
        pow_challenge: req.pow_challenge,
        pow_nonce: req.pow_nonce,
        signature: req.signature,
        signed: req.signed,
        audit_results: crate::mesh::client_audit::AuditResults {
            success: req.audit_results.success,
            passed: req.audit_results.passed,
            results: req
                .audit_results
                .results
                .into_iter()
                .map(|r| crate::mesh::client_audit::NodeProbeResult {
                    node_url: r.node_url,
                    upstream_ip: r.upstream_ip,
                    routed_to_allowed_ip: r.routed_to_allowed_ip,
                    node_id: r.node_id,
                    success: r.success,
                    error: r.error,
                    latency_ms: r.latency_ms,
                })
                .collect(),
            summary: crate::mesh::client_audit::AuditSummary {
                total: req.audit_results.summary.total,
                passed: req.audit_results.summary.passed,
                failed: req.audit_results.summary.failed,
                timestamp: req.audit_results.summary.timestamp,
            },
        },
    };

    if let Some(ref manager) = state.mesh.client_audit_manager {
        let response = manager.process_audit_report(report).await;
        let audit_id = uuid::Uuid::new_v4().to_string();

        let audit_event = AdminAuditEvent {
            audit_id: audit_id.clone(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            actor: AdminActor::new(AdminMutationAuthority::AdminManual),
            action: "submit_audit_report".to_string(),
            target_kind: "audit_report".to_string(),
            target_id: response.message.clone(),
            prior_state: None,
            requested_state: Some(serde_json::json!({
                "mesh_id": mesh_id_for_audit,
                "edge_node_id": edge_node_id_for_audit,
            })),
            resulting_state: Some(serde_json::json!({
                "accepted": response.accepted,
                "reputation_updated": response.reputation_updated,
                "quarantined": response.quarantined,
            })),
            mutation_status: if response.accepted {
                AdminMutationStatus::Applied
            } else {
                AdminMutationStatus::Failed
            },
            propagation_status: PropagationStatus::AppliedLocalOnly,
            event_id: None,
        };
        state.audit.log_audit_event(&audit_event);

        Ok(Json(AdminMutationResult {
            status: if response.accepted {
                AdminMutationStatus::Applied
            } else {
                AdminMutationStatus::Failed
            },
            target: mesh_id_for_audit.clone(),
            local_store_mutated: response.accepted,
            propagation: PropagationStatus::AppliedLocalOnly,
            event_id: None,
            audit_id: Some(audit_id),
            message: response.message,
        }))
    } else {
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Failed,
            target: mesh_id_for_audit,
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Audit manager not configured".to_string(),
        }))
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BlocklistCatchupStatsResponse {
    pub event_log_count: usize,
    pub oldest_timestamp: Option<u64>,
    pub newest_timestamp: Option<u64>,
    pub next_sequence: u64,
    pub ipc_event_log_count: usize,
    pub ipc_oldest_timestamp: Option<u64>,
    pub ipc_newest_timestamp: Option<u64>,
    pub ipc_next_sequence: u64,
    pub peer_cursor_count: usize,
    pub peer_cursor_oldest_update: Option<u64>,
    pub peer_cursor_newest_update: Option<u64>,
    pub cursor_persistence_enabled: bool,
    pub event_log_capacity: usize,
}

#[utoipa::path(
    get,
    path = "/mesh/blocklist/catchup-stats",
    responses(
        (status = 200, description = "Blocklist catchup statistics", body = BlocklistCatchupStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn get_blocklist_catchup_stats(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BlocklistCatchupStatsResponse>, StatusCode> {
    let mut event_log_count = 0usize;
    let mut oldest_timestamp = None;
    let mut newest_timestamp = None;
    let mut next_sequence = 0u64;
    let mut peer_cursor_count = 0usize;
    let mut peer_cursor_oldest_update = None;
    let mut peer_cursor_newest_update = None;
    let mut cursor_persistence_enabled = false;
    let mut event_log_capacity = 0usize;

    if let Some(transport) = &state.mesh.mesh_transport {
        if let Some(threat_intel) = transport.get_threat_intel() {
            let block_store = threat_intel.get_block_store();
            let (count, oldest, newest, seq) = block_store.event_log_stats();
            event_log_count = count;
            oldest_timestamp = oldest;
            newest_timestamp = newest;
            next_sequence = seq;
            peer_cursor_count = block_store.peer_cursor_count();
            let (pc_oldest, pc_newest) = block_store.peer_cursor_timestamp_range();
            peer_cursor_oldest_update = pc_oldest;
            peer_cursor_newest_update = pc_newest;
            cursor_persistence_enabled = block_store.has_cursor_persistence();
            event_log_capacity = block_store.event_log_capacity();
        }
    }

    let mut ipc_event_log_count = 0usize;
    let mut ipc_oldest_timestamp = None;
    let mut ipc_newest_timestamp = None;
    let mut ipc_next_sequence = 0u64;

    if let Some(ref pm) = state.process.process_manager {
        let ipc_stats = pm.blocklist_event_log_stats();
        ipc_event_log_count = ipc_stats.0;
        ipc_oldest_timestamp = ipc_stats.1;
        ipc_newest_timestamp = ipc_stats.2;
        ipc_next_sequence = ipc_stats.3;
    }

    Ok(Json(BlocklistCatchupStatsResponse {
        event_log_count,
        oldest_timestamp,
        newest_timestamp,
        next_sequence,
        ipc_event_log_count,
        ipc_oldest_timestamp,
        ipc_newest_timestamp,
        ipc_next_sequence,
        peer_cursor_count,
        peer_cursor_oldest_update,
        peer_cursor_newest_update,
        cursor_persistence_enabled,
        event_log_capacity,
    }))
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct SignatureFailureReport {
    pub timestamp: i64,
    pub session_id: Option<String>,
    pub path: Option<String>,
    pub expected_signature: Option<String>,
    pub actual_signature: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub mesh_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SignatureFailureResponse {
    pub accepted: bool,
    pub message: String,
    pub action_taken: Option<String>,
}

#[utoipa::path(
    post,
    path = "/mesh/report/signature-failure",
    request_body = SignatureFailureReport,
    responses(
        (status = 200, description = "Signature failure reported"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn report_signature_failure(
    State(state): State<Arc<AdminState>>,
    Json(report): Json<SignatureFailureReport>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let session_id_hash = report.session_id.as_deref().map(|sid| {
        format!(
            "sha256:{}",
            &hex::encode(Sha256::digest(sid.as_bytes()))[..16]
        )
    });

    tracing::warn!(
        "Signature failure reported: session_id={}, path={}, mesh_id={}",
        session_id_hash.as_deref().unwrap_or("unknown"),
        report.path.as_deref().unwrap_or("unknown"),
        report.mesh_id.as_deref().unwrap_or("unknown")
    );

    if let Some(ref _manager) = state.mesh.client_audit_manager {
        if let Some(ref hash) = session_id_hash {
            tracing::info!("Recording signature failure for session: {}", hash);
        }
    }

    let audit_id = uuid::Uuid::new_v4().to_string();

    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "report_signature_failure".to_string(),
        target_kind: "signature_failure".to_string(),
        target_id: report
            .mesh_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        prior_state: None,
        requested_state: None,
        resulting_state: Some(serde_json::json!({
            "session_id_hash": session_id_hash,
            "path": report.path,
            "mesh_id": report.mesh_id,
        })),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::AppliedLocalOnly,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: report.mesh_id.unwrap_or_else(|| "unknown".to_string()),
        local_store_mutated: false,
        propagation: PropagationStatus::AppliedLocalOnly,
        event_id: None,
        audit_id: Some(audit_id),
        message: "Signature failure recorded".to_string(),
    }))
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AttestCapabilityRequest {
    pub node_id: String,
    pub capability: String,
}

#[utoipa::path(
    post,
    path = "/mesh/attest-capability",
    request_body = AttestCapabilityRequest,
    responses(
        (status = 200, description = "Capability attested successfully"),
        (status = 400, description = "Failed to attest capability"),
        (status = 500, description = "Internal error")
    ),
    tag = "mesh",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn attest_capability(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(payload): Json<AttestCapabilityRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let config = state.process.config.read().await;
    let is_global = config
        .main
        .mesh
        .as_ref()
        .map(|m| m.role.is_global())
        .unwrap_or(false);
    if !is_global {
        return Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::UnauthorizedRejected,
            target: payload.node_id.clone(),
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Only global nodes can attest capabilities".to_string(),
        }));
    }

    if let Some(transport) = &state.mesh.mesh_transport {
        let audit_id = uuid::Uuid::new_v4().to_string();
        match transport
            .attest_capability(&payload.node_id, &payload.capability)
            .await
        {
            Some(_) => {
                let audit_event = AdminAuditEvent {
                    audit_id: audit_id.clone(),
                    timestamp: synvoid_utils::safe_unix_timestamp(),
                    actor: AdminActor::new(AdminMutationAuthority::AdminManual),
                    action: "mesh.attest_capability".to_string(),
                    target_kind: "node".to_string(),
                    target_id: payload.node_id.clone(),
                    prior_state: None,
                    requested_state: Some(serde_json::json!({
                        "node_id": payload.node_id,
                        "capability": payload.capability,
                    })),
                    resulting_state: Some(serde_json::json!({
                        "attested": true,
                    })),
                    mutation_status: AdminMutationStatus::Applied,
                    propagation_status: PropagationStatus::QueuedBestEffort,
                    event_id: None,
                };
                state.audit.log_audit_event(&audit_event);
                Ok(Json(AdminMutationResult {
                    status: AdminMutationStatus::Applied,
                    target: payload.node_id,
                    local_store_mutated: true,
                    propagation: PropagationStatus::QueuedBestEffort,
                    event_id: None,
                    audit_id: Some(audit_id),
                    message: "Capability attested successfully".to_string(),
                }))
            }
            None => Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::Failed,
                target: payload.node_id,
                local_store_mutated: false,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: "Attestation failed (check logs for reason)".to_string(),
            })),
        }
    } else {
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Failed,
            target: payload.node_id,
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Mesh transport not initialized".to_string(),
        }))
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOrgRequest {
    pub org_id: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrgResponse {
    pub org_id: String,
    pub name: Option<String>,
    pub public_key: String,
    pub created_at: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrgPublicKeyResponse {
    pub org_id: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub created_at: u64,
    pub quorum_signatures_count: usize,
}

#[utoipa::path(
    post,
    path = "/mesh/organizations",
    request_body = CreateOrgRequest,
    responses(
        (status = 200, description = "Organization created"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal error")
    ),
    tag = "mesh",
    security(("bearerAuth" = []))
)]
pub async fn create_organization(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(payload): Json<CreateOrgRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let mgr = state
        .mesh
        .org_key_manager
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let org = mgr
        .create_organization(payload.org_id, payload.name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let pub_key_hex = org
        .org_key
        .as_ref()
        .map(|k| k.public_key_hex())
        .unwrap_or_default();

    let audit_id = uuid::Uuid::new_v4().to_string();

    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "create_organization".to_string(),
        target_kind: "organization".to_string(),
        target_id: org.org_id.clone(),
        prior_state: None,
        requested_state: Some(serde_json::json!({
            "org_id": org.org_id,
            "name": org.name,
        })),
        resulting_state: Some(serde_json::json!({
            "org_id": org.org_id,
            "name": org.name,
            "public_key_derived": !pub_key_hex.is_empty(),
        })),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::AppliedLocalOnly,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: org.org_id,
        local_store_mutated: true,
        propagation: PropagationStatus::AppliedLocalOnly,
        event_id: None,
        audit_id: Some(audit_id),
        message: format!(
            "Organization created with public key: {}...",
            &pub_key_hex[..pub_key_hex.len().min(16)]
        ),
    }))
}

#[utoipa::path(
    get,
    path = "/mesh/organizations/{org_id}",
    responses(
        (status = 200, description = "Organization details", body = OrgResponse),
        (status = 404, description = "Organization not found")
    ),
    tag = "mesh",
    security(("bearerAuth" = []))
)]
pub async fn get_organization(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(org_id): Path<String>,
) -> Result<Json<OrgResponse>, StatusCode> {
    let mgr = state
        .mesh
        .org_key_manager
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let org = mgr
        .get_local_organization(&org_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    let pub_key_hex = org
        .org_key
        .as_ref()
        .map(|k| k.public_key_hex())
        .unwrap_or_default();

    Ok(Json(OrgResponse {
        org_id: org.org_id,
        name: org.name,
        public_key: pub_key_hex,
        created_at: org.created_at,
    }))
}

#[utoipa::path(
    get,
    path = "/mesh/organizations/{org_id}/public-key",
    responses(
        (status = 200, description = "Organization public key from DHT", body = OrgPublicKeyResponse),
        (status = 404, description = "Key not found")
    ),
    tag = "mesh",
    security(("bearerAuth" = []))
)]
pub async fn get_org_public_key(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(org_id): Path<String>,
) -> Result<Json<OrgPublicKeyResponse>, StatusCode> {
    let mgr = state
        .mesh
        .org_key_manager
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // Attempt sync first
    let _ = mgr.sync_from_dht().await;

    let pub_key = mgr
        .get_org_public_key(&org_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(OrgPublicKeyResponse {
        org_id: pub_key.org_id,
        key_id: pub_key.key_id,
        public_key_hex: hex::encode(&pub_key.public_key),
        created_at: pub_key.created_at,
        quorum_signatures_count: pub_key.quorum_signatures.len(),
    }))
}

#[utoipa::path(
    get,
    path = "/v1/mesh/raft/status",
    responses(
        (status = 200, description = "Raft status", body = RaftStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn get_raft_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<RaftStatusResponse>, StatusCode> {
    let Some(transport) = &state.mesh.mesh_transport else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };

    let raft_lock = transport.get_raft_instance();
    let instance = {
        let raft_guard = raft_lock.read();
        match raft_guard.as_ref() {
            Some(i) => i.clone(),
            None => return Err(StatusCode::SERVICE_UNAVAILABLE),
        }
    };

    let is_leader = instance.is_leader().await;
    let leader_id = instance.get_leader_id().await;
    let node_id = instance.node_id();

    Ok(Json(RaftStatusResponse {
        node_id,
        leader_id,
        term: 0,
        last_log_index: 0,
        last_applied_index: 0,
        membership: vec![],
        is_leader,
        state: "Active".to_string(),
    }))
}

#[utoipa::path(
    get,
    path = "/v1/mesh/dht/stats",
    responses(
        (status = 200, description = "DHT statistics", body = DhtStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn get_dht_stats(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<DhtStatsResponse>, StatusCode> {
    if let Some(transport) = &state.mesh.mesh_transport {
        if let Some(routing_mgr) = transport.get_routing_manager() {
            let total_peers = routing_mgr.total_peers().await;
            let bucket_count = routing_mgr.bucket_stats().await.len();

            let (record_count, pending_announces, cache_hits, cache_misses) =
                if let Some(record_mgr) = transport.get_record_store() {
                    let stats = record_mgr.get_stats();
                    (
                        stats.record_count,
                        stats.pending_announce_count,
                        stats.cache_hits,
                        stats.cache_misses,
                    )
                } else {
                    (0, 0, 0, 0)
                };

            return Ok(Json(DhtStatsResponse {
                node_id: transport.get_mesh_config().node_id().to_string(),
                total_peers,
                bucket_count,
                record_count,
                pending_announces,
                cache_hits,
                cache_misses,
            }));
        }
    }

    Err(StatusCode::SERVICE_UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_id_ban_sentinel_ip_is_zero() {
        let ip = mesh_id_ban_sentinel_ip();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_mesh_id_ban_reason_format() {
        let reason = mesh_id_ban_reason("my-mesh-id", "spam");
        assert_eq!(reason, "mesh_id_ban:my-mesh-id:spam");
    }

    #[test]
    fn test_mesh_id_ban_reason_with_empty_user_reason() {
        let reason = mesh_id_ban_reason("node-42", "");
        assert_eq!(reason, "mesh_id_ban:node-42:");
    }

    #[test]
    fn test_is_mesh_id_ban_reason_matches() {
        let reason = "mesh_id_ban:test-mesh:spam";
        assert!(is_mesh_id_ban_reason(reason, "test-mesh"));
    }

    #[test]
    fn test_is_mesh_id_ban_reason_no_match_different_id() {
        let reason = "mesh_id_ban:other-mesh:spam";
        assert!(!is_mesh_id_ban_reason(reason, "test-mesh"));
    }

    #[test]
    fn test_is_mesh_id_ban_reason_no_match_prefix_only() {
        let reason = "mesh_id_ban:";
        assert!(!is_mesh_id_ban_reason(reason, "test-mesh"));
    }

    #[test]
    fn test_is_mesh_id_ban_reason_no_match_not_ban() {
        let reason = "some other reason";
        assert!(!is_mesh_id_ban_reason(reason, "test-mesh"));
    }

    #[test]
    fn test_extract_mesh_id_from_ban_reason() {
        let reason = "mesh_id_ban:my-mesh-id:spam";
        assert_eq!(
            extract_mesh_id_from_ban_reason(reason),
            Some("my-mesh-id".to_string())
        );
    }

    #[test]
    fn test_extract_mesh_id_from_ban_reason_no_prefix() {
        let reason = "some other reason";
        assert_eq!(extract_mesh_id_from_ban_reason(reason), None);
    }

    #[test]
    fn test_extract_mesh_id_from_ban_reason_empty_mesh_id() {
        let reason = "mesh_id_ban::spam";
        assert_eq!(
            extract_mesh_id_from_ban_reason(reason),
            Some("".to_string())
        );
    }

    #[test]
    fn test_extract_mesh_id_from_ban_reason_no_colon_after_id() {
        let reason = "mesh_id_ban:just-id";
        assert_eq!(extract_mesh_id_from_ban_reason(reason), None);
    }

    #[test]
    fn test_extract_mesh_id_roundtrip() {
        let mesh_id = "sensor-node-7";
        let reason = "policy_violation";
        let encoded = mesh_id_ban_reason(mesh_id, reason);
        let decoded = extract_mesh_id_from_ban_reason(&encoded);
        assert_eq!(decoded, Some(mesh_id.to_string()));
    }
}
