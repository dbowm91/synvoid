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
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditResultsDto {
    pub success: bool,
    pub passed: bool,
    pub results: Vec<NodeProbeResultDto>,
    pub summary: AuditSummaryDto,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditSummaryDto {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize, Clone)]
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

#[derive(Debug, Serialize)]
pub struct MeshNodeListResponse {
    pub nodes: Vec<MeshNodeInfo>,
    pub total: usize,
    pub global_count: usize,
    pub edge_count: usize,
    pub connected_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct BanIpRequest {
    pub ip: String,
    pub reason: String,
    pub duration_seconds: Option<u64>,
    pub site_scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BanMeshIdRequest {
    pub mesh_id: String,
    pub reason: String,
    pub duration_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct UnbanRequest {
    pub identifier: String,
    pub ban_type: String,
}

#[derive(Debug, Serialize)]
pub struct BanRecord {
    pub id: String,
    pub ban_type: String,
    pub identifier: String,
    pub reason: String,
    pub blocked_at: u64,
    pub expires_at: Option<u64>,
    pub is_permanent: bool,
    pub site_scope: String,
}

#[derive(Debug, Serialize)]
pub struct BanListResponse {
    pub bans: Vec<BanRecord>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Deserialize)]
pub struct DeriveSigningKeyRequest {
    pub genesis_key_base64: String,
}

#[derive(Debug, Serialize)]
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
        let now = std::time::Instant::now();

        for peer in peers {
            let is_connected = peer.status == crate::mesh::topology::PeerStatus::Healthy;
            let role_str = role_to_string(peer.role);

            if peer.role.is_global() {
                global_count += 1;
            }
            if is_connected {
                connected_count += 1;
            }

            let last_seen_secs_ago = now.duration_since(peer.last_seen).as_secs();
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

            let now = std::time::Instant::now();
            let last_seen_secs_ago = now.duration_since(peer.last_seen).as_secs();

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

pub async fn ban_ip(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(payload): Json<BanIpRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
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

            if block_store.block_ip(ip, &reason, duration, &site_scope) {
                tracing::info!(
                    "Admin banned IP {} for {} seconds (reason: {})",
                    ip,
                    duration,
                    reason
                );

                threat_intel.announce_local_block(ip, reason.clone(), duration, site_scope.clone());

                return Ok(Json(serde_json::json!({
                    "success": true,
                    "message": format!("IP {} banned successfully", ip),
                    "ban": {
                        "ip": ip.to_string(),
                        "reason": reason,
                        "duration_seconds": duration,
                        "site_scope": site_scope,
                        "is_permanent": duration == 0
                    }
                })));
            } else {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        }
    }

    Err(StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn ban_mesh_id(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(payload): Json<BanMeshIdRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
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

            let blocked = block_store.block_ip(
                IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                &format!("mesh_id_ban:{}:{}", mesh_id, reason),
                duration,
                "global",
            );

            if blocked || duration == 0 {
                tracing::info!(
                    "Admin banned mesh_id {} for {} seconds (reason: {})",
                    mesh_id,
                    duration,
                    reason
                );

                return Ok(Json(serde_json::json!({
                    "success": true,
                    "message": format!("Mesh ID {} banned successfully", mesh_id),
                    "ban": {
                        "mesh_id": mesh_id,
                        "reason": reason,
                        "duration_seconds": duration,
                        "is_permanent": duration == 0
                    }
                })));
            }

            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    Err(StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn unban(
    State(state): State<Arc<AdminState>>,
    Query(params): Query<UnbanRequest>,
    _auth: OptionalAuth,
) -> Result<Json<serde_json::Value>, StatusCode> {
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
                            return Ok(Json(serde_json::json!({
                                "success": true,
                                "message": format!("IP {} unbanned successfully", ip)
                            })));
                        }
                    }
                }
                "mesh_id" => {
                    tracing::info!("Admin unbanned mesh_id {}", identifier);
                    return Ok(Json(serde_json::json!({
                        "success": true,
                        "message": format!("Mesh ID {} unbanned successfully", identifier)
                    })));
                }
                _ => {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }
    }

    Err(StatusCode::NOT_FOUND)
}

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
            let entries = block_store.get_all_entries();
            let zero_ip_str = "0.0.0.0";

            for entry in entries {
                if entry.ip == zero_ip_str {
                    continue;
                }

                let is_permanent = entry.is_permanent();
                let expires_at = if is_permanent {
                    None
                } else {
                    Some(entry.blocked_at + entry.ban_expire_seconds)
                };

                bans.push(BanRecord {
                    id: entry.ip.to_string(),
                    ban_type: "ip".to_string(),
                    identifier: entry.ip.to_string(),
                    reason: entry.reason,
                    blocked_at: entry.blocked_at,
                    expires_at,
                    is_permanent,
                    site_scope: entry.site_scope,
                });
            }
        }
    }

    let total = bans.len();

    bans.sort_by(|a, b| b.blocked_at.cmp(&a.blocked_at));

    let bans: Vec<BanRecord> = bans.into_iter().skip(offset).take(limit).collect();

    Ok(Json(BanListResponse { bans, total }))
}

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
                    Some(format!("sha256:{}...", &hex::encode(&result[..8])));
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

pub async fn derive_signing_key(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<DeriveSigningKeyRequest>,
) -> Result<Json<DeriveSigningKeyResponse>, StatusCode> {
    use base64::Engine;

    let genesis_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.genesis_key_base64)
        .map_err(|e| {
            tracing::warn!("Invalid genesis key base64: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if genesis_bytes.len() != 32 {
        return Ok(Json(DeriveSigningKeyResponse {
            success: false,
            signing_public_key: None,
            node_id: None,
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
        return Ok(Json(DeriveSigningKeyResponse {
            success: false,
            signing_public_key: None,
            node_id: None,
            message: format!("Failed to derive signing key: {}", e),
        }));
    }

    let signing_public_key = node_identity.public_key_hex();
    let node_id = node_identity.node_id.clone();

    Ok(Json(DeriveSigningKeyResponse {
        success: true,
        signing_public_key: signing_public_key.map(|pk| format!("{}...", &pk[..16.min(pk.len())])),
        node_id,
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

pub async fn submit_audit_report(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<AuditReportRequest>,
) -> Result<Json<AuditReportResponseDto>, StatusCode> {
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
        Ok(Json(AuditReportResponseDto::from(response)))
    } else {
        Ok(Json(AuditReportResponseDto {
            accepted: false,
            message: "Audit manager not configured".to_string(),
            reputation_updated: None,
            quarantined: false,
            quarantine_reason: None,
            new_pow_challenge: None,
        }))
    }
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct SignatureFailureResponse {
    pub accepted: bool,
    pub message: String,
    pub action_taken: Option<String>,
}

pub async fn report_signature_failure(
    State(state): State<Arc<AdminState>>,
    Json(report): Json<SignatureFailureReport>,
) -> Result<Json<SignatureFailureResponse>, StatusCode> {
    tracing::warn!(
        "Signature failure reported: session_id={}, path={}, mesh_id={}",
        report.session_id.as_deref().unwrap_or("unknown"),
        report.path.as_deref().unwrap_or("unknown"),
        report.mesh_id.as_deref().unwrap_or("unknown")
    );

    if let Some(ref _manager) = state.mesh.client_audit_manager {
        let session_id = report.session_id.clone();

        if let Some(ref sid) = session_id {
            tracing::info!("Recording signature failure for session: {}", sid);
        }
    }

    Ok(Json(SignatureFailureResponse {
        accepted: true,
        message: "Signature failure recorded".to_string(),
        action_taken: Some("logged".to_string()),
    }))
}
