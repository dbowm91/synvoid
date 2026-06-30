use super::state::AdminStateProvider;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};
use synvoid_ipc::current_timestamp;
use utoipa::ToSchema;
use uuid::Uuid;

use super::common::{
    parse_ip, OptionalAuth, PaginatedResponse, PaginationQuery, PAGINATION_LIMITS_DEFAULT,
};

const MAX_PROBE_EVENTS_ALL: usize = 10000;
const MAX_RECENT_ENDPOINTS_LIST: usize = 5;
const MAX_RECENT_ENDPOINTS_DETAIL: usize = 20;

fn empty_probe_response() -> Result<Json<PaginatedResponse<ProbeResponse>>, StatusCode> {
    Ok(Json(PaginatedResponse::empty()))
}

fn empty_probe_stats_response() -> Result<Json<ProbeStatsResponse>, StatusCode> {
    Ok(Json(ProbeStatsResponse {
        total_records: 0,
        active_records: 0,
        total_events: 0,
        top_endpoints: vec![],
    }))
}

fn empty_suspicious_word_list_response() -> Result<Json<SuspiciousWordListResponse>, StatusCode> {
    Ok(Json(SuspiciousWordListResponse {
        records: vec![],
        total: 0,
    }))
}

fn empty_suspicious_word_stats_response() -> Result<Json<SuspiciousWordStatsResponse>, StatusCode> {
    Ok(Json(SuspiciousWordStatsResponse {
        total_ips: 0,
        total_matches: 0,
        top_words: vec![],
    }))
}

fn empty_upstream_error_list_response() -> Result<Json<UpstreamErrorListResponse>, StatusCode> {
    Ok(Json(UpstreamErrorListResponse {
        records: vec![],
        total: 0,
    }))
}

fn empty_upstream_error_stats_response() -> Result<Json<UpstreamErrorStatsResponse>, StatusCode> {
    Ok(Json(UpstreamErrorStatsResponse {
        total_ips: 0,
        total_errors: 0,
        top_endpoints: vec![],
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BlockProbesRequest {
    pub ips: Vec<String>,
    pub duration: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProbeResponse {
    pub ip: String,
    pub event_count: u32,
    pub unique_endpoints: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub user_agent: Option<String>,
    pub recent_endpoints: Vec<ProbeEventResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProbeEventResponse {
    pub endpoint: String,
    pub method: String,
    pub timestamp: u64,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProbeStatsResponse {
    pub total_records: usize,
    pub active_records: usize,
    pub total_events: u32,
    pub top_endpoints: Vec<ProbeEndpointStatsResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProbeEndpointStatsResponse {
    pub endpoint: String,
    pub count: u32,
}

#[utoipa::path(
    get,
    path = "/probes",
    responses(
        (status = 200, description = "List of probing IPs", body = PaginatedResponse<ProbeResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn list_probes<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<ProbeResponse>>, StatusCode> {
    let tracker = match state.probe_tracker() {
        Some(t) => t,
        None => return empty_probe_response(),
    };

    let (limit, offset) = PAGINATION_LIMITS_DEFAULT.apply(query.limit, query.offset);

    let all_records = tracker.list_records(MAX_PROBE_EVENTS_ALL, 0);
    let total = all_records.len();

    let probes: Vec<ProbeResponse> = all_records
        .iter()
        .skip(offset)
        .take(limit)
        .map(|record| {
            let recent_endpoints: Vec<ProbeEventResponse> = record
                .events
                .iter()
                .rev()
                .take(MAX_RECENT_ENDPOINTS_LIST)
                .map(|e| ProbeEventResponse {
                    endpoint: e.endpoint.clone(),
                    method: e.method.clone(),
                    timestamp: e.timestamp,
                    user_agent: e.user_agent.clone(),
                })
                .collect();

            ProbeResponse {
                ip: record.ip.clone(),
                event_count: record.event_count,
                unique_endpoints: record.unique_endpoints.clone(),
                first_seen: record.first_seen,
                last_seen: record.last_seen,
                user_agent: record.user_agent.clone(),
                recent_endpoints,
            }
        })
        .collect();

    Ok(Json(PaginatedResponse::new(probes, total, limit, offset)))
}

#[utoipa::path(
    get,
    path = "/probes/{ip}",
    params(
        ("ip" = String, Path, description = "IP address to get probe info for")
    ),
    responses(
        (status = 200, description = "Probe information", body = ProbeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Probe not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn get_probe<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Path(ip): Path<String>,
) -> Result<Json<ProbeResponse>, StatusCode> {
    let tracker = match state.probe_tracker() {
        Some(t) => t,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let ip_addr: IpAddr = parse_ip(&ip)?;

    let record = tracker.get_record(&ip_addr).ok_or(StatusCode::NOT_FOUND)?;

    let recent_endpoints: Vec<ProbeEventResponse> = record
        .events
        .iter()
        .rev()
        .take(MAX_RECENT_ENDPOINTS_DETAIL)
        .map(|e| ProbeEventResponse {
            endpoint: e.endpoint.clone(),
            method: e.method.clone(),
            timestamp: e.timestamp,
            user_agent: e.user_agent.clone(),
        })
        .collect();

    Ok(Json(ProbeResponse {
        ip: record.ip,
        event_count: record.event_count,
        unique_endpoints: record.unique_endpoints,
        first_seen: record.first_seen,
        last_seen: record.last_seen,
        user_agent: record.user_agent,
        recent_endpoints,
    }))
}

#[utoipa::path(
    get,
    path = "/probes/stats",
    responses(
        (status = 200, description = "Probe statistics", body = ProbeStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn get_probe_stats<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
) -> Result<Json<ProbeStatsResponse>, StatusCode> {
    let tracker = match state.probe_tracker() {
        Some(t) => t,
        None => return empty_probe_stats_response(),
    };

    let stats = tracker.get_stats();

    Ok(Json(ProbeStatsResponse {
        total_records: stats.total_records,
        active_records: stats.active_records,
        total_events: stats.total_events,
        top_endpoints: stats
            .top_endpoints
            .into_iter()
            .map(|e| ProbeEndpointStatsResponse {
                endpoint: e.endpoint,
                count: e.count,
            })
            .collect(),
    }))
}

#[utoipa::path(
    delete,
    path = "/probes/{ip}",
    params(
        ("ip" = String, Path, description = "IP address to delete probe record for")
    ),
    responses(
        (status = 200, description = "Probe record deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Probe not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn delete_probe<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Path(ip): Path<String>,
) -> Result<Json<AdminMutationResult>, StatusCode> {
    let tracker = state.probe_tracker().ok_or(StatusCode::NOT_FOUND)?;

    let ip_addr: IpAddr = parse_ip(&ip)?;

    if tracker.clear_record(&ip_addr) {
        let audit_id = uuid::Uuid::new_v4().to_string();

        let audit_event = AdminAuditEvent {
            audit_id: audit_id.clone(),
            timestamp: synvoid_ipc::current_timestamp(),
            actor: AdminActor::new(AdminMutationAuthority::AdminManual),
            action: "delete_probe_record".to_string(),
            target_kind: "probe_record".to_string(),
            target_id: ip.clone(),
            prior_state: None,
            requested_state: None,
            resulting_state: Some(serde_json::json!({
                "ip": ip,
                "removed": true,
            })),
            mutation_status: AdminMutationStatus::Applied,
            propagation_status: PropagationStatus::AppliedLocalOnly,
            event_id: None,
        };
        state.log_admin_audit_event(&audit_event);

        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Applied,
            target: serde_json::json!(ip),
            local_store_mutated: true,
            propagation: PropagationStatus::AppliedLocalOnly,
            event_id: None,
            audit_id: Some(audit_id),
            message: "Probe record deleted".to_string(),
        }))
    } else {
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::NoOpAlreadyAbsent,
            target: serde_json::json!(ip),
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Probe record not found".to_string(),
        }))
    }
}

fn parse_duration(duration: &str) -> u64 {
    let duration = duration.trim();
    let num: u64 = duration
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);

    if duration.ends_with('s') {
        num
    } else if duration.ends_with('m') {
        num * 60
    } else if duration.ends_with('h') {
        num * 3600
    } else if duration.ends_with('d') {
        num * 86400
    } else if duration.ends_with('w') {
        num * 604800
    } else {
        num
    }
}

#[utoipa::path(
    post,
    path = "/probes/block",
    request_body = BlockProbesRequest,
    responses(
        (status = 200, description = "IPs blocked"),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn block_probes<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Json(req): Json<BlockProbesRequest>,
) -> Result<Json<AdminMutationResult>, StatusCode> {
    let ban_duration_secs = parse_duration(&req.duration);

    let mut blocked = Vec::new();
    let mut failed = Vec::new();

    for ip_str in &req.ips {
        match ip_str.parse::<IpAddr>() {
            Ok(_) => blocked.push(ip_str.clone()),
            Err(_) => failed.push(ip_str.clone()),
        }
    }

    if let Some(pm) = state.process_manager() {
        for ip in &blocked {
            tracing::info!(
                "Blocking probing IP {} for {} seconds",
                ip,
                ban_duration_secs
            );
            pm.handle_blocklist_update(
                vec![synvoid_ipc::ipc::BlockEntryData {
                    ip: ip.clone(),
                    reason: "Blocked via probe admin API".to_string(),
                    blocked_at: current_timestamp(),
                    ban_expire_seconds: ban_duration_secs,
                    site_scope: String::new(),
                    provenance_kind: Some("SupervisorManual".to_string()),
                    provenance_source: Some("probe_admin_api".to_string()),
                }],
                vec![],
            );
        }
        pm.trigger_blocklist_persist();
    }

    let audit_id = Uuid::new_v4().to_string();
    let target = serde_json::json!(format!("{} IPs", blocked.len()));
    let message = format!("Blocked {} IPs, {} failed", blocked.len(), failed.len());

    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_ipc::current_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "block_probes".to_string(),
        target_kind: "probe_ips".to_string(),
        target_id: format!("{} IPs", blocked.len()),
        prior_state: None,
        requested_state: Some(serde_json::json!({
            "ips": req.ips,
            "duration": req.duration,
        })),
        resulting_state: Some(serde_json::json!({
            "blocked": blocked,
            "failed": failed,
        })),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::QueuedBestEffort,
        event_id: None,
    };
    state.log_admin_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target,
        local_store_mutated: true,
        propagation: PropagationStatus::QueuedBestEffort,
        event_id: None,
        audit_id: Some(audit_id),
        message,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SuspiciousWordRecordResponse {
    pub ip: String,
    pub matched_word: String,
    pub endpoint: String,
    pub user_agent: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SuspiciousWordListResponse {
    pub records: Vec<SuspiciousWordRecordResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SuspiciousWordStatsResponse {
    pub total_ips: usize,
    pub total_matches: u64,
    pub top_words: Vec<SuspiciousWordCountResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SuspiciousWordCountResponse {
    pub word: String,
    pub count: u32,
}

#[utoipa::path(
    get,
    path = "/probes/suspicious-words",
    responses(
        (status = 200, description = "List of suspicious word records", body = SuspiciousWordListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn list_suspicious_words<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<SuspiciousWordListResponse>, StatusCode> {
    let tracker = match state.suspicious_word_tracker() {
        Some(t) => t,
        None => return empty_suspicious_word_list_response(),
    };

    let (limit, _offset) = PAGINATION_LIMITS_DEFAULT.apply(query.limit, query.offset);
    let records = tracker.list_records(limit);

    let total = records.len();
    let response_records: Vec<SuspiciousWordRecordResponse> = records
        .into_iter()
        .flat_map(|(ip, records)| {
            records
                .into_iter()
                .map(move |r| SuspiciousWordRecordResponse {
                    ip: ip.to_string(),
                    matched_word: r.matched_word,
                    endpoint: r.endpoint,
                    user_agent: r.user_agent,
                    timestamp: r.timestamp,
                })
        })
        .take(limit)
        .collect();

    Ok(Json(SuspiciousWordListResponse {
        records: response_records,
        total,
    }))
}

#[utoipa::path(
    get,
    path = "/probes/suspicious-words/stats",
    responses(
        (status = 200, description = "Suspicious word statistics", body = SuspiciousWordStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn get_suspicious_word_stats<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
) -> Result<Json<SuspiciousWordStatsResponse>, StatusCode> {
    let tracker = match state.suspicious_word_tracker() {
        Some(t) => t,
        None => return empty_suspicious_word_stats_response(),
    };

    let stats = tracker.get_stats();

    Ok(Json(SuspiciousWordStatsResponse {
        total_ips: stats.total_ips,
        total_matches: stats.total_matches,
        top_words: stats
            .top_words
            .into_iter()
            .map(|w| SuspiciousWordCountResponse {
                word: w.word,
                count: w.count,
            })
            .collect(),
    }))
}

#[utoipa::path(
    delete,
    path = "/probes/suspicious-words/{ip}",
    params(
        ("ip" = String, Path, description = "IP address to delete suspicious word record for")
    ),
    responses(
        (status = 200, description = "Suspicious word record deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Record not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn delete_suspicious_word<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Path(ip): Path<String>,
) -> Result<Json<AdminMutationResult>, StatusCode> {
    let tracker = state
        .suspicious_word_tracker()
        .ok_or(StatusCode::NOT_FOUND)?;

    let ip_addr: IpAddr = parse_ip(&ip)?;

    if tracker.clear_record(&ip_addr) {
        let audit_id = uuid::Uuid::new_v4().to_string();

        let audit_event = AdminAuditEvent {
            audit_id: audit_id.clone(),
            timestamp: synvoid_ipc::current_timestamp(),
            actor: AdminActor::new(AdminMutationAuthority::AdminManual),
            action: "delete_suspicious_word".to_string(),
            target_kind: "suspicious_word".to_string(),
            target_id: ip.clone(),
            prior_state: None,
            requested_state: None,
            resulting_state: Some(serde_json::json!({
                "ip": ip,
                "removed": true,
            })),
            mutation_status: AdminMutationStatus::Applied,
            propagation_status: PropagationStatus::AppliedLocalOnly,
            event_id: None,
        };
        state.log_admin_audit_event(&audit_event);

        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Applied,
            target: serde_json::json!(ip),
            local_store_mutated: true,
            propagation: PropagationStatus::AppliedLocalOnly,
            event_id: None,
            audit_id: Some(audit_id),
            message: "Suspicious word record deleted".to_string(),
        }))
    } else {
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::NoOpAlreadyAbsent,
            target: serde_json::json!(ip),
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Suspicious word record not found".to_string(),
        }))
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamErrorRecordResponse {
    pub ip: String,
    pub endpoint: String,
    pub status_code: u16,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamErrorListResponse {
    pub records: Vec<UpstreamErrorRecordResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamErrorStatsResponse {
    pub total_ips: usize,
    pub total_errors: u64,
    pub top_endpoints: Vec<UpstreamErrorEndpointCountResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamErrorEndpointCountResponse {
    pub endpoint: String,
    pub count: u32,
}

#[utoipa::path(
    get,
    path = "/probes/upstream-errors",
    responses(
        (status = 200, description = "List of upstream error records", body = UpstreamErrorListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn list_upstream_errors<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<UpstreamErrorListResponse>, StatusCode> {
    let tracker = match state.upstream_error_tracker() {
        Some(t) => t,
        None => return empty_upstream_error_list_response(),
    };

    let (limit, _offset) = PAGINATION_LIMITS_DEFAULT.apply(query.limit, query.offset);
    let records = tracker.list_records(limit);

    let total = records.len();
    let response_records: Vec<UpstreamErrorRecordResponse> = records
        .into_iter()
        .flat_map(|(ip, records)| {
            records
                .into_iter()
                .map(move |r| UpstreamErrorRecordResponse {
                    ip: ip.to_string(),
                    endpoint: r.endpoint,
                    status_code: r.status_code,
                    timestamp: r.timestamp,
                })
        })
        .take(limit)
        .collect();

    Ok(Json(UpstreamErrorListResponse {
        records: response_records,
        total,
    }))
}

#[utoipa::path(
    get,
    path = "/probes/upstream-errors/stats",
    responses(
        (status = 200, description = "Upstream error statistics", body = UpstreamErrorStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn get_upstream_error_stats<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
) -> Result<Json<UpstreamErrorStatsResponse>, StatusCode> {
    let tracker = match state.upstream_error_tracker() {
        Some(t) => t,
        None => return empty_upstream_error_stats_response(),
    };

    let stats = tracker.get_stats();

    Ok(Json(UpstreamErrorStatsResponse {
        total_ips: stats.total_ips,
        total_errors: stats.total_errors,
        top_endpoints: stats
            .top_endpoints
            .into_iter()
            .map(|e| UpstreamErrorEndpointCountResponse {
                endpoint: e.endpoint,
                count: e.count,
            })
            .collect(),
    }))
}

#[utoipa::path(
    delete,
    path = "/probes/upstream-errors/{ip}",
    params(
        ("ip" = String, Path, description = "IP address to delete upstream error record for")
    ),
    responses(
        (status = 200, description = "Upstream error record deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Record not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "probes"
)]
pub async fn delete_upstream_error<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Path(ip): Path<String>,
) -> Result<Json<AdminMutationResult>, StatusCode> {
    let tracker = state
        .upstream_error_tracker()
        .ok_or(StatusCode::NOT_FOUND)?;

    let ip_addr: IpAddr = parse_ip(&ip)?;

    if tracker.clear_record(&ip_addr) {
        let audit_id = uuid::Uuid::new_v4().to_string();

        let audit_event = AdminAuditEvent {
            audit_id: audit_id.clone(),
            timestamp: synvoid_ipc::current_timestamp(),
            actor: AdminActor::new(AdminMutationAuthority::AdminManual),
            action: "delete_upstream_error".to_string(),
            target_kind: "upstream_error".to_string(),
            target_id: ip.clone(),
            prior_state: None,
            requested_state: None,
            resulting_state: Some(serde_json::json!({
                "ip": ip,
                "removed": true,
            })),
            mutation_status: AdminMutationStatus::Applied,
            propagation_status: PropagationStatus::AppliedLocalOnly,
            event_id: None,
        };
        state.log_admin_audit_event(&audit_event);

        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Applied,
            target: serde_json::json!(ip),
            local_store_mutated: true,
            propagation: PropagationStatus::AppliedLocalOnly,
            event_id: None,
            audit_id: Some(audit_id),
            message: "Upstream error record deleted".to_string(),
        }))
    } else {
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::NoOpAlreadyAbsent,
            target: serde_json::json!(ip),
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Upstream error record not found".to_string(),
        }))
    }
}
