use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use super::super::state::AdminState;

use super::common::{PaginationQuery, PaginatedResponse, PAGINATION_LIMITS_DEFAULT, require_auth, OptionalAuth, parse_ip};

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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BlockProbesRequest {
    pub ips: Vec<String>,
    pub duration: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProbeResponse {
    pub ip: String,
    pub event_count: u32,
    pub unique_endpoints: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub user_agent: Option<String>,
    pub recent_endpoints: Vec<ProbeEventResponse>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProbeEventResponse {
    pub endpoint: String,
    pub method: String,
    pub timestamp: u64,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProbesListResponse {
    pub probes: Vec<ProbeResponse>,
    pub total: usize,
    pub has_more: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProbeStatsResponse {
    pub total_records: usize,
    pub active_records: usize,
    pub total_events: u32,
    pub top_endpoints: Vec<ProbeEndpointStatsResponse>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProbeEndpointStatsResponse {
    pub endpoint: String,
    pub count: u32,
}

#[utoipa::path(
    get,
    path = "/probes",
    tag = "Probes",
    responses(
        (status = 200, description = "List of probe records"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_probes(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<ProbeResponse>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

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
    tag = "Probes",
    responses(
        (status = 200, description = "Probe record details"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Probe not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_probe(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(ip): Path<String>,
) -> Result<Json<ProbeResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

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
    tag = "Probes",
    responses(
        (status = 200, description = "Probe statistics"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_probe_stats(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<ProbeStatsResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

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
    tag = "Probes",
    responses(
        (status = 204, description = "Probe deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Probe not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_probe(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(ip): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tracker = state.probe_tracker().ok_or(StatusCode::NOT_FOUND)?;

    let ip_addr: IpAddr = parse_ip(&ip)?;

    if tracker.clear_record(&ip_addr) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
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
    tag = "Probes",
    responses(
        (status = 200, description = "Probes blocked"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn block_probes(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Json(req): Json<BlockProbesRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let ban_duration = parse_duration(&req.duration);
    
    let mut blocked = Vec::new();
    let mut failed = Vec::new();

    for ip_str in req.ips {
        if ip_str.parse::<IpAddr>().is_ok() {
            blocked.push(ip_str);
        } else {
            failed.push(ip_str);
        }
    }

    let _ = state;
    Ok(Json(serde_json::json!({
        "blocked": blocked,
        "failed": failed,
        "duration_secs": ban_duration,
    })))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SuspiciousWordRecordResponse {
    pub ip: String,
    pub matched_word: String,
    pub endpoint: String,
    pub user_agent: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SuspiciousWordListResponse {
    pub records: Vec<SuspiciousWordRecordResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SuspiciousWordStatsResponse {
    pub total_ips: usize,
    pub total_matches: u64,
    pub top_words: Vec<SuspiciousWordCountResponse>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SuspiciousWordCountResponse {
    pub word: String,
    pub count: u32,
}

#[utoipa::path(
    get,
    path = "/probes/suspicious-words",
    tag = "Probes",
    responses(
        (status = 200, description = "List of suspicious words"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_suspicious_words(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<SuspiciousWordListResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

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
            records.into_iter().map(move |r| SuspiciousWordRecordResponse {
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
    tag = "Probes",
    responses(
        (status = 200, description = "Suspicious word statistics"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_suspicious_word_stats(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<SuspiciousWordStatsResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tracker = match state.suspicious_word_tracker() {
        Some(t) => t,
        None => return empty_suspicious_word_stats_response(),
    };

    let stats = tracker.get_stats();

    Ok(Json(SuspiciousWordStatsResponse {
        total_ips: stats.total_ips,
        total_matches: stats.total_matches,
        top_words: stats.top_words.into_iter().map(|w| SuspiciousWordCountResponse {
            word: w.word,
            count: w.count,
        }).collect(),
    }))
}

#[utoipa::path(
    delete,
    path = "/probes/suspicious-words/{ip}",
    tag = "Probes",
    responses(
        (status = 204, description = "Suspicious word record deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Record not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_suspicious_word(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(ip): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tracker = state.suspicious_word_tracker().ok_or(StatusCode::NOT_FOUND)?;

    let ip_addr: IpAddr = parse_ip(&ip)?;

    if tracker.clear_record(&ip_addr) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UpstreamErrorRecordResponse {
    pub ip: String,
    pub endpoint: String,
    pub status_code: u16,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UpstreamErrorListResponse {
    pub records: Vec<UpstreamErrorRecordResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UpstreamErrorStatsResponse {
    pub total_ips: usize,
    pub total_errors: u64,
    pub top_endpoints: Vec<UpstreamErrorEndpointCountResponse>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UpstreamErrorEndpointCountResponse {
    pub endpoint: String,
    pub count: u32,
}

#[utoipa::path(
    get,
    path = "/probes/upstream-errors",
    tag = "Probes",
    responses(
        (status = 200, description = "List of upstream errors"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_upstream_errors(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<UpstreamErrorListResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

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
            records.into_iter().map(move |r| UpstreamErrorRecordResponse {
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
    tag = "Probes",
    responses(
        (status = 200, description = "Upstream error statistics"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_upstream_error_stats(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<UpstreamErrorStatsResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tracker = match state.upstream_error_tracker() {
        Some(t) => t,
        None => return empty_upstream_error_stats_response(),
    };

    let stats = tracker.get_stats();

    Ok(Json(UpstreamErrorStatsResponse {
        total_ips: stats.total_ips,
        total_errors: stats.total_errors,
        top_endpoints: stats.top_endpoints.into_iter().map(|e| UpstreamErrorEndpointCountResponse {
            endpoint: e.endpoint,
            count: e.count,
        }).collect(),
    }))
}

#[utoipa::path(
    delete,
    path = "/probes/upstream-errors/{ip}",
    tag = "Probes",
    responses(
        (status = 204, description = "Upstream error record deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Record not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_upstream_error(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(ip): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tracker = state.upstream_error_tracker().ok_or(StatusCode::NOT_FOUND)?;

    let ip_addr: IpAddr = parse_ip(&ip)?;

    if tracker.clear_record(&ip_addr) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
