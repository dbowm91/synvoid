use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::mesh::yara_rules::{YaraRuleSubmission, YaraRuleSubmissionStatus};

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraStatusResponse {
    pub enabled: bool,
    pub node_id: String,
    pub node_role: String,
    pub current_version: Option<String>,
    pub pending_submissions: usize,
    pub total_submissions: usize,
    pub is_global: bool,
    pub last_sync_secs: u64,
    pub has_feed_manager: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraSubmissionResponse {
    pub submission_id: String,
    pub rules: String,
    pub description: String,
    pub submitted_by: String,
    pub submitted_at: u64,
    pub status: String,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<u64>,
    pub review_notes: Option<String>,
}

impl From<YaraRuleSubmission> for YaraSubmissionResponse {
    fn from(s: YaraRuleSubmission) -> Self {
        let status = match s.status {
            YaraRuleSubmissionStatus::Pending => "pending".to_string(),
            YaraRuleSubmissionStatus::Approved => "approved".to_string(),
            YaraRuleSubmissionStatus::Rejected => "rejected".to_string(),
        };
        Self {
            submission_id: s.submission_id,
            rules: s.rules,
            description: s.description,
            submitted_by: s.submitted_by,
            submitted_at: s.submitted_at,
            status,
            reviewed_by: s.reviewed_by,
            reviewed_at: s.reviewed_at,
            review_notes: s.review_notes,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraSubmissionsListResponse {
    pub submissions: Vec<YaraSubmissionResponse>,
    pub total: usize,
    pub pending_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraApprovalRequest {
    pub review_notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraRejectionRequest {
    pub review_notes: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraApproveResponse {
    pub success: bool,
    pub version: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraRejectResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraBroadcastResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraSyncResponse {
    pub success: bool,
    pub message: String,
}

pub async fn get_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<YaraStatusResponse>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let stats = yara_manager.get_stats();

    let last_sync_secs = stats.last_sync.elapsed().as_secs();

    Ok(Json(YaraStatusResponse {
        enabled: stats.node_role.bits() != 0,
        node_id: stats.node_id,
        node_role: format!("{:?}", stats.node_role),
        current_version: stats.current_version,
        pending_submissions: stats.pending_submissions,
        total_submissions: stats.total_submissions,
        is_global: stats.is_global,
        last_sync_secs,
        has_feed_manager: yara_manager.has_feed_manager(),
    }))
}

pub async fn list_submissions(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<YaraSubmissionsListResponse>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let all_submissions = yara_manager.get_all_submissions();

    let total = all_submissions.len();
    let pending_count = yara_manager.get_pending_submissions().len();

    let submissions: Vec<YaraSubmissionResponse> =
        all_submissions.into_iter().map(|s| s.into()).collect();

    Ok(Json(YaraSubmissionsListResponse {
        submissions,
        total,
        pending_count,
    }))
}

pub async fn get_submission(
    State(state): State<Arc<AdminState>>,
    Path(submission_id): Path<String>,
    _auth: OptionalAuth,
) -> Result<Json<YaraSubmissionResponse>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let submission = yara_manager
        .get_submission(&submission_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(submission.into()))
}

pub async fn approve_submission(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(submission_id): Path<String>,
    Json(req): Json<YaraApprovalRequest>,
) -> Result<Json<YaraApproveResponse>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    match yara_manager.approve_submission(&submission_id, req.review_notes) {
        Ok(version) => Ok(Json(YaraApproveResponse {
            success: true,
            version,
            message: format!("Submission {} approved and rules applied", submission_id),
        })),
        Err(e) => {
            tracing::error!("Failed to approve submission {}: {}", submission_id, e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn reject_submission(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(submission_id): Path<String>,
    Json(req): Json<YaraRejectionRequest>,
) -> Result<Json<YaraRejectResponse>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    match yara_manager.reject_submission(&submission_id, req.review_notes) {
        Ok(()) => Ok(Json(YaraRejectResponse {
            success: true,
            message: format!("Submission {} rejected", submission_id),
        })),
        Err(e) => {
            tracing::error!("Failed to reject submission {}: {}", submission_id, e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn broadcast_rules(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<YaraBroadcastResponse>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let version = yara_manager
        .get_current_version()
        .ok_or(StatusCode::NOT_FOUND)?;

    if let Err(e) = yara_manager.broadcast_approved_rules(&version) {
        tracing::error!("Failed to broadcast rules: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(YaraBroadcastResponse {
        success: true,
        message: format!("Rules version {} broadcast to mesh", version),
    }))
}

pub async fn sync_from_global(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<YaraSyncResponse>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    yara_manager.send_sync_request_to_global();

    Ok(Json(YaraSyncResponse {
        success: true,
        message: "Sync request sent to global nodes".to_string(),
    }))
}
