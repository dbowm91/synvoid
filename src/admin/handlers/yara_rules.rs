#![cfg(feature = "mesh")]

use super::super::audit::AuditLog;
use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use synvoid_core::admin_mutation::{AdminMutationResult, AdminMutationStatus, PropagationStatus};
use utoipa::ToSchema;

use crate::mesh::yara_rules::{YaraRuleSubmission, YaraRuleSubmissionStatus};

#[derive(Debug, Serialize, Deserialize, ToSchema)]
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

const RULES_PREVIEW_LENGTH: usize = 500;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraSubmissionResponse {
    pub submission_id: String,
    pub rules: String,
    pub rules_preview: Option<String>,
    pub rules_length: usize,
    pub description: String,
    pub submitted_by: String,
    pub submitted_at: u64,
    pub status: String,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<u64>,
    pub review_notes: Option<String>,
}

impl YaraSubmissionResponse {
    fn from_with_preview(s: YaraRuleSubmission, include_full_rules: bool) -> Self {
        let status = match s.status {
            YaraRuleSubmissionStatus::Pending => "pending".to_string(),
            YaraRuleSubmissionStatus::Approved => "approved".to_string(),
            YaraRuleSubmissionStatus::Rejected => "rejected".to_string(),
        };
        let rules_length = s.rules.len();
        let rules_preview = if s.rules.len() > RULES_PREVIEW_LENGTH {
            Some(format!(
                "{}...[truncated {} chars]",
                &s.rules[..RULES_PREVIEW_LENGTH],
                s.rules.len() - RULES_PREVIEW_LENGTH
            ))
        } else {
            None
        };
        Self {
            submission_id: s.submission_id,
            rules: if include_full_rules {
                s.rules
            } else {
                String::new()
            },
            rules_preview,
            rules_length,
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

impl From<YaraRuleSubmission> for YaraSubmissionResponse {
    fn from(s: YaraRuleSubmission) -> Self {
        Self::from_with_preview(s, true)
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraSubmissionsListResponse {
    pub submissions: Vec<YaraSubmissionResponse>,
    pub total: usize,
    pub pending_count: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraApprovalRequest {
    pub review_notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraRejectionRequest {
    pub review_notes: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraApproveResponse {
    pub success: bool,
    pub version: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraRejectResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraBroadcastResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraSyncResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraSubmitRequest {
    pub rules: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraSubmitResponse {
    pub success: bool,
    pub submission_id: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraApplyRequest {
    pub rules: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraApplyResponse {
    pub success: bool,
    pub version: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct YaraDeleteResponse {
    pub success: bool,
    pub message: String,
}

#[utoipa::path(
    get,
    path = "/yara/status",
    responses(
        (status = 200, description = "YARA rules status", body = YaraStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "YARA manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
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

#[utoipa::path(
    get,
    path = "/yara/submissions",
    responses(
        (status = 200, description = "List of YARA rule submissions", body = YaraSubmissionsListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "YARA manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
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

#[utoipa::path(
    get,
    path = "/yara/submissions/{submission_id}",
    params(
        ("submission_id" = String, Path, description = "Submission ID")
    ),
    responses(
        (status = 200, description = "YARA rule submission details", body = YaraSubmissionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Submission not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
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

#[utoipa::path(
    post,
    path = "/yara/submissions/{submission_id}/approve",
    params(
        ("submission_id" = String, Path, description = "Submission ID to approve")
    ),
    request_body = YaraApprovalRequest,
    responses(
        (status = 200, description = "Submission approved", body = YaraApproveResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Submission not found"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
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

#[utoipa::path(
    post,
    path = "/yara/submissions/{submission_id}/reject",
    params(
        ("submission_id" = String, Path, description = "Submission ID to reject")
    ),
    request_body = YaraRejectionRequest,
    responses(
        (status = 200, description = "Submission rejected", body = YaraRejectResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Submission not found"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
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

#[utoipa::path(
    post,
    path = "/yara/broadcast",
    responses(
        (status = 200, description = "Rules broadcast to mesh", body = YaraBroadcastResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "YARA manager not found or no current version"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
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

#[utoipa::path(
    post,
    path = "/yara/sync",
    responses(
        (status = 200, description = "Sync request sent", body = YaraSyncResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "YARA manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
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

#[utoipa::path(
    post,
    path = "/yara/submit",
    request_body = YaraSubmitRequest,
    responses(
        (status = 200, description = "Rules submitted for approval", body = YaraSubmitResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "YARA manager not found"),
        (status = 400, description = "Invalid rules"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
pub async fn submit_rules(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<YaraSubmitRequest>,
) -> Result<Json<YaraSubmitResponse>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    match yara_manager.submit_rule_for_approval(req.rules, req.description) {
        Ok(submission_id) => {
            state.audit.log(AuditLog::new(
                None,
                Some("admin".to_string()),
                "submit_yara_rules".to_string(),
                "yara/rules".to_string(),
                "unknown".to_string(),
                None,
                Some(format!("Rules submitted for approval: {}", submission_id)),
                true,
            ));
            Ok(Json(YaraSubmitResponse {
                success: true,
                submission_id,
                message: "Rules submitted for approval".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!("Failed to submit rules: {}", e);
            state.audit.log(AuditLog::new(
                None,
                Some("admin".to_string()),
                "submit_yara_rules".to_string(),
                "yara/rules".to_string(),
                "unknown".to_string(),
                None,
                Some(format!("Failed to submit rules: {}", e)),
                false,
            ));
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

#[utoipa::path(
    post,
    path = "/yara/apply",
    request_body = YaraApplyRequest,
    responses(
        (status = 200, description = "Rules applied directly"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - not a global node"),
        (status = 404, description = "YARA manager not found"),
        (status = 400, description = "Invalid rules"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
pub async fn apply_rules_direct(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<YaraApplyRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    if !yara_manager.is_global() {
        return Err(StatusCode::FORBIDDEN);
    }

    match yara_manager.apply_rules_direct(req.rules, req.version) {
        Ok(version) => {
            if let Err(e) = yara_manager.broadcast_approved_rules(&version) {
                tracing::warn!("Failed to broadcast applied rules: {}", e);
            }
            Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::Applied,
                target: version.clone(),
                local_store_mutated: true,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: format!("Rules applied directly, version {}", version),
            }))
        }
        Err(e) => {
            tracing::error!("Failed to apply rules directly: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

#[utoipa::path(
    delete,
    path = "/yara/submissions/{submission_id}",
    params(
        ("submission_id" = String, Path, description = "Submission ID to delete")
    ),
    responses(
        (status = 200, description = "Submission deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Submission not found"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "yara"
)]
pub async fn delete_submission(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(submission_id): Path<String>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let yara_manager = state
        .waf_tracking
        .yara_rules
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    match yara_manager.delete_submission(&submission_id) {
        Ok(()) => Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Applied,
            target: submission_id.clone(),
            local_store_mutated: true,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: format!("Submission {} deleted", submission_id),
        })),
        Err(e) => {
            tracing::error!("Failed to delete submission {}: {}", submission_id, e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
