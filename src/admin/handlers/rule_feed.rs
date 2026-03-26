use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;
use super::common::{StatusResponse, OptionalAuth};

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RuleFeedStatusResponse {
    pub enabled: bool,
    pub current_version: Option<String>,
    pub last_update: u64,
    pub last_check: u64,
    pub has_pending_update: bool,
    pub auto_apply: bool,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RuleFeedCheckResponse {
    pub updated: bool,
    pub new_version: Option<String>,
    pub changelog: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RuleFeedApplyResponse {
    pub success: bool,
    pub version: String,
    pub message: String,
}

#[utoipa::path(
    get,
    path = "/rules/feed/status",
    tag = "Rules",
    responses(
        (status = 200, description = "Rule feed status"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Rule feed manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<RuleFeedStatusResponse>, StatusCode> {

    let rule_feed_manager = state.rule_feed_manager.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    let status = RuleFeedStatusResponse {
        enabled: rule_feed_manager.inner.config.enabled,
        current_version: rule_feed_manager.get_current_version(),
        last_update: rule_feed_manager.get_last_update(),
        last_check: rule_feed_manager.get_last_check(),
        has_pending_update: rule_feed_manager.has_pending_update(),
        auto_apply: rule_feed_manager.inner.config.auto_apply,
        url: rule_feed_manager.inner.config.url.clone(),
    };

    Ok(Json(status))
}

#[utoipa::path(
    post,
    path = "/rules/feed/check",
    tag = "Rules",
    responses(
        (status = 200, description = "Rule feed check result"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Rule feed manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn check_for_updates(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<RuleFeedCheckResponse>, StatusCode> {

    let rule_feed_manager = state.rule_feed_manager.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    let result = rule_feed_manager.check_for_updates().await;

    match result {
        Ok(Some(new_version)) => {
            let changelog = rule_feed_manager.get_changelog()
                .into_iter()
                .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null))
                .collect();
            Ok(Json(RuleFeedCheckResponse {
                updated: true,
                new_version: Some(new_version),
                changelog,
            }))
        }
        Ok(None) => Ok(Json(RuleFeedCheckResponse {
            updated: false,
            new_version: None,
            changelog: Vec::new(),
        })),
        Err(e) => {
            tracing::error!("Failed to check for rule updates: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[utoipa::path(
    post,
    path = "/rules/feed/apply",
    tag = "Rules",
    responses(
        (status = 200, description = "Rule feed apply result"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Rule feed manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn apply_pending(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<RuleFeedApplyResponse>, StatusCode> {

    let rule_feed_manager = state.rule_feed_manager.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    if !rule_feed_manager.has_pending_update() {
        return Ok(Json(RuleFeedApplyResponse {
            success: false,
            version: String::new(),
            message: "No pending update to apply".to_string(),
        }));
    }

    match rule_feed_manager.apply_pending() {
        Ok(()) => {
            let version = rule_feed_manager.get_current_version().unwrap_or_default();
            Ok(Json(RuleFeedApplyResponse {
                success: true,
                version: version.clone(),
                message: format!("Successfully applied rules version {}", version),
            }))
        }
        Err(e) => {
            tracing::error!("Failed to apply pending rules: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[utoipa::path(
    delete,
    path = "/rules/feed/pending",
    tag = "Rules",
    responses(
        (status = 200, description = "Pending update discarded"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Rule feed manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn discard_pending(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<StatusResponse>, StatusCode> {

    let rule_feed_manager = state.rule_feed_manager.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    rule_feed_manager.discard_pending();

    Ok(Json(StatusResponse {
        status: "success".to_string(),
        message: "Pending update discarded".to_string(),
    }))
}
