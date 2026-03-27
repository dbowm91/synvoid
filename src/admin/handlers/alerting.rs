use crate::admin::alerting::{AlertConfig, AlertEvent};
use crate::admin::handlers::common::OptionalAuth;
use crate::admin::state::AdminState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AlertConfigResponse {
    pub config: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/alerting/config",
    tag = "Alerting",
    responses(
        (status = 200, description = "Alert configuration"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Alert manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_alert_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AlertConfigResponse>, StatusCode> {
    let alert_manager = state
        .process
        .alert_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let config = alert_manager.get_config().await;
    let json = serde_json::to_value(&config).unwrap_or(serde_json::Value::Null);

    Ok(Json(AlertConfigResponse { config: json }))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateAlertConfigRequest {
    pub config: serde_json::Value,
}

#[utoipa::path(
    put,
    path = "/alerting/config",
    tag = "Alerting",
    responses(
        (status = 200, description = "Alert configuration updated"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Alert manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_alert_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateAlertConfigRequest>,
) -> Result<Json<AlertConfigResponse>, StatusCode> {
    let alert_manager = state
        .process
        .alert_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let config: AlertConfig =
        serde_json::from_value(req.config.clone()).map_err(|_| StatusCode::BAD_REQUEST)?;
    alert_manager.update_config(config).await;

    Ok(Json(AlertConfigResponse { config: req.config }))
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TestAlertResponse {
    pub success: bool,
    pub message: String,
}

#[utoipa::path(
    post,
    path = "/alerting/test",
    tag = "Alerting",
    responses(
        (status = 200, description = "Test alert result", body = [TestAlertResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Alert manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn test_webhook(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TestAlertResponse>, StatusCode> {
    let alert_manager = state
        .process
        .alert_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let config = alert_manager.get_config().await;

    if !config.webhook_enabled || config.webhook_urls.is_empty() {
        return Ok(Json(TestAlertResponse {
            success: false,
            message: "Webhook not configured".to_string(),
        }));
    }

    let test_event = AlertEvent {
        timestamp: chrono::Utc::now().timestamp(),
        rule_name: "Test Alert".to_string(),
        metric: "test".to_string(),
        value: 1.0,
        threshold: 0.0,
        message: "This is a test alert from MaluWAF".to_string(),
    };

    alert_manager
        .send_webhook(&config.webhook_urls, &test_event)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(TestAlertResponse {
        success: true,
        message: "Test webhook sent".to_string(),
    }))
}
