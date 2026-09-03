use crate::admin::alerting::{AlertConfig, AlertEvent, DeliveryOutcome, WebhookDeliveryResult};
use crate::admin::handlers::common::OptionalAuth;
use crate::admin::state::AdminState;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AlertConfigResponse {
    pub config: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/alerting/config",
    responses(
        (status = 200, description = "Alert configuration", body = AlertConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Alert manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "alerting"
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
    let json = serde_json::to_value(&config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(AlertConfigResponse { config: json }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAlertConfigRequest {
    pub config: serde_json::Value,
}

#[utoipa::path(
    put,
    path = "/alerting/config",
    request_body = UpdateAlertConfigRequest,
    responses(
        (status = 200, description = "Alert configuration updated", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Alert manager not found"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "alerting"
)]
pub async fn update_alert_config(
    State(state): State<Arc<AdminState>>,
    Extension(client_ip): Extension<super::super::middleware::ClientIp>,
    Json(req): Json<UpdateAlertConfigRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let alert_manager = state
        .process
        .alert_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let config: AlertConfig =
        serde_json::from_value(req.config.clone()).map_err(|_| StatusCode::BAD_REQUEST)?;

    if let Err(e) = config.validate() {
        tracing::warn!("Alert config validation failed: {}", e);
        return Err(StatusCode::BAD_REQUEST);
    }

    alert_manager
        .update_config(config.clone())
        .await
        .map_err(|e| {
            tracing::warn!("Alert config validation failed in update_config: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    // Serialize first so a serialization failure surfaces as 500 instead of
    // silently returning a null config (see H-05).
    let resulting_state =
        serde_json::to_value(&config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual)
            .with_source_ip(client_ip.0.clone()),
        action: "alert.config.update".to_string(),
        target_kind: "alerting".to_string(),
        target_id: "alerting/config".to_string(),
        prior_state: None,
        requested_state: Some(req.config.clone()),
        resulting_state: Some(resulting_state),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "alerting/config".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: "Alert configuration updated".to_string(),
    }))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TestWebhookResult {
    pub outcome: DeliveryOutcome,
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub details: Vec<DestinationResultSummary>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DestinationResultSummary {
    pub url: String,
    pub success: bool,
    pub error: Option<String>,
}

impl From<WebhookDeliveryResult> for TestWebhookResult {
    fn from(r: WebhookDeliveryResult) -> Self {
        Self {
            outcome: r.outcome,
            attempted: r.attempted,
            succeeded: r.succeeded,
            failed: r.failed,
            details: r
                .details
                .into_iter()
                .map(|d| DestinationResultSummary {
                    url: d.url,
                    success: d.success,
                    error: d.error,
                })
                .collect(),
        }
    }
}

#[utoipa::path(
    post,
    path = "/alerting/test-webhook",
    responses(
        (status = 200, description = "Test webhook result", body = TestWebhookResult),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Alert manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "alerting"
)]
pub async fn test_webhook(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TestWebhookResult>, StatusCode> {
    let alert_manager = state
        .process
        .alert_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let config = alert_manager.get_config().await;

    if !config.webhook_enabled || config.webhook_urls.is_empty() {
        return Ok(Json(TestWebhookResult {
            outcome: DeliveryOutcome::Success,
            attempted: 0,
            succeeded: 0,
            failed: 0,
            details: vec![],
        }));
    }

    let test_event = AlertEvent {
        timestamp: chrono::Utc::now().timestamp(),
        rule_name: "Test Alert".to_string(),
        metric: "test".to_string(),
        value: 1.0,
        threshold: 0.0,
        message: "This is a test alert from SynVoid".to_string(),
    };

    let delivery = alert_manager
        .send_webhook(&config.webhook_urls, &test_event)
        .await;

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "alerting.test_webhook".to_string(),
        target_kind: "webhook".to_string(),
        target_id: "test".to_string(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: match delivery.outcome {
            DeliveryOutcome::Success => AdminMutationStatus::Applied,
            DeliveryOutcome::PartialFailure => AdminMutationStatus::Applied,
            DeliveryOutcome::Failure => AdminMutationStatus::Failed,
        },
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(delivery.into()))
}
