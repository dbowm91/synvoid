#![cfg(feature = "mesh")]

use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyShadowQuery {
    pub indicator: String,
    #[serde(default)]
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, ToSchema)]
pub struct PolicyShadowResponse {
    pub indicator_value: String,
    pub threat_type: String,
    pub decision_class: String,
    pub reason: String,
    pub advisory_status: Option<String>,
    pub advisory_freshness: Option<String>,
    pub canonical_freshness: Option<String>,
    pub raw_lookup_present: Option<bool>,
    pub composed_actionable: bool,
}

#[derive(Debug, Clone, serde::Serialize, ToSchema)]
pub struct PolicyShadowStatsResponse {
    pub actionable: u64,
    pub advisory_only: u64,
    pub not_actionable: u64,
    pub deferred: u64,
    pub not_configured: u64,
    pub raw_disagreement: u64,
    pub canonical_unavailable: u64,
    pub advisory_missing: u64,
}

fn parse_threat_type(s: &str) -> Option<synvoid_mesh::mesh::protocol::ThreatType> {
    match s {
        "IpBlock" | "ip_block" => Some(synvoid_mesh::mesh::protocol::ThreatType::IpBlock),
        "IpThrottle" | "ip_throttle" => Some(synvoid_mesh::mesh::protocol::ThreatType::IpThrottle),
        "RateLimitViolation" | "rate_limit_violation" => {
            Some(synvoid_mesh::mesh::protocol::ThreatType::RateLimitViolation)
        }
        "SuspiciousActivity" | "suspicious_activity" => {
            Some(synvoid_mesh::mesh::protocol::ThreatType::SuspiciousActivity)
        }
        "AsnBlock" | "asn_block" => Some(synvoid_mesh::mesh::protocol::ThreatType::AsnBlock),
        "DomainBlock" | "domain_block" => {
            Some(synvoid_mesh::mesh::protocol::ThreatType::DomainBlock)
        }
        "UrlBlock" | "url_block" => Some(synvoid_mesh::mesh::protocol::ThreatType::UrlBlock),
        "CertBlock" | "cert_block" => Some(synvoid_mesh::mesh::protocol::ThreatType::CertBlock),
        "Unspecified" | "unspecified" | "" => {
            Some(synvoid_mesh::mesh::protocol::ThreatType::Unspecified)
        }
        _ => None,
    }
}

#[utoipa::path(
    get,
    path = "/mesh/threat-intel/policy-shadow",
    params(
        ("indicator" = String, Query, description = "Indicator value to evaluate (e.g., IP address)"),
        ("type" = Option<String>, Query, description = "Threat type (e.g., IpBlock, DomainBlock)")
    ),
    responses(
        (status = 200, description = "Policy shadow evaluation", body = PolicyShadowResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat intelligence not available"),
        (status = 400, description = "Invalid threat type"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn get_policy_shadow(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<PolicyShadowQuery>,
    _auth: OptionalAuth,
) -> Result<Json<PolicyShadowResponse>, StatusCode> {
    let threat_type_str = query.r#type.as_deref().unwrap_or("IpBlock");
    let threat_type = parse_threat_type(threat_type_str).ok_or(StatusCode::BAD_REQUEST)?;

    let transport = state
        .mesh
        .mesh_transport
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let threat_intel = transport.get_threat_intel().ok_or(StatusCode::NOT_FOUND)?;

    let shadow = threat_intel.evaluate_indicator_policy_shadow(&query.indicator, threat_type);

    Ok(Json(PolicyShadowResponse {
        indicator_value: shadow.indicator_value,
        threat_type: shadow.threat_type,
        decision_class: format!("{:?}", shadow.decision_class),
        reason: shadow.reason,
        advisory_status: shadow.advisory_status,
        advisory_freshness: shadow.advisory_freshness,
        canonical_freshness: shadow.canonical_freshness,
        raw_lookup_present: shadow.raw_lookup_present,
        composed_actionable: shadow.composed_actionable,
    }))
}

#[utoipa::path(
    get,
    path = "/mesh/threat-intel/policy-shadow/stats",
    responses(
        (status = 200, description = "Policy shadow metrics summary", body = PolicyShadowStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn get_policy_shadow_stats(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<PolicyShadowStatsResponse>, StatusCode> {
    Ok(Json(PolicyShadowStatsResponse {
        actionable: synvoid_metrics::get_threat_intel_policy_shadow_actionable(),
        advisory_only: synvoid_metrics::get_threat_intel_policy_shadow_advisory_only(),
        not_actionable: synvoid_metrics::get_threat_intel_policy_shadow_not_actionable(),
        deferred: synvoid_metrics::get_threat_intel_policy_shadow_deferred(),
        not_configured: synvoid_metrics::get_threat_intel_policy_shadow_not_configured(),
        raw_disagreement: synvoid_metrics::get_threat_intel_policy_shadow_raw_disagreement(),
        canonical_unavailable:
            synvoid_metrics::get_threat_intel_policy_shadow_canonical_unavailable(),
        advisory_missing: synvoid_metrics::get_threat_intel_policy_shadow_advisory_missing(),
    }))
}
