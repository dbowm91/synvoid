//! ICMP admin contract (Phase 90: operator enforcement truth).
//!
//! Operator-visible status is derived from the verified enforcement report
//! (`EnforcementReport` + `verify_live()`), never from a compatibility
//! `enabled` boolean. Requested backend and selected backend are distinct
//! facts. Unsupported packet counters are absent (`null`), never fabricated
//! as zero. `GET /icmp/status` performs bounded read-only verification and
//! never mutates firewall policy.

use super::super::state::AdminState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(feature = "icmp-filter")]
use synvoid_core::admin_mutation::{AdminActor, AdminAuditEvent, AdminMutationAuthority};
use synvoid_core::admin_mutation::{AdminMutationResult, AdminMutationStatus, PropagationStatus};
use utoipa::ToSchema;

use super::common::OptionalAuth;

/// Canonical enforcement states exposed on the wire. `not_configured` is
/// the operator-facing alias for "no ICMP subsystem configured".
fn enforcement_state_str(state: &str) -> &str {
    state
}

/// Map the crate lifecycle state to its wire string.
#[cfg(feature = "icmp-filter")]
fn wire_enforcement_state(state: crate::icmp_filter::EnforcementState) -> &'static str {
    match state {
        crate::icmp_filter::EnforcementState::Applied => "applied",
        crate::icmp_filter::EnforcementState::Absent => "absent",
        crate::icmp_filter::EnforcementState::Drifted => "drifted",
        crate::icmp_filter::EnforcementState::Unknown => "unknown",
    }
}

/// Verified install receipt (fingerprint as hex: raw `u64` would lose
/// precision in JavaScript consumers).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IcmpApplyReceipt {
    pub backend: String,
    pub fingerprint_hex: String,
    pub generation: u64,
    pub applied_at_secs: u64,
    pub ownership_tag: String,
}

#[cfg(feature = "icmp-filter")]
impl From<&crate::icmp_filter::ApplyReceipt> for IcmpApplyReceipt {
    fn from(r: &crate::icmp_filter::ApplyReceipt) -> Self {
        Self {
            backend: format!("{:?}", r.backend),
            fingerprint_hex: crate::icmp_filter::fingerprint_hex(r.fingerprint),
            generation: r.generation,
            applied_at_secs: r.applied_at_secs,
            ownership_tag: r.ownership_tag.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IcmpStatusResponse {
    /// Compatibility: desired/configured enabled state, NOT proof of
    /// enforcement. New consumers must use `desired_enabled` +
    /// `enforcement`.
    pub enabled: bool,
    /// Compatibility: verified enforcement state (`applied` / `absent` /
    /// `drifted` / `unknown` / `not_configured`). New consumers must use
    /// `enforcement`.
    pub status: String,
    /// Compatibility: actual selected backend. New consumers must use
    /// `selected_backend`.
    pub backend: Option<String>,
    /// Always `None`: no backend currently supplies evidence-backed packet
    /// counters, and zero is a real measurement — never a honest
    /// representation of "unsupported". (Phase 90 Finding C.)
    pub stats: Option<IcmpStats>,
    /// Whether the ICMP subsystem is configured in this build.
    pub configured: bool,
    /// Desired enabled/disabled state from the shared lifecycle.
    pub desired_enabled: bool,
    /// Live enforcement truth: `applied` / `absent` / `drifted` /
    /// `unknown` / `not_configured`.
    pub enforcement: String,
    /// Actual selected backend (never the requested `Auto` choice).
    pub selected_backend: Option<String>,
    /// Desired generation from the shared lifecycle.
    pub desired_generation: u64,
    /// Desired policy fingerprint as hex (no raw `u64` on the wire).
    pub desired_fingerprint_hex: Option<String>,
    /// Last verified install receipt, retained as history across disable.
    pub last_receipt: Option<IcmpApplyReceipt>,
    /// Last verification error/detail, where present.
    pub last_verify_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IcmpStats {
    pub packets_blocked_v4: u64,
    pub packets_blocked_v6: u64,
    pub packets_allowed_v4: u64,
    pub packets_allowed_v6: u64,
    pub rate_limited_v4: u64,
    pub rate_limited_v6: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IcmpConfigResponse {
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateIcmpConfigRequest {
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IcmpBackend {
    pub name: String,
    /// Compatibility alias for `usable`. New consumers must use `usable`.
    pub available: bool,
    /// Compiled into this build.
    pub compiled: bool,
    /// Usable on this host (compiled + mechanism present + privilege).
    pub usable: bool,
    /// Human reason when unusable; `None` when usable.
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IcmpBackendsResponse {
    pub backends: Vec<IcmpBackend>,
    pub current_backend: Option<String>,
}

#[cfg(feature = "icmp-filter")]
fn not_configured_status() -> IcmpStatusResponse {
    IcmpStatusResponse {
        enabled: false,
        status: "not_configured".to_string(),
        backend: None,
        stats: None,
        configured: false,
        desired_enabled: false,
        enforcement: "not_configured".to_string(),
        selected_backend: None,
        desired_generation: 0,
        desired_fingerprint_hex: None,
        last_receipt: None,
        last_verify_error: None,
    }
}

#[utoipa::path(
    get,
    path = "/icmp/status",
    responses(
        (status = 200, description = "ICMP filter status (verified enforcement truth)", body = IcmpStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "icmp"
)]
pub async fn get_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IcmpStatusResponse>, StatusCode> {
    #[cfg(feature = "icmp-filter")]
    {
        let Some(icmp_filter) = state.icmp_filter() else {
            return Ok(Json(not_configured_status()));
        };

        // Bounded read-only verification under the manager write lock:
        // `verify_live()` performs readback only (no rule mutation) and
        // updates the shared lifecycle state. The lock is released before
        // JSON serialization. A readback error surfaces as `unknown` plus
        // diagnostic detail — never converted to `applied` from a cached
        // `enabled`.
        struct Snapshot {
            report: crate::icmp_filter::EnforcementReport,
        }
        let snapshot = {
            let mut filter = icmp_filter.write().await;
            filter.verify_live();
            let Some(report) = filter.report() else {
                return Ok(Json(not_configured_status()));
            };
            Snapshot { report }
        };
        let report = snapshot.report;
        let enforcement = wire_enforcement_state(report.live).to_string();
        let selected = Some(format!("{:?}", report.backend));
        let desired_enabled = report.desired_enabled.unwrap_or(false);

        #[allow(clippy::needless_return)]
        return Ok(Json(IcmpStatusResponse {
            // Compat aliases, documented as desired/verified (not proof).
            enabled: desired_enabled,
            status: enforcement.clone(),
            backend: selected.clone(),
            // Truthful absence: no backend supplies packet counters.
            stats: None,
            configured: true,
            desired_enabled,
            enforcement,
            selected_backend: selected,
            desired_generation: report.desired_generation,
            desired_fingerprint_hex: report
                .desired_fingerprint
                .map(crate::icmp_filter::fingerprint_hex),
            last_receipt: report.last_receipt.as_ref().map(IcmpApplyReceipt::from),
            last_verify_error: report.last_verify_error.clone(),
        }));
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = state;
        let _ = enforcement_state_str("not_configured");
        Ok(Json(IcmpStatusResponse {
            enabled: false,
            status: "not_configured".to_string(),
            backend: None,
            stats: None,
            configured: false,
            desired_enabled: false,
            enforcement: "not_configured".to_string(),
            selected_backend: None,
            desired_generation: 0,
            desired_fingerprint_hex: None,
            last_receipt: None,
            last_verify_error: None,
        }))
    }
}

#[utoipa::path(
    get,
    path = "/icmp/config",
    responses(
        (status = 200, description = "ICMP filter configuration", body = IcmpConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "icmp"
)]
pub async fn get_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IcmpConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;

    #[cfg(feature = "icmp-filter")]
    {
        let icmp_config = &config.main.icmp_filter;
        let json = serde_json::to_value(icmp_config).unwrap_or(serde_json::Value::Null);
        #[allow(clippy::needless_return)]
        return Ok(Json(IcmpConfigResponse { config: json }));
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = config;
        Ok(Json(IcmpConfigResponse {
            config: serde_json::Value::Null,
        }))
    }
}

#[utoipa::path(
    put,
    path = "/icmp/config",
    request_body = UpdateIcmpConfigRequest,
    responses(
        (status = 200, description = "ICMP filter config updated (verified lifecycle)"),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "icmp"
)]
pub async fn update_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateIcmpConfigRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    #[cfg(feature = "icmp-filter")]
    {
        // Admin wire shape is the application config DTO. Parse it directly;
        // model-to-model conversion below is exhaustive and typed (Phase 85:
        // no serde_json::Value bridge between the two IcmpFilterConfig types).
        let app_config: synvoid_config::icmp_filter::IcmpFilterConfig =
            match serde_json::from_value(req.config) {
                Ok(c) => c,
                Err(e) => {
                    return Ok(Json(AdminMutationResult {
                        status: AdminMutationStatus::InvalidRejected,
                        target: "icmp_config".to_string(),
                        local_store_mutated: false,
                        propagation: PropagationStatus::NotApplicable,
                        event_id: None,
                        audit_id: None,
                        message: format!("Invalid config: {}", e),
                    }));
                }
            };

        if let Err(e) = app_config.validate() {
            return Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::InvalidRejected,
                target: "icmp_config".to_string(),
                local_store_mutated: false,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: format!("Config validation error: {}", e),
            }));
        }

        // Exhaustive typed adaptation: validates exempt IPs, interfaces,
        // family mapping, rate-limit scope, and backend options. Rejects
        // inexpressible policy with a typed error instead of defaulting.
        let (policy, backend) =
            match crate::icmp_filter::adapt::adapt_app_config_to_policy(&app_config) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(Json(AdminMutationResult {
                        status: AdminMutationStatus::InvalidRejected,
                        target: "icmp_config".to_string(),
                        local_store_mutated: false,
                        propagation: PropagationStatus::NotApplicable,
                        event_id: None,
                        audit_id: None,
                        message: format!("Policy adaptation error: {}", e),
                    }));
                }
            };

        // Surface RFC-aware diagnostics without rewriting user rules.
        // Non-strict preserves existing behavior while making hazards visible.
        {
            let findings = crate::icmp_filter::validate_policy(
                &policy,
                crate::icmp_filter::ValidationRole::Host,
                false,
                crate::icmp_filter::ValidationOverride::default(),
            );
            for f in &findings {
                tracing::warn!("ICMP policy finding [{}]: {}", f.code, f.message);
            }
            let _ = backend;
        }

        // Build the enforcement DTO explicitly field-by-field (no JSON).
        let enforcement_config = {
            use crate::icmp_filter as icmp;
            let exempt_ips = policy.exempt_ips.clone();
            let map_rule =
                |r: &synvoid_config::icmp_filter::IcmpTypeRule| icmp::config::IcmpTypeRule {
                    icmp_type: r.icmp_type,
                    icmp_code: r.icmp_code,
                    action: match r.action {
                        synvoid_config::icmp_filter::IcmpAction::Block => {
                            icmp::config::IcmpAction::Block
                        }
                        synvoid_config::icmp_filter::IcmpAction::Allow => {
                            icmp::config::IcmpAction::Allow
                        }
                    },
                    description: r.description.clone(),
                };
            icmp::config::IcmpFilterConfig {
                enabled: app_config.enabled,
                filter_type: match app_config.filter_type {
                    synvoid_config::icmp_filter::FilterType::Auto => icmp::config::FilterType::Auto,
                    synvoid_config::icmp_filter::FilterType::Nftables => {
                        icmp::config::FilterType::Nftables
                    }
                    synvoid_config::icmp_filter::FilterType::Ebpf => icmp::config::FilterType::Ebpf,
                    synvoid_config::icmp_filter::FilterType::Pf => icmp::config::FilterType::Pf,
                    synvoid_config::icmp_filter::FilterType::WindowsFirewall => {
                        icmp::config::FilterType::WindowsFirewall
                    }
                    synvoid_config::icmp_filter::FilterType::Wfp => icmp::config::FilterType::Wfp,
                },
                direction: match app_config.direction {
                    synvoid_config::icmp_filter::Direction::Both => icmp::config::Direction::Both,
                    synvoid_config::icmp_filter::Direction::Inbound => {
                        icmp::config::Direction::Inbound
                    }
                    synvoid_config::icmp_filter::Direction::Outbound => {
                        icmp::config::Direction::Outbound
                    }
                },
                interfaces: match &app_config.interfaces {
                    synvoid_config::icmp_filter::InterfaceSpec::All => {
                        icmp::config::InterfaceSpec::All
                    }
                    synvoid_config::icmp_filter::InterfaceSpec::Specific(ifaces) => {
                        icmp::config::InterfaceSpec::Specific(ifaces.clone())
                    }
                },
                rate_limit: policy.rate_limit.map(|rl| icmp::config::RateLimitConfig {
                    enabled: true,
                    packets_per_second: rl.packets_per_second,
                    burst: rl.burst,
                }),
                exempt_ips,
                table_name: backend.table_name.clone(),
                icmp_type_rules: app_config.icmp_type_rules.iter().map(map_rule).collect(),
                icmpv6_type_rules: app_config.icmpv6_type_rules.iter().map(map_rule).collect(),
                ebpf_bytecode_path: backend.ebpf_bytecode_path.clone(),
            }
        };

        if let Err(e) = enforcement_config.validate() {
            return Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::InvalidRejected,
                target: "icmp_config".to_string(),
                local_store_mutated: false,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: format!("Enforcement config validation error: {}", e),
            }));
        }

        let Some(icmp_filter) = state.icmp_filter() else {
            return Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::Failed,
                target: "icmp_config".to_string(),
                local_store_mutated: false,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: "ICMP filter not initialized".to_string(),
            }));
        };

        // Transactional driver: install + verify before anything is called
        // applied. On rejection the previous generation is retained and
        // nothing is persisted as applied (Phase 87 rollback discipline,
        // Phase 90 Finding F).
        let verified: Option<IcmpApplyReceipt> = {
            let mut filter = icmp_filter.write().await;
            match filter.update_config(enforcement_config) {
                Ok(()) => filter
                    .report()
                    .and_then(|r| r.last_receipt.map(|rc| IcmpApplyReceipt::from(&rc))),
                Err(e) => {
                    let detail = filter
                        .report()
                        .and_then(|r| r.last_verify_error.clone())
                        .unwrap_or_else(|| e.to_string());
                    return Ok(Json(AdminMutationResult {
                        status: AdminMutationStatus::Failed,
                        target: "icmp_config".to_string(),
                        local_store_mutated: false,
                        propagation: PropagationStatus::NotApplicable,
                        event_id: None,
                        audit_id: None,
                        message: format!("Failed to update config: {e} ({detail})"),
                    }));
                }
            }
        };

        {
            // Persist the validated application DTO directly. The enforcement
            // DTO was already derived from it field-by-field above; no
            // model-to-model JSON conversion remains (Phase 85).
            let mut config = state.process.config.write().await;
            config.main.icmp_filter = app_config;
        }

        let message = match verified {
            Some(rc) => format!(
                "Configuration updated (backend {} generation {} fp {})",
                rc.backend, rc.generation, rc.fingerprint_hex
            ),
            None => "Configuration updated".to_string(),
        };
        #[allow(clippy::needless_return)]
        return Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Applied,
            target: "icmp_config".to_string(),
            local_store_mutated: true,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message,
        }));
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = (state, req);
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Failed,
            target: "icmp_config".to_string(),
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "ICMP filter not enabled (compile with icmp-filter feature)".to_string(),
        }))
    }
}

#[utoipa::path(
    post,
    path = "/icmp/enable",
    responses(
        (status = 200, description = "ICMP filter enabled (verified lifecycle)", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "icmp"
)]
pub async fn enable(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    #[cfg(feature = "icmp-filter")]
    {
        let Some(icmp_filter) = state.icmp_filter() else {
            return Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::Failed,
                target: "icmp_filter".to_string(),
                local_store_mutated: false,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: "ICMP filter not initialized".to_string(),
            }));
        };

        // Verified lifecycle: Applied is returned only when installation
        // plus live verification succeeds (Phase 90 Finding F).
        let receipt: IcmpApplyReceipt = {
            let mut filter = icmp_filter.write().await;
            match filter.enable() {
                Ok(rc) => {
                    crate::icmp_filter::metrics::icmp_filter_enabled(true);
                    crate::icmp_filter::metrics::icmp_filter_status("enabled");
                    IcmpApplyReceipt::from(&rc)
                }
                Err(e) => {
                    crate::icmp_filter::metrics::icmp_filter_status("error");
                    let detail = filter
                        .report()
                        .and_then(|r| r.last_verify_error.clone())
                        .unwrap_or_else(|| e.to_string());
                    return Ok(Json(AdminMutationResult {
                        status: AdminMutationStatus::Failed,
                        target: "icmp_filter".to_string(),
                        local_store_mutated: false,
                        propagation: PropagationStatus::NotApplicable,
                        event_id: None,
                        audit_id: None,
                        message: format!("Failed to enable: {e} ({detail})"),
                    }));
                }
            }
        };

        let audit_id = uuid::Uuid::new_v4().to_string();
        let audit_event = AdminAuditEvent {
            audit_id: audit_id.clone(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            actor: AdminActor::new(AdminMutationAuthority::AdminManual),
            action: "icmp_enable".to_string(),
            target_kind: "icmp_filter".to_string(),
            target_id: "icmp_filter".to_string(),
            prior_state: None,
            requested_state: Some(serde_json::json!({"enabled": true})),
            resulting_state: Some(serde_json::json!({
                "enabled": true,
                "backend": receipt.backend,
                "enforcement": "applied",
                "generation": receipt.generation,
                "fingerprint_hex": receipt.fingerprint_hex,
            })),
            mutation_status: AdminMutationStatus::Applied,
            propagation_status: PropagationStatus::NotApplicable,
            event_id: None,
        };
        state.audit.log_audit_event(&audit_event);

        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Applied,
            target: "icmp_filter".to_string(),
            local_store_mutated: true,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: Some(audit_id),
            message: format!(
                "ICMP filter enabled (backend {} generation {} fp {})",
                receipt.backend, receipt.generation, receipt.fingerprint_hex
            ),
        }))
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = state;
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Failed,
            target: "icmp_filter".to_string(),
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "ICMP filter not enabled (compile with icmp-filter feature)".to_string(),
        }))
    }
}

#[utoipa::path(
    post,
    path = "/icmp/disable",
    responses(
        (status = 200, description = "ICMP filter disabled (verified absent)", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "icmp"
)]
pub async fn disable(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    #[cfg(feature = "icmp-filter")]
    {
        let Some(icmp_filter) = state.icmp_filter() else {
            return Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::Failed,
                target: "icmp_filter".to_string(),
                local_store_mutated: false,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: "ICMP filter not initialized".to_string(),
            }));
        };

        // Verified lifecycle: Applied is returned only when owned
        // enforcement is verified absent. Unknown/Drifted dispositions are
        // Failed with the state preserved for diagnostics (Phase 90).
        {
            let mut filter = icmp_filter.write().await;
            if let Err(e) = filter.disable() {
                let detail = filter
                    .report()
                    .and_then(|r| r.last_verify_error.clone())
                    .unwrap_or_else(|| e.to_string());
                return Ok(Json(AdminMutationResult {
                    status: AdminMutationStatus::Failed,
                    target: "icmp_filter".to_string(),
                    local_store_mutated: false,
                    propagation: PropagationStatus::NotApplicable,
                    event_id: None,
                    audit_id: None,
                    message: format!("Failed to disable: {e} ({detail})"),
                }));
            }
            crate::icmp_filter::metrics::icmp_filter_enabled(false);
            crate::icmp_filter::metrics::icmp_filter_status("disabled");
        }

        let audit_id = uuid::Uuid::new_v4().to_string();
        let audit_event = AdminAuditEvent {
            audit_id: audit_id.clone(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            actor: AdminActor::new(AdminMutationAuthority::AdminManual),
            action: "icmp_disable".to_string(),
            target_kind: "icmp_filter".to_string(),
            target_id: "icmp_filter".to_string(),
            prior_state: None,
            requested_state: Some(serde_json::json!({"enabled": false})),
            resulting_state: Some(serde_json::json!({
                "enabled": false,
                "enforcement": "absent",
            })),
            mutation_status: AdminMutationStatus::Applied,
            propagation_status: PropagationStatus::NotApplicable,
            event_id: None,
        };
        state.audit.log_audit_event(&audit_event);

        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Applied,
            target: "icmp_filter".to_string(),
            local_store_mutated: true,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: Some(audit_id),
            message: "ICMP filter disabled (enforcement verified absent)".to_string(),
        }))
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = state;
        Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Failed,
            target: "icmp_filter".to_string(),
            local_store_mutated: false,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "ICMP filter not enabled (compile with icmp-filter feature)".to_string(),
        }))
    }
}

#[utoipa::path(
    get,
    path = "/icmp/backends",
    responses(
        (status = 200, description = "ICMP backend probe inventory with selected backend", body = IcmpBackendsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "icmp"
)]
pub async fn list_backends(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IcmpBackendsResponse>, StatusCode> {
    #[cfg(feature = "icmp-filter")]
    {
        // Probe truth (Phase 90 Finding D): compiled/usable/reason per
        // relevant backend, even when unusable. `available` stays as a
        // compatibility alias for `usable`.
        let backend_list: Vec<IcmpBackend> = crate::icmp_filter::probe_backend_inventory()
            .into_iter()
            .map(|e| IcmpBackend {
                name: format!("{:?}", e.backend),
                available: e.usable,
                compiled: e.compiled,
                usable: e.usable,
                reason: if e.usable { None } else { Some(e.reason) },
            })
            .collect();

        // Selected backend comes from the authoritative manager report,
        // never from requested config. Read lock held only for the report
        // snapshot; released before serialization.
        let current = {
            let mut selected = None;
            if let Some(f) = state.icmp_filter() {
                let guard = f.read().await;
                selected = guard.report().map(|r| format!("{:?}", r.backend));
            }
            selected
        };

        Ok(Json(IcmpBackendsResponse {
            backends: backend_list,
            current_backend: current,
        }))
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = state;
        Ok(Json(IcmpBackendsResponse {
            backends: vec![],
            current_backend: None,
        }))
    }
}

#[cfg(test)]
mod dto_tests {
    use super::*;

    fn applied_response() -> IcmpStatusResponse {
        IcmpStatusResponse {
            enabled: true,
            status: "applied".to_string(),
            backend: Some("Nftables".to_string()),
            stats: None,
            configured: true,
            desired_enabled: true,
            enforcement: "applied".to_string(),
            selected_backend: Some("Nftables".to_string()),
            desired_generation: 3,
            desired_fingerprint_hex: Some("0123456789abcdef".to_string()),
            last_receipt: Some(IcmpApplyReceipt {
                backend: "Nftables".to_string(),
                fingerprint_hex: "0123456789abcdef".to_string(),
                generation: 3,
                applied_at_secs: 1_700_000_000,
                ownership_tag: "nft:inet:synvoid_icmp:gen:0123456789abcdef".to_string(),
            }),
            last_verify_error: None,
        }
    }

    #[test]
    fn status_pins_applied_shape() {
        let json = serde_json::to_value(applied_response()).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["status"], "applied");
        assert_eq!(json["backend"], "Nftables");
        assert!(json["stats"].is_null());
        assert_eq!(json["configured"], true);
        assert_eq!(json["desired_enabled"], true);
        assert_eq!(json["enforcement"], "applied");
        assert_eq!(json["selected_backend"], "Nftables");
        assert_eq!(json["desired_generation"], 3);
        assert_eq!(json["desired_fingerprint_hex"], "0123456789abcdef");
        assert_eq!(json["last_receipt"]["generation"], 3);
        assert_eq!(json["last_receipt"]["fingerprint_hex"], "0123456789abcdef");
        // No raw u64 fingerprint on the wire (JS precision).
        assert!(json.get("desired_fingerprint").is_none());
        assert!(json["last_receipt"].get("fingerprint").is_none());
    }

    #[test]
    fn status_pins_disabled_shape() {
        let mut r = applied_response();
        r.enabled = false;
        r.status = "absent".to_string();
        r.desired_enabled = false;
        r.enforcement = "absent".to_string();
        r.last_verify_error = None;
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["status"], "absent");
        assert_eq!(json["enforcement"], "absent");
        assert!(json["stats"].is_null());
        // Receipt retained as history across disable.
        assert_eq!(json["last_receipt"]["generation"], 3);
    }

    #[test]
    fn status_pins_drifted_shape() {
        let mut r = applied_response();
        r.status = "drifted".to_string();
        r.enforcement = "drifted".to_string();
        r.last_verify_error = Some("owned table fingerprint mismatch".to_string());
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["enforcement"], "drifted");
        assert_eq!(
            json["last_verify_error"],
            "owned table fingerprint mismatch"
        );
    }

    #[test]
    fn status_pins_unknown_shape() {
        let mut r = applied_response();
        r.status = "unknown".to_string();
        r.enforcement = "unknown".to_string();
        r.last_verify_error = Some("readback failed: pfctl unavailable".to_string());
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["enforcement"], "unknown");
        assert!(json["last_verify_error"]
            .as_str()
            .unwrap()
            .contains("pfctl"));
    }

    #[test]
    fn status_pins_explicit_backend_selected() {
        let mut r = applied_response();
        r.backend = Some("Wfp".to_string());
        r.selected_backend = Some("Wfp".to_string());
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["backend"], "Wfp");
        assert_eq!(json["selected_backend"], "Wfp");
    }

    #[test]
    fn backends_pin_object_shape_with_reasons() {
        let resp = IcmpBackendsResponse {
            backends: vec![
                IcmpBackend {
                    name: "Nftables".to_string(),
                    available: true,
                    compiled: true,
                    usable: true,
                    reason: None,
                },
                IcmpBackend {
                    name: "Ebpf".to_string(),
                    available: false,
                    compiled: false,
                    usable: false,
                    reason: Some("eBPF backend requires Linux + icmp-ebpf feature".to_string()),
                },
            ],
            current_backend: Some("Nftables".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("backends").unwrap().is_array());
        assert_eq!(json["backends"][0]["usable"], true);
        assert_eq!(json["backends"][1]["usable"], false);
        assert!(json["backends"][1]["reason"]
            .as_str()
            .unwrap()
            .contains("icmp-ebpf"));
        assert_eq!(json["current_backend"], "Nftables");
        // Object shape (not a raw array) with selected backend.
        assert!(json.get("current_backend").is_some());
    }

    #[test]
    fn stats_unavailable_is_null_not_zero() {
        // A zero-filled stats object would claim a real measurement of
        // nothing-blocked. The contract is null (typed-unavailable).
        let r = applied_response();
        let json = serde_json::to_value(&r).unwrap();
        assert!(
            json["stats"].is_null(),
            "stats must be null when counters are unavailable, never zero-filled"
        );
    }
}
