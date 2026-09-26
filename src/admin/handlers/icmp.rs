use super::super::state::AdminState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(feature = "icmp-filter")]
use synvoid_core::admin_mutation::{AdminActor, AdminAuditEvent, AdminMutationAuthority};
use synvoid_core::admin_mutation::{AdminMutationResult, AdminMutationStatus, PropagationStatus};
use utoipa::ToSchema;

use super::common::OptionalAuth;

#[derive(Debug, Serialize, ToSchema)]
pub struct IcmpStatusResponse {
    pub enabled: bool,
    pub status: String,
    pub backend: Option<String>,
    pub stats: Option<IcmpStats>,
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct IcmpBackend {
    pub name: String,
    pub available: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IcmpBackendsResponse {
    pub backends: Vec<IcmpBackend>,
    pub current_backend: Option<String>,
}

#[utoipa::path(
    get,
    path = "/icmp/status",
    responses(
        (status = 200, description = "ICMP filter status", body = IcmpStatusResponse),
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
            return Ok(Json(IcmpStatusResponse {
                enabled: false,
                status: "not_configured".to_string(),
                backend: None,
                stats: None,
            }));
        };

        let filter = icmp_filter.read().await;
        let is_enabled = filter.is_enabled();
        let status_info = filter.status();

        let (status_str, stats) = if is_enabled {
            let st = status_info.unwrap_or_else(|| crate::icmp_filter::FilterStatus {
                enabled: true,
                backend: crate::icmp_filter::FilterBackend::Nftables,
                config: Default::default(),
            });
            let status_str = if st.enabled { "enabled" } else { "disabled" };

            let stats = IcmpStats {
                packets_blocked_v4: 0,
                packets_blocked_v6: 0,
                packets_allowed_v4: 0,
                packets_allowed_v6: 0,
                rate_limited_v4: 0,
                rate_limited_v6: 0,
            };

            tracing::debug!("ICMP stats requested but packet counters not available from backend");

            (status_str.to_string(), Some(stats))
        } else {
            ("disabled".to_string(), None)
        };

        let backend = filter.config().map(|cfg| format!("{:?}", cfg.filter_type));

        #[allow(clippy::needless_return)]
        return Ok(Json(IcmpStatusResponse {
            enabled: is_enabled,
            status: status_str,
            backend,
            stats,
        }));
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = state;
        Ok(Json(IcmpStatusResponse {
            enabled: false,
            status: "not_configured".to_string(),
            backend: None,
            stats: None,
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
        (status = 200, description = "ICMP filter config updated"),
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

        {
            let mut filter = icmp_filter.write().await;
            if let Err(e) = filter.update_config(enforcement_config) {
                return Ok(Json(AdminMutationResult {
                    status: AdminMutationStatus::Failed,
                    target: "icmp_config".to_string(),
                    local_store_mutated: false,
                    propagation: PropagationStatus::NotApplicable,
                    event_id: None,
                    audit_id: None,
                    message: format!("Failed to update config: {}", e),
                }));
            }
        }

        {
            // Persist the validated application DTO directly. The enforcement
            // DTO was already derived from it field-by-field above; no
            // model-to-model JSON conversion remains (Phase 85).
            let mut config = state.process.config.write().await;
            config.main.icmp_filter = app_config;
        }

        #[allow(clippy::needless_return)]
        return Ok(Json(AdminMutationResult {
            status: AdminMutationStatus::Applied,
            target: "icmp_config".to_string(),
            local_store_mutated: true,
            propagation: PropagationStatus::NotApplicable,
            event_id: None,
            audit_id: None,
            message: "Configuration updated".to_string(),
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
        (status = 200, description = "ICMP filter enabled", body = AdminMutationResult<String>),
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

        {
            let mut filter = icmp_filter.write().await;
            match filter.enable() {
                Ok(_) => {
                    crate::icmp_filter::metrics::icmp_filter_enabled(true);
                    crate::icmp_filter::metrics::icmp_filter_status("enabled");
                }
                Err(e) => {
                    crate::icmp_filter::metrics::icmp_filter_status("error");
                    return Ok(Json(AdminMutationResult {
                        status: AdminMutationStatus::Failed,
                        target: "icmp_filter".to_string(),
                        local_store_mutated: false,
                        propagation: PropagationStatus::NotApplicable,
                        event_id: None,
                        audit_id: None,
                        message: format!("Failed to enable: {}", e),
                    }));
                }
            }
        }

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
            resulting_state: Some(serde_json::json!({"enabled": true})),
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
            message: "ICMP filter enabled".to_string(),
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
        (status = 200, description = "ICMP filter disabled", body = AdminMutationResult<String>),
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

        {
            let mut filter = icmp_filter.write().await;
            match filter.disable() {
                Ok(_) => {
                    crate::icmp_filter::metrics::icmp_filter_enabled(false);
                    crate::icmp_filter::metrics::icmp_filter_status("disabled");
                }
                Err(e) => {
                    return Ok(Json(AdminMutationResult {
                        status: AdminMutationStatus::Failed,
                        target: "icmp_filter".to_string(),
                        local_store_mutated: false,
                        propagation: PropagationStatus::NotApplicable,
                        event_id: None,
                        audit_id: None,
                        message: format!("Failed to disable: {}", e),
                    }));
                }
            }
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
            resulting_state: Some(serde_json::json!({"enabled": false})),
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
            message: "ICMP filter disabled".to_string(),
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
        (status = 200, description = "List of ICMP filter backends", body = IcmpBackendsResponse),
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
        let backends = crate::icmp_filter::available_backends();
        let current = state.honeypot.icmp_filter.as_ref().and_then(|f| {
            let cfg = f.blocking_read();
            cfg.config().map(|c| format!("{:?}", c.filter_type))
        });

        let backend_list: Vec<IcmpBackend> = backends
            .iter()
            .map(|b| IcmpBackend {
                name: format!("{:?}", b),
                available: true,
            })
            .collect();

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
