use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;

use super::common::{OptionalAuth};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IcmpStatusResponse {
    pub enabled: bool,
    pub status: String,
    pub backend: Option<String>,
    pub stats: Option<IcmpStats>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IcmpStats {
    pub packets_blocked_v4: u64,
    pub packets_blocked_v6: u64,
    pub packets_allowed_v4: u64,
    pub packets_allowed_v6: u64,
    pub rate_limited_v4: u64,
    pub rate_limited_v6: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IcmpConfigResponse {
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateIcmpConfigRequest {
    pub config: serde_json::Value,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IcmpEnableResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IcmpBackend {
    pub name: String,
    pub available: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IcmpBackendsResponse {
    pub backends: Vec<IcmpBackend>,
    pub current_backend: Option<String>,
}

#[utoipa::path(
    get,
    path = "/icmp/status",
    tag = "ICMP",
    responses(
        (status = 200, description = "ICMP filter status"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
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

        let backend = match filter.config() {
            Some(cfg) => Some(format!("{:?}", cfg.filter_type)),
            None => None,
        };

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
    tag = "ICMP",
    responses(
        (status = 200, description = "ICMP filter configuration"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IcmpConfigResponse>, StatusCode> {

    let config = state.config.read().await;

    #[cfg(feature = "icmp-filter")]
    {
        let icmp_config = &config.main.icmp_filter;
        let json = serde_json::to_value(icmp_config).unwrap_or(serde_json::Value::Null);
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
    tag = "ICMP",
    responses(
        (status = 200, description = "ICMP filter config updated"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateIcmpConfigRequest>,
) -> Result<Json<IcmpEnableResponse>, StatusCode> {

    #[cfg(feature = "icmp-filter")]
    {
        let new_config: crate::icmp_filter::IcmpFilterConfig = match serde_json::from_value(req.config) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Json(IcmpEnableResponse {
                    success: false,
                    message: format!("Invalid config: {}", e),
                }));
            }
        };

        if let Err(e) = new_config.validate() {
            return Ok(Json(IcmpEnableResponse {
                success: false,
                message: format!("Config validation error: {}", e),
            }));
        }

        let Some(icmp_filter) = state.icmp_filter() else {
            return Ok(Json(IcmpEnableResponse {
                success: false,
                message: "ICMP filter not initialized".to_string(),
            }));
        };

        {
            let mut filter = icmp_filter.write().await;
            if let Err(e) = filter.update_config(new_config) {
                return Ok(Json(IcmpEnableResponse {
                    success: false,
                    message: format!("Failed to update config: {}", e),
                }));
            }
        }

        {
            let mut config = state.config.write().await;
            let icmp_cfg = icmp_filter.read().await;
            if let Some(cfg) = icmp_cfg.config() {
                config.main.icmp_filter = cfg.clone();
            }
        }

        return Ok(Json(IcmpEnableResponse {
            success: true,
            message: "Configuration updated".to_string(),
        }));
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = (state, req);
        Ok(Json(IcmpEnableResponse {
            success: false,
            message: "ICMP filter not enabled (compile with icmp-filter feature)".to_string(),
        }))
    }
}

#[utoipa::path(
    post,
    path = "/icmp/enable",
    tag = "ICMP",
    responses(
        (status = 200, description = "ICMP filter enabled"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn enable(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IcmpEnableResponse>, StatusCode> {

    #[cfg(feature = "icmp-filter")]
    {
        let Some(icmp_filter) = state.icmp_filter() else {
            return Ok(Json(IcmpEnableResponse {
                success: false,
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
                    return Ok(Json(IcmpEnableResponse {
                        success: false,
                        message: format!("Failed to enable: {}", e),
                    }));
                }
            }
        }

        Ok(Json(IcmpEnableResponse {
            success: true,
            message: "ICMP filter enabled".to_string(),
        }))
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = state;
        Ok(Json(IcmpEnableResponse {
            success: false,
            message: "ICMP filter not enabled (compile with icmp-filter feature)".to_string(),
        }))
    }
}

#[utoipa::path(
    post,
    path = "/icmp/disable",
    tag = "ICMP",
    responses(
        (status = 200, description = "ICMP filter disabled"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn disable(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IcmpEnableResponse>, StatusCode> {

    #[cfg(feature = "icmp-filter")]
    {
        let Some(icmp_filter) = state.icmp_filter() else {
            return Ok(Json(IcmpEnableResponse {
                success: false,
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
                    return Ok(Json(IcmpEnableResponse {
                        success: false,
                        message: format!("Failed to disable: {}", e),
                    }));
                }
            }
        }

        Ok(Json(IcmpEnableResponse {
            success: true,
            message: "ICMP filter disabled".to_string(),
        }))
    }

    #[cfg(not(feature = "icmp-filter"))]
    {
        let _ = state;
        Ok(Json(IcmpEnableResponse {
            success: false,
            message: "ICMP filter not enabled (compile with icmp-filter feature)".to_string(),
        }))
    }
}

#[utoipa::path(
    get,
    path = "/icmp/backends",
    tag = "ICMP",
    responses(
        (status = 200, description = "List of available ICMP backends"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_backends(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IcmpBackendsResponse>, StatusCode> {

    #[cfg(feature = "icmp-filter")]
    {
        let backends = crate::icmp_filter::available_backends();
        let current = state.icmp_filter.as_ref().and_then(|f| {
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
