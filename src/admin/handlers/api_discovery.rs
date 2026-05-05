use super::common::OptionalAuth;
use axum::{http::StatusCode, Json};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiDiscoveryResponse {
    pub name: String,
    pub version: String,
    pub openapi_url: String,
    pub docs_url: String,
    pub categories: Vec<ApiCategory>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiCategory {
    pub name: String,
    pub endpoints: Vec<ApiEndpoint>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiEndpoint {
    pub path: String,
    pub method: String,
}

fn get_api_endpoints() -> Vec<ApiCategory> {
    vec![
        ApiCategory {
            name: "stats".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/stats/summary".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/stats/sites".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/stats/history".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/stats/attacks".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/stats/cache".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/stats/bandwidth".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/stats/requests".to_string(),
                    method: "GET".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "sites".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/sites".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/sites".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/sites/{site_id}".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/sites/{site_id}".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/sites/{site_id}".to_string(),
                    method: "DELETE".to_string(),
                },
                ApiEndpoint {
                    path: "/sites/{site_id}/theme".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/sites/{site_id}/theme".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/sites/{site_id}/bot-detection".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/sites/{site_id}/bot-detection".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/sites/{site_id}/error-pages".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/sites/{site_id}/error-pages".to_string(),
                    method: "PUT".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "config".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/config/main".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/main".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/config/schema".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/reload".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/config/log-level".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/log-level".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/config/export".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/import".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/config/validate".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/config/versions".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/versions/{id}".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/rollback/{id}".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/config/diff".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/bundle".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/bundle".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/config/dns".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/dns".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/config/mesh".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/mesh".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/config/overseer".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/overseer".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/config/process-manager".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/process-manager".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/config/supervisor".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/config/supervisor".to_string(),
                    method: "PUT".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "mesh".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/mesh/status".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/nodes".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/nodes/{node_id}".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/organizations".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/organizations/{org_id}".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/organizations/{org_id}/public-key".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/topology".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/topology/graph".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/ban/ip".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/ban/mesh-id".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/ban".to_string(),
                    method: "DELETE".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/bans".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/behavioral/stats".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/behavioral/config".to_string(),
                    method: "GET".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "honeypot".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/honeypot/status".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/honeypot/control".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/honeypot/config".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/honeypot/config".to_string(),
                    method: "PUT".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "system".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/system/info".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/system/master".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/system/workers".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/system/workers/count".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/system/workers/scale".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/system/workers/{worker_id}/restart".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/system/workers/batch-restart".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/system/overseer".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/system/php-pools".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/system/php-pools/reload".to_string(),
                    method: "POST".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "probes".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/probes".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/stats".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/block".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/{ip}".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/{ip}".to_string(),
                    method: "DELETE".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/words".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/words/stats".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/words/{ip}".to_string(),
                    method: "DELETE".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/upstream".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/upstream/stats".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/probes/upstream/{ip}".to_string(),
                    method: "DELETE".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "yara".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/yara/status".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/yara/submissions".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/yara/submissions/{submission_id}".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/yara/submissions/{submission_id}".to_string(),
                    method: "DELETE".to_string(),
                },
                ApiEndpoint {
                    path: "/yara/submissions/{submission_id}/approve".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/yara/submissions/{submission_id}/reject".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/yara/broadcast".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/yara/sync".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/yara/submit".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/yara/apply".to_string(),
                    method: "POST".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "threat_level".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/threat-level".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/history".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/history/stats".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/baseline".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/reset".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/set/{level}".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/auto".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/history/backup".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/history/backups".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/history/backups".to_string(),
                    method: "DELETE".to_string(),
                },
                ApiEndpoint {
                    path: "/threat-level/history/prune".to_string(),
                    method: "POST".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "icmp".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/icmp/status".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/icmp/config".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/icmp/config".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/icmp/enable".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/icmp/disable".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/icmp/backends".to_string(),
                    method: "GET".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "logs".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/logs".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/audit-logs".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/error-pages".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/error-pages/{code}".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/error-pages/{code}".to_string(),
                    method: "PUT".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "plugins".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/plugins/status".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/plugins/metrics".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/plugins/metrics/{name}".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/plugins/{name}/reload".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/mesh/wasm-modules".to_string(),
                    method: "GET".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "serverless".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/serverless/functions".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/serverless/functions/{name}/stats".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/serverless/health".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/serverless/config".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/serverless/config".to_string(),
                    method: "PUT".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "theme".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/theme".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/theme".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/theme/css".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/theme/presets".to_string(),
                    method: "GET".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "alerting".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/alerts/config".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/alerts/config".to_string(),
                    method: "PUT".to_string(),
                },
                ApiEndpoint {
                    path: "/alerts/test-webhook".to_string(),
                    method: "POST".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "upstreams".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/upstreams".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/upstreams/{site_id}".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/upstreams/{site_id}/check".to_string(),
                    method: "POST".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "tcp_udp".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/tcp-udp/listeners".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/tcp-udp/listeners".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/tcp-udp/listeners/{listener_id}".to_string(),
                    method: "DELETE".to_string(),
                },
                ApiEndpoint {
                    path: "/tcp-udp/protocols".to_string(),
                    method: "GET".to_string(),
                },
            ],
        },
        ApiCategory {
            name: "rule_feed".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    path: "/rules/status".to_string(),
                    method: "GET".to_string(),
                },
                ApiEndpoint {
                    path: "/rules/check".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/rules/apply".to_string(),
                    method: "POST".to_string(),
                },
                ApiEndpoint {
                    path: "/rules/discard".to_string(),
                    method: "POST".to_string(),
                },
            ],
        },
    ]
}

#[utoipa::path(
    get,
    path = "/api",
    responses(
        (status = 200, description = "API discovery information", body = ApiDiscoveryResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "api"
)]
pub async fn get_api_discovery(
    _auth: OptionalAuth,
) -> Result<Json<ApiDiscoveryResponse>, StatusCode> {
    let categories = get_api_endpoints();

    Ok(Json(ApiDiscoveryResponse {
        name: "SynVoid Admin API".to_string(),
        version: "1.0.0".to_string(),
        openapi_url: "/api/openapi.json".to_string(),
        docs_url: "/api/docs".to_string(),
        categories,
    }))
}
