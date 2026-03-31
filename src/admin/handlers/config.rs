use super::super::state::AdminState;
use crate::log_controller;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::common::{OptionalAuth, StatusResponse};

#[derive(Debug, Serialize)]
pub struct MainConfigResponse {
    pub config: crate::config::main::MainConfig,
}

#[utoipa::path(
    get,
    path = "/config/main",
    tag = "Config",
    responses(
        (status = 200, description = "Main configuration"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_main_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MainConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;

    Ok(Json(MainConfigResponse {
        config: config.main.clone(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateMainConfigRequest {
    pub config: crate::config::main::MainConfig,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ConfigFieldSchema {
    pub path: String,
    pub label: String,
    pub field_type: String,
    pub default: Option<serde_json::Value>,
    pub description: String,
    pub impact: Option<String>,
    pub options: Option<Vec<String>>,
}

#[utoipa::path(
    get,
    path = "/config/schema",
    tag = "Config",
    responses(
        (status = 200, description = "Configuration schema", body = [ConfigFieldSchema]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_config_schema(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<ConfigFieldSchema>>, StatusCode> {
    let mut schema = vec![ConfigFieldSchema {
        path: "server.host".to_string(),
        label: "Listen Host".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::json!("0.0.0.0")),
        description: "IPv4 address to bind the main server to".to_string(),
        impact: Some("Use 0.0.0.0 for all interfaces, 127.0.0.1 for localhost only".to_string()),
        options: None,
    }];

    schema.push(ConfigFieldSchema {
        path: "server.port".to_string(),
        label: "Listen Port".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(8080)),
        description: "TCP port for the main HTTP server".to_string(),
        impact: Some("Ensure port is not already in use".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "server.host_v6".to_string(),
        label: "Listen Host (IPv6)".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::Value::Null),
        description: "IPv6 address to bind (e.g., ::1 for localhost, :: for all IPv6)".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "server.trusted_proxies".to_string(),
        label: "Trusted Proxies".to_string(),
        field_type: "array".to_string(),
        default: Some(serde_json::json!(["127.0.0.1", "::1"])),
        description: "IP addresses trusted to send X-Forwarded-For headers".to_string(),
        impact: Some("Must include your reverse proxy's IP if behind one".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tokio.worker_threads".to_string(),
        label: "Worker Threads".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::json!("auto")),
        description: "Number of Tokio runtime threads".to_string(),
        impact: Some("auto matches CPU cores".to_string()),
        options: Some(vec![
            "auto".to_string(),
            "1".to_string(),
            "2".to_string(),
            "4".to_string(),
            "8".to_string(),
            "16".to_string(),
        ]),
    });

    schema.push(ConfigFieldSchema {
        path: "http.header_read_timeout_secs".to_string(),
        label: "Header Read Timeout (seconds)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(10)),
        description: "Maximum time to read request headers".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "http.keep_alive_timeout_secs".to_string(),
        label: "Keep-Alive Timeout (seconds)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(60)),
        description: "Time to keep connections alive for".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "http.max_headers".to_string(),
        label: "Max Headers".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(128)),
        description: "Maximum number of headers allowed per request".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "http.max_request_line_size".to_string(),
        label: "Max Request Line Size".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(8192)),
        description: "Maximum size of the HTTP request line in bytes".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "http.max_request_size".to_string(),
        label: "Max Request Size (bytes)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(1048576)),
        description: "Maximum size of request body in bytes (default 1MB)".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.enabled".to_string(),
        label: "Enable TLS/SSL".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Enable HTTPS support".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.port".to_string(),
        label: "TLS Port".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(443)),
        description: "Port for HTTPS server".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.cert_path".to_string(),
        label: "Certificate Path".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::Value::Null),
        description: "Path to TLS certificate file (PEM)".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.key_path".to_string(),
        label: "Private Key Path".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::Value::Null),
        description: "Path to TLS private key file".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.prefer_post_quantum".to_string(),
        label: "Prefer Post-Quantum".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Enable post-quantum key exchange algorithms".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.tls_1_3_only".to_string(),
        label: "TLS 1.3 Only".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Only allow TLS 1.3 connections".to_string(),
        impact: Some("Disable for legacy client support".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.acme.enabled".to_string(),
        label: "Enable ACME".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Automatic certificate provisioning via Let's Encrypt".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.acme.email".to_string(),
        label: "ACME Email".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::Value::Null),
        description: "Email for Let's Encrypt account".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.acme.staging".to_string(),
        label: "Use ACME Staging".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Use Let's Encrypt staging (for testing)".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "tls.client_auth.enabled".to_string(),
        label: "Enable mTLS".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Require client certificates".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "http3.enabled".to_string(),
        label: "Enable HTTP/3".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Enable HTTP/3 (QUIC) support".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "http3.port".to_string(),
        label: "HTTP/3 Port".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(443)),
        description: "Port for HTTP/3 server".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "fallback.mode".to_string(),
        label: "Fallback Mode".to_string(),
        field_type: "enum".to_string(),
        default: Some(serde_json::json!("return_404")),
        description: "What to do when no site matches".to_string(),
        impact: None,
        options: Some(vec![
            "return_404".to_string(),
            "return_500".to_string(),
            "serve_static".to_string(),
        ]),
    });

    schema.push(ConfigFieldSchema {
        path: "fallback.upstream".to_string(),
        label: "Fallback Upstream".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::Value::Null),
        description: "Upstream to proxy requests to when no site matches".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "logging.level".to_string(),
        label: "Log Level".to_string(),
        field_type: "enum".to_string(),
        default: Some(serde_json::json!("info")),
        description: "Minimum log level to record".to_string(),
        impact: None,
        options: Some(vec![
            "trace".to_string(),
            "debug".to_string(),
            "info".to_string(),
            "warn".to_string(),
            "error".to_string(),
        ]),
    });

    schema.push(ConfigFieldSchema {
        path: "logging.access_log".to_string(),
        label: "Access Log".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Enable HTTP access logging".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "logging.access_log_dir".to_string(),
        label: "Access Log Directory".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::Value::Null),
        description: "Directory for access log files".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "logging.retention_days".to_string(),
        label: "Log Retention (days)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(5)),
        description: "Number of days to retain logs".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "metrics.enabled".to_string(),
        label: "Enable Metrics".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Enable Prometheus metrics endpoint".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "metrics.port".to_string(),
        label: "Metrics Port".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(9090)),
        description: "Port for Prometheus metrics endpoint".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "admin.enabled".to_string(),
        label: "Enable Admin API".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Enable the admin REST API".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "admin.port".to_string(),
        label: "Admin Port".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(8081)),
        description: "Port for the admin API server".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.ratelimit.mode".to_string(),
        label: "Rate Limit Mode".to_string(),
        field_type: "enum".to_string(),
        default: Some(serde_json::json!("shared")),
        description: "Rate limiting strategy".to_string(),
        impact: None,
        options: Some(vec![
            "shared".to_string(),
            "per_site".to_string(),
            "per_ip".to_string(),
        ]),
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.ratelimit.ip.per_second".to_string(),
        label: "Requests per Second (per IP)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(10)),
        description: "Maximum requests allowed per IP per second".to_string(),
        impact: Some(
            "Lower values provide stronger protection but may block legitimate burst traffic"
                .to_string(),
        ),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.ratelimit.ip.per_minute".to_string(),
        label: "Requests per Minute (per IP)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(60)),
        description: "Maximum requests allowed per IP per minute".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.ratelimit.ip.per_hour".to_string(),
        label: "Requests per Hour (per IP)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(500)),
        description: "Maximum requests allowed per IP per hour".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.ratelimit.ip.burst".to_string(),
        label: "Burst Allowance".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(20)),
        description: "Burst capacity for rate limiting".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.ratelimit.global.per_second".to_string(),
        label: "Global Requests per Second".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(500)),
        description: "Maximum global requests per second".to_string(),
        impact: Some("Protects against global traffic spikes".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.ratelimit.global.max_connections".to_string(),
        label: "Global Max Connections".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(1000)),
        description: "Maximum concurrent connections".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.blocked.paths".to_string(),
        label: "Blocked Paths".to_string(),
        field_type: "array".to_string(),
        default: Some(serde_json::json!(["/.env", "/.git", "/wp-login.php"])),
        description: "Paths to automatically block".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.blocked.use_regex".to_string(),
        label: "Use Regex for Blocked Paths".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Treat blocked paths as regular expressions".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.bot.block_ai_crawlers".to_string(),
        label: "Block AI Crawlers".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Block known AI/ML web crawlers and scrapers".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.bot.enable_css_honeypot".to_string(),
        label: "Enable CSS Honeypot".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Use CSS-based bot detection".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.bot.enable_js_challenge".to_string(),
        label: "Enable JS Challenge".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Use JavaScript-based challenge for bot detection".to_string(),
        impact: Some("May affect SEO crawlers".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.honeypot.endpoints_file".to_string(),
        label: "Honeypot Endpoints File".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::json!("config/honeypot_endpoints.txt")),
        description: "File containing honeypot endpoint paths".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.honeypot.block.enabled".to_string(),
        label: "Honeypot Auto-Block".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Automatically ban IPs that hit honeypot endpoints".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.honeypot.block.ban_duration".to_string(),
        label: "Honeypot Ban Duration".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::json!("24h")),
        description: "Duration to ban IPs that trigger honeypot".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.honeypot_probe.enabled".to_string(),
        label: "Enable Honeypot Probe Tracking".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Track patterns of probing activity via honeypot hits".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.suspicious_words.enabled".to_string(),
        label: "Enable Suspicious Words Detection".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Flag requests containing suspicious words in path/query".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.upstream_errors.enabled".to_string(),
        label: "Enable Upstream Error Tracking".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Track patterns of upstream error responses".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.css_challenge.enabled".to_string(),
        label: "Enable CSS Challenge".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Use CSS-based bot detection challenge".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.css_challenge.block.enabled".to_string(),
        label: "CSS Challenge Auto-Block".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Block clients that fail CSS challenge".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.pow_challenge.enabled".to_string(),
        label: "Enable PoW Challenge".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Use Proof-of-Work challenge for bot detection".to_string(),
        impact: Some("May increase CPU usage".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.pow_challenge.difficulty".to_string(),
        label: "PoW Difficulty".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(6)),
        description: "PoW challenge difficulty level".to_string(),
        impact: Some("Higher = more CPU intensive, harder for bots".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.challenge.priority".to_string(),
        label: "Challenge Priority".to_string(),
        field_type: "enum".to_string(),
        default: Some(serde_json::json!("pow_then_css")),
        description: "Order of challenge methods".to_string(),
        impact: None,
        options: Some(vec![
            "pow_then_css".to_string(),
            "css_then_pow".to_string(),
            "pow_only".to_string(),
            "css_only".to_string(),
        ]),
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.error_pages.mode".to_string(),
        label: "Error Pages Mode".to_string(),
        field_type: "enum".to_string(),
        default: Some(serde_json::json!("default")),
        description: "Choose between minimal unstyled error pages or custom HTML templates"
            .to_string(),
        impact: Some(
            "default mode provides stealthy minimal pages with no server info".to_string(),
        ),
        options: Some(vec!["default".to_string(), "custom".to_string()]),
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.error_pages.directory".to_string(),
        label: "Error Pages Directory".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::json!("config/error_pages")),
        description: "Directory containing custom error page HTML files".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.worker_pool.mode".to_string(),
        label: "Worker Pool Mode".to_string(),
        field_type: "enum".to_string(),
        default: Some(serde_json::json!("shared")),
        description: "Worker pool sharing strategy".to_string(),
        impact: None,
        options: Some(vec![
            "shared".to_string(),
            "dedicated".to_string(),
            "per_site".to_string(),
        ]),
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.worker_pool.workers".to_string(),
        label: "Worker Count".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(4)),
        description: "Number of worker processes".to_string(),
        impact: Some("More workers = more memory but better concurrency".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.worker_pool.auto_scale".to_string(),
        label: "Auto-Scale Workers".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Automatically adjust worker count based on load".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.worker_pool.worker_port_base".to_string(),
        label: "Worker Port Base".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(9000)),
        description: "Base port for worker IPC".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.persistence.enabled".to_string(),
        label: "Enable Persistence".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Persist state to disk".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.persistence.data_dir".to_string(),
        label: "Persistence Data Directory".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::Value::Null),
        description: "Directory for persisted data".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.persistence.persist_interval_secs".to_string(),
        label: "Persistence Interval (seconds)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(60)),
        description: "How often to persist state".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "threat_level.initial".to_string(),
        label: "Initial Threat Level".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(1)),
        description: "Starting threat level (1-5)".to_string(),
        impact: Some("Higher = more aggressive rate limiting".to_string()),
        options: Some(vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string(),
            "5".to_string(),
        ]),
    });

    schema.push(ConfigFieldSchema {
        path: "threat_level.auto_scale".to_string(),
        label: "Auto-Scale Threat Level".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Automatically adjust threat level based on attack detection".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "threat_level.scale_up_attacks_per_min".to_string(),
        label: "Scale Up Threshold (attacks/min)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(50)),
        description: "Attacks per minute to trigger scale up".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "threat_level.scale_down_attacks_per_min".to_string(),
        label: "Scale Down Threshold (attacks/min)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(10)),
        description: "Attacks per minute to trigger scale down".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "threat_level.cooldown_secs".to_string(),
        label: "Threat Level Cooldown (seconds)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(60)),
        description: "Minimum time between threat level changes".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "threat_level.escalation.enabled".to_string(),
        label: "Enable Escalation".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Escalate threat level on repeated violations".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "threat_level.escalation.violations_before_block".to_string(),
        label: "Violations Before Block".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(3)),
        description: "Violations before permanent block".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "ip_feeds.enabled".to_string(),
        label: "Enable IP Feeds".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(true)),
        description: "Enable IP blocklist feeds".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "ip_feeds.update_interval_hours".to_string(),
        label: "IP Feed Update Interval (hours)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(2)),
        description: "How often to update IP blocklists".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "ip_feeds.url".to_string(),
        label: "IP Feed URL".to_string(),
        field_type: "string".to_string(),
        default: Some(serde_json::json!(
            "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt"
        )),
        description: "URL of IP blocklist feed".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "ip_feeds.max_permanent_blocks".to_string(),
        label: "Max Permanent Blocks".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(1000000)),
        description: "Maximum number of permanently blocked IPs".to_string(),
        impact: Some("Higher = more memory usage".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.tcp.enabled".to_string(),
        label: "Enable TCP Filtering".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Enable TCP protocol proxying".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.tcp.worker_pool_size".to_string(),
        label: "TCP Worker Pool Size".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(4)),
        description: "Number of workers for TCP".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.udp.enabled".to_string(),
        label: "Enable UDP Filtering".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Enable UDP protocol proxying".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.udp.worker_pool_size".to_string(),
        label: "UDP Worker Pool Size".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(4)),
        description: "Number of workers for UDP".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.tarpit.enabled".to_string(),
        label: "Enable Tarpit".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Enable the scraper tarpit trap".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.upload.enabled".to_string(),
        label: "Enable File Upload".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Enable file upload handling".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.upload.max_size".to_string(),
        label: "Max Upload Size (bytes)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(10485760)),
        description: "Maximum file upload size (default 10MB)".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "defaults.traffic_shaping.enabled".to_string(),
        label: "Enable Traffic Shaping".to_string(),
        field_type: "boolean".to_string(),
        default: Some(serde_json::json!(false)),
        description: "Enable bandwidth throttling".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "rate_limit_memory.max_ip_entries".to_string(),
        label: "Rate Limit Memory Max Entries".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(1000000)),
        description: "Maximum number of IPs to track in memory".to_string(),
        impact: Some("Higher = more memory but better rate limiting accuracy".to_string()),
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "proxy_limits.max_response_size".to_string(),
        label: "Max Response Size (bytes)".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(10000000)),
        description: "Maximum response size to proxy (default 10MB)".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "proxy_limits.connection_pool_size".to_string(),
        label: "Connection Pool Size".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(100)),
        description: "Number of connections per upstream".to_string(),
        impact: None,
        options: None,
    });

    schema.push(ConfigFieldSchema {
        path: "blocklist_limits.max_entries".to_string(),
        label: "Blocklist Max Entries".to_string(),
        field_type: "integer".to_string(),
        default: Some(serde_json::json!(500000)),
        description: "Maximum blocked IPs to track".to_string(),
        impact: Some("Higher = more memory".to_string()),
        options: None,
    });

    Ok(Json(schema))
}

pub async fn update_main_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateMainConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let toml_content = toml::to_string_pretty(&req.config).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let config_dir = {
        let cfg = state.process.config.read().await;
        cfg.config_dir.clone()
    };

    let main_config_path = config_dir.join("main.toml");

    {
        let _guard = state.metrics.config_write_lock.write().await;
        tokio::fs::write(&main_config_path, toml_content)
            .await
            .map_err(|e| {
                tracing::error!("Failed to write main config: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    // Update in-memory config and broadcast to workers
    {
        let mut cfg = state.process.config.write().await;
        if cfg.load_main(&main_config_path).is_ok() {
            cfg.discover_sites();
        }
    }

    // Broadcast to workers if process manager is available
    if let Some(ref pm) = state.process.process_manager {
        pm.broadcast_config_reload(config_dir).await;
    }

    Ok(Json(StatusResponse::success(
        "Configuration updated and reloaded to workers.",
    )))
}

#[utoipa::path(
    post,
    path = "/config/reload",
    tag = "Config",
    responses(
        (status = 200, description = "Configuration reloaded", body = [StatusResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn reload_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<StatusResponse>, StatusCode> {
    let config_dir = {
        let config = state.process.config.read().await;
        config.config_dir.clone()
    };

    let mut config = state.process.config.write().await;
    let results = config.reload_all();

    let loaded = results.iter().filter(|r| r.1.is_ok()).count();
    let failed = results.iter().filter(|r| r.1.is_err()).count();

    let mimes_config = &config.main.mimes;
    let mut mimes_reloaded = false;
    let mut mimes_error = None;

    if mimes_config.enabled {
        if let Some(ref mimes_file) = mimes_config.file {
            match crate::mime::reload_mimes_from_file(mimes_file) {
                Ok(()) => {
                    mimes_reloaded = true;
                }
                Err(e) => {
                    mimes_error = Some(e.to_string());
                }
            }
        }
    }

    // Only broadcast to workers if all reloads succeeded
    let broadcast_success = failed == 0;

    drop(config);
    if broadcast_success {
        if let Some(ref pm) = state.process.process_manager {
            let config_dir = state.process.config.read().await.config_dir.clone();
            pm.broadcast_config_reload(config_dir).await;
        }
    }

    let message = if mimes_reloaded {
        if broadcast_success {
            format!(
                "Reloaded {} configs, {} failed, mimes reloaded, workers notified",
                loaded, failed
            )
        } else {
            format!(
                "Reloaded {} configs, {} failed (workers not notified)",
                loaded, failed
            )
        }
    } else if let Some(err) = mimes_error {
        if broadcast_success {
            format!(
                "Reloaded {} configs, {} failed, mimes reload failed: {}, workers notified",
                loaded, failed, err
            )
        } else {
            format!(
                "Reloaded {} configs, {} failed, mimes reload failed: {} (workers not notified)",
                loaded, failed, err
            )
        }
    } else {
        if broadcast_success {
            format!(
                "Reloaded {} configs, {} failed, workers notified",
                loaded, failed
            )
        } else {
            format!(
                "Reloaded {} configs, {} failed (workers not notified)",
                loaded, failed
            )
        }
    };

    Ok(Json(StatusResponse {
        status: if failed == 0 { "success" } else { "partial" }.to_string(),
        message,
    }))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SetLogLevelRequest {
    pub level: String,
}

#[utoipa::path(
    put,
    path = "/config/log-level",
    tag = "Config",
    request_body = SetLogLevelRequest,
    responses(
        (status = 200, description = "Log level updated", body = [StatusResponse]),
        (status = 400, description = "Invalid log level"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn set_log_level(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<SetLogLevelRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    match log_controller::set_log_level(&req.level) {
        Ok(level) => Ok(Json(StatusResponse {
            status: "success".to_string(),
            message: format!("Log level set to {}", level),
        })),
        Err(e) => {
            tracing::warn!("Invalid log level request: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

#[utoipa::path(
    get,
    path = "/config/log-level",
    tag = "Config",
    responses(
        (status = 200, description = "Current log level", body = [StatusResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_log_level(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<StatusResponse>, StatusCode> {
    let level = log_controller::get_log_level();
    Ok(Json(StatusResponse {
        status: "success".to_string(),
        message: format!("Current log level: {}", level),
    }))
}

#[utoipa::path(
    get,
    path = "/config/export",
    tag = "Config",
    responses(
        (status = 200, description = "Exported configuration as TOML"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn export_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<String, StatusCode> {
    let config = state.process.config.read().await;
    let toml_content = toml::to_string_pretty(&config.main).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(toml_content)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ImportConfigRequest {
    pub config: String,
}

#[utoipa::path(
    post,
    path = "/config/import",
    tag = "Config",
    request_body = ImportConfigRequest,
    responses(
        (status = 200, description = "Configuration imported", body = [StatusResponse]),
        (status = 400, description = "Invalid configuration"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn import_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<ImportConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let parsed: crate::config::main::MainConfig = toml::from_str(&req.config).map_err(|e| {
        tracing::error!("Failed to parse config TOML: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let toml_content = toml::to_string_pretty(&parsed).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let main_config_path = {
        let cfg = state.process.config.read().await;
        cfg.config_dir.join("main.toml")
    };

    {
        let _guard = state.metrics.config_write_lock.write().await;
        tokio::fs::write(&main_config_path, toml_content)
            .await
            .map_err(|e| {
                tracing::error!("Failed to write main config: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    let mut config = state.process.config.write().await;
    if let Err(e) = config.load_main(&main_config_path) {
        tracing::error!("Failed to reload imported config in memory: {}", e);
    }
    drop(config);

    if let Some(ref pm) = state.process.process_manager {
        let config_dir = state.process.config.read().await.config_dir.clone();
        pm.broadcast_config_reload(config_dir).await;
    }

    Ok(Json(StatusResponse::success(
        "Configuration imported and reloaded.",
    )))
}

use crate::utils::check_regex_complexity;

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RegexCheckResult {
    pub pattern: String,
    pub safe: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CheckRegexRequest {
    pub pattern: String,
}

#[utoipa::path(
    post,
    path = "/config/check-regex",
    tag = "Config",
    request_body = CheckRegexRequest,
    responses(
        (status = 200, description = "Regex check result", body = [RegexCheckResult]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn check_regex(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<CheckRegexRequest>,
) -> Result<Json<RegexCheckResult>, StatusCode> {
    let result = check_regex_complexity(&req.pattern);

    Ok(Json(RegexCheckResult {
        pattern: req.pattern,
        safe: result.safe,
        reason: result.reason,
    }))
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OverseerConfigResponse {
    pub config: crate::config::OverseerConfig,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateOverseerConfigRequest {
    pub config: crate::config::OverseerConfig,
}

#[utoipa::path(
    get,
    path = "/config/overseer",
    tag = "Config",
    responses(
        (status = 200, description = "Overseer configuration", body = [OverseerConfigResponse]),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_overseer_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<OverseerConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(OverseerConfigResponse {
        config: config.main.overseer.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/overseer",
    tag = "Config",
    request_body = UpdateOverseerConfigRequest,
    responses(
        (status = 200, description = "Overseer configuration updated", body = [StatusResponse]),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_overseer_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateOverseerConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    {
        let mut config = state.process.config.write().await;
        config.main.overseer = req.config.clone();
    }

    let main_config_path = {
        let cfg = state.process.config.read().await;
        cfg.config_dir.join("main.toml")
    };

    let toml_content = tokio::fs::read_to_string(&main_config_path)
        .await
        .map_err(|e| {
            tracing::error!("Failed to read main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut main_config: crate::config::MainConfig =
        toml::from_str(&toml_content).map_err(|e| {
            tracing::error!("Failed to parse main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    main_config.overseer = req.config;

    let toml_content = toml::to_string_pretty(&main_config).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tokio::fs::write(&main_config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let reload_path = std::env::current_dir()
        .map_err(|e| {
            tracing::error!("Failed to get current dir: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .join(".overseer_reload");

    if let Err(e) = tokio::fs::write(&reload_path, "1").await {
        tracing::warn!("Failed to write overseer reload signal: {}", e);
    } else {
        tracing::info!("Overseer reload signal written to {:?}", reload_path);
    }

    tracing::info!("Overseer config updated - reload signal sent");

    Ok(Json(StatusResponse::success(
        "Overseer config updated and reload signal sent.",
    )))
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProcessManagerConfigResponse {
    pub config: crate::config::ProcessManagerConfig,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateProcessManagerConfigRequest {
    pub config: crate::config::ProcessManagerConfig,
}

#[utoipa::path(
    get,
    path = "/config/process-manager",
    tag = "Config",
    responses(
        (status = 200, description = "Process manager configuration", body = [ProcessManagerConfigResponse]),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_process_manager_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ProcessManagerConfigResponse>, StatusCode> {
    if let Some(ref pm) = state.process.process_manager {
        Ok(Json(ProcessManagerConfigResponse {
            config: pm.get_config(),
        }))
    } else {
        let config = state.process.config.read().await;
        Ok(Json(ProcessManagerConfigResponse {
            config: config.main.process_manager.clone(),
        }))
    }
}

#[utoipa::path(
    put,
    path = "/config/process-manager",
    tag = "Config",
    request_body = UpdateProcessManagerConfigRequest,
    responses(
        (status = 200, description = "Process manager configuration updated", body = [StatusResponse]),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_process_manager_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateProcessManagerConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let needs_restart = if let Some(ref pm) = state.process.process_manager {
        match pm.update_config(req.config.clone()) {
            Ok(restart_needed) => {
                tracing::info!("Process manager config updated dynamically");
                restart_needed
            }
            Err(e) => {
                tracing::error!("Failed to update process manager config: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    } else {
        true
    };

    let _guard = state.metrics.config_write_lock.write().await;

    let (main_config_path, toml_content) = {
        let mut config = state.process.config.write().await;
        config.main.process_manager = req.config;
        let path = config.config_dir.join("main.toml");
        let content = toml::to_string_pretty(&config.main).map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        (path, content)
    };

    tokio::fs::write(&main_config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if needs_restart {
        Ok(Json(StatusResponse::success(
            "Process manager config updated. Restart required for changes to take effect.",
        )))
    } else {
        Ok(Json(StatusResponse::success(
            "Process manager config updated and applied dynamically.",
        )))
    }
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SupervisorConfigResponse {
    pub config: crate::config::SupervisorConfig,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateSupervisorConfigRequest {
    pub config: crate::config::SupervisorConfig,
}

#[utoipa::path(
    get,
    path = "/config/supervisor",
    tag = "Config",
    responses(
        (status = 200, description = "Supervisor configuration", body = [SupervisorConfigResponse]),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_supervisor_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SupervisorConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(SupervisorConfigResponse {
        config: config.main.supervisor.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/supervisor",
    tag = "Config",
    request_body = UpdateSupervisorConfigRequest,
    responses(
        (status = 200, description = "Supervisor configuration updated", body = [StatusResponse]),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_supervisor_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateSupervisorConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    {
        let mut config = state.process.config.write().await;
        config.main.supervisor = req.config.clone();
    }

    let main_config_path = {
        let cfg = state.process.config.read().await;
        cfg.config_dir.join("main.toml")
    };

    let toml_content = tokio::fs::read_to_string(&main_config_path)
        .await
        .map_err(|e| {
            tracing::error!("Failed to read main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut main_config: crate::config::MainConfig =
        toml::from_str(&toml_content).map_err(|e| {
            tracing::error!("Failed to parse main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    main_config.supervisor = req.config;

    let toml_content = toml::to_string_pretty(&main_config).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tokio::fs::write(&main_config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let reload_path = std::env::current_dir()
        .map_err(|e| {
            tracing::error!("Failed to get current dir: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .join(".worker_reload");

    if let Err(e) = tokio::fs::write(&reload_path, "1").await {
        tracing::warn!("Failed to write worker reload signal: {}", e);
    } else {
        tracing::info!("Worker reload signal written to {:?}", reload_path);
    }

    if let Some(ref pm) = state.process.process_manager {
        pm.reload_config();
    }

    tracing::info!("Supervisor config updated - reload signal sent to workers");

    Ok(Json(StatusResponse::success(
        "Supervisor config updated and reload signal sent to workers.",
    )))
}

// --- TLS config ---

#[derive(Debug, Serialize)]
pub struct TlsConfigResponse {
    pub config: crate::config::tls::TlsConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTlsConfigRequest {
    pub config: crate::config::tls::TlsConfig,
}

pub async fn get_tls_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TlsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TlsConfigResponse {
        config: config.main.tls.clone(),
    }))
}

pub async fn update_tls_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTlsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.tls = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("TLS config updated.")))
}

// --- HTTP config ---

#[derive(Debug, Serialize)]
pub struct HttpConfigResponse {
    pub config: crate::config::http::HttpConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateHttpConfigRequest {
    pub config: crate::config::http::HttpConfig,
}

pub async fn get_http_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<HttpConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(HttpConfigResponse {
        config: config.main.http.clone(),
    }))
}

pub async fn update_http_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateHttpConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.http = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("HTTP config updated.")))
}

// --- Security config ---

#[derive(Debug, Serialize)]
pub struct SecurityConfigResponse {
    pub config: crate::config::security::MainSecurityConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSecurityConfigRequest {
    pub config: crate::config::security::MainSecurityConfig,
}

pub async fn get_security_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SecurityConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(SecurityConfigResponse {
        config: config.main.security.clone(),
    }))
}

pub async fn update_security_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateSecurityConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.security = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Security config updated.")))
}

// --- Tunnel config ---

#[derive(Debug, Serialize)]
pub struct TunnelConfigResponse {
    pub config: crate::config::tunnel::TunnelConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTunnelConfigRequest {
    pub config: crate::config::tunnel::TunnelConfig,
}

pub async fn get_tunnel_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TunnelConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TunnelConfigResponse {
        config: config.main.tunnel.clone(),
    }))
}

pub async fn update_tunnel_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTunnelConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.tunnel = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Tunnel config updated.")))
}

// --- Plugins config ---

#[derive(Debug, Serialize)]
pub struct PluginsConfigResponse {
    pub config: crate::config::plugins::PluginConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePluginsConfigRequest {
    pub config: crate::config::plugins::PluginConfig,
}

pub async fn get_plugins_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<PluginsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(PluginsConfigResponse {
        config: config.main.plugins.clone(),
    }))
}

pub async fn update_plugins_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdatePluginsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.plugins = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Plugins config updated.")))
}

// --- Logging config ---

#[derive(Debug, Serialize)]
pub struct LoggingConfigResponse {
    pub config: crate::config::logging::LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateLoggingConfigRequest {
    pub config: crate::config::logging::LoggingConfig,
}

pub async fn get_logging_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<LoggingConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(LoggingConfigResponse {
        config: config.main.logging.clone(),
    }))
}

pub async fn update_logging_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateLoggingConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.logging = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Logging config updated.")))
}

// --- Traffic shaping config ---

#[derive(Debug, Serialize)]
pub struct TrafficShapingConfigResponse {
    pub config: crate::config::traffic::TrafficShapingConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTrafficShapingConfigRequest {
    pub config: crate::config::traffic::TrafficShapingConfig,
}

pub async fn get_traffic_shaping_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TrafficShapingConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TrafficShapingConfigResponse {
        config: config.main.traffic_shaping.clone(),
    }))
}

pub async fn update_traffic_shaping_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTrafficShapingConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.traffic_shaping = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success(
        "Traffic shaping config updated.",
    )))
}

// --- Threat level config ---

#[derive(Debug, Serialize)]
pub struct ThreatLevelConfigResponse {
    pub config: crate::config::protection::ThreatLevelConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateThreatLevelConfigRequest {
    pub config: crate::config::protection::ThreatLevelConfig,
}

pub async fn get_threat_level_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ThreatLevelConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(ThreatLevelConfigResponse {
        config: config.main.threat_level.clone(),
    }))
}

pub async fn update_threat_level_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateThreatLevelConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.threat_level = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success(
        "Threat level config updated.",
    )))
}

// --- IP feeds config ---

#[derive(Debug, Serialize)]
pub struct IpFeedsConfigResponse {
    pub config: crate::config::protection::IpFeedConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIpFeedsConfigRequest {
    pub config: crate::config::protection::IpFeedConfig,
}

pub async fn get_ip_feeds_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IpFeedsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(IpFeedsConfigResponse {
        config: config.main.ip_feeds.clone(),
    }))
}

pub async fn update_ip_feeds_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateIpFeedsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.ip_feeds = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("IP feeds config updated.")))
}

// --- DNS config (feature-gated) ---

#[cfg(feature = "dns")]
#[derive(Debug, Serialize)]
pub struct DnsConfigResponse {
    pub config: crate::config::dns::DnsConfig,
}

#[cfg(feature = "dns")]
#[derive(Debug, Deserialize)]
pub struct UpdateDnsConfigRequest {
    pub config: crate::config::dns::DnsConfig,
}

#[cfg(feature = "dns")]
pub async fn get_dns_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<DnsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(DnsConfigResponse {
        config: config.main.dns.clone(),
    }))
}

#[cfg(feature = "dns")]
pub async fn update_dns_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateDnsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.dns = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("DNS config updated.")))
}

// --- Rate limits config ---

#[derive(Debug, Serialize)]
pub struct RateLimitsConfigResponse {
    pub rate_limit_memory: crate::config::limits::RateLimitMemoryConfig,
    pub proxy_limits: crate::config::limits::ProxyLimitsConfig,
    pub blocklist_limits: crate::config::limits::BlocklistLimitsConfig,
    pub defaults: crate::config::defaults::RateLimitDefaults,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRateLimitsConfigRequest {
    pub rate_limit_memory: Option<crate::config::limits::RateLimitMemoryConfig>,
    pub proxy_limits: Option<crate::config::limits::ProxyLimitsConfig>,
    pub blocklist_limits: Option<crate::config::limits::BlocklistLimitsConfig>,
    pub defaults: Option<crate::config::defaults::RateLimitDefaults>,
}

pub async fn get_rate_limits_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<RateLimitsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(RateLimitsConfigResponse {
        rate_limit_memory: config.main.rate_limit_memory.clone(),
        proxy_limits: config.main.proxy_limits.clone(),
        blocklist_limits: config.main.blocklist_limits.clone(),
        defaults: config.main.defaults.ratelimit.clone(),
    }))
}

pub async fn update_rate_limits_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateRateLimitsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    {
        let mut config = state.process.config.write().await;
        if let Some(v) = req.rate_limit_memory {
            config.main.rate_limit_memory = v;
        }
        if let Some(v) = req.proxy_limits {
            config.main.proxy_limits = v;
        }
        if let Some(v) = req.blocklist_limits {
            config.main.blocklist_limits = v;
        }
        if let Some(v) = req.defaults {
            config.main.defaults.ratelimit = v;
        }
    }

    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Rate limits config updated.")))
}

// --- Bot detection config ---

#[derive(Debug, Serialize)]
pub struct BotDetectionConfigResponse {
    pub config: crate::config::defaults::BotDefaults,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBotDetectionConfigRequest {
    pub config: crate::config::defaults::BotDefaults,
}

pub async fn get_bot_detection_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BotDetectionConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(BotDetectionConfigResponse {
        config: config.main.defaults.bot.clone(),
    }))
}

pub async fn update_bot_detection_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateBotDetectionConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    {
        let mut config = state.process.config.write().await;
        config.main.defaults.bot = req.config;
    }

    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success(
        "Bot detection config updated.",
    )))
}

// --- Mesh config ---

#[derive(Debug, Serialize)]
pub struct MeshConfigResponse {
    pub config: Option<crate::config::mesh::MeshConfig>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMeshConfigRequest {
    pub config: Option<crate::config::mesh::MeshConfig>,
}

pub async fn get_mesh_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MeshConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(MeshConfigResponse {
        config: config.main.mesh.clone(),
    }))
}

pub async fn update_mesh_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateMeshConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    {
        let mut config = state.process.config.write().await;
        config.main.mesh = req.config;
    }

    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Mesh config updated.")))
}

// --- Validate config ---

#[derive(Debug, Deserialize)]
pub struct ValidateConfigRequest {
    pub config: crate::config::main::MainConfig,
}

#[derive(Debug, Serialize)]
pub struct ValidateConfigResponse {
    pub valid: bool,
    pub errors: Vec<String>,
}

pub async fn validate_config(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<ValidateConfigRequest>,
) -> Result<Json<ValidateConfigResponse>, StatusCode> {
    match req.config.validate() {
        Ok(()) => Ok(Json(ValidateConfigResponse {
            valid: true,
            errors: vec![],
        })),
        Err(e) => Ok(Json(ValidateConfigResponse {
            valid: false,
            errors: vec![format!("{}: {}", e.field, e.message)],
        })),
    }
}

// --- Helper: persist MainConfig to TOML file ---

async fn persist_main_config_and_notify(state: &Arc<AdminState>) -> Result<(), StatusCode> {
    let (main_config_path, toml_content, config_dir) = {
        let config = state.process.config.read().await;
        let path = config.config_dir.join("main.toml");
        let content = toml::to_string_pretty(&config.main).map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        (path, content, config.config_dir.clone())
    };

    tokio::fs::write(&main_config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Broadcast config reload to workers
    if let Some(ref pm) = state.process.process_manager {
        pm.broadcast_config_reload(config_dir).await;
    }

    Ok(())
}
