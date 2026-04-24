use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteSecurityConfig {
    #[serde(default)]
    pub reject_unknown_hosts: Option<bool>,
    #[serde(default)]
    pub more_clear_headers: Vec<String>,
    #[serde(default)]
    pub upstream: SiteUpstreamConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteUpstreamConfig {
    #[serde(default)]
    pub tls: Option<SiteUpstreamTlsConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteUpstreamTlsConfig {
    /// If false, disables TLS certificate verification. WARNING: This disables
    /// hostname verification but certificate chain validation still occurs. Use only for
    /// development or with explicit trust. Always set skip_verify_reason when enabling.
    #[serde(default = "default_tls_verify")]
    pub verify: Option<bool>,
    /// Base64-encoded CA certificate(s) to trust for upstream connections.
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// Override the server name (SNI) for upstream TLS connections.
    #[serde(default)]
    pub server_name: Option<String>,
    /// SKIP TLS VERIFICATION - WARNING: Disables hostname verification.
    /// Only use for local development or trusted internal services.
    /// Chain validation still occurs; this only bypasses hostname check.
    #[serde(default)]
    pub skip_verify: Option<bool>,
    /// REQUIRED when skip_verify is true: Document why verification is bypassed.
    /// Example: "Local development with self-signed cert"
    #[serde(default)]
    pub skip_verify_reason: Option<String>,
}

fn default_tls_verify() -> Option<bool> {
    Some(true)
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteSecurityHeadersConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default = "default_security_headers_enabled")]
    pub strict_transport_security: Option<String>,
    #[serde(default)]
    pub content_security_policy: Option<String>,
    #[serde(default)]
    pub x_frame_options: Option<String>,
    #[serde(default = "default_x_content_type_options")]
    pub x_content_type_options: Option<String>,
    #[serde(default = "default_x_xss_protection")]
    pub x_xss_protection: Option<String>,
    #[serde(default)]
    pub referrer_policy: Option<String>,
    #[serde(default)]
    pub permissions_policy: Option<String>,
    #[serde(default)]
    pub cache_control: Option<String>,
    #[serde(default)]
    pub expect_ct: Option<String>,
    #[serde(default = "default_cross_domain_policy")]
    pub x_permitted_cross_domain_policies: Option<String>,
    #[serde(default = "default_download_options")]
    pub x_download_options: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub more_clear_headers: Vec<String>,
    #[serde(default)]
    pub cors: SiteCorsConfig,
    #[serde(default)]
    pub cookie: SiteCookieConfig,

    #[serde(default = "default_some_true")]
    pub date_header: Option<bool>,
    #[serde(default = "default_date_jitter")]
    pub date_jitter_seconds: Option<u32>,
    #[serde(default)]
    pub server_token: Option<String>,
}

fn default_some_true() -> Option<bool> {
    Some(true)
}

fn default_security_headers_enabled() -> Option<String> {
    Some("max-age=31536000; includeSubDomains".to_string())
}

fn default_x_content_type_options() -> Option<String> {
    Some("nosniff".to_string())
}

fn default_x_xss_protection() -> Option<String> {
    Some("0".to_string())
}

fn default_cross_domain_policy() -> Option<String> {
    Some("none".to_string())
}

fn default_download_options() -> Option<String> {
    Some("noopen".to_string())
}

fn default_date_jitter() -> Option<u32> {
    Some(5)
}

impl SiteSecurityHeadersConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(ref samesite) = self.cookie.samesite {
            match samesite.to_lowercase().as_str() {
                "strict" | "lax" | "none" => {}
                _ => {
                    return Err(ConfigValidationError {
                        field: "security_headers.cookie.samesite".to_string(),
                        message: "SameSite must be 'strict', 'lax', or 'none'".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteCorsConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub allow_origin: Option<String>,
    #[serde(default)]
    pub allow_methods: Option<Vec<String>>,
    #[serde(default)]
    pub allow_headers: Option<Vec<String>>,
    #[serde(default)]
    pub allow_credentials: Option<bool>,
    #[serde(default)]
    pub max_age: Option<u64>,
    #[serde(default)]
    pub expose_headers: Option<Vec<String>>,
    #[serde(default = "default_allow_wildcard_cors")]
    pub allow_wildcard_cors: bool,
}

fn default_allow_wildcard_cors() -> bool {
    false
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteCookieConfig {
    #[serde(default)]
    pub secure: Option<bool>,
    #[serde(default)]
    pub httponly: Option<bool>,
    #[serde(default)]
    pub samesite: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteBlockedConfig {
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub use_regex: Option<bool>,
    #[serde(default)]
    pub block_methods: Option<Vec<String>>,
    #[serde(default)]
    pub block_response_code: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteWhitelistConfig {
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub user_agents: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteGeoipConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub blocked_countries: Vec<String>,
    #[serde(default)]
    pub allowed_countries: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteBasicAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub users: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub realm: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteAuthConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub login_path: Option<String>,
    #[serde(default)]
    pub session_duration_secs: Option<u64>,
    #[serde(default)]
    pub max_login_attempts: Option<u32>,
    #[serde(default)]
    pub lockout_duration_secs: Option<u64>,
}
