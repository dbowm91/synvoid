use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::validation::ConfigValidationError;

fn default_tls_1_3_only() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub watch_dir: Option<String>,
    #[serde(default = "default_prefer_post_quantum")]
    pub prefer_post_quantum: bool,
    #[serde(default = "default_tls_1_3_only")]
    pub tls_1_3_only: bool,
    #[serde(default)]
    pub enable_tls_12_fallback: bool,
    #[serde(default)]
    pub ocsp_stapling_enabled: bool,
    #[serde(default)]
    pub ocsp_response_path: Option<String>,
    #[serde(default = "default_tls_port")]
    pub port: u16,
    #[serde(default)]
    pub acme: AcmeConfig,
    #[serde(default)]
    pub client_auth: ClientAuthConfig,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            watch_dir: None,
            prefer_post_quantum: true,
            tls_1_3_only: true,
            enable_tls_12_fallback: false,
            ocsp_stapling_enabled: false,
            ocsp_response_path: None,
            port: default_tls_port(),
            acme: AcmeConfig::default(),
            client_auth: ClientAuthConfig::default(),
        }
    }
}

fn default_tls_port() -> u16 {
    443
}

fn default_prefer_post_quantum() -> bool {
    true
}

impl TlsConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.enabled {
            if self.cert_path.is_none() && !self.acme.enabled {
                return Err(ConfigValidationError {
                    field: "tls.cert_path".to_string(),
                    message: "TLS enabled but no cert_path provided and ACME is disabled"
                        .to_string(),
                });
            }
            if self.key_path.is_none() && !self.acme.enabled {
                return Err(ConfigValidationError {
                    field: "tls.key_path".to_string(),
                    message: "TLS enabled but no key_path provided and ACME is disabled"
                        .to_string(),
                });
            }
            if let Some(ref cert_path) = self.cert_path {
                if !std::path::Path::new(cert_path).exists() {
                    return Err(ConfigValidationError {
                        field: "tls.cert_path".to_string(),
                        message: format!("Certificate file not found: {}", cert_path),
                    });
                }
            }
            if let Some(ref key_path) = self.key_path {
                if !std::path::Path::new(key_path).exists() {
                    return Err(ConfigValidationError {
                        field: "tls.key_path".to_string(),
                        message: format!("Key file not found: {}", key_path),
                    });
                }
            }
        }
        if self.acme.enabled && self.acme.email.is_none() {
            return Err(ConfigValidationError {
                field: "tls.acme.email".to_string(),
                message: "ACME enabled but no email provided".to_string(),
            });
        }
        if self.acme.enabled && self.acme.domains.is_empty() {
            return Err(ConfigValidationError {
                field: "tls.acme.domains".to_string(),
                message: "ACME enabled but no domains specified".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub cache_dir: Option<String>,
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub challenge_type: AcmeChallengeType,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AcmeChallengeType {
    #[default]
    Http01,
    Dns01,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct ClientAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}
