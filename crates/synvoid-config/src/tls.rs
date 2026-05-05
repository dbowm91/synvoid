use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::validation::ConfigValidationError;

fn default_tls_1_3_only() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
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
    #[serde(default)]
    pub strict_protocol_validation: bool,
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
            strict_protocol_validation: false,
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
        if self.acme.enabled {
            self.acme.validate()?;
        }
        Ok(())
    }
}

impl AcmeConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.email.is_none() {
            return Err(ConfigValidationError {
                field: "tls.acme.email".to_string(),
                message: "ACME enabled but no email provided".to_string(),
            });
        }
        if self.domains.is_empty() {
            return Err(ConfigValidationError {
                field: "tls.acme.domains".to_string(),
                message: "ACME enabled but no domains specified".to_string(),
            });
        }
        if let Some(ref cache_dir) = self.cache_dir {
            let path = std::path::Path::new(cache_dir);
            if !path.exists() {
                if let Err(e) = std::fs::create_dir_all(path) {
                    return Err(ConfigValidationError {
                        field: "tls.acme.cache_dir".to_string(),
                        message: format!(
                            "ACME cache_dir does not exist and could not be created: {}",
                            e
                        ),
                    });
                }
            }
            let temp_file = path.join(".synvoid_acme_write_test");
            if let Err(e) = std::fs::write(&temp_file, b"") {
                return Err(ConfigValidationError {
                    field: "tls.acme.cache_dir".to_string(),
                    message: format!("ACME cache_dir is not writable: {}", e),
                });
            }
            let _ = std::fs::remove_file(&temp_file);
        }
        if self.enabled && !self.terms_of_service_agreed {
            tracing::warn!(
                "ACME is enabled but terms_of_service_agreed is false. \
                ACME will not be able to obtain certificates until the terms of service are agreed. \
                Set tls.acme.terms_of_service_agreed = true after reviewing the ACME terms of service."
            );
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema, ToSchema)]
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
    #[serde(default)]
    pub terms_of_service_agreed: bool,
}

#[derive(
    Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum AcmeChallengeType {
    #[default]
    Http01,
    Dns01,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema, ToSchema)]
pub struct ClientAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}
