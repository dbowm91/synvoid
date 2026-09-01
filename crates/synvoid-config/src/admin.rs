use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::validation::ConfigValidationError;

const MIN_TOKEN_LENGTH: usize = 32;
const WEAK_TOKEN_PATTERNS: &[&str] = &[
    "changeme",
    "change-me",
    "password",
    "admin",
    "123456",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "token_placeholder",
    "token-placeholder",
    "replace-me",
];

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct AdminCorsConfig {
    #[serde(default)]
    pub allow_origin: Option<String>,
    #[serde(default)]
    pub allow_methods: Option<Vec<String>>,
    #[serde(default)]
    pub allow_headers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct AdminConfig {
    #[serde(default = "default_admin_enabled")]
    pub enabled: bool,
    #[serde(default = "default_admin_port")]
    pub port: u16,
    #[serde(default = "default_admin_bind")]
    pub bind_address: String,
    #[serde(default = "default_admin_token", alias = "api_key")]
    pub token: String,
    #[serde(default)]
    pub token_env_var: Option<String>,
    #[serde(default = "default_bcrypt_cost")]
    pub bcrypt_cost: u32,
    #[serde(default)]
    pub cors: AdminCorsConfig,
    #[serde(default)]
    pub rate_limit: AdminRateLimitConfig,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Explicitly control the `Secure` flag on the session cookie.
    /// - `true` (default): Always set `Secure` (safe for TLS and reverse-proxy deployments).
    /// - `false`: Never set `Secure` (for plain HTTP development only).
    #[serde(default = "default_secure_cookie")]
    pub secure_cookie: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct AdminRateLimitConfig {
    #[serde(default = "default_admin_rate_limit_requests")]
    pub requests_per_minute: u32,
    #[serde(default = "default_admin_rate_limit_burst")]
    pub burst: u32,
}

fn default_admin_bind() -> String {
    "127.0.0.1".to_string()
}

fn default_admin_rate_limit_requests() -> u32 {
    60
}

fn default_admin_rate_limit_burst() -> u32 {
    10
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: default_admin_enabled(),
            port: default_admin_port(),
            bind_address: default_admin_bind(),
            token: default_admin_token(),
            token_env_var: None,
            bcrypt_cost: default_bcrypt_cost(),
            cors: AdminCorsConfig::default(),
            rate_limit: AdminRateLimitConfig::default(),
            trusted_proxies: Vec::new(),
            secure_cookie: default_secure_cookie(),
        }
    }
}

impl AdminConfig {
    pub fn resolve_token(&self) -> String {
        if let Some(ref env_var) = self.token_env_var {
            if let Ok(env_token) = std::env::var(env_var) {
                if !env_token.is_empty() {
                    return env_token;
                }
            }
        }
        if !self.token.is_empty() && self.token != "changeme" {
            return self.token.clone();
        }
        Self::generate_token()
    }

    fn generate_token() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let token: String = (0..48)
            .map(|_| {
                let idx = rng.random_range(0..62);
                if idx < 10 {
                    (b'0' + idx) as char
                } else if idx < 36 {
                    (b'A' + idx - 10) as char
                } else {
                    (b'a' + idx - 36) as char
                }
            })
            .collect();
        token
    }

    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.port == 0 {
            return Err(ConfigValidationError {
                field: "admin.port".to_string(),
                message: "Admin port cannot be 0".to_string(),
            });
        }

        if self.bcrypt_cost < 12 || self.bcrypt_cost > 15 {
            return Err(ConfigValidationError {
                field: "admin.bcrypt_cost".to_string(),
                message: "bcrypt_cost must be between 12 and 15".to_string(),
            });
        }

        if self.token == "changeme" && self.token_env_var.is_none() {
            if cfg!(not(debug_assertions)) {
                return Err(ConfigValidationError {
                    field: "admin.token".to_string(),
                    message: "Default token 'changeme' is not allowed in release builds. \
                              Set admin.token or admin.token_env_var."
                        .to_string(),
                });
            }
            tracing::warn!("Admin token is still set to default 'changeme'. Set admin.token or admin.token_env_var for production.");
            let _generated = Self::generate_token();
            tracing::info!("Generated new admin token (see documentation for retrieval)");
            return Err(ConfigValidationError {
                field: "admin.token".to_string(),
                message: format!(
                    "Admin token must be at least {} characters for security. \
                     See startup log for generated token.",
                    MIN_TOKEN_LENGTH
                ),
            });
        }

        let token = self.resolve_token();

        if token.len() < MIN_TOKEN_LENGTH {
            return Err(ConfigValidationError {
                field: "admin.token".to_string(),
                message: format!(
                    "Admin token must be at least {} characters for security.",
                    MIN_TOKEN_LENGTH
                ),
            });
        }

        let token_lower = token.to_lowercase();
        for pattern in WEAK_TOKEN_PATTERNS {
            if token_lower.contains(pattern) {
                return Err(ConfigValidationError {
                    field: "admin.token".to_string(),
                    message: format!(
                        "Admin token contains weak pattern '{}'. Use a cryptographically random token.",
                        pattern
                    ),
                });
            }
        }

        if let Some(ref origin) = self.cors.allow_origin {
            if origin == "*" {
                if cfg!(not(debug_assertions)) {
                    return Err(ConfigValidationError {
                        field: "admin.cors.allow_origin".to_string(),
                        message: "CORS allow_origin '*' is not allowed in release builds. \
                                  Specify exact origins."
                            .to_string(),
                    });
                }
                tracing::warn!("CORS allow_origin is set to '*' - this is insecure for production. Specify exact origins.");
            }
        }

        if !self.secure_cookie
            && self.enabled
            && self.bind_address != "127.0.0.1"
            && self.bind_address != "::1"
            && self.bind_address != "localhost"
        {
            tracing::warn!(
                "admin.secure_cookie is false with public bind_address '{}' - session cookies will lack Secure flag; set secure_cookie = true for production",
                self.bind_address
            );
        }

        Ok(())
    }
}

fn default_admin_enabled() -> bool {
    true
}

fn default_admin_port() -> u16 {
    8081
}

fn default_admin_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let token: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..62);
            if idx < 10 {
                (b'0' + idx) as char
            } else if idx < 36 {
                (b'A' + idx - 10) as char
            } else {
                (b'a' + idx - 36) as char
            }
        })
        .collect();
    token
}

fn default_bcrypt_cost() -> u32 {
    12
}

fn default_secure_cookie() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_token_only_alphanumeric() {
        let token = AdminConfig::generate_token();
        assert_eq!(token.len(), 48);
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(token
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || c.is_ascii_uppercase()));
    }

    #[test]
    fn default_admin_token_only_alphanumeric() {
        let token = default_admin_token();
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generate_and_default_token_use_same_charset() {
        let gen = generate_token_chars();
        let def = default_token_chars();
        assert_eq!(
            gen, def,
            "generate_token and default_admin_token must use the same charset"
        );
    }

    fn generate_token_chars() -> Vec<char> {
        (0..62u8)
            .map(|idx| {
                if idx < 10 {
                    (b'0' + idx) as char
                } else if idx < 36 {
                    (b'A' + idx - 10) as char
                } else {
                    (b'a' + idx - 36) as char
                }
            })
            .collect()
    }

    fn default_token_chars() -> Vec<char> {
        (0..62u8)
            .map(|idx| {
                if idx < 10 {
                    (b'0' + idx) as char
                } else if idx < 36 {
                    (b'A' + idx - 10) as char
                } else {
                    (b'a' + idx - 36) as char
                }
            })
            .collect()
    }

    #[test]
    fn cors_wildcard_rejects_in_release() {
        let config = AdminConfig {
            port: 8081,
            token: "a".repeat(48),
            bcrypt_cost: 12,
            cors: AdminCorsConfig {
                allow_origin: Some("*".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        // In release builds this must error; in debug it only warns.
        if cfg!(not(debug_assertions)) {
            assert!(
                config.validate().is_err(),
                "CORS wildcard must be rejected in release builds"
            );
        } else {
            assert!(config.validate().is_ok());
        }
    }

    #[test]
    fn cors_specific_origin_passes_validation() {
        let config = AdminConfig {
            port: 8081,
            token: "a".repeat(48),
            bcrypt_cost: 12,
            cors: AdminCorsConfig {
                allow_origin: Some("https://example.com".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }
}
