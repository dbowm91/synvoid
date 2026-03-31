use serde::{Deserialize, Serialize};

use super::validation::ConfigValidationError;

const MIN_TOKEN_LENGTH: usize = 32;
const WEAK_TOKEN_PATTERNS: &[&str] = &[
    "changeme", "password", "admin", "123456", "qwerty", "letmein", "welcome", "monkey", "dragon",
    "master",
];

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AdminCorsConfig {
    #[serde(default)]
    pub allow_origin: Option<String>,
    #[serde(default)]
    pub allow_methods: Option<Vec<String>>,
    #[serde(default)]
    pub allow_headers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AdminConfig {
    #[serde(default = "default_admin_enabled")]
    pub enabled: bool,
    #[serde(default = "default_admin_port")]
    pub port: u16,
    #[serde(default = "default_admin_bind")]
    pub bind_address: String,
    #[serde(default = "default_admin_token")]
    pub token: String,
    #[serde(default)]
    pub token_env_var: Option<String>,
    #[serde(default = "default_bcrypt_cost")]
    pub bcrypt_cost: u32,
    #[serde(default)]
    pub cors: AdminCorsConfig,
    #[serde(default)]
    pub rate_limit: AdminRateLimitConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
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
                let idx = rng.random_range(0..64);
                if idx < 10 {
                    (b'0' + idx) as char
                } else if idx < 36 {
                    (b'a' + idx - 10) as char
                } else {
                    (b'A' + idx - 36) as char
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

        if self.bcrypt_cost < 10 || self.bcrypt_cost > 15 {
            return Err(ConfigValidationError {
                field: "admin.bcrypt_cost".to_string(),
                message: "bcrypt_cost must be between 10 and 15".to_string(),
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
            let generated = Self::generate_token();
            tracing::info!("Generated admin token: {}", generated);
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
                tracing::warn!("CORS allow_origin is set to '*' - this is insecure for production. Specify exact origins.");
            }
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
            let idx = rng.random_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    token
}

fn default_bcrypt_cost() -> u32 {
    12
}

#[derive(Debug, Deserialize, Serialize, Clone)]
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
