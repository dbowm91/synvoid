use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteGrpcConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub max_message_size: Option<usize>,
    #[serde(default)]
    pub enable_request_validation: Option<bool>,
    #[serde(default)]
    pub enable_streaming: Option<bool>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub h2c_enabled: Option<bool>,
    #[serde(default)]
    pub h2_enabled: Option<bool>,
    #[serde(default)]
    pub reflection_enabled: Option<bool>,
    #[serde(default)]
    pub health_check_enabled: Option<bool>,
    #[serde(default)]
    pub max_concurrent_streams: Option<u32>,
}

impl SiteGrpcConfig {
    pub fn validate(&self) -> Result<(), crate::config::validation::ConfigValidationError> {
        if self.enabled.unwrap_or(false) {
            if self.upstream.is_none() {
                return Err(crate::config::validation::ConfigValidationError {
                    field: "grpc.upstream".to_string(),
                    message: "Upstream is required when gRPC is enabled".to_string(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteWebSocketConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub max_message_size: Option<usize>,
    #[serde(default)]
    pub mask_required: Option<bool>,
    #[serde(default)]
    pub enable_frame_validation: Option<bool>,
    #[serde(default)]
    pub enable_message_validation: Option<bool>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub ping_interval_secs: Option<u64>,
    #[serde(default)]
    pub ping_timeout_secs: Option<u64>,
}

impl SiteWebSocketConfig {
    pub fn validate(&self) -> Result<(), crate::config::validation::ConfigValidationError> {
        if self.enabled.unwrap_or(false) {
            if self.upstream.is_none() {
                return Err(crate::config::validation::ConfigValidationError {
                    field: "websocket.upstream".to_string(),
                    message: "Upstream is required when WebSocket is enabled".to_string(),
                });
            }
        }
        Ok(())
    }
}
