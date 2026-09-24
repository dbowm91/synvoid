use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct HttpConfig {
    #[serde(default = "default_header_read_timeout")]
    pub header_read_timeout_secs: u64,
    #[serde(default = "default_keep_alive_timeout")]
    pub keep_alive_timeout_secs: u64,
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    #[serde(default = "default_max_request_line_size")]
    pub max_request_line_size: usize,
    #[serde(default = "default_max_header_size_ingress")]
    pub max_header_size_ingress: usize,
    #[serde(default = "default_max_header_size_egress")]
    pub max_header_size_egress: usize,
    #[serde(default = "default_max_request_size")]
    pub max_request_size: usize,
    #[serde(default = "default_pipeline_limit")]
    pub pipeline_limit: usize,
    #[serde(default = "default_waf_stall_timeout")]
    pub waf_stall_timeout_secs: u64,
    #[serde(default = "default_max_stalled_requests")]
    pub max_stalled_requests: u32,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_strict_protocol_validation")]
    pub strict_protocol_validation: bool,
    #[serde(default = "default_max_streaming_body_size")]
    pub max_streaming_body_size: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            header_read_timeout_secs: default_header_read_timeout(),
            keep_alive_timeout_secs: default_keep_alive_timeout(),
            max_headers: default_max_headers(),
            max_request_line_size: default_max_request_line_size(),
            max_header_size_ingress: default_max_header_size_ingress(),
            max_header_size_egress: default_max_header_size_egress(),
            max_request_size: default_max_request_size(),
            pipeline_limit: default_pipeline_limit(),
            waf_stall_timeout_secs: default_waf_stall_timeout(),
            max_stalled_requests: default_max_stalled_requests(),
            max_connections: default_max_connections(),
            strict_protocol_validation: default_strict_protocol_validation(),
            max_streaming_body_size: default_max_streaming_body_size(),
        }
    }
}

fn default_header_read_timeout() -> u64 {
    10
}

fn default_waf_stall_timeout() -> u64 {
    5
}

fn default_max_stalled_requests() -> u32 {
    100
}
fn default_keep_alive_timeout() -> u64 {
    60
}
fn default_max_headers() -> usize {
    128
}
fn default_max_request_line_size() -> usize {
    8192
}
fn default_max_header_size_ingress() -> usize {
    4096
}
fn default_max_header_size_egress() -> usize {
    16384
}
fn default_max_request_size() -> usize {
    1048576
}
fn default_pipeline_limit() -> usize {
    32
}

fn default_max_connections() -> u32 {
    10000
}

fn default_strict_protocol_validation() -> bool {
    false
}

fn default_max_streaming_body_size() -> usize {
    10 * 1024 * 1024 // 10MB default
}

impl HttpConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.header_read_timeout_secs == 0 {
            return Err(ConfigValidationError {
                field: "http.header_read_timeout_secs".to_string(),
                message: "Timeout must be greater than 0".to_string(),
            });
        }
        if self.max_headers == 0 {
            return Err(ConfigValidationError {
                field: "http.max_headers".to_string(),
                message: "max_headers must be greater than 0".to_string(),
            });
        }
        // Phase 71: the TLS H2 path projects `max_headers` into
        // `max_header_list_size(u32)`. A value above `u32::MAX` would
        // truncate silently through the `as u32` cast, so fail closed here.
        if self.max_headers > u32::MAX as usize {
            return Err(ConfigValidationError {
                field: "http.max_headers".to_string(),
                message: "max_headers must fit in a u32 (H2 header-list limit)".to_string(),
            });
        }
        // Phase 71: `max_request_size` is the Hyper H1 parser-buffer ceiling
        // (`max_buf_size`), not a body limit. Hyper panics for values below
        // its minimum (8192), so fail closed with a named error instead of a
        // runtime panic. See `src/http/h1_policy.rs`.
        if self.max_request_size < MIN_H1_PARSER_BUFFER_SIZE {
            return Err(ConfigValidationError {
                field: "http.max_request_size".to_string(),
                message: format!(
                    "max_request_size must be at least {MIN_H1_PARSER_BUFFER_SIZE} (Hyper H1 parser-buffer minimum)"
                ),
            });
        }
        // Phase 71: `max_header_size_ingress` is enforced as an aggregate
        // post-parse request-header bound (431). Zero would reject every
        // request; fail closed at load time with a named error.
        if self.max_header_size_ingress == 0 {
            return Err(ConfigValidationError {
                field: "http.max_header_size_ingress".to_string(),
                message: "max_header_size_ingress must be greater than 0".to_string(),
            });
        }
        if self.max_connections == 0 {
            return Err(ConfigValidationError {
                field: "http.max_connections".to_string(),
                message: "max_connections must be greater than 0".to_string(),
            });
        }
        Ok(())
    }
}

/// Minimum value Hyper accepts for the H1 parser buffer (`max_buf_size`).
/// Mirrors `hyper::proto::h1::MINIMUM_MAX_BUFFER_SIZE`; kept as a literal so
/// `synvoid-config` does not gain a Hyper dependency for one bound. If Hyper
/// changes its minimum, `src/http/h1_policy.rs` documents the coupling.
pub const MIN_H1_PARSER_BUFFER_SIZE: usize = 8192;

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema, ToSchema)]
pub struct Http3Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_http3_port")]
    pub port: u16,
    #[serde(default)]
    pub host_v6: Option<String>,
    #[serde(default = "default_alt_svc_max_age")]
    pub alt_svc_max_age: u64,
    #[serde(default = "default_http3_max_request_size")]
    pub max_request_size: usize,
}

fn default_http3_port() -> u16 {
    443
}

fn default_alt_svc_max_age() -> u64 {
    86400
}

fn default_http3_max_request_size() -> usize {
    10 * 1024 * 1024 // 10MB default for HTTP/3
}

#[derive(Debug, Clone, JsonSchema, ToSchema)]
pub struct TokioConfig {
    pub worker_threads: usize,
}

impl Serialize for TokioConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.worker_threads as u64)
    }
}

impl<'de> Deserialize<'de> for TokioConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawValue {
            String(String),
            Number(usize),
        }

        let raw = Option::<RawValue>::deserialize(deserializer)?;

        let worker_threads = match raw {
            Some(RawValue::String(s)) if s.to_lowercase() == "auto" => {
                std::thread::available_parallelism()
                    .map(|p| p.get())
                    .unwrap_or(4)
            }
            Some(RawValue::String(s)) => s.parse().unwrap_or_else(|_| {
                std::thread::available_parallelism()
                    .map(|p| p.get())
                    .unwrap_or(4)
            }),
            Some(RawValue::Number(n)) => n,
            None => std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4),
        };

        Ok(Self { worker_threads })
    }
}

impl Default for TokioConfig {
    fn default() -> Self {
        Self {
            worker_threads: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        HttpConfig::default().validate().unwrap();
    }

    #[test]
    fn parser_buffer_minimum_matches_hyper_floor() {
        assert_eq!(MIN_H1_PARSER_BUFFER_SIZE, 8192);
        let mut config = HttpConfig::default();
        config.max_request_size = MIN_H1_PARSER_BUFFER_SIZE - 1;
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "http.max_request_size");
        config.max_request_size = MIN_H1_PARSER_BUFFER_SIZE;
        config.validate().unwrap();
    }

    #[test]
    fn max_headers_u32_overflow_fails_closed() {
        let mut config = HttpConfig::default();
        config.max_headers = u32::MAX as usize + 1;
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "http.max_headers");
        config.max_headers = u32::MAX as usize;
        config.validate().unwrap();
    }

    #[test]
    fn zero_ingress_bound_fails_closed() {
        let mut config = HttpConfig::default();
        config.max_header_size_ingress = 0;
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "http.max_header_size_ingress");
    }
}
