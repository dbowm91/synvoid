use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
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
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
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
            max_connections: default_max_connections(),
        }
    }
}

fn default_header_read_timeout() -> u64 {
    10
}

fn default_waf_stall_timeout() -> u64 {
    5
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
        if self.max_request_size == 0 {
            return Err(ConfigValidationError {
                field: "http.max_request_size".to_string(),
                message: "max_request_size must be greater than 0".to_string(),
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

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
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

#[derive(Debug, Clone, JsonSchema)]
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
