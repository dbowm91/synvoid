use std::fmt;

/// Centralized error type for the MaluWAF crate.
///
/// All public APIs that can fail should return `WafResult<T>`.
/// Module-specific errors can be converted via `From` implementations.
#[derive(Debug, thiserror::Error)]
pub enum WafError {
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("IPC message decode error: {0}")]
    IpcDecode(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Request parsing error: {0}")]
    RequestParse(String),

    #[error("Invalid file descriptor")]
    InvalidFd,

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Upstream error: {0}")]
    Upstream(String),
}

/// Convenience type alias for `Result<T, WafError>`.
pub type WafResult<T> = Result<T, WafError>;

/// Extension trait for converting error messages into `WafError`.
pub trait WafErrorExt<T> {
    /// Map the error to `WafError::Internal` with the given context.
    fn waf_internal(self, ctx: &str) -> WafResult<T>;

    /// Map the error to `WafError::IpcDecode` with the given context.
    fn waf_ipc(self, ctx: &str) -> WafResult<T>;

    /// Map the error to `WafError::Config` with the given context.
    fn waf_config(self, ctx: &str) -> WafResult<T>;

    /// Map the error to `WafError::Upstream` with the given context.
    fn waf_upstream(self, ctx: &str) -> WafResult<T>;
}

impl<T, E: fmt::Display> WafErrorExt<T> for Result<T, E> {
    fn waf_internal(self, ctx: &str) -> WafResult<T> {
        self.map_err(|e| WafError::Internal(format!("{}: {}", ctx, e)))
    }

    fn waf_ipc(self, ctx: &str) -> WafResult<T> {
        self.map_err(|e| WafError::IpcDecode(format!("{}: {}", ctx, e)))
    }

    fn waf_config(self, ctx: &str) -> WafResult<T> {
        self.map_err(|e| WafError::Config(format!("{}: {}", ctx, e)))
    }

    fn waf_upstream(self, ctx: &str) -> WafResult<T> {
        self.map_err(|e| WafError::Upstream(format!("{}: {}", ctx, e)))
    }
}

impl From<String> for WafError {
    fn from(s: String) -> Self {
        WafError::Internal(s)
    }
}

impl From<&str> for WafError {
    fn from(s: &str) -> Self {
        WafError::Internal(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_error_display() {
        let err = WafError::InvalidIp("bad".to_string());
        assert_eq!(err.to_string(), "Invalid IP address: bad");
    }

    #[test]
    fn test_waf_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let waf_err: WafError = io_err.into();
        assert!(matches!(waf_err, WafError::Io(_)));
    }

    #[test]
    fn test_waf_error_from_json() {
        let json_err = serde_json::from_str::<String>("invalid").unwrap_err();
        let waf_err: WafError = json_err.into();
        assert!(matches!(waf_err, WafError::Json(_)));
    }

    #[test]
    fn test_waf_error_from_string() {
        let waf_err: WafError = "something went wrong".into();
        assert!(matches!(waf_err, WafError::Internal(_)));
    }

    #[test]
    fn test_waf_error_ext() {
        let result: Result<(), std::io::Error> =
            Err(std::io::Error::new(std::io::ErrorKind::Other, "fail"));
        let mapped = result.waf_internal("context");
        assert!(mapped.is_err());
        let err = mapped.unwrap_err();
        assert!(err.to_string().contains("context"));
    }
}
