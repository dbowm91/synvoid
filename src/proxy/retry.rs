//! Retry logic for upstream requests.

use crate::config::site::RetryConfig;

pub(super) fn is_retryable_status(status: u16, config: &RetryConfig) -> bool {
    if !config.retry_on_status.is_empty() {
        return config.retry_on_status.contains(&status);
    }
    matches!(status, 502..=504)
}

pub(super) fn is_connection_error(
    error: &(dyn std::error::Error + Send + Sync + 'static),
) -> bool {
    if let Some(io_err) = error.downcast_ref::<std::io::Error>() {
        matches!(
            io_err.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::NetworkDown
                | std::io::ErrorKind::NotConnected
        )
    } else {
        let error_lower = error.to_string().to_lowercase();
        error_lower.contains("connection refused")
            || error_lower.contains("connection reset")
            || error_lower.contains("broken pipe")
            || error_lower.contains("network unreachable")
            || error_lower.contains("software caused connection abort")
    }
}

pub(super) fn is_timeout_error(
    error: &(dyn std::error::Error + Send + Sync + 'static),
) -> bool {
    if let Some(io_err) = error.downcast_ref::<std::io::Error>() {
        matches!(
            io_err.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        )
    } else {
        let error_lower = error.to_string().to_lowercase();
        error_lower.contains("timeout") || error_lower.contains("timed out")
    }
}

pub(super) fn calculate_backoff(attempt: u32, base_timeout_ms: u64) -> u64 {
    let delay = base_timeout_ms * 2u64.saturating_pow(attempt.min(5));
    delay.min(30000)
}
