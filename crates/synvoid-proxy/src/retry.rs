//! Retry logic for upstream requests.

use http::Method;
use synvoid_config::site::RetryConfig;

pub fn is_retryable_status(status: u16, config: &RetryConfig) -> bool {
    if !config.retry_on_status.is_empty() {
        return config.retry_on_status.contains(&status);
    }
    matches!(status, 502..=504)
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

pub fn is_connection_error(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
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
        let msg = error.to_string();
        contains_ignore_ascii_case(&msg, "connection refused")
            || contains_ignore_ascii_case(&msg, "connection reset")
            || contains_ignore_ascii_case(&msg, "broken pipe")
            || contains_ignore_ascii_case(&msg, "network unreachable")
            || contains_ignore_ascii_case(&msg, "software caused connection abort")
    }
}

pub fn is_timeout_error(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    if let Some(io_err) = error.downcast_ref::<std::io::Error>() {
        matches!(
            io_err.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        )
    } else {
        let msg = error.to_string();
        contains_ignore_ascii_case(&msg, "timeout") || contains_ignore_ascii_case(&msg, "timed out")
    }
}

pub fn calculate_backoff(attempt: u32, base_timeout_ms: u64) -> u64 {
    let delay = base_timeout_ms.saturating_mul(2u64.saturating_pow(attempt.min(5)));
    let capped = delay.min(30000);
    // Add jitter to avoid thundering herd
    let jitter = {
        use rand::Rng;
        rand::rng().random_range(0..capped / 2 + 1)
    };
    capped / 2 + jitter
}

pub fn is_idempotent_method(method: &Method) -> bool {
    matches!(
        method,
        &Method::GET | &Method::HEAD | &Method::OPTIONS | &Method::TRACE
    )
}

pub fn should_retry_request(method: &Method, config: &RetryConfig) -> bool {
    is_idempotent_method(method) || config.retry_non_idempotent
}
