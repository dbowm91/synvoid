use std::time::Duration;
use subtle::ConstantTimeEq;

const MAX_IDENTIFIER_LEN: usize = 256;
const MAX_CLIENT_ID_LEN: usize = 128;
const MAX_PEER_ID_LEN: usize = 128;
const MAX_AUTH_TOKEN_LEN: usize = 1024;
pub const MIN_MESSAGE_SIZE: usize = 1024;
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
pub const DEFAULT_MESSAGE_SIZE: usize = 1024 * 1024;

pub fn secure_token_compare(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub fn is_valid_token_format(token: &str) -> bool {
    !token.is_empty() && token.len() <= MAX_AUTH_TOKEN_LEN && !token.chars().any(|c| c.is_control())
}

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: &'static str,
    pub reason: String,
    pub value_preview: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Validation error for '{}': {} (value: '{}')",
            self.field, self.reason, self.value_preview
        )
    }
}

impl std::error::Error for ValidationError {}

pub fn validate_identifier(identifier: &str) -> Result<(), ValidationError> {
    let preview = truncate_preview(identifier, 32);

    if identifier.is_empty() {
        return Err(ValidationError {
            field: "identifier",
            reason: "cannot be empty".to_string(),
            value_preview: preview,
        });
    }

    if identifier.len() > MAX_IDENTIFIER_LEN {
        return Err(ValidationError {
            field: "identifier",
            reason: format!("exceeds max length of {} bytes", MAX_IDENTIFIER_LEN),
            value_preview: preview,
        });
    }

    for ch in identifier.chars() {
        if !is_safe_identifier_char(ch) {
            return Err(ValidationError {
                field: "identifier",
                reason:
                    "contains invalid characters (only alphanumeric, dash, underscore, dot allowed)"
                        .to_string(),
                value_preview: preview,
            });
        }
    }

    Ok(())
}

pub fn validate_client_id(client_id: &str) -> Result<(), ValidationError> {
    let preview = truncate_preview(client_id, 32);

    if client_id.is_empty() {
        return Err(ValidationError {
            field: "client_id",
            reason: "cannot be empty".to_string(),
            value_preview: preview,
        });
    }

    if client_id.len() > MAX_CLIENT_ID_LEN {
        return Err(ValidationError {
            field: "client_id",
            reason: format!("exceeds max length of {} bytes", MAX_CLIENT_ID_LEN),
            value_preview: preview,
        });
    }

    for ch in client_id.chars() {
        if !is_safe_id_char(ch) {
            return Err(ValidationError {
                field: "client_id",
                reason:
                    "contains invalid characters (only printable ASCII excluding control chars)"
                        .to_string(),
                value_preview: preview,
            });
        }
    }

    Ok(())
}

pub fn validate_peer_id(peer_id: &str) -> Result<(), ValidationError> {
    let preview = truncate_preview(peer_id, 32);

    if peer_id.is_empty() {
        return Err(ValidationError {
            field: "peer_id",
            reason: "cannot be empty".to_string(),
            value_preview: preview,
        });
    }

    if peer_id.len() > MAX_PEER_ID_LEN {
        return Err(ValidationError {
            field: "peer_id",
            reason: format!("exceeds max length of {} bytes", MAX_PEER_ID_LEN),
            value_preview: preview,
        });
    }

    for ch in peer_id.chars() {
        if !is_safe_id_char(ch) {
            return Err(ValidationError {
                field: "peer_id",
                reason:
                    "contains invalid characters (only printable ASCII excluding control chars)"
                        .to_string(),
                value_preview: preview,
            });
        }
    }

    Ok(())
}

pub fn validate_port(port: u16) -> Result<(), ValidationError> {
    if port == 0 {
        return Err(ValidationError {
            field: "port",
            reason: "port 0 is not valid".to_string(),
            value_preview: "0".to_string(),
        });
    }
    Ok(())
}

pub fn validate_max_message_size(size: usize) -> Result<usize, ValidationError> {
    if size < MIN_MESSAGE_SIZE {
        tracing::warn!(
            "max_message_size {} is below minimum {}, using minimum",
            size,
            MIN_MESSAGE_SIZE
        );
        return Ok(MIN_MESSAGE_SIZE);
    }
    if size > MAX_MESSAGE_SIZE {
        tracing::warn!(
            "max_message_size {} exceeds maximum {}, using maximum",
            size,
            MAX_MESSAGE_SIZE
        );
        return Ok(MAX_MESSAGE_SIZE);
    }
    Ok(size)
}

fn is_safe_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' || ch == ':'
}

fn is_safe_id_char(ch: char) -> bool {
    ch.is_ascii() && !ch.is_control() && ch != '\n' && ch != '\r' && ch != '\0' && ch != '\t'
}

fn truncate_preview(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

pub struct JitteredBackoff {
    base_delay: Duration,
    max_delay: Duration,
    multiplier: f64,
    current_attempt: u32,
}

impl JitteredBackoff {
    pub fn new(base_delay: Duration, max_delay: Duration, multiplier: f64) -> Self {
        Self {
            base_delay,
            max_delay,
            multiplier,
            current_attempt: 0,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        self.current_attempt += 1;

        let exp_delay = self.base_delay.as_secs_f64()
            * self
                .multiplier
                .powi(self.current_attempt.saturating_sub(1) as i32);
        let capped_delay = exp_delay.min(self.max_delay.as_secs_f64());

        let jitter = if capped_delay > 0.0 {
            let jitter_range = capped_delay * 0.3;
            let jitter_amount = (rand_jitter() - 0.5) * 2.0 * jitter_range;
            capped_delay + jitter_amount
        } else {
            capped_delay
        };

        Duration::from_secs_f64(jitter.max(0.0))
    }

    pub fn reset(&mut self) {
        self.current_attempt = 0;
    }

    pub fn attempt(&self) -> u32 {
        self.current_attempt
    }
}

fn rand_jitter() -> f64 {
    let mut bytes = [0u8; 8];
    rand::fill(&mut bytes);
    let value = u64::from_le_bytes(bytes);
    (value as f64) / (u64::MAX as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_identifier() {
        assert!(validate_identifier("my-tunnel-80").is_ok());
        assert!(validate_identifier("tcp-port-443").is_ok());
        assert!(validate_identifier("udp.port.dns").is_ok());
        assert!(validate_identifier("").is_err());
        assert!(validate_identifier(&"a".repeat(300)).is_err());
        assert!(validate_identifier("bad/identifier").is_err());
        assert!(validate_identifier("bad identifier").is_err());
    }

    #[test]
    fn test_validate_client_id() {
        assert!(validate_client_id("home-server-1").is_ok());
        assert!(validate_client_id("client_123").is_ok());
        assert!(validate_client_id("").is_err());
        assert!(validate_client_id(&"a".repeat(200)).is_err());
    }

    #[test]
    fn test_validate_peer_id() {
        assert!(validate_peer_id("waf-east-1").is_ok());
        assert!(validate_peer_id("peer_123").is_ok());
        assert!(validate_peer_id("").is_err());
    }

    #[test]
    fn test_jittered_backoff() {
        let mut backoff =
            JitteredBackoff::new(Duration::from_secs(1), Duration::from_secs(60), 2.0);

        let d1 = backoff.next_delay();
        let d2 = backoff.next_delay();
        let d3 = backoff.next_delay();

        assert!(d1.as_secs_f64() >= 0.5 && d1.as_secs_f64() <= 1.5);
        assert!(d2.as_secs_f64() > d1.as_secs_f64() * 0.5);
        assert!(d3.as_secs_f64() > d2.as_secs_f64() * 0.5);

        backoff.reset();
        assert_eq!(backoff.attempt(), 0);
    }

    #[test]
    fn test_secure_token_compare() {
        assert!(secure_token_compare("secret-token", "secret-token"));
        assert!(!secure_token_compare("secret-token", "wrong-token"));
        assert!(!secure_token_compare("", "token"));
        assert!(!secure_token_compare("token", ""));
        assert!(!secure_token_compare("", ""));
    }

    #[test]
    fn test_is_valid_token_format() {
        assert!(is_valid_token_format("valid-token-123"));
        assert!(is_valid_token_format("a"));
        assert!(!is_valid_token_format(""));
        assert!(!is_valid_token_format("token\nwith\nnewlines"));
        assert!(!is_valid_token_format("token\x00null"));
    }
}
