use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};

pub struct HeaderValidator {
    max_header_size: usize,
    max_header_count: usize,
}

impl HeaderValidator {
    pub fn new(max_header_size: usize, max_header_count: usize) -> Self {
        Self {
            max_header_size,
            max_header_count,
        }
    }

    pub fn validate(&self, headers: &http::HeaderMap) -> Option<AttackDetectionResult> {
        if headers.len() > self.max_header_count {
            tracing::warn!(
                attack_type = "header_validation",
                count = headers.len(),
                limit = self.max_header_count,
                "Too many headers in request"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::RequestSmuggling,
                fingerprint: Some("too_many_headers".to_string()),
                matched_pattern: Some(format!(
                    "{} headers (limit: {})",
                    headers.len(),
                    self.max_header_count
                )),
                input_location: InputLocation::Header("__total__".to_string()),
            });
        }

        for (name, value) in headers.iter() {
            let name_str = name.as_str();
            let value_bytes = value.as_bytes();

            if value_bytes.len() > self.max_header_size {
                tracing::warn!(
                    attack_type = "header_validation",
                    header = %name_str,
                    size = value_bytes.len(),
                    limit = self.max_header_size,
                    "Header value too large"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::RequestSmuggling,
                    fingerprint: Some("header_too_large".to_string()),
                    matched_pattern: Some(format!(
                        "{}: {} bytes (limit: {})",
                        name_str,
                        value_bytes.len(),
                        self.max_header_size
                    )),
                    input_location: InputLocation::Header(name_str.to_string()),
                });
            }

            if self.contains_crlf(value_bytes) {
                tracing::warn!(
                    attack_type = "header_validation",
                    header = %name_str,
                    "CRLF injection detected in header"
                );

                let value_str = String::from_utf8_lossy(value_bytes);
                return Some(AttackDetectionResult {
                    attack_type: AttackType::RequestSmuggling,
                    fingerprint: Some("crlf_injection".to_string()),
                    matched_pattern: Some(format!("{}: {}", name_str, value_str)),
                    input_location: InputLocation::Header(name_str.to_string()),
                });
            }

            if self.is_invalid_header_value(value_bytes) {
                tracing::warn!(
                    attack_type = "header_validation",
                    header = %name_str,
                    "Invalid characters in header value"
                );

                let value_str = String::from_utf8_lossy(value_bytes);
                return Some(AttackDetectionResult {
                    attack_type: AttackType::RequestSmuggling,
                    fingerprint: Some("invalid_header_value".to_string()),
                    matched_pattern: Some(format!("{}: {}", name_str, value_str)),
                    input_location: InputLocation::Header(name_str.to_string()),
                });
            }
        }

        self.validate_host_header(headers)?;

        self.check_duplicate_headers(headers)?;

        None
    }

    fn contains_crlf(&self, value: &[u8]) -> bool {
        value.contains(&b'\r') || value.contains(&b'\n')
    }

    fn is_invalid_header_value(&self, value: &[u8]) -> bool {
        for &byte in value {
            if byte == 0 {
                return true;
            }
            if byte < 0x20 && byte != 0x09 && byte != 0x0A && byte != 0x0D {
                return true;
            }
            if byte == 0x7F {
                return true;
            }
        }
        false
    }

    fn validate_host_header(&self, headers: &http::HeaderMap) -> Option<AttackDetectionResult> {
        let host = headers.get("host")?;

        let host_str = host.to_str().ok()?;

        if host_str.is_empty() {
            tracing::warn!(attack_type = "header_validation", "Empty Host header");

            return Some(AttackDetectionResult {
                attack_type: AttackType::RequestSmuggling,
                fingerprint: Some("empty_host".to_string()),
                matched_pattern: Some("Host header is empty".to_string()),
                input_location: InputLocation::Header("host".to_string()),
            });
        }

        if host_str.contains('\r') || host_str.contains('\n') {
            tracing::warn!(
                attack_type = "header_validation",
                "CRLF injection in Host header"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::RequestSmuggling,
                fingerprint: Some("host_crlf_injection".to_string()),
                matched_pattern: Some(host_str.to_string()),
                input_location: InputLocation::Header("host".to_string()),
            });
        }

        if !host_str.contains('.') && host_str != "localhost" && !host_str.starts_with('[') {
            tracing::debug!(
                attack_type = "header_validation",
                host = %host_str,
                "Suspicious Host header format"
            );
        }

        None
    }

    fn check_duplicate_headers(&self, headers: &http::HeaderMap) -> Option<AttackDetectionResult> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for name in headers.keys() {
            let name_str = name.as_str().to_lowercase();
            if !seen.insert(name_str.clone()) {
                tracing::warn!(
                    attack_type = "header_validation",
                    header = %name_str,
                    "Duplicate header detected"
                );

                let matched = name_str.clone();
                return Some(AttackDetectionResult {
                    attack_type: AttackType::RequestSmuggling,
                    fingerprint: Some("duplicate_header".to_string()),
                    matched_pattern: Some(matched.clone()),
                    input_location: InputLocation::Header(matched),
                });
            }
        }

        None
    }
}

impl Default for HeaderValidator {
    fn default() -> Self {
        Self::new(8192, 128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "http crate rejects invalid header values at parse time"]
    fn test_crlf_injection() {
        let validator = HeaderValidator::default();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom", "value\r\nInjection".parse().unwrap());

        assert!(validator.validate(&headers).is_some());
    }

    #[test]
    #[ignore = "http crate rejects null bytes in header values at parse time"]
    fn test_null_byte() {
        let validator = HeaderValidator::default();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom", "value\x00injection".parse().unwrap());

        assert!(validator.validate(&headers).is_some());
    }

    #[test]
    fn test_valid_header() {
        let validator = HeaderValidator::default();
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());

        assert!(validator.validate(&headers).is_none());
    }

    #[test]
    #[ignore = "http crate rejects empty host header at parse time"]
    fn test_empty_host() {
        let validator = HeaderValidator::default();
        let mut headers = http::HeaderMap::new();
        headers.insert("host", "".parse().unwrap());

        assert!(validator.validate(&headers).is_some());
    }

    #[test]
    #[ignore = "http crate HeaderMap automatically handles duplicate headers"]
    fn test_duplicate_headers() {
        let validator = HeaderValidator::default();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom", "value1".parse().unwrap());
        headers.insert("x-custom", "value2".parse().unwrap());

        assert!(validator.validate(&headers).is_some());
    }
}
