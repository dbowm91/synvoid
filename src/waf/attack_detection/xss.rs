use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};

pub struct XssDetector;

impl XssDetector {
    pub fn detect(input: &[u8], location: InputLocation) -> Option<AttackDetectionResult> {
        let result = libinjectionrs::detect_xss(input);

        if result.is_injection() {
            tracing::warn!(
                attack_type = "xss",
                location = %location,
                "XSS attack detected"
            );

            Some(AttackDetectionResult {
                attack_type: AttackType::Xss,
                fingerprint: None,
                matched_pattern: None,
                input_location: location,
            })
        } else {
            None
        }
    }

    pub fn detect_in_headers<F>(
        headers: &http::HeaderMap,
        mut check_header: F,
    ) -> Option<AttackDetectionResult>
    where
        F: FnMut(&str) -> bool,
    {
        let headers_to_check =
            crate::waf::attack_detection::patterns::DefaultPatterns::headers_to_check();

        for header_name in headers_to_check {
            if let Some(value) = headers.get(*header_name) {
                if !check_header(*header_name) {
                    continue;
                }

                if let Ok(value_str) = value.to_str() {
                    let input = value_str.as_bytes();
                    let location = InputLocation::Header(header_name.to_string());

                    if let Some(result) = Self::detect(input, location) {
                        return Some(result);
                    }

                    if let Ok(decoded) = urlencoding_decode(value_str) {
                        if decoded != value_str {
                            let location = InputLocation::Header(header_name.to_string());
                            if let Some(result) = Self::detect(decoded.as_bytes(), location) {
                                return Some(result);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

fn urlencoding_decode(input: &str) -> Result<String, ()> {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_detection_script() {
        let input = b"<script>alert('xss')</script>";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_detection_event_handler() {
        let input = b"<img src=x onerror=alert(1)>";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_detection_benign() {
        let input = b"<p>Hello, world!</p>";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_none());
    }
}
