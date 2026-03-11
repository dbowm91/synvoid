use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::detect_in_headers;

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
        check_header: F,
        normalizer: Option<&crate::waf::attack_detection::normalizer::InputNormalizer>,
    ) -> Option<AttackDetectionResult>
    where
        F: FnMut(&str) -> bool,
    {
        detect_in_headers(headers, check_header, normalizer, Self::detect)
    }
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
