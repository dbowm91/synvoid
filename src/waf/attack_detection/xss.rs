use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::detect_in_headers;
use crate::waf::attack_detection::normalizer::InputNormalizer;

pub struct XssDetector;

impl XssDetector {
    pub fn detect(input: &[u8], location: InputLocation) -> Option<AttackDetectionResult> {
        let normalized = InputNormalizer::new().normalize(std::str::from_utf8(input).unwrap_or(""));
        let result = libinjectionrs::detect_xss(normalized.as_bytes());

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

    #[test]
    fn test_xss_attack_type_field() {
        let input = b"<script>alert('xss')</script>";
        let result = XssDetector::detect(input, InputLocation::QueryString).unwrap();
        assert_eq!(result.attack_type, AttackType::Xss);
    }

    #[test]
    fn test_xss_svg_onload() {
        let input = b"<svg onload=alert(1)>";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_onmouseover() {
        let input = b"<div onmouseover=alert(1)>";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_onfocus() {
        let input = b"<input onfocus=alert(1)>";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_encoded_script_tags_detected() {
        let input = b"%3Cscript%3Ealert(1)%3C/script%3E";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_img_onerror() {
        let input = b"<img src=x onerror=alert(1)>";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_input_location_preserved() {
        let input = b"<script>alert('xss')</script>";
        let result = XssDetector::detect(input, InputLocation::PostBody).unwrap();
        assert!(matches!(result.input_location, InputLocation::PostBody));
    }

    #[test]
    fn test_xss_plain_text_benign() {
        let input = b"just some regular text without any tags";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_xss_href_javascript() {
        let input = b"<a href=javascript:alert(1)>";
        assert!(XssDetector::detect(input, InputLocation::QueryString).is_some());
    }
}
