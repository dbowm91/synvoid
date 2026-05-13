use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::normalizer::{InputNormalizer, NormalizedInput};
use crate::waf::attack_detection::patterns::DefaultPatterns;
use aho_corasick::AhoCorasick;
use std::sync::Arc;

pub struct XssDetector {
    inner: BasePatternDetector,
    normalizer: InputNormalizer,
}

impl XssDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::xss().as_slice(),
            DefaultPatterns::xss_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::Xss,
            "xss",
        );
        Self {
            inner,
            normalizer: InputNormalizer::new(),
        }
    }

    pub fn detect(&self, input: &[u8], location: InputLocation) -> Option<AttackDetectionResult> {
        let input_str = String::from_utf8_lossy(input);
        let normalized = self.normalizer.normalize(&input_str);
        self.detect_normalized(&normalized, location)
    }

    pub fn detect_normalized(
        &self,
        normalized: &NormalizedInput,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        // 1. Try pattern-based detection
        let search_target: &str = normalized.as_str();
        if let Some(mat) = self.inner.patterns_ref().find(search_target) {
            let matched = search_target[mat.start()..mat.end()].to_string();
            tracing::warn!(
                attack_type = "xss",
                matched_pattern = %matched,
                location = %location,
                "XSS detected (pattern)"
            );
            return Some(AttackDetectionResult {
                attack_type: AttackType::Xss,
                fingerprint: None,
                matched_pattern: Some(matched),
                input_location: location,
            });
        }

        // 2. Try libinjection detection
        let result = libinjectionrs::detect_xss(normalized.as_bytes());

        if result.is_injection() {
            tracing::warn!(
                attack_type = "xss",
                location = %location,
                "XSS attack detected (libinjection)"
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
}

impl PatternDetector for XssDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        self.detect(input.as_bytes(), location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_detection_script() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<script>alert('xss')</script>";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_detection_event_handler() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<img src=x onerror=alert(1)>";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_detection_benign() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<p>Hello, world!</p>";
        assert!(detector.detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_xss_attack_type_field() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<script>alert('xss')</script>";
        let result = detector.detect(input, InputLocation::QueryString).unwrap();
        assert_eq!(result.attack_type, AttackType::Xss);
    }

    #[test]
    fn test_xss_svg_onload() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<svg onload=alert(1)>";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_onmouseover() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<div onmouseover=alert(1)>";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_onfocus() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<input onfocus=alert(1)>";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_encoded_script_tags_detected() {
        let detector = XssDetector::new(2, &[]);
        let input = b"%3Cscript%3Ealert(1)%3C/script%3E";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_img_onerror() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<img src=x onerror=alert(1)>";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_input_location_preserved() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<script>alert('xss')</script>";
        let result = detector.detect(input, InputLocation::PostBody).unwrap();
        assert!(matches!(result.input_location, InputLocation::PostBody));
    }

    #[test]
    fn test_xss_plain_text_benign() {
        let detector = XssDetector::new(2, &[]);
        let input = b"just some regular text without any tags";
        assert!(detector.detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_xss_href_javascript() {
        let detector = XssDetector::new(2, &[]);
        let input = b"<a href=javascript:alert(1)>";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xss_pattern_match() {
        let detector = XssDetector::new(2, &["CUSTOM_XSS_PATTERN".to_string()]);

        // Use input that won't trigger base patterns - just the custom pattern in isolation
        let input = b"CUSTOM_XSS_PATTERN";
        let result = detector.detect(input, InputLocation::QueryString).unwrap();
        assert_eq!(
            result.matched_pattern,
            Some("CUSTOM_XSS_PATTERN".to_string())
        );
    }
}
