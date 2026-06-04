use crate::attack_detection::config::{AttackType, InputLocation};
use crate::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::attack_detection::patterns::DefaultPatterns;
use synvoid_core::url::url_decode_all;

pub struct XPathInjectionDetector {
    inner: BasePatternDetector,
}

impl XPathInjectionDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::xpath_injection().as_slice(),
            DefaultPatterns::xpath_injection_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::XPathInjection,
            "xpath_injection",
        );
        Self { inner }
    }

    fn detect_with_url_decode(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<crate::attack_detection::config::AttackDetectionResult> {
        let input_lower = input.to_lowercase();
        let decoded = if input_lower.contains('%') || input_lower.contains('+') {
            url_decode_all(&input_lower)
        } else {
            input_lower.clone()
        };

        if let Some(mat) = self.inner.patterns_ref().find(&decoded) {
            let matched = decoded[mat.start()..mat.end()].to_string();
            tracing::warn!(
                attack_type = "xpath_injection",
                matched_pattern = %matched,
                location = %location,
                "XPath injection detected"
            );
            return Some(crate::attack_detection::config::AttackDetectionResult {
                attack_type: AttackType::XPathInjection,
                fingerprint: None,
                matched_pattern: Some(matched),
                input_location: location,
            });
        }

        if decoded != input_lower {
            if let Some(mat) = self.inner.patterns_ref().find(&input_lower) {
                let matched = input_lower[mat.start()..mat.end()].to_string();
                tracing::warn!(
                    attack_type = "xpath_injection",
                    matched_pattern = %matched,
                    location = %location,
                    "XPath injection detected (encoded)"
                );
                return Some(crate::attack_detection::config::AttackDetectionResult {
                    attack_type: AttackType::XPathInjection,
                    fingerprint: None,
                    matched_pattern: Some(matched),
                    input_location: location,
                });
            }
        }

        None
    }
}

impl PatternDetector for XPathInjectionDetector {
    fn patterns(&self) -> &std::sync::Arc<aho_corasick::AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<crate::attack_detection::config::AttackDetectionResult> {
        self.detect_with_url_decode(input, location)
    }

    fn detect_in_headers<F>(
        &self,
        headers: &http::HeaderMap,
        _check_header: F,
        normalizer: Option<&crate::attack_detection::normalizer::InputNormalizer>,
    ) -> Option<crate::attack_detection::config::AttackDetectionResult>
    where
        F: FnMut(&str) -> bool,
    {
        self.inner.detect_in_all_headers(headers, normalizer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xpath_injection_basic() {
        let detector = XPathInjectionDetector::new(2, &[]);
        let input = "admin']";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xpath_injection_or() {
        let detector = XPathInjectionDetector::new(2, &[]);
        let input = "admin']or'1'='1";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xpath_injection_substring() {
        let detector = XPathInjectionDetector::new(2, &[]);
        let input = "substring(//user,1,1)";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xpath_injection_contains() {
        let detector = XPathInjectionDetector::new(2, &[]);
        let input = "contains(//user,'admin')";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xpath_injection_ancestor() {
        let detector = XPathInjectionDetector::new(2, &[]);
        let input = "ancestor::user";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xpath_injection_comment() {
        let detector = XPathInjectionDetector::new(2, &[]);
        let input = "comment()";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_xpath_injection_benign() {
        let detector = XPathInjectionDetector::new(2, &[]);
        let input = "search term";
        assert!(detector.detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_xpath_injection_true_false() {
        let detector = XPathInjectionDetector::new(2, &[]);
        let input = "admin']or true()";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }
}
