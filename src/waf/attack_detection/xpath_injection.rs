use crate::waf::attack_detection::config::{AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::patterns::DefaultPatterns;

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
}

impl PatternDetector for XPathInjectionDetector {
    fn patterns(&self) -> &std::sync::Arc<aho_corasick::AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<crate::waf::attack_detection::config::AttackDetectionResult> {
        self.inner.detect(input, location)
    }

    fn detect_in_headers<F>(
        &self,
        headers: &http::HeaderMap,
        _check_header: F,
        normalizer: Option<&crate::waf::attack_detection::normalizer::InputNormalizer>,
    ) -> Option<crate::waf::attack_detection::config::AttackDetectionResult>
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
