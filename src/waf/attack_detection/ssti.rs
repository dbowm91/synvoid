use crate::waf::attack_detection::config::{AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::patterns::DefaultPatterns;
use aho_corasick::AhoCorasick;
use std::sync::Arc;

pub struct SstiDetector {
    inner: BasePatternDetector,
}

impl SstiDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::ssti().as_slice(),
            DefaultPatterns::ssti_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::Ssti,
            "ssti",
        );
        Self { inner }
    }
}

impl PatternDetector for SstiDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<crate::waf::attack_detection::config::AttackDetectionResult> {
        self.inner.detect(input, location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssti_jinja2() {
        let detector = SstiDetector::new(2, &[]);
        let input = "{{config.items()}}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ssti_twig() {
        let detector = SstiDetector::new(2, &[]);
        let input = "{{_self.env.display(\"id\")}}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ssti_freemarker() {
        let detector = SstiDetector::new(2, &[]);
        let input = "${\"freemarker.template.utility.Execute\"?new()(\"id\")}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ssti_benign() {
        let detector = SstiDetector::new(2, &[]);
        let input = "Hello username";
        assert!(detector.detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_ssti_case_insensitive() {
        let detector = SstiDetector::new(2, &[]);
        let input = "{{CONFIG.ITEMS()}}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ssti_mixed_case() {
        let detector = SstiDetector::new(2, &[]);
        let input = "${\"Freemarker.Template.Utility.Execute\"?new()(\"id\")}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }
}
