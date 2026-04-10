use crate::utils::url_decode_all;
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

    fn detect_with_url_decode(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<crate::waf::attack_detection::config::AttackDetectionResult> {
        let input_lower = input.to_lowercase();
        let decoded = url_decode_all(&input_lower);

        if let Some(mat) = self.inner.patterns_ref().find(&decoded) {
            let matched = decoded[mat.start()..mat.end()].to_string();
            tracing::warn!(
                attack_type = "ssti",
                matched_pattern = %matched,
                location = %location,
                "SSTI detected"
            );
            return Some(
                crate::waf::attack_detection::config::AttackDetectionResult {
                    attack_type: AttackType::Ssti,
                    fingerprint: None,
                    matched_pattern: Some(matched),
                    input_location: location,
                },
            );
        }

        if decoded != input_lower {
            if let Some(mat) = self.inner.patterns_ref().find(&input_lower) {
                let matched = input_lower[mat.start()..mat.end()].to_string();
                tracing::warn!(
                    attack_type = "ssti",
                    matched_pattern = %matched,
                    location = %location,
                    "SSTI detected (encoded)"
                );
                return Some(
                    crate::waf::attack_detection::config::AttackDetectionResult {
                        attack_type: AttackType::Ssti,
                        fingerprint: None,
                        matched_pattern: Some(matched),
                        input_location: location,
                    },
                );
            }
        }

        None
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
        self.detect_with_url_decode(input, location)
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
