use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::normalizer::InputNormalizer;
use crate::waf::attack_detection::patterns::DefaultPatterns;
use aho_corasick::AhoCorasick;
use std::sync::Arc;

pub struct SqliDetector {
    inner: BasePatternDetector,
    normalizer: InputNormalizer,
}

impl SqliDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::sqli().as_slice(),
            DefaultPatterns::sqli_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::Sqli,
            "sqli",
        );
        Self {
            inner,
            normalizer: InputNormalizer::new(),
        }
    }

    pub fn detect(&self, input: &[u8], location: InputLocation) -> Option<AttackDetectionResult> {
        let input_str = std::str::from_utf8(input).unwrap_or("");
        let normalized = self.normalizer.normalize(input_str);

        // 1. Try pattern-based detection
        if let Some(mat) = self.inner.patterns_ref().find(&normalized.normalized) {
            let matched = normalized.normalized[mat.start()..mat.end()].to_string();
            tracing::warn!(
                attack_type = "sqli",
                matched_pattern = %matched,
                location = %location,
                "SQLi detected (pattern)"
            );
            return Some(AttackDetectionResult {
                attack_type: AttackType::Sqli,
                fingerprint: None,
                matched_pattern: Some(matched),
                input_location: location,
            });
        }

        // 2. Try libinjection detection
        let result = libinjectionrs::detect_sqli(normalized.as_bytes());

        if result.is_injection() {
            let fingerprint = result.fingerprint.map(|fp| fp.to_string());

            tracing::warn!(
                attack_type = "sqli",
                fingerprint = ?fingerprint,
                location = %location,
                "SQL injection detected (libinjection)"
            );

            Some(AttackDetectionResult {
                attack_type: AttackType::Sqli,
                fingerprint,
                matched_pattern: None,
                input_location: location,
            })
        } else {
            None
        }
    }
}

impl PatternDetector for SqliDetector {
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
    fn test_sqli_detection_basic() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"1' OR '1'='1";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_detection_union() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"1 UNION SELECT * FROM users";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_detection_benign() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"hello world";
        assert!(detector.detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_sqli_attack_type_field() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"1' OR '1'='1";
        let result = detector.detect(input, InputLocation::QueryString).unwrap();
        assert_eq!(result.attack_type, AttackType::Sqli);
    }

    #[test]
    fn test_sqli_union_select_all() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"1 UNION SELECT * FROM users";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_comment_bypass() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"1'/**/OR/**/1=1--";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_hex_encoded() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"0x27 OR 0x31=0x31";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_stacked_queries() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"1; DROP TABLE users--";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_input_location_preserved() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"1' OR '1'='1";
        let result = detector.detect(input, InputLocation::PostBody).unwrap();
        assert!(matches!(result.input_location, InputLocation::PostBody));
    }

    #[test]
    fn test_sqli_numeric_benign() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"42";
        assert!(detector.detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_sqli_boolean_based() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"1' AND 1=1--";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_sleep_based() {
        let detector = SqliDetector::new(2, &[]);
        let input = b"1' AND SLEEP(5)--";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_pattern_match() {
        let detector = SqliDetector::new(2, &["CUSTOM_SQLI_PATTERN".to_string()]);
        let input = b"SELECT * FROM users WHERE id = CUSTOM_SQLI_PATTERN";
        let result = detector.detect(input, InputLocation::QueryString).unwrap();
        assert_eq!(
            result.matched_pattern,
            Some("custom_sqli_pattern".to_string())
        );
    }
}
