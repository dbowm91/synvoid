use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::detect_in_headers;

pub struct SqliDetector;

impl SqliDetector {
    pub fn detect(input: &[u8], location: InputLocation) -> Option<AttackDetectionResult> {
        let result = libinjectionrs::detect_sqli(input);

        if result.is_injection() {
            let fingerprint = result.fingerprint.map(|fp| fp.to_string());

            tracing::warn!(
                attack_type = "sqli",
                fingerprint = ?fingerprint,
                location = %location,
                "SQL injection detected"
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
    fn test_sqli_detection_basic() {
        let input = b"1' OR '1'='1";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_detection_union() {
        let input = b"1 UNION SELECT * FROM users";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_detection_benign() {
        let input = b"hello world";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_sqli_attack_type_field() {
        let input = b"1' OR '1'='1";
        let result = SqliDetector::detect(input, InputLocation::QueryString).unwrap();
        assert_eq!(result.attack_type, AttackType::Sqli);
    }

    #[test]
    fn test_sqli_union_select_all() {
        let input = b"1 UNION SELECT * FROM users";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_comment_bypass() {
        let input = b"1'/**/OR/**/1=1--";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_hex_encoded() {
        let input = b"0x27 OR 0x31=0x31";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_stacked_queries() {
        let input = b"1; DROP TABLE users--";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_input_location_preserved() {
        let input = b"1' OR '1'='1";
        let result = SqliDetector::detect(input, InputLocation::PostBody).unwrap();
        assert!(matches!(result.input_location, InputLocation::PostBody));
    }

    #[test]
    fn test_sqli_numeric_benign() {
        let input = b"42";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_sqli_boolean_based() {
        let input = b"1' AND 1=1--";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_sqli_sleep_based() {
        let input = b"1' AND SLEEP(5)--";
        assert!(SqliDetector::detect(input, InputLocation::QueryString).is_some());
    }
}
