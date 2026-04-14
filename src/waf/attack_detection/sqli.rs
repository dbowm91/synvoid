use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::detect_in_headers;
use crate::waf::attack_detection::normalizer::InputNormalizer;

pub struct SqliDetector;

impl SqliDetector {
    pub fn detect(
        input: &[u8],
        location: InputLocation,
        normalizer: Option<&InputNormalizer>,
    ) -> Option<AttackDetectionResult> {
        let normalized = if let Some(n) = normalizer {
            n.normalize(std::str::from_utf8(input).unwrap_or(""))
        } else {
            InputNormalizer::new().normalize(std::str::from_utf8(input).unwrap_or(""))
        };
        let result = libinjectionrs::detect_sqli(normalized.as_bytes());

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
        let normalizer = normalizer.cloned();
        detect_in_headers(
            headers,
            check_header,
            normalizer.as_ref(),
            |input, location| Self::detect(input, location, normalizer.as_ref()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_detection_basic() {
        let input = b"1' OR '1'='1";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_some());
    }

    #[test]
    fn test_sqli_detection_union() {
        let input = b"1 UNION SELECT * FROM users";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_some());
    }

    #[test]
    fn test_sqli_detection_benign() {
        let input = b"hello world";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_none());
    }

    #[test]
    fn test_sqli_attack_type_field() {
        let input = b"1' OR '1'='1";
        let result = SqliDetector::detect(input, InputLocation::QueryString, None).unwrap();
        assert_eq!(result.attack_type, AttackType::Sqli);
    }

    #[test]
    fn test_sqli_union_select_all() {
        let input = b"1 UNION SELECT * FROM users";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_some());
    }

    #[test]
    fn test_sqli_comment_bypass() {
        let input = b"1'/**/OR/**/1=1--";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_some());
    }

    #[test]
    fn test_sqli_hex_encoded() {
        let input = b"0x27 OR 0x31=0x31";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_some());
    }

    #[test]
    fn test_sqli_stacked_queries() {
        let input = b"1; DROP TABLE users--";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_some());
    }

    #[test]
    fn test_sqli_input_location_preserved() {
        let input = b"1' OR '1'='1";
        let result = SqliDetector::detect(input, InputLocation::PostBody, None).unwrap();
        assert!(matches!(result.input_location, InputLocation::PostBody));
    }

    #[test]
    fn test_sqli_numeric_benign() {
        let input = b"42";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_none());
    }

    #[test]
    fn test_sqli_boolean_based() {
        let input = b"1' AND 1=1--";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_some());
    }

    #[test]
    fn test_sqli_sleep_based() {
        let input = b"1' AND SLEEP(5)--";
        assert!(SqliDetector::detect(input, InputLocation::QueryString, None).is_some());
    }
}
