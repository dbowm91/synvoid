use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;

use crate::utils::url_decode_all;
use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::patterns::DefaultPatterns;

static PRIVATE_IP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:^|[/:])(?:(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3})|(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:169\.254\.\d{1,3}\.\d{1,3})|(?:::ffff:(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}))|(?:::ffff:(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}))|(?:::ffff:(?:192\.168\.\d{1,3}\.\d{1,3}))|(?:::ffff:(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}))|(?:::1)|(?:\.local)|(?:0\.0\.0\.0)|(?:localhost)|(?:\[::1\])|(?:\[[:]?:?1\])|(?:\[::ffff:127\.0\.0\.1\])|(?:\[::ffff:0:127\.0\.0\.1\])|(?:\[fc00:/:7\])|(?:\[fd00:/:8\])|(?:\[fe80:/10\])|(?:\b0\b)|(?:\blocalhost\b))(?:[/:]|$)").unwrap()
});

pub struct SsrfDetector {
    inner: BasePatternDetector,
    private_ip_pattern: Option<&'static Regex>,
    allowed_domains: Vec<String>,
}

impl SsrfDetector {
    pub fn new(
        paranoia_level: u8,
        custom_patterns: &[String],
        block_private_ips: bool,
        allowed_domains: Vec<String>,
    ) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::ssrf().as_slice(),
            DefaultPatterns::ssrf_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::Ssrf,
            "ssrf",
        );
        let private_ip_pattern = if block_private_ips {
            Some(&*PRIVATE_IP_REGEX)
        } else {
            None
        };
        Self {
            inner,
            private_ip_pattern,
            allowed_domains,
        }
    }

    fn detect_with_url_decode(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        let input_lower = input.to_lowercase();
        let decoded = url_decode_all(&input_lower);

        if let Some(mat) = self.inner.patterns_ref().find(&decoded) {
            let matched = decoded[mat.start()..mat.end()].to_string();
            tracing::warn!(
                attack_type = "ssrf",
                matched_pattern = %matched,
                location = %location,
                "SSRF attack detected"
            );
            return Some(AttackDetectionResult {
                attack_type: AttackType::Ssrf,
                fingerprint: None,
                matched_pattern: Some(matched),
                input_location: location,
            });
        }

        if let Some(pattern) = self.private_ip_pattern {
            if pattern.is_match(&decoded) {
                tracing::warn!(
                    attack_type = "ssrf",
                    location = %location,
                    "SSRF with private IP detected"
                );
                return Some(AttackDetectionResult {
                    attack_type: AttackType::Ssrf,
                    fingerprint: None,
                    matched_pattern: Some("private_ip".to_string()),
                    input_location: location,
                });
            }
        }

        None
    }
}

impl PatternDetector for SsrfDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        self.detect_with_url_decode(input, location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_localhost() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect("http://localhost/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_metadata() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect(
                "http://169.254.169.254/latest/meta-data",
                InputLocation::QueryString
            )
            .is_some());
    }

    #[test]
    fn test_ssrf_private_ip() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect("http://192.168.1.1/secret", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_benign() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect("https://api.example.com/data", InputLocation::QueryString)
            .is_none());
    }
}
