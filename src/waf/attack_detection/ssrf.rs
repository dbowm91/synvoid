use aho_corasick::AhoCorasick;
use std::net::IpAddr;
use std::sync::Arc;

use crate::utils::url_decode_all;
use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::patterns::DefaultPatterns;

#[allow(dead_code)]
pub struct SsrfDetector {
    inner: BasePatternDetector,
    block_private_ips: bool,
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
        Self {
            inner,
            block_private_ips,
            allowed_domains,
        }
    }

    fn is_private_ip(ip: &str) -> bool {
        ip.parse::<IpAddr>().map_or(false, |addr| match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && (octets[1] & 0xF0) == 16)
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 169 && octets[1] == 254)
                    || octets[0] == 127
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                segments[0] == 0xFE80
                    || (segments[0] & 0xFE80) == 0xFC00
                    || segments[0] == 0xFF00
                    || segments == [0, 0, 0, 0, 0, 0, 0, 1]
            }
        })
    }

    fn extract_ips_from_url(input: &str) -> Vec<String> {
        let mut ips = Vec::new();
        let input_lower = input.to_lowercase();

        let mut in_url = false;
        let mut url_start = 0;
        let mut current = 0;
        let bytes = input_lower.as_bytes();

        while current < bytes.len() {
            if current + 4 < bytes.len()
                && bytes[current] == b'h'
                && bytes[current + 1] == b't'
                && bytes[current + 2] == b't'
                && bytes[current + 3] == b'p'
            {
                in_url = true;
                url_start = current;
                current += 4;
                if current < bytes.len() && bytes[current] == b's' {
                    current += 1;
                }
                continue;
            }

            if in_url
                && (bytes[current] == b' '
                    || bytes[current] == b'\n'
                    || bytes[current] == b'\r'
                    || bytes[current] == b'\''
                    || bytes[current] == b'"'
                    || bytes[current] == b'&'
                    || bytes[current] == b';')
            {
                in_url = false;
            }

            if in_url
                && bytes[current] == b'/'
                && current + 1 < bytes.len()
                && bytes[current + 1] == b'/'
            {
                url_start = current + 2;
            }

            if in_url && (bytes[current] == b':' || current == url_start) {
                let start = if bytes[current] == b':' && current > url_start {
                    current + 1
                } else {
                    current
                };
                let remaining = &input_lower[start..];

                if let Some(slash_pos) = remaining.find('/') {
                    let potential_ip = &remaining[..slash_pos];
                    if Self::looks_like_ip(potential_ip) {
                        ips.push(potential_ip.to_string());
                    }
                } else {
                    if Self::looks_like_ip(remaining) {
                        ips.push(remaining.to_string());
                    }
                }
            }

            current += 1;
        }

        ips
    }

    fn looks_like_ip(s: &str) -> bool {
        let s = s.trim_end_matches(|c| c == ']' || c == ':' || c == '/');
        s.chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == ':')
            && s.contains('.')
    }

    fn contains_private_ip_or_localhost(input: &str) -> bool {
        let input_lower = input.to_lowercase();

        if input_lower.contains("localhost") || input_lower.contains(".local") {
            return true;
        }

        for ip in Self::extract_ips_from_url(&input_lower) {
            if Self::is_private_ip(&ip) {
                return true;
            }
        }

        false
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

        if self.block_private_ips && Self::contains_private_ip_or_localhost(&decoded) {
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

    #[test]
    fn test_ssrf_10_network() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect("http://10.0.0.1/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_172_network() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect("http://172.16.0.1/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_localdomain() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect("http://server.local/internal", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_ipv6_localhost() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect("http://[::1]:8080/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_url_encoded() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect("http%3A%2F%2Flocalhost%2Fadmin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_no_block() {
        let detector = SsrfDetector::new(2, &[], false, vec![]);
        assert!(detector
            .detect("http://192.168.1.1/secret", InputLocation::QueryString)
            .is_none());
    }

    #[test]
    fn test_ssrf_127_loopback() {
        let detector = SsrfDetector::new(2, &[], true, vec![]);
        assert!(detector
            .detect("http://127.0.0.1:8080/admin", InputLocation::QueryString)
            .is_some());
    }
}
