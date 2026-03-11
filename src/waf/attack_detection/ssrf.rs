use aho_corasick::AhoCorasick;
use regex::Regex;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct SsrfDetector {
    automaton: Arc<AhoCorasick>,
    private_ip_pattern: Regex,
    allowed_domains: Vec<String>,
}

impl SsrfDetector {
    pub fn new(
        paranoia_level: u8,
        custom_patterns: &[String],
        block_private_ips: bool,
        allowed_domains: Vec<String>,
    ) -> Self {
        let mut patterns: Vec<String> = if paranoia_level >= 3 {
            DefaultPatterns::ssrf_high()
                .iter()
                .map(|s| s.to_lowercase())
                .collect()
        } else {
            DefaultPatterns::ssrf()
                .iter()
                .map(|s| s.to_lowercase())
                .collect()
        };

        for custom in custom_patterns {
            patterns.push(custom.to_lowercase());
        }

        let ac = AhoCorasick::new(&patterns).expect("Failed to build Aho-Corasick automaton");

        let private_ip_pattern = if block_private_ips {
            Regex::new(r"(?:^|[/:])(?:(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3})|(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:169\.254\.\d{1,3}\.\d{1,3})|(?:::ffff:(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}))|(?:::ffff:(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}))|(?:::ffff:(?:192\.168\.\d{1,3}\.\d{1,3}))|(?:::ffff:(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}))|(?:::1)|(?:\.local))(?:[/:]|$)")
                .expect("Failed to compile private IP regex")
        } else {
            Regex::new(r"^(?!.)").expect("Empty regex that never matches")
        };

        Self {
            automaton: Arc::new(ac),
            private_ip_pattern,
            allowed_domains,
        }
    }

    pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        let input_lower = input.to_lowercase();
        let decoded = self::decode_all(&input_lower);

        if let Some(_mat) = self.automaton.find(&decoded) {
            tracing::warn!(
                attack_type = "ssrf",
                location = %location,
                input_preview = %&input[..input.len().min(100)],
                "SSRF attack detected"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::Ssrf,
                fingerprint: None,
                matched_pattern: Some("ssrf_pattern".to_string()),
                input_location: location,
            });
        }

        if self.private_ip_pattern.is_match(&decoded) {
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

fn decode_all(input: &str) -> String {
    let mut result = input.to_string();

    for _ in 0..3 {
        let decoded = urlencoding_decode(&result);
        if decoded == result {
            break;
        }
        result = decoded;
    }

    result
}

fn urlencoding_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    if byte.is_ascii() {
                        result.push(byte as char);
                        continue;
                    }
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
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
