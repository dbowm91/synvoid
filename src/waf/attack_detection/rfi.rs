use aho_corasick::AhoCorasick;
use regex::Regex;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct RfiDetector {
    automaton: Arc<AhoCorasick>,
    ip_pattern: Regex,
}

impl RfiDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let mut patterns: Vec<String> = if paranoia_level >= 3 {
            DefaultPatterns::rfi_high()
                .iter()
                .map(|s| s.to_lowercase())
                .collect()
        } else {
            DefaultPatterns::rfi()
                .iter()
                .map(|s| s.to_lowercase())
                .collect()
        };

        for custom in custom_patterns {
            patterns.push(custom.to_lowercase());
        }

        let ac = AhoCorasick::new(&patterns).expect("Failed to build Aho-Corasick automaton");

        let ip_pattern = Regex::new(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
            .expect("Failed to compile IP regex");

        Self {
            automaton: Arc::new(ac),
            ip_pattern,
        }
    }

    pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        let input_lower = input.to_lowercase();
        let decoded = self::decode_all(&input_lower);

        if let Some(_mat) = self.automaton.find(&decoded) {
            tracing::warn!(
                attack_type = "rfi",
                location = %location,
                input_preview = %&input[..input.len().min(100)],
                "RFI attack detected"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::Rfi,
                fingerprint: None,
                matched_pattern: Some("rfi_pattern".to_string()),
                input_location: location,
            });
        }

        if self.ip_pattern.is_match(&decoded) {
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
}
