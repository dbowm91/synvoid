use aho_corasick::AhoCorasick;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct PathTraversalDetector {
    automaton: Arc<AhoCorasick>,
}

impl PathTraversalDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let mut patterns: Vec<String> = if paranoia_level >= 3 {
            DefaultPatterns::path_traversal_high()
                .iter()
                .map(|s| s.to_lowercase())
                .collect()
        } else {
            DefaultPatterns::path_traversal()
                .iter()
                .map(|s| s.to_lowercase())
                .collect()
        };

        for custom in custom_patterns {
            patterns.push(custom.to_lowercase());
        }

        let ac = AhoCorasick::new(&patterns).expect("Failed to build Aho-Corasick automaton");

        Self {
            automaton: Arc::new(ac),
        }
    }

    pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        let input_lower = input.to_lowercase();
        let decoded = self::decode_all(&input_lower);

        if let Some(_mat) = self.automaton.find(&decoded) {
            tracing::warn!(
                attack_type = "path_traversal",
                location = %location,
                input_preview = %&input[..input.len().min(100)],
                "Path traversal detected"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::PathTraversal,
                fingerprint: None,
                matched_pattern: Some("path_traversal_pattern".to_string()),
                input_location: location,
            });
        }

        if decoded != input_lower {
            if let Some(_mat) = self.automaton.find(&input_lower) {
                tracing::warn!(
                    attack_type = "path_traversal",
                    location = %location,
                    "Path traversal detected (encoded)"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::PathTraversal,
                    fingerprint: None,
                    matched_pattern: Some("path_traversal_pattern".to_string()),
                    input_location: location,
                });
            }
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
    fn test_path_traversal_basic() {
        let detector = PathTraversalDetector::new(2, &[]);
        assert!(detector
            .detect("../../../etc/passwd", InputLocation::Path)
            .is_some());
    }

    #[test]
    fn test_path_traversal_encoded() {
        let detector = PathTraversalDetector::new(2, &[]);
        assert!(detector
            .detect("%2e%2e%2fetc%2fpasswd", InputLocation::Path)
            .is_some());
    }

    #[test]
    fn test_path_traversal_benign() {
        let detector = PathTraversalDetector::new(2, &[]);
        assert!(detector
            .detect("/api/users/123", InputLocation::Path)
            .is_none());
    }
}
