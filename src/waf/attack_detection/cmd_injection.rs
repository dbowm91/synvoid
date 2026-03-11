use aho_corasick::AhoCorasick;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct CmdInjectionDetector {
    patterns: Arc<AhoCorasick>,
}

impl CmdInjectionDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let mut base_patterns: Vec<String> = DefaultPatterns::cmd_injection()
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        if paranoia_level >= 3 {
            base_patterns.extend(
                DefaultPatterns::cmd_injection_high()
                    .iter()
                    .map(|s| s.to_lowercase()),
            );
        }

        for pattern in custom_patterns {
            let pattern_lower = pattern.to_lowercase();
            if !base_patterns.contains(&pattern_lower) {
                base_patterns.push(pattern_lower);
            }
        }

        let patterns_str: Vec<&str> = base_patterns.iter().map(|s| s.as_str()).collect();
        let patterns = Arc::new(AhoCorasick::new(&patterns_str).unwrap());

        Self { patterns }
    }

    pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        let normalized = normalize_input(input);

        if self.patterns.is_match(&normalized) {
            if let Some(mat) = self.patterns.find(&normalized) {
                let matched = normalized[mat.start()..mat.end()].to_string();

                tracing::warn!(
                    attack_type = "cmd_injection",
                    matched_pattern = %matched,
                    location = %location,
                    "Command injection detected"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::CmdInjection,
                    fingerprint: None,
                    matched_pattern: Some(matched),
                    input_location: location,
                });
            }
        }

        None
    }

    pub fn detect_in_headers<F>(
        &self,
        headers: &http::HeaderMap,
        mut check_header: F,
    ) -> Option<AttackDetectionResult>
    where
        F: FnMut(&str) -> bool,
    {
        let headers_to_check = DefaultPatterns::headers_to_check();

        for header_name in headers_to_check {
            if let Some(value) = headers.get(*header_name) {
                if !check_header(*header_name) {
                    continue;
                }

                if let Ok(value_str) = value.to_str() {
                    let location = InputLocation::Header(header_name.to_string());

                    if let Some(result) = self.detect(value_str, location.clone()) {
                        return Some(result);
                    }
                }
            }
        }

        None
    }
}

fn normalize_input(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push('%');
                result.push_str(&hex);
            }
            '+' => result.push(' '),
            '\u{0000}' => {}
            '\t' | '\n' | '\r' => result.push(' '),
            c => result.push(c.to_ascii_lowercase()),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_injection_semicolon() {
        let detector = CmdInjectionDetector::new(2, &[]);
        let input = "; cat /etc/passwd";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_cmd_injection_pipe() {
        let detector = CmdInjectionDetector::new(2, &[]);
        let input = "| id";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_cmd_injection_backticks() {
        let detector = CmdInjectionDetector::new(2, &[]);
        let input = "`whoami`";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_cmd_injection_windows() {
        let detector = CmdInjectionDetector::new(2, &[]);
        let input = "& dir";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_cmd_injection_benign() {
        let detector = CmdInjectionDetector::new(2, &[]);
        let input = "Hello world";
        assert!(detector.detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_cmd_injection_case_insensitive() {
        let detector = CmdInjectionDetector::new(2, &[]);
        let input = "; CAT /ETC/PASSWD";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_cmd_injection_mixed_case() {
        let detector = CmdInjectionDetector::new(2, &[]);
        let input = "| WhOaMi";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }
}
