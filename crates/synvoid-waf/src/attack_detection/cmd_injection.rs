use crate::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::attack_detection::patterns::DefaultPatterns;
use aho_corasick::AhoCorasick;
use std::sync::Arc;

pub struct CmdInjectionDetector {
    inner: BasePatternDetector,
}

impl CmdInjectionDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::cmd_injection().as_slice(),
            DefaultPatterns::cmd_injection_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::CmdInjection,
            "cmd_injection",
        );
        Self { inner }
    }

    fn detect_with_normalization(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        let normalized = normalize_input(input);

        if let Some(mat) = self.inner.patterns_ref().find(&normalized) {
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

        None
    }
}

impl PatternDetector for CmdInjectionDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        self.detect_with_normalization(input, location)
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
