use aho_corasick::AhoCorasick;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct SstiDetector {
    patterns: Arc<AhoCorasick>,
    high_patterns: Arc<AhoCorasick>,
}

impl SstiDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let mut base_patterns: Vec<String> = DefaultPatterns::ssti()
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        if paranoia_level >= 3 {
            base_patterns.extend(
                DefaultPatterns::ssti_high()
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

        let high_patterns_str: Vec<String> = DefaultPatterns::ssti_high()
            .iter()
            .map(|s| s.to_lowercase())
            .collect();
        let high_patterns_str_ref: Vec<&str> =
            high_patterns_str.iter().map(|s| s.as_str()).collect();
        let high_patterns = Arc::new(AhoCorasick::new(&high_patterns_str_ref).unwrap());

        Self {
            patterns,
            high_patterns,
        }
    }

    pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        let normalized = input.to_lowercase();

        if self.patterns.is_match(&normalized) {
            if let Some(mat) = self.patterns.find(&normalized) {
                let matched = input[mat.start()..mat.end()].to_string();

                tracing::warn!(
                    attack_type = "ssti",
                    matched_pattern = %matched,
                    location = %location,
                    "Server-Side Template Injection detected"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::Ssti,
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

                    if let Ok(decoded) = urlencoding_decode(value_str) {
                        if decoded != value_str {
                            if let Some(result) = self.detect(&decoded, location) {
                                return Some(result);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

fn urlencoding_decode(input: &str) -> Result<String, ()> {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
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

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssti_jinja2() {
        let detector = SstiDetector::new(2, &[]);
        let input = "{{config.items()}}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ssti_twig() {
        let detector = SstiDetector::new(2, &[]);
        let input = "{{_self.env.display(\"id\")}}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ssti_freemarker() {
        let detector = SstiDetector::new(2, &[]);
        let input = "${\"freemarker.template.utility.Execute\"?new()(\"id\")}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ssti_benign() {
        let detector = SstiDetector::new(2, &[]);
        let input = "Hello username"; // completely benign, no template syntax
        assert!(detector.detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_ssti_case_insensitive() {
        let detector = SstiDetector::new(2, &[]);
        let input = "{{CONFIG.ITEMS()}}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ssti_mixed_case() {
        let detector = SstiDetector::new(2, &[]);
        let input = "${\"Freemarker.Template.Utility.Execute\"?new()(\"id\")}";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }
}
