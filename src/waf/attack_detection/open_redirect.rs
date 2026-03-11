use aho_corasick::AhoCorasick;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct OpenRedirectDetector {
    patterns: Arc<AhoCorasick>,
    redirect_param_patterns: Vec<&'static str>,
}

impl OpenRedirectDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let mut base_patterns: Vec<String> = DefaultPatterns::open_redirect()
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        if paranoia_level >= 3 {
            base_patterns.extend(
                DefaultPatterns::open_redirect_high()
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

        let redirect_param_patterns = vec![
            "redirect",
            "url",
            "link",
            "goto",
            "next",
            "dest",
            "destination",
            "callback",
            "return",
            "page",
            "ref",
            "reference",
            "site",
            "html",
            "val",
            "validate",
            "domain",
            "continue",
            "c",
            "path",
            "dir",
            "show",
            "view",
            "doc",
            "img_url",
            "source",
            "src",
            "target",
            "to",
            "out",
            "viewpage",
            "open",
            "file",
            "document",
            "folder",
            "pg",
            "style",
            "doc",
            "img_url",
            "return_path",
            "success_url",
            "error_url",
            "return_to",
            "return_url",
            "from_url",
            "redir_url",
            "redirect_uri",
            "redirect_url",
            "oauth_callback",
            "callback_url",
            "serve",
            "proxy",
            "bigimg",
            "url_link",
            "linkurl",
            "origin",
            "originUrl",
            "sourceUrl",
            "contentUrl",
            "shareUrl",
            "qpa",
            "query",
            "token",
            "email",
            "subject",
            "template",
            "func",
            "call",
            "mode",
            "name",
            "rest_url",
            "continue_url",
            "u",
            "urlfrom",
            "urlsrc",
        ];

        Self {
            patterns,
            redirect_param_patterns,
        }
    }

    fn is_redirect_param(&self, input: &str) -> bool {
        let input_lower = input.to_lowercase();
        for param in &self.redirect_param_patterns {
            if input_lower.contains(param) {
                return true;
            }
        }
        false
    }

    fn is_external_redirect(&self, input: &str) -> bool {
        let input_lower = input.to_lowercase();

        if input_lower.contains("javascript:")
            || input_lower.contains("vbscript:")
            || input_lower.contains("data:")
        {
            return true;
        }

        if input_lower.contains("//") || input_lower.contains("\\\\") || input_lower.contains("://")
        {
            return true;
        }

        let url_encoded_variants = [
            "%2f%2f",
            "%5c%5c",
            "%2f%2f%2f",
            "%5c%5c%5c",
            "%2e%2e",
            "..%2f",
            "..%5c",
            ".%2e",
            ".%5c",
        ];

        for variant in url_encoded_variants {
            if input_lower.contains(variant) {
                return true;
            }
        }

        false
    }

    pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        let input_lower = input.to_lowercase();

        if self.is_external_redirect(input) {
            if self.is_redirect_param(input) && self.patterns.is_match(&input_lower) {
                if let Some(mat) = self.patterns.find(&input_lower) {
                    let matched = input[mat.start()..mat.end()].to_string();

                    tracing::warn!(
                        attack_type = "open_redirect",
                        matched_pattern = %matched,
                        location = %location,
                        "Open redirect detected"
                    );

                    return Some(AttackDetectionResult {
                        attack_type: AttackType::OpenRedirect,
                        fingerprint: None,
                        matched_pattern: Some(matched),
                        input_location: location,
                    });
                }
            } else if input_lower.starts_with("javascript:")
                || input_lower.starts_with("vbscript:")
                || input_lower.starts_with("data:")
            {
                let matched = if let Some(mat) = self.patterns.find(&input_lower) {
                    input[mat.start()..mat.end()].to_string()
                } else {
                    input.chars().take(20).collect()
                };

                tracing::warn!(
                    attack_type = "open_redirect",
                    matched_pattern = %matched,
                    location = %location,
                    "Open redirect detected"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::OpenRedirect,
                    fingerprint: None,
                    matched_pattern: Some(matched),
                    input_location: location,
                });
            } else if input_lower.starts_with("//") || input_lower.starts_with("\\\\") {
                let matched = if let Some(mat) = self.patterns.find(&input_lower) {
                    input[mat.start()..mat.end()].to_string()
                } else {
                    input.chars().take(20).collect()
                };

                tracing::warn!(
                    attack_type = "open_redirect",
                    matched_pattern = %matched,
                    location = %location,
                    "Open redirect detected"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::OpenRedirect,
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
        _check_header: F,
    ) -> Option<AttackDetectionResult>
    where
        F: FnMut(&str) -> bool,
    {
        let redirect_headers = [
            "location",
            "refresh",
            "content-location",
            "x-redirect-to",
            "x-forwarded-url",
        ];

        for header_name in redirect_headers {
            if let Some(header_value) = headers.get(header_name) {
                if let Ok(value) = header_value.to_str() {
                    if self.is_external_redirect(value) {
                        if let Some(mat) = self.patterns.find(value) {
                            let matched = value[mat.start()..mat.end()].to_string();

                            tracing::warn!(
                                attack_type = "open_redirect",
                                matched_pattern = %matched,
                                location = %format!("header:{}", header_name),
                                "Open redirect detected in header"
                            );

                            return Some(AttackDetectionResult {
                                attack_type: AttackType::OpenRedirect,
                                fingerprint: None,
                                matched_pattern: Some(matched),
                                input_location: InputLocation::Header(header_name.to_string()),
                            });
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_redirect_double_slash() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "redirect=//evil.com";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_open_redirect_javascript() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "url=javascript:alert(1)";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_open_redirect_data() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "redirect=data:text/html,<script>alert(1)</script>";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_open_redirect_encoded() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "url=%2F%2Fgoogle.com";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_open_redirect_backslash() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "url=\\\\attacker.com";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_open_redirect_path_traversal() {
        let detector = OpenRedirectDetector::new(3, &[]);
        let input = "url=..%2F..%2Fevil.com";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_open_redirect_benign() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "/path/to/page";
        assert!(detector.detect(input, InputLocation::Path).is_none());
    }

    #[test]
    fn test_open_redirect_relative() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "/dashboard";
        assert!(detector.detect(input, InputLocation::Path).is_none());
    }

    #[test]
    fn test_open_redirect_location_header() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "//evil.com/path";
        assert!(detector
            .detect(input, InputLocation::Header("location".to_string()))
            .is_some());
    }

    #[test]
    fn test_open_redirect_case_insensitive() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "REDIRECT=//EVIL.COM";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_open_redirect_javascript_uppercase() {
        let detector = OpenRedirectDetector::new(2, &[]);
        let input = "URL=JAVASCRIPT:ALERT(1)";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }
}
