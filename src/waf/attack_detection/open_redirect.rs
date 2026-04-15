use crate::utils::url_decode_all;
use aho_corasick::AhoCorasick;
use std::borrow::Cow;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct OpenRedirectDetector {
    inner: BasePatternDetector,
    redirect_param_patterns: Vec<&'static str>,
}

impl OpenRedirectDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::open_redirect().as_slice(),
            DefaultPatterns::open_redirect_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::OpenRedirect,
            "open_redirect",
        );

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
            inner,
            redirect_param_patterns,
        }
    }

    fn is_redirect_param(&self, input_lower: &str) -> bool {
        self.redirect_param_patterns
            .iter()
            .any(|param| input_lower.contains(param))
    }

    fn is_external_redirect(&self, input_lower: &str) -> bool {
        if input_lower.contains('\n') || input_lower.contains('\r') {
            return true;
        }

        if input_lower.contains("javascript:")
            || input_lower.contains("vbscript:")
            || input_lower.contains("data:")
        {
            return true;
        }

        if let Some(scheme_end) = input_lower.find(':') {
            let scheme = &input_lower[..scheme_end];
            if !scheme.bytes().all(|b| b.is_ascii_lowercase()) {
                return true;
            }
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

        url_encoded_variants
            .iter()
            .any(|variant| input_lower.contains(variant))
    }

    fn detect_internal(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        let decoded = if input.contains('%') || input.contains('+') {
            url_decode_all(input)
        } else {
            input.to_string()
        };
        let decoded_lower: Cow<str> = if decoded.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(decoded.to_lowercase())
        } else {
            Cow::Borrowed(&decoded)
        };

        if !self.is_external_redirect(decoded_lower.as_ref()) {
            if decoded != input {
                return self.detect_internal(&decoded, location);
            }
            return None;
        }

        let is_redirect_param = self.is_redirect_param(decoded_lower.as_ref());

        if let Some(mat) = self.inner.patterns_ref().find(decoded_lower.as_ref()) {
            let matched = decoded_lower[mat.start()..mat.end()].to_string();
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

        if decoded != input && is_redirect_param {
            if let Some(mat) = self.inner.patterns_ref().find(decoded_lower.as_ref()) {
                let matched = decoded_lower[mat.start()..mat.end()].to_string();
                tracing::warn!(
                    attack_type = "open_redirect",
                    matched_pattern = %matched,
                    location = %location,
                    "Open redirect detected (encoded)"
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
}

impl PatternDetector for OpenRedirectDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        self.detect_internal(input, location)
    }

    fn detect_in_headers<F>(
        &self,
        headers: &http::HeaderMap,
        _check_header: F,
        _normalizer: Option<&crate::waf::attack_detection::normalizer::InputNormalizer>,
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
                    let value_lower: Cow<str> = if value.bytes().any(|b| b.is_ascii_uppercase()) {
                        Cow::Owned(value.to_lowercase())
                    } else {
                        Cow::Borrowed(value)
                    };

                    if self.is_external_redirect(&value_lower) {
                        if let Some(mat) = self.inner.patterns_ref().find(value_lower.as_ref()) {
                            let matched = value_lower[mat.start()..mat.end()].to_string();
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
                                input_location: InputLocation::Header(header_name.into()),
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
            .detect(input, InputLocation::Header("location".into()))
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
