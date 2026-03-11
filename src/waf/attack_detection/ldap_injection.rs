use aho_corasick::AhoCorasick;
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct LdapInjectionDetector {
    patterns: Arc<AhoCorasick>,
}

impl LdapInjectionDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let mut base_patterns: Vec<String> = DefaultPatterns::ldap_injection()
            .iter()
            .map(|s| s.to_string())
            .collect();

        if paranoia_level >= 3 {
            base_patterns.extend(
                DefaultPatterns::ldap_injection_high()
                    .iter()
                    .map(|s| s.to_string()),
            );
        }

        for pattern in custom_patterns {
            if !base_patterns.contains(pattern) {
                base_patterns.push(pattern.clone());
            }
        }

        let patterns_str: Vec<&str> = base_patterns.iter().map(|s| s.as_str()).collect();
        let patterns = Arc::new(AhoCorasick::new(&patterns_str).unwrap());

        Self { patterns }
    }

    pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        let input_lower = input.to_lowercase();

        if self.patterns.is_match(&input_lower) {
            if let Some(mat) = self.patterns.find(&input_lower) {
                let matched = input_lower[mat.start()..mat.end()].to_string();

                tracing::warn!(
                    attack_type = "ldap_injection",
                    matched_pattern = %matched,
                    location = %location,
                    "LDAP injection detected"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::LdapInjection,
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
        for (header_name, header_value) in headers.iter() {
            if let Ok(value) = header_value.to_str() {
                if let Some(result) =
                    self.detect(value, InputLocation::Header(header_name.to_string()))
                {
                    return Some(result);
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
    fn test_ldap_injection_basic() {
        let detector = LdapInjectionDetector::new(2, &[]);
        let input = "*)(&(objectClass=*";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ldap_injection_or() {
        let detector = LdapInjectionDetector::new(2, &[]);
        let input = "*(|(objectClass=*";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ldap_injection_admin() {
        let detector = LdapInjectionDetector::new(2, &[]);
        let input = "admin)(&(password=*";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ldap_injection_encoded() {
        let detector = LdapInjectionDetector::new(2, &[]);
        let input = "%29%28";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ldap_injection_benign() {
        let detector = LdapInjectionDetector::new(2, &[]);
        let input = "john.doe@example.com";
        assert!(detector.detect(input, InputLocation::QueryString).is_none());
    }

    #[test]
    fn test_ldap_injection_uid() {
        let detector = LdapInjectionDetector::new(2, &[]);
        let input = "(uid=admin)";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }

    #[test]
    fn test_ldap_injection_cn() {
        let detector = LdapInjectionDetector::new(2, &[]);
        let input = "(cn=admin)";
        assert!(detector.detect(input, InputLocation::QueryString).is_some());
    }
}
