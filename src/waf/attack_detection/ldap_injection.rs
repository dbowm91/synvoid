use crate::waf::attack_detection::config::{AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct LdapInjectionDetector {
    inner: BasePatternDetector,
}

impl LdapInjectionDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::ldap_injection().as_slice(),
            DefaultPatterns::ldap_injection_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::LdapInjection,
            "ldap_injection",
        );
        Self { inner }
    }

    pub fn detect(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<crate::waf::attack_detection::config::AttackDetectionResult> {
        self.inner.detect(input, location)
    }
}

impl PatternDetector for LdapInjectionDetector {
    fn patterns(&self) -> &std::sync::Arc<aho_corasick::AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<crate::waf::attack_detection::config::AttackDetectionResult> {
        self.inner.detect(input, location)
    }

    fn detect_in_headers<F>(
        &self,
        headers: &http::HeaderMap,
        _check_header: F,
        normalizer: Option<&crate::waf::attack_detection::normalizer::InputNormalizer>,
    ) -> Option<crate::waf::attack_detection::config::AttackDetectionResult>
    where
        F: FnMut(&str) -> bool,
    {
        self.inner.detect_in_all_headers(headers, normalizer)
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
