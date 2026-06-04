use crate::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::attack_detection::detector_common::detect_in_headers;

pub struct LibInjectionDetector {
    attack_type: AttackType,
    attack_name: &'static str,
}

impl LibInjectionDetector {
    pub fn new(attack_type: AttackType, attack_name: &'static str) -> Self {
        Self {
            attack_type,
            attack_name,
        }
    }

    pub fn detect(&self, input: &[u8], location: InputLocation) -> Option<AttackDetectionResult> {
        match self.attack_type {
            AttackType::Sqli => self.detect_sqli(input, location),
            AttackType::Xss => self.detect_xss(input, location),
            _ => None,
        }
    }

    fn detect_sqli(&self, input: &[u8], location: InputLocation) -> Option<AttackDetectionResult> {
        let result = libinjectionrs::detect_sqli(input);

        if result.is_injection() {
            let fingerprint = result.fingerprint.map(|fp| fp.to_string());

            tracing::warn!(
                attack_type = self.attack_name,
                fingerprint = ?fingerprint,
                location = %location,
                "{} detected",
                self.attack_name
            );

            Some(AttackDetectionResult {
                attack_type: self.attack_type,
                fingerprint,
                matched_pattern: None,
                input_location: location,
            })
        } else {
            None
        }
    }

    fn detect_xss(&self, input: &[u8], location: InputLocation) -> Option<AttackDetectionResult> {
        let result = libinjectionrs::detect_xss(input);

        if result.is_injection() {
            tracing::warn!(
                attack_type = self.attack_name,
                location = %location,
                "{} detected",
                self.attack_name
            );

            Some(AttackDetectionResult {
                attack_type: self.attack_type,
                fingerprint: None,
                matched_pattern: None,
                input_location: location,
            })
        } else {
            None
        }
    }

    pub fn detect_in_headers<F>(
        &self,
        headers: &http::HeaderMap,
        check_header: F,
        normalizer: Option<&crate::attack_detection::normalizer::InputNormalizer>,
    ) -> Option<AttackDetectionResult>
    where
        F: FnMut(&str) -> bool,
    {
        detect_in_headers(headers, check_header, normalizer, |input, location| {
            self.detect(input, location)
        })
    }
}
