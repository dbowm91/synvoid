use crate::attack_detection::config::{AttackType, InputLocation};
use crate::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::attack_detection::patterns::DefaultPatterns;
use aho_corasick::AhoCorasick;
use std::sync::Arc;
use synvoid_core::url::url_decode_all;

pub struct PathTraversalDetector {
    inner: BasePatternDetector,
}

impl PathTraversalDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::path_traversal().as_slice(),
            DefaultPatterns::path_traversal_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::PathTraversal,
            "path_traversal",
        );
        Self { inner }
    }

    fn detect_with_url_decode(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<crate::attack_detection::config::AttackDetectionResult> {
        let input_lower = input.to_lowercase();
        let decoded = if input_lower.contains('%') || input_lower.contains('+') {
            url_decode_all(&input_lower)
        } else {
            input_lower.clone()
        };

        if let Some(mat) = self.inner.patterns_ref().find(&decoded) {
            let matched = decoded[mat.start()..mat.end()].to_string();
            tracing::warn!(
                attack_type = "path_traversal",
                matched_pattern = %matched,
                location = %location,
                "Path traversal detected"
            );
            return Some(crate::attack_detection::config::AttackDetectionResult {
                attack_type: AttackType::PathTraversal,
                fingerprint: None,
                matched_pattern: Some(matched),
                input_location: location,
            });
        }

        if decoded != input_lower {
            if let Some(mat) = self.inner.patterns_ref().find(&input_lower) {
                let matched = input_lower[mat.start()..mat.end()].to_string();
                tracing::warn!(
                    attack_type = "path_traversal",
                    matched_pattern = %matched,
                    location = %location,
                    "Path traversal detected (encoded)"
                );
                return Some(crate::attack_detection::config::AttackDetectionResult {
                    attack_type: AttackType::PathTraversal,
                    fingerprint: None,
                    matched_pattern: Some(matched),
                    input_location: location,
                });
            }
        }

        None
    }
}

impl PatternDetector for PathTraversalDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<crate::attack_detection::config::AttackDetectionResult> {
        self.detect_with_url_decode(input, location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal_basic() {
        let detector = PathTraversalDetector::new(2, &[]);
        assert!(detector
            .detect("../../../etc/passwd", InputLocation::Path)
            .is_some());
    }

    #[test]
    fn test_path_traversal_encoded() {
        let detector = PathTraversalDetector::new(2, &[]);
        assert!(detector
            .detect("%2e%2e%2fetc%2fpasswd", InputLocation::Path)
            .is_some());
    }

    #[test]
    fn test_path_traversal_benign() {
        let detector = PathTraversalDetector::new(2, &[]);
        assert!(detector
            .detect("/api/users/123", InputLocation::Path)
            .is_none());
    }
}
