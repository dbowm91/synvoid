//! Compatibility facade for the canonical attack detector implementation.

pub use synvoid_waf::attack_detection::normalizer;
pub use synvoid_waf::attack_detection::*;

#[cfg(test)]
mod tests {
    use super::{AttackDetectionConfig, AttackDetector};
    use http::{HeaderMap, Method};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn root_waf_detector_uses_overlong_utf8_normalization() {
        let detector = AttackDetector::new(AttackDetectionConfig::default());
        let (result, _) = detector
            .check_request(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                &Method::GET,
                "/",
                Some("q=%C0%BCscript%C0%BE"),
                &HeaderMap::new(),
                None,
            )
            .await;

        assert!(result.is_some(), "overlong encoded XSS must be detected");
    }
}
