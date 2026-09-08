//! Detector-result to enforcement-candidate adapters.
//!
//! Domain detector results stay rich (they carry evidence); these `From`
//! implementations project each outcome onto the canonical contract
//! (`synvoid_core::enforcement`) at the composition boundary. `None` means
//! the detector makes no claim (allow by default policy) so the common allow
//! path allocates nothing.
//!
//! Every mapping is exhaustive over its source enum: adding a variant to a
//! detector result without updating the mapping is a compile error.

use synvoid_core::enforcement::{
    EnforcementCandidate, EnforcementClass, EnforcementReason, EnforcementSource,
};

use crate::attack_detection::AttackDetectionResult;
use crate::bot::BotDetectionResult;
use crate::endpoints::EndpointCheckResult;
use crate::flood::FloodDecision;

/// Map a flood-protector outcome to a candidate.
///
/// Preserves the historical `check_request_full` rendering:
/// `RateLimited` -> 429 block, `Blackholed` -> silent drop.
pub fn flood_candidate(decision: FloodDecision) -> Option<EnforcementCandidate> {
    match decision {
        FloodDecision::Allowed => None,
        FloodDecision::RateLimited => Some(EnforcementCandidate::new(
            EnforcementClass::Block,
            EnforcementSource::FloodProtection,
            EnforcementReason::FloodRateLimited,
        )),
        FloodDecision::Blackholed => Some(EnforcementCandidate::new(
            EnforcementClass::Drop,
            EnforcementSource::FloodProtection,
            EnforcementReason::FloodBlackholed,
        )),
    }
}

/// Map a bot-detector outcome to a candidate.
///
/// Preserves the historical rendering: `Blocked` -> 403 block,
/// `Tarpit` -> tarpit session.
pub fn bot_candidate(result: &BotDetectionResult) -> Option<EnforcementCandidate> {
    match result {
        BotDetectionResult::Allowed { .. } => None,
        BotDetectionResult::Blocked { .. } => Some(EnforcementCandidate::new(
            EnforcementClass::Block,
            EnforcementSource::BotPolicy,
            EnforcementReason::BotBlocked,
        )),
        BotDetectionResult::Tarpit { .. } => Some(EnforcementCandidate::new(
            EnforcementClass::Tarpit,
            EnforcementSource::BotPolicy,
            EnforcementReason::ScraperTarpitted,
        )),
    }
}

/// Map an endpoint-policy outcome to a candidate.
pub fn endpoint_candidate(result: &EndpointCheckResult) -> Option<EnforcementCandidate> {
    match result {
        EndpointCheckResult::Allowed => None,
        EndpointCheckResult::Blocked { .. } => Some(EnforcementCandidate::new(
            EnforcementClass::Block,
            EnforcementSource::EndpointPolicy,
            EnforcementReason::EndpointBlocked,
        )),
    }
}

/// Map a detected attack to a candidate.
///
/// The attack engine only produces denials; every `Some` detection maps to a
/// 403-class block. Diagnostic detail (attack type, input location) stays in
/// tracing, never in metric labels.
pub fn attack_candidate(result: &AttackDetectionResult) -> EnforcementCandidate {
    let _ = result;
    EnforcementCandidate::new(
        EnforcementClass::Block,
        EnforcementSource::AttackDetection,
        EnforcementReason::AttackDetected,
    )
}

/// Map a core streaming body-scan outcome to a candidate.
pub fn streaming_candidate(
    decision: &synvoid_core::streaming_waf::StreamingWafDecision,
) -> Option<EnforcementCandidate> {
    match decision {
        synvoid_core::streaming_waf::StreamingWafDecision::Continue => None,
        synvoid_core::streaming_waf::StreamingWafDecision::Block(..) => {
            Some(EnforcementCandidate::new(
                EnforcementClass::Block,
                EnforcementSource::StreamingBodyScan,
                EnforcementReason::BodyBlocked,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flood_mapping_is_exhaustive_and_stable() {
        assert_eq!(flood_candidate(FloodDecision::Allowed), None);
        assert_eq!(
            flood_candidate(FloodDecision::RateLimited),
            Some(EnforcementCandidate::new(
                EnforcementClass::Block,
                EnforcementSource::FloodProtection,
                EnforcementReason::FloodRateLimited,
            ))
        );
        assert_eq!(
            flood_candidate(FloodDecision::Blackholed),
            Some(EnforcementCandidate::new(
                EnforcementClass::Drop,
                EnforcementSource::FloodProtection,
                EnforcementReason::FloodBlackholed,
            ))
        );
    }

    #[test]
    fn bot_mapping_preserves_block_and_tarpit() {
        assert_eq!(
            bot_candidate(&BotDetectionResult::Allowed {
                reason: "legitimate".to_string()
            }),
            None
        );
        let blocked = bot_candidate(&BotDetectionResult::Blocked {
            reason: "detected_as_bot".to_string(),
            bot_type: "isbot".to_string(),
        })
        .expect("blocked bot must claim");
        assert_eq!(blocked.class, EnforcementClass::Block);
        assert_eq!(blocked.source, EnforcementSource::BotPolicy);
        let tarpitted = bot_candidate(&BotDetectionResult::Tarpit {
            reason: "scraper_detected".to_string(),
            bot_type: "scraper".to_string(),
        })
        .expect("tarpitted scraper must claim");
        assert_eq!(tarpitted.class, EnforcementClass::Tarpit);
        assert_eq!(tarpitted.reason, EnforcementReason::ScraperTarpitted);
    }

    #[test]
    fn endpoint_mapping_preserves_block() {
        assert_eq!(endpoint_candidate(&EndpointCheckResult::Allowed), None);
        let blocked = endpoint_candidate(&EndpointCheckResult::Blocked {
            response_code: 403,
            html: None,
            matched_pattern: Some("/admin".to_string()),
        })
        .expect("blocked endpoint must claim");
        assert_eq!(blocked.class, EnforcementClass::Block);
        assert_eq!(blocked.source, EnforcementSource::EndpointPolicy);
        assert_eq!(blocked.reason, EnforcementReason::EndpointBlocked);
    }

    #[test]
    fn streaming_mapping_preserves_block() {
        use synvoid_core::streaming_waf::StreamingWafDecision as CoreDecision;
        assert_eq!(streaming_candidate(&CoreDecision::Continue), None);
        let blocked = streaming_candidate(&CoreDecision::Block(403, "xss".to_string()))
            .expect("blocked chunk must claim");
        assert_eq!(blocked.class, EnforcementClass::Block);
        assert_eq!(blocked.source, EnforcementSource::StreamingBodyScan);
        assert_eq!(blocked.reason, EnforcementReason::BodyBlocked);
    }

    #[test]
    fn waf_decision_class_mapping_is_lossless() {
        use crate::primitives::WafDecision;
        use synvoid_challenge::ChallengeType;
        assert_eq!(WafDecision::Pass.class(), EnforcementClass::Allow);
        assert_eq!(
            WafDecision::Block(403, "x".to_string()).class(),
            EnforcementClass::Block
        );
        assert_eq!(WafDecision::Drop.class(), EnforcementClass::Drop);
        assert_eq!(
            WafDecision::Tarpit("/x".to_string()).class(),
            EnforcementClass::Tarpit
        );
        assert_eq!(WafDecision::Stall.class(), EnforcementClass::Stall);
        assert_eq!(
            WafDecision::Challenge(ChallengeType::PowChallenge, "html".to_string()).class(),
            EnforcementClass::Challenge
        );
        assert_eq!(
            WafDecision::ChallengeWithCookie {
                challenge_type: ChallengeType::CssChallenge,
                html: "html".to_string(),
                session_cookie_name: "n".to_string(),
                session_cookie_value: "v".to_string(),
                session_cookie_max_age: 60,
            }
            .class(),
            EnforcementClass::Challenge
        );
    }
}
