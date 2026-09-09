//! Root-test ownership: COMPOSITION
//! Rationale: Phase 24 Track 3 invariant closure. Exercises the canonical
//! enforcement contract through the public composition boundary (adapters in
//! synvoid-waf / synvoid-proxy / synvoid-http projected onto
//! synvoid-core::enforcement), proving reducer precedence, order
//! independence, idempotence, exhaustive adapter mappings, source/reason
//! preservation, and that allow/observe can never weaken terminal actions.

use synvoid_challenge::ChallengeType;
use synvoid_core::enforcement::{
    reduce, reduce_all, EnforcementCandidate, EnforcementClass, EnforcementReason,
    EnforcementSource,
};
use synvoid_http::{BodyPolicyError, FramingError};
use synvoid_proxy::protocol::trait_def::WafAction;
use synvoid_waf::attack_detection::{AttackDetectionResult, AttackType, InputLocation};
use synvoid_waf::bot::BotDetectionResult;
use synvoid_waf::endpoints::EndpointCheckResult;
use synvoid_waf::enforcement::{
    attack_candidate, bot_candidate, endpoint_candidate, flood_candidate, streaming_candidate,
};
use synvoid_waf::flood::FloodDecision;
use synvoid_waf::primitives::WafDecision;

const ALL_CLASSES: [EnforcementClass; 7] = [
    EnforcementClass::Allow,
    EnforcementClass::Observe,
    EnforcementClass::Challenge,
    EnforcementClass::Stall,
    EnforcementClass::Tarpit,
    EnforcementClass::Block,
    EnforcementClass::Drop,
];

fn candidate(class: EnforcementClass) -> EnforcementCandidate {
    EnforcementCandidate::new(
        class,
        EnforcementSource::AttackDetection,
        EnforcementReason::AttackDetected,
    )
}

// ─── Reducer precedence ─────────────────────────────────────────────────────

#[test]
fn reducer_pairwise_precedence_matches_rank() {
    for &a in &ALL_CLASSES {
        for &b in &ALL_CLASSES {
            let winner = reduce(candidate(a), candidate(b));
            let expected = if a.precedence_rank() >= b.precedence_rank() {
                a
            } else {
                b
            };
            assert_eq!(
                winner.class, expected,
                "reduce({a:?}, {b:?}) must select higher precedence rank"
            );
            // Symmetric call must agree on class.
            let winner_rev = reduce(candidate(b), candidate(a));
            assert_eq!(winner_rev.class, expected);
        }
    }
}

#[test]
fn reducer_is_idempotent() {
    for &class in &ALL_CLASSES {
        let c = candidate(class);
        assert_eq!(reduce(c, c), c);
        assert_eq!(reduce_all([c, c, c]), Some(c));
        assert_eq!(reduce_all([c]), Some(c));
    }
    assert_eq!(reduce_all([]), None, "empty set means allow");
}

#[test]
fn allow_and_observe_never_weaken_terminal() {
    let non_terminal = [EnforcementClass::Allow, EnforcementClass::Observe];
    let terminal = [
        EnforcementClass::Challenge,
        EnforcementClass::Stall,
        EnforcementClass::Tarpit,
        EnforcementClass::Block,
        EnforcementClass::Drop,
    ];
    for &t in &terminal {
        for &n in &non_terminal {
            assert_eq!(reduce(candidate(t), candidate(n)).class, t);
            assert_eq!(reduce(candidate(n), candidate(t)).class, t);
        }
        // A terminal candidate survives any number of allow/observe claims.
        let mut set = vec![candidate(t)];
        for &n in &non_terminal {
            set.push(candidate(n));
            set.push(candidate(n));
        }
        assert_eq!(reduce_all(set).map(|c| c.class), Some(t));
    }
}

#[test]
fn reduce_all_is_order_independent() {
    let set = [
        EnforcementCandidate::new(
            EnforcementClass::Block,
            EnforcementSource::AttackDetection,
            EnforcementReason::AttackDetected,
        ),
        EnforcementCandidate::new(
            EnforcementClass::Tarpit,
            EnforcementSource::BotPolicy,
            EnforcementReason::ScraperTarpitted,
        ),
        EnforcementCandidate::new(
            EnforcementClass::Challenge,
            EnforcementSource::OperatorManual,
            EnforcementReason::ChallengeRequired,
        ),
        EnforcementCandidate::new(
            EnforcementClass::Observe,
            EnforcementSource::Honeypot,
            EnforcementReason::Observed,
        ),
        EnforcementCandidate::new(
            EnforcementClass::Allow,
            EnforcementSource::RateLimit,
            EnforcementReason::Allowed,
        ),
    ];
    let forward = reduce_all(set).expect("non-empty set reduces");
    assert_eq!(forward.class, EnforcementClass::Block);
    let mut reversed = set.to_vec();
    reversed.reverse();
    assert_eq!(reduce_all(reversed), Some(forward));
    // Rotations must agree as well.
    for i in 1..set.len() {
        let mut rotated = set.to_vec();
        rotated.rotate_left(i);
        assert_eq!(reduce_all(rotated), Some(forward), "rotation {i} disagrees");
    }
    // Deterministic pseudo-shuffle (fixed seed, no RNG dependency).
    let mut shuffled = set.to_vec();
    shuffled.swap(0, 3);
    shuffled.swap(1, 4);
    assert_eq!(reduce_all(shuffled), Some(forward));
}

#[test]
fn winner_preserves_source_and_reason() {
    let block = EnforcementCandidate::new(
        EnforcementClass::Block,
        EnforcementSource::RateLimit,
        EnforcementReason::RateLimited,
    );
    let tarpit = EnforcementCandidate::new(
        EnforcementClass::Tarpit,
        EnforcementSource::BotPolicy,
        EnforcementReason::ScraperTarpitted,
    );
    let winner = reduce(block, tarpit);
    assert_eq!(winner, block, "winner must preserve source/reason verbatim");
    // Same-class ties resolve deterministically and preserve the winner's identity.
    let tie_a = EnforcementCandidate::new(
        EnforcementClass::Block,
        EnforcementSource::RateLimit,
        EnforcementReason::RateLimited,
    );
    let tie_b = EnforcementCandidate::new(
        EnforcementClass::Block,
        EnforcementSource::AttackDetection,
        EnforcementReason::AttackDetected,
    );
    assert_eq!(reduce(tie_a, tie_b), reduce(tie_b, tie_a));
    let tie_winner = reduce(tie_a, tie_b);
    assert!(tie_winner == tie_a || tie_winner == tie_b);
}

// ─── Exhaustive adapter mappings ────────────────────────────────────────────

#[test]
fn flood_adapter_is_exhaustive() {
    assert_eq!(flood_candidate(FloodDecision::Allowed), None);
    let limited = flood_candidate(FloodDecision::RateLimited).expect("rate-limited claims");
    assert_eq!(limited.class, EnforcementClass::Block);
    assert_eq!(limited.source, EnforcementSource::FloodProtection);
    assert_eq!(limited.reason, EnforcementReason::FloodRateLimited);
    let blackholed = flood_candidate(FloodDecision::Blackholed).expect("blackholed claims");
    assert_eq!(blackholed.class, EnforcementClass::Drop);
    assert_eq!(blackholed.reason, EnforcementReason::FloodBlackholed);
}

#[test]
fn bot_adapter_is_exhaustive() {
    assert_eq!(
        bot_candidate(&BotDetectionResult::Allowed {
            reason: "clean".to_string()
        }),
        None
    );
    let blocked = bot_candidate(&BotDetectionResult::Blocked {
        reason: "bot".to_string(),
        bot_type: "curl".to_string(),
    })
    .expect("blocked claims");
    assert_eq!(blocked.class, EnforcementClass::Block);
    assert_eq!(blocked.source, EnforcementSource::BotPolicy);
    assert_eq!(blocked.reason, EnforcementReason::BotBlocked);
    let tarpitted = bot_candidate(&BotDetectionResult::Tarpit {
        reason: "scraper".to_string(),
        bot_type: "scraper".to_string(),
    })
    .expect("tarpit claims");
    assert_eq!(tarpitted.class, EnforcementClass::Tarpit);
    assert_eq!(tarpitted.reason, EnforcementReason::ScraperTarpitted);
}

#[test]
fn endpoint_adapter_is_exhaustive() {
    assert_eq!(endpoint_candidate(&EndpointCheckResult::Allowed), None);
    let blocked = endpoint_candidate(&EndpointCheckResult::Blocked {
        response_code: 403,
        html: None,
        matched_pattern: Some("/admin".to_string()),
    })
    .expect("blocked endpoint claims");
    assert_eq!(blocked.class, EnforcementClass::Block);
    assert_eq!(blocked.source, EnforcementSource::EndpointPolicy);
    assert_eq!(blocked.reason, EnforcementReason::EndpointBlocked);
}

#[test]
fn attack_adapter_always_blocks_with_source_preserved() {
    let result = AttackDetectionResult {
        attack_type: AttackType::Sqli,
        fingerprint: None,
        matched_pattern: Some("1' OR '1'='1".to_string()),
        input_location: InputLocation::QueryString,
    };
    let c = attack_candidate(&result);
    assert_eq!(c.class, EnforcementClass::Block);
    assert_eq!(c.source, EnforcementSource::AttackDetection);
    assert_eq!(c.reason, EnforcementReason::AttackDetected);
}

#[test]
fn streaming_adapter_is_exhaustive() {
    use synvoid_core::streaming_waf::StreamingWafDecision as CoreDecision;
    assert_eq!(streaming_candidate(&CoreDecision::Continue), None);
    let blocked =
        streaming_candidate(&CoreDecision::Block(403, "xss".to_string())).expect("block claims");
    assert_eq!(blocked.class, EnforcementClass::Block);
    assert_eq!(blocked.source, EnforcementSource::StreamingBodyScan);
    assert_eq!(blocked.reason, EnforcementReason::BodyBlocked);
}

#[test]
fn waf_decision_class_mapping_covers_all_variants() {
    assert_eq!(WafDecision::Pass.class(), EnforcementClass::Allow);
    assert_eq!(
        WafDecision::Block(403, "x".to_string()).class(),
        EnforcementClass::Block
    );
    assert_eq!(WafDecision::Drop.class(), EnforcementClass::Drop);
    assert_eq!(
        WafDecision::Tarpit("/tarpit".to_string()).class(),
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

#[test]
fn proxy_waf_action_mapping_is_exhaustive_and_round_trips() {
    assert_eq!(WafAction::Allow.class(), EnforcementClass::Allow);
    assert_eq!(WafAction::Block.class(), EnforcementClass::Block);
    assert_eq!(WafAction::Challenge.class(), EnforcementClass::Challenge);
    assert_eq!(WafAction::Stall.class(), EnforcementClass::Stall);
    assert_eq!(WafAction::TarPit.class(), EnforcementClass::Tarpit);
    assert_eq!(WafAction::LogOnly.class(), EnforcementClass::Observe);
    // from_class covers every canonical class; Drop degrades fail-closed to Block.
    for &class in &ALL_CLASSES {
        let action = WafAction::from_class(class);
        if class == EnforcementClass::Drop {
            assert!(matches!(action, WafAction::Block));
        } else {
            assert_eq!(action.class(), class, "round-trip failed for {class:?}");
        }
    }
}

#[test]
fn http_body_policy_mapping_is_terminal_fail_closed() {
    for error in [BodyPolicyError::BlockedByWaf, BodyPolicyError::BodyTooLarge] {
        let c = error.candidate();
        assert_eq!(c.class, EnforcementClass::Block);
        assert!(c.class.is_terminal());
        assert_eq!(c.source, EnforcementSource::StreamingBodyScan);
    }
}

#[test]
fn http_framing_mapping_is_terminal_fail_closed() {
    let errors = [
        FramingError::DuplicateContentLength,
        FramingError::ContentLengthAndTransferEncoding,
        FramingError::UnsupportedTransferCoding,
        FramingError::InvalidContentLength,
        FramingError::DuplicateHost,
        FramingError::InvalidHost,
    ];
    for error in errors {
        let c = error.candidate();
        assert_eq!(c.class, EnforcementClass::Block, "{error:?} must deny");
        assert!(c.class.is_terminal());
        assert_eq!(error.status(), 400);
    }
}

#[test]
fn composed_adapters_resolve_through_reducer() {
    // A realistic multi-detector claim set must resolve to the strongest terminal
    // action with the winner's provenance intact.
    let claims = [
        flood_candidate(FloodDecision::RateLimited).unwrap(),
        bot_candidate(&BotDetectionResult::Tarpit {
            reason: "scraper".to_string(),
            bot_type: "scraper".to_string(),
        })
        .unwrap(),
        BodyPolicyError::BodyTooLarge.candidate(),
        FramingError::DuplicateContentLength.candidate(),
    ];
    let winner = reduce_all(claims).expect("claims reduce");
    assert_eq!(winner.class, EnforcementClass::Block);
    // A Drop anywhere must dominate every Block.
    let with_drop = [
        flood_candidate(FloodDecision::RateLimited).unwrap(),
        flood_candidate(FloodDecision::Blackholed).unwrap(),
    ];
    let winner = reduce_all(with_drop).expect("claims reduce");
    assert_eq!(winner.class, EnforcementClass::Drop);
    assert_eq!(winner.reason, EnforcementReason::FloodBlackholed);
}
