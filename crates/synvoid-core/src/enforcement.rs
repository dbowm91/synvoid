//! Canonical request-enforcement decision contract.
//!
//! This module is the single shared vocabulary through which independent
//! detectors (WAF attack detection, rate limiting, bot policy, flood
//! protection, honeypot, endpoint policy, streaming body scan, block store)
//! compose into one deterministic request disposition.
//!
//! # Design rules
//!
//! - Detectors keep their own domain-specific result types (they carry
//!   evidence, not just actions). Each detector maps its outcome to an
//!   [`EnforcementCandidate`] at the composition boundary.
//! - The rich response directive (`synvoid_waf::WafDecision`, which carries
//!   rendered HTML, cookies, status codes) is **not** replaced. It exposes a
//!   lossless [`EnforcementClass`] mapping instead.
//! - Transport-local adapters (e.g. `synvoid_proxy` protocol actions) map to
//!   and from [`EnforcementClass`] with exhaustive, tested conversions.
//! - [`EnforcementSource::as_str`] and [`EnforcementReason::as_str`] return
//!   frozen `&'static str` codes suitable for bounded-cardinality metric
//!   labels. Never put IPs, URLs, user agents, or rule text into labels.
//! - The common allow path allocates nothing: an empty candidate set means
//!   allow, and [`reduce_all`] returns `None` without touching the heap.
//!
//! Location rationale: this crate is the lowest-level crate that every
//! request-path crate (`synvoid-waf`, `synvoid-proxy`, `synvoid-http`,
//! `synvoid-http-client`) already depends on, so placing the contract here
//! creates no dependency cycle and no new workspace crate.

use serde::{Deserialize, Serialize};

/// Transport-neutral enforcement class.
///
/// Terminal precedence (highest first):
/// `Drop > Block > Tarpit > Stall > Challenge > Observe > Allow`.
///
/// See [`reduce`] for the conflict semantics. `Allow` and `Observe` are
/// non-terminal: they can never erase or weaken a terminal candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnforcementClass {
    /// No enforcement; the request proceeds.
    Allow,
    /// Log-only evidence; the request proceeds.
    Observe,
    /// Issue a challenge (PoW, CSS, auth); the request proceeds iff solved.
    Challenge,
    /// Artificially delay the response.
    Stall,
    /// Trap the client in a tarpit session.
    Tarpit,
    /// Reject with an error response.
    Block,
    /// Silently drop without a response.
    Drop,
}

impl EnforcementClass {
    /// Terminal precedence rank. Higher wins. Ordering is frozen:
    /// `Drop(6) > Block(5) > Tarpit(4) > Stall(3) > Challenge(2) >
    /// Observe(1) > Allow(0)`.
    pub const fn precedence_rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Observe => 1,
            Self::Challenge => 2,
            Self::Stall => 3,
            Self::Tarpit => 4,
            Self::Block => 5,
            Self::Drop => 6,
        }
    }

    /// Terminal classes deny or divert the request; `Allow`/`Observe` do not.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Allow | Self::Observe)
    }

    /// Frozen machine-readable code for metrics and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Observe => "observe",
            Self::Challenge => "challenge",
            Self::Stall => "stall",
            Self::Tarpit => "tarpit",
            Self::Block => "block",
            Self::Drop => "drop",
        }
    }
}

impl std::fmt::Display for EnforcementClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed provenance for an enforcement candidate.
///
/// The `as_str` codes preserve the pre-contract
/// `synvoid_request_enforcement_source_total` label values so existing
/// dashboards keep working; they are frozen as part of this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnforcementSource {
    /// Pre-existing block/blackhole state (checked at the composition root).
    BlockStore,
    /// IP / site / global rate limiter.
    RateLimit,
    /// Static endpoint block policy.
    EndpointPolicy,
    /// Honeypot / sensitive-endpoint hit.
    Honeypot,
    /// Bot / scraper / fingerprint policy.
    BotPolicy,
    /// SYN / connection / UDP flood protection.
    FloodProtection,
    /// Attack-detection rules engine.
    AttackDetection,
    /// Streaming / buffered request-body scan.
    StreamingBodyScan,
    /// Operator / manual enforcement action.
    OperatorManual,
    /// Mesh-derived (federated) enforcement.
    MeshDerived,
}

impl EnforcementSource {
    /// Frozen machine-readable code for metrics and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlockStore => "block_store",
            Self::RateLimit => "rate_limit",
            Self::EndpointPolicy => "endpoint_block",
            Self::Honeypot => "honeypot_hit",
            Self::BotPolicy => "bot_protection",
            Self::FloodProtection => "flood_protection",
            Self::AttackDetection => "attack_detection",
            Self::StreamingBodyScan => "streaming_body",
            Self::OperatorManual => "operator_manual",
            Self::MeshDerived => "mesh_derived",
        }
    }
}

impl std::fmt::Display for EnforcementSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bounded, stable reason codes.
///
/// Human-readable detail stays in logs/tracing; metrics and tests use these
/// codes so label cardinality stays bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnforcementReason {
    /// No detector claimed the request.
    Allowed,
    /// Log-only observation.
    Observed,
    /// IP is blocklisted at the composition root.
    Blocklisted,
    /// Rate limiter engaged (429-class).
    RateLimited,
    /// Static endpoint policy matched.
    EndpointBlocked,
    /// Sensitive/honeypot endpoint accessed.
    HoneypotHit,
    /// Bot policy denied the request.
    BotBlocked,
    /// Scraper diverted to the tarpit.
    ScraperTarpitted,
    /// Flood protection rate-limited the connection.
    FloodRateLimited,
    /// Flood protection entered blackhole/drop.
    FloodBlackholed,
    /// Attack-detection rule matched.
    AttackDetected,
    /// Request body scan blocked the request.
    BodyBlocked,
    /// Request body exceeded size limits.
    BodyTooLarge,
    /// Automated client must solve a challenge.
    ChallengeRequired,
    /// Operator / manual block.
    OperatorBlocked,
    /// Mesh-propagated enforcement.
    MeshBlocked,
    /// Fail-closed fallback for an unsupported/malformed outcome.
    UnsupportedOutcome,
}

impl EnforcementReason {
    /// Frozen machine-readable code for metrics and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Observed => "observed",
            Self::Blocklisted => "blocklisted",
            Self::RateLimited => "rate_limited",
            Self::EndpointBlocked => "endpoint_blocked",
            Self::HoneypotHit => "honeypot_hit",
            Self::BotBlocked => "bot_blocked",
            Self::ScraperTarpitted => "scraper_tarpitted",
            Self::FloodRateLimited => "flood_rate_limited",
            Self::FloodBlackholed => "flood_blackholed",
            Self::AttackDetected => "attack_detected",
            Self::BodyBlocked => "body_blocked",
            Self::BodyTooLarge => "body_too_large",
            Self::ChallengeRequired => "challenge_required",
            Self::OperatorBlocked => "operator_blocked",
            Self::MeshBlocked => "mesh_blocked",
            Self::UnsupportedOutcome => "unsupported_outcome",
        }
    }
}

impl std::fmt::Display for EnforcementReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One detector's claim on request disposition: what action, from which
/// source, for which bounded reason.
///
/// Candidates carry no response payload (no HTML, cookies, or
/// protocol-specific objects); rendering stays with the rich directive
/// (`WafDecision`) at the dispatch layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnforcementCandidate {
    /// Requested enforcement class.
    pub class: EnforcementClass,
    /// Which subsystem produced the claim.
    pub source: EnforcementSource,
    /// Bounded reason code.
    pub reason: EnforcementReason,
}

impl EnforcementCandidate {
    /// Build a candidate. Prefers `const` so call sites stay allocation-free.
    pub const fn new(
        class: EnforcementClass,
        source: EnforcementSource,
        reason: EnforcementReason,
    ) -> Self {
        Self {
            class,
            source,
            reason,
        }
    }
}

/// Reduce two candidates to the winning disposition.
///
/// - Higher [`EnforcementClass::precedence_rank`] always wins: a
///   lower-precedence candidate can never weaken a higher-precedence one, and
///   `Allow`/`Observe` can never erase a terminal candidate.
/// - Reduction is idempotent: `reduce(x, x) == x`.
/// - Ties (same class) are broken deterministically by `(source, reason)`
///   code order (lexicographic on the frozen `as_str` codes), lowest wins, so
///   the result never depends on candidate order, hash-map iteration, or task
///   completion order.
pub fn reduce(a: EnforcementCandidate, b: EnforcementCandidate) -> EnforcementCandidate {
    let rank_a = a.class.precedence_rank();
    let rank_b = b.class.precedence_rank();
    if rank_a != rank_b {
        return if rank_a > rank_b { a } else { b };
    }
    if a == b {
        return a;
    }
    let key_a = (a.source.as_str(), a.reason.as_str());
    let key_b = (b.source.as_str(), b.reason.as_str());
    if key_a <= key_b {
        a
    } else {
        b
    }
}

/// Reduce a candidate set to the winning disposition.
///
/// Returns `None` when the set is empty, which means `Allow` by default
/// policy. Reduction is order-independent for equivalent sets: folding
/// [`reduce`] over the candidates in any order yields the same winner
/// because class precedence selects the maximum rank and ties fall back to
/// the deterministic `(source, reason)` order.
pub fn reduce_all(
    candidates: impl IntoIterator<Item = EnforcementCandidate>,
) -> Option<EnforcementCandidate> {
    candidates.into_iter().reduce(reduce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_ranks_match_documented_order() {
        use EnforcementClass::*;
        assert!(
            Drop.precedence_rank() > Block.precedence_rank()
                && Block.precedence_rank() > Tarpit.precedence_rank()
                && Tarpit.precedence_rank() > Stall.precedence_rank()
                && Stall.precedence_rank() > Challenge.precedence_rank()
                && Challenge.precedence_rank() > Observe.precedence_rank()
                && Observe.precedence_rank() > Allow.precedence_rank()
        );
        assert!(!Allow.is_terminal());
        assert!(!Observe.is_terminal());
        for class in [Challenge, Stall, Tarpit, Block, Drop] {
            assert!(class.is_terminal(), "{class:?} must be terminal");
        }
    }

    #[test]
    fn source_and_reason_codes_are_frozen() {
        // Metric continuity: these strings are part of the contract.
        assert_eq!(EnforcementSource::BlockStore.as_str(), "block_store");
        assert_eq!(EnforcementSource::RateLimit.as_str(), "rate_limit");
        assert_eq!(EnforcementSource::EndpointPolicy.as_str(), "endpoint_block");
        assert_eq!(EnforcementSource::Honeypot.as_str(), "honeypot_hit");
        assert_eq!(EnforcementSource::BotPolicy.as_str(), "bot_protection");
        assert_eq!(
            EnforcementSource::FloodProtection.as_str(),
            "flood_protection"
        );
        assert_eq!(
            EnforcementSource::AttackDetection.as_str(),
            "attack_detection"
        );
        assert_eq!(
            EnforcementSource::StreamingBodyScan.as_str(),
            "streaming_body"
        );
    }

    #[test]
    fn metric_label_codes_contain_no_high_cardinality_chars() {
        // Codes must be safe as metric label values: lowercase snake_case.
        let classes = [
            EnforcementClass::Allow,
            EnforcementClass::Observe,
            EnforcementClass::Challenge,
            EnforcementClass::Stall,
            EnforcementClass::Tarpit,
            EnforcementClass::Block,
            EnforcementClass::Drop,
        ];
        for class in classes {
            let code = class.as_str();
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "class code must be snake_case: {code}"
            );
        }
        let sources = [
            EnforcementSource::BlockStore,
            EnforcementSource::RateLimit,
            EnforcementSource::EndpointPolicy,
            EnforcementSource::Honeypot,
            EnforcementSource::BotPolicy,
            EnforcementSource::FloodProtection,
            EnforcementSource::AttackDetection,
            EnforcementSource::StreamingBodyScan,
            EnforcementSource::OperatorManual,
            EnforcementSource::MeshDerived,
        ];
        for source in sources {
            let code = source.as_str();
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "source code must be snake_case: {code}"
            );
        }
    }

    fn candidate(class: EnforcementClass) -> EnforcementCandidate {
        // Fixed source/reason so pairwise tests isolate class precedence.
        EnforcementCandidate::new(
            class,
            EnforcementSource::AttackDetection,
            EnforcementReason::AttackDetected,
        )
    }

    fn all_classes() -> [EnforcementClass; 7] {
        use EnforcementClass::*;
        [Allow, Observe, Challenge, Stall, Tarpit, Block, Drop]
    }

    #[test]
    fn reducer_pairwise_precedence_is_exhaustive() {
        // Every ordered pair of classes: the higher-precedence class wins
        // regardless of argument order.
        let classes = all_classes();
        for &a in &classes {
            for &b in &classes {
                let expected = if a.precedence_rank() >= b.precedence_rank() {
                    a
                } else {
                    b
                };
                assert_eq!(
                    reduce(candidate(a), candidate(b)).class,
                    expected,
                    "reduce({a:?}, {b:?})"
                );
                assert_eq!(
                    reduce(candidate(b), candidate(a)).class,
                    expected,
                    "reduce({b:?}, {a:?}) must agree"
                );
            }
        }
    }

    #[test]
    fn reducer_is_idempotent() {
        let sources = [
            EnforcementSource::BlockStore,
            EnforcementSource::RateLimit,
            EnforcementSource::BotPolicy,
            EnforcementSource::FloodProtection,
            EnforcementSource::AttackDetection,
        ];
        for class in all_classes() {
            for source in sources {
                let c = EnforcementCandidate::new(class, source, EnforcementReason::AttackDetected);
                assert_eq!(reduce(c, c), c, "reduce(x, x) == x for {c:?}");
            }
        }
    }

    #[test]
    fn allow_and_observe_never_erase_terminal() {
        for terminal in [
            EnforcementClass::Challenge,
            EnforcementClass::Stall,
            EnforcementClass::Tarpit,
            EnforcementClass::Block,
            EnforcementClass::Drop,
        ] {
            let won = EnforcementCandidate::new(
                terminal,
                EnforcementSource::RateLimit,
                EnforcementReason::RateLimited,
            );
            let allow = EnforcementCandidate::new(
                EnforcementClass::Allow,
                EnforcementSource::AttackDetection,
                EnforcementReason::Allowed,
            );
            let observe = EnforcementCandidate::new(
                EnforcementClass::Observe,
                EnforcementSource::AttackDetection,
                EnforcementReason::Observed,
            );
            assert_eq!(reduce(won, allow), won);
            assert_eq!(reduce(allow, won), won);
            assert_eq!(reduce(won, observe), won);
            assert_eq!(reduce(observe, won), won);
        }
    }

    #[test]
    fn lower_precedence_never_weakens_higher() {
        // A full lower-triangle sweep: for every strictly-lower pair, the
        // higher class survives in both argument orders.
        let classes = all_classes();
        for (i, &higher) in classes.iter().enumerate() {
            for &lower in &classes[..i] {
                assert_eq!(reduce(candidate(higher), candidate(lower)).class, higher);
                assert_eq!(reduce(candidate(lower), candidate(higher)).class, higher);
            }
        }
    }

    #[test]
    fn tie_break_is_deterministic_and_order_independent() {
        // Same class, different provenance: winner is fixed by (source,
        // reason) code order, not by argument order.
        let a = EnforcementCandidate::new(
            EnforcementClass::Block,
            EnforcementSource::RateLimit,
            EnforcementReason::RateLimited,
        );
        let b = EnforcementCandidate::new(
            EnforcementClass::Block,
            EnforcementSource::AttackDetection,
            EnforcementReason::AttackDetected,
        );
        assert_eq!(reduce(a, b), reduce(b, a));
        // "attack_detection" < "rate_limit" lexicographically, so `b` wins.
        assert_eq!(reduce(a, b), b);
    }

    #[test]
    fn reduce_all_agrees_with_pairwise_fold_in_any_order() {
        // Representative multi-candidate sets, each evaluated in forward and
        // reverse order.
        use EnforcementClass::*;
        let raw: Vec<Vec<EnforcementCandidate>> = vec![
            vec![candidate(Allow), candidate(Allow)],
            vec![candidate(Allow), candidate(Observe)],
            vec![candidate(Challenge), candidate(Stall), candidate(Tarpit)],
            vec![
                candidate(Block),
                candidate(Tarpit),
                candidate(Stall),
                candidate(Challenge),
            ],
            vec![candidate(Drop), candidate(Block), candidate(Tarpit)],
            vec![
                EnforcementCandidate::new(
                    Block,
                    EnforcementSource::RateLimit,
                    EnforcementReason::RateLimited,
                ),
                EnforcementCandidate::new(
                    Block,
                    EnforcementSource::AttackDetection,
                    EnforcementReason::AttackDetected,
                ),
                candidate(Stall),
            ],
        ];
        let expected = [Allow, Observe, Tarpit, Block, Drop, Block];
        for (set, &want) in raw.iter().zip(expected.iter()) {
            let forward = reduce_all(set.iter().copied()).map(|c| c.class);
            let mut reversed = set.clone();
            reversed.reverse();
            let backward = reduce_all(reversed.into_iter()).map(|c| c.class);
            assert_eq!(forward, Some(want), "forward reduce of {set:?}");
            assert_eq!(backward, Some(want), "reversed reduce of {set:?}");
        }
    }

    #[test]
    fn reduce_all_empty_means_allow_without_allocation() {
        let none: Option<EnforcementCandidate> = reduce_all([]);
        assert_eq!(none, None);
        let none_vec: Option<EnforcementCandidate> = reduce_all(Vec::new());
        assert_eq!(none_vec, None);
    }
}
