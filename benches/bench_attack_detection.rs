use criterion::{criterion_group, criterion_main, Criterion};
use synvoid_core::enforcement::{
    reduce_all, EnforcementCandidate, EnforcementClass, EnforcementReason, EnforcementSource,
};
use synvoid_waf::attack_detection::{AttackDetectionResult, AttackType, InputLocation};
use synvoid_waf::bot::BotDetectionResult;
use synvoid_waf::endpoints::EndpointCheckResult;
use synvoid_waf::enforcement::{
    attack_candidate, bot_candidate, endpoint_candidate, flood_candidate, streaming_candidate,
};
use synvoid_waf::flood::FloodDecision;

/// WAF terminal-decision / reducer overhead (Phase 24 hot path).
///
/// Measures the canonical composition boundary only: adapter projection +
/// deterministic reduction. Detector execution cost itself is covered by
/// `bench_attack_detection_wave10` and `bench_normalization`.
fn representative_claims() -> Vec<EnforcementCandidate> {
    let attack = AttackDetectionResult {
        attack_type: AttackType::Xss,
        fingerprint: None,
        matched_pattern: Some("<script>".to_string()),
        input_location: InputLocation::QueryString,
    };
    vec![
        attack_candidate(&attack),
        flood_candidate(FloodDecision::RateLimited).unwrap(),
        bot_candidate(&BotDetectionResult::Tarpit {
            reason: "scraper".to_string(),
            bot_type: "scraper".to_string(),
        })
        .unwrap(),
        endpoint_candidate(&EndpointCheckResult::Allowed).unwrap_or(EnforcementCandidate::new(
            EnforcementClass::Allow,
            EnforcementSource::EndpointPolicy,
            EnforcementReason::Allowed,
        )),
        streaming_candidate(&synvoid_core::streaming_waf::StreamingWafDecision::Continue)
            .unwrap_or(EnforcementCandidate::new(
                EnforcementClass::Allow,
                EnforcementSource::StreamingBodyScan,
                EnforcementReason::Allowed,
            )),
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
        EnforcementCandidate::new(
            EnforcementClass::Block,
            EnforcementSource::BlockStore,
            EnforcementReason::Blocklisted,
        ),
    ]
}

fn benchmark_reducer(c: &mut Criterion) {
    let mut group = c.benchmark_group("enforcement_reduce");
    group.bench_function("reduce_all_8_mixed", |b| {
        b.iter(|| {
            let claims = representative_claims();
            criterion::black_box(reduce_all(claims));
        });
    });
    group.bench_function("reduce_all_allow_only", |b| {
        let allows = vec![
            EnforcementCandidate::new(
                EnforcementClass::Allow,
                EnforcementSource::RateLimit,
                EnforcementReason::Allowed,
            );
            8
        ];
        b.iter(|| criterion::black_box(reduce_all(allows.clone())));
    });
    group.finish();
}

fn benchmark_adapters(c: &mut Criterion) {
    let mut group = c.benchmark_group("waf_adapter");
    group.bench_function("flood_bot_endpoint_attack", |b| {
        let attack = AttackDetectionResult {
            attack_type: AttackType::Sqli,
            fingerprint: None,
            matched_pattern: Some("1' OR '1'='1".to_string()),
            input_location: InputLocation::Path,
        };
        let bot = BotDetectionResult::Blocked {
            reason: "bot".to_string(),
            bot_type: "curl".to_string(),
        };
        let endpoint = EndpointCheckResult::Blocked {
            response_code: 403,
            html: None,
            matched_pattern: Some("/admin".to_string()),
        };
        b.iter(|| {
            criterion::black_box(flood_candidate(FloodDecision::RateLimited));
            criterion::black_box(bot_candidate(&bot));
            criterion::black_box(endpoint_candidate(&endpoint));
            criterion::black_box(attack_candidate(&attack));
        });
    });
    group.finish();
}

criterion_group!(benches, benchmark_reducer, benchmark_adapters);
criterion_main!(benches);
