//! Phase 133 Workstream B / Phase 135 F-2 — GeoIP **consumer** evidence and
//! absent-provider semantics inside `synvoid-dns`.
//!
//! The provider suite (`crates/synvoid-geoip/tests/geoip_provider_evidence.rs`)
//! proves what a real database answers. This suite proves what `synvoid-dns`
//! *does* with the answer — and, after Phase 135, it can do so with a
//! DNS-owned double, because `synvoid-dns` no longer depends on `synvoid-geoip`
//! and therefore no longer needs a MaxMind database to be tested.
//!
//! ## The behavior change this pins
//!
//! Phase 133 F-2: a `GeoLocation` **block** rule with no provider did not match,
//! so evaluation fell through to the default `Allow`, and the decision did not
//! name the skipped rule. An operator who configured a country block without a
//! GeoIP database got no error, no log line, and no traffic blocked.
//!
//! Phase 135 makes the rule's condition tri-state (`GeoMatch::Yes` / `No` /
//! `Unavailable`) and applies a **restrictive** action when the condition is
//! indeterminate, while a permissive action is skipped. The decision `reason`
//! names the rule and the reason, and a warning is emitted once per firewall.
//!
//! These tests therefore assert the *fixed* behavior. The fail-open state is
//! preserved in the Phase 133 closeout as a finding, not re-tested here.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use synvoid_dns::firewall::{GeoLocation, GeoMatch, RuleIndeterminate};
use synvoid_dns::geo::{CountryInfo, CountryLookup};
use synvoid_dns::parsed_query::ParsedDnsQuery;
use synvoid_dns::{DnsFirewall, DnsFirewallAction, DnsFirewallRule, DnsFirewallRuleType};

/// A minimal wire-format query for `example.com` A.
fn example_query() -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in "example.com".split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    query
}

fn parse(query: &[u8]) -> ParsedDnsQuery<'_> {
    ParsedDnsQuery::parse(query).expect("hand-built query parses")
}

fn rule(
    id: &str,
    rule_type: DnsFirewallRuleType,
    target: &str,
    action: DnsFirewallAction,
) -> DnsFirewallRule {
    DnsFirewallRule {
        id: id.to_string(),
        rule_type,
        action,
        target: target.to_string(),
        ttl: 300,
        created_at: 0,
        expires_at: None,
        enabled: true,
    }
}

fn client_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
}

/// A DNS-owned double. Phase 135 is the first phase in which the consumer side
/// is testable without a real MaxMind database, because the capability is
/// DNS-owned.
struct StubLookup {
    country: Option<&'static str>,
    subdivision: Option<&'static str>,
    city: Option<&'static str>,
    asn: Option<u32>,
}

impl StubLookup {
    fn answering(country: &'static str) -> Arc<dyn CountryLookup> {
        Arc::new(Self {
            country: Some(country),
            subdivision: None,
            city: None,
            asn: None,
        })
    }

    /// A provider that exists but has no answer for anything — the shape a real
    /// provider has when no database is loaded.
    fn answerless() -> Arc<dyn CountryLookup> {
        Arc::new(Self {
            country: None,
            subdivision: None,
            city: None,
            asn: None,
        })
    }
}

impl CountryLookup for StubLookup {
    fn country_info(&self, _ip: IpAddr) -> Option<CountryInfo> {
        self.country.map(|code| CountryInfo {
            code: code.to_string(),
            name: "Stubland".to_string(),
            subdivision: self.subdivision.map(str::to_string),
            city: self.city.map(str::to_string),
        })
    }

    fn asn(&self, _ip: IpAddr) -> Option<u32> {
        self.asn
    }
}

// ---- F-2: the absent-provider case is now fail-closed ----------------------

/// F-2 fixed: a `GeoLocation` **block** rule with no provider is applied rather
/// than skipped. The decision names the rule and says why, so the operator can
/// see that the control fired because it could not be evaluated rather than
/// because the client matched.
#[test]
fn a_geo_block_rule_without_a_provider_fails_closed() {
    let mut firewall = DnsFirewall::new();
    assert!(
        !firewall.can_evaluate_geo_rules(),
        "precondition: this firewall has no country lookup"
    );
    firewall
        .add_rule(rule(
            "geo-block",
            DnsFirewallRuleType::GeoLocation,
            "RU",
            DnsFirewallAction::Block,
        ))
        .expect("rule accepted");

    let query = example_query();
    let decision = firewall
        .evaluate_query(&parse(&query), client_ip(), "example.com")
        .expect("evaluation succeeds");

    assert_eq!(
        decision.action,
        DnsFirewallAction::Block,
        "a restrictive geo rule must not silently pass traffic when unevaluable"
    );
    assert_eq!(decision.rule_id, "geo-block");
    assert!(
        decision.reason.contains("could not be evaluated"),
        "the reason must say the rule was unevaluable, got: {}",
        decision.reason
    );
    assert!(
        decision
            .reason
            .contains(RuleIndeterminate::NoCountryLookup.as_str()),
        "and name the reason, got: {}",
        decision.reason
    );
}

/// F-2 fixed: a **permissive** geo rule with no provider is skipped, not
/// applied. Granting "allow" to a rule nobody scoped would hand out access
/// nobody granted, so the asymmetry is deliberate and it is pinned.
#[test]
fn a_geo_allow_rule_without_a_provider_is_skipped_not_applied() {
    let mut firewall = DnsFirewall::new();
    firewall
        .add_rule(rule(
            "geo-allow",
            DnsFirewallRuleType::GeoLocation,
            "RU",
            DnsFirewallAction::Allow,
        ))
        .expect("rule accepted");

    let query = example_query();
    let decision = firewall
        .evaluate_query(&parse(&query), client_ip(), "example.com")
        .expect("evaluation succeeds");

    assert_eq!(
        decision.action,
        DnsFirewallAction::Allow,
        "the default is also allow, but for a different reason"
    );
    assert_eq!(
        decision.rule_id, "default",
        "an unevaluable permissive rule must not be reported as a match"
    );
}

/// Every restrictive action fails closed and every permissive one fails open.
/// Pinned as a matrix so adding an action forces a decision rather than
/// inheriting a default.
#[test]
fn the_indeterminate_posture_is_pinned_for_every_action() {
    let restrictive = [
        DnsFirewallAction::Block,
        DnsFirewallAction::Redirect {
            target: "sink.example".to_string(),
        },
        DnsFirewallAction::Sinkhole,
        DnsFirewallAction::RateLimit {
            limit: 10,
            window: std::time::Duration::from_secs(1),
        },
    ];
    for action in restrictive {
        assert!(
            action.fails_closed_when_indeterminate(),
            "{action:?} is restrictive and must fail closed"
        );
    }

    let permissive = [DnsFirewallAction::Allow, DnsFirewallAction::LogOnly];
    for action in permissive {
        assert!(
            !action.fails_closed_when_indeterminate(),
            "{action:?} is permissive and must fail open"
        );
    }
}

/// A provider that exists but cannot answer is *not* a misconfiguration: the
/// address is simply not in the location. Reporting `Unavailable` here would
/// turn one uncovered address into a fail-closed block, which is a much larger
/// behavioral change than F-2 asks for.
#[test]
fn an_answerless_provider_is_an_evaluated_no_not_an_indeterminate() {
    let lookup = StubLookup::answerless();
    let geo: GeoLocation = "RU".parse().expect("parses");

    assert_eq!(
        geo.matches_ip(client_ip(), Some(&lookup)),
        GeoMatch::No,
        "a provider that cannot answer this address is still an answer"
    );

    let mut firewall = DnsFirewall::new().with_country_lookup(lookup);
    firewall
        .add_rule(rule(
            "geo-block",
            DnsFirewallRuleType::GeoLocation,
            "RU",
            DnsFirewallAction::Block,
        ))
        .expect("rule accepted");

    let query = example_query();
    let decision = firewall
        .evaluate_query(&parse(&query), client_ip(), "example.com")
        .expect("evaluation succeeds");
    assert_eq!(
        decision.action,
        DnsFirewallAction::Allow,
        "with a provider attached, an unmatchable geo rule must not block"
    );
    assert_eq!(decision.rule_id, "default");
}

/// A geo rule the provider *can* evaluate behaves normally: a match applies the
/// action, and a non-match falls through. This is the positive matrix Phase 133
/// could not test in this crate (F-4) and is now directly testable.
#[test]
fn an_answering_provider_matches_on_country_code_case_insensitively() {
    let lookup = StubLookup::answering("ru");
    let geo: GeoLocation = "RU".parse().expect("parses");
    assert_eq!(geo.matches_ip(client_ip(), Some(&lookup)), GeoMatch::Yes);

    let other: GeoLocation = "US".parse().expect("parses");
    assert_eq!(other.matches_ip(client_ip(), Some(&lookup)), GeoMatch::No);
}

/// A region- or city-scoped rule against a provider that carries no subdivision
/// is an evaluated "no", not a misconfiguration — otherwise a GeoLite2-Country
/// database would fail-closed block everything.
#[test]
fn a_region_scoped_rule_needs_the_provider_to_carry_the_region() {
    let bare = StubLookup::answering("RU");
    let scoped: GeoLocation = "RU, Moscow".parse().expect("parses");
    assert_eq!(scoped.matches_ip(client_ip(), Some(&bare)), GeoMatch::No);

    let detailed: Arc<dyn CountryLookup> = Arc::new(StubLookup {
        country: Some("RU"),
        subdivision: Some("Moscow"),
        city: None,
        asn: None,
    });
    assert_eq!(
        scoped.matches_ip(client_ip(), Some(&detailed)),
        GeoMatch::Yes
    );
}

/// An ASN-scoped rule needs an ASN from the provider, and the seam is
/// `Option<u32>` — the provider's organization string never crosses
/// (Phase 133 F-10).
#[test]
fn an_asn_scoped_rule_uses_the_numeric_seam() {
    let no_asn = StubLookup::answering("RU");
    let scoped: GeoLocation = "RU, , , 64500".parse().expect("parses");
    assert_eq!(scoped.matches_ip(client_ip(), Some(&no_asn)), GeoMatch::No);

    let with_asn: Arc<dyn CountryLookup> = Arc::new(StubLookup {
        country: Some("RU"),
        subdivision: None,
        city: None,
        asn: Some(64500),
    });
    assert_eq!(
        scoped.matches_ip(client_ip(), Some(&with_asn)),
        GeoMatch::Yes
    );
}

// ---- rule ordering ---------------------------------------------------------

/// Evaluation is first-match-in-insertion-order, and an **unevaluable** geo
/// rule still participates in that order: being fail-closed, it wins over a
/// later rule rather than being skipped.
#[test]
fn a_fail_closed_geo_rule_precedes_a_later_matching_rule() {
    let mut firewall = DnsFirewall::new();
    firewall
        .add_rule(rule(
            "geo-block",
            DnsFirewallRuleType::GeoLocation,
            "RU",
            DnsFirewallAction::Block,
        ))
        .expect("rule accepted");
    firewall
        .add_rule(rule(
            "domain-block",
            DnsFirewallRuleType::Domain,
            "example.com",
            DnsFirewallAction::Block,
        ))
        .expect("rule accepted");

    let query = example_query();
    let decision = firewall
        .evaluate_query(&parse(&query), client_ip(), "example.com")
        .expect("evaluation succeeds");
    assert_eq!(
        decision.rule_id, "geo-block",
        "the first rule wins even when it is unevaluable and fail-closed"
    );
}

/// An unevaluable **permissive** geo rule is skipped, so a later matching rule
/// is reached. The other half of the ordering guarantee.
#[test]
fn an_unevaluable_permissive_geo_rule_is_skipped_by_evaluation() {
    let mut firewall = DnsFirewall::new();
    firewall
        .add_rule(rule(
            "geo-allow",
            DnsFirewallRuleType::GeoLocation,
            "RU",
            DnsFirewallAction::Allow,
        ))
        .expect("rule accepted");
    firewall
        .add_rule(rule(
            "domain-block",
            DnsFirewallRuleType::Domain,
            "example.com",
            DnsFirewallAction::Block,
        ))
        .expect("rule accepted");

    let query = example_query();
    let decision = firewall
        .evaluate_query(&parse(&query), client_ip(), "example.com")
        .expect("evaluation succeeds");
    assert_eq!(
        decision.rule_id, "domain-block",
        "a permissive rule that cannot be evaluated must not shadow a later rule"
    );
}

/// A *disabled* geo rule is skipped entirely, which remains the operator's
/// explicit way to park a geo control that cannot be evaluated. Recorded
/// because it is now the deliberate alternative to a fail-closed block.
#[test]
fn a_disabled_geo_rule_is_skipped_entirely() {
    let mut disabled = rule(
        "geo-block",
        DnsFirewallRuleType::GeoLocation,
        "RU",
        DnsFirewallAction::Block,
    );
    disabled.enabled = false;

    let mut firewall = DnsFirewall::new();
    firewall.add_rule(disabled).expect("rule accepted");
    firewall
        .add_rule(rule(
            "domain-block",
            DnsFirewallRuleType::Domain,
            "example.com",
            DnsFirewallAction::Block,
        ))
        .expect("rule accepted");

    let query = example_query();
    let decision = firewall
        .evaluate_query(&parse(&query), client_ip(), "example.com")
        .expect("evaluation succeeds");
    assert_eq!(decision.rule_id, "domain-block");
    assert_eq!(decision.action, DnsFirewallAction::Block);
}

// ---- `GeoLocation` shape ---------------------------------------------------

/// `GeoLocation` is DNS-owned and holds only primitives — `String`,
/// `Option<String>`, `Option<u32>`. No provider type appears in it.
#[test]
fn geo_location_is_dns_owned_and_holds_only_primitives() {
    let geo: GeoLocation = "US, California, Mountain View, 15169"
        .parse()
        .expect("parses");
    assert_eq!(geo.country, "US");
    assert_eq!(geo.region.as_deref(), Some("California"));
    assert_eq!(geo.city.as_deref(), Some("Mountain View"));
    assert_eq!(geo.asn, Some(15169));

    let bare: GeoLocation = "DE".parse().expect("parses");
    assert_eq!(bare.country, "DE");
    assert!(bare.region.is_none());
    assert!(bare.city.is_none());
    assert!(bare.asn.is_none());
}

/// F-3 closed (`plans/dns_geo_firewall_residual_closure.md`, Workstream A).
///
/// This test **used to assert the opposite**. It was
/// `geo_location_parsing_cannot_fail_and_typos_still_never_match`, and it pinned
/// two defects as intended behavior:
///
/// 1. `assert!("".parse::<GeoLocation>().is_ok(), "empty target parses")` — the
///    parser could not fail, so a spec with no country became a rule matching
///    nothing.
/// 2. `"RU, , , notanumber"` → `asn: None`, "an unparseable ASN is silently
///    dropped rather than rejected". This is the more dangerous half: an
///    ASN-scoped rule silently **widened** to country-only, so for an `Allow`
///    action a typo widened the grant.
///
/// Both are now rejected. The surviving truth in the old test is kept below: a
/// *valid* spec whose country is merely misspelled still parses, and still never
/// matches — a typo that is well-formed is a no-match, not a parse failure.
#[test]
fn a_well_formed_typo_still_parses_and_still_never_matches() {
    let lookup = StubLookup::answering("RU");
    let typo: GeoLocation = "RUUU".parse().expect("a well-formed typo still parses");
    assert_eq!(
        typo.matches_ip(client_ip(), Some(&lookup)),
        GeoMatch::No,
        "a typo must never match a real country code"
    );
}

/// A spec with no country cannot describe a location, so it is rejected instead
/// of becoming a rule that matches nothing with no diagnostic.
#[test]
fn a_missing_country_is_rejected_rather_than_matching_nothing() {
    for target in ["", "   ", ",", ",,,", " , , , "] {
        let error = target
            .parse::<GeoLocation>()
            .expect_err("a spec with no country must not parse");
        assert!(
            error.contains("country"),
            "the error must say the country is required, got: {error}"
        );
    }
}

/// The unparseable-ASN half of the old defect. A non-empty ASN field that is
/// not a number is a typo, and it is now an error instead of a silently dropped
/// constraint that widened the rule.
#[test]
fn a_malformed_asn_is_rejected_rather_than_silently_broadening_the_rule() {
    for target in [
        "RU, , , notanumber",
        "RU, , , 99999999999", // beyond u32
        "RU, , , -1",
        "RU, , , 64500x",
    ] {
        let error = target
            .parse::<GeoLocation>()
            .expect_err("a malformed ASN must not parse");
        assert!(
            error.contains("ASN"),
            "the error must name the ASN field, got: {error}"
        );
    }
}

/// Phase 135 F-16 must survive the tightening: an **empty** ASN field is a
/// placeholder, not a typo. Treating empty as an error would have been a
/// regression of the opposite kind, breaking a spec shape that F-16 deliberately
/// supports.
#[test]
fn an_empty_asn_field_stays_a_placeholder() {
    for target in ["RU, , , ", "RU, , ,", "RU, ,"] {
        let geo: GeoLocation = target.parse().expect("a placeholder ASN still parses");
        assert_eq!(geo.country, "RU");
        assert_eq!(
            geo.asn, None,
            "an empty ASN field is a placeholder, got {target:?}"
        );
    }
}

/// The arm at `firewall.rs` that handles a parse failure was described from
/// Phase 133 onward as defensive-only, kept "because a future validator would
/// land here". That validator is the parser, so the arm is now live — and a
/// restrictive rule with a malformed target must take the same fail-closed
/// posture as any other unevaluable geo rule rather than passing traffic.
#[test]
fn a_restrictive_rule_with_a_malformed_target_fails_closed() {
    let mut firewall = DnsFirewall::new().with_country_lookup(StubLookup::answering("RU"));
    firewall
        .add_rule(rule(
            "geo-typo",
            DnsFirewallRuleType::GeoLocation,
            "RU, , , notanumber",
            DnsFirewallAction::Block,
        ))
        .expect("the firewall stores a rule verbatim; it validates at evaluation");

    let query = example_query();
    let decision = firewall
        .evaluate_query(&parse(&query), client_ip(), "example.com")
        .expect("evaluation succeeds");

    assert_eq!(
        decision.action,
        DnsFirewallAction::Block,
        "a malformed geo target must not silently pass traffic"
    );
    assert_eq!(decision.rule_id, "geo-typo");
    assert!(
        decision
            .reason
            .contains(RuleIndeterminate::UnparseableTarget.as_str()),
        "the reason must name the unparseable target, got: {}",
        decision.reason
    );
}

/// The permissive counterpart: a malformed target on an `Allow` rule is skipped
/// rather than applied. Granting access from a rule nobody could scope is the
/// same hazard the no-provider case already pins.
#[test]
fn a_permissive_rule_with_a_malformed_target_is_skipped() {
    let mut firewall = DnsFirewall::new().with_country_lookup(StubLookup::answering("RU"));
    firewall
        .add_rule(rule(
            "geo-typo-allow",
            DnsFirewallRuleType::GeoLocation,
            "notanumber",
            DnsFirewallAction::Allow,
        ))
        .expect("the firewall stores a rule verbatim; it validates at evaluation");

    let query = example_query();
    let decision = firewall
        .evaluate_query(&parse(&query), client_ip(), "example.com")
        .expect("evaluation succeeds");

    assert_eq!(
        decision.action,
        DnsFirewallAction::Allow,
        "the default posture applies and the malformed allow rule is skipped"
    );
    assert_ne!(
        decision.rule_id, "geo-typo-allow",
        "a malformed allow rule must not be the deciding rule"
    );
}

/// Phase 135 F-16: the ASN lives at index 3, so a country+ASN rule must spell
/// out indices 1 and 2. Those placeholders used to become `Some("")` and then
/// fail the region and city comparisons, which made an ASN-scoped rule
/// unmatchable however it was written. An empty field is now a placeholder, not
/// a value.
#[test]
fn an_empty_field_is_a_placeholder_rather_than_an_empty_value() {
    let asn_only: GeoLocation = "RU, , , 64500".parse().expect("parses");
    assert_eq!(asn_only.country, "RU");
    assert_eq!(
        asn_only.region, None,
        "a placeholder must not become an empty region to match against"
    );
    assert_eq!(asn_only.city, None);
    assert_eq!(asn_only.asn, Some(64500));
}

/// `contains` is the convenience wrapper and must not resurrect the F-2 defect
/// by collapsing `Unavailable` into a match.
#[test]
fn contains_is_false_when_unavailable_but_matches_ip_reports_why() {
    let geo: GeoLocation = "RU".parse().expect("parses");
    assert!(!geo.contains(client_ip(), None));
    assert_eq!(geo.matches_ip(client_ip(), None), GeoMatch::Unavailable);
}
