//! Phase 133 Workstream B — GeoIP **consumer** evidence inside `synvoid-dns`.
//!
//! The provider suite (`crates/synvoid-geoip/tests/geoip_provider_evidence.rs`)
//! proves what a real database answers. This suite proves what `synvoid-dns`
//! *does* with the answer, and — more importantly — what it does when the
//! answer is unavailable. The plan makes the absent-provider case the
//! central question: "a rule that cannot be evaluated must not silently pass
//! traffic."
//!
//! Scope note: a `GeoLocation` rule's *positive* match requires a real MaxMind
//! database, which lives in the `synvoid-geoip` test fixtures. Rather than
//! duplicate that builder, the positive matrix is pinned provider-side and
//! recorded here as finding F-4. Once Phase 135 introduces a DNS-owned lookup
//! trait, the positive matrix becomes directly testable in this crate with a
//! DNS-owned double and no `synvoid-geoip` edge.

use std::net::{IpAddr, Ipv4Addr};

use synvoid_dns::firewall::GeoLocation;
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

// ---- Workstream B.5 — deterministic fallback for the absent provider -------

/// B-5a (F-2): a `GeoLocation` **block** rule with no provider configured does
/// not match, so evaluation falls through to the default `Allow`. The security
/// control silently disappears: an operator who configures a country block and
/// has no GeoIP database gets no error, no log line, and no traffic blocked.
///
/// This is the plan's "rule that cannot be evaluated must not silently pass
/// traffic" case, and today it does silently pass traffic.
#[test]
fn geo_block_rule_without_provider_silently_allows() {
    let mut firewall = DnsFirewall::new();
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
        "a geo block rule with no provider evaluates to the default Allow"
    );
    assert_eq!(decision.rule_id, "default");
    assert!(
        !decision.reason.contains("geo-block"),
        "the silently-skipped rule must not be named in the decision, which is \
         why the failure is invisible: got reason {:?}",
        decision.reason
    );
}

/// B-5b (F-5): the "provider present but unable to answer" case is **not**
/// directly testable from this crate, and the reason is itself the finding.
///
/// `GeoIpManager::new` takes a `synvoid_config::geoip::GeoIpConfig`, and
/// Phase 125 removed `synvoid-config` from `synvoid-dns` entirely. A provider
/// can therefore only reach this crate through a composition root that holds
/// both types. Constructing one here would mean re-adding the very edge this
/// campaign is removing.
///
/// The outcome is nonetheless determined, and pinned on both sides:
/// `GeoIpManager::get_country_info` returns `None` for every address when no
/// database is loaded (see `enabled_config_without_database_path_answers_none`
/// in the `synvoid-geoip` suite), and `GeoLocation::matches_ip` returns `false`
/// on `None` (B-5c). The two compose to the same fail-open result as B-5a.
#[test]
fn the_answerless_provider_case_is_unreachable_from_this_crate() {
    // The assertion is about the crate's own dependency surface, which is what
    // makes the case unreachable. `synvoid-config` is absent, so no
    // `GeoIpConfig` — and therefore no `GeoIpManager` — can be built here.
    //
    // This stays true after Phase 135 removes the `synvoid-geoip` edge: the
    // provider is then a DNS-owned trait object, which is even more obviously
    // not constructible from configuration here.
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("synvoid-config"),
        "synvoid-dns must not depend on synvoid-config; if this ever changes, \
         the answerless-provider case becomes testable here and B-5a should be \
         extended to cover it directly"
    );
}

/// B-5c: `GeoLocation::contains` returns `false` for every geo rule when no
/// provider is present, so the caller cannot distinguish an unevaluable rule
/// from a non-matching one.
#[test]
fn contains_is_false_for_every_geo_rule_without_a_provider() {
    let ip = client_ip();

    for target in [
        "RU",
        "US",
        "US, California",
        "US, California, Mountain View",
        "US, CA, SF, 15169",
    ] {
        let geo: GeoLocation = target.parse().expect("parses");
        assert!(
            !geo.contains(ip, None),
            "geo rule `{target}` must not match without a provider"
        );
        assert!(!geo.matches_ip(ip, None), "matches_ip agrees with contains");
    }
}

// ---- Workstream B.4 — rule evaluation order -------------------------------

/// B-4a: there is no `Health` rule type in the DNS firewall —
/// `DnsFirewallRuleType` is Domain, IpAddress, Subnet, QueryType, Opcode,
/// ResponseCode, GeoLocation, TimeWindow. `synvoid_dns::health` reports server
/// state and takes no part in query evaluation. What the firewall actually
/// has is first-match-in-insertion-order, and this pins it.
#[test]
fn evaluation_is_first_match_in_insertion_order() {
    let mut firewall = DnsFirewall::new();
    // Geo rule first: it cannot be evaluated, so the later domain rule wins.
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
        decision.rule_id, "domain-block",
        "an unevaluable rule is skipped, not treated as a match"
    );
    assert_eq!(decision.action, DnsFirewallAction::Block);
}

/// B-4b: order is the only thing that decides, so the same two rules in the
/// opposite order give the opposite outcome. This is what makes the B-5a
/// fail-open reachable in production: a geo rule placed *after* a matching
/// allow rule never runs, and a geo rule placed first is silently skipped.
#[test]
fn rule_order_is_the_only_tiebreak() {
    let mut firewall = DnsFirewall::new();
    firewall
        .add_rule(rule(
            "domain-allow",
            DnsFirewallRuleType::Domain,
            "example.com",
            DnsFirewallAction::Allow,
        ))
        .expect("rule accepted");
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

    assert_eq!(decision.rule_id, "domain-allow");
    assert_eq!(decision.action, DnsFirewallAction::Allow);
}

/// B-4c: a *disabled* geo rule is skipped, which is the only supported way to
/// park a geo control that cannot currently be evaluated. Recorded because it
/// is the operator's only recourse given B-5a.
#[test]
fn a_disabled_geo_rule_is_skipped() {
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
}

// ---- Workstream B.6 — `GeoLocation` shape ---------------------------------

/// B-6a: `GeoLocation` is DNS-owned and holds only primitives — `String`,
/// `Option<String>`, `Option<u32>`. No `synvoid-geoip` type appears in it, so
/// the *rule* half of the seam is already inversion-ready; only the parameter
/// of `contains` still names the provider.
#[test]
fn geo_location_is_dns_owned_and_holds_only_primitives() {
    let geo: GeoLocation = "US, California, Mountain View, 15169"
        .parse()
        .expect("parses");
    assert_eq!(geo.country, "US");
    assert_eq!(geo.region.as_deref(), Some("California"));
    assert_eq!(geo.city.as_deref(), Some("Mountain View"));
    assert_eq!(geo.asn, Some(15169));

    // Bare country, and country + region.
    let bare: GeoLocation = "DE".parse().expect("parses");
    assert_eq!(bare.country, "DE");
    assert!(bare.region.is_none());
    assert!(bare.city.is_none());
    assert!(bare.asn.is_none());
}

/// B-6b: the seam is exactly two provider methods. `GeoLocation::matches_ip`
/// calls `get_country_info` and `get_asn_info`; nothing else in the firewall
/// touches the provider. Pinned at the source level because a *third* call
/// would silently widen the Phase 135 trait surface.
#[test]
fn the_firewall_calls_exactly_two_provider_methods() {
    let src = include_str!("../src/firewall.rs");

    let provider_calls: Vec<&str> = src
        .lines()
        .flat_map(|line| {
            let mut found = Vec::new();
            for method in ["get_country_info", "get_asn_info"] {
                if line.contains(&format!(".{method}(")) {
                    found.push(method);
                }
            }
            found
        })
        .collect();
    assert_eq!(
        provider_calls,
        vec!["get_country_info", "get_asn_info"],
        "the DNS firewall's entire provider surface"
    );

    // No other `synvoid_geoip` symbol is reachable from the firewall beyond the
    // manager type in the `Option<...>` parameter.
    for symbol in [
        "lookup_country",
        "lookup_asn",
        "get_continent_code",
        "check_ip",
        "status()",
        "AsnInfo",
        "CountryInfo",
        "GeoIpResult",
    ] {
        assert!(
            !src.contains(symbol),
            "firewall.rs must not reach `{symbol}`: it would widen the seam"
        );
    }
}

/// B-6c (F-3): `GeoLocation::from_str` cannot fail. `"".split(',')` always
/// yields at least one element, so the `parts.is_empty()` guard is
/// unreachable, and a misspelled target becomes a country code that matches
/// nothing. The `if let Ok(geo)` guard in `rule_matches` is therefore dead
/// defensive code, and a typo degrades a security rule into a no-op with no
/// diagnostic.
#[test]
fn geo_location_parsing_cannot_fail_and_typos_never_match() {
    assert!("".parse::<GeoLocation>().is_ok(), "empty target parses");
    assert!(
        "  ,  ,  , notanumber".parse::<GeoLocation>().is_ok(),
        "garbage target parses"
    );

    let typo: GeoLocation = "RUUU".parse().expect("parses");
    assert_eq!(typo.country, "RUUU");
    assert!(
        !typo.contains(client_ip(), None),
        "and never matches, with no error surfaced"
    );

    let bad_asn: GeoLocation = "US, CA, SF, notanumber".parse().expect("parses");
    assert_eq!(
        bad_asn.asn, None,
        "an unparseable ASN is silently dropped rather than rejected"
    );
}
