//! Phase 133 Workstream B — GeoIP **provider** evidence.
//!
//! The plan requires proving what `GeoIpManager` actually returns to its
//! callers, not what its type signature suggests. This suite uses a real
//! MaxMind database image built by [`support::mmdb`] so that covered,
//! uncovered, and partially-populated addresses are genuinely distinct —
//! without it, "no database" and "database with no record" collapse into the
//! same uninformative `None`.
//!
//! Scope note: the consumer side of the seam (what `synvoid-dns` does with the
//! answer) lives in `crates/synvoid-dns/tests/geoip_rule_evidence.rs`. The
//! positive-match matrix is pinned here because that is where a real database
//! exists; see the Phase 133 closeout finding F-4.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use support::mmdb::{array, build, map, string, uint16, Record};
use synvoid_config::geoip::GeoIpConfig;
use synvoid_geoip::GeoIpManager;

const US_NET: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 0);
const RU_NET: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 0);
const BARE_NET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 0);
const NO_COUNTRY_NET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 0);

/// A full GeoIP2-City-shaped record for the United States.
fn us_record() -> Vec<u8> {
    map(&[
        (
            "country",
            map(&[
                ("iso_code", string("US")),
                ("names", map(&[("en", string("United States"))])),
            ]),
        ),
        (
            "subdivisions",
            array(&[map(&[("names", map(&[("en", string("California"))]))])]),
        ),
        (
            "city",
            map(&[("names", map(&[("en", string("Mountain View"))]))]),
        ),
        ("autonomous_system_number", uint16(15169)),
        ("autonomous_system_organization", string("GOOGLE")),
    ])
}

/// A country-only record: no subdivision, no city, no ASN.
fn ru_record() -> Vec<u8> {
    map(&[(
        "country",
        map(&[
            ("iso_code", string("RU")),
            ("names", map(&[("en", string("Russia"))])),
        ]),
    )])
}

/// A record whose country has an `iso_code` but no `names` map.
fn bare_iso_code_record() -> Vec<u8> {
    map(&[("country", map(&[("iso_code", string("DE"))]))])
}

/// A record with an ASN but no country at all.
fn asn_only_record() -> Vec<u8> {
    map(&[
        ("autonomous_system_number", uint16(64500)),
        ("autonomous_system_organization", string("EXAMPLE-AS")),
    ])
}

fn fixture_database() -> Vec<u8> {
    build(&[
        Record::new(US_NET, 24, us_record()),
        Record::new(RU_NET, 24, ru_record()),
        Record::new(BARE_NET, 24, bare_iso_code_record()),
        Record::new(NO_COUNTRY_NET, 24, asn_only_record()),
    ])
}

fn write_fixture(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("synvoid-phase133-{name}.mmdb"));
    std::fs::write(&path, fixture_database()).expect("write fixture database");
    path
}

fn manager_with_database(path: &std::path::Path) -> Arc<GeoIpManager> {
    let config = GeoIpConfig {
        enabled: true,
        database_path: Some(path.to_string_lossy().into_owned()),
        update_enabled: false,
        // See F-1: a non-empty `edition_ids` with no download credentials
        // panics inside `GeoIpUpdater::new`. These suites are about the lookup
        // surface, so they configure no auto-update editions at all.
        edition_ids: Vec::new(),
        ..Default::default()
    };
    Arc::new(GeoIpManager::new(config, &[], None).expect("enabled GeoIP config yields a manager"))
}

fn ip(v: Ipv4Addr) -> IpAddr {
    IpAddr::V4(v)
}

// ---- Workstream B.1 — missing database -------------------------------------

/// B-1a: `enabled = false` yields no manager at all, so every DNS-side
/// `Option<Arc<GeoIpManager>>` site becomes `None`. This is the shape the
/// consumer has to tolerate.
#[test]
fn disabled_config_yields_no_manager() {
    let config = GeoIpConfig {
        enabled: false,
        ..Default::default()
    };
    assert!(
        GeoIpManager::new(config, &[], None).is_none(),
        "a disabled GeoIP section must not produce a provider"
    );
}

/// B-1b: enabled with no `database_path` produces a provider whose lookups all
/// answer `None`. A provider that exists but cannot answer is materially
/// different from no provider, and `GeoIpManager::status()` is the only place
/// that difference is visible.
#[test]
fn enabled_config_without_database_path_answers_none() {
    let config = GeoIpConfig {
        enabled: true,
        database_path: None,
        update_enabled: false,
        edition_ids: Vec::new(),
        ..Default::default()
    };
    let manager = GeoIpManager::new(config, &[], None).expect("enabled config yields a manager");

    assert!(manager.get_country_info(ip(US_NET)).is_none());
    assert!(manager.get_asn_info(ip(US_NET)).is_none());

    let status = manager.status();
    assert!(status.enabled, "provider exists");
    assert!(
        !status.database_loaded,
        "but reports no database, which is the only way a caller can tell"
    );
}

/// B-1c: a `database_path` pointing at a nonexistent file is treated as
/// "no database", not as a startup error. `GeoIpLookup::new` returns
/// `Ok { reader: None }` for a missing path, so a typo in the path silently
/// disables every geo control.
#[test]
fn missing_database_file_is_treated_as_absent_not_as_an_error() {
    let path = std::env::temp_dir().join("synvoid-phase133-does-not-exist.mmdb");
    assert!(!path.exists());
    let manager = manager_with_database(&path);

    assert!(!manager.status().database_loaded);
    assert!(manager.get_country_info(ip(US_NET)).is_none());
}

// ---- Workstream B.2 — known and unknown locations --------------------------

/// B-2a: a covered address yields every field the DNS firewall reads.
#[test]
fn covered_address_resolves_every_field_the_firewall_reads() {
    let path = write_fixture("full");
    let manager = manager_with_database(&path);
    assert!(manager.status().database_loaded, "fixture must load");

    let info = manager
        .get_country_info(ip(Ipv4Addr::new(8, 8, 8, 8)))
        .expect("8.8.8.8 is inside 8.8.8.0/24");
    assert_eq!(info.code, "US");
    assert_eq!(info.name, "United States");
    assert_eq!(info.subdivision.as_deref(), Some("California"));
    assert_eq!(info.city.as_deref(), Some("Mountain View"));

    let asn = manager
        .get_asn_info(ip(Ipv4Addr::new(8, 8, 8, 8)))
        .expect("the US record carries an ASN");
    assert_eq!(asn.asn, 15169);
    assert_eq!(asn.organization, "GOOGLE");

    let _ = std::fs::remove_file(&path);
}

/// B-2b: an address outside every inserted network resolves to nothing, and
/// does so through the same `None` as a missing database. Callers therefore
/// cannot distinguish "unknown location" from "no provider configured".
#[test]
fn uncovered_address_resolves_nothing() {
    let path = write_fixture("uncovered");
    let manager = manager_with_database(&path);

    assert!(manager.status().database_loaded);
    assert!(manager
        .get_country_info(ip(Ipv4Addr::new(172, 16, 0, 1)))
        .is_none());
    assert!(manager
        .get_asn_info(ip(Ipv4Addr::new(172, 16, 0, 1)))
        .is_none());
}

/// B-2c: a record that carries only a country still answers `get_country_info`,
/// with `subdivision` and `city` absent. This is the shape a
/// GeoLite2-Country database produces, so region- and city-scoped DNS
/// firewall rules are unmatchable against one.
#[test]
fn country_only_record_omits_subdivision_and_city() {
    let path = write_fixture("country-only");
    let manager = manager_with_database(&path);

    let info = manager
        .get_country_info(ip(Ipv4Addr::new(203, 0, 113, 7)))
        .expect("203.0.113.0/24 carries a country");
    assert_eq!(info.code, "RU");
    assert_eq!(info.name, "Russia");
    assert!(info.subdivision.is_none());
    assert!(info.city.is_none());
    assert!(
        manager
            .get_asn_info(ip(Ipv4Addr::new(203, 0, 113, 7)))
            .is_none(),
        "and carries no ASN, so an ASN-scoped rule cannot match it"
    );

    let _ = std::fs::remove_file(&path);
}

/// B-2d: an IPv6 client against an IPv4-only database resolves to nothing.
/// `Reader::lookup` rejects IPv6 on an `ip_version = 4` database, so every
/// IPv6 client silently fails every GeoLocation rule.
#[test]
fn ipv6_client_against_an_ipv4_only_database_resolves_nothing() {
    let path = write_fixture("ipv6");
    let manager = manager_with_database(&path);

    let v6: IpAddr = "2001:db8::1".parse().expect("valid IPv6 literal");
    assert!(manager.get_country_info(v6).is_none());
    assert!(manager.get_asn_info(v6).is_none());

    let _ = std::fs::remove_file(&path);
}

// ---- Finding F-9: the two country lookups cannot disagree -------------------

/// F-9: `GeoIpManager::get_country_info` applies `?` to both
/// `lookup_country` and `lookup_country_info`, which reads as if a partial hit
/// could yield `None`. It cannot. Both decode the *same* path,
/// `country.iso_code`, and `lookup_country_info` substitutes `name = code`
/// when `country.names` is absent.
///
/// A record with an `iso_code` and no `names` map therefore answers, which
/// makes the second lookup a redundant database traversal on every request
/// rather than a correctness guard. Recorded here because Phase 135 replaces
/// this method and should not inherit a guard that cannot fire.
#[test]
fn a_bare_iso_code_record_answers_with_the_code_as_its_name() {
    let path = write_fixture("bare-iso");
    let manager = manager_with_database(&path);

    let info = manager
        .get_country_info(ip(Ipv4Addr::new(198, 51, 100, 5)))
        .expect("country.iso_code alone is sufficient to answer");
    assert_eq!(info.code, "DE");
    assert_eq!(
        info.name, "DE",
        "the name falls back to the code when names.en is absent"
    );
    assert!(info.subdivision.is_none());
    assert!(info.city.is_none());

    // And the converse: a record with a country but no ASN still answers for
    // the country while `get_asn_info` is `None`, so the two are independent.
    let asn_only = manager
        .get_asn_info(ip(Ipv4Addr::new(192, 0, 2, 5)))
        .expect("the ASN-only record carries an ASN");
    assert_eq!(asn_only.asn, 64500);
    assert_eq!(asn_only.organization, "EXAMPLE-AS");
    assert!(
        manager
            .get_country_info(ip(Ipv4Addr::new(192, 0, 2, 5)))
            .is_none(),
        "a record with no country yields no country, independently of the ASN"
    );

    let _ = std::fs::remove_file(&path);
}

/// F-10: the firewall reads only `AsnInfo::asn` and discards
/// `AsnInfo::organization`. The inversion trait therefore needs an
/// `Option<u32>`, not the provider's struct — a narrower seam than Phase 130
/// assumed, and one that cannot leak provider types into `synvoid-dns`.
#[test]
fn the_asn_seam_only_needs_the_asn_number() {
    let pki = std::env::temp_dir().join("synvoid-phase133-asn-shape.mmdb");
    std::fs::write(&pki, fixture_database()).expect("write fixture");
    let manager = manager_with_database(&pki);

    let info = manager
        .get_asn_info(ip(Ipv4Addr::new(8, 8, 8, 8)))
        .expect("the US record carries an ASN");
    // The firewall's use is `asn_info.asn != asn`; `organization` is unused.
    assert_eq!(info.asn, 15169);
    let _ = std::fs::remove_file(&pki);
}

// ---- Finding F-1: provider construction is not total -----------------------

/// F-1: `GeoIpUpdater::new` dereferences `DownloadSource::from_config(config)`
/// with `.unwrap()`, and that function returns `None` unless `update_url` or
/// (`account_id` **and** `license_key`) is set. So `[geoip] enabled = true`
/// with no download credentials aborts the process during provider
/// construction — even with `update_enabled = false`, and even though a
/// `None` source already means "there is nothing to download".
///
/// This pins the current behavior so the defect cannot be lost, and so
/// Phase 135 fixes it against a test that fails loudly if it regresses to a
/// different failure mode. The fix belongs to Phase 135, which owns GeoIP
/// provider construction; Phase 133 changes no production behavior.
///
/// The panic message is asserted rather than ignored so that a future fix
/// turns this test into a loud, deliberate signal (`FAILED`/`should_panic`
/// mismatch) instead of a silent pass.
#[test]
#[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
fn enabled_config_without_download_credentials_panics_during_construction() {
    let config = GeoIpConfig {
        enabled: true,
        database_path: None,
        update_enabled: false,
        // Default `edition_ids` is non-empty, which is what enters the
        // panicking `filter_map`.
        ..Default::default()
    };
    let _ = GeoIpManager::new(config, &[], None);
}

// ---- Workstream B.3 — privacy / logging -------------------------------------

/// B-3: the lookup path never logs the queried address. `get_country_info` and
/// `get_asn_info` are called per request from the DNS query path, so any
/// logging added here would turn a country lookup into a client-IP disclosure
/// channel.
#[test]
fn lookup_path_never_logs_the_queried_address() {
    let lookup_src = include_str!("../src/lookup.rs");
    let manager_src = include_str!("../src/manager.rs");

    // `src/lookup.rs` is the only module that touches a raw address, so it
    // must not reach any logging or printing sink at all. (`format!` is not
    // checked here: it is used to build database *file path* errors, which
    // disclose no client address.)
    for sink in ["tracing::", "log::", "println!", "eprintln!", "dbg!"] {
        assert!(
            !lookup_src.contains(sink),
            "src/lookup.rs must not contain `{sink}`: it is the address-touching module"
        );
    }

    // The two methods `synvoid-dns` calls, plus every per-address lookup they
    // delegate to, must be pure reads.
    let address_taking: &[(&str, &str)] = &[
        (manager_src, "get_country_info"),
        (manager_src, "get_asn_info"),
        (lookup_src, "lookup_country"),
        (lookup_src, "lookup_country_info"),
        (lookup_src, "lookup_subdivision"),
        (lookup_src, "lookup_city"),
        (lookup_src, "lookup_asn"),
    ];
    for (source, name) in address_taking {
        let body = function_body(source, name);
        for sink in ["tracing::", "log::", "println!", "eprintln!", "dbg!"] {
            assert!(
                !body.contains(sink),
                "`{name}` must not contain `{sink}`: it receives a client address"
            );
        }
    }
}

/// Extract a top-level `fn <name>(...) { .. }` body by brace matching.
fn function_body(src: &str, name: &str) -> String {
    let signature = format!("pub fn {name}(");
    let start = src
        .find(&signature)
        .unwrap_or_else(|| panic!("`{signature}` not found in manager.rs"));
    let open = src[start..]
        .find('{')
        .map(|offset| start + offset)
        .expect("function body opens with a brace");

    let mut depth = 0usize;
    for (index, byte) in src[open..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open..=open + index].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces in `{signature}`");
}
