//! Phase 138 — `[geoip]` is a real configuration section.
//!
//! ## The defect this pins
//!
//! `GeoIpConfig` was declared in this crate, exported, and consumed by
//! `synvoid-geoip`'s API signatures — but **no configuration struct owned a
//! `geoip` field**. `MainConfig` had none, and neither did `SiteSecurityConfig`.
//! A `[geoip]` section in `main.toml` therefore did not deserialize into
//! anything, and composition had no source from which to build a `GeoIpManager`.
//!
//! That is strictly worse than "declared but unowned": the type looks
//! configurable, so an operator can reasonably write `[geoip]` and observe no
//! effect and no diagnostic. Phase 138 gave `MainConfig` the field, which is
//! what makes the DNS geo wiring reachable at all.
//!
//! These tests assert the *persisted* schema, which is what this crate owns; the
//! runtime projection and the seam itself are asserted in
//! `crates/synvoid-dns/tests/geoip_composition_wiring.rs`.
//!
//! ## Why the fixtures are derived rather than hand-written
//!
//! `MainConfig` has required fields with no `#[serde(default)]` — `server`
//! (which in turn requires `host` and `port`), `fallback`, and others. A
//! hand-written minimal document would therefore be brittle for reasons that
//! have nothing to do with `[geoip]`, and would break whenever an unrelated
//! required field is added. Each test here starts from `MainConfig::default()`,
//! serialises it, and mutates only the `geoip` key — so the assertions stay
//! about `[geoip]` and the round trip is the real one an operator performs.

use synvoid_config::geoip::GeoIpConfig;
use synvoid_config::MainConfig;

fn main_config_toml() -> String {
    toml::to_string_pretty(&MainConfig::default()).expect("MainConfig serialises to TOML")
}

/// `MainConfig` must actually own the field. Without it the type is unreachable
/// from any configuration file and the whole wiring is dead on arrival.
#[test]
fn main_config_serializes_a_geoip_table() {
    let document = main_config_toml();

    assert!(
        document.contains("[geoip]"),
        "the serialised main config must contain a [geoip] table; got:\n{document}"
    );

    // And it must parse back, so the section is genuinely round-trippable
    // through the TOML an operator edits.
    let reparsed: MainConfig =
        toml::from_str(&document).expect("the serialised form must parse back");
    assert!(!reparsed.geoip.enabled, "the default must be disabled");
}

/// The positive case: a configured section reaches `MainConfig` with its values
/// intact, which is what lets composition build a provider.
#[test]
fn a_geoip_section_parses_into_main_config() {
    let mut value = serde_json::to_value(MainConfig::default()).expect("serialises");
    value["geoip"] = serde_json::json!({
        "enabled": true,
        "database_path": "/var/lib/synvoid/geoip/GeoLite2-City.mmdb",
        "block_countries": ["RU"],
        "allow_countries": ["US", "CA"],
    });

    let config: MainConfig =
        serde_json::from_value(value).expect("a MainConfig carrying a [geoip] section must parse");

    assert!(config.geoip.enabled);
    assert_eq!(
        config.geoip.database_path.as_deref(),
        Some("/var/lib/synvoid/geoip/GeoLite2-City.mmdb")
    );
    assert_eq!(config.geoip.block_countries, vec!["RU".to_string()]);
    assert_eq!(
        config.geoip.allow_countries,
        vec!["US".to_string(), "CA".to_string()]
    );
}

/// The backward-compatibility guarantee that made this change safe: a document
/// that does not mention the section still parses, and yields a **disabled**
/// one. `enabled` defaults to `false`, so no existing deployment starts
/// constructing a provider — the change is strictly opt-in.
#[test]
fn an_absent_geoip_section_defaults_to_disabled() {
    let mut value = serde_json::to_value(MainConfig::default()).expect("serialises");
    value
        .as_object_mut()
        .expect("MainConfig serialises to an object")
        .remove("geoip");

    let config: MainConfig = serde_json::from_value(value)
        .expect("a MainConfig with no [geoip] section must still parse");

    assert!(
        !config.geoip.enabled,
        "an absent [geoip] section must deserialize as disabled rather than fail"
    );
    assert_eq!(config.geoip.database_path, None);
}

/// The hazard this crate already carries elsewhere: a `#[derive(Default)]` that
/// disagrees with `#[serde(default = "...")]` makes an absent key and a Rust
/// default mean different things. `architecture/dns_config_runtime_matrix.md`
/// records that defect for `DnsFirewallConfig`.
///
/// `GeoIpConfig` is safe here **only because it has a hand-written `Default`**
/// that spells out the serde default functions. This test fails the moment
/// someone replaces it with a derive.
#[test]
fn the_hand_written_default_agrees_with_every_serde_default() {
    let absent = GeoIpConfig::default();
    let parsed: GeoIpConfig =
        toml::from_str("").unwrap_or_else(|e| panic!("an empty section must parse: {e}"));

    assert_eq!(absent.log_blocked, parsed.log_blocked);
    assert_eq!(absent.update_interval_hours, parsed.update_interval_hours);
    assert_eq!(absent.edition_ids, parsed.edition_ids);
    assert_eq!(absent.download_timeout_secs, parsed.download_timeout_secs);
    assert_eq!(absent.max_retries, parsed.max_retries);
    assert_eq!(absent.stale_threshold_days, parsed.stale_threshold_days);
    assert_eq!(absent.backoff_base_secs, parsed.backoff_base_secs);

    // `log_blocked` is where a derived `Default` would most visibly disagree:
    // serde says `true`, a derive would say `false`.
    assert!(
        absent.log_blocked,
        "`log_blocked` must default to true in Rust as well as in serde"
    );
    assert!(!absent.enabled, "the section must be opt-in");
    assert!(!absent.update_enabled, "auto-update must be opt-in");
}

/// The admin config endpoint's representation. `GET /config/main` serialises the
/// whole `MainConfig` into a `serde_json::Value` and `PUT` deserialises it back,
/// so the field must survive that round trip — otherwise an operator editing
/// the config through the admin UI would silently drop the section on save.
#[test]
fn the_field_survives_the_admin_json_round_trip() {
    let mut value = serde_json::to_value(MainConfig::default()).expect("serialises");
    value["geoip"]["enabled"] = serde_json::json!(true);
    value["geoip"]["database_path"] = serde_json::json!("/tmp/GeoLite2-City.mmdb");

    let restored: MainConfig =
        serde_json::from_value(value).expect("MainConfig deserialises from JSON");

    assert!(restored.geoip.enabled, "an enabled section must survive");
    assert_eq!(
        restored.geoip.database_path.as_deref(),
        Some("/tmp/GeoLite2-City.mmdb")
    );
}
