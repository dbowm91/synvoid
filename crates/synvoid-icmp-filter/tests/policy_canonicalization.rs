//! Phase 85 required tests: canonicalization, conversion, validation,
//! scope, and the no-JSON-bridge source invariant.

use std::net::IpAddr;
use synvoid_icmp_filter::{
    adapt_config_to_policy,
    config::{Direction, FilterType, IcmpAction, IcmpFilterConfig, IcmpTypeRule, InterfaceSpec},
    policy::{
        IcmpFamily, IcmpPolicy, IcmpRule, IcmpSelector, IcmpV6Type, IcmpVerdict, PolicyDirection,
        RateLimitPolicy,
    },
    validation::{validate_policy, FindingSeverity, ValidationOverride, ValidationRole},
};

// 1. Legacy/default TOML round-trip (enforcement DTO keeps wire compat).
#[test]
fn legacy_default_toml_round_trip() {
    let cfg = IcmpFilterConfig::new();
    let toml_str = toml::to_string_pretty(&cfg).expect("DTO must serialize to TOML");
    let back: IcmpFilterConfig = toml::from_str(&toml_str).expect("DTO must deserialize from TOML");
    assert!(back.interfaces.is_all());
    assert!(back.rate_limit.is_none());
}

// 1b. Legacy underscore table + PascalCase enums still read.
#[test]
fn legacy_spellings_accepted() {
    let toml_str = r#"
table_name = "synvoid_icmp"
filter_type = "Nftables"
direction = "Both"
"#;
    let cfg: IcmpFilterConfig = toml::from_str(toml_str).expect("legacy spellings must read");
    assert_eq!(cfg.filter_type, FilterType::Nftables);
    assert_eq!(cfg.direction, Direction::Both);
    let (_, backend) = adapt_config_to_policy(&cfg).unwrap();
    // Canonicalized internally, not preserved as underscore.
    assert_eq!(backend.table_name, "synvoid-icmp");
}

// 1c. Golden legacy TOML fixture parses.
#[test]
fn golden_legacy_toml_fixture() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/legacy_default.toml"
    );
    let text = std::fs::read_to_string(path).expect("fixture must exist");
    let cfg: IcmpFilterConfig = toml::from_str(&text).expect("fixture must parse");
    assert!(!cfg.enabled);
    let (policy, _) = adapt_config_to_policy(&cfg).unwrap();
    assert!(policy.rules.is_empty());
    assert!(policy.rate_limit.is_none());
}

// 1d. Golden canonical policy JSON fixture round-trips.
#[test]
fn golden_canonical_policy_json_fixture() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/canonical_policy.json"
    );
    let text = std::fs::read_to_string(path).expect("fixture must exist");
    let policy: IcmpPolicy = serde_json::from_str(&text).expect("fixture must parse");
    assert_eq!(policy.direction, PolicyDirection::Both);
    assert_eq!(policy.rules.len(), 2);
    assert_eq!(policy.rules[0].selector.family(), IcmpFamily::V4);
    assert_eq!(policy.rules[1].selector.family(), IcmpFamily::V6);
    let back = serde_json::to_string(&policy).unwrap();
    let again: IcmpPolicy = serde_json::from_str(&back).unwrap();
    assert_eq!(policy, again);
    // PTB rule in the fixture must be flagged by validation.
    let findings = validate_policy(
        &policy,
        ValidationRole::Host,
        false,
        ValidationOverride::default(),
    );
    assert!(findings.iter().any(|f| f.code == "icmpv6_ptb_blocked"));
}

// 2. Admin JSON shape compatibility: legacy JSON without v6/scope fields.
#[test]
fn legacy_json_without_v6_list_reads() {
    let json = r#"{"enabled":false,"filter_type":"auto","direction":"both",
        "interfaces":null,"rate_limit":null,"exempt_ips":[],
        "table_name":"synvoid_icmp","icmp_type_rules":[]}"#;
    // Enforcement DTO never had a required v6 list; absence means zero v6 rules.
    let cfg: IcmpFilterConfig = serde_json::from_str(json).expect("legacy JSON must read");
    assert!(cfg.icmpv6_type_rules.is_empty());
    let (policy, _) = adapt_config_to_policy(&cfg).unwrap();
    assert!(policy.rules_for_family(IcmpFamily::V6).next().is_none());
}

// 3. Exhaustive conversion preserves direction/interfaces/exemptions.
#[test]
fn exhaustive_conversion_preserves_intent() {
    let cfg = IcmpFilterConfig::new()
        .with_filter_type(FilterType::Nftables)
        .with_direction(Direction::Inbound)
        .with_interfaces(InterfaceSpec::Specific(vec!["eth0".to_string()]))
        .with_exempt_ips(vec!["10.0.0.1".parse::<IpAddr>().unwrap()])
        .with_icmp_type_rules(vec![IcmpTypeRule::new(8, IcmpAction::Block)])
        .with_icmpv6_type_rules(vec![IcmpTypeRule::new(128, IcmpAction::Block)]);
    let (policy, backend) = adapt_config_to_policy(&cfg).unwrap();
    assert_eq!(policy.direction, PolicyDirection::Inbound);
    assert!(!policy.interfaces.is_all());
    assert_eq!(policy.exempt_ips.len(), 1);
    assert_eq!(policy.rules.len(), 2);
    assert_eq!(
        backend.requested,
        synvoid_icmp_filter::policy::RequestedBackend::Nftables
    );
    assert_eq!(backend.table_name, "synvoid-icmp");
}

// 4. Invalid IP/interface/backend-option rejection.
#[test]
fn invalid_inputs_rejected_with_typed_errors() {
    // Interface with illegal chars / overlong.
    let bad_iface = IcmpFilterConfig::new()
        .with_interfaces(InterfaceSpec::Specific(vec!["bad name!".to_string()]));
    let err = adapt_config_to_policy(&bad_iface).unwrap_err();
    assert!(matches!(
        err,
        synvoid_icmp_filter::compat::AdaptError::InvalidInterface(_)
            | synvoid_icmp_filter::compat::AdaptError::Inexpressible(_)
    ));

    // Enabled rate limit with zero pps is rejected, not silently disabled.
    let mut bad_rl = IcmpFilterConfig::new();
    bad_rl.rate_limit = Some(synvoid_icmp_filter::config::RateLimitConfig {
        enabled: true,
        packets_per_second: 0,
        burst: 5,
    });
    assert!(adapt_config_to_policy(&bad_rl).is_err());

    // Empty eBPF path is rejected.
    let mut bad_ebpf = IcmpFilterConfig::new();
    bad_ebpf.ebpf_bytecode_path = Some(String::new());
    assert!(adapt_config_to_policy(&bad_ebpf).is_err());
}

// 5. Family separation: same numeric type, different families.
#[test]
fn v4_v6_families_never_confused() {
    let cfg = IcmpFilterConfig::new()
        .with_icmp_type_rules(vec![IcmpTypeRule::new(8, IcmpAction::Block)])
        .with_icmpv6_type_rules(vec![IcmpTypeRule::new(8, IcmpAction::Block)]);
    let (policy, _) = adapt_config_to_policy(&cfg).unwrap();
    let v4: Vec<_> = policy.rules_for_family(IcmpFamily::V4).collect();
    let v6: Vec<_> = policy.rules_for_family(IcmpFamily::V6).collect();
    assert_eq!(v4.len(), 1);
    assert_eq!(v6.len(), 1);
    assert_ne!(v4[0].selector, v6[0].selector);
}

// 6. Named and raw type/code round-trip through the policy model.
#[test]
fn named_and_raw_round_trip() {
    let named = IcmpSelector::V6 {
        icmp_type: IcmpV6Type::PacketTooBig,
        code: None,
    };
    let raw = IcmpSelector::raw_v6(200, Some(3));
    for sel in [named, raw] {
        let json = serde_json::to_string(&sel).unwrap();
        let back: IcmpSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(sel, back);
    }
    let rule = IcmpRule::new(named, IcmpVerdict::Block);
    let json = serde_json::to_string(&rule).unwrap();
    let back: IcmpRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

// 7+8. RFC safety: ND + PTB findings; strict upgrades PTB to error.
#[test]
fn rfc_safety_findings_and_strict_ptb() {
    let mut policy = IcmpPolicy::default();
    policy.rules.push(IcmpRule::new(
        IcmpSelector::V6 {
            icmp_type: IcmpV6Type::PacketTooBig,
            code: None,
        },
        IcmpVerdict::Block,
    ));
    policy.rules.push(IcmpRule::new(
        IcmpSelector::V6 {
            icmp_type: IcmpV6Type::NeighborSolicitation,
            code: None,
        },
        IcmpVerdict::Block,
    ));
    let findings = validate_policy(
        &policy,
        ValidationRole::Host,
        false,
        ValidationOverride::default(),
    );
    assert!(findings.iter().any(|f| f.code == "icmpv6_ptb_blocked"));
    assert!(findings.iter().any(|f| f.code == "icmpv6_nd_blocked"));
    let strict = validate_policy(
        &policy,
        ValidationRole::Host,
        true,
        ValidationOverride::default(),
    );
    assert!(strict
        .iter()
        .any(|f| f.code == "icmpv6_ptb_blocked" && f.severity == FindingSeverity::Error));
    // Explicit override silences the hazard it names.
    let acked = validate_policy(
        &policy,
        ValidationRole::Host,
        true,
        ValidationOverride {
            allow_block_packet_too_big: true,
            ..Default::default()
        },
    );
    assert!(!acked.iter().any(|f| f.code == "icmpv6_ptb_blocked"));
}

// 9. Rate-limit scope serializes as explicit global; disabled maps to none.
#[test]
fn rate_limit_scope_explicit_global() {
    let mut cfg = IcmpFilterConfig::new();
    cfg.rate_limit = Some(synvoid_icmp_filter::config::RateLimitConfig {
        enabled: true,
        packets_per_second: 10,
        burst: 20,
    });
    let (policy, _) = adapt_config_to_policy(&cfg).unwrap();
    let rl = policy.rate_limit.expect("enabled limit must map");
    assert_eq!(rl, RateLimitPolicy::global(10, 20));
    let json = serde_json::to_string(&rl).unwrap();
    assert!(json.contains("global"));
}

// 10. No serde-Value bridge between the two IcmpFilterConfig models.
//
// Wire JSON (admin HTTP <-> one DTO) is legitimate. The prohibited pattern
// is model-to-model conversion through serde_json::Value. This test scans
// the active ICMP sources for that shape-coupled bridge.
#[test]
fn no_json_bridge_between_icmp_models() {
    let root = workspace_root();
    let files = [
        "src/admin/handlers/icmp.rs",
        "src/icmp_filter/mod.rs",
        "src/icmp_filter/adapt.rs",
        "crates/synvoid-icmp-filter/src/compat.rs",
        "crates/synvoid-icmp-filter/src/policy.rs",
        "crates/synvoid-icmp-filter/src/config.rs",
        "crates/synvoid-config/src/icmp_filter.rs",
    ];
    let mut violations = Vec::new();
    for rel in files {
        let path = root.join(rel);
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("source must exist: {rel}"));
        let stripped = strip_line_comments(&text);
        // Prohibited: serializing one model's value then deserializing as the
        // other model's IcmpFilterConfig (either direction).
        if stripped.contains("serde_json::to_value(cfg)")
            || stripped.contains("serde_json::to_value(&cfg)")
        {
            violations.push(format!("{rel}: to_value on enforcement cfg"));
        }
        if stripped.contains("from_value::<synvoid_config::icmp_filter::IcmpFilterConfig>")
            && !rel.ends_with("adapt.rs")
            && path.to_string_lossy().contains("admin/handlers/icmp.rs")
            && stripped.contains("serde_json::to_value(cfg)")
        {
            violations.push(format!("{rel}: cross-model from_value bridge"));
        }
        // The exact historical bridge comment must be gone.
        if stripped.contains("Convert between the two IcmpFilterConfig types via JSON") {
            violations.push(format!("{rel}: historical JSON bridge comment"));
        }
    }
    // Direct cross-model from_value on an already-typed config value (not on
    // the admin wire `req.config`) is the bridge; wire parsing is allowed.
    let admin = std::fs::read_to_string(root.join("src/admin/handlers/icmp.rs")).unwrap();
    let admin_stripped = strip_line_comments(&admin);
    assert!(
        !admin_stripped.contains("serde_json::to_value(cfg)"),
        "admin must not serialize enforcement cfg to Value"
    );
    assert!(
        violations.is_empty(),
        "JSON bridge violations: {violations:?}"
    );
}

fn workspace_root() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !path.join("Cargo.toml").exists() {
        assert!(path.pop(), "workspace root not found");
    }
    // CARGO_MANIFEST_DIR is crates/synvoid-icmp-filter; workspace root holds
    // a [workspace] table. Walk up until it does.
    loop {
        let content = std::fs::read_to_string(path.join("Cargo.toml")).unwrap_or_default();
        if content.contains("[workspace]") {
            return path;
        }
        assert!(path.pop(), "workspace root not found");
    }
}

fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}
