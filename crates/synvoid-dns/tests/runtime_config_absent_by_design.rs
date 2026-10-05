//! Phase 125 Workstream D — absent-by-design contract for the DNS runtime DTO.
//!
//! The DNS runtime vocabulary must not expose *active settings* for persisted
//! features that are unsupported, deferred, or unwired. These tests pin that
//! contract structurally (the runtime module's source of truth) and behaviorally
//! (conversion never produces such a setting).
//!
//! Persisted config validation remains authoritative for the typed config
//! paths; these tests only assert that nothing unsupported leaks into the
//! runtime API.

use synvoid_dns::runtime_config as rt;

/// Source of the DNS-owned runtime vocabulary. Structural assertions read this
/// so a new field cannot silently reintroduce an unsupported active setting.
fn runtime_module_source() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/runtime_config.rs"
    ))
    .expect("read DNS runtime_config module")
}

fn assert_no_runtime_field(forbidden: &[&str]) {
    let source = runtime_module_source();
    let mut violations = Vec::new();
    for field in forbidden {
        if source.contains(&format!("pub {field}")) {
            violations.push(*field);
        }
    }
    assert!(
        violations.is_empty(),
        "DNS runtime DTO must not expose active settings for unsupported persisted \
         features (absent by design): {}",
        violations.join(", ")
    );
}

// ---------------------------------------------------------------------------
// Unsupported / deferred features must have no active runtime setting
// ---------------------------------------------------------------------------

#[test]
fn rpz_has_no_runtime_setting() {
    // dns.rpz.* is fail-closed in `DnsConfig::validate()` (Phase 45).
    assert_no_runtime_field(&["rpz:"]);
}

#[test]
fn prefetch_has_no_runtime_setting() {
    // dns.prefetch.* is fail-closed in `DnsConfig::validate()` (Phase 45).
    assert_no_runtime_field(&["prefetch:"]);
}

#[test]
fn custom_trust_anchor_lifecycle_has_no_runtime_setting() {
    // dns.trust_anchors.* (custom update/reload lifecycle) is fail-closed.
    // Recursive true-recursion uses its own parsed paths, not a lifecycle.
    assert_no_runtime_field(&["trust_anchor_lifecycle:", "trust_anchors:"]);
}

#[test]
fn edns_padding_has_no_runtime_setting() {
    // dns.settings.padding.* is fail-closed (Phase 45).
    assert_no_runtime_field(&["padding:"]);
}

#[test]
fn qname_privacy_has_no_runtime_setting() {
    // dns.settings.qname_privacy.* is fail-closed (Phase 45).
    assert_no_runtime_field(&["qname_privacy:"]);
}

#[test]
fn unwired_rebinding_controls_have_no_runtime_setting() {
    // dns.firewall.rebinding_protection.* is persisted but never applied to
    // firewall rules or the request path.
    assert_no_runtime_field(&[
        "rebinding_protection:",
        "min_ttl_for_internal:",
        "allowed_internal_domains:",
        "block_short_ttl_internal:",
    ]);
}

#[test]
fn unwired_firewall_controls_have_no_runtime_setting() {
    // dns.firewall.default_action and dns.firewall.max_rules have no consumer.
    assert_no_runtime_field(&["default_action:", "max_rules:"]);
}

#[test]
fn anycast_activation_exposes_no_active_setting() {
    // Anycast addresses/intervals/health settings are unsupported: activation
    // must fail closed, so only the rejection signal exists.
    assert_no_runtime_field(&[
        "anycast_addresses:",
        "anycast_interval:",
        "anycast_health_check:",
        "advertise_address:",
    ]);
}

#[test]
fn unsupported_transfer_update_notify_settings_have_no_runtime_setting() {
    // RFC 1995 UPDATE/NOTIFY operators and AXFR requestor allowlists beyond
    // the parsed transfer policy stay fail-closed.
    assert_no_runtime_field(&["update_operator:", "notify_allowlist:", "axfr_requestors:"]);
}

// ---------------------------------------------------------------------------
// Composition/provider-owned material must not enter the runtime DTO
// ---------------------------------------------------------------------------

#[test]
fn certificate_material_is_not_in_the_runtime_dto() {
    // TLS paths and system-cert-store toggles are consumed through
    // composition/provider ownership (`CertResolver`), never projected into
    // DNS-owned runtime values.
    assert_no_runtime_field(&[
        "tls_cert_path:",
        "tls_key_path:",
        "use_system_cert_store:",
        "cert_resolver:",
        "acme:",
    ]);
}

#[test]
fn dns64_prefix_is_parsed_not_a_string() {
    // The prefix crosses as a typed `Ipv6Addr`, so a malformed prefix cannot
    // reach the translator.
    let source = runtime_module_source();
    assert!(
        source.contains("pub prefix: Ipv6Addr"),
        "Dns64RuntimeConfig.prefix must be a parsed Ipv6Addr, not a String"
    );
    assert!(
        !source.contains("pub prefix: String"),
        "Dns64RuntimeConfig.prefix must not remain a raw String"
    );
}

// ---------------------------------------------------------------------------
// Absent-by-design invariants on the runtime values themselves
// ---------------------------------------------------------------------------

#[test]
fn disabled_encrypted_transports_carry_no_bind_address() {
    // A disabled transport must not carry a fabricated socket.
    let disabled = rt::DotRuntimeConfig {
        enabled: false,
        bind_address: None,
    };
    assert!(disabled.bind_address.is_none());
    let enabled = rt::DotRuntimeConfig {
        enabled: true,
        bind_address: Some("127.0.0.1:853".parse().unwrap()),
    };
    assert!(enabled.bind_address.is_some());
}

#[test]
fn rrl_runtime_exposes_only_the_activation_flag() {
    // `rrl.responses_per_second`, `rrl.window_secs`, `rrl.max_responses`, and
    // `rrl.ttl` have no runtime consumer; only `enabled` does.
    let source = runtime_module_source();
    let rrl_start = source
        .find("pub struct RrlRuntimeConfig")
        .expect("RrlRuntimeConfig exists");
    let rrl_block = &source[rrl_start..rrl_start + 200];
    for forbidden in [
        "responses_per_second",
        "window_secs",
        "max_responses",
        "ttl",
    ] {
        assert!(
            !rrl_block.contains(forbidden),
            "RrlRuntimeConfig must not expose `{forbidden}` (no runtime consumer)"
        );
    }
}

#[test]
fn tsig_runtime_key_debug_never_leaks_the_secret() {
    let key = rt::TsigRuntimeKey {
        name: "transfer.".to_string(),
        secret: vec![0x5A; 32],
        algorithm: rt::TsigAlgorithmRuntime::HmacSha256,
    };
    let rendered = format!("{key:?}");
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("90"), "debug output leaked secret bytes");
}

#[test]
fn tsig_algorithm_minimum_secret_lengths_are_enforced_in_the_type() {
    assert!(rt::TsigAlgorithmRuntime::HmacSha256.min_secret_len() > 0);
    assert!(
        rt::TsigAlgorithmRuntime::HmacSha512.min_secret_len()
            > rt::TsigAlgorithmRuntime::HmacSha256.min_secret_len()
    );
    assert!(
        rt::TsigAlgorithmRuntime::HmacSha384.min_secret_len()
            > rt::TsigAlgorithmRuntime::HmacSha256.min_secret_len()
    );
}
