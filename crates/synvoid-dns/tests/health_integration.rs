//! Integration tests for `DnsHealthChecker` wiring.
//!
//! These tests verify that the health checker state actually reflects runtime
//! configuration, not just manually-set test values. Each test constructs a
//! `DnsServer` with a specific config and asserts that the resulting
//! `DnsHealthStatus` snapshot matches the intended operational state.

mod support;

use support::runtime_config::{deferred_config, AuthoritativeRuntimeBuilder};
use synvoid_dns::health::{
    DnsHealthChecker, DnsHealthStatus, DnssecHealth, EncryptedTransportHealth, HealthState,
    RecursiveHealth, TransferUpdateHealth,
};
use synvoid_dns::server::DnsServer;

/// Build a server from DNS-owned runtime values (Phases 126/127 cutovers).
fn server_with(
    authoritative: synvoid_dns::runtime_config::AuthoritativeRuntimeConfig,
) -> DnsServer {
    server_with_all(
        authoritative,
        support::recursive_disabled(),
        deferred_config(),
    )
}

fn server_with_recursive(
    authoritative: synvoid_dns::runtime_config::AuthoritativeRuntimeConfig,
    recursive: synvoid_dns::runtime_config::RecursiveRuntimeConfig,
    deferred: synvoid_dns::runtime_config_deferred::DeferredDnsConfig,
) -> DnsServer {
    DnsServer::new(authoritative, recursive, deferred, None)
}

fn server_with_all(
    authoritative: synvoid_dns::runtime_config::AuthoritativeRuntimeConfig,
    recursive: synvoid_dns::runtime_config::RecursiveRuntimeConfig,
    deferred: synvoid_dns::runtime_config_deferred::DeferredDnsConfig,
) -> DnsServer {
    DnsServer::new(authoritative, recursive, deferred, None)
}

#[test]
fn health_checker_field_is_wired_into_dns_server() {
    // The simplest possible check: the new `health` field exists and is
    // accessible. Before the wiring fix, this would not have compiled.
    let server = server_with(AuthoritativeRuntimeBuilder::new().build());
    let _checker: std::sync::Arc<DnsHealthChecker> = server.health_checker();
}

#[test]
fn default_state_listener_not_bound() {
    // Freshly constructed server has no listener bound yet — liveness is
    // NotReady. The init_health_state() call sets config-derived flags but
    // does NOT mark the listener bound (that happens in start_standard_mode).
    let server = server_with(AuthoritativeRuntimeBuilder::new().build());
    let status = server.health_checker().status();
    assert_eq!(status.liveness, HealthState::NotReady);
    assert!(!status.listener_bound);
    assert_eq!(status.readiness, HealthState::NotReady);
}

#[test]
fn shutdown_clears_listener_bound() {
    // shutdown_runtime() must clear listener_bound. liveness returns to
    // NotReady.
    let mut server = server_with(AuthoritativeRuntimeBuilder::new().port(5353).build());

    // Simulate listener bind without spawning a real socket.
    server.health.set_listener_bound(true);
    let status = server.health_checker().status();
    assert_eq!(status.liveness, HealthState::Healthy);
    assert!(status.listener_bound);

    server.shutdown_runtime();
    let status = server.health_checker().status();
    assert_eq!(status.liveness, HealthState::NotReady);
    assert!(!status.listener_bound);
}

#[test]
fn cache_disabled_marks_cache_not_operational() {
    let server = server_with(
        AuthoritativeRuntimeBuilder::new()
            .cache_enabled(false)
            .build(),
    );
    let checker = server.health_checker();
    checker.set_listener_bound(true);
    let status = checker.status();
    assert!(!status.cache_operational);
    // Listener is bound but cache is not operational — readiness is Degraded.
    assert_eq!(status.readiness, HealthState::Degraded);
}

#[test]
fn cache_enabled_marks_cache_operational() {
    let server = server_with(
        AuthoritativeRuntimeBuilder::new()
            .cache_enabled(true)
            .build(),
    );
    let status = server.health_checker().status();
    assert!(status.cache_operational);
}

#[test]
fn recursive_disabled_marks_recursive_disabled() {
    let server = server_with(AuthoritativeRuntimeBuilder::new().build());
    let status = server.health_checker().status();
    assert!(matches!(status.recursive_state, RecursiveHealth::Disabled));
}

#[test]
fn recursive_enabled_marks_recursive_healthy_initially() {
    // With recursive.enabled = true and no actual recursive server
    // initialized, the optimistic default in init_health_state is Healthy.
    let server = server_with_recursive(
        AuthoritativeRuntimeBuilder::new().build(),
        support::recursive_runtime(),
        deferred_config(),
    );
    let status = server.health_checker().status();
    assert!(matches!(status.recursive_state, RecursiveHealth::Healthy));
    assert!(!matches!(
        status.recursive_state,
        RecursiveHealth::Degraded { .. }
    ));
}

#[test]
fn circuit_breaker_open_marks_recursive_degraded() {
    let server = server_with_recursive(
        AuthoritativeRuntimeBuilder::new().build(),
        support::recursive_runtime(),
        deferred_config(),
    );
    let checker = server.health_checker();
    checker.set_recursive_healthy();
    checker.set_circuit_breaker_open(true);
    let status = checker.status();
    match status.recursive_state {
        RecursiveHealth::Degraded {
            circuit_breaker_open,
        } => {
            assert!(circuit_breaker_open);
        }
        other => panic!("expected Degraded, got {:?}", other),
    }
}

#[test]
fn encrypted_transport_flags_match_config() {
    let server = server_with(
        AuthoritativeRuntimeBuilder::new()
            .dot(8853)
            .doh(8443)
            .build(),
    );
    let status = server.health_checker().status();
    let et = &status.encrypted_transport_state;
    assert!(et.dot_enabled);
    assert!(et.doh_enabled);
    assert!(!et.doq_enabled);
}

#[test]
fn transfer_update_flags_match_config() {
    let server = server_with(
        AuthoritativeRuntimeBuilder::new()
            .ixfr(true)
            .require_tsig(true)
            .update_enabled(true)
            .build(),
    );
    let status = server.health_checker().status();
    let tu = &status.transfer_update_state;
    assert!(tu.axfr_enabled);
    assert!(tu.ixfr_enabled);
    assert!(tu.update_enabled);
    assert!(tu.tsig_required);
}

#[test]
fn transfer_update_disabled_reflected() {
    let server = server_with(
        AuthoritativeRuntimeBuilder::new()
            .ixfr(false)
            .require_tsig(false)
            .update_enabled(false)
            .build(),
    );
    let status = server.health_checker().status();
    let tu = &status.transfer_update_state;
    assert!(!tu.ixfr_enabled);
    assert!(!tu.update_enabled);
    assert!(!tu.tsig_required);
}

#[test]
fn dnssec_disabled_initially() {
    let server = server_with(AuthoritativeRuntimeBuilder::new().build());
    let status = server.health_checker().status();
    let ds = &status.dnssec_state;
    assert_eq!(ds.keys_loaded, 0);
    assert!(ds.last_key_rotation.is_none());
    assert!(!ds.signing_enabled);
}

#[test]
fn dnssec_enabled_reflected() {
    let server = server_with_all(
        AuthoritativeRuntimeBuilder::new().build(),
        support::recursive_disabled(),
        support::runtime_config::deferred_dnssec_enabled(
            std::env::temp_dir().join("synvoid-health-test-keys"),
            "example.com",
        ),
    );
    let status = server.health_checker().status();
    assert!(status.dnssec_state.signing_enabled);
}

#[test]
fn zone_load_attempt_records_success_and_failure() {
    let server = server_with(AuthoritativeRuntimeBuilder::new().build());
    let checker = server.health_checker();
    checker.record_zone_load_attempt(true, None);
    checker.record_zone_load_attempt(true, None);
    checker.record_zone_load_attempt(false, Some("bad zone".to_string()));
    let status = checker.status();
    assert_eq!(status.zones_loaded, 2);
    assert_eq!(status.zones_failed, 1);
    assert_eq!(status.last_zone_load_error.as_deref(), Some("bad zone"));
    assert!(status.last_zone_load_time.is_some());
}

#[test]
fn degraded_zone_load_marks_readiness_degraded() {
    let server = server_with(AuthoritativeRuntimeBuilder::new().build());
    let checker = server.health_checker();
    checker.set_listener_bound(true);
    checker.record_zone_load_attempt(false, Some("invalid zone".to_string()));
    let status = checker.status();
    assert_eq!(status.liveness, HealthState::Healthy);
    assert_eq!(status.readiness, HealthState::Degraded);
}

#[test]
fn status_snapshot_serializes_as_json() {
    let server = server_with(AuthoritativeRuntimeBuilder::new().build());
    let json = server.health_checker().status_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("status_json is valid JSON");
    assert!(parsed.get("liveness").is_some());
    assert!(parsed.get("readiness").is_some());
    assert!(parsed.get("listener_bound").is_some());
}

#[test]
fn readiness_is_healthy_when_listening_and_no_failures() {
    let server = server_with(AuthoritativeRuntimeBuilder::new().build());
    let checker = server.health_checker();
    checker.set_listener_bound(true);
    let status = checker.status();
    assert_eq!(status.liveness, HealthState::Healthy);
    assert_eq!(status.readiness, HealthState::Healthy);
}

#[test]
fn serve_stale_does_not_affect_health() {
    // Sanity: serve_stale config exists but does not feed into health
    // observability — it's a per-request behavior, not a health dimension.
    let server = server_with(AuthoritativeRuntimeBuilder::new().serve_stale(true).build());
    let status = server.health_checker().status();
    assert!(status.cache_operational);
}

#[test]
fn shutdown_is_idempotent_for_health() {
    let mut server = server_with(AuthoritativeRuntimeBuilder::new().port(5354).build());
    server.health.set_listener_bound(true);
    server.shutdown_runtime();
    server.shutdown_runtime();
    let status = server.health_checker().status();
    assert!(!status.listener_bound);
    assert_eq!(status.liveness, HealthState::NotReady);
}

// Reference struct to silence unused-import warnings if a test above
// gets conditionally compiled out.
#[allow(dead_code)]
fn _type_asserts() {
    let _: DnsHealthStatus = DnsHealthStatus {
        liveness: HealthState::Healthy,
        readiness: HealthState::Healthy,
        listener_bound: true,
        zones_loaded: 0,
        zones_failed: 0,
        recursive_state: RecursiveHealth::Disabled,
        cache_operational: true,
        dnssec_state: DnssecHealth {
            keys_loaded: 0,
            last_key_rotation: None,
            signing_enabled: false,
        },
        encrypted_transport_state: EncryptedTransportHealth {
            dot_enabled: false,
            doh_enabled: false,
            doq_enabled: false,
            cert_valid: false,
        },
        transfer_update_state: TransferUpdateHealth {
            axfr_enabled: false,
            ixfr_enabled: false,
            update_enabled: false,
            tsig_required: false,
        },
        uptime_seconds: 0,
        last_zone_load_time: None,
        last_zone_load_error: None,
    };
}
