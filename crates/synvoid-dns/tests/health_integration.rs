//! Integration tests for `DnsHealthChecker` wiring.
//!
//! These tests verify that the health checker state actually reflects runtime
//! configuration, not just manually-set test values. Each test constructs a
//! `DnsServer` with a specific config and asserts that the resulting
//! `DnsHealthStatus` snapshot matches the intended operational state.

use synvoid_config::dns::{DnsConfig, DnsMode, DnsSecConfig, RecursiveDnsConfig, ServeStaleConfig};
use synvoid_dns::health::{
    DnsHealthChecker, DnsHealthStatus, DnssecHealth, EncryptedTransportHealth, HealthState,
    RecursiveHealth, TransferUpdateHealth,
};
use synvoid_dns::server::DnsServer;

fn default_config() -> DnsConfig {
    DnsConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 0, // not relevant for these tests
        mode: DnsMode::Standalone,
        ..Default::default()
    }
}

#[test]
fn health_checker_field_is_wired_into_dns_server() {
    // The simplest possible check: the new `health` field exists and is
    // accessible. Before the wiring fix, this would not have compiled.
    let cfg = default_config();
    let server = DnsServer::new(cfg, None);
    let _checker: std::sync::Arc<DnsHealthChecker> = server.health_checker();
}

#[test]
fn default_state_listener_not_bound() {
    // Freshly constructed server has no listener bound yet — liveness is
    // NotReady. The init_health_state() call sets config-derived flags but
    // does NOT mark the listener bound (that happens in start_standard_mode).
    let cfg = default_config();
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    assert_eq!(status.liveness, HealthState::NotReady);
    assert!(!status.listener_bound);
    assert_eq!(status.readiness, HealthState::NotReady);
}

#[test]
fn shutdown_clears_listener_bound() {
    // shutdown_runtime() must clear listener_bound. liveness returns to
    // NotReady.
    let mut cfg = default_config();
    cfg.bind_address = "127.0.0.1".to_string();
    cfg.port = 5353;
    let mut server = DnsServer::new(cfg, None);

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
    let mut cfg = default_config();
    cfg.settings.cache_enabled = false;
    let server = DnsServer::new(cfg, None);
    let checker = server.health_checker();
    checker.set_listener_bound(true);
    let status = checker.status();
    assert!(!status.cache_operational);
    // Listener is bound but cache is not operational — readiness is Degraded.
    assert_eq!(status.readiness, HealthState::Degraded);
}

#[test]
fn cache_enabled_marks_cache_operational() {
    let cfg = default_config();
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    assert!(status.cache_operational);
}

#[test]
fn recursive_disabled_marks_recursive_disabled() {
    let cfg = default_config();
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    assert!(matches!(status.recursive_state, RecursiveHealth::Disabled));
}

#[test]
fn recursive_enabled_marks_recursive_healthy_initially() {
    // With recursive.enabled = true and no actual recursive server
    // initialized, the optimistic default in init_health_state is Healthy.
    let mut cfg = default_config();
    cfg.recursive = RecursiveDnsConfig {
        enabled: true,
        ..RecursiveDnsConfig::default()
    };
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    assert!(matches!(status.recursive_state, RecursiveHealth::Healthy));
    assert!(!matches!(
        status.recursive_state,
        RecursiveHealth::Degraded { .. }
    ));
}

#[test]
fn circuit_breaker_open_marks_recursive_degraded() {
    let mut cfg = default_config();
    cfg.recursive = RecursiveDnsConfig {
        enabled: true,
        ..RecursiveDnsConfig::default()
    };
    let server = DnsServer::new(cfg, None);
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
    let mut cfg = default_config();
    cfg.dot.enabled = true;
    cfg.doh.enabled = true;
    cfg.doq.enabled = false;
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    let et = &status.encrypted_transport_state;
    assert!(et.dot_enabled);
    assert!(et.doh_enabled);
    assert!(!et.doq_enabled);
}

#[test]
fn transfer_update_flags_match_config() {
    let mut cfg = default_config();
    cfg.settings.ixfr_enabled = true;
    cfg.settings.require_tsig = true;
    cfg.settings.dynamic_update.enabled = true;
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    let tu = &status.transfer_update_state;
    assert!(tu.axfr_enabled);
    assert!(tu.ixfr_enabled);
    assert!(tu.update_enabled);
    assert!(tu.tsig_required);
}

#[test]
fn transfer_update_disabled_reflected() {
    let mut cfg = default_config();
    cfg.settings.ixfr_enabled = false;
    cfg.settings.require_tsig = false;
    cfg.settings.dynamic_update.enabled = false;
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    let tu = &status.transfer_update_state;
    assert!(!tu.ixfr_enabled);
    assert!(!tu.update_enabled);
    assert!(!tu.tsig_required);
}

#[test]
fn dnssec_disabled_initially() {
    let cfg = default_config();
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    let ds = &status.dnssec_state;
    assert_eq!(ds.keys_loaded, 0);
    assert!(ds.last_key_rotation.is_none());
    assert!(!ds.signing_enabled);
}

#[test]
fn dnssec_enabled_reflected() {
    let mut cfg = default_config();
    cfg.dnssec = DnsSecConfig {
        enabled: true,
        ..DnsSecConfig::default()
    };
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    assert!(status.dnssec_state.signing_enabled);
}

#[test]
fn zone_load_attempt_records_success_and_failure() {
    let cfg = default_config();
    let server = DnsServer::new(cfg, None);
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
    let cfg = default_config();
    let server = DnsServer::new(cfg, None);
    let checker = server.health_checker();
    checker.set_listener_bound(true);
    checker.record_zone_load_attempt(false, Some("invalid zone".to_string()));
    let status = checker.status();
    assert_eq!(status.liveness, HealthState::Healthy);
    assert_eq!(status.readiness, HealthState::Degraded);
}

#[test]
fn status_snapshot_serializes_as_json() {
    let cfg = default_config();
    let server = DnsServer::new(cfg, None);
    let json = server.health_checker().status_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("status_json is valid JSON");
    assert!(parsed.get("liveness").is_some());
    assert!(parsed.get("readiness").is_some());
    assert!(parsed.get("listener_bound").is_some());
}

#[test]
fn readiness_is_healthy_when_listening_and_no_failures() {
    let cfg = default_config();
    let server = DnsServer::new(cfg, None);
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
    let mut cfg = default_config();
    cfg.settings.serve_stale = ServeStaleConfig {
        enabled: true,
        ..ServeStaleConfig::default()
    };
    let server = DnsServer::new(cfg, None);
    let status = server.health_checker().status();
    assert!(status.cache_operational);
}

#[test]
fn shutdown_is_idempotent_for_health() {
    let mut cfg = default_config();
    cfg.bind_address = "127.0.0.1".to_string();
    cfg.port = 5354;
    let mut server = DnsServer::new(cfg, None);
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
