//! Phase 08 — DNS health realization and configuration redaction.
//!
//! ## What this suite exists to pin
//!
//! 1. `/health` reports what the runtime **realized**, not what configuration
//!    requested. `dns.capabilities` carries `realized` and `config_requested`
//!    side by side, so a configured-but-absent feature is visible instead of
//!    being silently claimed.
//! 2. `GET /config/dns` never serializes a TSIG secret. `PUT /config/dns` still
//!    accepts one, write-only: omitted keeps the stored secret, an empty string
//!    clears it.
//! 3. `TsigKeyConfig`'s `Debug` cannot leak the secret into a log line.
//!
//! The admin half lives in the root package because the admin router is where
//! `GET /config/dns` is assembled; the DNS half is exercised through
//! `synvoid_dns`'s public constructor and health checker.

#![cfg(feature = "dns")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use synvoid::admin::create_admin_router_with_state;
use synvoid::admin::state::AdminState;
use synvoid::config::admin::{AdminCorsConfig, AdminRateLimitConfig};
use synvoid::config::dns::{DnsConfig, TsigAlgorithm, TsigKeyConfig};
use synvoid::config::ConfigManager;
use synvoid::server::dns_runtime_config::dns_runtime_config_from_persisted;

use synvoid_dns::server::DnsServer;

const TEST_TOKEN: &str = "test_admin_token_that_is_at_least_32_chars_long";

// ── fixtures ─────────────────────────────────────────────────────────────────

fn disabled_rate_limit() -> AdminRateLimitConfig {
    AdminRateLimitConfig {
        requests_per_minute: u32::MAX,
        burst: u32::MAX,
    }
}

/// A DNS config with the top-level switch on. Constructed in one expression so
/// the fixture does not trip `clippy::field_reassign_with_default`.
fn dns_config(enabled: bool) -> DnsConfig {
    DnsConfig {
        enabled,
        ..DnsConfig::default()
    }
}

fn dns_config_with_tsig(secret: &str) -> DnsConfig {
    let mut config = dns_config(true);
    config.dnssec.tsig_keys = vec![TsigKeyConfig {
        name: "transfer-key.".to_string(),
        secret_base64: secret.to_string(),
        algorithm: TsigAlgorithm::HmacSha256,
    }];
    // An HSM PIN is the second credential in this section; it must be redacted
    // by the same read paths and preserved by the same write-only semantics.
    config.dnssec.hsm.pin = Some("1234".to_string());
    config
}

fn config_manager(config_dir: &std::path::Path, dns: DnsConfig) -> ConfigManager {
    let mut manager = ConfigManager::new(config_dir.to_path_buf());
    manager.main.dns = dns;
    manager
}

/// Build the real admin router and hand back the shared state.
///
/// `build_admin_state` calls `blocking_read` on the config lock, so the build
/// runs on the blocking pool exactly like the existing admin contract suites.
async fn admin_fixture(config_dir: &std::path::Path, dns: DnsConfig) -> (Router, Arc<AdminState>) {
    let manager = config_manager(config_dir, dns);
    let (router, state) = tokio::task::spawn_blocking(move || {
        let config = Arc::new(tokio::sync::RwLock::new(manager));
        create_admin_router_with_state(
            config,
            TEST_TOKEN.to_string(),
            AdminCorsConfig::default(),
            disabled_rate_limit(),
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            #[cfg(feature = "mesh")]
            None,
            #[cfg(feature = "icmp-filter")]
            None,
        )
    })
    .await
    .expect("router construction must not panic");
    (router, state.expect("the fixture must build admin state"))
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    serde_json::from_slice(&body).expect("response body is JSON")
}

async fn get_public_json(router: &Router, uri: &str) -> Value {
    let response = router
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("router handles the request");
    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    response_json(response).await
}

async fn get_admin_json(router: &Router, uri: &str) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router handles the request");
    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    response_json(response).await
}

/// Attach a live DNS health checker to the admin state and read
/// `dns.capabilities` back through the real `/health` endpoint.
async fn health_capabilities(
    router: &Router,
    state: &Arc<AdminState>,
    server: &DnsServer,
) -> Value {
    state.set_dns_health(server.health_checker());
    let body = get_public_json(router, "/health").await;
    body.get("dns")
        .and_then(|dns| dns.get("capabilities"))
        .unwrap_or_else(|| panic!("/health must expose dns.capabilities, got {body}"))
        .clone()
}

fn capability<'a>(capabilities: &'a Value, name: &str) -> &'a Value {
    capabilities
        .get(name)
        .unwrap_or_else(|| panic!("capability {name} missing from {capabilities}"))
}

fn assert_capability(capabilities: &Value, name: &str, realized: bool, requested: bool) {
    let entry = capability(capabilities, name);
    assert_eq!(
        entry["realized"], realized,
        "{name}.realized must report the runtime, got {entry}"
    );
    assert_eq!(
        entry["config_requested"], requested,
        "{name}.config_requested must report configuration, got {entry}"
    );
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral UDP")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Start a DNS server on a loopback ephemeral port, retrying a lost bind race.
///
/// Mirrors the DNS crate's `start_bound_dns_server` contract: predict, bind,
/// retry only on `AddrInUse`, and never mask a real startup error. `make` gets
/// the candidate port so a test can project it into the runtime config.
async fn start_on_loopback<F>(mut make: F) -> (DnsServer, u16)
where
    F: FnMut(u16) -> DnsServer,
{
    let mut last_error = String::new();
    for _ in 0..8 {
        let port = free_port();
        let mut server = make(port);
        match server.start().await {
            Ok(()) => return (server, port),
            Err(error) if error.contains("in use") => last_error = error,
            Err(error) => panic!("DNS server start failed: {error}"),
        }
    }
    panic!("DNS server could not bind a loopback port: {last_error}");
}

fn runtime_on_port(
    mut runtime: synvoid_dns::runtime_config::DnsRuntimeConfig,
    port: u16,
) -> synvoid_dns::runtime_config::DnsRuntimeConfig {
    runtime.authoritative.bind_address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    runtime
}

// ── 8. AXFR is not realized just because config asked ────────────────────────

#[tokio::test]
async fn axfr_reports_unrealized_even_when_config_requests_it() {
    let mut runtime = dns_runtime_config_from_persisted(&DnsConfig::default())
        .expect("default DNS config projects");
    // The persisted gate rejects `allow_transfer`, so request it on the
    // runtime value directly: the health contract must hold for the runtime
    // input, not only for configs that pass today's gate.
    runtime.authoritative.zone_transfer.allow_transfer =
        vec![synvoid_dns::runtime_config::IpNetwork::parse("10.0.0.0/8").expect("valid CIDR")];

    let server = DnsServer::new(runtime, None, None);
    let status = server.health_checker().status();
    assert!(
        !status.transfer_update_state.axfr_enabled,
        "no transfer handler is attached; AXFR answers NOTIMP"
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let (router, state) = admin_fixture(dir.path(), DnsConfig::default()).await;
    let capabilities = health_capabilities(&router, &state, &server).await;

    assert_capability(&capabilities, "axfr", false, true);
    assert_capability(&capabilities, "ixfr", false, true);
    assert_capability(&capabilities, "update", false, false);
}

// ── 9. DNSSEC signing is a loaded key handle, not a config bit ──────────────

#[tokio::test]
async fn dnssec_signing_requires_a_zone_key_handle() {
    let dir = tempfile::tempdir().expect("temp dir");
    let key_path = dir.path().join("keys");

    // Enabled, keys initialized, but no zone carries a handle.
    let mut config = dns_config(true);
    config.dnssec.enabled = true;
    config.dnssec.domain = "example.com".to_string();
    config.dnssec.key_path = key_path.to_string_lossy().to_string();
    config.recursive.enabled = false;
    let runtime = dns_runtime_config_from_persisted(&config).expect("DNSSEC config projects");
    let (mut server, _port) = start_on_loopback(|port| {
        DnsServer::new(runtime_on_port(runtime.clone(), port), None, None)
    })
    .await;

    let (router, state) = admin_fixture(dir.path(), config).await;
    let capabilities = health_capabilities(&router, &state, &server).await;
    assert_capability(&capabilities, "dnssec_signing", false, true);
    assert!(
        !server
            .health_checker()
            .status()
            .dnssec_state
            .signing_enabled,
        "keys existing in the manager is not signing; no zone holds a ZSK"
    );
    server.shutdown_runtime();

    // The positive half: one loaded zone receives the key handles and the flag
    // flips only because the zone can now sign.
    let dir = tempfile::tempdir().expect("temp dir");
    let key_path = dir.path().join("keys");
    let mut config = dns_config(true);
    config.dnssec.enabled = true;
    config.dnssec.domain = "signed.test".to_string();
    config.dnssec.key_path = key_path.to_string_lossy().to_string();
    config.recursive.enabled = false;
    config.zones.items = vec![synvoid::config::dns::DnsZoneEntry {
        zone: "signed.test".to_string(),
        records: vec![synvoid::config::dns::DnsRecordEntry {
            name: "@".to_string(),
            record_type: synvoid::config::dns::DnsRecordType::Soa,
            value: "ns1.signed.test. admin.signed.test. 1 3600 600 604800 300".to_string(),
            ttl: Some(60),
            priority: None,
        }],
        dnssec: None,
    }];
    let runtime = dns_runtime_config_from_persisted(&config).expect("DNSSEC config projects");
    let zones = runtime.zones.clone();
    assert_eq!(zones.len(), 1, "the fixture declares one zone");
    let (mut server, _port) = start_on_loopback(|port| {
        let server = DnsServer::new(runtime_on_port(runtime.clone(), port), None, None);
        server.load_zones(zones.clone()).expect("zone loads");
        server
    })
    .await;

    let (router, state) = admin_fixture(dir.path(), config).await;
    let capabilities = health_capabilities(&router, &state, &server).await;
    assert_capability(&capabilities, "dnssec_signing", true, true);
    server.shutdown_runtime();
}

// ── 10. recursive that fails to start is degraded, not healthy ──────────────

#[tokio::test]
async fn recursive_start_failure_reports_degraded_not_healthy() {
    // Hold the recursive port so the bind deterministically fails.
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").expect("occupy UDP port");
    let occupied_port = occupied.local_addr().expect("local addr").port();

    let mut config = dns_config(true);
    config.recursive.enabled = true;
    config.recursive.bind_address = "127.0.0.1".to_string();
    config.recursive.port = occupied_port;
    config.recursive.dnssec_validation = false;
    let runtime = dns_runtime_config_from_persisted(&config).expect("recursive config projects");
    let mut server = DnsServer::new(runtime, None, None);

    let error = server
        .start()
        .await
        .expect_err("recursive startup must fail on the held port");
    assert!(
        error.contains("recursive"),
        "the failure must name the recursive subsystem: {error}"
    );

    let status = server.health_checker().status();
    assert!(
        matches!(
            status.recursive_state,
            synvoid_dns::health::RecursiveHealth::Degraded { .. }
        ),
        "a recursive listener that never started must be degraded, got {:?}",
        status.recursive_state
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let (router, state) = admin_fixture(dir.path(), DnsConfig::default()).await;
    let capabilities = health_capabilities(&router, &state, &server).await;
    assert_capability(&capabilities, "recursive", false, true);
    assert_capability(&capabilities, "dot", false, false);
    assert_capability(&capabilities, "doh", false, false);
    assert_capability(&capabilities, "doq", false, false);
    assert_capability(&capabilities, "notify", false, false);
    drop(occupied);
}

// ── 11 + 12. redaction and write-only secrets ───────────────────────────────

#[tokio::test]
async fn dns_config_redacts_secrets_and_put_preserves_an_omitted_secret() {
    // A real 32-byte HMAC secret, not a marker: the assertion searches for the
    // encoded value as well as the field name.
    let secret = base64::engine::general_purpose::STANDARD.encode([0x42u8; 32]);
    let dir = tempfile::tempdir().expect("temp dir");
    let (router, state) = admin_fixture(dir.path(), dns_config_with_tsig(&secret)).await;

    let first = get_admin_json(&router, "/api/config/dns").await;
    let serialized = serde_json::to_string(&first).expect("response serializes");
    assert!(
        !serialized.contains("secret_base64"),
        "GET /config/dns must never serialize the field name: {serialized}"
    );
    assert!(
        !serialized.contains(&secret),
        "GET /config/dns must never serialize the secret value"
    );
    assert_eq!(
        first["config"]["dnssec"]["tsig_keys"][0]["name"], "transfer-key.",
        "the redacted key must remain identifiable by name"
    );
    assert_eq!(
        first["config"]["dnssec"]["tsig_keys"][0]["secret_set"], true,
        "the response must say a secret is stored"
    );

    // The HSM PIN is write-only too: presence is reported, the value is not.
    assert!(
        first["config"]["dnssec"]["hsm"].get("pin").is_none(),
        "GET /config/dns must not serialize the HSM PIN"
    );
    assert_eq!(
        first["config"]["dnssec"]["hsm"]["pin_set"], true,
        "the response must say an HSM PIN is stored"
    );

    // `/config/main` embeds the DNS section; the parent endpoint must not be a
    // side door to either credential.
    let main = get_admin_json(&router, "/api/config/main").await;
    let main_serialized = serde_json::to_string(&main).expect("response serializes");
    assert!(
        !main_serialized.contains("secret_base64"),
        "GET /config/main must not serialize a TSIG secret field"
    );
    assert!(
        !main_serialized.contains(&secret),
        "GET /config/main must not serialize the TSIG secret value"
    );
    assert!(
        main["config"]["dns"]["dnssec"]["hsm"].get("pin").is_none(),
        "GET /config/main must not serialize the HSM PIN"
    );

    // Round-trip the redacted document, changing only a non-secret field. The
    // omitted secret must be kept.
    let mut update = first["config"].clone();
    update["port"] = json!(5353);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/config/dns")
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "config": update }).to_string()))
                .unwrap(),
        )
        .await
        .expect("router handles the request");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "PUT with an omitted secret must be accepted"
    );

    {
        let stored = state.process.config.read().await;
        assert_eq!(stored.main.dns.port, 5353, "the update was applied");
        assert_eq!(
            stored.main.dns.dnssec.tsig_keys[0].secret_base64, secret,
            "an omitted secret_base64 keeps the stored secret"
        );
        assert_eq!(
            stored.main.dns.dnssec.hsm.pin.as_deref(),
            Some("1234"),
            "an omitted HSM PIN keeps the stored PIN"
        );
    }

    let second = get_admin_json(&router, "/api/config/dns").await;
    assert_eq!(
        second["config"]["dnssec"]["tsig_keys"][0]["secret_set"], true,
        "a subsequent GET still reports the secret as set"
    );

    // An explicit empty string clears it.
    let mut cleared = second["config"].clone();
    cleared["dnssec"]["tsig_keys"][0]["secret_base64"] = json!("");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/config/dns")
                .header("authorization", format!("Bearer {TEST_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "config": cleared }).to_string()))
                .unwrap(),
        )
        .await
        .expect("router handles the request");
    assert_eq!(response.status(), StatusCode::OK);

    {
        let stored = state.process.config.read().await;
        assert!(
            stored.main.dns.dnssec.tsig_keys[0].secret_base64.is_empty(),
            "an explicit empty string clears the stored secret"
        );
    }
}

// ── 13. Debug never prints the secret ───────────────────────────────────────

#[test]
fn tsig_key_debug_redacts_the_secret() {
    let secret = "c3VwZXItc2VjcmV0LXZhbHVlLXRoYXQtbXVzdC1ub3QtbGVhaw==";
    let key = TsigKeyConfig {
        name: "transfer-key.".to_string(),
        secret_base64: secret.to_string(),
        algorithm: TsigAlgorithm::HmacSha384,
    };

    let debug = format!("{key:?}");
    assert!(
        !debug.contains(secret),
        "the derived Debug must not contain the secret: {debug}"
    );
    assert!(
        debug.contains("<redacted>"),
        "the redaction must be explicit: {debug}"
    );

    // And nested through the config struct that a log line is most likely to
    // carry.
    let mut config = DnsConfig::default();
    config.dnssec.tsig_keys = vec![key];
    config.dnssec.hsm.pin = Some("9876".to_string());
    let debug = format!("{config:?}");
    assert!(
        !debug.contains(secret),
        "DnsConfig Debug must not leak the nested secret"
    );
    assert!(
        !debug.contains("9876"),
        "DnsConfig Debug must not leak the nested HSM PIN"
    );
}
