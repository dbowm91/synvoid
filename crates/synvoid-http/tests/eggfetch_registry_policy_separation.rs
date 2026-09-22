//! Phase 62 Workstream A: higher-level buffered+streaming ordering regression.
//!
//! Reproduces the exact acquisition order from
//! `upstream_proxy_dispatch_plan::prepare_upstream_proxy_dispatch_plan`:
//! the no-site-TLS buffered path requests `allow_plaintext: true` first,
//! then the streaming plan requests `UpstreamTlsConfig::default()`.
//! On the pre-Phase-62 tree the outer site-keyed registry collapsed both to
//! the first lane; this test proves they stay distinct and behaviorally
//! separated (strict lane rejects `http://` before I/O).

use std::time::Duration;

use synvoid_http_client::UpstreamTlsConfig;
use synvoid_proxy::client_registry::UpstreamClientRegistry;

fn buffered_legacy_default() -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        allow_plaintext: true,
        ..UpstreamTlsConfig::default()
    }
}

fn streaming_legacy_default() -> UpstreamTlsConfig {
    UpstreamTlsConfig::default()
}

#[tokio::test]
async fn buffered_then_streaming_plan_order_stays_separate() {
    let registry = UpstreamClientRegistry::new();
    let site = "plan-order-site";
    // Exact plan order: buffered first, streaming second.
    let buffered = registry
        .get_or_create_lane(site, &buffered_legacy_default())
        .expect("buffered legacy default must build");
    let streaming = registry
        .get_or_create_lane(site, &streaming_legacy_default())
        .expect("streaming legacy default must build");

    // Behavioral proof: strict (streaming) lane rejects plaintext before I/O.
    let err = streaming
        .send_buffered(
            http::Method::GET,
            "http://127.0.0.1:9/plan-order",
            None,
            http::HeaderMap::new(),
            None,
            None,
        )
        .await
        .expect_err("streaming lane must reject http:// before I/O");
    assert!(
        err.to_string().contains("plaintext"),
        "unexpected streaming-lane error: {err}"
    );

    // Buffered lane must pass the gate (fails later at connect to the
    // discard port, proving it attempted I/O instead of applying the strict
    // gate).
    let err = buffered
        .send_buffered(
            http::Method::GET,
            "http://127.0.0.1:9/plan-order",
            None,
            http::HeaderMap::new(),
            Some(Duration::from_millis(200)),
            None,
        )
        .await
        .expect_err("discard port must fail at I/O");
    assert!(
        !err.to_string().contains("plaintext not permitted"),
        "buffered lane must keep its legacy plaintext gate: {err}"
    );
}

#[tokio::test]
async fn invalid_ca_never_reaches_upstream_and_recovers_after_invalidation() {
    let registry = UpstreamClientRegistry::new();
    let site = "recovery-site";
    let bad = UpstreamTlsConfig {
        ca_cert_path: Some("/nonexistent/phase62-recovery-ca.pem".to_string()),
        ..UpstreamTlsConfig::default()
    };
    // Fail-closed: no lane, no default substitution.
    let err = match registry.get_or_create_lane(site, &bad) {
        Ok(_) => panic!("invalid CA must fail"),
        Err(e) => e,
    };
    assert!(err.to_string().contains(site));

    // Corrected policy for a different site works immediately.
    registry
        .get_or_create_lane("other-site", &UpstreamTlsConfig::default())
        .expect("valid policy must build");

    // Invalidate the failed site (removes all variants, including the absent
    // failed one) and reacquire with valid material: recovery.
    registry.invalidate(site);
    registry
        .get_or_create_lane(site, &UpstreamTlsConfig::default())
        .expect("recovery after invalidation must build");
}
