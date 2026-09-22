//! Phase 62 Workstream A: higher-level buffered+streaming ordering regression.
//!
//! Reproduces the exact acquisition order from
//! `upstream_proxy_dispatch_plan::prepare_upstream_proxy_dispatch_plan`:
//! the no-site-TLS buffered path requests `allow_plaintext: true` first,
//! then the streaming plan requests `UpstreamTlsConfig::default()`.
//! On the pre-Phase-62 tree the outer site-keyed registry collapsed both to
//! the first lane; this test proves they stay distinct and behaviorally
//! separated (strict lane rejects `http://` before I/O).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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

// Phase 63: hermetic loopback fixture. Binds port 0, counts accepted TCP
// connections, serves one minimal HTTP/1.1 200 per connection. Zero hits
// proves fail-before-I/O; one hit proves the request passed the policy gate.
async fn start_loopback_fixture() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture must bind loopback port 0");
    let addr = listener.local_addr().expect("fixture must have an addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut seen = 0usize;
                let _ = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        match sock.read(&mut buf[seen..]).await {
                            Ok(0) => break,
                            Ok(n) => {
                                seen += n;
                                if seen >= 4 && buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                                if seen == buf.len() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                })
                .await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (addr, hits)
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

    let (addr, hits) = start_loopback_fixture().await;
    let url = format!("http://{addr}/plan-order");

    // Behavioral proof: strict (streaming) lane rejects plaintext before I/O.
    let err = streaming
        .send_buffered(
            http::Method::GET,
            &url,
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
    // Settle window: any stray connection attempt would land here.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "streaming lane must open zero upstream connections"
    );

    // Buffered lane must pass the gate: exactly one fixture connection and
    // a 200 from the fixture server (stronger than "failed later at I/O").
    let resp = buffered
        .send_buffered(
            http::Method::GET,
            &url,
            None,
            http::HeaderMap::new(),
            Some(Duration::from_secs(5)),
            None,
        )
        .await
        .expect("buffered lane must pass the gate and reach the fixture");
    assert_eq!(resp.status_code(), 200);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "buffered lane must open exactly one fixture connection"
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
