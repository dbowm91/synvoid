//! Phase 06 data-plane hardening (findings C4, C6, C7).
//!
//! - C4: a `ServerlessInvokeRequest` is authorized as the authenticated session
//!   peer, never as the `caller_node_id` the message claims, and an unlisted
//!   peer never reaches the `serverless_function:` dispatch branch.
//! - C6: a chunk size is bounded before it can size an allocation, and the
//!   running wire-byte total cannot wrap.
//! - C7: providers are tried one at a time; a non-idempotent request executes
//!   on exactly one origin.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use synvoid_mesh::config::{MeshConfig, MeshNodeRole};
use synvoid_mesh::protocol::ProviderInfo;
use synvoid_mesh::proxy::{walk_providers_in_order, ProviderAttempt};
use synvoid_mesh::service_target::{ClientMetadata, ClientProtocol};
use synvoid_mesh::transport_peer::{
    read_chunked_http_response_body, rebuild_upstream_head, serverless_caller_identity,
    serverless_dispatch_authorized, stream_chunked_http_body, HttpResponseFramingError,
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(1);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(2);

fn crate_file(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn slice_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = source
        .find(start)
        .unwrap_or_else(|| panic!("guard anchor not found: {start}"));
    let rest = &source[start_index + start.len()..];
    let end_index = rest
        .find(end)
        .unwrap_or_else(|| panic!("guard end anchor not found: {end}"));
    &rest[..end_index]
}

fn provider(node_id: &str) -> ProviderInfo {
    ProviderInfo {
        node_id: node_id.to_string(),
        upstream_url: format!("http://{node_id}:8080"),
        waf_policy: None,
        hops: 0,
        ttl: Duration::from_secs(60),
        score: 1.0,
        priority_tier: 1,
        tier_claim: None,
        org_id: None,
        mesh_name: None,
    }
}

// ---------------------------------------------------------------------------
// C4 — serverless caller identity
// ---------------------------------------------------------------------------

/// A session authenticated as `node-X` whose request claims `caller_node_id =
/// node-Y` must be authorized as `node-X`.
///
/// The authorization decision is the identity handed to the serverless
/// manager, so this asserts that value rather than a log line.
#[test]
fn serverless_caller_is_session_identity() {
    let authenticated_peer = "node-X";
    let forged_claim = "node-Y";

    let identity = serverless_caller_identity(authenticated_peer, MeshNodeRole::ORIGIN);

    assert_eq!(
        identity.node_id, authenticated_peer,
        "the authenticated session peer is the only authorized caller"
    );
    assert_ne!(
        identity.node_id, forged_claim,
        "the claimed caller_node_id must never become the authorized caller"
    );
    assert_eq!(
        identity.role,
        MeshNodeRole::ORIGIN,
        "the role must be the session role Phase 03 resolved, not a hardcoded EDGE"
    );
}

/// The message handler must build the caller from the session identity.
///
/// `caller_node_id` is peer-controlled; if it reappears as `CallerContext
/// { node_id: ... }` the forgery is live again even though the helper above
/// still behaves.
#[test]
fn serverless_invoke_handler_uses_the_session_identity() {
    let peer = crate_file("src/mesh/transport_peer.rs");
    let handler = slice_between(
        &peer,
        "pub(crate) async fn handle_serverless_invoke_request(",
        "pub(crate) async fn handle_serverless_invoke_response(",
    );

    assert!(
        handler.contains("serverless_caller_identity(authenticated_peer, session_role)"),
        "the handler must derive the caller from the authenticated peer and session role"
    );
    assert!(
        !handler.contains("node_id: req.caller_node_id"),
        "the message's caller_node_id must not build the authorization context"
    );
    assert!(
        !handler.contains("role: crate::config::MeshNodeRole::EDGE"),
        "the caller role must not be hardcoded to EDGE"
    );
    assert!(
        peer.contains("claimed_caller = %req.caller_node_id"),
        "the claim stays as audit metadata in the dispatch log"
    );
}

/// A peer that is not in the origin's `peered_wafs` allowlist is refused before
/// the serverless branch runs.
#[test]
fn unlisted_peer_cannot_dispatch_serverless() {
    let listed_peer = "node-listed-edge";
    let unlisted_peer = "node-unlisted-edge";

    let mut config = MeshConfig::default();
    let upstream: synvoid_mesh::config::MeshUpstreamConfig =
        serde_json::from_value(serde_json::json!({
            "upstream_url": "http://127.0.0.1:1",
            "peered_wafs": [{"node_id": listed_peer, "allowed": true, "role": "edge"}],
        }))
        .expect("mesh upstream config");
    config
        .local_upstreams
        .insert("blog-public".to_string(), upstream);

    assert!(
        serverless_dispatch_authorized(&config, listed_peer),
        "an allowlisted peer must keep the serverless dispatch path"
    );
    assert!(
        !serverless_dispatch_authorized(&config, unlisted_peer),
        "a peer outside peered_wafs must be denied"
    );

    // The gate has to run before the dispatch branch, otherwise a denied peer
    // still reaches the function manager.
    let peer = crate_file("src/mesh/transport_peer.rs");
    let handler = slice_between(
        &peer,
        "async fn handle_http_proxy_stream(",
        "async fn write_mesh_http_error(",
    );
    let gate = handler.find("if !serverless_dispatch_authorized(&self.config, &peer_node_id)");
    let dispatch = handler.find("handle_serverless_proxy_stream(");
    let (gate, dispatch) = match (gate, dispatch) {
        (Some(gate), Some(dispatch)) => (gate, dispatch),
        _ => panic!("serverless gate and dispatch must both be present"),
    };
    assert!(
        gate < dispatch,
        "authorization must precede serverless dispatch"
    );
    assert!(
        handler.contains("\"403 Forbidden\""),
        "a denied peer must receive 403"
    );
}

// ---------------------------------------------------------------------------
// C6 — chunk bounds before allocation
// ---------------------------------------------------------------------------

/// `ffffffffffffffff` is `usize::MAX`. With a 64-byte cap the parser must fail
/// before sizing any buffer from it, and promptly.
#[tokio::test]
async fn chunk_size_above_cap_is_rejected_before_allocation() {
    let wire = b"ffffffffffffffff\r\n";

    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        read_chunked_http_response_body(&wire[..], Vec::new(), IDLE_TIMEOUT, TOTAL_TIMEOUT, 64, 64),
    )
    .await
    .expect("the cap check must return without reading the chunk payload");
    let elapsed = started.elapsed();

    assert!(
        matches!(
            &result,
            Err(HttpResponseFramingError::BodyTooLarge { limit: 64, .. })
        ),
        "an over-cap chunk size must be BodyTooLarge, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "rejection must be immediate, took {elapsed:?}"
    );
}

/// The streaming twin must reject the same size instead of wrapping
/// `total_wire_bytes`.
#[tokio::test]
async fn streaming_chunk_size_overflow_is_rejected() {
    let wire = b"ffffffffffffffff\r\n";
    let mut out = Vec::new();

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        stream_chunked_http_body(
            &wire[..],
            Vec::new(),
            &mut out,
            IDLE_TIMEOUT,
            TOTAL_TIMEOUT,
            64,
            64,
        ),
    )
    .await
    .expect("the streaming cap check must not wait for chunk data");

    assert!(
        matches!(
            &result,
            Err(HttpResponseFramingError::BodyTooLarge { limit: 64, .. })
        ),
        "an over-cap chunk size must be BodyTooLarge, got {result:?}"
    );
}

/// A chunk-size token with a sign or surrounding whitespace is not a size.
#[tokio::test]
async fn chunk_size_with_sign_or_whitespace_is_malformed() {
    for wire in [
        &b"+5\r\n"[..],
        &b"-5\r\n"[..],
        &b" 5\r\n"[..],
        &b"5 \r\n"[..],
    ] {
        let result = read_chunked_http_response_body(
            wire,
            Vec::new(),
            IDLE_TIMEOUT,
            TOTAL_TIMEOUT,
            1024,
            1024,
        )
        .await;
        assert!(
            matches!(
                &result,
                Err(HttpResponseFramingError::MalformedChunkedBody(_))
            ),
            "chunk size {:?} must be malformed, got {result:?}",
            String::from_utf8_lossy(wire)
        );
    }
}

// ---------------------------------------------------------------------------
// C7 — sequential provider selection
// ---------------------------------------------------------------------------

/// Two providers, a POST: exactly one receives the request. The first
/// provider is authoritative for a non-idempotent method.
#[tokio::test]
async fn post_is_sent_to_one_provider() {
    let sent: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = sent.clone();

    let walk = walk_providers_in_order(
        vec![provider("node-a"), provider("node-b")],
        &http::Method::POST,
        move |provider| {
            let recorder = recorder.clone();
            async move {
                recorder.lock().unwrap().push(provider.node_id.clone());
                ProviderAttempt::<usize, &'static str>::Failed {
                    error: "connect refused",
                    response_started: false,
                }
            }
        },
    )
    .await;

    let sent = sent.lock().unwrap().clone();
    assert_eq!(
        sent,
        vec!["node-a".to_string()],
        "a POST must reach exactly one provider"
    );
    assert!(walk.selected.is_none());
    assert_eq!(walk.failures.len(), 1);
    assert_eq!(walk.failures[0].0, "node-a");
}

/// A GET may retry, and stops at the first success.
#[tokio::test]
async fn get_retries_the_next_provider() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();

    let walk = walk_providers_in_order(
        vec![provider("node-a"), provider("node-b")],
        &http::Method::GET,
        move |provider| {
            let counter = counter.clone();
            async move {
                let attempt = counter.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    ProviderAttempt::Failed {
                        error: "connect refused",
                        response_started: false,
                    }
                } else {
                    ProviderAttempt::Succeeded(provider.node_id)
                }
            }
        },
    )
    .await;

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "a GET must be retried after a pre-response failure"
    );
    assert_eq!(
        walk.selected,
        Some(("node-b".to_string(), "node-b".to_string()))
    );
}

/// Response bytes after a failure were already received, so even a GET is not
/// replayed.
#[tokio::test]
async fn get_does_not_retry_after_response_bytes() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();

    let walk = walk_providers_in_order(
        vec![provider("node-a"), provider("node-b")],
        &http::Method::GET,
        move |_provider| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                ProviderAttempt::<(), &'static str>::Failed {
                    error: "truncated response",
                    response_started: true,
                }
            }
        },
    )
    .await;

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "a partially received response must not be replayed"
    );
    assert!(walk.selected.is_none());
    assert_eq!(walk.failures.len(), 1);
}

/// The fanout machinery is gone, not merely unused.
#[test]
fn provider_fanout_is_retired() {
    let proxy = crate_file("src/mesh/proxy.rs");
    assert!(
        !proxy.contains("MAX_PROVIDER_FANOUT"),
        "the fanout constant must be deleted"
    );
    assert!(
        !proxy.contains("ProviderTaskGuard"),
        "the task guard must be deleted"
    );
    assert!(
        proxy.contains("walk_providers_in_order("),
        "provider selection must go through the sequential walk"
    );
}

// ---------------------------------------------------------------------------
// C5 — the upstream header block is rebuilt, not spliced
// ---------------------------------------------------------------------------

fn preface_metadata(ip: &str, proto: ClientProtocol) -> ClientMetadata {
    ClientMetadata {
        client_ip: ip.parse().expect("fixture client address"),
        proto,
    }
}

fn lower_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_lowercase()
}

/// A peer that copies its client's forwarding headers must not reach the
/// customer upstream with them: the preface metadata is the only source.
#[test]
fn client_forwarding_headers_are_replaced_by_the_preface_identity() {
    let head = b"POST /login HTTP/1.1\r\n\
Host: blog.example\r\n\
Content-Length: 5\r\n\
Connection: keep-alive, X-Custom-Hop\r\n\
Keep-Alive: timeout=5\r\n\
X-Custom-Hop: 1\r\n\
Proxy-Authorization: Basic abc\r\n\
X-Forwarded-For: 203.0.113.9\r\n\
X-Real-IP: 203.0.113.9\r\n\
Forwarded: for=203.0.113.9\r\n\
X-Forwarded-Proto: https\r\n\
X-Forwarded-Host: evil.example\r\n\
X-Request-Id: req-123\r\n\
\r\n";
    let meta = preface_metadata("198.51.100.23", ClientProtocol::Https);

    let rebuilt = rebuild_upstream_head(head, Some(&meta));
    let text = lower_text(&rebuilt);

    assert!(
        String::from_utf8_lossy(&rebuilt).starts_with("POST /login HTTP/1.1\r\n"),
        "the request line must be preserved"
    );
    assert!(
        rebuilt.ends_with(b"\r\n\r\n"),
        "the blank line terminator must be preserved"
    );

    // Exactly one of each forwarded header, carrying the preface value.
    assert_eq!(
        text.matches("x-forwarded-for:").count(),
        1,
        "exactly one X-Forwarded-For must be emitted"
    );
    assert_eq!(
        text.matches("x-real-ip:").count(),
        1,
        "exactly one X-Real-IP must be emitted"
    );
    assert_eq!(
        text.matches("x-forwarded-proto:").count(),
        1,
        "exactly one X-Forwarded-Proto must be emitted"
    );
    assert!(
        text.contains("x-forwarded-for: 198.51.100.23"),
        "X-Forwarded-For must carry the preface client address"
    );
    assert!(
        text.contains("x-real-ip: 198.51.100.23"),
        "X-Real-IP must carry the preface client address"
    );
    assert!(
        text.contains("x-forwarded-proto: https"),
        "X-Forwarded-Proto must carry the preface protocol"
    );
    assert!(
        !text.contains("203.0.113.9"),
        "the client's claimed address must not appear anywhere upstream"
    );

    // Client-supplied forwarding and hop-by-hop headers are gone.
    for dropped in [
        "x-forwarded-host:",
        "forwarded:",
        "connection:",
        "keep-alive:",
        "x-custom-hop",
        "proxy-authorization",
    ] {
        assert!(
            !text.contains(dropped),
            "{dropped} must not be forwarded upstream"
        );
    }

    // End-to-end headers survive.
    assert!(text.contains("host: blog.example"), "Host is preserved");
    assert!(
        text.contains("x-request-id: req-123"),
        "custom end-to-end headers are preserved"
    );
    assert!(
        text.contains("content-length: 5"),
        "the validated body framing is preserved"
    );
}

/// Without preface metadata (a version 1 legacy peer) every client-supplied
/// forwarding header is still stripped, and nothing is synthesised.
#[test]
fn legacy_preface_strips_forwarding_headers_without_synthesising_them() {
    let head = b"GET / HTTP/1.1\r\n\
Host: blog.example\r\n\
X-Forwarded-For: 203.0.113.9\r\n\
X-Real-IP: 203.0.113.9\r\n\
Forwarded: for=203.0.113.9\r\n\
\r\n";

    let rebuilt = rebuild_upstream_head(head, None);
    let text = lower_text(&rebuilt);

    assert!(!text.contains("x-forwarded-for"));
    assert!(!text.contains("x-real-ip"));
    assert!(!text.contains("forwarded:"));
    assert!(text.contains("host: blog.example"));
}

/// The origin forwards chunked body bytes unchanged, so the rebuilt head keeps
/// exactly one validated `Transfer-Encoding: chunked` instead of the peer's
/// original hop-by-hop framing line.
#[test]
fn chunked_framing_is_re_emitted_exactly_once() {
    let head = b"POST /upload HTTP/1.1\r\n\
Host: blog.example\r\n\
Transfer-Encoding: chunked\r\n\
\r\n";

    let rebuilt = rebuild_upstream_head(head, None);
    let text = lower_text(&rebuilt);

    assert_eq!(
        text.matches("transfer-encoding:").count(),
        1,
        "one authoritative Transfer-Encoding must be emitted"
    );
    assert!(text.contains("transfer-encoding: chunked"));
}

/// The origin write site must use the rebuilt block, not the peer's raw bytes.
#[test]
fn origin_writes_the_rebuilt_header_block() {
    let peer = crate_file("src/mesh/transport_peer.rs");
    let handler = slice_between(
        &peer,
        "async fn handle_http_proxy_stream(",
        "async fn write_mesh_http_error(",
    );

    assert!(
        handler.contains("rebuild_upstream_head(&head.header_bytes, client_meta)"),
        "the origin must rebuild the upstream head from the preface metadata"
    );
    assert!(
        !handler.contains("write_all(&head.header_bytes)"),
        "the peer's raw header block must never be spliced upstream"
    );
}
