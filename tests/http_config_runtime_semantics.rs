//! Root-test ownership: COMPOSITION
//! Rationale: Phase 71 HTTP configuration runtime-semantics truthfulness.
//! Proves `http.max_header_size_ingress` is an enforced aggregate
//! request-header bound (431 before routing/WAF) at the canonical preflight
//! boundary, and guards that every `HttpConfig` field carries an explicit
//! runtime-semantics disposition in
//! `architecture/http_config_runtime_semantics_matrix.md`.
//!
//! Table style: no policy engine is duplicated here; the matrix is the
//! authority and this file pins its completeness plus the one newly
//! activated exact control.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use synvoid_challenge::css::{AssetRequestResult, CssAssetAction};
use synvoid_config::theme::ThemeConfig;
use synvoid_config::{HttpConfig, MainConfig};
use synvoid_http::{
    prepare_request_preflight, BufferedRequestWaf, ChallengePathWaf, EarlyWafHooks, RequestBodyWaf,
    RequestPreflightOutcome,
};
use synvoid_proxy::Router;
use synvoid_waf::ConnectionLimiter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ─── Stub WAF: denies nothing, routes everything past policy ─────────────────

struct StubWaf {
    theme: ThemeConfig,
}

impl EarlyWafHooks for StubWaf {
    fn verify_trust_token(&self, _client_ip: IpAddr, _token: &str) -> bool {
        false
    }
}

impl RequestBodyWaf for StubWaf {
    fn streaming(&self) -> Option<Box<dyn synvoid_http::shared_handler::StreamingWafScanner>> {
        None
    }

    fn check_request_body(&self, _chunk: &[u8]) -> (bool, Option<synvoid_waf::WafDecision>) {
        (true, None)
    }
}

impl ChallengePathWaf for StubWaf {
    fn generate_challenge_page(
        &self,
        _ip: &IpAddr,
        _app_path: Option<&str>,
    ) -> (String, Option<String>) {
        (String::new(), None)
    }

    fn css_enabled(&self) -> bool {
        false
    }

    fn css_session_cookie_name(&self) -> String {
        String::new()
    }

    fn record_css_asset_request(
        &self,
        _session_id: &str,
        _asset_name: &str,
    ) -> (AssetRequestResult, CssAssetAction) {
        (
            AssetRequestResult::UnknownAsset,
            CssAssetAction::DropConnection,
        )
    }

    fn css_verified_cookie_name(&self) -> String {
        String::new()
    }

    fn css_window_secs(&self) -> u64 {
        0
    }
}

#[async_trait::async_trait]
impl BufferedRequestWaf for StubWaf {
    fn error_page_theme(&self) -> &ThemeConfig {
        &self.theme
    }

    fn render_page_with_theme(
        &self,
        _status: u16,
        _message: Option<&str>,
        _override_theme: Option<&ThemeConfig>,
    ) -> String {
        String::new()
    }

    fn connection_limiter(&self) -> Option<Arc<ConnectionLimiter>> {
        None
    }

    fn is_over_bandwidth_limit(&self) -> bool {
        false
    }

    fn honeypot_ban_duration_secs(&self) -> u64 {
        0
    }

    fn stream_tarpit(
        &self,
        _path: &str,
        _user_agent: Option<&str>,
    ) -> synvoid_http::streaming_waf_decision::TarpitStream {
        Box::pin(futures::stream::empty())
    }

    fn generate_tarpit_response(&self, _path: &str) -> String {
        String::new()
    }

    async fn check_request_full(
        &self,
        _site_id: Option<&str>,
        _ip: IpAddr,
        _method: &str,
        _path: &str,
        _query: Option<&str>,
        _headers: &http::HeaderMap,
        _body: Option<&[u8]>,
        _ua: Option<&str>,
        _ja4_hash: Option<&str>,
        _site_bot_config: Option<&synvoid_config::site::SiteBotConfig>,
    ) -> synvoid_proxy::WafDecision {
        synvoid_proxy::WafDecision::Pass
    }

    async fn check_request_full_owned(
        self: Arc<Self>,
        _site_id: Option<String>,
        _ip: IpAddr,
        _method: String,
        _path: String,
        _query: Option<String>,
        _headers: http::HeaderMap,
        _body: Option<bytes::Bytes>,
        _ua: Option<String>,
        _ja4_hash: Option<String>,
        _site_bot_config: Option<synvoid_config::site::SiteBotConfig>,
    ) -> synvoid_proxy::WafDecision {
        synvoid_proxy::WafDecision::Pass
    }
}

/// Spawn an H1 server whose service is the canonical preflight with an empty
/// route table: fitting requests reach routing (404), oversized aggregate
/// headers are rejected first (431).
async fn spawn_preflight_server(http_config: HttpConfig) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let cfg = http_config.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let cfg = cfg.clone();
                        async move {
                            let main_config = Arc::new(MainConfig::default());
                            let router = Arc::new(Router::new(&main_config, HashMap::new()));
                            let waf = Arc::new(StubWaf {
                                theme: ThemeConfig::default(),
                            });
                            let outcome = prepare_request_preflight(
                                req,
                                IpAddr::V4(Ipv4Addr::LOCALHOST),
                                None,
                                router,
                                waf,
                                None,
                                main_config,
                                &cfg,
                                |_status,
                                 _site: &str,
                                 _bypassed: bool,
                                 _method: &str,
                                 _path: &str,
                                 _ua: Option<&str>| {},
                                || {},
                            )
                            .await?;
                            match outcome {
                                RequestPreflightOutcome::Continue(_) => Ok::<_, hyper::Error>(
                                    hyper::Response::new(http_body_util::Full::new(
                                        bytes::Bytes::from_static(b"routed"),
                                    )),
                                ),
                                RequestPreflightOutcome::Respond(resp) => {
                                    let (parts, body) = resp.into_parts();
                                    let bytes = http_body_util::BodyExt::collect(body)
                                        .await
                                        .map(|c| c.to_bytes())
                                        .unwrap_or_default();
                                    Ok(hyper::Response::from_parts(
                                        parts,
                                        http_body_util::Full::new(bytes),
                                    ))
                                }
                            }
                        }
                    },
                );
                let io = hyper_util::rt::TokioIo::new(stream);
                let conn = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .with_upgrades();
                let _ = conn.await;
            });
        }
    });
    addr
}

async fn raw_request(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn ingress_headers_within_limit_reach_routing() {
    let addr = spawn_preflight_server(HttpConfig {
        max_header_size_ingress: 256,
        ..HttpConfig::default()
    })
    .await;
    let resp = raw_request(
        addr,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    let status = resp.lines().next().unwrap_or("");
    assert!(
        status.contains("404"),
        "fitting headers must pass ingress policy and reach routing (empty table => 404), got: {resp:?}"
    );
}

#[tokio::test]
async fn ingress_headers_above_limit_rejected_before_routing() {
    let addr = spawn_preflight_server(HttpConfig {
        max_header_size_ingress: 256,
        ..HttpConfig::default()
    })
    .await;
    let mut req = String::from("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-Fill: ");
    req.push_str(&"A".repeat(1024));
    req.push_str("\r\n\r\n");
    let resp = raw_request(addr, req.as_bytes()).await;
    let status = resp.lines().next().unwrap_or("");
    assert!(
        status.contains("431"),
        "aggregate headers above the limit must be rejected with 431 before routing, got: {resp:?}"
    );
}

// ─── Disposition guard: every HttpConfig field has a matrix entry ────────────

/// Canonical field set under test. Adding a field to `HttpConfig` without
/// updating this table AND the architecture matrix fails this guard by
/// design (Phase 71 Workstream I).
const EXPECTED_FIELDS: &[(&str, &str)] = &[
    ("header_read_timeout_secs", "ACTIVE_EXACT"),
    ("keep_alive_timeout_secs", "DEPRECATED_COMPAT"),
    ("max_headers", "ACTIVE_EXACT"),
    ("max_request_line_size", "DEPRECATED_COMPAT"),
    ("max_header_size_ingress", "ACTIVE_EXACT"),
    ("max_header_size_egress", "DEPRECATED_COMPAT"),
    ("max_request_size", "ACTIVE_NARROWER_THAN_DOCS"),
    ("pipeline_limit", "DEPRECATED_COMPAT"),
    ("waf_stall_timeout_secs", "ACTIVE_EXACT"),
    ("max_stalled_requests", "ACTIVE_EXACT"),
    ("max_connections", "ACTIVE_NARROWER_THAN_DOCS"),
    ("strict_protocol_validation", "ACTIVE_EXACT"),
    ("max_streaming_body_size", "ACTIVE_EXACT"),
];

const ALLOWED_DISPOSITIONS: &[&str] = &[
    "ACTIVE_EXACT",
    "ACTIVE_NARROWER_THAN_DOCS",
    "INERT",
    "DUPLICATE_POLICY",
    "DEPRECATED_COMPAT",
];

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel))
        .expect("read repo file")
}

#[test]
fn http_config_fields_match_matrix() {
    // 1. The serialized default config exposes exactly the expected fields.
    let value = serde_json::to_value(HttpConfig::default()).expect("serialize HttpConfig");
    let obj = value
        .as_object()
        .expect("HttpConfig serializes to an object");
    let mut actual: Vec<&str> = obj.keys().map(String::as_str).collect();
    actual.sort_unstable();
    let mut expected: Vec<&str> = EXPECTED_FIELDS.iter().map(|(f, _)| *f).collect();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "HttpConfig fields changed: update EXPECTED_FIELDS and the runtime-semantics matrix"
    );

    // 2. Every disposition is from the allowed vocabulary.
    for (field, disposition) in EXPECTED_FIELDS {
        assert!(
            ALLOWED_DISPOSITIONS.contains(disposition),
            "field {field} has unknown disposition {disposition}"
        );
    }

    // 3. The matrix document covers every field with its disposition.
    let matrix = repo_file("architecture/http_config_runtime_semantics_matrix.md");
    for (field, disposition) in EXPECTED_FIELDS {
        assert!(
            matrix.contains(*field),
            "matrix must document field {field}"
        );
        assert!(
            matrix.contains(*disposition),
            "matrix must use disposition {disposition} for {field}"
        );
    }
}

#[test]
fn active_fields_have_executable_consumers() {
    // Spot-check that ACTIVE dispositions correspond to real runtime code,
    // not config plumbing. Each token must appear outside config/schema/UI
    // surface (i.e. in an executable consumer).
    let waf_decision = repo_file("crates/synvoid-http/src/waf_decision.rs");
    assert!(waf_decision.contains("max_stalled_requests"));
    assert!(waf_decision.contains("waf_stall_timeout_secs"));
    let preflight = repo_file("crates/synvoid-http/src/request_preparation.rs");
    assert!(preflight.contains("max_header_size_ingress"));
    assert!(preflight.contains("max_streaming_body_size"));
    let h1_policy = repo_file("src/http/h1_policy.rs");
    assert!(h1_policy.contains("header_read_timeout_secs"));
    assert!(h1_policy.contains("max_headers"));
    assert!(h1_policy.contains("max_request_size"));
    let accept_loop = repo_file("src/http/server/accept_loop.rs");
    assert!(accept_loop.contains("strict_protocol_validation"));
    let server = repo_file("src/http/server.rs");
    assert!(server.contains("max_connections"));
}

#[test]
fn deprecated_fields_are_marked_inert_in_operator_surfaces() {
    // DEPRECATED_COMPAT fields must not be described as active controls.
    let config_docs = repo_file("docs/CONFIGURATION.md");
    let admin_docs = repo_file("admin-ui/src/config_docs.rs");
    for field in [
        "keep_alive_timeout_secs",
        "max_request_line_size",
        "max_header_size_egress",
        "pipeline_limit",
    ] {
        for surface in [&config_docs, &admin_docs] {
            assert!(
                surface.contains(field),
                "operator surface must still document {field} (parseable compat key)"
            );
        }
    }
    // Each deprecated field's CONFIGURATION.md section must carry an
    // explicit not-enforced marker so operators are not misled.
    for field in [
        "keep_alive_timeout_secs",
        "max_request_line_size",
        "max_header_size_egress",
        "pipeline_limit",
    ] {
        let idx = config_docs.find(field).expect("field documented");
        let window = &config_docs[idx..(idx + 2000).min(config_docs.len())];
        assert!(
            window.contains("not enforced") || window.contains("Not enforced"),
            "docs/CONFIGURATION.md must mark {field} as not enforced"
        );
    }
}

#[test]
fn narrower_fields_state_exact_scope() {
    let config_docs = repo_file("docs/CONFIGURATION.md");
    assert!(
        config_docs.contains("parser-buffer") || config_docs.contains("parser buffer"),
        "max_request_size docs must state the parser-buffer scope"
    );
    assert!(
        config_docs.contains("concurrent") && config_docs.contains("max_connections"),
        "max_connections docs must state the concurrent-request admission scope"
    );
}
