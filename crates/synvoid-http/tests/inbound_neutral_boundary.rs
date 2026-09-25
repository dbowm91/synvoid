//! Phase 74 acceptance: the transport-neutral inbound boundary.
//!
//! Proves `InboundBody`/`InboundRequest`/`UpgradeCapability` preserve
//! behavior across Transports: body variants, errors, trailers, drop,
//! WAF blocks, the Hyper H1 adapter, live WebSocket dispatch through the
//! production neutral path, and H2 parity through the same conversion.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body::Body as _;
use synvoid_http::body_policy::{BodyPolicyError, RequestBodyWaf};
use synvoid_http::hyper_adapter::adapt_hyper_request;
use synvoid_http::inbound::{BoxTunnelIo, InboundBody, InboundBodyError, InboundRequest};
use synvoid_http::shared_handler::StreamingWafScanner;
use synvoid_http::streaming_waf_body::StreamingWafBody;
use synvoid_waf::WafDecision;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// InboundBody unit behavior
// ---------------------------------------------------------------------------

#[test]
fn empty_body_has_exact_zero_hint() {
    let body = InboundBody::empty();
    assert_eq!(body.size_hint().exact(), Some(0));
    assert!(body.is_end_stream());
}

#[tokio::test]
async fn fixed_body_round_trips() {
    let mut body = InboundBody::from_bytes(Bytes::from_static(b"abc"));
    assert_eq!(body.size_hint().exact(), Some(3));
    let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
        .await
        .expect("frame")
        .expect("ok");
    assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"abc"));
}

#[tokio::test]
async fn frame_stream_preserves_data_error_and_hints() {
    let frames = vec![
        Ok::<http_body::Frame<Bytes>, InboundBodyError>(http_body::Frame::data(
            Bytes::from_static(b"one"),
        )),
        Err::<http_body::Frame<Bytes>, InboundBodyError>(InboundBodyError::Protocol(
            "bad-frame".to_string(),
        )),
    ];
    let mut body = InboundBody::from_frame_stream(futures::stream::iter(frames));
    // Unknown length: size hint is a hint only, never exact here.
    assert_eq!(body.size_hint().exact(), None);
    let first = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
        .await
        .expect("frame")
        .expect("ok");
    assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"one"));
    let second = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
        .await
        .expect("frame");
    match second {
        Err(InboundBodyError::Protocol(msg)) => assert_eq!(msg, "bad-frame"),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[tokio::test]
async fn trailers_frame_crosses_neutral_body() {
    let mut map = http::HeaderMap::new();
    map.insert("x-checksum", "abc".parse::<http::HeaderValue>().unwrap());
    let frames = vec![
        Ok::<http_body::Frame<Bytes>, InboundBodyError>(http_body::Frame::data(
            Bytes::from_static(b"data"),
        )),
        Ok::<http_body::Frame<Bytes>, InboundBodyError>(http_body::Frame::trailers(map)),
    ];
    let mut body = InboundBody::from_frame_stream(futures::stream::iter(frames));
    let mut trailers_seen = 0;
    for _ in 0..2 {
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .expect("frame")
            .expect("ok");
        match frame.into_data() {
            Ok(_) => {}
            Err(frame) => {
                let tr = frame.trailers_ref().expect("trailers");
                assert_eq!(tr.get("x-checksum").unwrap(), "abc");
                trailers_seen += 1;
            }
        }
    }
    assert_eq!(trailers_seen, 1);
}

#[test]
fn error_variants_are_fail_closed_and_descriptive() {
    assert!(InboundBodyError::Transport("io down".to_string())
        .to_string()
        .contains("io down"));
    assert!(InboundBodyError::Cancelled
        .to_string()
        .contains("cancelled"));
    assert!(InboundBodyError::Protocol("framing".to_string())
        .to_string()
        .contains("framing"));
}

// ---------------------------------------------------------------------------
// WAF machinery over the neutral body
// ---------------------------------------------------------------------------

struct MarkerScanner {
    marker: &'static [u8],
    seen: Arc<AtomicUsize>,
}

impl StreamingWafScanner for MarkerScanner {
    fn scan_chunk(&mut self, chunk: &[u8]) -> synvoid_core::streaming_waf::StreamingWafDecision {
        self.seen.fetch_add(chunk.len(), Ordering::SeqCst);
        if chunk.windows(self.marker.len()).any(|w| w == self.marker) {
            synvoid_core::streaming_waf::StreamingWafDecision::Block(403, "marker".to_string())
        } else {
            synvoid_core::streaming_waf::StreamingWafDecision::Continue
        }
    }
}

async fn drive_with_scanner(
    body: InboundBody,
    marker: Option<&'static [u8]>,
    seen: &Arc<AtomicUsize>,
) -> Result<(Bytes, u64), String> {
    use http_body::Body as _;
    let scanner = marker.map(|m| MarkerScanner {
        marker: m,
        seen: seen.clone(),
    });
    let mut wrapped = StreamingWafBody::new(body, scanner, IpAddr::from([127, 0, 0, 1]));
    let mut pinned = Pin::new(&mut wrapped);
    let mut out = Vec::new();
    let mut total = 0u64;
    loop {
        match std::future::poll_fn(|cx| pinned.as_mut().poll_frame(cx)).await {
            None => break,
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    total += data.len() as u64;
                    out.extend_from_slice(data);
                }
            }
            Some(Err(e)) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    return Err("blocked".to_string());
                }
                return Err(format!("transport: {e}"));
            }
        }
    }
    Ok((Bytes::from(out), total))
}

#[tokio::test]
async fn neutral_body_streams_through_waf_and_blocks_mid_stream() {
    let seen = Arc::new(AtomicUsize::new(0));
    let body = InboundBody::from_bytes(Bytes::from_static(b"clean clean BLOCKME"));
    let err = drive_with_scanner(body, Some(b"BLOCKME"), &seen)
        .await
        .unwrap_err();
    assert_eq!(err, "blocked");
    assert_eq!(seen.load(Ordering::SeqCst), 19);
}

// ---------------------------------------------------------------------------
// Migrated body policy over neutral bodies
// ---------------------------------------------------------------------------

struct StubWaf;

impl RequestBodyWaf for StubWaf {
    fn streaming(&self) -> Option<Box<dyn StreamingWafScanner>> {
        None
    }

    fn check_request_body(&self, _chunk: &[u8]) -> (bool, Option<WafDecision>) {
        (false, Some(WafDecision::Drop))
    }
}

#[tokio::test]
async fn body_policy_collects_small_neutral_body() {
    let waf = StubWaf;
    let body = InboundBody::from_bytes(Bytes::from_static(b"hello"));
    let (bytes, size) = synvoid_http::body_policy::collect_and_scan_request_body(
        body,
        &waf,
        IpAddr::from([127, 0, 0, 1]),
        Some(5),
        1024 * 1024,
    )
    .await
    .unwrap();
    assert_eq!(&bytes[..], b"hello");
    assert_eq!(size, 0);
}

#[tokio::test]
async fn body_policy_rejects_oversize_unknown_length_body() {
    let waf = StubWaf;
    // Unknown length forces the chunk path, which enforces the SynVoid max.
    let frames = vec![Ok::<http_body::Frame<Bytes>, InboundBodyError>(
        http_body::Frame::data(Bytes::from(vec![0u8; 2048])),
    )];
    let body = InboundBody::from_frame_stream(futures::stream::iter(frames));
    let err = synvoid_http::body_policy::collect_and_scan_request_body(
        body,
        &waf,
        IpAddr::from([127, 0, 0, 1]),
        None,
        1024,
    )
    .await
    .unwrap_err();
    assert_eq!(err, BodyPolicyError::BodyTooLarge);
}

#[tokio::test]
async fn body_policy_waf_blocks_large_neutral_body() {
    let waf = StubWaf;
    // Above the 1 MiB scan threshold so the stub WAF verdict applies.
    let body = InboundBody::from_bytes(Bytes::from(vec![0u8; 2 * 1024 * 1024]));
    let err = synvoid_http::body_policy::collect_and_scan_request_body(
        body,
        &waf,
        IpAddr::from([127, 0, 0, 1]),
        Some(2 * 1024 * 1024),
        8 * 1024 * 1024,
    )
    .await
    .unwrap_err();
    assert_eq!(err, BodyPolicyError::BlockedByWaf);
}

// ---------------------------------------------------------------------------
// Hyper H1 adapter loopback
// ---------------------------------------------------------------------------

async fn read_until_marker(socket: &mut tokio::net::TcpStream, marker: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
            .await
            .expect("read timeout")
            .expect("read failed");
        assert!(n > 0, "closed before marker");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(marker.len()).any(|w| w == marker) {
            break;
        }
    }
    buf
}

#[tokio::test]
async fn adapter_converts_h1_body_and_classifies_upgrade() {
    use http_body_util::BodyExt as _;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(
                    |req: hyper::Request<hyper::body::Incoming>| async move {
                        let InboundRequest {
                            parts,
                            body,
                            upgrade,
                        } = adapt_hyper_request(req);
                        let tag = match upgrade {
                            Some(cap) => format!("upgrade:{}", cap.request().protocol),
                            None => "plain".to_string(),
                        };
                        let bytes = body.collect().await.unwrap().to_bytes();
                        let text = format!(
                            "{}:{}:{}",
                            parts.method,
                            tag,
                            String::from_utf8_lossy(&bytes)
                        );
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(Bytes::from(text)),
                        ))
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    // POST body round-trips through the neutral body.
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        .await
        .unwrap();
    let wire = read_until_marker(&mut socket, b"POST:plain:hello").await;
    assert!(
        String::from_utf8_lossy(&wire).contains("POST:plain:hello"),
        "missing body round-trip"
    );

    // WebSocket candidate captures a neutral capability.
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let wire = read_until_marker(&mut socket, b"upgrade:websocket").await;
    assert!(
        String::from_utf8_lossy(&wire).contains("GET:upgrade:websocket"),
        "missing upgrade classification"
    );
}

// ---------------------------------------------------------------------------
// Live WebSocket through the production neutral dispatch
// ---------------------------------------------------------------------------

const RFC_WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const RFC_WS_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

#[tokio::test]
async fn neutral_websocket_dispatch_echoes_with_readahead() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let svc =
            hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                let InboundRequest {
                    parts,
                    body: _,
                    upgrade,
                } = adapt_hyper_request(req);
                let out = synvoid_http::websocket_upgrade_dispatch::maybe_handle_websocket_upgrade(
                    upgrade,
                    false,
                    None,
                    (),
                    "upstream".to_string(),
                    parts.uri.path().to_string(),
                    Arc::new(()),
                    IpAddr::from([127, 0, 0, 1]),
                    parts.headers.clone(),
                    synvoid_config::site::SiteWebSocketConfig::default(),
                    |_io: BoxTunnelIo,
                     _path: std::path::PathBuf,
                     _t: (),
                     _p: String,
                     _w: Arc<()>,
                     _ip: IpAddr,
                     _c: synvoid_config::site::SiteWebSocketConfig| async move {},
                    |io: BoxTunnelIo,
                     _t: (),
                     _p: String,
                     _w: Arc<()>,
                     _ip: IpAddr,
                     _c: synvoid_config::site::SiteWebSocketConfig| async move {
                        let mut io = io;
                        let mut buf = vec![0u8; 8192];
                        loop {
                            match io.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    if io.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    },
                )
                .await;
                match out {
                    Some(Ok(resp)) => {
                        let (resp_parts, _) = resp.into_parts();
                        Ok::<_, std::convert::Infallible>(hyper::Response::from_parts(
                            resp_parts,
                            http_body_util::Full::new(Bytes::new()),
                        ))
                    }
                    _ => Ok(hyper::Response::new(http_body_util::Full::new(
                        Bytes::from_static(b"ordinary"),
                    ))),
                }
            });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .with_upgrades()
            .await;
    });

    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request = format!(
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {RFC_WS_KEY}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(b"HELLO-READAHEAD");
    socket.write_all(&request).await.unwrap();
    let wire = read_until_marker(&mut socket, b"\r\n\r\n").await;
    let head_end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8_lossy(&wire[..head_end]).into_owned();
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("http/1.1 101"), "{head}");
    assert!(head.contains(RFC_WS_ACCEPT), "{head}");
    assert!(lower.contains("sec-websocket-protocol: chat"), "{head}");
    let mut echo = wire[head_end..].to_vec();
    while echo.len() < 15 {
        let mut tmp = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
            .await
            .expect("echo timeout")
            .expect("echo read failed");
        assert!(n > 0, "tunnel closed before echo");
        echo.extend_from_slice(&tmp[..n]);
    }
    assert_eq!(&echo[..15], b"HELLO-READAHEAD");
    drop(socket);
}

#[tokio::test]
async fn neutral_websocket_decline_stays_ordinary() {
    // Decline is covered by the unit test in websocket_upgrade_dispatch and
    // the adapter classification test above; this pins the dispatch-level
    // None contract directly.
    let out: Option<Result<synvoid_http::BoxBodyResponse, hyper::Error>> =
        synvoid_http::websocket_upgrade_dispatch::maybe_handle_websocket_upgrade(
            None,
            false,
            None,
            (),
            "upstream".to_string(),
            "/plain".to_string(),
            Arc::new(()),
            IpAddr::from([127, 0, 0, 1]),
            http::HeaderMap::new(),
            synvoid_config::site::SiteWebSocketConfig::default(),
            |_io: BoxTunnelIo,
             _path: std::path::PathBuf,
             _t: (),
             _p: String,
             _w: Arc<()>,
             _ip: IpAddr,
             _c: synvoid_config::site::SiteWebSocketConfig| async move {},
            |_io: BoxTunnelIo,
             _t: (),
             _p: String,
             _w: Arc<()>,
             _ip: IpAddr,
             _c: synvoid_config::site::SiteWebSocketConfig| async move {},
        )
        .await;
    assert!(out.is_none());
}

// ---------------------------------------------------------------------------
// H2 parity through the same conversion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn h2_body_flows_through_neutral_conversion() {
    use http_body_util::BodyExt as _;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let svc =
            hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                let InboundRequest { body, .. } = adapt_hyper_request(req);
                let bytes = body.collect().await.unwrap().to_bytes();
                Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(
                    bytes,
                )))
            });
        let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(io, svc)
            .await;
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(tcp);
    let (mut sender, conn) = hyper::client::conn::http2::handshake::<
        _,
        _,
        http_body_util::Full<Bytes>,
    >(hyper_util::rt::TokioExecutor::new(), io)
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("POST")
        .uri("http://localhost/echo")
        .body(http_body_util::Full::new(Bytes::from_static(b"h2-bytes")))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let body = resp.collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"h2-bytes");
}
