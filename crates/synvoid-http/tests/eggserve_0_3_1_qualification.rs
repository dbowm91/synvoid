//! Phase 73 re-run prototypes against the exact published artifacts
//! `eggserve-server =0.3.1` / `eggserve-primitives =0.2.1`, re-pinned to
//! `0.4.0` / `0.2.2` by Phase 79 Finding B (0.3.1 cannot render an H1
//! terminal trailer block). The file name records the qualification that
//! introduced these prototypes.
//!
//! Test-only fixture: no production route changes, no production EggServe
//! dependency. Workstreams E (body), F (tunnel), G (drop/shutdown),
//! H (response stream) from
//! `plans/phase_73_eggserve_0_3_runtime_requalification_and_contract_gate.md`.

// =====================================================================
// Workstream E — body adaptation: EggServe RequestBody -> neutral body
// stream -> current body/WAF machinery. SynVoid stays the size/WAF
// authority: the EggServe policy is Stream with a non-preempting limit and
// the SynVoid limit is enforced in `drive_prototype`.
// =====================================================================
mod body_adaptation {
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use eggserve_primitives::request_body::IncomingError;
    use eggserve_primitives::{
        HeaderBlock, RequestBody, RequestBodyError, RequestBodyPolicy, Trailers,
    };
    use eggserve_server::{H1PolicyOwnership, PolicyOwner};
    use synvoid_core::streaming_waf::{StreamingWafDecision, StreamingWafScanner};
    use synvoid_http::streaming_waf_body::StreamingWafBody;
    /// Test-only adapter mirroring the intended production shape:
    /// poll the EggServe stream as `http_body` frames so the existing
    /// `StreamingWafBody` machinery consumes it unchanged.
    struct EggserveBodyAdapter {
        body: Pin<Box<RequestBody>>,
    }

    impl EggserveBodyAdapter {
        fn new(body: RequestBody) -> Self {
            Self {
                body: Box::pin(body),
            }
        }
    }

    impl http_body::Body for EggserveBodyAdapter {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, io::Error>>> {
            use futures::Stream as _;
            match self.body.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    Poll::Ready(Some(Ok(http_body::Frame::data(chunk))))
                }
                Poll::Ready(Some(Err(e))) => {
                    Poll::Ready(Some(Err(io::Error::other(e.to_string()))))
                }
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    /// Test scanner standing in for the WAF streaming scanner: blocks on a
    /// marker, counts every byte the machinery actually delivered.
    struct MarkerScanner {
        marker: &'static [u8],
        seen: Arc<AtomicUsize>,
    }

    impl StreamingWafScanner for MarkerScanner {
        fn scan_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision {
            self.seen.fetch_add(chunk.len(), Ordering::SeqCst);
            let hit = chunk.windows(self.marker.len()).any(|w| w == self.marker);
            if hit {
                StreamingWafDecision::Block(403, "prototype marker".to_string())
            } else {
                StreamingWafDecision::Continue
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum PrototypeBodyError {
        BlockedByWaf,
        BodyTooLarge { limit: usize, received: u64 },
        Transport(String),
    }

    /// Drive an EggServe body through the current streaming WAF machinery
    /// with an explicit SynVoid-owned size limit. The EggServe-side limit is
    /// expected to be non-preempting (`Stream { max_bytes: u64::MAX }` or the
    /// runtime ceiling held `External`); this loop is the authority that
    /// renders 413-equivalent (`BodyTooLarge`) and WAF-block
    /// (`BlockedByWaf`) outcomes.
    async fn drive_prototype(
        body: RequestBody,
        marker: Option<&'static [u8]>,
        synvoid_limit: usize,
        seen: &Arc<AtomicUsize>,
    ) -> Result<(Bytes, u64), PrototypeBodyError> {
        use http_body::Body as _;
        let scanner = marker.map(|m| MarkerScanner {
            marker: m,
            seen: seen.clone(),
        });
        let adapter = EggserveBodyAdapter::new(body);
        let client_ip = std::net::IpAddr::from([127, 0, 0, 1]);
        let mut wrapped = StreamingWafBody::new(adapter, scanner, client_ip);
        let mut pinned = Pin::new(&mut wrapped);
        let mut out = Vec::new();
        let mut total: u64 = 0;
        loop {
            let frame = std::future::poll_fn(|cx| pinned.as_mut().poll_frame(cx)).await;
            match frame {
                None => break,
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        total += data.len() as u64;
                        if total > synvoid_limit as u64 {
                            return Err(PrototypeBodyError::BodyTooLarge {
                                limit: synvoid_limit,
                                received: total,
                            });
                        }
                        out.extend_from_slice(data);
                    }
                }
                Some(Err(e)) => {
                    if e.kind() == io::ErrorKind::PermissionDenied {
                        return Err(PrototypeBodyError::BlockedByWaf);
                    }
                    return Err(PrototypeBodyError::Transport(e.to_string()));
                }
            }
        }
        Ok((Bytes::from(out), total))
    }

    fn seen_counter() -> Arc<AtomicUsize> {
        Arc::new(AtomicUsize::new(0))
    }

    const NO_MARKER: Option<&'static [u8]> = None;
    const LIMIT_1M: usize = 1024 * 1024;

    #[tokio::test]
    async fn empty_body_reaches_waf_machinery() {
        let seen = seen_counter();
        let body = RequestBody::empty();
        let (bytes, total) = drive_prototype(body, NO_MARKER, LIMIT_1M, &seen)
            .await
            .unwrap();
        assert!(bytes.is_empty());
        assert_eq!(total, 0);
        assert_eq!(seen.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fixed_content_length_body() {
        let seen = seen_counter();
        let body = RequestBody::from_bytes(b"hello world".to_vec(), u64::MAX);
        assert_eq!(body.declared_length(), Some(11));
        let (bytes, total) = drive_prototype(body, NO_MARKER, LIMIT_1M, &seen)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"hello world");
        assert_eq!(total, 11);
        // No marker configured, so no scanner is installed.
        assert_eq!(seen.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn multi_frame_body_preserves_order() {
        let seen = seen_counter();
        let chunks = vec![
            Ok::<Bytes, IncomingError>(Bytes::from_static(b"hel")),
            Ok::<Bytes, IncomingError>(Bytes::from_static(b"lo ")),
            Ok::<Bytes, IncomingError>(Bytes::from_static(b"world")),
        ];
        let stream = futures::stream::iter(chunks);
        let body = RequestBody::from_incoming(stream, Some(11), u64::MAX);
        let (bytes, total) = drive_prototype(body, NO_MARKER, LIMIT_1M, &seen)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"hello world");
        assert_eq!(total, 11);
    }

    #[tokio::test]
    async fn chunked_unknown_length_body() {
        let seen = seen_counter();
        let chunks = vec![
            Ok::<Bytes, IncomingError>(Bytes::from_static(b"chunk")),
            Ok::<Bytes, IncomingError>(Bytes::from_static(b"ed-body")),
        ];
        let stream = futures::stream::iter(chunks);
        let body = RequestBody::from_incoming(stream, None, u64::MAX);
        assert_eq!(body.declared_length(), None);
        let (bytes, total) = drive_prototype(body, NO_MARKER, LIMIT_1M, &seen)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"chunked-body");
        assert_eq!(total, 12);
    }

    #[tokio::test]
    async fn trailers_surface_after_completion() {
        let mut block = HeaderBlock::new();
        block.push_str("x-checksum", "abc").unwrap();
        let trailers = Trailers::new(block).unwrap();
        let mut body = RequestBody::from_bytes_with_trailers(b"data".to_vec(), u64::MAX, trailers);
        let mut collected = Vec::new();
        while let Some(chunk) = body.next_chunk().await.unwrap() {
            collected.extend_from_slice(&chunk);
        }
        assert_eq!(&collected[..], b"data");
        let got = body.trailers().await.unwrap().unwrap();
        assert_eq!(got.as_block().len(), 1);
        assert_eq!(
            got.as_block().get_first("x-checksum").unwrap().as_bytes(),
            b"abc"
        );
    }

    #[tokio::test]
    async fn body_transport_error_maps_to_transport() {
        let seen = seen_counter();
        let chunks = vec![Err::<Bytes, IncomingError>(IncomingError(
            "boom".to_string(),
        ))];
        let stream = futures::stream::iter(chunks);
        let body = RequestBody::from_incoming(stream, None, u64::MAX);
        let err = drive_prototype(body, NO_MARKER, LIMIT_1M, &seen)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PrototypeBodyError::Transport(ref m) if m.contains("boom")),
            "unexpected: {err:?}"
        );
    }

    #[tokio::test]
    async fn early_drop_marks_network_body_abandoned() {
        use futures::StreamExt as _;
        let stream = futures::stream::iter(vec![Ok::<Bytes, IncomingError>(Bytes::from_static(
            b"partial",
        ))])
        .chain(futures::stream::pending::<Result<Bytes, IncomingError>>());
        let mut body = RequestBody::from_incoming(stream, None, u64::MAX);
        let shared = body.shared();
        let first = body.next_chunk().await.unwrap().unwrap();
        assert_eq!(&first[..], b"partial");
        assert!(shared.is_body_active());
        assert!(!shared.is_body_terminal());
        drop(body);
        assert!(shared.is_body_terminal());
    }

    #[tokio::test]
    async fn synvoid_size_limit_wins_over_non_preempting_eggserve_policy() {
        // Intended production shape: Stream with a non-preempting limit plus
        // `global_request_body_ceiling = External`; the SynVoid limit below
        // (1024) must fire first on a 4096-byte body.
        let seen = seen_counter();
        let policy = RequestBodyPolicy::Stream {
            max_bytes: u64::MAX,
        };
        assert!(policy.allows_stream());
        let body = RequestBody::from_bytes(vec![0u8; 4096], policy.max_bytes().unwrap());
        let err = drive_prototype(body, NO_MARKER, 1024, &seen)
            .await
            .unwrap_err();
        // Fixed bodies yield up to 8 KiB per chunk, so the first chunk
        // already exceeds the 1024-byte SynVoid limit.
        assert_eq!(
            err,
            PrototypeBodyError::BodyTooLarge {
                limit: 1024,
                received: 4096,
            }
        );
    }

    #[tokio::test]
    async fn narrow_eggserve_limit_preempts_and_must_not_be_production_shape() {
        // Counter-case proving why the production shape must NOT use a
        // narrow EggServe limit: EggServe 413s before SynVoid
        // accounting/WAF sees the bytes.
        let mut body = RequestBody::from_bytes(b"hello".to_vec(), 3);
        let err = body.next_chunk().await.unwrap_err();
        assert!(err.is_limit_exceeded(), "unexpected: {err:?}");
        assert!(matches!(err, RequestBodyError::LimitExceeded { .. }));
    }

    #[tokio::test]
    async fn waf_block_fires_mid_stream() {
        let seen = seen_counter();
        let chunks = vec![
            Ok::<Bytes, IncomingError>(Bytes::from_static(b"clean clean ")),
            Ok::<Bytes, IncomingError>(Bytes::from_static(b"BLOCKME now")),
        ];
        let stream = futures::stream::iter(chunks);
        let body = RequestBody::from_incoming(stream, None, u64::MAX);
        let err = drive_prototype(body, Some(b"BLOCKME"), LIMIT_1M, &seen)
            .await
            .unwrap_err();
        assert_eq!(err, PrototypeBodyError::BlockedByWaf);
        // Both chunks reached the scanner; the block fired on the second,
        // i.e. mid-stream rather than as a pre-scan.
        assert_eq!(seen.load(Ordering::SeqCst), 23);
    }

    #[test]
    fn intended_production_ownership_shape_is_representable() {
        let ownership = H1PolicyOwnership {
            global_request_body_ceiling: PolicyOwner::External,
            ..H1PolicyOwnership::eggserve_owned()
        };
        assert_eq!(ownership.global_request_body_ceiling, PolicyOwner::External);
        assert_ne!(ownership, H1PolicyOwnership::eggserve_owned());
    }
}

// =====================================================================
// Workstream F — tunnel/WebSocket: one neutral one-shot upgrade
// capability over Hyper `OnUpgrade` and EggServe `TunnelCapability`.
// SynVoid keeps WebSocket validation; the handler only sees Tokio
// `AsyncRead + AsyncWrite`.
// =====================================================================
mod tunnel_capability {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bytes::Bytes;
    use eggserve_primitives::tunnel::{
        validate_handshake_headers, ProtocolName, TunnelKind, TunnelRequest,
    };
    use eggserve_primitives::{
        canonical::{ResponseBody, StatusCode},
        HeaderBlock, RequestBodyPolicy,
    };
    use eggserve_server::tunnel::{TunnelCapability, TunnelIo, TunnelShared};
    use eggserve_server::ResponseMetadataOwnership;
    use eggserve_server::{
        service_fn_with_tunnel, ConnectionContext, ConnectionShutdown, Request, RuntimeConfig,
        RuntimeState,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const RFC_WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const RFC_WS_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn ws_accept_value(key: &str) -> String {
        use base64::Engine as _;
        use sha1::Digest as _;
        let mut h = sha1::Sha1::new();
        h.update(key.as_bytes());
        h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    }

    fn header_map_from_eggserve(block: &HeaderBlock) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for field in block.iter() {
            if let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(field.name.as_str().as_bytes()),
                http::HeaderValue::from_bytes(field.value.as_bytes()),
            ) {
                map.append(name, value);
            }
        }
        map
    }

    fn ws_request_bytes(key: &str) -> Vec<u8> {
        format!(
            "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
        )
        .into_bytes()
    }

    /// Shared wire assertion: the neutral handshake decision rendered by
    /// either transport. Header names match case-insensitively; the accept
    /// value matches case-sensitively (base64).
    fn assert_ws_handshake_wire(wire: &str, expected_accept: &str) {
        let lower = wire.to_ascii_lowercase();
        assert!(lower.contains("http/1.1 101"), "wire: {wire}");
        assert!(lower.contains("upgrade: websocket"), "wire: {wire}");
        assert!(lower.contains("connection: upgrade"), "wire: {wire}");
        assert!(
            wire.contains(expected_accept),
            "accept mismatch in wire: {wire}"
        );
        assert!(
            lower.contains("sec-websocket-protocol: chat"),
            "wire: {wire}"
        );
    }

    async fn read_until_marker(socket: &mut TcpStream, marker: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
                .await
                .expect("read timeout")
                .expect("read failed");
            assert!(n > 0, "connection closed before marker");
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(marker.len()).any(|w| w == marker) {
                break;
            }
        }
        buf
    }

    /// Read the 101 head, then the echo. Bytes already buffered past the
    /// head (same-segment echo) are consumed first, never discarded.
    async fn read_handshake_and_echo(socket: &mut TcpStream) -> (String, Vec<u8>) {
        let wire = read_until_marker(socket, b"\r\n\r\n").await;
        let head_end = wire
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("head marker")
            + 4;
        let head = String::from_utf8_lossy(&wire[..head_end]).into_owned();
        let mut echo = wire[head_end..].to_vec();
        while echo.len() < 14 {
            let mut tmp = [0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
                .await
                .expect("echo timeout")
                .expect("echo read failed");
            assert!(n > 0, "tunnel closed before echo");
            echo.extend_from_slice(&tmp[..n]);
        }
        echo.truncate(14);
        (head, echo)
    }

    async fn spawn_eggserve_ws_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let runtime = RuntimeConfig::default();
        let policy = Arc::new(
            runtime
                .h1_connection_policy()
                .unwrap()
                .with_response_metadata_ownership(ResponseMetadataOwnership {
                    date: eggserve_server::PolicyOwner::External,
                    server: eggserve_server::PolicyOwner::External,
                }),
        );
        let state = Arc::new(RuntimeState::try_new(&runtime).unwrap());
        let shutdown = ConnectionShutdown::new();
        let server_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            // EggServe service embedding the neutral decision: SynVoid-owned
            // validation first, then one-shot accept; declined capabilities
            // stay ordinary HTTP.
            let service = service_fn_with_tunnel(
                |req: Request, tunnel: Option<TunnelCapability>| async move {
                    use eggserve_server::ServiceError;
                    let Some(capability) = tunnel else {
                        return Ok(eggserve_primitives::canonical::Response::builder()
                            .status(StatusCode::OK)
                            .body(ResponseBody::Bytes(b"ordinary".to_vec()))
                            .unwrap());
                    };
                    // WebSocket validation stays SynVoid-owned.
                    let map = header_map_from_eggserve(req.head().headers());
                    if !synvoid_http::validation_helpers::validate_websocket_upgrade(&map) {
                        drop(capability);
                        return Ok(eggserve_primitives::canonical::Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(ResponseBody::Empty)
                            .unwrap());
                    }
                    let key = req
                        .head()
                        .headers()
                        .get_first("sec-websocket-key")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let subprotocol = req
                        .head()
                        .headers()
                        .get_first("sec-websocket-protocol")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let mut handshake = HeaderBlock::new();
                    handshake
                        .push_str("sec-websocket-accept", ws_accept_value(&key))
                        .unwrap();
                    if !subprotocol.is_empty() {
                        handshake
                            .push_str("sec-websocket-protocol", subprotocol)
                            .unwrap();
                    }
                    capability
                        .accept(handshake, |mut io: TunnelIo| async move {
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
                        })
                        .map_err(|e| ServiceError::internal(e.to_string()))
                },
            );
            let _ = eggserve_server::serve_http1_connection_with_policy(
                stream,
                service,
                policy,
                ConnectionContext::for_tcp(addr, peer, None),
                state,
                &server_shutdown,
            )
            .await;
        });
        addr
    }

    #[tokio::test]
    async fn eggserve_accept_preserves_handshake_and_readahead_echo() {
        // The RFC 6455 reference vector proves the accept computation, not
        // just self-consistency.
        assert_eq!(ws_accept_value(RFC_WS_KEY), RFC_WS_ACCEPT);
        let addr = spawn_eggserve_ws_server().await;
        let mut socket = TcpStream::connect(addr).await.unwrap();
        let mut request = ws_request_bytes(RFC_WS_KEY);
        // Immediate post-upgrade bytes: must be delivered exactly once.
        request.extend_from_slice(b"PING-READAHEAD");
        socket.write_all(&request).await.unwrap();
        let (head, echo) = read_handshake_and_echo(&mut socket).await;
        assert_ws_handshake_wire(&head, RFC_WS_ACCEPT);
        assert_eq!(&echo, b"PING-READAHEAD");
        drop(socket);
    }

    #[tokio::test]
    async fn eggserve_declined_capability_stays_ordinary_http() {
        let addr = spawn_eggserve_ws_server().await;
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut wire = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut wire))
            .await
            .expect("read timeout")
            .expect("read failed");
        let text = String::from_utf8_lossy(&wire).to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 200"), "{text}");
        assert!(text.ends_with("ordinary"), "{text}");
        assert!(!text.contains("101"), "{text}");
    }

    #[tokio::test]
    async fn hyper_upgrade_serves_the_same_neutral_decision() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper::service::service_fn(
                |req: hyper::Request<hyper::body::Incoming>| async move {
                    if !synvoid_http::validation_helpers::validate_websocket_upgrade(req.headers())
                    {
                        let resp = hyper::Response::builder()
                            .status(200)
                            .body(http_body_util::Full::new(Bytes::from_static(b"ordinary")))
                            .unwrap();
                        return Ok::<_, std::convert::Infallible>(resp);
                    }
                    let key = req.headers()["sec-websocket-key"]
                        .to_str()
                        .unwrap()
                        .to_string();
                    let subprotocol = req.headers()["sec-websocket-protocol"]
                        .to_str()
                        .unwrap()
                        .to_string();
                    // Same neutral decision as the EggServe service above.
                    let accept = ws_accept_value(&key);
                    let upgraded = hyper::upgrade::on(req);
                    tokio::spawn(async move {
                        if let Ok(up) = upgraded.await {
                            let mut io = hyper_util::rt::TokioIo::new(up);
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
                        }
                    });
                    let resp = hyper::Response::builder()
                        .status(101)
                        .header("upgrade", "websocket")
                        .header("connection", "upgrade")
                        .header("sec-websocket-accept", accept)
                        .header("sec-websocket-protocol", subprotocol)
                        .body(http_body_util::Full::new(Bytes::new()))
                        .unwrap();
                    Ok::<_, std::convert::Infallible>(resp)
                },
            );
            let _ =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await;
        });
        let mut socket = TcpStream::connect(addr).await.unwrap();
        let mut request = ws_request_bytes(RFC_WS_KEY);
        request.extend_from_slice(b"PING-READAHEAD");
        socket.write_all(&request).await.unwrap();
        let (head, echo) = read_handshake_and_echo(&mut socket).await;
        assert_ws_handshake_wire(&head, RFC_WS_ACCEPT);
        assert_eq!(&echo, b"PING-READAHEAD");
        drop(socket);
    }

    /// The proposed neutral contract: validated intent plus a one-shot
    /// accept. Both transports back it (live proofs above); the unit tests
    /// below pin its semantics on the EggServe capability type.
    struct NeutralUpgrade {
        protocol: &'static str,
        accepted: bool,
    }

    impl NeutralUpgrade {
        fn accept_once(&mut self) -> Result<(), &'static str> {
            if self.accepted {
                return Err("already accepted");
            }
            self.accepted = true;
            Ok(())
        }
    }

    #[test]
    fn neutral_capability_is_one_shot() {
        let mut cap = NeutralUpgrade {
            protocol: "websocket",
            accepted: false,
        };
        assert_eq!(cap.protocol, "websocket");
        cap.accept_once().unwrap();
        assert_eq!(cap.accept_once().unwrap_err(), "already accepted");
    }

    #[test]
    fn eggserve_capability_accept_is_consuming_and_yields_101() {
        let request = TunnelRequest::new(
            TunnelKind::Http1Upgrade,
            Some(ProtocolName::new("websocket").unwrap()),
            None,
        );
        assert_eq!(request.kind(), TunnelKind::Http1Upgrade);
        let shared = Arc::new(TunnelShared::new());
        let sidecar = Arc::new(Mutex::new(None));
        let capability = TunnelCapability::new(request, None, shared.clone(), sidecar);
        let mut headers = HeaderBlock::new();
        headers
            .push_str("sec-websocket-accept", RFC_WS_ACCEPT)
            .unwrap();
        // `accept` consumes the capability: a second accept is a
        // compile-time impossibility, and the shared state agrees.
        let handshake = capability
            .accept(headers, |_io: TunnelIo| async move {})
            .unwrap();
        assert_eq!(handshake.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert!(!shared.try_accept());
    }

    #[test]
    fn handshake_rejects_forbidden_framing() {
        // Applications never control framing: content-length in handshake
        // headers is a deterministic error, not a silent strip.
        let mut headers = HeaderBlock::new();
        headers.push_str("content-length", "4").unwrap();
        assert!(validate_handshake_headers(&mut headers).is_err());
    }

    #[test]
    fn service_body_policy_and_reject_shape() {
        // Sanity on the imported policy vocabulary used by the services.
        assert!(RequestBodyPolicy::Reject.is_reject());
    }
}

// =====================================================================
// Workstream G — connection drop: a cloned EggServe `ConnectionShutdown`
// represents the WAF Drop contract (terminal response selected first,
// response committed, keep-alive closed, no truncation).
// =====================================================================
mod connection_drop {
    use std::sync::Arc;
    use std::time::Duration;

    use eggserve_primitives::canonical::{ResponseBody, StatusCode};
    use eggserve_server::{ConnectionContext, ConnectionShutdown, RuntimeConfig, RuntimeState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn shutdown_token_is_cloneable_idempotent_and_level_triggered() {
        let token = ConnectionShutdown::new();
        assert!(!token.is_shutdown());
        let clone = token.clone();
        // Signal-before-wait is observed promptly (level-triggered).
        clone.shutdown();
        assert!(token.is_shutdown());
        tokio::time::timeout(Duration::from_secs(5), token.cancelled())
            .await
            .expect("cancelled() must complete after shutdown");
        // Idempotent: repeated calls have no additional effect.
        token.shutdown();
        assert!(token.is_shutdown());
        // Independent tokens are independent connections.
        let other = ConnectionShutdown::new();
        assert!(!other.is_shutdown());
        let _ = Arc::new(token);
    }

    #[tokio::test]
    async fn waf_drop_maps_to_response_then_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let runtime = RuntimeConfig::default();
        let policy = Arc::new(runtime.h1_connection_policy().unwrap());
        let state = Arc::new(RuntimeState::try_new(&runtime).unwrap());
        let shutdown = ConnectionShutdown::new();
        let server_shutdown = shutdown.clone();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let fire = server_shutdown.clone();
            let service = eggserve_server::service_fn(move |_req: eggserve_server::Request| {
                let fire = fire.clone();
                async move {
                    // WAF Drop order: select the terminal response first, then
                    // signal graceful connection shutdown (the drop callback).
                    let response = eggserve_primitives::canonical::Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(ResponseBody::Bytes(b"blocked".to_vec()))
                        .unwrap();
                    fire.shutdown();
                    Ok(response)
                }
            });
            let _ = eggserve_server::serve_http1_connection_with_policy(
                stream,
                service,
                policy,
                ConnectionContext::for_tcp(addr, peer, None),
                state,
                &server_shutdown,
            )
            .await;
        });

        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /evil HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        // Read the full terminal response: headers, then exactly the
        // declared body (proves no truncation).
        let mut wire = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
                .await
                .expect("read timeout")
                .expect("read failed");
            assert!(n > 0, "closed before full response");
            wire.extend_from_slice(&tmp[..n]);
            if wire.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head_end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8_lossy(&wire[..head_end]).to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 403"), "{head}");
        let content_length: usize = head
            .lines()
            .find(|l| l.starts_with("content-length:"))
            .and_then(|l| l["content-length:".len()..].trim().parse().ok())
            .expect("terminal response must carry content-length");
        assert_eq!(content_length, 7);
        let mut body = wire[head_end..].to_vec();
        while body.len() < content_length {
            let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
                .await
                .expect("body timeout")
                .expect("body read failed");
            assert!(n > 0, "truncated terminal response");
            body.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(&body[..], b"blocked");
        // Keep-alive is closed: EOF follows, so no second request is
        // accepted afterward.
        let eof = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
            .await
            .expect("eof timeout")
            .expect("eof read failed");
        assert_eq!(eof, 0, "connection must close after Drop response");
        let text = String::from_utf8_lossy(&wire).to_ascii_lowercase();
        assert_eq!(text.matches("http/1.1").count(), 1);
        drop(socket);
        let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
    }
}

// =====================================================================
// Workstream H — response stream: `http::Response<BoxBody<Bytes,
// Infallible>>` -> EggServe canonical responses without full buffering.
// EggServe stays the final framing authority; SynVoid stays the
// application/security metadata authority (subject to the Workstream D
// external-ownership gate).
// =====================================================================
mod response_stream {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use eggserve_primitives::canonical::{
        normalize_response, BodyLength, NormalizeRequest, Response, ResponseBody, ResponseStream,
        ResponseStreamError, StatusCode,
    };
    use eggserve_primitives::{HeaderBlock, HeaderName, HeaderValue, Trailers};
    use futures::{Stream, StreamExt as _};
    use http_body::{Body as _, Frame};
    use http_body_util::combinators::BoxBody;
    use http_body_util::BodyExt;

    /// Test-only lazy bridge mirroring the intended production adapter:
    /// frames are pulled on demand (never buffered by the converter) and
    /// terminal trailer frames are captured for the canonical trailer slot.
    struct LazyFrameStream {
        inner: Option<BoxBody<Bytes, std::convert::Infallible>>,
        polls: Arc<AtomicUsize>,
        trailers_out: Arc<std::sync::Mutex<Option<Trailers>>>,
    }

    impl Stream for LazyFrameStream {
        type Item = Result<Bytes, ResponseStreamError>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            let this = self.get_mut();
            loop {
                let body = this.inner.as_mut().expect("polled after end");
                match Pin::new(body).poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                        Ok(data) => return Poll::Ready(Some(Ok(data))),
                        Err(frame) => {
                            if let Some(tr) = frame.trailers_ref() {
                                let mut block = HeaderBlock::new();
                                for (name, value) in tr.iter() {
                                    let n = HeaderName::new(name.as_str()).unwrap();
                                    let v = HeaderValue::from_bytes(value.as_bytes()).unwrap();
                                    block.push(n, v);
                                }
                                if let Ok(trailers) = Trailers::new(block) {
                                    *this.trailers_out.lock().unwrap() = Some(trailers);
                                }
                            }
                            continue;
                        }
                    },
                    Poll::Ready(Some(Err(never))) => match never {},
                    Poll::Ready(None) => {
                        this.inner = None;
                        return Poll::Ready(None);
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    /// Convert without full buffering: buffered `Bytes` only when the
    /// source advertises an exact length and streaming was not forced;
    /// otherwise a lazy canonical `Stream` (unknown length, or the known
    /// length plus a terminal-trailer future when the hint exists).
    ///
    /// Prototype limit, matching the upstream runtime: unknown-length
    /// streams carry no trailer future (upstream offers
    /// `with_known_length_and_trailers` only).
    async fn convert_response(
        resp: http::Response<BoxBody<Bytes, std::convert::Infallible>>,
        force_stream: bool,
        polls: &Arc<AtomicUsize>,
        trailers_out: &Arc<std::sync::Mutex<Option<Trailers>>>,
    ) -> Result<Response, String> {
        let (parts, body) = resp.into_parts();
        let status = StatusCode::new(parts.status.as_u16()).map_err(|e| e.to_string())?;
        let mut fields = Vec::new();
        for (name, value) in parts.headers.iter() {
            let n = HeaderName::new(name.as_str()).map_err(|e| e.to_string())?;
            let v = HeaderValue::from_bytes(value.as_bytes()).map_err(|e| e.to_string())?;
            fields.push((n, v));
        }
        let mut headed = Response::builder().status(status);
        for (n, v) in &fields {
            headed = headed.push_header(n.clone(), v.clone());
        }
        let exact = body.size_hint().exact();
        if !force_stream && exact.is_some() {
            let bytes = match body.collect().await {
                Ok(c) => c.to_bytes(),
                Err(never) => match never {},
            };
            // Zero-length sources stay `Empty` (no invented framing).
            let canonical = if bytes.is_empty() {
                ResponseBody::Empty
            } else {
                ResponseBody::Bytes(bytes.to_vec())
            };
            return headed.body(canonical).map_err(|e| e.to_string());
        }
        let lazy = LazyFrameStream {
            inner: Some(body),
            polls: polls.clone(),
            trailers_out: trailers_out.clone(),
        };
        let stream = match exact {
            Some(len) if force_stream => {
                let slot = trailers_out.clone();
                let trailer_future = Box::pin(async move { Ok(slot.lock().unwrap().take()) });
                ResponseStream::with_known_length_and_trailers(lazy, len, trailer_future)
            }
            _ => ResponseStream::new(lazy),
        };
        headed
            .body(ResponseBody::Stream(stream))
            .map_err(|e| e.to_string())
    }

    fn empty_slot() -> Arc<std::sync::Mutex<Option<Trailers>>> {
        Arc::new(std::sync::Mutex::new(None))
    }

    fn no_polls() -> Arc<AtomicUsize> {
        Arc::new(AtomicUsize::new(0))
    }

    #[tokio::test]
    async fn empty_response_maps_to_empty() {
        let polls = no_polls();
        let slot = empty_slot();
        let resp = http::Response::builder()
            .status(200)
            .body(http_body_util::Empty::<Bytes>::new().boxed())
            .unwrap();
        let converted = convert_response(resp, false, &polls, &slot).await.unwrap();
        assert_eq!(converted.status(), StatusCode::OK);
        assert!(matches!(converted.body(), Some(ResponseBody::Empty)));
        assert!(matches!(
            converted.body().unwrap().body_length(),
            BodyLength::Known(0)
        ));
    }

    #[tokio::test]
    async fn fixed_bytes_map_to_bytes() {
        let polls = no_polls();
        let slot = empty_slot();
        let resp = http::Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(http_body_util::Full::new(Bytes::from_static(b"fixed")).boxed())
            .unwrap();
        let converted = convert_response(resp, false, &polls, &slot).await.unwrap();
        assert!(matches!(
            converted.body(),
            Some(ResponseBody::Bytes(b)) if b == b"fixed"
        ));
        assert!(matches!(
            converted.body().unwrap().body_length(),
            BodyLength::Known(5)
        ));
    }

    #[tokio::test]
    async fn unknown_length_stream_stays_lazy() {
        let polls = no_polls();
        let slot = empty_slot();
        let frames = vec![
            Ok::<http_body::Frame<Bytes>, std::convert::Infallible>(http_body::Frame::data(
                Bytes::from_static(b"chunk-"),
            )),
            Ok::<http_body::Frame<Bytes>, std::convert::Infallible>(http_body::Frame::data(
                Bytes::from_static(b"one"),
            )),
        ];
        let body = BodyExt::boxed(http_body_util::StreamBody::new(futures::stream::iter(
            frames,
        )));
        assert_eq!(body.size_hint().exact(), None);
        let resp = http::Response::builder().status(200).body(body).unwrap();
        let converted = convert_response(resp, false, &polls, &slot).await.unwrap();
        // Conversion itself must not poll the source.
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            converted.body(),
            Some(ResponseBody::Stream(s)) if s.known_length().is_none()
        ));
        assert!(matches!(
            converted.body().unwrap().body_length(),
            BodyLength::Unknown
        ));
        let mut stream = converted;
        let taken = stream.take_body().unwrap();
        let ResponseBody::Stream(s) = taken else {
            panic!("expected stream");
        };
        let mut pinned = Box::pin(s);
        let mut out = Vec::new();
        while let Some(chunk) = pinned.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(&out, b"chunk-one");
        assert!(polls.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test]
    async fn known_length_stream_preserves_length_hint() {
        let polls = no_polls();
        let slot = empty_slot();
        // Exact-hint multi-frame source, forced through the streaming path.
        struct TwoFrames {
            chunks: Vec<Bytes>,
        }
        impl http_body::Body for TwoFrames {
            type Data = Bytes;
            type Error = std::convert::Infallible;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
                if self.chunks.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(http_body::Frame::data(self.chunks.remove(0)))))
                }
            }
            fn size_hint(&self) -> http_body::SizeHint {
                http_body::SizeHint::with_exact(11)
            }
        }
        let body = TwoFrames {
            chunks: vec![Bytes::from_static(b"hello "), Bytes::from_static(b"world")],
        };
        let boxed: BoxBody<Bytes, std::convert::Infallible> = body.boxed();
        let resp = http::Response::builder().status(200).body(boxed).unwrap();
        let converted = convert_response(resp, true, &polls, &slot).await.unwrap();
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            converted.body(),
            Some(ResponseBody::Stream(s)) if s.known_length() == Some(11)
        ));
        assert!(matches!(
            converted.body().unwrap().body_length(),
            BodyLength::Known(11)
        ));
    }

    #[tokio::test]
    async fn upstream_early_termination_surfaces_as_stream_error() {
        // A canonical stream whose producer fails mid-body: the error
        // surfaces at the EggServe layer without synthesizing bytes.
        struct FailAfterOne {
            sent: bool,
        }
        impl Stream for FailAfterOne {
            type Item = Result<Bytes, ResponseStreamError>;
            fn poll_next(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                if self.sent {
                    Poll::Ready(Some(Err(ResponseStreamError::new("upstream reset"))))
                } else {
                    self.sent = true;
                    Poll::Ready(Some(Ok(Bytes::from_static(b"partial-"))))
                }
            }
        }
        let stream = ResponseStream::new(FailAfterOne { sent: false });
        let mut pinned = Box::pin(stream);
        let first = pinned.next().await.unwrap().unwrap();
        assert_eq!(&first[..], b"partial-");
        let err = pinned.next().await.unwrap().unwrap_err();
        // Upstream detail is sanitized at the canonical layer: the error
        // surfaces without leaking transport text.
        assert_eq!(err.to_string(), "response stream failed");
    }

    #[tokio::test]
    async fn trailers_cross_with_known_length_stream() {
        let polls = no_polls();
        let slot = empty_slot();
        // Exact-hint source emitting data, then one terminal trailer frame.
        struct TrailerFrames {
            chunks: Vec<Bytes>,
            trailers: Option<http::HeaderMap>,
        }
        impl http_body::Body for TrailerFrames {
            type Data = Bytes;
            type Error = std::convert::Infallible;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
                if !self.chunks.is_empty() {
                    Poll::Ready(Some(Ok(Frame::data(self.chunks.remove(0)))))
                } else if let Some(t) = self.trailers.take() {
                    Poll::Ready(Some(Ok(Frame::trailers(t))))
                } else {
                    Poll::Ready(None)
                }
            }
            fn size_hint(&self) -> http_body::SizeHint {
                http_body::SizeHint::with_exact(4)
            }
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", "abc".parse().unwrap());
        let body = TrailerFrames {
            chunks: vec![Bytes::from_static(b"data")],
            trailers: Some(trailers),
        };
        let boxed: BoxBody<Bytes, std::convert::Infallible> = body.boxed();
        let resp = http::Response::builder().status(200).body(boxed).unwrap();
        let converted = convert_response(resp, true, &polls, &slot).await.unwrap();
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        let mut converted = converted;
        let taken = converted.take_body().unwrap();
        let ResponseBody::Stream(s) = taken else {
            panic!("expected stream");
        };
        let (mut bytes, trailer_future) = s.into_parts();
        let mut out = Vec::new();
        while let Some(chunk) = bytes.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(&out, b"data");
        let trailers = trailer_future
            .expect("known-length stream carries a trailer future")
            .await
            .unwrap()
            .expect("trailer frame must cross");
        assert_eq!(
            trailers
                .as_block()
                .get_first("x-checksum")
                .unwrap()
                .as_bytes(),
            b"abc"
        );
    }

    #[tokio::test]
    async fn head_and_body_forbidden_drop_without_polling() {
        let polls = no_polls();
        let slot = empty_slot();
        struct CountingFrames {
            chunks: Vec<Bytes>,
            polls: Arc<AtomicUsize>,
        }
        impl http_body::Body for CountingFrames {
            type Data = Bytes;
            type Error = std::convert::Infallible;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                if self.chunks.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(http_body::Frame::data(self.chunks.remove(0)))))
                }
            }
            fn size_hint(&self) -> http_body::SizeHint {
                http_body::SizeHint::with_exact(5)
            }
        }
        // HEAD: equivalent-GET length retained, no polling.
        let source_polls = Arc::new(AtomicUsize::new(0));
        let boxed: BoxBody<Bytes, std::convert::Infallible> = CountingFrames {
            chunks: vec![Bytes::from_static(b"hello")],
            polls: source_polls.clone(),
        }
        .boxed();
        let resp = http::Response::builder().status(200).body(boxed).unwrap();
        let converted = convert_response(resp, true, &polls, &slot).await.unwrap();
        let normalized = normalize_response(converted, &NormalizeRequest::new(true)).unwrap();
        assert!(matches!(
            normalized.body(),
            Some(ResponseBody::EmptyWithLength(5))
        ));
        assert_eq!(source_polls.load(Ordering::SeqCst), 0);
        // 204 with a (violating) body: dropped without polling.
        let source_polls = Arc::new(AtomicUsize::new(0));
        let boxed: BoxBody<Bytes, std::convert::Infallible> = CountingFrames {
            chunks: vec![Bytes::from_static(b"hello")],
            polls: source_polls.clone(),
        }
        .boxed();
        let resp = http::Response::builder().status(204).body(boxed).unwrap();
        let converted = convert_response(resp, true, &polls, &slot).await.unwrap();
        let normalized = normalize_response(converted, &NormalizeRequest::new(false)).unwrap();
        assert_eq!(normalized.status(), StatusCode::NO_CONTENT);
        assert!(matches!(
            normalized.body().unwrap().body_length(),
            BodyLength::Known(0)
        ));
        assert_eq!(source_polls.load(Ordering::SeqCst), 0);
        // 304 likewise.
        let boxed: BoxBody<Bytes, std::convert::Infallible> = CountingFrames {
            chunks: vec![Bytes::from_static(b"hello")],
            polls: source_polls.clone(),
        }
        .boxed();
        let resp = http::Response::builder().status(304).body(boxed).unwrap();
        let converted = convert_response(resp, true, &polls, &slot).await.unwrap();
        let normalized = normalize_response(converted, &NormalizeRequest::new(false)).unwrap();
        assert_eq!(normalized.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(source_polls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn duplicate_and_security_headers_preserved() {
        let polls = no_polls();
        let slot = empty_slot();
        let resp = http::Response::builder()
            .status(200)
            .header("date", "Sun, 06 Nov 1994 08:49:37 GMT")
            .header("server", "synvoid-test")
            .header("set-cookie", "a=1")
            .header("content-security-policy", "default-src 'none'")
            .header("cache-control", "no-store")
            .header("alt-svc", "h3=\":443\"")
            .body(http_body_util::Empty::<Bytes>::new().boxed())
            .unwrap();
        let mut resp = resp;
        resp.headers_mut()
            .append("x-repeat", "one".parse().unwrap());
        resp.headers_mut()
            .append("x-repeat", "two".parse().unwrap());
        let converted = convert_response(resp, false, &polls, &slot).await.unwrap();
        let headers = converted.headers();
        assert_eq!(
            headers.get_first("date").unwrap().as_bytes(),
            b"Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(
            headers.get_first("server").unwrap().as_bytes(),
            b"synvoid-test"
        );
        assert_eq!(headers.get_first("set-cookie").unwrap().as_bytes(), b"a=1");
        assert_eq!(
            headers
                .get_first("content-security-policy")
                .unwrap()
                .as_bytes(),
            b"default-src 'none'"
        );
        assert_eq!(
            headers.get_first("alt-svc").unwrap().as_bytes(),
            b"h3=\":443\""
        );
        let repeats: Vec<_> = headers
            .iter()
            .filter(|f| f.name.as_str() == "x-repeat")
            .collect();
        assert_eq!(repeats.len(), 2);
    }
}
