//! Phase 63 shared transport-benchmark primitives.
//!
//! Everything workload-shaped lives here and is identical for both lanes:
//! the deterministic multi-frame request body, the loopback servers, the
//! latency aggregation, and the result envelope. The only lane-specific
//! code is the thin client call in `adapters/legacy_7083f339.rs` and
//! `adapters/eggfetch_current.rs`.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use http_body::Body as HttpBody;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Deterministic multi-frame request body (Workstream B fixture).
///
/// Total payload `total_bytes` split into fixed `frame_bytes` frames (last
/// frame may be shorter). Fill is a deterministic per-byte pattern, so no
/// random allocation happens during timed measurement. Satisfies the
/// stricter legacy bounds (`Send + Sync + Unpin + 'static`, `Error: Error`)
/// so exactly the same body shape can be supplied to both lanes.
pub struct FixtureBody {
    chunks: Vec<Bytes>,
    index: usize,
    delay_per_frame: Option<Duration>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl FixtureBody {
    pub fn new(total_bytes: usize, frame_bytes: usize, delay_per_frame: Option<Duration>) -> Self {
        assert!(total_bytes > 0 && frame_bytes > 0);
        let mut chunks = Vec::new();
        let mut offset = 0usize;
        while offset < total_bytes {
            let len = (total_bytes - offset).min(frame_bytes);
            let mut v = vec![0u8; len];
            for (i, b) in v.iter_mut().enumerate() {
                *b = ((offset + i) % 251) as u8;
            }
            chunks.push(Bytes::from(v));
            offset += len;
        }
        Self {
            chunks,
            index: 0,
            delay_per_frame,
            sleep: None,
        }
    }

    pub fn frame_count(&self) -> usize {
        self.chunks.len()
    }
}

impl HttpBody for FixtureBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if let Some(d) = self.delay_per_frame {
            if self.sleep.is_none() {
                self.sleep = Some(Box::pin(tokio::time::sleep(d)));
            }
            if self.sleep.as_mut().unwrap().as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
        }
        if self.index >= self.chunks.len() {
            return Poll::Ready(None);
        }
        let chunk = self.chunks[self.index].clone();
        self.index += 1;
        Poll::Ready(Some(Ok(http_body::Frame::data(chunk))))
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let remaining: u64 = self.chunks[self.index..]
            .iter()
            .map(|c| c.len() as u64)
            .sum();
        http_body::SizeHint::with_exact(remaining)
    }
}

/// One measured request. `latency_us`/`bytes` are `None` on failure.
#[derive(Clone, Copy)]
pub struct Sample {
    pub latency_us: Option<u64>,
    pub bytes: u64,
}

#[derive(Serialize)]
pub struct LatencyStats {
    pub n: usize,
    pub failures: usize,
    pub duration_ms: f64,
    pub rps: f64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub bytes_total: u64,
}

pub fn summarize(samples: &[Sample], wall: Duration) -> LatencyStats {
    let mut lat: Vec<u64> = samples.iter().filter_map(|s| s.latency_us).collect();
    lat.sort_unstable();
    let failures = samples.len() - lat.len();
    let secs = wall.as_secs_f64().max(1e-9);
    let pct = |p: f64| -> u64 {
        if lat.is_empty() {
            return 0;
        }
        let idx = ((p / 100.0) * lat.len() as f64).ceil() as usize;
        lat[idx.saturating_sub(1).min(lat.len() - 1)]
    };
    LatencyStats {
        n: lat.len(),
        failures,
        duration_ms: wall.as_secs_f64() * 1000.0,
        rps: lat.len() as f64 / secs,
        p50_us: pct(50.0),
        p95_us: pct(95.0),
        p99_us: pct(99.0),
        min_us: lat.first().copied().unwrap_or(0),
        max_us: lat.last().copied().unwrap_or(0),
        bytes_total: samples.iter().map(|s| s.bytes).sum(),
    }
}

/// Provenance envelope written with every run (Workstream A/G).
#[derive(Serialize)]
pub struct RunEnvelope {
    pub lane: String,
    pub workload: String,
    pub revision_sha: String,
    pub harness_sha: String,
    pub adapter_file: String,
    pub adapter_sha: String,
    pub toolchain: String,
    pub host: String,
    pub target: String,
    pub profile: String,
    pub unix_secs: u64,
    pub protocol: String,
    pub requests: usize,
    pub warmup: usize,
    pub concurrency: usize,
    pub payload_total_bytes: usize,
    pub payload_frames: usize,
    pub payload_frame_bytes: usize,
    pub producer_delay_ms: u64,
    pub response_bytes: usize,
    pub stats: LatencyStats,
    pub extra: serde_json::Value,
}

pub fn provenance(lane: &str, workload: &str) -> (String, String, String, String, String, String) {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| "unknown".to_string());
    let _ = (lane, workload);
    (
        env("BENCH_REVISION_SHA"),
        env("BENCH_HARNESS_SHA"),
        env("BENCH_ADAPTER_SHA"),
        env("BENCH_TOOLCHAIN"),
        env("BENCH_HOST"),
        env("BENCH_PROFILE"),
    )
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Drain a response body to completion; measurement ends here on both lanes.
pub async fn drain_body<B>(body: B) -> Result<u64>
where
    B: HttpBody<Data = Bytes>,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    use http_body_util::BodyExt;
    let collected = body.collect().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(collected.to_bytes().len() as u64)
}

// ---------------------------------------------------------------------------
// H1 loopback server (raw TCP, plaintext, keep-alive).
//
// Speaks just enough HTTP/1.1 for the comparison: reads request line +
// headers, drains exactly Content-Length bytes, then responds with a fixed
// body. Identical bytes on the wire for both lanes; the server never knows
// which lane is calling.
// ---------------------------------------------------------------------------

pub struct H1Server {
    pub addr: SocketAddr,
    pub connections: Arc<AtomicUsize>,
    pub requests: Arc<AtomicUsize>,
    _task: tokio::task::JoinHandle<()>,
}

pub async fn start_h1_server(response_bytes: usize) -> Result<H1Server> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let (c, r) = (Arc::clone(&connections), Arc::clone(&requests));
    let body_pattern = Arc::new(pattern_bytes(response_bytes));
    let task = tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            c.fetch_add(1, Ordering::Relaxed);
            let (r2, pat) = (Arc::clone(&r), Arc::clone(&body_pattern));
            tokio::spawn(async move {
                if let Err(e) = serve_h1_conn(sock, &r2, &pat).await {
                    let _ = e;
                }
            });
        }
    });
    Ok(H1Server {
        addr,
        connections,
        requests,
        _task: task,
    })
}

fn pattern_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

async fn read_headers(
    sock: &mut tokio::net::TcpStream,
    buf: &mut Vec<u8>,
) -> Result<(usize, usize)> {
    loop {
        let n = sock.read_buf(buf).await?;
        if n == 0 {
            anyhow::bail!("eof before headers");
        }
        if let Some(pos) = find_double_crlf(buf) {
            let header_len = pos + 4;
            let content_len = parse_content_length(&buf[..header_len]);
            return Ok((header_len, content_len));
        }
        if buf.len() > 1 << 20 {
            anyhow::bail!("headers too large");
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers).to_ascii_lowercase();
    for line in text.lines().skip(1) {
        if let Some(v) = line.strip_prefix("content-length:") {
            return v.trim().parse().unwrap_or(0);
        }
    }
    0
}

async fn serve_h1_conn(
    mut sock: tokio::net::TcpStream,
    requests: &AtomicUsize,
    pattern: &[u8],
) -> Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: keep-alive\r\n\r\n",
        pattern.len()
    );
    let mut buf = Vec::with_capacity(8192);
    loop {
        buf.clear();
        let (header_len, content_len) = match read_headers(&mut sock, &mut buf).await {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        // Drain exactly the declared body; leftover bytes belong to the next
        // pipelined request (clients here never pipeline, but stay correct).
        let mut have = buf.len() - header_len;
        while have < content_len {
            let n = sock.read_buf(&mut buf).await?;
            if n == 0 {
                anyhow::bail!("eof in body");
            }
            have += n;
        }
        requests.fetch_add(1, Ordering::Relaxed);
        sock.write_all(header.as_bytes()).await?;
        // Frame the response body in 16 KiB writes on both lanes' behalf.
        for chunk in pattern.chunks(16 * 1024) {
            sock.write_all(chunk).await?;
        }
    }
}

// ---------------------------------------------------------------------------
// H2 loopback server (TLS + ALPN h2, multiplexed).
//
// Only speaks HTTP/2 prior-knowledge... no: only ALPN-negotiated h2. An H1
// client cannot complete a request here, so every recorded success provably
// ran over H2 on either lane.
// ---------------------------------------------------------------------------

pub struct H2Server {
    pub addr: SocketAddr,
    pub connections: Arc<AtomicUsize>,
    pub requests: Arc<AtomicUsize>,
    _task: tokio::task::JoinHandle<()>,
}

pub async fn start_h2_server(cert_dir: &Path, response_bytes: usize) -> Result<H2Server> {
    use tokio_rustls::TlsAcceptor;

    let ca_note = cert_dir.display().to_string();
    let cert_pem = std::fs::read(cert_dir.join("test-only-loopback-leaf.pem"))
        .with_context(|| format!("read leaf cert in {ca_note}"))?;
    let key_pem = std::fs::read(cert_dir.join("test-only-loopback-leaf.key"))
        .with_context(|| format!("read leaf key in {ca_note}"))?;
    let mut cert_rdr = &cert_pem[..];
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_rdr).collect::<Result<Vec<_>, _>>()?;
    let mut key_rdr = &key_pem[..];
    let key: rustls_pki_types::PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_rdr)?.context("leaf key missing")?;
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let (c, r) = (Arc::clone(&connections), Arc::clone(&requests));
    let pattern = Arc::new(pattern_bytes(response_bytes));
    let task = tokio::spawn(async move {
        use hyper::server::conn::http2::Builder;
        use hyper_util::rt::TokioExecutor;
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let (acceptor, r2, pat, c2) = (
                acceptor.clone(),
                Arc::clone(&r),
                Arc::clone(&pattern),
                Arc::clone(&c),
            );
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                c2.fetch_add(1, Ordering::Relaxed);
                let svc = hyper::service::service_fn(
                    move |_req: hyper::Request<hyper::body::Incoming>| {
                        let (r3, pat2) = (Arc::clone(&r2), Arc::clone(&pat));
                        async move {
                            r3.fetch_add(1, Ordering::Relaxed);
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(Bytes::copy_from_slice(&pat2)),
                            ))
                        }
                    },
                );
                let io = hyper_util::rt::TokioIo::new(tls);
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    Ok(H2Server {
        addr,
        connections,
        requests,
        _task: task,
    })
}
