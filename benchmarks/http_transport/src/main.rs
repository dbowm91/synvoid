//! Phase 63 transport comparison driver (manual-only, never CI).
//!
//! One process invocation runs ONE workload on ONE lane against an
//! in-process loopback server and writes ONE machine-readable JSON result.
//! The comparison script (`scripts/run_comparison.sh`) alternates lanes
//! (ABBA), repeats each workload, and aggregates with `summarize`.

mod common;

#[path = "../adapters/legacy_7083f339.rs"]
mod adapter_legacy;

#[cfg(feature = "eggfetch")]
#[path = "../adapters/eggfetch_current.rs"]
mod adapter_eggfetch;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use common::{now_unix_secs, provenance, summarize, H1Server, RunEnvelope, Sample};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PER_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, PartialEq)]
enum Workload {
    H1Sequential,
    H1Concurrent,
    H2Multiplexed,
    Stream1K,
    Stream64K,
    Stream1M,
    StreamConcurrent,
    StreamSlowProducer,
    EarlyDrop,
    ColdConstruct,
    Stream64KPhases,
}

impl Workload {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "h1-sequential" => Self::H1Sequential,
            "h1-concurrent" => Self::H1Concurrent,
            "h2-multiplexed" => Self::H2Multiplexed,
            "stream-1k" => Self::Stream1K,
            "stream-64k" => Self::Stream64K,
            "stream-1m" => Self::Stream1M,
            "stream-concurrent" => Self::StreamConcurrent,
            "stream-slow-producer" => Self::StreamSlowProducer,
            "early-drop" => Self::EarlyDrop,
            "stream-64k-phases" => Self::Stream64KPhases,
            "cold-construct" => Self::ColdConstruct,
            _ => bail!("unknown workload {s}"),
        })
    }

    fn name(&self) -> &'static str {
        match self {
            Self::H1Sequential => "h1-sequential",
            Self::H1Concurrent => "h1-concurrent",
            Self::H2Multiplexed => "h2-multiplexed",
            Self::Stream1K => "stream-1k",
            Self::Stream64K => "stream-64k",
            Self::Stream1M => "stream-1m",
            Self::StreamConcurrent => "stream-concurrent",
            Self::StreamSlowProducer => "stream-slow-producer",
            Self::EarlyDrop => "early-drop",
            Self::Stream64KPhases => "stream-64k-phases",
            Self::ColdConstruct => "cold-construct",
        }
    }

    fn defaults(&self) -> (usize, usize, usize) {
        // (requests, concurrency, warmup). Streaming counts are sized so a
        // repetition is second-scale, never single-digit-millisecond: tail
        // stalls in a millisecond window dominate the aggregate and cannot
        // adjudicate a >5% rule (Phase 63 run-1 lesson).
        match self {
            Self::H1Sequential => (40_000, 1, 2_000),
            Self::H1Concurrent => (200_000, 8, 10_000),
            Self::H2Multiplexed => (150_000, 16, 5_000),
            Self::Stream1K => (12_000, 1, 500),
            Self::Stream64K => (8_000, 1, 200),
            Self::Stream1M => (800, 1, 20),
            Self::StreamConcurrent => (15_000, 4, 100),
            Self::StreamSlowProducer => (50, 1, 5),
            Self::EarlyDrop => (800, 1, 20),
            Self::Stream64KPhases => (8_000, 1, 200),
            Self::ColdConstruct => (50, 1, 0),
        }
    }

    /// (total_bytes, frame_bytes, producer_delay) for streaming workloads.
    fn stream_geometry(&self) -> Option<(usize, usize, Option<Duration>)> {
        match self {
            Self::Stream1K => Some((1024, 256, None)),
            Self::Stream64K => Some((65_536, 4096, None)),
            Self::Stream1M => Some((1_048_576, 16_384, None)),
            Self::StreamConcurrent => Some((65_536, 4096, None)),
            Self::StreamSlowProducer => Some((65_536, 4096, Some(Duration::from_millis(1)))),
            Self::EarlyDrop => Some((65_536, 4096, None)),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct Config {
    lane: String,
    workload: Workload,
    requests: usize,
    concurrency: usize,
    warmup: usize,
    certs: PathBuf,
    out: PathBuf,
}

fn parse_args() -> Result<Config> {
    let mut lane = None;
    let mut workload = None;
    let mut requests = None;
    let mut concurrency = None;
    let mut warmup = None;
    let mut certs = PathBuf::from("certs");
    let mut out = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--lane" => lane = it.next(),
            "--workload" => {
                workload = Some(Workload::parse(&it.next().context("--workload value")?)?)
            }
            "--requests" => requests = Some(it.next().context("--requests value")?.parse()?),
            "--concurrency" => {
                concurrency = Some(it.next().context("--concurrency value")?.parse()?)
            }
            "--warmup" => warmup = Some(it.next().context("--warmup value")?.parse()?),
            "--certs" => certs = PathBuf::from(it.next().context("--certs value")?),
            "--out" => out = Some(PathBuf::from(it.next().context("--out value")?)),
            _ => bail!("unknown arg {a}"),
        }
    }
    // `summarize` is dispatched in main() before parse_args runs.
    let lane = lane.context("--lane legacy|eggfetch")?;
    let workload = workload.context("--workload ...")?;
    let (dr, dc, dw) = workload.defaults();
    Ok(Config {
        lane,
        workload,
        requests: requests.unwrap_or(dr),
        concurrency: concurrency.unwrap_or(dc),
        warmup: warmup.unwrap_or(dw),
        certs,
        out: out.context("--out <result.json>")?,
    })
}

/// Run `total` ops across `concurrency` tasks; each op is timed end-to-end
/// with a hang guard. Identical fan-out on both lanes.
async fn fan_out<C, F, Fut>(client: C, total: usize, concurrency: usize, op: F) -> Vec<Sample>
where
    C: Clone + Send + 'static,
    F: Fn(C) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = Sample> + Send + 'static,
{
    let concurrency = concurrency.max(1).min(total.max(1));
    let base = total / concurrency;
    let extra = total % concurrency;
    let mut handles = Vec::with_capacity(concurrency);
    for t in 0..concurrency {
        let (c, op) = (client.clone(), op.clone());
        let n = base + usize::from(t < extra);
        handles.push(tokio::spawn(async move {
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(op(c.clone()).await);
            }
            out
        }));
    }
    let mut all = Vec::with_capacity(total);
    for h in handles {
        all.extend(h.await.context("worker join").unwrap_or_default());
    }
    all
}

fn timed_sample<Fut>(fut: Fut) -> impl std::future::Future<Output = Sample> + Send
where
    Fut: std::future::Future<Output = Result<u64>> + Send,
{
    async move {
        let start = Instant::now();
        match tokio::time::timeout(REQUEST_TIMEOUT, fut).await {
            Ok(Ok(bytes)) => Sample {
                latency_us: Some(start.elapsed().as_micros() as u64),
                bytes,
            },
            _ => Sample {
                latency_us: None,
                bytes: 0,
            },
        }
    }
}

async fn run_h1_small(cfg: &Config, server: &H1Server) -> Result<RunEnvelope> {
    let url = format!("http://{}/small", server.addr);
    let (rev, harness, adapter, toolchain, host, profile) =
        provenance(&cfg.lane, cfg.workload.name());
    // Measured wall clock starts AFTER warmup: warmup exists to exclude
    // client construction and connection setup from steady-state evidence.
    let (samples, start) = match cfg.lane.as_str() {
        adapter_legacy::LANE => {
            let client = adapter_legacy::small_client();
            for _ in 0..cfg.warmup {
                let _ = adapter_legacy::small_get(&client, &url, PER_REQUEST_TIMEOUT).await;
            }
            let op = move |c: synvoid_http_client::HttpClient| {
                let url = url.clone();
                timed_sample(async move {
                    adapter_legacy::small_get(&c, &url, PER_REQUEST_TIMEOUT).await
                })
            };
            let start = Instant::now();
            (
                fan_out(client, cfg.requests, cfg.concurrency, op).await,
                start,
            )
        }
        #[cfg(feature = "eggfetch")]
        adapter_eggfetch::LANE => {
            let client = adapter_eggfetch::small_client()?;
            for _ in 0..cfg.warmup {
                let _ = adapter_eggfetch::small_get(&client, &url, PER_REQUEST_TIMEOUT).await;
            }
            let op = move |c: synvoid_http_client::eggfetch_transport::EggfetchUpstreamClient| {
                let url = url.clone();
                timed_sample(async move {
                    adapter_eggfetch::small_get(&c, &url, PER_REQUEST_TIMEOUT).await
                })
            };
            let start = Instant::now();
            (
                fan_out(client, cfg.requests, cfg.concurrency, op).await,
                start,
            )
        }
        other => bail!("lane {other} not built (eggfetch feature off?)"),
    };
    let wall = start.elapsed();
    let stats = summarize(&samples, wall);
    Ok(envelope(
        cfg,
        rev,
        harness,
        adapter,
        toolchain,
        host,
        profile,
        "h1",
        256,
        0,
        0,
        0,
        None,
        stats,
        serde_json::json!({
            "server_requests": server.requests.load(std::sync::atomic::Ordering::Relaxed),
            "server_connections": server.connections.load(std::sync::atomic::Ordering::Relaxed),
        }),
    ))
}

async fn run_h2_small(cfg: &Config) -> Result<RunEnvelope> {
    let server = common::start_h2_server(&cfg.certs, 256)
        .await
        .context("start h2 loopback server")?;
    let url = format!("https://localhost:{}/h2small", server.addr.port());
    let ca = cfg.certs.join("test-only-loopback-ca.pem");
    let ca = ca.to_str().context("ca path")?.to_string();
    let (rev, harness, adapter, toolchain, host, profile) =
        provenance(&cfg.lane, cfg.workload.name());
    // Measured wall clock starts AFTER warmup (see run_h1_small).
    let (samples, start) = match cfg.lane.as_str() {
        adapter_legacy::LANE => {
            let client = adapter_legacy::h2_client(&ca);
            for _ in 0..cfg.warmup {
                let _ = adapter_legacy::small_get(&client, &url, PER_REQUEST_TIMEOUT).await;
            }
            let op = move |c: synvoid_http_client::HttpClient| {
                let url = url.clone();
                timed_sample(async move {
                    adapter_legacy::small_get(&c, &url, PER_REQUEST_TIMEOUT).await
                })
            };
            let start = Instant::now();
            (
                fan_out(client, cfg.requests, cfg.concurrency, op).await,
                start,
            )
        }
        #[cfg(feature = "eggfetch")]
        adapter_eggfetch::LANE => {
            let client = adapter_eggfetch::h2_client(&ca)?;
            for _ in 0..cfg.warmup {
                let _ = adapter_eggfetch::small_get(&client, &url, PER_REQUEST_TIMEOUT).await;
            }
            let op = move |c: synvoid_http_client::eggfetch_transport::EggfetchUpstreamClient| {
                let url = url.clone();
                timed_sample(async move {
                    adapter_eggfetch::small_get(&c, &url, PER_REQUEST_TIMEOUT).await
                })
            };
            let start = Instant::now();
            (
                fan_out(client, cfg.requests, cfg.concurrency, op).await,
                start,
            )
        }
        other => bail!("lane {other} not built (eggfetch feature off?)"),
    };
    let wall = start.elapsed();
    let stats = summarize(&samples, wall);
    let load = std::sync::atomic::Ordering::Relaxed;
    Ok(envelope(
        cfg,
        rev,
        harness,
        adapter,
        toolchain,
        host,
        profile,
        "h2",
        256,
        0,
        0,
        0,
        None,
        stats,
        serde_json::json!({
            "server_requests": server.requests.load(load),
            "server_connections": server.connections.load(load),
        }),
    ))
}

async fn run_stream(
    cfg: &Config,
    server: &H1Server,
    total: usize,
    frame: usize,
    delay: Option<Duration>,
) -> Result<RunEnvelope> {
    let url = format!("http://{}/stream", server.addr);
    let (rev, harness, adapter, toolchain, host, profile) =
        provenance(&cfg.lane, cfg.workload.name());
    // Measured wall clock starts AFTER warmup (see run_h1_small).
    let (samples, start) = match cfg.lane.as_str() {
        adapter_legacy::LANE => {
            let client = adapter_legacy::stream_client();
            for _ in 0..cfg.warmup {
                let body = common::FixtureBody::new(total, frame, delay);
                let _ =
                    adapter_legacy::stream_post(&client, url.clone(), body, PER_REQUEST_TIMEOUT)
                        .await;
            }
            let op = move |c: synvoid_http_client::StreamingHttpClient| {
                let url = url.clone();
                timed_sample(async move {
                    // Body construction is inside the timed section on BOTH
                    // lanes (never timed on one side and excluded on the other).
                    let body = common::FixtureBody::new(total, frame, delay);
                    adapter_legacy::stream_post(&c, url, body, PER_REQUEST_TIMEOUT).await
                })
            };
            let start = Instant::now();
            (
                fan_out(client, cfg.requests, cfg.concurrency, op).await,
                start,
            )
        }
        #[cfg(feature = "eggfetch")]
        adapter_eggfetch::LANE => {
            let client = adapter_eggfetch::stream_client()?;
            for _ in 0..cfg.warmup {
                let body = common::FixtureBody::new(total, frame, delay);
                let _ =
                    adapter_eggfetch::stream_post(&client, &url, body, PER_REQUEST_TIMEOUT).await;
            }
            let op = move |c: synvoid_http_client::eggfetch_transport::EggfetchUpstreamClient| {
                let url = url.clone();
                timed_sample(async move {
                    let body = common::FixtureBody::new(total, frame, delay);
                    adapter_eggfetch::stream_post(&c, &url, body, PER_REQUEST_TIMEOUT).await
                })
            };
            let start = Instant::now();
            (
                fan_out(client, cfg.requests, cfg.concurrency, op).await,
                start,
            )
        }
        other => bail!("lane {other} not built (eggfetch feature off?)"),
    };
    let wall = start.elapsed();
    let stats = summarize(&samples, wall);
    // Frame count comes from the actual fixture body, not the formula.
    let frames = common::FixtureBody::new(total, frame, delay).frame_count();
    Ok(envelope(
        cfg,
        rev,
        harness,
        adapter,
        toolchain,
        host,
        profile,
        "h1",
        total,
        total,
        frames,
        frame,
        delay.map(|d| d.as_millis() as u64),
        stats,
        serde_json::json!({
            "server_requests": server.requests.load(std::sync::atomic::Ordering::Relaxed),
            "server_connections": server.connections.load(std::sync::atomic::Ordering::Relaxed),
        }),
    ))
}

/// Diagnostic TTH-vs-drain split at fixed geometry (sequential only).
/// The phase boundary (headers received) is identical on both lanes; the
/// per-request drain time is `total - tth` on the same clock.
async fn run_stream_phased(
    cfg: &Config,
    server: &H1Server,
    total: usize,
    frame: usize,
) -> Result<RunEnvelope> {
    if cfg.concurrency != 1 {
        bail!("stream-64k-phases is sequential-only");
    }
    let url = format!("http://{}/stream", server.addr);
    let (rev, harness, adapter, toolchain, host, profile) =
        provenance(&cfg.lane, cfg.workload.name());
    let mut totals: Vec<u64> = Vec::with_capacity(cfg.requests);
    let mut tths: Vec<u64> = Vec::with_capacity(cfg.requests);
    let mut failures = 0usize;
    // Measured wall clock starts AFTER warmup (see run_h1_small).
    let start = match cfg.lane.as_str() {
        adapter_legacy::LANE => {
            let client = adapter_legacy::stream_client();
            for _ in 0..cfg.warmup {
                let body = common::FixtureBody::new(total, frame, None);
                let _ = adapter_legacy::stream_post_phased(
                    &client,
                    url.clone(),
                    body,
                    PER_REQUEST_TIMEOUT,
                )
                .await;
            }
            let measured = Instant::now();
            for _ in 0..cfg.requests {
                let s = Instant::now();
                match tokio::time::timeout(
                    REQUEST_TIMEOUT,
                    adapter_legacy::stream_post_phased(
                        &client,
                        url.clone(),
                        common::FixtureBody::new(total, frame, None),
                        PER_REQUEST_TIMEOUT,
                    ),
                )
                .await
                {
                    Ok(Ok((_, tth))) => {
                        totals.push(s.elapsed().as_micros() as u64);
                        tths.push(tth);
                    }
                    _ => failures += 1,
                }
            }
            measured
        }
        #[cfg(feature = "eggfetch")]
        adapter_eggfetch::LANE => {
            let client = adapter_eggfetch::stream_client()?;
            for _ in 0..cfg.warmup {
                let body = common::FixtureBody::new(total, frame, None);
                let _ =
                    adapter_eggfetch::stream_post_phased(&client, &url, body, PER_REQUEST_TIMEOUT)
                        .await;
            }
            let measured = Instant::now();
            for _ in 0..cfg.requests {
                let s = Instant::now();
                match tokio::time::timeout(
                    REQUEST_TIMEOUT,
                    adapter_eggfetch::stream_post_phased(
                        &client,
                        &url,
                        common::FixtureBody::new(total, frame, None),
                        PER_REQUEST_TIMEOUT,
                    ),
                )
                .await
                {
                    Ok(Ok((_, tth))) => {
                        totals.push(s.elapsed().as_micros() as u64);
                        tths.push(tth);
                    }
                    _ => failures += 1,
                }
            }
            measured
        }
        other => bail!("lane {other} not built (eggfetch feature off?)"),
    };
    let wall = start.elapsed();
    let samples: Vec<Sample> = totals
        .iter()
        .map(|t| Sample {
            latency_us: Some(*t),
            bytes: total as u64,
        })
        .collect();
    let stats = summarize(&samples, wall);
    let mut drains: Vec<u64> = totals
        .iter()
        .zip(tths.iter())
        .map(|(t, h)| t.saturating_sub(*h))
        .collect();
    tths.sort_unstable();
    drains.sort_unstable();
    let pct = |v: &[u64], p: f64| -> u64 {
        if v.is_empty() {
            return 0;
        }
        let idx = ((p / 100.0) * v.len() as f64).ceil() as usize;
        v[idx.saturating_sub(1).min(v.len() - 1)]
    };
    Ok(envelope(
        cfg,
        rev,
        harness,
        adapter,
        toolchain,
        host,
        profile,
        "h1",
        total,
        total,
        total.div_ceil(frame),
        frame,
        None,
        stats,
        serde_json::json!({
            "tth_p50_us": pct(&tths, 50.0),
            "tth_p95_us": pct(&tths, 95.0),
            "drain_p50_us": pct(&drains, 50.0),
            "drain_p95_us": pct(&drains, 95.0),
            "phased_failures": failures,
        }),
    ))
}

async fn run_early_drop(
    cfg: &Config,
    server: &H1Server,
    total: usize,
    frame: usize,
) -> Result<RunEnvelope> {
    let url = format!("http://{}/stream", server.addr);
    let (rev, harness, adapter, toolchain, host, profile) =
        provenance(&cfg.lane, cfg.workload.name());
    let mut samples = Vec::with_capacity(cfg.requests);
    let mut tths = Vec::with_capacity(cfg.requests);
    let mut recovery_failures = 0usize;
    // Measured wall clock starts AFTER warmup (see run_h1_small).
    let start = match cfg.lane.as_str() {
        adapter_legacy::LANE => {
            let stream = adapter_legacy::stream_client();
            let small = adapter_legacy::small_client();
            let small_url = format!("http://{}/small", server.addr);
            for _ in 0..cfg.warmup {
                let body = common::FixtureBody::new(total, frame, None);
                if let Ok(resp) =
                    adapter_legacy::stream_headers(&stream, url.clone(), body, PER_REQUEST_TIMEOUT)
                        .await
                {
                    drop(resp.into_body());
                }
            }
            let measured = Instant::now();
            for _ in 0..cfg.requests {
                let start = Instant::now();
                let iter = tokio::time::timeout(REQUEST_TIMEOUT, async {
                    let body = common::FixtureBody::new(total, frame, None);
                    let t0 = Instant::now();
                    let resp = adapter_legacy::stream_headers(
                        &stream,
                        url.clone(),
                        body,
                        PER_REQUEST_TIMEOUT,
                    )
                    .await?;
                    let tth = t0.elapsed().as_micros() as u64;
                    // Early drop: headers received, body never consumed.
                    drop(resp.into_body());
                    // Recovery: the lane must serve a fresh request afterwards.
                    let small_body =
                        adapter_legacy::small_get(&small, &small_url, PER_REQUEST_TIMEOUT).await;
                    Result::<_, anyhow::Error>::Ok((tth, small_body.is_ok()))
                })
                .await;
                match iter {
                    Ok(Ok((tth, rec_ok))) => {
                        tths.push(tth);
                        recovery_failures += usize::from(!rec_ok);
                        samples.push(Sample {
                            latency_us: Some(start.elapsed().as_micros() as u64),
                            bytes: 0,
                        });
                    }
                    _ => {
                        recovery_failures += 1;
                        samples.push(Sample {
                            latency_us: None,
                            bytes: 0,
                        });
                    }
                }
            }
            measured
        }
        #[cfg(feature = "eggfetch")]
        adapter_eggfetch::LANE => {
            let stream = adapter_eggfetch::stream_client()?;
            let small = adapter_eggfetch::small_client()?;
            let small_url = format!("http://{}/small", server.addr);
            for _ in 0..cfg.warmup {
                let body = common::FixtureBody::new(total, frame, None);
                if let Ok(body) =
                    adapter_eggfetch::stream_headers(&stream, &url, body, PER_REQUEST_TIMEOUT).await
                {
                    drop(body);
                }
            }
            let measured = Instant::now();
            for _ in 0..cfg.requests {
                let start = Instant::now();
                let iter = tokio::time::timeout(REQUEST_TIMEOUT, async {
                    let body = common::FixtureBody::new(total, frame, None);
                    let t0 = Instant::now();
                    let body =
                        adapter_eggfetch::stream_headers(&stream, &url, body, PER_REQUEST_TIMEOUT)
                            .await?;
                    let tth = t0.elapsed().as_micros() as u64;
                    drop(body);
                    let small_body =
                        adapter_eggfetch::small_get(&small, &small_url, PER_REQUEST_TIMEOUT).await;
                    Result::<_, anyhow::Error>::Ok((tth, small_body.is_ok()))
                })
                .await;
                match iter {
                    Ok(Ok((tth, rec_ok))) => {
                        tths.push(tth);
                        recovery_failures += usize::from(!rec_ok);
                        samples.push(Sample {
                            latency_us: Some(start.elapsed().as_micros() as u64),
                            bytes: 0,
                        });
                    }
                    _ => {
                        recovery_failures += 1;
                        samples.push(Sample {
                            latency_us: None,
                            bytes: 0,
                        });
                    }
                }
            }
            measured
        }
        other => bail!("lane {other} not built (eggfetch feature off?)"),
    };
    let wall = start.elapsed();
    let stats = summarize(&samples, wall);
    tths.sort_unstable();
    let tth_pct = |p: f64| -> u64 {
        if tths.is_empty() {
            return 0;
        }
        let idx = ((p / 100.0) * tths.len() as f64).ceil() as usize;
        tths[idx.saturating_sub(1).min(tths.len() - 1)]
    };
    Ok(envelope(
        cfg,
        rev,
        harness,
        adapter,
        toolchain,
        host,
        profile,
        "h1",
        total,
        total,
        total.div_ceil(frame),
        frame,
        None,
        stats,
        serde_json::json!({
            "tth_p50_us": tth_pct(50.0),
            "tth_p95_us": tth_pct(95.0),
            "recovery_failures": recovery_failures,
        }),
    ))
}

fn run_cold(cfg: &Config) -> Result<RunEnvelope> {
    let (rev, harness, adapter, toolchain, host, profile) =
        provenance(&cfg.lane, cfg.workload.name());
    // Three outer loops of `requests` constructions; informational only.
    // The salt keeps every outer loop on fresh cache keys so all samples
    // measure real construction, not cache hits.
    let mut samples = Vec::with_capacity(3);
    let wall = Instant::now();
    for outer in 0..3 {
        let elapsed = match cfg.lane.as_str() {
            adapter_legacy::LANE => adapter_legacy::cold_construct(cfg.requests, outer),
            #[cfg(feature = "eggfetch")]
            adapter_eggfetch::LANE => adapter_eggfetch::cold_construct(cfg.requests, outer)?,
            other => bail!("lane {other} not built (eggfetch feature off?)"),
        };
        samples.push(Sample {
            latency_us: Some(elapsed.as_micros() as u64),
            bytes: 0,
        });
    }
    let wall = wall.elapsed();
    let stats = summarize(&samples, wall);
    Ok(envelope(
        cfg,
        rev,
        harness,
        adapter,
        toolchain,
        host,
        profile,
        "none",
        0,
        0,
        0,
        0,
        None,
        stats,
        serde_json::json!({"constructions_per_sample": cfg.requests}),
    ))
}

#[allow(clippy::too_many_arguments)]
fn envelope(
    cfg: &Config,
    revision_sha: String,
    harness_sha: String,
    adapter_sha: String,
    toolchain: String,
    host: String,
    profile: String,
    protocol: &str,
    response_bytes: usize,
    payload_total: usize,
    payload_frames: usize,
    payload_frame: usize,
    producer_delay_ms: Option<u64>,
    stats: common::LatencyStats,
    extra: serde_json::Value,
) -> RunEnvelope {
    RunEnvelope {
        lane: cfg.lane.clone(),
        workload: cfg.workload.name().to_string(),
        revision_sha,
        harness_sha,
        adapter_file: match cfg.lane.as_str() {
            #[cfg(feature = "eggfetch")]
            "eggfetch" => adapter_eggfetch::ADAPTER_FILE.to_string(),
            _ => adapter_legacy::ADAPTER_FILE.to_string(),
        },
        adapter_sha,
        toolchain,
        host,
        target: std::env::var("BENCH_TARGET")
            .unwrap_or_else(|_| std::env::consts::ARCH.to_string()),
        profile,
        unix_secs: now_unix_secs(),
        protocol: protocol.to_string(),
        requests: cfg.requests,
        warmup: cfg.warmup,
        concurrency: cfg.concurrency,
        payload_total_bytes: payload_total,
        payload_frames,
        payload_frame_bytes: payload_frame,
        producer_delay_ms: producer_delay_ms.unwrap_or(0),
        response_bytes,
        stats,
        extra,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // The harness links several rustls consumers (hyper-rustls, tokio-rustls,
    // eggfetch); feature unification may leave >1 provider available, which
    // disables auto-detection. Pin an explicit process default first.
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
    let raw: Vec<String> = std::env::args().collect();
    if raw.iter().any(|a| a == "summarize") {
        return run_summarize(&raw);
    }
    let cfg = parse_args()?;
    if cfg.lane != "legacy" && cfg.lane != "eggfetch" {
        bail!("--lane must be legacy|eggfetch");
    }
    let env = run_workload(&cfg).await?;
    std::fs::write(&cfg.out, serde_json::to_string_pretty(&env)?)?;
    println!(
        "{} {}: {} ok, {} failed, {:.0} rps, p50 {}us p95 {}us p99 {}us -> {}",
        env.lane,
        env.workload,
        env.stats.n,
        env.stats.failures,
        env.stats.rps,
        env.stats.p50_us,
        env.stats.p95_us,
        env.stats.p99_us,
        cfg.out.display()
    );
    if env.stats.failures > 0 && env.workload != "early-drop" {
        // Failures are recorded, but a non-zero count on a primary workload
        // must be loud: the adjudication may not silently ignore it.
        eprintln!(
            "WARNING: {} failures in {} {}",
            env.stats.failures, env.lane, env.workload
        );
    }
    Ok(())
}

async fn run_workload(cfg: &Config) -> Result<RunEnvelope> {
    match cfg.workload {
        Workload::H1Sequential | Workload::H1Concurrent => {
            let server: H1Server = common::start_h1_server(256).await?;
            run_h1_small(cfg, &server).await
        }
        Workload::H2Multiplexed => run_h2_small(cfg).await,
        Workload::Stream1K
        | Workload::Stream64K
        | Workload::Stream1M
        | Workload::StreamConcurrent
        | Workload::StreamSlowProducer => {
            let (total, frame, delay) = cfg.workload.stream_geometry().unwrap();
            let server: H1Server = common::start_h1_server(total).await?;
            run_stream(cfg, &server, total, frame, delay).await
        }
        Workload::EarlyDrop => {
            let (total, frame, _) = Workload::EarlyDrop.stream_geometry().unwrap();
            let server: H1Server = common::start_h1_server(total).await?;
            run_early_drop(cfg, &server, total, frame).await
        }
        Workload::Stream64KPhases => {
            // Diagnostic split (TTH vs drain) at the stream-64k geometry.
            let server: H1Server = common::start_h1_server(65_536).await?;
            run_stream_phased(cfg, &server, 65_536, 4096).await
        }
        Workload::ColdConstruct => Ok(run_cold(cfg)?),
    }
}

// ---------------------------------------------------------------------------
// summarize: aggregate per-rep JSON into a Markdown adjudication table.
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct FiledResult {
    lane: String,
    workload: String,
    stats: FiledStats,
}

#[derive(serde::Deserialize)]
struct FiledStats {
    failures: usize,
    rps: f64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
}

fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let m = v.len() / 2;
    if v.len() % 2 == 1 {
        v[m]
    } else {
        (v[m - 1] + v[m]) / 2.0
    }
}

fn median_u64(mut v: Vec<u64>) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let m = v.len() / 2;
    if v.len() % 2 == 1 {
        v[m]
    } else {
        (v[m - 1] + v[m]) / 2
    }
}

fn run_summarize(raw: &[String]) -> Result<()> {
    let mut files = Vec::new();
    let mut out: Option<String> = None;
    let mut it = raw.iter().skip_while(|a| *a != "summarize").skip(1);
    while let Some(a) = it.next() {
        if a == "--out" {
            out = it.next().cloned();
        } else {
            files.push(a.clone());
        }
    }
    let out = out.context("summarize --out <file>")?;
    let mut groups: BTreeMap<(String, String), Vec<FiledStats>> = BTreeMap::new();
    for f in &files {
        let text = std::fs::read_to_string(f).with_context(|| format!("read {f}"))?;
        let r: FiledResult = serde_json::from_str(&text).with_context(|| format!("parse {f}"))?;
        groups
            .entry((r.workload, r.lane))
            .or_default()
            .push(r.stats);
    }
    let workloads = [
        "h1-sequential",
        "h1-concurrent",
        "h2-multiplexed",
        "stream-1k",
        "stream-64k",
        "stream-1m",
        "stream-concurrent",
        "stream-slow-producer",
        "early-drop",
        "cold-construct",
        "stream-64k-phases",
    ];
    let mut md = String::from("# Transport comparison summary (generated)\n\n");
    md.push_str("| workload | lane | reps | median rps | min–max rps | median p50 (us) | median p95 (us) | median p99 (us) | total failures |\n");
    md.push_str("|---|---|---|---|---|---|---|---|---|\n");
    let mut verdicts = Vec::new();
    for w in workloads {
        for lane in ["legacy", "eggfetch"] {
            if let Some(v) = groups.get(&(w.to_string(), lane.to_string())) {
                let rps: Vec<f64> = v.iter().map(|s| s.rps).collect();
                let (min, max) = (
                    rps.iter().cloned().fold(f64::INFINITY, f64::min),
                    rps.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
                );
                md.push_str(&format!(
                    "| {} | {} | {} | {:.0} | {:.0}–{:.0} | {} | {} | {} | {} |\n",
                    w,
                    lane,
                    v.len(),
                    median(rps),
                    min,
                    max,
                    median_u64(v.iter().map(|s| s.p50_us).collect()),
                    median_u64(v.iter().map(|s| s.p95_us).collect()),
                    median_u64(v.iter().map(|s| s.p99_us).collect()),
                    v.iter().map(|s| s.failures).sum::<usize>(),
                ));
            }
        }
        if let (Some(l), Some(e)) = (
            groups.get(&(w.to_string(), "legacy".to_string())),
            groups.get(&(w.to_string(), "eggfetch".to_string())),
        ) {
            let lr = median(l.iter().map(|s| s.rps).collect());
            let er = median(e.iter().map(|s| s.rps).collect());
            let delta = if lr > 0.0 {
                (er - lr) / lr * 100.0
            } else {
                0.0
            };
            let lp95 = median_u64(l.iter().map(|s| s.p95_us).collect());
            let ep95 = median_u64(e.iter().map(|s| s.p95_us).collect());
            let flag = if delta < -5.0 {
                "MATERIAL (>5% rps)"
            } else {
                "clear"
            };
            verdicts.push(format!(
                "- {}: eggfetch median rps {:+.1}% vs legacy (p95 {}us vs {}us) — {}",
                w, delta, ep95, lp95, flag
            ));
        }
    }
    md.push_str("\n## Adjudication (>5% rule on median rps)\n\n");
    for v in verdicts {
        md.push_str(&v);
        md.push('\n');
    }
    std::fs::write(&out, &md)?;
    println!("{md}");
    Ok(())
}
