//! Internal eggfetch-backed transport lane (Phase 59).
//!
//! Production-capable eggfetch transport behind SynVoid's existing neutral
//! policy model ([`UpstreamTlsConfig`]). This module is crate-`pub` so the
//! hermetic differential suite (`tests/eggfetch_differential.rs`) and later
//! Phase 60 consumer batches can drive both lanes against the same fixtures,
//! but it is **internal**: it is NOT re-exported at the root
//! (`src/http_client/mod.rs`), carries no stability promise, and must not be
//! mistaken for the frozen compatibility surface inventoried in
//! `architecture/eggfetch_0_2_compatibility_matrix.md` §4.
//!
//! Design rule (one policy model, two comparable lanes): retry, upstream
//! selection/failover, WAF scanning, cache, auth, compression, redirect,
//! QUIC-tunnel, and mesh policy stay above transport. This lane consumes
//! exactly: [`UpstreamTlsConfig`], connect/pool/idle inputs, per-request
//! timeouts, and resolved-target/SNI hints.
//!
//! Intentional translation table (behavioral equivalence at the SynVoid
//! contract, not field-for-field identity):
//!
//! | SynVoid input | Eggfetch translation |
//! |---|---|
//! | `connect_timeout` | client `Timeout { connect }` (pool/write/read/total unset at client level) |
//! | `pool_max_idle_per_host` | `max_idle_connections_per_host` (physical idle cap) |
//! | `pool_idle_timeout` | `idle_timeout` |
//! | per-request `timeout` | `tokio::time::timeout` around execution (time-to-headers, exactly the legacy helper semantic); eggfetch `total` left unset so slow bodies keep legacy unbounded-completion behavior |
//! | `UpstreamTlsConfig` | [`upstream_tls_to_eggfetch`](crate::eggfetch_policy::upstream_tls_to_eggfetch) + per-request SNI hint; `skip_verify_reason` logged SynVoid-side only |
//! | `allow_plaintext` | pre-transport routing gate (http scheme rejected unless allowed; UDS exempt — no network plaintext involved) |
//!
//! Deliberately NOT set: any global/per-origin logical concurrency cap
//! (`max_connections` / `max_in_flight_requests`). The legacy lane bounds
//! only idle-pool state, so introducing an admission cap here would be a
//! new backpressure behavior, not a translation.
//!
//! Timeout error parity: the buffered wrappers return `anyhow!("request timed
//! out")` on expiry, byte-identical to the legacy helpers, so callers
//! matching on that string keep working. [`EggfetchUpstreamClient::execute`]
//! maps expiry to the typed [`eggfetch_core::Error::Timeout`] (`Total`
//! phase) to preserve error provenance for streaming callers.

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Method, Request, Response, Uri};
use http_body_util::{BodyExt, Full, Limited};
use moka::sync::Cache;

use crate::eggfetch_policy::{eggfetch_sni_hint, upstream_tls_to_eggfetch};
use crate::response::HttpResponse;
use crate::tls::{UpstreamTlsConfig, UpstreamTlsConfigHashable};

/// Opaque native response body for the eggfetch lane.
///
/// Re-exported here (not at crate root) so differential tests and future
/// internal consumers can name the streaming type without reaching into
/// `eggfetch_core` directly.
pub type EggfetchResponseBody = eggfetch_core::NativeResponseBody;

/// Snapshot of the SynVoid policy inputs that travel with a cached client.
///
/// `server_name` is stored (not baked into the shared `TlsConfig`) because
/// SNI override travels per-request via `TransportHints::sni_hostname`; one
/// cached client therefore never crosses incompatible SNI policy.
#[derive(Debug, Clone)]
struct StoredPolicy {
    allow_plaintext: bool,
    server_name: Option<String>,
    uds: bool,
}

impl From<&UpstreamTlsConfig> for StoredPolicy {
    fn from(cfg: &UpstreamTlsConfig) -> Self {
        Self {
            allow_plaintext: cfg.allow_plaintext,
            server_name: cfg.server_name.clone(),
            uds: false,
        }
    }
}

/// Registry key for the eggfetch lane.
///
/// Unlike the legacy [`crate::pool::UpstreamClientKey`], this key includes
/// the connect timeout: a shared client must never silently serve a
/// different connect bound than the caller requested.
#[derive(Hash, PartialEq, Eq, Clone)]
struct EggfetchClientKey {
    tls: UpstreamTlsConfigHashable,
    pool_max_idle: usize,
    pool_idle_secs: u64,
    connect_secs: u64,
    connect_subsec_nanos: u32,
}

impl EggfetchClientKey {
    fn new(
        tls: &UpstreamTlsConfig,
        pool_max_idle: usize,
        pool_idle: Duration,
        connect: Duration,
    ) -> Self {
        Self {
            tls: UpstreamTlsConfigHashable::from(tls),
            pool_max_idle,
            pool_idle_secs: pool_idle.as_secs(),
            connect_secs: connect.as_secs(),
            connect_subsec_nanos: connect.subsec_nanos(),
        }
    }
}

static EGGFETCH_CLIENT_CACHE: std::sync::LazyLock<Cache<EggfetchClientKey, eggfetch_core::Client>> =
    std::sync::LazyLock::new(|| {
        Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(300))
            .build()
    });

/// Production-capable eggfetch transport bound to one SynVoid policy.
///
/// Cheap to clone (the inner [`eggfetch_core::Client`] is reference-counted
/// pool state); prefer the [`cached`](Self::cached) constructor so identical
/// policies share route/connection reuse.
#[derive(Clone)]
pub struct EggfetchUpstreamClient {
    client: eggfetch_core::Client,
    policy: StoredPolicy,
}

impl EggfetchUpstreamClient {
    /// Build an eggfetch lane client for ordinary TCP (plain + TLS) egress.
    ///
    /// Fail-closed: an invalid CA/provider/policy returns `Err` (no silent
    /// fallback to defaults).
    pub fn build(
        connect_timeout: Duration,
        pool_max_idle_per_host: usize,
        pool_idle_timeout: Duration,
        tls: &UpstreamTlsConfig,
    ) -> Result<Self> {
        let egg_tls = upstream_tls_to_eggfetch(tls)?;
        let client = eggfetch_core::Client::builder()
            .tls_config(egg_tls)
            .timeout(eggfetch_client_timeout(connect_timeout))
            .max_idle_connections_per_host(pool_max_idle_per_host)
            .idle_timeout(pool_idle_timeout)
            .build();
        Ok(Self {
            client,
            policy: StoredPolicy::from(tls),
        })
    }

    /// Registry-backed constructor: identical policies share one client.
    pub fn cached(
        connect_timeout: Duration,
        pool_max_idle_per_host: usize,
        pool_idle_timeout: Duration,
        tls: &UpstreamTlsConfig,
    ) -> Result<Self> {
        let key = EggfetchClientKey::new(
            tls,
            pool_max_idle_per_host,
            pool_idle_timeout,
            connect_timeout,
        );
        if let Some(client) = EGGFETCH_CLIENT_CACHE.get(&key) {
            return Ok(Self {
                client,
                policy: StoredPolicy::from(tls),
            });
        }
        let built = Self::build(
            connect_timeout,
            pool_max_idle_per_host,
            pool_idle_timeout,
            tls,
        )?;
        EGGFETCH_CLIENT_CACHE.insert(key, built.client.clone());
        Ok(built)
    }

    /// Build an eggfetch lane client bound to one Unix-domain socket path.
    ///
    /// Mirrors the legacy `create_unix_http_client` capability through the
    /// qualified eggfetch UDS route. Truthful off-Unix: returns `Err`
    /// (`Unsupported`) instead of silently using TCP.
    pub fn build_uds(
        socket_path: &str,
        connect_timeout: Duration,
        pool_max_idle_per_host: usize,
        pool_idle_timeout: Duration,
    ) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (
                socket_path,
                connect_timeout,
                pool_max_idle_per_host,
                pool_idle_timeout,
            );
            anyhow::bail!("eggfetch UDS transport is not supported on this platform");
        }
        #[cfg(unix)]
        {
            if socket_path.is_empty() {
                anyhow::bail!("eggfetch UDS transport requires a non-empty socket path");
            }
            let client = eggfetch_core::Client::builder()
                .uds_path(socket_path.to_string())
                .timeout(eggfetch_client_timeout(connect_timeout))
                .max_idle_connections_per_host(pool_max_idle_per_host)
                .idle_timeout(pool_idle_timeout)
                .build();
            Ok(Self {
                client,
                policy: StoredPolicy {
                    allow_plaintext: true,
                    server_name: None,
                    uds: true,
                },
            })
        }
    }

    /// Raw handle for differential tests and advanced internal use.
    pub fn client(&self) -> &eggfetch_core::Client {
        &self.client
    }

    /// Per-request native options for this client's stored policy.
    ///
    /// SNI override and pinned destinations travel here, never baked into
    /// the shared client. `timeout_override` is an explicit phase-aware
    /// escape hatch; the buffered wrappers below intentionally pass `None`
    /// to preserve legacy time-to-headers semantics.
    pub(crate) fn native_options(
        &self,
        resolved: Option<eggfetch_core::ResolvedTarget>,
        timeout_override: Option<eggfetch_core::Timeout>,
    ) -> eggfetch_core::NativeRequestOptions {
        let hints = eggfetch_core::TransportHints {
            sni_hostname: self.policy.server_name.clone(),
            resolved_target: resolved,
            ..eggfetch_core::TransportHints::default()
        };
        let mut options = eggfetch_core::NativeRequestOptions::default().transport_hints(hints);
        if let Some(t) = timeout_override {
            options = options.timeout(t);
        }
        options
    }

    fn check_plaintext(&self, uri: &Uri) -> Result<()> {
        if self.policy.uds {
            return Ok(());
        }
        let is_tls = uri
            .scheme_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("https"));
        if !is_tls && !self.policy.allow_plaintext {
            anyhow::bail!("plaintext upstream not permitted by policy (allow_plaintext=false)");
        }
        Ok(())
    }

    /// Execute a native generic-body request through the eggfetch lane.
    ///
    /// Uses `execute_http_body` directly: no bytes-stream conversion, no
    /// forced buffering, trailers preserved. `timeout` bounds time-to-headers
    /// (legacy parity); pass phase-aware needs via `options_override`.
    pub async fn execute<B>(
        &self,
        req: Request<B>,
        timeout: Option<Duration>,
        resolved: Option<eggfetch_core::ResolvedTarget>,
    ) -> std::result::Result<Response<EggfetchResponseBody>, eggfetch_core::Error>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        self.check_plaintext(req.uri())
            .map_err(|e| eggfetch_core::Error::InvalidUrl(format!("plaintext policy gate: {e}")))?;
        let options = self.native_options(resolved, None);
        match timeout {
            Some(t) => {
                match tokio::time::timeout(t, self.client.execute_http_body(req, options)).await {
                    Ok(r) => r,
                    Err(_) => Err(eggfetch_core::Error::Timeout {
                        phase: eggfetch_core::TimeoutPhase::Total,
                        elapsed: t,
                    }),
                }
            }
            None => self.client.execute_http_body(req, options).await,
        }
    }

    /// Buffered request mirroring the legacy `send_request_with_body*`
    /// contract: same status/headers/body shape, same oversize→empty-body
    /// mapping, same `"request timed out"` message.
    pub async fn send_buffered(
        &self,
        method: Method,
        url: &str,
        body: Option<Bytes>,
        headers: http::HeaderMap,
        timeout: Option<Duration>,
        max_response_size: Option<usize>,
    ) -> Result<HttpResponse> {
        let uri: Uri = url
            .parse()
            .with_context(|| format!("eggfetch lane: invalid URL {url}"))?;
        self.check_plaintext(&uri)?;
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Full::new(body.unwrap_or_default()))
            .context("eggfetch lane: failed to build request")?;
        // Mirror the legacy helpers: caller headers replace, not append.
        *req.headers_mut() = headers;
        let options = self.native_options(None, None);
        let response = match timeout {
            Some(t) => {
                match tokio::time::timeout(t, self.client.execute_http_body(req, options)).await {
                    Ok(Ok(resp)) => resp,
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => return Err(anyhow::anyhow!("request timed out")),
                }
            }
            None => self.client.execute_http_body(req, options).await?,
        };
        Ok(native_to_httpresponse(response, max_response_size).await)
    }

    /// Buffered UDS request (`http://localhost{path}` logical URI over the
    /// bound socket), mirroring `send_unix_request_with_body` behavior.
    pub async fn send_uds_buffered(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        timeout: Option<Duration>,
    ) -> Result<HttpResponse> {
        if !self.policy.uds {
            anyhow::bail!("eggfetch lane: client is not UDS-bound");
        }
        let url = format!("http://localhost{path}");
        self.send_buffered(method, &url, body, http::HeaderMap::new(), timeout, None)
            .await
    }

    /// GET mirroring legacy `get_with_timeout` (String errors, no size limit,
    /// no redirect/retry policy).
    pub async fn get_with_timeout(
        &self,
        url: &str,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        self.send_buffered(
            Method::GET,
            url,
            None,
            http::HeaderMap::new(),
            Some(timeout),
            None,
        )
        .await
        .map_err(|e| e.to_string())
    }

    /// GET with HTTP Basic auth mirroring legacy `get_with_auth`.
    ///
    /// Credentials are serialized by SynVoid (`STANDARD` base64 of
    /// `user:pass`); the lane owns no auth policy.
    pub async fn get_with_basic_auth(
        &self,
        url: &str,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            basic_auth_header_value(username, password)
                .parse()
                .map_err(|e| format!("eggfetch lane: invalid auth header: {e}"))?,
        );
        self.send_buffered(Method::GET, url, None, headers, Some(timeout), None)
            .await
            .map_err(|e| e.to_string())
    }

    /// HEAD with HTTP Basic auth mirroring legacy `head_with_auth`.
    pub async fn head_with_basic_auth(
        &self,
        url: &str,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            basic_auth_header_value(username, password)
                .parse()
                .map_err(|e| format!("eggfetch lane: invalid auth header: {e}"))?,
        );
        self.send_buffered(Method::HEAD, url, None, headers, Some(timeout), None)
            .await
            .map_err(|e| e.to_string())
    }

    /// POST JSON mirroring legacy `post_json_with_timeout`.
    ///
    /// SynVoid keeps its own serialization (no eggfetch `json` feature);
    /// content type, timeout, and String-error behavior are unchanged.
    pub async fn post_json_with_timeout<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let json = serde_json::to_string(body).map_err(|e| e.to_string())?;
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/json"
                .parse()
                .map_err(|e| format!("eggfetch lane: invalid content type: {e}"))?,
        );
        self.send_buffered(
            Method::POST,
            url,
            Some(Bytes::from(json)),
            headers,
            Some(timeout),
            None,
        )
        .await
        .map_err(|e| e.to_string())
    }
}

/// HTTP Basic credential value mirroring the legacy helpers exactly:
/// `STANDARD` base64 of `username:password`, prefixed with `Basic `.
fn basic_auth_header_value(username: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
    )
}

/// Client-level timeout for the eggfetch lane: connect phase only.
///
/// Pool/write/read/total are intentionally unset here (no new bounding
/// behavior); per-request needs travel via [`EggfetchUpstreamClient`].
pub fn eggfetch_client_timeout(connect_timeout: Duration) -> eggfetch_core::Timeout {
    eggfetch_core::Timeout::builder()
        .connect(connect_timeout)
        .build()
}

/// SNI hint for a policy (re-export of the translator rule for lane users).
pub fn sni_hint_for(tls: &UpstreamTlsConfig) -> Option<String> {
    eggfetch_sni_hint(tls)
}

/// Adapts a `Send`-only streaming body for `Sync`-requiring combinators.
///
/// The native [`eggfetch_core::NativeResponseBody`] is `Send` but not
/// `Sync` (it owns a `Box<dyn Body + Send>` transport body, hence
/// eggfetch's own `boxed_unsync` surface). SynVoid's zero-copy forward
/// path (`swallow_body_errors` → `BoxBody::boxed`) requires `Sync`, so this
/// adapter provides it with a per-poll mutex.
///
/// Soundness: the mutex is held only for the duration of a synchronous
/// `poll_frame`/`size_hint` call, never across `.await`. Bodies are
/// per-request, so the lock is uncontended in practice. Frames (including
/// trailers) pass through untouched — no buffering, no re-framing.
pub struct SyncBody<B> {
    inner: std::sync::Mutex<B>,
}

impl<B> SyncBody<B> {
    pub fn new(inner: B) -> Self {
        Self {
            inner: std::sync::Mutex::new(inner),
        }
    }
}

impl<B> http_body::Body for SyncBody<B>
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::fmt::Debug + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        // Lock scope ends before return: never held across `.await`.
        // `unwrap` documents the invariant that bodies never panic while
        // polled; a poisoned mutex would mean the body already panicked,
        // in which case failing loud preserves the failure signal.
        let mut guard = self
            .get_mut()
            .inner
            .lock()
            .expect("SyncBody mutex poisoned: body panicked during poll");
        std::pin::Pin::new(&mut *guard).poll_frame(cx)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner
            .lock()
            .expect("SyncBody mutex poisoned")
            .size_hint()
    }
}

/// Adapt a native eggfetch response into SynVoid's buffered [`HttpResponse`].
///
/// Mirrors `HttpResponse::from_hyper` exactly: oversize (or collection
/// failure) yields status + headers + empty body, never an error.
pub async fn native_to_httpresponse(
    response: Response<EggfetchResponseBody>,
    max_size: Option<usize>,
) -> HttpResponse {
    let (parts, body) = response.into_parts();
    let status = parts.status;
    let headers = parts.headers;
    let bytes = if let Some(limit) = max_size {
        match Limited::new(body, limit).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => Bytes::new(),
        }
    } else {
        body.collect()
            .await
            .map(|collected| collected.to_bytes())
            .unwrap_or_default()
    };
    HttpResponse {
        status,
        headers,
        body: bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_tls() -> UpstreamTlsConfig {
        UpstreamTlsConfig::default()
    }

    #[test]
    fn lane_builds_for_default_policy() {
        let lane = EggfetchUpstreamClient::build(
            Duration::from_secs(5),
            10,
            Duration::from_secs(30),
            &default_tls(),
        )
        .expect("default policy must build");
        assert!(!lane.policy.uds);
        assert!(!lane.policy.allow_plaintext);
    }

    #[test]
    fn lane_rejects_invalid_ca_closed() {
        let tls = UpstreamTlsConfig {
            ca_cert_path: Some("/nonexistent/eggfetch-lane-ca.pem".to_string()),
            ..default_tls()
        };
        assert!(
            EggfetchUpstreamClient::build(
                Duration::from_secs(5),
                10,
                Duration::from_secs(30),
                &tls
            )
            .is_err(),
            "invalid CA must fail lane construction, never fall back"
        );
    }

    #[test]
    fn cached_lane_shares_policy_identity() {
        let tls = default_tls();
        let a = EggfetchUpstreamClient::cached(
            Duration::from_secs(5),
            10,
            Duration::from_secs(30),
            &tls,
        )
        .unwrap();
        assert!(!a.policy.uds);
        // Second construction with identical policy must hit the registry.
        let key = EggfetchClientKey::new(&tls, 10, Duration::from_secs(30), Duration::from_secs(5));
        let _b = EggfetchUpstreamClient::cached(
            Duration::from_secs(5),
            10,
            Duration::from_secs(30),
            &tls,
        )
        .unwrap();
        assert!(
            EGGFETCH_CLIENT_CACHE.get(&key).is_some(),
            "identical policy must resolve to the cached client"
        );
    }

    #[test]
    fn client_timeout_covers_connect_only() {
        let t = eggfetch_client_timeout(Duration::from_secs(7));
        assert_eq!(t.connect, Some(Duration::from_secs(7)));
        assert!(t.pool.is_none());
        assert!(t.write.is_none());
        assert!(t.read.is_none());
        assert!(t.total.is_none());
    }

    #[tokio::test]
    async fn sync_body_forwards_frames_and_is_sync() {
        use http_body::Body as _;
        use http_body_util::BodyExt as _;
        use std::collections::VecDeque;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct Chunks {
            chunks: VecDeque<Bytes>,
        }
        impl http_body::Body for Chunks {
            type Data = Bytes;
            type Error = std::io::Error;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
                Poll::Ready(
                    self.chunks
                        .pop_front()
                        .map(|c| Ok(http_body::Frame::data(c))),
                )
            }
        }

        // Compile-time proof the adapter heals the Send-only gap.
        fn assert_sync<T: Sync + Send>() {}
        assert_sync::<SyncBody<Chunks>>();

        let adapted = SyncBody::new(Chunks {
            chunks: [Bytes::from_static(b"a"), Bytes::from_static(b"b")].into(),
        });
        let collected = adapted.collect().await.unwrap().to_bytes();
        assert_eq!(collected.as_ref(), b"ab");
    }

    #[cfg(unix)]
    #[test]
    fn uds_lane_requires_nonempty_path() {
        assert!(EggfetchUpstreamClient::build_uds(
            "",
            Duration::from_secs(5),
            10,
            Duration::from_secs(30)
        )
        .is_err());
    }

    #[cfg(not(unix))]
    #[test]
    fn uds_lane_is_truthful_off_unix() {
        assert!(EggfetchUpstreamClient::build_uds(
            "/tmp/x.sock",
            Duration::from_secs(5),
            10,
            Duration::from_secs(30)
        )
        .is_err());
    }
}
