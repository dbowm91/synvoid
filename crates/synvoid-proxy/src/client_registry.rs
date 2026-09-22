use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use synvoid_http_client::eggfetch_transport::EggfetchUpstreamClient;
use synvoid_http_client::UpstreamTlsConfig;

/// Phase 62: policy-aware outer registry key.
///
/// The site lifecycle (invalidate on config change) is keyed by `site_id`,
/// but transport identity must also include every transport-affecting TLS
/// policy dimension. `UpstreamTlsConfig` already implements `Hash + Eq` and
/// is the canonical policy type, so it is embedded directly. This is
/// intentionally conservative: `skip_verify_reason` (audit-only) is included
/// in the key and may fragment entries with identical transport behavior but
/// different reason strings. Fragmentation is safe (never collapses distinct
/// policies); collapsing would be unsound. Documented per Phase 62
/// Workstream B.
///
/// Fixed registry connection settings (5s connect / 100 idle-per-host /
/// 30s idle) stay out of the key only while genuinely invariant: every
/// `get_or_create_lane` caller uses these constants. If callers begin
/// supplying them, they become part of identity (the inner
/// `EggfetchUpstreamClient::cached` key already includes them).
#[derive(Clone, Hash, PartialEq, Eq, Debug)]
struct LaneRegistryKey {
    site_id: String,
    tls_policy: UpstreamTlsConfig,
}

pub struct UpstreamClientRegistry {
    // Phase 62 (corrective): policy-aware map. One entry per
    // (site, TLS policy). The outer registry remains the site
    // lifecycle/invalidation layer; eggfetch remains the physical
    // connection-pool owner underneath via its own policy-keyed global
    // cache. Buffered and streaming callers intentionally request different
    // no-config defaults (buffered `allow_plaintext: true`, streaming
    // `UpstreamTlsConfig::default()`), so they now resolve to distinct
    // lanes instead of collapsing to whichever was inserted first.
    lane_clients: DashMap<LaneRegistryKey, Arc<EggfetchUpstreamClient>>,
}

impl UpstreamClientRegistry {
    pub fn new() -> Self {
        Self {
            lane_clients: DashMap::new(),
        }
    }

    /// Phase 62: eggfetch lane handle for a (site, TLS policy).
    ///
    /// Fail-closed: an invalid custom CA (or other lane-build failure)
    /// returns `Err` with site/policy context. It never silently substitutes
    /// a default verifying policy — a publicly trusted upstream must not
    /// connect despite a broken configured custom CA path.
    ///
    /// Unlike the legacy accessors, the TLS policy is required (no silent
    /// default): the legacy buffered and streaming paths disagree on the
    /// no-config default (buffered permits plaintext via `https_or_http`;
    /// streaming enforces `https_only` via the verifying default), so each
    /// caller passes the default that matches its own legacy contract.
    /// Buffered callers pass `allow_plaintext: true`; streaming callers pass
    /// `UpstreamTlsConfig::default()`.
    pub fn get_or_create_lane(
        &self,
        site_id: &str,
        tls: &UpstreamTlsConfig,
    ) -> anyhow::Result<Arc<EggfetchUpstreamClient>> {
        let key = LaneRegistryKey {
            site_id: site_id.to_string(),
            tls_policy: tls.clone(),
        };
        if let Some(existing) = self.lane_clients.get(&key) {
            return Ok(Arc::clone(existing.value()));
        }
        // Build outside the map lock. On failure return the translator's
        // explicit configuration/transport error with site context — no
        // fallback, no map poisoning.
        let lane = EggfetchUpstreamClient::cached(
            Duration::from_secs(5),
            100,
            Duration::from_secs(30),
            tls,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "eggfetch lane: site '{site_id}' TLS policy failed to build \
                 (bad custom CA path '{}'?): {e}",
                tls.ca_cert_path.as_deref().unwrap_or("<none>"),
            )
        })?;
        let lane = Arc::new(lane);
        // Another thread may have inserted the same key concurrently; both
        // lanes carry identical policy so either is correct.
        let entry = self
            .lane_clients
            .entry(key)
            .or_insert_with(|| Arc::clone(&lane));
        Ok(Arc::clone(entry.value()))
    }

    /// Remove every policy variant for one site.
    ///
    /// O(n) over total registry entries; acceptable because invalidation is
    /// configuration/control-plane frequency, never hot request-path.
    /// Documented per Phase 62 Workstream B.
    pub fn invalidate(&self, site_id: &str) {
        self.lane_clients.retain(|k, _| k.site_id != site_id);
    }

    pub fn clear(&self) {
        self.lane_clients.clear();
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.lane_clients.len()
    }
}

impl Default for UpstreamClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plaintext_policy() -> UpstreamTlsConfig {
        UpstreamTlsConfig {
            allow_plaintext: true,
            ..UpstreamTlsConfig::default()
        }
    }

    fn strict_policy() -> UpstreamTlsConfig {
        UpstreamTlsConfig::default()
    }

    // Phase 63: hermetic loopback fixture. Binds port 0 (proving the port is
    // ours for the duration of the test), counts accepted TCP connections,
    // and serves one minimal HTTP/1.1 200 response per connection. The hit
    // counter is the I/O proof: zero hits means the lane failed before any
    // network I/O; one hit means the request passed the policy gate.
    struct LoopbackFixture {
        addr: std::net::SocketAddr,
        hits: Arc<std::sync::atomic::AtomicUsize>,
        _task: tokio::task::JoinHandle<()>,
    }

    async fn start_loopback_fixture() -> LoopbackFixture {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture must bind loopback port 0");
        let addr = listener.local_addr().expect("fixture must have an addr");
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_clone = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                hits_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    // Bounded header read so keep-alive clients never RST;
                    // probe bodies are empty so no content-length drain needed.
                    let mut buf = vec![0u8; 8192];
                    let mut seen = 0usize;
                    let _ = tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            match sock.read(&mut buf[seen..]).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    seen += n;
                                    if seen >= 4 && buf[..seen].windows(4).any(|w| w == b"\r\n\r\n")
                                    {
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
        LoopbackFixture {
            addr,
            hits,
            _task: task,
        }
    }

    fn hit_count(fixture: &LoopbackFixture) -> usize {
        fixture.hits.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[test]
    fn buffered_first_streaming_second_do_not_collapse() {
        let registry = UpstreamClientRegistry::new();
        let buffered = registry
            .get_or_create_lane("s", &plaintext_policy())
            .expect("buffered lane must build");
        let strict = registry
            .get_or_create_lane("s", &strict_policy())
            .expect("strict lane must build");
        assert_eq!(
            registry.entry_count(),
            2,
            "same site with different plaintext policy must not collapse"
        );
        // Behavioral proof, not pointer inequality: the strict lane rejects
        // plaintext before network I/O (zero fixture connections), while the
        // buffered lane passes the gate (exactly one fixture connection and
        // a 200 response from the fixture server).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let fixture = start_loopback_fixture().await;
            let url = format!("http://{}/plaintext", fixture.addr);
            let err = strict
                .send_buffered(
                    http::Method::GET,
                    &url,
                    None,
                    http::HeaderMap::new(),
                    None,
                    None,
                )
                .await
                .expect_err("strict lane must reject http:// before I/O");
            assert!(
                err.to_string().contains("plaintext"),
                "unexpected strict-lane error: {err}"
            );
            // Settle window: any stray connection attempt would land here.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                hit_count(&fixture),
                0,
                "strict lane must open zero upstream connections"
            );
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
            assert_eq!(hit_count(&fixture), 1);
        });
    }

    #[test]
    fn streaming_first_buffered_second_do_not_collapse() {
        let registry = UpstreamClientRegistry::new();
        let strict = registry
            .get_or_create_lane("s", &strict_policy())
            .expect("strict lane must build");
        let buffered = registry
            .get_or_create_lane("s", &plaintext_policy())
            .expect("buffered lane must build");
        assert_eq!(registry.entry_count(), 2);
        // First acquisition must not permanently set site policy: the later
        // buffered lane still permits its legacy plaintext case at the gate.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let fixture = start_loopback_fixture().await;
            let url = format!("http://{}/x", fixture.addr);
            let err = strict
                .send_buffered(
                    http::Method::GET,
                    &url,
                    None,
                    http::HeaderMap::new(),
                    None,
                    None,
                )
                .await
                .expect_err("strict lane must reject plaintext");
            assert!(err.to_string().contains("plaintext"));
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                hit_count(&fixture),
                0,
                "strict lane must open zero upstream connections"
            );
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
                .expect("buffered lane must keep its legacy plaintext gate");
            assert_eq!(resp.status_code(), 200);
            assert_eq!(
                hit_count(&fixture),
                1,
                "buffered lane must attempt exactly one fixture connection"
            );
        });
    }

    #[test]
    fn distinct_tls_material_does_not_collapse() {
        let registry = UpstreamClientRegistry::new();
        let base = UpstreamTlsConfig::default();
        let other_ca = UpstreamTlsConfig {
            ca_cert_path: Some("/nonexistent/other-ca.pem".to_string()),
            ..UpstreamTlsConfig::default()
        };
        let other_sni = UpstreamTlsConfig {
            server_name: Some("sni.example.test".to_string()),
            ..UpstreamTlsConfig::default()
        };
        let skip = UpstreamTlsConfig {
            skip_verify: true,
            skip_verify_reason: Some("test-only".to_string()),
            ..UpstreamTlsConfig::default()
        };
        // Base + SNI + skip policies build; the bad-CA policy fails closed
        // (proving separation includes material that cannot even construct).
        registry
            .get_or_create_lane("s", &base)
            .expect("base must build");
        registry
            .get_or_create_lane("s", &other_sni)
            .expect("sni policy must build");
        registry
            .get_or_create_lane("s", &skip)
            .expect("skip policy must build");
        assert!(registry.get_or_create_lane("s", &other_ca).is_err());
        assert_eq!(
            registry.entry_count(),
            3,
            "failed construction must not insert an entry"
        );
        // skip_verify_reason is included in the key (conservative
        // fragmentation): same transport with a different audit reason is a
        // distinct entry, never a collapsed one.
        let skip_other_reason = UpstreamTlsConfig {
            skip_verify: true,
            skip_verify_reason: Some("different-reason".to_string()),
            ..UpstreamTlsConfig::default()
        };
        registry
            .get_or_create_lane("s", &skip_other_reason)
            .expect("reason variant must build");
        assert_eq!(registry.entry_count(), 4);
    }

    #[test]
    fn invalid_ca_fails_closed_without_default_substitution() {
        let registry = UpstreamClientRegistry::new();
        let bad = UpstreamTlsConfig {
            ca_cert_path: Some("/nonexistent/eggfetch-lane-ca.pem".to_string()),
            ..UpstreamTlsConfig::default()
        };
        let err = match registry.get_or_create_lane("bad-site", &bad) {
            Ok(_) => panic!("invalid CA must fail, never fall back"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("bad-site"),
            "error must identify the site: {err}"
        );
        assert_eq!(registry.entry_count(), 0);
        // No request can reach an upstream: there is no lane to send through.
        // Recovery after corrected policy + invalidation is proven by the
        // invalidation test below.
    }

    #[test]
    fn invalidation_removes_all_policy_variants_for_one_site() {
        let registry = UpstreamClientRegistry::new();
        registry
            .get_or_create_lane("a", &plaintext_policy())
            .unwrap();
        registry.get_or_create_lane("a", &strict_policy()).unwrap();
        registry.get_or_create_lane("b", &strict_policy()).unwrap();
        assert_eq!(registry.entry_count(), 3);
        registry.invalidate("a");
        assert_eq!(registry.entry_count(), 1);
        // Next acquisition rebuilds from current policy, not a stale entry.
        registry.get_or_create_lane("a", &strict_policy()).unwrap();
        assert_eq!(registry.entry_count(), 2);
    }

    #[test]
    fn clear_removes_everything() {
        let registry = UpstreamClientRegistry::new();
        registry
            .get_or_create_lane("a", &plaintext_policy())
            .unwrap();
        registry.get_or_create_lane("b", &strict_policy()).unwrap();
        registry.clear();
        assert_eq!(registry.entry_count(), 0);
    }
}
