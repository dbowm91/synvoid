use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use synvoid_http_client::eggfetch_transport::EggfetchUpstreamClient;
use synvoid_http_client::UpstreamTlsConfig;

pub struct UpstreamClientRegistry {
    // Phase 60 (retired): the only map. Eggfetch lane handles, keyed by
    // site. `EggfetchUpstreamClient::cached` keys by policy underneath, so
    // identical policies share one physical pool; this map preserves the
    // site-keyed lifecycle (invalidate on config change). The legacy
    // buffered/streaming client maps were removed once every dispatch path
    // (H1 buffered/streaming, streaming-WAF, H3, proxy cache) moved to the
    // lane — one handle serves both because the lane is body-generic.
    lane_clients: DashMap<String, Arc<EggfetchUpstreamClient>>,
}

impl UpstreamClientRegistry {
    pub fn new() -> Self {
        Self {
            lane_clients: DashMap::new(),
        }
    }

    /// Phase 60: eggfetch lane handle for a site (buffered and streaming).
    ///
    /// One map replaces the legacy buffered/streaming split: the lane is
    /// body-generic (`execute<B>`), so a single per-site handle serves both
    /// buffered and streaming dispatch. Construction mirrors the legacy
    /// parameters (5s connect, 100 idle/host, 30s idle).
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
    ) -> Arc<EggfetchUpstreamClient> {
        // `cached` fails only on invalid custom CA material; fall back to a
        // verifying default rather than poisoning the site entry (fail-closed:
        // requests then fail at handshake instead of using a wrong policy).
        let client = self
            .lane_clients
            .entry(site_id.to_string())
            .or_insert_with(|| {
                let lane = EggfetchUpstreamClient::cached(
                    Duration::from_secs(5),
                    100,
                    Duration::from_secs(30),
                    tls,
                )
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        site_id,
                        error = %e,
                        "eggfetch lane: site TLS policy failed to build (bad custom CA?); \
                         falling back to verifying default TLS (fail-closed)"
                    );
                    EggfetchUpstreamClient::build(
                        Duration::from_secs(5),
                        100,
                        Duration::from_secs(30),
                        &UpstreamTlsConfig::default(),
                    )
                    .expect("eggfetch lane must build for default policy")
                });
                Arc::new(lane)
            });
        Arc::clone(client.value())
    }

    pub fn invalidate(&self, site_id: &str) {
        self.lane_clients.remove(site_id);
    }

    pub fn clear(&self) {
        self.lane_clients.clear();
    }
}

impl Default for UpstreamClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}
