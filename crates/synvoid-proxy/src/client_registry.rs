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
        // plaintext before network I/O.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let err = strict
                .send_buffered(
                    http::Method::GET,
                    "http://127.0.0.1:9/plaintext",
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
        });
        // The buffered lane carries the plaintext-capable policy; its gate
        // must not reject the same scheme at the policy layer. (The request
        // itself will fail at connect to the discard port, proving it passed
        // the gate and attempted I/O.)
        let rt2 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt2.block_on(async {
            let err = buffered
                .send_buffered(
                    http::Method::GET,
                    "http://127.0.0.1:9/plaintext",
                    None,
                    http::HeaderMap::new(),
                    Some(Duration::from_millis(200)),
                    None,
                )
                .await
                .expect_err("unroutable discard port must fail at I/O, not at the gate");
            assert!(
                !err.to_string().contains("plaintext not permitted"),
                "buffered lane must not apply the strict plaintext gate: {err}"
            );
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
            let err = strict
                .send_buffered(
                    http::Method::GET,
                    "http://127.0.0.1:9/x",
                    None,
                    http::HeaderMap::new(),
                    None,
                    None,
                )
                .await
                .expect_err("strict lane must reject plaintext");
            assert!(err.to_string().contains("plaintext"));
            let err = buffered
                .send_buffered(
                    http::Method::GET,
                    "http://127.0.0.1:9/x",
                    None,
                    http::HeaderMap::new(),
                    Some(Duration::from_millis(200)),
                    None,
                )
                .await
                .expect_err("buffered lane must attempt I/O");
            assert!(
                !err.to_string().contains("plaintext not permitted"),
                "buffered lane must keep its legacy plaintext gate: {err}"
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
