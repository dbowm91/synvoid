//! Stub modules for root crate dependencies.
//!
//! These provide minimal interfaces so synvoid-mesh compiles independently.
//! The root crate will provide the real implementations via re-exports.

pub mod metrics {
    //! Stub metrics functions. Root crate provides the real recorder.

    pub fn record_dht_announce_sent() {}
    pub fn record_dht_announce_failed() {}
    pub fn record_dht_announce_queue_depth(_depth: usize) {}
    pub fn record_dht_store_operation(_success: bool) {}
    pub fn record_dht_store_rate_limited() {}
    pub fn record_dht_get_operation(_found: bool) {}
    pub fn record_dht_verification_failure() {}
    pub fn record_dht_bucket_peers(_bucket_index: usize, _count: u64) {}
    pub fn record_dht_peer_discovered() {}
    pub fn record_dht_peer_removed() {}
    pub fn increment_dht_records_by_type(_record_type: &str) {}
    pub fn record_global_node_liveness_count(_count: u64) {}
    pub fn get_global_node_liveness_count() -> u64 {
        0
    }
    pub fn record_global_node_quorum_lost() {}
    pub fn record_dropped_yara_broadcast() {}
    pub fn record_attack_type(_attack_type: &str) {}
    pub fn record_behavioral_fingerprint_dht_publish() {}
    pub fn record_behavioral_fingerprint_received() {}
    pub fn record_threat_intel_dht_lookup_hit() {}
    pub fn record_threat_intel_dht_lookup_miss() {}
    pub fn record_threat_intel_dht_publish() {}
    pub fn record_threat_intel_dht_publish_failed() {}
    pub fn record_threat_intel_dht_sync() {}
    pub fn record_threat_intel_dht_sync_success() {}
    pub fn record_threat_intel_dht_sync_failed() {}
    pub fn record_threat_intel_dht_sync_added(_count: u64) {}
    pub fn record_threat_intel_dht_sync_removed(_count: u64) {}
    pub fn record_threat_intel_policy_shadow_actionable() {}
    pub fn record_threat_intel_policy_shadow_advisory_only() {}
    pub fn record_threat_intel_policy_shadow_not_actionable() {}
    pub fn record_threat_intel_policy_shadow_deferred() {}
    pub fn record_threat_intel_policy_shadow_not_configured() {}
    pub fn record_threat_intel_policy_shadow_raw_disagreement() {}
    pub fn record_threat_intel_policy_shadow_canonical_unavailable() {}
    pub fn record_threat_intel_policy_shadow_advisory_missing() {}
    pub fn record_threat_intel_enforcement_permitted() {}
    pub fn record_threat_intel_enforcement_suppressed_advisory_only() {}
    pub fn record_threat_intel_enforcement_suppressed_not_actionable() {}
    pub fn record_threat_intel_enforcement_suppressed_deferred() {}
    pub fn record_threat_intel_enforcement_suppressed_not_configured() {}

    pub mod bandwidth {
        use parking_lot::RwLock;
        use std::sync::Arc;

        pub struct BandwidthTracker;

        impl BandwidthTracker {
            pub fn record_bytes_sent(&self, _bytes: u64) {}
            pub fn record_bytes_received(&self, _bytes: u64) {}
            pub fn record_site_mesh_egress(&self, _site_id: &str, _bytes: u64) {}
            pub fn record_site_mesh_ingress(&self, _site_id: &str, _bytes: u64) {}
        }

        static GLOBAL_BANDWIDTH: std::sync::LazyLock<Arc<RwLock<Option<Arc<BandwidthTracker>>>>> =
            std::sync::LazyLock::new(|| Arc::new(RwLock::new(None)));

        pub fn get_global_bandwidth_tracker_or_log() -> Option<Arc<BandwidthTracker>> {
            GLOBAL_BANDWIDTH.read().clone()
        }

        pub fn set_global_bandwidth_tracker(_tracker: Arc<BandwidthTracker>) {}
    }
}

pub mod http {
    //! Stub HTTP utilities. Root crate provides the real implementation.

    pub fn fallback_error_boxed(
    ) -> http::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>>
    {
        use http_body_util::BodyExt;
        let body = http_body_util::Full::new(bytes::Bytes::new())
            .map_err(|never| match never {})
            .boxed();
        http::Response::builder().status(502).body(body).unwrap()
    }

    pub mod response_transform {
        #[derive(Debug, Clone)]
        pub struct MinificationSettings<'a> {
            pub enabled: bool,
            pub html: bool,
            pub css: bool,
            pub js: bool,
            pub _marker: std::marker::PhantomData<&'a ()>,
        }

        #[derive(Debug, Clone)]
        pub struct CompressionSettings<'a> {
            pub enabled: bool,
            pub brotli_level: u32,
            pub gzip_level: u32,
            pub _marker: std::marker::PhantomData<&'a ()>,
        }

        pub fn apply_minification(
            body: bytes::Bytes,
            _content_type: Option<&str>,
            _settings: &MinificationSettings<'_>,
        ) -> bytes::Bytes {
            body
        }

        pub fn apply_compression(
            body: bytes::Bytes,
            _accept_encoding: Option<&str>,
            _settings: &CompressionSettings<'_>,
        ) -> (bytes::Bytes, Option<String>) {
            (body, None)
        }
    }
}

pub mod waf_stub {
    //! Stub WAF types. Root crate provides the real implementation.

    pub mod ratelimit {
        pub mod core {
            pub struct AtomicSlidingWindow {
                _window_secs: u64,
                _max_events: usize,
            }

            impl AtomicSlidingWindow {
                pub fn new(window_secs: u64, max_events: usize) -> Self {
                    Self {
                        _window_secs: window_secs,
                        _max_events: max_events,
                    }
                }

                pub fn try_acquire(&self) -> bool {
                    true
                }

                pub fn count(&self) -> u64 {
                    0
                }

                pub fn get_count(&self, _now_ms: u64) -> u64 {
                    0
                }

                pub fn increment(&self, _now_ms: u64) {}
            }
        }
    }

    pub mod threat_intel {
        pub mod feed_client {
            use serde::{Deserialize, Serialize};

            #[derive(Debug, Clone, Serialize, Deserialize)]
            pub struct ThreatFeedIndicator {
                pub threat_type: u8,
                pub indicator_value: String,
                pub severity: u8,
                pub reason: String,
                pub ttl_seconds: u64,
                pub source_node_id: String,
                pub site_scope: Option<String>,
                pub rate_limit_requests: Option<u64>,
                pub rate_limit_window_secs: Option<u64>,
                pub suspicious_pattern: Option<String>,
            }

            #[derive(Debug, Clone, Serialize, Deserialize)]
            pub struct ThreatFeedPayload {
                pub version: u64,
                pub timestamp: u64,
                pub indicators: Vec<ThreatFeedIndicator>,
                #[serde(default)]
                pub signature: String,
                #[serde(default)]
                pub signer_public_key: Option<String>,
            }

            impl ThreatFeedPayload {
                pub fn get_signable_content(&self) -> Vec<u8> {
                    let indicator_hashes: Vec<String> = self
                        .indicators
                        .iter()
                        .map(|i| format!("{}:{}:{}", i.threat_type, i.indicator_value, i.severity))
                        .collect();

                    format!(
                        "{}:{}:{}:{}",
                        self.version,
                        self.timestamp,
                        self.indicators.len(),
                        indicator_hashes.join(",")
                    )
                    .into_bytes()
                }
            }

            pub struct ThreatFeedClient;

            impl ThreatFeedClient {
                pub fn new(_url: &str) -> Self {
                    ThreatFeedClient
                }
            }
        }
    }
}

pub mod block_store {
    //! Stub BlockStore. Root crate provides the real implementation.

    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use synvoid_config::DenyListLimitsConfig;

    #[derive(Debug, Clone)]
    pub struct BlockEntry {
        pub ip: String,
        pub reason: String,
        pub blocked_at: u64,
        pub ban_expire_seconds: u64,
        pub site_scope: String,
        pub access_count: u64,
        pub last_access: u64,
    }

    impl BlockEntry {
        pub fn new(
            ip: IpAddr,
            reason: String,
            ban_expire_seconds: u64,
            site_scope: String,
        ) -> Self {
            let now = synvoid_utils::safe_unix_timestamp();
            Self {
                ip: ip.to_string(),
                reason,
                blocked_at: now,
                ban_expire_seconds,
                site_scope,
                access_count: 0,
                last_access: now,
            }
        }

        pub fn is_permanent(&self) -> bool {
            self.ban_expire_seconds == 0
        }

        pub fn is_expired(&self) -> bool {
            if self.is_permanent() {
                return false;
            }
            let now = synvoid_utils::safe_unix_timestamp();
            now > self.blocked_at + self.ban_expire_seconds
        }

        pub fn key(site_scope: &str, ip: &IpAddr) -> String {
            format!("block:{}:{}", site_scope, ip)
        }

        pub fn update_access(&mut self) {
            self.access_count = self.access_count.saturating_add(1);
            self.last_access = synvoid_utils::safe_unix_timestamp();
        }
    }

    pub struct BlockStore {
        enabled: bool,
        #[allow(dead_code)]
        persist_path: Option<PathBuf>,
        #[allow(dead_code)]
        config: DenyListLimitsConfig,
        entries: Arc<RwLock<HashMap<String, BlockEntry>>>,
    }

    pub trait BlockStoreApi: Send + Sync {
        fn block_ip(&self, ip: IpAddr, reason: &str, ttl_secs: u64, site_scope: &str) -> bool;
        fn is_blocked(&self, ip: &IpAddr, site_scope: &str) -> bool;
        fn unblock_ip(&self, ip: &IpAddr, site_scope: &str) -> bool;
        fn get_all_entries(&self) -> Vec<BlockEntry>;
    }

    impl BlockStore {
        pub fn new(
            _enabled: bool,
            data_dir: Option<PathBuf>,
            config: DenyListLimitsConfig,
        ) -> Self {
            let persist_path = data_dir.map(|d| d.join("blocks.json"));
            Self {
                enabled: _enabled,
                persist_path,
                config,
                entries: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        pub fn is_enabled(&self) -> bool {
            self.enabled
        }

        pub fn is_blocked(&self, ip: &IpAddr, site_scope: &str) -> bool {
            if !self.enabled {
                return false;
            }
            let key = BlockEntry::key(site_scope, ip);
            self.entries.read().contains_key(&key)
        }

        pub fn block_ip(&self, ip: IpAddr, reason: &str, ttl_secs: u64, site_scope: &str) -> bool {
            if !self.enabled {
                return false;
            }
            let key = BlockEntry::key(site_scope, &ip);
            let entry = BlockEntry::new(ip, reason.to_string(), ttl_secs, site_scope.to_string());
            self.entries.write().insert(key, entry);
            true
        }

        pub fn unblock_ip(&self, ip: &IpAddr, site_scope: &str) -> bool {
            if !self.enabled {
                return false;
            }
            let key = BlockEntry::key(site_scope, ip);
            self.entries.write().remove(&key).is_some()
        }

        pub fn get_all_entries(&self) -> Vec<BlockEntry> {
            if !self.enabled {
                return Vec::new();
            }
            self.entries.read().values().cloned().collect()
        }
    }

    impl BlockStoreApi for BlockStore {
        fn block_ip(&self, ip: IpAddr, reason: &str, ttl_secs: u64, site_scope: &str) -> bool {
            self.block_ip(ip, reason, ttl_secs, site_scope)
        }

        fn is_blocked(&self, ip: &IpAddr, site_scope: &str) -> bool {
            self.is_blocked(ip, site_scope)
        }

        fn unblock_ip(&self, ip: &IpAddr, site_scope: &str) -> bool {
            self.unblock_ip(ip, site_scope)
        }

        fn get_all_entries(&self) -> Vec<BlockEntry> {
            self.get_all_entries()
        }
    }
}

pub mod admin_stub {
    //! Stub admin functions. Root crate provides the real implementation.

    pub fn get_current_connections() -> u64 {
        0
    }

    pub fn get_cpu_memory_usage() -> (f32, f32) {
        (0.0, 0.0)
    }
}

pub mod static_files_stub {
    //! Stub static file types. Root crate provides the real implementation.

    pub mod client {
        pub struct ImageRightsClient;

        impl ImageRightsClient {
            pub fn new(_socket_path: impl AsRef<std::path::Path>) -> Self {
                ImageRightsClient
            }

            pub async fn mark_image_rights(
                &self,
                _site_id: &str,
                _body: Vec<u8>,
                _last_modified: Option<String>,
                _level: Option<String>,
                _intensity: Option<f32>,
                _seed: Option<u64>,
                _max_dimension: Option<u32>,
                _jpeg_quality: Option<u8>,
            ) -> Result<Vec<u8>, String> {
                Ok(vec![])
            }
        }
    }

    pub mod minifier {
        pub struct MinifierGenerator;

        impl MinifierGenerator {
            pub fn new() -> Self {
                MinifierGenerator
            }

            pub fn minify_html(&self, _input: &str) -> Result<String, String> {
                Ok(_input.to_string())
            }

            pub fn minify_css(&self, _input: &str) -> Result<String, String> {
                Ok(_input.to_string())
            }

            pub fn minify_js(&self, _input: &str) -> Result<String, String> {
                Ok(_input.to_string())
            }
        }
    }
}

pub mod upload_stub {
    //! Stub upload types. Root crate provides the real implementation.

    pub mod yara_rule_feed {
        use std::sync::Arc;

        pub struct YaraRuleFeedManager;

        impl YaraRuleFeedManager {
            pub fn new() -> Arc<Self> {
                Arc::new(YaraRuleFeedManager)
            }

            pub fn apply_rules(&self) -> Result<String, String> {
                Ok("1.0".to_string())
            }

            pub fn get_rules_for_scanner(&self) -> Option<String> {
                None
            }

            pub fn add_to_history_inline(
                &self,
                _version: String,
                _rules: String,
                _source: String,
            ) -> Result<(), String> {
                Ok(())
            }
        }
    }
}
