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
                    serde_json::to_vec(self).unwrap_or_default()
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

    pub struct BlockStore;

    impl BlockStore {
        pub fn new() -> Self {
            BlockStore
        }

        pub fn is_blocked(&self, _ip: &std::net::IpAddr) -> bool {
            false
        }

        pub fn block_ip(
            &self,
            _ip: std::net::IpAddr,
            _reason: &str,
            _ttl_secs: u64,
            _site_scope: &str,
        ) -> bool {
            true
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
        pub struct PoisonImageClient;

        impl PoisonImageClient {
            pub fn new(_socket_path: impl AsRef<std::path::Path>) -> Self {
                PoisonImageClient
            }

            pub async fn poison_image(
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
        use parking_lot::RwLock;
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
