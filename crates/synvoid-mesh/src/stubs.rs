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
    pub use synvoid_core::block_store::{
        BlockProvenance, BlockProvenanceKind, BlocklistPeerCursorRecord,
    };

    /// Cursor for replaying events from the log (stub for mesh crate independence).
    ///
    /// `since_sequence` controls the starting point:
    /// - `None`: replay from the oldest retained event (from start).
    /// - `Some(n)`: replay events with sequence `> n` (exclusive cursor).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BlocklistEventCursor {
        pub since_sequence: Option<u64>,
        pub max_events: u32,
    }

    /// Result of a catchup query against the event log (stub).
    #[derive(Debug, Clone)]
    pub struct BlocklistCatchupResult {
        pub events: Vec<synvoid_core::block_store::BlocklistEvent>,
        pub history_complete: bool,
        pub latest_sequence: u64,
        pub latest_timestamp: u64,
        pub snapshot_required: bool,
    }

    /// Result of applying a blocklist event.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BlocklistApplyResult {
        Applied,
        NoopDuplicate,
        IgnoredStale,
        InvalidTarget,
        StoreDisabled,
    }

    #[derive(Debug, Clone)]
    pub struct BlockEntry {
        pub ip: String,
        pub reason: String,
        pub blocked_at: u64,
        pub ban_expire_seconds: u64,
        pub site_scope: String,
        pub access_count: u64,
        pub last_access: u64,
        pub provenance_kind: String,
        pub provenance_source: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct MeshBlockEntry {
        pub mesh_id: String,
        pub reason: String,
        pub blocked_at: u64,
        pub ban_expire_seconds: u64,
        pub site_scope: String,
        pub access_count: u64,
        pub last_access: u64,
        pub provenance_kind: String,
        pub provenance_source: Option<String>,
    }

    /// Snapshot options for peer convergence (stub).
    #[derive(Debug, Clone)]
    pub struct BlocklistSnapshotOptions {
        pub include_ip_blocks: bool,
        pub include_mesh_id_blocks: bool,
        pub include_target_state: bool,
        pub site_scope: Option<String>,
        pub max_items: u32,
    }

    /// Snapshot cursor for pagination (stub).
    #[derive(Debug, Clone, Default)]
    pub struct BlocklistSnapshotCursor {
        pub page_token: Option<String>,
    }

    /// A snapshot chunk (stub).
    #[derive(Debug, Clone)]
    pub struct BlocklistSnapshotChunk {
        pub ip_blocks: Vec<synvoid_core::block_store::BlockRecord>,
        pub mesh_blocks: Vec<synvoid_core::block_store::BlockRecord>,
        pub target_state_records: Vec<synvoid_core::block_store::BlocklistTargetStateRecord>,
        pub next_page_token: Option<String>,
        pub has_more: bool,
        pub snapshot_complete: bool,
        pub truncated_reason: Option<String>,
    }

    /// Result of applying a snapshot (stub).
    #[derive(Debug, Clone, Default)]
    pub struct BlocklistSnapshotApplyResult {
        pub ip_blocks_applied: u32,
        pub ip_blocks_updated: u32,
        pub mesh_blocks_applied: u32,
        pub mesh_blocks_updated: u32,
        pub target_state_records_applied: u32,
        pub stale_records_ignored: u32,
        pub invalid_records_ignored: u32,
        pub expired_records_ignored: u32,
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
                provenance_kind: "LegacyUnknown".to_string(),
                provenance_source: None,
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
        fn block_ip_with_provenance(
            &self,
            ip: IpAddr,
            reason: &str,
            ttl_secs: u64,
            site_scope: &str,
            provenance: BlockProvenance,
        ) -> bool;
        fn is_blocked(&self, ip: &IpAddr, site_scope: &str) -> bool;
        fn unblock_ip(&self, ip: &IpAddr, site_scope: &str) -> bool;
        fn get_all_entries(&self) -> Vec<BlockEntry>;
        fn block_mesh_id_with_provenance(
            &self,
            mesh_id: &str,
            reason: &str,
            ttl_secs: u64,
            site_scope: &str,
            provenance: BlockProvenance,
        ) -> bool;
        fn unblock_mesh_id(&self, mesh_id: &str, site_scope: &str) -> bool;
        fn is_mesh_id_blocked(&self, mesh_id: &str, site_scope: &str) -> bool;
        fn get_all_mesh_entries(&self) -> Vec<MeshBlockEntry>;
        fn get_all_block_records(&self) -> Vec<synvoid_core::block_store::BlockRecord>;
        fn apply_blocklist_event(
            &self,
            event: &synvoid_core::block_store::BlocklistEvent,
        ) -> BlocklistApplyResult;
        fn query_blocklist_catchup(&self, cursor: &BlocklistEventCursor) -> BlocklistCatchupResult;
        fn record_blocklist_event_for_catchup(
            &self,
            event: &synvoid_core::block_store::BlocklistEvent,
        ) -> Option<u64>;
        fn event_log_stats(&self) -> (usize, Option<u64>, Option<u64>, u64);
        fn export_blocklist_snapshot(
            &self,
            options: &BlocklistSnapshotOptions,
            cursor: &BlocklistSnapshotCursor,
        ) -> BlocklistSnapshotChunk;
        fn apply_blocklist_snapshot(
            &self,
            snapshot: &BlocklistSnapshotChunk,
        ) -> BlocklistSnapshotApplyResult;
        fn get_blocklist_peer_cursor(
            &self,
            peer_id: &str,
            source_node: &str,
        ) -> Option<synvoid_core::block_store::BlocklistPeerCursorRecord>;
        fn update_blocklist_peer_cursor(
            &self,
            record: synvoid_core::block_store::BlocklistPeerCursorRecord,
        );
        fn persist_peer_cursors(&self);
        fn peer_cursor_count(&self) -> usize;
        fn peer_cursor_timestamp_range(&self) -> (Option<u64>, Option<u64>);
        fn has_cursor_persistence(&self) -> bool;
        fn event_log_capacity(&self) -> usize;
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

        pub fn block_ip_with_provenance(
            &self,
            ip: IpAddr,
            reason: &str,
            ttl_secs: u64,
            site_scope: &str,
            _provenance: BlockProvenance,
        ) -> bool {
            self.block_ip(ip, reason, ttl_secs, site_scope)
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

        pub fn block_mesh_id_with_provenance(
            &self,
            _mesh_id: &str,
            _reason: &str,
            _ttl_secs: u64,
            _site_scope: &str,
            _provenance: BlockProvenance,
        ) -> bool {
            true
        }

        pub fn unblock_mesh_id(&self, _mesh_id: &str, _site_scope: &str) -> bool {
            true
        }

        pub fn is_mesh_id_blocked(&self, _mesh_id: &str, _site_scope: &str) -> bool {
            false
        }

        pub fn get_all_mesh_entries(&self) -> Vec<MeshBlockEntry> {
            Vec::new()
        }

        pub fn get_all_block_records(&self) -> Vec<synvoid_core::block_store::BlockRecord> {
            Vec::new()
        }

        pub fn apply_blocklist_event(
            &self,
            _event: &synvoid_core::block_store::BlocklistEvent,
        ) -> BlocklistApplyResult {
            BlocklistApplyResult::Applied
        }

        pub fn query_blocklist_catchup(
            &self,
            _cursor: &BlocklistEventCursor,
        ) -> BlocklistCatchupResult {
            BlocklistCatchupResult {
                events: Vec::new(),
                history_complete: true,
                latest_sequence: 0,
                latest_timestamp: 0,
                snapshot_required: false,
            }
        }

        pub fn record_blocklist_event_for_catchup(
            &self,
            _event: &synvoid_core::block_store::BlocklistEvent,
        ) -> Option<u64> {
            None
        }

        pub fn event_log_stats(&self) -> (usize, Option<u64>, Option<u64>, u64) {
            (0, None, None, 0)
        }

        pub fn export_blocklist_snapshot(
            &self,
            _options: &BlocklistSnapshotOptions,
            _cursor: &BlocklistSnapshotCursor,
        ) -> BlocklistSnapshotChunk {
            BlocklistSnapshotChunk {
                ip_blocks: Vec::new(),
                mesh_blocks: Vec::new(),
                target_state_records: Vec::new(),
                next_page_token: None,
                has_more: false,
                snapshot_complete: true,
                truncated_reason: None,
            }
        }

        pub fn apply_blocklist_snapshot(
            &self,
            _snapshot: &BlocklistSnapshotChunk,
        ) -> BlocklistSnapshotApplyResult {
            BlocklistSnapshotApplyResult::default()
        }

        pub fn get_blocklist_peer_cursor(
            &self,
            _peer_id: &str,
            _source_node: &str,
        ) -> Option<synvoid_core::block_store::BlocklistPeerCursorRecord> {
            None
        }

        pub fn update_blocklist_peer_cursor(
            &self,
            _record: synvoid_core::block_store::BlocklistPeerCursorRecord,
        ) {
        }

        pub fn persist_peer_cursors(&self) {}

        pub fn peer_cursor_count(&self) -> usize {
            0
        }

        pub fn peer_cursor_timestamp_range(&self) -> (Option<u64>, Option<u64>) {
            (None, None)
        }

        pub fn has_cursor_persistence(&self) -> bool {
            false
        }

        pub fn event_log_capacity(&self) -> usize {
            0
        }
    }

    impl BlockStoreApi for BlockStore {
        fn block_ip(&self, ip: IpAddr, reason: &str, ttl_secs: u64, site_scope: &str) -> bool {
            self.block_ip(ip, reason, ttl_secs, site_scope)
        }

        fn block_ip_with_provenance(
            &self,
            ip: IpAddr,
            reason: &str,
            ttl_secs: u64,
            site_scope: &str,
            provenance: BlockProvenance,
        ) -> bool {
            self.block_ip_with_provenance(ip, reason, ttl_secs, site_scope, provenance)
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

        fn block_mesh_id_with_provenance(
            &self,
            mesh_id: &str,
            reason: &str,
            ttl_secs: u64,
            site_scope: &str,
            provenance: BlockProvenance,
        ) -> bool {
            self.block_mesh_id_with_provenance(mesh_id, reason, ttl_secs, site_scope, provenance)
        }

        fn unblock_mesh_id(&self, mesh_id: &str, site_scope: &str) -> bool {
            self.unblock_mesh_id(mesh_id, site_scope)
        }

        fn is_mesh_id_blocked(&self, mesh_id: &str, site_scope: &str) -> bool {
            self.is_mesh_id_blocked(mesh_id, site_scope)
        }

        fn get_all_mesh_entries(&self) -> Vec<MeshBlockEntry> {
            self.get_all_mesh_entries()
        }

        fn get_all_block_records(&self) -> Vec<synvoid_core::block_store::BlockRecord> {
            self.get_all_block_records()
        }

        fn apply_blocklist_event(
            &self,
            event: &synvoid_core::block_store::BlocklistEvent,
        ) -> BlocklistApplyResult {
            self.apply_blocklist_event(event)
        }

        fn query_blocklist_catchup(&self, cursor: &BlocklistEventCursor) -> BlocklistCatchupResult {
            self.query_blocklist_catchup(cursor)
        }

        fn record_blocklist_event_for_catchup(
            &self,
            event: &synvoid_core::block_store::BlocklistEvent,
        ) -> Option<u64> {
            self.record_blocklist_event_for_catchup(event)
        }

        fn event_log_stats(&self) -> (usize, Option<u64>, Option<u64>, u64) {
            self.event_log_stats()
        }

        fn export_blocklist_snapshot(
            &self,
            options: &BlocklistSnapshotOptions,
            cursor: &BlocklistSnapshotCursor,
        ) -> BlocklistSnapshotChunk {
            self.export_blocklist_snapshot(options, cursor)
        }

        fn apply_blocklist_snapshot(
            &self,
            snapshot: &BlocklistSnapshotChunk,
        ) -> BlocklistSnapshotApplyResult {
            self.apply_blocklist_snapshot(snapshot)
        }

        fn get_blocklist_peer_cursor(
            &self,
            peer_id: &str,
            source_node: &str,
        ) -> Option<synvoid_core::block_store::BlocklistPeerCursorRecord> {
            self.get_blocklist_peer_cursor(peer_id, source_node)
        }

        fn update_blocklist_peer_cursor(
            &self,
            record: synvoid_core::block_store::BlocklistPeerCursorRecord,
        ) {
            self.update_blocklist_peer_cursor(record)
        }

        fn persist_peer_cursors(&self) {
            self.persist_peer_cursors()
        }

        fn peer_cursor_count(&self) -> usize {
            self.peer_cursor_count()
        }

        fn peer_cursor_timestamp_range(&self) -> (Option<u64>, Option<u64>) {
            self.peer_cursor_timestamp_range()
        }

        fn has_cursor_persistence(&self) -> bool {
            self.has_cursor_persistence()
        }

        fn event_log_capacity(&self) -> usize {
            self.event_log_capacity()
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
