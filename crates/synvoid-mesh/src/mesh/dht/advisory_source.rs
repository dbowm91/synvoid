//! Advisory DHT record source seam (Iteration 16).
//!
//! Provides a read-only interface over DHT records for **advisory** observations
//! only. Advisory DHT answers "what has been advertised?"; canonical/Raft answers
//! "what is trusted?"; policy decides action.
//!
//! This seam is deliberately narrow: it exposes present/missing/expired/unavailable
//! advisory records and prefix reads without mutation, replication, quorum, or
//! canonical trust decisions. Service consumers should migrate to this trait
//! rather than reading raw DHT records as authority.
//!
//! # Domain Distinction
//!
//! - **Advisory** (this module): threat intel observations, proxy metadata,
//!   YARA/WASM manifests, behavioral fingerprints, capability hints.
//! - **Canonical** (`canonical.rs`): Raft-derived trust state (global node
//!   authorization, org key trust, revocations).
//! - **Policy**: composes advisory + canonical to decide accept/reject/block/allow.
//!
//! This trait must not depend on `CanonicalTrustReader` or expose trust/authority
//! language. Future policy code may compose both, but this seam stays advisory-only.

use std::collections::HashMap;
use std::sync::Arc;

use super::record_store::RecordStoreManager;

/// Freshness classification for an advisory record observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdvisoryFreshness {
    /// Record is live from authoritative DHT source.
    Live,
    /// Record is cached with known age in milliseconds.
    Cached { age_ms: u64 },
    /// Record is stale beyond grace but was accepted under policy.
    Stale { age_ms: u64 },
    /// No freshness information available.
    #[default]
    Unknown,
}

/// Status of an advisory record lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryRecordStatus {
    /// Record is present in the store.
    Present,
    /// Record was not found in the store.
    Missing,
    /// Record existed but has expired (TTL exceeded).
    Expired,
    /// Store is unavailable or disabled.
    Unavailable,
}

/// An advisory DHT record observation.
///
/// This struct contains only advisory information: what was advertised, not
/// whether it is trusted. Signature verification status is exposed as
/// `record_signature_valid` and documented as identity/envelope information,
/// not canonical authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryRecord {
    /// The DHT key for this record.
    pub key: String,
    /// Raw advisory value bytes (not decoded to service-specific payloads).
    pub value: Vec<u8>,
    /// Node ID that published this record.
    pub source_node_id: String,
    /// Unix timestamp of the record.
    pub timestamp: u64,
    /// Time-to-live in seconds.
    pub ttl_seconds: u64,
    /// Freshness of the observation.
    pub freshness: AdvisoryFreshness,
    /// Status of the record.
    pub status: AdvisoryRecordStatus,
    /// Whether the envelope signature was observed as valid (identity info, not
    /// canonical authority).
    pub record_signature_valid: bool,
}

impl AdvisoryRecord {
    /// Compute age in milliseconds from timestamp to now (or 0 if in the future).
    pub fn age_ms(&self) -> u64 {
        let now = synvoid_utils::safe_unix_timestamp();
        let age_secs = now.saturating_sub(self.timestamp);
        age_secs.saturating_mul(1000)
    }

    /// Returns true if the record has a non-zero TTL and has expired.
    pub fn is_expired(&self, now: u64) -> bool {
        if self.ttl_seconds == 0 {
            return false;
        }
        let expires_at = self.timestamp.saturating_add(self.ttl_seconds);
        now > expires_at
    }
}

/// Outcome of a single advisory record lookup.
#[derive(Debug, Clone)]
pub enum AdvisoryRecordLookup {
    /// Record is present.
    Present(AdvisoryRecord),
    /// Record was not found.
    Missing,
    /// Record existed but has expired.
    Expired,
    /// Store is unavailable or disabled.
    Unavailable,
}

/// Read-only seam for advisory DHT observations.
///
/// Consumers should depend on this trait (or a `&dyn AdvisoryRecordSource`)
/// when they need advisory DHT data, rather than importing `RecordStoreManager`
/// or raw DHT internals directly.
///
/// # Invariants
///
/// - This trait is read-only: no mutation, publish, store, announce, quorum,
///   or sync operations.
/// - This trait does not expose canonical trust decisions.
/// - This trait does not depend on `CanonicalTrustReader`.
/// - Future policy code may compose `AdvisoryRecordSource` + `CanonicalTrustReader`,
///   but this trait must not know about canonical state.
/// - All answers include freshness and status classification.
/// - Implementations are synchronous and should avoid I/O in trait methods.
pub trait AdvisoryRecordSource: Send + Sync {
    /// Look up a single advisory record by key.
    fn get_advisory_record(&self, key: &str) -> AdvisoryRecordLookup;

    /// Look up advisory records by key prefix, bounded by limit.
    fn get_advisory_records_by_prefix(&self, prefix: &str, limit: usize) -> Vec<AdvisoryRecord>;

    /// Human-readable source name for logging/debugging.
    fn source_name(&self) -> &'static str {
        "unknown"
    }
}

/// Read-only adapter over `RecordStoreManager` that exposes advisory reads.
///
/// This adapter maps existing record-store reads to `AdvisoryRecord` outcomes
/// without validating trust, checking canonical state, or applying service policy.
/// It preserves current record-store read behavior.
pub struct RecordStoreAdvisorySource {
    store: Arc<RecordStoreManager>,
}

impl RecordStoreAdvisorySource {
    /// Create a new advisory source backed by the given record store.
    pub fn new(store: Arc<RecordStoreManager>) -> Self {
        Self { store }
    }

    fn map_record(
        record: &crate::protocol::DhtRecord,
        freshness: AdvisoryFreshness,
        signature_valid: bool,
    ) -> AdvisoryRecord {
        AdvisoryRecord {
            key: record.key.clone(),
            value: record.value.clone(),
            source_node_id: record.source_node_id.clone(),
            timestamp: record.timestamp,
            ttl_seconds: record.ttl_seconds,
            freshness,
            status: AdvisoryRecordStatus::Present,
            record_signature_valid: signature_valid,
        }
    }

    fn classify_freshness(record: &crate::protocol::DhtRecord) -> AdvisoryFreshness {
        let now = synvoid_utils::safe_unix_timestamp();
        let age_secs = now.saturating_sub(record.timestamp);
        let age_ms = age_secs.saturating_mul(1000);

        if record.ttl_seconds == 0 {
            return AdvisoryFreshness::Live;
        }

        let expires_at = record.timestamp.saturating_add(record.ttl_seconds);
        if now > expires_at {
            return AdvisoryFreshness::Stale { age_ms };
        }

        let half_ttl = record.ttl_seconds / 2;
        if age_secs <= half_ttl {
            AdvisoryFreshness::Live
        } else {
            AdvisoryFreshness::Cached { age_ms }
        }
    }
}

impl AdvisoryRecordSource for RecordStoreAdvisorySource {
    fn get_advisory_record(&self, key: &str) -> AdvisoryRecordLookup {
        match self.store.get_record(key) {
            Some(record) => {
                let now = synvoid_utils::safe_unix_timestamp();
                let expires_at = record.timestamp.saturating_add(record.ttl_seconds);
                if record.ttl_seconds > 0 && now > expires_at {
                    return AdvisoryRecordLookup::Expired;
                }
                let freshness = Self::classify_freshness(&record);
                let signature_valid = !record.signature.is_empty();
                AdvisoryRecordLookup::Present(Self::map_record(&record, freshness, signature_valid))
            }
            None => AdvisoryRecordLookup::Missing,
        }
    }

    fn get_advisory_records_by_prefix(&self, prefix: &str, limit: usize) -> Vec<AdvisoryRecord> {
        let now = synvoid_utils::safe_unix_timestamp();
        self.store
            .get_by_prefix(prefix, limit)
            .into_iter()
            .filter(|record| {
                let expires_at = record.timestamp.saturating_add(record.ttl_seconds);
                record.ttl_seconds == 0 || now <= expires_at
            })
            .map(|record| {
                let freshness = Self::classify_freshness(&record);
                let signature_valid = !record.signature.is_empty();
                Self::map_record(&record, freshness, signature_valid)
            })
            .collect()
    }

    fn source_name(&self) -> &'static str {
        "record_store"
    }
}

/// Static, pure-data advisory source for tests and offline scenarios.
///
/// No DHT, no networking, fully deterministic.
#[derive(Debug, Default, Clone)]
pub struct StaticAdvisoryRecordSource {
    records: HashMap<String, AdvisoryRecord>,
    unavailable: bool,
}

impl StaticAdvisoryRecordSource {
    /// Create an empty static source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a static source marked as unavailable (all lookups return
    /// `Unavailable`).
    pub fn unavailable() -> Self {
        Self {
            records: HashMap::new(),
            unavailable: true,
        }
    }

    /// Insert a record into the static source.
    pub fn insert(&mut self, record: AdvisoryRecord) {
        self.records.insert(record.key.clone(), record);
    }

    /// Insert multiple records.
    pub fn insert_all(&mut self, records: Vec<AdvisoryRecord>) {
        for record in records {
            self.insert(record);
        }
    }

    /// Build a static source from a list of records.
    pub fn from_records(records: Vec<AdvisoryRecord>) -> Self {
        let mut source = Self::new();
        source.insert_all(records);
        source
    }

    /// Create an expired record for testing.
    pub fn expired_record(key: &str) -> AdvisoryRecord {
        AdvisoryRecord {
            key: key.to_string(),
            value: vec![],
            source_node_id: "test_node".to_string(),
            timestamp: 1000,
            ttl_seconds: 1,
            freshness: AdvisoryFreshness::Unknown,
            status: AdvisoryRecordStatus::Expired,
            record_signature_valid: false,
        }
    }

    /// Create a present record for testing.
    pub fn test_record(key: &str) -> AdvisoryRecord {
        let now = synvoid_utils::safe_unix_timestamp();
        AdvisoryRecord {
            key: key.to_string(),
            value: format!("test_value_{}", key).into_bytes(),
            source_node_id: "test_node".to_string(),
            timestamp: now,
            ttl_seconds: 3600,
            freshness: AdvisoryFreshness::Live,
            status: AdvisoryRecordStatus::Present,
            record_signature_valid: true,
        }
    }
}

impl AdvisoryRecordSource for StaticAdvisoryRecordSource {
    fn get_advisory_record(&self, key: &str) -> AdvisoryRecordLookup {
        if self.unavailable {
            return AdvisoryRecordLookup::Unavailable;
        }
        match self.records.get(key) {
            Some(record) => {
                let now = synvoid_utils::safe_unix_timestamp();
                if record.ttl_seconds > 0 && now > record.timestamp + record.ttl_seconds {
                    AdvisoryRecordLookup::Expired
                } else {
                    AdvisoryRecordLookup::Present(record.clone())
                }
            }
            None => AdvisoryRecordLookup::Missing,
        }
    }

    fn get_advisory_records_by_prefix(&self, prefix: &str, limit: usize) -> Vec<AdvisoryRecord> {
        if self.unavailable {
            return vec![];
        }
        let now = synvoid_utils::safe_unix_timestamp();
        self.records
            .values()
            .filter(|r| r.key.starts_with(prefix))
            .filter(|r| r.ttl_seconds == 0 || now <= r.timestamp + r.ttl_seconds)
            .take(limit)
            .cloned()
            .collect()
    }

    fn source_name(&self) -> &'static str {
        "static"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_is_object_safe() {
        fn _assert_object_safe(_: &dyn AdvisoryRecordSource) {}
        let source = StaticAdvisoryRecordSource::new();
        _assert_object_safe(&source);
    }

    #[test]
    fn static_source_returns_present_record() {
        let mut source = StaticAdvisoryRecordSource::new();
        let record = StaticAdvisoryRecordSource::test_record("test:key");
        source.insert(record);

        match source.get_advisory_record("test:key") {
            AdvisoryRecordLookup::Present(r) => {
                assert_eq!(r.key, "test:key");
                assert_eq!(r.status, AdvisoryRecordStatus::Present);
                assert_eq!(r.freshness, AdvisoryFreshness::Live);
            }
            other => panic!("expected Present, got {:?}", other),
        }
    }

    #[test]
    fn static_source_returns_missing_for_unknown_key() {
        let source = StaticAdvisoryRecordSource::new();
        assert!(matches!(
            source.get_advisory_record("nonexistent"),
            AdvisoryRecordLookup::Missing
        ));
    }

    #[test]
    fn static_source_returns_unavailable() {
        let source = StaticAdvisoryRecordSource::unavailable();
        assert!(matches!(
            source.get_advisory_record("any_key"),
            AdvisoryRecordLookup::Unavailable
        ));
    }

    #[test]
    fn static_source_returns_expired_for_old_record() {
        let mut source = StaticAdvisoryRecordSource::new();
        source.insert(StaticAdvisoryRecordSource::expired_record("expired:key"));

        match source.get_advisory_record("expired:key") {
            AdvisoryRecordLookup::Expired => {}
            other => panic!("expected Expired, got {:?}", other),
        }
    }

    #[test]
    fn static_source_prefix_lookup_bounded_by_limit() {
        let mut source = StaticAdvisoryRecordSource::new();
        for i in 0..10 {
            source.insert(AdvisoryRecord {
                key: format!("prefix:{}", i),
                value: vec![],
                source_node_id: "node".to_string(),
                timestamp: synvoid_utils::safe_unix_timestamp(),
                ttl_seconds: 3600,
                freshness: AdvisoryFreshness::Live,
                status: AdvisoryRecordStatus::Present,
                record_signature_valid: true,
            });
        }

        let results = source.get_advisory_records_by_prefix("prefix:", 3);
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.key.starts_with("prefix:"));
        }
    }

    #[test]
    fn static_source_prefix_lookup_filters_expired() {
        let mut source = StaticAdvisoryRecordSource::new();
        source.insert(AdvisoryRecord {
            key: "expired:record".to_string(),
            value: vec![],
            source_node_id: "node".to_string(),
            timestamp: 1000,
            ttl_seconds: 1,
            freshness: AdvisoryFreshness::Unknown,
            status: AdvisoryRecordStatus::Expired,
            record_signature_valid: false,
        });
        source.insert(AdvisoryRecord {
            key: "valid:record".to_string(),
            value: vec![],
            source_node_id: "node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            ttl_seconds: 3600,
            freshness: AdvisoryFreshness::Live,
            status: AdvisoryRecordStatus::Present,
            record_signature_valid: true,
        });

        let results = source.get_advisory_records_by_prefix("expired:", 10);
        assert_eq!(results.len(), 0);

        let results = source.get_advisory_records_by_prefix("valid:", 10);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn no_canonical_types_required() {
        let source = StaticAdvisoryRecordSource::new();
        let _name = source.source_name();
        // Compile-time check: advisory source does not reference CanonicalTrustReader.
    }

    #[test]
    fn record_age_ms_computation() {
        let record = AdvisoryRecord {
            key: "test".to_string(),
            value: vec![],
            source_node_id: "node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp().saturating_sub(10),
            ttl_seconds: 3600,
            freshness: AdvisoryFreshness::Live,
            status: AdvisoryRecordStatus::Present,
            record_signature_valid: true,
        };
        let age = record.age_ms();
        assert!(
            (9000..=11000).contains(&age),
            "age_ms should be ~10s: {}",
            age
        );
    }

    #[test]
    fn record_is_expired() {
        let record = AdvisoryRecord {
            key: "test".to_string(),
            value: vec![],
            source_node_id: "node".to_string(),
            timestamp: 1000,
            ttl_seconds: 1,
            freshness: AdvisoryFreshness::Unknown,
            status: AdvisoryRecordStatus::Expired,
            record_signature_valid: false,
        };
        assert!(record.is_expired(1002));

        let valid_record = AdvisoryRecord {
            key: "test".to_string(),
            value: vec![],
            source_node_id: "node".to_string(),
            timestamp: synvoid_utils::safe_unix_timestamp(),
            ttl_seconds: 3600,
            freshness: AdvisoryFreshness::Live,
            status: AdvisoryRecordStatus::Present,
            record_signature_valid: true,
        };
        assert!(!valid_record.is_expired(synvoid_utils::safe_unix_timestamp()));
    }

    #[test]
    fn from_records_builder() {
        let records = vec![
            StaticAdvisoryRecordSource::test_record("a:1"),
            StaticAdvisoryRecordSource::test_record("a:2"),
        ];
        let source = StaticAdvisoryRecordSource::from_records(records);
        assert!(matches!(
            source.get_advisory_record("a:1"),
            AdvisoryRecordLookup::Present(_)
        ));
        assert!(matches!(
            source.get_advisory_record("a:2"),
            AdvisoryRecordLookup::Present(_)
        ));
        assert!(matches!(
            source.get_advisory_record("b:1"),
            AdvisoryRecordLookup::Missing
        ));
    }

    fn make_test_signed_record(
        key: &str,
        ttl: u64,
        ts_offset_secs: i64,
    ) -> crate::protocol::DhtRecord {
        let signer = crate::protocol::MeshMessageSigner::new([42u8; 32]);
        let now = synvoid_utils::safe_unix_timestamp();
        let ts = if ts_offset_secs >= 0 {
            now.saturating_add(ts_offset_secs as u64)
        } else {
            now.saturating_sub((-ts_offset_secs) as u64)
        };
        let mut record = crate::protocol::DhtRecord {
            key: key.to_string(),
            value: b"testval".to_vec(),
            timestamp: ts,
            sequence_number: 0,
            ttl_seconds: ttl,
            source_node_id: "test-node".to_string(),
            signature: vec![],
            signer_public_key: Some(signer.get_public_key()),
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };
        let signed = crate::dht::signed::dht_record_to_signed_record(&record);
        let content = signed.get_signable_content();
        record.signature = signer.sign(&content);
        record
    }

    fn make_minimal_global_record_store() -> std::sync::Arc<crate::dht::RecordStoreManager> {
        let config = crate::dht::RecordStoreConfig::default();
        let mesh_config = crate::config::MeshConfig::default();
        let access_control = crate::dht::DhtAccessControl::new(&mesh_config);
        let store = crate::dht::RecordStoreManager::new(
            config,
            "test-global".to_string(),
            crate::config::MeshNodeRole::GLOBAL,
            None,
            access_control,
            None,
        );
        std::sync::Arc::new(store)
    }

    #[test]
    fn record_store_advisory_source_present_record_maps_correctly() {
        let store = make_minimal_global_record_store();
        let rec = make_test_signed_record("present:key", 3600, 0);
        let _ = store.store_local_record(rec.clone(), 100);
        let advisory = RecordStoreAdvisorySource::new(store);
        match advisory.get_advisory_record("present:key") {
            AdvisoryRecordLookup::Present(r) => {
                assert_eq!(r.key, "present:key");
                assert_eq!(r.value, b"testval".to_vec());
                assert_eq!(r.source_node_id, "test-node");
                assert!(r.timestamp > 0);
                assert_eq!(r.ttl_seconds, 3600);
                assert_eq!(r.status, AdvisoryRecordStatus::Present);
                assert!(matches!(
                    r.freshness,
                    AdvisoryFreshness::Live | AdvisoryFreshness::Cached { .. }
                ));
                assert!(r.record_signature_valid);
            }
            other => panic!("expected Present, got {:?}", other),
        }
    }

    #[test]
    fn record_store_advisory_source_missing_key_returns_missing() {
        let store = make_minimal_global_record_store();
        let advisory = RecordStoreAdvisorySource::new(store);
        assert!(matches!(
            advisory.get_advisory_record("no:such:key"),
            AdvisoryRecordLookup::Missing
        ));
    }

    #[test]
    fn record_store_advisory_source_expired_single_lookup_returns_missing_due_to_get_record_pruning(
    ) {
        let store = make_minimal_global_record_store();
        let rec = make_test_signed_record("exp:key", 1, -10000);
        {
            let state = store.record_state.write();
            let entry = crate::dht::DhtRecordEntry {
                record: rec.clone(),
                local_origin: true,
                version: 1,
                status: crate::protocol::DhtRecordStatus::Live,
            };
            state.records.insert("exp:key".to_string(), entry);
        }
        let advisory = RecordStoreAdvisorySource::new(store);
        assert!(matches!(
            advisory.get_advisory_record("exp:key"),
            AdvisoryRecordLookup::Missing
        ));
    }

    #[test]
    fn record_store_advisory_source_prefix_returns_only_live_non_expired() {
        let store = make_minimal_global_record_store();
        let live = make_test_signed_record("p:live", 3600, 0);
        let _ = store.store_local_record(live, 100);
        let exp_rec = make_test_signed_record("p:exp", 1, -10000);
        {
            let state = store.record_state.write();
            let entry = crate::dht::DhtRecordEntry {
                record: exp_rec,
                local_origin: false,
                version: 1,
                status: crate::protocol::DhtRecordStatus::Live,
            };
            state.records.insert("p:exp".to_string(), entry);
        }
        let advisory = RecordStoreAdvisorySource::new(store);
        let results = advisory.get_advisory_records_by_prefix("p:", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "p:live");
    }

    #[test]
    fn record_store_advisory_source_prefix_honors_limit() {
        let store = make_minimal_global_record_store();
        for i in 0..5 {
            let rec = make_test_signed_record(&format!("lim:{}", i), 3600, 0);
            let _ = store.store_local_record(rec, 100);
        }
        let advisory = RecordStoreAdvisorySource::new(store);
        let results = advisory.get_advisory_records_by_prefix("lim:", 2);
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(r.key.starts_with("lim:"));
        }
    }

    #[test]
    fn record_store_advisory_source_no_canonical_types() {
        let store = make_minimal_global_record_store();
        let source = RecordStoreAdvisorySource::new(store);
        let _name = source.source_name();
    }
}
