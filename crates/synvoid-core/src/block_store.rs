//! Block store provenance types shared across SynVoid subsystems.
//!
//! These types classify the source of a block entry for auditability.
//! They live in `synvoid-core` to avoid circular dependencies between
//! `synvoid-block-store` and `synvoid-mesh`.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Classifies the source of a block entry for auditability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockProvenanceKind {
    LocalWaf,
    LocalHoneypot,
    LocalAsnTracker,
    MeshThreatIntelPolicyGated,
    SupervisorSync,
    AdminManual,
    SupervisorManual,
    ProxyHealthProbe,
    Test,
    #[default]
    LegacyUnknown,
}

/// Provenance metadata for a block entry, indicating its source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProvenance {
    pub kind: BlockProvenanceKind,
    #[serde(default)]
    pub source: Option<String>,
}

impl Default for BlockProvenance {
    fn default() -> Self {
        Self {
            kind: BlockProvenanceKind::LegacyUnknown,
            source: None,
        }
    }
}

/// Classifies the type of enforcement target in a block record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockTargetKind {
    Ip,
    MeshId,
}

/// A first-class block entry for mesh-ID bans.
///
/// Unlike IP blocks which use `BlockEntry` keyed by `(site_scope, ip)`,
/// mesh-ID blocks are keyed by `(site_scope, mesh_id)` and can coexist
/// concurrently with different mesh IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshBlockEntry {
    pub mesh_id: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
    #[serde(default)]
    pub provenance: BlockProvenance,
}

impl MeshBlockEntry {
    pub fn new(
        mesh_id: String,
        reason: String,
        ban_expire_seconds: u64,
        site_scope: String,
        blocked_at: u64,
        provenance: BlockProvenance,
    ) -> Self {
        Self {
            mesh_id,
            reason,
            blocked_at,
            ban_expire_seconds,
            site_scope,
            access_count: 0,
            last_access: blocked_at,
            provenance,
        }
    }

    pub fn is_permanent(&self) -> bool {
        self.ban_expire_seconds == 0
    }

    pub fn is_expired(&self) -> bool {
        if self.is_permanent() {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.blocked_at + self.ban_expire_seconds
    }

    pub fn key(site_scope: &str, mesh_id: &str) -> String {
        format!("mesh_block:{}:{}", site_scope, mesh_id)
    }
}

/// Unified block record for admin listing, combining IP and mesh-ID blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRecord {
    pub target_kind: BlockTargetKind,
    pub identifier: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
    pub provenance: BlockProvenance,
}

/// Classifies a blocklist operation for event emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlocklistOperation {
    Block,
    Unblock,
}

/// A local, target-aware blocklist event staged for future distributed propagation.
///
/// This type captures the semantic intent of a block or unblock operation,
/// including provenance and targeting metadata. It is currently used for
/// structured local logging only — distributed mesh propagation is future work.
///
/// # Design Notes
///
/// - `identifier` holds the IP address string or mesh ID string, matching `target_kind`.
/// - `event_id` and `source_node` are reserved for future distributed idempotency
///   and traceability; they are `None` in local-only usage.
/// - Unblocks set `reason` to `None` since removal does not carry a reason.
/// - `ttl_secs` is optional; block operations may carry a TTL, unblocks do not.
/// - `version` is an optional monotonic sequence number when available from the source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEvent {
    pub operation: BlocklistOperation,
    pub target_kind: BlockTargetKind,
    pub identifier: String,
    pub site_scope: String,
    pub reason: Option<String>,
    pub provenance: BlockProvenance,
    pub timestamp: u64,
    pub source_node: Option<String>,
    pub event_id: Option<String>,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub version: Option<u64>,
}

impl BlocklistEvent {
    /// Create a block event for an IP target.
    pub fn block_ip(
        ip: &str,
        reason: &str,
        site_scope: &str,
        provenance: BlockProvenance,
        timestamp: u64,
    ) -> Self {
        Self {
            operation: BlocklistOperation::Block,
            target_kind: BlockTargetKind::Ip,
            identifier: ip.to_string(),
            site_scope: site_scope.to_string(),
            reason: Some(reason.to_string()),
            provenance,
            timestamp,
            source_node: None,
            event_id: None,
            ttl_secs: None,
            version: None,
        }
    }

    /// Create a block event for a mesh-ID target.
    pub fn block_mesh_id(
        mesh_id: &str,
        reason: &str,
        site_scope: &str,
        provenance: BlockProvenance,
        timestamp: u64,
    ) -> Self {
        Self {
            operation: BlocklistOperation::Block,
            target_kind: BlockTargetKind::MeshId,
            identifier: mesh_id.to_string(),
            site_scope: site_scope.to_string(),
            reason: Some(reason.to_string()),
            provenance,
            timestamp,
            source_node: None,
            event_id: None,
            ttl_secs: None,
            version: None,
        }
    }

    /// Create an unblock event for an IP target.
    pub fn unblock_ip(
        ip: &str,
        site_scope: &str,
        provenance: BlockProvenance,
        timestamp: u64,
    ) -> Self {
        Self {
            operation: BlocklistOperation::Unblock,
            target_kind: BlockTargetKind::Ip,
            identifier: ip.to_string(),
            site_scope: site_scope.to_string(),
            reason: None,
            provenance,
            timestamp,
            source_node: None,
            event_id: None,
            ttl_secs: None,
            version: None,
        }
    }

    /// Create an unblock event for a mesh-ID target.
    pub fn unblock_mesh_id(
        mesh_id: &str,
        site_scope: &str,
        provenance: BlockProvenance,
        timestamp: u64,
    ) -> Self {
        Self {
            operation: BlocklistOperation::Unblock,
            target_kind: BlockTargetKind::MeshId,
            identifier: mesh_id.to_string(),
            site_scope: site_scope.to_string(),
            reason: None,
            provenance,
            timestamp,
            source_node: None,
            event_id: None,
            ttl_secs: None,
            version: None,
        }
    }

    /// Generate a deterministic event ID from event fields.
    ///
    /// Format: `{source_node}:{timestamp}:{operation}:{target_kind}:{site_scope}:{identifier_hash}`
    pub fn generate_event_id(&self) -> String {
        let source = self.source_node.as_deref().unwrap_or("local");
        let op = match self.operation {
            BlocklistOperation::Block => "block",
            BlocklistOperation::Unblock => "unblock",
        };
        let kind = match self.target_kind {
            BlockTargetKind::Ip => "ip",
            BlockTargetKind::MeshId => "mesh_id",
        };
        let mut hasher = DefaultHasher::new();
        self.identifier.hash(&mut hasher);
        let id_hash = hasher.finish();
        format!(
            "{}:{}:{}:{}:{}:{:016x}",
            source, self.timestamp, op, kind, self.site_scope, id_hash
        )
    }

    /// Set the event ID and return self (builder pattern).
    pub fn with_event_id(mut self, event_id: String) -> Self {
        self.event_id = Some(event_id);
        self
    }

    /// Set the source node and return self (builder pattern).
    pub fn with_source_node(mut self, source_node: String) -> Self {
        self.source_node = Some(source_node);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocklist_event_block_ip() {
        let event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "test",
            "global",
            BlockProvenance::default(),
            12345,
        );
        assert_eq!(event.operation, BlocklistOperation::Block);
        assert_eq!(event.target_kind, BlockTargetKind::Ip);
        assert_eq!(event.identifier, "10.0.0.1");
        assert_eq!(event.site_scope, "global");
        assert_eq!(event.reason, Some("test".to_string()));
        assert_eq!(event.timestamp, 12345);
        assert!(event.source_node.is_none());
        assert!(event.event_id.is_none());
        assert!(event.ttl_secs.is_none());
        assert!(event.version.is_none());
    }

    #[test]
    fn test_blocklist_event_block_mesh_id() {
        let event = BlocklistEvent::block_mesh_id(
            "mesh-1",
            "attack",
            "global",
            BlockProvenance::default(),
            99999,
        );
        assert_eq!(event.operation, BlocklistOperation::Block);
        assert_eq!(event.target_kind, BlockTargetKind::MeshId);
        assert_eq!(event.identifier, "mesh-1");
        assert_eq!(event.reason, Some("attack".to_string()));
        assert!(event.ttl_secs.is_none());
        assert!(event.version.is_none());
    }

    #[test]
    fn test_blocklist_event_unblock_ip() {
        let event =
            BlocklistEvent::unblock_ip("10.0.0.2", "global", BlockProvenance::default(), 55555);
        assert_eq!(event.operation, BlocklistOperation::Unblock);
        assert_eq!(event.target_kind, BlockTargetKind::Ip);
        assert_eq!(event.identifier, "10.0.0.2");
        assert!(event.reason.is_none());
        assert!(event.ttl_secs.is_none());
        assert!(event.version.is_none());
    }

    #[test]
    fn test_blocklist_event_unblock_mesh_id() {
        let event =
            BlocklistEvent::unblock_mesh_id("mesh-2", "global", BlockProvenance::default(), 66666);
        assert_eq!(event.operation, BlocklistOperation::Unblock);
        assert_eq!(event.target_kind, BlockTargetKind::MeshId);
        assert_eq!(event.identifier, "mesh-2");
        assert!(event.reason.is_none());
        assert!(event.ttl_secs.is_none());
        assert!(event.version.is_none());
    }

    #[test]
    fn test_blocklist_event_serialization_roundtrip() {
        let event = BlocklistEvent::block_ip(
            "192.168.1.1",
            "test",
            "global",
            BlockProvenance {
                kind: BlockProvenanceKind::AdminManual,
                source: Some("admin".to_string()),
            },
            42,
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: BlocklistEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.operation, BlocklistOperation::Block);
        assert_eq!(deserialized.identifier, "192.168.1.1");
        assert_eq!(
            deserialized.provenance.kind,
            BlockProvenanceKind::AdminManual
        );
        assert_eq!(deserialized.provenance.source, Some("admin".to_string()));
        assert!(deserialized.ttl_secs.is_none());
        assert!(deserialized.version.is_none());
    }

    #[test]
    fn test_blocklist_event_with_distributed_fields() {
        let mut event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "distributed_test",
            "global",
            BlockProvenance::default(),
            1000,
        );
        event.ttl_secs = Some(3600);
        event.version = Some(5);
        event = event
            .with_event_id("node-a:1000:block:ip:global:abc123".to_string())
            .with_source_node("node-a".to_string());

        assert_eq!(event.ttl_secs, Some(3600));
        assert_eq!(event.version, Some(5));
        assert_eq!(
            event.event_id,
            Some("node-a:1000:block:ip:global:abc123".to_string())
        );
        assert_eq!(event.source_node, Some("node-a".to_string()));
    }

    #[test]
    fn test_blocklist_event_generate_event_id() {
        let event = BlocklistEvent::block_ip(
            "192.168.1.1",
            "test",
            "site-a",
            BlockProvenance::default(),
            42,
        )
        .with_source_node("node-1".to_string());

        let event_id = event.generate_event_id();
        assert!(event_id.starts_with("node-1:42:block:ip:site-a:"));
        assert_eq!(event_id.matches(':').count(), 5);
    }

    #[test]
    fn test_blocklist_event_generate_event_id_local_source() {
        let event = BlocklistEvent::unblock_mesh_id(
            "mesh-abc",
            "global",
            BlockProvenance::default(),
            999,
        );

        let event_id = event.generate_event_id();
        assert!(event_id.starts_with("local:999:unblock:mesh_id:global:"));
    }

    #[test]
    fn test_blocklist_event_ttl_secs() {
        let mut event = BlocklistEvent::block_ip(
            "10.0.0.1",
            "ttl_test",
            "global",
            BlockProvenance::default(),
            100,
        );
        assert!(event.ttl_secs.is_none());
        event.ttl_secs = Some(7200);
        assert_eq!(event.ttl_secs, Some(7200));
    }

    #[test]
    fn test_blocklist_event_version() {
        let mut event = BlocklistEvent::block_mesh_id(
            "mesh-v",
            "version_test",
            "global",
            BlockProvenance::default(),
            200,
        );
        assert!(event.version.is_none());
        event.version = Some(42);
        assert_eq!(event.version, Some(42));
    }

    #[test]
    fn test_blocklist_event_serialization_with_optional_fields() {
        let mut event = BlocklistEvent::block_ip(
            "10.0.0.99",
            "test",
            "global",
            BlockProvenance::default(),
            500,
        );
        event.ttl_secs = Some(1800);
        event.version = Some(3);
        event = event
            .with_event_id("evt-123".to_string())
            .with_source_node("node-x".to_string());

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: BlocklistEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ttl_secs, Some(1800));
        assert_eq!(deserialized.version, Some(3));
        assert_eq!(deserialized.event_id, Some("evt-123".to_string()));
        assert_eq!(deserialized.source_node, Some("node-x".to_string()));
    }

    #[test]
    fn test_blocklist_event_serialization_backward_compat() {
        let json = r#"{
            "operation": "block",
            "target_kind": "ip",
            "identifier": "10.0.0.1",
            "site_scope": "global",
            "reason": "test",
            "provenance": {"kind": "legacy_unknown"},
            "timestamp": 100
        }"#;
        let event: BlocklistEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.operation, BlocklistOperation::Block);
        assert!(event.ttl_secs.is_none());
        assert!(event.version.is_none());
    }
}
