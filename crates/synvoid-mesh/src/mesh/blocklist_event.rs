use serde::{Deserialize, Serialize};
use synvoid_core::block_store::{BlockProvenanceKind, BlockTargetKind, BlocklistOperation};

/// Wire-format event data for blocklist catchup responses.
/// Mirrors the proto `BlocklistEventData` message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlocklistEventData {
    pub event_id: String,
    pub source_node: String,
    pub timestamp: u64,
    pub operation: u32,
    pub target_kind: u32,
    pub identifier: String,
    pub site_scope: String,
    pub reason: Option<String>,
    pub provenance_kind: u32,
    pub provenance_source: Option<String>,
    pub ttl_secs: Option<u64>,
    pub version: Option<u64>,
    pub source_sequence: Option<u64>,
    pub logical_time: Option<u64>,
}

impl BlocklistEventData {
    pub fn from_event(event: &synvoid_core::block_store::BlocklistEvent) -> Self {
        Self {
            event_id: event.event_id.clone().unwrap_or_default(),
            source_node: event.source_node.clone().unwrap_or_default(),
            timestamp: event.timestamp,
            operation: operation_to_u32(event.operation),
            target_kind: target_kind_to_u32(event.target_kind),
            identifier: event.identifier.clone(),
            site_scope: event.site_scope.clone(),
            reason: event.reason.clone(),
            provenance_kind: provenance_kind_to_u32(event.provenance.kind),
            provenance_source: event.provenance.source.clone(),
            ttl_secs: event.ttl_secs,
            version: event.version,
            source_sequence: event.source_sequence,
            logical_time: event.logical_time,
        }
    }

    pub fn to_event(&self) -> synvoid_core::block_store::BlocklistEvent {
        synvoid_core::block_store::BlocklistEvent {
            operation: operation_from_u32(self.operation),
            target_kind: target_kind_from_u32(self.target_kind),
            identifier: self.identifier.clone(),
            site_scope: self.site_scope.clone(),
            reason: self.reason.clone(),
            provenance: synvoid_core::block_store::BlockProvenance {
                kind: provenance_kind_from_u32(self.provenance_kind),
                source: self.provenance_source.clone(),
            },
            timestamp: self.timestamp,
            source_node: if self.source_node.is_empty() {
                None
            } else {
                Some(self.source_node.clone())
            },
            event_id: if self.event_id.is_empty() {
                None
            } else {
                Some(self.event_id.clone())
            },
            ttl_secs: self.ttl_secs,
            version: self.version,
            source_sequence: self.source_sequence,
            logical_time: self.logical_time,
        }
    }
}

pub fn provenance_kind_to_u32(kind: BlockProvenanceKind) -> u32 {
    match kind {
        BlockProvenanceKind::LegacyUnknown => 0,
        BlockProvenanceKind::LocalWaf => 1,
        BlockProvenanceKind::LocalHoneypot => 2,
        BlockProvenanceKind::LocalAsnTracker => 3,
        BlockProvenanceKind::MeshThreatIntelPolicyGated => 4,
        BlockProvenanceKind::SupervisorSync => 5,
        BlockProvenanceKind::AdminManual => 6,
        BlockProvenanceKind::SupervisorManual => 7,
        BlockProvenanceKind::ProxyHealthProbe => 8,
        BlockProvenanceKind::Test => 9,
    }
}

pub fn provenance_kind_from_u32(val: u32) -> BlockProvenanceKind {
    match val {
        1 => BlockProvenanceKind::LocalWaf,
        2 => BlockProvenanceKind::LocalHoneypot,
        3 => BlockProvenanceKind::LocalAsnTracker,
        4 => BlockProvenanceKind::MeshThreatIntelPolicyGated,
        5 => BlockProvenanceKind::SupervisorSync,
        6 => BlockProvenanceKind::AdminManual,
        7 => BlockProvenanceKind::SupervisorManual,
        8 => BlockProvenanceKind::ProxyHealthProbe,
        9 => BlockProvenanceKind::Test,
        _ => BlockProvenanceKind::LegacyUnknown,
    }
}

pub fn operation_to_u32(op: BlocklistOperation) -> u32 {
    match op {
        BlocklistOperation::Block => 1,
        BlocklistOperation::Unblock => 2,
    }
}

pub fn operation_from_u32(val: u32) -> BlocklistOperation {
    match val {
        1 => BlocklistOperation::Block,
        2 => BlocklistOperation::Unblock,
        _ => BlocklistOperation::Block,
    }
}

pub fn target_kind_to_u32(kind: BlockTargetKind) -> u32 {
    match kind {
        BlockTargetKind::Ip => 1,
        BlockTargetKind::MeshId => 2,
    }
}

pub fn target_kind_from_u32(val: u32) -> BlockTargetKind {
    match val {
        1 => BlockTargetKind::Ip,
        2 => BlockTargetKind::MeshId,
        _ => BlockTargetKind::Ip,
    }
}

/// Wire-format IP block data for snapshot responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotIpBlockData {
    pub ip: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
    pub provenance_kind: u32,
    pub provenance_source: Option<String>,
}

/// Wire-format mesh block data for snapshot responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotMeshBlockData {
    pub mesh_id: String,
    pub reason: String,
    pub blocked_at: u64,
    pub ban_expire_seconds: u64,
    pub site_scope: String,
    pub access_count: u64,
    pub last_access: u64,
    pub provenance_kind: u32,
    pub provenance_source: Option<String>,
}

/// Wire-format target state data for snapshot responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotTargetStateData {
    pub target_kind: u32,
    pub site_scope: String,
    pub identifier: String,
    pub last_operation: u32,
    pub timestamp: u64,
    pub version: Option<u64>,
    pub event_id: Option<String>,
    pub source_node: Option<String>,
    pub provenance_kind: u32,
    pub provenance_source: Option<String>,
    pub recorded_at: u64,
    pub expires_at: Option<u64>,
    pub source_sequence: Option<u64>,
    pub logical_time: Option<u64>,
}

impl SnapshotIpBlockData {
    pub fn from_record(record: &synvoid_core::block_store::BlockRecord) -> Self {
        Self {
            ip: record.identifier.clone(),
            reason: record.reason.clone(),
            blocked_at: record.blocked_at,
            ban_expire_seconds: record.ban_expire_seconds,
            site_scope: record.site_scope.clone(),
            access_count: record.access_count,
            last_access: record.last_access,
            provenance_kind: provenance_kind_to_u32(record.provenance.kind),
            provenance_source: record.provenance.source.clone(),
        }
    }
}

impl SnapshotMeshBlockData {
    pub fn from_record(record: &synvoid_core::block_store::BlockRecord) -> Self {
        Self {
            mesh_id: record.identifier.clone(),
            reason: record.reason.clone(),
            blocked_at: record.blocked_at,
            ban_expire_seconds: record.ban_expire_seconds,
            site_scope: record.site_scope.clone(),
            access_count: record.access_count,
            last_access: record.last_access,
            provenance_kind: provenance_kind_to_u32(record.provenance.kind),
            provenance_source: record.provenance.source.clone(),
        }
    }
}

impl SnapshotTargetStateData {
    pub fn from_record(record: &synvoid_core::block_store::BlocklistTargetStateRecord) -> Self {
        Self {
            target_kind: target_kind_to_u32(record.target_kind),
            site_scope: record.site_scope.clone(),
            identifier: record.identifier.clone(),
            last_operation: operation_to_u32(record.last_operation),
            timestamp: record.timestamp,
            version: record.version,
            event_id: record.event_id.clone(),
            source_node: record.source_node.clone(),
            provenance_kind: provenance_kind_to_u32(record.provenance.kind),
            provenance_source: record.provenance.source.clone(),
            recorded_at: record.recorded_at,
            expires_at: record.expires_at,
            source_sequence: record.source_sequence,
            logical_time: record.logical_time,
        }
    }
}
