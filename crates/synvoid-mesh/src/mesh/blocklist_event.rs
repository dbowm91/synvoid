use serde::{Deserialize, Serialize};
use synvoid_core::block_store::{
    BlocklistOperation, BlockProvenanceKind, BlockTargetKind,
};

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
