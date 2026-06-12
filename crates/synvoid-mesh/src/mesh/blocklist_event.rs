use synvoid_core::block_store::{BlocklistOperation, BlockProvenanceKind, BlockTargetKind};

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
