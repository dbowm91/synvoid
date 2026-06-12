//! Block store provenance types shared across SynVoid subsystems.
//!
//! These types classify the source of a block entry for auditability.
//! They live in `synvoid-core` to avoid circular dependencies between
//! `synvoid-block-store` and `synvoid-mesh`.

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
