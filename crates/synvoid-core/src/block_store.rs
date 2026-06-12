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
