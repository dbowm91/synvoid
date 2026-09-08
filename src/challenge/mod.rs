//! Compatibility facade for `synvoid-challenge`.
//!
//! Canonical challenge orchestration (`ChallengeManager`, `ChallengeConfig`,
//! mesh-PoW, PoW/CSS/honeypot primitives) lives in the `synvoid-challenge`
//! crate. New code should import `synvoid_challenge` directly; this root path
//! remains for transitional API compatibility.
//! See `architecture/root_module_ledger.md`.

pub use synvoid_challenge::css::{
    AssetRequestResult, CssAssetAction, CssChallengeData, CssManager, CssVerificationResult,
};
pub use synvoid_challenge::honeypot::{HoneypotEntry, HoneypotTracker, HONEYPOT_PREFIX};
pub use synvoid_challenge::manager::{ChallengeConfig, ChallengeManager};
pub use synvoid_challenge::manager_pow::{PowChallenge, PowManager, PowResult};
pub use synvoid_challenge::mesh_pow::{
    MeshAuditResult, MeshPowChallenge, MeshPowConfig, MeshPowManager, MeshPowResult,
    MeshPowSolution,
};
pub use synvoid_challenge::pow::{has_leading_zeros, has_leading_zeros_ct, solve_pow_sync};
pub use synvoid_challenge::types::*;
