//! Canonical YARA execution boundary (Phase 26, closed by Phase 36).
//!
//! `synvoid-yara` is the single production owner of `yara-x`. It owns only
//! YARA-domain primitives reusable across upload policy, mesh distribution,
//! and the jail execution service:
//!
//! - [`engine`]: `YaraScanner`, rule sources, bounded compile/scan, match DTOs;
//! - [`artifact`]: local-compile binding metadata (no remote deserialization);
//! - [`executor`]: narrow `YaraExecutor` contract separating orchestration
//!   from execution;
//! - [`metrics`]: engine-local counters.
//!
//! Trust model (Phase 36): signed/approved source text is the canonical
//! executable input. Compilation happens locally; wire compiled bytes are
//! opaque metadata and never reach `yara_x::Rules::deserialize` (the API no
//! longer exists in this crate).
//!
//! The crate has no dependency on mesh, upload, HTTP, admin, WAF, or the root
//! crate. Upload policy and mesh distribution consume these contracts; the
//! jail service (`src/sandbox/yara_service.rs`) uses [`engine`] directly.

pub mod artifact;
pub mod engine;
pub mod executor;
pub mod metrics;

pub use artifact::{
    rule_digest, version_binding, CompiledArtifact, COMPILED_FORMAT_VERSION, MAX_COMPILED_BYTES,
    YARA_ENGINE_VERSION,
};
pub use engine::{
    compute_sha256, validate_rules_syntax, verify_content_digest, WindowedScanResult,
    YaraDirectoryConfig, YaraError, YaraMatch, YaraRuleManifest, YaraRuleProvenance,
    YaraRuleSourceType, YaraRulesSource, YaraScanner, DEFAULT_MALWARE_RULES,
    NO_EXCLUDED_CATEGORIES,
};
pub use executor::{InProcessYaraExecutor, YaraExecutor, YaraMatchMetadata};
