//! Compiled-rule artifact binding (Phase 26 Part C, closed by Phase 36).
//!
//! Trust model (Phase 36): signed/approved YARA **source text** is the
//! canonical executable input for remotely distributed rules. Compilation
//! occurs locally inside the YARA execution boundary (`synvoid-yara`).
//!
//! Mesh distributes signed canonical rule *text* plus digest/version. Wire
//! `compiled_rules` fields are retained for protocol compatibility but
//! production receive paths treat those bytes as opaque/non-executable
//! metadata: they are never passed to `yara_x::Rules::deserialize`,
//! directly or indirectly.
//!
//! This module therefore exposes only local-source helpers and metadata-only
//! binding checks. There is deliberately no public constructor that turns an
//! arbitrary `&[u8]` into executable rules: `from_bytes_with_binding` and
//! `deserialize_verified` were removed in Phase 36 because a
//! caller-supplied checksum is self-consistency, not trust proof.

use crate::engine::{compute_sha256, YaraError};

/// yara-x line that produced the current engine. Bumped when `yara-x` is
/// upgraded; locally compiled blobs carrying a different engine tag are
/// rejected deterministically by [`CompiledArtifact::verify_binding`].
/// Phase 40: `yara-x/1.20` via the temporary manifest-only compat fork
/// (`third-party/yara-x-compat`; exact upstream 1.20.0 sources, wasmtime
/// 47.0.4). 1.15-tagged artifacts reject deterministically through the
/// same binding check (see `old_engine_line_rejected_deterministically`).
pub const YARA_ENGINE_VERSION: &str = "yara-x/1.20";

/// Local serialization envelope version for [`CompiledArtifact`].
/// Increment when the envelope layout/meaning changes; binding checks reject
/// unknown versions deterministically. Phase 36: envelope layout unchanged
/// from 1 (engine-only incompatibility), so this stays at 1.
pub const COMPILED_FORMAT_VERSION: u32 = 1;

/// Maximum compiled-blob bytes accepted by [`CompiledArtifact::verify_binding`].
/// Binding checks never deserialize; this bounds metadata handling only.
pub const MAX_COMPILED_BYTES: usize = 8 * 1024 * 1024;

/// A locally compiled YARA artifact with source/engine binding.
///
/// Produced only by [`CompiledArtifact::compile`] from local source text.
/// There is no remote/deserialized constructor: mesh/remote bytes must never
/// become a `CompiledArtifact`.
#[derive(Debug, Clone)]
pub struct CompiledArtifact {
    /// Raw `yara_x::Rules::serialize` bytes (local compile output only).
    pub bytes: Vec<u8>,
    /// SHA-256 hex of the canonical source text the blob was compiled from.
    pub source_sha256: String,
    /// SHA-256 hex of `bytes`.
    pub compiled_sha256: String,
    /// Engine that produced the blob (see [`YARA_ENGINE_VERSION`]).
    pub engine_version: String,
    /// Envelope version (see [`COMPILED_FORMAT_VERSION`]).
    pub format_version: u32,
}

impl CompiledArtifact {
    /// Compile local source text and bind the result to source + engine version.
    ///
    /// The input is trusted local/canonical source (bundled, operator file,
    /// or mesh-approved text already validated). This never accepts remote
    /// serialized bytes.
    pub fn compile(source: &str) -> Result<Self, YaraError> {
        let rules =
            yara_x::compile(source).map_err(|e| YaraError::CompilationError(e.to_string()))?;
        let bytes = rules
            .serialize()
            .map_err(|e| YaraError::CompilationError(format!("serialize failed: {e}")))?;
        let source_sha256 = compute_sha256(source.as_bytes());
        let compiled_sha256 = compute_sha256(&bytes);
        Ok(Self {
            bytes,
            source_sha256,
            compiled_sha256,
            engine_version: YARA_ENGINE_VERSION.to_string(),
            format_version: COMPILED_FORMAT_VERSION,
        })
    }

    /// Check binding without deserializing (metadata-only).
    ///
    /// Usable by distribution/tooling code that must not execute rules.
    /// Passing this check does NOT authorize execution of the bytes: only
    /// locally compiled artifacts (via [`CompiledArtifact::compile`]) are
    /// executable inputs, and execution happens via source recompile
    /// (`YaraScanner::reload_with_rules`), never via deserialization of
    /// remote bytes.
    pub fn verify_binding(&self) -> Result<(), YaraError> {
        if self.bytes.len() > MAX_COMPILED_BYTES {
            return Err(YaraError::CompilationError(format!(
                "compiled artifact {} bytes exceeds limit {}",
                self.bytes.len(),
                MAX_COMPILED_BYTES
            )));
        }
        if self.engine_version != YARA_ENGINE_VERSION {
            return Err(YaraError::CompilationError(format!(
                "incompatible YARA engine: artifact {}, current {}",
                self.engine_version, YARA_ENGINE_VERSION
            )));
        }
        if self.format_version != COMPILED_FORMAT_VERSION {
            return Err(YaraError::CompilationError(format!(
                "incompatible artifact format: artifact {}, current {}",
                self.format_version, COMPILED_FORMAT_VERSION
            )));
        }
        let actual = compute_sha256(&self.bytes);
        if actual != self.compiled_sha256 {
            return Err(YaraError::CompilationError(format!(
                "compiled digest mismatch: expected {}, got {}",
                self.compiled_sha256, actual
            )));
        }
        Ok(())
    }
}

/// Deterministic rule digest used for version binding across mesh/upload/jail.
///
/// Lowercase hex SHA-256 of the canonical source text.
pub fn rule_digest(source: &str) -> String {
    compute_sha256(source.as_bytes())
}

/// Bind version + digest for distribution records: `version:digest`.
pub fn version_binding(version: &str, source: &str) -> String {
    format!("{}:{}", version, rule_digest(source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(
            rule_digest("rule a { condition: false }"),
            rule_digest("rule a { condition: false }")
        );
        assert_ne!(
            rule_digest("rule a { condition: false }"),
            rule_digest("rule b { condition: false }")
        );
    }

    #[test]
    fn compile_and_verify_binding() {
        let artifact = CompiledArtifact::compile("rule a { condition: false }").unwrap();
        assert_eq!(artifact.engine_version, YARA_ENGINE_VERSION);
        assert_eq!(artifact.format_version, COMPILED_FORMAT_VERSION);
        assert!(artifact.verify_binding().is_ok());
    }

    #[test]
    fn wrong_engine_rejected() {
        let mut artifact = CompiledArtifact::compile("rule a { condition: false }").unwrap();
        artifact.engine_version = "yara-x/0.0".to_string();
        assert!(artifact.verify_binding().is_err());
    }

    #[test]
    fn foreign_engine_line_rejected_deterministically() {
        // Phase 36 Part E: artifacts tagged with a different engine line
        // fail deterministically (binding-only, never deserialized).
        let mut artifact = CompiledArtifact::compile("rule a { condition: false }").unwrap();
        artifact.engine_version = "yara-x/9.99".to_string();
        assert!(artifact.verify_binding().is_err());
    }

    #[test]
    fn old_engine_line_rejected_deterministically() {
        // Phase 40: pre-upgrade 1.15-tagged artifacts reject deterministically
        // under the 1.20 engine tag (binding-only, never deserialized).
        // Local compiled bytes are metadata; execution always recompiles
        // approved source, so no migration path executes old blobs.
        let mut artifact = CompiledArtifact::compile("rule a { condition: false }").unwrap();
        artifact.engine_version = "yara-x/1.15".to_string();
        let err = artifact.verify_binding().expect_err("1.15 tag must reject");
        assert!(err.to_string().contains("incompatible YARA engine"));
    }

    #[test]
    fn tampered_bytes_rejected() {
        let mut artifact = CompiledArtifact::compile("rule a { condition: false }").unwrap();
        artifact.bytes.push(0xFF);
        // Digest no longer matches recorded value.
        assert!(artifact.verify_binding().is_err());
    }
}
