//! Compiled-rule artifact binding (Phase 26 Part C).
//!
//! Mesh distributes signed canonical rule *text* plus digest/version by
//! default. When a compiled blob is carried alongside (legacy peers, local
//! cache), it must be bound to the source text and to the engine that
//! produced it, and incompatible blobs must be rejected deterministically.
//!
//! The mesh process never deserializes/executes a mesh-provided compiled blob;
//! only the execution boundary (`engine::YaraScanner`, jail service) does, via
//! [`CompiledArtifact::deserialize_verified`].

use crate::engine::{compute_sha256, YaraError};

/// yara-x line that produced the current engine. Bumped when `yara-x` is
/// upgraded; old blobs are rejected by [`CompiledArtifact::deserialize_verified`]
/// when the recorded engine differs.
pub const YARA_ENGINE_VERSION: &str = "yara-x/1.15";

/// Local serialization envelope version for [`CompiledArtifact`].
/// Increment when the envelope layout changes; deserialization rejects
/// unknown versions deterministically.
pub const COMPILED_FORMAT_VERSION: u32 = 1;

/// Maximum compiled-blob bytes accepted by [`CompiledArtifact::deserialize_verified`].
pub const MAX_COMPILED_BYTES: usize = 8 * 1024 * 1024;

/// A compiled YARA artifact with source/engine binding.
#[derive(Debug, Clone)]
pub struct CompiledArtifact {
    /// Raw `yara_x::Rules::serialize` bytes.
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
    /// Compile source text and bind the result to source + engine version.
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

    /// Verify digest binding and engine/format compatibility, then deserialize.
    ///
    /// Never executes the rules; returns the live `yara_x::Rules` for the
    /// caller (execution boundary) to scan with.
    pub fn deserialize_verified(&self) -> Result<yara_x::Rules, YaraError> {
        self.verify_binding()?;
        yara_x::Rules::deserialize(&self.bytes)
            .map_err(|e| YaraError::CompilationError(format!("incompatible serialized rules: {e}")))
    }

    /// Check binding without deserializing (usable by distribution code that
    /// must not execute rules).
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

    /// Build an artifact from already-serialized bytes with explicit binding.
    /// Used when receiving a blob plus out-of-band source digest/version.
    pub fn from_bytes_with_binding(
        bytes: Vec<u8>,
        source_sha256: String,
        engine_version: String,
        format_version: u32,
    ) -> Result<Self, YaraError> {
        let compiled_sha256 = compute_sha256(&bytes);
        let artifact = Self {
            bytes,
            source_sha256,
            compiled_sha256,
            engine_version,
            format_version,
        };
        artifact.verify_binding()?;
        Ok(artifact)
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
    fn compile_and_verify_round_trip() {
        let artifact = CompiledArtifact::compile("rule a { condition: false }").unwrap();
        assert_eq!(artifact.engine_version, YARA_ENGINE_VERSION);
        assert_eq!(artifact.format_version, COMPILED_FORMAT_VERSION);
        assert!(artifact.verify_binding().is_ok());
        assert!(artifact.deserialize_verified().is_ok());
    }

    #[test]
    fn wrong_engine_rejected() {
        let mut artifact = CompiledArtifact::compile("rule a { condition: false }").unwrap();
        artifact.engine_version = "yara-x/0.0".to_string();
        assert!(artifact.verify_binding().is_err());
        assert!(artifact.deserialize_verified().is_err());
    }

    #[test]
    fn tampered_bytes_rejected() {
        let mut artifact = CompiledArtifact::compile("rule a { condition: false }").unwrap();
        artifact.bytes.push(0xFF);
        // Digest no longer matches recorded value.
        assert!(artifact.verify_binding().is_err());
    }

    #[test]
    fn garbage_bytes_rejected_deterministically() {
        let artifact = CompiledArtifact::from_bytes_with_binding(
            b"not-valid-compiled-rules".to_vec(),
            rule_digest("rule a { condition: false }"),
            YARA_ENGINE_VERSION.to_string(),
            COMPILED_FORMAT_VERSION,
        )
        .unwrap();
        // Binding passes (digest matches bytes), but yara-x deserialization fails.
        assert!(artifact.deserialize_verified().is_err());
    }
}
