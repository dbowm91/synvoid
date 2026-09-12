//! Narrow YARA execution contract (Phase 26 Part B).
//!
//! Orchestration (upload policy, mesh distribution, jail transport) programs
//! against [`YaraExecutor`]; only the execution boundary implements it with
//! `yara-x`. No file paths, command execution, or Wasmtime handles cross this
//! interface.

use crate::engine::{YaraError, YaraMatch};
use async_trait::async_trait;

/// Bounded YARA match metadata returned across the execution boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraMatchMetadata {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub category: String,
    pub severity: String,
    pub description: String,
}

impl From<YaraMatch> for YaraMatchMetadata {
    fn from(m: YaraMatch) -> Self {
        Self {
            rule_name: m.rule_name,
            namespace: m.namespace,
            tags: m.tags,
            category: m.category,
            severity: m.severity,
            description: m.description,
        }
    }
}

/// Narrow executor interface: validate/compile, digest-bound load, bounded
/// scan, unload. Implementations must enforce input/match bounds and must not
/// expose filesystem paths or generic execution.
#[async_trait]
pub trait YaraExecutor: Send + Sync {
    /// Syntax-validate rule text without retaining it. Used by distribution
    /// code (mesh approval) that must not compile in the control-plane
    /// process: the production implementation forwards to the execution
    /// boundary (jail/in-process engine owned by composition).
    fn validate(&self, rules: &str) -> Result<(), YaraError>;

    /// Load (or replace) a rule set bound to `digest_sha256_hex`
    /// (hex SHA-256 of `rules_text`) under `version`.
    fn load(
        &self,
        rules_id: &str,
        digest_sha256_hex: &str,
        rules_text: &str,
        version: Option<String>,
    ) -> Result<(), YaraError>;

    /// Scan bounded bytes with a loaded rule set.
    async fn scan(
        &self,
        rules_id: &str,
        data: &[u8],
        excluded_categories: &[&str],
    ) -> Result<Vec<YaraMatchMetadata>, YaraError>;

    /// Evict a loaded rule set. Missing IDs are not errors for idempotent
    /// unload, or return `NotFound`-style error per impl contract.
    fn unload(&self, rules_id: &str) -> Result<(), YaraError>;

    /// Currently loaded rule-set version, if any.
    fn version(&self, rules_id: &str) -> Option<String>;
}

/// In-process executor used by tests and by single-process deployments.
/// Production network paths prefer the jail implementation (see
/// `src/sandbox/yara_service.rs`, which implements the same DTO surface over
/// `synvoid_ipc::JailClient`).
pub struct InProcessYaraExecutor {
    inner: parking_lot::RwLock<
        std::collections::HashMap<String, std::sync::Arc<crate::engine::YaraScanner>>,
    >,
}

impl InProcessYaraExecutor {
    pub fn new() -> Self {
        Self {
            inner: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for InProcessYaraExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl YaraExecutor for InProcessYaraExecutor {
    fn validate(&self, rules: &str) -> Result<(), YaraError> {
        crate::engine::validate_rules_syntax(rules)
    }

    fn load(
        &self,
        rules_id: &str,
        digest_sha256_hex: &str,
        rules_text: &str,
        version: Option<String>,
    ) -> Result<(), YaraError> {
        if !crate::engine::verify_content_digest(rules_text.as_bytes(), digest_sha256_hex) {
            return Err(YaraError::CompilationError("digest mismatch".to_string()));
        }
        let scanner = crate::engine::YaraScanner::new(crate::engine::YaraRulesSource::Inline(
            rules_text.to_string(),
        ))?;
        if let Some(v) = version {
            scanner.reload_with_rules(rules_text, Some(v))?;
        }
        self.inner
            .write()
            .insert(rules_id.to_string(), std::sync::Arc::new(scanner));
        Ok(())
    }

    async fn scan(
        &self,
        rules_id: &str,
        data: &[u8],
        excluded_categories: &[&str],
    ) -> Result<Vec<YaraMatchMetadata>, YaraError> {
        let scanner = {
            let guard = self.inner.read();
            guard.get(rules_id).cloned().ok_or(YaraError::NoRules)?
        };
        let matches = scanner.scan_bytes(data, excluded_categories).await?;
        Ok(matches.into_iter().map(YaraMatchMetadata::from).collect())
    }

    fn unload(&self, rules_id: &str) -> Result<(), YaraError> {
        self.inner.write().remove(rules_id);
        Ok(())
    }

    fn version(&self, rules_id: &str) -> Option<String> {
        self.inner
            .read()
            .get(rules_id)
            .and_then(|s| s.get_version())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn executor_load_scan_unload_round_trip() {
        let exec = InProcessYaraExecutor::new();
        let rules = "rule detect_aaaa { strings: $s = \"AAAA\" condition: $s }";
        let digest = crate::engine::compute_sha256(rules.as_bytes());
        exec.validate(rules).unwrap();
        exec.load("r1", &digest, rules, Some("v1".into())).unwrap();
        assert_eq!(exec.version("r1").as_deref(), Some("v1"));
        let matches = exec.scan("r1", b"AAAA", &[]).await.unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "detect_aaaa");
        exec.unload("r1").unwrap();
        assert!(exec.scan("r1", b"AAAA", &[]).await.is_err());
    }

    #[test]
    fn executor_rejects_bad_digest_without_compiling() {
        let exec = InProcessYaraExecutor::new();
        let rules = "rule a { condition: false }";
        let err = exec.load("r1", &"0".repeat(64), rules, None).unwrap_err();
        assert!(matches!(err, YaraError::CompilationError(_)));
    }

    #[test]
    fn executor_rejects_invalid_syntax() {
        let exec = InProcessYaraExecutor::new();
        assert!(exec.validate("invalid rule syntax !!!!").is_err());
    }
}
