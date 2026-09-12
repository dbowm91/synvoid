//! Upload YARA policy facade (Phase 26).
//!
//! Generic engine, artifact binding, and executor contracts live in
//! `synvoid-yara` (the single production owner of `yara-x`). This module
//! re-exports those contracts for stability and adds only upload policy:
//! `YaraMatch` → `MalwareMatch` mapping and upload-facing scanner factories
//! that keep archive depth/size policy in upload, not in the engine.

pub use synvoid_yara::{
    compute_sha256, validate_rules_syntax, verify_content_digest, WindowedScanResult,
    YaraDirectoryConfig, YaraError, YaraMatch, YaraRuleManifest, YaraRuleProvenance,
    YaraRuleSourceType, YaraRulesSource, YaraScanner, DEFAULT_MALWARE_RULES,
    NO_EXCLUDED_CATEGORIES,
};

/// Map a generic engine match to the upload malware-match type.
///
/// Lives here (not in `synvoid-yara`) because `MalwareMatch`/
/// `MatchSource`/`MatchConfidence` are upload policy types.
pub fn yara_match_to_malware_match(m: &YaraMatch) -> crate::MalwareMatch {
    let mut meta = std::collections::HashMap::new();
    meta.insert("severity".to_string(), m.severity.clone());
    meta.insert("category".to_string(), m.category.clone());
    meta.insert("description".to_string(), m.description.clone());
    meta.insert("yara_rule".to_string(), m.rule_name.clone());

    crate::MalwareMatch {
        rule_name: m.rule_name.clone(),
        namespace: m.namespace.clone(),
        tags: m.tags.clone(),
        meta,
        source: crate::MatchSource::Yara,
        confidence: crate::MatchConfidence::High,
    }
}

/// Upload-facing scanner factory.
///
/// `archive_max_depth`/`archive_max_size` are upload archive-inspection policy
/// and are intentionally *not* forwarded to the engine (Phase 26: the engine
/// owns only YARA-generic bounds). They are accepted for call-site stability
/// and ignored.
pub fn create_yara_scanner(
    yara_rules_dir: Option<std::path::PathBuf>,
    scan_with_yara: bool,
    _archive_max_depth: u32,
    _archive_max_size: u64,
) -> Result<Option<YaraScanner>, YaraError> {
    YaraScanner::with_scan_executor(yara_rules_dir, scan_with_yara, 4, 64, 1000)
}

/// Upload-facing factory with explicit executor tuning.
///
/// Archive policy args are accepted for stability and ignored (see
/// [`create_yara_scanner`]).
pub fn create_yara_scanner_with_executor(
    yara_rules_dir: Option<std::path::PathBuf>,
    scan_with_yara: bool,
    _archive_max_depth: u32,
    _archive_max_size: u64,
    max_concurrent_scans: u32,
    max_queued_scans: u32,
    queue_timeout_ms: u64,
) -> Result<Option<YaraScanner>, YaraError> {
    YaraScanner::with_scan_executor(
        yara_rules_dir,
        scan_with_yara,
        max_concurrent_scans,
        max_queued_scans,
        queue_timeout_ms,
    )
}
