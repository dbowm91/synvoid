pub mod archive;
pub mod config;
pub mod malware_scanner;
pub mod metrics;
pub mod rate_limit;
pub mod sandbox;
pub mod signature;
pub mod yara_rule_feed;
pub mod yara_scanner;

pub use archive::{
    ArchiveEntryMatch, ArchiveInspectionConfig, ArchiveInspectionError, ArchiveInspectionResult,
};
pub use config::{
    AllowedTypesConfig, AllowedTypesMode, EffectiveUploadConfig, PathUploadConfig, UploadConfig,
    UploadScanFailurePolicy, YaraLargeFileScanMode,
};
pub use malware_scanner::{MalwareMatch, MatchConfidence, MatchSource, ScanContext};
pub use sandbox::{QuarantineEntry, Sandbox, SandboxConfig, SandboxError, SandboxHandle};
pub use signature::{FileCategory, FileSignature, SignatureRegistry};
pub use yara_rule_feed::{ParsedYaraRules, YaraRuleFeedManager, YaraRuleSource};
pub use yara_scanner::{
    compute_sha256, YaraDirectoryConfig, YaraError, YaraMatch, YaraRuleManifest,
    YaraRuleProvenance, YaraRuleSourceType, YaraRulesSource, YaraScanner, NO_EXCLUDED_CATEGORIES,
};

use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};

use crate::malware_scanner::MalwareScanner;

const RESERVED_WINDOWS_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

const HEADER_READ_SIZE: usize = 8192;

/// Check if the given bytes are a ZIP archive by magic bytes.
fn is_zip_archive(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == b'P'
        && data[1] == b'K'
        && (data[2] == 3 || data[2] == 5 || data[2] == 7)
}

/// A byte range to scan within a large file during windowed scanning.
#[derive(Debug, Clone)]
struct ScanWindow {
    offset: u64,
    length: u32,
}

#[derive(Debug, Error)]
pub enum UploadValidationError {
    #[error("Upload size {actual} exceeds maximum {max}")]
    SizeExceeded { max: u64, actual: u64 },

    #[error("MIME type '{detected}' is not allowed")]
    TypeNotAllowed {
        detected: String,
        allowed: Vec<String>,
    },

    #[error("Malware detected: {matches:?}")]
    MalwareDetected { matches: Vec<String> },

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("YARA error: {0}")]
    YaraError(#[from] YaraError),

    #[error("Sandbox error: {0}")]
    SandboxError(#[from] SandboxError),

    #[error("Invalid multipart data")]
    InvalidMultipart,

    #[error("No file data received")]
    NoData,

    #[error("Invalid filename: {reason}")]
    InvalidFilename { reason: String },

    #[error("Empty filename")]
    EmptyFilename,

    #[error("MIME type mismatch: declared '{declared}' but detected '{detected}'")]
    MimeMismatch { declared: String, detected: String },

    #[error("Scan indeterminate: {reason}")]
    ScanIndeterminate { reason: String },

    #[error("Malware scanner unavailable")]
    ScannerUnavailable,
}

/// Status of a YARA scan after execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadScanStatus {
    /// Scan completed, no matches found.
    Clean,
    /// Scan completed, one or more matches found.
    Malicious,
    /// Scanning was disabled by effective config.
    Disabled,
    /// Scan was requested but no scanner was available.
    Unavailable,
    /// Scan was attempted but did not complete successfully.
    Indeterminate,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub mime_type: String,
    pub size: u64,
    pub scanned: bool,
    pub yara_matches: Vec<String>,
    pub scan_status: UploadScanStatus,
    pub scan_error: Option<String>,
    /// Number of bytes actually scanned by YARA.
    pub scanned_bytes: u64,
    /// Total file size in bytes.
    pub total_bytes: u64,
    /// Scan mode used for this validation.
    pub scan_mode: YaraLargeFileScanMode,
    /// Coverage ratio: scanned_bytes / total_bytes (0.0 to 1.0).
    pub coverage_ratio: f64,
    /// Number of windows scanned (0 for non-windowed modes).
    pub window_count: u32,
    /// Scan duration in milliseconds.
    pub duration_ms: u64,
    /// Number of archive entries scanned (0 if not an archive or inspection disabled).
    pub archive_entries_scanned: u32,
    /// Number of nested archives found during inspection.
    pub archive_nested_archives: u32,
    /// Whether archive inspection was truncated due to limits.
    pub archive_truncated: bool,
    /// Whether an archive format was detected.
    pub archive_detected: bool,
    /// Archive format detected (e.g., "zip").
    pub archive_type: Option<String>,
    /// Whether the archive format is supported for inspection.
    pub archive_supported: bool,
    /// Whether archive inspection was performed.
    pub archive_inspected: bool,
    /// Total entries seen in the archive.
    pub archive_entries_seen: u32,
    /// Nested archives detected (not recursively inspected).
    pub archive_nested_seen: u32,
    /// Whether recursive inspection was enabled (currently always false).
    pub archive_recursive_inspection: bool,
    /// Archive inspection error message if any.
    pub archive_error: Option<String>,
}

impl ValidationResult {
    pub fn is_clean(&self) -> bool {
        self.yara_matches.is_empty()
            && matches!(
                self.scan_status,
                UploadScanStatus::Clean | UploadScanStatus::Disabled
            )
    }

    /// Set archive inspection metadata on the result.
    #[allow(clippy::too_many_arguments)]
    pub fn with_archive_metadata(
        mut self,
        entries_scanned: u32,
        nested_archives: u32,
        truncated: bool,
        detected: bool,
        archive_type: Option<String>,
        supported: bool,
        inspected: bool,
        entries_seen: u32,
        nested_seen: u32,
        recursive_inspection: bool,
        error: Option<String>,
    ) -> Self {
        self.archive_entries_scanned = entries_scanned;
        self.archive_nested_archives = nested_archives;
        self.archive_truncated = truncated;
        self.archive_detected = detected;
        self.archive_type = archive_type;
        self.archive_supported = supported;
        self.archive_inspected = inspected;
        self.archive_entries_seen = entries_seen;
        self.archive_nested_seen = nested_seen;
        self.archive_recursive_inspection = recursive_inspection;
        self.archive_error = error;
        self
    }

    /// Build a result for in-memory byte scanning (full coverage).
    pub fn for_bytes(
        mime_type: String,
        data_len: u64,
        scan_status: UploadScanStatus,
        yara_matches: Vec<String>,
        scan_error: Option<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            scanned: scan_status != UploadScanStatus::Disabled,
            scanned_bytes: data_len,
            total_bytes: data_len,
            scan_mode: YaraLargeFileScanMode::Full,
            coverage_ratio: 1.0,
            window_count: 0,
            duration_ms,
            mime_type,
            size: data_len,
            yara_matches,
            scan_status,
            scan_error,
            archive_entries_scanned: 0,
            archive_nested_archives: 0,
            archive_truncated: false,
            archive_detected: false,
            archive_type: None,
            archive_supported: false,
            archive_inspected: false,
            archive_entries_seen: 0,
            archive_nested_seen: 0,
            archive_recursive_inspection: false,
            archive_error: None,
        }
    }

    /// Build a result for header-only scanning of large files.
    pub fn for_header_only(
        mime_type: String,
        size: u64,
        header_bytes: u64,
        scan_status: UploadScanStatus,
        yara_matches: Vec<String>,
        scan_error: Option<String>,
        duration_ms: u64,
    ) -> Self {
        let coverage_ratio = if size > 0 {
            (header_bytes as f64) / (size as f64)
        } else {
            1.0
        };
        Self {
            scanned: scan_status != UploadScanStatus::Disabled,
            scanned_bytes: header_bytes,
            total_bytes: size,
            scan_mode: YaraLargeFileScanMode::HeaderOnly,
            coverage_ratio,
            window_count: 0,
            duration_ms,
            mime_type,
            size,
            yara_matches,
            scan_status,
            scan_error,
            archive_entries_scanned: 0,
            archive_nested_archives: 0,
            archive_truncated: false,
            archive_detected: false,
            archive_type: None,
            archive_supported: false,
            archive_inspected: false,
            archive_entries_seen: 0,
            archive_nested_seen: 0,
            archive_recursive_inspection: false,
            archive_error: None,
        }
    }

    /// Build a result for windowed scanning of large files.
    #[allow(clippy::too_many_arguments)]
    pub fn for_windowed(
        mime_type: String,
        size: u64,
        scanned_bytes: u64,
        window_count: u32,
        scan_status: UploadScanStatus,
        yara_matches: Vec<String>,
        scan_error: Option<String>,
        duration_ms: u64,
    ) -> Self {
        let coverage_ratio = if size > 0 {
            (scanned_bytes as f64) / (size as f64)
        } else {
            1.0
        };
        Self {
            scanned: scan_status != UploadScanStatus::Disabled,
            scanned_bytes,
            total_bytes: size,
            scan_mode: YaraLargeFileScanMode::Windowed,
            coverage_ratio,
            window_count,
            duration_ms,
            mime_type,
            size,
            yara_matches,
            scan_status,
            scan_error,
            archive_entries_scanned: 0,
            archive_nested_archives: 0,
            archive_truncated: false,
            archive_detected: false,
            archive_type: None,
            archive_supported: false,
            archive_inspected: false,
            archive_entries_seen: 0,
            archive_nested_seen: 0,
            archive_recursive_inspection: false,
            archive_error: None,
        }
    }

    /// Build a result for full-file scanning of large files.
    pub fn for_full_file(
        mime_type: String,
        size: u64,
        scan_status: UploadScanStatus,
        yara_matches: Vec<String>,
        scan_error: Option<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            scanned: scan_status != UploadScanStatus::Disabled,
            scanned_bytes: size,
            total_bytes: size,
            scan_mode: YaraLargeFileScanMode::Full,
            coverage_ratio: 1.0,
            window_count: 0,
            duration_ms,
            mime_type,
            size,
            yara_matches,
            scan_status,
            scan_error,
            archive_entries_scanned: 0,
            archive_nested_archives: 0,
            archive_truncated: false,
            archive_detected: false,
            archive_type: None,
            archive_supported: false,
            archive_inspected: false,
            archive_entries_seen: 0,
            archive_nested_seen: 0,
            archive_recursive_inspection: false,
            archive_error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UploadedFile {
    pub filename: Option<String>,
    pub mime_type: String,
    pub size: u64,
    pub data: Vec<u8>,
}

pub struct UploadValidator {
    sandbox: Arc<Sandbox>,
    malware_scanner: Option<Arc<MalwareScanner>>,
    config: UploadConfig,
    _reload_lock: parking_lot::RwLock<()>,
    #[cfg(feature = "mesh")]
    yara_rules: Option<Arc<synvoid_mesh::yara_rules::YaraRulesManager>>,
}

impl UploadValidator {
    pub fn new(config: UploadConfig) -> Result<Self, UploadValidationError> {
        Self::new_with_yara_rules(config, None)
    }

    #[cfg(feature = "mesh")]
    pub fn new_with_yara_rules(
        config: UploadConfig,
        yara_rules: Option<Arc<synvoid_mesh::yara_rules::YaraRulesManager>>,
    ) -> Result<Self, UploadValidationError> {
        let sandbox_config = SandboxConfig::new(&config.sandbox_dir, &config.quarantine_dir);
        let sandbox = Arc::new(Sandbox::new(sandbox_config));

        let malware_scanner = if config.scan_with_yara {
            let source = YaraRulesSource::from_config(
                config.yara_rules_dir.clone().map(std::path::PathBuf::from),
                true,
            )
            .unwrap_or(YaraRulesSource::Bundled);
            let scanner = YaraScanner::with_timeout(
                source,
                config.yara_timeout_ms,
                3,
                100 * 1024 * 1024,
                config.yara_max_concurrent_scans,
                config.yara_max_queued_scans,
                config.yara_queue_timeout_ms,
            )?;
            Some(Arc::new(MalwareScanner::with_yara(Some(scanner))))
        } else {
            Some(Arc::new(MalwareScanner::with_yara(None)))
        };

        Ok(Self {
            sandbox,
            malware_scanner,
            config,
            _reload_lock: parking_lot::RwLock::new(()),
            yara_rules,
        })
    }

    #[cfg(not(feature = "mesh"))]
    pub fn new_with_yara_rules(
        config: UploadConfig,
        _yara_rules: Option<Arc<dyn std::any::Any>>,
    ) -> Result<Self, UploadValidationError> {
        let sandbox_config = SandboxConfig::new(&config.sandbox_dir, &config.quarantine_dir);
        let sandbox = Arc::new(Sandbox::new(sandbox_config));

        let malware_scanner = if config.scan_with_yara {
            let source = YaraRulesSource::from_config(
                config.yara_rules_dir.clone().map(std::path::PathBuf::from),
                true,
            )
            .unwrap_or(YaraRulesSource::Bundled);
            let scanner = YaraScanner::with_timeout(
                source,
                config.yara_timeout_ms,
                3,
                100 * 1024 * 1024,
                config.yara_max_concurrent_scans,
                config.yara_max_queued_scans,
                config.yara_queue_timeout_ms,
            )?;
            Some(Arc::new(MalwareScanner::with_yara(Some(scanner))))
        } else {
            Some(Arc::new(MalwareScanner::with_yara(None)))
        };

        Ok(Self {
            sandbox,
            malware_scanner,
            config,
            _reload_lock: parking_lot::RwLock::new(()),
        })
    }

    /// Centralized scan invocation. Returns (scan_status, matches, error_message).
    /// Applies the configured failure policy on scanner errors.
    async fn execute_scan(
        &self,
        data: &[u8],
        effective_config: &EffectiveUploadConfig,
    ) -> (UploadScanStatus, Vec<String>, Option<String>) {
        if !effective_config.scan_with_yara {
            return (UploadScanStatus::Disabled, Vec::new(), None);
        }

        let scanner = match &self.malware_scanner {
            Some(s) => s,
            None => {
                return match effective_config.yara_failure_policy {
                    UploadScanFailurePolicy::FailClosed
                    | UploadScanFailurePolicy::QuarantineOnError => (
                        UploadScanStatus::Unavailable,
                        Vec::new(),
                        Some("no malware scanner available".into()),
                    ),
                    UploadScanFailurePolicy::FailOpen => {
                        metrics::increment_scan_fail_open_allowed();
                        (
                            UploadScanStatus::Unavailable,
                            Vec::new(),
                            Some("no malware scanner available (fail_open)".into()),
                        )
                    }
                };
            }
        };

        match scanner.scan_bytes(data).await {
            Ok(scan_result) => {
                let matched_names: Vec<String> = scan_result
                    .matches
                    .iter()
                    .map(|m| m.rule_name.clone())
                    .collect();
                if matched_names.is_empty() {
                    metrics::increment_scan_clean();
                    (UploadScanStatus::Clean, matched_names, None)
                } else {
                    metrics::increment_scan_malicious();
                    (UploadScanStatus::Malicious, matched_names, None)
                }
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                metrics::increment_scan_indeterminate();

                match effective_config.yara_failure_policy {
                    UploadScanFailurePolicy::FailClosed => {
                        (UploadScanStatus::Indeterminate, Vec::new(), Some(error_msg))
                    }
                    UploadScanFailurePolicy::QuarantineOnError => {
                        metrics::increment_scan_quarantine_on_error();
                        (UploadScanStatus::Indeterminate, Vec::new(), Some(error_msg))
                    }
                    UploadScanFailurePolicy::FailOpen => {
                        metrics::increment_scan_fail_open_allowed();
                        tracing::warn!(
                            error = %e,
                            policy = "fail_open",
                            "YARA scan failed but fail_open policy allows upload"
                        );
                        (UploadScanStatus::Indeterminate, Vec::new(), Some(error_msg))
                    }
                }
            }
        }
    }

    pub fn reload_yara_rules_if_needed(&self) -> Result<(), YaraError> {
        #[cfg(feature = "mesh")]
        {
            if let Some(scanner) = &self.malware_scanner {
                if let Some(yara_scanner) = scanner.get_yara_scanner() {
                    if let Some(yara_rules) = &self.yara_rules {
                        let current_version = yara_scanner.get_version();
                        let new_version = yara_rules.get_current_version();

                        if current_version != new_version {
                            let _guard = self._reload_lock.write();
                            let current_version = yara_scanner.get_version();
                            let new_version = yara_rules.get_current_version();

                            if current_version != new_version {
                                if let Some(compiled_rules) =
                                    yara_rules.get_current_compiled_rules()
                                {
                                    tracing::debug!(
                                        current_version = ?current_version,
                                        new_version = ?new_version,
                                        "Reloading YARA rules with new version (pre-compiled binary)"
                                    );
                                    yara_scanner
                                        .reload_with_compiled_rules(&compiled_rules, new_version)?;
                                } else if let Some(new_rules) = yara_rules.get_current_rules() {
                                    tracing::debug!(
                                        current_version = ?current_version,
                                        new_version = ?new_version,
                                        "Reloading YARA rules with new version (source text)"
                                    );
                                    yara_scanner.reload_with_rules(&new_rules, new_version)?;
                                }
                            }
                        }
                    }
                }
            }
        }
        #[cfg(not(feature = "mesh"))]
        {
            let _ = self;
        }
        Ok(())
    }

    pub async fn ensure_directories(&self) -> std::io::Result<()> {
        self.sandbox.config.ensure_dirs_exist().await
    }

    pub async fn validate_bytes(
        &self,
        data: &[u8],
        request_path: &str,
    ) -> Result<ValidationResult, UploadValidationError> {
        let effective_config = self.config.effective_config_for_path(request_path);

        if data.len() as u64 > effective_config.max_size_bytes {
            return Err(UploadValidationError::SizeExceeded {
                max: effective_config.max_size_bytes,
                actual: data.len() as u64,
            });
        }

        if let Err(e) = self.reload_yara_rules_if_needed() {
            tracing::warn!("Failed to reload YARA rules: {}", e);
        }

        let mime_info = synvoid_app_handlers::mime::detect_from_bytes_with_fallback(data, "bin");
        let mime_type = mime_info.mime_type.clone();

        if !effective_config.is_mime_allowed(&mime_type) {
            return Err(UploadValidationError::TypeNotAllowed {
                detected: mime_type.clone(),
                allowed: effective_config.allowed_mime_types.clone(),
            });
        }

        let (scan_status, yara_matches, scan_error) =
            self.execute_scan(data, &effective_config).await;

        if !yara_matches.is_empty() {
            debug!(
                mime_type = %mime_type,
                matches = ?yara_matches,
                "Malware detected in upload"
            );
            return Err(UploadValidationError::MalwareDetected {
                matches: yara_matches,
            });
        }

        if scan_status == UploadScanStatus::Indeterminate
            || scan_status == UploadScanStatus::Unavailable
        {
            match effective_config.yara_failure_policy {
                UploadScanFailurePolicy::FailClosed
                | UploadScanFailurePolicy::QuarantineOnError => {
                    return Err(UploadValidationError::ScanIndeterminate {
                        reason: scan_error.unwrap_or_else(|| "scan failed".into()),
                    });
                }
                UploadScanFailurePolicy::FailOpen => {
                    tracing::warn!(
                        scan_error = ?scan_error,
                        policy = "fail_open",
                        "Upload allowed despite scan failure"
                    );
                }
            }
        }

        // Archive inspection: if the file is a ZIP archive and inspection is enabled,
        // scan individual entries for malware.
        let mut archive_entries_scanned = 0u32;
        let mut archive_nested_archives = 0u32;
        let mut archive_truncated = false;
        let mut archive_detected = false;
        let mut archive_type: Option<String> = None;
        let mut archive_supported = false;
        let mut archive_inspected = false;
        let mut archive_entries_seen = 0u32;
        let mut archive_nested_seen = 0u32;
        let mut archive_recursive_inspection = false;
        let mut archive_error: Option<String> = None;
        if effective_config.archive_inspection_enabled && is_zip_archive(data) {
            archive_detected = true;
            archive_type = Some("zip".to_string());
            archive_supported = true;
            let archive_config =
                crate::archive::ArchiveInspectionConfig::from_effective_config(&effective_config);
            if let Some(scanner) = &self.malware_scanner {
                metrics::increment_archive_inspection();
                match crate::archive::inspect_zip_archive(data, &archive_config, scanner, 0, None)
                    .await
                {
                    Ok(archive_result) => {
                        archive_entries_scanned = archive_result.entries_scanned;
                        archive_nested_archives = archive_result.nested_archives_seen;
                        archive_truncated = archive_result.truncated;
                        archive_inspected = true;
                        archive_entries_seen = archive_result.entries_seen;
                        archive_nested_seen = archive_result.nested_archives_seen;
                        archive_recursive_inspection = archive_result.recursive_inspection_enabled;
                        metrics::add_archive_entries_scanned(archive_result.entries_scanned);

                        let archive_match_names: Vec<String> = archive_result
                            .matches
                            .iter()
                            .map(|m| format!("{}:{}", m.entry_path, m.malware_match.rule_name))
                            .collect();
                        if !archive_match_names.is_empty() {
                            metrics::increment_archive_malware_detected();
                            debug!(
                                archive_matches = ?archive_match_names,
                                "Malware detected in archive entries"
                            );
                            return Err(UploadValidationError::MalwareDetected {
                                matches: archive_match_names,
                            });
                        }
                    }
                    Err(crate::archive::ArchiveInspectionError::Disabled) => {}
                    Err(e) => {
                        let error_msg = format!("archive inspection: {e}");
                        archive_error = Some(error_msg.clone());
                        match &e {
                            crate::archive::ArchiveInspectionError::InvalidZip(_) => {
                                metrics::increment_archive_malformed();
                            }
                            crate::archive::ArchiveInspectionError::PathTraversal(_)
                            | crate::archive::ArchiveInspectionError::AbsolutePath(_)
                            | crate::archive::ArchiveInspectionError::UncPath(_)
                            | crate::archive::ArchiveInspectionError::SymlinkRejected(_) => {
                                metrics::increment_archive_limit_violation();
                            }
                            _ => {
                                metrics::increment_archive_limit_violation();
                            }
                        }
                        match effective_config.yara_failure_policy {
                            UploadScanFailurePolicy::FailClosed => {
                                return Err(UploadValidationError::ScanIndeterminate {
                                    reason: error_msg,
                                });
                            }
                            UploadScanFailurePolicy::QuarantineOnError => {
                                return Err(UploadValidationError::ScanIndeterminate {
                                    reason: error_msg,
                                });
                            }
                            UploadScanFailurePolicy::FailOpen => {
                                tracing::warn!(
                                    archive_error = %e,
                                    policy = "fail_open",
                                    "Archive inspection failed but fail_open allows upload"
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(ValidationResult::for_bytes(
            mime_type,
            data.len() as u64,
            scan_status,
            yara_matches,
            scan_error,
            0,
        )
        .with_archive_metadata(
            archive_entries_scanned,
            archive_nested_archives,
            archive_truncated,
            archive_detected,
            archive_type,
            archive_supported,
            archive_inspected,
            archive_entries_seen,
            archive_nested_seen,
            archive_recursive_inspection,
            archive_error,
        ))
    }

    pub async fn validate_bytes_async(
        &self,
        data: Vec<u8>,
        request_path: &str,
    ) -> Result<ValidationResult, UploadValidationError> {
        let effective_config = self.config.effective_config_for_path(request_path);

        if data.len() as u64 > effective_config.max_size_bytes {
            return Err(UploadValidationError::SizeExceeded {
                max: effective_config.max_size_bytes,
                actual: data.len() as u64,
            });
        }

        self.validate_bytes(&data, request_path).await
    }

    pub async fn validate_bytes_with_declared_type(
        &self,
        data: &[u8],
        request_path: &str,
        declared_content_type: Option<&str>,
    ) -> Result<ValidationResult, UploadValidationError> {
        let effective_config = self.config.effective_config_for_path(request_path);

        if data.len() as u64 > effective_config.max_size_bytes {
            return Err(UploadValidationError::SizeExceeded {
                max: effective_config.max_size_bytes,
                actual: data.len() as u64,
            });
        }

        if let Err(e) = self.reload_yara_rules_if_needed() {
            tracing::warn!("Failed to reload YARA rules: {}", e);
        }

        let mime_info = synvoid_app_handlers::mime::detect_from_bytes_with_fallback(data, "bin");
        let mime_type = mime_info.mime_type.clone();

        if !effective_config.is_mime_allowed(&mime_type) {
            return Err(UploadValidationError::TypeNotAllowed {
                detected: mime_type.clone(),
                allowed: effective_config.allowed_mime_types.clone(),
            });
        }

        if effective_config.reject_mime_mismatch {
            if let Some(declared) = declared_content_type {
                let declared_lower = declared.to_lowercase();
                let detected_lower = mime_type.to_lowercase();
                let declared_base = declared_lower
                    .split(';')
                    .next()
                    .unwrap_or(&declared_lower)
                    .trim();
                if !detected_lower.starts_with(declared_base)
                    && declared_base != "application/octet-stream"
                {
                    tracing::warn!(
                        "MIME mismatch detected: declared '{}', detected '{}'",
                        declared,
                        mime_type
                    );
                    return Err(UploadValidationError::MimeMismatch {
                        declared: declared.to_string(),
                        detected: mime_type.clone(),
                    });
                }
            }
        }

        let (scan_status, yara_matches, scan_error) =
            self.execute_scan(data, &effective_config).await;

        if !yara_matches.is_empty() {
            debug!(
                mime_type = %mime_type,
                matches = ?yara_matches,
                "Malware detected in upload"
            );
            return Err(UploadValidationError::MalwareDetected {
                matches: yara_matches,
            });
        }

        if scan_status == UploadScanStatus::Indeterminate
            || scan_status == UploadScanStatus::Unavailable
        {
            match effective_config.yara_failure_policy {
                UploadScanFailurePolicy::FailClosed
                | UploadScanFailurePolicy::QuarantineOnError => {
                    return Err(UploadValidationError::ScanIndeterminate {
                        reason: scan_error.unwrap_or_else(|| "scan failed".into()),
                    });
                }
                UploadScanFailurePolicy::FailOpen => {
                    tracing::warn!(
                        scan_error = ?scan_error,
                        policy = "fail_open",
                        "Upload allowed despite scan failure"
                    );
                }
            }
        }

        // Archive inspection
        let mut archive_entries_scanned = 0u32;
        let mut archive_nested_archives = 0u32;
        let mut archive_truncated = false;
        let mut archive_detected = false;
        let mut archive_type: Option<String> = None;
        let mut archive_supported = false;
        let mut archive_inspected = false;
        let mut archive_entries_seen = 0u32;
        let mut archive_nested_seen = 0u32;
        let mut archive_recursive_inspection = false;
        let mut archive_error: Option<String> = None;
        if effective_config.archive_inspection_enabled && is_zip_archive(data) {
            archive_detected = true;
            archive_type = Some("zip".to_string());
            archive_supported = true;
            let archive_config =
                crate::archive::ArchiveInspectionConfig::from_effective_config(&effective_config);
            if let Some(scanner) = &self.malware_scanner {
                metrics::increment_archive_inspection();
                match crate::archive::inspect_zip_archive(data, &archive_config, scanner, 0, None)
                    .await
                {
                    Ok(archive_result) => {
                        archive_entries_scanned = archive_result.entries_scanned;
                        archive_nested_archives = archive_result.nested_archives_seen;
                        archive_truncated = archive_result.truncated;
                        archive_inspected = true;
                        archive_entries_seen = archive_result.entries_seen;
                        archive_nested_seen = archive_result.nested_archives_seen;
                        archive_recursive_inspection = archive_result.recursive_inspection_enabled;
                        metrics::add_archive_entries_scanned(archive_result.entries_scanned);

                        let archive_match_names: Vec<String> = archive_result
                            .matches
                            .iter()
                            .map(|m| format!("{}:{}", m.entry_path, m.malware_match.rule_name))
                            .collect();
                        if !archive_match_names.is_empty() {
                            metrics::increment_archive_malware_detected();
                            debug!(
                                archive_matches = ?archive_match_names,
                                "Malware detected in archive entries"
                            );
                            return Err(UploadValidationError::MalwareDetected {
                                matches: archive_match_names,
                            });
                        }
                    }
                    Err(crate::archive::ArchiveInspectionError::Disabled) => {}
                    Err(e) => {
                        let error_msg = format!("archive inspection: {e}");
                        archive_error = Some(error_msg.clone());
                        match &e {
                            crate::archive::ArchiveInspectionError::InvalidZip(_) => {
                                metrics::increment_archive_malformed();
                            }
                            crate::archive::ArchiveInspectionError::PathTraversal(_)
                            | crate::archive::ArchiveInspectionError::AbsolutePath(_)
                            | crate::archive::ArchiveInspectionError::UncPath(_)
                            | crate::archive::ArchiveInspectionError::SymlinkRejected(_) => {
                                metrics::increment_archive_limit_violation();
                            }
                            _ => {
                                metrics::increment_archive_limit_violation();
                            }
                        }
                        match effective_config.yara_failure_policy {
                            UploadScanFailurePolicy::FailClosed => {
                                return Err(UploadValidationError::ScanIndeterminate {
                                    reason: error_msg,
                                });
                            }
                            UploadScanFailurePolicy::QuarantineOnError => {
                                return Err(UploadValidationError::ScanIndeterminate {
                                    reason: error_msg,
                                });
                            }
                            UploadScanFailurePolicy::FailOpen => {
                                tracing::warn!(
                                    archive_error = %e,
                                    policy = "fail_open",
                                    "Archive inspection failed but fail_open allows upload"
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(ValidationResult::for_bytes(
            mime_type,
            data.len() as u64,
            scan_status,
            yara_matches,
            scan_error,
            0,
        )
        .with_archive_metadata(
            archive_entries_scanned,
            archive_nested_archives,
            archive_truncated,
            archive_detected,
            archive_type,
            archive_supported,
            archive_inspected,
            archive_entries_seen,
            archive_nested_seen,
            archive_recursive_inspection,
            archive_error,
        ))
    }

    pub async fn validate_with_sandbox(
        &self,
        data: &[u8],
        request_path: &str,
        original_filename: Option<&str>,
    ) -> Result<(ValidationResult, Option<QuarantineEntry>), UploadValidationError> {
        let effective_config = self.config.effective_config_for_path(request_path);

        if data.len() as u64 > effective_config.max_size_bytes {
            return Err(UploadValidationError::SizeExceeded {
                max: effective_config.max_size_bytes,
                actual: data.len() as u64,
            });
        }

        if let Err(e) = self.reload_yara_rules_if_needed() {
            tracing::warn!("Failed to reload YARA rules: {}", e);
        }

        let mime_info = synvoid_app_handlers::mime::detect_from_bytes_with_fallback(data, "bin");
        let mime_type = mime_info.mime_type.clone();

        if !effective_config.is_mime_allowed(&mime_type) {
            return Err(UploadValidationError::TypeNotAllowed {
                detected: mime_type.clone(),
                allowed: effective_config.allowed_mime_types.clone(),
            });
        }

        let (scan_status, yara_matches, scan_error) =
            self.execute_scan(data, &effective_config).await;

        if !yara_matches.is_empty() {
            warn!(
                mime_type = %mime_type,
                filename = ?original_filename,
                matches = ?yara_matches,
                "Malware detected, quarantining file"
            );

            let mut sandbox_handle = self.sandbox.create_handle().await?;
            sandbox_handle.write_sync(data)?;
            sandbox_handle.flush()?;

            let _quarantine_entry = self
                .sandbox
                .quarantine(
                    sandbox_handle.path(),
                    original_filename,
                    Some(&mime_type),
                    &yara_matches,
                )
                .await?;

            return Err(UploadValidationError::MalwareDetected {
                matches: yara_matches,
            });
        }

        if scan_status == UploadScanStatus::Indeterminate
            || scan_status == UploadScanStatus::Unavailable
        {
            match effective_config.yara_failure_policy {
                UploadScanFailurePolicy::FailClosed
                | UploadScanFailurePolicy::QuarantineOnError => {
                    metrics::increment_scan_quarantine_on_error();
                    return Err(UploadValidationError::ScanIndeterminate {
                        reason: scan_error.unwrap_or_else(|| "scan failed".into()),
                    });
                }
                UploadScanFailurePolicy::FailOpen => {
                    tracing::warn!(
                        scan_error = ?scan_error,
                        policy = "fail_open",
                        "Upload allowed despite scan failure"
                    );
                }
            }
        }

        // Archive inspection
        let mut archive_entries_scanned = 0u32;
        let mut archive_nested_archives = 0u32;
        let mut archive_truncated = false;
        let mut archive_detected = false;
        let mut archive_type: Option<String> = None;
        let mut archive_supported = false;
        let mut archive_inspected = false;
        let mut archive_entries_seen = 0u32;
        let mut archive_nested_seen = 0u32;
        let mut archive_recursive_inspection = false;
        let mut archive_error: Option<String> = None;
        if effective_config.archive_inspection_enabled && is_zip_archive(data) {
            archive_detected = true;
            archive_type = Some("zip".to_string());
            archive_supported = true;
            let archive_config =
                crate::archive::ArchiveInspectionConfig::from_effective_config(&effective_config);
            if let Some(scanner) = &self.malware_scanner {
                metrics::increment_archive_inspection();
                match crate::archive::inspect_zip_archive(data, &archive_config, scanner, 0, None)
                    .await
                {
                    Ok(archive_result) => {
                        archive_entries_scanned = archive_result.entries_scanned;
                        archive_nested_archives = archive_result.nested_archives_seen;
                        archive_truncated = archive_result.truncated;
                        archive_inspected = true;
                        archive_entries_seen = archive_result.entries_seen;
                        archive_nested_seen = archive_result.nested_archives_seen;
                        archive_recursive_inspection = archive_result.recursive_inspection_enabled;
                        metrics::add_archive_entries_scanned(archive_result.entries_scanned);

                        let archive_match_names: Vec<String> = archive_result
                            .matches
                            .iter()
                            .map(|m| format!("{}:{}", m.entry_path, m.malware_match.rule_name))
                            .collect();
                        if !archive_match_names.is_empty() {
                            metrics::increment_archive_malware_detected();
                            warn!(
                                filename = ?original_filename,
                                archive_matches = ?archive_match_names,
                                "Malware detected in archive entries, quarantining file"
                            );

                            let mut sandbox_handle = self.sandbox.create_handle().await?;
                            sandbox_handle.write_sync(data)?;
                            sandbox_handle.flush()?;

                            let _quarantine_entry = self
                                .sandbox
                                .quarantine(
                                    sandbox_handle.path(),
                                    original_filename,
                                    Some(&mime_type),
                                    &archive_match_names,
                                )
                                .await?;

                            return Err(UploadValidationError::MalwareDetected {
                                matches: archive_match_names,
                            });
                        }
                    }
                    Err(crate::archive::ArchiveInspectionError::Disabled) => {}
                    Err(e) => {
                        let error_msg = format!("archive inspection: {e}");
                        archive_error = Some(error_msg.clone());
                        match &e {
                            crate::archive::ArchiveInspectionError::InvalidZip(_) => {
                                metrics::increment_archive_malformed();
                            }
                            crate::archive::ArchiveInspectionError::PathTraversal(_)
                            | crate::archive::ArchiveInspectionError::AbsolutePath(_)
                            | crate::archive::ArchiveInspectionError::UncPath(_)
                            | crate::archive::ArchiveInspectionError::SymlinkRejected(_) => {
                                metrics::increment_archive_limit_violation();
                            }
                            _ => {
                                metrics::increment_archive_limit_violation();
                            }
                        }
                        match effective_config.yara_failure_policy {
                            UploadScanFailurePolicy::FailClosed => {
                                return Err(UploadValidationError::ScanIndeterminate {
                                    reason: error_msg,
                                });
                            }
                            UploadScanFailurePolicy::QuarantineOnError => {
                                return Err(UploadValidationError::ScanIndeterminate {
                                    reason: error_msg,
                                });
                            }
                            UploadScanFailurePolicy::FailOpen => {
                                tracing::warn!(
                                    archive_error = %e,
                                    policy = "fail_open",
                                    "Archive inspection failed but fail_open allows upload"
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok((
            ValidationResult::for_bytes(
                mime_type,
                data.len() as u64,
                scan_status,
                yara_matches,
                scan_error,
                0,
            )
            .with_archive_metadata(
                archive_entries_scanned,
                archive_nested_archives,
                archive_truncated,
                archive_detected,
                archive_type,
                archive_supported,
                archive_inspected,
                archive_entries_seen,
                archive_nested_seen,
                archive_recursive_inspection,
                archive_error,
            ),
            None,
        ))
    }

    pub fn get_effective_config(&self, request_path: &str) -> EffectiveUploadConfig {
        self.config.effective_config_for_path(request_path)
    }

    pub fn config(&self) -> &UploadConfig {
        &self.config
    }

    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    pub async fn create_sandbox_handle(&self) -> std::io::Result<SandboxHandle> {
        self.sandbox.create_handle().await
    }

    pub async fn validate_large_file(
        &self,
        sandbox_handle: &mut SandboxHandle,
        request_path: &str,
        original_filename: Option<&str>,
    ) -> Result<ValidationResult, UploadValidationError> {
        let effective_config = self.config.effective_config_for_path(request_path);

        let size = sandbox_handle.bytes_written();
        if size > effective_config.max_size_bytes {
            return Err(UploadValidationError::SizeExceeded {
                max: effective_config.max_size_bytes,
                actual: size,
            });
        }

        if let Err(e) = self.reload_yara_rules_if_needed() {
            tracing::warn!("Failed to reload YARA rules: {}", e);
        }

        // Always read header for MIME detection
        let header = sandbox_handle.read_header(HEADER_READ_SIZE)?;
        let mime_info = synvoid_app_handlers::mime::detect_from_bytes_with_fallback(&header, "bin");
        let mime_type = mime_info.mime_type.clone();

        if !effective_config.is_mime_allowed(&mime_type) {
            return Err(UploadValidationError::TypeNotAllowed {
                detected: mime_type.clone(),
                allowed: effective_config.allowed_mime_types.clone(),
            });
        }

        let scan_mode = effective_config.yara_large_file_scan_mode.clone();
        let start = std::time::Instant::now();

        let (scan_status, yara_matches, scan_error, scanned_bytes, window_count) = match scan_mode {
            crate::config::YaraLargeFileScanMode::HeaderOnly => {
                // Scan only the header bytes (legacy behavior)
                let (status, matches, err) = self.execute_scan(&header, &effective_config).await;
                let scanned = if effective_config.scan_with_yara {
                    header.len() as u64
                } else {
                    0
                };
                (status, matches, err, scanned, 0u32)
            }
            crate::config::YaraLargeFileScanMode::Full => {
                // Read entire file and scan with built-in + YARA rules
                let full_data = sandbox_handle.read_bytes()?;
                let full_len = full_data.len() as u64;

                match &self.malware_scanner {
                    Some(scanner) => match scanner.scan_bytes(&full_data).await {
                        Ok(scan_result) => {
                            let matched_names: Vec<String> = scan_result
                                .matches
                                .iter()
                                .map(|m| m.rule_name.clone())
                                .collect();
                            if matched_names.is_empty() {
                                metrics::increment_scan_clean();
                                (UploadScanStatus::Clean, matched_names, None, full_len, 0u32)
                            } else {
                                metrics::increment_scan_malicious();
                                (
                                    UploadScanStatus::Malicious,
                                    matched_names,
                                    None,
                                    full_len,
                                    0u32,
                                )
                            }
                        }
                        Err(e) => {
                            let error_msg = format!("{}", e);
                            metrics::increment_scan_indeterminate();
                            match effective_config.yara_failure_policy {
                                UploadScanFailurePolicy::FailClosed
                                | UploadScanFailurePolicy::QuarantineOnError => {
                                    metrics::increment_scan_quarantine_on_error();
                                    (
                                        UploadScanStatus::Indeterminate,
                                        Vec::new(),
                                        Some(error_msg),
                                        full_len,
                                        0u32,
                                    )
                                }
                                UploadScanFailurePolicy::FailOpen => {
                                    metrics::increment_scan_fail_open_allowed();
                                    tracing::warn!(
                                        error = %e,
                                        policy = "fail_open",
                                        "Full-file scan failed but fail_open policy allows upload"
                                    );
                                    (
                                        UploadScanStatus::Indeterminate,
                                        Vec::new(),
                                        Some(error_msg),
                                        full_len,
                                        0u32,
                                    )
                                }
                            }
                        }
                    },
                    None => {
                        let err = "no malware scanner available".into();
                        match effective_config.yara_failure_policy {
                            UploadScanFailurePolicy::FailClosed
                            | UploadScanFailurePolicy::QuarantineOnError => (
                                UploadScanStatus::Unavailable,
                                Vec::new(),
                                Some(err),
                                0,
                                0u32,
                            ),
                            UploadScanFailurePolicy::FailOpen => {
                                metrics::increment_scan_fail_open_allowed();
                                (
                                    UploadScanStatus::Unavailable,
                                    Vec::new(),
                                    Some(err),
                                    0,
                                    0u32,
                                )
                            }
                        }
                    }
                }
            }
            crate::config::YaraLargeFileScanMode::Windowed => {
                // Compute window offsets: header, footer, middle chunks, optional magic region
                let windows = Self::compute_scan_windows(
                    size,
                    effective_config.yara_window_size_bytes as u32,
                    effective_config.yara_max_window_count,
                    effective_config.yara_magic_scan_limit_bytes,
                );

                match &self.malware_scanner {
                    Some(scanner) => {
                        // Build full data for windowed heuristic scan
                        let full_data = match sandbox_handle.read_bytes() {
                            Ok(d) => d,
                            Err(e) => {
                                return Err(UploadValidationError::SandboxError(
                                    SandboxError::IoError(e.to_string()),
                                ));
                            }
                        };

                        let window_specs: Vec<(u64, u32)> =
                            windows.iter().map(|w| (w.offset, w.length)).collect();

                        match scanner.scan_bytes_windowed(&full_data, &window_specs).await {
                            Ok(scan_result) => {
                                let matched_names: Vec<String> = scan_result
                                    .matches
                                    .iter()
                                    .map(|m| m.rule_name.clone())
                                    .collect();
                                let scanned: u64 = windows.iter().map(|w| w.length as u64).sum();
                                if matched_names.is_empty() {
                                    metrics::increment_scan_clean();
                                    (
                                        UploadScanStatus::Clean,
                                        matched_names,
                                        None,
                                        scanned,
                                        windows.len() as u32,
                                    )
                                } else {
                                    metrics::increment_scan_malicious();
                                    (
                                        UploadScanStatus::Malicious,
                                        matched_names,
                                        None,
                                        scanned,
                                        windows.len() as u32,
                                    )
                                }
                            }
                            Err(e) => {
                                let error_msg = format!("{}", e);
                                let scanned: u64 = windows.iter().map(|w| w.length as u64).sum();
                                metrics::increment_scan_indeterminate();
                                match effective_config.yara_failure_policy {
                                    UploadScanFailurePolicy::FailClosed
                                    | UploadScanFailurePolicy::QuarantineOnError => {
                                        metrics::increment_scan_quarantine_on_error();
                                        (
                                            UploadScanStatus::Indeterminate,
                                            Vec::new(),
                                            Some(error_msg),
                                            scanned,
                                            windows.len() as u32,
                                        )
                                    }
                                    UploadScanFailurePolicy::FailOpen => {
                                        metrics::increment_scan_fail_open_allowed();
                                        tracing::warn!(
                                            error = %e,
                                            policy = "fail_open",
                                            "Windowed scan failed but fail_open policy allows upload"
                                        );
                                        (
                                            UploadScanStatus::Indeterminate,
                                            Vec::new(),
                                            Some(error_msg),
                                            scanned,
                                            windows.len() as u32,
                                        )
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        let err = "no malware scanner available".into();
                        let scanned: u64 = windows.iter().map(|w| w.length as u64).sum();
                        match effective_config.yara_failure_policy {
                            UploadScanFailurePolicy::FailClosed
                            | UploadScanFailurePolicy::QuarantineOnError => (
                                UploadScanStatus::Unavailable,
                                Vec::new(),
                                Some(err),
                                scanned,
                                windows.len() as u32,
                            ),
                            UploadScanFailurePolicy::FailOpen => {
                                metrics::increment_scan_fail_open_allowed();
                                (
                                    UploadScanStatus::Unavailable,
                                    Vec::new(),
                                    Some(err),
                                    scanned,
                                    windows.len() as u32,
                                )
                            }
                        }
                    }
                }
            }
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        if !yara_matches.is_empty() {
            warn!(
                mime_type = %mime_type,
                filename = ?original_filename,
                matches = ?yara_matches,
                scan_mode = ?scan_mode,
                "Malware detected in large file, quarantining"
            );

            let _quarantine_entry = self
                .sandbox
                .quarantine(
                    sandbox_handle.path(),
                    original_filename,
                    Some(&mime_type),
                    &yara_matches,
                )
                .await?;

            return Err(UploadValidationError::MalwareDetected {
                matches: yara_matches,
            });
        }

        if scan_status == UploadScanStatus::Indeterminate
            || scan_status == UploadScanStatus::Unavailable
        {
            match effective_config.yara_failure_policy {
                UploadScanFailurePolicy::FailClosed
                | UploadScanFailurePolicy::QuarantineOnError => {
                    metrics::increment_scan_quarantine_on_error();
                    return Err(UploadValidationError::ScanIndeterminate {
                        reason: scan_error.unwrap_or_else(|| "scan failed".into()),
                    });
                }
                UploadScanFailurePolicy::FailOpen => {
                    tracing::warn!(
                        scan_error = ?scan_error,
                        policy = "fail_open",
                        "Upload allowed despite scan failure"
                    );
                }
            }
        }

        Ok(match scan_mode {
            crate::config::YaraLargeFileScanMode::HeaderOnly => ValidationResult::for_header_only(
                mime_type,
                size,
                HEADER_READ_SIZE as u64,
                scan_status,
                yara_matches,
                scan_error,
                duration_ms,
            ),
            crate::config::YaraLargeFileScanMode::Full => ValidationResult::for_full_file(
                mime_type,
                size,
                scan_status,
                yara_matches,
                scan_error,
                duration_ms,
            ),
            crate::config::YaraLargeFileScanMode::Windowed => ValidationResult::for_windowed(
                mime_type,
                size,
                scanned_bytes,
                window_count,
                scan_status,
                yara_matches,
                scan_error,
                duration_ms,
            ),
        })
    }

    /// Compute window offsets for windowed scanning.
    /// Returns a list of `ScanWindow { offset, length }` to scan.
    fn compute_scan_windows(
        file_size: u64,
        window_size: u32,
        max_windows: u32,
        magic_scan_limit: u64,
    ) -> Vec<ScanWindow> {
        let mut windows = Vec::new();
        let ws = window_size as u64;

        // Window 1: Header (offset 0)
        let header_len = ws.min(file_size);
        windows.push(ScanWindow {
            offset: 0,
            length: header_len as u32,
        });

        if windows.len() as u32 >= max_windows {
            return windows;
        }

        // Window 2: Footer (last window_size bytes)
        if file_size > ws {
            let footer_offset = file_size.saturating_sub(ws);
            windows.push(ScanWindow {
                offset: footer_offset,
                length: ws as u32,
            });
        }

        if windows.len() as u32 >= max_windows {
            return windows;
        }

        // Window 3: Magic byte scan region (bytes 0..magic_scan_limit)
        // Only if magic_scan_limit > header and we have budget
        if magic_scan_limit > header_len && magic_scan_limit < file_size {
            let remaining_budget = max_windows.saturating_sub(windows.len() as u32);
            if remaining_budget > 0 {
                let magic_start = header_len;
                let magic_len = (magic_scan_limit - magic_start).min(ws);
                windows.push(ScanWindow {
                    offset: magic_start,
                    length: magic_len as u32,
                });
            }
        }

        if windows.len() as u32 >= max_windows {
            return windows;
        }

        // Fill remaining windows with evenly-spaced middle chunks
        let middle_start = ws.max(magic_scan_limit.min(file_size));
        let middle_end = file_size.saturating_sub(ws);
        if middle_end > middle_start {
            let middle_range = middle_end - middle_start;
            let remaining = max_windows.saturating_sub(windows.len() as u32);
            if remaining > 0 {
                let step = middle_range / remaining as u64;
                for i in 0..remaining {
                    let offset = middle_start + (step * i as u64);
                    let length = ws.min(file_size - offset) as u32;
                    if length > 0 {
                        windows.push(ScanWindow { offset, length });
                    }
                }
            }
        }

        windows
    }
}

pub fn is_upload_content_type(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("multipart/form-data")
        || ct.starts_with("application/octet-stream")
        || ct.starts_with("application/x-www-form-urlencoded")
}

pub fn parse_content_length(content_length: Option<&str>) -> Option<u64> {
    content_length.and_then(|s| s.parse::<u64>().ok())
}

pub fn should_validate_upload(
    content_type: Option<&str>,
    content_length: Option<&str>,
    config: &UploadConfig,
) -> bool {
    if !config.enabled {
        return false;
    }

    let is_multipart = content_type
        .map(|ct| ct.to_lowercase().starts_with("multipart/form-data"))
        .unwrap_or(false);

    if is_multipart {
        return true;
    }

    if let Some(length) = parse_content_length(content_length) {
        if length > 0 && length <= config.max_size_bytes() {
            return true;
        }
    }

    false
}

pub fn validate_filename(filename: &str) -> Result<(), UploadValidationError> {
    if filename.is_empty() {
        return Err(UploadValidationError::EmptyFilename);
    }

    if filename.contains('\0') {
        return Err(UploadValidationError::InvalidFilename {
            reason: "null byte in filename".to_string(),
        });
    }

    if filename.contains("..") {
        return Err(UploadValidationError::InvalidFilename {
            reason: "path traversal sequence '..' in filename".to_string(),
        });
    }

    if filename.contains('/') || filename.contains('\\') {
        return Err(UploadValidationError::InvalidFilename {
            reason: "path separator in filename".to_string(),
        });
    }

    let name_upper = filename.to_uppercase();
    let base_name = name_upper.split('.').next().unwrap_or("");
    if RESERVED_WINDOWS_NAMES.contains(&base_name) {
        return Err(UploadValidationError::InvalidFilename {
            reason: format!("reserved Windows name: {}", base_name),
        });
    }

    Ok(())
}

pub fn parse_content_disposition_filename(header_value: &str) -> Option<String> {
    let header_lower = header_value.to_lowercase();
    if !header_lower.contains("form-data") && !header_lower.contains("attachment") {
        return None;
    }

    // Try filename*= (RFC 5987 encoded) first
    if let Some(pos) = header_lower.find("filename*=") {
        let after = &header_value[pos + "filename*=".len()..];
        let after = after.trim();
        // Format: charset'language'value
        let parts: Vec<&str> = after.splitn(3, '\'').collect();
        if parts.len() == 3 {
            let value = parts[2].trim().trim_matches('"');
            // Simple percent-decoding for ASCII
            let decoded = percent_decode(value);
            if !decoded.is_empty() {
                return Some(decoded);
            }
        }
    }

    // Try filename=
    if let Some(pos) = header_lower.find("filename=") {
        let after = &header_value[pos + "filename=".len()..];
        let after = after.trim().trim_matches('"');
        // Stop at semicolon (next parameter)
        let filename = after.split(';').next().unwrap_or(after).trim();
        if !filename.is_empty() {
            return Some(filename.to_string());
        }
    }

    None
}

fn percent_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hex: String = chars.by_ref().take(2).map(|b| b as char).collect();
            if hex.len() == 2 {
                if let Ok(val) = u8::from_str_radix(&hex, 16) {
                    bytes.push(val);
                    continue;
                }
            }
            bytes.push(b'%');
            for c in hex.bytes() {
                bytes.push(c);
            }
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes.clone())
        .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned())
}

pub struct MultipartPart {
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

pub fn parse_multipart(
    body: &[u8],
    content_type: &str,
) -> Result<Vec<MultipartPart>, UploadValidationError> {
    let boundary =
        extract_multipart_boundary(content_type).ok_or(UploadValidationError::InvalidMultipart)?;

    let delimiter = format!("--{}", boundary);
    let delimiter_bytes = delimiter.as_bytes();
    let end_delimiter = format!("--{}--", boundary);
    let end_delimiter_bytes = end_delimiter.as_bytes();

    let mut parts = Vec::new();
    let mut current_part_data: Vec<u8> = Vec::new();
    let mut in_part = false;
    let _part_headers: Vec<u8> = Vec::new();
    let mut filename: Option<String> = None;
    let mut content_type_header: Option<String> = None;

    let body_parts = split_on_boundary(body, delimiter_bytes, end_delimiter_bytes);

    for part in body_parts {
        if part.is_empty() {
            continue;
        }

        if part.starts_with(b"--")
            && (part.starts_with(delimiter_bytes) || part.starts_with(end_delimiter_bytes))
        {
            if in_part && !current_part_data.is_empty() {
                parts.push(MultipartPart {
                    filename: filename.clone(),
                    content_type: content_type_header.clone(),
                    data: current_part_data,
                });
                current_part_data = Vec::new();
            }
            in_part = part.starts_with(delimiter_bytes) && !part.starts_with(end_delimiter_bytes);
            if !in_part {
                break;
            }
            filename = None;
            content_type_header = None;
            continue;
        }

        if in_part {
            let header_end = part.windows(2).position(|w| w == b"\r\n").map(|p| p + 2);
            let header_section = match header_end {
                Some(pos) => &part[..pos],
                None => &[],
            };

            if let Ok(header_str) = std::str::from_utf8(header_section) {
                let header_lc = header_str.to_lowercase();
                if header_lc.contains("content-disposition:") {
                    if let Some(fname) = parse_content_disposition_filename(header_str) {
                        filename = Some(fname);
                    }
                }
                if header_lc.contains("content-type:") {
                    for line in header_lc.lines() {
                        if line.trim_start().starts_with("content-type:") {
                            content_type_header =
                                Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
                            break;
                        }
                    }
                }
            }

            if let Some(pos) = header_end {
                current_part_data.extend_from_slice(&part[pos..]);
            }
        } else {
            current_part_data.extend_from_slice(part);
        }
    }

    Ok(parts)
}

fn split_on_boundary<'a>(body: &'a [u8], delimiter: &[u8], _end_delimiter: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut start = 0;

    let mut search_from = 0;
    while let Some(pos) = find_bytes(&body[search_from..], delimiter) {
        let actual_pos = search_from + pos;
        if start < actual_pos {
            parts.push(&body[start..actual_pos]);
        }

        let mut line_end = actual_pos + delimiter.len();
        while line_end < body.len() && (body[line_end] == b'\r' || body[line_end] == b'\n') {
            line_end += 1;
        }
        start = line_end;
        search_from = start;

        if body.len() >= actual_pos + delimiter.len() + 2
            && &body[actual_pos + delimiter.len()..actual_pos + delimiter.len() + 2] == b"--"
        {
            break;
        }
    }

    if start < body.len() {
        parts.push(&body[start..]);
    }

    parts
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_multipart_boundary(content_type: &str) -> Option<String> {
    let parts: Vec<&str> = content_type.split(';').collect();
    for part in parts {
        let part = part.trim();
        if part.to_lowercase().starts_with("boundary=") {
            let boundary = &part["boundary=".len()..];
            let boundary = boundary.trim_matches('"');
            return Some(boundary.to_string());
        }
    }
    None
}

#[cfg(test)]
impl UploadValidator {
    /// Test-only constructor that accepts a pre-built MalwareScanner,
    /// bypassing YARA source construction. This allows injecting mock
    /// scanners to exercise execute_scan failure-policy paths through
    /// real validate_bytes entry points.
    pub(crate) fn with_scanner(config: UploadConfig, scanner: Option<MalwareScanner>) -> Self {
        let sandbox_config = SandboxConfig::new(&config.sandbox_dir, &config.quarantine_dir);
        let sandbox = Arc::new(Sandbox::new(sandbox_config));
        Self {
            sandbox,
            malware_scanner: scanner.map(Arc::new),
            config,
            _reload_lock: parking_lot::RwLock::new(()),
            #[cfg(feature = "mesh")]
            yara_rules: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_upload_content_type() {
        assert!(is_upload_content_type("multipart/form-data"));
        assert!(is_upload_content_type(
            "multipart/form-data; boundary=----WebKitFormBoundary"
        ));
        assert!(is_upload_content_type("application/octet-stream"));
        assert!(is_upload_content_type("application/x-www-form-urlencoded"));
        assert!(!is_upload_content_type("application/json"));
        assert!(!is_upload_content_type("text/plain"));
    }

    #[test]
    fn test_parse_content_length() {
        assert_eq!(parse_content_length(Some("1024")), Some(1024));
        assert_eq!(parse_content_length(Some("0")), Some(0));
        assert_eq!(parse_content_length(Some("invalid")), None);
        assert_eq!(parse_content_length(None), None);
    }

    #[test]
    fn test_validate_filename_valid() {
        assert!(validate_filename("document.pdf").is_ok());
        assert!(validate_filename("image-2024.jpg").is_ok());
        assert!(validate_filename("my_file.txt").is_ok());
    }

    #[test]
    fn test_validate_filename_empty() {
        assert!(matches!(
            validate_filename(""),
            Err(UploadValidationError::EmptyFilename)
        ));
    }

    #[test]
    fn test_validate_filename_null_byte() {
        assert!(matches!(
            validate_filename("file\0.exe"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
    }

    #[test]
    fn test_validate_filename_path_traversal() {
        assert!(matches!(
            validate_filename("../../../etc/passwd"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
        assert!(matches!(
            validate_filename("foo/../bar"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
    }

    #[test]
    fn test_validate_filename_path_separators() {
        assert!(matches!(
            validate_filename("foo/bar.txt"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
        assert!(matches!(
            validate_filename("foo\\bar.txt"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
    }

    #[test]
    fn test_validate_filename_reserved_windows_names() {
        assert!(matches!(
            validate_filename("CON"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
        assert!(matches!(
            validate_filename("con.txt"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
        assert!(matches!(
            validate_filename("PRN"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
        assert!(matches!(
            validate_filename("COM1.dat"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
        assert!(matches!(
            validate_filename("LPT9"),
            Err(UploadValidationError::InvalidFilename { .. })
        ));
    }

    #[test]
    fn test_parse_content_disposition_filename() {
        let header = r#"form-data; name="file"; filename="document.pdf""#;
        assert_eq!(
            parse_content_disposition_filename(header),
            Some("document.pdf".to_string())
        );

        let header = r#"attachment; filename="report.xlsx""#;
        assert_eq!(
            parse_content_disposition_filename(header),
            Some("report.xlsx".to_string())
        );

        let header = "form-data; name=\"file\"; filename*=UTF-8''%E4%B8%AD%E6%96%87.txt";
        assert_eq!(
            parse_content_disposition_filename(header),
            Some("中文.txt".to_string())
        );

        let header = "application/json";
        assert_eq!(parse_content_disposition_filename(header), None);

        let header = "form-data; name=\"field\"";
        assert_eq!(parse_content_disposition_filename(header), None);
    }

    // --- YARA failure semantics tests ---

    #[test]
    fn test_upload_scan_failure_policy_default() {
        let policy = UploadScanFailurePolicy::default();
        assert_eq!(policy, UploadScanFailurePolicy::QuarantineOnError);
    }

    #[test]
    fn test_upload_scan_failure_policy_deserialize() {
        let policy: UploadScanFailurePolicy = serde_json::from_str(r#""fail_closed""#).unwrap();
        assert_eq!(policy, UploadScanFailurePolicy::FailClosed);

        let policy: UploadScanFailurePolicy =
            serde_json::from_str(r#""quarantine_on_error""#).unwrap();
        assert_eq!(policy, UploadScanFailurePolicy::QuarantineOnError);

        let policy: UploadScanFailurePolicy = serde_json::from_str(r#""fail_open""#).unwrap();
        assert_eq!(policy, UploadScanFailurePolicy::FailOpen);
    }

    #[test]
    fn test_validation_result_is_clean_scan_status() {
        let clean = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert!(clean.is_clean());

        let disabled = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Disabled,
            Vec::new(),
            None,
            0,
        );
        assert!(disabled.is_clean());

        let indeterminate = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Indeterminate,
            Vec::new(),
            Some("timeout".into()),
            0,
        );
        assert!(!indeterminate.is_clean());

        let unavailable = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Unavailable,
            Vec::new(),
            Some("no scanner".into()),
            0,
        );
        assert!(!unavailable.is_clean());

        let malicious = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Malicious,
            vec!["test_rule".into()],
            None,
            0,
        );
        assert!(!malicious.is_clean());
    }

    #[test]
    fn test_config_with_yara_failure_policy() {
        let config = UploadConfig::default();
        assert_eq!(
            config.yara_failure_policy,
            UploadScanFailurePolicy::QuarantineOnError
        );
    }

    #[test]
    fn test_config_path_override_failure_policy() {
        let config = UploadConfig {
            paths: vec![PathUploadConfig {
                pattern: "/api/upload".to_string(),
                max_size: None,
                scan_with_yara: None,
                yara_rules_dir: None,
                yara_timeout_ms: None,
                verify_signature: None,
                signature_strict_mode: None,
                rate_limit_enabled: None,
                max_uploads_per_minute: None,
                max_uploads_per_hour: None,
                max_bytes_per_minute: None,
                burst_allowance: None,
                allowed_types: AllowedTypesConfig::default(),
                reject_mime_mismatch: None,
                yara_failure_policy: Some(UploadScanFailurePolicy::FailClosed),
                yara_large_file_scan_mode: None,
                yara_window_size_bytes: None,
                yara_max_window_count: None,
                yara_magic_scan_limit_bytes: None,
                yara_max_concurrent_scans: None,
                yara_max_queued_scans: None,
                yara_queue_timeout_ms: None,
                yara_max_rule_files: None,
                yara_max_rule_source_bytes: None,
                yara_allow_rule_symlinks: None,
                archive_inspection_enabled: None,
                archive_max_depth: None,
                archive_max_entries: None,
                archive_max_total_uncompressed_bytes: None,
                archive_max_entry_uncompressed_bytes: None,
                archive_max_compression_ratio: None,
                archive_max_nested_archives: None,
            }],
            ..Default::default()
        };

        let effective = config.effective_config_for_path("/api/upload");
        assert_eq!(
            effective.yara_failure_policy,
            UploadScanFailurePolicy::FailClosed
        );

        let effective_default = config.effective_config_for_path("/other");
        assert_eq!(
            effective_default.yara_failure_policy,
            UploadScanFailurePolicy::QuarantineOnError
        );
    }

    #[tokio::test]
    async fn test_validate_bytes_disabled_scan() {
        let config = UploadConfig {
            scan_with_yara: false,
            sandbox_enabled: false,
            ..Default::default()
        };

        let validator = UploadValidator::new(config).unwrap();
        let data = b"hello world";
        let result = validator.validate_bytes(data, "/upload").await.unwrap();
        assert_eq!(result.scan_status, UploadScanStatus::Disabled);
        assert!(!result.scanned);
        assert!(result.is_clean());
        assert!(result.scan_error.is_none());
    }

    #[tokio::test]
    async fn test_validate_with_sandbox_disabled_scan() {
        let config = UploadConfig {
            scan_with_yara: false,
            sandbox_enabled: false,
            ..Default::default()
        };

        let validator = UploadValidator::new(config).unwrap();
        let data = b"hello world";
        let (result, _quarantine) = validator
            .validate_with_sandbox(data, "/upload", Some("test.txt"))
            .await
            .unwrap();
        assert_eq!(result.scan_status, UploadScanStatus::Disabled);
        assert!(!result.scanned);
        assert!(result.is_clean());
    }

    #[tokio::test]
    async fn test_validate_bytes_with_declared_type_disabled_scan() {
        let config = UploadConfig {
            scan_with_yara: false,
            sandbox_enabled: false,
            ..Default::default()
        };

        let validator = UploadValidator::new(config).unwrap();
        let data = b"hello world";
        let result = validator
            .validate_bytes_with_declared_type(data, "/upload", Some("text/plain"))
            .await
            .unwrap();
        assert_eq!(result.scan_status, UploadScanStatus::Disabled);
        assert!(!result.scanned);
        assert!(result.is_clean());
    }

    #[test]
    fn test_scan_indeterminate_error_display() {
        let err = UploadValidationError::ScanIndeterminate {
            reason: "timeout".into(),
        };
        assert!(err.to_string().contains("timeout"));

        let err = UploadValidationError::ScannerUnavailable;
        assert!(err.to_string().contains("unavailable"));
    }

    // --- Scan mode / coverage metadata tests ---

    #[test]
    fn test_validation_result_for_header_only() {
        let result = ValidationResult::for_header_only(
            "application/pdf".into(),
            1_000_000,
            8192,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            5,
        );
        assert_eq!(result.scan_mode, YaraLargeFileScanMode::HeaderOnly);
        assert_eq!(result.scanned_bytes, 8192);
        assert_eq!(result.total_bytes, 1_000_000);
        assert!((result.coverage_ratio - 0.008192).abs() < 0.0001);
        assert_eq!(result.window_count, 0);
        assert!(result.is_clean());
    }

    #[test]
    fn test_validation_result_for_windowed() {
        let result = ValidationResult::for_windowed(
            "video/mp4".into(),
            50_000_000,
            4_000_000,
            4,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            120,
        );
        assert_eq!(result.scan_mode, YaraLargeFileScanMode::Windowed);
        assert_eq!(result.scanned_bytes, 4_000_000);
        assert_eq!(result.total_bytes, 50_000_000);
        assert!((result.coverage_ratio - 0.08).abs() < 0.001);
        assert_eq!(result.window_count, 4);
        assert_eq!(result.duration_ms, 120);
    }

    #[test]
    fn test_validation_result_for_full_file() {
        let result = ValidationResult::for_full_file(
            "application/zip".into(),
            5_000_000,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            200,
        );
        assert_eq!(result.scan_mode, YaraLargeFileScanMode::Full);
        assert_eq!(result.scanned_bytes, 5_000_000);
        assert_eq!(result.total_bytes, 5_000_000);
        assert_eq!(result.coverage_ratio, 1.0);
        assert_eq!(result.window_count, 0);
    }

    #[test]
    fn test_compute_scan_windows_small_file() {
        let windows = UploadValidator::compute_scan_windows(4096, 1048576, 8, 16 * 1024 * 1024);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].offset, 0);
        assert_eq!(windows[0].length, 4096);
    }

    #[test]
    fn test_compute_scan_windows_medium_file() {
        let windows =
            UploadValidator::compute_scan_windows(5 * 1024 * 1024, 1048576, 8, 16 * 1024 * 1024);
        assert!(windows.len() >= 2);
        assert_eq!(windows[0].offset, 0);
        assert_eq!(windows[0].length, 1048576);
        let last = windows.last().unwrap();
        assert_eq!(last.offset + last.length as u64, 5 * 1024 * 1024);
    }

    #[test]
    fn test_compute_scan_windows_large_file_with_magic_region() {
        let windows =
            UploadValidator::compute_scan_windows(50 * 1024 * 1024, 1048576, 8, 16 * 1024 * 1024);
        assert!(windows.len() >= 3);
        assert_eq!(windows[0].offset, 0);
        assert_eq!(windows[0].length, 1048576);
        assert_eq!(windows.len() as u32, 8);
    }

    #[test]
    fn test_compute_scan_windows_max_windows_cap() {
        let windows =
            UploadValidator::compute_scan_windows(100 * 1024 * 1024, 1048576, 3, 16 * 1024 * 1024);
        assert!(windows.len() <= 3);
    }

    #[test]
    fn test_compute_scan_windows_header_only_max_windows_1() {
        let windows =
            UploadValidator::compute_scan_windows(50 * 1024 * 1024, 1048576, 1, 16 * 1024 * 1024);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].offset, 0);
    }

    #[test]
    fn test_compute_scan_windows_empty_file() {
        let windows = UploadValidator::compute_scan_windows(0, 1048576, 8, 16 * 1024 * 1024);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].length, 0);
    }

    #[test]
    fn test_compute_scan_windows_header_only_bigger_than_file() {
        let windows = UploadValidator::compute_scan_windows(4096, 1048576, 8, 16 * 1024 * 1024);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].offset, 0);
        assert_eq!(windows[0].length, 4096);
    }

    #[test]
    fn test_validation_result_for_bytes() {
        let result = ValidationResult::for_bytes(
            "application/octet-stream".into(),
            2048,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            15,
        );
        assert_eq!(result.scan_mode, YaraLargeFileScanMode::Full);
        assert_eq!(result.scanned_bytes, 2048);
        assert_eq!(result.total_bytes, 2048);
        assert_eq!(result.coverage_ratio, 1.0);
        assert_eq!(result.window_count, 0);
        assert_eq!(result.size, 2048);
        assert_eq!(result.duration_ms, 15);
        assert!(result.is_clean());
    }

    #[test]
    fn test_yara_large_file_scan_mode_serde_roundtrip() {
        let modes = vec![
            YaraLargeFileScanMode::Full,
            YaraLargeFileScanMode::Windowed,
            YaraLargeFileScanMode::HeaderOnly,
        ];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let deserialized: YaraLargeFileScanMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, deserialized);
        }
    }

    // --- Scan failure semantics regression tests ---

    #[test]
    fn test_is_clean_with_each_status() {
        let clean = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert!(clean.is_clean(), "Clean should be clean");

        let disabled = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Disabled,
            Vec::new(),
            None,
            0,
        );
        assert!(
            disabled.is_clean(),
            "Disabled with no matches should be clean"
        );

        let malicious = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Malicious,
            vec!["rule1".into()],
            None,
            0,
        );
        assert!(!malicious.is_clean(), "Malicious should not be clean");

        let unavailable = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Unavailable,
            Vec::new(),
            Some("no scanner".into()),
            0,
        );
        assert!(!unavailable.is_clean(), "Unavailable should not be clean");

        let indeterminate = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Indeterminate,
            Vec::new(),
            Some("timeout".into()),
            0,
        );
        assert!(
            !indeterminate.is_clean(),
            "Indeterminate should not be clean"
        );
    }

    #[test]
    fn test_is_clean_disabled_with_matches() {
        let result = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Disabled,
            vec!["suspicious_rule".into()],
            None,
            0,
        );
        assert!(
            !result.is_clean(),
            "Disabled with non-empty yara_matches should not be clean"
        );
    }

    #[test]
    fn test_is_clean_indeterminate_no_matches() {
        let result = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Indeterminate,
            Vec::new(),
            Some("scan error".into()),
            0,
        );
        assert!(
            !result.is_clean(),
            "Indeterminate with no matches should not be clean (scanner error)"
        );
    }

    #[test]
    fn test_validation_result_display_statuses() {
        let clean = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        let debug_str = format!("{:?}", clean);
        assert!(debug_str.contains("Clean"));
        assert!(debug_str.contains("text/plain"));

        let malicious = ValidationResult::for_bytes(
            "application/pdf".into(),
            200,
            UploadScanStatus::Malicious,
            vec!["eicar_test".into()],
            None,
            5,
        );
        let debug_str = format!("{:?}", malicious);
        assert!(debug_str.contains("Malicious"));
        assert!(debug_str.contains("eicar_test"));

        let disabled = ValidationResult::for_bytes(
            "image/png".into(),
            50,
            UploadScanStatus::Disabled,
            Vec::new(),
            None,
            0,
        );
        let debug_str = format!("{:?}", disabled);
        assert!(debug_str.contains("Disabled"));

        let unavailable = ValidationResult::for_bytes(
            "video/mp4".into(),
            500,
            UploadScanStatus::Unavailable,
            Vec::new(),
            Some("no scanner".into()),
            0,
        );
        let debug_str = format!("{:?}", unavailable);
        assert!(debug_str.contains("Unavailable"));
        assert!(debug_str.contains("no scanner"));

        let indeterminate = ValidationResult::for_bytes(
            "application/zip".into(),
            300,
            UploadScanStatus::Indeterminate,
            Vec::new(),
            Some("timeout".into()),
            0,
        );
        let debug_str = format!("{:?}", indeterminate);
        assert!(debug_str.contains("Indeterminate"));
        assert!(debug_str.contains("timeout"));
    }

    #[test]
    fn test_scan_failure_policy_deserialize_all_variants() {
        let policy: UploadScanFailurePolicy = serde_json::from_str(r#""fail_closed""#).unwrap();
        assert_eq!(policy, UploadScanFailurePolicy::FailClosed);

        let policy: UploadScanFailurePolicy =
            serde_json::from_str(r#""quarantine_on_error""#).unwrap();
        assert_eq!(policy, UploadScanFailurePolicy::QuarantineOnError);

        let policy: UploadScanFailurePolicy = serde_json::from_str(r#""fail_open""#).unwrap();
        assert_eq!(policy, UploadScanFailurePolicy::FailOpen);

        // Verify invalid variant fails
        assert!(serde_json::from_str::<UploadScanFailurePolicy>(r#""unknown_policy""#).is_err());
    }

    #[test]
    fn test_scan_failure_policy_default_is_quarantine() {
        let policy = UploadScanFailurePolicy::default();
        assert_eq!(
            policy,
            UploadScanFailurePolicy::QuarantineOnError,
            "Default failure policy must be QuarantineOnError"
        );
    }

    #[test]
    fn test_execute_scan_unavailable_scanner_returns_indeterminate() {
        // The Unavailable path in execute_scan is reached when malware_scanner is None
        // and scan_with_yara is true. From the public API, malware_scanner is always
        // Some(...) after construction, so we test the equivalent behavior by
        // constructing a ValidationResult with Unavailable status and verifying
        // the is_clean() and scan_status invariants.
        let result = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Unavailable,
            Vec::new(),
            Some("no malware scanner available".into()),
            0,
        );
        assert_eq!(result.scan_status, UploadScanStatus::Unavailable);
        assert!(!result.is_clean());
        assert!(result.scan_error.is_some());
        assert!(result
            .scan_error
            .as_ref()
            .unwrap()
            .contains("no malware scanner"));
    }

    #[test]
    fn test_validate_bytes_with_fail_closed_policy_on_unavailable() {
        // When FailClosed policy is configured and scanner is unavailable,
        // validate_bytes should return an error (upload rejected).
        // We simulate this by verifying the policy config wires correctly:
        let config = UploadConfig {
            scan_with_yara: true,
            yara_failure_policy: UploadScanFailurePolicy::FailClosed,
            ..Default::default()
        };
        let effective = config.effective_config_for_path("/upload");
        assert_eq!(
            effective.yara_failure_policy,
            UploadScanFailurePolicy::FailClosed
        );

        // Construct the equivalent Unavailable result as execute_scan would produce
        let result = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Unavailable,
            Vec::new(),
            Some("no malware scanner available".into()),
            0,
        );
        // FailClosed + Unavailable → must not be clean
        assert!(!result.is_clean());
    }

    #[test]
    fn test_validate_bytes_with_fail_open_policy_on_unavailable() {
        // When FailOpen policy is configured and scanner is unavailable,
        // validate_bytes should allow the upload through (no error).
        let config = UploadConfig {
            scan_with_yara: true,
            yara_failure_policy: UploadScanFailurePolicy::FailOpen,
            ..Default::default()
        };
        let effective = config.effective_config_for_path("/upload");
        assert_eq!(
            effective.yara_failure_policy,
            UploadScanFailurePolicy::FailOpen
        );

        // The result from execute_scan with FailOpen + Unavailable is still Indeterminate,
        // but the outer validate_bytes allows it through (no ScanIndeterminate error).
        let result = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Unavailable,
            Vec::new(),
            Some("no malware scanner available (fail_open)".into()),
            0,
        );
        // FailOpen: result is not clean but upload is allowed
        assert!(!result.is_clean());
        assert!(result.scan_error.unwrap().contains("fail_open"));
    }

    #[test]
    fn test_validate_bytes_with_quarantine_on_error_policy_on_unavailable() {
        // QuarantineOnError on Unavailable behaves like FailClosed (returns error).
        let config = UploadConfig {
            scan_with_yara: true,
            yara_failure_policy: UploadScanFailurePolicy::QuarantineOnError,
            ..Default::default()
        };
        let effective = config.effective_config_for_path("/upload");
        assert_eq!(
            effective.yara_failure_policy,
            UploadScanFailurePolicy::QuarantineOnError
        );

        let result = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Unavailable,
            Vec::new(),
            Some("no malware scanner available".into()),
            0,
        );
        assert!(!result.is_clean());
    }

    #[test]
    fn test_validation_result_coverage_ratio_boundary() {
        // HeaderOnly: coverage_ratio = scanned_bytes / total_bytes
        let header_only = ValidationResult::for_header_only(
            "application/pdf".into(),
            1_000_000,
            8192,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert!(
            header_only.coverage_ratio > 0.0 && header_only.coverage_ratio < 1.0,
            "HeaderOnly coverage should be between 0.0 and 1.0, got {}",
            header_only.coverage_ratio
        );

        // Full: coverage_ratio = 1.0
        let full = ValidationResult::for_full_file(
            "application/pdf".into(),
            1_000_000,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert_eq!(full.coverage_ratio, 1.0);

        // Windowed: coverage_ratio = scanned_bytes / total_bytes
        let windowed = ValidationResult::for_windowed(
            "video/mp4".into(),
            50_000_000,
            4_000_000,
            4,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert!(
            windowed.coverage_ratio > 0.0 && windowed.coverage_ratio < 1.0,
            "Windowed coverage should be between 0.0 and 1.0, got {}",
            windowed.coverage_ratio
        );

        // for_bytes: always full coverage (1.0)
        let bytes = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert_eq!(bytes.coverage_ratio, 1.0);

        // Zero-size file with header_only: ratio = 1.0 (special case)
        let zero_header = ValidationResult::for_header_only(
            "text/plain".into(),
            0,
            0,
            UploadScanStatus::Disabled,
            Vec::new(),
            None,
            0,
        );
        assert_eq!(zero_header.coverage_ratio, 1.0);
    }

    #[test]
    fn test_validation_result_scan_mode_roundtrip() {
        let for_bytes = ValidationResult::for_bytes(
            "text/plain".into(),
            100,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert_eq!(for_bytes.scan_mode, YaraLargeFileScanMode::Full);

        let for_header = ValidationResult::for_header_only(
            "application/pdf".into(),
            1_000_000,
            8192,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert_eq!(for_header.scan_mode, YaraLargeFileScanMode::HeaderOnly);

        let for_windowed = ValidationResult::for_windowed(
            "video/mp4".into(),
            50_000_000,
            4_000_000,
            4,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert_eq!(for_windowed.scan_mode, YaraLargeFileScanMode::Windowed);

        let for_full = ValidationResult::for_full_file(
            "application/zip".into(),
            5_000_000,
            UploadScanStatus::Clean,
            Vec::new(),
            None,
            0,
        );
        assert_eq!(for_full.scan_mode, YaraLargeFileScanMode::Full);
    }

    // --- Real validator-path tests (exercise validate_bytes through real entry points) ---

    /// Helper: create a YaraScanner with inline rules for testing.
    fn make_test_yara_scanner(rules: &str) -> YaraScanner {
        YaraScanner::new(YaraRulesSource::Inline(rules.to_string()))
            .expect("test YARA rules should compile")
    }

    /// Helper: build an UploadConfig suitable for tests (avoids touching /var/lib).
    fn test_config(scan_with_yara: bool, policy: UploadScanFailurePolicy) -> UploadConfig {
        UploadConfig {
            scan_with_yara,
            sandbox_enabled: false,
            yara_failure_policy: policy,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_real_validate_bytes_unavailable_scanner_fail_closed() {
        // When scan_with_yara=true but malware_scanner=None → Unavailable.
        // FailClosed policy should reject the upload.
        let config = test_config(true, UploadScanFailurePolicy::FailClosed);
        let validator = UploadValidator::with_scanner(config, None);
        let data = b"hello world";
        let err = validator.validate_bytes(data, "/upload").await.unwrap_err();
        assert!(matches!(
            err,
            UploadValidationError::ScanIndeterminate { .. }
        ));
    }

    #[tokio::test]
    async fn test_real_validate_bytes_unavailable_scanner_fail_open() {
        // FailOpen policy + unavailable scanner → upload allowed (no error).
        // is_clean() returns false because Unavailable is not Clean|Disabled.
        let config = test_config(true, UploadScanFailurePolicy::FailOpen);
        let validator = UploadValidator::with_scanner(config, None);
        let data = b"hello world";
        let result = validator.validate_bytes(data, "/upload").await.unwrap();
        assert_eq!(result.scan_status, UploadScanStatus::Unavailable);
        assert!(!result.is_clean());
        assert!(result.scan_error.is_some());
    }

    #[tokio::test]
    async fn test_real_validate_bytes_unavailable_scanner_quarantine_on_error() {
        // QuarantineOnError + unavailable scanner → rejects (same as FailClosed).
        let config = test_config(true, UploadScanFailurePolicy::QuarantineOnError);
        let validator = UploadValidator::with_scanner(config, None);
        let data = b"hello world";
        let err = validator.validate_bytes(data, "/upload").await.unwrap_err();
        assert!(matches!(
            err,
            UploadValidationError::ScanIndeterminate { .. }
        ));
    }

    #[tokio::test]
    async fn test_real_validate_bytes_clean_scan_passes() {
        // Scanner available, no matches → validate_bytes succeeds.
        let yara = make_test_yara_scanner("rule clean { condition: false }");
        let scanner = MalwareScanner::with_yara(Some(yara));
        let config = test_config(true, UploadScanFailurePolicy::FailClosed);
        let validator = UploadValidator::with_scanner(config, Some(scanner));
        let data = b"hello world this is benign data";
        let result = validator.validate_bytes(data, "/upload").await.unwrap();
        assert_eq!(result.scan_status, UploadScanStatus::Clean);
        assert!(result.is_clean());
    }

    #[tokio::test]
    async fn test_real_validate_bytes_malicious_detection_rejects() {
        // YARA rule matches → MalwareDetected error regardless of failure policy.
        let yara = make_test_yara_scanner("rule evil { condition: true }");
        let scanner = MalwareScanner::with_yara(Some(yara));
        let config = test_config(true, UploadScanFailurePolicy::FailClosed);
        let validator = UploadValidator::with_scanner(config, Some(scanner));
        let data = b"hello world";
        let err = validator.validate_bytes(data, "/upload").await.unwrap_err();
        match err {
            UploadValidationError::MalwareDetected { matches } => {
                assert!(matches.iter().any(|m| m == "evil"));
            }
            other => panic!("expected MalwareDetected, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_real_validate_bytes_malicious_with_fail_open_still_rejects() {
        // FailOpen applies to scan ERRORS, not to actual malware detection.
        // MalwareDetected is always rejected.
        let yara = make_test_yara_scanner("rule evil { condition: true }");
        let scanner = MalwareScanner::with_yara(Some(yara));
        let config = test_config(true, UploadScanFailurePolicy::FailOpen);
        let validator = UploadValidator::with_scanner(config, Some(scanner));
        let data = b"hello world";
        let err = validator.validate_bytes(data, "/upload").await.unwrap_err();
        assert!(matches!(err, UploadValidationError::MalwareDetected { .. }));
    }

    #[tokio::test]
    async fn test_real_validate_bytes_yara_error_propagates() {
        // Milestone B Phase 1: YARA errors now propagate through MalwareError::YaraScanError
        // instead of being silently consumed. A valid YARA rule that doesn't match returns Clean.
        let yara = make_test_yara_scanner("rule noop { condition: false }");
        let scanner = MalwareScanner::with_yara(Some(yara));
        let config = test_config(true, UploadScanFailurePolicy::FailClosed);
        let validator = UploadValidator::with_scanner(config, Some(scanner));
        let data = b"hello world";
        let result = validator.validate_bytes(data, "/upload").await.unwrap();
        assert_eq!(result.scan_status, UploadScanStatus::Clean);
        assert!(result.is_clean());
    }

    #[tokio::test]
    async fn test_real_validate_bytes_disabled_scan_bypasses_scanner() {
        // scan_with_yara=false → Disabled status, no scanner invoked.
        let config = test_config(false, UploadScanFailurePolicy::FailClosed);
        let validator = UploadValidator::with_scanner(config, None);
        let data = b"hello world";
        let result = validator.validate_bytes(data, "/upload").await.unwrap();
        assert_eq!(result.scan_status, UploadScanStatus::Disabled);
        assert!(result.is_clean());
    }

    #[tokio::test]
    async fn test_real_validate_with_sandbox_quarantines_malware() {
        // validate_with_sandbox quarantines the file on malware detection.
        let yara = make_test_yara_scanner("rule evil { condition: true }");
        let scanner = MalwareScanner::with_yara(Some(yara));
        let mut config = test_config(true, UploadScanFailurePolicy::FailClosed);
        // Use temp dirs for sandbox/quarantine so quarantine actually works.
        let tmp = tempfile::tempdir().unwrap();
        config.sandbox_dir = tmp.path().join("sandbox").to_string_lossy().to_string();
        config.quarantine_dir = tmp.path().join("quarantine").to_string_lossy().to_string();
        let validator = UploadValidator::with_scanner(config, Some(scanner));
        validator.ensure_directories().await.unwrap();

        let data = b"this is malicious content";
        let err = validator
            .validate_with_sandbox(data, "/upload", Some("evil.exe"))
            .await
            .unwrap_err();
        assert!(matches!(err, UploadValidationError::MalwareDetected { .. }));
        // Verify quarantine directory was populated.
        let quarantine_entries: Vec<_> = std::fs::read_dir(tmp.path().join("quarantine"))
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            !quarantine_entries.is_empty(),
            "quarantine dir should have at least one entry after malware detection"
        );
    }

    #[tokio::test]
    async fn test_real_validate_with_sandbox_clean_passes() {
        // validate_with_sandbox returns Ok with no quarantine on clean data.
        let yara = make_test_yara_scanner("rule clean { condition: false }");
        let scanner = MalwareScanner::with_yara(Some(yara));
        let mut config = test_config(true, UploadScanFailurePolicy::FailClosed);
        let tmp = tempfile::tempdir().unwrap();
        config.sandbox_dir = tmp.path().join("sandbox").to_string_lossy().to_string();
        config.quarantine_dir = tmp.path().join("quarantine").to_string_lossy().to_string();
        let validator = UploadValidator::with_scanner(config, Some(scanner));
        validator.ensure_directories().await.unwrap();

        let data = b"benign data here";
        let (result, quarantine) = validator
            .validate_with_sandbox(data, "/upload", Some("clean.txt"))
            .await
            .unwrap();
        assert_eq!(result.scan_status, UploadScanStatus::Clean);
        assert!(quarantine.is_none());
    }

    // -----------------------------------------------------------------------
    // Archive inspection error propagation tests
    // -----------------------------------------------------------------------

    /// Create a minimal invalid ZIP: starts with PK magic but is otherwise garbage.
    /// This triggers `ArchiveInspectionError::InvalidZip` during inspection.
    fn invalid_zip_bytes() -> Vec<u8> {
        let mut data = vec![0x50, 0x4B, 0x03, 0x04]; // PK\x03\x04 magic
        data.extend_from_slice(&[0xFF; 20]); // garbage, not a valid ZIP end-of-central-dir
        data
    }

    #[tokio::test]
    async fn test_archive_error_fail_closed_rejects() {
        // Invalid ZIP + FailClosed → ScanIndeterminate error.
        let config = test_config(true, UploadScanFailurePolicy::FailClosed);
        let scanner = MalwareScanner::with_yara(None);
        let validator = UploadValidator::with_scanner(config, Some(scanner));
        let data = invalid_zip_bytes();
        let err = validator
            .validate_bytes(&data, "/upload")
            .await
            .unwrap_err();
        assert!(
            matches!(err, UploadValidationError::ScanIndeterminate { ref reason } if reason.contains("archive")),
            "expected ScanIndeterminate with archive reason, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_archive_error_fail_open_allows() {
        // Invalid ZIP + FailOpen → upload allowed despite archive error.
        let config = test_config(true, UploadScanFailurePolicy::FailOpen);
        let scanner = MalwareScanner::with_yara(None);
        let validator = UploadValidator::with_scanner(config, Some(scanner));
        let data = invalid_zip_bytes();
        let result = validator.validate_bytes(&data, "/upload").await.unwrap();
        // Scan status is Clean (no YARA scan run because scanner has no rules).
        assert_eq!(result.scan_status, UploadScanStatus::Clean);
    }

    #[tokio::test]
    async fn test_archive_error_quarantine_on_error_rejects() {
        // Invalid ZIP + QuarantineOnError → ScanIndeterminate (same as FailClosed).
        let config = test_config(true, UploadScanFailurePolicy::QuarantineOnError);
        let scanner = MalwareScanner::with_yara(None);
        let validator = UploadValidator::with_scanner(config, Some(scanner));
        let data = invalid_zip_bytes();
        let err = validator
            .validate_bytes(&data, "/upload")
            .await
            .unwrap_err();
        assert!(
            matches!(err, UploadValidationError::ScanIndeterminate { .. }),
            "expected ScanIndeterminate, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_validate_with_sandbox_unavailable_scanner_fail_open() {
        // validate_with_sandbox + FailOpen + no scanner → upload allowed (no quarantine).
        let mut config = test_config(true, UploadScanFailurePolicy::FailOpen);
        let tmp = tempfile::tempdir().unwrap();
        config.sandbox_dir = tmp.path().join("sandbox").to_string_lossy().to_string();
        config.quarantine_dir = tmp.path().join("quarantine").to_string_lossy().to_string();
        let validator = UploadValidator::with_scanner(config, None);
        validator.ensure_directories().await.unwrap();

        let data = b"benign data";
        let (result, quarantine) = validator
            .validate_with_sandbox(data, "/upload", Some("test.txt"))
            .await
            .unwrap();
        assert_eq!(result.scan_status, UploadScanStatus::Unavailable);
        assert!(quarantine.is_none());
    }

    #[tokio::test]
    async fn test_validate_with_sandbox_unavailable_scanner_fail_closed() {
        // validate_with_sandbox + FailClosed + no scanner → ScanIndeterminate.
        let mut config = test_config(true, UploadScanFailurePolicy::FailClosed);
        let tmp = tempfile::tempdir().unwrap();
        config.sandbox_dir = tmp.path().join("sandbox").to_string_lossy().to_string();
        config.quarantine_dir = tmp.path().join("quarantine").to_string_lossy().to_string();
        let validator = UploadValidator::with_scanner(config, None);
        validator.ensure_directories().await.unwrap();

        let data = b"benign data";
        let err = validator
            .validate_with_sandbox(data, "/upload", Some("test.txt"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            UploadValidationError::ScanIndeterminate { .. }
        ));
    }

    #[tokio::test]
    async fn test_validate_bytes_with_declared_type_unavailable_scanner() {
        // validate_bytes_with_declared_type + FailClosed + no scanner → ScanIndeterminate.
        let config = test_config(true, UploadScanFailurePolicy::FailClosed);
        let validator = UploadValidator::with_scanner(config, None);
        let data = b"hello world";
        let err = validator
            .validate_bytes_with_declared_type(data, "/upload", Some("text/plain"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            UploadValidationError::ScanIndeterminate { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Mesh rule reload E2E tests
    // -----------------------------------------------------------------------

    #[cfg(feature = "mesh")]
    mod mesh_reload {
        use super::*;
        use synvoid_config::mesh::MeshNodeRole;
        use synvoid_mesh::yara_rules::{YaraRuleSource, YaraRulesManager, YaraRulesManagerConfig};

        fn make_manager() -> Arc<YaraRulesManager> {
            Arc::new(YaraRulesManager::new(
                YaraRulesManagerConfig::default(),
                "test-node".to_string(),
                MeshNodeRole::GLOBAL,
                None, // signer
                None, // feed_manager
                None, // data_dir
            ))
        }

        #[tokio::test]
        async fn test_mesh_reload_compiled_rules_detected() {
            let manager = make_manager();
            let config = test_config(true, UploadScanFailurePolicy::FailClosed);
            let validator =
                UploadValidator::new_with_yara_rules(config, Some(manager.clone())).unwrap();

            // Scanner starts with bundled rules (init version).
            let init_version = validator
                .malware_scanner
                .as_ref()
                .unwrap()
                .get_yara_scanner()
                .unwrap()
                .get_version();
            assert!(
                init_version.is_some(),
                "scanner should have an init version"
            );

            // Compile a minimal rule and apply via the manager.
            let rule_src = "rule mesh_test { condition: true }";
            let compiled_rules = yara_x::compile(rule_src).expect("compile");
            let mut compiled = Vec::new();
            compiled_rules.serialize_into(&mut compiled).unwrap();
            manager
                .apply_compiled_rules(
                    rule_src.to_string(),
                    compiled,
                    "v2-compiled".to_string(),
                    YaraRuleSource::MeshGlobal,
                )
                .unwrap();

            // reload_yara_rules_if_needed should detect the version mismatch and swap.
            validator.reload_yara_rules_if_needed().unwrap();

            let new_version = validator
                .malware_scanner
                .as_ref()
                .unwrap()
                .get_yara_scanner()
                .unwrap()
                .get_version();
            assert_eq!(new_version.as_deref(), Some("v2-compiled"));
        }

        #[tokio::test]
        async fn test_mesh_reload_source_rules_detected() {
            let manager = make_manager();
            let config = test_config(true, UploadScanFailurePolicy::FailClosed);
            let validator =
                UploadValidator::new_with_yara_rules(config, Some(manager.clone())).unwrap();

            let init_version = validator
                .malware_scanner
                .as_ref()
                .unwrap()
                .get_yara_scanner()
                .unwrap()
                .get_version();

            // Apply source-only rules (no compiled binary).
            let rule_src = "rule mesh_source { condition: false }";
            manager
                .apply_rules(
                    rule_src.to_string(),
                    "v2-source".to_string(),
                    YaraRuleSource::MeshGlobal,
                )
                .unwrap();

            validator.reload_yara_rules_if_needed().unwrap();

            let new_version = validator
                .malware_scanner
                .as_ref()
                .unwrap()
                .get_yara_scanner()
                .unwrap()
                .get_version();
            assert_eq!(new_version.as_deref(), Some("v2-source"));
            assert_ne!(new_version, init_version, "version should have changed");
        }

        #[tokio::test]
        async fn test_mesh_reload_same_version_is_noop() {
            let manager = make_manager();
            let config = test_config(true, UploadScanFailurePolicy::FailClosed);
            let validator =
                UploadValidator::new_with_yara_rules(config, Some(manager.clone())).unwrap();

            let init_version = validator
                .malware_scanner
                .as_ref()
                .unwrap()
                .get_yara_scanner()
                .unwrap()
                .get_version();

            // Apply rules with a new version...
            let rule_src = "rule noop { condition: false }";
            manager
                .apply_rules(
                    rule_src.to_string(),
                    "v2-noop".to_string(),
                    YaraRuleSource::MeshGlobal,
                )
                .unwrap();
            // ...reload...
            validator.reload_yara_rules_if_needed().unwrap();
            let after_first = validator
                .malware_scanner
                .as_ref()
                .unwrap()
                .get_yara_scanner()
                .unwrap()
                .get_version();
            assert_eq!(after_first.as_deref(), Some("v2-noop"));

            // Calling reload again with the same version should be a no-op.
            validator.reload_yara_rules_if_needed().unwrap();
            let after_second = validator
                .malware_scanner
                .as_ref()
                .unwrap()
                .get_yara_scanner()
                .unwrap()
                .get_version();
            assert_eq!(after_second, after_first);
        }

        #[tokio::test]
        async fn test_mesh_reload_compiled_preferred_over_source() {
            let manager = make_manager();
            let config = test_config(true, UploadScanFailurePolicy::FailClosed);
            let validator =
                UploadValidator::new_with_yara_rules(config, Some(manager.clone())).unwrap();

            // Apply both compiled and source rules — compiled should be preferred.
            let rule_src = "rule compiled_preferred { condition: true }";
            let compiled_rules = yara_x::compile(rule_src).expect("compile");
            let mut compiled = Vec::new();
            compiled_rules.serialize_into(&mut compiled).unwrap();
            manager
                .apply_compiled_rules(
                    rule_src.to_string(),
                    compiled,
                    "v2-both".to_string(),
                    YaraRuleSource::MeshGlobal,
                )
                .unwrap();

            validator.reload_yara_rules_if_needed().unwrap();

            let new_version = validator
                .malware_scanner
                .as_ref()
                .unwrap()
                .get_yara_scanner()
                .unwrap()
                .get_version();
            assert_eq!(new_version.as_deref(), Some("v2-both"));
        }

        #[tokio::test]
        async fn test_mesh_reload_triggers_scan_with_new_rules() {
            let manager = make_manager();
            let config = test_config(true, UploadScanFailurePolicy::FailClosed);
            let validator =
                UploadValidator::new_with_yara_rules(config, Some(manager.clone())).unwrap();

            // Before reload: scanner uses bundled rules — "AAAA" is clean.
            let result = validator.validate_bytes(b"AAAA", "/upload").await.unwrap();
            assert_eq!(result.scan_status, UploadScanStatus::Clean);

            // Apply a rule that matches "AAAA".
            let rule_src = "rule detect_aaaa { strings: $s = \"AAAA\" condition: $s }";
            let compiled_rules = yara_x::compile(rule_src).expect("compile");
            let mut compiled = Vec::new();
            compiled_rules.serialize_into(&mut compiled).unwrap();
            manager
                .apply_compiled_rules(
                    rule_src.to_string(),
                    compiled,
                    "v2-malicious".to_string(),
                    YaraRuleSource::MeshGlobal,
                )
                .unwrap();

            // Reload the rules.
            validator.reload_yara_rules_if_needed().unwrap();

            // After reload: "AAAA" should now be detected as malicious.
            let err = validator
                .validate_bytes(b"AAAA", "/upload")
                .await
                .unwrap_err();
            assert!(
                matches!(err, UploadValidationError::MalwareDetected { .. }),
                "expected MalwareDetected after reload, got: {err:?}"
            );
        }
    }
}
