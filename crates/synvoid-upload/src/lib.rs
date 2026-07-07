pub mod config;
pub mod malware_scanner;
pub mod metrics;
pub mod rate_limit;
pub mod sandbox;
pub mod signature;
pub mod yara_rule_feed;
pub mod yara_scanner;

pub use config::{
    AllowedTypesConfig, AllowedTypesMode, EffectiveUploadConfig, PathUploadConfig, UploadConfig,
    UploadScanFailurePolicy,
};
pub use malware_scanner::MalwareMatch;
pub use sandbox::{QuarantineEntry, Sandbox, SandboxConfig, SandboxError, SandboxHandle};
pub use signature::{FileCategory, FileSignature, SignatureRegistry};
pub use yara_rule_feed::{ParsedYaraRules, YaraRuleFeedManager, YaraRuleSource};
pub use yara_scanner::{
    YaraError, YaraMatch, YaraRulesSource, YaraScanner, NO_EXCLUDED_CATEGORIES,
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
}

impl ValidationResult {
    pub fn is_clean(&self) -> bool {
        self.yara_matches.is_empty()
            && matches!(
                self.scan_status,
                UploadScanStatus::Clean | UploadScanStatus::Disabled
            )
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
            let scanner =
                YaraScanner::with_timeout(source, config.yara_timeout_ms, 3, 100 * 1024 * 1024)?;
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
            let scanner =
                YaraScanner::with_timeout(source, config.yara_timeout_ms, 3, 100 * 1024 * 1024)?;
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

        Ok(ValidationResult {
            mime_type,
            size: data.len() as u64,
            scanned: scan_status != UploadScanStatus::Disabled,
            yara_matches,
            scan_status,
            scan_error,
        })
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

        Ok(ValidationResult {
            mime_type,
            size: data.len() as u64,
            scanned: scan_status != UploadScanStatus::Disabled,
            yara_matches,
            scan_status,
            scan_error,
        })
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

        Ok((
            ValidationResult {
                mime_type,
                size: data.len() as u64,
                scanned: scan_status != UploadScanStatus::Disabled,
                yara_matches,
                scan_status,
                scan_error,
            },
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

        let header = sandbox_handle.read_header(HEADER_READ_SIZE)?;
        let mime_info = synvoid_app_handlers::mime::detect_from_bytes_with_fallback(&header, "bin");
        let mime_type = mime_info.mime_type.clone();

        if !effective_config.is_mime_allowed(&mime_type) {
            return Err(UploadValidationError::TypeNotAllowed {
                detected: mime_type.clone(),
                allowed: effective_config.allowed_mime_types.clone(),
            });
        }

        let (scan_status, yara_matches, scan_error) =
            self.execute_scan(&header, &effective_config).await;

        if !yara_matches.is_empty() {
            warn!(
                mime_type = %mime_type,
                filename = ?original_filename,
                matches = ?yara_matches,
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

        Ok(ValidationResult {
            mime_type,
            size,
            scanned: scan_status != UploadScanStatus::Disabled,
            yara_matches,
            scan_status,
            scan_error,
        })
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
            let header_end = part
                .windows(2)
                .position(|w| w == [b'\r', b'\n'])
                .map(|p| p + 2);
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
        let clean = ValidationResult {
            mime_type: "text/plain".into(),
            size: 100,
            scanned: true,
            yara_matches: Vec::new(),
            scan_status: UploadScanStatus::Clean,
            scan_error: None,
        };
        assert!(clean.is_clean());

        let disabled = ValidationResult {
            mime_type: "text/plain".into(),
            size: 100,
            scanned: false,
            yara_matches: Vec::new(),
            scan_status: UploadScanStatus::Disabled,
            scan_error: None,
        };
        assert!(disabled.is_clean());

        let indeterminate = ValidationResult {
            mime_type: "text/plain".into(),
            size: 100,
            scanned: true,
            yara_matches: Vec::new(),
            scan_status: UploadScanStatus::Indeterminate,
            scan_error: Some("timeout".into()),
        };
        assert!(!indeterminate.is_clean());

        let unavailable = ValidationResult {
            mime_type: "text/plain".into(),
            size: 100,
            scanned: true,
            yara_matches: Vec::new(),
            scan_status: UploadScanStatus::Unavailable,
            scan_error: Some("no scanner".into()),
        };
        assert!(!unavailable.is_clean());

        let malicious = ValidationResult {
            mime_type: "text/plain".into(),
            size: 100,
            scanned: true,
            yara_matches: vec!["test_rule".into()],
            scan_status: UploadScanStatus::Malicious,
            scan_error: None,
        };
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
}
