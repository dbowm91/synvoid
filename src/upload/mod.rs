pub mod config;
pub mod sandbox;
pub mod yara_scanner;

pub use config::{AllowedTypesConfig, AllowedTypesMode, EffectiveUploadConfig, PathUploadConfig, UploadConfig};
pub use sandbox::{QuarantineEntry, Sandbox, SandboxConfig, SandboxError, SandboxHandle};
pub use yara_scanner::{YaraError, YaraMatch, YaraScanResult, YaraScanner};

use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};

const HEADER_READ_SIZE: usize = 8192;

#[derive(Debug, Error)]
pub enum UploadValidationError {
    #[error("Upload size {actual} exceeds maximum {max}")]
    SizeExceeded { max: u64, actual: u64 },

    #[error("MIME type '{detected}' is not allowed")]
    TypeNotAllowed { detected: String, allowed: Vec<String> },

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
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub mime_type: String,
    pub size: u64,
    pub scanned: bool,
    pub yara_matches: Vec<String>,
}

impl ValidationResult {
    pub fn is_clean(&self) -> bool {
        self.yara_matches.is_empty()
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
    yara_scanner: Option<Arc<YaraScanner>>,
    config: UploadConfig,
}

impl UploadValidator {
    pub fn new(config: UploadConfig) -> Result<Self, UploadValidationError> {
        let sandbox_config = SandboxConfig::new(&config.sandbox_dir, &config.quarantine_dir);
        let sandbox = Arc::new(Sandbox::new(sandbox_config));

        let yara_scanner = if config.scan_with_yara {
            let scanner = if let Some(rules_dir) = &config.yara_rules_dir {
                let path = Path::new(rules_dir);
                if path.exists() {
                    YaraScanner::with_rules_from_dir(path)?
                } else {
                    YaraScanner::with_embedded_rules()?
                }
            } else {
                YaraScanner::with_embedded_rules()?
            };
            Some(Arc::new(scanner))
        } else {
            None
        };

        Ok(Self {
            sandbox,
            yara_scanner,
            config,
        })
    }

    pub async fn ensure_directories(&self) -> std::io::Result<()> {
        self.sandbox.config.ensure_dirs_exist().await
    }

    pub fn validate_bytes(&self, data: &[u8], request_path: &str) -> Result<ValidationResult, UploadValidationError> {
        let effective_config = self.config.effective_config_for_path(request_path);

        if data.len() as u64 > effective_config.max_size_bytes {
            return Err(UploadValidationError::SizeExceeded {
                max: effective_config.max_size_bytes,
                actual: data.len() as u64,
            });
        }

        let mime_info = crate::mime::detect_from_bytes_with_fallback(data, "bin");
        let mime_type = mime_info.mime_type.clone();

        if !crate::mime::global_registry()
            .read()
            .is_mime_allowed(&mime_type, &effective_config.allowed_mime_types)
        {
            return Err(UploadValidationError::TypeNotAllowed {
                detected: mime_type.clone(),
                allowed: effective_config.allowed_mime_types,
            });
        }

        let (scanned, yara_matches) = if effective_config.scan_with_yara {
            if let Some(scanner) = &self.yara_scanner {
                let result = scanner.scan_bytes(data)?;
                let matches = result.matched_rule_names();
                (true, matches)
            } else {
                (false, Vec::new())
            }
        } else {
            (false, Vec::new())
        };

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

        Ok(ValidationResult {
            mime_type,
            size: data.len() as u64,
            scanned,
            yara_matches,
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

        self.validate_bytes(&data, request_path)
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

        let mime_info = crate::mime::detect_from_bytes_with_fallback(data, "bin");
        let mime_type = mime_info.mime_type.clone();

        if !crate::mime::global_registry()
            .read()
            .is_mime_allowed(&mime_type, &effective_config.allowed_mime_types)
        {
            return Err(UploadValidationError::TypeNotAllowed {
                detected: mime_type.clone(),
                allowed: effective_config.allowed_mime_types,
            });
        }

        let (scanned, yara_matches) = if effective_config.scan_with_yara {
            if let Some(scanner) = &self.yara_scanner {
                let result = scanner.scan_bytes(data)?;
                let matches = result.matched_rule_names();
                (true, matches)
            } else {
                (false, Vec::new())
            }
        } else {
            (false, Vec::new())
        };

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

            let quarantine_entry = self
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

        Ok((
            ValidationResult {
                mime_type,
                size: data.len() as u64,
                scanned,
                yara_matches,
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

        let header = sandbox_handle.read_header(HEADER_READ_SIZE)?;
        let mime_info = crate::mime::detect_from_bytes_with_fallback(&header, "bin");
        let mime_type = mime_info.mime_type.clone();

        if !crate::mime::global_registry()
            .read()
            .is_mime_allowed(&mime_type, &effective_config.allowed_mime_types)
        {
            return Err(UploadValidationError::TypeNotAllowed {
                detected: mime_type.clone(),
                allowed: effective_config.allowed_mime_types,
            });
        }

        let (scanned, yara_matches) = if effective_config.scan_with_yara {
            if let Some(scanner) = &self.yara_scanner {
                let result = scanner.scan_file_with_fallback(sandbox_handle.path())?;
                let matches = result.matched_rule_names();
                (true, matches)
            } else {
                (false, Vec::new())
            }
        } else {
            (false, Vec::new())
        };

        if !yara_matches.is_empty() {
            warn!(
                mime_type = %mime_type,
                filename = ?original_filename,
                matches = ?yara_matches,
                "Malware detected in large file, quarantining"
            );

            let quarantine_entry = self
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

        Ok(ValidationResult {
            mime_type,
            size,
            scanned,
            yara_matches,
        })
    }
}

pub fn is_upload_content_type(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("multipart/form-data")
}

pub fn parse_content_length(content_length: Option<&str>) -> Option<u64> {
    content_length.and_then(|s| s.parse::<u64>().ok())
}

pub fn should_validate_upload(content_type: Option<&str>, content_length: Option<&str>, config: &UploadConfig) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_upload_content_type() {
        assert!(is_upload_content_type("multipart/form-data"));
        assert!(is_upload_content_type("multipart/form-data; boundary=----WebKitFormBoundary"));
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
}
