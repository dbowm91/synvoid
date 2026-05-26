use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightConfig {
    pub validation_timeout_secs: u64,
    pub require_config_check: bool,
    pub require_capability_check: bool,
    pub min_startup_time_ms: u64,
    pub max_startup_time_ms: u64,
}

impl Default for PreflightConfig {
    fn default() -> Self {
        Self {
            validation_timeout_secs: 30,
            require_config_check: true,
            require_capability_check: true,
            min_startup_time_ms: 100,
            max_startup_time_ms: 10000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreflightResult {
    pub success: bool,
    pub version: String,
    pub startup_time_ms: u64,
    pub config_compatible: bool,
    pub capabilities: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl PreflightResult {
    pub fn is_valid(&self) -> bool {
        self.success && self.errors.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    #[error("Binary not found: {0}")]
    BinaryNotFound(PathBuf),

    #[error("Binary is not executable: {0}")]
    NotExecutable(PathBuf),

    #[error("Binary failed to start: {0}")]
    StartupFailed(String),

    #[error("Binary startup timeout after {0}ms")]
    StartupTimeout(u64),

    #[error("Binary exited unexpectedly with code {0:?}")]
    UnexpectedExit(Option<i32>),

    #[error("Config validation failed: {0}")]
    ConfigValidationFailed(String),

    #[error("Capability check failed: {0}")]
    CapabilityCheckFailed(String),

    #[error("Version extraction failed: {0}")]
    VersionExtractionFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Validation output parse error: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightValidationOutput {
    pub version: String,
    pub config_valid: bool,
    pub config_errors: Vec<String>,
    pub capabilities: Vec<String>,
    pub startup_time_ms: u64,
    pub warnings: Vec<String>,
}

pub struct PreflightValidator {
    config: PreflightConfig,
}

impl Default for PreflightValidator {
    fn default() -> Self {
        Self::new(PreflightConfig::default())
    }
}

impl PreflightValidator {
    pub fn new(config: PreflightConfig) -> Self {
        Self { config }
    }

    pub fn validate_binary(
        &self,
        binary_path: &PathBuf,
        config_path: Option<&PathBuf>,
    ) -> Result<PreflightResult, PreflightError> {
        if !binary_path.exists() {
            return Err(PreflightError::BinaryNotFound(binary_path.clone()));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(binary_path)?;
            let mode = metadata.permissions().mode();
            if (mode & 0o111) == 0 {
                return Err(PreflightError::NotExecutable(binary_path.clone()));
            }
        }

        let version = self.extract_version(binary_path)?;

        let config_compatible = if self.config.require_config_check {
            if let Some(cfg_path) = config_path {
                self.validate_config_compatibility(binary_path, cfg_path)?
            } else {
                true
            }
        } else {
            true
        };

        let capabilities = if self.config.require_capability_check {
            self.check_capabilities(binary_path)?
        } else {
            vec![]
        };

        let startup_result = self.test_binary_startup(binary_path, config_path)?;

        let mut warnings = startup_result.warnings;
        let mut errors = Vec::new();

        if !config_compatible {
            errors.push("Config compatibility check failed".to_string());
        }

        if !startup_result.config_valid {
            warnings.push(format!(
                "Config validation warnings: {:?}",
                startup_result.config_errors
            ));
        }

        if startup_result.startup_time_ms < self.config.min_startup_time_ms {
            warnings.push(format!(
                "Startup time {}ms is suspiciously fast (min expected: {}ms)",
                startup_result.startup_time_ms, self.config.min_startup_time_ms
            ));
        }

        if startup_result.startup_time_ms > self.config.max_startup_time_ms {
            warnings.push(format!(
                "Startup time {}ms is slow (max expected: {}ms)",
                startup_result.startup_time_ms, self.config.max_startup_time_ms
            ));
        }

        let success = errors.is_empty();

        Ok(PreflightResult {
            success,
            version,
            startup_time_ms: startup_result.startup_time_ms,
            config_compatible,
            capabilities,
            warnings,
            errors,
        })
    }

    fn extract_version(&self, binary_path: &PathBuf) -> Result<String, PreflightError> {
        let output = Command::new(binary_path)
            .arg("--version")
            .output()
            .map_err(|e| PreflightError::VersionExtractionFailed(e.to_string()))?;

        if !output.status.success() {
            return Ok("unknown".to_string());
        }

        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(if version.is_empty() {
            "unknown".to_string()
        } else {
            version
        })
    }

    fn validate_config_compatibility(
        &self,
        binary_path: &PathBuf,
        config_path: &PathBuf,
    ) -> Result<bool, PreflightError> {
        if !config_path.exists() {
            return Ok(true);
        }

        let output = Command::new(binary_path)
            .arg("--preflight-validate")
            .arg("--config-path")
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match output {
            Ok(out) => {
                if out.status.success() {
                    if let Ok(validation) =
                        serde_json::from_slice::<PreflightValidationOutput>(&out.stdout)
                    {
                        return Ok(validation.config_valid);
                    }
                    Ok(true)
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!("Config validation returned non-zero: {}", stderr);
                    Ok(false)
                }
            }
            Err(e) => {
                tracing::debug!("Config validation command failed (older binary?): {}", e);
                Ok(true)
            }
        }
    }

    fn check_capabilities(&self, binary_path: &PathBuf) -> Result<Vec<String>, PreflightError> {
        let capabilities = vec![
            "http1".to_string(),
            "http2".to_string(),
            "websocket".to_string(),
            "tls".to_string(),
        ];

        let output = Command::new(binary_path)
            .arg("--preflight-validate")
            .arg("--check-capabilities")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match output {
            Ok(out) => {
                if out.status.success() {
                    if let Ok(validation) =
                        serde_json::from_slice::<PreflightValidationOutput>(&out.stdout)
                    {
                        return Ok(validation.capabilities);
                    }
                }
                Ok(capabilities)
            }
            Err(e) => {
                tracing::debug!("Capability check failed (older binary?): {}", e);
                Ok(capabilities)
            }
        }
    }

    fn test_binary_startup(
        &self,
        binary_path: &PathBuf,
        config_path: Option<&PathBuf>,
    ) -> Result<PreflightValidationOutput, PreflightError> {
        let start = Instant::now();
        let timeout = Duration::from_secs(self.config.validation_timeout_secs);

        let mut cmd = Command::new(binary_path);
        cmd.arg("--preflight-validate")
            .arg("--startup-test")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(cfg) = config_path {
            cmd.arg("--config-path").arg(cfg);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| PreflightError::StartupFailed(e.to_string()))?;

        loop {
            if start.elapsed() >= timeout {
                let _ = child.kill();
                return Err(PreflightError::StartupTimeout(timeout.as_millis() as u64));
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    let startup_time_ms = start.elapsed().as_millis() as u64;

                    if status.success() {
                        let output = child
                            .wait_with_output()
                            .map_err(|e| PreflightError::StartupFailed(e.to_string()))?;

                        if let Ok(validation) =
                            serde_json::from_slice::<PreflightValidationOutput>(&output.stdout)
                        {
                            return Ok(validation);
                        }

                        return Ok(PreflightValidationOutput {
                            version: "unknown".to_string(),
                            config_valid: true,
                            config_errors: vec![],
                            capabilities: vec![],
                            startup_time_ms,
                            warnings: vec![],
                        });
                    } else {
                        let output = child
                            .wait_with_output()
                            .map_err(|e| PreflightError::StartupFailed(e.to_string()))?;

                        let stderr = String::from_utf8_lossy(&output.stderr);
                        return Err(PreflightError::StartupFailed(stderr.to_string()));
                    }
                }
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(PreflightError::StartupFailed(e.to_string()));
                }
            }
        }
    }

    pub fn quick_validate(binary_path: &PathBuf) -> Result<bool, PreflightError> {
        if !binary_path.exists() {
            return Err(PreflightError::BinaryNotFound(binary_path.clone()));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(binary_path)?;
            let mode = metadata.permissions().mode();
            if (mode & 0o111) == 0 {
                return Err(PreflightError::NotExecutable(binary_path.clone()));
            }
        }

        let output = Command::new(binary_path)
            .arg("--version")
            .output()
            .map_err(PreflightError::IoError)?;

        Ok(output.status.success())
    }
}

pub fn run_preflight_validation(
    config_path: Option<&PathBuf>,
    check_capabilities: bool,
    startup_test: bool,
) -> Result<PreflightValidationOutput, Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static STARTUP_TIME: AtomicU64 = AtomicU64::new(0);
    let start = Instant::now();

    let config_valid = if let Some(path) = config_path {
        if path.exists() {
            let mut config_manager = ConfigManager::new(path.clone());
            config_manager.load_main(path.join("main.toml")).is_ok()
        } else {
            false
        }
    } else {
        true
    };

    let capabilities = if check_capabilities {
        vec![
            "http1".to_string(),
            "http2".to_string(),
            "websocket".to_string(),
            "tls".to_string(),
        ]
    } else {
        vec![]
    };

    if startup_test {
        let version = env!("CARGO_PKG_VERSION").to_string();
        STARTUP_TIME.store(start.elapsed().as_millis() as u64, Ordering::SeqCst);

        let output = PreflightValidationOutput {
            version,
            config_valid,
            config_errors: vec![],
            capabilities,
            startup_time_ms: STARTUP_TIME.load(Ordering::SeqCst),
            warnings: vec![],
        };

        let json = serde_json::to_string(&output)?;
        println!("{}", json);
        std::process::exit(0);
    }

    let version = env!("CARGO_PKG_VERSION").to_string();
    let output = PreflightValidationOutput {
        version,
        config_valid,
        config_errors: vec![],
        capabilities,
        startup_time_ms: start.elapsed().as_millis() as u64,
        warnings: vec![],
    };

    Ok(output)
}

use crate::config::ConfigManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preflight_config_defaults() {
        let config = PreflightConfig::default();
        assert_eq!(config.validation_timeout_secs, 30);
        assert!(config.require_config_check);
        assert!(config.require_capability_check);
    }

    #[test]
    fn test_preflight_result_is_valid() {
        let result = PreflightResult {
            success: true,
            version: "1.0.0".to_string(),
            startup_time_ms: 500,
            config_compatible: true,
            capabilities: vec![],
            warnings: vec![],
            errors: vec![],
        };
        assert!(result.is_valid());

        let result_with_errors = PreflightResult {
            success: true,
            version: "1.0.0".to_string(),
            startup_time_ms: 500,
            config_compatible: false,
            capabilities: vec![],
            warnings: vec![],
            errors: vec!["Config failed".to_string()],
        };
        assert!(!result_with_errors.is_valid());
    }
}
