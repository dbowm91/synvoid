// Submodule: WAF background tasks, UploadValidator initialization, and
// port-honeypot setup.

use std::sync::Arc;

use crate::honeypot_port::{PortHoneypotConfig, PortHoneypotRunner};
use crate::server::UnifiedServer;
use synvoid_config::ConfigManager;
use synvoid_upload::UploadValidator;
use tokio::sync::RwLock;

/// Start background tasks for WAF components (ASN cleanup, etc.).
pub fn start_waf_background_tasks(unified_server: &Arc<UnifiedServer>) {
    unified_server.get_waf().start_background_tasks();
}

/// Build the [`UploadValidator`] from main config defaults and register it
/// as the WAF's upload validator. Failures are logged and ignored.
pub async fn init_upload_validator(config: &Arc<RwLock<ConfigManager>>) {
    let upload_config = {
        let config = config.read().await;
        let defaults = &config.main.defaults.upload;
        synvoid_upload::UploadConfig {
            enabled: defaults.enabled,
            max_size: defaults.max_size.clone(),
            memory_threshold: defaults.memory_threshold.clone(),
            scan_with_yara: defaults.scan_with_yara,
            sandbox_enabled: defaults.sandbox_enabled,
            sandbox_dir: defaults.sandbox_dir.clone(),
            quarantine_dir: defaults.quarantine_dir.clone(),
            yara_rules_dir: defaults.yara_rules_dir.clone(),
            yara_timeout_ms: defaults.yara_timeout_ms,
            verify_signature: true,
            signature_strict_mode: false,
            rate_limit_enabled: true,
            max_uploads_per_minute: 30,
            max_uploads_per_hour: 200,
            max_bytes_per_minute: "100MB".to_string(),
            burst_allowance: 5,
            allowed_types: synvoid_upload::AllowedTypesConfig {
                mode: synvoid_upload::AllowedTypesMode::Allowlist,
                mime_types: defaults.allowed_types.mime_types.clone(),
            },
            paths: Vec::new(),
            reject_mime_mismatch: false,
            yara_failure_policy: match defaults.yara_failure_policy.as_str() {
                "fail_closed" => synvoid_upload::UploadScanFailurePolicy::FailClosed,
                "fail_open" => synvoid_upload::UploadScanFailurePolicy::FailOpen,
                _ => synvoid_upload::UploadScanFailurePolicy::QuarantineOnError,
            },
            yara_large_file_scan_mode: match defaults.yara_large_file_scan_mode.as_str() {
                "windowed" => synvoid_upload::YaraLargeFileScanMode::Windowed,
                "header_only" => synvoid_upload::YaraLargeFileScanMode::HeaderOnly,
                _ => synvoid_upload::YaraLargeFileScanMode::Full,
            },
            yara_window_size_bytes: defaults.yara_window_size_bytes,
            yara_max_window_count: defaults.yara_max_window_count,
            yara_magic_scan_limit_bytes: defaults.yara_magic_scan_limit_bytes,
            yara_max_concurrent_scans: defaults.yara_max_concurrent_scans,
            yara_max_queued_scans: defaults.yara_max_queued_scans,
            yara_queue_timeout_ms: defaults.yara_queue_timeout_ms,
        }
    };

    match UploadValidator::new(upload_config) {
        Ok(validator) => {
            let validator = Arc::new(validator);
            crate::waf::set_upload_validator(validator);
            tracing::info!("UploadValidator initialized");
        }
        Err(e) => {
            tracing::warn!("Failed to initialize UploadValidator: {}", e);
        }
    }
}

/// Build a [`PortHoneypotRunner`] from main config defaults. Returns
/// `None` if disabled or if the runner fails to start.
pub async fn build_port_honeypot(
    config: &Arc<RwLock<ConfigManager>>,
) -> Option<Arc<PortHoneypotRunner>> {
    let honeypot_port_config = {
        let config = config.read().await;
        config.main.honeypot_port.clone()
    };

    if !honeypot_port_config.enabled {
        tracing::info!("Port honeypot is disabled");
        return None;
    }

    let port_honeypot_config = PortHoneypotConfig {
        enabled: honeypot_port_config.enabled,
        min_port: honeypot_port_config
            .ports
            .iter()
            .copied()
            .min()
            .unwrap_or(10000),
        max_port: honeypot_port_config
            .ports
            .iter()
            .copied()
            .max()
            .unwrap_or(60000),
        num_honeypot_ports: honeypot_port_config.ports.len(),
        site_scope: honeypot_port_config.site_scope.clone(),
        ..Default::default()
    };

    match PortHoneypotRunner::new(port_honeypot_config) {
        Ok(runner) => {
            tracing::info!("Port honeypot runner initialized");
            Some(runner)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize port honeypot runner: {}", e);
            None
        }
    }
}

/// Spawn the port-honeypot background task.
pub fn spawn_port_honeypot(port_honeypot_runner: Option<Arc<PortHoneypotRunner>>) {
    if let Some(runner) = port_honeypot_runner {
        let runner_clone = runner.clone();
        tokio::spawn(async move {
            runner_clone.run().await;
        });
    }
}
