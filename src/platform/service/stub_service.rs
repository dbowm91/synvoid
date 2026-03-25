use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::platform::PlatformError;

pub const SERVICE_NAME: &str = "maluwaf";
pub const SERVICE_DISPLAY_NAME: &str = "MaluWAF Web Application Firewall";
pub const SERVICE_DESCRIPTION: &str =
    "High-performance Web Application Firewall with advanced attack detection and bot mitigation";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum ServiceState {
    #[default]
    Stopped,
    Running,
}


#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub auto_start: bool,
    pub binary_path: Option<PathBuf>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: SERVICE_NAME.to_string(),
            display_name: SERVICE_DISPLAY_NAME.to_string(),
            description: SERVICE_DESCRIPTION.to_string(),
            auto_start: true,
            binary_path: None,
        }
    }
}

impl ServiceConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

pub trait ServiceControl: Send + Sync {
    fn install(&self, _config: &ServiceConfig) -> Result<(), PlatformError>;
    fn uninstall(&self, _name: &str) -> Result<(), PlatformError>;
    fn start(&self, _name: &str) -> Result<(), PlatformError>;
    fn stop(&self, _name: &str) -> Result<(), PlatformError>;
    fn status(&self, _name: &str) -> Result<ServiceState, PlatformError>;
    fn is_installed(&self, _name: &str) -> bool;
}

pub struct UnixServiceManager {
    running: Arc<AtomicBool>,
}

impl UnixServiceManager {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Default for UnixServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceControl for UnixServiceManager {
    fn install(&self, config: &ServiceConfig) -> Result<(), PlatformError> {
        let service_file = if cfg!(target_os = "linux") {
            format!("/etc/systemd/system/{}.service", config.name)
        } else if cfg!(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )) {
            format!("/usr/local/etc/rc.d/{}", config.name)
        } else {
            return Err(PlatformError::NotSupported(
                "Service installation not supported on this platform".to_string(),
            ));
        };

        tracing::info!(
            "Service '{}' would be installed at: {}",
            config.name,
            service_file
        );
        tracing::info!("Use your system's service manager to install MaluWAF as a service.");

        Err(PlatformError::NotSupported(
            "Automatic service installation not implemented. Please use your system's service manager (systemd, rc.d, etc.)".to_string(),
        ))
    }

    fn uninstall(&self, name: &str) -> Result<(), PlatformError> {
        tracing::info!("Service '{}' uninstall requested", name);
        Err(PlatformError::NotSupported(
            "Automatic service uninstallation not implemented. Please use your system's service manager.".to_string(),
        ))
    }

    fn start(&self, name: &str) -> Result<(), PlatformError> {
        let cmd = if cfg!(target_os = "linux") {
            format!("systemctl start {}", name)
        } else {
            format!("service {} start", name)
        };

        tracing::info!("Start service with: {}", cmd);
        Err(PlatformError::NotSupported(
            "Automatic service start not implemented. Please use your system's service manager."
                .to_string(),
        ))
    }

    fn stop(&self, name: &str) -> Result<(), PlatformError> {
        let cmd = if cfg!(target_os = "linux") {
            format!("systemctl stop {}", name)
        } else {
            format!("service {} stop", name)
        };

        tracing::info!("Stop service with: {}", cmd);
        Err(PlatformError::NotSupported(
            "Automatic service stop not implemented. Please use your system's service manager."
                .to_string(),
        ))
    }

    fn status(&self, name: &str) -> Result<ServiceState, PlatformError> {
        if cfg!(target_os = "linux") {
            let output = std::process::Command::new("systemctl")
                .args(["is-active", name])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.trim() == "active" {
                    return Ok(ServiceState::Running);
                }
            }
        }

        Ok(ServiceState::Stopped)
    }

    fn is_installed(&self, name: &str) -> bool {
        if cfg!(target_os = "linux") {
            std::path::Path::new(&format!("/etc/systemd/system/{}.service", name)).exists()
        } else if cfg!(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )) {
            std::path::Path::new(&format!("/usr/local/etc/rc.d/{}", name)).exists()
        } else {
            false
        }
    }
}

pub fn service_manager() -> UnixServiceManager {
    UnixServiceManager::new()
}

pub fn is_running_as_service() -> bool {
    std::env::var("INVOCATION_ID").is_ok() || std::env::var("JOURNAL_STREAM").is_ok()
}
