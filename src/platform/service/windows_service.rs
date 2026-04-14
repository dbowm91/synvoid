use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::platform::PlatformError;

pub const SERVICE_NAME: &str = "MaluWAF";
pub const SERVICE_DISPLAY_NAME: &str = "MaluWAF Web Application Firewall";
pub const SERVICE_DESCRIPTION: &str =
    "High-performance Web Application Firewall with advanced attack detection and bot mitigation";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    StartPending,
    Running,
    StopPending,
    PausePending,
    Paused,
    ContinuePending,
}

impl Default for ServiceState {
    fn default() -> Self {
        ServiceState::Stopped
    }
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub auto_start: bool,
    pub dependencies: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub binary_path: Option<PathBuf>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: SERVICE_NAME.to_string(),
            display_name: SERVICE_DISPLAY_NAME.to_string(),
            description: SERVICE_DESCRIPTION.to_string(),
            auto_start: true,
            dependencies: Vec::new(),
            username: None,
            password: None,
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

    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_auto_start(mut self, auto_start: bool) -> Self {
        self.auto_start = auto_start;
        self
    }

    pub fn with_dependencies(mut self, deps: Vec<String>) -> Self {
        self.dependencies = deps;
        self
    }

    pub fn with_credentials(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    pub fn with_binary_path(mut self, path: PathBuf) -> Self {
        self.binary_path = Some(path);
        self
    }
}

pub trait ServiceControl: Send + Sync {
    fn install(&self, config: &ServiceConfig) -> Result<(), PlatformError>;
    fn uninstall(&self, name: &str) -> Result<(), PlatformError>;
    fn start(&self, name: &str) -> Result<(), PlatformError>;
    fn stop(&self, name: &str) -> Result<(), PlatformError>;
    fn status(&self, name: &str) -> Result<ServiceState, PlatformError>;
    fn is_installed(&self, name: &str) -> bool;
}

pub struct WindowsServiceManager {
    running: Arc<AtomicBool>,
}

impl WindowsServiceManager {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    pub fn run_service<F>(&self, name: &str, mut on_start: F) -> Result<(), PlatformError>
    where
        F: FnMut() + Send + 'static,
    {
        self.running.store(true, Ordering::SeqCst);

        tracing::info!("Windows service '{}' starting", name);

        on_start();

        while self.running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }

        tracing::info!("Windows service '{}' stopped", name);
        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Default for WindowsServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceControl for WindowsServiceManager {
    fn install(&self, config: &ServiceConfig) -> Result<(), PlatformError> {
        let binary_path = config.binary_path.clone().unwrap_or_else(|| {
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("maluwaf.exe"))
        });

        let output = std::process::Command::new("sc")
            .args([
                "create",
                &config.name,
                "binPath=",
                &format!("\"{}\"", binary_path.display()),
                "DisplayName=",
                &config.display_name,
                "start=",
                if config.auto_start { "auto" } else { "demand" },
            ])
            .output()
            .map_err(|e| PlatformError::NotSupported(format!("Failed to create service: {}", e)))?;

        if !output.status.success() {
            return Err(PlatformError::NotSupported(format!(
                "sc create failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let desc_output = std::process::Command::new("sc")
            .args(["description", &config.name, &config.description])
            .output();

        if let Ok(output) = desc_output {
            if !output.status.success() {
                tracing::warn!(
                    "Failed to set service description: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        tracing::info!("Service '{}' installed successfully", config.name);
        Ok(())
    }

    fn uninstall(&self, name: &str) -> Result<(), PlatformError> {
        let output = std::process::Command::new("sc")
            .args(["delete", name])
            .output()
            .map_err(|e| PlatformError::NotSupported(format!("Failed to delete service: {}", e)))?;

        if !output.status.success() {
            return Err(PlatformError::NotSupported(format!(
                "sc delete failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        tracing::info!("Service '{}' uninstalled successfully", name);
        Ok(())
    }

    fn start(&self, name: &str) -> Result<(), PlatformError> {
        let output = std::process::Command::new("sc")
            .args(["start", name])
            .output()
            .map_err(|e| PlatformError::NotSupported(format!("Failed to start service: {}", e)))?;

        if !output.status.success() {
            return Err(PlatformError::NotSupported(format!(
                "sc start failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        tracing::info!("Service '{}' started successfully", name);
        Ok(())
    }

    fn stop(&self, name: &str) -> Result<(), PlatformError> {
        let output = std::process::Command::new("sc")
            .args(["stop", name])
            .output()
            .map_err(|e| PlatformError::NotSupported(format!("Failed to stop service: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("not started") {
                return Err(PlatformError::NotSupported(format!(
                    "sc stop failed: {}",
                    stderr
                )));
            }
        }

        tracing::info!("Service '{}' stopped successfully", name);
        Ok(())
    }

    fn status(&self, name: &str) -> Result<ServiceState, PlatformError> {
        let output = std::process::Command::new("sc")
            .args(["query", name])
            .output()
            .map_err(|e| PlatformError::NotSupported(format!("Failed to query service: {}", e)))?;

        if !output.status.success() {
            return Err(PlatformError::NotSupported(format!(
                "sc query failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("STATE") {
                if line.contains("STOPPED") {
                    return Ok(ServiceState::Stopped);
                } else if line.contains("START_PENDING") {
                    return Ok(ServiceState::StartPending);
                } else if line.contains("RUNNING") {
                    return Ok(ServiceState::Running);
                } else if line.contains("STOP_PENDING") {
                    return Ok(ServiceState::StopPending);
                } else if line.contains("PAUSE_PENDING") {
                    return Ok(ServiceState::PausePending);
                } else if line.contains("PAUSED") {
                    return Ok(ServiceState::Paused);
                } else if line.contains("CONTINUE_PENDING") {
                    return Ok(ServiceState::ContinuePending);
                }
            }
        }

        Ok(ServiceState::Stopped)
    }

    fn is_installed(&self, name: &str) -> bool {
        std::process::Command::new("sc")
            .args(["query", name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

pub fn service_manager() -> WindowsServiceManager {
    WindowsServiceManager::new()
}

pub fn is_running_as_service() -> bool {
    std::env::var("SESSIONNAME").is_err() && !std::env::var("TERM").is_ok()
}
