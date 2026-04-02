use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::platform::PlatformError;

pub const SERVICE_NAME: &str = "maluwaf";
pub const SERVICE_DISPLAY_NAME: &str = "MaluWAF Web Application Firewall";
pub const SERVICE_DESCRIPTION: &str =
    "High-performance Web Application Firewall with advanced attack detection and bot mitigation";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

    fn run_systemctl(&self, args: &[&str], action: &str) -> Result<(), PlatformError> {
        let output = std::process::Command::new("systemctl")
            .args(args)
            .output()
            .map_err(|e| PlatformError::NotSupported(format!("Failed to run systemctl: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PlatformError::NotSupported(format!(
                "systemctl {} failed: {}",
                action, stderr
            )));
        }

        Ok(())
    }

    fn install_linux(&self, config: &ServiceConfig) -> Result<(), PlatformError> {
        let binary_path = config.binary_path.clone().unwrap_or_else(|| {
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("maluwaf"))
        });

        let unit_content = format!(
            "[Unit]\n\
             Description={}\n\
             After=network.target\n\
             Documentation=https://maluwaf.dev\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={} --config /etc/maluwaf/config.toml\n\
             WorkingDirectory=/var/lib/maluwaf\n\
             Restart=always\n\
             RestartSec=5\n\
             LimitNOFILE=65536\n\
             User=root\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            config.display_name,
            binary_path.display()
        );

        let service_file = format!("/etc/systemd/system/{}.service", config.name);

        std::fs::write(&service_file, &unit_content).map_err(|e| {
            PlatformError::NotSupported(format!("Failed to write service file: {}", e))
        })?;

        tracing::info!("Service unit file written to {}", service_file);

        self.run_systemctl(&["daemon-reload"], "daemon-reload")?;

        if config.auto_start {
            self.run_systemctl(&["enable", &config.name], "enable")?;
            tracing::info!("Service '{}' enabled", config.name);
        }

        Ok(())
    }

    fn uninstall_linux(&self, name: &str) -> Result<(), PlatformError> {
        let _ = self.run_systemctl(&["stop", name], "stop");
        let _ = self.run_systemctl(&["disable", name], "disable");

        let service_file = format!("/etc/systemd/system/{}.service", name);
        if std::path::Path::new(&service_file).exists() {
            std::fs::remove_file(&service_file).map_err(|e| {
                PlatformError::NotSupported(format!("Failed to remove service file: {}", e))
            })?;
            tracing::info!("Removed service file {}", service_file);
        }

        self.run_systemctl(&["daemon-reload"], "daemon-reload")?;

        Ok(())
    }
}

impl Default for UnixServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceControl for UnixServiceManager {
    fn install(&self, config: &ServiceConfig) -> Result<(), PlatformError> {
        if cfg!(target_os = "linux") {
            self.install_linux(config)
        } else if cfg!(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )) {
            Err(PlatformError::NotSupported(
                "rc.d service installation not yet implemented. Please install manually."
                    .to_string(),
            ))
        } else {
            Err(PlatformError::NotSupported(
                "Service installation not supported on this platform".to_string(),
            ))
        }
    }

    fn uninstall(&self, name: &str) -> Result<(), PlatformError> {
        if cfg!(target_os = "linux") {
            self.uninstall_linux(name)
        } else {
            Err(PlatformError::NotSupported(
                "Service uninstallation not supported on this platform".to_string(),
            ))
        }
    }

    fn start(&self, name: &str) -> Result<(), PlatformError> {
        if cfg!(target_os = "linux") {
            self.run_systemctl(&["start", name], "start")
        } else {
            Err(PlatformError::NotSupported(
                "Automatic service start not supported on this platform".to_string(),
            ))
        }
    }

    fn stop(&self, name: &str) -> Result<(), PlatformError> {
        if cfg!(target_os = "linux") {
            self.run_systemctl(&["stop", name], "stop")
        } else {
            Err(PlatformError::NotSupported(
                "Automatic service stop not supported on this platform".to_string(),
            ))
        }
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
