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

    fn install_bsd(&self, config: &ServiceConfig) -> Result<(), PlatformError> {
        let binary_path = config.binary_path.clone().unwrap_or_else(|| {
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("maluwaf"))
        });

        let rc_script = format!(
            r#"#!/bin/sh
#
# PROVIDE: {name}
# REQUIRE: NETWORKING
# KEYWORD: shutdown
#
# {description}
#

. /etc/rc.subr

name="{name}"
rcvar=$(set_rcvar)
command="{binary_path}"
command_args="--config /etc/maluwaf/config.toml"
pidfile="/var/run/{{name}}.pid"
procname="${{command}}"

start_cmd="{{name}}_start"
stop_cmd="{{name}}_stop"
status_cmd="{{name}}_status"

{name}_start() {{
    echo "Starting ${{name}}."
    /usr/sbin/daemon -P "$pidfile" -r -f $command ${{command_args}}
}}

{name}_stop() {{
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "Stopping ${{name}} (PID: $pid)."
            kill -TERM "$pid"
            for i in 1 2 3 4 5; do
                sleep 1
                kill -0 "$pid" 2>/dev/null || break
            done
            if kill -0 "$pid" 2>/dev/null; then
                echo "Force killing ${{name}}."
                kill -KILL "$pid"
            fi
            rm -f "$pidfile"
        else
            rm -f "$pidfile"
        fi
    fi
}}

{name}_status() {{
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "${{name}} is running as PID $pid."
            return 0
        fi
        rm -f "$pidfile"
    fi
    echo "${{name}} is not running."
    return 1
}}

load_rc_config $name
run_rc_command "$1"
"#,
            name = config.name,
            description = config.display_name,
            binary_path = binary_path.display()
        );

        let rc_dir = if cfg!(target_os = "freebsd") {
            "/usr/local/etc/rc.d"
        } else {
            "/etc/rc.d"
        };

        let rc_script_path = format!("{}/{}", rc_dir, config.name);

        std::fs::write(&rc_script_path, &rc_script).map_err(|e| {
            PlatformError::NotSupported(format!("Failed to write rc.d script: {}", e))
        })?;

        let output = std::process::Command::new("chmod")
            .args(["+x", &rc_script_path])
            .output()
            .map_err(|e| PlatformError::NotSupported(format!("Failed to chmod: {}", e)))?;

        if !output.status.success() {
            return Err(PlatformError::NotSupported(
                "Failed to make rc.d script executable".to_string(),
            ));
        }

        tracing::info!("BSD rc.d script installed to {}", rc_script_path);

        if config.auto_start {
            self.enable_bsd(&config.name)?;
        }

        Ok(())
    }

    fn enable_bsd(&self, name: &str) -> Result<(), PlatformError> {
        let rc_conf_line = format!("{}_enable=\"YES\"", name);

        let rc_conf_path = if cfg!(target_os = "freebsd") {
            "/etc/rc.conf.d/maluwaf"
        } else {
            "/etc/rc.conf.local"
        };

        let rc_conf_path_buf = PathBuf::from(rc_conf_path);
        let parent_dir = rc_conf_path_buf.parent().unwrap();

        if !parent_dir.exists() {
            std::fs::create_dir_all(parent_dir).map_err(|e| {
                PlatformError::NotSupported(format!("Failed to create rc.conf.d dir: {}", e))
            })?;
        }

        let existing = std::fs::read_to_string(rc_conf_path).unwrap_or_default();
        let mut lines: Vec<&str> = existing.lines().collect();

        lines.retain(|line| !line.starts_with(&format!("{}_enable", name)));

        let mut new_content = lines.join("\n");
        if !new_content.is_empty() {
            new_content.push('\n');
        }
        new_content.push_str(&rc_conf_line);
        new_content.push('\n');

        std::fs::write(rc_conf_path, &new_content)
            .map_err(|e| PlatformError::NotSupported(format!("Failed to write rc.conf: {}", e)))?;

        tracing::info!("Enabled {} in {}", name, rc_conf_path);
        Ok(())
    }

    fn uninstall_bsd(&self, name: &str) -> Result<(), PlatformError> {
        self.stop_bsd(name)?;

        let rc_script_path = if cfg!(target_os = "freebsd") {
            format!("/usr/local/etc/rc.d/{}", name)
        } else {
            format!("/etc/rc.d/{}", name)
        };

        if std::path::Path::new(&rc_script_path).exists() {
            std::fs::remove_file(&rc_script_path).map_err(|e| {
                PlatformError::NotSupported(format!("Failed to remove rc.d script: {}", e))
            })?;
            tracing::info!("Removed rc.d script {}", rc_script_path);
        }

        let rc_conf_path = if cfg!(target_os = "freebsd") {
            "/etc/rc.conf.d/maluwaf"
        } else {
            "/etc/rc.conf.local"
        };

        if std::path::Path::new(rc_conf_path).exists() {
            let existing = std::fs::read_to_string(rc_conf_path).unwrap_or_default();
            let lines: Vec<&str> = existing
                .lines()
                .filter(|line| !line.starts_with(&format!("{}_enable", name)))
                .collect();

            let new_content = lines.join("\n");
            std::fs::write(rc_conf_path, new_content).map_err(|e| {
                PlatformError::NotSupported(format!("Failed to update rc.conf: {}", e))
            })?;
        }

        Ok(())
    }

    fn start_bsd(&self, name: &str) -> Result<(), PlatformError> {
        if cfg!(target_os = "freebsd") {
            let output = std::process::Command::new("service")
                .arg(format!("{} start", name))
                .output()
                .map_err(|e| {
                    PlatformError::NotSupported(format!("Failed to run service: {}", e))
                })?;

            if !output.status.success() {
                return Err(PlatformError::NotSupported(format!(
                    "service {} start failed: {}",
                    name,
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        } else if cfg!(target_os = "openbsd") {
            let output = std::process::Command::new("rcctl")
                .args(["start", name])
                .output()
                .map_err(|e| PlatformError::NotSupported(format!("Failed to run rcctl: {}", e)))?;

            if !output.status.success() {
                return Err(PlatformError::NotSupported(format!(
                    "rcctl start {} failed: {}",
                    name,
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        } else {
            return Err(PlatformError::NotSupported(
                "Service start not supported on this BSD variant".to_string(),
            ));
        }

        Ok(())
    }

    fn stop_bsd(&self, name: &str) -> Result<(), PlatformError> {
        if cfg!(target_os = "freebsd") {
            let output = std::process::Command::new("service")
                .arg(format!("{} stop", name))
                .output()
                .map_err(|e| {
                    PlatformError::NotSupported(format!("Failed to run service: {}", e))
                })?;

            if !output.status.success() {
                tracing::warn!(
                    "service {} stop failed: {}",
                    name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        } else if cfg!(target_os = "openbsd") {
            let output = std::process::Command::new("rcctl")
                .args(["stop", name])
                .output()
                .map_err(|e| PlatformError::NotSupported(format!("Failed to run rcctl: {}", e)))?;

            if !output.status.success() {
                tracing::warn!(
                    "rcctl stop {} failed: {}",
                    name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        Ok(())
    }

    fn status_bsd(&self, name: &str) -> Result<ServiceState, PlatformError> {
        if cfg!(target_os = "freebsd") {
            let output = std::process::Command::new("service")
                .arg(format!("{} status", name))
                .output()
                .map_err(|e| {
                    PlatformError::NotSupported(format!("Failed to run service: {}", e))
                })?;

            if output.status.success()
                || String::from_utf8_lossy(&output.stdout).contains("is running")
            {
                return Ok(ServiceState::Running);
            }
        } else if cfg!(target_os = "openbsd") {
            let output = std::process::Command::new("rcctl")
                .args(["get", name])
                .output()
                .map_err(|e| PlatformError::NotSupported(format!("Failed to run rcctl: {}", e)))?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("status=ON") {
                    return Ok(ServiceState::Running);
                }
            }
        }

        Ok(ServiceState::Stopped)
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
            self.install_bsd(config)
        } else {
            Err(PlatformError::NotSupported(
                "Service installation not supported on this platform".to_string(),
            ))
        }
    }

    fn uninstall(&self, name: &str) -> Result<(), PlatformError> {
        if cfg!(target_os = "linux") {
            self.uninstall_linux(name)
        } else if cfg!(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )) {
            self.uninstall_bsd(name)
        } else {
            Err(PlatformError::NotSupported(
                "Service uninstallation not supported on this platform".to_string(),
            ))
        }
    }

    fn start(&self, name: &str) -> Result<(), PlatformError> {
        if cfg!(target_os = "linux") {
            self.run_systemctl(&["start", name], "start")
        } else if cfg!(any(target_os = "freebsd", target_os = "openbsd")) {
            self.start_bsd(name)
        } else {
            Err(PlatformError::NotSupported(
                "Automatic service start not supported on this platform".to_string(),
            ))
        }
    }

    fn stop(&self, name: &str) -> Result<(), PlatformError> {
        if cfg!(target_os = "linux") {
            self.run_systemctl(&["stop", name], "stop")
        } else if cfg!(any(target_os = "freebsd", target_os = "openbsd")) {
            self.stop_bsd(name)
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
        } else if cfg!(any(target_os = "freebsd", target_os = "openbsd")) {
            return self.status_bsd(name);
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
            let rc_script = if cfg!(target_os = "freebsd") {
                format!("/usr/local/etc/rc.d/{}", name)
            } else {
                format!("/etc/rc.d/{}", name)
            };
            std::path::Path::new(&rc_script).exists()
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
