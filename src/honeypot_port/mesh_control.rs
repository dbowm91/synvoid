use crate::honeypot_port::PortManager;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HoneypotControlCommand {
    Enable,
    Disable,
    Pause {
        reason: String,
        duration_secs: Option<u32>,
    },
    Resume,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotStatus {
    pub enabled: bool,
    pub paused: bool,
    pub pause_reason: Option<String>,
    pub pause_timestamp: Option<u64>,
    pub active_ports: Vec<u16>,
    pub last_control_command: Option<HoneypotControlCommand>,
    pub last_control_time: Option<u64>,
}

pub struct HoneypotMeshController {
    port_manager: Arc<PortManager>,
    status: Arc<RwLock<HoneypotStatus>>,
}

impl HoneypotMeshController {
    pub fn new(port_manager: Arc<PortManager>) -> Self {
        Self {
            port_manager,
            status: Arc::new(RwLock::new(HoneypotStatus {
                enabled: true,
                paused: false,
                pause_reason: None,
                pause_timestamp: None,
                active_ports: Vec::new(),
                last_control_command: None,
                last_control_time: None,
            })),
        }
    }

    pub fn get_status(&self) -> HoneypotStatus {
        let mut status = self.status.read().clone();
        status.active_ports = self.port_manager.get_active_ports();
        status
    }

    pub fn handle_control_command(
        &self,
        command: HoneypotControlCommand,
    ) -> Result<(), HoneypotControlError> {
        let now = crate::utils::current_timestamp();

        match &command {
            HoneypotControlCommand::Enable => {
                self.port_manager.resume();
                let mut status = self.status.write();
                status.enabled = true;
                status.paused = false;
                status.pause_reason = None;
                status.pause_timestamp = None;
                status.last_control_command = Some(command);
                status.last_control_time = Some(now);
                tracing::info!("Honeypot enabled via mesh control");
            }
            HoneypotControlCommand::Disable => {
                self.port_manager.pause("disabled_by_mesh");
                let mut status = self.status.write();
                status.enabled = false;
                status.last_control_command = Some(command);
                status.last_control_time = Some(now);
                tracing::info!("Honeypot disabled via mesh control");
            }
            HoneypotControlCommand::Pause {
                reason,
                duration_secs,
            } => {
                let reason_str = reason.clone();
                self.port_manager.pause(&reason_str);
                let mut status = self.status.write();
                status.paused = true;
                status.pause_reason = Some(reason_str.clone());
                status.pause_timestamp = Some(now);
                status.last_control_command = Some(command.clone());
                status.last_control_time = Some(now);
                let reason_for_log = reason_str.clone();

                if let Some(duration) = duration_secs {
                    let duration_secs = *duration;
                    let reason_for_task = reason_str;
                    let status_clone = self.status.clone();

                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(duration_secs as u64)).await;
                        let mut status = status_clone.write();
                        if status.pause_reason.as_ref() == Some(&reason_for_task) {
                            status.paused = false;
                            status.pause_reason = None;
                            status.pause_timestamp = None;
                            tracing::info!("Honeypot auto-resumed after pause duration");
                        }
                    });
                }

                tracing::info!("Honeypot paused via mesh control: {}", reason_for_log);
            }
            HoneypotControlCommand::Resume => {
                self.port_manager.resume();
                let mut status = self.status.write();
                status.paused = false;
                status.pause_reason = None;
                status.pause_timestamp = None;
                status.last_control_command = Some(command);
                status.last_control_time = Some(now);
                tracing::info!("Honeypot resumed via mesh control");
            }
        }

        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.status.read().enabled
    }

    pub fn is_paused(&self) -> bool {
        self.status.read().paused || self.port_manager.is_paused()
    }

    pub fn can_accept_connection(&self) -> bool {
        let status = self.status.read();
        status.enabled && !status.paused && !self.port_manager.is_paused()
    }

    pub fn update_active_ports(&self) {
        let ports = self.port_manager.get_active_ports();
        self.status.write().active_ports = ports;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HoneypotControlError {
    #[error("Honeypot is not enabled")]
    NotEnabled,
    #[error("Honeypot is already paused: {0}")]
    AlreadyPaused(String),
    #[error("Honeypot is not paused")]
    NotPaused,
    #[error("Invalid command: {0}")]
    InvalidCommand(String),
}

impl Serialize for HoneypotControlError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeypot_port::config::PortHoneypotConfig;
    use crate::honeypot_port::rotation::PortManager;
    use std::sync::Arc;

    fn make_controller() -> HoneypotMeshController {
        let config = Arc::new(PortHoneypotConfig::default());
        let registry = crate::honeypot_port::responses::HoneypotResponderRegistry::new();
        let port_manager = Arc::new(PortManager::new(config, registry));
        HoneypotMeshController::new(port_manager)
    }

    #[test]
    fn test_initial_status() {
        let controller = make_controller();
        let status = controller.get_status();

        assert!(status.enabled);
        assert!(!status.paused);
    }

    #[test]
    fn test_enable_command() {
        let controller = make_controller();

        // Initially enabled
        assert!(controller.is_enabled());

        // Disable
        controller
            .handle_control_command(HoneypotControlCommand::Disable)
            .unwrap();
        assert!(!controller.is_enabled());

        // Enable again
        controller
            .handle_control_command(HoneypotControlCommand::Enable)
            .unwrap();
        assert!(controller.is_enabled());
    }

    #[test]
    fn test_pause_command() {
        let controller = make_controller();

        controller
            .handle_control_command(HoneypotControlCommand::Pause {
                reason: "maintenance".to_string(),
                duration_secs: None,
            })
            .unwrap();

        assert!(controller.is_paused());

        let status = controller.get_status();
        assert!(status.paused);
        assert_eq!(status.pause_reason, Some("maintenance".to_string()));
    }

    #[test]
    fn test_resume_command() {
        let controller = make_controller();

        controller
            .handle_control_command(HoneypotControlCommand::Pause {
                reason: "test".to_string(),
                duration_secs: None,
            })
            .unwrap();

        assert!(controller.is_paused());

        controller
            .handle_control_command(HoneypotControlCommand::Resume)
            .unwrap();

        assert!(!controller.is_paused());
    }

    #[test]
    fn test_can_accept_connection() {
        let controller = make_controller();

        // Should accept by default
        assert!(controller.can_accept_connection());

        // After disable, should not accept
        controller
            .handle_control_command(HoneypotControlCommand::Disable)
            .unwrap();
        assert!(!controller.can_accept_connection());

        // After enable, should accept again
        controller
            .handle_control_command(HoneypotControlCommand::Enable)
            .unwrap();
        assert!(controller.can_accept_connection());
    }

    #[test]
    fn test_pause_blocks_connections() {
        let controller = make_controller();

        controller
            .handle_control_command(HoneypotControlCommand::Pause {
                reason: "test".to_string(),
                duration_secs: None,
            })
            .unwrap();

        // Even if enabled, paused should block
        assert!(!controller.can_accept_connection());
    }
}
