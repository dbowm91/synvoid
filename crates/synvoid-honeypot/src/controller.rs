use crate::PortHoneypotRunner;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone)]
pub struct PortHoneypotController {
    runner: Arc<RwLock<Option<Arc<PortHoneypotRunner>>>>,
    config: Arc<RwLock<synvoid_config::honeypot_port::HoneypotPortConfig>>,
}

impl PortHoneypotController {
    pub fn new(
        runner: Arc<PortHoneypotRunner>,
        config: synvoid_config::honeypot_port::HoneypotPortConfig,
    ) -> Self {
        Self {
            runner: Arc::new(RwLock::new(Some(runner))),
            config: Arc::new(RwLock::new(config)),
        }
    }

    pub fn from_runner(runner: Arc<PortHoneypotRunner>) -> Self {
        Self {
            runner: Arc::new(RwLock::new(Some(runner))),
            config: Arc::new(RwLock::new(
                synvoid_config::honeypot_port::HoneypotPortConfig::default(),
            )),
        }
    }

    pub fn get_config(&self) -> synvoid_config::honeypot_port::HoneypotPortConfig {
        self.config.read().clone()
    }

    pub fn update_config(
        &self,
        new_config: synvoid_config::honeypot_port::HoneypotPortConfig,
    ) -> Result<(), String> {
        let mut config = self.config.write();
        *config = new_config;
        Ok(())
    }

    pub fn get_runner(&self) -> Option<Arc<PortHoneypotRunner>> {
        self.runner.read().clone()
    }

    pub fn is_running(&self) -> bool {
        self.runner
            .read()
            .as_ref()
            .map(|r| r.is_running())
            .unwrap_or(false)
    }

    pub fn current_port(&self) -> u16 {
        self.runner
            .read()
            .as_ref()
            .map(|r| r.current_port())
            .unwrap_or(0)
    }

    pub fn get_status(&self) -> crate::mesh_control::HoneypotStatus {
        crate::mesh_control::HoneypotStatus {
            enabled: self.is_running(),
            paused: false,
            pause_reason: None,
            pause_timestamp: None,
            active_ports: vec![self.current_port()],
            last_control_command: None,
            last_control_time: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ControllerStatus {
    pub enabled: bool,
    pub paused: bool,
    pub pause_reason: Option<String>,
    pub active_ports: Vec<u16>,
    pub total_connections: u64,
}
