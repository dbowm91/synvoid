use crate::config::PortHoneypotConfig;
use crate::PortHoneypotRunner;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone)]
pub struct PortHoneypotController {
    runner: Arc<RwLock<Option<Arc<PortHoneypotRunner>>>>,
    config: Arc<RwLock<PortHoneypotConfig>>,
}

impl PortHoneypotController {
    pub fn new(runner: Arc<PortHoneypotRunner>, config: PortHoneypotConfig) -> Self {
        Self {
            runner: Arc::new(RwLock::new(Some(runner))),
            config: Arc::new(RwLock::new(config)),
        }
    }

    pub fn from_runner(runner: Arc<PortHoneypotRunner>) -> Self {
        let config = runner.config().clone();
        Self {
            runner: Arc::new(RwLock::new(Some(runner))),
            config: Arc::new(RwLock::new(config)),
        }
    }

    pub fn get_config(&self) -> PortHoneypotConfig {
        self.config.read().clone()
    }

    pub fn update_config(&self, new_config: PortHoneypotConfig) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::PortHoneypotController;
    use crate::{
        config::{PortHoneypotConfig, StorageConfig},
        PortHoneypotRunner,
    };

    #[tokio::test]
    async fn controller_from_runner_uses_the_runners_runtime_config() {
        let config = PortHoneypotConfig {
            site_scope: "tenant-a".into(),
            storage: StorageConfig {
                database_path: ":memory:".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let runner = PortHoneypotRunner::new(config).unwrap();
        let controller = PortHoneypotController::from_runner(runner);
        assert_eq!(controller.get_config().site_scope, "tenant-a");
    }
}
