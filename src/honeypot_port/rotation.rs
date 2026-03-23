use crate::honeypot_port::config::PortHoneypotConfig;
use crate::honeypot_port::responses::{HoneypotResponder, HoneypotResponderRegistry};
use parking_lot::RwLock;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub enum PortMode {
    Random {
        min_port: u16,
        max_port: u16,
        num_ports: usize,
        rotation_interval_secs: u64,
    },
    Stable {
        ports: Vec<StablePort>,
    },
    Hybrid {
        stable_ports: Vec<StablePort>,
        random_min: u16,
        random_max: u16,
        num_random: usize,
        rotation_interval_secs: u64,
    },
}

#[derive(Clone)]
pub struct StablePort {
    pub port: u16,
    pub service_name: String,
    pub responder: Arc<dyn HoneypotResponder>,
}

struct ActivePort {
    port: u16,
    service_name: String,
    responder: Arc<dyn HoneypotResponder>,
    started_at: Instant,
}

pub struct PortManager {
    mode: PortMode,
    config: Arc<PortHoneypotConfig>,
    current_ports: Arc<RwLock<HashMap<u16, ActivePort>>>,
    responder_registry: Arc<HoneypotResponderRegistry>,
    paused: Arc<RwLock<bool>>,
    paused_reason: Arc<RwLock<Option<String>>>,
    last_rotation: Arc<RwLock<Instant>>,
}

impl PortManager {
    pub fn new(
        config: Arc<PortHoneypotConfig>,
        responder_registry: HoneypotResponderRegistry,
    ) -> Self {
        let registry_for_mode = responder_registry.clone();
        let mode = Self::build_mode(&config, &registry_for_mode);

        Self {
            mode,
            config,
            current_ports: Arc::new(RwLock::new(HashMap::new())),
            responder_registry: Arc::new(responder_registry),
            paused: Arc::new(RwLock::new(false)),
            paused_reason: Arc::new(RwLock::new(None)),
            last_rotation: Arc::new(RwLock::new(Instant::now())),
        }
    }

    fn build_mode(config: &PortHoneypotConfig, registry: &HoneypotResponderRegistry) -> PortMode {
        if config.stable_ports.is_empty() {
            PortMode::Random {
                min_port: config.min_port,
                max_port: config.max_port,
                num_ports: config.num_honeypot_ports,
                rotation_interval_secs: config.rotation_interval_secs,
            }
        } else {
            let ports: Vec<StablePort> = config
                .stable_ports
                .iter()
                .map(|sp| {
                    let responder = registry.get_or_default(&sp.service).unwrap_or_else(|| {
                        Arc::new(crate::honeypot_port::responders::StaticResponder::http())
                    });
                    StablePort {
                        port: sp.port,
                        service_name: sp.service.clone(),
                        responder,
                    }
                })
                .collect();
            PortMode::Stable { ports }
        }
    }

    pub fn is_paused(&self) -> bool {
        *self.paused.read()
    }

    pub fn pause(&self, reason: &str) {
        *self.paused.write() = true;
        *self.paused_reason.write() = Some(reason.to_string());
        tracing::info!("Honeypot ports paused: {}", reason);
    }

    pub fn resume(&self) {
        *self.paused.write() = false;
        *self.paused_reason.write() = None;
        tracing::info!("Honeypot ports resumed");
    }

    pub fn paused_reason(&self) -> Option<String> {
        self.paused_reason.read().clone()
    }

    pub fn get_active_ports(&self) -> Vec<u16> {
        self.current_ports.read().keys().cloned().collect()
    }

    pub fn get_port_info(&self, port: u16) -> Option<PortInfo> {
        self.current_ports.read().get(&port).map(|p| PortInfo {
            port: p.port,
            service_name: p.service_name.clone(),
            responder_name: p.responder.name().to_string(),
            started_at: p.started_at,
        })
    }

    pub fn should_rotate(&self) -> bool {
        let rotation_interval = match &self.mode {
            PortMode::Random {
                rotation_interval_secs,
                ..
            } => Duration::from_secs(*rotation_interval_secs),
            PortMode::Hybrid {
                rotation_interval_secs,
                ..
            } => Duration::from_secs(*rotation_interval_secs),
            PortMode::Stable { .. } => return false,
        };

        self.last_rotation.read().elapsed() > rotation_interval
    }

    pub fn rotate(&self) -> Vec<(u16, Arc<dyn HoneypotResponder>)> {
        *self.last_rotation.write() = Instant::now();
        self.current_ports.write().clear();
        self.select_ports()
    }

    pub fn select_ports(&self) -> Vec<(u16, Arc<dyn HoneypotResponder>)> {
        match &self.mode {
            PortMode::Random {
                min_port,
                max_port,
                num_ports,
                ..
            } => self.select_random_ports(*min_port, *max_port, *num_ports),
            PortMode::Stable { ports } => ports
                .iter()
                .map(|sp| {
                    let responder = sp.responder.clone();
                    (sp.port, responder)
                })
                .collect(),
            PortMode::Hybrid {
                stable_ports,
                random_min,
                random_max,
                num_random,
                ..
            } => {
                let mut result: Vec<(u16, Arc<dyn HoneypotResponder>)> = stable_ports
                    .iter()
                    .map(|sp| {
                        let responder = sp.responder.clone();
                        (sp.port, responder)
                    })
                    .collect();

                let random: Vec<(u16, Arc<dyn HoneypotResponder>)> =
                    self.select_random_ports(*random_min, *random_max, *num_random);
                result.extend(random);
                result
            }
        }
    }

    fn select_random_ports(
        &self,
        min_port: u16,
        max_port: u16,
        num_ports: usize,
    ) -> Vec<(u16, Arc<dyn HoneypotResponder>)> {
        let mut rng = rand::rng();
        let mut ports: Vec<u16> = (min_port..=max_port).collect();

        let services = self.get_cycle_services();

        (0..num_ports)
            .filter_map(|i| {
                if ports.is_empty() {
                    return None;
                }

                let idx = rng.random_range(0..ports.len());
                let port = ports.remove(idx);

                let service_idx = i % services.len();
                let responder = services[service_idx].clone();

                Some((port, responder))
            })
            .collect()
    }

    fn get_cycle_services(&self) -> Vec<Arc<dyn HoneypotResponder>> {
        vec![
            self.responder_registry
                .get_or_default("ssh")
                .unwrap_or_else(|| {
                    Arc::new(crate::honeypot_port::responders::VulnerableAppResponder::ubuntu_ssh())
                }),
            self.responder_registry
                .get_or_default("http")
                .unwrap_or_else(|| {
                    Arc::new(crate::honeypot_port::responders::VulnerableAppResponder::wordpress())
                }),
            self.responder_registry
                .get_or_default("mysql")
                .unwrap_or_else(|| {
                    Arc::new(crate::honeypot_port::responders::VulnerableAppResponder::mysql())
                }),
            self.responder_registry
                .get_or_default("redis")
                .unwrap_or_else(|| {
                    Arc::new(crate::honeypot_port::responders::VulnerableAppResponder::redis())
                }),
            self.responder_registry
                .get_or_default("elasticsearch")
                .unwrap_or_else(|| {
                    Arc::new(
                        crate::honeypot_port::responders::VulnerableAppResponder::elasticsearch(),
                    )
                }),
            self.responder_registry
                .get_or_default("docker")
                .unwrap_or_else(|| {
                    Arc::new(crate::honeypot_port::responders::VulnerableAppResponder::docker_api())
                }),
            self.responder_registry
                .get_or_default("jenkins")
                .unwrap_or_else(|| {
                    Arc::new(crate::honeypot_port::responders::VulnerableAppResponder::jenkins())
                }),
            self.responder_registry
                .get_or_default("tomcat")
                .unwrap_or_else(|| {
                    Arc::new(crate::honeypot_port::responders::VulnerableAppResponder::tomcat())
                }),
        ]
    }

    pub fn record_port_active(
        &self,
        port: u16,
        service_name: String,
        responder: Arc<dyn HoneypotResponder>,
    ) {
        let mut ports = self.current_ports.write();
        ports.insert(
            port,
            ActivePort {
                port,
                service_name,
                responder,
                started_at: Instant::now(),
            },
        );
    }

    pub fn get_responder_for_port(&self, port: u16) -> Option<Arc<dyn HoneypotResponder>> {
        self.current_ports
            .read()
            .get(&port)
            .map(|p| p.responder.clone())
    }
}

#[derive(Clone, Debug)]
pub struct PortInfo {
    pub port: u16,
    pub service_name: String,
    pub responder_name: String,
    pub started_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeypot_port::config::PortHoneypotConfig;
    use std::sync::Arc;

    fn make_config() -> Arc<PortHoneypotConfig> {
        Arc::new(PortHoneypotConfig::default())
    }

    #[test]
    fn test_port_manager_default_disabled() {
        let config = make_config();
        let registry = HoneypotResponderRegistry::new();

        let manager = PortManager::new(config, registry);

        assert!(!manager.is_paused());
    }

    #[test]
    fn test_port_manager_pause_resume() {
        let config = make_config();
        let registry = HoneypotResponderRegistry::new();

        let manager = PortManager::new(config, registry);

        manager.pause("test");
        assert!(manager.is_paused());
        assert_eq!(manager.paused_reason(), Some("test".to_string()));

        manager.resume();
        assert!(!manager.is_paused());
        assert_eq!(manager.paused_reason(), None);
    }

    #[test]
    fn test_port_manager_select_ports() {
        let config = make_config();
        let registry = HoneypotResponderRegistry::new();

        let manager = PortManager::new(config, registry);

        let ports = manager.select_ports();

        // Default config has 3 ports
        assert_eq!(ports.len(), 3);

        // All ports should be in valid range
        for (port, _) in ports {
            assert!(port >= 10000);
            assert!(port <= 60000);
        }
    }

    #[test]
    fn test_port_manager_get_active_ports() {
        let config = make_config();
        let registry = HoneypotResponderRegistry::new();

        let manager = PortManager::new(config, registry);

        let ports = manager.select_ports();
        for (port, responder) in ports {
            manager.record_port_active(port, responder.name().to_string(), responder);
        }

        let active = manager.get_active_ports();
        assert_eq!(active.len(), 3);
    }

    #[test]
    fn test_port_manager_rotate() {
        let config = make_config();
        let registry = HoneypotResponderRegistry::new();

        let manager = PortManager::new(config, registry);

        let initial_ports: Vec<u16> = manager.select_ports().iter().map(|(p, _)| *p).collect();

        // Rotate should give different ports (statistically likely)
        let rotated = manager.rotate();

        // Should have same number of ports
        assert_eq!(rotated.len(), 3);
    }

    #[test]
    fn test_responder_registry_get_or_default() {
        let mut registry = crate::honeypot_port::responses::HoneypotResponderRegistry::new();

        // Empty registry should return None
        assert!(registry.get_or_default("ssh").is_none());

        // After register, should find
        registry.register(Arc::new(
            crate::honeypot_port::responders::StaticResponder::ssh(),
        ));

        assert!(registry.get("ssh_static").is_some());
    }
}
