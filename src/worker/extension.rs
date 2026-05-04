use std::sync::Arc;

use crate::metrics::payloads::HealthStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionFailurePolicy {
    FailClosed,
    FailOpen,
}

#[derive(Clone)]
pub enum ExtensionRuntime {
    #[cfg(feature = "mesh")]
    Mesh(MeshExtensionRuntime),
    #[cfg(feature = "dns")]
    Dns(DnsExtensionRuntime),
    Serverless(ServerlessExtensionRuntime),
    Honeypot(HoneypotExtensionRuntime),
}

impl ExtensionRuntime {
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "mesh")]
            ExtensionRuntime::Mesh(r) => r.name(),
            #[cfg(feature = "dns")]
            ExtensionRuntime::Dns(r) => r.name(),
            ExtensionRuntime::Serverless(r) => r.name(),
            ExtensionRuntime::Honeypot(r) => r.name(),
        }
    }

    pub fn failure_policy(&self) -> ExtensionFailurePolicy {
        match self {
            #[cfg(feature = "mesh")]
            ExtensionRuntime::Mesh(r) => r.failure_policy(),
            #[cfg(feature = "dns")]
            ExtensionRuntime::Dns(r) => r.failure_policy(),
            ExtensionRuntime::Serverless(r) => r.failure_policy(),
            ExtensionRuntime::Honeypot(r) => r.failure_policy(),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            #[cfg(feature = "mesh")]
            ExtensionRuntime::Mesh(r) => r.start().await,
            #[cfg(feature = "dns")]
            ExtensionRuntime::Dns(r) => r.start().await,
            ExtensionRuntime::Serverless(r) => r.start().await,
            ExtensionRuntime::Honeypot(r) => r.start().await,
        }
    }

    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            #[cfg(feature = "mesh")]
            ExtensionRuntime::Mesh(r) => r.stop().await,
            #[cfg(feature = "dns")]
            ExtensionRuntime::Dns(r) => r.stop().await,
            ExtensionRuntime::Serverless(r) => r.stop().await,
            ExtensionRuntime::Honeypot(r) => r.stop().await,
        }
    }

    pub fn health_check(&self) -> HealthStatus {
        match self {
            #[cfg(feature = "mesh")]
            ExtensionRuntime::Mesh(r) => r.health_check(),
            #[cfg(feature = "dns")]
            ExtensionRuntime::Dns(r) => r.health_check(),
            ExtensionRuntime::Serverless(r) => r.health_check(),
            ExtensionRuntime::Honeypot(r) => r.health_check(),
        }
    }
}

#[derive(Clone)]
pub struct ExtensionInfo {
    pub name: &'static str,
    pub failure_policy: ExtensionFailurePolicy,
    pub health: HealthStatus,
    pub runtime: ExtensionRuntime,
}

pub struct ExtensionRegistry {
    extensions: std::sync::RwLock<Vec<ExtensionInfo>>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self {
            extensions: std::sync::RwLock::new(Vec::new()),
        }
    }

    pub fn register(&self, runtime: ExtensionRuntime) {
        let info = ExtensionInfo {
            name: runtime.name(),
            failure_policy: runtime.failure_policy(),
            health: runtime.health_check(),
            runtime,
        };
        self.extensions.write().unwrap().push(info);
    }

    pub fn get_health_statuses(&self) -> Vec<(&'static str, ExtensionFailurePolicy, HealthStatus)> {
        self.extensions
            .read()
            .unwrap()
            .iter()
            .map(|e| (e.name, e.failure_policy, e.runtime.health_check()))
            .collect()
    }

    pub async fn start_all(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for ext in self.extensions.read().unwrap().iter() {
            if let Err(e) = ext.runtime.start().await {
                tracing::error!("Failed to start extension {}: {}", ext.name, e);
                return Err(e);
            }
        }
        Ok(())
    }

    pub async fn stop_all(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for ext in self.extensions.read().unwrap().iter() {
            if let Err(e) = ext.runtime.stop().await {
                tracing::error!("Failed to stop extension {}: {}", ext.name, e);
            }
        }
        Ok(())
    }

    pub fn refresh_health(&self) {
        let mut extensions = self.extensions.write().unwrap();
        for ext in extensions.iter_mut() {
            ext.health = ext.runtime.health_check();
        }
    }
}

impl Default for ExtensionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "mesh")]
#[derive(Clone)]
pub struct MeshExtensionRuntime {
    enabled: bool,
    transport_manager: Option<Arc<crate::mesh::transports::MeshTransportManager>>,
    threat_intel: Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>,
    signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
}

#[cfg(feature = "mesh")]
impl MeshExtensionRuntime {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        enabled: bool,
        transport_manager: Option<Arc<crate::mesh::transports::MeshTransportManager>>,
        threat_intel: Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>,
        signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> Self {
        Self {
            enabled,
            transport_manager,
            threat_intel,
            signer,
        }
    }

    pub fn name(&self) -> &'static str {
        "mesh"
    }

    pub fn failure_policy(&self) -> ExtensionFailurePolicy {
        ExtensionFailurePolicy::FailClosed
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub fn health_check(&self) -> HealthStatus {
        if !self.enabled {
            return HealthStatus::Unknown;
        }
        if self.transport_manager.is_some() && self.threat_intel.is_some() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        }
    }
}

#[cfg(feature = "dns")]
#[derive(Clone)]
pub struct DnsExtensionRuntime {
    dns_server: Option<Arc<crate::dns::DnsServer>>,
}

#[cfg(feature = "dns")]
impl DnsExtensionRuntime {
    pub fn new(dns_server: Option<Arc<crate::dns::DnsServer>>) -> Self {
        Self { dns_server }
    }

    pub fn name(&self) -> &'static str {
        "dns"
    }

    pub fn failure_policy(&self) -> ExtensionFailurePolicy {
        ExtensionFailurePolicy::FailClosed
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub fn health_check(&self) -> HealthStatus {
        self.dns_server
            .as_ref()
            .map(|_| HealthStatus::Healthy)
            .unwrap_or(HealthStatus::Unknown)
    }
}

#[derive(Clone)]
pub struct ServerlessExtensionRuntime {
    manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
}

impl ServerlessExtensionRuntime {
    pub fn new(manager: Option<Arc<crate::serverless::manager::ServerlessManager>>) -> Self {
        Self { manager }
    }

    pub fn name(&self) -> &'static str {
        "serverless"
    }

    pub fn failure_policy(&self) -> ExtensionFailurePolicy {
        ExtensionFailurePolicy::FailOpen
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref m) = self.manager {
            m.shutdown().await;
        }
        Ok(())
    }

    pub fn health_check(&self) -> HealthStatus {
        if let Some(ref m) = self.manager {
            let functions = m.get_all_functions();
            if functions.is_empty() {
                HealthStatus::Unknown
            } else {
                HealthStatus::Healthy
            }
        } else {
            HealthStatus::Unknown
        }
    }
}

#[derive(Clone)]
pub struct HoneypotExtensionRuntime {
    runner: Option<Arc<crate::honeypot_port::PortHoneypotRunner>>,
}

impl HoneypotExtensionRuntime {
    pub fn new(runner: Option<Arc<crate::honeypot_port::PortHoneypotRunner>>) -> Self {
        Self { runner }
    }

    pub fn name(&self) -> &'static str {
        "honeypot"
    }

    pub fn failure_policy(&self) -> ExtensionFailurePolicy {
        ExtensionFailurePolicy::FailOpen
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub fn health_check(&self) -> HealthStatus {
        self.runner
            .as_ref()
            .map(|_| HealthStatus::Healthy)
            .unwrap_or(HealthStatus::Unknown)
    }
}
