use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::config::serverless::FunctionDefinition;

#[derive(Debug, Clone)]
pub struct InstancePoolConfig {
    pub min_instances: usize,
    pub max_instances: usize,
    pub idle_timeout_seconds: u64,
    pub scale_up_threshold: f64,
    pub scale_down_threshold: f64,
    pub scale_up_cooldown_seconds: u64,
    pub scale_down_cooldown_seconds: u64,
    pub pre_warm_instances: usize,
}

impl Default for InstancePoolConfig {
    fn default() -> Self {
        Self {
            min_instances: 1,
            max_instances: 10,
            idle_timeout_seconds: 300,
            scale_up_threshold: 0.7,
            scale_down_threshold: 0.3,
            scale_up_cooldown_seconds: 30,
            scale_down_cooldown_seconds: 60,
            pre_warm_instances: 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstanceMetrics {
    pub requests_handled: u64,
    pub total_duration_ms: u64,
    pub last_used: Instant,
    pub is_idle: bool,
}

impl InstanceMetrics {
    fn new() -> Self {
        Self {
            requests_handled: 0,
            total_duration_ms: 0,
            last_used: Instant::now(),
            is_idle: true,
        }
    }
}

pub struct ServerlessInstance {
    pub id: String,
    pub function_name: String,
    pub instance: Arc<crate::plugin::WasmRuntime>,
    pub metrics: RwLock<InstanceMetrics>,
    pub created_at: Instant,
    pub state: RwLock<InstanceState>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstanceState {
    Initializing,
    Ready,
    Busy,
    Evicted,
}

pub struct InstancePool {
    config: InstancePoolConfig,
    function_definition: FunctionDefinition,
    runtime: Arc<crate::plugin::WasmRuntime>,
    instances: RwLock<Vec<Arc<ServerlessInstance>>>,
    active_instances: RwLock<HashMap<String, Arc<ServerlessInstance>>>,
    idle_instances: RwLock<Vec<Arc<ServerlessInstance>>>,
    last_scale_up: RwLock<Instant>,
    last_scale_down: RwLock<Instant>,
    shutdown_tx: tokio::sync::watch::Sender<()>,
}

impl ServerlessInstance {
    pub fn new(
        id: String,
        function_name: String,
        instance: Arc<crate::plugin::WasmRuntime>,
    ) -> Self {
        Self {
            id,
            function_name,
            instance,
            metrics: RwLock::new(InstanceMetrics::new()),
            created_at: Instant::now(),
            state: RwLock::new(InstanceState::Initializing),
        }
    }

    pub fn mark_ready(&self) {
        *self.state.write() = InstanceState::Ready;
    }

    pub fn mark_busy(&self) {
        *self.state.write() = InstanceState::Busy;
    }

    pub fn mark_idle(&self) {
        *self.state.write() = InstanceState::Ready;
        self.metrics.write().is_idle = true;
    }

    pub fn record_request(&self, duration_ms: u64) {
        let mut metrics = self.metrics.write();
        metrics.requests_handled += 1;
        metrics.total_duration_ms += duration_ms;
        metrics.last_used = Instant::now();
        metrics.is_idle = false;
    }

    pub fn is_idle(&self) -> bool {
        self.metrics.read().is_idle
    }

    pub fn idle_duration(&self) -> Duration {
        self.metrics.read().last_used.elapsed()
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

impl InstancePool {
    pub fn new(config: InstancePoolConfig, function_definition: FunctionDefinition) -> Self {
        let wasm_path = std::path::Path::new(&function_definition.name).with_extension("wasm");
        let runtime = crate::plugin::WasmPluginManager::new()
            .load_plugin_with_limits(
                &wasm_path,
                crate::plugin::WasmResourceLimits {
                    max_memory_mb: function_definition.memory_mb.unwrap_or(64),
                    max_cpu_fuel: function_definition.cpu_fuel.unwrap_or(0),
                    timeout_seconds: function_definition.timeout_seconds.unwrap_or(30),
                    max_instances: function_definition.max_instances.unwrap_or(10),
                    memory_budget_mb: None,
                    wasi_enabled: false,
                },
            )
            .expect("Failed to load serverless function");

        Self {
            config,
            function_definition,
            runtime,
            instances: RwLock::new(Vec::new()),
            active_instances: RwLock::new(HashMap::new()),
            idle_instances: RwLock::new(Vec::new()),
            last_scale_up: RwLock::new(Instant::now()),
            last_scale_down: RwLock::new(Instant::now()),
            shutdown_tx: tokio::sync::watch::channel(()).0,
        }
    }

    pub async fn initialize(&self) -> Result<(), InstancePoolError> {
        let min_to_create = self
            .config
            .pre_warm_instances
            .min(self.config.max_instances);

        for i in 0..min_to_create {
            let instance = self.spawn_instance(format!(
                "{}-{}-{}",
                self.function_definition.name,
                i,
                uuid::Uuid::new_v4()
            ))?;
            instance.mark_ready();
            let instance_clone = instance.clone();
            self.instances.write().push(instance);
            self.idle_instances.write().push(instance_clone);
        }

        Ok(())
    }

    fn spawn_instance(&self, id: String) -> Result<Arc<ServerlessInstance>, InstancePoolError> {
        let instance = Arc::new(ServerlessInstance::new(
            id,
            self.function_definition.name.clone(),
            self.runtime.clone(),
        ));

        Ok(instance)
    }

    pub async fn get_instance(&self) -> Result<Arc<ServerlessInstance>, InstancePoolError> {
        // Try to get from idle pool
        let instance = {
            let mut idle = self.idle_instances.write();
            idle.pop()
        };

        // If no idle instance, try to scale up
        let instance = if let Some(inst) = instance {
            inst
        } else {
            let current_count = self.instances.read().len();
            if current_count < self.config.max_instances {
                self.scale_up(1).await?;
                let mut idle = self.idle_instances.write();
                idle.pop().ok_or(InstancePoolError::NoInstancesAvailable)?
            } else {
                return Err(InstancePoolError::NoInstancesAvailable);
            }
        };

        instance.mark_busy();
        self.active_instances
            .write()
            .insert(instance.id.clone(), instance.clone());
        Ok(instance)
    }

    pub fn return_instance(&self, instance_id: &str) {
        let mut active = self.active_instances.write();
        if let Some(instance) = active.remove(instance_id) {
            let idle_duration = instance.idle_duration();

            if idle_duration > Duration::from_secs(self.config.idle_timeout_seconds) {
                *instance.state.write() = InstanceState::Evicted;
                self.evict_instance(instance);
            } else {
                instance.mark_idle();
                self.idle_instances.write().push(instance);
            }
        }
    }

    fn evict_instance(&self, instance: Arc<ServerlessInstance>) {
        let mut instances = self.instances.write();
        instances.retain(|i| i.id != instance.id);
    }

    pub async fn scale_up(&self, count: usize) -> Result<(), InstancePoolError> {
        let last_scale = *self.last_scale_up.read();
        if last_scale.elapsed() < Duration::from_secs(self.config.scale_up_cooldown_seconds) {
            return Ok(());
        }

        let current = self.instances.read().len();
        let target = (current + count).min(self.config.max_instances);
        let to_create = target - current;

        for i in 0..to_create {
            match self.spawn_instance(format!(
                "{}-{}-{}",
                self.function_definition.name,
                current + i,
                uuid::Uuid::new_v4()
            )) {
                Ok(instance) => {
                    instance.mark_ready();
                    self.instances.write().push(instance.clone());
                    self.idle_instances.write().push(instance);
                }
                Err(e) => {
                    tracing::warn!("Failed to spawn instance during scale up: {}", e);
                }
            }
        }

        *self.last_scale_up.write() = Instant::now();

        Ok(())
    }

    pub async fn scale_down(&self, count: usize) -> Result<(), InstancePoolError> {
        let last_scale = *self.last_scale_down.read();
        if last_scale.elapsed() < Duration::from_secs(self.config.scale_down_cooldown_seconds) {
            return Ok(());
        }

        let current = self.instances.read().len();
        let target = current.saturating_sub(count).max(self.config.min_instances);
        let to_remove = current - target;

        if to_remove == 0 {
            return Ok(());
        }

        let mut instances_to_remove = Vec::new();
        {
            let idle = self.idle_instances.read();
            let idle_count = idle.len();
            let take_count = idle_count.min(to_remove);

            for i in 0..take_count {
                if let Some(instance) = idle.get(idle_count.saturating_sub(i + 1)) {
                    instances_to_remove.push(instance.id.clone());
                }
            }
        }

        {
            let mut idle = self.idle_instances.write();
            idle.retain(|i| !instances_to_remove.contains(&i.id));
        }

        {
            let mut instances = self.instances.write();
            instances.retain(|i| {
                if instances_to_remove.contains(&i.id) {
                    *i.state.write() = InstanceState::Evicted;
                    false
                } else {
                    true
                }
            });
        }

        *self.last_scale_down.write() = Instant::now();

        Ok(())
    }

    pub fn get_instance_count(&self) -> usize {
        self.instances.read().len()
    }

    pub fn get_idle_count(&self) -> usize {
        self.idle_instances.read().len()
    }

    pub fn get_active_count(&self) -> usize {
        self.active_instances.read().len()
    }

    pub fn get_utilization(&self) -> f64 {
        let total = self.instances.read().len();
        if total == 0 {
            return 0.0;
        }
        let active = self.active_instances.read().len();
        active as f64 / total as f64
    }

    pub async fn run_autoscaler(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    tracing::info!("InstancePool autoscaler shutdown signal received");
                    break;
                }
                _ = interval.tick() => {
                    let utilization = self.get_utilization();

                    if utilization >= self.config.scale_up_threshold {
                        let current = self.instances.read().len();
                        if current < self.config.max_instances {
                            let to_add = ((current as f64 * 0.5) as usize).max(1);
                            if let Err(e) = self.scale_up(to_add).await {
                                tracing::warn!("Autoscaler scale up failed: {}", e);
                            }
                        }
                    } else if utilization <= self.config.scale_down_threshold {
                        let current = self.instances.read().len();
                        if current > self.config.min_instances {
                            let to_remove = ((current as f64 * 0.3) as usize).max(1);
                            if let Err(e) = self.scale_down(to_remove).await {
                                tracing::warn!("Autoscaler scale down failed: {}", e);
                            }
                        }
                    }

                    self.evict_idle_instances().await;
                }
            }
        }
    }

    pub async fn shutdown(&self, timeout_secs: u64) {
        let _ = self.shutdown_tx.send(());

        let active_count = self.active_instances.read().len();
        if active_count > 0 {
            tracing::info!(
                "Waiting for {} active instance(s) to complete (timeout: {}s)",
                active_count,
                timeout_secs
            );

            let start = Instant::now();
            loop {
                let active = self.active_instances.read().len();
                if active == 0 {
                    break;
                }
                if start.elapsed().as_secs() >= timeout_secs {
                    tracing::warn!(
                        "Shutdown timeout: {} active instance(s) forcibly evicted",
                        active
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let instances_to_evict: Vec<Arc<ServerlessInstance>> =
            self.instances.read().iter().cloned().collect();
        for instance in instances_to_evict {
            *instance.state.write() = InstanceState::Evicted;
        }

        self.instances.write().clear();
        self.idle_instances.write().clear();
        self.active_instances.write().clear();

        tracing::info!(
            "InstancePool for '{}' shut down, evicted all instances",
            self.function_definition.name
        );
    }

    async fn evict_idle_instances(&self) {
        let timeout = Duration::from_secs(self.config.idle_timeout_seconds);

        let instances_to_evict: Vec<String> = {
            let idle = self.idle_instances.read();
            idle.iter()
                .filter(|i| i.idle_duration() > timeout)
                .map(|i| i.id.clone())
                .collect()
        };

        for id in instances_to_evict {
            self.return_instance(&id);
        }
    }

    pub fn get_metrics(&self) -> PoolMetrics {
        let instances = self.instances.read();
        let total_requests: u64 = instances
            .iter()
            .map(|i| i.metrics.read().requests_handled)
            .sum();
        let total_duration: u64 = instances
            .iter()
            .map(|i| i.metrics.read().total_duration_ms)
            .sum();

        PoolMetrics {
            total_instances: instances.len(),
            idle_instances: self.idle_instances.read().len(),
            active_instances: self.active_instances.read().len(),
            total_requests,
            total_duration_ms: total_duration,
            utilization: self.get_utilization(),
        }
    }

    pub fn check_health(&self) -> PoolHealth {
        let instances = self.instances.read();
        let mut healthy = 0;
        let mut unhealthy = 0;
        let mut unhealthy_reasons: Vec<String> = Vec::new();

        for instance in instances.iter() {
            let state = instance.state.read();
            let metrics = instance.metrics.read();

            let instance_healthy = match *state {
                InstanceState::Ready | InstanceState::Busy => {
                    !(metrics.requests_handled == 0 && instance.age() > Duration::from_secs(60))
                }
                InstanceState::Initializing | InstanceState::Evicted => false,
            };

            if instance_healthy {
                healthy += 1;
            } else {
                unhealthy += 1;
                unhealthy_reasons.push(format!(
                    "{}:{:?}:{}reqs:{}idle_for{:?}",
                    instance.id,
                    *state,
                    metrics.requests_handled,
                    metrics.is_idle,
                    metrics.last_used.elapsed()
                ));
            }
        }

        PoolHealth {
            healthy_instances: healthy,
            unhealthy_instances: unhealthy,
            total_instances: instances.len(),
            utilization: self.get_utilization(),
            unhealthy_reasons,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolHealth {
    pub healthy_instances: usize,
    pub unhealthy_instances: usize,
    pub total_instances: usize,
    pub utilization: f64,
    pub unhealthy_reasons: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PoolMetrics {
    pub total_instances: usize,
    pub idle_instances: usize,
    pub active_instances: usize,
    pub total_requests: u64,
    pub total_duration_ms: u64,
    pub utilization: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum InstancePoolError {
    #[error("No instances available")]
    NoInstancesAvailable,
    #[error("Instance creation failed: {0}")]
    InstanceCreationFailed(#[from] crate::plugin::WasmPluginError),
    #[error("Instance not found: {0}")]
    InstanceNotFound(String),
    #[error("Pool at maximum capacity")]
    AtMaxCapacity,
    #[error("Pool at minimum capacity")]
    AtMinCapacity,
}
