use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use parking_lot::RwLock;
use thiserror::Error;

use crate::config::serverless::{FunctionDefinition, ServerlessConfig};
use crate::http_client::ErasedBody;
#[cfg(feature = "mesh")]
use crate::mesh::config::MeshNodeRole;
use crate::plugin::{WasmPluginManager, WasmResourceLimits};
use crate::serverless::async_compilation::{
    AsyncCompilationHandle, AsyncCompilationManager, CompilationState,
};
use crate::serverless::instance_pool::{InstancePool, InstancePoolConfig};
use crate::serverless::registry::get_global_serverless_registry;
use crate::serverless::routing::{MethodMatch, RouteMatch, ServerlessRoute, parse_routes};

#[derive(Debug, Clone)]
pub struct CallerContext {
    pub node_id: String,
    #[cfg(feature = "mesh")]
    pub role: MeshNodeRole,
    pub org_id: Option<String>,
    pub tier: Option<u32>,
    pub is_local: bool,
}

impl CallerContext {
    pub fn local() -> Self {
        Self {
            node_id: "local".to_string(),
            #[cfg(feature = "mesh")]
            role: MeshNodeRole::SERVERLESS_ORIGIN,
            org_id: None,
            tier: None,
            is_local: true,
        }
    }

    #[cfg(feature = "mesh")]
    pub fn mesh(node_id: String, role: MeshNodeRole) -> Self {
        Self {
            node_id,
            role,
            org_id: None,
            tier: None,
            is_local: false,
        }
    }
}

#[derive(Error, Debug)]
pub enum ServerlessError {
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    #[error("WASM runtime error: {0}")]
    WasmError(String),
    #[error("Function execution error: {0}")]
    ExecutionError(String),
    #[error("No serverless configuration")]
    NoConfig,
    #[error("Function disabled")]
    Disabled,
    #[error("No matching route found for: {0}")]
    NoMatchingRoute(String),
    #[error("Remote execution required for: {0}")]
    RemoteExecutionRequired(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Function compilation in progress: {0}")]
    CompilationInProgress(String),
    #[error("Function compilation failed: {0}")]
    CompilationFailed(String),
}

#[derive(Clone)]
pub struct ServerlessFunction {
    pub definition: FunctionDefinition,
    pub runtime: Option<Arc<crate::plugin::WasmRuntime>>,
    pub compilation_handle: Option<Arc<AsyncCompilationHandle>>,
}

#[derive(Debug, Clone)]
pub struct ServerlessResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
    pub function_name: String,
    pub execution_time_ms: u64,
}

pub struct ServerlessManager {
    functions: RwLock<HashMap<String, ServerlessFunction>>,
    pools: RwLock<HashMap<String, Arc<InstancePool>>>,
    config: RwLock<Option<ServerlessConfig>>,
    runtime: Arc<WasmPluginManager>,
    routes: RwLock<Vec<ServerlessRoute>>,
    #[cfg(feature = "mesh")]
    record_store: RwLock<Option<Arc<crate::mesh::dht::RecordStoreManager>>>,
    #[cfg(feature = "mesh")]
    routing_manager:
        RwLock<Option<Arc<crate::mesh::hierarchical_routing::HierarchicalRoutingManager>>>,
    #[cfg(feature = "mesh")]
    transport: RwLock<Option<Arc<crate::mesh::transport::MeshTransport>>>,
    event_subscriptions: RwLock<HashMap<String, Vec<String>>>,
    #[cfg(feature = "mesh")]
    org_manager: RwLock<Option<Arc<crate::mesh::organization::OrganizationManager>>>,
    #[cfg(feature = "mesh")]
    revocation_list: RwLock<Option<Arc<crate::mesh::peer_auth::GlobalNodeRevocationList>>>,
    compilation_manager: Arc<AsyncCompilationManager>,
}

impl ServerlessManager {
    pub fn new() -> Self {
        Self {
            functions: RwLock::new(HashMap::new()),
            pools: RwLock::new(HashMap::new()),
            config: RwLock::new(None),
            runtime: Arc::new(WasmPluginManager::new()),
            routes: RwLock::new(Vec::new()),
            #[cfg(feature = "mesh")]
            record_store: RwLock::new(None),
            #[cfg(feature = "mesh")]
            routing_manager: RwLock::new(None),
            #[cfg(feature = "mesh")]
            transport: RwLock::new(None),
            event_subscriptions: RwLock::new(HashMap::new()),
            #[cfg(feature = "mesh")]
            org_manager: RwLock::new(None),
            #[cfg(feature = "mesh")]
            revocation_list: RwLock::new(None),
            compilation_manager: Arc::new(AsyncCompilationManager::new()),
        }
    }

    pub fn with_runtime(mut self, runtime: Arc<WasmPluginManager>) -> Self {
        self.runtime = runtime;
        self
    }

    /// Mesh-only features for DHT-integrated serverless execution.
    ///
    /// When the `mesh` feature is enabled, these methods become available:
    /// - `set_record_store()` - Registers functions in the DHT for distributed lookup
    /// - `set_routing_manager()` - Enables hierarchical routing for multi-region deployments
    /// - `set_org_manager()` - Sets the organization manager for tenant isolation
    /// - `set_revocation_list()` - Configures the global node revocation list for security
    /// - `set_transport()` - Sets the mesh transport for peer-to-peer communication
    /// - `verify_caller_permission()` - DHT-based permission verification for function calls
    ///
    /// These features are only available when building with `--features mesh` and allow
    /// serverless functions to participate in the mesh distributed hash table.
    #[cfg(feature = "mesh")]
    pub fn set_record_store(&self, store: Arc<crate::mesh::dht::RecordStoreManager>) {
        *self.record_store.write() = Some(store);
    }

    #[cfg(feature = "mesh")]
    pub fn set_routing_manager(
        &self,
        manager: Arc<crate::mesh::hierarchical_routing::HierarchicalRoutingManager>,
    ) {
        *self.routing_manager.write() = Some(manager);
    }

    #[cfg(feature = "mesh")]
    pub fn set_org_manager(&self, manager: Arc<crate::mesh::organization::OrganizationManager>) {
        *self.org_manager.write() = Some(manager);
    }

    #[cfg(feature = "mesh")]
    pub fn set_revocation_list(&self, list: Arc<crate::mesh::peer_auth::GlobalNodeRevocationList>) {
        *self.revocation_list.write() = Some(list);
    }

    #[cfg(feature = "mesh")]
    pub fn set_transport(&self, transport: Arc<crate::mesh::transport::MeshTransport>) {
        *self.transport.write() = Some(transport);
    }

    pub fn subscribe_to_event(&self, function_name: &str, topic: String) {
        let mut subs = self.event_subscriptions.write();
        subs.entry(topic.clone()).or_insert_with(Vec::new);
        if let Some(funcs) = subs.get_mut(&topic) {
            if !funcs.contains(&function_name.to_string()) {
                funcs.push(function_name.to_string());
                tracing::debug!(
                    "Function '{}' subscribed to event topic '{}'",
                    function_name,
                    topic
                );
            }
        }
    }

    pub fn unsubscribe_from_event(&self, function_name: &str, topic: &str) {
        let mut subs = self.event_subscriptions.write();
        if let Some(funcs) = subs.get_mut(topic) {
            funcs.retain(|f| f != function_name);
            tracing::debug!(
                "Function '{}' unsubscribed from event topic '{}'",
                function_name,
                topic
            );
        }
    }

    pub fn get_subscribed_functions(&self, topic: &str) -> Vec<String> {
        self.event_subscriptions
            .read()
            .get(topic)
            .cloned()
            .unwrap_or_default()
    }

    pub fn publish_event(&self, topic: &str, payload: &[u8]) {
        let subscribers = self.get_subscribed_functions(topic);
        if subscribers.is_empty() {
            return;
        }

        tracing::debug!(
            "Publishing event to topic '{}' for {} subscribers",
            topic,
            subscribers.len()
        );

        let pools = self.pools.read().clone();
        let functions = self.functions.read().clone();
        let topic_owned = topic.to_string();

        for function_name in subscribers {
            if let Some(function) = functions.get(&function_name) {
                if let Some(pool) = pools.get(&function_name) {
                    let payload = payload.to_vec();
                    let function_name = function_name.clone();
                    let pool = pool.clone();
                    let env = function.definition.env.clone();
                    let topic_for_spawn = topic_owned.clone();
                    tokio::spawn(async move {
                        if let Ok(instance) = pool.get_instance().await {
                            let result = instance.instance.invoke_handler(
                                "POST",
                                &format!("/_events/{}", topic_for_spawn),
                                "",
                                &payload,
                                env,
                            );
                            if result.is_ok() {
                                tracing::debug!("Event dispatched to function '{}'", function_name);
                            }
                            pool.return_instance(&instance.id);
                        }
                    });
                }
            }
        }
    }

    #[cfg(feature = "mesh")]
    pub fn verify_caller_permission(
        &self,
        function_name: &str,
        caller_node_id: &str,
        caller_role: crate::mesh::config::MeshNodeRole,
        caller_org_id: Option<&str>,
        caller_tier: Option<u32>,
    ) -> Result<(), ServerlessError> {
        let functions_guard = self.functions.read();
        let function = functions_guard
            .get(function_name)
            .ok_or_else(|| ServerlessError::FunctionNotFound(function_name.to_string()))?;

        let def = &function.definition;

        if let Some(ref revocation_list) = *self.revocation_list.read() {
            if let Some(info) = revocation_list.is_node_revoked(caller_node_id) {
                return Err(ServerlessError::PermissionDenied(format!(
                    "Node {} is revoked: {}",
                    caller_node_id, info.reason
                )));
            }
        }

        if def.require_trusted_caller {
            if !caller_role.is_global() {
                return Err(ServerlessError::PermissionDenied(format!(
                    "Function {} requires trusted (global) caller, but node {} is not global",
                    function_name, caller_node_id
                )));
            }
        }

        if let Some(ref allowed_callers) = def.allowed_callers {
            if !allowed_callers.is_empty() && !allowed_callers.contains(&caller_node_id.to_string())
            {
                return Err(ServerlessError::PermissionDenied(format!(
                    "Node {} not in allowed callers list for function {}",
                    caller_node_id, function_name
                )));
            }
        }

        if let Some(ref allowed_orgs) = def.allowed_orgs {
            if !allowed_orgs.is_empty() {
                let caller_org = caller_org_id.ok_or_else(|| {
                    ServerlessError::PermissionDenied(format!(
                        "Function {} requires org membership, but caller {} has no org",
                        function_name, caller_node_id
                    ))
                })?;
                if !allowed_orgs.contains(&caller_org.to_string()) {
                    return Err(ServerlessError::PermissionDenied(format!(
                        "Org {} not in allowed orgs list for function {}",
                        caller_org, function_name
                    )));
                }
            }
        }

        if let Some(min_tier) = def.min_tier_level {
            let caller_tier_val = caller_tier.ok_or_else(|| {
                ServerlessError::PermissionDenied(format!(
                    "Function {} requires tier {}, but caller {} has no tier",
                    function_name, min_tier, caller_node_id
                ))
            })?;
            if caller_tier_val < min_tier {
                return Err(ServerlessError::PermissionDenied(format!(
                    "Caller tier {} is below minimum tier {} for function {}",
                    caller_tier_val, min_tier, function_name
                )));
            }

            if let Some(ref org_manager) = *self.org_manager.read() {
                let claim = crate::mesh::organization::TierClaim::new(
                    min_tier,
                    format!("tier_{}", min_tier),
                    caller_org_id.unwrap_or("default").to_string(),
                    "mesh".to_string(),
                    uuid::Uuid::new_v4().to_string(),
                );
                if !org_manager.validate_tier_claim(&claim) {
                    return Err(ServerlessError::PermissionDenied(format!(
                        "Tier claim verification failed for function {}",
                        function_name
                    )));
                }
            }
        }

        Ok(())
    }

    pub fn initialize(&self, config: ServerlessConfig) -> Result<(), ServerlessError> {
        if !config.enabled {
            return Err(ServerlessError::Disabled);
        }

        *self.config.write() = Some(config.clone());

        let mut all_routes: Vec<ServerlessRoute> = Vec::new();

        for func_def in &config.functions {
            let compilation_handle = self.compilation_manager.get_or_create(&func_def.name);
            compilation_handle.start_compilation();

            let function = ServerlessFunction {
                definition: func_def.clone(),
                runtime: None,
                compilation_handle: Some(compilation_handle.clone()),
            };

            self.functions
                .write()
                .insert(func_def.name.clone(), function);

            get_global_serverless_registry().register(func_def);

            if let Some(routes_config) = &func_def.routes {
                if !routes_config.is_empty() {
                    let mut func_routes = parse_routes(routes_config, &func_def.name, 1000);
                    all_routes.append(&mut func_routes);
                }
            }

            let func_def_clone = func_def.clone();
            let func_name = func_def.name.clone();
            let runtime = self.runtime.clone();
            let (tx, _rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let compile_result = tokio::task::spawn_blocking({
                    let func_def = func_def_clone.clone();
                    let runtime = runtime.clone();
                    move || {
                        #[cfg(feature = "mesh")]
                        if let Some(wasm_dist) = crate::mesh::get_global_wasm_dist_manager() {
                            if let Some(data) = wasm_dist.get_module_data(
                                &func_def.name,
                                crate::mesh::protocol::WasmModuleType::Serverless,
                            ) {
                                let limits = crate::plugin::WasmResourceLimits {
                                    max_memory_mb: func_def.memory_mb.unwrap_or(64),
                                    max_table_elements: None,
                                    max_cpu_fuel: func_def.cpu_fuel.unwrap_or(1000000),
                                    timeout_seconds: func_def.timeout_seconds.unwrap_or(30),
                                    max_instances: 1,
                                    memory_budget_mb: None,
                                    wasi_enabled: false,
                                    allowed_dht_prefixes: Vec::new(),
                                    ..Default::default()
                                };
                                return runtime.load_plugin_from_memory(
                                    &func_def.name,
                                    &data,
                                    limits,
                                );
                            }
                        }
                        let wasm_dir = std::path::PathBuf::from("plugins");
                        let wasm_path = wasm_dir.join(&func_def.name).with_extension("wasm");
                        if !wasm_path.exists() {
                            return Err(crate::plugin::WasmPluginError::LoadFailed(format!(
                                "WASM file not found: {}",
                                wasm_path.display()
                            )));
                        }
                        let limits = crate::plugin::WasmResourceLimits {
                            max_memory_mb: func_def.memory_mb.unwrap_or(64),
                            max_table_elements: None,
                            max_cpu_fuel: func_def.cpu_fuel.unwrap_or(1000000),
                            timeout_seconds: func_def.timeout_seconds.unwrap_or(30),
                            max_instances: 1,
                            memory_budget_mb: None,
                            wasi_enabled: false,
                            allowed_dht_prefixes: Vec::new(),
                            ..Default::default()
                        };
                        runtime.load_plugin_with_limits(&wasm_path, limits)
                    }
                })
                .await;
                let _ = tx.send((func_name.clone(), compile_result, func_def_clone));
            });
            let func_name = func_def.name.clone();
            let func_def_clone = func_def.clone();
            let pool_config = InstancePoolConfig {
                min_instances: func_def_clone.min_instances.unwrap_or(1),
                max_instances: func_def_clone.max_instances.unwrap_or(10),
                idle_timeout_seconds: func_def_clone.idle_timeout_seconds.unwrap_or(300),
                scale_up_threshold: 0.7,
                scale_down_threshold: 0.3,
                scale_up_cooldown_seconds: 30,
                scale_down_cooldown_seconds: 60,
                pre_warm_instances: func_def_clone.pre_warm_instances.unwrap_or(2),
                max_scale_up_per_tick: 5,
            };
            let pool = Arc::new(
                InstancePool::new(pool_config, func_def_clone.clone())
                    .map_err(|e| ServerlessError::WasmError(e.to_string()))?,
            );
            let pool_clone_for_init = pool.clone();
            let pool_clone_for_autoscaler = pool.clone();
            let func_name_for_init = func_name.clone();
            tokio::spawn(async move {
                if let Err(e) = pool_clone_for_init.initialize().await {
                    tracing::error!(
                        "Failed to pre-warm instances for {}: {}",
                        func_name_for_init,
                        e
                    );
                }
            });
            tokio::spawn(async move {
                pool_clone_for_autoscaler.run_autoscaler().await;
            });
            self.pools.write().insert(func_name.clone(), pool);
            self.compilation_manager.mark_compiling(&func_name);

            #[cfg(feature = "mesh")]
            {
                let record_store = self.record_store.read().clone();
                if let Some(rs) = record_store {
                    let key = crate::mesh::dht::keys::DhtKey::serverless_function(&func_def.name);
                    let node_id = self
                        .transport
                        .read()
                        .as_ref()
                        .map(|t| t.get_mesh_config().node_id().to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    let value = serde_json::json!({
                        "function_name": func_def.name,
                        "version": 1,
                        "node_id": node_id,
                        "routes": func_def.routes,
                        "allowed_methods": func_def.allowed_methods,
                        "memory_mb": func_def.memory_mb,
                        "timeout_seconds": func_def.timeout_seconds,
                        "priority": 100,
                        "announced_at": chrono::Utc::now().timestamp(),
                    });
                    if let Ok(bytes) = serde_json::to_vec(&value) {
                        rs.store_and_announce(key.as_str().to_string(), bytes, 3600);
                        tracing::debug!("Registered serverless function {} in DHT", func_def.name);
                    }
                }

                let routing_manager = self.routing_manager.read().clone();
                if let Some(routing) = routing_manager {
                    let upstream_id = format!("serverless_function:{}", func_def.name);
                    let routing_clone = routing.clone();
                    let func_name = func_def.name.clone();
                    tokio::spawn(async move {
                        routing_clone.register_local_upstream(&upstream_id).await;
                        tracing::debug!(
                            "Registered serverless function {} in hierarchical routing",
                            func_name
                        );
                    });
                }

                if let Some(ref transport) = *self.transport.read() {
                    transport.announce_serverless();
                }
            }
        }

        all_routes.sort_by_key(|r| r.priority);
        *self.routes.write() = all_routes;

        Ok(())
    }

    pub fn process_pending_compilations(&self) {
        for (name, function) in self.functions.read().iter() {
            if let Some(ref compilation_handle) = function.compilation_handle {
                let state = compilation_handle.poll_state();
                if state.is_ready() && function.runtime.is_none() {
                    tracing::warn!(
                        "Function '{}' marked as ready but no runtime available",
                        name
                    );
                }
                if let Some(error) = state.error() {
                    tracing::error!("Function '{}' compilation failed: {}", name, error);
                }
            }
        }
    }

    pub fn get_compilation_status(&self, function_name: &str) -> Option<CompilationState> {
        self.functions
            .read()
            .get(function_name)
            .and_then(|f| f.compilation_handle.as_ref())
            .map(|h| h.poll_state())
    }

    #[allow(dead_code)]
    #[cfg(feature = "mesh")]
    async fn register_function_dht(&self, func_def: &FunctionDefinition) {
        let store = self.record_store.read().clone();
        if let Some(rs) = store {
            let key = crate::mesh::dht::keys::DhtKey::serverless_function(&func_def.name);
            let node_id = self
                .transport
                .read()
                .as_ref()
                .map(|t| t.get_mesh_config().node_id().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let value = serde_json::json!({
                "function_name": func_def.name,
                "version": 1,
                "node_id": node_id,
                "routes": func_def.routes,
                "allowed_methods": func_def.allowed_methods,
                "memory_mb": func_def.memory_mb,
                "timeout_seconds": func_def.timeout_seconds,
                "priority": 100,
                "announced_at": chrono::Utc::now().timestamp(),
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                rs.store_and_announce(key.as_str().to_string(), bytes, 3600);
                tracing::debug!("Registered serverless function {} in DHT", func_def.name);
            }
        }
    }

    #[allow(dead_code)]
    fn load_function_wasm(
        &self,
        func_def: &FunctionDefinition,
    ) -> Result<Arc<crate::plugin::WasmRuntime>, ServerlessError> {
        #[cfg(feature = "mesh")]
        if let Some(wasm_dist) = crate::mesh::get_global_wasm_dist_manager() {
            #[cfg(feature = "mesh")]
            if let Some(data) = wasm_dist.get_module_data(
                &func_def.name,
                crate::mesh::protocol::WasmModuleType::Serverless,
            ) {
                tracing::debug!(
                    "Loading serverless function '{}' from mesh WASM store",
                    func_def.name
                );
                let (default_memory, default_cpu, default_timeout) = self.get_default_limits();
                let limits = WasmResourceLimits {
                    max_memory_mb: func_def.memory_mb.unwrap_or(default_memory),
                    max_table_elements: None,
                    max_cpu_fuel: func_def.cpu_fuel.unwrap_or(default_cpu),
                    timeout_seconds: func_def.timeout_seconds.unwrap_or(default_timeout),
                    max_instances: 1,
                    memory_budget_mb: None,
                    wasi_enabled: false,
                    allowed_dht_prefixes: Vec::new(),
                    ..Default::default()
                };
                return self
                    .runtime
                    .load_plugin_from_memory(&func_def.name, &data, limits)
                    .map_err(|e| ServerlessError::WasmError(e.to_string()));
            }
        }

        let wasm_dir = std::path::PathBuf::from("plugins");
        let wasm_path = wasm_dir.join(&func_def.name).with_extension("wasm");

        if !wasm_path.exists() {
            return Err(ServerlessError::FunctionNotFound(format!(
                "WASM file not found: {}",
                wasm_path.display()
            )));
        }

        let (default_memory, default_cpu, default_timeout) = self.get_default_limits();
        let limits = WasmResourceLimits {
            max_memory_mb: func_def.memory_mb.unwrap_or(default_memory),
            max_table_elements: None,
            max_cpu_fuel: func_def.cpu_fuel.unwrap_or(default_cpu),
            timeout_seconds: func_def.timeout_seconds.unwrap_or(default_timeout),
            max_instances: 1,
            memory_budget_mb: None,
            wasi_enabled: false,
            allowed_dht_prefixes: Vec::new(),
            ..Default::default()
        };

        self.runtime
            .load_plugin_with_limits(&wasm_path, limits)
            .map_err(|e| ServerlessError::WasmError(e.to_string()))
    }

    pub async fn load_function_wasm_async(
        &self,
        func_def: &FunctionDefinition,
    ) -> Result<Arc<crate::plugin::WasmRuntime>, ServerlessError> {
        let runtime = self.runtime.clone();
        let func_def = func_def.clone();
        let default_limits = self.get_default_limits();

        let result = tokio::task::spawn_blocking(move || {
            #[cfg(feature = "mesh")]
            if let Some(wasm_dist) = crate::mesh::get_global_wasm_dist_manager() {
                #[cfg(feature = "mesh")]
                if let Some(data) = wasm_dist.get_module_data(
                    &func_def.name,
                    crate::mesh::protocol::WasmModuleType::Serverless,
                ) {
                    tracing::debug!(
                        "Loading serverless function '{}' from mesh WASM store (async)",
                        func_def.name
                    );
                    let limits = WasmResourceLimits {
                        max_memory_mb: func_def.memory_mb.unwrap_or(default_limits.0),
                        max_table_elements: None,
                        max_cpu_fuel: func_def.cpu_fuel.unwrap_or(default_limits.1),
                        timeout_seconds: func_def.timeout_seconds.unwrap_or(default_limits.2),
                        max_instances: 1,
                        memory_budget_mb: None,
                        wasi_enabled: false,
                        allowed_dht_prefixes: Vec::new(),
                        ..Default::default()
                    };
                    return runtime
                        .load_plugin_from_memory(&func_def.name, &data, limits)
                        .map_err(|e| ServerlessError::WasmError(e.to_string()));
                }
            }

            let wasm_dir = std::path::PathBuf::from("plugins");
            let wasm_path = wasm_dir.join(&func_def.name).with_extension("wasm");

            if !wasm_path.exists() {
                return Err(ServerlessError::FunctionNotFound(format!(
                    "WASM file not found: {}",
                    wasm_path.display()
                )));
            }

            let limits = WasmResourceLimits {
                max_memory_mb: func_def.memory_mb.unwrap_or(default_limits.0),
                max_table_elements: None,
                max_cpu_fuel: func_def.cpu_fuel.unwrap_or(default_limits.1),
                timeout_seconds: func_def.timeout_seconds.unwrap_or(default_limits.2),
                max_instances: 1,
                memory_budget_mb: None,
                wasi_enabled: false,
                allowed_dht_prefixes: Vec::new(),
                ..Default::default()
            };

            runtime
                .load_plugin_with_limits(&wasm_path, limits)
                .map_err(|e| ServerlessError::WasmError(e.to_string()))
        })
        .await
        .map_err(|e| ServerlessError::WasmError(format!("Task join error: {}", e)))??;

        Ok(result)
    }

    fn get_default_limits(&self) -> (usize, u64, u64) {
        let config = self.config.read();
        if let Some(ref cfg) = *config {
            (
                cfg.default_memory_mb,
                cfg.default_cpu_fuel,
                cfg.default_timeout_seconds,
            )
        } else {
            (64, 1000000, 30)
        }
    }

    pub fn get_function(&self, name: &str) -> Option<ServerlessFunction> {
        self.functions.read().get(name).cloned()
    }

    pub fn get_all_functions(&self) -> HashMap<String, ServerlessFunction> {
        self.functions.read().clone()
    }

    pub fn has_function(&self, name: &str) -> bool {
        self.functions.read().contains_key(name)
    }

    pub fn find_matching_function(&self, path: &str) -> Option<ServerlessFunction> {
        let config = self.config.read();
        if let Some(ref cfg) = *config {
            for func in &cfg.functions {
                if path == func.path || path.starts_with(&format!("{}/", func.path)) {
                    return self.functions.read().get(&func.name).cloned();
                }
            }
        }
        None
    }

    pub fn find_matching_route(
        &self,
        path: &str,
        method: &Method,
    ) -> Option<(ServerlessFunction, ServerlessRoute)> {
        let routes = self.routes.read();
        for route in routes.iter() {
            if route.matches(path, method) {
                if let Some(function) = self.functions.read().get(&route.function_name).cloned() {
                    return Some((function, route.clone()));
                }
            }
        }
        drop(routes);

        if let Some(function) = self.find_matching_function(path) {
            let fallback_route = ServerlessRoute {
                matcher: RouteMatch::Prefix(function.definition.path.clone()),
                method: MethodMatch::Any,
                priority: i32::MAX,
                function_name: function.definition.name.clone(),
            };
            return Some((function, fallback_route));
        }

        None
    }

    pub fn is_enabled(&self) -> bool {
        self.config
            .read()
            .as_ref()
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    pub async fn shutdown(&self) {
        let pools = self.pools.read().clone();
        for (name, pool) in pools {
            tracing::info!("Shutting down serverless pool: {}", name);
            pool.shutdown(30).await;
        }
        self.pools.write().clear();
        tracing::info!("ServerlessManager shutdown complete");
    }

    #[cfg(feature = "mesh")]
    pub async fn invoke_for_mesh(
        &self,
        function_name: &str,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
        caller: CallerContext,
    ) -> Result<ServerlessResponse, ServerlessError> {
        let function = self
            .functions
            .read()
            .get(function_name)
            .cloned()
            .ok_or_else(|| ServerlessError::FunctionNotFound(function_name.to_string()))?;

        if !function.definition.public_function.unwrap_or(false) {
            self.verify_caller_permission(
                function_name,
                &caller.node_id,
                caller.role,
                caller.org_id.as_deref(),
                caller.tier,
            )?;
        }

        get_global_serverless_registry().record_invocation(function_name);

        tracing::debug!(
            "Mesh invoking function '{}' for {} {}",
            function_name,
            method,
            path
        );

        let pool = self.pools.read().get(function_name).cloned();

        if let Some(pool) = pool {
            let instance = pool.get_instance().await.map_err(|e| {
                get_global_serverless_registry().record_error(function_name);
                ServerlessError::WasmError(format!("Failed to get instance from pool: {}", e))
            })?;

            let start = Instant::now();
            let uri = path.to_string();
            let method_str = method.to_string();

            let headers_map: std::collections::HashMap<String, String> = headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let headers_json = serde_json::to_string(&headers_map).map_err(|e| {
                get_global_serverless_registry().record_error(function_name);
                ServerlessError::ExecutionError(e.to_string())
            })?;

            let body_vec = body.map(|b| b.to_vec()).unwrap_or_default();
            let env = function.definition.env.clone();

            let result = instance
                .instance
                .invoke_handler(&method_str, &uri, &headers_json, &body_vec, env)
                .map_err(|e| {
                    get_global_serverless_registry().record_error(function_name);
                    ServerlessError::ExecutionError(e.to_string())
                });

            let duration_ms = start.elapsed().as_millis() as u64;
            instance.record_request(duration_ms);
            pool.return_instance(&instance.id);

            return result.map(|response| {
                let status_code = response.status().as_u16();
                let mut resp_headers = HashMap::new();
                for (k, v) in response.headers().iter() {
                    if let Ok(val) = v.to_str() {
                        resp_headers.insert(k.to_string(), val.to_string());
                    }
                }
                ServerlessResponse {
                    status_code,
                    headers: resp_headers,
                    body: response.into_body(),
                    function_name: function_name.to_string(),
                    execution_time_ms: duration_ms,
                }
            });
        }

        let Some(runtime) = function.runtime else {
            if let Some(ref compilation_handle) = function.compilation_handle {
                let state = compilation_handle.poll_state();
                if let crate::serverless::async_compilation::CompilationState::Failed { error } =
                    state
                {
                    get_global_serverless_registry().record_error(function_name);
                    return Err(ServerlessError::CompilationFailed(error));
                }
                if matches!(
                    state,
                    crate::serverless::async_compilation::CompilationState::Compiling { .. }
                ) {
                    tracing::debug!(
                        "Function '{}' compilation in progress, waiting...",
                        function_name
                    );
                    match compilation_handle.wait_for_completion().await {
                        Ok(()) => {
                            let func = self.functions.read().get(function_name).cloned();
                            if let Some(func) = func {
                                if let Some(runtime) = func.runtime.clone() {
                                    return self
                                        .invoke_with_runtime(
                                            runtime,
                                            function_name,
                                            method,
                                            path,
                                            headers,
                                            body,
                                        )
                                        .await;
                                }
                            }
                        }
                        Err(e) => {
                            get_global_serverless_registry().record_error(function_name);
                            return Err(ServerlessError::CompilationFailed(e.to_string()));
                        }
                    }
                }
            }
            get_global_serverless_registry().record_error(function_name);
            return Err(ServerlessError::WasmError(
                "No WASM runtime available".to_string(),
            ));
        };

        self.invoke_with_runtime(runtime, function_name, method, path, headers, body)
            .await
    }

    async fn invoke_with_runtime(
        &self,
        runtime: Arc<crate::plugin::WasmRuntime>,
        function_name: &str,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
    ) -> Result<ServerlessResponse, ServerlessError> {
        let start = Instant::now();
        let uri = path.to_string();
        let method_str = method.to_string();

        let headers_map: std::collections::HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let headers_json = serde_json::to_string(&headers_map).map_err(|e| {
            get_global_serverless_registry().record_error(function_name);
            ServerlessError::ExecutionError(e.to_string())
        })?;

        let body_vec = body.map(|b| b.to_vec()).unwrap_or_default();

        let funcs = self.functions.read();
        let env = funcs
            .get(function_name)
            .map(|f| f.definition.env.clone())
            .unwrap_or_default();
        drop(funcs);

        runtime
            .invoke_handler(&method_str, &uri, &headers_json, &body_vec, env)
            .map(|response| {
                let status_code = response.status().as_u16();
                let mut resp_headers = HashMap::new();
                for (k, v) in response.headers().iter() {
                    if let Ok(val) = v.to_str() {
                        resp_headers.insert(k.to_string(), val.to_string());
                    }
                }
                let execution_time_ms = start.elapsed().as_millis() as u64;
                ServerlessResponse {
                    status_code,
                    headers: resp_headers,
                    body: response.into_body(),
                    function_name: function_name.to_string(),
                    execution_time_ms,
                }
            })
            .map_err(|e| {
                get_global_serverless_registry().record_error(function_name);
                ServerlessError::ExecutionError(e.to_string())
            })
    }

    pub async fn invoke_serverless_with_runtime(
        &self,
        runtime: Arc<crate::plugin::WasmRuntime>,
        function_name: &str,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
    ) -> Result<Response<Bytes>, ServerlessError> {
        let uri = path.to_string();
        let method_str = method.to_string();

        let headers_map: std::collections::HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let headers_json = serde_json::to_string(&headers_map).map_err(|e| {
            get_global_serverless_registry().record_error(function_name);
            ServerlessError::ExecutionError(e.to_string())
        })?;

        let body_vec = body.map(|b| b.to_vec()).unwrap_or_default();

        let funcs = self.functions.read();
        let env = funcs
            .get(function_name)
            .map(|f| f.definition.env.clone())
            .unwrap_or_default();
        drop(funcs);

        runtime
            .invoke_handler(&method_str, &uri, &headers_json, &body_vec, env)
            .map_err(|e| {
                get_global_serverless_registry().record_error(function_name);
                ServerlessError::ExecutionError(e.to_string())
            })
    }

    /// CPU offload invocation: dispatch a function with raw input bytes and
    /// return the response body. No caller permission checks are performed
    /// because CPU offload requests originate from the local data plane and
    /// are considered trusted.
    pub async fn invoke_for_cpu_offload(
        &self,
        function_name: &str,
        input: &[u8],
        _timeout_ms: u64,
    ) -> Result<Vec<u8>, ServerlessError> {
        let function = self
            .functions
            .read()
            .get(function_name)
            .cloned()
            .ok_or_else(|| ServerlessError::FunctionNotFound(function_name.to_string()))?;

        get_global_serverless_registry().record_invocation(function_name);

        if let Some(pool) = self.pools.read().get(function_name).cloned() {
            let instance = pool.get_instance().await.map_err(|e| {
                get_global_serverless_registry().record_error(function_name);
                ServerlessError::WasmError(format!("Failed to get instance from pool: {}", e))
            })?;

            let start = Instant::now();
            let env = function.definition.env.clone();
            let body_vec = input.to_vec();
            let uri = "/".to_string();
            let method_str = "POST".to_string();
            let headers_json = "{}".to_string();

            let result = instance
                .instance
                .invoke_handler(&method_str, &uri, &headers_json, &body_vec, env)
                .map_err(|e| {
                    get_global_serverless_registry().record_error(function_name);
                    ServerlessError::ExecutionError(e.to_string())
                });

            let duration_ms = start.elapsed().as_millis() as u64;
            instance.record_request(duration_ms);
            pool.return_instance(&instance.id);

            return result.map(|response| response.into_body().to_vec());
        }

        let Some(runtime) = function.runtime else {
            if let Some(ref compilation_handle) = function.compilation_handle {
                if let crate::serverless::async_compilation::CompilationState::Compiling {
                    ..
                } = compilation_handle.poll_state()
                {
                    compilation_handle
                        .wait_for_completion()
                        .await
                        .map_err(|e| {
                            get_global_serverless_registry().record_error(function_name);
                            ServerlessError::CompilationFailed(e.to_string())
                        })?;
                    if let Some(func) = self.functions.read().get(function_name).cloned() {
                        if let Some(runtime) = func.runtime.clone() {
                            return self
                                .invoke_runtime_for_offload(runtime, function_name, input)
                                .await;
                        }
                    }
                }
            }
            get_global_serverless_registry().record_error(function_name);
            return Err(ServerlessError::WasmError(
                "No WASM runtime available for CPU offload".to_string(),
            ));
        };

        self.invoke_runtime_for_offload(runtime, function_name, input)
            .await
    }

    async fn invoke_runtime_for_offload(
        &self,
        runtime: Arc<crate::plugin::WasmRuntime>,
        function_name: &str,
        input: &[u8],
    ) -> Result<Vec<u8>, ServerlessError> {
        let funcs = self.functions.read();
        let env = funcs
            .get(function_name)
            .map(|f| f.definition.env.clone())
            .unwrap_or_default();
        drop(funcs);

        let body_vec = input.to_vec();
        let uri = "/".to_string();
        let method_str = "POST".to_string();
        let headers_json = "{}".to_string();

        runtime
            .invoke_handler(&method_str, &uri, &headers_json, &body_vec, env)
            .map(|response| response.into_body().to_vec())
            .map_err(|e| {
                get_global_serverless_registry().record_error(function_name);
                ServerlessError::ExecutionError(e.to_string())
            })
    }
}

impl Default for ServerlessManager {
    fn default() -> Self {
        Self::new()
    }
}

static GLOBAL_SERVERLESS_MANAGER: std::sync::LazyLock<
    parking_lot::RwLock<Option<Arc<ServerlessManager>>>,
> = std::sync::LazyLock::new(|| parking_lot::RwLock::new(None));

pub fn set_global_serverless_manager(manager: Arc<ServerlessManager>) {
    *GLOBAL_SERVERLESS_MANAGER.write() = Some(manager);
}

pub fn get_global_serverless_manager() -> Option<Arc<ServerlessManager>> {
    GLOBAL_SERVERLESS_MANAGER.read().clone()
}

pub fn clear_global_serverless_manager() {
    *GLOBAL_SERVERLESS_MANAGER.write() = None;
}

#[cfg(feature = "mesh")]
pub async fn handle_serverless_function(
    manager: &ServerlessManager,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    caller: CallerContext,
) -> Result<Response<Bytes>, ServerlessError> {
    let (function, route) = manager
        .find_matching_route(path, method)
        .ok_or_else(|| ServerlessError::NoMatchingRoute(format!("{} {}", method, path)))?;

    let function_name = function.definition.name.clone();
    get_global_serverless_registry().record_invocation(&function_name);

    if !function.definition.public_function.unwrap_or(false) {
        manager.verify_caller_permission(
            &function_name,
            &caller.node_id,
            caller.role,
            caller.org_id.as_deref(),
            caller.tier,
        )?;
    }

    tracing::debug!(
        "Routing {} {} to function '{}' via route (priority: {})",
        method,
        path,
        function_name,
        route.priority
    );

    // Check if we have a local WASM runtime for this function or compilation in progress
    let compilation_in_progress = function
        .compilation_handle
        .as_ref()
        .map(|h| {
            matches!(
                h.poll_state(),
                crate::serverless::async_compilation::CompilationState::Compiling { .. }
            )
        })
        .unwrap_or(false);

    let has_local_runtime = function.runtime.is_some()
        || manager.pools.read().contains_key(&function_name)
        || compilation_in_progress;

    // If no local runtime and not compiling, try to find a provider via DHT
    #[cfg(feature = "mesh")]
    if !has_local_runtime {
        let upstream_id = format!("serverless_function:{}", function_name);
        if let Some(rs) = manager.record_store.read().as_ref() {
            if rs.get_record(&upstream_id).is_some() {
                tracing::debug!(
                    "Serverless function '{}' not local, found provider in DHT",
                    function_name
                );
                return Err(ServerlessError::RemoteExecutionRequired(upstream_id));
            }
        }
    }

    let pool = manager.pools.read().get(&function_name).cloned();

    if let Some(pool) = pool {
        let instance = pool.get_instance().await.map_err(|e| {
            get_global_serverless_registry().record_error(&function_name);
            ServerlessError::WasmError(format!("Failed to get instance from pool: {}", e))
        })?;

        let start = Instant::now();
        let uri = path.to_string();
        let method_str = method.to_string();

        let headers_map: std::collections::HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let headers_json = serde_json::to_string(&headers_map).map_err(|e| {
            get_global_serverless_registry().record_error(&function_name);
            ServerlessError::ExecutionError(e.to_string())
        })?;

        let body_vec = body.map(|b| b.to_vec()).unwrap_or_default();

        let env = function.definition.env.clone();
        let result = instance
            .instance
            .invoke_handler(&method_str, &uri, &headers_json, &body_vec, env)
            .map_err(|e| {
                get_global_serverless_registry().record_error(&function_name);
                ServerlessError::ExecutionError(e.to_string())
            });

        let duration_ms = start.elapsed().as_millis() as u64;
        instance.record_request(duration_ms);
        pool.return_instance(&instance.id);

        return result;
    }

    let Some(runtime) = function.runtime else {
        if let Some(ref compilation_handle) = function.compilation_handle {
            let state = compilation_handle.poll_state();
            if let crate::serverless::async_compilation::CompilationState::Failed { error } = state
            {
                get_global_serverless_registry().record_error(&function_name);
                return Err(ServerlessError::CompilationFailed(error));
            }
            if matches!(
                state,
                crate::serverless::async_compilation::CompilationState::Compiling { .. }
            ) {
                tracing::debug!(
                    "Function '{}' compilation in progress, waiting...",
                    function_name
                );
                match compilation_handle.wait_for_completion().await {
                    Ok(()) => {
                        let func = manager.functions.read().get(&function_name).cloned();
                        if let Some(func) = func {
                            if let Some(runtime) = func.runtime.clone() {
                                return manager
                                    .invoke_serverless_with_runtime(
                                        runtime,
                                        &function_name,
                                        method,
                                        path,
                                        headers,
                                        body,
                                    )
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        get_global_serverless_registry().record_error(&function_name);
                        return Err(ServerlessError::CompilationFailed(e.to_string()));
                    }
                }
            }
        }
        get_global_serverless_registry().record_error(&function_name);
        return Err(ServerlessError::WasmError(
            "No WASM runtime available".to_string(),
        ));
    };

    let uri = path.to_string();
    let method_str = method.to_string();

    let headers_map: std::collections::HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let headers_json = serde_json::to_string(&headers_map).map_err(|e| {
        get_global_serverless_registry().record_error(&function_name);
        ServerlessError::ExecutionError(e.to_string())
    })?;

    let body_vec = body.map(|b| b.to_vec()).unwrap_or_default();

    let env = function.definition.env.clone();
    runtime
        .invoke_handler(&method_str, &uri, &headers_json, &body_vec, env)
        .map_err(|e| {
            get_global_serverless_registry().record_error(&function_name);
            ServerlessError::ExecutionError(e.to_string())
        })
}

pub async fn handle_serverless_function_streaming(
    manager: &ServerlessManager,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Box<dyn ErasedBody>,
    _context: CallerContext,
) -> Result<Response<Bytes>, ServerlessError> {
    let routes = manager.routes.read();
    let Some(route) = routes.iter().find(|r| r.matches(path, method)) else {
        return Err(ServerlessError::NoMatchingRoute(path.to_string()));
    };

    let function_name = route.function_name.clone();
    let functions = manager.functions.read();
    let Some(function) = functions.get(&function_name).cloned() else {
        return Err(ServerlessError::FunctionNotFound(function_name));
    };
    drop(functions);
    drop(routes);

    let Some(runtime) = function.runtime else {
        return Err(ServerlessError::WasmError(
            "No WASM runtime available for streaming".to_string(),
        ));
    };

    let uri = path.to_string();
    let method_str = method.to_string();

    let headers_map: std::collections::HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let headers_json = serde_json::to_string(&headers_map).map_err(|e| {
        get_global_serverless_registry().record_error(&function_name);
        ServerlessError::ExecutionError(e.to_string())
    })?;

    let env = function.definition.env.clone();
    runtime
        .invoke_handler_streaming(&method_str, &uri, &headers_json, body, env)
        .map_err(|e| {
            get_global_serverless_registry().record_error(&function_name);
            ServerlessError::ExecutionError(e.to_string())
        })
}
