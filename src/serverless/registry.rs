use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::config::serverless::FunctionDefinition;

#[derive(Clone)]
pub struct FunctionMetadata {
    pub name: String,
    pub description: Option<String>,
    pub route_count: usize,
    pub allowed_methods: Vec<String>,
    pub memory_mb: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub registered_at: Instant,
    pub last_invoked: Option<Instant>,
    pub invocation_count: u64,
    pub error_count: u64,
}

#[derive(Clone)]
pub struct FunctionStats {
    pub invocation_count: u64,
    pub error_count: u64,
    pub avg_errors_per_invocation: f64,
}

pub struct ServerlessRegistry {
    functions: RwLock<HashMap<String, FunctionMetadata>>,
}

impl ServerlessRegistry {
    pub fn new() -> Self {
        Self {
            functions: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, def: &FunctionDefinition) {
        let metadata = FunctionMetadata {
            name: def.name.clone(),
            description: def.description.clone(),
            route_count: def.routes.as_ref().map(|r| r.len()).unwrap_or(0),
            allowed_methods: def.allowed_methods.clone().unwrap_or_default(),
            memory_mb: def.memory_mb,
            timeout_seconds: def.timeout_seconds,
            registered_at: Instant::now(),
            last_invoked: None,
            invocation_count: 0,
            error_count: 0,
        };
        self.functions.write().insert(def.name.clone(), metadata);
    }

    pub fn unregister(&self, name: &str) -> bool {
        self.functions.write().remove(name).is_some()
    }

    pub fn get(&self, name: &str) -> Option<FunctionMetadata> {
        self.functions.read().get(name).cloned()
    }

    pub fn list(&self) -> Vec<FunctionMetadata> {
        self.functions.read().values().cloned().collect()
    }

    pub fn record_invocation(&self, name: &str) {
        if let Some(metadata) = self.functions.write().get_mut(name) {
            metadata.invocation_count += 1;
            metadata.last_invoked = Some(Instant::now());
        }
    }

    pub fn record_error(&self, name: &str) {
        if let Some(metadata) = self.functions.write().get_mut(name) {
            metadata.error_count += 1;
        }
    }

    pub fn get_stats(&self, name: &str) -> Option<FunctionStats> {
        self.functions.read().get(name).map(|m| {
            let avg = if m.invocation_count > 0 {
                m.error_count as f64 / m.invocation_count as f64
            } else {
                0.0
            };
            FunctionStats {
                invocation_count: m.invocation_count,
                error_count: m.error_count,
                avg_errors_per_invocation: avg,
            }
        })
    }
}

impl Default for ServerlessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

static SERVERLESS_REGISTRY: std::sync::LazyLock<Arc<ServerlessRegistry>> =
    std::sync::LazyLock::new(|| Arc::new(ServerlessRegistry::new()));

pub fn get_global_serverless_registry() -> Arc<ServerlessRegistry> {
    SERVERLESS_REGISTRY.clone()
}
