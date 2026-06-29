use std::sync::Arc;
use std::time::{Duration, Instant};

use wasmtime::{Instance, Store};

use crate::sandbox::types::PluginCapabilities;
use crate::wasm_runtime::RequestContext;

pub struct PooledInstance {
    pub instance: Instance,
    pub(crate) store: Store<RequestContext>,
    pub filter_name: String,
    pub max_cpu_fuel: u64,
    pub(crate) allowed_dht_prefixes: Vec<String>,
    pub(crate) capabilities: Arc<PluginCapabilities>,
}

impl PooledInstance {
    pub fn prepare_for_request(
        &mut self,
        env: std::collections::HashMap<String, String>,
        timeout_seconds: u64,
        allowed_dht_prefixes: Vec<String>,
        capabilities: Arc<PluginCapabilities>,
    ) {
        self.store.data_mut().start = Instant::now();
        self.store.data_mut().timeout = Duration::from_secs(timeout_seconds);
        self.store.data_mut().env = env;
        self.store.data_mut().body_receiver = None;
        self.store.data_mut().allowed_dht_prefixes = allowed_dht_prefixes;
        self.store.data_mut().capabilities = capabilities;
        if self.max_cpu_fuel > 0 {
            self.store.set_fuel(self.max_cpu_fuel).ok();
        }
    }
}

pub trait WasmPool {
    fn get(&self, filter_name: &str) -> Option<PooledInstance>;
    fn return_instance(&self, instance: PooledInstance);
    fn max_size(&self) -> usize;
}
