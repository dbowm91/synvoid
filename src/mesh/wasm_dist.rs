use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::mesh::protocol::{WasmModuleInfo, WasmModuleType};

#[allow(clippy::new_without_default)]
pub struct WasmDistManager {
    store: WasmModuleStore,
}

impl Default for WasmDistManager {
    fn default() -> Self {
        Self {
            store: WasmModuleStore::new(),
        }
    }
}

impl WasmDistManager {
    pub fn new() -> Self {
        Self {
            store: WasmModuleStore::new(),
        }
    }

    pub fn store(&self, info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        self.store.store(info)
    }

    pub fn store_versioned(&self, info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        self.store.store_versioned(info)
    }

    pub fn get_module(&self, name: &str, module_type: WasmModuleType) -> Option<WasmModuleInfo> {
        self.store.get(name, module_type)
    }

    pub fn get_module_data(&self, name: &str, module_type: WasmModuleType) -> Option<Vec<u8>> {
        self.store.get_data(name, module_type)
    }

    pub fn get_module_by_version(
        &self,
        name: &str,
        module_type: WasmModuleType,
        version: u64,
    ) -> Option<WasmModuleInfo> {
        self.store.get_by_version(name, module_type, version)
    }

    pub fn get_module_latest_version(
        &self,
        name: &str,
        module_type: WasmModuleType,
    ) -> Option<(u64, WasmModuleInfo)> {
        self.store.get_latest_version(name, module_type)
    }

    pub fn list_module_versions(&self, name: &str, module_type: WasmModuleType) -> Vec<u64> {
        self.store.list_versions(name, module_type)
    }
}

#[derive(Debug, Clone)]
pub enum WasmStoreError {
    StoreError(String),
}

impl std::fmt::Display for WasmStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WasmStoreError::StoreError(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for WasmStoreError {}

#[derive(Clone, Default)]
pub struct WasmModuleStore {
    modules: Arc<RwLock<HashMap<(String, WasmModuleType, u64), WasmModuleInfo>>>,
}

impl WasmModuleStore {
    pub fn new() -> Self {
        Self {
            modules: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn store(&self, info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        let mut modules = self.modules.write();
        modules.insert(
            (info.module_name.clone(), info.module_type, info.version),
            info,
        );
        Ok(())
    }

    pub fn store_versioned(&self, info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        self.store(info)
    }

    pub fn get(&self, name: &str, module_type: WasmModuleType) -> Option<WasmModuleInfo> {
        let modules = self.modules.read();
        modules
            .values()
            .filter(|m| m.module_name == name && m.module_type == module_type)
            .max_by_key(|m| m.version)
            .cloned()
    }

    pub fn get_data(&self, name: &str, module_type: WasmModuleType) -> Option<Vec<u8>> {
        self.get(name, module_type).map(|m| m.data)
    }

    pub fn get_by_version(
        &self,
        name: &str,
        module_type: WasmModuleType,
        version: u64,
    ) -> Option<WasmModuleInfo> {
        let modules = self.modules.read();
        modules
            .get(&(name.to_string(), module_type, version))
            .cloned()
    }

    pub fn get_latest_version(
        &self,
        name: &str,
        module_type: WasmModuleType,
    ) -> Option<(u64, WasmModuleInfo)> {
        self.get(name, module_type).map(|m| (m.version, m))
    }

    pub fn list_versions(&self, name: &str, module_type: WasmModuleType) -> Vec<u64> {
        let modules = self.modules.read();
        let mut versions: Vec<u64> = modules
            .keys()
            .filter(|(n, t, _)| n == name && *t == module_type)
            .map(|(_, _, v)| *v)
            .collect();
        versions.sort();
        versions
    }
}

#[allow(dead_code)]
static WASM_DIST_MANAGER: std::sync::LazyLock<Arc<RwLock<Option<Arc<WasmDistManager>>>>> =
    std::sync::LazyLock::new(|| Arc::new(RwLock::new(None)));

pub fn set_global_wasm_dist_manager(manager: Arc<WasmDistManager>) {
    *WASM_DIST_MANAGER.write() = Some(manager);
}

pub fn get_global_wasm_dist_manager() -> Option<Arc<WasmDistManager>> {
    WASM_DIST_MANAGER.read().clone()
}

pub fn new_wasm_module_store() -> WasmModuleStore {
    WasmModuleStore::new()
}
