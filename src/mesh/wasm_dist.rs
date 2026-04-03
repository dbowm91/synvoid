use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use crate::mesh::protocol::{WasmModuleInfo, WasmModuleType};

static WASM_DIST_MANAGER: LazyLock<Arc<RwLock<Option<Arc<WasmDistManager>>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

pub fn set_global_wasm_dist_manager(manager: Arc<WasmDistManager>) {
    let mut global = WASM_DIST_MANAGER.write();
    *global = Some(manager);
}

pub fn get_global_wasm_dist_manager() -> Option<Arc<WasmDistManager>> {
    WASM_DIST_MANAGER.read().clone()
}

pub struct WasmModuleStore {
    modules: RwLock<HashMap<String, WasmModuleEntry>>,
}

struct WasmModuleEntry {
    info: WasmModuleInfo,
    stored_at: std::time::Instant,
}

impl WasmModuleStore {
    pub fn new() -> Self {
        Self {
            modules: RwLock::new(HashMap::new()),
        }
    }

    pub fn store(&self, info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        let key = Self::module_key(&info.module_name, info.module_type);

        let computed_checksum = Self::compute_checksum(&info.data);
        if computed_checksum != info.checksum {
            return Err(WasmStoreError::ChecksumMismatch {
                expected: info.checksum,
                actual: computed_checksum,
            });
        }

        let entry = WasmModuleEntry {
            info,
            stored_at: std::time::Instant::now(),
        };

        self.modules.write().insert(key, entry);
        Ok(())
    }

    pub fn get(&self, name: &str, module_type: WasmModuleType) -> Option<WasmModuleInfo> {
        let key = Self::module_key(name, module_type);
        self.modules
            .read()
            .get(&key)
            .map(|entry| entry.info.clone())
    }

    pub fn get_data(&self, name: &str, module_type: WasmModuleType) -> Option<Vec<u8>> {
        let key = Self::module_key(name, module_type);
        self.modules
            .read()
            .get(&key)
            .map(|entry| entry.info.data.clone())
    }

    pub fn has_module(&self, name: &str, module_type: WasmModuleType) -> bool {
        let key = Self::module_key(name, module_type);
        self.modules.read().contains_key(&key)
    }

    pub fn list_modules(&self, module_type: Option<WasmModuleType>) -> Vec<WasmModuleInfo> {
        let modules = self.modules.read();
        match module_type {
            Some(t) => modules
                .values()
                .filter(|e| e.info.module_type == t)
                .map(|e| e.info.clone())
                .collect(),
            None => modules.values().map(|e| e.info.clone()).collect(),
        }
    }

    pub fn remove(&self, name: &str, module_type: WasmModuleType) -> bool {
        let key = Self::module_key(name, module_type);
        self.modules.write().remove(&key).is_some()
    }

    pub fn clear(&self) {
        self.modules.write().clear();
    }

    fn module_key(name: &str, module_type: WasmModuleType) -> String {
        format!("{:?}:{}", module_type, name)
    }

    fn compute_checksum(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    pub fn compute_data_checksum(data: &[u8]) -> String {
        Self::compute_checksum(data)
    }

    pub fn get_module_info(
        &self,
        name: &str,
        module_type: WasmModuleType,
    ) -> Option<(u64, String)> {
        let key = Self::module_key(name, module_type);
        self.modules
            .read()
            .get(&key)
            .map(|entry| (entry.info.size_bytes, entry.info.checksum.clone()))
    }
}

impl Default for WasmModuleStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WasmStoreError {
    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("Module not found: {0}")]
    NotFound(String),
    #[error("Store error: {0}")]
    StoreError(String),
}

#[derive(Clone)]
pub struct WasmDistManager {
    store: Arc<WasmModuleStore>,
}

impl WasmDistManager {
    pub fn new() -> Self {
        Self {
            store: Arc::new(WasmModuleStore::new()),
        }
    }

    pub fn store(&self, info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        self.store.store(info)
    }

    pub fn get_module(&self, name: &str, module_type: WasmModuleType) -> Option<WasmModuleInfo> {
        self.store.get(name, module_type)
    }

    pub fn get_module_data(&self, name: &str, module_type: WasmModuleType) -> Option<Vec<u8>> {
        self.store.get_data(name, module_type)
    }

    pub fn has_module(&self, name: &str, module_type: WasmModuleType) -> bool {
        self.store.has_module(name, module_type)
    }

    pub fn has_all_modules(&self, names: &[String], module_type: WasmModuleType) -> bool {
        names.iter().all(|n| self.has_module(n, module_type))
    }

    pub fn list_plugins(&self) -> Vec<WasmModuleInfo> {
        self.store.list_modules(Some(WasmModuleType::Plugin))
    }

    pub fn list_serverless(&self) -> Vec<WasmModuleInfo> {
        self.store.list_modules(Some(WasmModuleType::Serverless))
    }

    pub fn remove(&self, name: &str, module_type: WasmModuleType) -> bool {
        self.store.remove(name, module_type)
    }

    pub fn module_count(&self) -> usize {
        self.store.modules.read().len()
    }
}

impl Default for WasmDistManager {
    fn default() -> Self {
        Self::new()
    }
}
