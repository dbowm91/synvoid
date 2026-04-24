use parking_lot::RwLock;
use std::sync::Arc;

use crate::mesh::protocol::{WasmModuleInfo, WasmModuleType};

#[allow(clippy::new_without_default)]
pub struct WasmDistManager;

impl Default for WasmDistManager {
    fn default() -> Self {
        Self
    }
}

impl WasmDistManager {
    pub fn new() -> Self {
        Self
    }

    #[allow(clippy::new_without_default)]
    pub fn store(&self, _info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        Err(WasmStoreError::StoreError(
            "WasmDistManager is disabled".to_string(),
        ))
    }

    pub fn store_versioned(&self, _info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        Err(WasmStoreError::StoreError(
            "WasmDistManager is disabled".to_string(),
        ))
    }

    pub fn get_module(&self, _name: &str, _module_type: WasmModuleType) -> Option<WasmModuleInfo> {
        None
    }

    pub fn get_module_data(&self, _name: &str, _module_type: WasmModuleType) -> Option<Vec<u8>> {
        None
    }

    pub fn get_module_by_version(
        &self,
        _name: &str,
        _module_type: WasmModuleType,
        _version: u64,
    ) -> Option<WasmModuleInfo> {
        None
    }

    pub fn get_module_latest_version(
        &self,
        _name: &str,
        _module_type: WasmModuleType,
    ) -> Option<(u64, WasmModuleInfo)> {
        None
    }

    pub fn list_module_versions(&self, _name: &str, _module_type: WasmModuleType) -> Vec<u64> {
        Vec::new()
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

#[allow(clippy::new_without_default)]
pub struct WasmModuleStore;

impl Default for WasmModuleStore {
    fn default() -> Self {
        Self
    }
}

impl WasmModuleStore {
    pub fn new() -> Self {
        Self
    }

    pub fn store(&self, _info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        Err(WasmStoreError::StoreError(
            "WasmModuleStore is disabled".to_string(),
        ))
    }

    pub fn store_versioned(&self, _info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        Err(WasmStoreError::StoreError(
            "WasmModuleStore is disabled".to_string(),
        ))
    }

    pub fn get(&self, _name: &str, _module_type: WasmModuleType) -> Option<WasmModuleInfo> {
        None
    }

    pub fn get_data(&self, _name: &str, _module_type: WasmModuleType) -> Option<Vec<u8>> {
        None
    }

    pub fn get_by_version(
        &self,
        _name: &str,
        _module_type: WasmModuleType,
        _version: u64,
    ) -> Option<WasmModuleInfo> {
        None
    }

    pub fn get_latest_version(
        &self,
        _name: &str,
        _module_type: WasmModuleType,
    ) -> Option<(u64, WasmModuleInfo)> {
        None
    }

    pub fn list_versions(&self, _name: &str, _module_type: WasmModuleType) -> Vec<u64> {
        Vec::new()
    }
}

#[allow(dead_code)]
static WASM_DIST_MANAGER: std::sync::LazyLock<Arc<RwLock<Option<Arc<WasmDistManager>>>>> =
    std::sync::LazyLock::new(|| Arc::new(RwLock::new(None)));

pub fn set_global_wasm_dist_manager(_manager: Arc<WasmDistManager>) {
    tracing::warn!("WasmDistManager is disabled - set_global_wasm_dist_manager is a no-op");
}

pub fn get_global_wasm_dist_manager() -> Option<Arc<WasmDistManager>> {
    None
}

pub fn new_wasm_module_store() -> WasmModuleStore {
    WasmModuleStore::new()
}
