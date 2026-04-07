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

struct WasmModuleVersionData {
    info: WasmModuleInfo,
    #[allow(dead_code)]
    stored_at: std::time::Instant,
}

struct VersionedWasmModuleEntry {
    current_version: u64,
    versions: HashMap<u64, WasmModuleVersionData>,
}

struct WasmModuleEntry {
    info: WasmModuleInfo,
    stored_at: std::time::Instant,
    version: u64,
}

pub struct WasmModuleStore {
    modules: RwLock<HashMap<String, VersionedWasmModuleEntry>>,
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
            version: 1,
        };

        let mut modules = self.modules.write();
        let versioned_entry = modules
            .entry(key)
            .or_insert_with(|| VersionedWasmModuleEntry {
                current_version: 1,
                versions: HashMap::new(),
            });

        versioned_entry.current_version = entry.version;
        versioned_entry.versions.insert(
            entry.version,
            WasmModuleVersionData {
                info: entry.info,
                stored_at: entry.stored_at,
            },
        );

        Ok(())
    }

    pub fn store_versioned(&self, info: WasmModuleInfo) -> Result<(), WasmStoreError> {
        let key = Self::module_key(&info.module_name, info.module_type);

        let computed_checksum = Self::compute_checksum(&info.data);
        if computed_checksum != info.checksum {
            return Err(WasmStoreError::ChecksumMismatch {
                expected: info.checksum,
                actual: computed_checksum,
            });
        }

        let mut modules = self.modules.write();
        let versioned_entry = modules
            .entry(key)
            .or_insert_with(|| VersionedWasmModuleEntry {
                current_version: 0,
                versions: HashMap::new(),
            });

        let new_version = versioned_entry.current_version + 1;
        versioned_entry.current_version = new_version;
        versioned_entry.versions.insert(
            new_version,
            WasmModuleVersionData {
                info,
                stored_at: std::time::Instant::now(),
            },
        );

        Ok(())
    }

    pub fn get(&self, name: &str, module_type: WasmModuleType) -> Option<WasmModuleInfo> {
        self.get_by_version(name, module_type, 0).or_else(|| {
            self.get_latest_version(name, module_type)
                .map(|(_, info)| info)
        })
    }

    pub fn get_by_version(
        &self,
        name: &str,
        module_type: WasmModuleType,
        version: u64,
    ) -> Option<WasmModuleInfo> {
        let key = Self::module_key(name, module_type);
        let modules = self.modules.read();
        modules.get(&key).and_then(|entry| {
            if version == 0 {
                entry
                    .versions
                    .get(&entry.current_version)
                    .map(|v| v.info.clone())
            } else {
                entry.versions.get(&version).map(|v| v.info.clone())
            }
        })
    }

    pub fn get_latest_version(
        &self,
        name: &str,
        module_type: WasmModuleType,
    ) -> Option<(u64, WasmModuleInfo)> {
        let key = Self::module_key(name, module_type);
        let modules = self.modules.read();
        modules.get(&key).map(|entry| {
            let version = entry.current_version;
            let info = entry.versions.get(&version).unwrap().info.clone();
            (version, info)
        })
    }

    pub fn list_versions(&self, name: &str, module_type: WasmModuleType) -> Vec<u64> {
        let key = Self::module_key(name, module_type);
        let modules = self.modules.read();
        modules
            .get(&key)
            .map(|entry| {
                let mut versions: Vec<u64> = entry.versions.keys().copied().collect();
                versions.sort_unstable();
                versions
            })
            .unwrap_or_default()
    }

    pub fn gc_old_versions(
        &self,
        name: &str,
        module_type: WasmModuleType,
        keep_versions: u64,
    ) -> usize {
        let key = Self::module_key(name, module_type);
        let mut modules = self.modules.write();

        let Some(entry) = modules.get_mut(&key) else {
            return 0;
        };

        if keep_versions == 0 {
            return 0;
        }

        let current_version = entry.current_version;
        let mut versions: Vec<u64> = entry.versions.keys().copied().collect();
        versions.sort_unstable();

        let versions_to_remove: Vec<u64> = versions
            .into_iter()
            .rev()
            .skip(keep_versions as usize)
            .filter(|&v| v != current_version)
            .collect();

        let count = versions_to_remove.len();
        for version in versions_to_remove {
            entry.versions.remove(&version);
        }

        count
    }

    pub fn get_data(&self, name: &str, module_type: WasmModuleType) -> Option<Vec<u8>> {
        let key = Self::module_key(name, module_type);
        self.modules
            .read()
            .get(&key)
            .and_then(|entry| entry.versions.get(&entry.current_version))
            .map(|entry| entry.info.data.clone())
    }

    pub fn has_module(&self, name: &str, module_type: WasmModuleType) -> bool {
        let key = Self::module_key(name, module_type);
        self.modules.read().contains_key(&key)
    }

    pub fn list_modules(&self, module_type: Option<WasmModuleType>) -> Vec<WasmModuleInfo> {
        let modules = self.modules.read();
        modules
            .values()
            .filter(|e| {
                e.versions
                    .get(&e.current_version)
                    .map(|v| module_type.map(|t| v.info.module_type == t).unwrap_or(true))
                    .unwrap_or(false)
            })
            .filter_map(|e| e.versions.get(&e.current_version).map(|v| v.info.clone()))
            .collect()
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
            .and_then(|entry| entry.versions.get(&entry.current_version))
            .map(|entry| (entry.info.size_bytes, entry.info.checksum.clone()))
    }

    pub fn get_current_version(&self, name: &str, module_type: WasmModuleType) -> Option<u64> {
        let key = Self::module_key(name, module_type);
        self.modules.read().get(&key).map(|e| e.current_version)
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

    pub fn gc_module_old_versions(
        &self,
        name: &str,
        module_type: WasmModuleType,
        keep_versions: u64,
    ) -> usize {
        self.store.gc_old_versions(name, module_type, keep_versions)
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

    pub fn get_module_current_version(
        &self,
        name: &str,
        module_type: WasmModuleType,
    ) -> Option<u64> {
        self.store.get_current_version(name, module_type)
    }
}

impl Default for WasmDistManager {
    fn default() -> Self {
        Self::new()
    }
}
