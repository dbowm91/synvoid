use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;

use crate::plugin::WasmPluginManager;

static GLOBAL_PLUGIN_MANAGER: std::sync::LazyLock<Arc<GlobalPluginManager>> =
    std::sync::LazyLock::new(|| Arc::new(GlobalPluginManager::new()));

#[derive(Debug, Error)]
pub enum MemoryBudgetError {
    #[error("Memory budget exceeded: requested {requested}MB but only {available}MB available (max {max}MB)")]
    Exceeded {
        requested: usize,
        available: usize,
        max: usize,
    },
    #[error("Plugin '{0}' not found in budget allocations")]
    PluginNotFound(String),
}

pub struct GlobalWasmMemoryBudget {
    max_total_memory_mb: usize,
    current_allocated_mb: RwLock<usize>,
    plugin_allocations: RwLock<HashMap<String, usize>>,
}

impl GlobalWasmMemoryBudget {
    pub fn new(max_memory_mb: usize) -> Self {
        Self {
            max_total_memory_mb: max_memory_mb,
            current_allocated_mb: RwLock::new(0),
            plugin_allocations: RwLock::new(HashMap::new()),
        }
    }

    pub fn try_allocate(
        &self,
        plugin_name: &str,
        memory_mb: usize,
    ) -> Result<(), MemoryBudgetError> {
        let mut current = self.current_allocated_mb.write();
        let new_total = (*current).saturating_add(memory_mb);

        if new_total > self.max_total_memory_mb {
            let available = self.max_total_memory_mb.saturating_sub(*current);
            return Err(MemoryBudgetError::Exceeded {
                requested: memory_mb,
                available,
                max: self.max_total_memory_mb,
            });
        }

        *current = new_total;
        self.plugin_allocations
            .write()
            .insert(plugin_name.to_string(), memory_mb);

        tracing::debug!(
            "GlobalWasmMemoryBudget: allocated {}MB for plugin '{}' (total: {}/{}MB)",
            memory_mb,
            plugin_name,
            new_total,
            self.max_total_memory_mb
        );

        Ok(())
    }

    pub fn deallocate(&self, plugin_name: &str) -> usize {
        let mut current = self.current_allocated_mb.write();
        let allocation = self
            .plugin_allocations
            .write()
            .remove(plugin_name)
            .unwrap_or(0);

        if allocation > 0 {
            *current = (*current).saturating_sub(allocation);
            tracing::debug!(
                "GlobalWasmMemoryBudget: deallocated {}MB for plugin '{}' (total: {}/{}MB)",
                allocation,
                plugin_name,
                *current,
                self.max_total_memory_mb
            );
        }

        allocation
    }

    pub fn get_current_usage_mb(&self) -> usize {
        *self.current_allocated_mb.read()
    }

    pub fn get_max_mb(&self) -> usize {
        self.max_total_memory_mb
    }

    pub fn get_plugin_count(&self) -> usize {
        self.plugin_allocations.read().len()
    }

    pub fn get_plugin_allocation(&self, plugin_name: &str) -> Option<usize> {
        self.plugin_allocations.read().get(plugin_name).copied()
    }
}

impl Default for GlobalWasmMemoryBudget {
    fn default() -> Self {
        Self::new(256)
    }
}

pub struct GlobalPluginManager {
    wasm_manager: Arc<WasmPluginManager>,
    memory_budget: Arc<GlobalWasmMemoryBudget>,
}

impl GlobalPluginManager {
    pub fn new() -> Self {
        Self {
            wasm_manager: Arc::new(WasmPluginManager::new()),
            memory_budget: Arc::new(GlobalWasmMemoryBudget::default()),
        }
    }

    pub fn with_max_memory(mut self, max_bytes: usize) -> Self {
        self.memory_budget = Arc::new(GlobalWasmMemoryBudget::new(max_bytes / (1024 * 1024)));
        self
    }

    pub fn get_wasm_manager(&self) -> Arc<WasmPluginManager> {
        self.wasm_manager.clone()
    }

    pub fn memory_budget(&self) -> &Arc<GlobalWasmMemoryBudget> {
        &self.memory_budget
    }

    pub fn record_allocation(&self, bytes: usize) {
        self.memory_budget
            .try_allocate("global", bytes / (1024 * 1024))
            .ok();
    }

    pub fn record_deallocation(&self, _bytes: usize) {
        self.memory_budget.deallocate("global");
    }

    pub fn current_memory_usage(&self) -> usize {
        self.memory_budget.get_current_usage_mb() * 1024 * 1024
    }

    pub fn max_memory_bytes(&self) -> usize {
        self.memory_budget.get_max_mb() * 1024 * 1024
    }
}

impl Default for GlobalPluginManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_global_plugin_manager() -> Arc<GlobalPluginManager> {
    GLOBAL_PLUGIN_MANAGER.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_plugin_manager_creation() {
        let mgr = GlobalPluginManager::new();
        assert_eq!(mgr.current_memory_usage(), 0);
        assert_eq!(mgr.max_memory_bytes(), 256 * 1024 * 1024);
    }

    #[test]
    fn test_allocation_tracking() {
        let mgr = GlobalPluginManager::new();
        mgr.record_allocation(100);
        assert_eq!(mgr.current_memory_usage(), 100);
        mgr.record_allocation(50);
        assert_eq!(mgr.current_memory_usage(), 150);
        mgr.record_deallocation(30);
        assert_eq!(mgr.current_memory_usage(), 0);
    }

    #[test]
    fn test_deallocation_underflow_protection() {
        let mgr = GlobalPluginManager::new();
        mgr.record_allocation(50);
        mgr.record_deallocation(100);
        assert_eq!(mgr.current_memory_usage(), 0);
    }

    #[test]
    fn test_get_global_plugin_manager() {
        let mgr1 = get_global_plugin_manager();
        let mgr2 = get_global_plugin_manager();
        assert!(Arc::ptr_eq(&mgr1, &mgr2));
    }

    #[test]
    fn test_memory_budget_basic_allocation() {
        let budget = GlobalWasmMemoryBudget::new(100);

        assert_eq!(budget.get_max_mb(), 100);
        assert_eq!(budget.get_current_usage_mb(), 0);
        assert_eq!(budget.get_plugin_count(), 0);

        budget.try_allocate("plugin1", 30).unwrap();
        assert_eq!(budget.get_current_usage_mb(), 30);
        assert_eq!(budget.get_plugin_count(), 1);

        budget.try_allocate("plugin2", 40).unwrap();
        assert_eq!(budget.get_current_usage_mb(), 70);

        budget.try_allocate("plugin3", 30).unwrap_err();
        assert_eq!(budget.get_current_usage_mb(), 70);
    }

    #[test]
    fn test_memory_budget_deallocation() {
        let budget = GlobalWasmMemoryBudget::new(100);

        budget.try_allocate("plugin1", 30).unwrap();
        budget.try_allocate("plugin2", 40).unwrap();
        assert_eq!(budget.get_current_usage_mb(), 70);

        let deallocated = budget.deallocate("plugin1");
        assert_eq!(deallocated, 30);
        assert_eq!(budget.get_current_usage_mb(), 40);
        assert_eq!(budget.get_plugin_count(), 1);

        budget.deallocate("nonexistent");
        assert_eq!(budget.get_current_usage_mb(), 40);
    }

    #[test]
    fn test_memory_budget_exceeded_error() {
        let budget = GlobalWasmMemoryBudget::new(50);

        let err = budget.try_allocate("plugin1", 60).unwrap_err();
        assert!(matches!(err, MemoryBudgetError::Exceeded { .. }));

        if let MemoryBudgetError::Exceeded {
            requested,
            available,
            max,
        } = err
        {
            assert_eq!(requested, 60);
            assert_eq!(available, 50);
            assert_eq!(max, 50);
        }
    }

    #[test]
    fn test_global_plugin_manager_with_custom_budget() {
        let mgr = GlobalPluginManager::new().with_max_memory(100 * 1024 * 1024);
        assert_eq!(mgr.max_memory_bytes(), 100 * 1024 * 1024);
    }
}
