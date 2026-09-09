//! Adapter impls binding the canonical plugin manager to the HTTP narrow traits.
//!
//! Phase 21: these impls lived on the root-crate duplicate `PluginManager` in
//! `src/plugin/mod.rs`. The manager is now canonical in
//! `synvoid-plugin-runtime`; the impls live here because this crate owns the
//! traits (orphan rule), keeping request-path code on narrow traits.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;

use synvoid_plugin_runtime::plugin_manager::PluginManager;
use synvoid_plugin_runtime::{WasmFilterResult, WasmPluginError};

impl crate::AxumDynamicRouterLookup for PluginManager {
    fn get_axum_router(&self) -> Option<Arc<axum::Router>> {
        PluginManager::get_axum_router(self)
    }

    fn get_axum_router_by_name(&self, name: &str) -> Option<Arc<axum::Router>> {
        PluginManager::get_axum_router_by_name(self, name)
    }
}

impl crate::WasmFilterBackend for PluginManager {
    fn apply_wasm_filters(
        &self,
        request: http::Request<Bytes>,
        env: HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        PluginManager::apply_wasm_filters(self, request, env)
    }

    fn apply_wasm_filters_with_plugins(
        &self,
        request: http::Request<Bytes>,
        plugin_names: &[String],
        env: HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        PluginManager::apply_wasm_filters_with_plugins(self, request, plugin_names, env)
    }
}
