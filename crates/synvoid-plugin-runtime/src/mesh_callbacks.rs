//! Trait-based mesh DHT integration for WASM host functions.
//! The root crate registers a provider at startup.

use std::sync::Arc;

/// Trait for mesh DHT operations. Implemented by the root crate when mesh feature is enabled.
pub trait MeshDhtProvider: Send + Sync + 'static {
    fn get_record(&self, key: &str) -> Option<Vec<u8>>;
    fn check_threat(&self, ip: &str) -> bool;
    fn store_event(&self, topic: &str, data: &[u8]);
}

static MESH_PROVIDER: std::sync::OnceLock<Arc<dyn MeshDhtProvider>> = std::sync::OnceLock::new();

pub fn set_mesh_provider(provider: Arc<dyn MeshDhtProvider>) {
    let _ = MESH_PROVIDER.set(provider);
}

pub(crate) fn get_mesh_provider() -> Option<Arc<dyn MeshDhtProvider>> {
    MESH_PROVIDER.get().cloned()
}
