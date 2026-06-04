//! Trait abstractions for mesh integration.
//! The root crate implements these traits and wires them at startup.

use std::sync::Arc;

/// Provider for WASM module distribution from mesh DHT.
pub trait MeshWasmDistProvider: Send + Sync + 'static {
    fn get_module_data(&self, name: &str) -> Option<Vec<u8>>;
}

/// Provider for DHT record operations.
pub trait MeshDhtProvider: Send + Sync + 'static {
    fn store_function(&self, name: &str, data: Vec<u8>, ttl: u64);
    fn get_record(&self, key: &str) -> Option<Vec<u8>>;
}

/// Provider for mesh transport announcements.
pub trait MeshTransportProvider: Send + Sync + 'static {
    fn announce_serverless(&self);
    fn node_id(&self) -> String;
}

/// Provider for organization/tier validation.
pub trait MeshOrganizationProvider: Send + Sync + 'static {
    fn validate_tier_claim(&self, tier: u32, org: &str) -> bool;
    fn is_node_revoked(&self, node_id: &str) -> Option<String>;
}

/// Provider for hierarchical routing registration.
pub trait MeshRoutingProvider: Send + Sync + 'static {
    fn register_function(&self, name: &str, node_id: &str);
}

static MESH_WASM_DIST: std::sync::OnceLock<Arc<dyn MeshWasmDistProvider>> =
    std::sync::OnceLock::new();
static MESH_DHT: std::sync::OnceLock<Arc<dyn MeshDhtProvider>> = std::sync::OnceLock::new();
static MESH_TRANSPORT: std::sync::OnceLock<Arc<dyn MeshTransportProvider>> =
    std::sync::OnceLock::new();
static MESH_ORG: std::sync::OnceLock<Arc<dyn MeshOrganizationProvider>> =
    std::sync::OnceLock::new();
static MESH_ROUTING: std::sync::OnceLock<Arc<dyn MeshRoutingProvider>> =
    std::sync::OnceLock::new();

pub fn set_mesh_wasm_dist(p: Arc<dyn MeshWasmDistProvider>) {
    let _ = MESH_WASM_DIST.set(p);
}
pub fn set_mesh_dht(p: Arc<dyn MeshDhtProvider>) {
    let _ = MESH_DHT.set(p);
}
pub fn set_mesh_transport(p: Arc<dyn MeshTransportProvider>) {
    let _ = MESH_TRANSPORT.set(p);
}
pub fn set_mesh_org(p: Arc<dyn MeshOrganizationProvider>) {
    let _ = MESH_ORG.set(p);
}
pub fn set_mesh_routing(p: Arc<dyn MeshRoutingProvider>) {
    let _ = MESH_ROUTING.set(p);
}

pub(crate) fn get_mesh_wasm_dist() -> Option<Arc<dyn MeshWasmDistProvider>> {
    MESH_WASM_DIST.get().cloned()
}
pub(crate) fn get_mesh_dht() -> Option<Arc<dyn MeshDhtProvider>> {
    MESH_DHT.get().cloned()
}
pub(crate) fn get_mesh_transport() -> Option<Arc<dyn MeshTransportProvider>> {
    MESH_TRANSPORT.get().cloned()
}
pub(crate) fn get_mesh_org() -> Option<Arc<dyn MeshOrganizationProvider>> {
    MESH_ORG.get().cloned()
}
pub(crate) fn get_mesh_routing() -> Option<Arc<dyn MeshRoutingProvider>> {
    MESH_ROUTING.get().cloned()
}
