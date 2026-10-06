---
name: topology_visualizer
description: Mesh topology Admin API (peer partition + D3-style graph payloads). Use when touching /mesh/topology endpoints. Backend-only — no admin-ui page consumes it yet.
---

# Skill: Mesh Topology Admin API

## Context
The backend exposes mesh topology data via Admin API. The capability is
**real and routed**, but there is **no frontend consumer**: there is no
`admin-ui/src/pages/topology.rs` and a repo-wide grep for `topolog` under
`admin-ui/src` returns zero hits. Treat this as a backend API for API clients
and future UI work, not as a shipped visualizer feature.

The whole module is `#![cfg(feature = "mesh")]`, so the endpoints exist only in
mesh-feature builds; `src/admin/handlers/mod.rs` gates `pub mod mesh_topology;`
the same way.

## When to Use
Use this skill when:
- Adding or changing Admin API endpoints for mesh topology
- Building a D3.js-compatible graph payload or a frontend consumer for it
- Extending peer partition logic for global/edge nodes

## Key Files
- `src/admin/handlers/mesh_topology.rs` - Handler implementation
- `src/admin/routes.rs` - Route registration (the `/mesh/topology` and
  `/mesh/topology/graph` entries, ~lines 617-622)
- `src/admin/handlers/mod.rs` - Module declaration (`#[cfg(feature = "mesh")] pub mod mesh_topology;`)
- `src/admin/handlers/api_discovery.rs` - Both paths are advertised in the
  self-describing endpoint catalog
- `crates/synvoid-mesh/src/mesh/topology.rs` - `MeshTopology::get_all_peers()`,
  `get_topology_version()`
- `src/admin/handlers/mesh_admin.rs` - The same `mesh_transport.get_topology()`
  accessor is reused by the non-topology mesh admin handlers

## Implementation Pattern

### 1. Response Structures
```rust
pub struct TopologyResponse {
    pub version: u64,
    pub total_peers: usize,
    pub global_nodes: Vec<TopologyPeerInfo>,
    pub edge_nodes: Vec<TopologyPeerInfo>,
    pub connections: Vec<ConnectionInfo>,
    pub metrics: TopologyMetrics,
}

pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}
```

### 2. Handler Pattern
```rust
pub async fn get_mesh_topology(
    _auth: OptionalAuth,
    State(state): State<Arc<AdminState>>,
    Query(query): Query<TopologyQuery>,
) -> Result<Json<TopologyResponse>, StatusCode> {
    let topology_opt = state.mesh.mesh_transport.as_ref().map(|t| t.get_topology());
    let topology = match topology_opt {
        Some(t) => t,
        None => return Err(StatusCode::NOT_FOUND),
    };
    // ...
}
```

### 3. Global/Edge Partition
```rust
let mut global_nodes: Vec<&PeerState> = Vec::new();
let mut edge_nodes: Vec<&PeerState> = Vec::new();

for peer in &all_peers {
    if peer.is_global {
        global_nodes.push(peer);
    } else {
        edge_nodes.push(peer);
    }
}
```

### 4. Graph Data for D3.js
```rust
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String,  // "global" or "edge"
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub color: String,      // "#4CAF50" for global, "#2196F3" for edge
    pub size: f64,
}

pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub weight: f64,
    pub label: Option<String>,
}
```

### 5. Route Registration
In `src/admin/routes.rs` (~lines 617-622):
```rust
.route(
    "/mesh/topology",
    get(handlers::mesh_topology::get_mesh_topology),
)
.route(
    "/mesh/topology/graph",
    get(handlers::mesh_topology::get_topology_graph),
)
```

### 6. Module Declaration
In `src/admin/handlers/mod.rs`:
```rust
pub mod mesh_topology;
```

## AdminState Access
`MeshState` in `AdminState` contains `mesh_transport: Option<Arc<MeshTransport>>`:
- Get topology via `mesh_transport.as_ref().map(|t| t.get_topology())`
- Then call `topology.get_all_peers().await` and `topology.get_topology_version().await`

## Verification
Both routes are mesh-only and return `404` when `mesh_transport` is `None`.
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/mesh/topology
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/mesh/topology/graph
```
There is no UI page to click through; verify with `curl` (or `swagger-ui`) and a
mesh-feature build.

## Common Issues
1. **partition() on Vec<PeerState>** - `into_iter().partition()` doesn't work on `Vec<&PeerState>`; use manual for loop
2. **PeerState field access** - Don't assume fields like `peer_count`, `uptime_secs` exist; use only `PeerState` fields from `types.rs`
3. **MeshState is not MeshTopology** - Get `MeshTopology` via `MeshTransport::get_topology()`

## Geo to Coordinates
```rust
fn geo_to_x(geo: &Option<String>) -> f64 {
    let geo_str = geo.as_deref().unwrap_or("default");
    let hash = Sha256::digest(geo_str.as_bytes());
    let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
    (val as f64 % 1000.0) - 500.0
}
```
