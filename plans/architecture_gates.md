# Architecture Regression Gates

**Status**: OPEN
**Last Updated**: 2026-05-02

## Overview

Architectural regressions are easy in this codebase because modules can import across boundaries freely and default features compile many subsystems together. Without tests and CI gates, optional subsystems will creep back into core paths.

## Feature Profile Checks

### Profile Definitions

| Profile | Features | Purpose |
|---------|----------|---------|
| `core` | none | Minimal HTTP/TLS proxy without mesh or DNS |
| `mesh` | mesh | Core + mesh networking (DHT, Raft, transport) |
| `dns` | dns | Core + DNS server and resolver |
| `full` | mesh,dns | All features (current default) |

### Check Results (2026-05-02)

| Profile | Command | Result | Errors |
|---------|---------|--------|--------|
| core | `cargo check --no-default-features` | **FAIL** | 215 errors |
| mesh | `cargo check --no-default-features --features mesh` | **FAIL** | 85 errors |
| dns | `cargo check --no-default-features --features dns` | **FAIL** | 259 errors |
| full | `cargo check --no-default-features --features mesh,dns` | **PASS** | 0 errors |

### Profile Check Commands

```bash
# Core profile (minimal - no mesh, no dns)
cargo check --no-default-features

# Mesh profile (core + mesh networking)
cargo check --no-default-features --features mesh

# DNS profile (core + DNS server/resolver)
cargo check --no-default-features --features dns

# Full profile (all features - current default)
cargo check --no-default-features --features mesh,dns

# Default features check (should match full)
cargo check
```

## Dependency Boundary Violations

The profile checks reveal several categories of boundary violations:

### 1. Direct Mesh Imports Without Feature Guards

**Severity**: High - prevents core-only compilation

Files that directly import `crate::mesh::*` without `#[cfg(feature = "mesh")]` guards:

- `src/worker/unified_server.rs` - references `crate::mesh::protocol::MeshMessageSigner`, `crate::mesh::backend`, `crate::mesh::config::MeshNodeRole`, `crate::mesh::threat_intel`
- `src/admin/handlers/mesh_admin.rs` - uses `crate::mesh::config::MeshNodeRole` directly
- `src/config/tunnel.rs` - has `pub mesh: Option<crate::mesh::config::MeshConfig>` without feature guard
- `src/serverless/manager.rs` - uses `crate::mesh::config::MeshNodeRole`
- `src/tls/server.rs` - has `mesh_config: Option<Arc<crate::mesh::config::MeshConfig>>` without feature guard

### 2. DNS Module Depends on Mesh

**Severity**: High - prevents dns-only compilation

The DNS module (`src/dns/*`) has hard dependencies on mesh types:

- `src/dns/anycast_sync.rs` - imports `crate::mesh::protocol::MeshMessage`, `crate::mesh::config::MeshNodeRole`
- `src/dns/mesh_sync/dht.rs` - imports `crate::mesh::dht::SignedDhtRecord`, `crate::mesh::dht::SignedRecordType`
- `src/dns/mesh_sync/registry.rs` - imports `crate::mesh::dht::routing::manager::DhtRoutingManager`, `crate::mesh::dht::record_store::RecordStoreManager`
- `src/dns/mesh_sync/mod.rs` - imports mesh DHT types
- `src/dns/server/startup.rs` - imports `crate::mesh::transport::MeshTransport`
- `src/dns/server/mod.rs` - imports `crate::mesh::transport::MeshTransport`

This creates a fundamental coupling: DNS cannot exist without mesh.

### 3. Admin API Depends on Mesh Types

**Severity**: Medium - admin handlers reference mesh types directly

`src/admin/handlers/mesh_admin.rs` and `src/admin/handlers/mesh_topology.rs` use mesh types in their function signatures without feature guards.

### 4. HTTP/TLS Servers Accept Mesh Config

**Severity**: Medium - config structs include mesh types without guards

`src/tls/server.rs` accepts `Option<Arc<crate::mesh::config::MeshConfig>>` in its struct definition and method signatures without proper feature gating.

## Forbidden Import Patterns

### Core Profile Boundaries

The following imports are **forbidden** in modules that should compile under `--no-default-features`:

| From Module | Forbidden Import | Reason |
|-------------|-----------------|--------|
| `src/http/*` | `crate::mesh::` | HTTP core should not require mesh |
| `src/proxy/*` | `crate::dns::` | Proxy core should not require DNS |
| `src/router.rs` | `crate::mesh::` | Router should not require mesh |
| `src/config/*` | `crate::mesh::config::MeshConfig` (in public structs) | Config should be composable without mesh |
| `src/waf/*` | `crate::mesh::threat_intel::` | WAF core should not require mesh threat intel |
| `src/serverless/*` | `crate::mesh::config::MeshNodeRole` | Serverless should not require mesh role awareness |

### DNS Profile Boundaries

| From Module | Forbidden Import | Reason |
|-------------|-----------------|--------|
| `src/dns/*` | `crate::mesh::protocol::MeshMessage` | DNS module should be separable from mesh messaging |
| `src/dns/*` | `crate::mesh::dht::routing::` | DNS sync should not require DHT routing |

### Mesh Profile Boundaries

| From Module | Forbidden Import | Reason |
|-------------|-----------------|--------|
| `src/mesh/*` | `crate::dns::resolver::DnsResolver` (in non-DNS-specific transport) | Mesh transport should work without DNS resolver |

## CI/Local Verification Commands

### Profile Compilation Checks

Run these to verify feature boundaries:

```bash
# Verify core profile compiles (no mesh, no dns)
cargo check --no-default-features

# Verify mesh profile compiles
cargo check --no-default-features --features mesh

# Verify dns profile compiles
cargo check --no-default-features --features dns

# Verify full profile compiles
cargo check --no-default-features --features mesh,dns
```

### Dependency Boundary Checks

```bash
# Check for direct mesh imports in non-mesh modules (should return empty for clean boundaries)
rg "crate::mesh::" src/http/ src/proxy/ src/router.rs --type rust | grep -v "\#\[cfg(feature"

# Check for direct dns imports outside dns module
rg "crate::dns::" src/ --type rust | grep -v "src/dns/" | grep -v "\#\[cfg(feature"

# Verify feature-gated imports
rg "cfg\(feature = \"(mesh|dns)\"" src/ --type rust
```

### Suggested CI Pipeline

```yaml
# .github/workflows/architecture-gates.yml
name: Architecture Gates

on: [push, pull_request]

jobs:
  profile-checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
        with:
          profile: minimal
      - name: Core profile
        run: cargo check --no-default-features
      - name: Mesh profile
        run: cargo check --no-default-features --features mesh
      - name: DNS profile
        run: cargo check --no-default-features --features dns
      - name: Full profile
        run: cargo check --no-default-features --features mesh,dns

  boundary-checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan for forbidden imports
        run: |
          # Core profile should not have mesh imports in HTTP/proxy/router
          echo "Checking for mesh imports in core modules..."
          rg "crate::mesh::" src/http/ src/proxy/ src/router.rs --type rust || true
```

### Local Verification Script

```bash
#!/bin/bash
# scripts/check_architecture_gates.sh

set -e

echo "=== Architecture Regression Gates ==="

echo ""
echo "1. Profile compilation checks..."
echo ""

echo "  [core] checking --no-default-features..."
cargo check --no-default-features 2>&1 | tail -5

echo "  [mesh] checking --no-default-features --features mesh..."
cargo check --no-default-features --features mesh 2>&1 | tail -5

echo "  [dns] checking --no-default-features --features dns..."
cargo check --no-default-features --features dns 2>&1 | tail -5

echo "  [full] checking --no-default-features --features mesh,dns..."
cargo check --no-default-features --features mesh,dns 2>&1 | tail -5

echo ""
echo "2. Dependency boundary checks..."
echo ""

# Check for mesh imports in modules that shouldn't need it
echo "  Scanning for mesh imports in HTTP/proxy core..."
mesh_imports=$(rg "crate::mesh::" src/http/ src/proxy/ src/router.rs --type rust 2>/dev/null || true)
if [ -n "$mesh_imports" ]; then
    echo "  WARNING: Found mesh imports in core modules:"
    echo "$mesh_imports"
fi

echo ""
echo "=== Done ==="
```

## What Needs Fixing

### Priority 1: Fix Core Profile

The core profile (no features) should compile. This requires:

1. Feature-gate `src/worker/unified_server.rs` mesh references with `#[cfg(feature = "mesh")]`
2. Feature-gate `src/config/tunnel.rs` MeshConfig field
3. Feature-gate `src/tls/server.rs` mesh_config field
4. Feature-gate `src/serverless/manager.rs` mesh references
5. Feature-gate admin handler mesh type references

### Priority 2: Decouple DNS from Mesh

The DNS module should not require mesh types. This requires:

1. Remove `crate::mesh::protocol::MeshMessage` from `src/dns/anycast_sync.rs`
2. Replace mesh DHT types with a simpler DNS-specific sync mechanism
3. Create a DNS-native sync protocol that doesn't depend on mesh messaging

### Priority 3: Document Feature Boundaries

After fixing, document which modules can be combined:

- core: HTTP, proxy, router, waf core
- mesh: core + all mesh/DHT/Raft code
- dns: core + DNS server/resolver (currently requires mesh)
- full: mesh + dns combined

## Done Criteria

- [ ] `cargo check --no-default-features` passes
- [ ] `cargo check --no-default-features --features mesh` passes
- [ ] `cargo check --no-default-features --features dns` passes
- [ ] `cargo check --no-default-features --features mesh,dns` passes
- [ ] Forbidden import patterns documented and checked
- [ ] CI pipeline includes profile checks
- [ ] Local verification script available