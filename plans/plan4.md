# Plugin Architecture Improvement Plan

**Last updated**: 2026-04-19
**Status**: DRAFT - Proposed improvements for Plugin & Serverless systems

---

## Overview

This plan outlines a series of architectural improvements to MaluWAF's plugin system, covering WASM filtering, serverless functions, and Axum-based native extensions. The focus is on unification, security hardening, and better observability.

---

## Wave Structure

| Wave | Focus | Priority |
|------|-------|----------|
| Wave 1 | Unified Registry & Configuration | High |
| Wave 2 | ABI Standardization & Developer Experience | Medium |
| Wave 3 | Security & Isolation | High |
| Wave 4 | Mesh & Distribution Enhancements | Medium |
| Wave 5 | Observability & Telemetry | Low |

---

## Wave 1: Unified Registry & Configuration

### Phase 1.1: Unified Plugin Registry

**Goal**: Merge `WasmPluginManager` and `AxumPluginWrapper` into a single `PluginRegistry`.

| ID | Action | File | Status |
|----|--------|------|--------|
| W1.1.1 | Define `PluginType` enum (Wasm, Axum, Serverless) | src/plugin/mod.rs | 📋 PLANNING |
| W1.1.2 | Implement `PluginRegistry` with unified storage | src/plugin/mod.rs | 📋 PLANNING |
| W1.1.3 | Refactor `PluginManager` to use `PluginRegistry` | src/plugin/mod.rs | 📋 PLANNING |
| W1.1.4 | Update `PluginManagerLifecycle` for unified hot-reload | src/plugin/mod.rs | 📋 PLANNING |

### Phase 1.2: Centralized Plugin Configuration

**Goal**: Move plugin-specific limits and environment variables into a structured configuration.

| ID | Action | File | Status |
|----|--------|------|--------|
| W1.2.1 | Add `PluginConfig` to `SiteConfig` | src/config/site/mod.rs | 📋 PLANNING |
| W1.2.2 | Map site-specific plugin env vars during invocation | src/plugin/wasm_runtime.rs | 📋 PLANNING |

---

## Wave 2: ABI Standardization & Developer Experience

### Phase 2.1: Serverless ABI Refinement

**Goal**: Standardize the communication format between host and guest, aligning with WASI-HTTP.

| ID | Action | File | Status |
|----|--------|------|--------|
| W2.1.1 | Implement `maluwaf-guest-sdk` crate for Rust plugins | (new crate) | 📋 PLANNING |
| W2.1.2 | Refactor `handle_request` to use a structured response header | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| W2.1.3 | Add support for streaming response bodies in serverless | src/serverless/manager.rs | 📋 PLANNING |
| W2.1.4 | Implement initial support for `wasi-http:proxy` world | src/plugin/wasm_runtime.rs | 📋 PLANNING |

---

## Wave 3: Security & Isolation

### Phase 3.1: Capability-based Host Functions

**Goal**: Restrict plugin access to host resources.

| ID | Action | File | Status |
|----|--------|------|--------|
| W3.1.1 | Implement per-plugin allowlist for `get_env` keys | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| W3.1.2 | Add restricted network access for WASM (WASI-socket) | src/plugin/wasm_runtime.rs | 📋 PLANNING |

### Phase 3.2: Axum Plugin Sandboxing (Research)

**Goal**: Investigate process-based isolation for native plugins.

| ID | Action | File | Status |
|----|--------|------|--------|
| W3.2.1 | Prototype IPC bridge for `AxumDynamic` backends | src/plugin/axum_loader.rs | 📋 PLANNING |
| W3.2.2 | Implement watchdog for external plugin processes | src/plugin/mod.rs | 📋 PLANNING |

---

## Wave 4: Mesh & Distribution Enhancements

### Phase 4.1: Secure & Efficient Distribution

**Goal**: Optimize WASM module propagation across the mesh.

| ID | Action | File | Status |
|----|--------|------|--------|
| W4.1.1 | Add Ed25519 signature verification for mesh plugins | src/mesh/wasm_dist.rs | 📋 PLANNING |
| W4.1.2 | Implement content-addressed storage (CAS) for modules | src/mesh/wasm_dist.rs | 📋 PLANNING |
| W4.1.3 | Add delta-compression for module updates | src/mesh/wasm_dist.rs | 📋 PLANNING |

---

## Wave 5: Observability & Telemetry

### Phase 5.1: Plugin Telemetry

**Goal**: Expose granular metrics for all plugin types.

| ID | Action | File | Status |
|----|--------|------|--------|
| W5.1.1 | Add `prometheus` metrics for Axum plugin request counts | src/plugin/axum_loader.rs | 📋 PLANNING |
| W5.1.2 | Implement `tracing` spans across the plugin boundary | src/plugin/wasm_runtime.rs | 📋 PLANNING |
| W5.1.3 | Add per-function latency histograms for serverless | src/serverless/manager.rs | 📋 PLANNING |

---

## Reference Commands

```bash
# Test WASM runtime integration
cargo test --package maluwaf --lib plugin::wasm_runtime::tests

# Benchmark WASM filter overhead
cargo bench --bench bench_wasm

# Run plugin-specific integration tests
cargo test --test test_plugins
```
