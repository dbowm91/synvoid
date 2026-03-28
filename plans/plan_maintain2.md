# Dependency Reduction Plan for MaluWAF

## Executive Summary

This plan identifies truly unused dependencies that can be safely removed without impacting features or the overseer/master/worker architecture.

---

## Analysis Results

### Dependencies Confirmed UNUSED (Safe to Remove)

| Dependency | Version | Evidence | Recommendation |
|------------|---------|----------|----------------|
| **flare** | 0.1.0 | No code references (`grep` found 0 matches) | **REMOVE** |
| **ab_glyph** | 0.2.32 | No code references (font rendering library) | **REMOVE** |
| **wasmtime-wasi** | 36 | No imports; only core `wasmtime` is used | **REMOVE** |

### Dependencies Confirmed ACTIVE (Do NOT Remove)

| Dependency | Used By | Status |
|------------|---------|--------|
| **webpki-roots** | `src/http_client/mod.rs:224` | ACTIVE - TLS certificate roots |
| **wasmtime** | `src/plugin/wasm_runtime.rs:7` | ACTIVE - WASM plugin runtime |
| **bincode** | `src/serialization.rs:46-53` | ACTIVE (legacy compat wrapper) |
| **rkyv** | mesh/dht files, dns/* files | ACTIVE - zero-copy serialization |
| **flare** | NOT USED | See above |
| **ab_glyph** | NOT USED | See above |

---

## Proposed Changes

### Remove from Cargo.toml (lines 122-124, 182)

```diff
- flare = "0.1"
- ab_glyph = "0.2"
```

```diff
- wasmtime-wasi = "36"
```

### Total removals: 3 dependencies

---

## Impact Assessment

| Aspect | Impact |
|--------|--------|
| Binary size reduction | Negligible (~10-50KB) |
| Feature impact | None - these are unused |
| Architecture impact | None |
| Build compatibility | None |

---

## Verification Commands

After removal, verify:

```bash
# 1. Check no remaining references to removed deps
grep -r "use flare" src/
grep -r "use ab_glyph" src/
grep -r "use wasmtime_wasi" src/

# 2. Verify build still works
cargo build --release

# 3. Run integration tests
cargo test --test integration_test
```

---

## Notes

1. **flare**: Appears to be a placeholder dependency - no code uses it
2. **ab_glyph**: Font rendering library - no code references found
3. **wasmtime-wasi**: WASI bindings not needed; only core `wasmtime` used for plugin system

The main binary size opportunity would require:
- Making `dns` feature truly optional (currently always compiled)
- Making `mesh` feature optional (in default features)
- These are out of scope for this conservative plan.

---

## Unchanged Dependencies

The following were considered but are actually used:
- `webpki-roots` - TLS CA roots for HTTP client
- `wasmtime` - WASM plugin infrastructure  
- `bincode` - serialization compat layer
- `rkyv` - zero-copy serialization for DHT/DNS
- All other dependencies - actively used

---