# WASM Component Support

This project uses `wasmtime` with the `component-model` feature enabled to support modern WASM components.

## Loading Components

The `WasmPluginManager` provides a `load_component` method for experimentally loading WASM components.
However, note that full support depends on matching the WASM component ABI with the expected host exports (such as memory allocation and request routing).

When writing new plugins or migrating old modules, ensure they follow the component model specifications.

**Example**:
```rust
let manager = WasmPluginManager::new();
let result = manager.load_component(Path::new("plugin.wasm"));
```

## Known Limitations
- The current implementation of `load_component` may return `LoadFailed` if the component ABI does not perfectly align with `maluwaf`'s host functions.
- Avoid relying on direct memory exports when migrating to the component model, as components encapsulate memory.
