# WASM Component Support

This project uses `wasmtime` with the `component-model` feature enabled to support modern WASM components.

## WIT Interface Definition

The `src/plugin/plugin.wit` file defines the formal interface between host and guest:

```wit
interface host {
    log: func(level: string, message: string);
    get-header: func(name: string) -> option<string>;
    set-header: func(name: string, value: string);
    get-method: func() -> string;
    get-uri: func() -> string;
    get-body: func() -> list<u8>;
    set-body: func(data: list<u8>);
    set-status: func(code: u16);
    get-env: func(key: string) -> option<string>;
    check-timeout: func() -> bool;
    mesh-query-dht: func(key: string) -> result<list<u8>, s8>;
    mesh-check-threat: func(ip: string) -> s8;
    mesh-emit-event: func(topic: string, data: list<u8>) -> result<(), s8>;
    guest-alloc: func(size: u32) -> u32;
    guest-free: func(ptr: u32, size: u32);
}

world plugin {
    import host;
    export filter-request: func() -> s32;
    export transform-response: func() -> s32;
}
```

## Loading Components

The `WasmPluginManager::load_component()` method loads WASM components using the wasmtime Component API:

```rust
let manager = WasmPluginManager::new();
let result = manager.load_component(Path::new("plugin.wasm"));
```

## Host Bindings

The `load_component` implementation (`src/plugin/wasm_runtime.rs`) creates a `ComponentLinker` and links host functions via `link_host_functions()`. The `create_component_store()` helper creates a store with resource limits.

## Plugin Exports

Plugins must export:
- `filter-request: func() -> s32` - Returns 0=pass, 1=block, 2=challenge
- `transform-response: func() -> s32` - Returns 0=success, -1=error

## Guest ABI

Components can use the host's `guest-alloc` and `guest-free` functions for memory management. The host provides these as part of the `host` interface import.