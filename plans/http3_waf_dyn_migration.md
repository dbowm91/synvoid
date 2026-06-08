# HTTP/3 WAF Dyn Migration — Current State (H01 findings)

**Date:** 2026-06-07

## Struct Shape (`src/http3/server.rs:20-33`)

`Http3Server` holds `waf: Arc<WafCore>` — a concrete type, not a trait object.

## Constructor Signature (`src/http3/server.rs:36-63`)

```rust
pub fn new(addr, config, router, waf: Arc<WafCore>, main_config, shutdown_rx) -> Self
```

## Call Site (`src/server/mod.rs:1288-1295`)

Passes `state.waf.clone()` where `state.waf: Arc<WafCore>` (line 37).

## Dispatch Signature (`crates/synvoid-http/src/http3_request_dispatch.rs:79-103`)

Already generic: `handle_http3_request_dispatch<Waf, S, W>(..., waf: &Waf) where Waf: Http3RequestWaf + ?Sized`.

`WafCore` implements `Http3RequestWaf` at `src/waf/mod.rs:131`.

## H02 Changes Required

The dispatch crate (`synvoid-http`) needs **no changes**. Only two files need modification:

1. **`src/http3/server.rs`** — Make `Http3Server` generic over `Waf: Http3RequestWaf + ?Sized` (or store `Arc<dyn Http3RequestWaf>`). Update field type, constructor parameter, and `serve()` where `self.waf` is used.

2. **`src/server/mod.rs`** — Update the call site (line 1288) to pass the trait object / generic parameter to `Http3Server::new`.

## Baseline Compilation

- `cargo check -p synvoid-http` — OK (pre-existing warnings only)
- `cargo check --lib --no-default-features` — OK (pre-existing warnings only)
