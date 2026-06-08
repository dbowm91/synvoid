# HTTP/3 RequestWaf Object-Safety Investigation

**Tasks:** WGH-H01, WGH-H02, WGH-H03
**Date:** 2026-06-08

## WGH-H01: `Http3RequestWaf` Trait Definition

**File:** `crates/synvoid-http/src/http3_request_dispatch.rs:28`

```rust
#[async_trait]
pub trait Http3RequestWaf: Send + Sync {
    async fn check_request_full(&self, ...) -> WafDecision;
    fn generate_tarpit_response(&self, path: &str) -> String;
}
```

### Object-Safety Analysis

| Criterion | Status | Notes |
|-----------|--------|-------|
| Generic methods | ✅ None | Both methods use concrete types |
| `async fn` without `async_trait` | ✅ Wrapped | `#[async_trait]` desugars to `Pin<Box<dyn Future>>`, so object-safe |
| Methods returning `Self` | ✅ None | No `-> Self` methods |
| Associated types | ✅ None | No `type Foo = ...` declarations |
| `Sized` bounds | ✅ None | No explicit `Sized` requirement |

**Verdict:** `Http3RequestWaf` is fully object-safe. `dyn Http3RequestWaf` is usable.

### Evidence: Function Already Accepts `?Sized`

The dispatch function `handle_http3_request_dispatch` at line 79 already bounds:
```rust
where Waf: Http3RequestWaf + ?Sized
```

This means it already works with `dyn Http3RequestWaf` — the call site `self.waf.as_ref()` at `src/http3/server.rs:278` already coerces `Arc<WafCore>` to `&WafCore` and passes it as `&Waf` where `Waf: Http3RequestWaf + ?Sized`. Changing the field to `Arc<dyn Http3RequestWaf>` requires only a type change; the function signature needs no modification.

### Sole Implementor

`WafCore` at `src/waf/mod.rs:131` is the only implementor in the workspace. The impl delegates directly to inherent `WafCore` methods.

## WGH-H02: Chosen Strategy

**Strategy A: Use `Arc<dyn Http3RequestWaf>`** — trivially applicable.

### Why not B (generic propagation)

Making `Http3Server<W: Http3RequestWaf>` generic would propagate `W` to:
- `Http3Server::new` at `src/http3/server.rs:36`
- All call sites in `src/server/mod.rs` (lines 1288-1295)
- Any future code constructing `Http3Server`

Generic propagation is small here (only 1 call site), but there is no reason to impose generics when `dyn` dispatch is already supported.

### Why not C (adapter trait)

An adapter trait is unnecessary — the trait is already object-safe. The `WafAccess` trait (`src/waf/access.rs`) already covers the additional `connection_limiter()`, `is_over_bandwidth_limit()`, and `streaming()` accesses that `src/http3/server.rs` performs at lines 269-272. These are called on `self.waf` (concrete `Arc<WafCore>`) before the `as_ref()` cast, so they do not block the `dyn` strategy.

### Why not D (defer)

`Http3RequestWaf` is already object-safe with zero friction. The only required change is a single field type in `Http3Server`.

### Required Change (if implemented later)

```
src/http3/server.rs:
  struct Http3Server {
-     waf: Arc<WafCore>,
+     waf: Arc<dyn Http3RequestWaf>,
  }
```

And in `new()`:
```
-     waf: Arc<WafCore>,
+     waf: Arc<dyn Http3RequestWaf>,
```

Call site in `src/server/mod.rs` would need `.clone()` on the `Arc<dyn ...>` — no semantic change.

## WGH-H03: Implementation

**Not implemented in this task.** Strategy A is documented for future execution. The change is a one-line field type swap with no behavioral impact.

## Acceptance

Acceptance checks (compilation verification) run against the current workspace state — no source changes were made.
