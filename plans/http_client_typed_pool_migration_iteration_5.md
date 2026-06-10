# HTTP Client Typed Pool Migration — Iteration 5

## Goal

Remove the dead `TypedConnectionPool` code path and residual files left over from the HTTP client extraction into `crates/synvoid-http-client/`. The typed pool was an alternative implementation ("Option 3") that was superseded by `ErasedHttpClient`. It is defined and re-exported but never consumed anywhere in the workspace. This pass also removes the root `webpki-roots` dependency (only consumer was the dead `typed_pool.rs`) and updates all referencing docs.

## Non-Goals

- Do not touch `ErasedHttpClient` or `StreamingHttpClient` — these are active production paths.
- Do not implement HTTP/2 pooling (HTTP2-POOL deferred item).
- Do not restructure the `crates/synvoid-http-client/` crate layout.
- Do not remove `streaming_waf_body.rs` shim — it is actively used by `src/tls/server.rs`.

## Phase 1 — Remove Dead `typed_pool.rs` Files

### Required Changes

1. Delete `src/http_client/typed_pool.rs` (root copy — 282 lines, not compiled).
2. Delete `crates/synvoid-http-client/src/typed_pool.rs` (crate copy — definition file).
3. In `crates/synvoid-http-client/src/lib.rs`:
   - Remove `mod typed_pool;` (line 27).
   - Remove `pub use typed_pool::{TypedConnectionPool, TypedHttpClient, TypedPoolKey};` (line 33).
4. Verify no remaining references: `rg "TypedConnectionPool|TypedHttpClient|TypedPoolKey" --type rust`

### Acceptance Criteria

- `cargo check -p synvoid-http-client` passes.
- `rg "typed_pool" --type rust` returns zero matches (excluding this plan).

## Phase 2 — Remove Root `webpki-roots` Dependency

### Required Changes

1. In root `Cargo.toml`, remove lines 173-174:
   ```toml
   # webpki-roots — root-owned for src/http_client/typed_pool.rs TLS root cert loading
   webpki-roots = "0.26"
   ```
2. Verify no root `src/` files import `webpki_roots`: `rg "webpki_roots" --type rust src/`

### Acceptance Criteria

- `cargo check --workspace` passes.
- `webpki-roots` appears only in `crates/synvoid-http-client/Cargo.toml`.

## Phase 3 — Clean Up Residual Root Files

### Required Changes

1. Delete `src/http_client/erased_pool.rs` (root copy — 613 lines, not compiled; no `mod erased_pool` in `mod.rs`).
2. Verify `src/http_client/mod.rs` does NOT declare `mod erased_pool` or `mod typed_pool`.
3. Verify `src/http_client/streaming_waf_body.rs` IS still declared and used (it is — keep it).

### Acceptance Criteria

- Only `mod.rs`, `quic_tunnel_dispatch.rs`, and `streaming_waf_body.rs` remain in `src/http_client/`.
- `cargo check --workspace` passes.

## Phase 4 — Update Documentation

### Required Changes

1. **`architecture/http_shared.md`**:
   - Remove the `typed_pool.rs` entry from the Module Structure diagram.
   - Remove the "Typed Connection Pool" section (lines 80-89).
   - Remove the `TypedPoolKey.is_http2` reference in Feature Gates.
   - Remove the `typed_pool.rs` row from the file reference table.

2. **`skills/erased_http_client.md`**:
   - Remove the `typed_pool.rs` row from the Location Reference table.
   - Update status to note typed pool has been removed.

3. **`src/http_client/AGENTS.override.md`**:
   - Remove the `typed_pool.rs` bullet point.

4. **`architecture/proxy_deep_dive.md`**:
   - Remove references to `typed_pool.rs` in the connection pooling section.

5. **`architecture/networking_deep_dive.md`**:
   - Remove or update the HTTP/2 note referencing "typed pool branches."

6. **`AGENTS.md`**:
   - Update `HTTP2-POOL` deferred item to remove "typed pool branches" reference.
   - Remove `TypedConnectionPool` from Key Codebase Facts if present.

7. **`plans/root_dependency_ownership.md`** and related ownership docs:
   - Update `webpki-roots` ownership to reflect root no longer depends on it directly.

### Acceptance Criteria

- No doc references `TypedConnectionPool`, `TypedHttpClient`, or `typed_pool` except historical plan files.

## Phase 5 — Run Tests and Fix Issues

### Required Changes

1. Run `cargo fmt --all --check`.
2. Run `cargo check --workspace --all-targets`.
3. Run `cargo check --workspace --all-targets --no-default-features`.
4. Run `cargo check --workspace --all-targets --features mesh,dns`.
5. Run `cargo test -p synvoid-http-client`.
6. Run broader tests if targeted pass.
7. Fix any compilation errors or test failures.

### Acceptance Criteria

- All targeted checks pass.
- No regressions in HTTP client functionality.

## Validation Commands

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test -p synvoid-http-client
cargo check --workspace --all-targets --no-default-features
cargo check --workspace --all-targets --features mesh,dns
```

## Completion Criteria

This iteration is complete when:

- `TypedConnectionPool`, `TypedHttpClient`, and `TypedPoolKey` are fully removed from the codebase.
- Root `webpki-roots` dependency is removed.
- Residual root `typed_pool.rs` and `erased_pool.rs` files are deleted.
- All architecture docs, skills, and agent guidance are updated.
- All compilation checks and tests pass.
- No new architecture work has been introduced.
