# HTTP Client Typed Pool Migration — Iteration 5

## Goal

Move the remaining root-owned HTTP client typed-pool/TLS-root ownership into `crates/synvoid-http-client`, then remove stale root dependencies and comments. This is the next low-risk boundary cleanup before starting the larger mesh trust-domain split.

The target end state is:

- HTTP client pooling, typed-pool construction, and TLS root loading live in `synvoid-http-client`;
- root imports the public API from `synvoid-http-client` instead of owning duplicate implementation files;
- root no longer declares `webpki-roots` unless a verified root `src/` use remains;
- `plans/root_dependency_ownership_iteration_2.md` and `Cargo.toml` agree;
- behavior is preserved.

## Non-Goals

Do not redesign the HTTP client.

Do not change TLS trust-store behavior.

Do not change timeout, pooling, retry, proxy, or typed-client semantics unless required to preserve the existing behavior after moving code.

Do not remove or rewrite `synvoid-http-client` public APIs unnecessarily.

Do not start the mesh trust-domain split in this pass.

Do not change feature defaults.

Do not perform broad dependency cleanup outside HTTP-client ownership.

## Phase 1 — Inventory Current HTTP Client Ownership

### Required Searches

Run:

```bash
rg "typed_pool|TypedPool|HttpClient|webpki_roots|webpki-roots|RootCertStore|ClientConfig" src crates Cargo.toml
find src/http_client crates/synvoid-http-client -maxdepth 3 -type f | sort
```

Classify each relevant file into one of these buckets:

- root composition/import shim;
- root-owned implementation that should move;
- existing `synvoid-http-client` implementation;
- duplicate or near-duplicate code;
- tests/examples/docs.

Pay particular attention to:

- `src/http_client/typed_pool.rs`;
- any `src/http_client/mod.rs` re-exports;
- `crates/synvoid-http-client/src/*`;
- `crates/synvoid-http-client/Cargo.toml`;
- root `Cargo.toml` dependency comments for `webpki-roots`.

### Acceptance Criteria

The implementation move is based on actual imports and call sites, not assumptions.

Record the classification in the commit message or a short plan note if the move becomes non-trivial.

## Phase 2 — Move Typed Pool Implementation Into `synvoid-http-client`

### Required Changes

Move root-owned typed-pool/TLS-root implementation into the library crate.

Preferred shape:

```text
crates/synvoid-http-client/src/typed_pool.rs
```

If a file already exists there, merge root-only behavior into it rather than creating a parallel implementation.

Expose only the public API root actually needs from `crates/synvoid-http-client/src/lib.rs`.

Root should become one of these:

1. no `src/http_client` module at all, if all call sites can import `synvoid_http_client::*` directly; or
2. a thin compatibility shim that only re-exports crate-owned types/functions.

Preferred compatibility shim shape if needed:

```rust
pub use synvoid_http_client::typed_pool::{...};
```

Do not leave implementation logic in root if it can be moved cleanly.

### Acceptance Criteria

Root no longer owns typed-pool implementation logic.

`crates/synvoid-http-client` owns TLS root loading needed by typed pool.

Existing root call sites compile with either direct crate imports or a thin root re-export.

## Phase 3 — Reconcile Dependencies

### Required Changes

After moving the implementation, run:

```bash
rg "webpki_roots|webpki-roots" Cargo.toml src crates
cargo tree -p synvoid -i webpki-roots
cargo tree -p synvoid-http-client -i webpki-roots
```

If root `src/` no longer uses `webpki_roots`, remove this from root `Cargo.toml`:

```toml
webpki-roots = "0.26"
```

Keep `webpki-roots` in `crates/synvoid-http-client/Cargo.toml` if the crate uses it.

Update the root dependency comment block so it no longer says root owns `webpki-roots`.

Update `plans/root_dependency_ownership_iteration_2.md` so the `webpki-roots` row reflects the final state.

Expected final row if the move succeeds:

```markdown
| webpki-roots | synvoid-http-client | no | none | TLS root loading owned by `crates/synvoid-http-client`; root imports/re-exports client APIs only. |
```

### Acceptance Criteria

`webpki-roots` ownership is consistent across manifests, comments, and the ownership note.

`cargo check -p synvoid-http-client` passes.

`cargo check --workspace --all-targets` passes or failures are documented as unrelated/pre-existing.

## Phase 4 — Preserve Behavior With Focused Tests

### Required Tests

Add or move tests near the implementation in `synvoid-http-client`.

Test the behavior that can be tested without live network calls:

- typed-pool config/default construction;
- TLS root store construction does not panic;
- pool key / typed-client identity behavior if present;
- timeout or policy defaults if encoded in the typed pool;
- API compatibility for root call sites if a shim remains.

Do not add live HTTP, QUIC, DNS, or external network tests.

If existing tests already cover this behavior, move them with the implementation and update imports.

### Acceptance Criteria

The moved code has at least equivalent local test coverage.

No test requires external network access.

## Phase 5 — Update Imports and Shims

### Required Changes

Update root call sites to use the new crate-owned API.

Search after migration:

```bash
rg "crate::http_client|super::http_client|src/http_client|typed_pool" src crates
```

If root `src/http_client/mod.rs` remains, keep it intentionally tiny and comment that it is a compatibility re-export only.

If root `src/http_client/typed_pool.rs` remains, it should contain no implementation logic. Prefer deleting it if possible.

### Acceptance Criteria

There is a single implementation owner for typed-pool behavior.

Root HTTP-client module, if present, is a re-export shim only.

No stale imports point to deleted root modules.

## Phase 6 — Documentation and Ownership Cleanup

### Required Changes

Update any docs/comments that mention root ownership of HTTP client typed-pool behavior.

At minimum, update:

- root `Cargo.toml` comments;
- `plans/root_dependency_ownership_iteration_2.md`;
- any module-level comments in `src/http_client` or `crates/synvoid-http-client`.

Do not create a large new doc unless needed. This is a cleanup pass.

### Acceptance Criteria

No known comments falsely state that root owns `webpki-roots` or typed-pool TLS root loading.

The ownership trail points to `synvoid-http-client`.

## Validation Commands

Run focused checks first:

```bash
cargo fmt --all --check
cargo check -p synvoid-http-client
cargo test -p synvoid-http-client
cargo check -p synvoid
```

Then run workspace checks:

```bash
cargo check --workspace --all-targets
cargo test --workspace --all-targets
```

Feature checks:

```bash
cargo check --workspace --all-targets --no-default-features
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broad checks are too expensive or blocked by unrelated failures, record exactly which targeted checks passed and what remains unverified.

## Completion Criteria

This iteration is complete when:

- typed-pool implementation lives in `synvoid-http-client`;
- root contains at most a thin compatibility re-export for HTTP-client APIs;
- root `webpki-roots` dependency is removed unless a verified root import remains;
- `plans/root_dependency_ownership_iteration_2.md` matches the final dependency state;
- tests cover the moved implementation without live network calls;
- no unrelated mesh or architecture work is included.

## Follow-Up Recommendation

After this migration, reassess root dependency ownership one more time. If the repo remains stable, start the next major architecture track: an internal `synvoid-mesh` trust-domain split. That pass should begin with a design note defining advisory DHT state, canonical Raft/global-node state, identity, transport, and policy boundaries before moving code.
