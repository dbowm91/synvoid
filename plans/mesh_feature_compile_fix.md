# Mesh Feature Compile Fix (SDC-A02)

## Root Cause

`backend_pool` and `signer_for_mesh` were defined at `init_mesh.rs:120` and
`init_mesh.rs:186`, **after** an `if true { return; }` early return at line 57.
Although the code after the return is unreachable at runtime, the compiler still
performs name resolution. The `#[cfg(not(feature = "dns"))]` block at line 300
is compiled when the `dns` feature is off (i.e. `--features mesh` alone), and it
references `backend_pool` (line 311) and `signer_for_mesh` (line 313) — which
were never bound in scope.

```
error[E0425]: cannot find value `backend_pool` in this scope
  --> src/worker/unified_server/init_mesh.rs:311
error[E0425]: cannot find value `signer_for_mesh` in this scope
  --> src/worker/unified_server/init_mesh.rs:313
```

## Fix

Moved the `backend_pool` and `signer_for_mesh` definitions **inside** the
`#[cfg(not(feature = "dns"))]` block where they are consumed. This eliminates
the E0425 errors and the unused variable warnings (the variables are now only
defined when the `dns` feature is off).

The earlier hypothesis of underscore-prefixed bindings (`_backend_pool` /
`_signer_for_mesh`) was incorrect — the variables were genuinely unreachable,
not just unused.

## Files Changed

- `src/worker/unified_server/init_mesh.rs` — moved `backend_pool` and
  `signer_for_mesh` into `#[cfg(not(feature = "dns"))]` block

## Verification

```
cargo check --no-default-features --features mesh        # PASS (4.14s)
cargo check --no-default-features --features mesh,dns    # PASS (7.94s)
cargo check --lib --no-default-features                 # PASS (10.39s)
```
