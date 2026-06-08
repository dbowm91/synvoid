# Workspace All-Targets Failure Inventory

## Status: GREEN

All prior failures resolved. `cargo check --workspace --all-targets` passes with warnings only.

## Historical failures (all resolved before this pass)

| Crate/target | Error code | File | Root cause | Resolution |
|---|---|---|---|---|
| `myapp-dynamic` example | E0507 | `examples/dynamic-plugin-example/src/lib.rs:43` | Unused `Box::from_raw` return value | Resolved in prior work |
| `synvoid-ipc` test | missing `sha2` | `crates/synvoid-ipc/Cargo.toml` | Missing dev-dependency | Resolved in prior work |
| `admin-ui` | E0277, E0282, E0609, missing deps | `admin-ui/src/**` | Multiple type/field errors | Resolved in prior work |
| `synvoid-mesh` tests | various | `crates/synvoid-mesh/src/**` | Stale imports after crate extraction | Resolved in prior work |

## Validation commands (2026-06-08 — HWD-F01 full matrix)

| Command | Result |
|---|---|
| `cargo fmt` | PASS |
| `cargo check --lib --no-default-features` | PASS |
| `cargo check --no-default-features --features dns` | PASS |
| `cargo check --no-default-features --features mesh` | PASS |
| `cargo check --no-default-features --features mesh,dns` | PASS |
| `cargo check -p synvoid-http` | PASS |
| `cargo check -p synvoid-http3` | PASS |
| `cargo check -p synvoid-upload` | PASS |
| `cargo check --workspace --all-targets` | PASS |
| `cargo test --workspace --no-run` | PASS |
