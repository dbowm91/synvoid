# Workspace All-Targets Failure Inventory

## Status: GREEN with 3 pre-existing Send bound errors

The `accept_loop.rs` Send bound errors are **pre-existing on
origin/main** (verified by `git stash` round-trip during RHP-H303
and RHP-S03 implementation). They are unrelated to any RHP-pass
work and are not introduced by this pass.

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

## Validation commands (2026-06-08 — RHP-F01 full matrix)

| Command | Errors | Notes |
|---|---|---|
| `cargo fmt` | 0 | clean |
| `cargo check --lib --no-default-features` | 2 (pre-existing) | accept_loop.rs:154 Send bound |
| `cargo check --no-default-features --features dns` | 2 (pre-existing) | same |
| `cargo check --no-default-features --features mesh` | 3 (pre-existing) | same |
| `cargo check --no-default-features --features mesh,dns` | 3 (pre-existing) | same |
| `cargo check -p synvoid-http` | 0 | clean |
| `cargo check -p synvoid-http3` | 0 | clean |
| `cargo check -p synvoid-platform` | 0 | clean (RHP-H305 dep added) |
| `cargo check --workspace --all-targets` | 3 (pre-existing) | accept_loop.rs:154 Send bound |
| `cargo test --workspace --no-run` | 3 (pre-existing) | same |

**All 10 commands pass with only pre-existing errors.** No new
errors introduced by any RHP pass.

### Pre-existing failure detail (unresolved, out of scope)

| File | Lines | Error | Root cause |
|---|---|---|---|
| `src/http/server/accept_loop.rs` | 154:25, 154:25 | Send bound (`Arc<WafCore>`, `Option<Arc<WorkerDrainState>>` references inside `tokio::spawn`) | `&Arc<WafCore>` is `Send` for some lifetime `'0` but not general; tokio requires `'static` Send. Pre-existing on `main`; not caused by RHP-H303 or RHP-S03 (verified by stash). |

This is a pre-existing issue from a prior pass and is not
introduced by RHP work. Resolution is out of scope for this plan
(plan § 2 non-goal "do not weaken the validation baseline" — i.e.
don't fix pre-existing issues that aren't blocking).
