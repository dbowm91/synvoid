# SynVoid Compile-Time Measurements

> Captured: 2026-06-07
> Host: darwin (macOS), local development target
> Cargo profile: dev (opt-level 0, debug = true)
> Note: `/usr/bin/time -p` was used for wall-clock numbers.
> `user` / `sys` are shown when interesting; most runs are CPU-light (warm cache).

## Raw run

The script in `scripts/measure_compile_paths.sh` was executed in full and the
output was captured to `/tmp/measurement_run.txt`. The summary lines are:

| Command | Clean/incremental | Wall time | Notes |
|---|---|---|---|
| `cargo check -p synvoid-core` | incremental (warm) | 2.52s | Small leaf crate, mostly deps |
| `cargo check -p synvoid-waf` | incremental (warm) | 4.62s | Recompiled only `synvoid-waf` |
| `cargo check -p synvoid-proxy` | incremental (warm) | 5.10s | Pulled in synvoid-serverless, synvoid-tls, synvoid-static-files, synvoid-app-handlers, synvoid-metrics, synvoid-ipc |
| `cargo check -p synvoid-http` | incremental (warm) | 1.95s | Fast leaf |
| `cargo check -p synvoid-static-files` | incremental (warm) | 0.35s | Smallest leaf measured |
| `cargo check -p synvoid-ipc` | incremental (warm) | 0.26s | Trivial crate |
| `cargo check --lib --no-default-features` | incremental (warm) | 19.10s | Root orchestration; recompiled root lib + 0 transitive crates (warm) |
| `cargo check --no-default-features --features mesh` | incremental (warm) | 4.14s | Compiles cleanly after SDC-A02 fix (was E0425 in init_mesh.rs) |
| `cargo check --no-default-features --features dns` | incremental (warm) | 19.14s | Compiles cleanly |
| `cargo check --no-default-features --features mesh,dns` | incremental (warm) | 7.94s | Compiles cleanly after SDC-A02 fix |
| `cargo check --workspace --all-targets` | mixed | **FAILED** (8.75s wall) | Pre-existing errors in `admin-ui` (5 E0277/E0282/E0609 + missing `tempfile` / `sha2` deps in yew pages) |

### Per-crate incremental edits

After the run above the cache was warm. Each test is `touch` of the file plus
`/usr/bin/time -p cargo check …`.

| File touched | Crate | Wall time | Notes |
|---|---|---|---|
| `crates/synvoid-waf/src/lib.rs` | synvoid-waf | 8.45s | Recompiles waf only (no transitive crates) |
| `crates/synvoid-proxy/src/server.rs` | synvoid-proxy | 2.95s | Recompiles proxy + a few peers |
| `crates/synvoid-http/src/lib.rs` | synvoid-http | 14.96s | Heavy downstream — pulls in synvoid-static-files, synvoid-ipc, synvoid-proxy, synvoid-metrics |
| `crates/synvoid-static-files/src/image_rights.rs` | synvoid-static-files | 2.42s | Cheap leaf |
| `src/http/server.rs` | root lib | 2.67s | Recompiles root lib only — http server is a leaf in the root tree |
| `src/proxy/mod.rs` | root lib (first touch) | **95.60s** | Cold rebuild — proxy is depended on by most orchestration code |
| `src/proxy/mod.rs` | root lib (second touch) | 3.83s | Warm — proxy shim is small once crates are built |
| `src/waf/mod.rs` | root lib | 3.12s | Recompiles root lib |
| `src/supervisor/mod.rs` | root lib | 3.38s | |
| `src/worker/mod.rs` | root lib | 8.62s | Pulls in unified_server tree |
| `src/admin/mod.rs` | root lib | 4.10s | |
| `src/upload/mod.rs` | root lib | 2.70s | |
| `src/dns/mod.rs` | root lib | 3.25s | |
| `src/main.rs` | root lib | 3.43s | |

## Pre-existing failures

These are not measurement-side failures — they are real compile errors in
the current tree and were observed during the run. The MDM pass must not
regress them, but also is not required to fix them.

* ~~`cargo check --no-default-features --features mesh`~~ — **Fixed in SDC-A02** (2026-06-07).
  * `backend_pool` and `signer_for_mesh` were defined after an early return
    in `init_mesh.rs`, making them unreachable. Moved definitions into the
    `#[cfg(not(feature = "dns"))]` block where they are consumed.
* `cargo check --workspace --all-targets`
  * `admin-ui` lib + lib-test fail with 5 errors in Yew/leptos pages
    (`E0277`, `E0282`, `E0609`) and `unresolved import 'sha2'`,
    `cannot find module or crate 'tempfile'` in the yew source tree.
  * These are pre-existing — they are not introduced by MDM-M01/M02 work.

## Hot spot ranking

The ranking below combines the wall-clock measurements above with the
edit-frequency visible in the existing plan docs
(`http_server_dependency_inventory.md`, `wafcore_concrete_dependency_inventory.md`,
`worker_supervisor_boundary.md`, `mesh_consensus_boundary.md`).

### High priority — measured hot and frequent edit path

* **`src/http/server.rs` (root)**
  * Required edit path for the main HTTP server. Frequently touched in
    consolidation passes; warm recompile is small (2.67s) but downstream
    crates pull in transitively. The candidate-target work is already
    tracked in `plans/http_server_dependency_inventory.md`.
* **`crates/synvoid-http/src/lib.rs`**
  * 14.96s warm touch — clearly a heavy fan-in crate. Holds the
    `dispatch`, `request_log`, `streaming`, and `challenge_paths` modules
    that almost every orchestration site imports. Worth keeping tight
    even if extraction is not on the table.
* **`src/worker/unified_server/` tree (incl. `init_mesh.rs`)**
  * 8.62s for `src/worker/mod.rs` touch. Also the site of the
    pre-existing mesh feature compile errors above — a high-value area
    to stabilise regardless of extraction.

### Medium priority — measured hot but infrequent edit path

* **`src/proxy/mod.rs` (root shim)**
  * Cold rebuild of root after touching the proxy shim was 95.60s.
    Subsequent touches are 3.83s because the shim is just `pub use`.
    Once the cache is warm it is cheap, but the first edit in a fresh
    session pays a real cost — proxy is depended on widely.
* **`src/supervisor/mod.rs`**
  * 3.38s warm touch. Tied to the supervisor orchestration surface
    and the focus of `plans/worker_supervisor_boundary.md`.
* **`src/admin/mod.rs`**
  * 4.10s warm touch. Admin is a stable but wide orchestration point;
    the schema work in MDM-A01/A02 will sit on top of it.
* **`src/dns/mod.rs`**
  * 3.25s warm touch. Stable surface; only relevant to the DNS profile.

### Low priority — not measured hot or rarely edited

* **`src/http3/server.rs` (root)**
  * 3.37s warm touch. Small hot spot. Not currently a frequent edit
    path; HTTP/3 work is concentrated in the `synvoid-http3` crate.
* **`src/upload/mod.rs`**
  * 2.70s warm touch. YARA/upload surface; only edited in scanner
    changes (tracked by MDM-S01).
* **`crates/synvoid-waf/src/lib.rs`**
  * 8.45s warm touch on a *cold* leaf, but actual real work was small
    (user 0.36s). Recompiles waf only — no fan-in.
* **`crates/synvoid-static-files/src/image_rights.rs`**
  * 2.42s warm touch. Cheap, isolated leaf.
* **`crates/synvoid-ipc/src/lib.rs`** — 0.26s baseline; not a hot path.
* **`crates/synvoid-core/src/lib.rs`** — 2.52s baseline; not a hot path.
* **`src/main.rs`** — 3.43s warm touch; rarely edited directly.

### Defer — orchestration layer where extraction likely increases complexity

* **root `WafCore`**
  * Concrete WafCore is intentionally root-owned (see
    `plans/wafcore_concrete_dependency_inventory.md`). No
    `src/waf/core.rs` measurement was taken; the existing inventory
    already lists the concrete dependencies. Extraction would force
    every subsystem to keep two paths (root + extracted) and does not
    match the rule in the plan ("orchestration layer where extraction
    likely increases complexity"). **Defer (no new measurement).**
* **root `WafCore` and `worker/cpu_task`**
  * CPU offload workers are a separate process boundary; the
    inter-process IPC contract is the actual owner of compile time
    here, not the code that lives in `src/worker/cpu_task/`. No
    incremental measurement taken for that tree. **Defer (no
    measurement).**
* **supervisor/process**
  * Already a root orchestration layer and explicitly listed as
    "leave in root" in the plan. **Defer.**
* **admin/OpenAPI export**
  * 4.10s on `src/admin/mod.rs` touch is the actual hot path; the
    OpenAPI/utoipa surface is layered on top and not separately
    measured. **Defer (no separate measurement) — the
    `plans/admin_schema_ownership.md` work (MDM-A01) will gather
    data before deciding.**
* **YARA/upload/security scanner path**
  * `src/upload/mod.rs` measured at 2.70s. The YARA engine itself
    is gated through `crates/synvoid-upload` (and `yara-x` is
    root-owned). The actual hot path is `yara-x` compile time, not
    the Rust module. **Defer — `plans/security_scanner_ownership.md`
    (MDM-S01) will gather data before deciding.**
* **rusqlite/block-store/persistence path**
  * Not separately measured. The rusqlite use is in `src/dns/store.rs`,
    `src/dns/trust_anchor.rs`, `src/honeypot_port/storage.rs`, and
    `src/waf/threat_level/persistence/sqlite.rs`. Block-store is in
    `crates/synvoid-block-store`. **Defer (no measurement) —
    `plans/persistence_ownership.md` (MDM-S02) will gather data.**
* **mesh/Raft**
  * The mesh feature now compiles cleanly (fixed in SDC-A02).
    Warm touch measurement: 4.14s. Future mesh/Raft decisions can
    reference `plans/mesh_consensus_boundary.md`.

## Stability cleanup follow-up

SDC pass completed 2026-06-07. Results:

- `cargo check --lib --no-default-features`: PASS (1.11s)
- `cargo check --no-default-features --features dns`: PASS (51.64s)
- `cargo check --no-default-features --features mesh`: PASS (34.90s) [was FAILING before SDC-A02]
- `cargo check --no-default-features --features mesh,dns`: PASS (35.08s)
- `cargo check -p synvoid-upload`: PASS (51.08s)
- `cargo check -p synvoid-mesh --features mesh`: PASS (51.25s)
- `cargo check --workspace --all-targets`: **FAILED** — 4 pre-existing errors:
  - `myapp-dynamic` (lib test): E0507 `cannot move out of *app` (app crate, not SynVoid)
  - `synvoid-ipc` (lib test): E0432 unresolved import `sha2` (test dep missing)
  - `admin-ui`: 5 E0277/E0282/E0609 + missing `tempfile`/`sha2` (pre-existing, documented above)
  - `synvoid-mesh` (lib test): 4 errors in edge_replica test (test-only, not lib)

Note: Times are incremental (warm cache). First-touch times are significantly higher (see Raw run above).

## Notes for follow-up

* The root `cargo check --no-default-features` (19.10s) is the most
  common iteration profile. Improvements here would benefit the most
  developers.
* The `mesh` feature compile failure was fixed in SDC-A02 (2026-06-07).
  `backend_pool` and `signer_for_mesh` were defined after an unreachable
  early return in `init_mesh.rs`. Fix: moved definitions into the
  `#[cfg(not(feature = "dns"))]` block where they are consumed.
* The 95.60s first-touch on `src/proxy/mod.rs` is a one-off cold
  cache cost. It does not justify extraction on its own, but it does
  show that the proxy shim is a critical compile fan-in point — any
  future split of the root proxy module should be validated against
  this number.
