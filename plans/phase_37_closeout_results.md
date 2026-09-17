# Phase 37 Closeout: Direct Wasmtime Migration to Supported LTS

Status: complete (2026-09-17).
Plan: `plans/phase_37_wasmtime_lts_runtime_migration.md`.
Roadmap: `plans/runtime_dependency_security_followup_roadmap.md` (Phase 38 consumes these results).

## Landed state

- Direct runtime: **wasmtime 36.0.15** (36 LTS, supported through 2027-08-20),
  from crates.io. Declared in `crates/synvoid-plugin-runtime/Cargo.toml`
  (`version = "36.0.15"`, features `["component-model"]`, defaults on) and the
  root dev-dependency for `benches/bench_wasm.rs` (same pin).
- `[patch.crates-io]` wasmtime git entry **removed**; `deny.toml`
  `allow-git` **removed** (zero git sources remain: no `git =` in any manifest,
  no `git+` source in `Cargo.lock`; `unknown-git = "deny"` holds with no exceptions).
- Lock: `wasmtime 36.0.15` + `wasmtime 40.0.4` (yara-x transitive, unchanged),
  single `bumpalo 3.19.0`, no `wasmtime-wasi`/`wasi-filesystem`, no git source.
- Direct 42.0.2: absent (`cargo tree -i wasmtime@42.0.2 --workspace` matches nothing).

## Part A — resolver proof (before touching runtime code)

Isolated scratch crate (`wasmtime =36.0.15` + `bumpalo =3.19.0` +
`oxc_allocator =0.95.0`): resolves with a single `bumpalo 3.19.0`
(wasmtime 36's `cranelift-codegen 0.123.15` accepts the 3.19 range),
`wasmtime-wasi` absent, no git source. Workspace lock reproduces this exactly.
The `bumpalo` conflict that blocks wasmtime >=43/46 does not apply to the 36 line.

## Part B — API inventory (all source-compatible, proven by compile + tests)

Audited every direct Wasmtime use in `wasm_runtime.rs`, `instance_pool.rs`,
`pool.rs`, `spin/runtime.rs`, `test_fixtures.rs`, `benches/bench_wasm.rs`:

- `Config`: `cranelift_opt_level(SpeedAndSize)`, `max_wasm_stack(1<<20)`,
  `memory_init_cow(true)`, `consume_fuel(true)`, `epoch_interruption(true)` —
  all present in 36, unchanged call sites.
- `Engine::new/default/increment_epoch`; `Store::new/limiter/set_fuel/get_fuel/set_epoch_deadline/data/data_mut`.
- `ResourceLimiter::{memory_growing, table_growing}` — signatures unchanged.
- `Module::{new, from_binary, from_file}`, `get_export`; `Linker::{new,
  func_wrap, instantiate}`; `Instance::{get_func, get_export, get_typed_func}`;
  `Func::typed/call`, `TypedFunc::call`; `Caller::get_export/data`;
  `Extern::{into_memory, Memory}`; `Memory::{data_size, grow, data_mut}`;
  `StoreContextMut`; `wasmtime::Error`.
- Component-model path (`Component`, `ComponentLinker`, `linker.instance("host")`,
  `func_wrap` — `#[allow(dead_code)]` helpers) compiles under 36's
  `component-model` feature.
- No missing capability: no pooling-allocator config, no async, no WASI use.
  Zero runtime-code changes were required — manifest + lock only.
- Failure classification is message-substring based (`"fuel"`, `"trap"`,
  `"timed out"`); the 36 trap texts are covered by the passing fuel/epoch/trap
  fixture tests below, so no silent reclassification.

## Part C — behavior parity (invariants hold)

Fuel on for sandboxed tiers, epoch interruption as wall-clock backstop (background
incrementer unchanged), memory/table growth limits via `ResourceLimiter`,
bounded host-call budgets, unchanged signature/trust-tier policy, WASI
filesystem still absent, unsafe native extensions still opt-in and separate,
unchanged hot-reload generation semantics, Spin manifest path unchanged
(`Config`/`Engine`/`OptLevel` only).

## Part D — patch/source removal (done, see above)

`tools/synvoid-repo-guards/tests/dependency_security.rs`
(`wasmtime_direct_version_matches_baseline`) updated to the new policy: pins the
baseline `wasmtime-direct-version` anchor (now `36.0.15`), asserts NO wasmtime git
patch remains, keeps the 0269-tracking requirement, and asserts the baseline
records the direct 36 LTS line as patched. `deny.toml` `[[bans.skip]]` moved to
`=36.0.15`.

## Part E — feature surface (parity kept, minimization deferred)

`cargo tree -e features -i wasmtime@36.0.15` shows defaults + `component-model`
— the same shape as the 42.0.2 declaration. Minimization (cache, profiling,
`wat`, gc, threads, parallel-compilation, …) was evaluated and explicitly
deferred to a follow-up: `wat` is load-bearing (`Module::new` with WAT text in
benches), `threads` changes accepted guest proposals, and each removal needs
per-capability guest-compat tests. The plan sanctions this split; no footprint
claim is made for this phase.

## Part F — fixtures/tests (all pass, `--profile ci`)

- `cargo test -p synvoid-plugin-runtime --all-features`: 346 lib + 7 + 6
  integration = 359 passed, 0 failed. Covers filter pass/block/challenge,
  response transform, handler path, guest alloc/free contract, memory/table
  limits, fuel exhaustion, epoch-deadline interruption (infinite-loop +
  incrementer), host-call denial/timeout, malformed-module and missing-export
  rejection, hot-reload generation replacement, pooled reset/isolation.
- `cargo test -p synvoid-serverless --all-features`: 20 passed.
- `cargo test -p synvoid-jail-runtime --all-features`: 4 passed.
- `cargo bench --bench bench_wasm --no-run`: compiles (root dev-dep at 36.0.15).

## Part G — performance (no regression; 36 LTS is faster here)

`bench_wasm`, `--profile ci`, same host (38.0.15 = after / 42.0.2-git = before):

| Bench | 42.0.2 (before) | 36.0.15 (after) |
|---|---|---|
| fresh `instantiate_and_call` | 6.88 µs | 6.54 µs (~5% faster) |
| pooled `get_from_pool_and_call` | 305 ns | 279 ns (~8% faster) |
| `fresh_instantiate` | 7.62 µs | 7.12 µs (~7% faster) |
| `pool_reuse` | 303 ns | 280 ns (~8% faster) |

Jail-IPC benches unaffected (no wasmtime). Release binary size / clean-rebuild
time not separately measured: default feature set and Cranelift backend are
unchanged, so no footprint claim is made or needed.

## Part H — advisory disposition

- Advisory DB (`RUSTSEC-2026-0269.md`): patched ranges include
  `>=36.0.14,<37.0.0` → 36.0.15 is patched by version.
- Isolated `cargo audit` on the 36.0.15 scratch resolve (no ignores): zero
  findings — direct line needs no ignore and is unaffected by the 2026-04
  advisory group either.
- Workspace `cargo audit`: clean (6 pre-existing unmaintained warnings only).
  `cargo deny check`: advisories/bans/licenses/sources all ok.
- The 0269 ignore (deny + audit, mirrored sets verified by
  `audit_config_mirrors_deny_ignores`) is retained SOLELY for transitive
  40.0.4; remove condition is yara-x moving off wasmtime 40.x. Phase 38
  normalizes the final multi-version record.
- 16 advisory ignores total (unchanged count); Re-audit 2026-10-01.

## Process note (lockfile hygiene)

The first `cargo generate-lockfile` after the manifest edit re-resolved the
whole graph and floated `yara-x-macros`/`yara-x-parser` 1.15.0 → 1.20.0 while
`yara-x` stayed 1.15.0 — an incompatible mix that broke
`synvoid-jail-runtime --all-features` (`RegexpId` errors inside yara-x 1.15
sources). Fixed by restoring the committed lock and applying a targeted
`cargo update -p wasmtime@42.0.2 --precise 36.0.15` instead (464-line diff
confined to the wasmtime subgraph swap vs 1411 lines). Lesson for future
version moves: prefer targeted `cargo update -p <pkg> --precise <v>` over full
regeneration, and re-run the yara/jail suites after any lock touch.

## Docs updated

`AGENTS.md` (Known Issues), `SECURITY.md` (triage, policy, patch, limitation
sections), `architecture/dependency_security_baseline_phase25.md`
(§1/§3/§4/§6, anchors, Reviewed date; §8 addendum below is mirrored here),
`architecture/{plugin_wasm,spin,layer_3_5_deep_dive,agent_knowledge_maintenance}.md`
(+ new recurring checklist item 8), `docs/RELEASE.md`,
`.opencode/skills/{supply_chain,serverless_wasm}/SKILL.md` (latter pruned a
stale `wasmtime_wasi::WasiCtxBuilder` section describing code that does not
exist). `README.md` has no version-pinned wasmtime content (untouched).
Historical phase/closeout reports and the Phase 38 plan (which already
specified this exact end state) left as-is.

## Acceptance criteria status

- [x] Direct runtime resolves to 36.0.14+ LTS (36.0.15).
- [x] Direct 42.0.2 absent.
- [x] Containment/resource semantics preserved (no runtime-code change; suites green).
- [x] WASI filesystem remains absent.
- [x] Git patch + `allow-git` removed.
- [x] Plugin, Spin (via serverless/jail suites), pooling, hot-reload, benchmark fixtures pass.
- [x] Direct 0269 exposure eliminated by version, not ignored.
- [x] Feature minimization disposition recorded with rationale (deferred follow-up).
- [x] Graph + security docs distinguish direct 36 LTS from transitive YARA-X line.
