# Persistence / rusqlite Ownership Audit

> Created as part of MDM-S02.
> Scope: rusqlite usage, block store, threat-level SQLite history, mesh
> DHT/raft persistence, and other persistent-state surfaces.
> No code movement in this audit.

## Summary

rusqlite is used by **four** distinct subsystems:

1. **DNS trust anchors and zone store** — owned by `synvoid-dns`.
2. **Honeypot connection records** — owned by `synvoid-honeypot`.
3. **Mesh DHT record store + Raft state machine + edge replica** — owned by
   `synvoid-mesh`.
4. **Threat-level SQLite history** — owned by the root
   `src/waf/threat_level/persistence/sqlite.rs` module.

`synvoid-block-store` (the persistent IP block store crate) does **not** use
rusqlite. It uses JSON serialization to disk (see
`crates/synvoid-block-store/src/lib.rs:78-89`). It is the only "store" in
this audit that is genuinely a different persistence model.

The root `Cargo.toml` direct `rusqlite` dep is justified today because one
real root module (`src/waf/threat_level/persistence/sqlite.rs`) and three
dead root files (`src/dns/store.rs`, `src/dns/trust_anchor.rs`,
`src/honeypot_port/storage.rs`) reference it. The dead files can be deleted,
but the threat-level file is real and on a non-trivial code path. The
direct root dep is therefore **not removable in this pass** without also
moving the threat-level SQLite code, which is a clean boundary but not a
measured hot path.

## Files in scope (count: 11 source files + 5 Cargo.toml entries)

| Module/file | Current crate | Data owned | Candidate target crate | Root dep removable? | Notes |
|---|---|---|---|---|---|
| `crates/synvoid-dns/src/store.rs` | `synvoid-dns` | DNS zone persistent cache (sqlite) | `synvoid-dns` (KEEP) | n/a (own crate dep) | `use rusqlite::{params, Connection};` (line 2). Backed by `synvoid-dns/Cargo.toml:56` direct dep. |
| `crates/synvoid-dns/src/trust_anchor.rs` | `synvoid-dns` | RFC 5011 trust-anchor roll history (sqlite) | `synvoid-dns` (KEEP) | n/a | `use rusqlite::{params, Connection};` (line 3). Backs `TrustAnchorManager` and the RFC 5011 state machine. |
| `crates/synvoid-dns/Cargo.toml` | `synvoid-dns` | n/a (manifest) | n/a | n/a | `rusqlite = "0.32"` (line 56). |
| `crates/synvoid-honeypot/src/storage.rs` | `synvoid-honeypot` | Honeypot connection records (sqlite) | `synvoid-honeypot` (KEEP) | n/a | `use rusqlite::{params, Connection, OptionalExtension};` (line 2). Backs `HoneypotStorage`. |
| `crates/synvoid-honeypot/Cargo.toml` | `synvoid-honeypot` | n/a (manifest) | n/a | n/a | `rusqlite = "0.32"` (line 17). |
| `crates/synvoid-mesh/src/mesh/dht/record_store_disk.rs` | `synvoid-mesh` | DHT record persistence (sqlite) | `synvoid-mesh` (KEEP) | n/a | `use rusqlite::{params, Connection};` (line 2). Backs the disk-backed DHT record store. |
| `crates/synvoid-mesh/src/mesh/raft/state_machine.rs` | `synvoid-mesh` | Raft state-machine snapshot data (sqlite) | `synvoid-mesh` (KEEP) | n/a | `use rusqlite::{params, Connection};` (line 21). State machine persists applied entries. |
| `crates/synvoid-mesh/src/mesh/raft/edge_replica.rs` | `synvoid-mesh` | Edge-replica sqlite mirror | `synvoid-mesh` (KEEP) | n/a | `use rusqlite::{params, Connection};` (line 7). |
| `crates/synvoid-mesh/src/mesh/raft/instance.rs` | `synvoid-mesh` | Raft snapshot manager | `synvoid-mesh` (KEEP) | n/a | Indirectly via `state_machine`. |
| `crates/synvoid-mesh/src/mesh/raft/regression_tests.rs` | `synvoid-mesh` (test only) | regression test sqlite usage | `synvoid-mesh` (KEEP) | n/a | `use rusqlite::Connection;` (line 908). |
| `crates/synvoid-mesh/Cargo.toml` | `synvoid-mesh` | n/a (manifest) | n/a | n/a | `rusqlite = "0.32"` (search shows it in cargo tree). |
| `src/waf/threat_level/persistence/sqlite.rs` | **root** | Threat-level history (sqlite) | `synvoid-waf` (potential) | NO — only with code movement | `use rusqlite::{params, Connection, OptionalExtension};` (line 4). 754+ lines. Re-exported at `src/waf/threat_level/mod.rs:8` as `BackupInfo`, `SqliteBackup`, `SqliteHistory`. Used by `use_sqlite_history` config flag (line 33). |
| `src/waf/threat_level/persistence/mod.rs:1` | **root** | module declaration | n/a | n/a | `pub mod sqlite;` — confirms `sqlite.rs` IS compiled. |
| `src/dns/store.rs` | **root** (NOT COMPILED) | duplicate of `synvoid-dns` | delete | part of root dep | `use rusqlite::{params, Connection};` (line 6). `src/dns/mod.rs` is `pub use synvoid_dns::*;` so this file is never compiled. |
| `src/dns/trust_anchor.rs` | **root** (NOT COMPILED) | duplicate of `synvoid-dns` | delete | part of root dep | `use rusqlite::{params, Connection};` (line 3). Same fate as above. |
| `src/honeypot_port/storage.rs` | **root** (NOT COMPILED) | duplicate of `synvoid-honeypot` | delete | part of root dep | `use rusqlite::{params, Connection, OptionalExtension};` (line 2). `src/honeypot_port/mod.rs` is `pub use synvoid_honeypot::*;` so this file is never compiled. |
| `src/block_store.rs` | **root** (re-export shim) | re-exports `synvoid_block_store::*` | n/a | n/a | 1 line: `pub use synvoid_block_store::*;`. Live consumers: `src/supervisor/state.rs:4`, `src/process/manager.rs:105,151,1205`. |
| `src/dns/mod.rs` | **root** (re-export shim) | re-exports `synvoid_dns::*` | n/a | n/a | 15 lines. `pub use synvoid_dns::*;` under `#[cfg(feature = "dns")]`. |
| `src/honeypot_port/mod.rs` | **root** (re-export shim) | re-exports `synvoid_honeypot::*` | n/a | n/a | 1 line. |
| `src/worker_pool/shared_state.rs` | **root** | shared worker pool persistence (not sqlite) | n/a | n/a | `last_persist`, `persist_path`, `persist_enabled` (lines 16-19). JSON-based, not sqlite. Listed for completeness. |
| `src/process/manager.rs:1205` | **root** | `trigger_blocklist_persist` | n/a | n/a | calls `BlockStore::trigger_persist`. |
| `src/supervisor/state.rs:4,30` | **root** | holds `Arc<BlockStore>` in `SupervisorState` | n/a | n/a | the only place `BlockStore` is held in supervisor state. |
| `crates/synvoid-block-store/src/lib.rs:78-89` | `synvoid-block-store` | `BlockStore` struct, `persist_path`, `persist_tx` | `synvoid-block-store` (KEEP) | n/a | Uses JSON+filesystem, NOT rusqlite. Description "Persistent IP block store with LRU eviction and disk persistence". |
| `crates/synvoid-block-store/Cargo.toml` | `synvoid-block-store` | n/a | n/a | n/a | No rusqlite. |
| `Cargo.toml:160` | **root** | direct dep declaration | n/a | NO (with movement) / YES (after dead-file deletion) | `rusqlite = { version = "0.32", features = ["bundled", "backup"] }`. |

## Dependency chain (cargo tree evidence)

`cargo tree -p synvoid -i rusqlite --no-default-features`:

```
rusqlite v0.32.1
├── synvoid v0.1.0  (root, direct)
├── synvoid-dns v0.1.0  (direct dep)
├── synvoid-honeypot v0.1.0  (direct dep)
└── synvoid-mesh v0.1.0  (direct dep, transitive into synvoid-block-store
                            via mesh feature)
```

All four owners are workspace members with their own direct dep. Root
removal would not affect any leaf crate's compile.

## What is actually compiled (live) vs. dead

| File | `pub mod`/re-export chain | Compiled? |
|---|---|---|
| `src/waf/threat_level/persistence/sqlite.rs` | `src/waf/threat_level/persistence/mod.rs:1` declares `pub mod sqlite;` | YES (live) |
| `src/dns/store.rs` | `src/dns/mod.rs:1` is `pub use synvoid_dns::*;` (no `pub mod store`) | NO (dead) |
| `src/dns/trust_anchor.rs` | same as above | NO (dead) |
| `src/honeypot_port/storage.rs` | `src/honeypot_port/mod.rs:1` is `pub use synvoid_honeypot::*;` (no `pub mod storage`) | NO (dead) |

The dead files were likely left over from the pre-extraction refactor that
moved DNS and honeypot into their own crates. Removing them is a small
mechanical task and is the prerequisite for any future removal of the
root's `rusqlite` direct dep.

## Live cross-crate consumers

| Consumer | Imports | Resolves to |
|---|---|---|
| `src/dns/resolver.rs:42` | `use crate::dns::trust_anchor::{...};` | re-export shim → `synvoid-dns` (live) |
| `src/honeypot_port/listener.rs:14` | `use crate::honeypot_port::storage::{HoneypotRecord, HoneypotStorage};` | re-export shim → `synvoid-honeypot` (live) |
| `src/honeypot_port/runner.rs:10` | `use crate::honeypot_port::storage::HoneypotStorage;` | re-export shim → `synvoid-honeypot` (live) |
| `src/honeypot_port/threat_intel.rs:3,178` | `use crate::honeypot_port::storage::HoneypotRecord;` | re-export shim → `synvoid-honeypot` (live) |
| `src/supervisor/state.rs:4` | `use crate::block_store::BlockStore;` | re-export shim → `synvoid-block-store` (live) |
| `src/process/manager.rs:105,151,1205` | `Arc<crate::block_store::BlockStore>`, `trigger_blocklist_persist` | re-export shim → `synvoid-block-store` (live) |
| `src/waf/threat_level/mod.rs:8` | `pub use persistence::sqlite::{BackupInfo, SqliteBackup, SqliteHistory};` | live (root) |

The cross-crate paths are all clean re-exports today.

## Threat-level SQLite (the live root case)

`src/waf/threat_level/persistence/sqlite.rs` (754 lines) is the only
real `rusqlite` use at root. The data it owns:

- `ThreatHistory` time-series (`src/waf/threat_level/persistence/mod.rs:146`),
  with per-minute/hour/day/week/month buckets.
- `SqliteHistory` persistent mirror (optional, gated by
  `use_sqlite_history` config flag at `src/waf/threat_level/mod.rs:33`).
- `SqliteBackup` snapshot helper using `rusqlite::backup` API.
- `BackupInfo` metadata struct.

This is a clean candidate to move to `synvoid-waf`:

- It only depends on `crate::waf::threat_level::baseline::BaselineStats`
  and `rusqlite` + `serde` + `std::fs`. No orchestration deps.
- It does not depend on HTTP, IPC, or supervisor state.
- It is only constructed inside `src/waf/threat_level/` plumbing and
  re-exported as part of the `synvoid-waf` API.

However, the plan rules say: "Do not move WafCore into synvoid-waf." This
is not WafCore, but it is in the same `src/waf/threat_level/` area, which
is a deliberately root-owned layer. Moving it would either need a sibling
crate (e.g. `synvoid-threat-level`) or relaxing the non-goal. No new
crates in this pass.

The threat-level SQLite path is not on a hot edit path. `git log` was not
run as part of this audit, but the file is stable infrastructure code
with no recent churn signal in the inventory.

## Block store is a different beast

`synvoid-block-store` is **not** a rusqlite store. It uses `serde_json` to
serialize a `Vec<BlockEntry>` to `blocks.json` on a periodic timer
(`crates/synvoid-block-store/src/lib.rs:78-217`). The `Cargo.toml:5`
description is "Persistent IP block store with LRU eviction and disk
persistence" — explicit that it is JSON-based, not sqlite.

This means the candidate list in the plan ("synvoid-block-store,
synvoid-waf, synvoid-metrics, synvoid-admin, root-only for now") is a bit
misleading for the block-store crate. It already owns its own persistence
and is not the right target for the rusqlite audit.

## Conclusion

- 3 of 4 live `rusqlite` owners (`synvoid-dns`, `synvoid-honeypot`,
  `synvoid-mesh`) are correctly owning their own data and their own dep.
- 1 of 4 live `rusqlite` owners is at root: `src/waf/threat_level/persistence/sqlite.rs`.
  This is a real, not-dead, ~750-line module.
- The root `Cargo.toml:160` `rusqlite` direct dep is also (invisibly)
  serving 3 dead root files (`src/dns/store.rs`, `src/dns/trust_anchor.rs`,
  `src/honeypot_port/storage.rs`) that are no longer compiled.
- After deleting the 3 dead files, the root direct dep would still be
  needed for the live `src/waf/threat_level/persistence/sqlite.rs`.
- That module is a clean candidate to move to `synvoid-waf` (or a new
  `synvoid-threat-level` crate), but no measurement shows it is a hot
  rebuild path. Default: do not move in this pass.
- The dead-file deletion is a small prerequisite task that does not
  require plan-level authorization; it is a mechanical cleanup.

## Side notes for MDM-R02

- The dead `src/dns/store.rs`, `src/dns/trust_anchor.rs`,
  `src/honeypot_port/storage.rs` files can be deleted in a tiny batch.
  They are not on any non-dead import path. The compiled effect is zero.
- After that deletion, the root `rusqlite` dep is still needed for
  `src/waf/threat_level/persistence/sqlite.rs`. Without moving that file,
  the direct dep must stay.
- The `cargo check --workspace --all-targets` evidence (acceptance for
  this audit) will not change.

## MDM-S03 Decision

| Subsystem | Decision | Reason |
|---|---|---|
| DNS trust-anchor sqlite (`synvoid-dns/src/trust_anchor.rs`) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-dns`) | Already correctly owned. The root re-export shim is clean. No measured hot path. |
| DNS zone persistent store (`synvoid-dns/src/store.rs`) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-dns`) | Same as above. |
| Honeypot storage (`synvoid-honeypot/src/storage.rs`) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-honeypot`) | Already correctly owned. The root re-export shim is clean. |
| Mesh DHT record store (`synvoid-mesh/src/mesh/dht/record_store_disk.rs`) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-mesh`) | DHT persistence is a mesh-internal concern. The plan says "do not split Raft from mesh" and the DHT record store is a peer of the Raft state machine in the same crate. |
| Mesh Raft state machine (`synvoid-mesh/src/mesh/raft/state_machine.rs`) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-mesh`) | Plan non-goal: "Do not split Raft from mesh." |
| Mesh edge replica (`synvoid-mesh/src/mesh/raft/edge_replica.rs`) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-mesh`) | Same as above. |
| Threat-level SQLite history (`src/waf/threat_level/persistence/sqlite.rs`, ~750 lines) | `DEFER_LOW_VALUE` (do not move in this pass) | Clean candidate to move to `synvoid-waf` or a new `synvoid-threat-level` crate, but no measurement shows it is on a hot rebuild path. The plan rules forbid moving WafCore into `synvoid-waf`; this is adjacent to WafCore and shares the same cautious policy. The file is stable infrastructure code. **No new crates in this pass.** |
| `synvoid-block-store` (IP block store, JSON-based, not sqlite) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-block-store`) | Already correctly owned and uses JSON, not rusqlite. Not part of the rusqlite extraction question. |
| Dead `src/dns/store.rs`, `src/dns/trust_anchor.rs`, `src/honeypot_port/storage.rs` (3 files, not compiled) | `EXTRACT_LATER_CLEAN_BOUNDARY` (i.e. delete them) | Belongs in MDM-R02 as a 1–5 dep cleanup batch. Removing them does not change the live dep graph (no `pub mod` declaration references them). |
| Root `rusqlite` direct dep (`Cargo.toml:160`) | `DEFER_LOW_VALUE` (leave in root) | Cannot be removed without also moving `src/waf/threat_level/persistence/sqlite.rs` (the one live root consumer). Movement is deferred; dep stays. The 3 dead files would let a partial removal of dead `use rusqlite::*` references from root, but the live `sqlite.rs` still needs the dep, so no net change. |

**Overall MDM-S03 verdict:** `KEEP_ROOT_ORCHESTRATION` for all 7 of the
leaf-crate-owned sqlite modules. `DEFER_LOW_VALUE` for the threat-level
SQLite movement (clean boundary, not measured hot). `EXTRACT_LATER_CLEAN_BOUNDARY`
for the 3 dead root files. **No extraction in this audit pass.**

The plan's "synvoid-block-store" candidate for the persistence audit is
**not** the right target for rusqlite — it is JSON-based. The audit
correctly identifies that the right targets for the live root
`src/waf/threat_level/persistence/sqlite.rs` code would be
`synvoid-waf` (no new crate) or a hypothetical `synvoid-threat-level`
crate, but neither is justified without measurements showing hot rebuild
cost.
