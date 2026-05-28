# Review Conflicts

**Generated:** 2026-05-28

Cross-module conflict analysis from all 14 `*_review_plan.md` files.

## Conflicts Requiring Resolution

### 1. MeshNodeRole: Enum vs Bitmask Struct

- **Modules disagreeing:** `config_review_plan.md` (config.md:200) vs `mesh_review_plan.md` (mesh.md)
- **config.md:** Documents `MeshNodeRole` as an `enum` with variants `GLOBAL`, `EDGE`, `ORIGIN` (line 200)
- **mesh.md:** Documents `MeshNodeRole` as a bitmask struct with associated constants: `GLOBAL(0b010)`, `EDGE(0b001)`, `ORIGIN(0b100)`, `GLOBAL_EDGE(0b011)`, `GLOBAL_ORIGIN(0b110)`, `EDGE_ORIGIN(0b101)`, `ALL(0b111)`, `SERVERLESS_ORIGIN(0b1000)`
- **Actual:** Bitmask struct with associated constants at `mesh.rs:223` (confirmed by both modules)
- **Resolution:** config.md is wrong. Update to match mesh.md's bitmask documentation. The type is `struct(u8)` with associated constants — cannot use `match` on it, must use `contains()` or `is_global()`.

### 2. DrainStatus/WorkerDrainState: Two Incomplete Snapshots

- **Modules disagreeing:** `process_infra_review_plan.md` identifies the same incompleteness flagged in both `drain.md:18-33` and `supervisor.md:207-238`
- **drain.md:** Documents `DrainStatus` and `WorkerDrainState` with fewer fields
- **supervisor.md:** Documents the same structs with different (but still incomplete) field sets
- **Actual:** Both docs are incomplete snapshots. `DrainStatus` needs: `is_draining`, `connections_drained`, `drain_start`, `drain_elapsed_secs`, `drain_remaining_secs`, `drain_complete`. `WorkerDrainState` needs: `active_connections`, `idle_connections`, `connections_drained`, `drain_start`
- **Resolution:** Both documents must be updated to the full struct definitions. They don't conflict with each other — they're both incomplete. A single canonical source should be chosen (recommend `drain.md`) and `supervisor.md` should cross-reference it.

### 3. Buffer Pool Tier Count: 3 vs 4

- **Modules disagreeing:** `process_infra_review_plan.md` (worker_architecture.md:23-24 says 3) vs `networking_review_plan.md` (networking_deep_dive.md says 4)
- **worker_architecture.md:** "Three tiers: small (4KB), medium (32KB), large (128KB)"
- **networking_deep_dive.md:** Correctly identifies 4 tiers (small/medium/large/jumbo)
- **Actual:** 4 tiers at `crates/synvoid-utils/src/buffer/pool.rs:200-208`: small, medium, large, jumbo (256KB)
- **Resolution:** worker_architecture.md is wrong. Update to 4 tiers with correct sizes.

### 4. SiteConnectionLimiter: Removed Code Still Referenced (3 files)

- **Modules disagreeing:** `waf_security_review_plan.md`, `networking_review_plan.md`, and AGENTS.md all agree it was removed, but architecture docs still reference it
- **Files still referencing removed struct:**
  - `waf.md:180` — described as "Per-site wrapper with site-specific limits"
  - `waf_deep_dive.md:24` — claims "struct exists but is not instantiated as a separate entity"
  - `networking_deep_dive.md:82` — references `limiter.rs:306-346` (file is only 304 lines)
- **Actual:** `SiteConnectionLimiter` struct was removed 2026-05-27. Per-site limiting lives inside `ConnectionLimiter` directly via `DashMap`.
- **Resolution:** Delete all three references. Already fixed in code (AGENTS.md confirms), but architecture docs are stale.

### 5. filter.md Security-Critical: Allow/Deny Priority Reversed

- **Modules disagreeing:** `utilities_review_plan.md` (filter.md) contradicts the actual code
- **filter.md:** "Allow/Deny Priority: Allowlist checked first, then denylist"
- **Actual code:** Denylist is checked first (`:74-84`), then allowlist (`:86-96`)
- **Impact:** Security-relevant documentation error. Deny-first is correct for security filtering.
- **Resolution:** Fix filter.md to match actual deny-first behavior. This is a security-critical doc error.

### 6. Buffer Pool Sizes: Wrong Across Documents

- **worker_architecture.md:** small (4KB), medium (32KB), large (128KB) — 3 tiers, wrong sizes
- **waf_deep_dive.md:164:** Small 4KB, Medium 64KB, Large 256KB, Jumbo 256KB+ — 4 tiers, partially correct sizes
- **Actual:** 4 tiers at `crates/synvoid-utils/src/buffer/pool.rs:23-27`
- **Resolution:** Reconcile both documents to the actual tier definitions.

### 7. Overseer/Master Naming Inconsistency in IPC Messages

- **Modules disagreeing:** `process_infra_review_plan.md` identifies naming inconsistency within the same Message enum
- **ipc_process.md:** Documents `OverseerUpgradePrepare`, `OverseerUpgradePrepareAck`, `OverseerUpgradeCommit` variants
- **Actual code:** Message enum uses `Supervisor*` prefix for upgrade/drain variants (`SupervisorUpgradePrepare`, `SupervisorDrainWorkers`, etc.)
- **However:** Legacy `Master*` variants still exist in the enum (`MasterShutdown`, `MasterConfigReload`, `MasterHealthCheck`, etc.)
- **Resolution:** This is a real code inconsistency, not just a doc issue. The `Master*` variants should be renamed to `Supervisor*` in a coordinated breaking change.

### 8. admin_deep_dive.md Middleware Order vs Actual

- **Modules disagreeing:** `admin_observability_review_plan.md` documents conflicting middleware order
- **admin_deep_dive.md line 154-159:** `Request → Client IP → Auth → CSRF → Rate Limit`
- **Actual code (mod.rs:807-819):** `Request → Rate Limit (outer) → YARA Rate Limit → CSRF → Auth → Client IP (inner)`
- **Impact:** CSRF is before Auth (doc says Auth before CSRF). YARA rate limit layer omitted entirely.
- **Resolution:** Update documentation to match actual middleware stack.

### 9. supports_seatbelt() Method: Exists in Docs, Not in Code

- **Modules disagreeing:** `process_infra_review_plan.md` flags both `platform.md:43` and `platform_deep_dive.md:69`
- **platform.md:** Lists `supports_seatbelt()` in capability queries
- **platform_deep_dive.md:** Claims "Seatbelt sandboxing is not yet fully implemented"
- **Actual:** `supports_seatbelt()` method does not exist on `Platform` enum. macOS sandboxing IS implemented but feature-gated via `#[cfg(feature = "macos-sandbox")]`.
- **Resolution:** Remove `supports_seatbelt()` from docs. Replace with feature-gate documentation.

### 10. request_body_size Double Assignment: Fixed Claim vs Actual Code

- **Modules disagreeing:** `http_server_review_plan.md` vs AGENTS.md
- **AGENTS.md:** Claims "request_body_size double assignment" is FIXED (2026-05-27)
- **http_server_review_plan.md:** Reports the double assignment pattern still exists at `server.rs:1533/1561` and `server.rs:1633`
- **Resolution:** Verify whether the fix was incomplete or the AGENTS.md entry is stale. The double assignment may be intentional (WAF body size vs content-length header recording).

### 11. TunnelBackend Location: Two Different Claims

- **Modules disagreeing:** `tls_crypto_review_plan.md` (layer_3_5_deep_dive.md:134) vs actual code
- **layer_3_5_deep_dive.md:** Claims `TunnelBackend` is at `src/tunnel/upstream.rs`
- **Actual:** `TunnelBackend` enum is at `src/tunnel/router.rs:200`. The `upstream.rs` file header explicitly documents the struct was removed from there.
- **Resolution:** Update layer_3_5_deep_dive.md to point to `src/tunnel/router.rs:200`.

## Inter-Module Dependencies

### 1. DrainStatus/WorkerDrainState → drain.md + supervisor.md

Both `drain.md` and `supervisor.md` document the same structs. Any fix to one must be coordinated with the other. Recommend making `drain.md` the canonical source and `supervisor.md` cross-references it.

### 2. SiteConnectionLimiter Removal → waf.md + waf_deep_dive.md + networking_deep_dive.md

All three docs reference the same removed struct. The fix is atomic: remove all three references. Already fixed in code (AGENTS.md 2026-05-27). The architecture docs are the remaining debt.

### 3. Overseer/Master → process_lifecycle.md + supervisor.md + platform_deep_dive.md + ipc_process.md

All four documents reference `src/overseer/`, `src/master/`, or `src/startup/master.rs` which no longer exist. The fix must update all four documents simultaneously. The `Master*` IPC message variants also need a coordinated rename.

### 4. MeshNodeRole → config.md + mesh.md

The type is defined in `mesh.rs` but documented in both `config.md` and `mesh.md`. The fix must update `config.md` to match `mesh.md` (which already has the correct bitmask documentation).

### 5. Buffer Pool Tiers → worker_architecture.md + networking_deep_dive.md + waf_deep_dive.md

Three documents reference buffer pool tiers with different counts and sizes. All must be reconciled to the actual 4-tier definition.

### 6. filter.md Allow/Deny Priority → Security Module Dependencies

The reversed priority documentation in `filter.md` could mislead developers implementing WAF rules or ICMP filter policies. The `waf_security_review_plan.md` documents deny-first behavior as correct. Any security-related module that references filter.md behavior will get wrong information.

### 7. ListenerConfigBase → networking_review_plan.md (Dead Code)

`listener.md` documents `ListenerConfigBase` as used by HTTP Server, HTTP/3, ICMP Filter, and Platform modules. The networking review found it is **never instantiated or imported** by any module. TCP/UDP listeners define their own types. This is dead code that should be removed, but it means listener.md's integration points section is entirely wrong.

### 8. admin_deep_dive.md Middleware Order → All Admin Handlers

Any developer extending the admin middleware stack will use the documented order (Auth before CSRF). The actual order (CSRF before Auth) means CSRF tokens are validated before authentication — a different security model. This affects `auth.md`, `admin_deep_dive.md`, and any future admin handler development.

### 9. proxy.md vs proxy_deep_dive.md → Document Consolidation

`proxy_routing_review_plan.md` recommends removing duplicate struct listings from `proxy.md` since `proxy_deep_dive.md` has partially corrected them. However, `proxy_deep_dive.md` also has errors (line numbers, field names). Both need fixing before consolidation.

### 10. pqa-mesh Feature Flag → networking_review_plan.md + overview_review_plan.md

`networking_review_plan.md` found `pqc-mesh` feature flag is defined in `Cargo.toml` but has zero `#[cfg(feature = "pqc-mesh")]` usages — it's a dead flag. `overview_review_plan.md` lists it as an existing feature. Any module relying on this flag for conditional compilation will find it has no effect.

## AGENTS.md Stale Entries

These AGENTS.md entries were flagged as stale or potentially incorrect by multiple modules:

### 1. SiteConnectionLimiter Dead Code (3 modules agree)

- **AGENTS.md entry:** "SiteConnectionLimiter dead code — ✅ FIXED 2026-05-27 - removed dead code"
- **Modules flagging:** waf_security_review_plan.md, networking_review_plan.md, process_infra_review_plan.md
- **Issue:** AGENTS.md correctly says it's fixed, but architecture docs (`waf.md:180`, `waf_deep_dive.md:24`, `networking_deep_dive.md:82`) still reference the removed struct. The AGENTS.md entry is accurate but the architecture docs are stale.

### 2. request_body_size Double Assignment (2 modules disagree on status)

- **AGENTS.md entry:** "request_body_size double assignment — ✅ FIXED 2026-05-27 - removed duplicate assignment"
- **Modules flagging:** http_server_review_plan.md reports the double assignment pattern still exists at lines 1533/1561 and 1633
- **Issue:** Either the fix was incomplete, or the AGENTS.md entry is stale. Needs verification.

### 3. Overseer/Master References (4 modules agree they're stale)

- **AGENTS.md entry:** "Supervisor manages lifecycle, consolidates Supervisor" — awkward wording
- **Modules flagging:** process_infra_review_plan.md, overview_review_plan.md, tls_crypto_review_plan.md, config_review_plan.md
- **Issue:** AGENTS.md should say "consolidates Overseer + Master" not "consolidates Supervisor". Also, AGENTS.md's Known File Path Corrections table doesn't include `src/overseer/` or `src/master/` removals.

### 4. DrainManager Location (2 modules agree)

- **AGENTS.md entry:** "PL-5 DrainManager ported to Supervisor — ✅ FIXED"
- **Modules flagging:** process_infra_review_plan.md (supervisor.md:157 references `overseer/drain_manager.rs` instead of `src/supervisor/drain_manager.rs`)
- **Issue:** AGENTS.md is correct, but the architecture doc still references the old location.

### 5. buffer pool tier count (2 modules agree)

- **AGENTS.md entry:** "BufferPool: 4 tiers (small/medium/large/jumbo)" — correct
- **Modules flagging:** process_infra_review_plan.md (worker_architecture.md says 3 tiers), networking_review_plan.md (networking_deep_dive.md says 4 tiers)
- **Issue:** AGENTS.md is correct but worker_architecture.md contradicts it.

### 6. Platform supports_seatbelt() (2 modules agree)

- **AGENTS.md entry:** "macOS sandbox feature gate exists (`Cargo.toml:38` — just needs enabling)"
- **Modules flagging:** process_infra_review_plan.md (platform.md:43 lists `supports_seatbelt()` which doesn't exist)
- **Issue:** AGENTS.md is accurate about the feature gate, but platform.md documents a method that doesn't exist.

### 7. DNS-2/_max_wait_ms (2 modules agree it's stale)

- **AGENTS.md entry:** "DNS-QUERY: QueryCoalescer max_wait_ms — Async redesign with tokio::timeout" — marked FIXED
- **Modules flagging:** dns_review_plan.md (dns.md:790 and dns_deep_dive.md:70 still reference the stale `_max_wait_ms` issue)
- **Issue:** AGENTS.md is correct that it's fixed, but both DNS architecture docs still reference the stale issue.

### 8. PooledInstance DHT Prefix Leak (2 modules agree it's stale)

- **AGENTS.md entry:** "PooledInstance DHT prefix leak — ✅ FIXED 2026-05-27"
- **Modules flagging:** wasm_plugin_review_plan.md (plugin_deep_dive.md:108 still claims the fields are NOT reset)
- **Issue:** AGENTS.md is correct, but plugin_deep_dive.md was written before the fix and still claims the bug exists.

## Summary Statistics

| Category | Count |
|----------|-------|
| Conflicts Requiring Resolution | 11 |
| Inter-Module Dependencies | 10 |
| AGENTS.md Stale Entries | 8 |
| **Total Cross-Module Issues** | **29** |
| Modules Involved | 14 |
| Security-Critical Conflicts | 2 (filter.md priority reversal, middleware order inversion) |
