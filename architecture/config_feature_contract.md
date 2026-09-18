# Config Feature Contract (Phase 41)

Binding contract for fail-closed configuration: operator configuration must
not request a capability the compiled binary silently ignores, and
process-count configuration must not feed unbounded derived capacities.

## 1. Capability matrix

Every `#[cfg(feature = ...)]` field in `synvoid-config` mapped to its TOML
key path, root feature, and disposition. Derived from actual Serde paths,
not filenames.

| Struct | Field | TOML path | Feature | Disposition |
|--------|-------|-----------|---------|-------------|
| `MainConfig` | `dns: DnsConfig` | `[dns]` | `dns` | capability-bearing / reject-when-absent |
| `MainConfig` | `mesh: Option<MeshConfig>` | `[mesh]` | `mesh` | capability-bearing / reject-when-absent |
| `TunnelConfig` | `mesh: Option<MeshConfig>` | `[tunnel.mesh]` | `mesh` | capability-bearing / reject-when-absent |
| `MainConfig` | `icmp_filter: IcmpFilterConfig` | `[icmp_filter]` | `icmp-filter` | capability-bearing / reject-when-absent |

### Compile-only implementation details (no preflight)

- `MeshConfig::load_node_identity()` (`#[cfg(feature = "mesh")]`): key
  derivation implementation, not a TOML key.
- `GlobalNodeConfig::load_keys()` Ed25519 branch
  (`#[cfg(feature = "mesh")]`): crypto implementation, not a TOML key.
- `TunnelConfig::has_mesh()` / `is_global_node()`
  (`#[cfg(feature = "mesh")]`): accessors, not TOML keys.
- `lib.rs` gated re-exports (`#[cfg(feature = "dns")] pub use dns::{...}`):
  type visibility only; the TOML surface is the owning field above.

### Compatibility fields

None. All capability-bearing sections are reject-when-absent, including
inert tables with only `enabled = false`. Rationale: the binary did not
understand the section, and accepting it would let operators believe
otherwise.

## 2. Preflight

`MainConfig::from_toml_str()` is the canonical parse/validation seam
(shared with fuzzing):

1. parse raw TOML (`toml::Value`, no FS/network side effects);
2. `validate_config_capability_presence(raw, CompiledCapabilities::current())`;
3. typed `MainConfig` deserialization;
4. `MainConfig::validate()`.

`CompiledCapabilities { dns, mesh, icmp_filter }` records
`cfg!(feature = ...)` for the current binary. The preflight rejects any
present capability table when its feature is absent, with exact config
paths:

```text
dns: configuration is present but this binary was built without the 'dns' feature
mesh: configuration is present but this binary was built without the 'mesh' feature
tunnel.mesh: configuration is present but this binary was built without the 'mesh' feature
icmp_filter: configuration is present but this binary was built without the 'icmp-filter' feature
```

Migration: rebuild with the named `--features ...` or remove the
unsupported section. Config editors and the admin API must preserve or
reject explicitly — never silently strip sections on write-back.

Unknown keys outside capability-owned sections retain Serde's default
(ignore) behavior; this phase deliberately does not add global
`deny_unknown_fields`.

## 3. Process / supervisor validation

`MainConfig::validate()` invokes:

- `ProcessManagerConfig::validate()`
- `SupervisorConfig::validate()` (both `supervisor` and `supervisor_compat`)
- `TunnelConfig::validate()` → `tunnel.mesh` supervision (mesh builds)
- top-level `mesh` supervision (mesh builds)
- `DnsConfig::validate()` when `dns.enabled` (dns builds)
- `IcmpFilterConfig::validate()` when `icmp_filter.enabled` (icmp-filter builds)

Pool relationship (from `synvoid-ipc` consumers):

- `min_workers` / `max_workers` / `pre_spawn_workers` /
  `warm_workers_target` govern the legacy worker pool (`spawn_worker`,
  `ensure_warm_workers`: `pre_spawn.max(min)` feeds `spawn_worker`).
- `unified_server_workers` governs the independent `UnifiedServerWorker`
  data-plane pool (`spawn_unified_server_workers`). No
  `unified_server_workers <= max_workers` invariant is enforced.

Bounds:

- `min_workers`, `max_workers`: `1..=1024`, `min <= max`.
- `unified_server_workers`: `1..=256` (process/IPC/shm bound; derived
  `(unified+10) * 2048` connection slots stay to a few MB).
- `pre_spawn_workers`, `warm_workers_target`: `<= max_workers` (owning
  capacity).
- `max_restart_attempts`: `<= 1000`.
- Second-granularity timeouts: `1..=86400`; millisecond IPC timeouts:
  `1..=3600000`.
- `restart_backoff_max_secs >= restart_cooldown_secs` (process),
  `>= restart_delay_secs` (overseer).
- `SupervisorConfig` scale thresholds in `(0, 1)` with
  `scale_down < scale_up`.
- `control_api_addr` must parse as `SocketAddr`.
- `worker_port_base + max_workers <= 65535` (legacy `base + id` port
  derivation stays in u16 range).

`OverseerConfig::validate()` exists for any future runtime consumer;
`OverseerConfig` is not part of `MainConfig` today.

Lower-level update paths (`ProcessManager::update_config`,
`SupervisorConfigBuilder::try_build`, admin `PUT /config/process-manager`
and `PUT /config/supervisor`) invoke the same validators, so the admin
mutation path cannot persist invalid process settings (400, not silent).

## 4. Checked runtime derivations

Config validation is the first barrier; runtime constructors still
validate because they are callable without TOML:

- `src/supervisor/process.rs`: `unified_server_workers.checked_add(10)`;
  overflow logs an error and skips table init instead of wrapping.
- `synvoid-upstream` `SharedConnectionTable::new` /
  `SharedRateLimitTable::new` (Phase 42: `ConnectionTableLayout` /
  `RateLimitTableLayout`): `checked_mul` / `checked_add` (plus checked
  ceil-division for dirty bits) for heartbeat/connection/counter sizes,
  `u64::try_from` before `set_len`, explicit nonzero + upper bounds +
  512 MiB mapping ceiling, release-mode alignment proofs; offset getters
  reuse the layout object with checked arithmetic and return `None` on
  overflow/misalignment. v1 magic+version headers; `open_existing`
  validates without truncating; files are 0600 under a 0700 runtime dir
  with symlink/non-regular rejection. Full contract:
  `architecture/shared_memory_atomic_contract.md`.
- `synvoid-ipc`: `worker_port_for_id(base, id)` (`checked_add`, u16
  range), `allocate_worker_id` saturates on overflow instead of wrapping,
  restart backoff uses `checked_mul`/`checked_pow` capped at
  `backoff_max`, respawn paths skip with an error on port overflow.

## 5. Mesh supervision truthfulness

Authoritative validation: `MeshSupervisionConfig::validate()`
(`crates/synvoid-config/src/mesh.rs`). Mesh restart is not implemented:

- `restart_enabled = true` is rejected.
- While restart is disabled, any non-default `restart_limit`,
  `restart_window_secs`, `restart_backoff_initial_secs`,
  `restart_backoff_max_secs` is rejected (staged-future contract: fields
  exist for a future restart capability, but tuning them now is
  operator-misleading).

`build_mesh_supervision_policy()` surfaces the same rejection so worker
startup fails before task construction even outside TOML parsing.
`execute_mesh_restart` is not implemented in this phase (explicit
non-goal).

Stale "overridden/warned" wording (policy-build override) is superseded
by this fail-closed contract.

## 6. Tests

- `synvoid-config` feature-profile parser tests (run under the actual
  profile; dev-deps do not re-enable features):
  - minimal binary rejects `[dns]`, `[mesh]`, `[tunnel.mesh]`,
    `[icmp_filter]`;
  - dns build accepts valid DNS; mesh build accepts valid mesh and
    rejects `restart_enabled = true` + non-default restart tuning;
  - unknown keys outside capability sections remain ignored;
  - `usize::MAX` / near-overflow and zero/min/max boundaries fail
    without panic.
- `tests/config_capability_preflight_guard.rs`: new
  `#[cfg(feature)]` fields in `synvoid-config` must appear in the
  preflight + this matrix.
