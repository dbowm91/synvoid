# Sandbox Jail IPC Protocol (Phase 22, Phase 26 YARA boundary, Phase 29 package split)

Status: operational. WASM and YARA jail children run as dedicated binaries
(`synvoid-wasm-jail`, `synvoid-yara-jail` from `synvoid-jail-runtime`, Phase 29)
with legacy `synvoid --wasm-jail` / `--yara-jail` forwarding shims retained for
compat. All serve a real bounded request loop over a parent-created stdio
transport. This document is the normative spec for the jail frame protocol,
operations, transport ordering, supervision, failure semantics, and
observability.

Canonical implementation (Phase 29):

- Protocol DTOs, framing, policy, errors, limits, metrics, parent handle,
  restart policy, child serve-loop driver, and deterministic binary resolution:
  `crates/synvoid-ipc/src/` (`jail_protocol.rs`, `jail_process.rs`,
  `jail_binary.rs` — exe-dir lookup only, no CWD/PATH/writable-dir search)
- Child execution services, sandbox-entry sequencing, and child-only
  observability: `crates/synvoid-jail-runtime/src/` (`wasm_service.rs`,
  `yara_service.rs`, `sandbox_entry.rs`, `headers.rs`; binaries in `src/bin/`)
- Parent policy/composition facades: `src/sandbox/` (`policy.rs`
  `JailClient` + `spawn_resolved`, `mod.rs` forwarding shims,
  `wasm_service.rs`/`yara_service.rs` pure re-exports)
- OS sandbox backends (Landlock, Capsicum, Pledge, Job Objects, Seatbelt):
  `crates/synvoid-platform/src/sandbox.rs` (canonical; root
  `src/platform/sandbox.rs` is a pure facade)
- YARA engine (Phase 26 canonical owner): `crates/synvoid-yara/src/`
  (`engine.rs`, `artifact.rs`, `executor.rs`). The jail service uses
  `synvoid_yara::{YaraScanner, YaraRulesSource}` directly, never
  `synvoid-upload`.
- WASM engine: `crates/synvoid-plugin-runtime/src/` consumed by the jail
  runtime (hook-only capabilities rebuilt in-jail).
- Behavioral + static-policy coverage: `tests/jail_isolation_guard.rs`
  (composition; unit coverage in `synvoid-ipc` for pure framing, golden pins
  in `crates/synvoid-ipc/tests/jail_protocol_golden.rs`, packaged-binary
  round trips in
  `crates/synvoid-jail-runtime/tests/jail_binary_integration.rs`) plus
  `tools/synvoid-repo-guards/tests/yara_execution_boundary.rs` (Phase 26
  ownership) and `tools/synvoid-repo-guards/tests/jail_runtime_boundary.rs`
  (Phase 29 package/process split).

Related: `architecture/process_lifecycle.md` (jail supervision),
`architecture/plugin_runtime_sandbox.md` (Phase 22 jail section),
`architecture/runtime_operations_drill.md` (jail drill).

## 1. Security model

The parent (supervisor or worker composition root) remains authoritative for:

- deciding whether a workload may execute
- validating plugin/rule identity and trust policy (signatures, manifests,
  capability policy) **before** asking a jail to load anything
- setting execution deadlines and size limits
- creating and supervising jail processes
- terminating/restarting unhealthy jails
- deciding fail-open vs fail-closed behavior; security-sensitive execution
  defaults fail closed

The jail process receives only the minimum capability required to execute the
workload: module/rule bytes already approved by the parent, bounded invocation
input, and runtime limits. It never receives application configuration, admin
authority, mesh credentials, block-store mutation handles, or network access.
The jail never decides plugin trust or signature policy.

## 2. Transport: parent-created stdio pipes

The IPC transport is a pair of anonymous pipes created by the parent **before**
spawn and inherited by the child as stdin (parent→child requests) and stdout
(parent←child responses). Stderr remains a log channel and is never parsed.

Why stdio pipes satisfy Phase D/E:

- **Parent-created**: pipes exist before the child starts; the child never binds,
  connects to, or names any socket or filesystem path for IPC.
- **Ordering-safe**: descriptors are inherited, so the child can apply
  `SandboxLevel::Strict` restrictions first and enter the request loop after;
  no post-sandbox filesystem or network access is required to establish IPC.
- **No connectable namespace**: anonymous pipes cannot be connected to by any
  third local process. Peer identity is guaranteed by descriptor inheritance,
  so no nonce/token handshake is added (per the Phase 22 plan, redundant token
  machinery is omitted and this paragraph documents why).
- **Crash semantics**: parent exit closes the pipes; the child observes EOF on
  stdin and exits promptly (never left running inert-but-alive). Child exit
  closes stdout; the parent observes EOF, never crashes, and applies the
  restart policy.
- **Cross-platform**: anonymous piped stdio works identically on Unix and
  Windows; no UDS path permissions or named-pipe ACLs are required.

The existing `synvoid-ipc` endpoint transport (`IpcEndpoint`/`IpcStream`) is
deliberately **not** reused for jail IPC: named endpoints have a connectable
namespace and would require post-sandbox bind/connect. Postcard framing
conventions from `ipc_framing.rs` (4-byte big-endian length prefix +
postcard payload) are reused.

No secrets or payloads travel in argv or environment. Dedicated binaries take
empty argv (binary identity implies kind); the legacy compat fallback argv is
exactly `synvoid --wasm-jail` or `synvoid --yara-jail`. The single test-only
exception is `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` (Section 8), which carries no
secret. Parent binary resolution (`synvoid_ipc::resolve_jail_binary`) uses
only the current-executable directory plus the compat fallback — never the
working directory, `PATH`, or writable plugin directories. `verify_jail_binary`
checks existence/regular-file/non-empty (+ Unix executable bit) where
practical; `ensure_dedicated_jail_binaries_available()` is the startup
preflight for jail-required deployments. `synvoid-wasm-jail --version` /
`synvoid-yara-jail --version` report the jail runtime version plus the `SVJL`
protocol version (wire compat is governed by `JAIL_PROTOCOL_VERSION`, v1).

## 3. Frame protocol (versioned, length-bounded, typed)

Every message on stdin/stdout is one frame:

```
[u32 BE total postcard length][postcard(JailRequest | JailResponse)]
```

Envelope fields:

| Field     | Type | Rule                                              |
|-----------|------|---------------------------------------------------|
| `magic`   | u32  | Must equal `JAIL_MAGIC` (`b"SVJL"`), else reject  |
| `version` | u16  | Must equal `JAIL_PROTOCOL_VERSION` (1), else reject |
| `id`      | u64  | Parent-assigned, nonzero, strictly increasing per connection |
| `op` / `result` | enum | Typed operation or typed result (Section 4) |

Rejection rules (all adversarially tested):

- unknown magic or version → typed `ProtocolViolation` response when the frame
  is still parseable, otherwise the child exits and the parent restarts it
- frame length above `JAIL_MAX_FRAME_BYTES` → reject before allocating
  (length prefix is validated prior to any payload read)
- truncated frame (EOF mid-frame) → connection error; parent restarts the jail
- duplicate or non-increasing request ID → reject (replay/reorder detection)
- malformed postcard → framing error; the stream position is unrecoverable, so
  the child exits and the parent quarantines/restarts that instance
- responses arriving after the parent-side deadline are never applied: a timed
  out call quarantines and restarts the jail rather than continuing on a
  potentially desynchronized stream

Concurrency discipline: **at most one in-flight request per jail process** (no
pipelining). The parent serializes calls with a mutex; a dedicated reader
thread demultiplexes the single outstanding response with `recv_timeout`. This
makes request-ID matching trivial and eliminates queue-depth accounting (depth
is always 0 or 1).

Size bounds (all `pub const` in `synvoid_ipc`, defined in `jail_protocol`):

| Bound | Value | Applies to |
|-------|-------|-----------|
| `JAIL_MAX_FRAME_BYTES` | 8 MiB | any single frame (covers module/rule loads) |
| `JAIL_MAX_INVOKE_INPUT_BYTES` | 1 MiB | WASM invoke input (headers+body) |
| `JAIL_MAX_INVOKE_OUTPUT_BYTES` | 1 MiB | WASM invoke output body |
| `JAIL_MAX_SCAN_INPUT_BYTES` | 4 MiB | YARA scan buffer |
| `JAIL_MAX_MODULES` | 16 | loaded WASM modules per jail |
| `JAIL_MAX_RULESETS` | 16 | loaded YARA rule sets per jail |
| `JAIL_MAX_MATCHES` | 256 | YARA matches returned per scan |
| `JAIL_MAX_ID_LEN` | 128 | module/rules IDs, header names |
| `JAIL_MAX_HEADERS` | 64 | headers per invoke |

Error message strings crossing the boundary are truncated to 512 chars and
must never contain secrets, paths, or rule text.

## 4. Narrow operations

There is no generic command-execution RPC. The operation set is closed:

WASM (`JailOperation::Wasm*`):

- `Ping` → `Pong` (handshake + health; the first Ping doubles as the
  version handshake)
- `WasmLoad { module_id, digest_sha256_hex, wasm_bytes, fuel, memory_pages,
  timeout_ms, capabilities }` — `capabilities` carries **only** the four
  request/response hook flags (`request_inspect`, `request_mutate`,
  `response_inspect`, `response_mutate`). Any other authority
  (filesystem, network, mesh, admin, persistence, metrics) cannot be expressed
  and is therefore never granted inside the jail, regardless of what the
  parent-side manifest allowed. The child recomputes SHA-256 over `wasm_bytes`
  and compares in constant time; mismatch fails the load.
- `WasmInvoke { module_id, method, uri, headers, body }` — invokes the
  `handle_request` export with bounded input; returns `{ status, headers,
  body }` (`headers` is empty in v1; reserved). Duplicate header names are
  collapsed last-wins when encoding to the guest JSON header map.
- `WasmUnload { module_id }`, `Shutdown`

YARA (`JailOperation::Yara*`):

- `YaraLoadRules { rules_id, digest_sha256_hex, rules_text }` — parent supplies
  already-validated rule text; child verifies the digest in constant time and
  compiles. Compilation errors are typed and never terminate the jail.
  (Corrective pass: mesh-side full syntax validation stays in-process in the
  supervisor AFTER trust admission — see `mesh.md` §13. The jail owns YARA
  *execution*; no validation IPC op exists by design.)
- `YaraScan { rules_id, data }` — scans a bounded buffer; returns bounded
  match DTOs (`rule_name`, `namespace`, `tags`, `category`, `severity`,
  `description`, each length-truncated, at most `JAIL_MAX_MATCHES`).
- `YaraUnload { rules_id }`, shared `Ping`/`Shutdown`

`filter_request` / `transform_response` WASM hooks are intentionally **not**
exposed in v1: the synchronous WAF-pipeline filter path needs inline
fail-closed integration that is not yet migrated (Section 7). The jail
`handle_request` path serves serverless/CPU-offload workloads today and the
operation enum is versioned for extension.

## 5. Execution containment inside the jail

WASM service (`crates/synvoid-jail-runtime/src/wasm_service.rs`):

- modules instantiate via `WasmResourceLimits` derived from the load request
  (fuel required nonzero, memory cap, per-invocation timeout, epoch deadline on,
  all-deny base capabilities plus only the requested hook flags)
- production guest-ABI policy enforced (`guest_alloc` + `guest_free` required)
- trap/fuel/timeout errors map to typed `ExecutionFailed`; a trapped module
  stays loaded (failures are per-invocation) unless the runtime is corrupted,
  in which case the child exits and the parent restarts it

YARA service (`crates/synvoid-jail-runtime/src/yara_service.rs` over `crates/synvoid-yara`):

- one `synvoid_yara::YaraScanner` per rules ID with per-scan timeout,
  single-flight scan semaphore, bounded input; compile/scan errors are typed
  and non-fatal (Phase 26: no `synvoid-upload` coupling; digest re-verified
  in-jail via `verify_content_digest` semantics)

Both services enforce the module/ruleset count caps and input/output bounds
from the `JAIL_MAX_*` consts before delegating to the underlying runtime.

## 6. Supervision and shutdown

Jail processes are supervisor-owned (`JailHandle` in `synvoid_ipc::jail_process`,
spawned via deterministic `synvoid_ipc::resolve_jail_binary` exe-dir lookup and
driven from `src/sandbox/policy.rs` `JailClient::spawn_resolved` composition):

- restart policy: bounded restarts (`max_restarts`, default 5) with exponential
  backoff (`base_backoff` 100 ms, 2× growth, `max_backoff` 5 s cap) to avoid
  fork/restart storms; exhaustion surfaces `RestartBudgetExhausted` and fails
  closed
- any protocol violation, framing error, timeout, ID mismatch, or unexpected
  child exit quarantines that instance (discard pipe state) and restarts within
  budget; the parent never continues on a desynchronized stream
- deterministic shutdown order: stop accepting new calls → fail fast queued
  callers → send `Shutdown` with a short grace deadline → `kill` on expiry →
  `wait` (reap) → join the reader thread; no jail process is left behind

## 7. Call-site policy (incremental migration)

`IsolationPolicy` (`synvoid_ipc::jail_protocol`, consumed via `JailClient` in
`src/sandbox/policy.rs`):

- `InProcess` (default) — current behavior, no jail
- `Preferred { fallback_in_process: bool }` — route to jail when healthy;
  documented fallback only where safe (YARA detection scans and fail-open
  response transforms); never for fail-closed request filtering
- `Required` — jail or fail closed; a missing/unhealthy jail, launch failure,
  or timeout is a hard error and must never silently fall back to in-process
  execution

`resolve_route(jail_ready)` is the single decision point and is unit-tested,
including "required + unavailable ⇒ FailClosed" and "no silent fallback".
Production routing defaults to `InProcess`; jail adoption per call site is an
explicit config change with before/after result-comparison tests on
deterministic fixtures (in-process vs jail output equality is asserted in
`tests/jail_isolation_guard.rs`).

## 8. Platform support and sandbox ordering

Child startup order:

1. capture stdin/stdout handles (already inherited; no I/O yet)
2. apply `ProcessSandbox::with_paths(SandboxLevel::Strict, …)`
3. enter the framed request loop

Sandbox backends are platform-selected (`crates/synvoid-platform/src/sandbox.rs`:
Landlock on Linux, Seatbelt/sandbox-exec profile on macOS where available, stub
elsewhere; root `src/platform/sandbox.rs` is a pure facade).
On platforms without a strict backend, or when restriction fails, the child
exits nonzero (fail closed) **unless** the test-only escape hatch
`SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` is set, in which case it logs an explicit
warning and serves without OS restrictions. The hatch exists so hermetic tests
can exercise the real child binary on any platform; production spawn paths
never set it (asserted by `tests/jail_isolation_guard.rs`), and the drill
documents that `Required` isolation on an unsupportable platform fails closed.

## 9. Failure semantics (parent side)

Typed `JailError` variants: `Unavailable`, `HandshakeFailed`,
`ProtocolViolation`, `Oversized`, `Timeout`, `ChildExited`, `FramingError`,
`ResourceExhausted`, `Unsupported`, `RestartBudgetExhausted`, `PolicyDenied`,
`ExecutionFailed`, `DigestMismatch`, `NotFound`. An empty or malformed response
is never treated as successful execution.

## 10. Observability

Jail metrics (in `synvoid_ipc::jail_protocol`, `jail_metrics_snapshot()`) use process-local atomic counters —
no string labels, so metric cardinality is structurally bounded (module names,
digests, paths, and rule text never appear):

- `starts`, `restarts`, `exits`, `shutdowns`
- `invocations_total`, per-`JailKind` invocations
- `failures_total` plus per-`JailErrorCode` counters (fixed enum ⇒ fixed width)
- `timeouts_total`, `oversized_rejected_total`, `protocol_violations_total`,
  `restart_budget_exhausted_total`
- invocation latency recorded via `tracing` spans plus a bounded
  last-latency-micros gauge per kind (histograms remain the job of the global
  metrics exporter reading these counters)

Child lifecycle transitions log at info level with kind + reason (bounded
vocabulary); request/response payloads are never logged.

## 11. Test mapping

| Phase 22 requirement | Coverage |
|----------------------|----------|
| WASM round trip | `jail_isolation_guard` live-child + in-memory service tests (`minimal_handler` fixture ⇒ 200) |
| YARA round trip | inline rule match/no-match via service and live child |
| child receives only expected frames | framing tests: only well-formed frames accepted; unknown ops rejected |
| oversized/truncated/malformed rejected | length-prefix, EOF-mid-frame, bad-postcard tests |
| unknown version/operation rejected | version-mismatch + unknown-variant tests |
| deadline ⇒ timeout | parent `recv_timeout` + restart test with a hung peer |
| child crash isolated, restart bounded | `RestartTracker` unit tests + fail-closed on dead child |
| parent EOF ⇒ child exit | serve-loop EOF test (returns `ConnectionClosed`, exits 0) |
| no network access where forbidden | platform-gated: strict backend denies sockets; documented per-platform matrix below |
| no non-allowlisted FS access | platform-gated allowlist open test |
| required mode fails closed | `resolve_route` + spawn-failure tests |
| no fallback in required mode | static assertion + behavioral test |
| graceful shutdown, no orphans | live-child `Shutdown` + `wait` reaping test |

Platform coverage matrix (no OS matrix in CI per repo policy; CI runs Linux):

| Check | Linux | macOS | Windows |
|-------|-------|-------|---------|
| framing/protocol/service logic | ✓ always | ✓ always | ✓ always |
| live child round trip | ✓ (Landlock or fail-closed skip) | ✓ via hatch or Seatbelt | ✓ via hatch |
| strict FS/network denial | ✓ when Landlock enforces | best-effort, documented | best-effort, documented |

Note on plan verification names: the Phase 22 plan lists
`cargo test --test supervisor_spawn_guard` and `plugin_capability_guard`;
neither exists as a root test target. Jail coverage lives in
`tests/jail_isolation_guard.rs` (spawn ownership, supervision, shutdown) plus
the existing `tests/plugin_guard.rs` (capability boundary, unchanged) — no
duplicate guard files were created for plan-name parity.
