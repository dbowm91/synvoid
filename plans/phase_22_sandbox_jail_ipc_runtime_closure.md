# Phase 22 Plan: Sandbox Jail IPC and Runtime Closure

Status: detailed handoff plan.

Roadmap position: Track 3, Phase 22 of `plans/roadmap.md`.

Primary goal: turn the existing fail-closed WASM/YARA jail process entry points into an operational, bounded, supervised out-of-process execution boundary without weakening the in-process plugin/runtime security model.

## Context

`src/sandbox/mod.rs` currently exposes `run_wasm_jail_mode()` and `run_yara_jail_mode()`. Both apply `ProcessSandbox::with_paths(SandboxLevel::Strict, ...)`, then log that jail IPC is not implemented and exit with status 1. The architecture documentation accurately describes these as jail-process stubs.

This is good fail-closed behavior, but the process-isolation defense is not currently usable. This phase completes the narrow IPC/execution path and integrates it only after adversarial tests prove bounded behavior.

## Security model

The parent/root process remains authoritative for:

- deciding whether a workload may execute
- validating plugin/rule identity and trust policy
- setting execution deadlines and size limits
- creating and supervising jail processes
- terminating/restarting unhealthy jails
- deciding fail-open vs fail-closed behavior; security-sensitive execution defaults fail closed

The jail process must receive only the minimum capability required to execute the workload. It must not gain general access to application configuration, admin authority, mesh credentials, block-store mutation, arbitrary networking, or unrestricted filesystem state.

## Constraints

- Reuse `synvoid-ipc`/platform primitives where they fit instead of creating an unrelated IPC stack.
- Do not pass secrets or raw plugin/rule payloads in command-line arguments.
- Establish the IPC transport before applying restrictions if the sandbox would otherwise prevent creation/binding; prefer inherited descriptors/handles or an already-created local endpoint.
- Every message is length-bounded and versioned.
- No unbounded queues, payload buffers, output buffers, or execution time.
- Parent crash/EOF must terminate or render the child inert.
- Child crash/protocol violation must not crash the parent.
- Unsupported platforms/configurations remain explicit and fail closed rather than silently reverting to unisolated execution when process isolation was required.
- Preserve existing plugin signature/capability policy from Track 2.

## Phase A: Specify the jail protocol

Create `architecture/sandbox_jail_protocol.md` before implementation.

Define a minimal framed protocol with:

- protocol magic/version
- request ID
- operation kind
- bounded payload length
- optional deadline/budget metadata supplied by parent
- typed success/error response
- response length bound

Prefer a binary/data-only protocol already supported by repository serialization primitives. Do not use ad-hoc newline-delimited JSON for untrusted binary payloads unless there is a strong compatibility reason.

The protocol must reject:

- unknown versions/operations
- frames above configured maximum
- truncated frames
- duplicate/invalid request IDs where ordering requires uniqueness
- malformed serialization
- responses after deadline/cancellation where applicable

## Phase B: Define narrow WASM operations

Do not expose a generic remote shell/runtime API. Define only operations required by SynVoid.

Preferred persistent-jail model:

- load/prepare a module identified by a content digest and validated metadata
- invoke a known plugin operation with bounded input
- unload/evict a module
- health/ping/shutdown control messages

The parent must perform trust/signature/manifest/capability validation before asking the jail to load a module. The jail may independently verify the content digest and enforce runtime limits, but it must not become the authority for whether a plugin is trusted.

Return bounded structured output and typed runtime/trap/timeout errors. Never allow plugin output to request arbitrary parent-side capability execution through this protocol unless such a capability has a separately reviewed narrow message type.

## Phase C: Define narrow YARA operations

Provide only the operations required for rule evaluation, for example:

- load/compile a validated rule set identified by digest
- scan a bounded byte buffer using a loaded rule set
- unload/evict rules
- health/ping/shutdown

Rule compilation/evaluation errors must be typed and must not terminate the jail process unless the runtime itself is corrupted/unrecoverable.

If YARA implementation ownership lives outside the root, put protocol DTOs/worker logic in the lowest appropriate existing crate and keep root process launch/composition in `src/sandbox`.

## Phase D: Parent-created IPC transport

Implement a cross-platform transport using existing platform/IPC abstractions.

Preferred Unix design:

1. parent creates a socketpair or private Unix-domain endpoint with owner-only permissions;
2. parent spawns the jail with only the required endpoint descriptor inherited;
3. child validates endpoint identity/state;
4. child applies strict sandbox restrictions;
5. child enters the framed request loop.

Preferred Windows design:

- use an appropriately ACL-restricted named pipe or inherited handle through the existing platform abstraction;
- restrict handle inheritance to the intended IPC handle only;
- apply available job/process restrictions before servicing requests.

Do not make the child bind a world-visible path after sandboxing.

## Phase E: Authentication and peer identity

Local inherited IPC should derive trust primarily from process/handle ownership, but add a startup handshake/non-reusable random nonce if the chosen transport can be independently connected to by another local process.

Requirements:

- nonce generated by OS CSPRNG
- nonce not exposed via ordinary logs or process arguments
- constant-time comparison when secret comparison is required
- handshake state expires after successful establishment

For socketpair/inherited-handle designs with no connectable namespace, do not add redundant token machinery solely for ceremony; document why peer identity is guaranteed by inheritance.

## Phase F: Resource limits and supervision

Parent and child must both enforce limits.

At minimum specify/configure:

- maximum frame/input/output size
- maximum loaded module/rule count
- maximum aggregate cached bytes
- invocation timeout/deadline
- WASM fuel/epoch/memory/table/instance limits already provided by runtime
- YARA scan/input limits
- jail idle timeout if useful
- restart/backoff policy after crash
- maximum restart rate to avoid fork/restart storms

Integrate jail processes with existing supervisor/task/process ownership rather than spawning detached unmanaged children.

Shutdown order must be deterministic:

1. stop accepting new jail requests
2. drain/cancel bounded in-flight work
3. send shutdown when possible
4. terminate child after grace deadline
5. reap process/handles

## Phase G: Integrate call sites behind explicit policy

Do not redirect all plugin/YARA calls to the jail in one change.

Add a policy/config mode with explicit semantics, for example:

- in-process runtime allowed
- process isolation preferred with documented fallback, only where safe
- process isolation required (fail closed if jail unavailable)

For untrusted/sandbox-required workloads, default to fail closed when required isolation cannot be established.

Migrate call sites incrementally with tests comparing results between in-process and jail execution for deterministic fixtures.

## Phase H: Failure semantics

Specify typed parent-side errors for:

- jail unavailable/not started
- handshake failure
- protocol violation
- oversized request/response
- timeout
- child exited/trapped
- serialization/framing failure
- resource limit exceeded
- unsupported platform/mode

A protocol violation or malformed response should quarantine/restart that jail instance rather than continuing on a desynchronized stream.

Never treat an empty/malformed response as successful plugin/YARA execution.

## Phase I: Observability

Add bounded metrics/logs for:

- jail starts/restarts/exits by kind and reason
- active/ready state
- invocation count and failures by bounded error category
- timeout/resource-limit events
- queue depth if a bounded queue exists
- invocation latency histogram

Do not label metrics with module names, rule text, paths, digests, or other unbounded values.

## Phase J: Tests

Add deterministic tests for:

- successful WASM round trip
- successful YARA round trip
- child receives only expected request frames
- oversized/truncated/malformed frames are rejected
- unknown protocol version/operation is rejected
- request deadline terminates/returns timeout
- child crash is isolated and restart policy is bounded
- parent EOF causes child exit
- child cannot connect to arbitrary network endpoints where strict sandbox forbids it
- child cannot open non-allowlisted filesystem paths
- required-isolation mode fails closed when launch/setup fails
- no fallback to in-process execution occurs in required mode
- graceful shutdown/reaping leaves no jail process behind

Where OS sandbox tests are platform-specific, feature/cfg-gate them explicitly and document coverage rather than pretending they ran everywhere.

## Documentation and CLI surface

Update:

- `architecture/process_lifecycle.md`
- `architecture/plugin_runtime_sandbox.md`
- `architecture/overview.md`
- `architecture/final_surface_audit.md`
- CLI help for `--wasm-jail` / `--yara-jail` if these flags are user-visible
- `architecture/runtime_operations_drill.md`

The docs must stop describing jail mode as a stub only after runtime round-trip evidence exists.

## Acceptance criteria

Phase 22 is complete when:

- WASM and YARA jail entry points enter a real bounded request loop rather than unconditionally exiting
- transport setup and sandbox ordering do not require broad post-sandbox filesystem/network access
- protocol is versioned, length-bounded, typed, and adversarially tested
- required-isolation mode never silently falls back to unisolated execution
- jail processes are supervisor-owned, restart-bounded, drainable, and reaped
- plugin trust/capability validation remains authoritative outside the jail and is not weakened
- WASM/YARA execution deadlines and memory/input/output bounds are enforced
- malformed child behavior cannot crash or desynchronize the parent indefinitely
- platform-specific support/limitations are explicit
- architecture docs and runtime drill reflect operational behavior

## Rejection criteria

Reject an implementation that:

- exposes a generic command execution RPC
- sends secrets through argv or logs
- creates a connectable local socket with permissive filesystem permissions
- accepts unbounded frame lengths or output
- falls back silently to in-process execution when isolation is required
- leaves jail children detached from supervisor/shutdown ownership
- lets the jail process decide plugin trust/signature policy independently of the parent
- marks the feature complete with only a ping test and no real WASM/YARA workload round trip

## Verification

At minimum run:

```bash
cargo fmt --all -- --check
cargo check
cargo test -p synvoid-ipc
cargo test -p synvoid-plugin-runtime
cargo test --test supervisor_spawn_guard
cargo test --test plugin_capability_guard
```

Run the new jail protocol/process integration tests on every locally supported target. Add only focused CI coverage that fits the repository's simplified CI policy; do not create a large OS matrix solely for this phase.
