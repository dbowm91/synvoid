# Phase 08 Plan: Main Data-Plane Sandbox

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: Phase 07 (systemd/non-root baseline).

## The finding

The jail sandbox is real: `prepare_sandbox`/Landlock/seccomp is applied in the
jail entry path, and the jail protocol/qualification tests cover it. The main
`UnifiedServerWorker` is not sandboxed. The process that parses untrusted HTTP,
runs the WAF and handles TLS has no in-process filesystem/network/syscall
confinement beyond the OS user and the systemd unit.

The shipped unit currently supplies `NoNewPrivileges`, `ProtectSystem`,
`ProtectHome` and `PrivateTmp`, but it also runs as root and has no
`CapabilityBoundingSet`, `SystemCallFilter` or address-family restriction.
Phase 07 fixes the user/capability layer; this phase adds the in-process layer.

Relevant constraints:

- `crates/synvoid-platform/src/sandbox.rs` exposes `SandboxRequest`,
  `Guarantee`, `prepare_sandbox`, `EnteredSandbox`, `ThreadScope`, and the
  Linux Landlock backend. The backend applies `restrict_self()` to the calling
  thread and descendants; `no_new_privs` is established atomically.
- `VETTED_ABI` is Landlock V1 (filesystem read/write allowlists). Network
  scoping and all-threads enforcement are not silently claimed.
- The worker spawns Tokio threads, CPU offload work, jail children, ACME/DNS
  sockets, and optionally Wasmtime JIT. A sandbox applied after the runtime
  starts will not cover already-created threads.
- Wasmtime JIT needs `mmap`/`mprotect` executable mappings. Do not use
  `MemoryDenyWriteExecute` or a seccomp filter that denies those mappings
  unless the plugin path is disabled.

## Recommended sequence

1. Phase 07: non-root service account, capabilities and systemd hardening.
2. This phase 08A: filesystem Landlock on the worker, applied before Tokio
   threads, with `required`/`auto`/`off` policy.
3. Phase 08B: seccomp/systemd syscall filtering after a measured allowlist;
   only then claim syscall isolation.
4. Keep the jail sandbox as-is; do not replace it with the worker sandbox.

## Work items

### 08.1 Configuration and policy

- Add an explicit `[security] worker_sandbox = "off" | "auto" | "required"`
  (or an equivalent typed field) with a documented default. Recommended:
  `auto` on Linux after qualification; `off` elsewhere until a backend is
  qualified.
- `required` fails startup when Landlock cannot enforce every requested
  guarantee; `auto` logs the enforcement report and continues only if the
  filesystem layer is fully enforced; `off` is explicit.
- Record the resolved mode and enforcement report in the startup log and the
  admin/doctor status. Do not claim “sandboxed” when the backend is a stub.

### 08.2 Apply the worker sandbox before the runtime

- Identify the worker-process entry (`--unified-server-worker` dispatch in
  `src/commands/`) and apply `prepare_sandbox`/`enter` **before** the Tokio
  runtime, CPU worker and jail children are spawned.
- Build the request from `PlatformPaths`/the effective config:
  - read: config dir, cert/ACME dir, rules/YARA dir, static/admin-ui assets,
    GeoIP/root hints, system CA paths, runtime read-only assets;
  - write: log dir, data dir (block store/threat history/honeypot DB),
    runtime/pid/socket dir, cache/tmp, and the config dir only if the admin
    editor is enabled and intentionally writable;
  - do not add blanket `/` or `$HOME` read access.
- Request only guarantees the worker needs. `AmbientFilesystemDenied` +
  `FilesystemReadAllowlist` + `InheritedIpcUsable` are the core. Do not require
  `NetworkDenied` (the worker is a proxy) or `ExecDenied` (it may spawn the
  CPU/jail binaries); if those are desired, run the worker in a separate
  profile and test it.
- Use `ThreadScope::CurrentThreadPlusDescendants` and verify the entry point
  runs before the runtime creates threads. If that invariant cannot be met,
  do not ship the sandbox; an after-the-fact `restrict_self()` on one thread
  is not a worker sandbox.

### 08.3 Qualification paths

Exercise every worker capability under the sandbox:

- HTTP/1, H2, H3, TLS/ACME, static files, proxy/upstream, WebSocket.
- WAF body scanning, honeypot/threat persistence, block-store writes.
- Admin listener, session/CSRF, config reload, WebSocket metrics/logs.
- DNS server, TCP/UDP pools (after Phase 02), tunnels/QUIC.
- Plugin/WASM and YARA (if enabled): the jail child path, shared memory,
  instance pool, upload scanning.
- Log rotation, pid/socket creation, graceful drain/restart.

Fail the phase if any required path cannot be expressed in the allowlist.

### 08.4 Seccomp / syscall filtering

- Start with a systemd `SystemCallFilter` profile or a conservative
  `seccompiler` allowlist; do not copy the jail's categorical filter blindly.
- Include the syscalls Tokio, rustls/aws-lc-rs, quinn, Wasmtime JIT, DNS,
  file I/O and the plugin path need. Test on the pinned kernel/architectures.
- Keep `MemoryDenyWriteExecute` off for JIT-enabled profiles; if a no-plugin
  build is shipped, a stricter profile can be a documented variant.
- A syscall filter that only passes on one architecture is not a production
  default; gate it and record the supported matrix.

### 08.5 Tests and evidence

- Add a native qualification test that starts the worker with `required` and
  exercises the capability list above.
- Add a negative test: a path outside the allowlist is denied; a missing
  `required` backend fails startup.
- Run the existing `sandbox-native-qualification` CI job and
  `jail_isolation_guard`; extend it for the worker entry.
- Record the `EnforcementReport` and `systemd-analyze security` output in the
  phase evidence.

## Non-goals

- Replacing the jail sandbox or the jail IPC protocol.
- A macOS/Windows main-process sandbox in this phase; Linux is the production
  strict-isolation target.
- Wasmtime JIT removal.
- A new sandbox crate; use `synvoid-platform`.

## Risks

- Applying Landlock after Tokio threads start leaves them unsandboxed. The
  entry-point ordering is the critical invariant.
- JIT/Wasmtime, ACME, config writes and log rotation are the likely allowlist
  breakages; qualify them before defaulting to `auto`.
- A `required` mode that fails on a missing optional path can take down a
  working deployment; keep the allowlist derived from the actual runtime
  paths, not a hand-written list.

## Exit criteria

- A Linux worker can start with `worker_sandbox = "required"`, serve the
  qualified capability list, and deny an unlisted path.
- The default mode is documented and observable; no log claims isolation when
  the backend is unavailable.
- The production recommendation is non-root + Landlock + systemd hardening,
  with seccomp either qualified or explicitly deferred.

## Completion evidence

Implemented 2026-11-11. `[security] worker_sandbox = "off" | "auto" | "required"`
was added (default `off`), with validation, examples and docs. The UnifiedServerWorker
entry applies Landlock (`CurrentThreadPlusDescendants`, filesystem read/write
allowlists, inherited IPC and descendant confinement) before the Tokio runtime
is built. `required` fails closed when the backend cannot enforce the request;
`auto` continues only for pre-application backend failures and logs every
enforcement decision. Native Linux tests prove an allowed path is readable and
an unlisted path is denied. Deferred: seccomp/syscall filtering and full
qualification of Granian/app-server children and writable `/tmp`; those are
documented as limitations, not claimed.

