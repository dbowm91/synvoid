# Phase 06 Plan: Multi-Worker Semantics and Qualification

Status: **COMPLETE** (2026-11-11).
Campaign: `plans/multi_listener_canonical_roadmap.md`.
Predecessor: Phase 02 and Phase 04.
Depends on: dynamic binding/lifecycle and working TLS/H3.

## Scope

Qualify multi-listener support beyond the default one-worker process:

- per-listener `SO_REUSEPORT` sharing across workers;
- one listener plan shared by every worker;
- HTTP/3 ownership decision;
- restart-only listener reload semantics;
- full verification and release evidence.

This is the final phase. It runs after the canonical path works for the default
single worker.

## Multi-worker current state

- `unified_server_workers` is passed as `--total-workers`; all workers receive
  the same scalar addresses (`crates/synvoid-ipc/src/manager.rs:911-934`).
- `reuse_port` is passed globally, not per listener.
- `validate_ports_or_skip_for_shared_port` skips the entire pre-bind check when
  `total_workers > 1 && reuse_port`:
  `src/worker/unified_server/state.rs:49-51,251-258`.
- The pre-bind check probes numeric ports on `127.0.0.1` over TCP only:
  `crates/synvoid-ipc/src/manager.rs:2541-2573`.
- `bind_tcp_reuse` / `bind_udp_reuse` always set `SO_REUSEPORT` on Unix:
  `crates/synvoid-platform/src/socket_bind.rs:49-95`.

## Required semantics

### Shared plan

- Every worker must receive the same normalized listener plan.
- If any worker cannot bind the full plan, it must fail readiness.
- The supervisor must not report the deployment ready while only a subset of
  workers/listeners are bound.
- Dynamic listener names must be stable across workers; worker-local suffixes
  belong in metrics/log fields, not listener identity.

### Reuse policy

- `reuse_port` becomes a property of a plan when `unified_server_workers > 1`.
- Single-worker startup keeps duplicate-address rejection, even though the
  platform helper sets `SO_REUSEPORT`.
- Multi-worker sharing must be explicit; do not use `SO_REUSEPORT` to hide
  duplicate listener definitions.
- Pre-bind checks must be address- and transport-aware. Do not skip all checks
  merely because reuse is enabled.

### HTTP/3 ownership

Choose and document one of:

1. **Single owner (recommended for this campaign):** one deterministic worker
   binds every HTTP/3 endpoint; the other workers do not. This avoids QUIC
   connection migration moving a flow to a worker that does not own it.
2. **Qualified shared QUIC:** all workers bind H3 with reuse and the design is
   proven under connection migration and worker restart.

If option 1 is chosen:

- validate `http3 = true` + `workers > 1` is supported only with the owner
  assignment, or reject it until the supervisor assignment exists;
- expose the H3 owner in admin/metrics;
- ensure worker restart does not lose the H3 endpoint without supervisor
  reassignment.

If option 2 is deferred, explicitly reject multi-worker H3 with a typed error
and document the limitation. The default one-worker deployment is unaffected.

## Reload

Listener definitions are startup state in this campaign.

- A config reload that changes listener names, addresses, ports, TLS/ALPN, or
  H3 pairing must be marked restart-required.
- Do not report “configuration reloaded” as if new sockets were applied.
- Update admin reload responses and docs to distinguish reloadable settings
  from listener changes.
- Dynamic rebinding is a later feature. Do not partially implement it.

## Qualification matrix

Run and record:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --profile ci --all-targets -- -D warnings`
- `cargo nextest run --workspace` (or the repository's full nextest command)
- `cargo test --workspace --doc --profile ci`
- `cargo audit`
- `cargo deny check`
- `cargo xtask verify`
- config tests for legacy and canonical listener shapes
- multi-listener service tests on ephemeral ports
- TLS/H2/H3 transport tests
- multi-worker single-listener and multi-listener startup tests
- failure/rollback test for one listener bind failure
- port-release test after shutdown
- benchmark `multi-listener` and TCP/UDP multi-port run

Do not run a release gate from a dirty tree. `cargo xtask verify-release`
requires a clean commit and is not part of the implementation branch gate unless
the release process explicitly requests it.

## Tests

- Two workers bind two HTTP listeners with reuse and both serve.
- One worker fails to bind one listener: supervisor does not mark the
  deployment ready; other workers are not left silently partial.
- Single-worker duplicate listener definitions are rejected before bind.
- Multi-worker H3 follows the chosen ownership rule.
- Listener config reload returns a restart-required result and does not imply
  a live rebind.
- Existing single-worker multi-listener tests remain green.
- Benchmark evidence is a new dated run; old unsupported results remain
  append-only.

## Exit criteria

- Default one-worker multi-listener deployment is qualified.
- Multi-worker TCP/HTTP/HTTPS listener sharing is qualified or explicitly
  rejected with a typed error.
- HTTP/3 multi-worker ownership is decided, implemented, and documented.
- Listener reload is truthfully restart-required.
- Full verification and benchmark evidence are recorded.
- No documentation claims multiple listeners without a test or a named
  limitation.

## Risks

- `SO_REUSEPORT` can mask configuration errors; validation remains mandatory.
- HTTP/3 migration is the highest-risk multi-worker area; the single-owner
  model is recommended until proven otherwise.
- Listener identity must remain stable across workers, or admin/metrics/bench
  evidence will disagree.
- Restart-only reload is a product limitation; state it plainly rather than
  pretending live rebinding exists.
