# Phase 01 Plan: Two-Node Loopback Contract Harness

Status: **IMPLEMENTED** (2026-11-14; fixture + two-node contract suites green in `ea638ff9`).

Registered in: `plans/roadmap.md`.
Campaign: `plans/mesh_trust_boundaries_roadmap.md`.
Predecessor: none. Run first; every later phase adds a test here.

## The finding

The mesh stack has no test that opens a real mesh connection between two
nodes. The registry defect (A1) and the stream-pool defect (A2) both survived
CI because nothing exercises the path they break:

- `grep -rn "peer_connections" crates/synvoid-mesh/tests/` returns nothing.
  Every existing mesh test constructs topology, config, or protocol structures
  directly and never inserts a connection.
- `cargo test -p synvoid-proxy --test mesh_listener_backends` reports
  `running 0 tests` without `--features mesh`; the feature-gated assertions
  never execute in the configuration CI uses for that binary.
- The live topology in `runtime/mesh-qual/` is the only place a session is
  established, and it is manual.

The result is that four commits of transport work could each pass all gates
while the data plane remained unreachable. The audit found the same shape at
every layer: a unit-tested component behind an integration point that is never
assembled.

## Root cause

The mesh crate tests the pieces it can construct cheaply (framing, config
realization, authorization tables) and skips the assembly step, because
assembling it requires a QUIC endpoint, a PKI, two identities, and a backend.
That setup has never been factored into a reusable fixture, so each attempt
would be bespoke and was deferred. The deferred setup is where all the defects
live.

## Fix scope

### H1 — Reusable harness module

Create `crates/synvoid-mesh/tests/support/mesh_harness.rs` (included by the new
contract binary, not a separate crate) that builds a complete two-node world:

- a throwaway CA and two node certificates whose DNS SAN is each node's
  realized `node_id`, generated in-process with
  `MeshCertManager::generate_ca_certificate` / `sign_certificate`
  (`crates/synvoid-mesh/src/mesh/cert.rs:1031`, `:1080`);
- two `MeshConfig`s on `bind_address = "127.0.0.1"` with **port 0**, each with
  its own temp `private_key_path` so the realized ids are stable for the test;
- two `MeshTransport`s built through the same constructor and
  `initialize_mesh_transports(..., listen_endpoint = true)` path production
  uses (`crates/synvoid-mesh/src/mesh/backend.rs:509-515`), never a hand-rolled
  struct literal;
- a minimal HTTP/1.1 origin backend on `127.0.0.1:0` (fixed response plus an
  echo route) recorded as the origin's `local_upstreams["blog-public"]`;
- a helper that returns the edge-side `MeshProxy` and the origin's realized
  node id, so a test is three lines: build, request, assert.

Port 0 is deliberate: it removes the "two tests race for 50052" flake class.
Read the bound port from the endpoint's local address, not from config. Note
that `QuicRuntime::local_port()` reports the configured value
(`crates/synvoid-tunnel/src/quic/runtime.rs:449-455`); Phase 07 fixes that, and
the harness must not depend on it.

### H2 — Contract tests

Add `crates/synvoid-mesh/tests/mesh_two_node_contract.rs` with these cases.
Tests that fail at `4add005f` land `#[ignore]`d with the phase that un-ignores
them in the reason string, so CI stays green and the intent stays recorded.

| Test | Un-ignored in | Asserts |
|---|---|---|
| `harness_builds_two_nodes` | 01 | two endpoints bind, two identities realize, handshake completes |
| `origin_records_peer_in_topology` | 01 | `topology.get_peer(origin_node_id)` is present on the edge after connect |
| `peer_lookup_by_node_id` | 02 | `peer(node_id)` returns the established session; fails today |
| `two_sequential_requests_succeed` | 02 | a second request over the same session is not sent on a closed stream |
| `unpeered_peer_gets_403` | 02 | `peered_wafs` denial is reachable through the data plane |
| `unknown_service_gets_502` | 02 | no `Host` fallback, no upstream URL in the error |
| `forged_hello_is_rejected` | 03 | impersonation matrix across strict/tofu/permissive |
| `unsigned_threat_announce_is_rejected` | 04 | empty signature is a hard failure |
| `site_config_over_1mib_is_acked` | 05 | reliable delivery plus ack |
| `spoofed_xff_does_not_reach_upstream` | 06 | client headers are not promoted |
| `oversized_chunk_is_rejected_before_alloc` | 06 | 413, no allocation |

Group-level helpers live in `support/` and are shared; do not duplicate the PKI
setup per test.

### H3 — Make the harness impossible to skip

- Add a `mesh-contract` step to `verify_steps()` in
  `tools/xtask/src/verify.rs:131`:
  `cargo nextest run -p synvoid-mesh --cargo-profile ci --profile ci --test mesh_two_node_contract`.
- Add a nonzero-test guard to the same step. `nextest list` the binary and fail
  the step if the count is 0. This is the direct lesson from
  `mesh_listener_backends` reporting `running 0 tests`.
- If the new binary needs a root-test ownership entry, add it to
  `tests/OWNERSHIP.toml` in the same change; `root_test_ownership_guard` is
  part of `root-guards`.

### H4 — Determinism

The harness must not depend on wall-clock ordering, external network, or fixed
ports. Bind every socket to port 0; give each node its own temp dir; drive
readiness by polling the endpoint state with a bounded timeout, never by
`sleep`. Run the binary ten times consecutively before declaring the phase
done.

## Invariants

- The harness assembles nodes through the production constructor path. A test
  that builds `MeshTransport` by hand proves nothing about production.
- No test depends on the value of `min_peer_connections` or on any default
  that Phase 07 changes.
- Ignored tests carry the un-ignoring phase in their reason string. An ignored
  test with no owner phase is a defect.

## Verification

- `cargo test -p synvoid-mesh --test mesh_two_node_contract --profile ci`
  executes at least the Phase 01 cases and reports a nonzero count.
- The same command run ten times produces no bind failures and no flakes.
- `cargo nextest list -p synvoid-mesh --test mesh_two_node_contract` is
  non-empty inside the `cargo xtask verify` step.
- `cargo fmt --all -- --check` and the workspace clippy gate stay green.
- `cargo xtask verify` includes the new step and passes.

## Non-goals

- Replacing `runtime/mesh-qual/qualify.sh`. The in-process harness is for CI
  regression; the process-level topology remains the qualification artifact.
- Testing the worker/supervisor process split. That stays in the harness under
  `runtime/`.
- Adding a general integration-test framework, coverage tooling, or snapshot
  testing.
