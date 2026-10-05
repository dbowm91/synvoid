# Phase 131 Closeout — DNS Conformance Determinism

Date: 2026-10-05.
Plan: `plans/phase_131_dns_conformance_determinism_free_port.md`.
Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 130 `CLOSED QUALIFIED`
(`architecture/dns_runtime_dto_phase130_closeout.md`, finding F-3).
Disposition: **CLOSED QUALIFIED**.

## What this phase found before it fixed anything

The Phase 130 recommendation was to "either hold the reservation socket open
until the server binds, or serialize the listener tests". The first half of that
recommendation is **not implementable**, and the phase plan's own
Workstream A anticipated the problem by asking which option matches what the
affected suites actually bind.

`DnsServer::start` binds the authoritative sockets itself:

```text
crates/synvoid-dns/src/server/startup.rs — start_standard_mode
  let socket       = UdpSocket::bind(bind_addr)          // released only on drop
  let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
```

Both binds happen internally, on the same address, before any task is spawned.
So:

- a reservation cannot be held across the call — the reservation occupies the
  exact port the server must bind;
- a UDP-only reservation is not a partial fix — UDP and TCP port spaces are
  independent, so reserving UDP does not constrain the TCP bind;
- the remaining suggested remedy, serializing the listener tests, is exactly the
  thing this phase's rejection criteria forbid, and it would hide the contention
  rather than remove it.

The premise of F-3 was therefore wrong in a way that mattered: this is not a
window that can be closed, it is an assumption that should not be made.

## The remediation

`support::start_bound_dns_server` removes the assumption instead of narrowing
the window:

1. propose an ephemeral port (`free_port`, still only a prediction);
2. let the server perform the **real** bind;
3. if that bind is observed to have lost a race, take a new port.

Nothing sleeps. The retry is not blind: it discriminates a lost bind from every
other startup failure, so a genuine error still fails for its own reason instead
of being retried eight times and then reported as a port problem.

Discrimination keys on the two `map_err` prefixes `startup.rs` already emits —
`"Failed to bind DNS UDP socket: "` and `"Failed to bind DNS TCP socket: "` —
plus `AddrInUse` text. That is a string contract, so it is itself pinned by a
test that reads `src/server/startup.rs` and fails if either prefix is renamed.
Without that pin, a rename would silently convert every conflict into a
non-retryable error and the suites would go back to being intermittently red
with a far more confusing failure mode.

## Suite migration

| Suite | Change |
|---|---|
| `dns_phase45_contract.rs` | 4 tests moved to the helper; the local `start_server(port)` shim is gone |
| `transport_lifecycle.rs` | 4 listener tests moved; the local `ephemeral_port()` shim and its TOCTOU disclaimer are gone |
| `dns_recursive_isolation.rs` | anycast test uses a non-binding port constant |
| `support/context.rs` | `ephemeral_port()` **deleted** — the same anti-pattern in a second place |

Two deliberate non-changes:

- `udp_port_reusable_after_shutdown` and `tcp_port_reusable_after_shutdown` rebind
  **the same port** and are not retried. Reusing the exact port is the behavior
  under test, so retrying would turn a real failure into a pass. The helper's
  server *is* the first lifecycle in each, so the port under test is one the
  server genuinely bound and released.
- `shutdown_before_start_is_safe` and `recursive_server_handle_is_not_leaked`
  never start a server, so they take `UNBOUND_TEST_PORT` instead of predicting an
  ephemeral one. Nothing binds, so reserving buys nothing.

The anycast test is the same case: `start()` rejects anycast *before* any bind, so
its port was never reserved and never needed to be.

## Evidence

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --profile ci --all-targets -- -D warnings` | pass |
| `cargo test -p synvoid-dns --profile ci` | pass — 609 lib tests + every integration suite |
| `cargo test -p synvoid-dns --profile ci --test bind_determinism` | pass — 5/5 |
| Repeated-run matrix: 10x `nextest` over the four affected binaries | **10/10, exit 0** |
| `scripts/dns/conformance.sh` | **10/10** internal, twice; external 5 runnable / 5 skipped |

The repeated-run matrix is the actual determinism claim. Ten successive
parallel `nextest` runs over `bind_determinism`, `dns_phase45_contract`,
`transport_lifecycle` and `dns_recursive_isolation` — 84 tests per run, each run
re-contending the same ephemeral port space — all passed with exit code 0.

`bind_determinism.rs` is a new 5-test suite:

1. `reported_port_is_the_port_the_server_listens_on` — the property the old
   helper could not provide: a test can no longer dial a port the server never
   got.
2. `bind_conflict_discrimination_matches_only_addr_in_use_binds` — both
   `AddrInUse` shapes retry; zero-port, anycast, `EACCES`, `EADDRNOTAVAIL` and an
   unrelated message that merely contains "in use" do not.
3. `startup_source_still_contains_the_bind_error_prefixes` — the string contract
   is pinned at source level.
4. `repeated_binds_are_deterministic` — ten consecutive binds in one process,
   each reporting a port that accepts a connection.
5. `a_non_bind_startup_error_is_not_retried` — `#[should_panic]` on the exact
   reason, proving a real error is not swallowed by the retry loop.

The lane was added to `scripts/dns/conformance.sh`, taking internal conformance
from 9/9 to 10/10. It runs in the conformance script rather than only in the
crate suite because it is what makes the other listener lanes trustworthy.

## Findings

### F-1: the recommended fix was impossible, and the reason is structural

Recorded because a future reader will otherwise assume the obvious remedy was
missed. Any design where a component both picks a port and hands it to another
component that binds it has this problem; the only real fixes are to remove the
prediction (done here) or to let the binder report the port it got.

### F-2: the same anti-pattern existed in a second helper

`support/context.rs` had its own `ephemeral_port()`, byte-identical in behavior
and carrying its own copy of the same disclaimer. `support/mod.rs` documented it
as *the* way to get a port for listeners, so it was the helper a new test would
have reached for. Deleted rather than left as a hazard.

### F-3 (residual, recorded not fixed): two root live-proof suites still predict ports

`tests/eggbench_qualification_live_proof.rs` and
`tests/eggbench_m003_telemetry_live_proof.rs` each carry a local `free_port()`
with the same predict-then-bind shape.

They are **not** fixed here, and the reason is the phase's own evidence rule:
both are `#[ignore]`d opt-in tests that require a separately built binary, so
they cannot be executed as evidence in this phase. Changing untestable code would
trade a recorded flake for an unverified edit.

Their residual is precise, and the two halves need different remedies:

- the origin and metrics listeners are bound by the test itself, so binding `:0`
  and reading the port back removes those races outright;
- the `listen_port` passed to the external binary as an argument cannot be fixed
  that way at all, because the binary would have to report the port it bound.

Neither is in CI, and neither is in the DNS conformance lane.

### F-4: nextest's "leaky" marker appeared intermittently, exit code unaffected

The `(1 leaky)` annotation appeared in 2 of the first 10 matrix runs and did not
recur in the 10 runs that followed. All runs exited 0. Recorded as an
observation, not a diagnosis: nothing in this phase changed process lifetime, and
no claim is made about its cause.

## Acceptance criteria

| Criterion | Status |
|---|---|
| no test binds a port obtained by a released reservation | met — zero remaining `free_port()` callers in the crate |
| affected suites green across the repeated-run matrix | met — 10/10 |
| production code and behavior unchanged | met — no file under `crates/synvoid-dns/src/**` or `src/**` was modified |
| Phase 130 F-3 recommendation closed or residual recorded | met — closed, with matrix F-11 and the pointer in the Phase 130 closeout |

## Rejection criteria checked

- not serialized: the suites run fully parallel in every matrix run;
- no sleep or retry added to production or to the assertions — the only retry is
  conflict-gated in a test helper, and the pre-existing `sleep`s in
  `transport_lifecycle.rs` are untouched because they are part of what those
  lifecycle tests exercise;
- no assertion changed: `dns_phase45_contract` keeps all four original
  assertions, and the two reuse tests keep their same-port rebind;
- determinism claimed from a 10-run matrix, not a single green run.

## Effect on later phases

Phases 132–136 record evidence on the DNS conformance lane. That lane is now
deterministic across repeated runs, so a red lane in those phases is a real
signal rather than a known flake.

`synvoid-dns` remains class 1. No dependency edge changed, no provider was
inverted, and no persisted schema or default was touched.
