# Phase 131 Plan: DNS Conformance Determinism — `free_port()` TOCTOU Remediation

Status: **CLOSED QUALIFIED** (2026-10-05). Closeout:
`architecture/dns_provider_inversion_phase131_closeout.md`.

The suggested remedy in Phase 130 F-3 turned out to be structurally
impossible: `DnsServer::start` binds UDP and TCP on the same port internally, so
a held reservation occupies the port the server needs. The assumption was
removed instead of the window narrowed — the server performs the real bind and a
new port is taken only when that bind is observed to have lost a race. Evidence:
10/10 repeated parallel `nextest` runs, conformance 10/10 twice, new 5-test
`bind_determinism` suite. Matrix F-11 records the finding; the Phase 130 closeout
carries a supersession pointer.

Residual recorded, not fixed: the two `#[ignore]`d Eggbench live-proof suites
still predict ports and cannot be executed as evidence in this phase.

Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 130 `CLOSED QUALIFIED`
(`architecture/dns_runtime_dto_phase130_closeout.md`, finding F-3).
Registered in: `plans/roadmap.md`.

## Goal

Remove the reservation race that makes the DNS conformance lane intermittently
red, so the lanes recorded as evidence by Phases 132–136 are trustworthy.

This is a test-infrastructure change. It must not alter production behavior.

## Background

`free_port()` at `crates/synvoid-dns/tests/support/runtime_config.rs:460`
binds an ephemeral UDP port, reads its number, and drops the socket. A
concurrently starting test can claim that port in the window between release and
the caller's own bind. `dns_phase45_contract` was observed failing once inside
a full conformance run and passing 5/5 standalone.

Affected callers bind real loopback listeners:

- `crates/synvoid-dns/tests/dns_phase45_contract.rs`
- `crates/synvoid-dns/tests/dns_recursive_isolation.rs`
- `crates/synvoid-dns/tests/transport_lifecycle.rs`

The same helper shape exists in two root suites:
`tests/eggbench_qualification_live_proof.rs:146` and
`tests/eggbench_m003_telemetry_live_proof.rs:184`. The Phase 130 finding names
the DNS suites; this phase records the root occurrences rather than silently
leaving an identical race behind, and fixes them only if the same remediation
applies without changing what those suites prove.

## Workstream A — reservation held until bind

Replace the release-then-bind helper with a reservation that owns the socket
until the listener is bound:

- a reservation type that holds the bound `UdpSocket` and releases it only
  once the caller has bound its own socket, or explicitly drops it;
- a helper that reports the reserved port **and** the guard, so no caller can
  accidentally reintroduce the old pattern;
- a documented contract stating that the reservation is advisory and that a
  caller must still handle a lost bind rather than assume the port is free.

Correctness detail: UDP and TCP port spaces are independent on all supported
platforms, so a UDP reservation does not by itself prevent a TCP bind. Either
hold reservations in the same protocol the listener uses, or reserve in both
spaces and require the caller to bind both. Choose the option that matches what
the affected suites actually bind, and record the choice.

## Workstream B — suite migration

- migrate every DNS-suite caller to the reservation helper;
- ensure the guard is dropped on every path, including the error path, so a
  failing test does not leak a held port into the rest of the run;
- keep `dns_runtime()` binding port 0 unchanged: `DnsServer::start` rejects a
  zero port, and that rejection is itself covered behavior.

## Workstream C — determinism proof

The claim is "deterministic", so it needs more than one green run:

- run the affected suites N times in sequence (N ≥ 10) and record the result;
- run them under the repository's own parallel test profile to exercise the
  contended case rather than only the serial case;
- run `scripts/dns/conformance.sh` at least twice and record both.

If any run still fails, this phase does not close. Record the residual honestly
rather than reclassifying it as unrelated.

## Workstream D — documentation

Append the remediation and its residual status to
`architecture/dns_config_runtime_matrix.md` (F-11) and correct the Phase 130
F-3 text in the Phase 130 closeout to point at the successor rather than
leaving it as an open recommendation.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test -p synvoid-dns --profile ci --test dns_phase45_contract
cargo test -p synvoid-dns --profile ci --test transport_lifecycle
cargo test -p synvoid-dns --profile ci --test dns_recursive_isolation
cargo xtask verify
./scripts/dns/conformance.sh
```

Plus the repeated-run matrix from Workstream C.

## Acceptance criteria

- no test binds a port obtained by a released reservation;
- the affected suites are green across the repeated-run matrix;
- production code and behavior are unchanged;
- the Phase 130 F-3 recommendation is closed or its residual is recorded.

## Rejection criteria

Reject a closeout that:

- serializes the whole suite instead of removing the race, thereby hiding the
  contention rather than fixing it;
- adds a sleep or retry;
- changes what any test asserts;
- claims determinism from a single green run.

## Closeout

`architecture/dns_provider_inversion_phase131_closeout.md`.
