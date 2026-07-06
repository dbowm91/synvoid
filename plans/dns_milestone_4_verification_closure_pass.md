# DNS Milestone 4 Verification and Closure Pass

## Context

Milestone 4 implementation has moved beyond planning. The current repo contains new DNS health/readiness surfaces, expanded metrics, diagnostic docs, internal conformance scripts, benchmark harnesses, production profile docs, example configs, and additional hardening/interop test suites.

The remaining risk is proof quality and integration fidelity. Several additions are structurally correct, but Milestone 4 should not close until the repo proves that:

- DNS CI actually runs and passes the new suites.
- Health and metrics are wired from runtime paths, not only implemented as standalone collectors.
- Conformance is labeled accurately as internal interop unless external `dig`/`kdig`/`delv`/`ldns`/`named-checkzone` checks exist.
- Benchmarks have a baseline result record.
- Production profile claims match real config/runtime behavior.
- Example configs are safe, valid, and non-aspirational.

## Objective

Perform a verification/closure pass over Milestone 4 Phase 1-4 work. The pass should either close Milestone 4 for DNS or produce precise blockers with no ambiguous "looks done" state.

## Non-goals

Do not add new protocol features. Do not expand recursive resolver scope. Do not weaken DNS safety or validation to satisfy tests. Do not convert internal interop tests into production claims unless external tool verification is actually added.

## Workstream 1: CI execution and status confirmation

Tasks:

- Inspect GitHub Actions runs for the latest `main` commit.
- Confirm the DNS CI job runs after the latest Milestone 4 additions.
- Confirm DNS CI covers:
  - `cargo fmt -p synvoid-dns -- --check`;
  - `cargo clippy -p synvoid-dns --all-targets -- -D warnings`;
  - `cargo test -p synvoid-dns --release`;
  - all Milestone 2 and Milestone 3 DNS suites;
  - new Milestone 4 interop suites;
  - `cargo check -p synvoid-dns --all-features`.
- If combined status checks remain empty, identify whether this is a connector limitation, workflow trigger issue, direct-push behavior, branch protection setting, or actual CI absence.
- Add a CI status note to `plans/dns_milestone_4_phase_04_production_profile_release_gate.md` or a final DNS verification record.

Acceptance criteria:

- Latest DNS CI pass/fail state is known.
- Missing status visibility is explained.
- DNS CI status is not conflated with unrelated workspace status.

## Workstream 2: Health surface integration audit

Current state:

- `DnsHealthChecker` exists with liveness/readiness, listener, zones, recursive, cache, DNSSEC, encrypted transport, transfer/update, uptime, and zone-load error state.

Tasks:

- Find every `DnsHealthChecker` construction site.
- Verify whether `DnsServer` owns or exposes the health checker.
- Verify listener startup calls `set_listener_bound(true)` and shutdown/reset paths clear it.
- Verify zone load/reload success and failure call `record_zone_load_attempt` or equivalent.
- Verify cache creation/disable/failure updates `set_cache_operational`.
- Verify recursive mode updates recursive health and circuit-breaker state.
- Verify DNSSEC key loading/signing state updates DNSSEC health.
- Verify DoT/DoH/DoQ config/cert validation updates encrypted transport state.
- Verify AXFR/IXFR/UPDATE/TSIG config updates transfer/update health.
- Add tests for health snapshots after startup, degraded zone load, cache disabled/failure, recursive disabled/degraded, encrypted cert invalid, and control-plane enabled/disabled.

Acceptance criteria:

- Health state reflects runtime state, not only manually set test values.
- Liveness/readiness transitions are test-backed.

## Workstream 3: Metrics wiring and taxonomy audit

Current state:

- `DnsMetrics` has a broad counter taxonomy and emits through the `metrics` facade for core counters.

Tasks:

- Audit call sites for each new metric family:
  - transport queries/errors;
  - operation counts;
  - zone load/reload success/failure;
  - DNSSEC key rotation/signing failure;
  - UPDATE accepted/rejected;
  - NOTIFY sent/received;
  - AXFR/IXFR accepted/rejected;
  - recursive upstream failures/circuit transitions;
  - cache invalidation/rejection events.
- Identify metrics that exist but are not yet wired.
- Add tests or lightweight instrumentation checks proving representative events increment expected counters.
- Confirm no qname, full client IP, TSIG key name, or high-cardinality labels are emitted.
- Confirm `_total` naming is used for counters and not gauges.
- Update `architecture/dns_operations_diagnostics.md` with exact metric names and meanings.

Acceptance criteria:

- Metrics are emitted by real code paths.
- Any unwired metrics are documented as pending rather than implied production observability.

## Workstream 4: Internal conformance versus external interoperability classification

Current state:

- `scripts/dns/conformance.sh` runs Rust integration-test suites for authoritative, truncation, DNSSEC, transfers, update/notify, encrypted, and recursive behavior.

Tasks:

- Rename or document the script as internal conformance/interop if it does not invoke external tools.
- Add optional external-tool checks if feasible:
  - `dig` for authoritative, truncation, AXFR;
  - `kdig` for DoT;
  - `curl` for DoH;
  - `delv` for DNSSEC validation smoke;
  - `ldns-verify-zone` and/or `named-checkzone` for zone fixtures.
- Make external checks tool-detected and skip with explicit output when tools are unavailable.
- Separate required internal CI checks from optional external local checks.
- Add a documented command matrix mapping each DNS feature to internal and external verification status.

Acceptance criteria:

- The repo does not overclaim external interoperability when only internal tests run.
- Optional external checks are runnable and clearly reported.

## Workstream 5: Benchmark harness verification and baseline record

Current state:

- Criterion dependency and benchmarks exist for cache, wire, zone, coalescer, and limits.
- Benchmark scripts and a results template exist.

Tasks:

- Run `cargo bench -p synvoid-dns --no-run` to confirm all benchmarks compile.
- Run the DNS benchmark script locally if feasible.
- Fill `benchmarks/dns/RESULTS_TEMPLATE.md` into a dated baseline result file or update the template with explicit placeholder instructions.
- Verify benchmarks record:
  - commit SHA;
  - CPU/platform;
  - Rust version;
  - build mode;
  - benchmark command;
  - key results;
  - known noise/variance.
- Add at least one non-timing stress test to CI if not already present, or document why benchmarks remain manual-only.
- Ensure benchmark scripts do not require privileged ports or external network by default.

Acceptance criteria:

- Benchmark harness compiles.
- A baseline result record exists or the lack of baseline is a tracked blocker.
- Benchmarks are reproducible and safe to run locally.

## Workstream 6: Production-profile accuracy audit

Current state:

- `architecture/dns_production_profiles.md` defines production-supported, beta, and experimental profiles.
- Example configs exist for authoritative public, DNSSEC signed, encrypted DoT/DoH, local recursive, and transfer primary.

Tasks:

- Audit every profile status against actual tested behavior.
- Verify local recursive profile claims do not overstate DNSSEC validation if validation depends on a specific recursive provider.
- Verify DNSSEC signed profile clearly distinguishes primitive/internal tests from external validation if external tools are not wired.
- Verify transfer profile requires allowlist and TSIG where appropriate.
- Verify encrypted transport profile is not marked production-supported unless cert config and client interop are proven.
- Verify examples parse with config loader or add tests that parse each example.
- Verify examples do not enable unsafe recursive or control-plane exposure by default.
- Verify default config claims match actual `synvoid-config` defaults.

Acceptance criteria:

- Production profiles are conservative and match tested behavior.
- Example configs are parse-tested or clearly marked illustrative.

## Workstream 7: Diagnostic script and docs verification

Tasks:

- Run or shellcheck scripts where feasible:
  - `scripts/dns/conformance.sh`;
  - `scripts/dns/run_benchmarks.sh`;
  - `scripts/dns/benchmark_report.sh`;
  - `scripts/dns/stress_tests.sh`;
  - `scripts/dns_diagnostic_smoke.sh`.
- Ensure scripts use repo-relative paths robustly.
- Ensure scripts fail clearly and do not hide command failures.
- Ensure docs reference correct script paths and commands.
- Confirm diagnostic smoke does not assume privileged port 53 unless documented.

Acceptance criteria:

- Operational scripts are runnable and documented.

## Workstream 8: Final release-gate command record

Run and record:

```bash
cargo fmt --all --check
cargo clippy -p synvoid-dns --all-targets -- -D warnings
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo test -p synvoid-dns --test axfr_ixfr_transfer_semantics
cargo test -p synvoid-dns --test update_authorized_semantics
cargo test -p synvoid-dns --test notify_behavior
cargo test -p synvoid-dns --test dnssec_known_vectors
cargo test -p synvoid-dns --test control_plane_exclusion
cargo test -p synvoid-dns --test encrypted_transport
cargo test -p synvoid-dns --test verification_gate
cargo test -p synvoid-dns --test dns_interop_authoritative
cargo test -p synvoid-dns --test dns_interop_truncation
cargo test -p synvoid-dns --test dns_interop_dnssec
cargo test -p synvoid-dns --test dns_interop_transfers
cargo test -p synvoid-dns --test dns_interop_update_notify
cargo test -p synvoid-dns --test dns_interop_encrypted
cargo test -p synvoid-dns --test dns_interop_recursive
cargo test -p synvoid-dns --test dns_stress_resource_limits
cargo check -p synvoid-dns --all-features
cargo bench -p synvoid-dns --no-run
cargo check --workspace
```

Optional local external checks:

```bash
./scripts/dns/conformance.sh --release
./scripts/dns/run_benchmarks.sh
./scripts/dns/stress_tests.sh
./scripts/dns_diagnostic_smoke.sh
```

Record for each command:

- pass/fail;
- commit SHA;
- platform;
- notable warnings;
- unrelated workspace failures;
- exact deferrals.

Acceptance criteria:

- A final verification record exists and can be used for release decision-making.

## Workstream 9: Closure decision

After the verification pass, classify Milestone 4 as one of:

- `Closed`: all required DNS checks pass; docs/profiles are accurate; only explicit future enhancements remain.
- `Closed with deferrals`: DNS is release-ready for specified profiles; external tooling, benchmarks, or experimental features remain documented deferrals.
- `Blocked`: required DNS checks fail or docs overclaim unverified behavior.

Required close criteria:

- DNS CI status known or visibility limitation documented.
- Health and metrics are wired or unwired portions are documented.
- Internal versus external conformance status is explicit.
- Benchmark compile and baseline status known.
- Production profiles are conservative and accurate.
- Example configs are parse-tested or clearly illustrative.
- Final release-gate commands are recorded.

## Expected likely deferrals

These are acceptable if explicitly documented:

- External `delv`/`ldns-verify-zone`/`named-checkzone` checks not available in CI.
- Performance benchmarks manual-only due to unstable CI timing.
- DoQ external client interop limited by available tooling.
- Full recursive resolver parity with mature resolvers.
- Full NSEC3 closest-encloser proof validation.
- HSM-backed production DNSSEC key ceremony.
