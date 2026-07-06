# DNS Milestone 4 Deferred Item Closeout Plan

## Context

DNS Milestone 4 is functionally closed for the documented supported profiles. The latest closure report records:

- 608 DNS crate unit tests passing.
- 31 DNS integration suites with 1101 total tests passing locally in release mode.
- `cargo fmt` clean.
- `cargo clippy -p synvoid-dns --all-targets --all-features` clean.
- Health/readiness wired into `DnsServer` and covered by integration tests.
- Five documented watchable metrics wired to production event sites.
- Internal conformance script corrected to distinguish in-process tests from optional external live-wire checks.
- Five DNS example configs corrected and parse-tested.
- Benchmark harness compiling with SHA-aware result template.

Remaining items are deferrals and closeout tasks, not blockers for the current DNS release posture. This plan closes or explicitly parks those items so they do not remain ambiguous.

## Objective

Eliminate ambiguity around Milestone 4 residual work by either completing the deferred item or recording a precise, owner-ready deferral with scope, risk, and acceptance criteria.

## Non-goals

Do not add new DNS protocol features. Do not broaden recursive resolver behavior. Do not claim full external DNS certification. Do not wire every speculative metric unless there is an operator use case. Do not make CI performance-sensitive.

## Deferred item inventory

1. GitHub Actions remote CI confirmation for the closure commit.
2. Optional external live-wire interoperability checks.
3. Twenty-seven unwired non-watchable metrics.
4. Benchmark baseline timing results.
5. Production-profile wording and support-status conservatism.
6. Optional external DNSSEC tooling coverage.
7. Script execution polish for diagnostics/benchmarks/conformance.

## Workstream 1: Remote CI confirmation

Current state:

- Local release gate is recorded as passing.
- GitHub Actions was not re-run as part of the closure report.
- Connector combined statuses for `main` have repeatedly returned empty status arrays.
- `.github/workflows/ci.yml` now covers the full DNS integration inventory.

Tasks:

- Trigger or wait for a GitHub Actions run on the current `main` commit.
- Confirm the DNS job includes all currently expected suites:
  - base DNS crate tests;
  - Milestone 2 correctness suites;
  - Milestone 3 hardening suites;
  - Milestone 4 interop/stress suites;
  - all-features DNS compile check.
- Capture the run URL, commit SHA, job name, and pass/fail result in a verification record.
- If GitHub status remains invisible through the connector, document the reason if identifiable:
  - no branch protection statuses;
  - direct-push workflow run not exposed through combined status API;
  - connector limitation;
  - workflow trigger mismatch;
  - GitHub Actions disabled.
- If the DNS job fails, classify failure as DNS, environment, dependency/cache, or unrelated workspace issue.

Acceptance criteria:

- A remote CI result for the DNS job is recorded, or a precise status-visibility limitation is documented.
- DNS release posture does not depend on unverified assumptions about remote CI.

## Workstream 2: External live-wire interoperability checks

Current state:

- `scripts/dns/conformance.sh` runs internal in-process Rust interop suites.
- It detects external tools but does not spawn a live server or execute live external commands.
- The script is now honest about this distinction.

Tasks:

- Decide whether external live-wire checks are required for current release or deferred to a later conformance milestone.
- If required, add a local-only live-wire harness that starts Synvoid DNS on ephemeral ports and runs available tools:
  - `dig` for authoritative A/AAAA/SOA/NODATA/NXDOMAIN/truncation/AXFR smoke;
  - `kdig` for DoT smoke where TLS fixture is available;
  - `curl` for DoH POST smoke;
  - `delv` for DNSSEC validation smoke if signed fixture is available;
  - `named-checkzone` and/or `ldns-verify-zone` for zone fixture linting.
- Tool-detect and skip unavailable commands with explicit SKIP output.
- Keep external live-wire tests optional/local-only unless CI image installs tools and the server harness is stable.
- If deferred, add a clear deferral note to the conformance docs and production profile docs.

Acceptance criteria:

- External live-wire coverage is either implemented with runnable commands or explicitly deferred as non-blocking.
- Docs never call internal in-process tests “external interoperability.”

## Workstream 3: Unwired metrics policy

Current state:

- Five documented watchable metrics are wired.
- Twenty-seven additional metric methods remain unwired and are not documented as watchable.
- The closure report marks these low priority.

Tasks:

- Inventory the 27 unwired metrics by family:
  - transport;
  - recursive;
  - DNSSEC;
  - cache;
  - control plane;
  - zone lifecycle;
  - encode/limits.
- For each metric, choose one of three outcomes:
  - wire now because it is operator-critical;
  - keep as future-reserved but remove from operator docs;
  - delete until there is a real event site.
- Prefer deletion for speculative metrics with no current call site unless an obvious event site exists.
- Prefer wiring if the metric is already referenced by operations docs, alert rules, or production profile guidance.
- Add tests only for metrics that are documented or alertable.
- Avoid qname/client-IP/TSIG-key high-cardinality labels.

Acceptance criteria:

- No unwired metric is documented as production-observable.
- Every documented metric has at least one runtime call site and one test or smoke proof.
- Future-reserved metrics are clearly internal and low-risk.

## Workstream 4: Benchmark baseline results

Current state:

- Criterion benchmarks compile with `cargo bench -p synvoid-dns --no-run`.
- `RESULTS_TEMPLATE.md` records metadata fields and current benchmark inventory.
- No actual timing baseline is recorded in the inspected closure report.

Tasks:

- Run `scripts/dns/run_benchmarks.sh` on a stable local host.
- Capture:
  - commit SHA;
  - platform;
  - CPU/RAM;
  - Rust version;
  - cargo version;
  - build mode;
  - benchmark command;
  - mean/stddev/variance for each benchmark group.
- Save a dated baseline file under `benchmarks/dns/results/`, for example:
  - `benchmarks/dns/results/YYYY-MM-DD-baseline.md`
- Mark benchmark results as local reference values, not CI pass/fail thresholds.
- Add a note explaining how to compare future results without treating noisy timing as a hard gate.

Acceptance criteria:

- At least one baseline result file exists.
- Baseline is tied to a commit SHA and hardware profile.
- Benchmarks remain manual/reference unless a stable CI performance environment exists.

## Workstream 5: Production profile support-status audit

Current state:

- `architecture/dns_production_profiles.md` marks profiles as Production-Supported, Beta, or Experimental.
- Example configs parse and validate.
- External live-wire checks are not yet executed automatically.

Tasks:

- Re-audit each support status against the verification actually performed.
- Profiles that rely only on internal in-process tests should say “production-supported by internal test coverage” or be downgraded to beta if external client compatibility is required.
- Local recursive profile must clearly state the recursive DNSSEC validation boundary, especially if validation depends on using the true recursive provider rather than public upstream forwarding.
- DNSSEC-signed profile must distinguish:
  - primitive/known-vector coverage;
  - live signed-answer path coverage;
  - external `delv`/`ldns` coverage if absent.
- Encrypted profile must distinguish DoT/DoH internal tests from external client tests.
- Transfer profile must state TSIG positive/negative coverage accurately.
- Add a short “release support matrix” table that maps each profile to:
  - internal tests;
  - external checks;
  - benchmark coverage;
  - known deferrals.

Acceptance criteria:

- Support labels are conservative and evidence-backed.
- Operators can see what has been tested without reading commit history.

## Workstream 6: External DNSSEC tooling deferral or implementation

Current state:

- DNSSEC primitive tests and live signing tests exist.
- External `delv`, `ldns-verify-zone`, and `named-checkzone` execution remains optional/manual.

Tasks:

- Decide whether external DNSSEC checks are a release requirement for DNSSEC production-supported status.
- If required, add signed zone fixtures and local script commands for:
  - `dig +dnssec`;
  - `delv`;
  - `ldns-verify-zone`;
  - `named-checkzone`.
- If not required, explicitly mark external DNSSEC tooling as deferred and keep DNSSEC support status appropriately conservative.
- Ensure NSEC3 closest-encloser limitations remain explicitly documented if not fully proven.

Acceptance criteria:

- DNSSEC profile language matches the level of external verification available.
- No DNSSEC production claim depends on unexecuted external tooling.

## Workstream 7: Script polish and safety

Current state:

- Diagnostic, conformance, stress, and benchmark scripts exist.
- Diagnostic smoke script now checks for `dig` and warns about privileged port 53.

Tasks:

- Run `bash -n` over all DNS scripts.
- If `shellcheck` is available, run it and either fix findings or document non-issues.
- Verify scripts use repo-relative paths and can run from any current working directory.
- Verify scripts do not assume privileged port 53 unless explicitly documented.
- Verify scripts fail clearly on command failure.
- Add `--help` support where missing if useful.
- Ensure script docs match real arguments and behavior.

Acceptance criteria:

- Scripts are safe, deterministic, and documented for operator use.

## Workstream 8: Final closeout record

Create or update a final closeout record containing:

- commit SHA;
- remote CI status or status limitation;
- external live-wire status;
- metrics decision table;
- benchmark baseline status;
- production profile support matrix;
- DNSSEC external tooling status;
- script validation status;
- remaining accepted deferrals.

Suggested path:

- `plans/dns_milestone_4_deferred_items_closeout_complete.md`

Closure states:

- `Fully closed`: all deferrals implemented.
- `Closed with accepted deferrals`: release-ready for specified profiles; deferred items explicitly non-blocking.
- `Blocked`: a release-profile claim is unsupported by tests/docs.

## Required commands

```bash
cargo fmt --all --check
cargo clippy -p synvoid-dns --all-targets --all-features -- -D warnings
cargo test -p synvoid-dns --release --no-fail-fast
cargo check -p synvoid-dns --all-features
cargo bench -p synvoid-dns --no-run
bash -n scripts/dns/conformance.sh
bash -n scripts/dns/run_benchmarks.sh
bash -n scripts/dns/benchmark_report.sh
bash -n scripts/dns/stress_tests.sh
bash -n scripts/dns_diagnostic_smoke.sh
```

Optional commands:

```bash
./scripts/dns/conformance.sh --release
./scripts/dns/run_benchmarks.sh
./scripts/dns/stress_tests.sh
./scripts/dns_diagnostic_smoke.sh --help
shellcheck scripts/dns/conformance.sh scripts/dns/run_benchmarks.sh scripts/dns/benchmark_report.sh scripts/dns/stress_tests.sh scripts/dns_diagnostic_smoke.sh
```

Optional external live-wire tools, if implemented:

```bash
dig +dnssec @127.0.0.1 -p <port> <name> A
delv @127.0.0.1 -p <port> <name> A +rtrace
kdig +tls @127.0.0.1 -p <port> <name> A
curl -H 'accept: application/dns-message' --data-binary @query.bin https://127.0.0.1:<port>/dns-query
named-checkzone <origin> <zonefile>
ldns-verify-zone <signed-zonefile>
```

## Completion criteria

This closeout is complete when:

- Remote CI status is known or status visibility is documented.
- External live-wire checks are implemented or explicitly deferred.
- Unwired metrics are inventoried and classified.
- A benchmark baseline exists or is explicitly deferred.
- Production support labels are conservative and evidence-backed.
- DNSSEC external tooling status is explicit.
- Scripts pass syntax checks and are documented.
- A final closeout record classifies the release posture precisely.
