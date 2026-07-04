# DNS CI and Housekeeping Corrective Pass

## Context

DNS Milestone 2 is functionally closed: local verification recorded passing DNS-specific fmt/test/check commands, `synvoid-dns` passed 576 tests, and `synvoid-dns --all-features` checked cleanly. The remaining problems are not DNS implementation blockers, but they weaken repo-level confidence and future handoff quality.

Known residual items from the Milestone 2 completion record:

- CI does not run `synvoid-dns` or `synvoid-config` DNS unit tests.
- CI has stale feature flags: `icmp-nftables`, `icmp-ebpf`, and `icmp-winfw` references need review against current feature names such as `icmp-filter` and `flood-ebpf`.
- CI runs are failing due to `synvoid-tunnel` compile errors, reportedly unrelated to DNS.
- `AGENTS.md` references `architecture/dns_phase_07_cache_semantics_invalidation.md`, which is missing or misnamed.
- `scripts/check_imports.py` still has dead checks for deleted `src/dns/` mesh imports.
- DNS query coalescing lacks server-path integration tests even though unit coverage is strong.
- Query coalescing namespace is hardcoded to `Authoritative`.
- EDNS keepalive is parsed but not wired, which is acceptable under one-query-per-connection TCP but must remain documented.
- Query timeout applies to initial TCP read, not full query processing.

## Objective

Make the repo-level verification surface match the now-closed DNS Milestone 2 implementation. The goal is to ensure CI catches DNS regressions, remove stale references, classify unrelated workspace failures, and leave the repository ready for Milestone 3 work without carrying avoidable housekeeping debt.

## Non-goals

Do not expand this pass into DNSSEC correctness, persistent DNS-over-TCP, DoT/DoH/DoQ conformance, recursive resolver feature work, RPZ expansion, performance testing, or any production feature additions. This pass is verification and hygiene only.

## Workstream 1: CI workflow DNS coverage

Primary file:

- `.github/workflows/ci.yml`

Tasks:

- Inspect the current CI workflow and identify all jobs that run Rust tests/checks.
- Add DNS-specific commands to CI, preferably in a targeted job so DNS regressions are visible:

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
```

- Keep `cargo check --workspace` if already present, but do not let workspace-only failures obscure DNS-specific signal.
- If the repo intentionally keeps CI lightweight, add a `dns` job triggered by path filters for:
  - `crates/synvoid-dns/**`
  - `crates/synvoid-config/src/dns/**`
  - `architecture/dns*`
  - `.opencode/skills/dns_dnssec/**`
  - DNS test paths.
- Ensure CI runs on PRs and pushes where expected.

Acceptance criteria:

- CI has a clear DNS verification job or equivalent step.
- DNS tests are no longer only locally verified.
- CI output can distinguish DNS failures from unrelated workspace failures.

## Workstream 2: Stale feature flag cleanup

Primary files:

- `.github/workflows/ci.yml`
- `Cargo.toml`
- crate-level `Cargo.toml` files touching ICMP/tunnel/flood features
- docs mentioning ICMP feature names

Tasks:

- Audit current feature names in workspace manifests.
- Replace stale CI flags:
  - `icmp-nftables` -> current nftables/filter feature if applicable.
  - `icmp-ebpf` -> current eBPF/flood feature if applicable.
  - `icmp-winfw` -> current Windows firewall feature if applicable, or remove if no longer present.
- Avoid guessing feature replacements. Verify features directly from manifests.
- Add a CI feature-matrix comment documenting why each feature set exists.
- If some feature combinations are intentionally unsupported, remove them from CI and document that decision.

Acceptance criteria:

- CI no longer references nonexistent features.
- Feature-check commands match current manifests.
- Any unsupported combinations are explicitly documented.

## Workstream 3: Classify and fix `synvoid-tunnel` CI failures

Primary likely files:

- `crates/synvoid-tunnel/**`
- workspace `Cargo.toml`
- `.github/workflows/ci.yml`

Tasks:

- Reproduce current CI failure locally or inspect GitHub Actions logs.
- Identify the first `synvoid-tunnel` compile error.
- Classify the failure:
  - stale feature flag;
  - missing dependency;
  - platform-specific compile issue;
  - API drift;
  - test-only failure;
  - unrelated code defect.
- If fix is small and low-risk, fix it in this pass.
- If fix is larger, isolate DNS CI from tunnel failure and create a follow-up plan or issue for tunnel.
- Do not mark unrelated tunnel failures as DNS regressions.

Acceptance criteria:

- CI failure source is known.
- DNS-specific CI can pass independently even if tunnel requires a separate fix.
- If tunnel remains broken, the follow-up path is explicit.

## Workstream 4: Stale DNS path and import guard cleanup

Primary files:

- `scripts/check_imports.py`
- `AGENTS.md`
- `crates/synvoid-dns/AGENTS.override.md`
- DNS architecture docs

Tasks:

- Update `scripts/check_imports.py` to reflect the new canonical DNS crate path.
- Remove dead checks for deleted `src/dns/` implementation imports unless they intentionally guard against reintroduction.
- If keeping a guard against reintroducing `src/dns`, rename it as a canonicality guard and make the message explicit.
- Search for stale references:

```bash
rg "src/dns" .
rg "architecture/dns_phase_07_cache_semantics_invalidation.md" .
rg "dns_phase_07_cache_semantics_invalidation" .
rg "crates/synvoid-dns" AGENTS.md .opencode crates/synvoid-dns -g '*.md'
```

- Fix the missing/misnamed plan reference in `AGENTS.md`. Prefer referencing the actual plan file under `plans/`, likely `plans/dns_phase_07_cache_semantics_invalidation.md` or the updated Milestone 2 cache integration plan.

Acceptance criteria:

- No stale doc points implementers to missing files.
- Import guards match the canonical crate layout.
- `src/dns` references are either historical notes or explicit anti-regression guards.

## Workstream 5: DNS server-path coalescing integration tests

Primary files:

- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/src/server/query.rs`
- DNS integration tests under `crates/synvoid-dns/tests/`

Tasks:

- Add server-path tests that exercise coalescing through the actual query handler, not only the coalescer unit type.
- Confirm ordinary positive queries can coalesce when identical.
- Confirm NODATA/NXDOMAIN coalesce only if policy permits and response dimensions match.
- Confirm DO bit, qclass, transport class, client identity, and namespace differences do not coalesce.
- Confirm AXFR, IXFR, NOTIFY, and UPDATE bypass coalescing through the server path.
- Confirm owner failure cancels in-flight state in handler integration.

Acceptance criteria:

- Coalescing safety is proven at server integration boundary.
- Unit and integration behavior align.

## Workstream 6: Coalescing namespace policy cleanup

Problem: `QueryKey` includes a namespace dimension, but construction currently appears hardcoded to `Authoritative`.

Tasks:

- Decide whether current coalescer is authoritative-only by design.
- If authoritative-only, rename/comment the key constructor to make that clear and document recursive coalescing as deferred.
- If shared across recursive and authoritative contexts, add namespace parameter to `QueryKey::from_parsed` and call sites.
- Add tests proving namespace differences do not coalesce if shared.
- Update docs/matrix accordingly.

Acceptance criteria:

- Namespace hardcoding is no longer ambiguous.
- Recursive behavior cannot accidentally share authoritative coalescing state.

## Workstream 7: EDNS keepalive and query timeout documentation

Tasks:

- Confirm EDNS keepalive is parsed but intentionally not wired due to one-query-per-connection TCP policy.
- Ensure `architecture/dns.md` and config matrix state this accurately.
- Document that TCP timeout currently covers initial read and not full query processing.
- If a small bounded-processing timeout wrapper is feasible around handler execution, add it; otherwise defer explicitly.

Acceptance criteria:

- Operators and future agents do not infer unsupported EDNS keepalive behavior.
- Query timeout semantics are explicit.

## Workstream 8: Verification record update

After fixes, update the final verification plan or architecture doc with:

- commands run;
- CI workflow changes;
- feature flag changes;
- tunnel status;
- DNS CI status;
- remaining deferred items.

Required commands:

```bash
cargo fmt --all --check
cargo test -p synvoid-config dns
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

If CI is available, include the GitHub Actions run result or status URL in the commit/PR notes.

## Completion criteria

This corrective pass is complete when:

- CI includes DNS-specific verification.
- CI feature flags match current manifests.
- `synvoid-tunnel` CI failures are fixed or explicitly isolated from DNS closure.
- stale DNS path/import references are cleaned up.
- missing plan references are corrected.
- server-path coalescing tests exist or a precise deferral is documented.
- coalescing namespace policy is explicit.
- EDNS keepalive and query timeout limitations are documented.
- final verification record is updated.
