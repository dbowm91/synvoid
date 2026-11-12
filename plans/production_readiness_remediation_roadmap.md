# Production Readiness Remediation Roadmap

Status: **COMPLETE** (implemented 2026-11-11; evidence in each phase plan).
Audited baseline: `d507fefa` (`fix: skip content-negotiation headers in
payload scans`), SynVoid 1.1.0.

Origin: the 2026-11-10 production-readiness audit of the WAF, security,
scalability and multi-service surface. The audit found a credible
HTTP/WAF core but a red dependency gate and a service surface that does not
match its documentation. This roadmap converts those findings into ordered,
independently reviewable phases.

This is not a release claim. `cargo audit` and `cargo deny check` are red at
the audited baseline, so the release gate is already failing before any
feature work starts.

## Target outcomes

1. `cargo audit` and `cargo deny check` pass, or every remaining advisory is a
   named, capability-assessed exception with an owner and review date.
2. The service surface is truthful: HTTP virtual hosts work, and TCP/UDP and
   multiple HTTP listeners are either implemented and tested or explicitly
   unsupported.
3. The default process model is safe: one worker is the default; multi-worker
   operation is an explicit, documented opt-in with known state limits.
4. Per-site WAF controls (`action`, `paranoia_level`, `custom_patterns`,
   SSRF allowlists) are either enforced or removed from the schema and docs.
5. Header scanning and ban escalation no longer turn benign browser traffic
   into bans.
6. The operator install is non-root by default and has a real container
   artifact or no unverified container documentation.
7. The main data plane has a documented, tested isolation story.
8. Body limits and the large-upload path are explicit and produce the correct
   status codes.
9. Multi-service performance claims are backed by a reproducible benchmark
   harness and dated results.

## Phase table

| Phase | Plan | Priority | Depends on | Primary outcome |
|---|---|---|---|---|
| 01 | `production_readiness_phase_01_dependency_security.md` | P0 | none | Dependency gate green; advisory triage documented |
| 02 | `production_readiness_phase_02_tcp_udp_services.md` | P0 | none (01 for release) | TCP/UDP services either real or explicitly unsupported |
| 03 | `production_readiness_phase_03_http_listener_truthfulness.md` | P0 | none | Per-site `listen` ports either bound or removed |
| 04 | `production_readiness_phase_04_worker_pool_and_state.md` | P1 | none | One worker by default; multi-worker opt-in is safe |
| 05 | `production_readiness_phase_05_waf_site_policy.md` | P1 | none | Per-site WAF policy is enforced or removed |
| 06 | `production_readiness_phase_06_header_fp_and_escalation.md` | P1 | 05 (shares policy plumbing) | Header FPs and ban escalation calibrated |
| 07 | `production_readiness_phase_07_packaging.md` | P1 | 01, 08 (for final gate) | Non-root systemd unit and real container artifact |
| 08 | `production_readiness_phase_08_main_data_plane_sandbox.md` | P1 | 07 | Worker isolation story is real and tested |
| 09 | `production_readiness_phase_09_body_policy.md` | P1 | 05 (policy plumbing) | Explicit body caps and 413 semantics |
| 10 | `production_readiness_phase_10_multi_service_benchmarks.md` | P2 | 02, 03, 04, 09 for final numbers | Reproducible multi-service performance evidence |

## Ordering and parallelism

- Start Phase 01 immediately. It is independent and blocks the release gate.
- Phase 04 is a small default/validation change and can run in parallel with
  Phases 01 and 05.
- Phases 05 and 06 both touch WAF policy. 05 owns the policy-resolution seam;
  06 consumes it for header scanning and escalation. Run 05 first.
- Phase 02 and 03 are the service-surface decision points. They can run in
  parallel on separate branches, but 10 needs both before final numbers.
- Phase 07 after Phase 01 so the release gate is meaningful; Phase 08 after 07
  because the OS-level unit is the first isolation layer.
- Phase 09 after 05 because per-site policy resolution is the natural place to
  carry a per-site body cap.
- Phase 10 runs last for headline numbers, but its harness and baseline can be
  built earlier.

## Decision gates

These are product decisions, not implementation gaps. Each plan records the
recommended choice and the fallback.

| Gate | Question | Recommended choice |
|---|---|---|
| D1 | Implement TCP/UDP proxying or mark it unsupported? | Implement TCP first and UDP request/response second; keep the feature Beta until the service tests and soak pass. If raw UDP is not a product requirement, stop after TCP and remove the UDP docs/config. |
| D2 | Implement multiple HTTP listener ports or keep one listener with virtual hosts? | **Superseded 2026-11-11.** The original recommendation kept one HTTP listener per process for 1.1 and removed the unbound per-site `listen` surface. Product intent is multi-listener; see `plans/multi_listener_canonical_roadmap.md`. |
| D3 | WAF default action: `block` or `stall`? | `block`. It matches the current hard-coded behavior and avoids the 5-second stall budget becoming a resource-exhaustion lever. Update the docs that currently claim `stall` is the default. |
| D4 | Implement per-site `paranoia_level`/`custom_patterns` or remove them? | Implement via a bounded per-site detector cache. Operators need a way to tune a noisy site without disabling a detector globally. If the cache cannot be bounded safely, remove the fields and document a global-only policy. |
| D5 | Sandbox the worker by default? | Ship systemd hardening first; add Landlock in `auto` mode after qualification and make `required` the production recommendation. Do not claim in-process seccomp until Wasmtime JIT and the plugin path are qualified. |
| D6 | Shared state for N>1 workers or explicit opt-in? | Explicit opt-in. Default to one worker, scale with `worker_threads`, and require an acknowledgement for `workers > 1` while sessions/CSRF/admin counters remain worker-local. |

## Binding constraints

All phases inherit the repository rules:

- Request-path code consumes narrow traits; concrete `BlockStore`,
  threat-intel, mesh and composition handles stay in composition roots
  (`architecture/request_path_capability_boundary.md`).
- Facade dispositions are guard-enforced; new domain logic goes in the owning
  `synvoid-*` crate, not a root facade
  (`architecture/facade_disposition_matrix.md`,
  `architecture/root_module_ledger.md`).
- Admin mutations return typed `AdminMutationResult`, never generic success;
  block/unblock emits `AdminAuditEvent`; raw session tokens are never stored
  (`architecture/admin_control_plane_authority.md`).
- Reduced-feature binaries fail closed on capability-bearing sections; every
  phase must preserve `--no-default-features`, `mesh`, `dns`, `icmp-filter`
  and `mesh,dns` compilation.
- Every new root `tests/*.rs` file needs a `tests/OWNERSHIP.toml` entry in the
  same commit; `class = "domain"` is rejected.
- Security invariants remain: constant-time secret comparison, async-only
  bcrypt with bounded executors, fail-closed encryption/decryption, no raw
  keys in logs or argv.
- Benchmarks stay manual-only; do not add routine CI transport/perf gates.
- Historical closeouts are corrected by pointer, never rewritten.

## Baseline evidence

At `d507fefa` (2026-11-10):

- `cargo audit`: 53 advisories plus 18 warnings; exit non-zero.
- `cargo deny check`: `advisories FAILED`.
- `cargo test -p synvoid-waf --profile ci`: 364 passed.
- TCP/UDP pools are constructed but no `add_listener` production call exists;
  UDP has no upstream-to-client receive path.
- Per-site `listen` entries are parsed and routed, but startup binds only the
  global HTTP, TLS and HTTP/3 addresses.
- `WorkerPoolDefaults::default().workers` is 4 while the shipped config sets 1
  and the supervisor warns that the canonical data plane is one worker.
- `check_attack` hard-codes `WafDecision::Block(403, "Attack Detected")`;
  `action`, `paranoia_level` and `custom_patterns` are parsed but not applied.
- The shipped systemd unit runs as root; no Dockerfile exists and the
  deployment guide marks the image unverified.

## Verification strategy

Per phase, run the narrow tests named in that plan. Before merging a phase:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --profile ci --all-targets -- -D warnings
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo test --test security_regression --profile ci -- --test-threads=1
cargo xtask verify
```

Before any release:

```bash
cargo xtask verify-full
cargo xtask verify-release
cargo audit
cargo deny check
```

Plus the phase-specific live evidence: systemd unit verification, container
smoke, `configtest`, and the multi-service benchmark results.

## Out of scope

- New product features beyond the truthful service surface.
- A distributed session store or a full control-plane redesign.
- Public-crate promotion or release publication.
- DNS/mesh architecture changes.
- A broad admin UI redesign.
- Production deployment of a specific customer environment.

## Registration

Registered in: `plans/roadmap.md`.

## Completion

All ten phases are implemented and the repository gate is green:
`cargo xtask verify` (fmt, clippy, deny, core compile, repo guards, security
regression, root guards, admin contract, failure injection), the full workspace
nextest run (8,450 passed, 10 skipped), and workspace doctests. `cargo audit`
and `cargo deny check` both exit 0. Per-phase caveats are recorded in each plan.
