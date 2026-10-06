# Architecture Maintenance and Auditability Campaign Closeout

Status: **CLOSED QUALIFIED — 2026-09-29**.

Campaign phases: 96–101 are implemented, reconciled, and closed. Baseline:
`30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2`. Implementation range:
`30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2..2bfc3c6cfd1a1f2454f801cc02c01a0cbafa2e30`.
The proof-bearing implementation SHA is
`2bfc3c6cfd1a1f2454f801cc02c01a0cbafa2e30`; the documentation-only closure
commit follows that verified source tree.

## Dependency graph

`cargo metadata --format-version 1 --no-deps` reports 53 workspace members:
44 `synvoid-*` crates and nine non-`synvoid-*` workspace members (root app,
`pqc`, `admin-ui`, two examples, fuzz, xtask, repo guards). The earlier
Phase 35 table in `crate_granularity_audit.md` is historical; the Phase 101
reconciliation there lists actual current internal direct/reverse edges for
all changed boundaries.

> Superseded count (re-measured 2026-10-06): the 44/9 split above no longer
> holds — it predates later crate additions and mis-classifies `fuzz` and
> `repo guards`, which are named `synvoid-fuzz` and `synvoid-repo-guards` and
> therefore count as `synvoid-*`. Current: **53 members = 47 `synvoid-*` + 6
> non-`synvoid-*`** (root app `synvoid`, `pqc`, `admin-ui`, `myapp-dynamic`,
> `my-waf-app`, `xtask`). The 53 total is unchanged.

Confirmed absent normal dependency paths using `cargo tree -e normal -i`:

- metrics → WAF and block-store → WAF;
- jail runtime → IPC;
- config-model → config runtime;
- upload/honeypot → mesh.

Jail protocol has no internal dependency and has two consumers (IPC parent and
jail runtime). HTTP3 now owns the transport request state machines and has no
reverse cycle. Mesh still has 14 direct internal dependencies including
application/service integrations; see the future-candidate decision below.

## Capability preservation

| Capability | Evidence and result |
|---|---|
| Minimal WAF/reverse proxy | `verify-full` minimal profile and no-default integration coverage; passed. |
| Default build | `cargo xtask verify` core compile, guards, and root behavior; passed 10/10 steps. |
| H1 plaintext / TLS H1 | `http_h1_parser_parity`, `http_tls_parity`, and existing H1 transport suites; included in full workspace verification. |
| H2 | Existing HTTP/2 transport/proxy suites; included in full workspace verification. |
| HTTP/3 | HTTP3 ownership and request/WAF boundary suites, HTTP3 config validation; included in full verification. |
| WAF block/pass/challenge/tarpit | WAF and root policy suites; `synvoid-waf` package passed in prior phase qualification and campaign-wide full run. |
| Admin routes/config mutation | `cargo xtask verify`: 66 admin contract tests passed; typed mutation guard suite passed. |
| Mesh required/optional/disabled | composition-root behavior, mesh startup rollback, worker supervision and lifecycle suites; mesh package passed 1,093 tests. |
| Raft/canonical and advisory DHT | Existing mesh canonical reader, protocol compatibility, and DHT integration suites; mesh package passed 1,093 tests. |
| DNS with/without mesh | bounded DNS and mesh+DNS feature profiles passed; full workspace tests passed. |
| WASM/YARA jail | live jail round trips and protocol serve-loop tests in `jail_isolation_guard`; included in root guard pass. |
| Upload and mesh rule source | upload package passed 130 tests with mesh feature; source-only reload and provider adapter tests. |
| Honeypot mesh integration | honeypot package passed 204 tests with mesh feature; publisher contract adapter. |
| Tunnel/VPN and ICMP compile paths | bounded compile profiles and full profile matrix. |
| Unsafe native extension | still opt-in; disabled-build rejection and feature boundary guards passed. |

No capability removal or authority change was intended. Mesh/YARA upload adapter
is available at the root composition boundary; the YARA manager is
Supervisor-owned and not instantiated in the process-separated upload worker,
so no active worker-local wiring is claimed.

## Configuration and wire compatibility

Phase 99 golden/config fixtures, tracked examples, capability rejection tests,
and identity realization tests remain the compatibility authority. The bounded
feature matrix in `verify-full` exercises minimal, mesh, DNS, ICMP, and mesh+DNS
builds. Configuration DTO defaults and serialized names live in
`synvoid-config-model`; file discovery, parse ordering, validation, and key
realization remain in `synvoid-config`/mesh runtime. See
`config_model_phase99_closeout.md` for the specific fixture inventory.

Jail protocol remains SVJL v1. Frozen golden frames, typed bounds/errors, the
dedicated jail binaries, and live WASM/YARA round trips are covered by the
Phase 97 jail protocol and root jail-isolation suites. HTTP H1/H2/H3 continue to
share canonical request normalization and policy; no second normalization
owner was added. Mesh protocol serialization and canonical/advisory authority
tests remain in `synvoid-mesh-protocol` and `synvoid-mesh`.

## Security and dependencies

- `cargo deny check`: passed. The existing two advisory ignores and temporary
  manifest-only third-party patches remain unchanged. Existing duplicate
  version warnings include `ahash`; no new git dependency was introduced.
- `cargo audit`: passed with six allowed unmaintained advisories:
  `RUSTSEC-2023-0089` atomic-polyfill, `RUSTSEC-2025-0141` bincode (two
  resolved versions), `RUSTSEC-2025-0057` fxhash, `RUSTSEC-2024-0370`
  proc-macro-error, and `RUSTSEC-2026-0173` proc-macro-error2. No vulnerability
  finding was reported.
- No unsafe/native loader ownership moved into the low-capability crates; no
  private-key custody or crypto signing authority moved to a model/protocol
  leaf. The policy guard enforces new low-capability dependency budgets.
- Release all-feature clippy initially exposed Linux-only nftables renderer
  helpers as dead code on this macOS host. The crate now marks that Linux-only
  helper module's non-Linux dead-code status explicitly; the all-targets,
  all-features clippy command then passed with no errors (third-party warnings
  remain as listed in compiler output).
- Exact-SHA hosted result: GitHub Actions run [36515438452](https://github.com/dbowm91/synvoid/actions/runs/36515438452)
  completed successfully on `2bfc3c6cfd1a1f2454f801cc02c01a0cbafa2e30`;
  both `ci` and `dependency-security` jobs passed. Conditional native
  qualification jobs were skipped and are not claimed as evidence.

## Performance and footprint

Phase 96–100 changes are primarily dependency direction, DTO ownership,
protocol relocation, and typed grouping. The Phase 100 grouping adds no lock,
allocation, dynamic dispatch, or serialization to mesh hot paths. HTTP3 and
jail protocol moves preserve the same request/frame algorithms. Existing
The focused release benchmark `cargo bench --bench bench_metrics_hotpath --
--warm-up-time 1 --measurement-time 2 --sample-size 10` ran on 2026-09-29.
Observed Criterion ranges: existing-site request start 17.121–17.750 ns,
request end 16.952–17.566 ns, proxied counter 12.373–12.656 ns, upstream
success 12.481–12.830 ns, request start/end round trip 33.349–34.229 ns,
global request end 9.178–10.356 ns, and global request-latency recording
3.531–3.569 ns. Cold/new-site registration was 142–248 µs with high variance.
These are current-head measurements only, on this host, with 10 samples; the
campaign has no frozen comparable pre-change sample, so these are not
before/after claims. Other existing focused benchmark targets include proxy
headers/cache, upstream selection, buffer pool, WAF normalization/detection,
and transport comparison. There is no prior campaign-head capture for block-store hot path,
jail process round trip, configuration startup, mesh DHT/canonical/proxy, or
release package size, so no numeric before/after claim is made for those
surfaces. This is an explicit evidence gap; it is not interpreted as measured
zero regression. The default `synvoid` release binary measured 78,689,008
bytes; the no-default-features binary measured 65,694,720 bytes on this host.
These are single-host final sizes, with no frozen baseline for a size delta.

## Future boundary decisions

- **Mesh consensus: RETAIN / defer.** The final graph does not satisfy the
  extraction preconditions: mesh still depends directly on application-facing
  proxy/cache, serverless, tunnel, config, and transport services. Existing
  transport trait seams and independent Raft invariants are insufficient to
  establish a clean one-way protocol-only dependency. Do not create a consensus
  extraction plan until an application-service-free state-machine boundary and
  a measurable audit/dependency benefit are demonstrated.
- **synvoid-filter: RETAIN.** Its small LOC is not a maintenance justification;
  no concrete dependency or invariant benefit from merging was established.
- **process manager vs IPC: DEFER.** Phase 97 isolated the jail protocol, but
  generic process management still shares IPC transport, config-bearing
  process-manager APIs, metrics, platform, TLS, and utility contracts. The
  remaining graph is not a clean one-way extraction boundary.

## Final qualification ledger

| Command/evidence | Result |
|---|---|
| `cargo xtask verify` | Passed 10/10 steps, 2026-09-29. |
| `cargo xtask verify-full` | Passed all 10 stages; 7,845 tests passed, 7 skipped, 215 binaries; all doctests passed. |
| `cargo xtask verify-release` | Passed on the proof-bearing implementation tree; release package checks passed, including 47 publishable packages (17 packaged-source-verified, 30 deferred behind internal predecessors) and both jail binaries. No publishing occurred. |
| `cargo clippy --all-targets --all-features -- -D warnings` | Passed after the host-specific Linux renderer annotation. |
| `cargo deny check` / `cargo audit` | Passed; six allowed unmaintained warnings as listed above. |
| Focused Phases 96–100 suites | Passed as listed in each phase closeout. |
| Hosted CI and dependency-security on proof-bearing SHA | Passed on exact SHA `2bfc3c6cfd1a1f2454f801cc02c01a0cbafa2e30`, run 36515438452. |

Final verdict: **CLOSED QUALIFIED**. Focused performance evidence is limited
to current-host measurements without a frozen pre-change comparator; release
size deltas and several uninstrumented subsystem hot paths therefore remain
unquantified. This evidence limitation was accepted without asserting zero
regression. No registered downstream plan was blocked on this campaign.
Mesh-consensus remains deferred, synvoid-filter remains retained, and
process-manager/IPC extraction remains deferred pending a cleaner boundary.
