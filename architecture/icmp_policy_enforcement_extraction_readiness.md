# ICMP Policy/Enforcement Extraction Readiness (Phase 88)

Status: decided **RETAIN** (keep internal under `synvoid-icmp-filter`; no
extraction, no promotion, no publication). Re-evaluation triggers below.

Planning baseline: `81638c251592913579bd9bbce51d013c44d67910`.
Implementation head at decision: Phase 87 closeout `c0f22d45` plus the
Phase 88 evidence in this record (PF grammar corrections, native syntax
tests, doctests, manifest-robustness fix).

Plan: `plans/phase_88_icmp_extraction_readiness_and_platform_qualification.md`.
Roadmap: `plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

No crate was published and no external repository was created in this
campaign.

## 1. Disposition: RETAIN

Keep the functionality internal. The reusable niche is real (see §2), the
boundary is clean (Phases 85–87), but extraction/promotion is not
justified today because:

1. **No native privileged proof exists for any lane.** Phase acceptance
   requires Linux nftables apply/update/readback/drift/cleanup proof on a
   privileged host. No Linux, Windows, BSD, or privileged macOS host was
   available in this campaign (dev host: non-root macOS, no containers).
   Promoting now would promise reuse value that is not kernel-proven —
   the exact failure the acceptance bar exists to prevent.
2. **Publication hygiene gaps remain** (§5): MSRV undeclared/unevidenced,
   no runnable examples or crate README, SynVoid-branded names embedded
   in the public surface, `tracing` calls inside backends and a hard
   `metrics` edge (not feature-gated), and three workspace-bound tests
   that fail outside the workspace by design.
3. **Single consumer.** Only SynVoid consumes the boundary; extraction
   would move files without reducing maintenance authority.

This is not a quality verdict on the cleanup: Phases 85–87 stand as
landed, tested improvements to the internal boundary (including three
real PF grammar defects caught by native parser evidence, §4).

## 2. Ecosystem comparison (final API, re-checked 2026-09-26)

| Candidate | Version / license / date | Verdict |
|-----------|--------------------------|---------|
| Net Lattice (`net-lattice`) | 1.0.0, MPL-2.0, Sep 2026, maintained (linux/darwin/windows backends) | Different layer: interfaces/routes/neighbors/DNS inspection + mutation plans. No ICMP filter domain, no type/code policy, no RFC safety validation. Not a substitute. (MPL-2.0 file-copyleft would also need legal review before adoption.) |
| `nftables` | 0.6.3 (JSON API abstraction) | Mechanism, not policy: builds nftables rulesets. Our nft lane could migrate to it later (see §3); it does not provide the ICMP semantic layer. |
| `pfctl` | 0.7.0 (macOS PF library) | Mechanism, not policy. Same adoption note as `nftables`. |
| `wfp` | 0.2.0, adopted as a dependency | Building block, not competitor. Confirms the plan's "use per-platform building blocks" direction. |
| ICMP packet/probe crates | various | Different layer (sending probes vs filtering inbound/outbound ICMP). |

Remaining differentiated functionality (tested, host-independent):
family-aware ICMP type/code policy, RFC 4890/8201 safety validation with
explicit overrides, explicit rate-limit scope, requested-policy/backend
capability compilation with exact/unsupported reporting,
operation-specific privilege diagnostics, transactional/scoped
enforcement, and live owned-state verification with drift reporting. The
gap is real — the decision is about proof and burden, not duplication.

## 3. Subprocess vs native adjudication

| Backend | Current mechanism | Decision | Rationale |
|---------|-------------------|----------|-----------|
| nftables | `nft -f` batch + `nft --json` readback | **Retain subprocess deliberately** | The batch is atomic; JSON readback needs no new dependency. A native crate (`nftables` 0.6.3) adds async/maintenance surface with no demonstrated atomicity/readback advantage for infrequent control-plane ops. |
| PF (macOS/BSD) | `pfctl -f/-s` | **Retain subprocess deliberately** | Anchor replace is atomic per anchor; cardinality readback works. Same dependency-economy argument. |
| eBPF attach | `tc` qdisc/filter + XDP attach | **Retain temporarily** | Lane is experimental/optional; does not contaminate the baseline API. Native TC-netlink migration needs its own correctness/readback case. |
| WFP / winfw | native APIs (`wfp`, COM) | N/A (already native) | — |

No retained subprocess prevents the Phase 87 transaction/readback
contract: nft batches are atomic, PF anchor loads replace atomically,
WFP uses engine transactions, winfw's staged semantics are explicit.

## 4. Native platform qualification matrix

Evidence tiers: `supported` (native privileged proof) / `experimental`
(compiles + best-effort) / `compile-only` (cross-target check) /
`unsupported` (explicit error). Cross-compilation is never runtime proof.

| Lane | Compile evidence | Native evidence (this campaign) | Tier |
|------|------------------|---------------------------------|------|
| Linux nftables | host + `x86_64-unknown-linux-gnu` (±`icmp-ebpf`) clean | **Absent** (no Linux host) | `experimental` |
| Linux eBPF | same as above | **Absent** | `experimental` (optional) |
| macOS PF | host + `--features icmp-pf` clean | **Grammar proof**: real builder output accepted by platform `pfctl -n -f -` (2 native tests). Privileged load proof **absent** (non-root host) | `experimental` |
| Windows WFP / winfw | `x86_64-pc-windows-msvc` + `-gnu`, lib + `--tests`, clean | **Absent** (no Windows host) | `compile-only` |
| FreeBSD / OpenBSD PF | shared builder shape; grammar fixed from macOS proof | **Absent** (no BSD host; OpenBSD `icmp6-type` vs `icmp-type` keyword split is code-represented, unproven) | `experimental` |
| NetBSD | compiles to `UnsupportedPlatform` | N/A (unsupported by design; NPF future trigger) | `unsupported` |

The grammar proof caught three real defects that routine CI never could
(direction `in out`, missing trailing newline, trailing `all` after type
match) plus the macOS rate-limit grammar impossibility (now a typed
admission rejection). This is recorded as what it is — parser evidence,
not enforcement proof — and it is why the matrix refuses every
`supported` label.

## 5. Extraction/publication hygiene audit (against Phase 47 bar)

| Bar (§4 items) | Finding |
|----------------|---------|
| 1. Independently useful purpose | Pass: ICMP semantic policy/enforcement is a real niche (§2). |
| 2. No hidden root/runtime requirement | Mostly pass: zero workspace deps; `default = []`; no root-relative paths or env vars. Fail detail: `metrics` is a hard dependency and `tracing` calls sit inside backends (extraction needs feature-gated observability). |
| 3. MSRV declared + tested | **Fail**: no `rust-version`; packaged-tarball older-toolchain evidence never run. |
| 4. Semver/wire policy written | **Fail**: no crate README/changelog policy. |
| 5. Consumer docs + runnable examples | **Fail**: rustdoc is clean (`-D warnings`) + 3 doctests, but no examples/ and no README; module docs still carry phase-history narrative. |
| 6. Deterministic invariant tests | Pass: 48 lib + 5 + 12 + 7 integration + 3 doctests, all deterministic; fake-backend suite proves the state machine. |
| 7. Registry/maintenance burden justified | **Fail**: 5 backends × platforms + Windows dep weight (wfp→windows-sys 0.61 alongside workspace 0.59; windows_firewall→`windows` 0.62) for one consumer. |

Package evidence: `cargo package -p synvoid-icmp-filter --allow-dirty
--no-verify` assembles (25 files); out-of-workspace tarball `cargo test`
passes 48 lib tests; 3 workspace-bound guard tests fail standalone by
design (they assert workspace layout/docs — at extraction they re-home
to the parent repo); the manifest-closure test initially failed on cargo
manifest normalization (target-table quoting) and was fixed to accept
both spellings. `cargo deny check` and `cargo audit` show no new
findings (only pre-existing allowlisted advisories).

Dependency flow for a future split (recorded, not executed): the
portable core (`policy`, `validation`, capability requirements,
compile-neutral plan types) has zero backend deps and could stand alone;
enforcement adapters carry the target-gated backends. A two-crate split
is the likely shape IF the triggers below are ever met — but the split
itself would add API/versioning burden for one consumer today, which is
part of the RETAIN rationale.

## 6. Re-evaluation triggers (all must be re-checked, none are ordered work)

1. Native Linux nftables qualification on a privileged host
   (install / type-code policy / exemption / rate / update / readback /
   drift / disable / rollback-path).
2. Native proof (or explicit tier acceptance with justification) for
   every other lane claimed above `compile-only`.
3. A second real consumer, or ecosystem shift that changes §2.
4. Hygiene closure: MSRV evidence, examples + README, de-SynVoid public
   naming, feature-gated observability, standalone-portable tests.

## 7. Residual blockers / future work (not registered plans)

- Privileged native qualification for all lanes (needs hosts; Phase 91
  prepares the harness without claiming proof).
- PF exact-semantic readback (currently cardinality) and eBPF map-content
  verification (currently attachment liveness).
- `cargo publish --dry-run` never executed (no promotion intent);
  `cargo publish` remains manual per `docs/releasing.md` in all cases.

## 8. Post-RETAIN operator-truth note (Phase 90, closed)


Phase 90 closed the third residual above without touching the RETAIN
verdict: enable/disable/config replacement now share one verified
lifecycle (`drive_enable`/`drive_disable`/`drive_update` over one
`DriverState` with explicit desired power state); `GET /icmp/status`
serves `EnforcementReport` truth plus bounded read-only `verify_live()`
(selected backend, Applied/Absent/Drifted/Unknown, hex fingerprints,
receipts, verification detail; stats `null`, never fabricated zeros);
`/icmp/backends` serves probe truth (`probe_backend_inventory()` with
compiled/usable/reason per backend, selected backend from the report);
mutations return `Applied` only on verified success with backend and
enforcement detail in audit/result; the admin UI models filtering (typed
status/backends structs, re-fetch after mutation, object-shaped backends
response). Compat `enabled`/`status`/`backend`/`available` fields remain as
documented aliases. No extraction/publication status changed. Plan:
`plans/phase_90_icmp_operator_enforcement_truth_and_admin_contract.md`.

## 9. Post-RETAIN harness note (Phase 91, preparation only)

Phase 91 built the safe opt-in Linux nftables qualification harness the
Phase 88 trigger needs (ignored native matrix with disposable
network-namespace/veth topology, `setns`-isolated crate enforcement,
packet-level cases for install/type-code/exemption/rate-limit/update/
drift/disable/rollback, ledgered idempotent cleanup, bounded evidence
artifact; non-privileged unit/preflight/dry-run coverage in routine CI;
operator front-end `cargo xtask icmp-qualify`). Harness, safety gates,
fixtures, and docs are implemented and tested; no privileged run was
available at closure (this host is macOS), so Linux nftables remains at
its current evidence tier — unqualified, not passed. RETAIN remains in
force. No Phase 92 qualification/extraction re-evaluation is registered
until a suitable privileged host produces real evidence. Plan:
`plans/phase_91_icmp_privileged_native_qualification_harness.md`.
