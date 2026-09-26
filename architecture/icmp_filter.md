# ICMP Filter Architecture

## 1. Purpose and Responsibility

The ICMP Filter module (canonical: `crates/synvoid-icmp-filter/`; `src/icmp_filter/mod.rs` re-exports the crate plus the composition-boundary adapter in `src/icmp_filter/adapt.rs`) provides **cross-platform ICMP packet filtering** with pluggable backends, operation-specific privilege probing, strict backend selection, and feature-gated compilation.

**Core Responsibilities:**
- Family-aware ICMPv4/ICMPv6 policy (`policy::IcmpPolicy`, the single semantic owner — Phase 85)
- Pluggable backend architecture behind the narrow `IcmpFilter` trait
- Operation-specific privilege/mechanism probes (`platform::BackendProbe`)
- Strict explicit selection vs observable `Auto` fallback (`select_backend_for_host`)
- RFC-aware validation diagnostics (`validation`, Phase 85)

**Explicitly out of scope:** generic firewall abstraction (the reusable value is the ICMP semantic layer: type/code policy, safety validation, capability negotiation, verification), metrics/tracing ownership, NetBSD NPF (future trigger only).

---

## 2. Support tiers (Phase 86 truthfulness contract)

Tiers are evidence-based, never inferred from cross-compilation:

| Tier | Meaning |
|------|---------|
| `supported` | Native privileged apply/update/readback/drift/cleanup proof recorded (Phase 88 matrix) |
| `experimental` | Compiles; best-effort behavior; no native proof yet |
| `compile-only` | Cross-target `cargo check` evidence only |
| `unsupported` | No backend; explicit error (NetBSD) |

Current disposition (Phase 86 exit; native proof belongs to Phase 88):

| Backend | Platform | Feature gate | Tier | Notes |
|---------|----------|--------------|------|-------|
| nftables | Linux | `icmp-filter` (root forwards no backend sub-features) | `experimental` | Baseline lane; transactional batch; global rate limit |
| eBPF (XDP/TC) | Linux | `icmp-ebpf` (per-crate, optional) | `experimental` | Needs BTF + `CAP_BPF`/root (load) + `CAP_NET_ADMIN`/root (attach); `tc` subprocess retained deliberately (Phase 88 adjudicates) |
| PF (macOS) | macOS | `icmp-pf` (per-crate) | `experimental` | Anchor reload is staged, not transactional |
| PF (FreeBSD) | FreeBSD | `icmp-pf` (per-crate) | `experimental` | Qualified separately from OpenBSD/macOS |
| PF (OpenBSD) | OpenBSD | `icmp-pf` (per-crate) | `experimental` | Grammar/capability differences represented explicitly |
| WFP | Windows | `icmp-wfp` (per-crate; pulls `wfp` 0.2 + `windows-sys`) | `compile-only` | **Primary Windows lane**: typed ICMP conditions + engine transactions; LUID interface resolution; no rate limiting (rejected, never emulated) |
| Windows Firewall COM | Windows | `icmp-winfw` (per-crate; pulls `windows_firewall` 0.8) | `compile-only` | Compatibility fallback only: no transactions, no rate limit, no readback; rules visible to Defender/GPO UI |
| NetBSD | NetBSD | — | `unsupported` | Native filter is **NPF** (https://man.netbsd.org/npf.7), not PF; compiles to `UnsupportedPlatform`; NPF is a separately scoped future backend |

Root `icmp-filter` forwards **no** backend sub-features (`icmp-ebpf`, `icmp-pf`, `icmp-winfw`, `icmp-wfp` are enabled per-crate explicitly). Never enable eBPF by default: `aya` stays optional.

---

## 3. Static capability vs runtime state (Phase 86)

`traits::BackendCapabilities` is static expressiveness only:

| Backend | block/allow | rate-limit (global) | type | code | iface | index-required | transactions |
|---------|-------------|---------------------|------|------|-------|----------------|--------------|
| nftables | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| eBPF | ✓ | ✓ | ✓ | ✓ | ✓ | — | — (prepare-then-attach) |
| PF (FreeBSD/OpenBSD) | ✓ | ✓ | ✓ | ✓ | ✓ | — | — (staged anchor reload) |
| PF (macOS) | ✓ | — (rejected at admission; bare `max-src-conn-rate` is invalid macOS grammar per native `pfctl -n`) | ✓ | ✓ | ✓ | — | — (staged anchor reload) |
| WFP | ✓ | — | ✓ | ✓ | ✓ | ✓ (LUID) | ✓ |
| winfw | ✓ | — | ✓ | ✓ | ✓ | — (friendly names) | — |

Runtime facts live in `platform::BackendProbe { compiled, mechanism_present, privilege, usable, reason }`. Policy fit is evaluated per-request via `check_policy_compatibility(backend, &IcmpPolicy)` against `PolicyRequirements` (rate-global, iface, type/code, v6) — a `true` in the table never means "currently enforcing". Windows lanes reject rate-limited policy at construction with `Unsupported` detail.

---

## 4. Privilege probes (Phase 86)

- nftables: root **or** `CAP_NET_ADMIN` (parsed from `/proc/self/status CapEff`, fixture-testable via `parse_cap_eff_status`). Never consults BPF sysctls.
- eBPF load: root **or** `CAP_BPF`; kernel/BTF presence is mechanism, reported separately. `unprivileged_bpf_disabled` is diagnostic context only.
- eBPF attach (XDP/TC): root **or** `CAP_NET_ADMIN` — distinct from load privilege.
- PF / Windows lanes: Administrator/root (`is_admin`); the coarse helper is not authoritative for Linux backend probes.
- The ICMP vocabulary contains no low-port/`CAP_NET_BIND_SERVICE` check: no ICMP backend requires it.
- Docs never claim `CAP_BPF + CAP_NET_ADMIN` while checking less: each probe names the exact authority it checks.

---

## 5. Backend selection (Phase 86)

`select_backend_for_host(requested) -> Result<SelectionReport>`:

- `Auto`: probes and falls back in documented order (Linux: eBPF-if-usable else nftables baseline; Windows: WFP primary else winfw compat; macOS/BSD: the single PF lane). The `SelectionReport { backend, requested, reason }` is logged and returned — fallback is always observable.
- Explicit: satisfies that exact backend or fails (`BackendUnavailable` with probe detail, `FeatureNotEnabled` when the feature is off, `Config` for wrong-platform). No warn-and-switch (the old eBPF→nftables and WFP→winfw silent fallbacks are deleted).

---

## 6. Public API

| Method | Description |
|--------|-------------|
| `IcmpFilterManager::new(config)` | Strict selection + construction |
| `select_backend_for_host(requested)` | Observable selection with reason |
| `check_policy_compatibility(backend, policy)` | Exact-fit check, typed mismatches |
| `probe_nftables()` / `probe_ebpf_load()` / `probe_ebpf_attach()` | Operation-specific probes |
| `enable()` / `disable()` | Lifecycle (idempotence hardens in Phase 87) |
| `is_enabled()` / `is_enforcing()` | Local state (verified state arrives in Phase 87) |
| `status() -> FilterStatus` | Desired-state status (verified state arrives in Phase 87) |
| `is_available() -> bool` | Any usable backend on this host |
| `available_backends()` | Usable backends on this host |
| `has_privilege_for(operation)` | Probe-backed privilege predicate |

---

## 7. Integration Points

- **Supervisor**: ICMP flood protection management
- **Admin API**: filter status, config (typed adaptation, no JSON bridge — Phase 85), backend list
- **Platform**: backend-specific kernel integration; Windows LUID resolution via `platform::resolve_interface_luid`

---

## 8. Transactional enforcement and verification (Phase 87, built)

- `enforce::compile_policy` compiles `IcmpPolicy` + capabilities + backend
  options to `Exact(EnforcementPlan)` / `Unsupported` with zero mutation.
- `drive_update` (shared by the manager and the fake tests) installs
  through backend atomic/staged replacement, verifies live owned state,
  and advances `ApplyReceipt { backend, fingerprint, generation,
  applied_at_secs, ownership_tag }` only on `Verified`. `Drifted`,
  `Unknown`, and unexpected `Absent` are errors, never hidden success.
- `EnforcementReport { backend, desired_fingerprint, desired_generation,
  last_receipt, live: Applied/Absent/Drifted/Unknown, last_verify_error }`
  separates desired/applied/verified; `verify_live()` re-probes without
  changing generations. `FilterStatus` remains a compat desired-state view.
- Ownership: nft marker chain `gen_<fp>` in the owned table (single-batch
  flush+create); PF table-scoped anchors (single-load replace, legacy
  sweep); WFP stable provider/sublayer GUIDs per table in one transaction;
  winfw table-scoped prefixes with upsert-verify-retire + legacy sweep;
  eBPF prepare-offline then attach with retained-handle rollback attempt.
- Readback per lane: nft JSON table+chains+marker (exact); PF
  presence-plus-cardinality (documented); WFP provider-GUID enumeration;
  winfw per-rule existence; eBPF attachment liveness (map content
  explicitly unverified). Unrelated operator state is tolerated everywhere.
- Metrics are lifecycle-only (`apply_finished_total{backend,result}`,
  `drift_detected_total`, `verification_observed_total{backend,state}`,
  enabled/status gauges). Packet-outcome counters were removed (zero
  backend evidence); per-packet truth lives in backend APIs
  (`EbpfFilter::get_stats`), not core metrics.
- Crash recovery: nft/PF re-install idempotently; WFP dynamic filters die
  with the session (no sweep needed); winfw COM rules persist (tracked +
  legacy sweep on disable); eBPF attachments may linger (documented).

## 9. Phase 88 handoff (not yet built)

- Native privileged qualification per tier table above is Phase 88
  evidence; tiers must be lowered wherever proof is absent.
- The admin status endpoint still returns the compat desired-state view;
  `report()`/`verify_live()` are available for operator surfacing.
