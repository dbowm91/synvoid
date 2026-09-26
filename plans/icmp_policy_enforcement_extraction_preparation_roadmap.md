# ICMP Policy/Enforcement Extraction Preparation Roadmap (Phases 85–88)

Status: Phase 85 closed 2026-09-26 (`20dfc148`; closeout
`architecture/icmp_phase85_policy_canonicalization_closeout.md`); Phases
86–88 remain planned and registered 2026-09-26.

Registered in: `plans/roadmap.md`.

Baseline: `main` at `81638c251592913579bd9bbce51d013c44d67910`.

## Purpose

Prepare `crates/synvoid-icmp-filter` for a later standalone-library extraction without publishing, renaming, or splitting it into an external repository in this campaign.

The current crate contains a useful cross-platform enforcement seam, but the present implementation is not yet a truthful public-library boundary. The cleanup must first establish one semantic ICMP policy owner, make platform/backend support claims match compilable and runtime-qualified behavior, remove silent semantic degradation, make policy replacement failure-safe, and distinguish local desired state from verified kernel enforcement.

The intended eventual niche is **ICMP-specific policy compilation and enforcement**, not a generic cross-platform firewall abstraction. Current Rust already has generic cross-platform firewall work (for example Net Lattice) and per-platform building blocks. SynVoid's potentially reusable value is the ICMPv4/ICMPv6 semantic layer: type/code-aware policy, protocol-safety validation, rate-limit semantics, backend capability negotiation, privilege diagnostics, and enforcement verification.

This roadmap is therefore an extraction-preparation campaign, not an extraction campaign.

## Current-head findings that make cleanup prerequisite

### 1. Two incompatible ICMP configuration models exist

`crates/synvoid-config/src/icmp_filter.rs` and
`crates/synvoid-icmp-filter/src/config.rs` independently define
`IcmpFilterConfig`, `FilterType`, `IcmpAction`, `IcmpTypeRule`,
`Direction`, `InterfaceSpec`, and rate-limit configuration.

The two shapes have already diverged materially:

- table-name defaults differ (`synvoid-icmp` vs `synvoid_icmp`);
- config stores exemptions as strings while the enforcement crate stores
  `IpAddr`;
- rate-limit optionality differs;
- only the enforcement model has a separate ICMPv6 rule list;
- eBPF bytecode-path field names differ;
- interface validation rules differ;
- serde casing behavior differs.

The admin path currently bridges the two models through
`serde_json::to_value` / `serde_json::from_value`. That is shape-coupled,
loss-prone runtime conversion and must not be the basis of a public boundary.

### 2. Backend and privilege truth is inconsistent

Linux `is_admin()` currently mixes BPF policy with generic network-admin
capability checks. `can_modify_nftables()` delegates to that mixed probe, so
`unprivileged_bpf_disabled` can affect an unrelated nftables answer.
The implementation also does not actually test the capability combination
documented for eBPF.

The Windows source imports `wfp`, `windows_firewall`, and `windows_sys`,
but the crate manifest does not declare those backend dependencies. The WFP
path also calls a nonexistent `InterfaceSpec::names()` method and only
accepts numeric interface indices in practice.

### 3. Platform support claims are broader than qualified behavior

The PF cfg currently groups FreeBSD, OpenBSD, and NetBSD. NetBSD's native
packet filter is NPF, so NetBSD must not be advertised as a PF lane.
FreeBSD/OpenBSD PF behavior must also be qualified separately rather than
treated as one ABI/grammar contract.

Root/user documentation currently describes broader macOS/FreeBSD/Windows
ICMP support than the root feature forwarding and routine verification prove.

### 4. Runtime state is desired-state-biased

`FilterStatus` reports in-process state and requested config, not verified
live kernel state. Config updates generally remove the old policy before the
replacement is known to install successfully. That can create an enforcement
gap or leave runtime state ambiguous after failure.

`BackendCapabilities` also mixes static backend capability with runtime
enforcement state. A public policy compiler needs to distinguish static
expressiveness, runtime availability/privilege, requested-policy
compatibility, and verified applied state.

## Research boundary

The implementation phases should re-check current APIs/versions before adding
dependencies. The following are the current reference points, not mandatory
dependencies:

- Net Lattice cross-platform firewall model:
  https://docs.rs/net-lattice/latest/net_lattice/
- Linux nftables candidates:
  https://docs.rs/nftnl/latest/nftnl/
  https://docs.rs/rustables/latest/rustables/
  https://docs.rs/nftables/latest/nftables/
- macOS direct PF candidate:
  https://docs.rs/pfctl/latest/pfctl/
- Windows Filtering Platform:
  https://docs.rs/wfp/latest/wfp/
- ICMPv6 firewall guidance:
  https://www.rfc-editor.org/rfc/rfc4890
- IPv6 Path MTU Discovery:
  https://www.rfc-editor.org/rfc/rfc8201
- NetBSD NPF:
  https://man.netbsd.org/npf.7

## Binding constraints

1. Preserve existing SynVoid `[icmp_filter]` TOML/admin compatibility unless a
   current behavior is demonstrably broken. Any necessary schema change needs
   explicit aliases/migration tests.
2. Do not publish or create an external repository in Phases 85–88.
3. Do not expand this into a general firewall framework.
4. Linux nftables remains the required baseline Linux enforcement lane.
   eBPF remains optional and must not define the base API.
5. An explicit backend request is strict. Only `Auto` may fall back, and the
   selected backend/reason must be observable.
6. Requested policy semantics must never be silently weakened. Unsupported
   semantics are rejected or returned as an explicit compile result.
7. Routine CI remains proportionate. Do not recreate the removed broad OS
   matrix merely for this campaign; native privileged qualification belongs in
   focused/manual evidence unless repository CI policy changes separately.
8. Remove NetBSD from the PF claim now. NPF implementation is a separate future
   decision and is not required for this cleanup.
9. Do not make metrics/tracing or SynVoid admin/config types part of the
   reusable semantic contract.
10. Do not replace subprocess backends merely for aesthetic purity. A native
    API replacement needs a demonstrated correctness, atomicity, readback,
    security, maintenance, or dependency advantage.

## Execution order

1. Phase 85 — canonical policy model, explicit config adaptation, typed ICMP
   semantics, and protocol/rate-limit validation.
2. Phase 86 — backend/platform/privilege truthfulness and feature qualification.
3. Phase 87 — compile-before-mutate enforcement, transactional replacement,
   receipts, readback, and drift state.
4. Phase 88 — extraction-readiness audit, native-platform qualification,
   subprocess/native-backend adjudication, and final go/no-go evidence.

Phase 86 depends on Phase 85 because backend capability must be evaluated
against one policy vocabulary. Phase 87 depends on both. Phase 88 is a
qualification/decision phase and must not paper over residual implementation
gaps.

## Detailed plans

- `plans/phase_85_icmp_policy_model_and_config_canonicalization.md`
- `plans/phase_86_icmp_backend_platform_and_privilege_truthfulness.md`
- `plans/phase_87_icmp_transactional_enforcement_and_state_verification.md`
- `plans/phase_88_icmp_extraction_readiness_and_platform_qualification.md`

## Campaign acceptance criteria

The campaign is ready to close only when:

- there is one canonical semantic ICMP policy model;
- SynVoid config/schema DTOs use explicit typed adaptation and no JSON
  round-trip between duplicate config models remains;
- ICMPv4/ICMPv6 family semantics are explicit and RFC-sensitive validation can
  identify dangerous IPv6 filtering;
- rate-limit scope/meaning is documented and unsupported scope is rejected;
- backend selection distinguishes explicit strict requests from `Auto`;
- backend capability, runtime availability, privilege, requested-policy
  compatibility, and live enforcement state are separate concepts;
- Windows feature lanes compile with declared dependencies or are removed from
  advertised support;
- FreeBSD/OpenBSD PF and NetBSD NPF reality are represented truthfully;
- applying a replacement policy does not knowingly remove a working policy
  before the replacement has been compiled/validated and staged;
- status can distinguish applied, absent, drifted, and unknown/unverifiable
  enforcement state;
- packet counters are not claimed unless a backend supplies real evidence;
- platform support docs and feature gates match actual qualification;
- the Phase 47 public-crate promotion bar is evaluated without publishing;
- a final architecture record gives a clear extraction go/no-go and names any
  residual blockers.

## Campaign rejection criteria

Reject closeout that:

- merely renames the duplicate config structs while retaining serde-shape
  conversion;
- treats root/admin privilege as equivalent to backend-specific capability;
- falls back from an explicitly requested backend without returning an error;
- reports `enabled = true` as proof that kernel enforcement exists;
- advertises NetBSD PF support;
- calls cross-compilation native runtime proof;
- introduces a second generic firewall abstraction alongside existing ecosystem
  work;
- makes eBPF or `aya` mandatory for ordinary ICMP enforcement;
- adds a broad permanent CI matrix contrary to the repository's current
  verification strategy;
- promotes/publishes the crate before the final readiness decision.
