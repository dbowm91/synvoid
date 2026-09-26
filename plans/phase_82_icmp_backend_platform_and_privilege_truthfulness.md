# Phase 82 Plan: ICMP Backend, Platform, and Privilege Truthfulness

Status: planned.

Registered in: `plans/roadmap.md` and
`plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

Depends on: Phase 81 canonical policy/config boundary.

## Goal

Make every advertised ICMP backend feature compile truthfully, probe the
privilege/capability it actually needs, and report platform support without
conflating compile availability, privilege, semantic capability, or active
enforcement.

This phase does not yet redesign replacement transactions/readback; that is
Phase 83.

## Workstream A — repair the Cargo feature/dependency graph

Audit `crates/synvoid-icmp-filter/Cargo.toml`, root feature forwarding, and
all backend cfgs as one graph.

Current source references Windows crates that are not declared in the ICMP
crate manifest. Resolve this explicitly:

- declare target-gated optional dependencies required by the retained Windows
  backend(s);
- make `icmp-wfp`, `icmp-winfw`, `icmp-pf`, and `icmp-ebpf` features
  actually activate every dependency they require;
- decide which backend features the root `icmp-filter` feature intentionally
  forwards per target, if any;
- do not claim a platform is enabled merely because source files exist.

Before choosing versions, re-check current crate APIs, MSRV, licenses,
maintenance, and compatibility with the workspace toolchain.

## Workstream B — qualify and simplify Windows ownership

The current Windows paths have concrete compile/runtime gaps:

- `wfp` and `windows_firewall` imports have no manifest dependency;
- `windows_sys` is used in privilege checks without a crate-local dependency;
- WFP calls `InterfaceSpec::names()`, which does not exist;
- interface filtering effectively requires numeric indices;
- interface enumeration/name resolution contains stubs.

Use the current WFP ecosystem as the preferred production candidate because it
offers typed protocol/ICMP conditions and transactions, but make the final
choice on evidence rather than this plan's preference.

Choose one of two explicit outcomes:

### Outcome A — one primary Windows backend

Qualify WFP as the supported Windows enforcement lane, retain the Windows
Firewall backend only as a documented compatibility/fallback feature if it has
distinct value, or remove/deprecate the duplicate lane before extraction.

### Outcome B — two justified Windows backends

Keep both only if tests demonstrate distinct support/operational value and the
capability matrix explains the difference.

In either outcome:

- implement real interface name/index resolution;
- test ICMPv4 and ICMPv6 type/code matching;
- test exemption ordering/precedence;
- test transaction failure behavior;
- never claim rate limiting when the selected API does not implement it.

Cross-compilation is compile evidence only. Native Windows application/removal
proof belongs in Phase 84.

## Workstream C — make Linux privilege probes operation-specific

Delete the current semantic coupling where generic Linux `is_admin()` reads
`unprivileged_bpf_disabled`.

Introduce operation-specific probe results. The exact types may vary, but the
API should be able to express:

```text
BackendProbe {
    compiled,
    mechanism_present,
    privilege,
    usable,
    reason,
}
```

Linux requirements:

- nftables probing checks the authority actually needed for nftables and does
  not consult BPF sysctls;
- eBPF probing distinguishes BPF-load privilege from network attach privilege
  and runtime/kernel support;
- root remains sufficient where appropriate but is not the only modeled case;
- capability parsing/probing is fixture-testable;
- `CAP_NET_BIND_SERVICE` / low-port checks are removed from the ICMP public
  privilege vocabulary unless an actual ICMP backend requires them.

Do not claim `CAP_BPF + CAP_NET_ADMIN` in docs while checking only
`CAP_NET_ADMIN`.

## Workstream D — separate static capability from runtime state

Refactor `BackendCapabilities` so it describes backend expressiveness only.

Runtime facts must be separate:

- compiled into this build;
- mechanism present on host;
- sufficient privilege;
- currently selected;
- currently enforcing (Phase 83 will strengthen this to verified state).

Policy compatibility should be evaluated against the Phase 81 policy, not a
single static boolean. Examples:

- rate limit supported globally but not per source;
- type matching supported but code matching may differ;
- interface filtering may require a resolvable interface index;
- a backend may support a feature in principle but not in the current build.

Remove static `is_enforcing: true` from a compile-time capability descriptor.

## Workstream E — strict explicit backend selection

Change manager selection semantics:

- `Auto`: may probe and select a fallback in a documented priority order;
- explicit `Nftables`, `Ebpf`, `Pf`, `Wfp`, etc.: fail if that exact
  backend is unavailable or cannot express the requested policy.

Return the selection reason/probe report to callers. Do not log a warning and
silently switch an explicit eBPF request to nftables or an explicit WFP request
to another Windows backend.

## Workstream F — correct BSD platform boundaries

Immediately remove NetBSD from the PF cfg/support claim.

NetBSD disposition for this campaign:

- compile to an explicit unsupported/no-backend result for ICMP enforcement;
- document NPF as the correct future backend trigger;
- do not add an NPF implementation in Phase 82 unless a separately approved
  plan expands scope.

Treat FreeBSD and OpenBSD PF as separately qualified variants. Shared source
may remain where safe, but grammar/capability/privilege differences must be
represented explicitly.

macOS PF remains a distinct Darwin backend even if implementation code shares
rule-building concepts.

Reference: https://man.netbsd.org/npf.7

## Workstream G — reconcile support documentation

After code/feature corrections, update at least:

- `architecture/icmp_filter.md`
- `docs/FEATURE_STATUS.md`
- `docs/PLATFORM_SUPPORT.md`
- relevant ICMP skill guidance
- any platform helper docs that currently claim PF on NetBSD

Documentation must distinguish:

- supported/qualified;
- experimental/best-effort;
- compile-only;
- unavailable.

Do not upgrade a tier based only on cross-target `cargo check`.

## Required tests

Add unit/contract tests for:

- Linux capability bit parsing and BPF-sysctl independence from nftables;
- explicit backend request no-fallback behavior;
- `Auto` fallback selection and reason;
- policy capability mismatch rejection;
- Windows interface resolution helpers;
- target/feature manifest closure;
- NetBSD no-PF compile cfg;
- capability docs/table consistency where a repo guard is practical.

Use target checks where toolchains are available, but record them as compile
evidence:

```bash
cargo check -p synvoid-icmp-filter --target <target> --features <backend>
```

Native privileged enforcement tests are Phase 84 evidence.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-icmp-filter --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo xtask test guards
cargo xtask verify
```

Add target-specific compile commands to the phase evidence for every retained
advertised backend that the local toolchain can build.

Do not add a permanent broad CI matrix in this phase.

## Acceptance criteria

- Every retained backend feature has a complete declared dependency path.
- No active Windows feature references undeclared crates or nonexistent
  methods.
- Linux nftables availability is independent of BPF-specific sysctls.
- eBPF privilege reporting matches what the implementation actually checks.
- Static capability, host availability/privilege, and runtime selection are
  separate.
- Explicit backend requests cannot silently fall back.
- NetBSD is no longer routed through PF.
- FreeBSD/OpenBSD/macOS support is documented at the evidence tier actually
  achieved.
- Root feature documentation matches forwarding/compilation truth.

## Rejection criteria

Reject the phase if it:

- fixes docs but leaves feature builds broken;
- adds missing Windows dependencies without compiling the feature lane;
- equates "administrator" with every backend-specific capability;
- keeps a generic `is_admin()` as the authoritative Linux backend probe;
- retains NetBSD in the PF cfg;
- calls cross-compilation runtime qualification;
- keeps two Windows backends without a written capability reason;
- makes eBPF a default dependency.
