# Phase 93 Plan: ICMP Linux nftables Native Qualification

Status: **NATIVE ATTEMPT PENDING** (2026-09-26); Phase 92 is CORRECTED and a manual, opt-in Linux runner lane is being added to test whether its disposable namespace environment satisfies the native prerequisites.

Registered in: `plans/roadmap.md` and
`plans/icmp_linux_native_qualification_gate_roadmap.md`.

Planning baseline: `main` at
`826e634d7b9475c7b0b44badd2f51f07df6ddd17`.

Depends on: Phase 92 **CORRECTED**.

Harness prerequisite: Phase 91
`cargo xtask icmp-qualify` +
`crates/synvoid-icmp-filter/tests/nft_native_qualification.rs`.

## Goal

Produce the first privileged, packet-level native enforcement proof for the
Linux nftables lane using the Phase 91 disposable network-namespace harness.

This is a qualification/evidence phase, not an implementation-expansion
phase. Product changes discovered by the matrix require a separate corrective
unless they are trivial harness-only fixes that do not change enforcement
semantics.

## Host prerequisites

Use a controlled/disposable Linux host or VM.

Required:

- Linux kernel with network namespaces;
- root or effective `CAP_NET_ADMIN` sufficient for namespace/veth/nftables
  operations;
- `ip`;
- `nft`;
- `ping` with IPv4 and IPv6 support;
- Rust toolchain matching repository requirements;
- clean checkout at the proof-bearing SHA;
- no stale `synvoid-q*` namespaces from a previous interrupted run.

Prefer a disposable VM even though firewall state is isolated in netns.

Do not perform the qualification inside a container/runtime that blocks
network-namespace or nftables operations in ways that would make the result
non-representative without documenting that limitation.

## Pre-qualification gate

Before the privileged run:

1. Phase 92 is closed with exact SHA and all focused tests green.
2. Working tree is clean.
3. Run:
   ```bash
   cargo xtask icmp-qualify --check
   cargo xtask icmp-qualify --dry-run
   ```
4. Review the dry-run resource names and case inventory.
5. Confirm no stale harness namespaces:
   only prefix-scoped cleanup is allowed.
6. Record:
   - git SHA;
   - distro/kernel;
   - architecture;
   - nftables version;
   - Rust version;
   - privilege mode (root vs capability).

A refused preflight is **BLOCKED**, not passed.

## Native execution

Run the documented dual-gated command on the exact proof-bearing SHA, for
example:

```bash
SYNVOID_ICMP_QUALIFY_NATIVE=1 \
  cargo xtask icmp-qualify --native --json --out <artifact-path>
```

Use the implementation's actual CLI syntax if Phase 92 legitimately changes
it.

Do not bypass the xtask safety gates by invoking internal helpers manually for
the proof-bearing run.

## Required qualification cases

All Phase 91 native cases are mandatory:

1. **install + owned-state readback**
   - apply owned nftables state;
   - read it back through the crate;
   - prove the harness is operating outside the host/default netns.

2. **ICMP type/code behavior**
   - IPv4 Echo Request allow/block behavior;
   - IPv6 Echo Request allow/block behavior;
   - at least one code-qualified rule;
   - evidence must include packet behavior, not only nft syntax.

3. **exemptions**
   - blocked class + exempt source allowed;
   - non-exempt source remains subject to policy.

4. **global rate limit**
   - below-threshold traffic;
   - above-threshold burst;
   - refill/recovery;
   - bounded timing tolerances documented.

5. **atomic update/replacement**
   - generation A -> B;
   - B behavior/readback verified;
   - stale generation A absent.

6. **drift detection**
   - externally mutate/delete an owned object inside the disposable namespace;
   - `verify_live()` returns Absent/Drifted as appropriate, never Applied.

7. **disable + cleanup**
   - manager disable verifies Absent;
   - peer ICMP behavior recovers;
   - owned nftables objects disappear.

8. **rollback/failure path**
   - deterministic failure against an existing known-good generation;
   - no false generation/receipt advance;
   - previous generation remains effective where the backend contract promises
     preservation.

Phase 92 lifecycle corrections must be exercised by the native run where
applicable, especially disabled/Absent success and generation truth.

## Repeatability requirement

A single clean run is necessary but not sufficient.

After the first successful run:

1. run prefix-scoped cleanup and confirm no harness resources remain;
2. execute a second full native run with a different run id;
3. require the same case disposition;
4. confirm cleanup again.

The two runs need not produce identical timing, but semantic outcomes must be
stable.

If the second run exposes leaked state or order dependence, qualification
fails.

## Evidence artifact and closeout record

Preserve both bounded machine-readable artifacts under the repository's
evidence convention or attach/reference them from the architecture record.

Create/update:

`architecture/icmp_linux_nftables_native_qualification.md`

It must record:

- exact proof-bearing SHA;
- host/kernel/distro/architecture;
- nft/Rust versions;
- privilege mode;
- preflight result;
- each mandatory case result for run 1 and run 2;
- relevant policy fingerprints/generations;
- drift/failure-injection observations;
- cleanup result and no-leftover check;
- deviations/limitations;
- terminal disposition.

Do not dump arbitrary environment variables, unrelated firewall state, or
secrets.

## Repository verification around the native proof

At the same proof-bearing SHA, also run:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-icmp-filter --profile ci
cargo test -p xtask
cargo xtask test guards
cargo xtask verify
cargo deny check
cargo audit
```

The native matrix supplements routine verification; it does not replace it.

## Support-tier reconciliation

If all mandatory cases pass twice with clean cleanup:

- record Linux nftables as native-qualified/supported in
  `architecture/icmp_filter.md`,
  `docs/PLATFORM_SUPPORT.md`, and other current-authority support matrices;
- distinguish this internal evidence tier from public/class-3 crate support;
- leave Linux eBPF experimental unless separately qualified;
- leave macOS/FreeBSD/OpenBSD/Windows tiers unchanged.

If any mandatory case fails:

- terminal disposition is **FAILED**;
- keep Linux nftables at its existing lower tier;
- register a focused corrective tied to the failing invariant;
- do not delete or weaken the failing case.

If no suitable host is available:

- terminal disposition is **BLOCKED**;
- keep the current tier;
- do not claim qualification.

## Extraction disposition

Even a QUALIFIED result satisfies only Phase 88 trigger #1.

The Phase 88 RETAIN decision also cited:

- other platform-native proof/support-tier decisions;
- publication hygiene;
- maintenance burden;
- second-consumer/ecosystem justification.

Therefore Phase 93 must not automatically register an extraction or
publication phase.

A separate re-evaluation may be proposed only after reviewing all Phase 88
triggers against then-current evidence.

## Acceptance criteria

Phase 93 may close **QUALIFIED** only when:

- Phase 92 is closed CORRECTED;
- preflight is ready on a suitable Linux host;
- all eight mandatory native cases pass;
- packet-level v4/v6 behavior is observed;
- disabled/Absent lifecycle semantics behave correctly;
- drift and rollback paths behave truthfully;
- two consecutive runs pass with distinct run ids;
- prefix-scoped cleanup leaves no harness resources after each run;
- machine-readable evidence artifacts are preserved;
- routine repository verification is green at the proof-bearing SHA;
- support docs are updated without overstating other platforms;
- RETAIN extraction disposition is explicitly preserved.

## Rejection criteria

Reject qualification that:

- runs in the host/default firewall namespace;
- bypasses the dual opt-in/preflight gates;
- counts syntax generation as packet-level proof;
- treats a skipped/refused test as pass;
- runs only once and ignores cleanup/repeatability;
- changes a mandatory case merely to obtain green;
- upgrades eBPF/PF/WFP/Windows support from Linux evidence;
- treats Linux qualification as publication approval.

## Phase 93 disposition (2026-09-26)

Phase 92 is closed CORRECTED. Preflight was run with
`cargo xtask icmp-qualify --check` on Darwin/macOS. It refused because this
host is not Linux, lacks `ip` and `nft`, and does not have the required
root/CAP_NET_ADMIN qualification environment. The command exited nonzero as
required for refusal. `cargo xtask icmp-qualify --dry-run` passed and showed
only the expected prefix-scoped `synvoid-q-*` disposable namespaces/veth and
owned nft table, with no resources spawned. No stale Linux qualification
namespace could exist on this host, and no native run was attempted.

The macOS preflight remains **BLOCKED**, unqualified; it produced no native
proof and no Linux support-tier upgrade. The manual workflow-dispatch attempt
is a separate disposable Linux VM candidate and must pass the full preflight
and two-run matrix before Phase 93 can qualify. Phase 88 RETAIN remains
unchanged. The harness evidence record is
`architecture/icmp_linux_nftables_native_qualification.md`. Phase 92's
implementation SHA is `94d50efacb4146cfeafc608ac37d3c357c1247ee`; the
authenticated route regression and routine hosted proof are on
`e86fb35372b1b66bb59c8a6336bf32e55ff5c93e`.
