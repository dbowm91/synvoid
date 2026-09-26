# Phase 93 Plan: ICMP Linux nftables Native Qualification

Status: **FAILED — BACKEND DEFECT FOUND** (2026-09-26); the suitable Linux host passed preflight, but all eight native cases failed in nftables ruleset parsing. Linux nftables remains unqualified; Phase 95 is registered for the focused corrective.

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

Initial workflow attempt `36275026606` at SHA
`c9861c2f4e7f1c25f6e8c9313af9be716bb8907f` reached Ubuntu 24.04 x86_64 and
installed nftables/iproute2, but failed before preflight because `sudo`
discarded the runner's Cargo `PATH` (`env: 'cargo': No such file or
directory`). It created no harness namespace and produced no native artifact.
The workflow was corrected to invoke the runner Cargo binary by absolute path
while explicitly preserving its Cargo/Rustup environment. The corrected
workflow requires a fresh exact-SHA attempt; the failed attempt is not host
qualification evidence.

The next attempt, `36277087104` at SHA
`7bd3ae59d8f0122e0ff4321238923383de0fe689`, passed Linux/tool/privilege
preflight (`cap_net_admin=true`) but failed before native execution: the
root-run Cargo check created a root-owned target build lock, and the following
runner-user dry-run could not open it. No native namespace matrix ran. The
workflow now performs the dry-run as the runner first, then invokes the
already-built xtask binary directly for privileged checks, native passes, and
cleanup. This is a workflow ordering/ownership defect; repeat on a new
proof-bearing SHA.

## Phase 93 disposition (2026-09-26)

The exact-SHA manual run `36279326809` at
`947e4f707cc5aefa9aca78a15b19d6ecfc8c04d4` reached native execution on
Ubuntu 24.04.5 x86_64, kernel `6.17.0-1022-azure`, Rust `1.98.1`, nftables
`1.0.9`, and iproute2 `6.1.0`. The runner was root with
`cap_net_admin=true`; Linux/tool/privilege preflight and the zero-mutation
topology dry-run both passed.

The first native matrix returned **0/8**: install/readback, ICMP type/code,
exemptions, global rate-limit, replacement, drift, disable cleanup, and
rollback. The nft parser rejected the generated replacement ruleset with
syntax errors at the table/chain declarations. The active backend composes a
`flush table inet ...` command with a declarative `table inet ... { ... }`
ruleset in `crates/synvoid-icmp-filter/src/nftables.rs`; Phase 95 will
correct and independently qualify that batch semantics. No Phase 93 evidence
artifact was uploaded because the workflow passed a relative output path to a
test process whose working directory differs from the workspace root; the
workflow now uses an absolute workspace path and runs prefix-scoped cleanup
after failed as well as successful passes. The hosted log for run
`36279326809` is the current bounded failure evidence; the corrected
workflow will preserve JSON evidence on the next attempt.

Disposition: **FAILED**, not qualified. Linux nftables stays at its existing
unqualified evidence tier; no platform support-tier upgrade, extraction, or
publication is authorized. Phase 88 remains **RETAIN**. Focused follow-up:
`plans/phase_95_icmp_nftables_batch_corrective.md`.
