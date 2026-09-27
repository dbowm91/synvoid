# Phase 95 Plan: ICMP nftables Replacement Batch Corrective

Status: **CLOSED — QUALIFIED** (2026-09-27). The backend batch is corrected
and the full two-run native matrix passes 8/8 per pass on the exact
proof-bearing SHA. Phase 93 is superseded as **QUALIFIED**; Linux nftables
moves to the native-supported evidence tier. Phase 88 remains **RETAIN**;
no extraction or publication is authorized.

Registered in: `plans/roadmap.md` and
`plans/icmp_linux_native_qualification_gate_roadmap.md`.

Plan baseline: Phase 93 failed on exact attempt
`36279326809` at SHA `947e4f707cc5aefa9aca78a15b19d6ecfc8c04d4`.

Depends on: Phase 93 **FAILED — BACKEND DEFECT FOUND** (now superseded
**QUALIFIED** via this corrective's proof).

## Finding

The Phase 93 disposable Ubuntu 24.04.5 x86_64 runner passed Linux/tool/root
preflight (`cap_net_admin=true`) and the zero-mutation dry-run. Its native
nftables matrix failed **0/8** cases with nft parser syntax errors while
applying the replacement ruleset. The current backend emits a
`flush table inet ...` command followed by declarative
`table inet ... { ... }` syntax in `crates/synvoid-icmp-filter/src/nftables.rs`.
Native batch parsing rejected this composition; correct it without reducing
the Phase 93 behavioral matrix or replacement atomicity.

The attempt did not upload machine-readable JSON because the workflow's
relative evidence path resolved from the crate test working directory. The
workflow has been corrected to pass an absolute workspace path and to run
prefix-scoped cleanup after a native pass even when the matrix exits nonzero.

## Scope and acceptance

1. Render an nftables batch that is valid on the supported Linux nftables
   version and preserves atomic replacement semantics. Do not flush or remove
   unrelated tables, chains, rules, or host firewall state.
2. Add deterministic tests for the exact batch grammar used by install,
   replacement, disable, drift repair, and rollback. Tests must reject the
   previously failing `flush table` plus declarative table composition.
3. Run the complete `synvoid-icmp-filter` package suite and repository
   verification.
4. On a disposable privileged Linux host, run the complete Phase 93 native
   matrix twice with distinct run IDs. Require 8/8 cases per pass, exact
   owned-state readback, packet behavior, replacement, drift, disable,
   rollback, and cleanup after each pass.
5. Upload both bounded JSON artifacts at the workspace artifact path even
   when a run fails. Verify the workflow invokes cleanup after a failing
   matrix before propagating its exit status.
6. Reconcile `architecture/icmp_linux_nftables_native_qualification.md`, the
   Phase 93 disposition, this plan, and the root roadmap. Phase 93 may be
   superseded as **QUALIFIED** only after the full exact-SHA two-run proof.

## Constraints

- Phase 88 remains **RETAIN** until its independent re-evaluation trigger is
  satisfied; Linux nftables qualification alone does not authorize extraction.
- No Linux proof upgrades eBPF, PF, WFP, Windows Firewall, or other platform
  evidence tiers.
- Keep the native lane manual and opt-in; routine CI remains non-privileged.
- A preflight refusal or missing artifact is never a pass.
- Do not weaken the matrix, issue standalone shell firewall commands outside
  the harness namespace, or claim support on unsupported platforms.

## Phase 95 closeout (2026-09-27)

Phase 95 is **CLOSED — QUALIFIED** on proof-bearing SHA
`39bfced25d51267ee5837eaecedae7da9af163d0`.

### Backend defects corrected (all proven by the native matrix)

The Phase 93 failure (`flush table` + split declarative `table inet` block,
nft 1.0.9 `syntax error, unexpected '{'`, 0/8) was the first of six
backend defects exposed across four native attempts on the corrective line.
Each fix preserves the Phase 93 behavioral matrix and atomic replacement;
none touches unrelated tables, host firewall state, or other platforms:

1. **Imperative atomic batch** (`crates/synvoid-icmp-filter/src/nft_batch.rs`,
   new pure renderer; `nftables.rs` delegates): one `nft -f -` transaction
   with `destroy table inet <owned>` (idempotent, no-op when absent) +
   `add table` + `add chain` hook input/output + `add rule` per match +
   `add chain gen_<16hex>` marker. Every line is a complete imperative
   command (stdin batch mode rejects declarative blocks). `destroy` (not
   `flush`) truly clears the previous generation — `flush table` leaves
   chains including stale `gen_*` markers behind, turning replacement into
   rule-append (`atomic_update_replacement stale_absent=false`, run
   `36333721321` 5/8).
2. **Double-protocol type matches**: `ip protocol icmp icmp type 8 …`
   (and `ip6 nexthdr icmpv6 icmpv6 type …`, plus code-qualified forms).
   The single-proto form `ip protocol icmp type 8` parses `type` as
   unexpected (run `36332367209`, 0/8 on the imperative rewrite).
3. **Global limit precedes per-type ACCEPTs**: the rate cap is emitted as
   early rules after exempt ACCEPTs and before type rules; the terminal
   base stays a plain drop. The previous embedded-limit-after-allow left
   allowed types uncapped.
4. **Owned delete argv single source of truth**: `remove_ruleset` executes
   exactly `nft_batch::delete_table_argv` (a sliced argv dropped the
   `delete` verb and made disable a no-op: `disable_cleanup
   owned_gone=false`, run `36333721321`).
5. **Paired echo-reply auto-allowance**: when the policy allows v4 8
   (resp. v6 128) with no explicit reply rule, both hook chains also
   `ALLOW` v4 0 (resp. v6 129). Without this the kernel reply hits the
   base DROP, so allow-echo generations never observe ping success
   (`atomic_update_replacement allowed_b=false`,
   `rate_limit_global below=0/3`, run `36333721321`). An explicit reply
   rule always wins; a blocked request never auto-allows.
6. **Harness burst reliability** (`nft_native_qualification.rs`, harness-only,
   no enforcement-semantics change): the burst step intends flood count mode
   (per its own comment) but ran interval `ping -c 40 -i 0.01`, which never
   exceeds the 10/s burst-20 bucket (two consecutive `below=3/3
   burst_loss=false recovered=true`, runs `36334614281`/`36335116081`).
   It now runs `ping -f -c 100 -w 10` flood — strictly stronger burst,
   same below/burst-loss/recovery property.

Deterministic coverage lives in `nft_batch` unit tests (run on every
platform without `nft`): imperative destroy+add sequence, legacy
flush-plus-declarative rejection, owned-scope atomicity, shared
install/replacement/drift/rollback renderer, owned delete argv, direction
matrix, exempt/rate/code rules, v6, marker format, reply pairing and
precedence, limit-before-allow ordering. The previously failing
composition is explicitly rejected by test.

### Native proof (exact SHA, two runs)

Workflow `icmp-native-qualification` in `.github/workflows/ci.yml`,
dispatched with `icmp_native_qualification=true` against the proof SHA:

- Proof SHA: `39bfced25d51267ee5837eaecedae7da9af163d0`.
- Hosted run: `36335520434` (workflow_dispatch on `main`).
- Host: disposable GitHub-hosted Linux VM, Ubuntu 24.04, x86_64, kernel
  `6.17.0-1022-azure`, Rust `1.98.1` (pinned), nftables `1.0.9`,
  iproute2 `6.1.0`, iputils-ping `20240117`, root with `euid=0` and
  `cap_net_admin=true`. Linux/tool/privilege preflight and the
  zero-mutation dry-run both passed.
- Run `36335520434-a`: **8/8** (`install_and_owned_state_readback`,
  `icmp_type_code_behavior` incl. v4/v6 packet behavior,
  `exemptions`, `rate_limit_global` below/burst/recovery,
  `atomic_update_replacement` A-blocked/B-allowed with stale generation
  absent across fingerprints `89e51f4f6341e417`→`108765c43394382f`
  generations 1→2, `drift_detection`, `disable_cleanup` with verified
  Absent + peer recovery + owned objects gone,
  `rollback_failure_path` with previous generation effective).
  Namespace isolation proven (host `net:[4026531833]` vs target
  `net:[4026532313]`). Prefix-scoped cleanup verified with no harness
  namespaces remaining.
- Run `36335520434-b`: **8/8** with identical dispositions, distinct run
  id and namespaces, same fingerprints/generations (deterministic).
  Cleanup verified again.
- Artifacts: both bounded JSON evidences uploaded at the workspace
  artifact path (`target/icmp-qualify-36335520434-a.json`,
  `target/icmp-qualify-36335520434-b.json`; 2 files, artifact
  `icmp-native-qualification-36335520434`). The workflow runs
  prefix-scoped cleanup after a failing matrix before propagating its
  exit status, and uploads with `if: always()` — verified by the earlier
  failing attempts on this line, which uploaded their JSONs.
- Routine verification at the proof SHA: local `cargo xtask verify`
  10/10 plus hosted `ci` + `dependency-security` success on run
  `36335520434` (recorded below; closeout committed only after green).

### Disposition

- Phase 93 is superseded as **QUALIFIED** by this exact-SHA two-run proof.
  Linux nftables moves to the repository's native-supported evidence tier
  (`docs/PLATFORM_SUPPORT.md`, `architecture/icmp_filter.md`); the
  binding record is
  `architecture/icmp_linux_nftables_native_qualification.md`.
- Linux eBPF remains experimental unless separately qualified; macOS,
  FreeBSD/OpenBSD, Windows tiers are unchanged.
- Phase 88 remains **RETAIN**. This satisfies only its Linux-nftables
  native-proof trigger; other triggers (platform proof, publication
  hygiene, maintenance, second-consumer justification) are untouched, so
  no extraction or publication phase is registered or unblocked by this
  closeout. No other registered plan was blocked on Phase 95.
- The native lane stays manual and opt-in; routine CI remains
  non-privileged.
