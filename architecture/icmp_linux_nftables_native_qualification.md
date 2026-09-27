# ICMP Linux nftables Native Qualification

Status: **QUALIFIED** (2026-09-27) via Phase 95 corrective proof. Linux
nftables is native-supported; see the Phase 95 proof below. eBPF, PF, WFP,
Windows Firewall and other platform tiers are unchanged; Phase 88 remains
**RETAIN** with no extraction authorized.

Plan: `plans/phase_93_icmp_linux_nftables_native_qualification.md`
(superseded QUALIFIED).
Corrective: `plans/phase_95_icmp_nftables_batch_corrective.md` (closed
QUALIFIED).
Gate roadmap: `plans/icmp_linux_native_qualification_gate_roadmap.md`.
Phase 92 lifecycle prerequisite: **CORRECTED**.

## Host and preflight

- Host: Darwin/macOS (`x86_64` process on Apple Silicon), kernel
  `25.6.0 Darwin Kernel Version 25.6.0`.
- Required Linux kernel, network namespaces, root/CAP_NET_ADMIN,
  `ip`, and `nft`: unavailable. `ping` is present.
- `cargo xtask icmp-qualify --check`: **REFUSED**, nonzero exit as designed;
  refusal reasons were non-Linux host, missing native opt-in, insufficient
  privilege, missing `ip`, and missing `nft`.
- `cargo xtask icmp-qualify --dry-run`: **PASS**, zero mutation. It listed
  prefix-scoped `synvoid-q-*` namespaces, `svqa-*`/`svqb-*` veth devices,
  and owned `synvoid_q_*` nft table, with planned cleanup. No resource was
  spawned.
- Native runs, packet observations, generation/readback observations,
  cleanup checks, and machine-readable native artifacts: **NOT RUN**.
- Native run IDs / proof-bearing SHA / nft and Rust native-host versions:
  not applicable; no proof-bearing native execution took place.

## Disposition

The macOS preflight is **BLOCKED**, not passed. The manual workflow attempt
is pending; Linux nftables retains its prior unqualified evidence tier until
the full matrix and artifact review pass. eBPF, PF, WFP, Windows Firewall and
other platform tiers are unchanged. Phase 88 extraction disposition remains
**RETAIN**.

The manual workflow is `icmp-native-qualification` in `.github/workflows/ci.yml`
and is dispatched with `icmp_native_qualification=true`. It runs two complete
native passes with distinct run IDs, proves packet behavior and owned-state
readback, verifies cleanup after each, and uploads bounded JSON artifacts.
Record the exact run and artifact details here before changing the support
tier.

## Workflow attempt history

Run `36275026606` at SHA
`c9861c2f4e7f1c25f6e8c9313af9be716bb8907f` used an Ubuntu 24.04 x86_64
GitHub-hosted runner. Tool installation and host recording succeeded, but
preflight stopped at the root command with `env: 'cargo': No such file or
directory`: `sudo` reset the runner's Cargo path. No topology preflight,
native run, or evidence artifact was produced. This is a workflow handoff
failure, not a native qualification result. The workflow now calls Cargo by
absolute path and explicitly carries the runner Cargo/Rustup environment; a
new exact-SHA attempt is required.

Run `36277087104` at SHA
`7bd3ae59d8f0122e0ff4321238923383de0fe689` proved the runner passed the
native preflight (`platform: linux`, opt-in present, `euid=0
cap_net_admin=true`, and `ip`/`nft`/`ping` present). It then failed before
the dry-run because the privileged Cargo check had created a root-owned
`target/debug/.cargo-build-lock`; no native matrix ran. The workflow was
reordered so the runner-user dry-run builds first, then privileged steps call
the compiled xtask binary directly, avoiding Cargo lock ownership. This
attempt is not native qualification evidence.

Run `36279326809` at SHA
`947e4f707cc5aefa9aca78a15b19d6ecfc8c04d4` passed the native preflight and
zero-mutation dry-run on Ubuntu 24.04.5 x86_64, kernel `6.17.0-1022-azure`,
Rust `1.98.1`, nftables `1.0.9`, iproute2 `6.1.0`, as root with
`cap_net_admin=true`. The native matrix failed **0/8** cases; nft reported
syntax errors parsing the generated ruleset batch. The backend currently
combines `flush table inet ...` and declarative `table inet ... { ... }`
syntax in `crates/synvoid-icmp-filter/src/nftables.rs`. No JSON artifact was
uploaded because the relative output path resolved under the test crate's
working directory. The workflow is corrected to use an absolute workspace
path and to run prefix-scoped cleanup after a failed pass. The hosted job log
is the current failure evidence; repeat the full two-run matrix after
`plans/phase_95_icmp_nftables_batch_corrective.md` closes.

Disposition: **FAILED / UNQUALIFIED**. Linux nftables retains its existing
evidence tier. eBPF, PF, WFP, Windows Firewall and other platform tiers are
unchanged; Phase 88 remains **RETAIN**.

## Phase 95 qualification proof (2026-09-27)

Phase 95 corrected the backend batch (imperative destroy+add atomic batch,
double-protocol type matches, limit-before-allow ordering, owned delete
argv, echo-reply pairing) plus one harness-only burst-reliability fix
(flood instead of interval burst, strictly stronger), then re-ran the exact
Phase 93 matrix twice on the proof-bearing SHA:

- Proof SHA: `39bfced25d51267ee5837eaecedae7da9af163d0`.
- Hosted run: `36335520434` (workflow_dispatch on `main`).
- Host: disposable GitHub-hosted Linux VM, Ubuntu 24.04, x86_64, kernel
  `6.17.0-1022-azure`, Rust `1.98.1`, nftables `1.0.9`, iproute2 `6.1.0`,
  as root with `euid=0` and `cap_net_admin=true`. Preflight and the
  zero-mutation dry-run passed.
- Pass A (`36335520434-a`, namespaces `synvoid-q-a-90887e`/`synvoid-q-b-90887e`):
  8/8 — install/readback (`89e51f4f6341e417` gen 1 verified), v4/v6
  type-code packet behavior, exemptions, rate-limit
  (below/burst/recovery), replacement (`89e51f4f6341e417`→`108765c43394382f`
  gen 1→2, stale absent), drift (`Drifted`, owned chain missing),
  disable (verified Absent, peer restored, owned gone), rollback
  (rejected generation, previous effective). Isolation proven
  (host `net:[4026531833]` vs target `net:[4026532313]`). Cleanup
  verified, no harness namespaces remain.
- Pass B (`36335520434-b`, namespaces `synvoid-q-a-90887f`/`synvoid-q-b-90887f`):
  8/8 with identical dispositions, fingerprints, and generations
  (deterministic). Cleanup verified again.
- Artifacts: both bounded JSON evidences uploaded
  (`target/icmp-qualify-36335520434-a.json`,
  `target/icmp-qualify-36335520434-b.json`).
- Routine verification at the proof SHA: local `cargo xtask verify`
  10/10 plus hosted `ci` + `dependency-security` success on the same run.

Disposition: **QUALIFIED**. Linux nftables is native-supported
(`docs/PLATFORM_SUPPORT.md`, `architecture/icmp_filter.md`). eBPF, PF,
WFP, Windows Firewall and other platform tiers are unchanged; Phase 88
remains **RETAIN**.
