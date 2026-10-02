# Subsystem Boundary Extraction Campaign Closeout (Phases 105–112)

Status: **CLOSED QUALIFIED** (2026-10-02).

Campaign plans: `plans/phase_105_dns_hickory_patch_security_requalification.md` through `plans/phase_112_extraction_gate_refresh_campaign_closeout.md`.

## Proof and scope

- Baseline: `19c0636535f3728e80b7c6777ec6a552c38c61a0` (Phase 105–112 plan registration).
- Implementation range: Phase 105 Hickory qualification SHA `857d2e76dd453dc9dd0c84aa89bc1293cc8a1e1b` through current Phase 111 closeout `bcdfaa283c0f78f31d1443de61cb055f14b29944`; Phase 106 implementation `a87d0b0c`; Phase 109 implementation/verification commit `cbfbd798`.
- Proof-bearing implementation head: `e7c0ec5a1317599b6f98e37a534b53544842a29c`; terminal documentation closeout follows on top of this tested tree.
- Hosted proof already attached to Phase 105: run `36922488692` passed `ci` and `dependency-security` on `857d2e76dd453dc9dd0c84aa89bc1293cc8a1e1b`.
- Final proof-bearing implementation/evidence SHA: `e7c0ec5a1317599b6f98e37a534b53544842a29c`.
- Hosted exact-SHA run `36955732943` passed `ci` and `dependency-security` on that SHA. Native sandbox and ICMP jobs were skipped by workflow conditions; no native qualification claim is made here.
- Local `cargo xtask verify` passed all 10 steps with `PKG_CONFIG_PATH=/usr/local/opt/xz/lib/pkgconfig`, matching the Phase 105 macOS x86_64 XZ toolchain workaround.
- Local `cargo xtask verify-full` passed all 10 steps: 7,896 tests across 217 binaries (8 skipped), minimal profile tests, all configured feature profile checks, and workspace doctests. The first run exposed a fragmented-WebSocket test decoder bounds bug; the helper now waits for complete frames, the focused regression passed, and the full rerun passed.
- `cargo xtask verify-release` passed 14/14 steps on the clean proof-bearing tree. Package inspection validated metadata and contents for all 47 publishable crates; 18 packaged sources verified and 29 remained deferred because their internal predecessors are not yet published. Both jail artifacts were present. No publication occurred.
- Final local `cargo deny check` passed; `cargo audit` reported no vulnerabilities and six allowed unmaintained advisories.

## Workspace and dependency graph

`cargo metadata --format-version 1` reports 53 workspace members/packages and 47 package names beginning `synvoid-`. The complete dependency metadata currently contains 1,037 packages and 187 internal path edges across dependency kinds. Those totals are present-head inventory, not a claimed campaign-wide reduction; there is no single before/after measurement for all dependency kinds.

| Area | Before → after evidence | Maintenance/capability result |
|---|---|---|
| Hickory | `hickory-proto`, `hickory-net`, and `hickory-resolver` 0.26.1 → 0.26.3; no new dependency or fork | Security requalification only. Transitive minimum-version selection also changed existing `windows-sys` and `socket2` versions; see `dns_hickory_patch_requalification.md`. No DNS implementation LOC removed. |
| Honeypot | Three direct normal SynVoid dependencies (`synvoid-config-model`, `synvoid-utils`, `synvoid-http-client`) → zero; current crate has zero normal SynVoid edges | Runtime config moved to crate ownership; transport and threat publication are injected. Existing functionality and DTO compatibility retained. No external repo, published package, or long-lived cross-repo edge. |
| DNS | 48 active normal direct entries at Phase 108 → 47 at Phase 109; `synvoid-platform` removed after zero source references; expanded tree 864 → 853 lines | One unused edge removed, no source LOC or active transitive subtree removed, no performance/binary-size claim. Six required SynVoid siblings plus optional mesh remain. |
| Mesh | No direct dependency edge, crate, module, or LOC removed in Phase 110 | Consensus/DHT remain within `synvoid-mesh`; protocol rustdoc clarifies wire/API versioning and replay assumptions. Existing app/service edges are live in adapters and dispatch. |
| Tunnel / Eggstack | No dependency, wire protocol, runtime code, or repository changed in Phase 111 | Eggtunnel was unavailable for parity inspection; Eggress relay/QUIC is proxy transport and does not prove tunnel-session equivalence. No fork/repo added. |
| Default/minimal feature graphs | No feature declaration changed by Phases 105–111. Phase 109 removes one manifest edge; Phase 110–111 documentation-only | Existing reduced-feature fail-closed behavior remains. Phase 112 final profile matrix completed via `verify-full` (minimal profile tests plus all configured feature profile checks passed). |
| New external packages | None added by Phases 105–111. Hickory updates were lockfile version selection within existing dependencies. | No added repository-release coordination. |

No measured maintenance reduction is attributed to moved files alone. Hickory's five bounded same-host benches in Phase 105 found no repeatable material regression; no new comparable transport, mesh, or honeypot benchmark fixture was run in Phases 106–111. This is an evidence gap, not a zero-regression claim.

## Domain decisions

### Honeypot — CLOSED DEFER

Phase 106's package boundary is application-neutral and has zero normal SynVoid dependencies. Phase 107 passed `cargo package`, non-uploading `cargo publish --dry-run`, a packaged-tarball consumer test outside the workspace, 207 crate tests, and `cargo xtask verify-release` (14/14). Independent extraction remains DEFER: no MSRV/support or semver contract, versioned storage schema, hard input/queue ceilings, deliberate DB permission/encryption policy, parser fuzz/property campaign, multi-target native proof, or second production consumer. The detailed blockers and threat model are in `architecture/honeypot_standalone_qualification_phase107.md`. No publish or repository move occurred.

### DNS — CLOSED DEFER

Hickory 0.26.3 is qualified. Message parsing and ordinary resolver/recursor mechanics already use Hickory; remaining custom server, transport, policy, cache and custody code lacks parity evidence for removal. Phase 109 removed the dead platform edge but DNS still depends on config, core, TLS, GeoIP, utils, DNSSEC keystore, and optional mesh. A runtime-config owner, neutral TLS/Geo/mesh/lifecycle seams and a standalone consumer remain prerequisites. No external repo or publication occurred.

### ICMP — RETAIN; one trigger newly satisfied

The Linux nftables native trigger is satisfied by Phase 95's exact-SHA hosted proof, run `36335520434`, with two deterministic 8/8 privileged matrix passes on proof SHA `39bfced25d51267ee5837eaecedae7da9af163d0`. Current support tiers: Linux nftables supported; Linux eBPF and macOS/FreeBSD/OpenBSD PF experimental; Windows WFP and Windows Firewall compile-only; NetBSD unsupported. No second independent production consumer exists. MSRV, semver/support docs, examples, and optional observability remain hygiene gaps. Phase 88's RETAIN disposition remains; no ICMP extraction/promotion plan is unblocked.

### Process sandbox — DEFER

The production guarantee consumer is `synvoid-jail-runtime`; other paths are an upload directory-isolation helper and tests, not a second independent consumer of the guarantee contract. Current native support remains Linux Landlock plus receipt-backed seccomp guarantees; BSD paths are experimental, macOS Seatbelt is experimental/deprecated, and Windows is process limits only with strict filesystem isolation failing closed. No independent BSD native evidence or Windows launch AppContainer boundary was found in the repository record.

| Guarantee vocabulary from SynVoid | SynVoid guarantee contract | Birdcage | `skarn-sandbox` 1.0.1 |
|---|---|---|---|
| Ambient filesystem denial | Required request; Landlock supported on Linux; platform limits are explicit | Filesystem restrictions; Linux namespaces/macOS Seatbelt | `fs_read`/`fs_read_write` allowlists plus system-read policy |
| Read/write allowlists | Typed path rules; unsupported vectors fail closed where backend cannot enforce | Filesystem exceptions | Separate read and read/write path sets |
| Explicit deny | Unsupported or typed fail-closed where backend cannot represent deny-overrides | No equivalent guarantee report model established in reviewed API | `fs_deny_read` paths |
| Inherited resources and IPC | `PreopenedResource`; jail stdio IPC captured before entry and retained | No SynVoid jail IPC equivalent | Worker execution model; app must arrange inherited resources |
| Network denial | Explicit required/optional guarantee with seccomp receipt on Linux | Network restriction supported | `NetPolicy` / network policy |
| Child creation and exec denial | Explicit per-guarantee seccomp categories on Linux; unsupported means failure | No process syscall controls advertised | Worker is born sandboxed, but equivalent caller-selectable denial contract not established here |
| Descendant confinement | Explicit guarantee and retained entry witness | No guarantee evidence contract equivalent established | Restrictions persist across exec; broader descendant proof not assessed |
| Process/job memory bounds | Linux/macOS resource capability declarations are backend-specific; Windows Job Object limits are supported, strict filesystem guarantees are not | Not a primary advertised feature | Windows AppContainer + Job Object; backend maturity is stated as lower |
| Owner termination | Jail parent owns child lifecycle and kills/tears down on failure/shutdown | Application-owned child | Worker/CLI lifecycle is separate from portable policy |
| Required vs optional | `Guarantee::{Required,Optional}` and `require_all`; unsupported required request rejects entry | Restrictions are configured as exceptions rather than per-guarantee requirements | `fail_closed` is policy-level; does not mirror per-guarantee requirement selection |
| Enforcement report/evidence | `EnforcementReport` records actual applied capability; `EnteredSandbox` is retained evidence | No comparable receipt-backed applied-guarantee report documented | `RestrictionReport` reports restriction status, but SynVoid's retained witness and jail contract differ |

This is an API/semantics comparison, not a claim that every SynVoid platform
backend is more secure. Birdcage source: <https://github.com/phylum-dev/birdcage>
(archived 2026-07-06); crate: <https://docs.rs/birdcage/0.8.1/>. Skarn source:
<https://github.com/Rani367/Skarn>; crate API:
<https://docs.rs/skarn-sandbox/1.0.1/skarn_sandbox/>.

Ecosystem comparison checked 2026-10-02: Birdcage 0.8.1 supports filesystem/network confinement on Linux/macOS and its GitHub repository was archived 2026-07-06. `skarn-sandbox` 1.0.1 (Rust 1.95) exposes filesystem read/read-write/exec/deny rules, network policy, fail-closed policy and restriction reports across macOS Seatbelt, Linux Landlock+seccomp and Windows AppContainer; its project describes Windows as least exercised. These are close alternatives, but do not replace SynVoid's caller-selected required/optional guarantee set, prepare/enter staging, retained `EnteredSandbox` evidence witness, preopened/inherited jail IPC contract, and explicit descendant/owner lifecycle semantics. The contract is meaningfully specialized; this alone does not clear the second-consumer and native-platform triggers. Keep DEFER and do not extract.

### YARA — DEFER

Official [YARA-X 1.21.0](https://github.com/VirusTotal/yara-x/releases/tag/v1.21.0) is the latest release as of 2026-10-02 (published 2026-09-29). Its published manifest resolves Wasmtime `45.0.3`; the lockfile uses the in-tree manifest-only YARA-X 1.20.0 fork with Wasmtime 48.0.3 to satisfy RUSTSEC-2026-0315/-0316 and the current feature-specific advisory gate. `synvoid-yara` remains the sole `yara-x` production consumer; Eggsec has no dependency or source use of its scanner/compiler/artifact/executor API. No source deserializers or compiled-artifact loading were introduced. Retain the fork and DEFER repository extraction until a clean official Wasmtime resolution and a second real API consumer both exist. `cargo audit` reported no vulnerability failure; six repository-allowed unmaintained-crate warnings remain.

### Mesh — RETAIN INTERNAL

No aggregate external repository exists or was created. The binding authority contract remains `architecture/distributed_state_contract.md`; canonical writes still require Raft quorum, and DHT/advisory state cannot become canonical trust. Phase 110's ownership evidence and future narrowing gate are in `architecture/mesh_boundary_decomposition_phase110.md`. No new crate qualifies before transport dispatch and config/identity capabilities become narrow one-way seams.

### Tunnel — DEFER

The available Eggress checkout supplied generic byte relay and proxy/H3 transport evidence. Eggtunnel source was absent; authenticated session, registration, wire-version, drain, and peer-auth parity could not be established. SynVoid retains existing tunnel, VPN, datagram, TUN/WireGuard, route and mesh semantics. Phase 111's matrix is in `architecture/tunnel_convergence_phase111.md`; no upstream or local implementation changes were made.

## Future plan status

Phases 105–112 are formally closed (CLOSED QUALIFIED campaign; see Proof and scope above). Phase 112 was unblocked by Phase 111's closeout and is now closed. No further extraction or upstream-adoption plan is unblocked: honeypot, DNS, ICMP, sandbox, YARA, mesh and tunnel each retain a concrete trigger listed above. Reopen only through a scoped plan when its trigger is evidenced; no blocked plan was silently promoted. Post-closeout Phase 113 (documentation/evidence reconciliation) is ACTIVE / READY; Phase 114 (tunnel/Eggtunnel evidence refresh) is PLANNED / READY AFTER PHASE 113. Neither reopens the qualified implementation, and neither authorizes extraction or adoption.

## Verification and residuals

Local Phase 110 proof: `cargo fmt --all -- --check`; `cargo test -p synvoid-mesh-protocol --profile ci` (8 tests); `cargo test -p synvoid-mesh --profile ci` (1,093 tests); `cargo check --no-default-features --features mesh --profile ci`; `cargo check --no-default-features --features mesh,dns --profile ci`; `cargo deny check`; `cargo audit` (six allowed unmaintained warnings, no vulnerability failure). Final-head routine/full/release verification and focused Phase 112 package lanes are complete and recorded below (Phase 113 reconciliation; proof-bearing implementation SHA unchanged).

| Verification | Terminal evidence |
| --- | --- |
| `cargo fmt --all -- --check` | Passed on proof-bearing tree |
| `cargo xtask verify` | 10/10 passed |
| `cargo xtask verify-full` | 10/10 passed; 7,896 tests across 217 binaries, 8 skipped |
| `cargo xtask verify-release` | 14/14 passed |
| `cargo deny check` | Passed |
| `cargo audit` | No vulnerabilities; six accepted unmaintained warnings |
| hosted `ci` + `dependency-security` | Run `36955732943` passed on `e7c0ec5a1317599b6f98e37a534b53544842a29c` |

Hosted native sandbox and ICMP jobs were skipped by workflow conditions; no native qualification claim is made here. Phase 112 made no new native qualification claim.

Accepted residuals: no cross-platform tunnel migration or benchmark claim; DNS and honeypot remain in workspace; current native evidence is platform-scoped; tunnel parity/adoption remained deferred by Phase 111; independent package support gates remain open. These residuals are captured as explicit DEFER/RETAIN decisions rather than extraction success. Phase 114 separately reopens the research evidence for tunnel convergence; it does not retroactively make Phase 112's tested source state unqualified.
