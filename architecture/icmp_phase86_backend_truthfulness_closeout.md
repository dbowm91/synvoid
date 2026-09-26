# Phase 86 Closeout: ICMP Backend, Platform, and Privilege Truthfulness

Status: closed 2026-09-26.

Planning baseline: `81638c251592913579bd9bbce51d013c44d67910`.
Implementation SHA: `f1be64d6e873fcaf0ff6a61a1eb18caaf29c9d87`
(built on Phase 85 closeout `87757ac7`).

Plan: `plans/phase_86_icmp_backend_platform_and_privilege_truthfulness.md`.
Roadmap: `plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

## Decision

Outcome A: WFP is the primary supported Windows lane; the Windows
Firewall COM lane is retained as a documented compatibility fallback
(Defender/GPO visibility; no transactions, no rate limiting, no
readback). Every retained backend feature has a complete declared
dependency path; explicit backend requests are strict; NetBSD is out of
the PF lane.

## Workstream dispositions

- **A (feature/dependency graph):** `icmp-wfp = ["dep:wfp",
  "dep:windows-sys"]`, `icmp-winfw = ["dep:windows_firewall"]`, all
  target-gated under `[target.'cfg(windows)'.dependencies]` (`wfp` 0.2
  mullvad MIT/Apache, `windows_firewall` 0.8 MIT/Apache, `windows-sys`
  0.59 matching the workspace standard with
  `Win32_Foundation/Security/NetworkManagement_IpHelper/Ndis/Networking_WinSock`).
  Root `icmp-filter` intentionally forwards **no** backend sub-features;
  eBPF stays opt-in (`aya` optional, never default). `cargo deny check`
  passes with the new edges.
- **B (Windows ownership):** both lanes rewritten against verified
  current APIs (wfp 0.2 typed builders + `FilterWeight::Exact` ordering +
  `Transaction`; windows_firewall 0.8 `FirewallRule` builder + getset
  setters + `remove_rule`). The pre-existing code never compiled (missing
  manifest deps, nonexistent `InterfaceSpec::names()` /
  `Condition::new` / `ConditionField::InterfaceIndex`, a 0.2-era
  `windows_firewall` API, and a `&mut self`/config borrow that only
  compiled nowhere). Real LUID resolution
  (`platform::resolve_interface_luid`: numeric→index→LUID,
  names→alias→LUID, hard error otherwise); dead `interface_name_to_alias`
  stub removed; `get_network_interfaces` enumerates via
  `GetAdaptersAddresses`. Exemption precedence is explicit weights
  (exempt > type rules > base block). WFP/WinFW constructors reject
  rate-limited policy via `check_policy_compatibility` (never claim rate
  limiting). `cargo check --target x86_64-pc-windows-msvc/gnu --features
  icmp-wfp,icmp-winfw` (incl. `--tests`) is clean — recorded as compile
  evidence only, not runtime qualification.
- **C (Linux probes):** `probe_nftables()` (root/`CAP_NET_ADMIN`, never
  BPF sysctls), `probe_ebpf_load()` (`CAP_BPF`/root; BTF = mechanism;
  sysctl = diagnostic context), `probe_ebpf_attach()`
  (`CAP_NET_ADMIN`/root); `BackendProbe { compiled, mechanism_present,
  privilege, usable, reason }`. Pure `parse_cap_eff_*`/`cap_is_set`
  helpers are fixture-tested. `is_admin()` no longer reads the BPF
  sysctl. `BindLowPort`/`LowPortBinding`/`can_bind_low_ports` removed
  from the ICMP vocabulary (no ICMP backend requires low-port binding;
  no in-repo callers).
- **D (capability vs runtime):** `BackendCapabilities` is static
  expressiveness only (`supports_rate_limit_global`,
  `supports_code_matching`, `interface_requires_index`,
  `supports_transactions` added; `requires_admin`/`is_enforcing`
  deleted). `check_policy_compatibility(backend, &IcmpPolicy)` evaluates
  `PolicyRequirements` exactly; mismatches are typed, never downgraded.
- **E (strict selection):** `select_backend_for_host` returns
  `SelectionReport { backend, requested, reason }`. Explicit requests
  fail (`BackendUnavailable` + probe detail, `FeatureNotEnabled`,
  wrong-platform `Config`); the eBPF→nftables and WFP→winfw silent
  fallbacks are deleted. `Auto` order is documented (Linux eBPF-if-usable
  else nftables baseline; Windows WFP else winfw; macOS/BSD single PF
  lane) and always logged/returned. All `create_filter` lanes route
  through it.
- **F (BSD):** NetBSD removed from every PF cfg; `PfBsdFilter` tracks
  FreeBSD/OpenBSD only; NetBSD (and unknown targets) compile to
  `UnsupportedPlatform` whose message names NPF
  (https://man.netbsd.org/npf.7) as the future trigger. No NPF
  implementation added (out of scope per plan).
- **G (docs):** `architecture/icmp_filter.md` rewritten around
  evidence tiers (`supported/experimental/compile-only/unsupported`),
  the static-vs-runtime split, probe authorities, selection contract,
  and the 87/88 handoff; `docs/FEATURE_STATUS.md` and
  `docs/PLATFORM_SUPPORT.md` carry the lane/tier table with the NetBSD
  exclusion; the `icmp_filter` skill lists canonical Phase 85/86 files
  and invariants.

## Acceptance mapping

- Complete declared dependency paths for every retained feature. ✓
- No active Windows feature references undeclared crates or nonexistent
  methods (both lanes compile on msvc+gnu targets). ✓
- nftables independent of BPF sysctls (probe + test). ✓
- eBPF privilege matches implementation (load vs attach split). ✓
- Static capability, availability/privilege, selection separated. ✓
- Explicit requests cannot silently fall back (deleted fallbacks +
  selection tests). ✓
- NetBSD out of PF (cfg scan test). ✓
- FreeBSD/OpenBSD/macOS tiered at achieved evidence. ✓
- Root forwarding matches truth (forwards none; documented). ✓

## Verification evidence (implementation head)

- `cargo fmt --all -- --check`: pass.
- `cargo test -p synvoid-icmp-filter --profile ci`: 44 lib + 5
  truthfulness + 12 canonicalization pass; also green with
  `--features icmp-pf`.
- `cargo clippy --profile ci -p synvoid-icmp-filter --all-targets --
  -D warnings`: pass (incl. Phase 85 `derivable_impls` cleanup).
- `cargo check --no-default-features --features icmp-filter
  --profile ci`: pass.
- Admin contract (`mesh,dns,icmp-filter`): 22 + 18 + 24 pass.
- `cargo xtask test guards`: 3/3 pass.
- `cargo deny check`: advisories/bans/licenses/sources ok.
- Target compile evidence (compile-only, not runtime proof):
  `x86_64-pc-windows-msvc` + `x86_64-pc-windows-gnu` with
  `icmp-wfp,icmp-winfw` (lib + `--tests`); `x86_64-unknown-linux-gnu`
  with and without `icmp-ebpf`. The Linux cross-check caught two real
  defects (uncaptured `&t` borrow, feature-ungated unused import).
- Native privileged enforcement tests: none in this phase by design;
  Phase 88 records native proof.

## Residuals / Phase 87 unblocked

- `FilterStatus { enabled, backend, config }` is still
  desired-state-biased; `is_enforcing() == enabled` is local truth only;
  packet counters are not backend evidence. Phase 87 owns receipts,
  transactions, readback/drift, and metric truthfulness.
- Windows exemption/type-rule weight ordering is designed, not natively
  proven; WFP `is_available()` is feature presence, not engine proof.
- `PfFilter`/`PfBsdFilter` grammar differences are represented
  (variant-conditional clauses) but not natively qualified per variant.
- Full `cargo xtask verify` end-to-end belongs to Phase 88 campaign
  closeout.
