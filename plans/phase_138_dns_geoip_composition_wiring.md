# Phase 138 Plan: Wire `[geoip]` in Composition

Status: **REGISTERED** (2026-10-05). Not started.

Campaign: `plans/dns_residual_truthfulness_roadmap.md` (REGISTERED).
Predecessor: Phase 137. Source campaign:
`plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`
(CLOSED QUALIFIED). Registered in: `plans/roadmap.md`.

Source residual: Phase 135 **F-17**, recorded not fixed in
`architecture/dns_provider_inversion_phase135_closeout.md` and carried in
`architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md` §
"Residual work this campaign deliberately left" item 2.

## Correction to the registered problem statement

Phase 136 and the campaign closeout describe F-17 as: no composition path
constructs a `GeoIpManager`, so every `geoip:` field in root is `None`. That is
accurate. But the Phase 135 closeout also describes the adapter as "written and
ready", and **that is incomplete in a way that changes the scope.**

The gap is not only in composition. It is inside `synvoid-dns` itself:

- `crates/synvoid-dns/src/server/mod.rs:1871` — `let geoip_lookup = None;` is
  **hardcoded** in `DnsServer::new`.
- `crates/synvoid-dns/src/server/mod.rs:1884` — `DnsFirewall::new()` is never
  given `.with_country_lookup(...)`.
- `firewall.rs:48` is a **separate field** from `DnsServer::geoip_lookup`
  (`mod.rs:1646`), so setting one does not set the other.

All three `with_country_lookup` builders — `firewall.rs:89`,
`server/zone.rs:460`, `mesh_sync/registry.rs:64` — have **zero production
callers**. The only call site anywhere in the tree is
`crates/synvoid-dns/tests/geoip_rule_evidence.rs:245`.

So this phase edits a class-1 crate, not just a composition root. The Phase 136
statement that Phase 135 left "a tripwire guard [making it] impossible to do by
accident" is true but does not imply the work is composition-only.

## The silent-allow trap

Wiring without a database would **regress the fail-closed posture Phase 135
established.** The mechanism:

- `GeoLocation::matches_ip` maps a **present-but-answerless** provider to
  `GeoMatch::No`, not `Unavailable` (`crates/synvoid-dns/src/firewall.rs:483-489`).
  `Unavailable` is produced only when `country_lookup` is `None`
  (`firewall.rs:479-481`).
- A `GeoMatch::No` means "the provider answered: this address is not in the
  block set", so a restrictive rule does not apply.
- The once-per-firewall warning at `firewall.rs:270` keys on
  `RuleIndeterminate::NoCountryLookup`, which a **present** provider never
  produces — so the operator gets **no diagnostic at all**.

Net effect: `[geoip] enabled = true` with `database_path` unset, plus a
restrictive geo rule, would block all traffic today (correct, loud) and
silently allow all traffic after a naive wiring (incorrect, silent). This phase
must not ship that.

`src/geo/dns_provider.rs:72-75` and `:114-116` already warn about exactly this
in code comments, and `crates/synvoid-geoip/src/lookup.rs:19-21` makes a path
typo indistinguishable from "no database" (a non-existent path returns
`Ok(reader: None)`).

## Goal

Make a configured `[geoip]` section actually evaluate GeoLocation rules, with
startup semantics that stay fail-closed and loud when the database is absent.

## Workstream A — decide startup semantics when the database is missing

This is the phase's first decision, because it determines Workstreams B and C.

Options:

1. **`[geoip] enabled = true` with no usable database → refuse to start.**
   Precedent exists in the same function: `src/server/resources.rs:155-174`
   fails closed on an unactivatable zone, with the rationale at `:161-166`
   ("Serving authoritative DNS without it is worse than refusing to start").
   The closer analogue for a *degradable artifact* is
   `crates/synvoid-auth/src/lib.rs:168-173` — `try_new` returns `Ok` for a
   missing store but `Err` when present-and-unreadable, "so a truncated/corrupt
   authorization database can never silently become an empty one."
2. **Distinguish "no database configured" from "database unreadable"**: fail
   only on the latter, and treat the former as absent-provider. This keeps the
   Phase 135 fail-closed posture (no provider → `Unavailable` → restrictive
   rule applies) but means an operator who enables `[geoip]` without a path
   blocks all traffic. Defensible, but must be documented, not silent.
3. **Load the database before accepting config**, failing closed on any error.

Record the choice and its operator-visible consequence. Whichever is chosen, the
Phase 135 fail-closed rule must still hold: a restrictive geo rule that cannot
be evaluated applies its action.

## Workstream B — thread the lookup inside `synvoid-dns`

- replace `let geoip_lookup = None;` (`server/mod.rs:1871`) with a real
  `Option<Arc<dyn CountryLookup>>` parameter on the construction path;
- pass the same handle to `DnsFirewall::new().with_country_lookup(...)` at
  `:1884`, or make the firewall read the server's field — decide and record
  which, noting the two are currently **separate fields**;
- wire `server/zone.rs:460` and `mesh_sync/registry.rs:64` if the construction
  path uses them.

`DnsServer::new(DnsRuntimeConfig, CertResolver)` is the canonical construction
path. Adding a third parameter changes a public signature in a class-1 crate;
record that and check `architecture/dns_config_runtime_matrix.md` plus the
`dns_runtime_config_ownership` guard in
`tools/synvoid-repo-guards/tests/dns_runtime_config_ownership.rs` for whether a
`DnsRuntimeConfig` field addition is required instead.

## Workstream C — construct the provider in composition

- implement `CountryLookup` over `Arc<GeoIpManager>` at
  `src/geo/dns_provider.rs` — `as_country_lookup` (`:76-80`) and
  `database_loaded()` (`:50-52`) already exist;
- construct `GeoIpManager` from `synvoid_config::geoip::GeoIpConfig`
  (`crates/synvoid-config/src/geoip.rs:5-50`). Only `enabled` gates
  construction (`crates/synvoid-geoip/src/manager.rs:42-44`); no download
  credentials are required after the Phase 135 `unwrap` fix
  (`crates/synvoid-geoip/src/updater.rs:153-173`);
- `GeoIpManager::new` is cheap and I/O-light (one synchronous open/mmap, no
  spawned task; `start_auto_update` is a separate call), so this does not
  change startup latency materially.

## Workstream D — update the tripwire guard

`tools/synvoid-repo-guards/tests/dns_dependency_edges.rs:582-613`
(`geoip_provider_is_still_unwired_by_composition`) **must be deleted, not
weakened.** Its own assert message at `:611-612` says: "delete this gate in that
phase rather than weakening it here."

Two properties of the current gate must be recorded before deletion, because
they are wrong in the closeout's description:

- it is **substring-based**, not semantic — it flags any line under `src/`
  outside `src/geo/` containing `GeoIpManager::new(`. A `type G = GeoIpManager;`
  plus `G::new(...)` would not trip it. The Phase 136 claim that wiring is
  "impossible by accident" overstates the mechanism.
- the Phase 135 closeout says it fails on any "**non-test** root file". The
  implementation has **no `#[cfg(test)]` awareness** — it only skips lines whose
  `trim_start` begins with `//`. An in-file test module outside `src/geo/` would
  trip it.

Add a replacement gate that pins the **positive** invariant instead: composition
constructs a geo provider and threads it into the DNS construction path.

## Workstream E — evidence

- positive: a configured `[geoip]` with a real database evaluates a
  GeoLocation rule correctly (already covered by
  `crates/synvoid-geoip/tests/geoip_provider_evidence.rs` with a hand-written
  MMDB; add a `synvoid-dns` in-crate case using the DNS-owned double);
- positive: a wired-but-database-less provider does **not** silently allow a
  restrictive rule — assert whichever semantics Workstream A chose, including
  the diagnostic;
- the Phase 135 `GeoMatch::{Yes,No,Unavailable}` matrix stays green;
- the tripwire guard is replaced, not deleted outright.

## Workstream F — operator-visible change

Wiring GeoIP **activates two previously-dead paths**: geo-A-record steering
(`crates/synvoid-dns/src/query.rs:884-886`) and mesh edge geo derivation
(`mesh_sync/registry.rs:69-70`). These become live for the first time. Record
both in the closeout as activated, not as unchanged.

## Workstream G — documentation

- `architecture/dns.md`, `architecture/dns_config_runtime_matrix.md`;
- correct the F-17 row in
  `architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md`
  and `architecture/dns_provider_inversion_phase135_closeout.md` **by pointer**;
- `docs/FEATURE_STATUS.md` — it currently does not mention `[geoip]` at all;
- `AGENTS.md`, whose geo-firewall posture paragraph describes the current
  block-everything consequence and must be restated.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-geoip --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo check --features dns
cargo deny check
cargo audit
cargo xtask verify
```

## Acceptance criteria

- a configured `[geoip]` provider is constructed in composition and reaches both
  `DnsServer` and `DnsFirewall`;
- the chosen Workstream A semantics hold, and a restrictive geo rule that cannot
  be evaluated still applies its action;
- a wired-but-database-less provider produces a **diagnostic**, not silence;
- the tripwire guard is replaced by a positive gate;
- `docs/FEATURE_STATUS.md` and `AGENTS.md` describe the real behavior.

## Rejection criteria

Reject a closeout that:

- weakens or keeps the tripwire guard instead of deleting it;
- implements `CountryLookup` inside `synvoid-dns` (providers stay in
  composition);
- wires the provider such that a missing database silently allows a restrictive
  rule;
- claims the phase was composition-only without recording the
  `server/mod.rs:1871` and `:1884` changes;
- makes a persisted TOML, OpenAPI, or admin schema change without a separate
  explicit decision;
- omits the two newly activated paths (geo A-record steering, mesh edge geo
  derivation) from the operator-visible change record.

## Closeout

`architecture/dns_provider_inversion_phase138_closeout.md`.
