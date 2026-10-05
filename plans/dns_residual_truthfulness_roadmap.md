# DNS Residual Truthfulness Roadmap — Phases 137–140

Status: **REGISTERED** (2026-10-05). Not started.

Predecessor: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`
(**CLOSED QUALIFIED**). That campaign closed with six residuals it deliberately
left unregistered. This campaign is the registered successor for four of them,
re-scoped against a code audit rather than carried forward from the closeout
wording.

Registered in: `plans/roadmap.md`.

## Why this campaign re-scopes rather than carries forward

An audit of the six residuals against the code on 2026-10-05 found that
**three of the closeout's problem statements are wrong**, in ways that would
cause the registered work to be built incorrectly:

| Residual | What the closeout says | What the code shows |
|---|---|---|
| F-6 ALPN | "no ALPN is configured anywhere"; affects DoT/DoH/DoQ | **DoQ already sets `doq` ALPN** (`crates/synvoid-dns/src/doq.rs:72`). Scope is DoT + DoH, which **share one builder** needing *different* values (`secure_server.rs:55-65`), so this changes a signature, not a list. |
| F-17 GeoIP | "adapter written and ready"; composition-only | `crates/synvoid-dns/src/server/mod.rs:1871` hardcodes `let geoip_lookup = None;` and `:1884` never calls `with_country_lookup`. All three builders have **zero production callers**. Work is inside a class-1 crate. |
| mesh inversion | "8 types across DHT record storage, routing, and signed provenance" | **7 types** (the 8 is a `sort -u` path count). The `anycast_sync.rs` transport/wire cluster is omitted by that description. And **all four injection points have zero callers** — the surface is dead at runtime. |

A fifth correction: the zone-reload residual implies a runtime reload path
exists. **It does not** (see Preconditions below), so it is not a phase.

Each phase's plan carries its own correction section. Corrections are applied to
historical closeouts **by pointer only**; no historical record is rewritten.

## Phases

| Phase | Scope | Gate / dependency |
|---|---|---|
| **137** — ALPN for DoT and DoH | advertise `h2` on DoH, keep DoT and DoQ unchanged | none; **do first**, it is the cheapest and corrects a live over-claim |
| **138** — Wire `[geoip]` in composition | construct and thread a real geo provider; replace the tripwire guard | needs a startup-semantics decision (Workstream A) |
| **139** — Mesh coupling disposition and inversion | decide wire-or-delete first; invert only if wired | **gated on its own Workstream A disposition** |
| **140** — `prefer_post_quantum` truthfulness | document the setting as telemetry; optionally rename | none; smallest item |

Phases 137, 138 and 140 are independent. Phase 139 is gated internally and may
terminate at its disposition step without inverting anything.

Sequencing note: 137 before 138 is a convenience, not a dependency — both touch
DNS but neither reads the other's output. Running 138 first would leave the
F-6 "anywhere" over-claim in `architecture/dns_config_runtime_matrix.md` live a
little longer.

## Preconditions — registered, not phased

Two residuals are deliberately **not** given phases, because the audit showed
neither has a live trigger. They are recorded here so whoever builds the
triggering lane inherits the requirement rather than rediscovering it.

### P-1 — Zone activation is not atomic across a multi-zone batch

Source: Phase 132 closeout, "Two operational notes".

`load_zones_inner` (`crates/synvoid-dns/src/server/zone.rs:68-247`) inserts each
zone as it validates (`zone.rs:234-235`) and returns `Err` on the first failure,
with no rollback. A bad second entry leaves the first inserted — **and leaves it
out of the lookup index**, because `rebuild_zone_index()` (`zone.rs:238`) runs
only after full success. The Phase 132 closeout describes the first half of this
and not the second.

**No runtime reload path exists today**, which is why this is not a phase:

- the only production `load_zones` caller is startup
  (`src/server/resources.rs:167`), pinned by
  `composition_activates_configured_zones`
  (`tools/synvoid-repo-guards/tests/dns_runtime_config_ownership.rs:396`);
- `load_zones_from_store` (`zone.rs:249`) has no caller anywhere;
- `SupervisorCommand::ReloadConfig => SIGHUP`
  (`crates/synvoid-ipc/src/command.rs:171`) is skipped at stream registration
  (`crates/synvoid-platform/src/unix.rs:401`); the IPC reload that does land
  (`src/server/mod.rs:705-711`) only calls `cfg.reload_all()`, which iterates
  **site** configs (`crates/synvoid-config/src/lib.rs:240-246`);
- anycast mesh sync would insert zones at runtime
  (`crates/synvoid-dns/src/anycast_sync.rs:686`, `update_local_zone` `:864`) but
  is unwired; `architecture/worker_task_lifecycle.md:131` lists it "(unowned)".

**Requirement on whoever builds a reload lane:** make `load_zones_inner`
validate-all-then-commit. The loop already builds each `Zone` locally and
mutates shared state only at `zone.rs:235`, so this is a local reorder — no
store change, no rollback bookkeeping, and startup fail-closed behavior is
unchanged. An atomic per-zone helper already exists
(`replace_zone_with_validation`, `zone.rs:301-314`). No existing test pins the
non-atomic behavior, so only new tests are needed. The `ShardedZoneStore`
(`crates/synvoid-dns/src/server/sharded_store.rs:14-17`) has no `replace_all`
and no transaction, so a staged-apply design would need one; validate-then-commit
does not.

Optional companion guard: assert `load_zones_from_store` still has no production
caller, so drift is caught before it becomes a live partial-load path.

### P-2 — A public authoritative profile cannot be queried from loopback

Source: Phase 132 closeout, "Two operational notes".

`examples/dns/authoritative_public.toml:37-39` enables the firewall with
`block_internal_ips = true`, which installs **8** `Subnet`/`Block` rules
(`crates/synvoid-dns/src/server/mod.rs:1886-1982`), including
`127.0.0.0/8` `block_loopback` (`:1923-1933`) and `::1/128` (`:1947-1957`).
Correct for a public profile, but the failure mode is **silence** — the block is
at firewall admission, so an operator sees no SERVFAIL, just no answer.

Loopback is **not separately controllable**; it is inseparable from the 8-rule
set. A future phase reading only the Phase 132 closeout could wrongly assume a
loopback-specific knob exists.

This is a truthfulness gap, not a defect. `docs/FEATURE_STATUS.md` (119 lines)
does not mention `loopback`, `authoritative_public`, or `block_internal` at all.
The cheap correct remedy is a documentation note plus a local-verification test
that reuses the existing in-memory override at
`tests/dns_zone_startup_activation.rs:205-211` (which sets
`block_internal_ips: false`), matching the pattern already in the repo.

**Explicitly do not** add a config flag to exempt loopback: that needs a
persisted-TOML schema change and weakens a correct production posture. Note also
that `crates/synvoid-dns/src/firewall.rs:626 create_default_firewall_rules` is a
dead parallel helper with no callers, whose rule list has not been diffed
against the live 8-rule set — unverified, and worth resolving before it is
mistaken for the live path.

## Minor residuals — no phase, recorded here

- **F-11 (low)** — the mTLS "No CA certificates found for client authentication"
  branch is still dead at `crates/synvoid-tls/src/cert_resolver.rs:300-318`:
  `load_ca_certs` already returns `Err("No CA certificates found in file")` at
  `:411`, so `!ca_certs.is_empty()` cannot be false via a file that yields no
  certificates. Diagnostic-only; the reachable cases are already pinned.
- **F-3 (low)** — `GeoLocation::from_str` still cannot fail:
  `crates/synvoid-dns/src/firewall.rs:572`'s `parts.is_empty()` is unreachable
  because `"".split(',')` always yields one element. A typo silently produces a
  never-matching rule. Fold into Phase 138 if that phase already touches
  `firewall.rs`; otherwise it is a standalone low-severity item.
- **131 F-3 (residual)** — two `#[ignore]`d Eggbench live-proof suites still
  predict ports. Unchanged and untestable here; the origin/metrics listeners
  could bind `:0` and read the port back, but the `listen_port` passed to the
  external binary as an argument cannot be fixed that way.

## Binding constraints for this campaign

- no provider trait implemented inside `synvoid-dns`; providers stay in
  composition roots;
- no trait signature may name a `synvoid-mesh`, `synvoid-tls`, or `synvoid-geoip`
  type;
- no persisted TOML, OpenAPI, or admin schema change without a separate
  explicit decision;
- no class, support, promotion, or publication claim. `synvoid-dns` remains
  **class 1**; inverting mesh does not by itself qualify it, because the edge is
  `optional` (see F-18 in the Phase 136 closeout);
- `architecture/distributed_state_contract.md` remains binding: DHT is never
  policy authority or a fallback, and `MeshMessage` protobufs remain in
  `synvoid-mesh`;
- every claim corrected from a closeout is corrected **by pointer**, and every
  skipped verification lane is recorded as not-run with its reason.
