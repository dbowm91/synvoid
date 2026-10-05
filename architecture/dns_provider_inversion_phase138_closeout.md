# Phase 138 Closeout: Wire `[geoip]` in Composition

Date: 2026-10-05
Plan: `plans/phase_138_dns_geoip_composition_wiring.md`
Campaign: `plans/dns_residual_truthfulness_roadmap.md` (ACTIVE)
Predecessor: Phase 137 (`architecture/dns_provider_inversion_phase137_closeout.md`)
Residual source: Phase 135 **F-17**
Disposition: **CLOSED QUALIFIED** — and narrower than its plan, with an
explicitly authorised schema change inside it

## The headline

`[geoip]` is a real configuration section and composition builds a geo provider
from it. The DNS-owned `CountryLookup` capability now reaches both of its
consumers. **The phase is "wired, not yet load-bearing"**: no DNS firewall rule
can be declared, so nothing consumes the capability at runtime.

## Two findings that reshaped the phase

Both were found during implementation, and both would have caused the phase to be
built wrong if the plan had been followed literally.

### 1. `[geoip]` was not a configuration section at all

`GeoIpConfig` and `SiteGeoipConfig` are declared and exported by
`synvoid-config`, and `synvoid-geoip`'s `new` accepts both — but **no
configuration struct owned a `geoip` field**. `MainConfig` had none;
`SiteSecurityConfig` had none. A case-insensitive search of the whole config
crate for `geoip` returns only the two type definitions, the module declaration,
and two re-export lines. The only `geo` fields in the crate are `Option<String>`
peer and anycast location labels (`mesh.rs:204,337`, `dns_anycast.rs:38`).

So Workstream C's instruction — construct the manager "from
`synvoid_config::geoip::GeoIpConfig`" — had nothing to read, and the plan's own
rejection criteria (no persisted TOML change without separate authorization) were
in direct conflict with completing the phase.

**This was surfaced to the user rather than decided unilaterally**, and adding
`#[serde(default)] pub geoip: GeoIpConfig` to `MainConfig` was explicitly
authorized. It is additive: `enabled` defaults to `false`, so every existing
configuration parses unchanged and no deployment starts constructing a provider.
A site-level section was **not** authorized and is left as residual work.

This is a worse state than "declared but unowned": the type looks configurable,
so an operator can write `[geoip]` and observe no effect and no diagnostic.

### 2. No DNS firewall rule can be declared, so the phase's central risk is unreachable

The plan's motivating hazard — that naive wiring would convert a fail-closed
block into a **silent allow** — requires a `GeoLocation` firewall rule. None can
exist:

| Link | Reality |
|---|---|
| `DnsFirewallConfig` (`crates/synvoid-config/src/dns/dns_firewall.rs:139-157`) | fields are `enabled`, `default_action`, `block_internal_ips`, `block_zone_transfers`, `max_rules`, `rebinding_protection` — **no `rules`** |
| `firewall_runtime` adapter (`src/server/dns_runtime_config.rs:253-259`) | projects only `enabled` and the two booleans |
| `DnsFirewallRuleType::GeoLocation` | zero hits in `synvoid-config`; built only in `synvoid-dns` and one test |
| `.add_rule(` call sites repo-wide | 9, all the hardcoded `Subnet`/`Block` block inside `DnsServer::new`; 2 unrelated in `synvoid-platform` |
| admin/runtime rule injection | none — `src/admin/` has no firewall mutation |

Two consequences:

- The silent-allow trap is **not currently reachable**, which is why this phase
  could ship without the loud-failure machinery Workstream E contemplated.
- `AGENTS.md`, `architecture/dns.md`, and the Phase 135 closeout all stated that
  a configured restrictive geo rule "blocks all DNS traffic". That consequence
  was **unreachable** — the antecedent does not exist. All three are corrected.

## What changed

| File | Change |
|---|---|
| `crates/synvoid-config/src/main_config.rs` | `pub geoip: GeoIpConfig` (`#[serde(default)]`), plus the manual `default_config` entry |
| `src/geo/dns_provider.rs` | new `country_lookup_from_config`, the single place persisted `[geoip]` becomes a DNS capability |
| `src/geo/mod.rs` | re-export |
| `src/server/resources.rs` | builds the capability and passes it to `DnsServer::new` |
| `crates/synvoid-dns/src/server/mod.rs` | `DnsServer::new` takes `country_lookup`; the hardcoded `let geoip_lookup = None;` is gone; the firewall gets the same handle |
| `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` | tripwire **deleted**, positive gate installed |

### Why a constructor parameter, not a builder

`cert_resolver` is already injected as a `new` parameter, so the pattern exists.
A builder (`with_country_lookup`) would have left `let geoip_lookup = None;` in
place as the default — which is the exact shape of the dead seam this phase
removes, and a `new` call that forgot the builder would silently have no lookup.
A required parameter makes forgetting impossible.

### The two fields were separate, and now cannot drift

`DnsFirewall::country_lookup` and `DnsServer::geoip_lookup` are different fields,
so setting one does not set the other. The constructor wires both from the same
handle, and `can_evaluate_geo_rules()` is what pins it.

## Workstream A resolved: warn, do not refuse

The plan made startup semantics the first decision. It was not, for the reason
above — the question governs behavior no configuration can reach. Within that
constraint, the phase chose **not to refuse to start**, for two evidence-based
reasons:

1. **The information needed to fail has already been discarded.**
   `GeoIpManager::new` returns `Option` and **never reports a load failure**: an
   unparseable database yields a manager with no reader plus a `warn!`
   (`crates/synvoid-geoip/src/manager.rs:48-58`). `GeoIpLookup::new` returns
   `Ok(reader: None)` for a non-existent path
   (`crates/synvoid-geoip/src/lookup.rs:19-22`). Composition therefore cannot
   distinguish "no path configured" from "path typo" from "corrupt database", so a
   refusal would have to reject all three.
2. **A refusal would be unobservable and harmful.** No DNS geo rule can be
   declared, so refusing startup over a section nothing reads would break a
   currently-harmless configuration for no benefit.

The phase warns instead, via the pre-existing `database_loaded()`. The auth
precedent (`AuthManager::try_new` fails on present-but-unreadable) remains the
right model — but it is **unreachable** until `synvoid-geoip` surfaces load
failures, which is carried forward as a precondition.

## The deleted tripwire was weaker than described

The plan recorded two properties; implementation found a third.

1. **Substring-based, not semantic** — a `type G = GeoIpManager;` plus `G::new(...)`
   would not trip it.
2. **No `#[cfg(test)]` awareness** — it only skipped `//` lines, so an in-file
   test module outside `src/geo/` *would* trip it, while the Phase 135 closeout
   claimed it failed only on "non-test" files.
3. **It exempted `src/geo/` entirely** (new) — the module where the construction
   naturally belongs. So it would not have fired even for a legitimate wiring; it
   only prevented construction *outside* the adapter.

Deleted, as its own assert message instructed. The Phase 136 claim that wiring was
"impossible by accident" overstated the mechanism.

## The replacement gate, and proof it can fail

`geoip_capability_is_wired_through_composition` pins the **positive** invariant:
the provider is constructed from config, composition passes it, `MainConfig` owns
the field, and `synvoid-dns` neither hardcodes `None` nor omits the firewall
wiring. A gate that only checks an absence cannot notice when the thing it
forbade becomes the thing that is required.

Mutation-tested, three regressions, each caught:

| Mutation | Result |
|---|---|
| composition passes `None` again (F-17 returns) | FAILED |
| `MainConfig` loses the `geoip` field | FAILED — "must own a `geoip: GeoIpConfig` field" |
| DNS re-hardcodes `let geoip_lookup = None;` | FAILED — "must not hardcode" |

Tree restored and the gate re-run clean after each.

## Evidence

**`crates/synvoid-dns/tests/geoip_composition_wiring.rs`** (5, all passing) — the
seam. Injected handle reaches the server field; reaches the firewall's separate
field; stays `None` when not injected; independent of the firewall being enabled;
preserved across a `DnsServer` clone. The module doc states plainly that it does
*not* claim a geo rule can be evaluated in production, and lists the evidence.

**`crates/synvoid-config/tests/geoip_config_schema.rs`** (5, all passing) — the
configuration source. `MainConfig` serializes a `[geoip]` table and parses it back;
a configured section reaches the struct intact; an absent section defaults to
disabled; the hand-written `Default` agrees with every serde default; the field
survives the admin `GET`/`PUT` JSON round trip.

That last one guards a real hazard: `GeoIpConfig` is safe **only because it has a
hand-written `Default`**. A derived one would make `log_blocked` `false` in Rust
and `true` in serde — the exact defect `architecture/dns_config_runtime_matrix.md`
records for `DnsFirewallConfig`.

The fixtures derive from `MainConfig::default()` rather than hand-written TOML,
because `MainConfig` has required fields (`server`, which requires `host`/`port`;
`fallback`) whose absence would make a minimal document brittle for reasons
unrelated to `[geoip]`.

**`src/geo/dns_provider.rs`** unit tests (3 new, all passing) — the construction
path. A disabled section yields no capability even with a path set; an enabled
section with no database still constructs a provider that answers `None`; and a
path typo is recorded as **indistinguishable** from no path, which is the
limitation that forced the warn-don't-refuse decision.

## API-visible consequence

Adding the field changes one response body: admin `GET /config/main` serializes the
whole `MainConfig` into a `serde_json::Value`, so the JSON now contains a
`geoip` key. **No typed OpenAPI schema changes** — the response DTO is
`serde_json::Value`, not a typed object. `PUT /config/main` deserializes into
`MainConfig` with `#[serde(default)]`, so a client that PUTs a config it built
without `geoip` still succeeds. A GET-then-PUT round trip preserves the section,
which is the point.

## Dependency measurement

Re-measured, not carried forward. This phase added **no dependency** — it added
a persisted *field* to an existing type, and `synvoid-config` was already a root
dependency.

```
$ cargo metadata --format-version 1 --no-deps   # synvoid-dns direct synvoid deps
['synvoid-dnssec-keystore', 'synvoid-mesh']
```

| Measure | Phase 137 | Phase 138 | Delta |
|---|---|---|---|
| Direct SynVoid normal edges | 2 | **2** | none |
| Expanded `cargo tree -e normal` lines (default) | 552 | **552** | none |
| Expanded `cargo tree -e normal` lines (`--features mesh`) | 2047 | **2047** | none |

`synvoid-dns` still has **no `synvoid-geoip` edge** — the capability is injected,
not linked. The guard `synvoid_dns_has_no_geoip_edge` still passes, and
`synvoid-dns` remains **class 1**.

## The entitlement ledger had to be extended, and that is the guard working

`root_dependencies_have_path_entitlement` failed on the first full run:

```
synvoid-config: consumed from src/geo outside ledger allowlist
tracing:        consumed from src/geo outside ledger allowlist
```

This phase was the **first** non-test consumer of either dependency from
`src/geo/` — before it, `src/geo/dns_provider.rs` referenced `synvoid_config`
only inside its `#[cfg(test)]` module, and never used `tracing`. Both entries in
`architecture/root_dependency_ownership.md` gained `geo`, with the reason
recorded in the `synvoid-config` note.

Recorded rather than worked around: the ledger is a deliberate allowlist, and
extending it for a composition module that genuinely needs to read persisted
config and emit a diagnostic is the intended use — the alternative, suppressing
the warning or moving it out of the adapter, would have been worse.

## A pre-existing test race found, not caused by this phase

`cargo test -p synvoid-dns --features mesh` failed once, in
`crates/synvoid-dns/tests/metrics_wiring.rs:90`
(`circuit_breaker_opens_metric_threshold_behavior`). It is **not** a regression,
and the mechanism is proven rather than argued:

| Evidence | Result |
|---|---|
| Current tree, default parallelism | 1 failure in 8 runs |
| Current tree, `--test-threads=1` | **6/6 pass** — cross-test interleaving is required for the failure |
| Failing test in isolation | passes |
| Base commit `f576b8b0`, parallel | 0 failures in 10 runs — *inconclusive* at an observed ~10% rate |

All four tests in that file share two pieces of **process-global** state:
`static COUNTER_STORE`, which `reset_counters()` *clears*, and the global
metrics recorder installed by `metrics::set_default_local_recorder`. A concurrent
`reset_counters()` from any sibling test wipes the store mid-assertion. That is
the race.

Why this phase cannot have caused it: the only change to that file is adding a
third `None` argument to `DnsServer::new` in two *other* tests
(`:118`, `:133`). Both `None`s were already present, so the runtime behaviour of
those tests is byte-identical, and this phase added no test to that binary.
`metrics_wiring` also runs as its own binary, so the new
`geoip_composition_wiring` suite cannot change its scheduling.

The honest summary: a latent test-isolation defect in `metrics_wiring.rs`,
exposed by `--features mesh` timing. It is **recorded, not fixed here** —
it is unrelated to the geo seam, and fixing shared test infrastructure inside a
phase whose scope is dependency wiring would be the kind of unrequested scope
expansion this campaign has been correcting. The mitigation for the verification
lane was to run the suite serialized, which it passes 6/6.

Carried forward as a defect for a dedicated fix: give each test its own counter
store, or serialise the file.

## Verification

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --profile ci --all-targets -- -D warnings` | pass, 0 warnings |
| `cargo check --features dns` | pass |
| `cargo test -p synvoid-config --profile ci` | pass (98 + 94 + the 5 new schema pins) |
| `cargo test -p synvoid-dns --profile ci` | pass (lib 618; all integration suites) |
| `cargo test -p synvoid-dns --profile ci --features mesh` | pass (lib 625) — with one pre-existing flake, see above |
| `cargo test -p synvoid-geoip --profile ci` | pass (10 + 13) |
| `cargo test -p synvoid-repo-guards --profile ci` | pass, incl. the new positive gate (16/16 in `dns_dependency_edges`, 8/8 in `module_ownership`) |
| root `--lib` geo unit tests | 6/6 pass (3 new for the construction path) |
| `cargo deny check` | pass — advisories, bans, licenses, sources all ok |
| `cargo audit` | exit 0; 6 allowed warnings, unchanged from baseline |
| `./scripts/dns/conformance.sh` | internal **10/10** |
| `cargo xtask verify` | **10 steps, 10 passed, 0 failed, 0 skipped** (663.4s) |

### Lanes recorded as not-run

`./scripts/dns/conformance.sh` reports **5 external lanes runnable but not
executed** (they need a `DnsServer` already listening) and **5 skipped for
missing tools** (`kdig`, `named-checkzone`, `ldns-verify-zone`). That is the
script's normal external mode, unchanged by this phase, and the internal lane —
the one that gates DNS behavior — is 10/10.

**No geo interop lane exists or was run.** Nothing in the repo exercises a real
MMDB against the DNS firewall end to end, because no firewall rule can be
declared. `synvoid-geoip`'s own MMDB evidence
(`crates/synvoid-geoip/tests/geoip_provider_evidence.rs`) passes and is the
closest available coverage; the DNS side is covered by the injected-handle pins
instead. Recorded rather than implied.

## What this phase does not claim

- **No class, support, or promotion change.** `synvoid-dns` remains **class 1**.
- **No firewall rule capability.** The capability is present; nothing can consume
  it. This is not "geo firewall works".
- **No site-level geo configuration.** `SiteGeoipConfig` is in the same position
  `GeoIpConfig` was — declared, exported, owned by nothing. `resources.rs` passes
  `&[]` and says so. Wiring a site section is a second schema change and was not
  authorized.
- **No change to the Phase 135 fail-closed rule.** It still holds; it is simply
  not reachable yet.
- **No change to the mesh geo path.** `resolve_from_mesh` still runs only under
  `--features mesh` and an unwired registry.

## Residual work this phase leaves

- **The firewall-rule configuration path** — the real prerequisite for the geo
  feature. It requires a persisted `rules` field, its own authorization, and a
  decision on the currently-inert `default_action` / `max_rules` /
  `rebinding_protection`.
- **`synvoid-geoip` must surface load failures** before a fail-closed startup
  refusal is possible. Until `GeoIpManager::new` can distinguish "unset" from
  "corrupt" from "typo", the auth `try_new` model is unreachable.
- **Site-level geo policy** — same schema-authorization question.
- **Mesh geo derivation** stays a Phase 139 concern, not this one.
- **F-3** (`GeoLocation::from_str` cannot fail) was a minor residual the umbrella
  offered to fold into this phase "if that phase already touches `firewall.rs`".
  It does not — `firewall.rs` is untouched here — so it remains unaddressed.
