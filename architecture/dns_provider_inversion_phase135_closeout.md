# Phase 135 Closeout: GeoIP Provider Inversion

Date: 2026-10-05
Plan: `plans/phase_135_dns_geoip_provider_inversion.md`
Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`
Predecessor: Phase 134 (`architecture/dns_provider_inversion_phase134_closeout.md`)
Disposition: **CLOSED QUALIFIED**

## What this phase did

Three things, in this order, because the first two were mandatory carry-forward
workstreams from Phase 133 and the third depended on them:

1. **F-1** — made `GeoIpManager::new` total. It used to abort the process on a
   config-reachable input.
2. **F-2** — gave a `GeoLocation` firewall rule that cannot be evaluated a
   deliberate fail-closed meaning instead of silently allowing traffic.
3. **Inverted the seam** — DNS now asks for country and ASN through a DNS-owned
   `CountryLookup` capability, and `synvoid-geoip` is gone from DNS's dependency
   closure entirely.

## Dependency proof

```
$ cargo metadata --format-version 1 --no-deps   # synvoid-dns direct synvoid deps
['synvoid-dnssec-keystore', 'synvoid-mesh']
$ cargo tree -p synvoid-dns -e normal | grep -c synvoid-geoip
0
```

| Measure | Phase 123 baseline | Phase 133 | Phase 134 | Phase 135 |
|---|---|---|---|---|
| Direct SynVoid normal edges | 7 | 4 | 3 | **2** |
| Expanded `cargo tree -e normal` lines | 838 | 827 | 717 | **552** |

The campaign target was 2 direct edges. It is met. The remaining edge is
optional `synvoid-mesh`, which Phase 130 judged not to be a narrow seam and
which stays out of scope.

`CountryInfo` is a **new** DNS-owned type, not a re-export of
`synvoid_geoip::CountryInfo`. A re-export would have looked like inversion while
keeping the edge alive, which is why `dns_declares_exactly_the_two_geo_capability_methods`
asserts the struct is declared locally *and* that no `pub use synvoid_geoip`
exists.

## F-1 — `GeoIpManager::new` no longer panics (behavior change, fixed)

`GeoIpUpdater::new` evaluated `source.as_ref().unwrap()`, and
`DownloadSource::from_config` returns `None` unless `update_url` or
(`account_id` **and** `license_key`) is set. So `[geoip] enabled = true` with no
download credentials aborted the process — even with `update_enabled = false`,
and even though a `None` source already means "there is nothing to download".

It now yields an empty edition list, with a debug line when editions were
configured but no source is available. `start_auto_update` iterates editions, so
it becomes a no-op rather than failing or spinning.

The Phase 133 pin was a `#[should_panic]` test, written so the fix would fail
loudly rather than pass silently. It is **inverted, not deleted**: it now
asserts the provider is constructed, reports no loaded database, and has zero
editions and no source. Two more tests cover `update_enabled = true` with no
credentials, and a configured source still building one edition per id — so the
fix cannot be a blanket "never build editions".

## F-2 — a geo rule that cannot be evaluated no longer passes traffic (behavior change, fixed)

This is a **deliberate, security-relevant behavior change** and the most
consequential thing this phase did.

### Before

`GeoLocation::matches_ip` returned `bool`. With no provider it returned `false`,
which was indistinguishable from "the provider answered: not this country". A
`GeoLocation` **block** rule therefore did not match, evaluation fell through to
the default `Allow`, and the decision did not name the skipped rule. An
operator who configured a country block and had no GeoIP database got no error,
no log line, and no blocked traffic.

### After

The rule's condition is tri-state:

```rust
pub enum GeoMatch { Yes, No, Unavailable }
```

`matches_ip` returns `Unavailable` only when there is **no provider at all**. A
provider that exists but cannot answer a given address returns `No`, because that
is a real answer — reporting `Unavailable` would turn every uncovered address
into a fail-closed block, which is a much larger change than F-2 asks for and
would make a GeoLite2-Country database block everything.

`evaluate_query` then applies this posture:

| Rule action | Indeterminate | Why |
|---|---|---|
| `Block`, `Redirect`, `Sinkhole`, `RateLimit` | **applied** (fail closed) | a control that cannot be evaluated must not silently let traffic through |
| `Allow`, `LogOnly` | **skipped** (fail open) | applying "allow" to a rule nobody scoped would grant access nobody granted |

The asymmetry is intentional and pinned as a matrix for every action, so adding
an action forces a decision rather than inheriting a default.

Three further changes make the condition visible rather than silent:

- the decision `reason` names the rule, that it could not be evaluated, why, and
  which action was applied;
- a `warn!` is emitted **once per firewall instance** (an `AtomicBool`), because
  the condition is evaluated per query and would otherwise flood the log;
- `DnsFirewall::can_evaluate_geo_rules()` reports the capability's presence, and
  a **disabled** rule remains the operator's explicit way to park a geo control.

`GeoLocation::contains` is kept as a convenience wrapper, with a doc comment
warning that it collapses `Unavailable` into `false` — which is the F-2 defect —
so the evaluation path must use `matches_ip`.

## F-16 — an ASN-scoped geo rule was unmatchable (found and fixed here)

Writing the F-2 tests surfaced this. `GeoLocation`'s comma format puts the ASN
at index 3, so a country+ASN rule must spell out indices 1 and 2. Those
placeholders became `Some("")` rather than `None`, and then failed the region and
city comparisons against a provider that has neither. An ASN-scoped rule could
not match however it was written.

An empty field is now a placeholder, not a value. This also means an
ASN-scoped rule — which the seam deliberately supports via
`asn() -> Option<u32>` (Phase 133 F-10) — is reachable at all.

## F-17 — `[geoip]` is unwired in composition (recorded, not fixed)

**No composition path constructs a `GeoIpManager`.** Every `geoip:` field in the
root is `None` (`src/server/resources.rs:291`, `src/server/service_assembly.rs:267`,
`src/waf/mod.rs:1166`), and nothing in the root ever called `with_geoip` on the DNS
server or the mesh registry. So today:

- the `GeoLocation` firewall rule type exists, parses, and can never match;
- the WAF's `geoip` field and its `AsnTracker` are permanently `None`.

This interacts with F-2 in a way that must not be understated. Because the
provider is never constructed, a configured **restrictive** `GeoLocation` rule
will, after this change, block **all** DNS traffic rather than silently allowing
it. That is the correct fail-closed direction, and it is now loud (warning plus
a decision reason), but it is a visible behavior change for any operator who has
such a rule configured today.

Wiring GeoIP is deliberately **not** done here. It would activate country
classification in production for the first time — a feature change, not a
refactor — and it needs its own phase, its own evidence, and a decision about
which country sets and sites apply. The composition adapter
(`src/geo/dns_provider.rs`) is written and ready for that phase.

> **Correction, Phase 138.** Three claims here were wrong, and each would have
> misdirected the phase that followed. Corrected by pointer; the original text
> is preserved below. See
> `architecture/dns_provider_inversion_phase138_closeout.md`.
>
> 1. "The composition adapter is written and **ready**" was incomplete in a way
>    that changed the scope. The adapter existed, but `DnsServer::new` hardcoded
>    `let geoip_lookup = None;` **inside `synvoid-dns`**, so the phase was never
>    composition-only.
> 2. The tripwire "fails the moment any **non-test** root file constructs a
>    `GeoIpManager`" — it had no `#[cfg(test)]` awareness, and it **exempted
>    `src/geo/`** entirely, which is where the construction naturally belongs. It
>    would not have fired for a legitimate wiring. It was deleted in Phase 138
>    and replaced by a positive gate.
> 3. The operational consequence recorded for F-2 is **unreachable**: no
>    `GeoLocation` rule can be declared, because `DnsFirewallConfig` has no
>    `rules` field and every `add_rule` call site is hardcoded.

Because "unwired" is a state that can change silently, a **tripwire guard**
exists: `geoip_provider_is_still_unwired_by_composition` fails the moment any
non-test root file constructs a `GeoIpManager`, with a message pointing at F-17
and F-2 and instructing the author to give it its own phase rather than weaken
the gate. Its presence is why the operational consequence above cannot quietly
become a different one.

## The seam

```rust
// crates/synvoid-dns/src/geo.rs — DNS-owned
pub struct CountryInfo { code, name, subdivision, city }
pub trait CountryLookup: Send + Sync {
    fn country_info(&self, ip: IpAddr) -> Option<CountryInfo>;
    fn asn(&self, ip: IpAddr) -> Option<u32>;
}
```

`asn` returns `Option<u32>`, not the provider's `AsnInfo`, because the firewall
reads only the number (Phase 133 F-10) — carrying the struct would put a
provider type in the request path for no reader.

The composition adapter (`src/geo/dns_provider.rs`) maps the provider's
`CountryInfo` field by field and `AsnInfo` to its number. It does **not**
reproduce the provider's redundant second country lookup (Phase 133 F-9) — that
traversal stays the provider's business.

`as_country_lookup` maps a `None` manager to `None`. That is deliberate: a
provider that *appears* present but cannot answer would convert a fail-closed
block into an evaluated "no match" and quietly allow traffic again.

Composition home recorded in `architecture/root_module_ledger.md` (new `geo`
row) and `architecture/root_dependency_ownership.md` (`geo` added to the
`synvoid-dns` and `synvoid-geoip` consumer columns, with F-17 noted).

## Gating the seam

| Gate | Pins |
|---|---|
| `synvoid_dns_has_no_geoip_edge` | manifest declares no `synvoid-geoip` |
| `dns_source_names_no_geoip_provider_symbol` | no `use`/`::` path names the provider crate, `GeoIpManager`, or the two concrete methods |
| `dns_declares_exactly_the_two_geo_capability_methods` | the two evidenced signatures, a locally declared `CountryInfo`, and no `pub use synvoid_geoip` |
| `geoip_provider_is_still_unwired_by_composition` | F-17 tripwire |
| `dns_geo_seam_width_is_enforced_by_the_capability_gates` | replaces the Phase 133 seam gate, which became vacuously false once the concrete methods left the crate |

The Phase 133 gate `dns_names_exactly_the_two_geoip_provider_methods` asserted
that `{get_country_info, get_asn_info}` each appear exactly once in the crate.
After inversion they appear zero times, so the assertion was vacuously false.
Rather than delete it or weaken it to `0`, it is retargeted at the *capability's*
declarations, which is what the gate's intent was all along.

## Testing consequence

`crates/synvoid-dns/tests/geoip_rule_evidence.rs` no longer needs a MaxMind
database. It uses a DNS-owned `StubLookup`, which is what made two things
directly testable that Phase 133 could only derive:

- the answerless-provider case (Phase 133 F-5 recorded it as unreachable from
  this crate);
- the **positive** `GeoLocation` matrix (Phase 133 F-4): case-insensitive country
  match, region- and city-scoped rules, and the numeric ASN seam.

The provider's own behavior stays proven in
`crates/synvoid-geoip/tests/geoip_provider_evidence.rs`, which keeps the
hand-written MMDB fixture — 13 tests there, 14 here.

## Verification

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --profile ci --all-targets -- -D warnings` (touched crates) | clean, and clean again with `--features mesh` |
| `cargo test -p synvoid-dns --profile ci` | pass, exit 0 |
| `cargo test -p synvoid-dns --profile ci --features mesh` | pass, exit 0 |
| `cargo test -p synvoid-geoip --profile ci` | pass (13 evidence + 10 existing) |
| `cargo test -p synvoid-tls --profile ci` | pass (20 evidence + 3 existing) |
| `cargo test -p synvoid-repo-guards --profile ci` | pass, 143 repo-guard tests |
| `cargo metadata` / `cargo tree` edge proof | `synvoid-geoip` absent; 2 direct edges |
| `cargo test --profile ci --features dns --test dns_runtime_config_parity` | **43/43 unchanged** |
| `cargo test --profile ci --features dns --test dns_zone_startup_activation` | 4/4 |
| `./scripts/dns/conformance.sh` | **Internal 10/10**; 5 external runnable, 5 skipped (tools not installed) |
| `cargo xtask verify` | **10/10 passed** |

## Not done, deliberately

- **GeoIP is not wired** (F-17). That is a feature change, not an inversion.
- No mesh work.
- `GeoLocation::from_str` still cannot fail (Phase 133 F-3). It now fails closed
  on an unparseable target, so a typo is a loud no-op rather than a silent one,
  but validation at rule-construction time is still open.
- `synvoid-dns` remains class 1. Dependency reduction is not publication
  readiness.
