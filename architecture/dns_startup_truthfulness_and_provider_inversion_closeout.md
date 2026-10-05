# DNS Startup Truthfulness and Provider-Inversion Campaign Closeout

Date: 2026-10-05
Umbrella plan: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`
Terminal phase: `plans/phase_136_dns_provider_inversion_qualification.md`
Dispositions: **CLOSED QUALIFIED** (Phases 131–136)

## Summary

All six phases closed. The campaign began with three findings that Phases
125–130 recorded rather than fixed, and it ended with the two provider seams
inverted, a startup crash fixed, a fail-open security control closed, and the
DNS crate reduced to two direct SynVoid dependencies.

| Phase | Disposition | Substance |
|---|---|---|
| 131 | CLOSED QUALIFIED | conformance determinism; the `free_port()` TOCTOU assumption removed |
| 132 | CLOSED QUALIFIED | authoritative zone startup activation; a fail-wrong zone defect and a fail-closed config rule |
| 133 | CLOSED QUALIFIED | provider-inversion evidence gate; **GO for TLS and GeoIP**, 12 findings |
| 134 | CLOSED QUALIFIED | TLS provider inversion; `synvoid-tls` edge removed |
| 135 | CLOSED QUALIFIED | GeoIP provider inversion **plus** the F-1 crash and the F-2 fail-open fix |
| 136 | CLOSED QUALIFIED | terminal qualification, documentation reconciliation, class decision |

## The two operator-visible behavior changes

These are stated first because they are what actually changes for someone
running this, and both came out of Phase 135.

### 1. `[geoip] enabled = true` no longer crashes the process

`GeoIpManager::new` used to `.unwrap()` a `DownloadSource` that is `None` unless
`update_url` or (`account_id` **and** `license_key`) is configured. A config
section that documented no credentials requirement could therefore kill the
process at startup — even with `update_enabled = false`, and even though a `None`
source already means "there is nothing to download". It now yields an empty
edition list and logs at debug level.

### 2. A GeoLocation firewall rule that cannot be evaluated now fails closed

`GeoLocation::matches_ip` returned `bool`, so "no provider configured" was
indistinguishable from "the provider says this client is not in that country". A
`GeoLocation` **block** rule therefore did not match, evaluation fell through to
the default `Allow`, and the decision did not even name the skipped rule. An
operator who configured a country block and had no GeoIP database got no error,
no log line, and no blocked traffic — the control silently did not exist.

The condition is now tri-state, and the posture is deliberately asymmetric:

- **restrictive** actions (Block, Redirect, Sinkhole, RateLimit) are **applied**
  when the rule cannot be evaluated;
- **permissive** actions (Allow, LogOnly) are skipped, because applying "allow"
  to a rule nobody scoped would grant access nobody granted.

The decision names the rule and the reason, and a warning fires once per
firewall rather than per query.

### Read this before relying on change 2

**`[geoip]` is constructed nowhere in composition.** No root path builds a
`GeoIpManager`; every `geoip:` field is `None`; nothing ever wired the provider
into the DNS server or the mesh registry. So today a configured **restrictive**
`GeoLocation` rule will, after this campaign, block **all** DNS traffic rather
than silently allowing it.

That is the correct fail-closed direction and it is now loud. It is still a
visible change for an operator who has such a rule configured, and the recourse
is to disable the rule. Wiring GeoIP would activate country classification in
production for the first time — a feature change, not a refactor — so it is
deferred to its own phase, and the tripwire guard
`geoip_provider_is_still_unwired_by_composition` fails the moment a root file
constructs a provider.

## Dependency state, measured

```text
$ cargo metadata --format-version 1 --no-deps    # synvoid-dns direct SynVoid deps
  synvoid-dnssec-keystore  optional=False
  synvoid-mesh             optional=True

$ cargo tree -p synvoid-dns -e normal | wc -l
552
```

### The measurement is feature-conditional, and saying otherwise would be false

`synvoid-mesh` is `optional`, so a plain `cargo tree` does **not** include it. The
552-line figure above is the **default-feature** closure. Enabling the one
remaining optional edge changes the picture substantially:

```text
$ cargo tree -p synvoid-dns -e normal | wc -l                 # default features
552
$ cargo tree -p synvoid-dns -e normal --features mesh | wc -l  # with mesh
2047
```

Under `--features mesh`, **all five** dependencies this campaign and its
predecessor removed reappear in DNS's normal closure —
`synvoid-config`, `synvoid-core`, `synvoid-utils`, `synvoid-tls`, and
`synvoid-geoip` — reaching **1495 additional lines**. Every one of them arrives
the same way, as a transitive dependency of `synvoid-mesh`:

```text
$ cargo tree -p synvoid-dns -e normal --features mesh -i synvoid-tls
synvoid-tls
├── synvoid-ipc -> synvoid-static-files -> synvoid-proxy -> synvoid-mesh -> synvoid-dns
└── synvoid-mesh -> synvoid-dns
```

(Version suffixes and repeated `(*)` subtrees elided; every crate named is a
workspace path dependency.) `synvoid-geoip` is simpler still — within DNS's
closure it has exactly one reverse path, `synvoid-geoip -> synvoid-mesh ->
synvoid-dns`.

No removed crate is a **direct** edge again. The campaign's structural work
holds: DNS still depends on exactly one required sibling
(`synvoid-dnssec-keystore`) plus optional mesh. What the feature-conditional
measurement shows is that the *weight* of the mesh edge is far larger than its
arity of one suggests, and that no amount of further work on the DNS side can
shrink that closure while mesh remains a direct edge.

This is recorded as Phase 136 **F-18** and it is the strongest available
argument for why mesh inversion is the remaining blocker, and why class 1 is
correct.

### Direct SynVoid normal edges

| Crate | Terminal | Kind |
|---|---|---|
| `synvoid-dnssec-keystore` | present | required — a deliberate security-custody leaf |
| `synvoid-mesh` | present | optional, feature-gated (`mesh`) |

### Former dependencies, by closure

| Crate | Phase 123 | Default closure | Under `--features mesh` |
|---|---|---|---|
| `synvoid-config` | yes | **absent** | present, transitively via `synvoid-mesh` |
| `synvoid-core` | yes | **absent** | present, transitively via `synvoid-mesh` |
| `synvoid-utils` | yes | **absent** | present, transitively via `synvoid-mesh` |
| `synvoid-tls` | yes | **absent** | present, transitively via `synvoid-mesh` |
| `synvoid-geoip` | yes | **absent** | present, transitively via `synvoid-mesh` |

| Point | Direct SynVoid normal edges | Default-feature `cargo tree -e normal` lines |
|---|---|---|
| Phase 123 baseline | 7 | 838 |
| Phase 130 | 4 | 827 |
| Phase 133 (evidence gate) | 4 | 827 |
| Phase 134 (TLS inverted) | 3 | 717 |
| Phase 135 (GeoIP inverted) | **2** | **552** |

The campaign target was 2 direct edges. It is met. The whole trajectory above is
the **default-feature** closure, consistent across all five measurements; the
mesh-enabled figure is reported separately precisely so the two are not
confused.

`synvoid-tls` and `synvoid-geoip` are not merely indirect in the default closure
— they are **entirely absent** from it, which is why the expanded tree fell 275
lines rather than the handful two edge removals suggest: `synvoid-tls` alone was
transitively carrying `instant-acme`, `rcgen`, `x509-parser`, `rsa`, `dashmap`,
and `notify` into a crate that needs none of them.

**The plan's expectation about `synvoid-config` was wrong and is corrected
here.** Phase 136 assumed `synvoid-config` would still appear transitively
through `synvoid-tls` and `synvoid-geoip`. It does not: with both providers gone
from the default closure, it left with them. "Absent", "present only
transitively", and "present transitively under a non-default feature" are three
different claims. The Phase 130 record made the second; this campaign measured
all three.

`synvoid-tls` and `synvoid-geoip` still exist and are still used — by the root's
own HTTPS/HTTP/3 servers, by `synvoid-ipc`, and (for GeoIP) by `synvoid-mesh`. They
are providers, and they remain reachable from composition. What changed is that
the DNS crate no longer links them.

## What the DNS crate owns now

| Capability | Trait | Module | Composition adapter |
|---|---|---|---|
| TLS server config | `SecureTransportConfig::server_config` | `crates/synvoid-dns/src/secure_transport.rs` | `src/tls/dns_providers.rs` |
| ACME DNS-01 TXT | `AcmeTxtChallenges::txt_value` | same | same |
| Country + ASN | `CountryLookup::country_info`, `CountryLookup::asn` | `crates/synvoid-dns/src/geo.rs` | `src/geo/dns_provider.rs` |

Neither module names a provider type, and the result types (`rustls::ServerConfig`
is rustls's; `CountryInfo`) are either external or DNS-owned. `CountryInfo` is a
**new** DNS type, not a re-export — a re-export would have looked like inversion
while keeping the edge alive, which is why a gate asserts both the local
declaration and the absence of any `pub use synvoid_geoip`.

## Carried-forward findings and their resolution

The three that started this campaign:

| Original finding | Resolution |
|---|---|
| `[dns.zones]` parsed, converted, then discarded (Phase 128 F-2 / matrix F-6) | **fixed, Phase 132.** Composition activates configured zones and fails startup closed on an unactivatable one. Wiring it exposed two hidden defects: record names could never match, so a configured zone answered authoritative NXDOMAIN for every name it contained; and all four shipped examples declared a record-less zone. Both fixed, plus a `validate()` rule. |
| `free_port()` TOCTOU (Phase 130 F-3) | **resolved by removing the assumption, Phase 131.** The recommended remedy — hold the reservation until bind — is structurally impossible, because `DnsServer::start` binds UDP and TCP on the same port internally. The server now performs the real bind and takes a new port only when that bind is observed to have lost a race, with a conflict-gated retry and no sleeps. 10/10 repeated parallel runs at terminal qualification. |
| Provider inversion DEFER (Phase 130 Workstream E) | **complete for the two narrow seams, Phases 133–135.** mesh remains out. |

Findings discovered during the campaign:

| ID | Severity | Resolution |
|---|---|---|
| 133 F-1 | high | `GeoIpManager::new` panic | **fixed, Phase 135** |
| 133 F-2 | high | geo rule silently allows traffic | **fixed, Phase 135** |
| 133 F-6 | medium | no ALPN anywhere in the TLS path | recorded, deliberately not changed |
| 133 F-16 | low | dead mTLS "no CA certificates" branch | recorded |
| 135 F-16 | — | ASN-scoped geo rule unmatchable | **fixed, Phase 135** |
| 135 F-17 | — | `[geoip]` unwired in composition | recorded; deferred to its own phase, with a tripwire guard |
| 134 F-13 | — | root depends on `rustls` again for one use | recorded in the root dependency ledger, reverting the Phase 31 removal |
| 134 F-14 | — | a guard needed strengthening, not loosening | resolved |
| 134 F-15 | — | a Phase 132 guard was coupled to rustfmt line shape | resolved |
| 136 F-18 | **medium** | the terminal closure measurement is feature-conditional; under `mesh`, all five removed dependencies return transitively | recorded, and it **strengthens** the class-1 decision |
| 131 F-1…F-4 | — | determinism residuals | see the Phase 131 closeout |
| 132 F-1…F-4 | — | zone activation residuals | see the Phase 132 closeout |

The Phase 130 record's claim that DNS calls **zero** methods on `CertResolver` was
wrong, and it mattered: it moved the inversion target from a certificate-loading
trait to a rustls-shaped one. Corrected by pointer in
`architecture/dns_runtime_dto_phase130_closeout.md`, not by rewriting it.

## Verification

Every lane below was executed in this campaign. Lanes that could not run are
recorded as not-run, with the reason.

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | clean, every phase |
| `cargo clippy --profile ci --all-targets -- -D warnings` | clean, every phase |
| `cargo test -p synvoid-dns --profile ci` | pass, 618 lib tests |
| `cargo test -p synvoid-dns --profile ci --features mesh` | pass, 625 lib tests |
| `cargo test -p synvoid-tls --profile ci` | 23 pass |
| `cargo test -p synvoid-geoip --profile ci` | 23 pass |
| `cargo test -p synvoid-config --profile ci` | pass, 6 suites |
| `cargo test -p synvoid-dnssec-keystore --profile ci` | pass |
| `cargo test -p synvoid-repo-guards --profile ci` | pass |
| `cargo check --no-default-features` | clean |
| `cargo check --no-default-features --features mesh` | clean |
| `cargo check --no-default-features --features dns` | clean |
| `cargo check --no-default-features --features mesh,dns` | clean |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok (exit 0) |
| `cargo audit` | exit 0, 6 allowed warnings, 0 vulnerabilities |
| root `dns_runtime_config_parity` | **43/43, unchanged all campaign** |
| `runtime_config_absent_by_design` | **15/15, unchanged** |
| `dns_zone_startup_activation` | 4/4 |
| `./scripts/dns/conformance.sh` | **internal 10/10** (was 9/9) |
| Phase 131 determinism, 10 repeated parallel runs | **10/10**, 5 tests each |
| `cargo xtask verify` | **10/10** at every phase, including terminal qualification (Phase 133 477.2s, Phase 134 439.8s, Phase 136 10/10) |

### Not run, with reasons

- **`cargo package -p synvoid-dns`** — fails with
  `no matching package named 'synvoid-dnssec-keystore' found`. Sibling SynVoid
  crates are unpublished to crates.io. Pre-existing and unrelated to this
  campaign; it is also why `synvoid-dns` cannot be published, which is a fact the
  class decision below already accounts for.
- **External DNS interop lanes** (`kdig`, `ldns-verify-zone`,
  `named-checkzone`, `delv`) — the tools are not installed on this host.
  `conformance.sh` reports them as skipped, not passed: 5 runnable, 5 skipped.
- **The two `#[ignore]`d Eggbench live-proof suites** — they require a separately
  built binary and cannot execute as evidence here. They still contain a local
  predict-then-bind `free_port()`; see the Phase 131 closeout residuals.

## Class / support decision

**`synvoid-dns` remains class 1. No promotion, no publication claim, no external
support claim.**

The conditions for class 2 in
`architecture/public_crate_release_policy.md` are **not** met:

1. **`synvoid-mesh` is still a direct, concrete edge, and it is heavy.** It is
   `optional` in the manifest, but the mesh-gated DNS code reaches 8 types across
   DHT record storage, routing, and signed provenance. Phase 130 judged this not
   to be a narrow seam, and nothing in this campaign changed that judgement. Phase
   136 quantified the cost (**F-18**): enabling it takes DNS's normal closure from
   552 lines to 2047 and returns every dependency the two prior campaigns
   removed. Mesh inversion requires its own design phase, and it is the single
   remaining blocker.
2. **The crate cannot be packaged**, because sibling SynVoid crates are
   unpublished. That is a supply-chain fact, not a code fact, and dependency
   reduction does not change it.
3. **The public API surface is not a stable contract.** The two capabilities
   introduced here are new, and the DNS runtime DTOs they sit beside are new since
   Phase 125. There is no outside-workspace consumer evidence of stability, and
   the only outside-workspace evidence that exists concerns the configuration
   surface — which is not promotion and must not be described as such.

What this campaign *did* establish is narrower and worth stating precisely: the
DNS crate's two narrow provider seams are inverted behind DNS-owned capabilities
implemented in composition, its dependency on the shared utility and persistence
crates is gone, and it now depends on one required SynVoid sibling
(`synvoid-dnssec-keystore`, a deliberate security-custody leaf) plus optional
mesh. That is a real reduction in coupling and a real improvement in
testability. It is not, by itself, a step toward publication readiness, and it is
not presented as one.

## Residual work this campaign deliberately left

1. **mesh provider inversion** — needs its own design phase. Not registered here.
2. **Wiring `[geoip]`** — a feature change with its own phase; the tripwire guard
   makes it impossible to do by accident.
3. **ALPN for the encrypted transports** — `build_server_config` configures none,
   so a client requiring ALPN negotiation cannot use the DoT/DoH/DoQ listeners
   (F-6). Recorded; a protocol behavior change, not a refactor.
   > **Resolved by Phase 137, with two corrections to this item.** (1) DoQ was
   > already correct — it set `doq` ALPN per RFC 9250 — so "DoT/DoH/DoQ" was
   > wrong; the gap was DoT and DoH. (2) DoT and DoH share one builder and need
   > *different* values, so this was a signature change rather than a list edit.
   > ALPN now lives at the DNS call sites, per transport. See
   > `architecture/dns_provider_inversion_phase137_closeout.md`.
4. **`prefer_post_quantum` is telemetry, not a gate** (F-7). It selects nothing;
   availability comes from the compiled-in rustls feature.
5. **Zone reload atomicity** (Phase 132 F-4) — a multi-zone batch can leave a
   partial set on a runtime reload. Harmless at startup, where the process is
   about to exit.
6. **A public authoritative profile cannot be queried over loopback** (Phase 132
   F-3) — `block_internal_ips` blocks `127.0.0.0/8`, which is correct for the
   profile but means local `dig @127.0.0.1` fails as silence.

## Supersessions

Applied by pointer, never by rewriting a historical record:

- `architecture/dns_runtime_dto_phase130_closeout.md` — the "zero methods on
  `CertResolver`" error, and the DEFER that followed from it.
- `architecture/dns_application_neutral_readiness_phase109.md` — "provider
  inversion is not eligible" is no longer the blocker; it is scheduled.
- `architecture/dns_runtime_dto_conversion_research.md` — the
  injected-concrete-`CertResolver` note.
- `architecture/dns_config_runtime_matrix.md` — F-6's resolution pointer, plus
  the Phase 131/132/133/134/135 finding sections.
- `architecture/dns_provider_inversion_phase133_closeout.md` — the F-6 "no ALPN
  is configured" scope: DoQ already set `doq` ALPN, so the gap was DoT and DoH.
  Resolved by Phase 137.
