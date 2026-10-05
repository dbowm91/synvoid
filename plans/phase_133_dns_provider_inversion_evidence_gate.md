# Phase 133 Plan: Provider-Inversion Evidence Gate (TLS + GeoIP)

Status: **CLOSED QUALIFIED** (2026-10-05).

Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 132.
Registered in: `plans/roadmap.md`.

## Outcome

**GO for both providers.** The decisions name the exact traits, method
signatures, and implementing types; see the closeout's Decision section.

Corrections to this plan's premises, found while producing the evidence:

- The GeoIP seam is **two** methods, not one (`get_asn_info` at
  `firewall.rs:361` is easy to miss).
- The TLS seam has **three** call sites, not one: DoQ is QUIC and duplicates the
  contract in its own `create_tls_config` (F-12).
- There is no `Health` firewall rule type. `DnsFirewallRuleType` is Domain,
  IpAddress, Subnet, QueryType, Opcode, ResponseCode, GeoLocation, TimeWindow;
  `synvoid_dns::health` reports server state and takes no part in query
  evaluation. What the firewall has is first-match-in-insertion-order, which is
  what Workstream B item 4 now pins.

Twelve findings are recorded, two of them high severity and both deferred to
Phase 135 by design: a config-reachable panic in `GeoIpManager::new` (F-1) and
a GeoLocation block rule that silently allows traffic when no provider is
configured (F-2).

## Goal

Produce, as executable tests, the evidence Phase 130 found missing, and re-gate
TLS and GeoIP inversion on it.

**This phase inverts nothing.** It ends with a GO/DEFER decision per provider.
If either provider fails its gate, Phases 134/135 are re-scoped or dropped and
the campaign continues without it.

## Correction to the Phase 130 record

Phase 130 Workstream E states that DNS calls **zero** methods on
`CertResolver`. That is wrong, and the correction matters because it changes
the inversion target:

`SecureDnsServerBase::create_tls_acceptor`
(`crates/synvoid-dns/src/secure_server.rs:47`) calls
`resolver.build_server_config()`, which returns
`Result<Arc<rustls::ServerConfig>, Box<dyn Error + Send + Sync>>`.

So the real seam is a **rustls-shaped** capability — exactly what Phase 130
predicted would be needed. The correct Phase 130 closeout is amended by pointer,
not rewritten.

## Workstream A — TLS evidence

Required proof, each as an executable test:

1. **SNI behavior** — `CertResolver` implements
   `rustls::server::ResolvesServerCert` (`crates/synvoid-tls/src/cert_resolver.rs:335`).
   Prove selection by SNI name, the default-certificate fallback, and the
   unknown-name path.
2. **Reload semantics** — `CertResolver::reload_tx()` and
   `watch_for_cert_changes` exist. Prove who triggers a reload and prove that
   DNS does not, so inversion cannot change reload behavior.
3. **Private-key ownership** — keys are read and held inside `synvoid-tls`;
   prove DNS never receives key material, only `Arc<CertifiedKey>` /
   `Arc<ServerConfig>`.
4. **ALPN** — record what is actually configured. `build_server_config` sets
   protocol versions, an optional client verifier, and a cert resolver, and sets
   **no ALPN**. Prove that, and record the consequence for DoT/DoH/DoQ
   (h2 for DoH, no ALPN advertisement today) as a finding rather than silently
   adding ALPN — that would be a behavior change.
5. **mTLS** — `build_server_config` also builds
   `WebPkiClientVerifier` when client auth is configured. Prove the failure
   paths ("no CA certificates found", "CA path not configured") surface
   unchanged through the TLS acceptor's error path, because a DNS-owned trait
   must not swallow them.
6. **DoT/DoH/DoQ startup and failure parity** — no resolver, acceptor build
   failure, and zero-port rejection behave identically before and after
   inversion.
7. **Protocol version policy** — TLS 1.3-only vs TLS 1.2 fallback vs backward
   compatibility mode, including the `prefer_post_quantum` provider choice.

## Workstream B — GeoIP evidence

The only method DNS calls is
`GeoIpManager::get_country_info(IpAddr) -> Option<CountryInfo>`, at three sites:
`crates/synvoid-dns/src/mesh_sync/registry.rs:75`,
`crates/synvoid-dns/src/firewall.rs:333`, and
`crates/synvoid-dns/src/server/query.rs:881`. The provider handle threads
through `Option<Arc<GeoIpManager>>` at
`crates/synvoid-dns/src/firewall.rs:47`,
`crates/synvoid-dns/src/server/query.rs:870`,
`crates/synvoid-dns/src/server/mod.rs:1603` and `:1645`, and
`crates/synvoid-dns/src/mesh_sync/mod.rs:163`.

Required proof:

1. **Missing database** — behavior when no GeoIP DB is loaded.
2. **Unknown location** — behavior for an address the DB does not cover.
3. **Privacy/logging** — whether a lookup logs the client IP, and at what
   level. A country lookup in the request path must not become a client-IP
   disclosure channel.
4. **Health + Geo ordering** — firewall rule evaluation order when both a
   health rule and a GeoLocation rule match.
5. **Deterministic fallback** — pin what each of the `Option<..>` sites does
   when the provider is absent. Phase 130 recorded that the absence case is
   expressed by `None` at these call sites with no test pinning it. A
   GeoLocation firewall rule with no provider must have a deliberate,
   fail-closed meaning: a rule that cannot be evaluated must not silently pass
   traffic.
6. **`GeoLocation::contains` shape** — confirm the firewall's
   `GeoLocation` is a DNS type parameterized by the provider, and that
   inversion keeps it DNS-owned.

## Workstream C — mesh stays out

Record, with the type list, that mesh remains a distributed-authority surface
requiring its own design phase. Do not scope it, and do not implement a partial
mesh trait "while we are here".

## Workstream D — decision

Per provider, record **GO** or **DEFER** with the evidence that decided it. A
GO must name the exact DNS-owned capability that will be introduced in Phase
134/135 — its trait name, method signatures, and the concrete type that
implements it in composition. An abstract "we can define a trait" is not a GO.

Update:

- `architecture/dns_application_neutral_readiness_phase109.md` via supersession
  pointer;
- `architecture/dns_runtime_dto_conversion_research.md`;
- the campaign roadmap and `plans/roadmap.md`.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test -p synvoid-tls --profile ci
cargo test -p synvoid-geoip --profile ci
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo xtask verify
```

## Acceptance criteria

- every item in Workstreams A and B exists as a named, passing test, or is
  recorded as a finding with its current behavior pinned;
- the Phase 130 `CertResolver` method-count error is corrected by pointer;
- each provider carries a GO/DEFER decision naming the exact capability;
- no production behavior changed in this phase.

## Rejection criteria

Reject an evidence gate that:

- asserts only that a trait *could* be written;
- leaves the GeoIP absent-provider case unpinned;
- adds ALPN or any other TLS behavior change;
- inverts a provider;
- overwrites the Phase 130 or Phase 109 historical record instead of
  superseding it.

## Closeout

`architecture/dns_provider_inversion_phase133_closeout.md`.
