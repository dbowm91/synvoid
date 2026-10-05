# Phase 133 Closeout: Provider-Inversion Evidence Gate (TLS + GeoIP)

Date: 2026-10-05
Plan: `plans/phase_133_dns_provider_inversion_evidence_gate.md`
Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`
Predecessor: Phase 132 (`architecture/dns_provider_inversion_phase132_closeout.md`)
Disposition: **CLOSED QUALIFIED**

## What this phase did and did not do

It produced executable evidence for both provider seams and issued a
GO/DEFER decision for each. It inverted nothing and changed no production
behavior. Its only production-adjacent edits are three new repo-guard gates
that pin the seams' current shape.

The Phase 130 claim that DNS calls *zero* methods on `CertResolver` is wrong,
and the correction matters: it moves the inversion target from "a
certificate-loading trait" to a **rustls-shaped** one, which is far narrower.

## Evidence added

| Suite | Tests | Pins |
|---|---|---|
| `crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs` | 20 | SNI exact / wildcard / default / empty, reload semantics, key custody, ALPN, mTLS, version policy |
| `crates/synvoid-dns/tests/encrypted_transport_startup_contract.rs` | 7 | DoT/DoH startup and failure parity, error propagation, port release |
| `crates/synvoid-geoip/tests/geoip_provider_evidence.rs` | 11 | missing DB, unknown location, partial records, privacy, construction totality |
| `crates/synvoid-dns/tests/geoip_rule_evidence.rs` | 9 | absent-provider fallback, rule ordering, `GeoLocation` shape |
| `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` §5 | 4 new gates | key custody, reload isolation, seam width, duplicated contract |

Every claim below is observed through a real rustls handshake or a real MaxMind
database, not by reading struct fields. The MMDB fixture
(`crates/synvoid-geoip/tests/support/mmdb.rs`) is a purpose-built minimal
writer: the repository shipped no `.mmdb` fixture, and without one "no database"
and "database with no record for this address" collapse into the same
uninformative `None`.

## Decisions

### TLS: **GO**

The seam is **two** provider types with **one** method each, reached at
**three** call sites:

1. `CertResolver::build_server_config() -> Result<Arc<rustls::ServerConfig>, _>`
   — called at `crates/synvoid-dns/src/secure_server.rs:53` (DoT and DoH) and
   `crates/synvoid-dns/src/doq.rs:112` (DoQ, via `quinn`).
2. `AcmeDnsChallenge::get_txt_value(&str) -> Option<String>` — called once, at
   `crates/synvoid-dns/src/server/query.rs:997`.

`synvoid-dns` names `CertResolver` only as a type; `build_server_config` is the
only method it calls on it (finding F-12 for the duplication, and the guard
`dns_does_not_drive_certificate_reload` for everything else).

Phase 134 introduces exactly:

```rust
// crates/synvoid-dns/src/secure_server.rs
pub trait SecureTransportConfig: Send + Sync {
    fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String>;
}

// crates/synvoid-dns/src/server/mod.rs (or a sibling runtime module)
pub trait AcmeTxtChallenges: Send + Sync {
    fn txt_value(&self, domain: &str) -> Option<String>;
}
```

Composition implements both — `CertResolver` and `AcmeDnsChallenge` already
satisfy the required method sets and need no new type. The traits name no
`synvoid-tls` type, so the edge can be deleted. `rustls` and `tokio-rustls`
are already direct dependencies of `synvoid-dns`, so no new supply-chain
surface appears.

The `String` error keeps the existing `"Failed to build TLS config: {e}"`
wrapping at the DNS layer, so the messages pinned in
`encrypted_transport_startup_contract.rs` are reproduced rather than changed.

### GeoIP: **GO**

The seam is exactly **two** methods, called at **four** sites:

- `get_country_info(IpAddr) -> Option<CountryInfo>` —
  `firewall.rs:333`, `mesh_sync/registry.rs:75`, `server/query.rs:881`
- `get_asn_info(IpAddr) -> Option<AsnInfo>` — `firewall.rs:361`

Phase 135 introduces exactly:

```rust
// crates/synvoid-dns/src/geo.rs  (new, DNS-owned)
pub struct CountryInfo {
    pub code: String,
    pub name: String,
    pub subdivision: Option<String>,
    pub city: Option<String>,
}

pub trait CountryLookup: Send + Sync {
    fn country_info(&self, ip: IpAddr) -> Option<CountryInfo>;
    fn asn(&self, ip: IpAddr) -> Option<u32>;
}
```

`CountryInfo` is a **new DNS-owned type**, not a re-export of
`synvoid_geoip::CountryInfo` — a re-export would keep the edge alive, which is
the mistake `dns_dependency_edges.rs` exists to catch (it gates both the
manifest edge and the source level, because removing a manifest edge alone does
not stop a re-export or a `use` alias).

The trait is narrower than the provider's: `GeoLocation::matches_ip` reads only
`asn_info.asn` and discards `organization` (finding F-10), so the seam needs
`Option<u32>`, not `AsnInfo`.

Composition implements the trait for `Arc<GeoIpManager>`, which requires the
constructor fix in F-1.

### mesh: still out

`synvoid-mesh` remains a distributed-authority surface, not a narrow seam. The
mesh-gated DNS code reaches 8 types across DHT storage, routing, and signed
provenance. No partial mesh trait was introduced. It requires its own design
phase and stays unregistered.

## Findings

### F-1 — `GeoIpManager::new` panics on a config-reachable input (severity: high)

`GeoIpUpdater::new` (`crates/synvoid-geoip/src/updater.rs:147`) evaluates
`source.as_ref().unwrap()`, and `DownloadSource::from_config` returns `None`
unless `update_url` or (`account_id` **and** `license_key`) is set. So
`[geoip] enabled = true` with no download credentials **aborts the process**
during provider construction — even with `update_enabled = false`, and even
though `None` already means "there is nothing to download".

Pinned by `enabled_config_without_download_credentials_panics_during_construction`
in the `synvoid-geoip` suite.

**Not fixed in this phase.** Phase 133 changes no production behavior, and the
fix belongs to Phase 135, which owns GeoIP provider construction. The test is
written so that fixing it produces a loud, deliberate failure rather than a
silent pass, and Phase 135's plan names it as its first workstream.

### F-2 — a GeoLocation block rule with no provider silently allows traffic (severity: high)

`GeoLocation::matches_ip` returns `false` when the provider is absent, so
`DnsFirewall::evaluate_query` skips the rule and falls through to the default
`Allow`. The decision does not name the skipped rule, so an operator who
configures a country block without a GeoIP database gets no error, no log line,
and no traffic blocked. This is the plan's "a rule that cannot be evaluated
must not silently pass traffic" case, and today it does silently pass traffic.

Pinned by `geo_block_rule_without_provider_silently_allows`. Phase 135 must
choose and implement the fail-closed semantics; this phase records the current
behavior rather than changing it.

### F-3 — `GeoLocation::from_str` cannot fail (severity: low)

`"".split(',')` always yields at least one element, so the `parts.is_empty()`
guard is unreachable and `if let Ok(geo)` in `rule_matches` is dead defensive
code. A misspelled target becomes a country code that matches nothing, and an
unparseable ASN is silently dropped. A typo degrades a security rule into a
no-op with no diagnostic. Pinned by
`geo_location_parsing_cannot_fail_and_typos_never_match`.

### F-4 — the positive GeoLocation matrix is only testable where a real database exists (severity: none, informational)

A positive `contains` requires a real MMDB, which lives in the `synvoid-geoip`
test fixtures. Duplicating that builder into `synvoid-dns` to test four
additional cases was rejected. The matrix is pinned provider-side; once Phase
135 introduces the DNS-owned trait it becomes directly testable in `synvoid-dns`
with a DNS-owned double and no `synvoid-geoip` edge. Recorded so the split is
not mistaken for a gap.

### F-5 — `synvoid-dns` cannot construct a provider at all (severity: none, informational)

`GeoIpManager::new` takes a `synvoid_config::geoip::GeoIpConfig`, and Phase 125
removed the `synvoid-config` edge entirely. A provider can therefore only reach
the crate through a composition root holding both types. The consequence is that
the "provider present but unable to answer" case is not directly testable from
`synvoid-dns`; its outcome is instead determined from both sides
(`get_country_info` returns `None` with no database, and `matches_ip` returns
`false` on `None`). Pinned by
`the_answerless_provider_case_is_unreachable_from_this_crate`, which asserts the
dependency surface that makes it unreachable.

### F-6 — no ALPN is configured (severity: medium, recorded not changed)

> **Correction, Phase 137.** This finding is accurate about the **provider** and
> over-claims about the transports. Corrected by pointer; the original text is
> preserved above as the Phase 133 record. See
> `architecture/dns_provider_inversion_phase137_closeout.md`.
>
> 1. "no ALPN is configured" is true of `build_server_config` and was presented
>    as true of the encrypted transports. **DoQ already set `doq` ALPN**
>    (`crates/synvoid-dns/src/doq.rs:72`) and was correct per RFC 9250. The gap
>    was **DoT and DoH only**, so "which is relevant to DoH" understated it and
>    the campaign summary's "the DoT/DoH/DoQ listeners" was wrong.
> 2. Both provider pins named above **remain true and unmodified**. Phase 137
>    resolved F-6 at the DNS call sites, leaving the provider alone — the
>    opposite of the F-1 disposition, where the fix landed in the layer the pin
>    covered.

`build_server_config` sets protocol versions, an optional client verifier, and
the certificate resolver — and no ALPN. `ServerConfig::alpn_protocols` is empty,
and a client offering `h2` and `doq` completes the handshake with no negotiated
protocol (pinned by `no_alpn_is_negotiated_even_when_the_client_offers_one`).

Consequence: a client that *requires* ALPN negotiation cannot use these
listeners, which is relevant to DoH. Adding ALPN would be a protocol behavior
change and is deliberately not done in an evidence phase.

### F-7 — `prefer_post_quantum` is not a gate (severity: low)

It emits a debug log and a counter and selects nothing. A client offering *only*
`X25519MLKEM768` completes a handshake against a server built with the flag off
(pinned by `prefer_post_quantum_does_not_gate_the_hybrid_key_exchange`); the
compiled-in `prefer-post-quantum` rustls feature, not this setting, governs
availability. Phase 134 must not describe its trait as "honouring a
post-quantum preference" — there is no preference to honour.

### F-8 — the permissive version branch is not the default (severity: none, informational)

`build_server_config` admits TLS 1.2 and 1.3 when neither version flag is set,
and only warns. That branch is reachable solely through explicit configuration,
because `InternalTlsConfig::default()` sets `tls_1_3_only = true`. Recorded
because "neither flag set" and "the default" are easy to conflate; the default
is asserted by `the_internal_tls_config_default_is_tls_1_3_only`.

### F-9 — `get_country_info`'s second lookup cannot change the answer (severity: low)

`?` is applied to both `lookup_country` and `lookup_country_info`, which reads
as a partial-hit guard. Both decode the same `country.iso_code` path, and
`lookup_country_info` substitutes `name = code` when `country.names` is absent —
proven by `a_bare_iso_code_record_answers_with_the_code_as_its_name`. The second
call is a redundant database traversal on every request, not a correctness
guard. Phase 135 should not inherit it.

### F-10 — the ASN seam is narrower than the provider type (severity: none, informational)

`GeoLocation::matches_ip` reads only `AsnInfo::asn`. The trait needs
`Option<u32>`, so no provider type reaches the request path. Pinned by
`the_asn_seam_only_needs_the_asn_number`.

### F-11 — the mTLS "no CA certificates" branch in `build_server_config` is dead (severity: low)

`build_server_config` wraps the CA load in `if !ca_certs.is_empty()` and
returns `"No CA certificates found for client authentication"` otherwise. But
`load_ca_certs` already returns `Err("No CA certificates found in file")`
when the file yields no certificates, so it can never return an empty
`RootCertStore` to reach that branch.

The consequence is diagnostic, not behavioral: the message an operator sees for
an empty or malformed CA file is the `load_ca_certs` one, not the
client-auth-specific one, and the latter is unreachable text. Pinned by
`client_auth_with_an_empty_ca_file_is_a_hard_error`,
`a_malformed_ca_file_is_rejected_before_the_verifier_is_built`, and
`a_missing_ca_file_reports_the_io_failure` — the last of which shows the third,
genuinely reachable case (an unreadable path, which surfaces the IO error).

### F-12 — the encrypted-transport TLS contract is duplicated, not shared (severity: low)

DoT and DoH use `SecureDnsServerBase::create_tls_acceptor`. DoQ is QUIC and has
its own `DoqServer::create_tls_config` (`crates/synvoid-dns/src/doq.rs:105`),
because `quinn` needs a `QuicServerConfig` rather than a `TlsAcceptor`, and
`DoqRuntimeConfig` does not implement `DnsServerConfig` at all.

Both copies hardcode the same two literals and both call the same single
provider method. An inversion that updates one and not the other would silently
give DoQ different diagnostics from DoT and DoH. Pinned by
`encrypted_transport_error_contract_is_duplicated_consistently`, which requires
the literals to appear in both files or in neither, and requires exactly one
`build_server_config()` call in each.

This does not change the Phase 134 GO: the seam is still one method, and the
trait satisfies all three call sites. It does mean Phase 134 has three call
sites to convert, not one.

## Also established (not findings)

- **Key custody is already one-way.** `synvoid-dns` receives only
  `Arc<rustls::ServerConfig>`; no `PrivateKeyDer`, `CertifiedKey`,
  `load_private_key`, or `key_provider` appears anywhere in
  `crates/synvoid-dns/src`. Now gated.
- **Reload is already provider-internal.** DNS never names `reload_tx`,
  `watch_for_cert_changes`, or `load_certificates`. A successful load emits
  exactly one broadcast event; a failed load emits none. A reload is visible
  through an already-built `ServerConfig`, which is why the replacement trait
  must stay clone-cheap and keep the same interior-mutable indirection. Now
  gated.
- **The client-IP lookup path is silent.** `src/lookup.rs` and the two
  `manager.rs` methods DNS calls contain no `tracing`, `log`, `println!`,
  `eprintln!`, or `dbg!`. Since these run per request, any logging added later
  would turn a country lookup into a client-IP disclosure channel.
- **Acceptor failure releases the port.** The bind happens before the acceptor
  is built, and the listener is dropped on the error path, so a missing
  certificate is a retryable startup failure rather than a permanent conflict.

## Supersessions (by pointer, not rewrite)

- `architecture/dns_runtime_dto_conversion_research.md` — the "zero methods on
  `CertResolver`" statement is superseded by the Decision section above.
- `architecture/dns_application_neutral_readiness_phase109.md` — provider
  inversion is no longer "unsupported/unproven"; it is GO with a named trait.
- `architecture/dns_provider_inversion_phase130_closeout.md` — same correction
  for Workstream E.

## Not done, deliberately

- No trait was introduced. Phase 133's own rejection criteria forbid it.
- No TLS behavior changed, including the absent ALPN (F-6).
- No mesh work.
- No provider was inverted, so the dependency graph is unchanged at 4 direct
  SynVoid normal edges. Phases 134 and 135 target 2.

## Verification

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --profile ci --all-targets -- -D warnings` (touched crates) | clean |
| `cargo test -p synvoid-tls --profile ci` | pass (20 evidence + 3 existing) |
| `cargo test -p synvoid-geoip --profile ci` | pass (11 evidence + 10 existing) |
| `cargo test -p synvoid-dns --profile ci` | pass, exit 0 |
| `cargo test -p synvoid-dns --profile ci --features mesh` | pass, exit 0 |
| `cargo test -p synvoid-repo-guards --profile ci` | pass, 143 repo-guard tests |
| `cargo test --profile ci --features dns --test dns_runtime_config_parity` | **43/43 unchanged** |
| `./scripts/dns/conformance.sh` | **Internal 10/10**; 5 external runnable, 5 skipped (tools not installed) |
| `cargo xtask verify` | **10/10 passed, 477.2s** |

### Two pre-existing `-D warnings` failures found and fixed

`cargo clippy --all-targets -- -D warnings` did **not** pass on this branch
before this phase, contrary to the Phase 132 record. Both were in files this
phase did not otherwise touch, and both are recorded here because the earlier
"clippy clean" claim was not reproducible on the current toolchain:

- `tools/synvoid-repo-guards/tests/dependency_security.rs:607` —
  `clippy::unnecessary_unwrap` on `found.is_none()` followed by
  `found.unwrap()`. Rewritten as a `match` on `found`, semantics unchanged.
- `tools/synvoid-repo-guards/tests/dns_runtime_config_ownership.rs:19` — an
  unused `PathBuf` import.

Neither is a behavior change. Both were blocking the gate this phase needs.
