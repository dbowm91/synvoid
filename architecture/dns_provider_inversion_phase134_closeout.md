# Phase 134 Closeout: TLS Provider Inversion

Date: 2026-10-05
Plan: `plans/phase_134_dns_tls_provider_inversion.md`
Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`
Predecessor: Phase 133 (`architecture/dns_provider_inversion_phase133_closeout.md`)
Disposition: **CLOSED QUALIFIED**

## What this phase did

Removed the direct `synvoid-tls` dependency edge from `synvoid-dns` by
replacing the two concrete provider types with two DNS-owned capabilities
implemented in composition. No TLS behavior changed.

| Provider type removed | DNS-owned capability | Composition adapter |
|---|---|---|
| `Arc<CertResolver>` | `SecureTransportConfig::server_config` | `src/tls/dns_providers.rs::CertResolverTransport` |
| `Arc<AcmeDnsChallenge>` | `AcmeTxtChallenges::txt_value` | `src/tls/dns_providers.rs::AcmeChallengeLookup` |

Both traits live in the new `crates/synvoid-dns/src/secure_transport.rs`. Neither
names a `synvoid-tls` type; the only external type in either signature is
`rustls::ServerConfig`, which is what `TlsAcceptor::from` and
`quinn::QuicServerConfig::try_from` already consumed.

## Dependency proof

```
$ cargo metadata --format-version 1 --no-deps   # synvoid-dns direct synvoid deps
['synvoid-dnssec-keystore', 'synvoid-geoip', 'synvoid-mesh']
confirmed: no synvoid-tls edge

$ cargo tree -p synvoid-dns -e normal | grep -c synvoid-tls
0
```

| Measure | Before (Phase 133) | After | Change |
|---|---|---|---|
| Direct SynVoid normal edges | 4 | **3** | −1, target met |
| Expanded `cargo tree -e normal` lines | 827 | **717** | −110 |

The 110-line drop is larger than one crate because `synvoid-tls` transitively
carried `instant-acme`, `rcgen`, `x509-parser`, `rsa`, `dashmap`, and `notify`
into the DNS closure. None of those are DNS concerns.

`synvoid-tls` still exists for the root's own HTTPS and HTTP/3 servers
(`src/tls/server.rs`, `get_cert_resolver`), which is correct: those are
composition, and they hold the concrete type deliberately. `ServerSharedState`
keeps `Option<Arc<CertResolver>>`; only the DNS wiring is inverted.

Zero `synvoid_tls` references remain in `crates/synvoid-dns/src`.

## Composition home

`src/tls/dns_providers.rs`, recorded in `architecture/root_dependency_ownership.md`
by extending the `synvoid-dns` root-consumer allowlist from `dns, server` to
`dns, server, tls`.

`src/tls/` was chosen because it already re-exports both providers
(`pub use synvoid_tls::CertResolver`, `pub use synvoid_tls::AcmeDnsChallenge`)
as a compatibility surface. Putting the adapters there means the one module
that already knows both concrete types is also the only module that bridges
them to the DNS capabilities, and the root dependency guard now enforces that.

The adapters hold an `Arc` to the provider and are themselves `Clone`, so
cloning is cheap and certificate state stays shared — the property Phase 133
proved is required for a reload to be visible through an already-built
`ServerConfig`. Both `as_transport` and `as_acme_challenges` map `None` to
`None`, so a disabled TLS section still reports "No TLS certificate resolver
available" rather than becoming a provider that fails for a different reason.

## F-12 resolved as planned

Phase 133 found the encrypted-transport TLS contract **duplicated**: DoT and DoH
share `SecureDnsServerBase::create_tls_acceptor`, while DoQ is QUIC with its own
`DoqServer::create_tls_config` (`crates/synvoid-dns/src/doq.rs:105`) because
`quinn` needs a `QuicServerConfig` and `DoqRuntimeConfig` does not implement
`DnsServerConfig`.

Both copies were converted in the same commit, both now call
`SecureTransportConfig::server_config()`, and both keep the same two literals.
The Phase 133 guard
`encrypted_transport_error_contract_is_duplicated_consistently` was updated to
match the new method name and additionally asserts that **neither** file calls
the concrete `build_server_config()` any more, so a partial revert fails.

## New gates

| Gate | Pins |
|---|---|
| `synvoid_dns_has_no_tls_edge` | manifest declares no `synvoid-tls` in any dependency section |
| `dns_source_names_no_tls_provider_symbol` | no `use`/`::` path in `synvoid-dns/src` names `synvoid_tls`, `CertResolver`, `AcmeDnsChallenge`, or `build_server_config` |
| `dns_declares_exactly_the_two_tls_capabilities` | both traits exist and declare exactly the two evidenced signatures |

The signature gate asserts the exact method signatures rather than just method
names, so a signature change fails as a gate violation instead of silently
widening or narrowing the seam.

## The DNS-side test now proves more than it did

`crates/synvoid-dns/tests/encrypted_transport_startup_contract.rs` previously
constructed a real `CertResolver` to produce its failing messages. That is
impossible once the edge is gone, and reconstructing one in a test would have
meant re-adding the dependency the phase exists to remove.

It now uses a **DNS-owned stub** implementing `SecureTransportConfig`, with a
sentinel error message chosen by the test. This is a strictly better contract
test: a constant can no longer masquerade as a propagated message, because the
expected text comes from the stub rather than from a hard-coded literal in the
assertion. The provider's own behavior — what those messages *are* — remains
proven in `crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs`, which
is where a real provider belongs.

The stub's success path builds a genuine `rustls::ServerConfig` whose cert
resolver yields no certificate, reproducing the "provider built a config but
holds no material" case without `synvoid-tls`.

## One guard made formatting-robust

`composition_activates_configured_zones` (Phase 132) located the constructor by
matching `DnsServer::new(runtime_cfg` on a single line. Adding a second argument
made rustfmt wrap the call, so the guard failed on formatting alone while its
actual invariant — zones cloned before the runtime config is moved — remained
satisfied.

It now anchors on `DnsServer::new(` and scans forward for the moved
`runtime_cfg`. The invariant is unchanged; the anchor is no longer coupled to
line shape. Worth recording because the failure mode was a false positive that
could have been "fixed" by weakening the real assertion.

## Parity

Nothing about TLS behavior moved. The five Phase 133 evidence suites for
`synvoid-tls` pass unchanged (20 evidence + 3 existing), and the DNS-side
startup contract still asserts the same strings:

- `"No TLS certificate resolver available"` — absent provider, all transports;
- `"Failed to build TLS config: {e}"` — provider failure, propagated verbatim;
- `"Invalid {name} bind address: port cannot be zero"` — before any socket;
- an acceptor failure still releases the bound port.

No ALPN was added (F-6) and `prefer_post_quantum` was not documented as a
preference (F-7), exactly as the Phase 133 plan required.

## Verification

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --profile ci --all-targets -- -D warnings` (touched crates) | clean |
| `cargo test -p synvoid-dns --profile ci` | pass, exit 0 |
| `cargo test -p synvoid-dns --profile ci --features mesh` | pass, exit 0 |
| `cargo test -p synvoid-tls --profile ci` | pass (20 evidence + 3 existing) |
| `cargo test -p synvoid-repo-guards --profile ci` | pass, 143 repo-guard tests |
| `cargo metadata` / `cargo tree` edge proof | `synvoid-tls` absent |
| `cargo test --profile ci --features dns --test dns_runtime_config_parity` | **43/43 unchanged** |
| `cargo test --profile ci --features dns --test dns_zone_startup_activation` | 4/4 |
| `./scripts/dns/conformance.sh` | **Internal 10/10**; 5 external runnable, 5 skipped (tools not installed) |
| `cargo deny check` | see campaign qualification (Phase 136) |
| `cargo xtask verify` | **10/10 passed, 439.8s** |

## Not done, deliberately

- `synvoid-geoip` is still a direct edge. That is Phase 135.
- No TLS behavior change of any kind, including the absent ALPN.
- `SecureTransportConfig` returns `String`, not a typed error. That is a
  separate change; widening it here would alter the failure text operators see.
- `synvoid-dns` remains class 1. Dependency reduction is not publication
  readiness, and the campaign's success criteria say so explicitly.
