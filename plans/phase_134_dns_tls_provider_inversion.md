# Phase 134 Plan: TLS Provider Inversion

Status: **CLOSED QUALIFIED** (2026-10-05). Phase 133 returned **GO** — see
`architecture/dns_provider_inversion_phase133_closeout.md`. Closeout:
`architecture/dns_provider_inversion_phase134_closeout.md`.

Outcome: the `synvoid-tls` edge is gone. Direct SynVoid normal edges 4 → 3
(`synvoid-dnssec-keystore`, `synvoid-geoip`, optional `synvoid-mesh`); expanded
normal-tree lines 827 → 717. No TLS behavior changed.

Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 133 GO for TLS.
Registered in: `plans/roadmap.md`.

## Goal

Remove the direct `synvoid-tls` dependency edge from `synvoid-dns` by
introducing a DNS-owned secure-transport capability, implemented in a
composition root.

Conditional: proceeds only on a Phase 133 **GO**. On DEFER, this phase is
dropped and the campaign proceeds to Phase 135. **GO received.**

## Background

`synvoid-dns` names `synvoid_tls` in five modules, always as a type in a
signature or field — never for a DNS-owned concept:

| Site | Use |
|---|---|
| `crates/synvoid-dns/src/server/mod.rs:23,1652,1767` | `Option<Arc<CertResolver>>` field + constructor |
| `crates/synvoid-dns/src/secure_server.rs:28,34` | `SecureDnsServerBase` field + constructor |
| `crates/synvoid-dns/src/secure_server.rs:53` | **call site 1** — `build_server_config()` (DoT + DoH) |
| `crates/synvoid-dns/src/doq.rs:16,23` | constructor parameters |
| `crates/synvoid-dns/src/doq.rs:105,112` | **call site 2** — its own `create_tls_config` (DoQ, QUIC) |
| `crates/synvoid-dns/src/server/mod.rs:1594,1621,1667,2073` | `Option<Arc<synvoid_tls::AcmeDnsChallenge>>` |
| `crates/synvoid-dns/src/server/query.rs:997` | **call site 3** — the single `get_txt_value` call |

`synvoid-dns` already depends on `rustls` and `tokio-rustls` directly, so a
rustls-shaped DNS capability adds **no** new dependency.

### F-12 — the contract is duplicated, so there are two TLS call sites

DoT and DoH share `SecureDnsServerBase::create_tls_acceptor`. DoQ does **not**
share that base: it is QUIC, needs a `quinn::QuicServerConfig` rather than a
`TlsAcceptor`, and `DoqRuntimeConfig` does not implement `DnsServerConfig` at
all. `DoqServer::create_tls_config` (`crates/synvoid-dns/src/doq.rs:105`)
re-implements the same two error literals around its own call.

Both copies must be converted together. Converting one and leaving the other
would give DoQ different diagnostics from DoT and DoH, which
`encrypted_transport_error_contract_is_duplicated_consistently` will catch.

## Workstream A — DNS-owned capability

Two narrow capabilities, both in a new DNS-owned module:

1. **Secure transport config** — the only thing DNS actually needs from TLS is a
   built rustls server config:

   ```rust
   pub trait SecureTransportConfig: Send + Sync {
       fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String>;
   }
   ```

   The error is a `String` because the current call site already flattens the
   provider error into `"Failed to build TLS config: {e}"`; preserving the
   message keeps the existing failure text.

2. **ACME TXT challenge lookup** — one method, matching
   `AcmeDnsChallenge::get_txt_value` (`crates/synvoid-tls/src/acme_dns.rs:48`):

   ```rust
   pub trait AcmeTxtChallenges: Send + Sync {
       fn txt_value(&self, domain: &str) -> Option<String>;
   }
   ```

Design constraints:

- The traits must not mention `synvoid_tls` in any signature.
- `rustls::ServerConfig` is a rustls type, not a SynVoid type, and is the
  correct return type: it is what `TlsAcceptor::from` consumes.
- Use `Arc<dyn Trait>` at the call sites, replacing `Option<Arc<CertResolver>>`
  with `Option<Arc<dyn SecureTransportConfig>>`. This is the same shape the
  Phase 125–130 composition-boundary work already uses elsewhere in the repo.
- The trait object must stay **cheap to clone and interior-mutable behind an
  `Arc`**. Phase 133 proved a reload is visible through an already-built
  `ServerConfig` because the resolver's certificate map is shared; a trait that
  forces a rebuild per handshake would break certificate reload.

## Workstream B — composition implementation

Implement both traits in root composition, over the concrete TLS types:

- `src/server/` (or the TLS adapter location the root module ledger assigns) —
  newtype wrappers holding `Arc<CertResolver>` and `Arc<AcmeDnsChallenge>`,
  delegating the one or two methods each.
- `src/server/resources.rs:140` passes the wrapped provider instead of
  `cert_resolver.clone()`.
- The `with_acme_dns_challenges` builder at `server/mod.rs:2073` and its callers
  are updated to the trait.
- Both `create_tls_acceptor` (`secure_server.rs:47`) and `create_tls_config`
  (`doq.rs:105`) are converted in the same commit, keeping their two literals
  identical.

Check `architecture/root_module_ledger.md` and
`architecture/facade_disposition_matrix.md` for the correct composition home
before adding a file, and record the choice.

## Workstream C — dependency removal

- remove the `synvoid-tls` manifest edge from `crates/synvoid-dns/Cargo.toml`;
  note it currently requests `features = ["dns"]`, so confirm nothing else in
  the crate needs that feature;
- zero remaining `synvoid_tls` references in `crates/synvoid-dns/src/**`;
- if a DNS test needs a real resolver, it must build one through the
  composition-owned wrapper or use a test double — not by re-adding the edge.
  Phase 133's `encrypted_transport_startup_contract.rs` currently constructs a
  `CertResolver` directly and will have to move to a double;
- extend `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` with a live
  manifest gate and a source-level gate, following the existing whole-token
  matching convention so `SecureTransportConfig` does not trip a `Config` gate.

## Workstream D — parity

- DoT, DoH, and DoQ startup, handshake, and failure paths unchanged;
- the "no TLS certificate resolver available" error unchanged;
- zero-port rejection unchanged, and the port is still released on an acceptor
  failure;
- ACME TXT answer unchanged, including the absent-challenges case;
- `tls_1_3_only` / fallback / backward-compat policy unchanged, verified through
  the Phase 133 evidence tests;
- **no ALPN is added** (F-6) and **`prefer_post_quantum` is not described as a
  preference** (F-7 — it is telemetry only and gates nothing). Neither is in
  scope, and adding either would be a TLS behavior change disguised as an
  inversion.

## Workstream E — documentation

- `architecture/dns.md` — the DNS-owned capability and the composition
  implementation;
- `architecture/dns_config_runtime_matrix.md` — Phase 131/132/133 findings plus
  this phase's (F-12…);
- `architecture/request_path_capability_boundary.md` if the new traits are
  request-path-adjacent;
- `AGENTS.md` facade table if a canonical home changed;
- campaign roadmap and `plans/roadmap.md`.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo metadata --format-version 1 --no-deps | # assert no synvoid-tls dep on synvoid-dns
cargo tree -p synvoid-dns -e normal
cargo tree -p synvoid-dns -e normal -i synvoid-tls
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-tls --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo deny check
cargo audit
cargo xtask verify
```

## Acceptance criteria

- no direct `synvoid-tls` edge, proven by `cargo metadata` and `cargo tree`;
- zero `synvoid_tls` references in `crates/synvoid-dns/src/**`;
- DoT/DoH/DoQ and ACME parity green;
- the provider is implemented in composition, not in `synvoid-dns`;
- direct SynVoid normal edges fall from 4 to 3.

## Rejection criteria

Reject a closeout that:

- leaves a `synvoid_tls` path in a trait signature;
- implements the provider inside `synvoid-dns`;
- re-adds the manifest edge for a test;
- changes TLS behavior (ALPN, protocol versions, mTLS) to make inversion
  easier;
- claims the edge is removed without `cargo metadata` / `cargo tree` proof.

## Closeout

`architecture/dns_provider_inversion_phase134_closeout.md`.
