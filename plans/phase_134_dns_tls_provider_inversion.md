# Phase 134 Plan: TLS Provider Inversion

Status: **PLANNED** (2026-10-05).

Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 133 GO for TLS.
Registered in: `plans/roadmap.md`.

## Goal

Remove the direct `synvoid-tls` dependency edge from `synvoid-dns` by
introducing a DNS-owned secure-transport capability, implemented in a
composition root.

Conditional: proceeds only on a Phase 133 **GO**. On DEFER, this phase is
dropped and the campaign proceeds to Phase 135.

## Background

`synvoid-dns` names `synvoid_tls` in five modules, always as a type in a
signature or field — never for a DNS-owned concept:

| Site | Use |
|---|---|
| `crates/synvoid-dns/src/server/mod.rs:23,1652,1767` | `Option<Arc<CertResolver>>` field + constructor |
| `crates/synvoid-dns/src/secure_server.rs:28,34` | `SecureDnsServerBase` field + constructor |
| `crates/synvoid-dns/src/dot.rs:35`, `doh.rs:39`, `doq.rs:16,23` | constructor parameters |
| `crates/synvoid-dns/src/server/mod.rs:1594,1621,1667,2073` | `Option<Arc<synvoid_tls::AcmeDnsChallenge>>` |
| `crates/synvoid-dns/src/server/query.rs:993` | the single `get_txt_value` call |

`synvoid-dns` already depends on `rustls` and `tokio-rustls` directly, so a
rustls-shaped DNS capability adds **no** new dependency.

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

## Workstream B — composition implementation

Implement both traits in root composition, over the concrete TLS types:

- `src/server/` (or the TLS adapter location the root module ledger assigns) —
  newtype wrappers holding `Arc<CertResolver>` and `Arc<AcmeDnsChallenge>`,
  delegating the one or two methods each.
- `src/server/resources.rs:140` passes the wrapped provider instead of
  `cert_resolver.clone()`.
- The `with_acme_dns_challenges` builder at `server/mod.rs:2073` and its callers
  are updated to the trait.

Check `architecture/root_module_ledger.md` and
`architecture/facade_disposition_matrix.md` for the correct composition home
before adding a file, and record the choice.

## Workstream C — dependency removal

- remove the `synvoid-tls` manifest edge from `crates/synvoid-dns/Cargo.toml`;
  note it currently requests `features = ["dns"]`, so confirm nothing else in
  the crate needs that feature;
- zero remaining `synvoid_tls` references in `crates/synvoid-dns/src/**`;
- if a DNS test needs a real resolver, it must build one through the
  composition-owned wrapper or use a test double — not by re-adding the edge;
- extend `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` with a live
  manifest gate and a source-level gate, following the existing whole-token
  matching convention so `SyncTransportConfig` does not trip a `Config` gate.

## Workstream D — parity

- DoT, DoH, and DoQ startup, handshake, and failure paths unchanged;
- the "no TLS certificate resolver available" error unchanged;
- zero-port rejection unchanged;
- ACME TXT answer unchanged, including the absent-challenges case;
- `tls_1_3_only` / fallback / backward-compat policy and the `prefer_post_quantum`
  provider choice unchanged, verified through the Phase 133 evidence tests.

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
