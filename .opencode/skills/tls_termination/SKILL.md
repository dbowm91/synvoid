---
name: tls_termination
description: TLS termination — cert resolver hot-reload, ACME, SNI peeking, JA4, post-quantum option. Use when touching HTTPS listeners, certificates, or TLS config.
---

# Skill: TLS Termination

## Context

TLS termination lives canonically in `synvoid-tls`; `src/tls/` holds the
`HttpsServer` composition (cert-resolver use lives in the crate — do not
invert this). Full reference: `architecture/tls.md`,
`architecture/tls_deep_dive.md`.

## When to Use

- Changing certificate loading, hot-reload, or ACME (HTTP-01/DNS-01)
- Touching SNI routing/peeking or JA4 fingerprinting
- Modifying `TlsConfig` / `prefer_post_quantum` handling
- Debugging TLS handshake or cert-watch failures

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-tls/src/cert_resolver.rs` | Cert resolver with hot-reload (`watch_for_cert_changes`); honors `prefer_post_quantum` |
| `crates/synvoid-tls/src/config.rs` | `TlsConfig` / `InternalTlsConfig` conversion |
| `crates/synvoid-tls/src/sni_peek.rs` | SNI peeking for routing before termination |
| `crates/synvoid-tls/src/acme.rs`, `acme_dns.rs` | ACME issuance (HTTP-01 / DNS-01) |
| `src/tls/server.rs` | `HttpsServer` composition; logs PQ status at startup |
| `crates/synvoid-config/src/tls.rs` | `TlsConfig` schema (`prefer_post_quantum` defaults true) |

## Non-Negotiables

1. **`prefer_post_quantum = true` is the config default but only takes
   effect in `--features post-quantum` builds**; without the feature the
   server logs "disabled (feature not enabled)". Never describe PQ as
   unconditionally on.
2. **TLS 1.3-only by default** (`tls_1_3_only = true`); 1.2 fallback is
   explicit opt-in (`enable_tls_12_fallback`).
3. **Cert/key files follow the key-custody rules**: mode `0o600`, atomic
   write/rename; overly-permissive files are refused on load.
4. JA4 wiring for bot detection lives in `src/tls/server.rs` — coordinate
   with the `waf_bot_detection` skill when changing fingerprints.

## Verification

```bash
cargo nextest run -p synvoid-tls --cargo-profile ci --profile ci
```
