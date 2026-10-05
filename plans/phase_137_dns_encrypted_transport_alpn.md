# Phase 137 Plan: ALPN Negotiation for DoT and DoH

Status: **REGISTERED** (2026-10-05). Not started.

Campaign: `plans/dns_residual_truthfulness_roadmap.md` (REGISTERED).
Predecessor: Phase 136 (the campaign that recorded this residual, CLOSED
QUALIFIED). Registered in: `plans/roadmap.md`.

Source residual: Phase 133 **F-6** (severity medium), recorded not changed in
`architecture/dns_provider_inversion_phase133_closeout.md` and carried in
`architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md` §
"Residual work this campaign deliberately left" item 3.

## Correction to the registered problem statement

Phase 136 and the campaign closeout record F-6 as "no ALPN is configured" and
the Phase 133 closeout states the consequence applies to "the DoT/DoH/DoQ
listeners". **Both are over-claims and this plan corrects them before scoping.**

`crates/synvoid-dns/src/doq.rs:71-72` already configures ALPN for DoQ:

```rust
let mut server_crypto = (*tls_config).clone();
server_crypto.alpn_protocols = vec![b"doq".to_vec()];
```

DoQ is therefore correct today (RFC 9250). The real gap is **DoT and DoH only**.
`architecture/dns_config_runtime_matrix.md:1507` says "no ALPN is configured
anywhere in the TLS path" and must be corrected by this phase. A plan written
from the original wording would over-build by touching a correct transport.

This correction is applied **by pointer** in the Phase 133 closeout and the
campaign closeout; historical records are not rewritten.

## The actual structural problem

The Phase 133 closeout frames this as "a protocol behavior change". That is
true but understates the cost, and the matrix (`:1524-1526`) frames it as "all
three transports at once", which is wrong in a way that matters:

**DoT and DoH share one TLS builder that needs two different ALPN values.**

| Transport | Entry | Builder | ALPN needed |
|---|---|---|---|
| DoT | `crates/synvoid-dns/src/dot.rs` `start_server` | `secure_server.rs:101` → `create_tls_acceptor` (`secure_server.rs:55-65`) | none (RFC 7858 defines none) |
| DoH | `crates/synvoid-dns/src/doh.rs:65` `start_server` | **the same** `create_tls_acceptor` | `h2` |
| DoQ | `crates/synvoid-dns/src/doq.rs:69` | `doq.rs:116` `create_tls_config` | `doq` — already set |

There is no correct DoT ALPN value. `dot` is IANA-registered but is not offered
by mainstream DoT clients, and advertising it would make rustls **require**
negotiation, breaking those clients. So DoT must keep an empty ALPN list while
DoH must advertise `h2` — through a shared builder.

Adding `h2` to `create_tls_acceptor` as-is would silently break DoT. This is the
reason the phase changes a signature rather than a constant.

## Blast radius (rustls 0.23.44)

`src/server/hs.rs:100-118` in rustls: when the server's `our_protocols` is
non-empty and there is no overlap with the client's, the server sends a fatal
`NoApplicationProtocol` alert. Because the check sits inside
`if let Some(their_protocols)`, **a client offering no ALPN at all still
connects.** So the concrete risk is narrower than "DoT breaks" — it is "a DoT
client that offers an ALPN we did not advertise is now rejected."

## Why DoH `h2` is correct and `http/1.1` is not

`crates/synvoid-dns/src/doh.rs:95` builds the connection server with
`hyper::server::conn::http2::Builder`. There is no `http1` import on that path.
DoH in this crate is HTTP/2-only by construction, so advertising `http/1.1`
would be a protocol lie the handler cannot honour. `h2` alone is correct.

DoH's protocol version is already a fixed constant by construction
(`crates/synvoid-dns/src/runtime_config.rs:328-331` records served routes as
"fixed protocol constants … absent by design").

## Goal

Advertise ALPN per transport so that a DoH client requiring ALPN negotiation
completes a handshake, without changing DoT or DoQ behavior.

## Workstream A — decide the ALPN plumbing shape

Options, in preference order:

1. **Set ALPN at the call sites, after `create_tls_acceptor` returns**, mutating
   a clone exactly as `doq.rs:71-72` already does. Requires no signature change
   to `SecureTransportConfig` and keeps the Phase 134 seam intact. **Preferred.**
2. Add an `alpn: Vec<Vec<u8>>` parameter to
   `SecureTransportConfig::server_config()` (`secure_transport.rs:44`) or thread
   it through `create_tls_acceptor`. More explicit, but re-opens a trait
   signature Phase 134 deliberately closed.

Record which was chosen and why. If option 2, note explicitly that it re-opens
the Phase 134 seam and must not widen the provider's responsibilities.

## Workstream B — implement DoH ALPN

- advertise exactly `h2` on the DoH path;
- leave the DoT path with an empty `alpn_protocols`;
- leave `doq.rs` untouched, and add a guard that keeps its `doq` ALPN intact;
- do not add an ALPN config knob. The repo's convention is that served protocol
  constants are absent by design, and a knob would recreate the inert-setting
  problem this campaign exists to close (see `architecture/dns_config_runtime_matrix.md`
  and the F-2 `PERSISTURE` reclassification precedent at `:1212-1215`).

## Workstream C — update the duplication guard

`tools/synvoid-repo-guards/tests/dns_dependency_edges.rs:325` documents that
DoT and DoH share `create_tls_acceptor` while DoQ duplicates the two error
literals. The guard at `:335` requires both literals in both files or neither.
Extend it to assert:

- the DoQ `doq` ALPN literal is still present (no regression against the
  already-correct transport);
- DoT and DoH do **not** share one ALPN value, i.e. the DoH path sets `h2` and
  the DoT path does not.

## Workstream D — evidence

New pins in `crates/synvoid-dns/tests/encrypted_transport_startup_contract.rs`
or a sibling suite:

- a DoH handshake with a client offering only `h2` negotiates `h2`;
- a DoH handshake with a client offering `h2` and `doq` negotiates `h2`;
- a DoT handshake with a client offering no ALPN still succeeds;
- a DoT handshake with a client offering a non-advertised protocol still
  succeeds **or** fails — record which, as the actual observed behavior, rather
  than assuming;
- a DoQ handshake still negotiates `doq` (parity with today's behavior).

**Two existing pins stay true and must NOT be inverted:**
`build_server_config_configures_no_alpn_protocols`
(`crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs:536`) and
`no_alpn_is_negotiated_even_when_the_client_offers_one` (`:557`). Both assert
that the *provider* configures no ALPN, which remains correct because ALPN is
set at the DNS call sites, not in the provider. This is the opposite of the
Phase 135 F-1 case, where the pin was inverted because the fix landed in the
same layer the pin covered.

## Workstream E — documentation

- correct `architecture/dns_config_runtime_matrix.md:1507` and `:1524-1526`
  (the "anywhere" and "all three transports" claims);
- correct the F-6 row in
  `architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md`
  and `architecture/dns_provider_inversion_phase133_closeout.md` **by pointer**
  — add a correction note, do not rewrite the historical finding;
- `architecture/dns.md` if it describes the encrypted transports.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-tls --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo deny check
cargo audit
./scripts/dns/conformance.sh
cargo xtask verify
```

## Acceptance criteria

- a DoH client that requires ALPN negotiation completes a handshake and
  negotiates `h2`;
- DoT and DoQ handshake behavior is unchanged from the pre-phase baseline, with
  the observed behavior recorded rather than assumed;
- the two `synvoid-tls` provider ALPN pins are unmodified and still pass;
- the duplication guard proves DoT and DoH do not share one ALPN value;
- no persisted TOML, OpenAPI, or admin schema change.

## Rejection criteria

Reject a closeout that:

- sets one ALPN value on the shared `create_tls_acceptor` and thereby changes
  DoT behavior;
- modifies or deletes the two `synvoid-tls` provider ALPN pins;
- touches DoQ's existing `doq` ALPN;
- adds a configuration knob for ALPN;
- advertises `http/1.1` on a path whose handler is HTTP/2-only;
- leaves `architecture/dns_config_runtime_matrix.md` asserting "no ALPN
  anywhere".

## Closeout

`architecture/dns_provider_inversion_phase137_closeout.md`.
