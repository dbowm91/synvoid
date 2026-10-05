# Phase 137 Closeout: ALPN Negotiation for DoH

Date: 2026-10-05
Plan: `plans/phase_137_dns_encrypted_transport_alpn.md`
Campaign: `plans/dns_residual_truthfulness_roadmap.md` (REGISTERED)
Predecessor: Phase 136 (`architecture/dns_provider_inversion_phase136_closeout.md`)
Residual source: Phase 133 **F-6**
Disposition: **CLOSED QUALIFIED**

## What this phase did

DoH now advertises ALPN `h2`. DoT and DoQ are unchanged, deliberately and for
different reasons. ALPN is applied at the DNS call sites, not in the TLS
provider, so the provider capability is untouched.

The headline is small, but the phase is not a one-line constant edit, for the
reason recorded in the plan: **DoT and DoH share one TLS builder and need two
different ALPN values.** A change that set `h2` on the shared builder would have
silently broken DoT.

## The corrections this phase made before scoping

The plan carried a correction section, and it was load-bearing. The registered
problem statement was wrong in two ways:

1. **"No ALPN is configured anywhere in the TLS path" was an over-claim.**
   `crates/synvoid-dns/src/doq.rs:72` already set `doq` ALPN and was correct per
   RFC 9250. A phase scoped from the original wording would have touched the one
   transport that had nothing wrong with it.
2. **"On all three transports at once" was the wrong instruction to leave
   behind.** The gap was DoT and DoH, which *share* one builder. The work was a
   signature change, not a list edit.

A plan written from the closeout wording alone would have over-built on DoQ and
under-specified the shared builder. Both corrections are applied **by pointer** —
`architecture/dns_provider_inversion_phase133_closeout.md` and
`architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md` each
carry a correction note; neither historical finding was rewritten.

## Workstream A — the plumbing shape actually chosen

The plan offered two options and marked option 1 (set ALPN at the call sites
after `create_tls_acceptor` returns) as **preferred**.

**Option 1 as literally written is not achievable**, and this is worth
recording rather than quietly substituting something else. `create_tls_acceptor`
is called *internally* by `start_server` (`secure_server.rs`, `let acceptor =
Arc::new(self.create_tls_acceptor(...)?)`) and its result is never returned to a
caller. There is no call site to mutate.

The shape actually implemented is the nearest correct one: **`alpn_protocols` is
a parameter** on both `create_tls_acceptor` and `start_server`, and each
transport passes its own constant. This keeps the *intent* of option 1 — ALPN is
applied outside the provider, at the transport's own call site — without
re-opening the Phase 134 trait seam. `SecureTransportConfig::server_config()`
is unchanged, and still takes no ALPN argument.

| Location | Change |
|---|---|
| `secure_server.rs` | `pub type AlpnProtocols = &'static [&'static [u8]]`; new private `with_alpn`; parameter on `create_tls_acceptor` and `start_server` |
| `dot.rs` | `pub const DOT_ALPN: AlpnProtocols = &[]` |
| `doh.rs` | `pub const DOH_ALPN: AlpnProtocols = &[b"h2"]` |
| `doq.rs` | **untouched** |

### `with_alpn` returns the provider's object untouched for DoT

```rust
if alpn_protocols.is_empty() {
    return shared;
}
```

DoT's `ServerConfig` is the provider's own `Arc`, not a clone. This is stronger
than "DoT behavior is unchanged" — it is structurally incapable of having
changed, because nothing is copied or mutated.

The clone taken for DoH is **shallow**: `rustls::ServerConfig` is `Clone` and its
certificate resolver is itself `Arc`-backed, so certificate reload stays visible
through the already-built config. That is the property
`a_reload_is_visible_through_an_already_built_server_config` pins on the provider
side, and it survives this change. The doc comment on `with_alpn` says so, so a
future refactor that caches per call does not silently break reload.

### Why ALPN is not a config knob

The plan forbade one, and the guard enforces it: `runtime_config.rs` must not
mention ALPN at all. Served protocol constants are absent by design
(`architecture/dns_config_runtime_matrix.md`), and a knob there would be inert by
construction — the exact defect class this campaign exists to close (the F-2
`PERSISTENCE` precedent). ALPN is a property of the protocol a transport speaks,
so it lives next to that transport's implementation, not in a config DTO.

A second reason the parameter is not on the `DnsServerConfig` trait (which
`DotRuntimeConfig` / `DohRuntimeConfig` implement): putting it there would have
made a protocol constant look like an operator setting on the runtime DTO, which
is precisely the confusion the guard forbids.

## Workstream B/D — wire evidence

New suite: `crates/synvoid-dns/tests/encrypted_transport_alpn_negotiation.rs`.
Every pin is a **real handshake against a real loopback listener**, not a struct
field. `alpn_protocols` being non-empty does not prove anything is negotiated,
and a non-empty list changes handshake *outcomes*; only the wire shows that.

Certificate material is generated in process with `rcgen` (added as a
**dev-dependency** of `synvoid-dns`, matching `synvoid-tls`, `synvoid-mesh`,
`synvoid-tunnel`, and `synvoid-http-client`), so no fixture PEM is checked in and
nothing expires. It adds no normal edge.

The 8 tests and their **observed** results:

| Test | Result |
|---|---|
| `doh_negotiates_h2_for_a_client_that_offers_only_h2` | negotiates `h2` |
| `doh_negotiates_h2_over_a_mixed_offer` | offers `doq`+`h2` → negotiates `h2` (server preference wins) |
| `doh_rejects_a_client_that_offers_no_shared_protocol` | offers `dot` only → handshake **fails** |
| `dot_completes_a_handshake_from_a_client_that_offers_no_alpn` | succeeds, negotiates nothing |
| `dot_ignores_an_alpn_offer_rather_than_rejecting_it` | offers `h2` → **succeeds**, negotiates nothing |
| `the_shared_builder_does_not_make_dot_and_doh_agree` | same offer, different answers: DoT `None`, DoH `h2` |
| `doq_still_negotiates_doq` | real QUIC handshake → negotiates `doq` |
| `the_provider_supplies_no_alpn_of_its_own` | provider's `alpn_protocols` is empty |

### The DoT case was observed, not assumed

The plan asked for this explicitly ("still succeeds **or** fails — record
which, as the actual observed behavior, rather than assuming"). Observed: a DoT
client that *offers* `h2` **succeeds**, with no protocol selected. This is
narrower and more precise than the plan's blast-radius note predicted: the
mismatch check is gated on the server having a non-empty list, and DoT has none,
so there is nothing to mismatch.

The practical consequence is now pinned rather than merely argued: had DoT been
given the IANA-registered `dot` identifier, rustls would send a fatal
`NoApplicationProtocol` alert for exactly this client.

`doh_rejects_a_client_that_offers_no_shared_protocol` is the flip side and is
easy to forget: advertising `h2` means DoH **must not** serve a client speaking
something else. That is correct, not a regression — the handler is HTTP/2-only.

## The two provider pins stay true, and that was the design constraint

`crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs`:

- `build_server_config_configures_no_alpn_protocols` (`:536`) — **unmodified, passes**
- `no_alpn_is_negotiated_even_when_the_client_offers_one` (`:557`) — **unmodified, passes**

Both assert the *provider* configures no ALPN, which is still true because ALPN
is applied above it. This is the opposite of the Phase 135 F-1 disposition, where
the fix landed inside the layer the pin covered and the pin had to be inverted.
Choosing the call-site placement is what kept them valid.

## Workstream C — the source gate, and proof it can fail

New guard: `encrypted_transport_alpn_is_per_transport`
(`tools/synvoid-repo-guards/tests/dns_dependency_edges.rs`). It asserts the
shared base hardcodes **no** protocol, each stream transport passes its own
constant, DoT's constant is empty and contains no `h2`, DoH's is exactly
`[b"h2"]` with no `http/1.1`, DoQ keeps its `doq` value and is not routed through
the base, and `runtime_config.rs` never mentions ALPN.

A gate that cannot fail is worse than no gate, so it was **mutation-tested**.
Three deliberate regressions, each caught with an actionable message:

| Mutation | Result |
|---|---|
| `DOT_ALPN` changed to `&[b"h2"]` | FAILED — "must stay empty" + "must not advertise `h2`" |
| `b"h2"` hardcoded in `secure_server.rs` | FAILED — "the shared builder hardcodes the ALPN protocol" |
| a comment mentioning `alpn` added to `runtime_config.rs` | FAILED — "must not mention ALPN" |

Tree restored and the guard re-run clean after each.

## A real defect found and fixed: a tautological test

`crates/synvoid-dns/tests/encrypted_transport.rs` contained:

```rust
#[test]
fn doq_alpn_is_doq() {
    assert_eq!(b"doq", b"doq");
}
```

This compares two byte-string literals. It asserts **nothing** about the code, it
would pass if the entire DoQ ALPN configuration were deleted, and it was the only
test in the repository purporting to pin DoQ's ALPN. It is now replaced by
`doq_still_negotiates_doq`, which drives a real QUIC handshake.

This is recorded as a finding rather than a silent cleanup: **a green suite
containing that test provided no evidence about DoQ ALPN**, and the previous
campaign recorded DoQ's ALPN as "already correct" partly on the strength of a
test that could not detect its absence. (The `doq.rs:72` source line is real; the
conclusion was right by inspection, not by test.)

## Workstream E — documentation

| File | Correction |
|---|---|
| `architecture/dns_config_runtime_matrix.md:1507` | F-6 row no longer says "anywhere in the TLS path"; it now names the provider and points at Phase 137 |
| `architecture/dns_config_runtime_matrix.md` §F-6 detail | Supersession block correcting both over-claims, original text preserved |
| `architecture/dns_provider_inversion_phase133_closeout.md` §F-6 | Correction block; original finding preserved |
| `architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md` | Residual item 3 annotated; new Supersessions entry |
| `architecture/dns.md` | Encrypted-transport table gains an **ALPN** column, plus a note on why the provider configures none and why there is no knob |

## Dependency measurement

Re-run, not carried forward. `rcgen` is a dev-dependency, so it cannot affect the
normal closure.

```
$ cargo metadata --format-version 1 --no-deps   # synvoid-dns direct synvoid deps
['synvoid-dnssec-keystore', 'synvoid-mesh']
$ cargo tree -p synvoid-dns -e normal | grep -c rcgen
0
```

| Measure | Phase 136 terminal | Phase 137 | Delta |
|---|---|---|---|
| Direct SynVoid normal edges | 2 | **2** | none |
| Expanded `cargo tree -e normal` lines (default) | 552 | **552** | none |
| Expanded `cargo tree -e normal` lines (`--features mesh`) | 2047 | **2047** | none |
| `rcgen` occurrences in the normal closure | — | **0** | dev-only |

Unchanged, as expected: this phase adds no dependency and removes none.
`rcgen` is a dev-dependency and does not appear in the normal closure, which was
checked rather than assumed. `synvoid-dns` remains **class 1**; the remaining
optional `synvoid-mesh` edge is unchanged and still out of scope.

## Verification

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --profile ci --all-targets -- -D warnings` | pass, 0 warnings |
| `cargo test -p synvoid-dns --profile ci` | pass (lib 618; all integration suites) |
| `cargo test -p synvoid-dns --profile ci --features mesh` | pass (lib 625; all integration suites) |
| `cargo test -p synvoid-tls --profile ci` | pass, incl. both ALPN pins unmodified |
| `cargo test -p synvoid-repo-guards --profile ci` | pass, incl. the new gate (16/16 in `dns_dependency_edges`) |
| `cargo deny check` | pass — advisories, bans, licenses, sources all ok |
| `cargo audit` | exit 0; 6 allowed warnings, unchanged from baseline |
| `./scripts/dns/conformance.sh` | internal **10/10** |
| `cargo xtask verify` | **10 steps, 10 passed, 0 failed, 0 skipped** (564.6s) |

### Lanes recorded as not-run

`./scripts/dns/conformance.sh` reports **5 external lanes runnable but not
executed** and **5 skipped for missing tools**. The runnable five require a
`DnsServer` already listening on a local port, which no in-repo harness provides
and which CI does not provide either; the skipped five need `kdig`,
`named-checkzone`, and `ldns-verify-zone`, none of which are installed here. This
is the script's normal external mode and is unchanged by this phase. The internal
lane — which is the one that gates DNS behavior — is 10/10.

**Transport-interoperability lanes are not run for this phase.** The ALPN work is
in-process TLS and QUIC against real listeners, covered by
`encrypted_transport_alpn_negotiation.rs`. `kdig`-based DoT/DoQ interop would
require the missing tool, and none of the external lanes assert ALPN anyway.

## What this phase does not claim

- **No class, support, or promotion change.** `synvoid-dns` remains **class 1**.
- **No persisted TOML, OpenAPI, or admin schema change.** There is no
  configuration knob; the served protocol constants remain absent by design.
- **No change to the Phase 134 provider seam.** `SecureTransportConfig` is
  untouched and still configures no ALPN.
- **No change to DoQ.** `doq.rs` is byte-identical to its pre-phase state.
- **No claim that the root WAF HTTPS listener is in scope.** It reads ALPN at
  `src/tls/server.rs:398` but never assigns `alpn_protocols`. That is a
  separate, unowned observation; this phase did not touch it and does not resolve
  it.

## Residual work this phase leaves

- **P-2 (loopback docs gap)** and the F-3 / F-11 / 131-F-3 minor residuals in
  `plans/dns_residual_truthfulness_roadmap.md` are untouched by this phase.
- **The WAF HTTPS listener ALPN observation above** is recorded, not registered.
  It is a different subsystem with its own ownership question.
