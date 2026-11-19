# DNS Serving Correctness and Trust Boundaries Roadmap

Status: **IMPLEMENTED** (2026-11-19; all ten phases are in the working tree,
based on `ea638ff9`; gate evidence is in
`architecture/dns_serving_correctness_closeout.md`).
Research baseline: `ea638ff9` (merged `main`), audited 2026-11-16.
Audit: `plans/dns_capability_audit.md` (findings D1–D39; D40 was found and
fixed at the phase-10 gate).

Predecessor context:

- DNS residual truthfulness and provider inversion:
  `plans/dns_residual_truthfulness_roadmap.md` (closed qualified);
- DNS runtime DTO conversion:
  `plans/dns_runtime_dto_conversion_roadmap.md` (closed qualified);
- mesh trust boundaries: `plans/mesh_trust_boundaries_roadmap.md`
  (phases 01–06b implemented; 04b/04c/06c/07 pending — this campaign depends on
  04b for the DHT author binding that D11 inherits).

## Why this campaign exists

The DNS capability is listed as production-ready, but a read-only audit found
that the server does not currently produce valid DNS responses in either
serving mode, and that one unauthenticated 30-byte packet stops the UDP
listener for the lifetime of the process. The suite is green (1260 tests)
because no test decodes a response the way a client does, and no test sends a
malformed EDNS option.

The audit is not a list of edge cases. It is three structural gaps:

1. **There is no single owner-name encoder.** Records are stored relative, and
   one path emits them verbatim (`www`) while the other emits presentation-format
   ASCII (`example.com`). Signing uses the same relative name, so DNSSEC signs
   names that do not exist.
2. **There is no single admission path.** UDP validates and consults the
   firewall; TCP validates and consults the firewall; DoT/DoH/DoQ call the
   handler directly. Parsers are bounded differently on each path, and the
   EDNS parser has no bound at all.
3. **Denial proofs and signatures are synthesized per query** instead of being
   derived from the zone, so NSEC/NSEC3 records assert names and types that are
   not true.

Everything else in the audit — transfer ACLs, TSIG presence checks, resolver
error mapping, DHT registration trust — follows from one of those three or from
a control that is wired but never enforced.

## Current state at the audit baseline (pre-remediation)

| Layer | State at `ea638ff9` |
|---|---|
| Authoritative wire encoding | `@` answers correct; every non-apex answer owned by a relative name (D1, probe) |
| Recursive wire encoding | every name written as ASCII, no length labels (D2) |
| EDNS parsing | OOB panic on a declared RDLENGTH beyond the packet (D3, probe) |
| EDNS responses | OPT CLASS holds RDLENGTH, TTL carries extended RCODE 16 (D7) |
| DNSSEC signing | RRSIG over the relative owner; unverifiable (D4) |
| Denial of existence | NSEC bitmap hardcoded; NSEC3 hash not applied at `iterations = 0` (D5, D6) |
| Recursive semantics | upstream errors become cached NODATA; stale served for 24 h (D9, D10) |
| Admission | encrypted listeners bypass validator, firewall, rate limit (D12b) |
| Connection limits | encrypted listeners spawn one task per connection, uncapped (D33) |
| Control plane | AXFR/IXFR/UPDATE/NOTIFY config-gated; TSIG presence-checked only (D19–D22) |
| Mesh DNS | DHT domain registrations applied with `authenticated: true`, no signature (D11) |
| Truthfulness | `/health` claims AXFR enabled while AXFR answers NOTIMP (D34) |

## Findings index

`Phase` is where the finding is closed. Severity and evidence are in the audit
document; `L` marks findings that are latent behind the config validator.

| ID | Sev | Finding | L | Phase |
|---|---|---|---|---|
| D1 | Critical | Authoritative answers carry a relative owner name | | 01 |
| D2 | Critical | Recursive answers encode names as ASCII | | 01 |
| D3 | Critical | EDNS option loop bounded by declared RDLENGTH; remote panic | | 03 |
| D4 | Critical | RRSIG canonical data uses the relative owner | | 04 |
| D5 | Critical | NSEC3 hash not applied at iteration 0; wrong input form | | 05 |
| D6 | Critical | NSEC/NSEC3 proofs fabricated per query | | 05 |
| D7 | High | OPT written with payload size in CLASS slot; RCODE 16 | | 02 |
| D8 | High | Client EDNS buffer floored to 4096 | | 02 |
| D9 | High | Resolver errors and bogus DNSSEC become cached NODATA | | 06 |
| D10 | High | Stale served instead of refreshed; TTL 0 for 24 h | | 06 |
| D11 | High | DHT domain registrations trusted without authenticity | | 08 |
| D12 | High | TSIG scanner reads past the packet (pre-ACL) | L | 03 |
| D12b | High | Encrypted transports bypass validator, firewall, rate limit | | 03 |
| D13 | Med | Error responses set QDCOUNT=0 but append the question | | 02 |
| D14 | Med | `QR=1` answered with NOTIMP (reflection/loop) | | 03 |
| D15 | Med | EDNS loop guard off-by-one | | 03 |
| D16 | Med | ECS prefix length unbounded; fixed-array slice panic | | 03 |
| D17 | Med | ARCOUNT ignored; `has_edns`/`dnssec_ok` forgeable | | 02 |
| D18 | Med | Whole-zone clone per query, including history | | 09 |
| D19 | Med | `require_tsig` checks presence, not validity | L | 07 |
| D20 | Med | ACL entry equal to a zone origin grants every client | L | 07 |
| D21 | Med | IXFR fallback ignores `axfr_enabled`/`tcp_only` | L | 07 |
| D22 | Med | UPDATE keying, prerequisite classes, RRset semantics wrong | L | 07 |
| D23 | Med | RFC 5011 accepts self-referential CDS; REVOKE unauthenticated | L | 06 |
| D24 | Med | Key rotation never reaches the served zone | | 05 |
| D25 | Med | Recursive cache key case-sensitive; coalescer broadcasts raw packet | | 06 |
| D26 | Med | Recursive firewall never wired (`None`) | | 06 |
| D27 | Med | Custom upstream port dropped; silent system fallback | | 06 |
| D28 | Med | Wildcards/delegations accepted but not implemented | | 09 |
| D29 | Med | Duplicate records not deduplicated; `add_record` unnormalized | | 09 |
| D30 | Med | Cookies validated but unenforced; no config knob | | 07 |
| D31 | Med | RFC 5011 task never started; anchors are a startup snapshot | L | 06 |
| D33 | Med | Encrypted listeners unbounded | | 03 |
| D34 | Med | `/health` reports config intent, not realized state | | 08 |
| D35 | Med | `GET /config/dns` returns TSIG secrets in plaintext | | 08 |
| D36 | High | DNSKEY RRset signed with the ZSK, not the KSK | | 04 |
| D37 | High | SOA unsigned in NXDOMAIN/NODATA responses | | 04 |
| D38 | Med | NSEC3 owner length byte and next-hash are built from the base32 string | | 05 |
| D39 | High | TSIG MAC not RFC 8945 canonical; responses append bare RDATA | | 07 |
| L1–L10 | Low | Canonical ordering, signing-failure behavior, salt/iteration caps, `count_labels`, TXT canonicalization, label-with-dot, QCLASS, recursion, dead code | | 04, 05, 06 |

## Target model

Five invariants; every phase either establishes one or is a consequence of one.

**I1 — One encoder.** Every owner name on the wire is produced by a single
function from `(record.name, zone.origin)`. No call site builds a name itself.

**I2 — One admission path.** Every listener (UDP, TCP, DoT, DoH, DoQ) passes
the same admission function: size bound, structural validation, firewall,
rate limit, then dispatch. A listener that skips a step is a test failure, not a
review finding.

**I3 — Proofs come from the zone.** RRSIGs cover canonical FQDNs; NSEC/NSEC3
chains are built once at zone load from the records that exist, and negative
answers select a covering proof instead of synthesizing one.

**I4 — Fail closed and say so.** A resolver failure is SERVFAIL, not NODATA.
A signing failure is SERVFAIL, not an unsigned RRset. Health and status report
what the runtime realized, not what the config requested.

**I5 — Trust follows the channel.** A mesh peer's domain registration is
honoured only when it is signed by the node that owns the registration and the
domain is one that node is authorized to advertise.

## Decisions

**T1 — Precompute the denial chain at zone load.** Store a canonical owner
index (names sorted by RFC 4034 §6.1 order) and, for NSEC3, the hash-sorted
chain. Per-query synthesis cannot be made consistent with the zone, and the
existing helpers mix owner strings with hash bytes. Cost: invalidation on every
zone mutation; the zone store already clones on read (D18), so the index rides
the same rebuild path.

**T2 — Keep NSEC as the default denial mode, fix both.** RFC 9276 recommends
NSEC or NSEC3 with zero iterations; this server already defaults to NSEC. NSEC3
stays supported and must pass RFC 5155 known-answer vectors (hickory's are a
usable cross-check).

**T3 — Implement TSIG properly or keep the control plane off.** A presence
check is worse than no auth because it looks like auth. The campaign implements
RFC 8945 canonical MAC and full-RR emission, and does not lift the
`allow_transfer`/`dynamic_update` gates; flipping those gates is a separate
product decision after phase 07 is green.

**T4 — Do not build a custom recursor.** hickory's recursor enforces bailiwick,
CNAME limits, and 0x20; the wrapper around it is what is broken. Fix the
wrapper (encoding, error mapping, cache keys, stale policy) and delete the
wrapper checks that only log.

**T5 — Delete RFC 5011 rather than fake it.** The manager has no live consumer,
never observes the root DNSKEY RRset, and its promotion check is
self-referential. A static trust-anchor file is the honest model. Keep the file
loader and `build_trust_anchors`; remove the state machine, `observe_*`, the
unused task, and the `trust_anchors` config section (or keep the section as a
typed `Unsupported` that says static anchors live in the file).

**T6 — DHT registrations need a signature bound to the advertising node.**
Depends on mesh Phase 04b (record author binding). DNS refuses an unauthenticated
registration and keeps the anycast path's "ask the capability" shape. Until
04b lands, `resolve_from_mesh` must not answer from DHT-sourced entries.

**T7 — One writer for zone state.** Zone mutation (load, update, mesh sync)
rebuilds the owner index and the denial chain, and bumps the serial, in one
place. This is what makes wildcards, dedupe, and NSEC chains consistent.

**T8 — External validation is opt-in, self-validation is mandatory.** CI runs
hickory-based verification of every emitted RRSIG and NSEC/NSEC3 proof. The
`delv`/`ldns-verify-zone` lanes in `scripts/dns/conformance.sh` are placeholders
today; phase 10 makes them real invocations that skip cleanly when a tool is
absent. A skipped tool is reported as skipped, never as validation.

## Phases

| Phase | Plan | Closes | Depends on |
|---|---|---|---|
| 01 | `plans/dns_serving_correctness_phase_01_wire_encoding_contract.md` | D1, D2 | — |
| 02 | `plans/dns_serving_correctness_phase_02_response_envelope_and_edns.md` | D7, D8, D13, D17 | 01 |
| 03 | `plans/dns_serving_correctness_phase_03_parser_bounds_and_admission.md` | D3, D12, D14, D15, D16, D12b, D33 | 02 |
| 04 | `plans/dns_serving_correctness_phase_04_dnssec_signing.md` | D4, D36, D37, L1–L4 | 01 |
| 05 | `plans/dns_serving_correctness_phase_05_denial_of_existence.md` | D5, D6, D24, D38, L5 | 04 |
| 06 | `plans/dns_serving_correctness_phase_06_recursive_semantics.md` | D9, D10, D23, D25, D26, D27, D31 | 01 |
| 07 | `plans/dns_serving_correctness_phase_07_control_plane_verification.md` | D19, D20, D21, D22, D30, D39 | 03 |
| 08 | `plans/dns_serving_correctness_phase_08_mesh_dns_and_config_truth.md` | D11, D34, D35 | mesh 04b |
| 09 | `plans/dns_serving_correctness_phase_09_authoritative_completeness.md` | D18, D28, D29 | 01, 05 |
| 10 | `plans/dns_serving_correctness_phase_10_verification_and_release_gate.md` | remaining lows, release claims | 01–09 |

Ordering rationale: wire encoding (01) and the envelope (02) are what make
every other fix observable; parsers and admission (03) remove the remote-panic
class before more code is added; DNSSEC (04, 05) depends on the encoder from
01; recursive (06) is independent but shares the encoder; control plane (07)
needs the admission and TSIG parser from 03; mesh/config (08) is gated on the
mesh campaign; completeness (09) needs the owner index from 05; the release gate
(10) needs everything.

## Verification matrix

| Claim | Evidence |
|---|---|
| Every answer owner is an FQDN | phase 01 test decodes the owner of a non-apex authoritative answer and of a recursive answer through an independent parser |
| EDNS responses are well-formed | phase 02 test parses the OPT: CLASS = payload, TTL = 0/DO, RDLENGTH = options |
| No parser panics on hostile input | phase 03 fuzz targets for EDNS, TSIG, and the whole packet; a table of adversarial packets asserted to return an error |
| Every listener applies the same controls | phase 03 test drives one blocked query through each transport and asserts the same refusal |
| RRSIGs verify | phase 04 test verifies a served RRSIG against the served DNSKEY using hickory's verifier, for apex and non-apex |
| Denial proofs verify | phase 05 tests NXDOMAIN/NODATA/wildcard for NSEC and NSEC3, plus RFC 5155 known-answer hashes |
| Resolver failures are visible | phase 06 test injects an upstream failure and asserts SERVFAIL, no negative cache |
| TSIG is canonical | phase 07 test verifies a MAC against an independently computed RFC 8945 digest, and transfers reject a forged one |
| Mesh registrations are authentic | phase 08 test injects an unsigned and a wrongly-signed registration and asserts both are refused |
| Health is honest | phase 08 test asserts `/health` flags track realized state |
| Release claims are true | phase 10 runs the full matrix, updates `FEATURE_STATUS`, and records the exact SHA |

## Non-goals

- A new zone-transfer or update product surface. The gates stay closed.
- Anycast, RPZ, prefetch, and DoH JSON API changes beyond correctness.
- Replacing hickory or the keystore.
- DNSSEC algorithm additions (only 8/15 are accepted today and stay).
- Performance work beyond removing the per-query zone clone (D18) and the
  per-query upstream `NS` lookup (D9's neighbour), which are correctness
  side-effects of phases 06 and 09.
