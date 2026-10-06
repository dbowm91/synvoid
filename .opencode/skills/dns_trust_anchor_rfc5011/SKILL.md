---
name: dns_trust_anchor_rfc5011
description: RFC 5011 DNSSEC trust-anchor state machine — the 6 anchor states, trust-point observation gating, Missing→Pending restoration, and why [dns] trust_anchors.enabled currently fails validation. Use when working on trust-anchor rollover, anchor state transitions, or the DNSSEC trust-anchor database.
---

# Skill: DNSSEC Trust Anchors (RFC 5011)

## Context

SynVoid carries an RFC 5011 trust-anchor state machine in
`crates/synvoid-dns/src/trust_anchor.rs` (~1800 lines). It tracks the lifecycle of
a configured root trust anchor as DNSKEY/DS observations arrive, so that anchor
rotation does not require redeploying the resolver.

This subsystem is **separately owned from DNSSEC signing and validation**. Key
*custody* (private keys, HSM access) lives exclusively in
`crates/synvoid-dnssec-keystore/`; trust anchors are public keys and carry no
private material. Do not move key handling into this module.

Operator-facing background: `docs/RFC5011_TRUST_ANCHOR.md`.

## When to Use

Use this skill when:

- Changing trust-anchor state transitions or observation windows
- Working on anchor rollover / revocation / removal handling
- Touching the trust-anchor SQLite schema
- Debugging why a configured anchor is not being used for validation

## The state machine

`TrustAnchorState` has **six** variants:

| Variant | Meaning (from the source doc comments) |
|---------|---------------------------------------|
| `Valid` | Key is fully trusted and actively used for validation |
| `Seen` | Observed in the DNSKEY RRset but not yet validated via CDS/CDNSKEY (RFC 5011 §3) |
| `Pending` | Validated via CDS/CDNSKEY, awaiting the 30-day observation period (RFC 5011 §3.2) |
| `Revoked` | Key has the REVOKE bit set (RFC 5011 §4) |
| `Removed` | Key was removed from the zone; waiting out the confirmation period |
| `Missing` | Key was configured but never observed |

`TrustAnchorManager` is the coordinator (`crates/synvoid-dns/src/trust_anchor.rs`).
State is persisted in a SQLite database; the default path is
`/var/lib/synvoid/dns/trust_anchors.db`, and the schema carries a `trust_point`
column (`INTEGER NOT NULL`) on the anchor rows.

### `Missing` → `Pending` restoration is gated

Restoring a `Missing` anchor to `Pending` requires `trust_point == 0`. A
non-zero trust point means the anchor has previously been observed and timed, so
it must re-accumulate observation rather than being reinstated immediately. This
check appears in both the normal transition path and the re-scan path — if you
add a transition, do not bypass it.

## Known limitation: unsynchronized trust-anchor views

`TrustAnchorManager` and the resolver's `hickory_proto::TrustAnchors` set are
**not kept synchronized**. Code that needs "what anchors is the validator
actually using" must not assume it matches manager state. Treat any attempt to
unify these as a design change requiring its own review, not a bug fix.

## Configuration status: deferred, fails closed

`[dns] trust_anchors.enabled = true` is a **deferred capability** and is rejected
by config validation with a typed `Unsupported` error. Validation runs from
`DnsConfig::validate()` via `self.trust_anchors.validate()`
(`crates/synvoid-config/src/dns/mod.rs`), and the rejection is pinned by a test
that sets `cfg.trust_anchors.enabled = true` and asserts
`expect_unsupported(&cfg, "dns.trust_anchors.enabled")`.

This is the Phase 45 fail-closed pattern: rather than silently ignoring the flag,
activation is refused. Do not "fix" this by making the flag a no-op, and do not
treat the state machine as reachable in a default build.

Broader context: `crates/synvoid-dns/AGENTS.override.md`, and the deferred-feature
list in `architecture/dns_config_runtime_matrix.md`.

## Pitfalls

- Treating `Seen` as trusted. Only `Valid` anchors are actively used.
- Reinstating a `Missing` anchor without checking `trust_point == 0`.
- Assuming `TrustAnchorManager` reflects what `hickory_proto` validates against.
- Describing `[dns] trust_anchors` as an active operator feature — it currently
  refuses to activate.
- Reaching for private-key APIs here; custody is
  `crates/synvoid-dnssec-keystore/` only (guard: `dnssec_keystore_boundary`).

## Verification

```bash
cargo test -p synvoid-dns --profile ci
```

The crate-level suite under `crates/synvoid-dns/tests/` covers DNSSEC
configuration fidelity and related contract surfaces. Config-rejection
behavior is pinned by the crate's own config tests.

> Sections titled "Wave/M/P0.x fix log" in related skills are historical
> evidence, not TODOs. Locate claims by symbol; line numbers drift.