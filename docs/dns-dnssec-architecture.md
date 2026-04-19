# DNS / DNSSEC Architecture

## DNSSEC Validation in Forwarding Mode

When operating as a forwarding resolver, MaluWAF does **not** perform full DNSSEC validation itself. Instead it relies on the upstream recursive resolver:

1. Client sends query with `DO` (DNSSEC OK) bit.
2. MaluWAF forwards to upstream with `DO` bit set.
3. Upstream returns RRSIG + DNSKEY/NSEC/NSEC3 records alongside the answer.
4. MaluWAF verifies the AD (Authenticated Data) bit from upstream and, if set, propagates it to the client.

Full inline validation (trust anchor → DS chain → RRSIG verification) is planned for a future release.

## NSEC3 Support

MaluWAF generates NSEC3 records for authoritative zones it serves. Supported hash algorithms:

| Algorithm | Hash | Status |
|-----------|------|--------|
| 1 (SHA-1) | 20 bytes | Fully supported |
| 2 (SHA-256) | 32 bytes | Implemented but base32 encoding is non-standard for non-20-byte outputs |

The custom `base32_encode` function in `src/dns/dnssec.rs:1478` produces RFC 4648 output without padding. For SHA-1 (20 bytes) this matches the expected NSEC3 owner name format per RFC 5155. For SHA-256 the encoding works in practice but is not rigorously tested against RFC 5155 test vectors. SHA-1 is the default (`Nsec3Config::default()` uses algorithm 1).

### NSEC3 Parameters

```
algorithm:  1 (SHA-1) — default
flags:      0 (no opt-out)
iterations: 0 (recommended by RFC 9276)
salt:       empty (or user-configured)
```

## Trust Anchor Management (RFC 5011)

`src/dns/trust_anchor.rs` implements RFC 5011 automated trust anchor rollover:

```
NewKeySeen → [validate via CDS/CDNSKEY] → Pending
Pending    → [pending_observation_days]  → Valid
Valid      → [REVOKE bit set]           → Revoked
Revoked    → [revocation_grace_days]    → Removed
Removed    → [extended_removal_days]    → Purged
Valid      → [absent retention_days]    → Missing
```

Key state transitions are driven by `process_rfc5011_updates()` which runs periodically. Configuration is via `TrustAnchorConfig` — see `src/dns/trust_anchor.rs` for field definitions.

For detailed RFC 5011 documentation including state machine diagrams, configuration options, and implementation notes, see [`/docs/RFC5011_TRUST_ANCHOR.md`](./RFC5011_TRUST_ANCHOR.md).

## AD Bit Propagation

The AD bit is set on responses only when:

1. The zone is DNSSEC-signed (has DNSKEY records).
2. The RRSIG chain validates successfully (authoritative mode) **or** the upstream resolver set AD (forwarding mode).

In forwarding mode AD is passed through from upstream. In authoritative mode AD is set after local RRSIG verification.

## Relevant Source

- `src/dns/dnssec.rs` — NSEC3 generation, base32 encoding, key tag calculation
- `src/dns/trust_anchor.rs` — RFC 5011 state machine
- `src/dns/dnssec_handler.rs` — DNSSEC response assembly
- `src/dns/server/dnssec_impl.rs` — Server-side NSEC3 synthesis
