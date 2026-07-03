# ADR-002: DNSSEC Validation Limited to Recursive Resolver

## Status
Accepted

## Date
2026-03-20

## Context
SynVoid supports multiple DNS resolver providers: Google, Cloudflare, System, Custom, and Recursive. DNSSEC validation was being discussed for all providers.

## Decision
**DNSSEC validation is implemented ONLY for the `Recursive` provider.** The following providers do NOT perform DNSSEC validation (they are stub/forwarding resolvers):
- `Google` - forwards to Google's DNS, we don't re-validate
- `Cloudflare` - forwards to Cloudflare's DNS, we don't re-validate
- `System` - uses system resolver, no validation
- `Custom` - uses custom upstream IPs, no validation

**To enable DNSSEC validation**, users must use the `Recursive` provider with:
```toml
[dns.recursive]
upstream_provider = "Recursive"
dnssec_validation = true
trust_anchors.enabled = true
trust_anchor_path = "trusted-key.key"
```

## Rationale

### Why Not All Providers?
1. **Google/Cloudflare**: These are already validating resolvers. The AD bit in responses indicates they have validated the chain. Re-validating would be redundant and potentially cause issues if their trust anchors differ from ours.

2. **System Resolver**: Depends on OS configuration, which may or may not perform DNSSEC validation. We cannot control or rely on this.

3. **Custom Upstream**: Uses custom upstream IPs with no guarantee of DNSSEC support.

### Why Recursive Only?
The `Recursive` provider via `HickoryRecursor` performs full DNSSEC chain-of-trust validation:
- Validates DNSKEY records against trust anchors
- Verifies RRSIG signatures on records
- Checks NSEC/NSEC3 proofs of nonexistence
- Validates DS records in the parent zone

This gives us full control over the validation process and trust anchor management via RFC 5011.

## Consequences

### Positive
- Clear user expectation: DNSSEC requires Recursive provider
- Full control over validation logic and trust anchors
- RFC 5011 automatic key rotation works correctly
- Simpler implementation (no conditional validation logic)

### Negative
- Users who want DNSSEC must run a recursive resolver
- Additional configuration required for DNSSEC
- Cannot validate DNSSEC for zones using third-party DNS providers

## Implementation Details
- `TrustAnchorManager` handles RFC 5011 key rotation
- `HickoryRecursor` performs full chain-of-trust validation
- `is_dnssec_validated` flag propagates to AD bit in responses

## References
- `crates/synvoid-dns/src/trust_anchor.rs` - RFC 5011 state machine
- `skills/dns_dnssec.md` - Detailed DNSSEC architecture documentation
