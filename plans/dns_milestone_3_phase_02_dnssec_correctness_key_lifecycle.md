# DNS Milestone 3 Phase 2: DNSSEC Correctness and Key Lifecycle

## Objective

Move DNSSEC from broad feature coverage toward trustworthy authoritative DNSSEC operation. This phase focuses on signing semantics, denial-of-existence proofs, key lifecycle, validation boundaries, AD/CD bit policy, signer observability, and explicit deferrals.

## Context

Milestone 1 removed the major authoritative AD misuse and moved signed negative response paths toward typed encoding. Milestone 2 verified cache/runtime/config safety. DNSSEC is still a high-risk subsystem and should not be considered production-grade until key lifecycle, denial proofs, signatures, and policy boundaries are tested with external tooling.

## Non-goals

Do not build a full recursive validating resolver in this phase. Recursive DNSSEC validation belongs to recursive-resolver work unless needed to enforce AD/CD boundaries. Do not add HSM production workflows beyond interface correctness unless already present.

## Primary files

- `crates/synvoid-dns/src/dnssec.rs`
- `crates/synvoid-dns/src/dnssec_key_mgmt.rs`
- `crates/synvoid-dns/src/dnssec_signing.rs`
- `crates/synvoid-dns/src/dnssec_validation.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/server/response.rs`
- `crates/synvoid-dns/src/server/response_encoder.rs`
- `crates/synvoid-dns/src/server/zone.rs`
- `crates/synvoid-dns/src/trust_anchor.rs`
- `crates/synvoid-dns/src/hsm.rs`
- `crates/synvoid-config/src/dns/*`
- DNSSEC docs and ADRs

## Workstream 1: DNSSEC capability boundary audit

Tasks:

- List all DNSSEC features currently claimed in docs/config/code.
- Classify each as implemented/tested, implemented/untested, partial, or deferred.
- Ensure docs do not claim full production DNSSEC unless proven by tests and external validation.
- Clarify authoritative signing versus recursive validation boundaries.
- Confirm AD is never set by authoritative signing alone.
- Confirm CD affects only recursive validation behavior where implemented.

Acceptance criteria:

- DNSSEC status is explicit and non-aspirational.
- operators can distinguish signing support from validating-recursive support.

## Workstream 2: RR canonicalization and signing input correctness

Tasks:

- Audit canonical owner-name normalization.
- Audit canonical RR ordering within RRsets.
- Audit RDATA canonicalization for supported DNSSEC-signed RR types.
- Ensure wildcard-expanded signatures are represented correctly.
- Ensure TTL used in RRSIG original TTL is stable.
- Ensure signature inception/expiration values are sane and configurable.

Tests:

- canonical ordering deterministic.
- mixed-case owner signs canonical lower-case name.
- RRset signature stable across insertion order.
- wildcard owner behavior tested or deferred.
- TTL/original TTL encoded correctly.

Acceptance criteria:

- signing input is deterministic and protocol-aware.

## Workstream 3: DNSKEY, DS, and algorithm policy

Tasks:

- Audit supported algorithms and docs. Avoid RSA/Ed25519 mismatch in comments or config.
- Ensure DNSKEY flags distinguish KSK and ZSK correctly.
- Ensure DS digest generation is correct for supported digest algorithms.
- Ensure unsupported algorithm config fails validation.
- Add key-size/algorithm policy docs.
- Ensure key IDs/key tags are calculated correctly.

Tests:

- DNSKEY wire encoding parses externally or through internal parser.
- DS digest known-vector tests.
- KSK/ZSK flags correct.
- unsupported algorithm rejected.
- key tag deterministic.

Acceptance criteria:

- DNSKEY/DS output can be trusted by a parent-zone workflow or explicitly marked non-production.

## Workstream 4: RRSIG generation and response inclusion

Tasks:

- Ensure signed positive responses include correct RRSIGs when DO bit is set.
- Ensure DO=false behavior is correct: omit DNSSEC records unless policy says otherwise.
- Ensure DNSKEY queries return DNSKEY RRset and RRSIGs where appropriate.
- Ensure RRSIG labels field is correct, including wildcard cases.
- Ensure signature expiration/inception validation is exposed in tests.
- Ensure response size/truncation handles signatures correctly.

Tests:

- signed A RRset with DO=true includes RRSIG.
- DO=false omits RRSIG.
- DNSKEY query returns DNSKEY and RRSIG.
- oversized signed answer truncates correctly.
- AD remains false for authoritative signed answers.

Acceptance criteria:

- signed response shape is correct and flag-safe.

## Workstream 5: NSEC denial-of-existence correctness

Tasks:

- Audit NSEC chain construction for zone contents.
- Ensure canonical name ordering.
- Ensure NSEC type bitmaps include correct RR types.
- Ensure NXDOMAIN proofs include correct covering NSEC records.
- Ensure NODATA proofs include owner NSEC with missing type absent and existing types present.
- Ensure wildcard no-data/no-match cases are correct or explicitly deferred.

Tests:

- NODATA proof for existing owner missing type.
- NXDOMAIN proof for nonexistent owner.
- wildcard denial behavior tested or deferred.
- type bitmap known cases.
- external validation smoke if possible.

Acceptance criteria:

- NSEC denial proofs are correct for supported cases.

## Workstream 6: NSEC3 policy and deferral boundary

Tasks:

- Audit NSEC3 support claims.
- Verify salt, iterations, hash algorithm, opt-out policy handling.
- If full closest-encloser proofs are not implemented, mark NSEC3 as experimental or deferred.
- Add tests for hash generation and basic proof records if supported.
- Ensure config cannot enable unsafe incomplete NSEC3 in production profile without warning/fail-fast.

Acceptance criteria:

- NSEC3 is either correct for supported cases or clearly non-production/deferred.

## Workstream 7: Key lifecycle and rollover

Tasks:

- Define KSK/ZSK lifecycle states: generated, published, active, retire-pending, retired, revoked if supported.
- Implement or verify rollover timing policy.
- Ensure old signatures remain valid during rollover windows.
- Ensure cache invalidation on key/signature changes.
- Ensure key material storage permissions and error handling are appropriate.
- Audit HSM integration boundary if enabled.

Tests:

- key generation creates expected metadata.
- active key selected deterministically.
- rollover publishes new key before retiring old key.
- signatures use active ZSK.
- DNSKEY RRset includes expected KSK/ZSK during rollover.
- cache invalidation on rollover.

Acceptance criteria:

- key lifecycle is not ad hoc and has safe rollover semantics.

## Workstream 8: Trust anchors and recursive validation boundary

Tasks:

- Audit trust-anchor config validation.
- Ensure trust anchors are used only in recursive validation context.
- Ensure authoritative responses do not set AD based on local signing.
- If recursive validation is partial, document that AD is not production-ready for recursion.
- Add tests proving authoritative and recursive DNSSEC policy boundaries.

Acceptance criteria:

- AD/CD/trust-anchor behavior is policy-correct and documented.

## Workstream 9: External interoperability smoke tests

Where tooling is available, add manual or automated smoke tests using common DNS tools:

```bash
dig +dnssec example.test A @127.0.0.1 -p <port>
delv @127.0.0.1 -p <port> example.test A
ldns-verify-zone <zonefile>
named-checkzone <origin> <zonefile>
```

If external tools are not available in CI, add documented local verification scripts.

Acceptance criteria:

- at least one external DNSSEC validation path is documented.
- failures are captured as explicit deferrals.

## Workstream 10: Documentation

Update:

- `architecture/dns.md`
- `docs/dns-dnssec-architecture.md`
- DNSSEC ADRs
- config matrix
- agent skills

Document:

- supported algorithms;
- supported denial proof modes;
- DNSSEC signing status;
- recursive validation boundary;
- key rollover model;
- external verification commands;
- deferred limitations.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns dnssec
cargo test -p synvoid-dns dnssec_signing
cargo test -p synvoid-dns dnssec_validation
cargo test -p synvoid-dns authoritative_negative
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 2 is complete when authoritative DNSSEC signing semantics, DNSKEY/DS/RRSIG output, denial proofs, key lifecycle, AD/CD boundaries, and documentation are tested and accurate, with incomplete NSEC3 or recursive-validation items clearly deferred.
