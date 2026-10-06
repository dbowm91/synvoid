---
name: threat_feed_production
description: Production and cryptographic signing of threat intelligence feeds for mesh distribution.
---

# Producing Authoritative Threat Feeds

This skill provides the technical specification and workflow for producing cryptographically signed threat intelligence feeds for SynVoid.

## Feed Protocol Specification

A SynVoid threat feed is a signed JSON payload. Authenticity is ensured by an Ed25519 signature of a deterministic string representation of the indicators.

### 1. Payload Structure
```json
{
  "version": 1,
  "timestamp": 1713523200,
  "indicators": [
    {
      "threat_type": 1,
      "indicator_value": "1.2.3.4",
      "severity": 3,
      "reason": "Known botnet member",
      "ttl_seconds": 86400,
      "source_node_id": "global-node-1",
      "site_scope": "site_123",
      "rate_limit_requests": null,
      "rate_limit_window_secs": null,
      "suspicious_pattern": null
    }
  ],
  "signature": "BASE64URL_NOPAD_SIGNATURE",
  "signer_public_key": "BASE64URL_NOPAD_PUBLIC_KEY"
}
```

Types: `ThreatFeedPayload` / `ThreatFeedIndicator` at
`crates/synvoid-mesh/src/stubs.rs` (the mesh-side copy of the WAF feed types).
Notes that matter when producing a feed:

- `version` is `MESH_MESSAGE_VERSION as u64`, currently **1**
  (`crates/synvoid-mesh-protocol/src/constants.rs`).
- `site_scope` is `Option<String>` and serializes as `null` when the
  indicator is not site-scoped — an empty string on the wire is not equivalent.
- `signature` and `signer_public_key` are both
  `base64::engine::general_purpose::URL_SAFE_NO_PAD`, **not** standard base64.
- The consumer rejects any payload with an empty `signature` or a missing/
  empty `signer_public_key`, and requires the signer key to be in its trusted
  set, before any indicator is imported
  (`src/waf/threat_intel/feed_client.rs` `verify_feed_signature()`).

### 2. Signing Format (Deterministic)
Before signing, the indicators must be hashed into a single string to prevent tampering.
Producer: `ThreatIntelligenceManager::get_feed_signable_content()`
(`crates/synvoid-mesh/src/mesh/threat_intel.rs`). Consumer recomputes the
identical string via `ThreatFeedPayload::get_signable_content()`
(`crates/synvoid-mesh/src/stubs.rs`) — the two must stay byte-identical.

**Signature Content Format**:
`{version}:{timestamp}:{indicator_count}:{indicator_1_hash},{indicator_2_hash},...`

**Indicator Hash**:
`{threat_type as u8}:{indicator_value}:{severity as u8}`

The string is signed as UTF-8 bytes with the Ed25519 signer.

### 3. Key Hierarchy
*   **Genesis Key**: Can sign a "Root Feed" that all nodes in the mesh trust by default.
*   **Organization Key**: Can sign feeds for specific organizations.
*   **Global Node Key**: Can sign feeds for specific clusters.

## Production Workflow

### A. Manual Export (CLI)
Global nodes can export their current threat database to a signed feed file.

```bash
# Export all indicators as signed JSON
synvoid --export-threat-feed

# Export with a specific signing key (32-byte raw Ed25519 private key)
synvoid --export-threat-feed --sign-with /path/to/private_key

# Export indicators filtered by site scope
synvoid --export-threat-feed --site-id mysite

# Combine options
synvoid --export-threat-feed --sign-with /path/to/private_key --site-id mysite
```

Key loading precedence (exactly as implemented in
`src/supervisor/cli_commands.rs` `load_threat_feed_payload()`; it fails closed
with "No signing key available" rather than emitting an unsigned feed):
1. `--sign-with PATH` — raw 32-byte Ed25519 private key file (any other length
   is a hard error)
2. Genesis key private key from `[tunnel.mesh]` config
3. Configured node signing key (`mesh_config.signing_key()`)

### B. Quorum Signing
**Not implemented as a feed-signing flow.** There is no `QuorumSignRequest` /
`QuorumSignature` aggregate-naming step in the feed path — grep finds no such
type repo-wide. `QuorumSignature` / `QuorumSignatureProto` exist
(`crates/synvoid-mesh/src/mesh/organization.rs`,
`crates/synvoid-mesh/src/mesh/protocol.rs`) but they back **DHT org-key quorum
records**, not feed publication. Feed signing is single-signer; the feed
consumer's trust check (`is_trusted_signer`) is the authority gate. For
multi-party approval of a feed, the DHT org-key quorum path
(`org_key_trust_chain` skill) is the real mechanism — do not invent a feed-level
quorum.

## Abuse Prevention Checklist
1.  **Attribute Source**: Every indicator must have a `source_node_id`.
2.  **Verify Timestamps**: The consumer rejects any feed whose `timestamp` is
    older than `FEED_SIGNATURE_TIMESTAMP_VALIDITY_SECS` = **3600 seconds**
    (`src/waf/threat_intel/feed_client.rs`), enforced as
    `now.saturating_sub(payload.timestamp) > 3600`. This is the actual
    replay bound — it is 1 hour, not 24.
3.  **Strict Typing**: Ensure `threat_type` matches the intended block action (e.g., `IpBlock` vs `RateLimitViolation`).
4.  **Signature Binding**: The signature must cover the count and order of indicators.
5.  **Trust the signer, not the transport**: the feed URL is untrusted input;
    only a key in the consumer's trusted-signer set is accepted.
