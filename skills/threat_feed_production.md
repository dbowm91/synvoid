# Producing Authoritative Threat Feeds

This skill provides the technical specification and workflow for producing cryptographically signed threat intelligence feeds for MaluWAF.

## Feed Protocol Specification

A MaluWAF threat feed is a signed JSON payload. Authenticity is ensured by an Ed25519 signature of a deterministic string representation of the indicators.

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
      "site_scope": "site_123"
    }
  ],
  "signature": "BASE64_SIGNATURE",
  "signer_public_key": "BASE64_PUBLIC_KEY"
}
```

### 2. Signing Format (Deterministic)
Before signing, the indicators must be hashed into a single string to prevent tampering:

**Signature Content Format**:
`{version}:{timestamp}:{indicator_count}:{indicator_1_hash},{indicator_2_hash},...`

**Indicator Hash**:
`{threat_type as u8}:{indicator_value}:{severity as u8}`

### 3. Key Hierarchy
*   **Genesis Key**: Can sign a "Root Feed" that all nodes in the mesh trust by default.
*   **Organization Key**: Can sign feeds for specific organizations.
*   **Global Node Key**: Can sign feeds for specific clusters.

## Production Workflow

### A. Manual Export (CLI)
Global nodes can export their current threat database to a signed feed file.

```bash
# Recommended implementation (WIP)
maluwaf --export-threat-feed --site <site_id> --sign-with <path_to_private_key> --out feed.json
```

### B. Automated Quorum Signing
For high-integrity feeds, use the quorum system to require multiple global nodes to sign off on a feed before it is published.

1.  **Initiate**: Node A creates a `QuorumSignRequest` containing the feed hash.
2.  **Verify**: Peer global nodes verify the indicators against their own local logs.
3.  **Approve**: Nodes return their `QuorumSignature`.
4.  **Publish**: Once quorum is met, the aggregated signature is attached to the feed.

## Abuse Prevention Checklist
1.  **Attribute Source**: Every indicator must have a `source_node_id`.
2.  **Verify Timestamps**: Reject any feed with a timestamp older than 24 hours (prevents replay attacks).
3.  **Strict Typing**: Ensure `threat_type` matches the intended block action (e.g., `IpBlock` vs `RateLimitViolation`).
4.  **Signature Binding**: The signature must cover the count and order of indicators.
