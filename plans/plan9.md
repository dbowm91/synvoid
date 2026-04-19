# YARA Rules and File Upload Security Improvement Plan

## Background & Motivation
A review of the RustWAF codebase revealed that while the YARA rules distribution and file upload security systems are generally robust and operational, there are critical gaps in how they integrate with the mesh network:
1. **Mesh Broadcast Bottleneck:** In `src/worker/unified_server.rs`, the mesh forwarder task currently hardcodes the broadcast role filter to `Some(MeshNodeRole::GLOBAL)`. This means that "push" updates like `YaraRuleAnnounce` and `ThreatAnnounce` from global nodes only reach other global nodes. Edge nodes must rely on periodic DHT synchronization to receive these updates, delaying their response to emerging threats.
2. **Missing Threat Intelligence Integration:** The `UploadValidator` effectively detects and quarantines malware during file uploads using built-in rules and YARA. However, these detections are only logged and blocked locally; the source IP of the malicious upload is not reported to the mesh via the `ThreatIntelligenceManager`.

## Scope & Impact
This plan outlines surgical improvements to address these gaps, enhancing the real-time collective security of the mesh network.

**Affected Files:**
- `src/worker/unified_server.rs`
- `src/http/server.rs`
- `src/tls/server.rs`

## Proposed Solution & Implementation Steps

### Step 1: Fix Mesh Forwarder Broadcast Filter
Update the forwarder task in `src/worker/unified_server.rs` to selectively apply the role filter based on the message type.
- Inspect the incoming `MeshMessage`.
- If the message is an announcement that should reach all nodes (e.g., `YaraRuleAnnounce`, `ThreatAnnounce`, `GlobalNodeAnnounce`, `NetworkPolicyUpdate`), use `None` for the role filter to broadcast to everyone.
- If the message is a submission or request meant only for global nodes (e.g., `YaraRuleSubmission`, `ThreatSyncRequest`), keep the filter as `Some(MeshNodeRole::GLOBAL)`.

### Step 2: Integrate Malware Detection with Threat Intel (HTTP)
In `src/http/server.rs`, when the `UploadValidator` detects malware (i.e., `!result.is_clean()` or `UploadValidationError::MalwareDetected`):
- Extract the client IP address.
- Retrieve the `ThreatIntelligenceManager` instance.
- Call `threat_intel.announce_local_block(client_ip, reason, ttl, site_scope)` to instantly block the IP locally and announce the threat to the mesh. The reason should indicate "Malware detected in upload".

### Step 3: Integrate Malware Detection with Threat Intel (TLS)
Apply the exact same logic as Step 2 to `src/tls/server.rs` to ensure uploads via HTTPS are equally protected and reported.

## Alternatives Considered
- **Changing DHT Sync Interval:** Instead of fixing the push mechanism, we could lower the DHT sync interval. However, this increases overhead and still doesn't provide the near-instant response required for active attacks, making fixing the gossip push the better approach.
- **Reporting via Log Parsing:** We could build a separate service to parse logs for malware detections and feed them to Threat Intel. This adds unnecessary complexity and latency compared to direct, in-process integration.

## Verification & Testing
1. **Unit/Integration Tests:** Add tests to verify that `YaraRuleAnnounce` messages are correctly forwarded without a role filter.
2. **Mesh Propagation Test:** Spin up a local mesh with one Global node and two Edge nodes. Publish a new YARA rule from the Global node and verify that Edge nodes receive the `YaraRuleAnnounce` instantly via gossip, rather than waiting for the DHT sync.
3. **Upload Threat Reporting Test:** Send a benign EICAR test file to an upload endpoint. Verify that the file is blocked and that a corresponding `ThreatIndicator` for the client's IP is generated and propagated to other nodes in the mesh.
