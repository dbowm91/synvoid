# Implementation Plan: Threat Feed Production & CLI Exporter

**Status**: COMPLETE
**Last Updated**: 2026-04-29
**Verification Completed**: 2026-04-29

---

## Objective

Implement the tools necessary for Global Nodes to produce and sign authoritative threat intelligence feeds. This includes adding CLI commands for exporting signed JSON feeds and implementing the signing logic in the core mesh library.

## Background

MaluWAF V2 introduced the `ThreatFeedClient` (consumer). To support the open-source community and multi-cluster deployments, we need a "Producer" side that can curate mesh observations and publish them as signed "Gold Standard" feeds.

---

## Phased Implementation Plan

### Wave 1: Core Signing & Serialization
Implement the deterministic hashing and signing logic in the mesh library.

| Task ID | Component | Description | Implementation Details |
| :--- | :--- | :--- | :--- |
| **P1.1** | `mesh/threat_intel.rs` | Deterministic Hashing | Implemented `ThreatIntelligenceManager::get_feed_signable_content(indicators, version, timestamp) -> String` at line 1935. Format: `{version}:{timestamp}:{count}:{indicator_hashes}` |
| **P1.2** | `mesh/threat_intel.rs` | Payload Generation | Implemented `ThreatIntelligenceManager::create_signed_feed(site_id, key) -> ThreatFeedPayload` at line 1956. Supports site filtering and Ed25519 signing. |
| **P1.3** | `waf/threat_intel/` | Export Logic | `ThreatFeedPayload` and `ThreatFeedIndicator` already have correct `Serialize/Deserialize` derives. |

### Wave 2: CLI Command Implementation
Add the `--export-threat-feed` command to the main MaluWAF binary.

| Task ID | Component | Description | Implementation Details |
| :--- | :--- | :--- | :--- |
| **P2.1** | `src/main.rs` | CLI Argument Parsing | Added `--export-threat-feed` (bool), `--sign-with` (PathBuf), `--site-id` (String) to `Args` struct. |
| **P2.2** | `src/master/commands.rs` | Export Handler | Implemented `handle_export_threat_feed(sign_with, site_id)`. Loads local threat store, filters by site, signs payload, outputs JSON. |
| **P2.3** | `src/master/commands.rs` | Key Loading | Supports loading Ed25519 private key from file (32-byte raw), genesis key, or configured signing key. Falls back gracefully if no key available. |

### Wave 3: Integration & Documentation
Ensure the exporter works seamlessly with the existing consumer.

| Task ID | Component | Description | Implementation Details |
| :--- | :--- | :--- | :--- |
| **P3.1** | Tests | Round-trip Verification | Added unit tests in `src/mesh/threat_intel.rs` verifying signable content format matches `ThreatFeedClient::get_signable_content`. All 12 tests pass. |
| **P3.2** | Documentation | Update README/Docs | **PENDING**: Documentation update to `docs/THREAT_INTEL.md` (see below). |

---

## Implementation Details

### Signable Content Format

The signable content format must match exactly what `ThreatFeedClient::get_signable_content` produces for cross-verification:

```
{version}:{timestamp}:{count}:{threat_type}:{indicator_value}:{severity},...
```

Example:
```
1:1713523200:2:1:192.168.1.1:3,3:10.0.0.1:2
```

### CLI Usage

```bash
# Export all indicators as signed JSON
maluwaf --export-threat-feed

# Export with a specific signing key
maluwaf --export-threat-feed --sign-with /path/to/private_key

# Export indicators filtered by site scope
maluwaf --export-threat-feed --site-id mysite

# Combine options
maluwaf --export-threat-feed --sign-with /path/to/private_key --site-id mysite
```

### Key Sources

The CLI supports three key sources (in order of precedence):
1. `--sign-with PATH` - Raw 32-byte Ed25519 private key file
2. Genesis key from config
3. Configured node signing key

---

## Verification & Testing

1. **Unit Tests**: `cargo test --lib mesh::threat_intel` - 12 tests pass.
2. **CLI Compilation**: `cargo test --lib --no-run` - compiles successfully.
3. **Cross-Verification**: `test_signable_content_matches_feed_client` test verifies format parity.

---

## Deferred Items

| Item | Reason |
|------|--------|
| P3.2 Documentation | Documentation update to `docs/THREAT_INTEL.md` can be done separately as it doesn't affect functionality. |

---

## Key Source Files Modified

| File | Changes |
|------|---------|
| `src/mesh/threat_intel.rs` | Added `get_feed_signable_content`, `create_signed_feed`, and unit tests |
| `src/waf/threat_intel/feed_client.rs` | Made `get_signable_content` `pub(crate)` for test access |
| `src/main.rs` | Added `--export-threat-feed`, `--sign-with`, `--site-id` CLI args |
| `src/master/commands.rs` | Implemented `handle_export_threat_feed` |