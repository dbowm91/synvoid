# YARA Rules & File Upload Security - Implementation Plan

## Overview

This plan addresses enabling capability-based authorization for DHT and making YARA file upload scanning configurable per-site.

1. **Enable Capability-Based Authorization** - Wire the existing `CapabilityAccessVerifier` to enforce that only authorized nodes can publish YARA rules and threat intel to DHT
2. **Per-Site YARA Scan Configuration** - Add `scan_on_upload` field to `[site.static]` config with default enabled

---

## Problem Statement

### Issue 1: Capability-Based Authorization Not Enabled

**Location**: `src/mesh/dht/capability_access.rs`

The `CapabilityAccessVerifier` struct exists with correct key mappings:
- `yara_rules_manifest:*` → requires "waf" capability
- `yara_rule:*` → requires "waf" capability
- `threat_indicator:*` → requires "threat_intel" capability

**Problem**: The verifier is **never instantiated or wired** to the record store. No call to `set_capability_verifier()` exists anywhere in the codebase.

**Impact**: Any node can currently publish YARA rules or threat intel to DHT without capability verification.

### Issue 2 (Combined with Issue 3): Per-Site `scan_on_upload` Ignored

**Current State**: File upload scanning is always enabled, ignoring any config.

**Desired**: Each site should be able to control whether uploaded files are scanned:

```toml
[site.static]
scan_on_upload = true  # Default: true
```

---

## Implementation Plan

### Task 1: Enable Capability-Based Authorization

#### Step 1.1: Create Capability Attestation Lookup Function

The `CapabilityAccessVerifier` needs a function to look up attestations from DHT or local cache.

**Location**: `src/mesh/dht/capability_access.rs:26-32`

Current signature:
```rust
pub fn new(
    verify_fn: impl Fn(&str, &str) -> Option<CapabilityAttestation> + 'static + Send + Sync,
) -> Self
```

**Required**: Create a verifier that looks up attestations from DHT.

**Implementation**: Query DHT for `capability_attestation:{node_id}:{capability}` on every write.

#### Step 1.2: Wire Verifier to Record Store

**Where to add**: Mesh initialization in `src/worker/unified_server.rs`

The record store is obtained at line 911:
```rust
if let Some(record_store) = transport_manager.get_record_store() {
    yara_rules.set_record_store(record_store.clone());
    crate::mesh::set_global_record_store(record_store);
}
```

Add after line 913:
```rust
let capability_verifier = CapabilityAccessVerifier::new(move |node_id: &str, capability: &str| {
    // Query record store for capability_attestation:{node_id}:{capability}
    // Return Some(CapabilityAttestation) if valid signature
    // Return None if not found/invalid
});
record_store.set_capability_verifier(Some(Arc::new(capability_verifier)));
```

#### Step 1.3: Ensure Global Nodes Have Attestations

**Where to add**: After capability verifier is wired in `unified_server.rs`

Global nodes self-publish their capabilities on startup:

```rust
// Announce capabilities (waf, threat_intel) for self
let node_id = node_id.clone();
for capability in ["waf", "threat_intel"] {
    let signer = signer.as_ref().expect("signer required for capability announcement");
    let public_key = signer.get_public_key();
    let timestamp = crate::utils::current_timestamp();

    // Build attestation content and sign it
    let content = format!("{},{},{},{}", node_id, capability, node_id, timestamp);
    let signature = signer.sign(content.as_bytes());

    let attestation = CapabilityAttestation::new(
        node_id.clone(),
        capability.to_string(),
        node_id.clone(),  // attested_by_global_node (self)
        public_key,       // signer_public_key
        signature,        // signature
        timestamp,
    );
    // Serialize and publish to DHT with key: capability_attestation:{node_id}:{capability}
    // TTL: 7 days (86400 * 7)
}
```

### Task 2: Per-Site YARA Scan Configuration

Add ability to disable/enable file upload scanning per-site under `[site.static]`.

#### Step 2.1: Add `scan_on_upload` to `SiteStaticConfig`

**Location**: `src/config/site/static_files.rs`

Add field at end of struct:
```rust
#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteStaticConfig {
    // ... existing fields ...
    #[serde(default = "default_scan_on_upload")]
    pub scan_on_upload: Option<bool>,
}

fn default_scan_on_upload() -> bool {
    true
}
```

#### Step 2.2: Wire in `FileManagerConfig::from_static_config()`

**Location**: `src/static_files/file_manager.rs:119`

Change:
```rust
// BEFORE (hardcoded)
scan_on_upload: true,

// AFTER
scan_on_upload: config.scan_on_upload.unwrap_or(true),
```

---

## File Changes Summary

| File | Change | Lines |
|------|-------|-------|
| `src/mesh/dht/capability_access.rs` | Use existing | Full |
| `src/worker/unified_server.rs` | Wire verifier + publish attestations | ~913-925 |
| `src/config/site/static_files.rs` | Add `scan_on_upload` field | ~190 |
| `src/static_files/file_manager.rs` | Wire config | ~105-130 |

---

## Testing Checklist

- [ ] Capability verifier rejects non-global node publishing yara_rules_manifest
- [ ] Capability verifier rejects non-global node publishing threat_indicator  
- [ ] Capability verifier allows global node with valid attestation
- [ ] `scan_on_upload = false` disables file scanning
- [ ] `scan_on_upload = true` (or unset) enables file scanning
- [ ] Integration test for full mesh flow

---

## Dependencies

- Existing `CapabilityAccessVerifier` structure in `src/mesh/dht/capability_access.rs`
- Existing `CapabilityAttestation` in `src/mesh/dht/capability_attestation.rs` (note: no `expires_at` field - TTL handled separately)
- Existing `DhtKey::capability_attestation` in `src/mesh/dht/keys.rs`
- Existing `SiteStaticConfig` and `FileManagerConfig::from_static_config()` config path

---

## Risk Assessment

| Risk | Mitigation |
|------|----------|
| Breaking existing deployments | Default `scan_on_upload = true` maintains current behavior for files |
| Attestation lookup | Direct DHT lookup for now (can add caching later) |
| Backward compatibility | Global nodes self-publish attestations on startup - no breaking change |