# Mesh & DHT Architecture Security Improvement Plan

## Overview

This plan addresses security gaps identified in the mesh networking and DHT architecture review. The primary focus is on capability-based access control for DNS DHT records and extending the capability system to provide defense-in-depth for privileged keys.

## Review Summary

| Area | Current State | Priority |
|------|--------------|----------|
| Anti-Sybil (Edge PoW) | 64-bit difficulty, identity key binding | Low |
| Capability System | YARA/ThreatIntel covered, DNS not | HIGH |
| Global Node Auth | Genesis key self-signature | Done |
| Origin Attestation | Global node signature required | Done |
| DHT Propagation | Global-only broadcast | Done |
| Signature Verification | Ed25519 on DHT read | Done |
| DNS Capability | Missing | **HIGH** |

---

## Issue #1: DNS DHT Records Lack Capability Protection

**Priority**: HIGH

### Problem

The DNS-related DHT keys (`dns_zone:*`, `dns_record:*`, `dns_domain_registration:*`) are marked as `is_privileged()` in `keys.rs:549-562`, which triggers the `require_global_node()` check in `record_store_crud.rs:92-99`. However, this provides implicit protection only.

The codebase already has explicit capability checking for the `dns_server` capability in `transport.rs:768-780` that requires `is_global`, but this check is only used during DNS query serving, NOT during DHT storage operations.

For defense-in-depth, we should add an explicit capability mapping so that storing DNS records requires the `dns_server` capability.

### Affected Files

1. `src/mesh/dht/capability_access.rs` - Add DNS key mappings
2. `src/mesh/dht/record_store_crud.rs` - Ensure capability check runs before/alongside privileged check

### Implementation

The `key_requires_capability()` function uses string-based key matching via `DhtKey::from_str()`. Add DNS key mappings:

**Note**: `DnsDomainRegistration` uses key prefix `dns_domain_reg:` (not `dns_domain_registration:`). See `keys.rs:462-464`.

```rust
// In src/mesh/dht/capability_access.rs:34-42 UPDATE:

pub fn key_requires_capability(key: &str) -> Option<(&'static str, &'static str)> {
    let dht_key = DhtKey::from_str(key);
    match dht_key {
        // Existing
        DhtKey::YaraRulesManifest { .. } => Some(("waf", "YaraRulesManifest")),
        DhtKey::YaraRuleContent { .. } => Some(("waf", "YaraRuleContent")),
        DhtKey::ThreatIndicator(_, _) => Some(("threat_intel", "ThreatIndicator")),
        // ADD: DNS keys
        DhtKey::DnsZone(_) => Some(("dns_server", "DnsZone")),
        DhtKey::DnsRecord(_, _) => Some(("dns_server", "DnsRecord")),
        DhtKey::DnsDomainRegistration(_) => Some(("dns_server", "DnsDomainRegistration")),
        _ => None,
    }
}

Then ensure the capability check in `record_store_crud.rs` is applied to DNS keys:

The existing flow at `record_store_crud.rs:92-151` checks:
1. Stake manager (`stake.rs:75-83`)
2. Global node check for privileged keys (`record_store_crud.rs:92-99`)
3. Edge write enabled (`record_store_crud.rs:102-111`)
4. Access control (`record_store_crud.rs:113-124`)
5. Global signature required (`record_store_crud.rs:126-132`)
6. Self-only check (`record_store_crud.rs:134-140`)
7. Capability verifier (`record_store_crud.rs:142-151`)

We should ensure capability verification runs for privileged keys. Currently capability check is step 7, after the privileged check at step 2.

### Action Items

- [ ] Add DNS key mappings to `key_requires_capability()` in `capability_access.rs`
- [ ] Add unit tests for DNS capability mapping
- [ ] Verify capability check is applied during DHT storage

---

## Issue #2: Extend Capability System to Privileged Keys

**Priority**: MEDIUM

### Problem

Currently, the capability system only covers YARA and ThreatIntel keys. The privileged keys (Organization, TierKey, GlobalNodeList, etc.) rely solely on the `is_global_node()` check for protection.

For defense-in-depth, we should add capability mappings for privileged keys so that:
1. Nodes must have the appropriate capability to store network-critical records
2. The capability check provides authorization layer independent of node role

### Implementation

Add capability mappings for privileged keys in `capability_access.rs`:

```rust
DhtKey::Organization(_) => Some(("network_admin", "Organization")),
DhtKey::TierKey(_, _) => Some(("network_admin", "TierKey")),
DhtKey::MemberCertificate(_, _) => Some(("network_admin", "MemberCertificate")),
DhtKey::GlobalNodeList => Some(("network_admin", "GlobalNodeList")),
DhtKey::OrgNameReservation(_) => Some(("network_admin", "OrgNameReservation")),
DhtKey::AnycastNode(_) => Some(("network_admin", "AnycastNode")),
```

### Action Items

- [ ] Add privileged key capability mappings
- [ ] Add capability attestation tests

---

## Issue #3: Configuration Review for Production

**Priority**: MEDIUM

### Stake System

Current defaults in `stake.rs`:
- `min_stake_for_dht_write: 30`
- `min_stake_for_dht_read: 10`
- Role weights: Global=1.5x, Origin=1.2x, Edge=1.0x

Assessment: Reasonable for production, but consider:
- Increasing `min_stake_for_dht_write` to 50 for higher security
- Enabling `strict_mode` for production deployments

### Edge Node PoW Difficulty

Current: 64 bits (8 bytes leading zeros)

Assessment: Light for modern GPU farms. Consider:
- Increasing to 72 bits for production (still doable for legitimate nodes)
- 80 bits would make it impractical for mass Sybil attacks

Configuration option to add in `mesh.config.toml`:
```toml
[mesh.edge_pow]
difficulty = 72  # Default: 64, Recommended for production: 72-80
```

### Action Items

- [ ] Document recommended production settings
- [ ] Add PoW difficulty configuration option

---

## Issue #4: Documentation

**Priority**: LOW

### Documentation Required

1. **Security Model Document** - Document the trust model:
   - Genesis key as root of trust
   - Global nodes as CA
   - Edge node PoW requirement
   - Origin node attestation requirement

2. **Capability Model Document** - Document capabilities:
   - `dns_server` - Can serve DNS queries and store DNS records
   - `waf` - Can publish YARA rules
   - `threat_intel` - Can publish threat indicators
   - `network_admin` - Can publish network policy/organization records (future)

3. **Attack Scenarios** - Document threat model:
   - Sybil attacks (mitigated by PoW)
   - DNS poisoning (mitigated by capability + global-only)
   - Route hijacking (mitigated by signature verification)

### Action Items

- [ ] Create `docs/MESH_SECURITY_MODEL.md`
- [ ] Create `docs/CAPABILITIES.md`

---

## Implementation Order

1. **Phase 1** (Immediate):
   - Add DNS capability mapping to `capability_access.rs`
   - Add unit tests

2. **Phase 2** (Soon):
   - Extend capability system for privileged keys
   - Configuration documentation

3. **Phase 3** (Later):
   - Documentation (security model, capabilities)

---

## Testing Plan

### Test #1: DNS Capability Mapping

**Note**: The key prefix for domain registration is `dns_domain_reg:`, not `dns_domain_registration:` (see `keys.rs:462-464`).

```rust
#[test]
fn test_dns_zone_requires_capability() {
    let (cap, name) = CapabilityAccessVerifier::key_requires_capability("dns_zone:example.com").unwrap();
    assert_eq!(cap, "dns_server");
    assert_eq!(name, "DnsZone");
}

#[test]
fn test_dns_record_requires_capability() {
    let (cap, name) = CapabilityAccessVerifier::key_requires_capability("dns_record:example.com:www").unwrap();
    assert_eq!(cap, "dns_server");
    assert_eq!(name, "DnsRecord");
}

#[test]
fn test_dns_domain_reg_requires_capability() {
    // Note: key prefix is "dns_domain_reg:", NOT "dns_domain_registration:"
    let (cap, name) = CapabilityAccessVerifier::key_requires_capability("dns_domain_reg:example.com").unwrap();
    assert_eq!(cap, "dns_server");
    assert_eq!(name, "DnsDomainRegistration");
}
```

### Test #2: Capability Verification Flow

Test that an edge node without `dns_server` capability cannot store DNS records.

### Test #3: Integration Test

Test full flow:
1. Global node publishes DNS zone
2. Edge node attempts to publish DNS zone (should fail)
3. Verify DNS records are readable from DHT

---

## Risk Assessment

| Change | Risk | Mitigation |
|--------|------|-----------|
| DNS capability mapping | Low - adds protection | Already have privileged check as fallback |
| Privileged key capabilities | Low - defense in depth | Gradual rollout, test first |
| PoW difficulty increase | Medium - affects edge onboarding | Make configurable, default unchanged |

---

## Success Criteria

- [ ] Edge nodes cannot store DNS records to DHT without global node attestation
- [ ] Capability verification runs for DNS keys
- [ ] Unit tests pass for all capability mappings
- [ ] Integration tests verify the full flow
- [ ] Documentation complete

---

## Open Questions

1. **Backwards Compatibility**: Should we allow unsigned DNS records for backwards compatibility with early deployments, or require signatures?

2. **Capability Revocation**: Should we implement capability revocation for misbehaving nodes?

3. **Multi-Global DNS**: Should multiple global nodes be able to serve DNS, or single source of truth?

---

## Appendix: File Reference

| File | Purpose | Changes |
|------|---------|---------|
| `src/mesh/dht/capability_access.rs` | Capability verification | Add DNS mappings |
| `src/mesh/dht/keys.rs` | DHT key definitions | None |
| `src/mesh/transport.rs:762-790` | Node capability verification | None (already done) |
| `src/mesh/dht/record_store_crud.rs` | DHT storage logic | May need ordering fix |
| `src/mesh/peer_auth.rs` | Node authentication | None |
| `src/mesh/dht/stake.rs` | Stake/reputation system | None |
| `src/mesh/dht/routing/node_id.rs` | PoW implementation | Optional difficulty increase |