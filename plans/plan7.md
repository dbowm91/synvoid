# Documentation Improvement Plan - Plan 7

## Context and Motivation

MaluWAF has grown significantly beyond its original scope. The codebase contains **35+ distinct features** that are well-implemented but lack adequate user-facing documentation. Current documentation primarily **lists features** without explaining:
- **HOW** each feature works
- **WHY** it matters (use cases, security implications)
- **HOW TO CONFIGURE** with working examples

This creates a gap between implementation capability and user awareness. Many powerful features go undiscovered, and users cannot fully leverage the WAF's capabilities.

---

## Scope of Work

This plan covers documentation improvements across the entire MaluWAF project, focusing on user-facing documentation in `/docs` and any necessary skill documentation updates.

### Definitions

- **New Document**: A `.md` file that doesn't exist in `/docs`
- **Expand Document**: An existing `/docs/*.md` file requiring significant addition of content
- **Feature**: A distinct capability in the codebase that warrants user-facing documentation
- **Working Example**: A complete configuration snippet that demonstrates practical usage

---

## Feature Inventory and Documentation Status

### Category A: High Priority Features (No User Documentation)

| # | Feature | Location | Current Status | Gap |
|---|---------|----------|-----------------|-----|
| 1 | Behavioral Intelligence | `src/mesh/behavioral.rs`, `src/mesh/behavioral_intel.rs` | `skills/behavioral_intel.md` only | No `/docs` entry |
| 2 | Post-Quantum Hybrid Signatures | `src/mesh/hybrid_signature.rs`, `src/mesh/ml_dsa.rs` | `skills/hybrid_post_quantum.md` only | No `/docs` entry |
| 3 | Streaming WAF Engine | `src/waf/attack_detection/streaming.rs` | `skills/streaming_waf.md` only | No `/docs` entry |
| 4 | DHT Neighborhood Persistence | `src/mesh/dht/record_store_persist.rs` | `skills/dht_persistence.md` only | No `/docs` entry |
| 5 | Signed Rule Feed | `src/waf/rule_feed.rs` | `docs/SIGNED_RULE_FEED.md` exists | Incomplete - missing FAILSECURE behavior, hot reload flow |

### Category B: High Priority Features (Incomplete User Documentation)

| # | Feature | Location | Current Doc | Gaps |
|---|---------|----------|-------------|------|
| 6 | Attack Detection Types | `src/waf/attack_detection/*.rs` | `docs/ATTACK_DETECTION.md` | All types listed but superficial - missing implementation details for LDAP, XPath, Open Redirect, Request Smuggling, Header Validation |
| 7 | Traffic Shaper | `src/waf/traffic_shaper/` | Not in user docs | No bandwidth shaping, token bucket, connection limiting, monthly caps documentation |
| 8 | Config Version Manager | `src/admin/audit.rs` | `skills/admin_api.md` only | No `/docs` config rollback, audit trail documentation |

### Category C: Medium Priority Features (Expand Existing)

| # | Feature | Location | Current Doc | Needed Addition |
|---|---------|----------|-------------|-----------------|
| 9 | WAF Mesh - Origin Reachability | `src/mesh/verification.rs` | `docs/WAF_MESH.md` | Origin verification, penalty system |
| 10 | WAF Mesh - Capability Attestation | `src/mesh/dht/capability_attestation.rs` | `docs/WAF_MESH.md` | DHT write authorization |
| 11 | WAF Mesh - Genesis Key Rotation | `src/mesh/config_identity.rs` | `docs/WAF_MESH.md` | Multi-genesis key support |
| 12 | WAF Mesh - Tier Key Encryption | `src/mesh/tier_key_encryption.rs` | `docs/WAF_MESH.md` | AES-256-GCM encryption |
| 13 | Serverless - Scheduler | `src/serverless/scheduler.rs` | `docs/SERVERLESS.md` | Timer configuration, event distribution |
| 14 | Serverless - Event Consumer | `src/serverless/manager.rs` | `docs/SERVERLESS.md` | Event subscriptions, mesh events |
| 15 | Serverless - Access Control | `src/serverless/` | `docs/SERVERLESS.md` | allowed_callers, tier levels |

### Category D: Low Priority Features (Advanced DNS)

| # | Feature | Location | Current Status | Notes |
|---|---------|----------|----------------|-------|
| 16 | HSM PKCS#11 for DNSSEC | `src/dns/hsm.rs` | No `/docs`, `skills/dns_dnssec.md` partial | In active rollout |
| 17 | DNS Anycast | `src/dns/anycast.rs` | No docs | In active rollout |
| 18 | DNS RPZ (Response Policy Zones) | `src/dns/rpz.rs` | No docs | In active rollout |
| 19 | DNS64 | `src/dns/dns64.rs` | No docs | Appears partial - translation not wired |
| 20 | DNS Cookies | `src/dns/cookie.rs` | No docs | In active rollout |

**Note**: Features 16-20 are in active rollout and should be documented regardless of implementation completeness.

### Category E: Partially Implemented / Potential Bugs (Flag for Review)

| # | Feature | Location | Issue |
|---|---------|----------|-------|
| 21 | DNS64 Translation | `src/dns/dns64.rs` | Translation not wired into query path |
| 22 | Streaming WAF VecDeque | `src/waf/attack_detection/streaming.rs:26` | `pending_chunks` field never used |
| 23 | Serverless Hot Reload | `src/serverless/manager.rs` | `deploy_function`, `reload_function` mentioned but not fully present |
| 24 | SiteTrafficShaper | `src/waf/traffic_shaper/global.rs:182` | Per-site shaping exists but may not be wired into request path |

---

## Documentation Standards

All improved documentation MUST follow these principles:

### 1. Explain HOW It Works

For each feature, provide:
- Technical architecture overview
- Key data structures and their purposes
- Request/data flow through components
- Code references for deeper investigation

### 2. Explain WHY It Matters

For each feature, provide:
- Primary use case(s)
- Security or performance implications
- Trade-offs vs alternatives
- Scalability considerations (500K RPS target)

### 3. Configuration with Examples

Every configurable feature includes:
- Complete configuration reference table
- Working example (full TOML snippet)
- Default values and rationale
- Security implications of settings

### 4. Debugging and Verification

For each feature, include:
- Common failure modes
- Metrics to monitor
- How to verify correct operation
- Log points and levels

---

## Implementation Plan

### Phase 1: Critical Gaps (Priority P0)

**Estimated: ~1,400 lines of new/expanded content**

#### 1.1 Create `docs/BEHAVIORAL_INTELLIGENCE.md` (New)

**Rationale**: No user-facing documentation exists for this privacy-first distributed fingerprinting system.

**Content Structure**:
```
1. Overview
   - What is behavioral intelligence
   - How it differs from traditional bot detection
   - Privacy-first design principles

2. How It Works
   - BehavioralFeatures (7 metrics extracted per request)
   - LSH bucket algorithm (1024 buckets, SHA256-based)
   - Similarity matching with 0.85 threshold
   - Paranoia level elevation integration

3. DHT Integration
   - behavior_fingerprint:{hash} key format
   - TTL and synchronization
   - Anonymized broadcasting

4. Configuration
   - All BehavioralConfig options
   - Working example in TOML

5. Privacy Design
   - NO client IPs stored
   - Node ID anonymization
   - Differential privacy considerations

6. Metrics and Monitoring
   - All exported metrics
   - What to watch

7. Troubleshooting
   - Common issues
   - Debug steps
```

**Key Files Referenced**:
- `src/mesh/behavioral.rs:5-75` (BehavioralFingerprint, BehavioralFeatures, LSH)
- `src/mesh/behavioral_intel.rs:65-280` (Manager, analysis, matching)

**Lines Estimate**: ~250

---

#### 1.2 Create `docs/POST_QUANTUM_MESH.md` (New)

**Rationale**: Post-quantum signatures are critical for long-term security but users need guidance on enabling and using them.

**Content Structure**:
```
1. Overview
   - Why post-quantum signatures matter
   - Quantum threat timeline
   - Hybrid signature approach

2. Technical Details
   - HybridSignature structure (Ed25519 64B + ML-DSA-44 2420B)
   - Binary serialization format (length-prefixed)
   - sign_hybrid/verify_hybrid flow

3. Backward Compatibility
   - Ed25519-only nodes work with hybrid verifiers
   - Fallback behavior
   - Key exchange for ML-DSA keys

4. Configuration
   - How to enable (Cargo feature + TOML)
   - All ml_dsa_* options
   - Key generation guidance

5. Security Considerations
   - Fail-open behavior
   - Signature verification order
   - Long-term key management

6. Use Cases
   - Protecting historical threat intel
   - Critical infrastructure mesh networks
   - Compliance requirements

7. Troubleshooting
   - Common issues
   - Key rotation procedures
```

**Key Files Referenced**:
- `src/mesh/hybrid_signature.rs:17-67` (HybridSignature, serialization)
- `src/mesh/ml_dsa.rs` (ML-DSA-44 implementation)
- `src/mesh/protocol.rs:135-186` (sign_hybrid, verify_hybrid)

**Lines Estimate**: ~200

---

#### 1.3 Create `docs/STREAMING_WAF.md` (New)

**Rationale**: Streaming WAF enables real-time attack detection during large uploads but users don't know it exists.

**Content Structure**:
```
1. Overview
   - When to use streaming (large uploads, HTTP/3)
   - Difference from batch WAF processing
   - Fail-closed security model

2. Technical Details
   - StreamingWafCore structure
   - Chunk processing flow
   - check_body_only_via_normalized integration
   - Memory budget (256KB default, 1000 concurrent)

3. Integration Points
   - HTTP/3 body handling (server.rs:264-281)
   - How chunks flow through scanning

4. Configuration
   - chunk_size, max_buffered_chunks
   - Working example

5. Memory Management
   - 256KB buffer limit per request
   - 1000 concurrent × 256KB = 256MB max
   - Trade-offs

6. Metrics and Monitoring
   - Streaming-specific metrics
   - Memory pressure indicators

7. Troubleshooting
   - 413 errors from overflow
   - Performance tuning
```

**Key Files Referenced**:
- `src/waf/attack_detection/streaming.rs:19-102` (StreamingWafCore, scan_chunk)
- `src/waf/attack_detection/mod.rs:872-1024` (check_body_only_via_normalized)
- `src/http3/server.rs:264-296` (HTTP/3 integration)

**Lines Estimate**: ~180

---

#### 1.4 Expand `docs/SIGNED_RULE_FEED.md`

**Rationale**: Existing document is incomplete. FAILSECURE behavior of DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER is critical security knowledge.

**Current Gaps**:
- DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER behavior not documented
- Three-way pattern merge not explained
- Hot reload IPC flow not detailed
- Disk persistence details missing

**Content to Add**:
```
1. Security: Fail-Closed Default Key
   - DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER panics at startup
   - Why this is intentional (fail-closed)
   - What operators must do

2. Pattern Merge Process
   - Default patterns + Config patterns + Feed patterns
   - How merge priority works
   - Why three layers provide defense in depth

3. Hot Reload Flow (new section)
   - Callback triggered on new rules
   - IPC broadcast to all workers
   - Worker reloads AttackDetector
   - Zero-downtime update

4. Disk Persistence (new section)
   - storage_dir/rules.json format
   - What persists across restarts
   - Offline network scenarios

5. Configuration Updates
   - Add storage_dir, allow_downgrade explanations
   - Update_interval_hours implications
   - Emergency deployment workflow
```

**Lines Estimate**: +150 (from ~150 to ~300)

---

#### 1.5 Create `docs/DHT_PERSISTENCE.md` (New)

**Rationale**: Neighborhood persistence is complex but important for mesh reliability. Users need to understand the concept.

**Content Structure**:
```
1. Overview
   - What is neighborhood persistence
   - Why "closest" records matter
   - How it improves mesh convergence

2. Technical Details
   - SHA256-based key distance calculation
   - Closest N records selection
   - Atomic file writes (temp + rename)

3. Persistence Flow
   - When persist runs (interval-based)
   - What records are excluded
   - Age-based filtering

4. Loading Flow
   - Schema version checking
   - Expired record handling
   - Error recovery

5. Configuration
   - neighborhood_persistence_enabled
   - neighborhood_cache_size
   - persist_max_age_secs
   - persist_interval_secs
   - peer_cache_path

6. Troubleshooting
   - Corrupted file recovery
   - Schema version mismatch handling
   - Concurrent access considerations
```

**Key Files Referenced**:
- `src/mesh/dht/record_store_persist.rs:11-134` (PersistedNeighborhood, load/save)
- `src/mesh/dht/record_store_persist.rs:199-205` (key_distance)

**Lines Estimate**: ~150

---

#### 1.6 Expand `docs/ATTACK_DETECTION.md`

**Rationale**: All detection types documented but superficially. Users need implementation details.

**Current Gaps**:
- LDAP/XPath: URL-decode-then-retry pattern not explained
- Open Redirect: 100+ redirect params, CRLF check not mentioned
- Request Smuggling: 10+ fingerprint types not listed
- Header Validation: Host header special-casing not documented

**Content to Add**:

```markdown
## LDAP Injection Detection

### How Detection Works
1. Normalize input (lowercase + URL decode if % or + present)
2. Aho-Corasick pattern matching
3. If no match but input was URL-decoded, retry on original
4. [Explain why this matters for encoded attacks]

### Patterns by Paranoia Level
| Level | Patterns |
|-------|----------|
| 1 | Basic filter manipulation |
| 2 | + DN injection, encoded variants |
| 3 | + Wildcards, special chars |

### Example Attacks
```
*)(&(objectClass=*
admin)(&(password=*
%29%28
```

## XPath Injection Detection

[same structure as LDAP]

## Open Redirect Detection

### How Detection Works
1. Check if parameter is redirect-related (100+ common names)
2. If yes, validate redirect target
3. Check for dangerous protocols, CRLF, //, \\, etc.
4. [Explain why parameter name check is important]

### Redirect Parameter Names
[subset of the 100+ patterns - document key ones]

## Request Smuggling Detection

### Fingerprint Types
| Fingerprint | Attack |
|-------------|--------|
| cl_te_conflict | Content-Length + Transfer-Encoding conflict |
| duplicate_pseudo_header | HTTP/2 duplicate pseudo-headers |
| crlf_injection | Newlines in header values |
| multipart_bomb | Excessive boundaries in body |

[etc]

## Header Validation

### Special Host Header Validation
- Format checking
- CRLF injection detection
- Empty header rejection

### Duplicate Header Detection
[explain how it works]
```

**Lines Estimate**: +300 (from ~500 to ~800)

---

#### 1.7 Expand `docs/CONFIGURATION.md`

**Rationale**: Missing Traffic Shaper and Behavioral Intelligence configuration sections.

**Content to Add**:

```markdown
## Traffic Shaping

### How It Works
[Token bucket algorithm explanation]
[Difference from rate limiting]

### Global Configuration
[Full table of global_traffic_shaping options]

### Site Configuration
[Per-site override options]

### Attack Mode Integration
[How threat_level affects rates]

### Connection Limiting
[Separate from bandwidth shaping]

### Monthly Bandwidth Caps
[Enforcement mechanism]

### Example Configurations

**Heavy DDoS Protection:**
[toml snippet]

**Metered Deployment:**
[toml snippet with monthly caps]

---

## Behavioral Intelligence

### Configuration Options
[table with all BehavioralConfig options]

### Example:
[toml snippet]
```

**Lines Estimate**: +250 (from ~728 to ~978)

---

### Phase 2: Enhanced Existing Docs (Priority P1)

**Estimated: ~1,550 lines of new content**

#### 2.1 Expand `docs/WAF_MESH.md`

**Add New Sections**:

```markdown
## Origin Reachability System

### How It Works
[VerificationTaskManager flow]

### Verification Flow
1. Edge reports failure
2. Global creates VerificationTask
3. Peers verify TCP reachability
4. Penalty applied if threshold exceeded

### Penalty Mechanism
- Initial penalty: -20
- Recovery: +5 every 10 minutes
- Self-healing after ~40 minutes

### Configuration
[table]

## Capability Attestation

### DHT Keys Requiring Attestation
[table of keys and required capabilities]

### How to Attest a Node
[step-by-step]

### Authorization Flow
[CapabilityAccessVerifier explanation]

## Genesis Key Rotation

### Multi-Genesis Key Support
[how to configure multiple keys]

### Rotation Process
1. Generate new key
2. Announce via GenesisKeyTransition
3. Global nodes verify and update
4. Transition period with both keys

### Configuration
[table]

### Security Notes
[empty authorized_genesis_keys = deny all]

## Tier Key Encryption

### What Gets Encrypted
[table of privileged records]

### Master Key Derivation
[HKDF from node_identity.private_key]

### Encryption Flow
[AES-256-GCM context derivation]
```

**Lines Estimate**: +400 (from ~575 to ~975)

---

#### 2.2 Expand `docs/SERVERLESS.md`

**Add New Sections**:

```markdown
## Serverless Scheduler

### Timer Configuration
[how to set up cron-like timers]

### Event Distribution
[publish_event flow]

### Example: Scheduled Cleanup
[toml snippet]

## Event Consumer

### Event Subscriptions
[how topics work]

### WASM Integration
[mesh_emit_event function]

### Mesh Events
[how serverless works via mesh]

## Access Control

### allowed_callers
[whitelist configuration]

### allowed_orgs
[organization restriction]

### require_trusted_caller
[when to enable]

### min_tier_level
[tier-based access explanation]

## Pre-warming and Autoscaling

### Instance Pool Configuration
[pre_warm_instances, min_instances, max_instances]

### Scale Triggers
[70% up, 30% down thresholds]

### Metrics for Scaling Decisions
[which metrics to monitor]
```

**Lines Estimate**: +300 (from ~200 to ~500)

---

#### 2.3 Expand `docs/API_REFERENCE.md`

**Add New Sections**:

```markdown
## Config Versioning Endpoints

### GET /api/config/versions
[response format]

### GET /api/config/versions/{id}
[how to retrieve specific version]

### POST /api/config/rollback/{id}
[rollback process, pre-rollback snapshot]

### GET /api/config/diff
[diff between versions]

## Mesh Topology Endpoints

### GET /api/mesh/topology
[full topology response]

### GET /api/mesh/topology/graph
[D3.js-compatible format]

## Audit Endpoints

### GET /api/admin/audit/logs
[pagination, filtering]
```

**Lines Estimate**: +200 (from ~800 to ~1000)

---

#### 2.4 Expand `docs/THREAT_INTEL.md`

**Add New Sections**:

```markdown
## Behavioral Fingerprint Integration

### How Fingerprints Sync
[DHT behavior_fingerprint: key format]

### Privacy Design
[no client IPs, anonymization]

### Local Analysis
[analyze_request O(1) lookup]

## Re-announcement System

### How It Works
[all non-expired re-announced]

### hub_only_mode Effect
[non-global nodes don't re-announce]
```

**Lines Estimate**: +150 (from ~568 to ~718)

---

### Phase 3: Advanced DNS Features (Priority P2-P3)

**Estimated: ~760 lines of new content**

#### 3.1 Create `docs/DNS_HSM_PKCS11.md` (New)

**Content Structure**:
```
1. Overview
   - What HSM provides for DNSSEC
   - Why key security matters

2. Supported Algorithms
   - Ed25519 (EdDSA)
   - RSA-SHA256

3. PKCS#11 Configuration
   - module_path, slot_id, pin
   - Key label vs key ID search

4. SoftHSM Fallback
   - For testing without hardware
   - Configuration

5. Key Management
   - Key retrieval by label/ID
   - Signing flow

6. Vendor Compatibility
   - SoftHSM2, NitroKey, YubiHSM, etc.

7. Complete Example
   [full working TOML]
```

**Key Files Referenced**:
- `src/dns/hsm.rs` (Pkcs11Hsm, SoftHsm, HsmManager)

**Lines Estimate**: ~200

---

#### 3.2 Create `docs/DNS_ANYCAST.md` (New)

**Content Structure**:
```
1. Overview
   - What anycast provides
   - DDoS resistance use case

2. AnycastSocketManager
   - Multi-address binding
   - Health monitoring
   - PKTINFO for destination detection

3. Zone Synchronization
   - AnycastZoneSync
   - AXFR/IXFR support
   - Mesh-based sync

4. Configuration
   [table with all options]

5. Example
   [full working TOML]
```

**Key Files Referenced**:
- `src/dns/anycast.rs` (AnycastSocketManager)
- `src/dns/anycast_sync.rs` (AnycastZoneSync)

**Lines Estimate**: ~180

---

#### 3.3 Create `docs/DNS_RPZ.md` (New)

**Content Structure**:
```
1. Overview
   - What RPZ provides
   - Use cases (threat blocking, parental controls)

2. Pattern Matching
   - QNAME wildcards
   - IP patterns with CIDR
   - Passthru action

3. Actions
   - Nxdomain, Nodata, Passthru, Drop, TcpOnly, Custom

4. Configuration
   [table with all options]

5. Example: Block Malware Domains
   [full TOML]
```

**Key Files Referenced**:
- `src/dns/rpz.rs` (RpzZone, RpzManager)

**Lines Estimate**: ~180

---

## Potential Bugs and Issues to Flag

These issues were identified during the documentation review process. They should be investigated and resolved as part of the documentation effort, since documenting incomplete or buggy features helps track what needs fixing.

### Issue 1: DNS64 Translation Not Wired

**Location**: `src/dns/dns64.rs`

**Problem**: `Dns64Translator` struct exists but `translate_aaaa_response()` returns response unchanged. Translation is not integrated into query path.

**Status**: Document as "incomplete - in active rollout". The feature should work but isn't wired yet.

**Action Required**: Verify translation integration and either fix or document as experimental feature.

---

### Issue 2: StreamingWafCore VecDeque Never Used (Dead Code)

**Location**: `src/waf/attack_detection/streaming.rs:26`

**Problem**: `pending_chunks: VecDeque<Bytes>` field exists but is never written to. Current implementation uses `state.current_input.push_str()` instead. This is dead code or incomplete zero-copy implementation.

**Status**: Document as "known limitation - zero-copy not implemented".

**Action Required**: Either remove dead code OR implement proper zero-copy chunk handling. Document current behavior.

---

### Issue 3: SiteTrafficShaper May Not Be Wired

**Location**: `src/waf/traffic_shaper/global.rs:182`

**Problem**: `SiteTrafficShaper` exists with per-site limits, but investigation suggests only GlobalTrafficShaper may be wired into request path. Per-site bandwidth shaping may not actually work.

**Status**: Needs verification - may work but unclear from code.

**Action Required**: Verify if per-site bandwidth shaping works, document accordingly.

---

### Issue 4: Serverless Hot Reload Incomplete

**Location**: `src/serverless/manager.rs`

**Problem**: `deploy_function` and `reload_function` mentioned in skill docs but not fully present in manager.rs implementation.

**Status**: Partially implemented - documentation should clarify what's available vs what's planned.

**Action Required**: Verify implementation status, document what exists and note what's missing.

---

### Issue 5: BehavioralIntelligenceManager Paranoia Elevation Location

**Location**: `src/waf/attack_detection/mod.rs:190-216`

**Problem**: The integration point where behavioral intel adjusts paranoia level exists, but the exact behavior and interaction with different attack types needs verification.

**Status**: Code exists but needs verification of correct operation.

**Action Required**: Verify the paranoia elevation integration works correctly with all attack detectors.

---

## Issues Summary Table

| # | Issue | Severity | Action |
|---|-------|----------|--------|
| 1 | DNS64 Translation Not Wired | Medium | Fix or document as incomplete |
| 2 | Streaming VecDeque Dead Code | Low | Remove or implement properly |
| 3 | SiteTrafficShaper Unverified | Medium | Verify wired-ness |
| 4 | Serverless Hot Reload Partial | Low | Document what's implemented |
| 5 | Behavioral Paranoia Integration | Low | Verify correct operation |

---

## Summary Statistics

| Category | Documents | Lines Estimate |
|----------|-----------|----------------|
| Phase 1 (P0) | 6 docs, 4 new + 2 expanded | ~1,400 |
| Phase 2 (P1) | 4 docs, all expanded | ~1,550 |
| Phase 3 (P2-P3) | 3 docs, all new | ~560 |
| **Total** | **13 docs** | **~3,510 lines** |

### Document Count by Priority

| Priority | New | Expanded | Total |
|----------|-----|----------|-------|
| P0 | 4 | 2 | 6 |
| P1 | 0 | 4 | 4 |
| P2-P3 | 3 | 0 | 3 |
| **Total** | **7** | **6** | **13** |

### Issues Identified

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | DNS64 Translation Not Wired | Medium | Incomplete - needs fix or documentation |
| 2 | Streaming VecDeque Dead Code | Low | Known limitation |
| 3 | SiteTrafficShaper Unverified | Medium | Needs verification |
| 4 | Serverless Hot Reload Partial | Low | Partially implemented |
| 5 | Behavioral Paranoia Integration | Low | Needs verification |

---

## Timeline Recommendations

Given the scope, consider phased implementation:

**Phase 1** (2-3 weeks):
- BEHAVIORAL_INTELLIGENCE.md
- POST_QUANTUM_MESH.md
- STREAMING_WAF.md
- SIGNED_RULE_FEED.md expansion
- DHT_PERSISTENCE.md
- ATTACK_DETECTION.md expansion
- CONFIGURATION.md expansion

**Phase 2** (2-3 weeks):
- WAF_MESH.md expansion
- SERVERLESS.md expansion
- API_REFERENCE.md expansion
- THREAT_INTEL.md expansion

**Phase 3** (1-2 weeks):
- DNS_HSM_PKCS11.md
- DNS_ANYCAST.md
- DNS_RPZ.md

**Total**: 6-8 weeks for full implementation

---

## Dependencies and Prerequisites

1. **Code Reference Accuracy**: All code references must be verified against current codebase before documentation is finalized. Line numbers may have changed since investigation.

2. **Working Examples**: All TOML examples must be tested for correctness. Config schema should be validated against `src/config/` structures.

3. **Issue Resolution**: DNS64, Streaming VecDeque, SiteTrafficShaper, and Serverless hot reload should be investigated and either fixed or documented as experimental. See Issues Summary Table above.

4. **Skill Doc Sync**: After user docs are updated, corresponding skill files should be reviewed for consistency. Skill docs contain implementation details that may have diverged from current code.

5. **Verification Process**: Each document should be reviewed by at least one code walkthrough before finalization to ensure technical accuracy.

---

## Scope Clarification

This plan covers **user-facing documentation improvements** only. The goal is to ensure users understand:
- What features exist
- How to configure them
- Why they matter
- How to troubleshoot issues

This plan does **NOT** cover:
- Code refactoring or bug fixes (issues 1-5 are documented for tracking, not immediate fixes)
- New feature development
- Skill documentation updates (synced after user docs complete)

---

## Success Criteria

1. Every feature in categories A-D has user-facing documentation
2. All documented features include working configuration examples
3. All documented features explain HOW and WHY
4. No code references are broken/outdated
5. Phase 1 complete before Phase 2 begins
6. All potential bugs (issues 1-5) flagged and assigned
7. DNS64 and SiteTrafficShaper wired-ness verified

---

## Next Steps

1. **Review and approve** this plan
2. **Investigate issues 1-5** - verify DNS64 wiring, SiteTrafficShaper wiring, Serverless hot reload, Behavioral paranoia integration
3. **Fix or document** identified issues
4. **Begin Phase 1** - Create BEHAVIORAL_INTELLIGENCE.md, POST_QUANTUM_MESH.md, STREAMING_WAF.md, DHT_PERSISTENCE.md; Expand SIGNED_RULE_FEED.md, ATTACK_DETECTION.md, CONFIGURATION.md
5. **Review each document** before moving to next phase
6. **Sync with skill docs** after user docs updated

---

*Plan created: 2026-04-27*
*Features investigated: 35+*
*Documents to create/update: 13*
*Total estimated lines: ~3,510*