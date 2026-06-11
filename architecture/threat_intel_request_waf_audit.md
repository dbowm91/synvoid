# Threat-Intel Request/WAF Audit — Iteration 36

**Date**: 2026-06-11  
**Scope**: Repository-wide audit of request/WAF paths for threat-intel usage  
**Goal**: Verify that actionability-sensitive runtime consumers use strict or policy-composed APIs, not raw advisory/local lookups

## Audit Summary

The WAF request path does not query `ThreatIntelligenceManager` directly. Instead, mesh enforcement (`handle_incoming_threat`) populates `BlockStore` state, and WAF request code reads `BlockStore` as local enforcement state. This boundary is correct and requires no migration.

Strict and composed lookup wrappers (`lookup_*_policy_strict`, `lookup_*_policy_composed`) are defined but have zero external production callers outside `threat_intel.rs` itself. They are staged for future use when request/WAF consumers need policy-gated threat-intel decisions directly.

## Audit Table

| Surface | Finding | Classification | Required Action | Status |
|---------|---------|----------------|-----------------|--------|
| `handle_incoming_threat` (`threat_intel.rs:1159`) | Mesh-sourced enforcement mutations (block_ip, rate-limit, suspicious, ip throttle) | enforcement | `PermitAction` gate via `evaluate_incoming_threat_policy` | gated |
| `apply_sync` (`threat_intel.rs:1982`) | Delegates to `handle_incoming_threat` | enforcement via delegation | same gate | gated |
| `handle_hot_threat_gossip` (`threat_intel.rs:592`) | Delegates to `handle_incoming_threat` | enforcement via delegation | same gate | gated |
| Mesh ThreatSync/ThreatSyncResponse handlers (`threat_intel.rs:2541,2597`) | Delegate to `handle_incoming_threat` | enforcement via delegation | same gate | gated |
| WAF `check_block_store` (`waf/mod.rs:541`) | Reads BlockStore, not ThreatIntelligenceManager | enforcement via BlockStore | BlockStore populated by gated mesh path | audited |
| WAF `check_early` (`waf/mod.rs:709`) | Reads BlockStore | enforcement via BlockStore | BlockStore populated by gated mesh path | audited |
| WAF `maybe_escalate_and_block` (`waf/mod.rs:682`) | Escalates to block_ip via BlockStore | enforcement via BlockStore | BlockStore populated by gated mesh path | audited |
| WAF ASN scraping (`waf/asn_tracker.rs:152`) | Calls block_ip directly (local-origin detection) | local-origin detection | first-party, correctly ungated | audited |
| WAF honeypot block (`waf/mod.rs:734`) | Calls block_ip directly (local-origin detection) | local-origin detection | first-party, correctly ungated | audited |
| WAF threat-intel feed dedup (`waf/threat_intel/feed_client.rs:395`) | `lookup_local_indicator` for indicator dedup before announcement | advisory cache/bookkeeping | not enforcement, no mutation | audited |
| Worker IPC BlocklistUpdate (`worker/unified_server/lifecycle.rs:260`) | Populates BlockStore from Supervisor sync | advisory cache/bookkeeping | blocklist sync, not threat-intel query | audited |
| Admin IP ban (`admin/handlers/mesh_admin.rs:407`) | Direct block_ip (admin manual action) | admin/debug | manual admin action, not automated enforcement | audited |
| Admin mesh-ID ban (`admin/handlers/mesh_admin.rs:465`) | Direct block_ip (admin manual action) | admin/debug | manual admin action, not automated enforcement | audited |
| Supervisor gRPC block_ip (`supervisor/api.rs:96`) | Direct block_ip (supervisor action) | admin/debug | manual supervisor action | audited |
| Proxy upstream probing (`synvoid-proxy/src/server.rs:487`) | Auto-ban on upstream errors | local-origin detection | first-party, correctly ungated | audited |
| Shadow admin endpoint (`admin/handlers/threat_intel_policy.rs:100`) | `evaluate_indicator_policy_shadow` | shadow/observability | no enforcement mutation | audited |

## Key Findings

1. **No raw threat-intel lookups on the WAF request hot path.** The WAF reads `BlockStore` state, which is populated by the mesh enforcement path through `handle_incoming_threat`. This is the correct architecture.

2. **Strict/composed wrappers have zero external callers.** They are defined and tested but not yet consumed by request/WAF code. This is expected — the WAF does not need to query threat-intel directly because it reads BlockStore.

3. **Local-origin detection is correctly ungated.** `announce_local_block`, `announce_local_rate_limit`, honeypot blocks, and ASN scraping represent first-party evidence and do not pass through the mesh enforcement gate.

4. **Admin/debug actions are manual.** Admin ban endpoints and supervisor gRPC `block_ip` are manual actions, not automated enforcement from mesh advisory data.

## Boundary Invariant

The request/WAF boundary must be preserved:

- **Mesh enforcement** (`handle_incoming_threat`) populates `BlockStore` through the enforcement plane, gated by `PermitAction`.
- **WAF request code** reads `BlockStore` as local enforcement state.
- **Raw DHT/local advisory lookups** are not on the request/WAF hot path.

Future threat-intel integrations that affect WAF behavior should either:
1. Route through `handle_incoming_threat` (enforcement plane), or
2. Use strict/composed lookup wrappers for read-only policy-gated decisions.

Do not add raw advisory lookups to request/WAF hot paths.
