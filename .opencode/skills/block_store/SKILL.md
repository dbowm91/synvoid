---
name: block_store
description: Persistent IP/mesh-ID blocklists — provenance-tracked writes, worker admission reads, eBPF hooks, admin observability. Use when adding blocks, touching admission, or syncing blocklists.
---

# Skill: Block Store

## Context

`synvoid-block-store` is the canonical enforcement primitive: persistent
IP/mesh-ID blocklists with provenance tracking and a sequence-numbered event
log for peer catch-up. Root `src/block_store.rs` is composition glue, not
the store itself. Full reference: `architecture/block_store.md`,
`architecture/block_store_deep_dive.md`,
`architecture/blocklist_provenance_preservation.md`,
`architecture/blocklist_reconciliation.md`,
`architecture/blocklist_remove_consistency.md`.

## When to Use

- Writing a new block (IP or mesh ID) from any subsystem
- Touching worker admission or WAF/proxy/HTTP enforcement reads
- Syncing blocklists across mesh peers (event log catch-up)
- Adding blockstore admin endpoints or metrics

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-block-store/src/lib.rs` | Canonical store: `block_ip_with_provenance()`, `is_mesh_id_blocked()`, shards, event log |
| `crates/synvoid-waf/src/traits.rs` | Narrow `BlockListStore` trait consumed by request-path code |
| `src/block_store.rs` | Root composition wiring (not the store) |
| `architecture/enforcement_decision_contract.md` | Pass/Drop/Stall/Block/Challenge/Tarpit verdict contract |

## Non-Negotiables

1. **New block writes use `block_ip_with_provenance()` with a
   `BlockProvenanceKind`** — `LegacyUnknown` only for compat/tests/mocks.
2. **Worker admission reads BlockStore, never `ThreatIntelligenceManager`**;
   the WAF pipeline itself queries/mutates no block/threat state
   (see `architecture/manual_enforcement_ownership.md`).
3. **Raw lookups are diagnostic-only**: `lookup_local_indicator*` and
   `lookup_threat_indicator_in_dht` never gate enforcement; use
   `lookup_*_policy_strict`.
4. **`is_mesh_id_blocked()` is admin/control-plane only** — never in
   WAF/request/proxy/HTTP/3 code.
5. **New consumers need `ThreatIntelConsumerKind::Enforcement` +
   `ThreatIntelConsumerAction::PermitAction`** before mutating state.

## Verification

```bash
cargo nextest run -p synvoid-block-store --cargo-profile ci --profile ci
cargo xtask test guards
```
