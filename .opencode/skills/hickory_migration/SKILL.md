---
name: hickory_migration
description: hickory-dns resolver migration patterns and DNS library upgrade procedures.
---

# hickory-dns 0.25 → 0.26 Migration

**Status**: COMPLETED (2026-04-26) — Historical reference only.

## Overview

The hickory-dns crates (hickory-proto, hickory-resolver, hickory-recursor) version 0.26 has been successfully implemented. This document is retained for historical reference; the migration is complete and no further action is needed.

## Key Changes Applied

### 1. Dependency Updates
- Upgraded `hickory-proto` and `hickory-resolver` to `0.26`.
- Enabled `recursor` and `system-config` features on `hickory-resolver`.
- Removed `hickory-recursor` as it is now integrated into `hickory-resolver`.

### 2. API Changes
- **Message Fields**: `Message.queries()`, `Message.answers()`, `Message.authentic_data()` migrated to direct field access (`queries`, `answers`, `authentic_data`).
- **Record Fields**: `Record.data()` migrated to `Record.data`.
- **RData Fields**: `SOA`, `SRV`, `MX` methods (e.g., `refresh()`, `port()`) migrated to fields.
- **Lookup Iteration**: `Lookup` iteration changed to `.answers().iter()`. `LookupIp` still uses `.iter()`.
- **Resolver Construction**: Migrated to `TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())`.

### 3. Recursor Migration
- `Recursor` type now requires a generic connection provider: `Recursor<TokioRuntimeProvider>`.
- `Recursor::resolve` returns `Message` instead of `Lookup`.
- DNSSEC validation status checked via `message.authentic_data`.

## Files Modified

- `crates/synvoid-dns/src/resolver.rs`
- `crates/synvoid-dns/src/recursive.rs`
- `Cargo.toml`
- `src/waf/rule_feed.rs` (fix test panic)
