# hickory-dns 0.25 → 0.26 Migration

**Status**: Deferred - Requires significant API changes

## Overview

The hickory-dns crates (hickory-proto, hickory-resolver, hickory-recursor) version 0.26 has breaking changes that require extensive migration effort. This migration was deferred due to the scope of changes (~75+ compilation errors).

## Key Breaking Changes

### 1. Crate Restructuring

- **`hickory-recursor` crate merged into `hickory-resolver`** (behind `recursor` feature)
- Network protocol support moved from `hickory-proto` to new `hickory-net` crate
- `hickory-client` subsumed into `hickory-net` (no future releases expected)

### 2. Cargo.toml Changes Required

```toml
# Old (0.25)
hickory-proto = { version = "0.25", features = ["dnssec-ring", "text-parsing"], optional = true }
hickory-resolver = { version = "0.25", features = ["system-config"], optional = true }
hickory-recursor = { version = "0.25", features = ["dnssec-ring"], optional = true }

# New (0.26)
hickory-proto = { version = "0.26", features = ["dnssec-ring"], optional = true }  # text-parsing removed
hickory-resolver = { version = "0.26", features = ["system-config", "recursor"], optional = true }
# hickory-recursor removed - use recursor feature on hickory-resolver
```

### 3. Import Path Changes (resolver.rs)

- `hickory_recursor::Recursor` → `hickory_resolver::recursor::Recursor`
- `hickory_recursor::DnssecPolicy` → `hickory_resolver::recursor::DnssecPolicy`
- `NameServerConfigGroup` import path changed
- `TokioConnectionProvider` import path changed

### 4. RData Method→Field Changes

Many RData accessors changed from methods to fields:

| Old (method) | New (field) |
|--------------|-------------|
| `soa.refresh()` | `soa.refresh` |
| `soa.retry()` | `soa.retry` |
| `soa.expire()` | `soa.expire` |
| `soa.minimum()` | `soa.minimum` |
| `srv.priority()` | `srv.priority` |
| `srv.weight()` | `srv.weight` |
| `srv.port()` | `srv.port` |
| `srv.target()` | `srv.target` |
| `mx.exchange()` | `mx.exchange` |
| `mx.preference()` | `mx.preference` |

### 5. Removed Functionality

- `ResolverConfig::google()` removed - use `ResolverConfig::from_parts`
- `ResolverConfig::cloudflare()` removed - use `ResolverConfig::from_parts`
- `ResolverOpts.validate` field removed - validation automatic when trust anchors present

### 6. Message/Query API Changes

- `Message.queries()` method replaced with direct `queries` field access
- `Lookup.iter()` replaced with `Lookup.iter_records()`

## Migration Approach

1. **Update Cargo.toml** to use new versions and features
2. **Update all imports** from `hickory_recursor` to `hickory_resolver::recursor`
3. **Systematically change** all RData method calls to field access
4. **Update resolver configuration** to use new API
5. **Test DNSSEC validation behavior** - automatic validation may change behavior

## Testing

```bash
# Run DNS tests
cargo test --lib dns

# Run with DNS feature
cargo test --features dns

# Full check
cargo check --lib -p maluwaf --features dns
```

## Files to Modify

- `src/dns/resolver.rs` - Main import and API changes
- `src/dns/recursive.rs` - RecursiveDnsServer changes
- `src/dns/server/` - Authoritative server if applicable
- `Cargo.toml` - Version and feature changes