---
name: filter
description: Protocol filtering with allow/deny lists, strict mode, and per-port protocol matching for admission control.
---

# Skill: Filter (Protocol Filtering)

## Context
The filter crate provides generic protocol-level filtering used by tarpit and honeypot for admission decisions. It implements allow/deny lists with strict mode fallback.

## When to Use
- Adding new protocol types or filter rules
- Modifying admission control logic for tarpit/honeypot
- Debugging protocol detection or filtering behavior

## Key Files
- `crates/synvoid-filter/src/lib.rs` — single-file crate (134 lines)

## Architecture

### Core Traits
```rust
pub trait FilterAction {
    fn is_allow(&self) -> bool;
    fn is_drop(&self) -> bool;
}

pub trait Protocol: Send + Sync + Clone + Eq + Hash + Debug {
    fn as_str(&self) -> &str;
    fn from_str(s: &str) -> Option<Self>;
}
```

### Filter Logic
```rust
pub struct ProtocolFilterCore<P: Protocol, A: FilterAction> {
    enabled: bool,
    strict_mode: bool,
    protocol_allowlist: HashSet<P>,
    protocol_denylist: HashSet<P>,
    _phantom: PhantomData<A>,
}
```

Evaluation order:
1. If denylist contains protocol → **deny**
2. If allowlist contains protocol → **allow**
3. If strict mode → **deny** (default-deny)
4. If not strict mode → **allow**

### Per-Port Configuration
```rust
pub struct PortConfigBase<P: Protocol, A: FilterAction> {
    expected_protocol: P,
    action: A,
}
```

## Design Patterns
- Zero-dependency pure trait crate
- PhantomData for generic type parameters
- Denylist takes precedence over allowlist
- Strict mode provides default-deny posture

## Integration Points
- `synvoid-tarpit` — protocol admission decisions
- `synvoid-honeypot` — protocol-aware listener configuration

## Testing
```bash
cargo test -p synvoid-filter --all-targets
```
