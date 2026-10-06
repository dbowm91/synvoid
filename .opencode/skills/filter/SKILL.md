---
name: filter
description: Zero-dependency protocol filtering crate — allow/deny lists, strict-mode evaluation order, and per-port protocol matching for TCP/UDP listener admission. Use when adding protocols or changing filter admission.
---

# Skill: Filter (Protocol Filtering)

## Context
The filter crate provides generic protocol-level filtering used by the **TCP and
UDP listeners** (`src/tcp/`, `src/udp/`) for admission decisions. It implements
allow/deny lists with strict-mode fallback. It is not consumed by tarpit or
honeypot — those crates have no `synvoid-filter` dependency.

## When to Use
- Adding new protocol types or filter rules
- Modifying admission control logic for the TCP/UDP listeners
- Debugging protocol detection or filtering behavior

## Key Files
- `crates/synvoid-filter/src/lib.rs` — single-file crate (134 lines, zero
  dependencies: its `[dependencies]` table is empty)

## Architecture

### Core Traits
```rust
pub trait FilterAction: PartialEq {
    fn is_allow(&self) -> bool;
    fn is_drop(&self) -> bool;
}

pub trait Protocol: Send + Sync {
    fn as_str(&self) -> &str;
    fn from_str(s: &str) -> Self
    where
        Self: Sized;
}
```

Note: `Protocol::from_str` returns `Self`, not `Option<Self>` — a caller that
fails to map a string must decide its own fallback. `FilterAction: PartialEq`
lets callers assert equality on the returned action.

### Filter Logic
```rust
// The lists are Vec<String>, not HashSet<P>, and live in BaseFilterConfig.
#[derive(Clone)]
pub struct BaseFilterConfig {
    pub enabled: bool,
    pub strict_mode: bool,
    pub protocol_allowlist: Vec<String>,
    pub protocol_denylist: Vec<String>,
}

pub struct ProtocolFilterCore<P: Protocol, A: FilterAction> {
    config: BaseFilterConfig,
    _phantom: PhantomData<P>,
    _action_phantom: PhantomData<A>,
}
```

`ProtocolFilterCore::check(expected_protocol, detected_protocol, allow_action,
mismatch_action) -> A` evaluates in this order:
1. `!config.enabled` → **allow**
2. denylist contains the detected protocol → **mismatch** (deny)
3. allowlist contains the detected protocol → **allow**
4. allowlist non-empty, no match, `strict_mode` → **mismatch**
5. `strict_mode` **and** `expected_protocol != detected_protocol` → **mismatch**
6. otherwise → **allow**

Two easy-to-miss properties: with an **empty allowlist** step 4 never runs, so
strict mode only enforces the expected-vs-detected check (step 5); and strict
mode is a mismatch check, not a blanket deny of unrecognized protocols.

### Per-Port Configuration
```rust
pub struct PortConfigBase<P: Protocol, A: FilterAction> {
    pub expected_protocol: P,
    pub action: A,
}
```

Also public: `BaseFilterConfig::new(enabled, strict_mode, allowlist,
denylist)`, builder methods `with_allowlist` / `with_denylist` /
`with_strict_mode`, accessors `enabled()` / `strict_mode()`, and the free fn
`check_protocol_match(expected, actual) -> bool` (`as_str()` equality).

## Design Patterns
- Zero-dependency pure trait crate
- PhantomData for generic type parameters
- Denylist takes precedence over allowlist
- Strict mode provides default-deny posture **for allowlist misses and
  expected/detected mismatches**

## Integration Points
- `src/tcp/filter.rs` + `src/tcp/protocol.rs` — TCP listener protocol
  admission (`FilterAction { Allow, Drop, Stall }`, `Protocol`)
- `src/udp/filter.rs` + `src/udp/protocol.rs` — UDP listener protocol
  admission (`UdpFilterAction { Allow, Drop, RateLimit{rate}, Challenge }`,
  `UdpProtocol`)

## Testing
```bash
cargo test -p synvoid-filter --all-targets
```
