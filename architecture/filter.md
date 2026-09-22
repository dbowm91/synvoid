# Filter Architecture

## 1. Purpose and Responsibility

The Filter module is now the `synvoid-filter` crate (`crates/synvoid-filter/`). The former root `src/filter/` facade was removed in Phase 03 (see `facade_disposition_matrix.md` §4); the canonical implementation lives in the dedicated crate. It provides a **generic, type-parameterized protocol filtering framework** with allowlist/denylist support and strict mode. Used for ICMP filtering and HTTP listener protocol enforcement.

**Core Responsibilities:**
- Generic protocol matching with type parameters
- Allowlist and denylist filtering
- Strict mode for unknown protocol handling
- Port-based protocol expectation enforcement

---

## 2. Key Data Structures

```rust
pub trait FilterAction: PartialEq {
    fn is_allow(&self) -> bool;
    fn is_drop(&self) -> bool;
}

pub trait Protocol: Send + Sync {
    fn as_str(&self) -> &str;
    fn from_str(s: &str) -> Self where Self: Sized;
}

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

pub struct PortConfigBase<P: Protocol, A: FilterAction> {
    pub expected_protocol: P,
    pub action: A,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ProtocolFilterCore::new(config: BaseFilterConfig)` | Constructor |
| `check(&str, &P, A, A) -> A` | Main filtering logic (expected, detected, allow, mismatch) |
| `with_allowlist(protocols)` | Set allowlist |
| `with_denylist(protocols)` | Set denylist |
| `with_strict_mode(strict)` | Enable strict mode |
| `enabled() / strict_mode()` | Accessors |
| `check_protocol_match(&P, &P) -> bool` | Standalone helper |

---

## 4. Public API — Additional Types

| Type | Description |
|------|-------------|
| `PortConfigBase` | Maps expected protocol to action for a given port |

---

## 5. Integration Points

- **ICMP Filter**: Protocol detection and enforcement for ICMP packets
- **HTTP Listener**: Protocol expectation for incoming connections
- **Listener**: Shared configuration with `ListenerConfigBase`

---

## 6. Key Implementation Details

- **Generic Design**: Type-parameterized over protocol and action types
- **Strict Mode**: When enabled, unknown protocols are denied by default (allowlist miss → mismatch; expected/detected mismatch → mismatch). When disabled with an empty allowlist, non-denylisted protocols pass.
- **Allow/Deny Priority**: Denylist checked first, then allowlist (deny takes precedence for security). Disabled filter (`enabled=false`) always returns allow.
- **Zero-Cost Abstractions**: `PhantomData` for compile-time type safety
