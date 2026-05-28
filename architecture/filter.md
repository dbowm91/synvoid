# Filter Architecture

## 1. Purpose and Responsibility

The Filter module (`src/filter/`) provides a **generic, type-parameterized protocol filtering framework** with allowlist/denylist support and strict mode. Used for ICMP filtering and HTTP listener protocol enforcement.

**Core Responsibilities:**
- Generic protocol matching with type parameters
- Allowlist and denylist filtering
- Strict mode for unknown protocol handling
- Port-based protocol expectation enforcement

---

## 2. Key Data Structures

```rust
pub trait FilterAction {
    fn is_allow(&self) -> bool;
    fn is_drop(&self) -> bool;
}

pub trait Protocol {
    fn as_str(&self) -> &str;
    fn from_str(s: &str) -> Option<Self>;
}

pub struct BaseFilterConfig<P: Protocol> {
    pub enabled: bool,
    pub strict_mode: bool,
    pub protocol_allowlist: Vec<P>,
    pub protocol_denylist: Vec<P>,
}

pub struct ProtocolFilterCore<P, A> {
    config: BaseFilterConfig<P>,
    _phantom: PhantomData<A>,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ProtocolFilterCore::new(config)` | Constructor |
| `check(expected, detected, allow, deny) -> A` | Main filtering logic |
| `with_allowlist(protocols)` | Set allowlist |
| `with_denylist(protocols)` | Set denylist |
| `with_strict_mode(strict)` | Enable strict mode |
| `check_protocol_match(expected, detected) -> bool` | Standalone helper |

---

## 4. Integration Points

- **ICMP Filter**: Protocol detection and enforcement for ICMP packets
- **HTTP Listener**: Protocol expectation for incoming connections
- **Listener**: Shared configuration with `ListenerConfigBase`

---

## 5. Key Implementation Details

- **Generic Design**: Type-parameterized over protocol and action types
- **Strict Mode**: When enabled, unknown protocols are denied by default
- **Allow/Deny Priority**: Allowlist checked first, then denylist
- **Zero-Cost Abstractions**: PhantomData for compile-time type safety
