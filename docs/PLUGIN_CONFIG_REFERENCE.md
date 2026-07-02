# Plugin Configuration Reference

Comprehensive reference for WASM plugin and unsafe native extension configuration in SynVoid.

## 1. Overview

SynVoid supports two plugin systems:

| System | Sandboxing | Use Case |
|--------|-----------|----------|
| **WASM Plugins** | Full sandbox (fuel, memory, epoch, capability gates) | Request/response filtering, custom logic |
| **Unsafe Native Extensions** | None — full process authority | Trusted operator extensions (dev convenience) |

WASM plugins are the **only production-grade sandboxed model**. Unsafe native extensions bypass all sandbox constraints and must only be loaded from fully trusted sources.

All configuration lives under the `[plugins]` table in the server config file.

---

## 2. Server Config

### `[plugins]` — Top-Level

```toml
[plugins]

[plugins.wasm]
max_memory_mb = 64
max_cpu_fuel = 1000000
timeout_seconds = 30

[[plugins.wasm.plugins]]
name = "my_plugin"
path = "/etc/synvoid/plugins/my_plugin.wasm"
memory_mb = 128          # optional: override global max_memory_mb
cpu_fuel = 500000        # optional: override global max_cpu_fuel
timeout_seconds = 10     # optional: override global timeout_seconds
priority = 100           # optional: lower runs first
on_error = "fail_closed" # optional: "fail_open" | "fail_closed"
allowed_dht_prefixes = ["site:example.com"]

[plugins.unsafe_native]
enabled = false
allow_in_production = false
hot_reload_enabled = false
risk_acknowledgement = "I understand native extensions run with full process authority"
allowed_dirs = ["/opt/synvoid/native-extensions"]

[[plugins.unsafe_native.allowed_libraries]]
path = "/opt/synvoid/native-extensions/foo.so"
sha256 = "abc123..."
```

### `PluginConfig` — Top-Level Struct

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `wasm` | `WasmPluginGlobalConfig` | `{}` | WASM plugin global config and instance list |
| `unsafe_native` | `UnsafeNativePluginConfig` | `{}` | Unsafe native extension config |
| `native_plugins_compat` | `Option<UnsafeNativePluginConfig>` | `None` | **Deprecated.** Alias for `unsafe_native` |

### `[plugins.wasm]` — `WasmPluginGlobalConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_memory_mb` | `usize` | `64` | Global WASM memory limit (MB) applied to all instances unless overridden |
| `max_cpu_fuel` | `u64` | `1_000_000` | Global Wasmtime fuel budget per execution |
| `timeout_seconds` | `u64` | `30` | Global execution timeout (seconds) |
| `plugins` | `Vec<WasmPluginInstanceConfig>` | `[]` | Per-instance plugin configurations |

### `[[plugins.wasm.plugins]]` — `WasmPluginInstanceConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `String` | *(required)* | Unique plugin identifier |
| `path` | `String` | *(required)* | Path to `.wasm` file |
| `memory_mb` | `Option<usize>` | `None` | Override `max_memory_mb` for this instance |
| `cpu_fuel` | `Option<u64>` | `None` | Override `max_cpu_fuel` for this instance |
| `timeout_seconds` | `Option<u64>` | `None` | Override `timeout_seconds` for this instance |
| `priority` | `Option<i32>` | `None` | Execution order (lower runs first) |
| `on_error` | `Option<WasmOnError>` | `None` | Error behavior: `"fail_open"` (default) or `"fail_closed"` |
| `allowed_dht_prefixes` | `Vec<String>` | `[]` | Restrict DHT site access to these prefixes |

### `[plugins.unsafe_native]` — `UnsafeNativePluginConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable loading of unsafe native extensions |
| `allow_in_production` | `bool` | `false` | Allow loading in production mode |
| `risk_acknowledgement` | `Option<String>` | `None` | Exact risk acknowledgement string required in production |
| `allowed_dirs` | `Vec<String>` | `[]` | Directories from which extensions may be loaded |
| `hot_reload_enabled` | `bool` | `false` | Enable hot-reload for native extensions (separate from WASM) |
| `allowed_libraries` | `Vec<UnsafeNativeAllowedLibrary>` | `[]` | Explicit library allowlist with optional hash verification |

### `[[plugins.unsafe_native.allowed_libraries]]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | `String` | *(required)* | Absolute path to the shared library |
| `sha256` | `Option<String>` | `None` | Expected SHA-256 hex digest; if provided, hash must match before loading |

**Production requirements** — all must be true for native extensions to load in production:

1. `enabled = true`
2. `allow_in_production = true`
3. `risk_acknowledgement` set to the required string
4. Non-empty `allowed_dirs` configured

---

## 3. Plugin Manifest (`synvoid-plugin.toml`)

Each WASM plugin includes a `synvoid-plugin.toml` manifest alongside the `.wasm` binary.

### Complete Example

```toml
name = "example-plugin"
version = "0.1.0"
entry = "plugin.wasm"
trust_tier = "local_sandboxed"

[capabilities]
request_inspect = true
request_mutate = false
response_inspect = true
response_mutate = false
metrics = true
persistence = false
filesystem_read = []
filesystem_write = []
network = []
mesh = false
admin_events = false

[capabilities.mesh_policy]
allow_threat_check = false
dht_read_prefixes = []
dht_write_prefixes = []
event_emit_topics = []

[capabilities.filesystem_policy]
read_roots = []
write_roots = []
allow_create = false
allow_overwrite = false
max_read_bytes = 0
max_write_bytes = 0

[capabilities.network_policy]
allowed_hosts = []
allowed_ports = []
allowed_cidrs = []
deny_private_ranges = true
max_request_bytes = 0
max_response_bytes = 0
timeout_ms = 0

[capabilities.persistence_policy]
namespace = ""
max_key_bytes = 0
max_value_bytes = 0
max_total_bytes = 0
allow_delete = false
ttl_required = false
max_ttl_ms = 0

[capabilities.metrics_policy]
allowed_metric_prefixes = []
max_metric_name_bytes = 0
max_label_count = 0
max_label_key_bytes = 0
max_label_value_bytes = 0
allowed_label_keys = []
denied_label_keys = []

[limits]
timeout_ms = 50
max_input_bytes = 262144
max_output_bytes = 262144
max_concurrency = 4
memory_pages = 64
fuel = 1000000
state_model = "host_context_isolated"

[signature]
signature = "..."
key_id = "key1"
algorithm = "ed25519"
binary_sha256 = "..."
manifest_sha256 = "..."
```

### Manifest Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `String` | *(required)* | Plugin name (must not be empty) |
| `version` | `String` | *(required)* | Semver version string |
| `entry` | `String` | *(required)* | WASM entry file path (must not be empty) |
| `trust_tier` | `PluginTrustTier` | `"local_sandboxed"` | Trust tier controlling capability enforcement |
| `capabilities` | `PluginCapabilities` | `{}` | Declared capability set (default-deny) |
| `limits` | `PluginLimits` | `{}` | Per-invocation resource limits |
| `signature` | `Option<PluginSignatureConfig>` | `None` | Ed25519 signature metadata |

---

## 4. Trust Tier Reference

| Tier | TOML Value | Sandbox | Signature Required | Use Case |
|------|-----------|---------|-------------------|----------|
| `Disabled` | `"disabled"` | N/A | N/A | Plugin cannot load at all |
| `LocalTrusted` | `"local_trusted"` | Bounded by declared capabilities | No | Operator explicitly trusts the plugin |
| `LocalSandboxed` | `"local_sandboxed"` | Full sandbox enforced | No | Default. Unsigned local plugin |
| `SignedSandboxed` | `"signed_sandboxed"` | Full sandbox enforced | Yes | Signature verified |
| `DevelopmentHotReload` | `"development_hot_reload"` | Relaxed | No | Dev-only: permissive reload, must not be in production |

**Default**: `LocalSandboxed` (if omitted from manifest).

**Enforcement rules**:

- `SignedSandboxed` with `RequireSigned` policy: missing signature → rejected
- `DevelopmentHotReload`: bypasses signing; not allowed in production unless explicitly overridden
- `Disabled`: load is always rejected
- Production mode: signing not enforced for any tier when `is_production = false`

---

## 5. Capability Model

All capabilities are **default-deny**. Each must be explicitly granted in the manifest.

### Top-Level Capabilities

| Capability | Manifest Field | Type | Default | Description |
|-----------|---------------|------|---------|-------------|
| Request Inspect | `request_inspect` | `bool` | `false` | Read-only inspection of incoming requests |
| Request Mutate | `request_mutate` | `bool` | `false` | Mutation of incoming request headers/body |
| Response Inspect | `response_inspect` | `bool` | `false` | Read-only inspection of outgoing responses |
| Response Mutate | `response_mutate` | `bool` | `false` | Mutation of outgoing response headers/body |
| Metrics | `metrics` | `bool` | `false` | Emit counters and gauges |
| Persistence | `persistence` | `bool` | `false` | Access the KV persistence API |
| Filesystem Read | `filesystem_read` | `Vec<String>` | `[]` | Read paths (empty = denied) |
| Filesystem Write | `filesystem_write` | `Vec<String>` | `[]` | Write paths (empty = denied) |
| Network | `network` | `Vec<String>` | `[]` | Outbound destinations (empty = denied) |
| Mesh | `mesh` | `bool` | `false` | Access mesh DHT queries |
| Admin Events | `admin_events` | `bool` | `false` | Receive admin/control-plane events |

### Sub-Capability Policies

When a top-level capability is enabled, sub-policies provide fine-grained scoping.

#### `[capabilities.mesh_policy]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_threat_check` | `bool` | `false` | Allow `mesh_check_threat` host calls |
| `dht_read_prefixes` | `Vec<String>` | `[]` | DHT key prefixes allowed for reads |
| `dht_write_prefixes` | `Vec<String>` | `[]` | DHT key prefixes allowed for writes |
| `event_emit_topics` | `Vec<String>` | `[]` | Mesh event topic prefixes allowed for emission |
| `max_key_bytes` | `usize` | `0` | Max DHT key size (0 = global default) |
| `max_value_bytes` | `usize` | `0` | Max DHT value size (0 = global default) |
| `max_event_bytes` | `usize` | `0` | Max event payload size (0 = global default) |

Strict tiers (`SignedSandboxed`, `LocalSandboxed`) reject empty or wildcard `"*"` prefixes.

#### `[capabilities.filesystem_policy]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `read_roots` | `Vec<String>` | `[]` | Directories the plugin may read from |
| `write_roots` | `Vec<String>` | `[]` | Directories the plugin may write to |
| `allow_create` | `bool` | `false` | Allow creating new files within write roots |
| `allow_overwrite` | `bool` | `false` | Allow overwriting existing files |
| `max_read_bytes` | `usize` | `0` | Max bytes per read (0 = global default) |
| `max_write_bytes` | `usize` | `0` | Max bytes per write (0 = global default) |

All paths are canonicalized and checked against allowed roots. Symlink escapes are rejected.

#### `[capabilities.network_policy]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_hosts` | `Vec<String>` | `[]` | Hostnames (exact match, lowercase) |
| `allowed_ports` | `Vec<u16>` | `[]` | Ports (empty = all ports, subject to host) |
| `allowed_cidrs` | `Vec<String>` | `[]` | CIDR ranges |
| `deny_private_ranges` | `bool` | `true` | Deny private/link-local/loopback |
| `max_request_bytes` | `usize` | `0` | Max outbound request payload |
| `max_response_bytes` | `usize` | `0` | Max inbound response payload |
| `timeout_ms` | `u64` | `0` | Connection/request timeout |

#### `[capabilities.persistence_policy]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `namespace` | `String` | `""` | Storage namespace (auto-derived from site + plugin identity) |
| `max_key_bytes` | `usize` | `0` | Max key size in bytes |
| `max_value_bytes` | `usize` | `0` | Max value size in bytes |
| `max_total_bytes` | `usize` | `0` | Max total storage for this plugin |
| `allow_delete` | `bool` | `false` | Allow deleting stored keys |
| `ttl_required` | `bool` | `false` | Require TTL for all writes (untrusted plugins) |
| `max_ttl_ms` | `u64` | `0` | Maximum TTL duration |

Cross-plugin namespace access is rejected. Persistence is namespaced by `(site_id, plugin_name, plugin_hash)`.

#### `[capabilities.metrics_policy]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_metric_prefixes` | `Vec<String>` | `[]` | Allowed metric name prefixes (e.g. `["plugin.my_plugin."]`) |
| `max_metric_name_bytes` | `usize` | `0` | Max metric name size |
| `max_label_count` | `usize` | `0` | Max labels per metric |
| `max_label_key_bytes` | `usize` | `0` | Max label key size |
| `max_label_value_bytes` | `usize` | `0` | Max label value size |
| `allowed_label_keys` | `Vec<String>` | `[]` | Explicitly allowed label keys |
| `denied_label_keys` | `Vec<String>` | `[]` | Denied label keys (high-cardinality / sensitive) |

---

## 6. Resource Limits

### `[limits]` — `PluginLimits`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout_ms` | `u64` | `50` | Per-invocation timeout (milliseconds) |
| `max_input_bytes` | `usize` | `262_144` (256 KB) | Max input payload size |
| `max_output_bytes` | `usize` | `262_144` (256 KB) | Max output payload size |
| `max_concurrency` | `usize` | `4` | Max concurrent invocations |
| `memory_pages` | `Option<u32>` | `None` | WASM linear memory page limit (64 KiB per page) |
| `fuel` | `Option<u64>` | `None` | Wasmtime fuel limit per invocation |
| `state_model` | `PluginStateModel` | `"host_context_isolated"` | Cross-request state semantics |

### State Models

| Value | Description |
|-------|-------------|
| `"host_context_isolated"` | Pooled instance, host context reset between requests, guest memory persists |
| `"fresh_instance_per_request"` | New instance per request, full isolation, no pool reuse |
| `"stateful_pooled"` | Pooled, guest globals persist (explicit stateful plugins) |

### Enforcement Rules

- **Input/output size**: Rejected with `ResourceLimitError::InputTooLarge` / `OutputTooLarge`
- **Concurrency**: Rejected with `ResourceLimitError::ConcurrencyLimitExceeded`
- **Fuel**: Exhausted fuel → `Trap::FuelExhausted`
- **Timeout**: Enforced via epoch interruption; `ResourceLimitError::Timeout`
- **Memory**: Linear memory capped by `memory_pages` × 64 KiB

### Per-Instance Overrides

Server config `[[plugins.wasm.plugins]]` fields `memory_mb`, `cpu_fuel`, `timeout_seconds` override the global `[plugins.wasm]` defaults for that specific instance. Manifest `[limits]` provides the plugin-declared bounds; runtime enforces the stricter of the two.

---

## 7. Signing

### Algorithm

```toml
[signature]
algorithm = "ed25519"
```

Currently supported: `Ed25519` only.

### `[signature]` — `PluginSignatureConfig`

| Field | Type | Description |
|-------|------|-------------|
| `signature` | `String` | Hex-encoded Ed25519 signature |
| `key_id` | `String` | Public key identifier for verification |
| `algorithm` | `String` | Signing algorithm (e.g. `"ed25519"`) |
| `binary_sha256` | `String` | Expected SHA-256 hash of the WASM binary (hex) |
| `manifest_sha256` | `String` | Expected SHA-256 hash of the canonical signing payload (hex) |

For `SignedSandboxed` in production: empty `binary_sha256` or `manifest_sha256` fields are rejected.

### Canonical Signing Payload

The manifest signing payload is a deterministic newline-delimited string covering:

```
name=<name>
version=<version>
entry=<entry>
trust_tier=<trust_tier>
cap_<Cap>=<true|false>          # sorted by capability name
mesh_allow_threat_check=<bool>
mesh_dht_read_prefixes=<sorted,joined>
mesh_dht_write_prefixes=<sorted,joined>
mesh_event_emit_topics=<sorted,joined>
mesh_max_key_bytes=<n>
mesh_max_value_bytes=<n>
mesh_max_event_bytes=<n>
fs_read_roots=<sorted,joined>
fs_write_roots=<sorted,joined>
fs_allow_create=<bool>
fs_allow_overwrite=<bool>
net_allowed_hosts=<sorted,joined>
net_allowed_ports=<sorted,joined>
net_deny_private_ranges=<bool>
persistence_allow_delete=<bool>
persistence_ttl_required=<bool>
metrics_allowed_prefixes=<sorted,joined>
limits_timeout_ms=<n>
limits_max_input_bytes=<n>
limits_max_output_bytes=<n>
limits_max_concurrency=<n>
limits_memory_pages=<n|none>
limits_fuel=<n|none>
```

The `signature` field itself is excluded from the payload (signs the manifest content, not the signature).

### Trusted Keys Config

```toml
[plugin_load]
dev_mode = false
allow_local_trusted = false

[[plugin_load.trusted_keys]]
key_id = "key1"
algorithm = "ed25519"
public_key = "base64url_encoded_ed25519_public_key"
```

| Field | Type | Description |
|-------|------|-------------|
| `dev_mode` | `bool` | Allow `DevelopmentHotReload` tier |
| `allow_local_trusted` | `bool` | Allow `LocalTrusted` tier |
| `trusted_keys` | `Vec<TrustedPluginKey>` | Public keys for signature verification |

---

## 8. Hot Reload Configuration

Hot reload is configured via `HotReloadConfig` (runtime struct, not TOML):

```rust
pub struct HotReloadConfig {
    pub enabled: bool,                    // Whether hot reload is enabled at all
    pub production_enabled: bool,         // Allow in production mode
    pub unsafe_native_enabled: bool,      // Separate gate for native extensions
    pub require_signed_wasm: bool,        // Require signed WASM for hot reload
    pub watch_dirs: Vec<PathBuf>,         // Directories to watch
    pub stability_policy: FileStabilityPolicy, // File stability detection
}
```

**File stability policy**:

```rust
pub struct FileStabilityPolicy {
    pub stable_interval: Duration, // Default: 100ms — wait for writes to settle
    pub max_wait: Duration,        // Default: 5s — max wait before force-reload
}
```

Hot reload gates:

- WASM and native extensions have **separate** enable flags
- Production mode requires `production_enabled = true`
- Hot reload waits for file stability (no partial writes) before committing
- Failed reloads never replace a working plugin (prepare-then-commit with generation tracking)

---

## 9. Migration: `native_plugins_compat`

The deprecated `[plugins.native_plugins]` config key maps to `[plugins.unsafe_native]`.

### Behavior

1. If `[native_plugins]` is present, its value is migrated to `[unsafe_native]`
2. A deprecation warning is logged at startup
3. Migration only overwrites `[unsafe_native]` if it is at defaults (not explicitly configured)
4. If both keys are present and `[unsafe_native]` was explicitly set, the explicit value wins

### Before (deprecated)

```toml
[plugins.native_plugins]
enabled = true
allow_in_production = true
risk_acknowledgement = "I understand the risks"
allowed_dirs = ["/opt/native"]
hot_reload_enabled = true
```

### After (current)

```toml
[plugins.unsafe_native]
enabled = true
allow_in_production = true
risk_acknowledgement = "I understand the risks"
allowed_dirs = ["/opt/native"]
hot_reload_enabled = true
```
