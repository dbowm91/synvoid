# Plugin Operator Runbook

Practical guide for managing WASM plugins and unsafe native extensions in production SynVoid deployments.

## 1. Quick Start

Minimal configuration to get a WASM plugin running:

**Server config** (`synvoid.toml`):

```toml
[plugins.wasm]
max_memory_mb = 64
max_cpu_fuel = 1000000
timeout_seconds = 30

[[plugins.wasm.plugins]]
name = "my-filter"
path = "/etc/synvoid/plugins/my_filter.wasm"
```

**Plugin manifest** (`/etc/synvoid/plugins/synvoid-plugin.toml`):

```toml
name = "my-filter"
version = "1.0.0"
entry = "my_filter.wasm"
trust_tier = "local_sandboxed"

[capabilities]
request_inspect = true
response_inspect = true

[limits]
timeout_ms = 50
max_input_bytes = 262144
max_output_bytes = 262144
max_concurrency = 4
```

Place the `.wasm` file alongside the manifest in the plugins directory. Start the server — the plugin loads automatically.

## 2. Plugin Installation

### Directory Layout

```
/etc/synvoid/plugins/
├── synvoid-plugin.toml          # manifest (per-plugin)
├── my_filter.wasm               # plugin binary
├── my_filter.sig                # optional Ed25519 signature
└── another_plugin/
    ├── synvoid-plugin.toml
    └── another_plugin.wasm
```

### Manifest Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique plugin identifier |
| `version` | Yes | Semver version string |
| `entry` | Yes | WASM filename (relative to manifest) |
| `trust_tier` | No | Trust level (default: `local_sandboxed`) |

### Capabilities (default-deny)

All capabilities default to `false` or empty. Only grant what the plugin needs:

```toml
[capabilities]
request_inspect = true       # Read request headers/body
request_mutate = false       # Modify request headers/body
response_inspect = true      # Read response headers/body
response_mutate = false      # Modify response headers/body
metrics = false              # Emit custom metrics
persistence = false          # KV store access
mesh = false                 # DHT queries
admin_events = false         # Control-plane events

# Path-allowlisted capabilities (empty = denied)
filesystem_read = []
filesystem_write = []
network = []
```

### Resource Limits

```toml
[limits]
timeout_ms = 50              # Per-invocation timeout (ms)
max_input_bytes = 262144     # 256 KB input limit
max_output_bytes = 262144    # 256 KB output limit
max_concurrency = 4          # Concurrent invocations (semaphore)
memory_pages = 64            # Optional: 64 KiB per page
fuel = 1000000               # Optional: wasmtime fuel budget
```

### Server Config Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_memory_mb` | `64` | Global max memory per plugin (MB) |
| `max_cpu_fuel` | `1000000` | Global CPU fuel budget |
| `timeout_seconds` | `30` | Global plugin timeout (seconds) |

### Signing

For `SignedSandboxed` plugins, include a signature block:

```toml
[signature]
signature = "abcd1234..."        # hex-encoded Ed25519 signature
key_id = "operator-key-1"        # must match a trusted key
algorithm = "ed25519"            # only ed25519 supported
binary_sha256 = "sha256hex..."  # SHA-256 of .wasm file
manifest_sha256 = "sha256hex..." # SHA-256 of canonical manifest
```

Trusted keys are configured in server config:

```toml
[plugins]
dev_mode = false
allow_local_trusted = false

[[plugins.trusted_keys]]
key_id = "operator-key-1"
algorithm = "ed25519"
public_key = "base64-url-no-pad..."
```

## 3. Trust Tiers

| Tier | Use When | Signing Required | Production Safe |
|------|----------|-----------------|-----------------|
| `Disabled` | Plugin should not load | N/A | Yes |
| `LocalSandboxed` | Default. Unsigned local plugin, sandbox enforced | No | Yes |
| `LocalTrusted` | Operator explicitly trusts the plugin | No | Yes (with caution) |
| `SignedSandboxed` | Third-party or remote plugins | Yes (Ed25519) | Yes |
| `DevelopmentHotReload` | Local development only | No | **No** |

**Default**: `local_sandboxed`. Use this unless you have a specific reason not to.

**Production rules**:
- `DevelopmentHotReload` is rejected in production unless explicit override is set.
- `SignedSandboxed` requires a valid `[signature]` block; empty `binary_sha256` or `manifest_sha256` are rejected.
- `LocalTrusted` requires `allow_local_trusted = true` in server config.

## 4. Unsafe Native Extensions

Native shared-library plugins (`.so`/`.dylib`/`.dll`) run inside the SynVoid address space with **full process authority**. They are NOT sandboxed, NOT subject to capability checks, fuel limits, or any WASM constraints.

**This is a security boundary.** Only load native extensions from trusted sources.

### Production Gate Requirements

All four conditions must be met for a native extension to load:

```toml
[plugins.unsafe_native]
enabled = false                    # Must be true to load anything
allow_in_production = false        # Must be true in production mode
risk_acknowledgement = "I acknowledge unsafe native extensions have full process authority"
allowed_dirs = ["/opt/synvoid/native-extensions"]  # Must be non-empty
```

**Rejection conditions**:
- `enabled = false` → rejected
- Production mode + `allow_in_production = false` → rejected
- Missing or wrong `risk_acknowledgement` string → rejected
- Empty `allowed_dirs` → rejected
- Plugin path not under an allowed directory → rejected
- World-writable file (`others-w` bit set) → rejected

### Additional Protections

- FFI panics are caught via `std::panic::catch_unwind`
- `Arc<Library>` handles retained for plugin lifetime (prevents use-after-free)
- Optional SHA-256 hash verification for loaded binaries
- Separate hot-reload gate (`unsafe_native_enabled`)

### Config Migration

The deprecated `native_plugins_enabled` key migrates to `unsafe_native_enabled` with a deprecation warning at startup.

## 5. Hot Reload

### Configuration

```toml
[plugins.wasm.hot_reload]
enabled = false                   # Global hot-reload gate
production_enabled = false        # Production-specific gate
unsafe_native_enabled = false     # Separate gate for native extensions
require_signed_wasm = false       # Require signature on reload
```

### Behavior

- **Disabled by default.** Must be explicitly enabled.
- **Production** requires `production_enabled = true`.
- **Native extensions** have their own gate (`unsafe_native_enabled`).
- File changes are debounced (300ms initial, 3 consecutive stable checks at 100ms intervals, 5s max wait).
- Atomic swap: new plugin validates before replacing the old one. If validation fails, the old plugin remains active.

### Lifecycle States

```
Loading → Active | FailedLoad
Active → Reloading | Disabled | Quarantined | Unloading
Reloading → Active | FailedLoad
Disabled → Active (operator reset)
Quarantined → Disabled | Removed
Unloading → Removed
```

### Generation Tracking

Every load creates a generation with:
- Monotonic generation ID (never reused)
- Binary and manifest SHA-256 hashes
- Load timestamp and previous generation link

## 6. Monitoring

### Key Metrics

| Metric | Labels | Meaning |
|--------|--------|---------|
| `synvoid_plugin_invoke_total` | plugin, hook | Total plugin invocations |
| `synvoid_plugin_pool_hit_total` | plugin | Pooled instance reused |
| `synvoid_plugin_pool_miss_total` | plugin | No pooled instance; fresh created |
| `synvoid_plugin_pool_dropped_total` | plugin | Poisoned instance discarded |
| `synvoid_plugin_concurrency_limit_exceeded_total` | plugin | Semaphore exhaustion |
| `synvoid_plugin_state_transition_total` | from, to, reason | Lifecycle state changes |
| `synvoid_plugin_load_total` | plugin, result | Plugin load attempts |
| `synvoid_plugin_hot_reload_total` | plugin, result | Hot-reload attempts |
| `synvoid_plugin_capability_violation_total` | plugin, capability | Capability denials |
| `synvoid_plugin_host_call_failure_total` | plugin, host_function, failure_class | Host API failures |
| `synvoid_plugin_serialization_rejection_total` | plugin, hook, failure_class, tier | ABI frame rejections |
| `synvoid_unsafe_native_extension_loaded_total` | plugin | Native extension loads |
| `synvoid_unsafe_native_extension_load_failed_total` | plugin | Native load failures |
| `synvoid_unsafe_native_extension_reloaded_total` | plugin | Native hot-reloads |

### What to Watch

- **`pool_miss_total` climbing**: Plugin pool too small or instances being dropped frequently.
- **`concurrency_limit_exceeded_total`**: Increase `max_concurrency` in manifest or investigate slow invocations.
- **`capability_violation_total`**: Plugin requesting capabilities not in its manifest. Check if manifest needs updating.
- **`state_transition_total` with `to=Quarantined`**: Plugin failing repeatedly. Investigate logs.
- **`host_call_failure_total` with `failure_class=Timeout`**: Host call taking too long. Check network backends or DHT.
- **`serialization_rejection_total`**: ABI frame too large. Increase `max_input_bytes`/`max_output_bytes` or investigate oversized requests.

### ABI Error Codes

| Code | Name | Cause |
|------|------|-------|
| `0` | `ABI_SUCCESS` | Success |
| `-1` | `ABI_ERR_CAPABILITY_DENIED` | Missing capability |
| `-2` | `ABI_ERR_INVALID_POINTER` | Bad guest pointer/range |
| `-3` | `ABI_ERR_TIMEOUT` | Host call timed out |
| `-4` | `ABI_ERR_INPUT_TOO_LARGE` | Input exceeds size limit |
| `-5` | `ABI_ERR_UNAVAILABLE` | Resource unavailable |
| `-6` | `ABI_ERR_INTERNAL` | Internal host error |

## 7. Troubleshooting

### Plugin fails to load

1. Check the manifest exists alongside the `.wasm` file.
2. Verify `entry` matches the `.wasm` filename exactly.
3. For `SignedSandboxed`: confirm `[signature]` block is present and `binary_sha256`/`manifest_sha256` are non-empty.
4. Check trust tier is valid: `local_sandboxed`, `signed_sandboxed`, `local_trusted`, `disabled`, `development_hot_reload`.
5. For sandboxed tiers: ensure `fuel` is non-zero in manifest limits.

### Plugin loads but invocations fail

1. **`ABI_ERR_CAPABILITY_DENIED` (-1)**: Add the required capability to the manifest's `[capabilities]` section.
2. **`ABI_ERR_TIMEOUT` (-3)**: Increase `timeout_ms` in manifest limits.
3. **`ABI_ERR_INPUT_TOO_LARGE` (-4)**: Increase `max_input_bytes` in manifest limits.
4. **`ABI_ERR_UNAVAILABLE` (-5)**: Plugin pool exhausted or concurrency limit hit.
5. **`ABI_ERR_INVALID_POINTER` (-2)**: Plugin WASM is malformed — check that `guest_alloc` and `guest_free` exports exist.

### Plugin quarantine

If a plugin is quarantined:

1. Check metrics: `synvoid_plugin_state_transition_total{to="Quarantined"}`
2. Review logs for the specific failure reason.
3. Fix the underlying issue (bad manifest, oversized input, missing capability).
4. Reset the plugin: `reset_plugin("plugin-name")`

### Hot reload not working

1. Confirm `[plugins.wasm.hot_reload] enabled = true`.
2. In production, confirm `production_enabled = true`.
3. Check file stability: changes must stabilize for 3 consecutive checks (100ms apart) after initial 300ms debounce.
4. For native extensions: confirm `unsafe_native_enabled = true`.

### Unsigned plugin rejected

1. Production defaults to `RequireSigned` signing policy.
2. Either sign the plugin (add `[signature]` block) or switch to `AllowUnsignedWithWarning` policy.
3. For development, set `dev_mode = true` to disable signing enforcement.

## 8. Security Checklist

### Production Hardening

- [ ] All plugins use `local_sandboxed` or `signed_sandboxed` trust tier
- [ ] No `DevelopmentHotReload` plugins in production
- [ ] `dev_mode = false` in server config
- [ ] `allow_local_trusted = false` unless explicitly needed
- [ ] Signed plugins have valid Ed25519 signatures with non-empty `binary_sha256` and `manifest_sha256`
- [ ] Trusted keys are configured and key IDs match
- [ ] Each plugin's manifest grants only the capabilities it needs (default-deny)
- [ ] Filesystem/network allowlists are specific, not wildcard
- [ ] `max_concurrency` is set appropriately (not unbounded)
- [ ] `timeout_ms` is set per-plugin (not relying on global default)
- [ ] Hot reload is disabled or explicitly configured with `production_enabled`
- [ ] Unsafe native extensions are disabled (`enabled = false`) unless absolutely required
- [ ] If native extensions are enabled: `allow_in_production = true`, `risk_acknowledgement` set, `allowed_dirs` non-empty
- [ ] World-writable plugin files are rejected (check permissions)

### Capability Audit

Review each plugin's capabilities against its actual needs:

| Capability | Risk Level | Notes |
|------------|-----------|-------|
| `request_inspect` | Low | Read-only |
| `request_mutate` | Medium | Can modify requests |
| `response_inspect` | Low | Read-only |
| `response_mutate` | Medium | Can modify responses |
| `metrics` | Low | Emit counters/gauges |
| `persistence` | Medium | KV store access |
| `filesystem_read` | High | Path-allowlisted |
| `filesystem_write` | High | Path-allowlisted |
| `network` | High | Host/port-allowlisted |
| `mesh` | High | DHT queries (default-deny at sub-capability level) |
| `admin_events` | High | Control-plane events |

### Response Mutation Policy

Even with `response_mutate = true`, plugins cannot modify:
- `set-cookie`, `content-length`, `transfer-encoding`, `connection`, `authorization`
- Headers prefixed with `x-plugin-*` are always allowed.

## 9. Emergency Procedures

### Disable a Plugin

```rust
disable_plugin("plugin-name", "reason: suspected compromise")
```

- Prevents all new invocations immediately.
- Existing in-flight invocations complete normally.
- Plugin transitions to `DisabledByConfig`.

### Quarantine a Plugin

```rust
quarantine_plugin("plugin-name", "reason: anomalous behavior detected")
```

- Blocks all invocations (existing and new).
- Plugin transitions to `Quarantined`.
- Requires explicit operator action to restore.

### Remove a Plugin

```rust
remove_plugin("plugin-name")
```

- Fully removes from the registry.
- Plugin transitions to `Removed`.
- Cannot be recovered without re-adding configuration.

### Reset a Plugin

```rust
reset_plugin("plugin-name")
```

- Re-enables a `Disabled` or `Quarantined` plugin.
- Resets failure counters.
- Transitions to `Loaded`.

### Disable Unsafe Native Extensions

Set in server config:

```toml
[plugins.unsafe_native]
enabled = false
```

This prevents all native extension loads immediately, regardless of other settings.

### Emergency Rollback

If a hot-reloaded plugin causes issues:

1. Check the generation counter in logs/metrics.
2. The previous generation is still loaded in the generation history.
3. Use `reset_plugin()` to restore the last known-good state, or
4. Set `hot_reload.enabled = false` to prevent further reloads.
5. Manually replace the `.wasm` file with the previous version.
6. Restart the server if needed.

### Monitoring During Incident

Watch these metrics in real-time:

```
synvoid_plugin_state_transition_total{to="Quarantined"}
synvoid_plugin_state_transition_total{to="DisabledByRuntimeFailure"}
synvoid_plugin_capability_violation_total
synvoid_plugin_host_call_failure_total
synvoid_plugin_concurrency_limit_exceeded_total
```

A spike in `state_transition_total{to="Quarantined"}` with concurrent `capability_violation_total` suggests a plugin is misbehaving and being auto-quarantined. If auto-quarantine is not desired, adjust the `PluginFailurePolicy` thresholds.
