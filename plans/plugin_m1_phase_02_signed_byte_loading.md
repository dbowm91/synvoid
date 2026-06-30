# Plugin Milestone 1 Phase 2: Signed Byte Loading and TOCTOU Closure

## Goal

Make signed plugin loading bind the manifest, signature, hash, entry path, and instantiated WASM bytes into one indivisible load transaction.

A `SignedSandboxed` plugin must be verified against the exact bytes that are instantiated. No file load path should verify one artifact and instantiate another, and no file load path should attempt signature verification without the actual binary bytes.

## Problem Statement

The current policy path accepts `binary_bytes: Option<&[u8]>`. File-based loads call enforcement with `None`, which means signature verification either fails against an empty byte slice or can become incomplete when hashes are missing. This is not production-grade. Signed plugins must fail closed unless the runtime verifies the actual file bytes.

The second problem is time-of-check/time-of-use. Loading by file path can read metadata/manifest, enforce policy, and later let Wasmtime read the file again. A file can change between verification and instantiation. The load path should instead read bytes once, verify those bytes, and instantiate from the verified byte slice.

## Desired Architecture

Introduce a prepared load object that owns the verified bytes:

```rust
pub struct PreparedPluginLoad {
    pub manifest: PluginManifest,
    pub effective_limits: WasmResourceLimits,
    pub wasm_bytes: bytes::Bytes,
    pub source_path: Option<PathBuf>,
    pub binary_sha256: String,
    pub manifest_sha256: String,
    pub verified_key_id: Option<String>,
}
```

Then instantiate with:

```rust
WasmRuntime::load_from_bytes_with_priority(
    &prepared.manifest.name,
    &prepared.wasm_bytes,
    prepared.effective_limits,
    priority,
)
```

Avoid `Module::from_file()` in production plugin loading paths. It is acceptable to keep it for tests or a low-level helper, but manager-level file loading should use verified bytes.

## Implementation Steps

### 1. Add a File Read and Canonicalization Step

For file-based loads:

1. Reject symlink plugin files unless an explicit operator policy later permits them.
2. Canonicalize the `.wasm` path.
3. Discover the manifest path from the canonical wasm path.
4. Parse the manifest.
5. Verify `manifest.entry` resolves to the same canonical wasm path or to a file within the same plugin directory.
6. Read the wasm bytes into memory.
7. Compute `binary_sha256` from those bytes.
8. Enforce load policy with `Some(&wasm_bytes)`.
9. Instantiate from the same bytes.

Recommended helper:

```rust
fn prepare_file_plugin_load(&self, path: &Path) -> Result<PreparedPluginLoad, WasmPluginError>
```

### 2. Make `SignedSandboxed` Strict

For `PluginTrustTier::SignedSandboxed`:

- A `[signature]` block is required.
- `binary_sha256` must be non-empty and must match the actual bytes.
- `manifest_sha256` must be non-empty and must match the canonical manifest signing payload.
- `key_id` must resolve to a trusted key.
- `algorithm` must be `ed25519` unless additional algorithms are intentionally added.
- The Ed25519 signature must verify.

Do not allow a signed plugin with empty hash fields in production. If backwards compatibility is needed for development, gate it behind `dev_mode = true` and never under `SignedSandboxed` production semantics.

### 3. Return Verification Metadata

`verify_plugin_signature()` currently returns `PluginSignatureVerification::Valid`. Extend the result or add a wrapper that returns useful metadata:

```rust
pub struct VerifiedPluginSignature {
    pub key_id: String,
    pub binary_sha256: String,
    pub manifest_sha256: String,
    pub algorithm: PluginSignatureAlgorithm,
}
```

Store this in `PreparedPluginLoad` and expose it in plugin info/audit logs. This is needed for later operator observability.

### 4. Memory/Mesh Loads Require Metadata

Current memory loads construct/default a manifest when no file path exists. For mesh-delivered or memory-loaded plugins, add a stricter path:

```rust
pub fn load_plugin_from_memory_with_manifest(
    &self,
    manifest: PluginManifest,
    data: &[u8],
    priority: i32,
) -> Result<Arc<WasmRuntime>, WasmPluginError>
```

Keep the old `load_plugin_from_memory()` only for tests or local development and ensure it defaults to `LocalSandboxed` with all-deny capabilities. If it remains public, document that it cannot produce `SignedSandboxed` semantics without a manifest.

For mesh-loaded plugins, require signed metadata before production loading. A mesh-distributed plugin should not be accepted as a nameless byte blob.

### 5. Close Duplicate Name and Replacement Races

After verification, use the manifest name as the canonical plugin identity. Reject duplicate names before inserting. For reloads, load/verify/instantiate the new runtime first, then atomically replace the old runtime by name only after the new runtime is valid.

Avoid this sequence:

1. Remove old plugin.
2. Try to load new plugin.
3. Fail and leave no plugin.

Prefer:

1. Prepare and instantiate new plugin.
2. Acquire write lock.
3. Replace old plugin with new plugin.
4. Invalidate sorted cache.

## Required Tests

### Signature Tests

Add tests for:

- Valid signed plugin loads successfully with the trusted key.
- Missing signature block fails for `SignedSandboxed`.
- Empty `binary_sha256` fails for production `SignedSandboxed`.
- Binary hash mismatch fails.
- Manifest hash mismatch fails.
- Unknown key ID fails.
- Malformed public key fails.
- Malformed signature fails.
- Wrong signature over otherwise correct manifest fails.

### TOCTOU Tests

Add a test that simulates a file changing between preparation and instantiation. The desired implementation should instantiate from the already-read verified bytes, so changing the file after preparation must not affect the instantiated module.

If direct TOCTOU simulation is cumbersome, add a regression test that verifies `WasmPluginManager::load_plugin()` internally calls the bytes path rather than `Module::from_file()`.

### Mesh/Memory Tests

Add tests for:

- `load_plugin_from_memory_with_manifest()` enforces `SignedSandboxed` signature checks against provided bytes.
- `load_plugin_from_memory()` defaults to local sandboxed/all-deny and cannot accidentally grant mesh/request capabilities.
- Mesh plugin loading rejects unsigned production plugin metadata.

### Reload Tests

Add tests for:

- A failed signed reload leaves the old plugin active.
- Reload with tampered bytes fails.
- Reload with a valid new version succeeds and updates source hash metadata.

## Edge Cases

- Manifest `entry` values containing `..`, absolute paths, or symlink escapes must be rejected unless explicitly allowed by a future operator policy.
- If the manifest file is absent, the default local sandboxed manifest may still be allowed for local development, but it should not be eligible for production `SignedSandboxed` behavior.
- If `allow_local_trusted = false`, a local trusted plugin should fail before any expensive instantiation work.
- Signature verification should not log raw signature material or public key material.
- Audit logs should include hashes and key IDs, not secret key material.

## Acceptance Criteria

This phase is complete when:

- Manager-level file plugin loading reads WASM bytes once and instantiates from those verified bytes.
- `SignedSandboxed` file plugins cannot load without actual byte verification.
- Binary hash, manifest hash, trusted key lookup, and Ed25519 signature verification are all fail-closed.
- Reload cannot remove a working plugin unless the replacement has fully loaded and verified.
- Mesh/memory plugin APIs have a manifest-bearing production path.
- Tests cover valid signatures, tampering, missing metadata, reload failure, and memory-loaded signature enforcement.

## Non-Goals

- Per-plugin capability mapping, except as needed from Phase 1. Phase 1 owns authority wiring.
- Runtime failure/quarantine behavior. Phase 3 owns invocation state.
- ABI pointer safety. Phase 4 owns guest memory boundary changes.
