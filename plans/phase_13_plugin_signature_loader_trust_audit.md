# Phase 13 Plan: Plugin Signature Verification and Loader Trust Audit

Status: completed.

Roadmap position: Track 2, Phase 13 of `plans/roadmap.md`.

Primary goal: make `SignedSandboxed` a real trust tier and verify that development hot reload cannot become accidental production behavior.

## Context

Phase 7 introduced trust tiers, manifests, default-deny capabilities, limits, and failure isolation. The final cleanup pass added call-site capability gating for WASM request/response and mesh host functions. Remaining deferred items are cryptographic signature verification and loader-level trust-tier enforcement, especially `DevelopmentHotReload` gating.

## Non-Goals

Do not build a plugin marketplace.

Do not stabilize the plugin ABI as public semver-stable.

Do not allow unsigned production plugins by default.

Do not weaken default-deny capability enforcement.

## Deliverables

1. Signature verification implementation or explicit fail-closed behavior for `SignedSandboxed`.
2. Manifest/binary hash coverage documented and tested.
3. Trusted key configuration path.
4. Loader audit for all trust tiers.
5. Tests for valid signature, invalid signature, tampered binary, missing key, unsigned production rejection, and dev hot-reload gating.
6. Updated docs: `architecture/plugin_runtime_sandbox.md`, optional `architecture/plugin_loader_trust_audit.md`, and final verification report.

## Phase A: Inventory Signing and Loader Paths

Run:

```bash
rg "SignedSandboxed|DevelopmentHotReload|SigningPolicy|signature|verify|PluginManifest|load_plugin|load_plugins|hot_reload|allow_unsigned|dev_mode" crates/synvoid-plugin-runtime src/plugin src/server tests architecture
```

Create or update `architecture/plugin_loader_trust_audit.md`:

```markdown
| Loader path | File | Trust tier source | Signature behavior | Dev-mode behavior | Production behavior | Status |
|-------------|------|-------------------|--------------------|-------------------|---------------------|--------|
```

Include:

- direct WASM load,
- global plugin manager load,
- hot reload load,
- Axum native plugin load if applicable,
- Spin/serverless compatibility paths if they reuse plugin config.

## Phase B: Define Signature Coverage

Decide what is signed.

Minimum coverage:

- plugin binary SHA-256 or stronger digest,
- manifest fields that affect trust/capabilities/limits,
- plugin name/version/entry,
- capabilities,
- limits,
- trust tier,
- optional build metadata if present.

Suggested manifest shape:

```toml
[signature]
algorithm = "ed25519"
public_key_id = "operator-key-1"
binary_sha256 = "..."
manifest_sha256 = "..."
signature = "base64-url-no-pad..."
```

If the existing schema differs, adapt without broad churn.

## Phase C: Trusted Key Configuration

Add or wire trusted key config.

Options:

1. Global plugin config includes trusted public keys.
2. Key files live under a configured trust directory.
3. Development/test keys are accepted only in test/dev mode.

Rules:

- Missing key must fail closed for `SignedSandboxed`.
- Unknown key ID must fail closed.
- Malformed key must fail closed.
- Do not read arbitrary key paths from plugin manifest unless explicitly allowed and canonicalized.

Example type:

```rust
pub struct TrustedPluginKey {
    pub key_id: String,
    pub algorithm: PluginSignatureAlgorithm,
    pub public_key: Vec<u8>,
}
```

## Phase D: Verification Implementation

Preferred algorithm: Ed25519 if project already has a suitable dependency or can add one with clear entitlement. If dependency addition is contested, implement fail-closed policy first and document cryptographic verification as blocked.

Expected function shape:

```rust
pub fn verify_plugin_signature(
    manifest: &PluginManifest,
    binary_bytes: &[u8],
    trusted_keys: &TrustedPluginKeys,
) -> Result<PluginSignatureVerification, PluginSignatureError>;
```

Verification steps:

1. Check `SignedSandboxed` requires signature block.
2. Compute binary hash and compare to manifest hash.
3. Compute canonical manifest signing payload.
4. Resolve trusted public key by key ID.
5. Verify signature.
6. Return structured success/failure.

Canonicalization must be deterministic. Avoid signing raw TOML text if formatting differences are expected. Prefer a canonical serialized struct excluding the signature field.

## Phase E: Loader Enforcement

Add enforcement at plugin load boundary:

- `SignedSandboxed`: must verify signature.
- `LocalSandboxed`: unsigned allowed only if config permits local sandboxed plugins.
- `LocalTrusted`: requires explicit local trust config.
- `DevelopmentHotReload`: requires explicit dev mode/hot-reload config and must be rejected in production default.
- `Disabled`: never loads.

Example policy check:

```rust
match manifest.trust_tier {
    PluginTrustTier::Disabled => Err(PluginLoadError::Disabled),
    PluginTrustTier::SignedSandboxed => verify_plugin_signature(...).map(|_| ()),
    PluginTrustTier::DevelopmentHotReload if !config.dev_mode => Err(PluginLoadError::DevHotReloadNotAllowed),
    PluginTrustTier::LocalTrusted if !config.allow_local_trusted => Err(PluginLoadError::LocalTrustedNotAllowed),
    _ => Ok(()),
}
```

Apply to all loader paths, including hot reload.

## Phase F: Guardrails

Extend `tests/plugin_capability_boundary_guard.rs` or add `tests/plugin_signature_policy_guard.rs`.

Guard checks:

- Every path that loads a plugin calls the trust/signature policy function.
- `DevelopmentHotReload` is only accepted behind explicit config gate.
- `SignedSandboxed` cannot bypass verification.
- Signature errors are not logged with raw secret key material.
- New plugin load paths fail closed until classified.

Add liveness checks for any exceptions.

## Phase G: Tests

Unit tests:

- `signed_sandboxed_requires_signature`
- `signed_sandboxed_rejects_unknown_key`
- `signed_sandboxed_rejects_invalid_signature`
- `signed_sandboxed_rejects_tampered_binary`
- `signed_sandboxed_accepts_valid_signature`
- `development_hot_reload_rejected_without_dev_mode`
- `development_hot_reload_allowed_with_explicit_dev_mode`
- `disabled_plugin_never_loads`
- `local_trusted_requires_explicit_config`
- `hot_reload_uses_same_trust_policy_as_initial_load`

If full crypto is deferred:

- tests must assert `SignedSandboxed` fails closed with `VerificationUnavailable`, not silently loads.

## Phase H: Documentation

Update:

- `architecture/plugin_runtime_sandbox.md`
- `architecture/semver_stability_policy.md`
- `architecture/final_verification_cleanup_report.md`
- `AGENTS.md` command list if a new guard is added.

Document:

- exact signature coverage,
- supported algorithms,
- trusted key config,
- fail-closed behavior,
- production versus development behavior,
- known limitations.

## Verification Commands

```bash
cargo fmt --all -- --check
cargo check --no-default-features --features mesh,dns
cargo check
cargo test -p synvoid-plugin-runtime signature
cargo test -p synvoid-plugin-runtime sandbox
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_failure_does_not_poison_manager
cargo test --test plugin_signature_policy_guard
```

Adjust test names to actual implementation.

## Acceptance Criteria

This phase is complete when:

- `SignedSandboxed` requires verified signature or fails closed if verification is unavailable.
- Signature covers plugin binary and capability-affecting manifest fields.
- Trusted key resolution is explicit and safe.
- Development hot reload is rejected without explicit dev-mode config.
- Hot reload uses the same trust policy as initial load.
- Tests cover missing, invalid, tampered, and valid signatures.
- Docs no longer list plugin signing as an unresolved policy placeholder.

## Handoff Notes

It is acceptable to implement fail-closed signature policy before adding crypto. It is not acceptable for `SignedSandboxed` to silently behave like unsigned local sandboxed.
