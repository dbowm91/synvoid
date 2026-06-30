# Semver and Stability Policy

Status: Policy declaration.

Scope: versioning, compatibility, and deprecation rules for the SynVoid project.

## Versioning

SynVoid is pre-1.0. All releases follow `0.Y.Z` semantics:

- **Major (Y)**: Breaking changes to any public surface listed in `architecture/final_surface_audit.md`.
- **Patch (Z)**: Bug fixes, internal refactors, documentation updates.

There is no 1.0 target date. The project will remain pre-1.0 until the public surface audit stabilizes and a compatibility test suite exists.

## Stability Classifications

Every public surface is classified in `architecture/final_surface_audit.md`:

| Label | Meaning |
|-------|---------|
| `stable` | External-facing, semver-stable after 1.0. Breaks require major version bump. |
| `stable_within_workspace` | Shared across workspace crates. May break on minor/patch bumps. |
| `stable_internal` | Internal to a single crate or binary. No external promises. |
| `transitional` | Will be removed or relocated. No compatibility promises. |

## What Is Not Stable

The following surfaces have no compatibility promises before 1.0:

- **Root re-exports** (`synvoid::*`): Compatibility facades that will be removed as crates are extracted.
- **Plugin WASM ABI**: Guest export signatures, host function signatures, and memory layout may change without notice. No versioned ABI compatibility tests exist.
- **Plugin manifest schema**: Fields may be added, renamed, or removed. Deserialize tolerates missing fields via `#[serde(default)]`, but new required fields may be added.
- **Plugin signature and trust API** (`synvoid-plugin-runtime::sandbox::types`): `verify_plugin_signature`, `enforce_plugin_load_policy`, `PluginLoadConfig`, `TrustedPluginKey`, `PluginSignatureConfig`, `PluginSignatureVerification`, `PluginSignatureError`, `PluginLoadError` — these types and functions are new in Phase 13 and may change shape as loader integration matures.
- **Admin REST API**: Response shapes, status codes, and endpoint paths may change. The `AdminMutationResult` type is the target contract but not all endpoints use it yet.
- **CLI flags and config keys**: May be renamed or removed. Config migration is not provided.
- **Binary interfaces**: `server` and `synvoid-vpn` are operator-facing but not semver-stable.

## What Is Stable

- **Dedicated workspace crate public APIs** (e.g., `synvoid-waf`, `synvoid-proxy`, `synvoid-config`): Changes follow semver once 1.0 is reached. Before 1.0, changes are documented in CHANGELOG.
- **Security invariants**: Capability checks, sandbox enforcement, and audit event generation are correctness requirements, not API contracts. They may change implementation but not security behavior.

## Deprecation

Deprecation is not yet formalized. When the project reaches 1.0:

1. Deprecated items will carry `#[deprecated]` attributes with a `since` version and `note` pointing to the replacement.
2. Deprecated items will be removed in the next major version after deprecation.
3. No removal will happen without a CHANGELOG entry and at least one minor release with the deprecation in place.

## Breaking Change Policy

Before 1.0, breaking changes are permitted on minor version bumps (per SemVer spec for `0.Y.Z`). They must:

1. Be documented in CHANGELOG under "Breaking Changes".
2. Update the stability classification in `architecture/final_surface_audit.md` if the surface changes tier.
3. Not remove security invariants or weaken sandbox enforcement.

After 1.0, breaking changes require a major version bump and a migration guide.

## Related Documents

- `architecture/final_surface_audit.md` — complete surface classification
- `architecture/release_hardening_report.md` — release checklist
- `CHANGELOG.md` — release history
