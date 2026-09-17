# Phase 36 Plan: YARA-X Deserialization Exposure Closure and Engine Upgrade

Status: planned (2026-09-16).

Roadmap: `plans/runtime_dependency_security_followup_roadmap.md`.

Primary goal: remove remote/mesh compiled YARA bytes from the executable trust path, then move `synvoid-yara` from `yara-x 1.15` to a release that fixes GHSA-2jx3-ff3v-j7jj (target: 1.20.0 or newer compatible 1.20.x).

This phase is security-motivated, not a feature upgrade.

## Why this is first

Current code in `crates/synvoid-yara/src/engine.rs` calls:

```rust
yara_x::Rules::deserialize(compiled_rules)
```

inside the compiled-rule reload path.

YARA-X <=1.18 is affected by GHSA-2jx3-ff3v-j7jj, where malformed serialized rule data accepted by the safe `Rules::deserialize` API can lead to memory corruption / undefined behavior. The issue is fixed in YARA-X 1.19.0 and later.

SynVoid is currently on YARA-X 1.15. The risk is material because mesh/upload composition retains a compiled-rule path and `UploadValidator` prefers `YaraRulesManager::get_current_compiled_rules()` when a new mesh rule version appears.

The repository's architectural intent already says mesh distributes source text and keeps compiled blobs opaque for wire compatibility. This phase must make production behavior match that intent.

## Part A — Freeze the current data-flow with tests before changing it

Add tests that prove the current boundary and prevent accidental ambiguity during the migration.

Inventory and cover:

- `YaraRulesManager::apply_compiled_rules(...)`;
- `get_current_compiled_rules()`;
- mesh `YaraCompiledRuleAnnounce` decode/storage;
- upload YARA reload selection;
- `YaraScanner` compiled-rule reload entry points;
- `CompiledArtifact::{compile, verify_binding, deserialize_verified, from_bytes_with_binding}`;
- local compiled bundle loading, if any production path remains;
- child jail YARA reload/compile paths.

Add one regression test that demonstrates a mesh-origin compiled byte vector can currently reach the compiled reload selection path. The test must stop before invoking malformed bytes against the vulnerable 1.15 deserializer; it exists only to pin the pre-fix routing fact.

## Part B — Remove mesh/remote compiled bytes from the executable path

Change the trust model to:

> Signed/approved YARA **source text** is the canonical executable input for remotely distributed rules. Compilation occurs locally inside the YARA execution boundary.

Requirements:

1. `UploadValidator` must not prefer `get_current_compiled_rules()` over source rules for mesh updates.
2. Mesh may retain `compiled_rules` fields for protocol/wire compatibility, but production receive paths must treat those bytes as opaque/non-executable metadata.
3. A remote compiled blob must never be passed to `yara_x::Rules::deserialize`, directly or indirectly.
4. Rule approval/version/digest semantics remain source-based.
5. A valid source update must continue to trigger local compilation and atomic scanner replacement.
6. Invalid source must fail closed according to the existing YARA/update policy.
7. Legacy peers carrying compiled bytes but no acceptable source must not cause local execution of the blob. Define the behavior explicitly: reject/degrade/retain previous rules according to existing availability policy, but do not deserialize the blob.

If `local_compiled_rules` exists only for legacy wire compatibility after this change, rename/document it accordingly or remove internal preference APIs that imply executable authority.

## Part C — Narrow raw compiled deserialization APIs

Audit all `Rules::deserialize` call sites after Part B.

Target state:

- zero call sites for remotely originated bytes;
- any remaining deserialization is limited to a strongly authenticated local artifact path with explicit engine/version/digest provenance;
- no public method accepts an arbitrary `&[u8]` and turns it into executable rules without proving that provenance.

`CompiledArtifact::from_bytes_with_binding(...)` currently computes `compiled_sha256` from the bytes it receives, so the resulting self-consistency check alone is not a trust proof. Do not treat an attacker-supplied checksum or caller-supplied engine string as authorization.

Preferred disposition:

- if compiled artifacts have no production consumer after Part B, remove `deserialize_verified` / `from_bytes_with_binding` from the public production surface and keep only compile/metadata helpers actually used;
- if a local packaged compiled bundle is still required, introduce a typed verified-artifact constructor that requires authenticated manifest/source provenance before deserialization.

Do not preserve a raw-byte API solely for hypothetical future use.

## Part D — Upgrade YARA-X

Target `yara-x = 1.20.0` or the newest compatible 1.20.x available at implementation time.

Before modifying code, record:

```bash
cargo tree -p synvoid-yara --depth 2
cargo tree -i yara-x --workspace
cargo tree -i wasmtime@40.0.4 --workspace
cargo tree -e features -i yara-x --workspace
cargo audit
cargo deny check advisories
```

Then update `crates/synvoid-yara/Cargo.toml` and lockfile.

Expected upstream changes as of planning:

- YARA-X 1.19+ fixes GHSA-2jx3-ff3v-j7jj;
- 1.20.0 uses Wasmtime 45.0.3 rather than the current transitive 40.0.4;
- API surface remains broadly compatible but must be validated by compilation/tests rather than assumed.

Do not add a git dependency for YARA-X unless a released crate is proven insufficient for a concrete blocker.

## Part E — Bump engine/artifact compatibility identifiers

Update:

```rust
YARA_ENGINE_VERSION
```

from the current `yara-x/1.15` value to the landed engine line.

Old compiled artifacts must fail deterministically rather than being opportunistically deserialized under the new engine.

Audit whether `COMPILED_FORMAT_VERSION` also needs a bump. The rule is:

- engine-only incompatibility => engine-version bump is sufficient;
- SynVoid envelope layout/meaning change => bump `COMPILED_FORMAT_VERSION` too.

Tests must cover old-engine rejection and successful local recompile from canonical source.

## Part F — Revalidate scanner semantics and resource limits

YARA-X upgrades must not silently alter SynVoid policy.

Re-run/extend tests for:

- bounded rule compilation;
- scan timeout behavior;
- scan concurrency/queue limits;
- large-file/windowed scanning;
- archive inspection interaction;
- reload atomicity;
- previous-rules retention on failed update;
- mesh source update propagation;
- jail execution path;
- signature/provenance validation;
- max compiled/source sizes;
- fail-open/fail-closed upload policy behavior.

If YARA-X 1.20 changes warnings or parser strictness, classify the behavior change explicitly. Do not suppress new diagnostics globally just to preserve old tests.

## Part G — Performance and footprint evidence

Capture before/after for representative cases:

- bundled rule compile time;
- representative production rule-set compile time;
- clean-buffer scan throughput;
- match-heavy scan throughput;
- scanner construction/reload latency;
- release binary or relevant crate build-size delta;
- YARA dependency subtree size.

Use existing benches if they already measure these paths; extend them only where evidence is missing.

Do not enable YARA-X `pulley` or disable default modules as part of this phase unless separately justified by measurements and consumer compatibility.

## Part H — Advisory cleanup from the YARA upgrade

After the graph resolves, recompute rather than copy the existing Wasmtime ignores.

Run:

```bash
cargo tree -i wasmtime --workspace
cargo tree -e features -i wasmtime@45.0.3 --workspace   # adjust to resolved version
cargo audit
cargo deny check advisories
```

Expected direction:

- the YARA-X 1.15 / Wasmtime 40.0.4 path disappears;
- old 40.x-specific Wasmtime ignores should be removed if no longer reachable;
- RUSTSEC-2026-0269 may still apply to the YARA-X transitive Wasmtime line. If so, retain only the exact ignore that the final graph requires, with updated dependency path and proof that `wasmtime-wasi` remains unresolved/unreachable;
- GHSA-2jx3-ff3v-j7jj must not remain ignored: the dependency itself should be upgraded past the vulnerable range.

Do not call a package "patched" merely because the vulnerable capability is absent.

## Acceptance criteria

Phase 36 is complete only when:

- `synvoid-yara` resolves to YARA-X >=1.19, target 1.20.x;
- no mesh/remote compiled rule bytes can reach `Rules::deserialize`;
- remote rule execution recompiles authenticated/approved source locally;
- old engine-version compiled artifacts reject deterministically;
- any remaining compiled deserialization API has an authenticated local provenance boundary, or is removed;
- upload/jail/YARA reload behavior remains correct under existing failure policies;
- the old Wasmtime 40.0.4 path is absent if YARA-X 1.20 resolves as expected;
- obsolete advisory ignores are removed rather than carried forward;
- `cargo audit`/`cargo deny` results are documented truthfully for the new graph.

## Rejection criteria

Reject an implementation that:

- merely upgrades YARA-X but leaves remote compiled bytes executable;
- keeps YARA-X 1.15 and adds an advisory ignore for GHSA-2jx3-ff3v-j7jj;
- treats a caller-supplied checksum as proof a compiled blob is trusted;
- weakens rule signatures/provenance or upload fail-closed behavior;
- accepts old 1.15 compiled artifacts under the new engine;
- introduces a YARA-X fork without a concrete released-crate blocker;
- changes YARA module coverage or scan semantics without explicit evidence.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo check -p synvoid-yara --all-targets
cargo test -p synvoid-yara
cargo test -p synvoid-upload --all-features
cargo test -p synvoid-jail-runtime --all-features
cargo test -p synvoid-mesh --all-features yara
cargo tree -i yara-x --workspace
cargo tree -i wasmtime --workspace
cargo audit
cargo deny check
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo check --no-default-features
cargo check --no-default-features --features mesh
```

Record the final YARA-X version, transitive Wasmtime version/features, removed ignores, and any parser/behavior delta in the closeout evidence.
