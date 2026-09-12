# Phase 26 Plan: YARA Execution Boundary Consolidation

Status: ready for implementation after Phase 25.

Roadmap position: Track 4, Phase 26.

Primary goal: make YARA parsing/compilation/scanning a single security boundary so network-facing mesh and upload orchestration do not independently link or execute the YARA compiler.

## Current state

The repository already has the important primitive: Phase 22 established a versioned, bounded, supervised YARA jail. `src/sandbox/yara_service.rs` implements `JailHandler` for `JailKind::Yara`, re-verifies the SHA-256 digest, bounds loaded rulesets/input/matches, applies scan timeouts, and rejects wrong-kind operations.

However YARA capability remains distributed:

- `crates/synvoid-upload` directly depends on `yara-x` and owns `YaraScanner`;
- `crates/synvoid-mesh` directly depends on `yara-x` and compiles/serializes rules in `mesh/yara_rules.rs` for syntax validation/distribution;
- the child jail imports `synvoid_upload::YaraScanner`, coupling generic YARA execution to the upload domain;
- mesh distribution stores rule text/compiled bytes and includes YARA-specific state, making it easy for compilation to migrate back into the control-plane process.

This phase is not a new sandbox protocol. It consolidates ownership around the existing jail semantics.

## Target architecture

Introduce a dedicated low-level crate, tentatively `crates/synvoid-yara/`, with no dependency on mesh, upload, HTTP, admin, WAF, or the root crate.

It should own only YARA-domain primitives that are reusable and independently testable:

- `YaraRulesSource` / normalized rule input types;
- `YaraScanner` or equivalent engine wrapper;
- bounded compile/deserialize/scan operations;
- match DTO/internal result types not tied to upload policy;
- archive/depth/resource policy primitives only if they are truly YARA-generic;
- explicit engine version / serialized-rule compatibility metadata if compiled rule blobs remain part of distribution.

`yara-x` must have one production owner: `synvoid-yara` (plus unavoidable transitive copies inside upstream dependencies if any). `synvoid-upload` becomes a policy/orchestration consumer. `synvoid-mesh` must not compile YARA rules directly after this phase.

## Part A — Extract the canonical engine

1. Inventory `crates/synvoid-upload/src/yara_scanner.rs` and all YARA-specific helpers/tests.
2. Classify code into:
   - generic YARA engine;
   - upload policy (MIME/archive/upload disposition, retention, upload-specific limits);
   - mesh distribution/approval policy;
   - jail transport/service adaptation.
3. Move only generic engine code to `synvoid-yara`.
4. Preserve public behavior with explicit adapters/re-exports where stability policy requires them.
5. Make `synvoid-yara` independently testable without network access or mesh features.

Do not move upload archive policy wholesale simply because the scanner currently implements it; keep ownership semantic.

## Part B — Define a narrow execution contract

Create an engine/executor interface that separates orchestration from execution. Prefer a narrow trait/DTO surface such as:

- validate/compile rules;
- load rules by digest/version;
- scan bounded bytes;
- unload rules;
- return bounded match metadata.

The root/jail adapter may implement this over `synvoid-ipc::JailClient`. Tests may use an in-process engine implementation. Production call sites that process untrusted rules/content should prefer the jail implementation when isolation policy requires it.

Do not expose arbitrary file paths, arbitrary command execution, or generic Wasmtime handles through this interface.

## Part C — Remove YARA compilation from mesh

Refactor `crates/synvoid-mesh/src/mesh/yara_rules.rs` so mesh owns distribution/approval/versioning only.

Required changes:

1. Remove direct `yara-x` dependency from `synvoid-mesh`.
2. Replace `yara_x::compile()` syntax validation with an injected/narrow YARA validation capability provided by composition or with prevalidated signed artifacts produced by the YARA service.
3. If compiled rule blobs remain distributed:
   - include compiler/engine format version metadata;
   - bind digest/signature to rule source + compiled artifact + engine version;
   - reject incompatible serialized versions deterministically;
   - never deserialize/execute a mesh-provided compiled blob in the mesh process.
4. Prefer distributing signed canonical rule text plus digest/version unless compiled-blob distribution has measured value that justifies compatibility risk.
5. Preserve existing mesh approval semantics: edge submission, global approval, signatures, size/count limits, version ordering, and persistence must not weaken.

## Part D — Decouple upload from engine implementation

`crates/synvoid-upload` should consume `synvoid-yara` contracts rather than own `yara-x`.

Keep upload-specific responsibilities in upload:

- upload validation pipeline;
- archive recursion/depth policy;
- MIME/file policy;
- upload quarantine/decision mapping;
- mesh rule-source selection where feature-gated;
- upload-specific observability.

Do not let `synvoid-yara` depend back on `synvoid-upload`.

## Part E — Jail integration

Adapt `src/sandbox/yara_service.rs` to use `synvoid-yara` directly rather than `synvoid-upload::YaraScanner`.

Preserve all Phase 22 invariants:

- parent-created framed IPC only;
- digest re-verification inside jail using constant-time comparison where applicable;
- maximum rule sets/input/matches;
- typed errors;
- timeout and supervisor restart bounds;
- `IsolationPolicy::Required` fails closed;
- no generic execution operation.

Phase 29 will move this child-side service into an explicit runtime package. This phase should leave that move mechanical by removing upload-domain coupling first.

## Part F — Wasmtime/YARA dependency reduction

After extraction run:

```bash
cargo tree -i yara-x --workspace
cargo tree -i wasmtime --workspace
cargo tree -i wasmtime-wasi --workspace
```

Target graph:

- `synvoid-mesh` no longer reaches `yara-x`;
- `synvoid-upload` no longer directly reaches `yara-x` except through the narrow `synvoid-yara` crate if the in-process test implementation remains linked;
- production parent processes should not compile untrusted YARA rules in mesh/upload orchestration;
- remaining vulnerable transitive Wasmtime paths have a substantially smaller authority domain and their Phase 25 exception can be removed or narrowed.

If `yara-x` still forces an advisory-affected Wasmtime line, isolate that dependency to the YARA runtime package and document that the main mesh/control-plane crate no longer links it.

## Required tests

Add tests for:

- rule validation equivalence before/after extraction;
- deterministic rule digest/version binding;
- serialized-rule version rejection if compiled blobs remain supported;
- mesh approval cannot cause local compile without going through the injected executor/service;
- upload scanning behavior equivalence;
- jail load/scan/unload round trip using the new crate;
- malformed/oversized rule and input rejection;
- timeout/crash required-isolation behavior remains unchanged;
- a static guard: `crates/synvoid-mesh` contains no `yara_x`/`yara-x` production reference;
- a dependency guard: only approved crate(s) may declare `yara-x`.

Move single-crate tests into `synvoid-yara/tests` according to root test ownership policy.

## Documentation updates

Update:

- `architecture/sandbox_jail_protocol.md`;
- mesh YARA/distribution docs and relevant skills;
- upload architecture docs;
- `architecture/crate_granularity_audit.md`;
- `architecture/root_dependency_ownership.md` if root direct dependencies change;
- `deny.toml` advisory rationale after the dependency graph changes;
- `AGENTS.md` stale path/security invariant references.

## Acceptance criteria

Phase 26 is complete when:

- one crate is the canonical production owner of the YARA engine;
- `synvoid-mesh` does not depend on or call `yara-x`;
- upload policy no longer owns the generic YARA compiler/scanner implementation;
- YARA jail imports the generic engine directly;
- untrusted rule compilation is performed only through the approved execution boundary for production paths;
- mesh approval/distribution semantics and upload decisions remain behaviorally compatible;
- all resource bounds/fail-closed jail behavior remain intact;
- dependency tree evidence shows a smaller YARA/Wasmtime authority domain;
- Phase 25 advisory exceptions are removed or narrowed accordingly.

## Rejection criteria

Reject an implementation that:

- moves `yara-x` to a new crate but still compiles rules independently inside mesh and upload processes;
- makes `synvoid-yara` depend on mesh/upload/root;
- replaces signed rule/version semantics with an opaque compiled blob lacking engine-version binding;
- permits mesh-delivered native code or arbitrary Wasmtime execution;
- weakens jail resource limits to preserve old in-process behavior.

## Verification

```bash
cargo test -p synvoid-yara --all-targets
cargo test -p synvoid-upload --all-targets
cargo test -p synvoid-mesh --all-targets --features mesh
cargo test --test security_regression --profile ci -- --test-threads=1
cargo xtask verify
cargo tree -i yara-x --workspace
cargo tree -i wasmtime --workspace
cargo deny check
cargo audit
```