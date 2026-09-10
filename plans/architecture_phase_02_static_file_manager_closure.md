# Phase 02 — Static File-Manager Ownership and Functional Closure

Status: implementation handoff plan
Baseline reviewed: `src/static_files/file_manager.rs`, root-module ledger, HTTP/WebDAV consumers

## Objective

Give the file-manager subsystem one canonical implementation owner, remove misleading no-op background refresh behavior, and converge root consumers without weakening path traversal, symlink, upload, archive, extension, or malware-scanning policy.

This phase is both an ownership cleanup and a functional-correctness pass. It must not be treated as a mechanical file move.

## Current state

`src/static_files/mod.rs` is classified as a transitional compatibility facade over `crates/synvoid-static-files`, but it still declares a substantial local `file_manager` implementation. Known consumers include the root HTTP file-manager API and WebDAV handler.

`FileManager` itself includes filesystem validation, directory listing/mutations, upload restrictions, malware/YARA scanning, and rate limiting. It depends on `SiteStaticConfig` and `synvoid-upload`, so most of the implementation appears reusable rather than inherently application-root-specific.

A concrete functional residual exists: `reload_yara_rules_if_needed()` currently returns `Ok(())` under both mesh and non-mesh configurations without performing a refresh, while `start_periodic_yara_refresh()` advertises repeated refresh behavior. A background operation must not report successful work that is not performed.

## Scope

Inspect/modify as needed:

- `src/static_files/mod.rs`
- `src/static_files/file_manager.rs`
- `crates/synvoid-static-files/`
- `src/http/file_manager.rs`
- `src/http/webdav.rs`
- `crates/synvoid-config/src/site/*`
- `crates/synvoid-upload/*` interfaces used by scanning/rate limiting
- tests covering file manager, WebDAV, upload/malware scanning, and path safety
- `architecture/root_module_ledger.md`
- `architecture/root_module_burndown_report.md`
- `src/static_files/AGENTS.override.md`

## Work plan

### 1. Build a consumer/dependency matrix

Search every direct import of `crate::static_files::file_manager::*` and every public type/method exported by the module.

Classify dependencies as:

- reusable domain dependency suitable for `synvoid-static-files` (`synvoid-config` DTOs, `synvoid-upload`, filesystem primitives);
- root application dependency that requires an adapter/closure/trait;
- legacy/dead dependency that can be removed.

Do not decide ownership from directory location alone.

### 2. Choose canonical owner

Preferred outcome: move the reusable `FileManager`, config, DTOs, errors, path validation, scanning hooks, and filesystem operations into `crates/synvoid-static-files` and leave root as a pure re-export/adapter surface.

If a specific root-only dependency blocks extraction, introduce the narrowest possible injected trait/callback at the root boundary. Do not make `synvoid-static-files` depend on the root `synvoid` crate.

If investigation proves the entire manager is application-specific, update the ownership ledger accordingly instead of pretending it is transitional. That outcome requires explicit written justification and elimination of duplicate/ambiguous ownership language.

### 3. Resolve YARA refresh semantics

Determine whether the active scanner/rule manager exposes a real version/reload operation.

If real refresh is supported:

- wire `reload_yara_rules_if_needed()` to observable scanner/rule-version state;
- avoid unnecessary scanner rebuilds when the version is unchanged;
- surface reload failures accurately;
- make periodic task cancellation/lifecycle ownership explicit so it does not outlive the runtime owner.

If real refresh is not supported or not needed because scanner state is immutable/recreated elsewhere:

- remove `new_with_periodic_refresh`, `start_periodic_yara_refresh`, and/or misleading refresh naming rather than returning success;
- document the actual rule update lifecycle.

Acceptance must forbid a no-op success placeholder.

### 4. Preserve and strengthen filesystem safety

Before moving code, freeze existing behavior with tests for:

- `..` traversal and attempted escape above root;
- symlinked ancestor escape;
- missing-leaf mutations whose nearest existing ancestor is outside root;
- hidden-file policy;
- blocked/allowed extensions;
- max path depth;
- file size limits;
- directory/file type confusion;
- destructive operations on non-empty directories;
- upload malware detection and rate limiting.

Review check/use races in path resolution. Do not expand this phase into a wholesale platform-specific `openat2` rewrite unless a demonstrable exploit exists, but ensure the extraction does not worsen TOCTOU or symlink behavior.

### 5. Move consumers to canonical imports

Update `src/http/file_manager.rs`, `src/http/webdav.rs`, and all other consumers to import the canonical crate path or a deliberate root adapter.

Avoid keeping both root implementation and crate implementation for compatibility. A compatibility facade may `pub use` canonical types; it must not fork behavior.

### 6. Normalize API/type ownership

Keep filesystem/domain errors in the canonical file-manager module. HTTP status mapping may remain in the root HTTP adapter if that prevents transport semantics from leaking into the static-files crate.

Similarly, admin authentication and `ConfigManager` orchestration belong in root HTTP/admin adapters, not in the reusable file manager.

### 7. Update ownership documentation and guards

After convergence:

- update `architecture/root_module_ledger.md` disposition for `static_files`;
- update `architecture/root_module_burndown_report.md`;
- update `src/static_files/AGENTS.override.md`;
- add a static ownership guard that fails if implementation code is reintroduced under a facade expected to be pure.

## Rejection criteria

Reject an implementation that:

- leaves two `FileManager` implementations;
- preserves no-op refresh methods that report success;
- moves root admin/auth/HTTP response concerns into `synvoid-static-files`;
- weakens traversal/symlink/hidden-file/malware checks to simplify extraction;
- introduces broad application traits where narrow injected behavior suffices;
- adds a new crate for file-manager code when `synvoid-static-files` is already the natural domain owner.

## Acceptance criteria

1. Exactly one canonical `FileManager` implementation exists.
2. All consumers reference that implementation directly or through a pure compatibility re-export.
3. Periodic YARA/rule refresh performs real observable work with accurate failure reporting, or the unsupported/no-op refresh surface is removed.
4. Existing and added negative path-safety tests pass before and after the ownership move.
5. HTTP/admin authentication and response mapping remain root/application concerns.
6. The root-module ledger no longer says `static_files::file_manager` “needs investigation”; it records a final ownership decision.
7. No new crate is introduced.

## Verification

Run at minimum:

```text
cargo fmt --all -- --check
cargo test --profile ci file_manager
cargo test --profile ci webdav
cargo test --profile ci upload
cargo clippy --profile ci --all-targets -- -D warnings
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
```

If YARA behavior is feature-dependent, add the smallest feature-specific test invocation needed to prove both supported and unsupported lifecycle semantics.
