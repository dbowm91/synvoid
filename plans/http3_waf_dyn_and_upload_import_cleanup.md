# SynVoid HTTP/3 WAF Trait-Object and Upload Import Cleanup Plan

> Status: proposed surgical follow-up after the workspace-green pass.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: complete two low-risk cleanup items now that the workspace is green: decouple HTTP/3 from concrete `WafCore` using `Arc<dyn Http3RequestWaf>`, and reconcile upload import/directness documentation with the actual code.

## 0. Current state

The repo is now broadly validation-clean:

```text
cargo check --lib --no-default-features                 PASS
cargo check --no-default-features --features dns        PASS
cargo check --no-default-features --features mesh       PASS
cargo check --no-default-features --features mesh,dns   PASS
cargo check --workspace --all-targets                   PASS
cargo test --workspace --no-run                         PASS
```

Recent cleanup established:

```text
- root `yara-x` removed
- dead root upload duplicates removed
- mesh feature compiles
- workspace all-targets passes
- HTTP/3 object-safety investigated
```

The two remaining small issues are:

```text
1. `src/http3/server.rs` still stores concrete `Arc<WafCore>` even though `Http3RequestWaf` is object-safe.
2. Upload/YARA ownership docs and imports are not fully aligned. Some notes say import directness improved, while `plans/security_scanner_ownership.md` still shows `crate::upload::submodule` paths resolving through the root shim.
```

This pass should stay small. Do not restart broad modularization.

## 1. Source-of-truth prior artifacts

Use these files as context:

```text
plans/workspace_all_targets_failure_inventory.md
plans/next_modularization_recommendation.md
plans/http3_request_waf_object_safety.md
plans/http3_server_dependency_inventory.md
plans/security_scanner_ownership.md
plans/root_dependency_ownership.md
```

Important prior findings:

```text
- `Http3RequestWaf` is object-safe.
- `handle_http3_request_dispatch` already accepts `Waf: Http3RequestWaf + ?Sized`.
- Strategy A is selected: use `Arc<dyn Http3RequestWaf>`.
- Dead root upload duplicate files were deleted.
- Root `src/upload/mod.rs` remains a compatibility shim: `pub use synvoid_upload::*;`.
```

## 2. Non-goals

Do not do these in this pass:

```text
Do not create new crates.
Do not move `src/http3/server.rs` into `synvoid-http3`.
Do not move `src/http/server.rs`.
Do not move `WafCore`.
Do not move worker or supervisor.
Do not split Raft from mesh.
Do not change IPC wire names such as `PoisonImage`.
Do not remove image_poisoning compatibility shims.
Do not reintroduce root upload duplicate modules.
Do not redesign upload/YARA scanning behavior.
```

## 3. Hard constraints

1. Preserve runtime behavior.
2. Keep `src/http3/server.rs` root-owned for now.
3. Only change HTTP/3 WAF storage from concrete `Arc<WafCore>` to trait object if validation stays green.
4. Do not weaken type bounds in `synvoid-http` dispatch helpers unless necessary.
5. Prefer direct internal imports from `synvoid_upload` for upload submodules.
6. Keep root `crate::upload::*` compatibility for broad callers.
7. Documentation must match code after the pass.
8. All profile checks and workspace checks must remain green.

## 4. Validation matrix

After each task, run task-specific checks.

At the end of each wave, run:

```bash
cargo fmt
cargo check --lib --no-default-features
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http
cargo check -p synvoid-http3
cargo check -p synvoid-upload
```

At the end of the full pass, run:

```bash
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

## 5. Wave H: HTTP/3 WAF trait-object decoupling

Purpose: remove the last unnecessary concrete `WafCore` storage from `Http3Server` while keeping the server root-owned.

### Task HWD-H01: verify current HTTP/3 WAF field and constructor

Inspect:

```text
src/http3/server.rs
src/server/mod.rs
crates/synvoid-http/src/http3_request_dispatch.rs
```

Confirm current shape:

```rust
use crate::waf::WafCore;

pub struct Http3Server {
    waf: Arc<WafCore>,
}

impl Http3Server {
    pub fn new(..., waf: Arc<WafCore>, ...) -> Self { ... }
}
```

Confirm the dispatch function still supports dynamically sized WAF:

```rust
where Waf: Http3RequestWaf + ?Sized
```

Update or create a short implementation note:

```text
plans/http3_waf_dyn_migration.md
```

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
```

No source changes except the note.

### Task HWD-H02: change `Http3Server` WAF storage to `Arc<dyn Http3RequestWaf>`

Target file:

```text
src/http3/server.rs
```

Required change:

```rust
// before
use crate::waf::WafCore;
use synvoid_http::Http3RequestWaf;

pub struct Http3Server {
    waf: Arc<WafCore>,
}

pub fn new(..., waf: Arc<WafCore>, ...) -> Self

// after
use synvoid_http::Http3RequestWaf;

pub struct Http3Server {
    waf: Arc<dyn Http3RequestWaf>,
}

pub fn new(..., waf: Arc<dyn Http3RequestWaf>, ...) -> Self
```

Keep existing `WafAccess` usage intact. If `server.rs` also calls `connection_limiter`, `is_over_bandwidth_limit`, or `streaming` on `self.waf`, the trait object may need to include both traits:

```rust
Arc<dyn Http3RequestWaf + synvoid_waf::access::WafAccess>
```

If Rust rejects multiple non-auto traits in a trait object, define a local composite trait in root:

```rust
trait Http3WafBackend: Http3RequestWaf + synvoid_waf::access::WafAccess {}
impl<T> Http3WafBackend for T where T: Http3RequestWaf + synvoid_waf::access::WafAccess {}
```

Then use:

```rust
Arc<dyn Http3WafBackend>
```

Do not change dispatch semantics.

Acceptance:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http3
cargo check --lib --no-default-features
```

Stop condition:

If this propagates into broad root/server/worker generics, revert and document why. The expected change should be small.

### Task HWD-H03: update HTTP/3 construction call sites

Target likely file:

```text
src/server/mod.rs
```

Where an `Arc<WafCore>` is passed into `Http3Server::new`, coerce/clone it into the trait-object type expected by `new`.

Preferred pattern:

```rust
let http3_waf: Arc<dyn Http3WafBackend> = waf.clone();
Http3Server::new(..., http3_waf, ...)
```

or if only one trait is needed:

```rust
let http3_waf: Arc<dyn Http3RequestWaf> = waf.clone();
```

Do not create a second WAF instance.

Acceptance:

```bash
cargo check --no-default-features --features mesh,dns
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

### Task HWD-H04: update HTTP/3 dependency inventory

Update:

```text
plans/http3_server_dependency_inventory.md
plans/http3_request_waf_object_safety.md
plans/next_modularization_recommendation.md
```

Record:

```text
- Http3Server no longer stores concrete Arc<WafCore>.
- Http3RequestWaf Strategy A implemented successfully.
- Remaining root-owned HTTP3 blockers, if any: WorkerDrainState, bind_udp_reuse, root ownership decision.
- Whether this makes moving src/http3/server.rs closer or still not worth it.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 6. Wave U: upload import/directness consistency cleanup

Purpose: ensure code and docs agree on upload/YARA ownership after dead root duplicate deletion.

### Task HWD-U01: inventory current upload imports

Run:

```bash
rg -n "crate::upload::(yara_scanner|malware_scanner|rate_limit|sandbox|config|metrics|signature|yara_rule_feed)" src crates
rg -n "synvoid_upload::(yara_scanner|malware_scanner|rate_limit|sandbox|config|metrics|signature|yara_rule_feed)" src crates
```

Update:

```text
plans/security_scanner_ownership.md
```

with a current table:

```text
File | Current import | Preferred import | Action | Notes
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

No source changes except the inventory.

### Task HWD-U02: replace remaining internal `crate::upload::submodule` imports

Patch internal live code to import direct module paths from `synvoid_upload` where practical.

Likely files, if still present:

```text
src/worker/cpu_task/yara.rs
src/worker/cpu_task/state.rs
src/static_files/file_manager.rs
```

Examples:

```rust
use crate::upload::yara_scanner::{YaraRulesSource, YaraScanner};
```

becomes:

```rust
use synvoid_upload::yara_scanner::{YaraRulesSource, YaraScanner};
```

And:

```rust
use crate::upload::malware_scanner::MalwareScanner;
use crate::upload::rate_limit::*;
use crate::upload::YaraError;
```

becomes direct `synvoid_upload` imports where available.

Keep broad root re-export imports such as `use crate::upload::UploadValidator;` if they are part of compatibility-oriented root orchestration and do not reach into submodules.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-upload
cargo check --workspace --all-targets
```

### Task HWD-U03: update ownership docs and recommendation file

Update:

```text
plans/security_scanner_ownership.md
plans/root_dependency_ownership.md
plans/next_modularization_recommendation.md
```

Record:

```text
- Dead root upload files remain deleted.
- Internal submodule imports now point directly at `synvoid_upload` where practical.
- Root `src/upload/mod.rs` remains a public compatibility shim.
- Root `yara-x` remains removed.
- YARA runtime owners remain `synvoid-upload` and `synvoid-mesh`.
```

Acceptance:

```bash
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

## 7. Wave F: final validation

Purpose: prove the two surgical changes did not destabilize the now-green workspace.

### Task HWD-F01: run full validation matrix

Run:

```bash
cargo fmt
cargo check --lib --no-default-features
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http
cargo check -p synvoid-http3
cargo check -p synvoid-upload
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

Update:

```text
plans/workspace_all_targets_failure_inventory.md
plans/next_modularization_recommendation.md
```

Record pass/fail status.

Acceptance:

All commands pass, or any failure is documented with exact cause and whether it was introduced by this pass.

## 8. Recommended task order

Use this exact order:

```text
HWD-H01  verify current HTTP/3 WAF field and constructor
HWD-H02  change Http3Server WAF storage to Arc<dyn Http3RequestWaf> or composite trait object
HWD-H03  update HTTP/3 construction call sites
HWD-H04  update HTTP/3 dependency inventory
HWD-U01  inventory current upload imports
HWD-U02  replace remaining internal crate::upload::submodule imports
HWD-U03  update ownership docs and recommendation file
HWD-F01  run full validation matrix
```

## 9. Subagent prompt template

Use this prompt for smaller agents:

```text
You are implementing SynVoid task HWD-XX from plans/http3_waf_dyn_and_upload_import_cleanup.md.
Scope is limited to this task. Preserve behavior. Do not create new crates. Do not move HTTP server, HTTP3 server, WafCore, worker, supervisor, Raft, mesh, or proxy code. Do not change IPC wire names or compatibility shims. For HTTP/3, only decouple WAF storage from concrete Arc<WafCore> if validation stays green. For upload cleanup, prefer direct synvoid_upload submodule imports and keep root upload as a compatibility shim. Run the task acceptance commands and report exact failures.
```

## 10. Success criteria

This pass is successful when:

```text
1. Http3Server no longer stores concrete Arc<WafCore> if the trait-object swap validates cleanly.
2. Http3RequestWaf object-safety plan is marked implemented or explicitly deferred with reason.
3. Remaining internal upload submodule imports are direct to synvoid_upload where practical.
4. Documentation matches actual upload import state.
5. Root upload remains a compatibility shim.
6. Root yara-x remains removed.
7. Workspace validation remains green.
```
