# SynVoid HTTP WAF Access and Static-Files Extraction Plan

> Status: proposed next-pass handoff.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: make the next HTTP/server/HTTP3 migration blockers smaller without destabilizing the root server. This pass focuses on two bounded tracks: extracting the small image-poisoning helper into `synvoid-static-files`, and defining the WAF access seam needed by HTTP/3 and future HTTP server movement.

## 0. Current state

Recent refactor passes succeeded at major crate separation and consolidation:

```text
Proxy:
  root src/proxy/mod.rs is a compatibility shim.
  canonical ProxyServer lives in crates/synvoid-proxy.
  ProxyServer no longer stores Arc<WafCore>.

HTTP:
  crates/synvoid-http now owns many reusable HTTP request-flow, dispatch, streaming, WAF-decision, and response helper modules.
  many root src/http modules are now pure compatibility shims.
  root src/http/server.rs remains root-owned.
  root src/http/mod.rs still lists explicit modules for path stability.

HTTP/3:
  src/http3/server.rs remains root-owned.
  crates/synvoid-http3 contains an accurate blocker note.
  WafProcessor, RouteResolver, MetricsSink, and DrainState already exist, but WafProcessor does not cover all WafCore access used by HTTP/3.
```

Existing inventories should be treated as source-of-truth context for this pass:

```text
plans/http_module_overlap_matrix.md
plans/http_root_only_modules.md
plans/http_server_dependency_inventory.md
plans/http3_server_dependency_inventory.md
```

Important findings from those inventories:

```text
- 24 root HTTP modules are pure re-export shims.
- 11 root HTTP modules are root-state adapter shims.
- 6 root HTTP modules remain root-only implementations.
- image_poisoning.rs is the smallest root-only HTTP module and is the best immediate extraction candidate.
- src/http/server.rs should remain root-owned until a server-runtime context pass.
- src/http3/server.rs should remain root-owned until WafCore exposes connection limiter, bandwidth, and streaming access through a trait.
```

## 1. Pass objectives

This pass has two primary objectives.

### Objective A: extract image poisoning

Move the small image-poisoning helper out of root HTTP and into `synvoid-static-files`, because it is a static-file/security image pipeline concern rather than HTTP server orchestration.

Target outcome:

```text
crates/synvoid-static-files owns image_poisoning logic.
root src/http/image_poisoning.rs becomes a compatibility shim.
root src/http/mod.rs keeps public path stability.
```

### Objective B: define WAF access seam for HTTP3/server

Define a narrow trait that covers the WafCore capabilities not covered by `WafProcessor` but needed by HTTP3/server-style code:

```text
connection limiter access
bandwidth-limit check
streaming scanner/accessor
possibly tarpit/block/drop policy access if already used directly
```

Target outcome:

```text
synvoid-waf exposes a small WafAccess-like trait.
root WafCore implements that trait or has a small adapter implementing it.
HTTP3 inventory can be updated from KEEP_ROOT_UNTIL_WAFCORE_TRAIT_EXTENSION to a smaller remaining-blocker state.
Do not move HTTP3 server yet unless it becomes trivially clean.
```

## 2. Explicit non-goals

Do not do these in this pass:

```text
Do not move src/http/server.rs.
Do not move worker.
Do not move supervisor.
Do not split Raft/consensus from mesh.
Do not move WafCore into synvoid-waf.
Do not create broad god traits.
Do not create new crates.
Do not move the full file-manager/WebDAV/admin file surface.
Do not prune large root dependency groups while also moving code.
```

## 3. Hard constraints

1. No extracted crate may depend on root `synvoid`.
2. `synvoid-core` must remain dependency-light.
3. The WAF access trait must stay narrow: target 3-5 methods, stop if it wants more than 7.
4. Do not expose internal locks, channels, task handles, or `ArcSwap` internals through traits.
5. Do not make `synvoid-http3` import root `synvoid`.
6. Preserve public root paths via compatibility shims.
7. Preserve behavior; this is structural.
8. Keep each task diff small.

## 4. Validation matrix

For each task, run the task-specific checks. At the end of each wave, run:

```bash
cargo fmt
cargo check -p synvoid-static-files
cargo check -p synvoid-waf
cargo check -p synvoid-http
cargo check -p synvoid-http3
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

At the end of the full pass, run:

```bash
cargo check --workspace --all-targets
```

If full workspace clippy is noisy, use targeted clippy:

```bash
cargo clippy -p synvoid-static-files --all-targets -- -D warnings
cargo clippy -p synvoid-waf --all-targets -- -D warnings
cargo clippy -p synvoid-http3 --all-targets -- -D warnings
```

## 5. Wave S: extract image poisoning into synvoid-static-files

Purpose: complete the smallest root-only HTTP extraction identified by `plans/http_root_only_modules.md`.

### Task HWS-S01: inspect current image-poisoning dependencies

Do not move code yet.

Create:

```text
plans/image_poisoning_extraction_inventory.md
```

Inspect:

```text
src/http/image_poisoning.rs
crates/synvoid-static-files/src/**
crates/synvoid-config/src/** for SiteImagePoisonConfig
```

Document:

```text
Symbol | Current location | Used by | Target location | Notes
```

At minimum, classify:

```text
apply_image_poisoning
invalidate_image_poison_cache_for_site
IMAGE_POISON_CACHE or equivalent cache static
SiteImagePoisonConfig
PoisonImageClient
any error/result types
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check -p synvoid-static-files
```

### Task HWS-S02: add image-poisoning module to synvoid-static-files

Target crate:

```text
crates/synvoid-static-files
```

Add module:

```text
crates/synvoid-static-files/src/image_poisoning.rs
```

Move the implementation from:

```text
src/http/image_poisoning.rs
```

to the new module.

Preferred import direction:

```text
synvoid-static-files may depend on synvoid-config if it needs SiteImagePoisonConfig.
Use synvoid_static_files::client::PoisonImageClient if already available.
Do not import root synvoid.
```

Update:

```text
crates/synvoid-static-files/src/lib.rs
```

with:

```rust
pub mod image_poisoning;
pub use image_poisoning::{apply_image_poisoning, invalidate_image_poison_cache_for_site};
```

Acceptance:

```bash
cargo check -p synvoid-static-files
```

Stop condition:

If `SiteImagePoisonConfig` is not accessible without root imports and adding `synvoid-config` creates a cycle, stop and report the cycle. Do not duplicate config structs unless explicitly approved.

### Task HWS-S03: replace root image_poisoning module with shim

Target file:

```text
src/http/image_poisoning.rs
```

Replace implementation with:

```rust
// Root compatibility shim — canonical implementation is in synvoid-static-files.
pub use synvoid_static_files::image_poisoning::*;
```

Keep root `src/http/mod.rs` unchanged except for any required re-export adjustments.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

### Task HWS-S04: update root-only HTTP inventory

Update:

```text
plans/http_root_only_modules.md
```

Reflect that `image_poisoning.rs` is now extracted and root is a shim.

Adjust the root-only count from 6 to 5 if appropriate.

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 6. Wave W: define WAF access trait

Purpose: cover the concrete `WafCore` accesses that block HTTP/3 and future HTTP server movement but are not covered by `WafProcessor`.

Known missing access from inventories:

```text
connection_limiter
is_over_bandwidth_limit()
streaming()
```

Potentially related access:

```text
FloodProtector/FloodDecision are already in synvoid-waf and do not need root abstraction.
TarpitService and BlockListStore already exist.
ThreatLevelProvider already exists.
```

### Task HWS-W01: inventory exact WafCore access in HTTP3 and HTTP server

Create:

```text
plans/waf_access_trait_inventory.md
```

Inspect:

```text
src/http3/server.rs
src/http/server.rs
src/http/server/**
src/http/*waf*
src/http/*streaming*
```

Search:

```bash
rg "\.connection_limiter|is_over_bandwidth_limit|\.streaming\(|streaming\(" src/http src/http3
rg "WafCore" src/http src/http3
```

Record:

```text
Access | File/location | Used for | Existing trait covers? | Proposed trait method | Notes
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task HWS-W02: define `WafAccess` trait in synvoid-waf

Target crate:

```text
crates/synvoid-waf
```

Add to an existing traits module or a new module:

```text
crates/synvoid-waf/src/access.rs
```

Candidate shape:

```rust
use std::net::IpAddr;
use std::sync::Arc;

use crate::{ConnectionLimiter, StreamingConfig};

pub trait WafAccess: Send + Sync + 'static {
    fn connection_limiter(&self) -> Option<Arc<ConnectionLimiter>>;
    fn is_over_bandwidth_limit(&self, site_id: &str, client_ip: IpAddr) -> bool;
    fn streaming_config(&self) -> Option<StreamingConfig>;
}
```

Adjust names/types to match current `synvoid-waf` exports. If `streaming()` returns a reference or a config wrapper, prefer returning a small cloned DTO rather than exposing internal WafCore state.

If returning `Arc<ConnectionLimiter>` leaks too much, define a narrower trait instead:

```rust
pub trait ConnectionLimitAccess: Send + Sync + 'static {
    fn try_acquire_connection(&self, site_id: &str, client_ip: IpAddr) -> Option<ConnectionTokenGuardLike>;
}
```

But prefer the smallest change that fits existing call sites.

Acceptance:

```bash
cargo check -p synvoid-waf
cargo test -p synvoid-waf --no-run
```

Stop condition:

If the trait needs more than 7 methods, stop and report. That means the boundary is too broad and should be split.

### Task HWS-W03: implement WafAccess for root WafCore or adapter

Target crate:

```text
root synvoid crate
```

Preferred implementation:

```rust
impl synvoid_waf::access::WafAccess for crate::waf::WafCore { ... }
```

If direct implementation creates privacy or lifetime issues, use adapter:

```rust
pub struct RootWafAccess {
    inner: Arc<WafCore>,
}

impl synvoid_waf::access::WafAccess for RootWafAccess { ... }
```

Do not make private WafCore internals public solely for this trait. Add small accessor methods on WafCore only if needed.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task HWS-W04: update HTTP3 inventory and blocker note

Update:

```text
plans/http3_server_dependency_inventory.md
crates/synvoid-http3/src/lib.rs
```

The new blocker status should distinguish:

```text
Resolved by WafAccess:
  connection limiter access if covered
  bandwidth-limit check if covered
  streaming access if covered

Remaining blockers:
  WorkerDrainState if still concrete
  platform bind_udp_reuse root utility if still root-only
  any concrete function signatures in synvoid-http HTTP3 helpers that still take WafCore directly
```

Acceptance:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
```

## 7. Wave Q: optional HTTP3 signature cleanup

Do not move HTTP3 server in this wave unless it becomes trivial. The purpose is to reduce concrete WafCore coupling in helper signatures.

### Task HWS-Q01: make synvoid-http HTTP3 helpers accept WafAccess where needed

Target crate:

```text
crates/synvoid-http
```

Inspect HTTP3 helper modules:

```text
crates/synvoid-http/src/http3_request_flow.rs
crates/synvoid-http/src/http3_request_dispatch.rs
crates/synvoid-http/src/http3_waf_dispatch.rs
crates/synvoid-http/src/traffic_control.rs
```

If any helper takes concrete WafCore-like access indirectly, change it to accept a generic:

```rust
A: synvoid_waf::access::WafAccess
```

or a narrow `&dyn WafAccess`.

Do not change call semantics.

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If changing signatures fans out into root worker/server rewrites, stop and update the inventory rather than continuing.

### Task HWS-Q02: reduce HTTP3 server concrete WafCore field usage

Target crate:

```text
root synvoid crate
```

Update `src/http3/server.rs` to use `WafAccess` for the specific methods it covers, while still storing concrete `Arc<WafCore>` if broader server code requires it.

This is an intermediate step. The file may still remain root-owned.

Acceptance:

```bash
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

Stop condition:

If this change forces moving the entire HTTP3 server or genericizing the whole struct, stop and document the remaining blocker.

### Task HWS-Q03: decide whether HTTP3 server is ready to move

Update:

```text
plans/http3_server_dependency_inventory.md
```

Decision options:

```text
KEEP_ROOT_UNTIL_WAFACCESS_USED
KEEP_ROOT_UNTIL_DRAIN_TRAIT_OBJECT
KEEP_ROOT_UNTIL_PLATFORM_SOCKET_SEAM
MOVE_READY
```

Do not move code in this task.

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 8. Wave R: root dependency cleanup, only if safe

Purpose: prune only dependencies made obsolete by this pass. Do not do broad manifest surgery.

### Task HWS-R01: update root dependency ownership notes for static-files and WAF access

Update:

```text
plans/root_dependency_ownership.md
```

Focus only on dependencies affected by this pass:

```text
image/static file related:
  stegoeggo
  infer
  walkdir
  lightningcss
  minify-html
  minify-js
  brotli

WAF access related:
  no likely direct dependency removal expected

HTTP3 related:
  quinn
  h3
  h3-quinn
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task HWS-R02: prune only clearly obsolete dependencies

If `image_poisoning` extraction makes any root dependencies unused, remove them in a tiny batch.

Rules:

```text
1-4 dependencies maximum.
Do not prune quinn/h3/h3-quinn while HTTP3 server remains root-owned.
Do not prune config/static-file deps without compiler validation.
If removal fails, restore and mark KEEP_ROOT_FOR_NOW.
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --workspace --all-targets
cargo check --no-default-features --features mesh,dns
```

## 9. Recommended task order

Use this exact order:

```text
HWS-S01  inspect current image-poisoning dependencies
HWS-S02  add image-poisoning module to synvoid-static-files
HWS-S03  replace root image_poisoning module with shim
HWS-S04  update root-only HTTP inventory
HWS-W01  inventory exact WafCore access in HTTP3 and HTTP server
HWS-W02  define WafAccess trait in synvoid-waf
HWS-W03  implement WafAccess for root WafCore or adapter
HWS-W04  update HTTP3 inventory and blocker note
HWS-Q01  make synvoid-http HTTP3 helpers accept WafAccess where needed
HWS-Q02  reduce HTTP3 server concrete WafCore field usage
HWS-Q03  decide whether HTTP3 server is ready to move
HWS-R01  update root dependency ownership notes
HWS-R02  prune only clearly obsolete dependencies
```

## 10. Subagent prompt template

Use this prompt for smaller agents:

```text
You are implementing SynVoid task HWS-XX from plans/http_waf_access_and_static_files_pass.md.
Scope is limited to this task. Preserve behavior. Do not create new crates. Do not move src/http/server.rs, worker, supervisor, WafCore, Raft, or HTTP3 server unless the task explicitly says to. Do not add dependencies from extracted crates back to root synvoid. Prefer compatibility shims and small traits. If a trait grows beyond 7 methods or exposes internal locks/channels/runtime handles, stop and report the boundary problem. Run the task acceptance commands and report exact failures.
```

## 11. Success criteria

This pass is successful when:

```text
1. image_poisoning canonical implementation lives in synvoid-static-files.
2. root src/http/image_poisoning.rs is a compatibility shim.
3. http_root_only_modules.md no longer lists image_poisoning as root-only.
4. synvoid-waf exposes a narrow WafAccess-like trait or equivalent smaller traits.
5. root WafCore or a root adapter implements that trait.
6. HTTP3 blocker note is updated to reflect WafAccess progress.
7. HTTP3 remains root-owned unless dependency inventories prove it is move-ready.
8. src/http/server.rs remains root-owned.
9. root dependencies are pruned only if compiler-verified safe.
10. proxy and existing HTTP shims remain intact.
```
