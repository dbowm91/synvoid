# Root Crate Facade Reduction — Iteration 91

## Purpose

This plan implements the first roadmap item from `plans/roadmap.md`: root crate facade reduction.

The goal is to shrink the architectural authority of the root crate without performing a risky broad file migration. The first pass should classify the current `src/lib.rs` surface, document which root modules are permanent application/runtime modules versus transitional compatibility facades, and add guardrails that prevent new domain code from depending on root paths when a dedicated domain crate exists.

This is a boundary-finalization pass, not a rewrite. It should make future moves safer by turning implicit root ownership into an explicit ledger.

## Current State

The root package is still the easiest import path for much of SynVoid. `src/lib.rs` currently exports a broad set of modules:

```rust
pub mod admin;
pub mod app_server;
pub mod auth;
pub mod block_store;
pub mod captcha;
pub mod cgi;
pub mod challenge;
pub mod common;
pub mod config;
pub mod drain;
pub mod fastcgi;
pub mod filter;
pub mod honeypot_port;
pub mod http;
pub mod http3;
pub mod http_client;
pub mod listener;
pub mod location_matcher;
pub mod log_controller;
pub mod logging;
pub mod mesh;
pub mod metrics;
pub mod mime;
pub mod php;
pub mod platform;
pub mod plugin;
pub mod process;
pub mod protocol;
pub mod proxy;
pub mod router;
pub mod router_adapter;
pub mod sandbox;
pub mod serder;
pub mod server;
pub mod serverless;
pub mod spin;
pub mod startup;
pub mod static_files;
pub mod streaming;
pub mod supervisor;
pub mod tarpit;
pub mod tcp;
pub mod theme;
pub mod tls;
pub mod tunnel;
pub mod udp;
pub mod upload;
pub mod utils;
pub mod vpn_client;
pub mod waf;
pub mod worker;
```

It also re-exports several already-extracted crates:

```rust
pub use synvoid_geoip as geoip;
pub use synvoid_integrity as integrity;
pub use synvoid_proxy_cache as proxy_cache;
pub use synvoid_upstream as upstream;
pub use synvoid_utils::serialization;
```

The workspace already contains many dedicated crates that should be canonical owners for domain code: `synvoid-config`, `synvoid-core`, `synvoid-waf`, `synvoid-http`, `synvoid-http3`, `synvoid-http-client`, `synvoid-proxy`, `synvoid-proxy-cache`, `synvoid-tls`, `synvoid-mesh`, `synvoid-dns`, `synvoid-serverless`, `synvoid-static-files`, `synvoid-block-store`, `synvoid-app-server`, `synvoid-ipc`, `synvoid-platform`, `synvoid-metrics`, `synvoid-theme`, `synvoid-tunnel`, `synvoid-upload`, and related crates.

The risk is that root paths remain convenient and will keep absorbing implementation or dependency shortcuts unless the repo marks what is canonical.

## Non-Goals

Do not move large implementation modules in this pass.

Do not change public behavior, CLI behavior, feature defaults, or runtime startup/shutdown semantics.

Do not delete compatibility modules unless they are already pure re-export facades and all uses are trivially updated.

Do not break downstream root imports intentionally in this pass. Deprecation and migration should be staged.

Do not attempt to solve unified worker composition-root decomposition here. That is the next roadmap handoff after root ownership is inventoried.

## Desired Outcome

After this pass:

1. Every root module exported by `src/lib.rs` has a documented ownership classification.
2. There is an architecture ledger describing target owner crate, current status, and blocker for each root module.
3. Obvious already-extracted modules are marked as compatibility facades instead of implied implementation owners.
4. A small boundary guard test or script prevents new domain crates from importing root `synvoid::` paths where direct domain-crate imports should be used.
5. `src/lib.rs` becomes more self-documenting without causing churn.

## Classification Model

Use these exact status names in the ledger.

### `keep_app_root`

The module belongs in the root application crate because it composes process-level runtime behavior, CLI startup, supervisor/worker orchestration, sandbox process mode, or application-specific integration.

Likely examples:

```text
startup
supervisor
worker
server
process
sandbox
listener
tcp
udp
log_controller
logging
```

Some of these may eventually split further, but they are not simple domain-crate moves.

### `facade_existing_crate`

The module should be a compatibility facade over an already-existing dedicated crate. New code should prefer the dedicated crate.

Likely examples:

```text
config       -> synvoid-config
waf          -> synvoid-waf
http         -> synvoid-http
http3        -> synvoid-http3
http_client  -> synvoid-http-client
proxy        -> synvoid-proxy
proxy_cache  -> synvoid-proxy-cache
tls          -> synvoid-tls
mesh         -> synvoid-mesh
dns          -> synvoid-dns
serverless   -> synvoid-serverless
static_files -> synvoid-static-files
block_store  -> synvoid-block-store
app_server   -> synvoid-app-server
platform     -> synvoid-platform
metrics      -> synvoid-metrics
theme        -> synvoid-theme
tunnel       -> synvoid-tunnel
upload       -> synvoid-upload
upstream     -> synvoid-upstream
geoip        -> synvoid-geoip
integrity    -> synvoid-integrity
utils        -> synvoid-utils, where applicable
```

### `split_required`

The module has mixed responsibilities. Some parts belong in a domain crate, but some are root adapters or app-layer glue.

Likely examples:

```text
admin
plugin
router
router_adapter
common
protocol
filter
streaming
```

These need a follow-up plan before movement.

### `legacy_or_stale`

The module appears to be historical, stale, or an old compatibility path. It may be deleted or collapsed after verification.

Candidates must be verified before classification. Do not mark as stale based on name alone.

Possible examples to inspect:

```text
cgi
fastcgi
php
spin
captcha
challenge
tarpit
mime
serder
location_matcher
honeypot_port
```

Some of these may still be active; classify based on actual imports and responsibility.

## Implementation Plan

### Phase 1 — Create Root Module Ledger

Create a new file:

```text
architecture/root_module_ledger.md
```

The ledger should contain a table with these columns:

```markdown
| Root module | Current responsibility | Classification | Target owner | Current status | Blocker / next step |
|-------------|------------------------|----------------|--------------|----------------|---------------------|
```

Use one row for every public module or root re-export currently exposed by `src/lib.rs`.

Start with conservative classifications. If uncertain, use `split_required` and write the uncertainty in the blocker column.

Suggested opening text:

```markdown
# Root Module Ownership Ledger

This ledger records the intended ownership of modules exported by the root `synvoid` crate. It exists to prevent the root crate from silently remaining the canonical owner of domain implementation code after dedicated crates have been introduced.

Classification values:

- `keep_app_root`: root application/runtime composition remains the owner;
- `facade_existing_crate`: compatibility facade over a dedicated crate; new code should prefer the dedicated crate;
- `split_required`: mixed module that needs a targeted extraction plan;
- `legacy_or_stale`: candidate for deletion or collapse after verification.
```

For the first version, at minimum classify these high-confidence rows:

```markdown
| Root module | Current responsibility | Classification | Target owner | Current status | Blocker / next step |
|-------------|------------------------|----------------|--------------|----------------|---------------------|
| config | Compatibility access to configuration types and loaders | facade_existing_crate | synvoid-config | transitional facade | Prefer direct `synvoid_config` imports in domain crates |
| waf | Compatibility access to WAF implementation and adapters | facade_existing_crate | synvoid-waf plus root adapters where needed | transitional / mixed | Split concrete app adapter from crate-owned WAF primitives |
| http | Root HTTP compatibility surface and app adapters | split_required | synvoid-http plus root app server glue | mixed | Inventory remaining root-only HTTP modules before moving |
| http3 | Compatibility path for HTTP/3 server | facade_existing_crate | synvoid-http3 | largely extracted | Prefer `synvoid_http3` in new code |
| mesh | Compatibility path for mesh types | facade_existing_crate | synvoid-mesh | extracted with root re-export/adapters | Prefer `synvoid_mesh` in new code |
| tls | Compatibility path for TLS helpers | facade_existing_crate | synvoid-tls | transitional facade | Prefer `synvoid_tls` in domain crates |
| proxy | Compatibility path for proxy/router components | facade_existing_crate | synvoid-proxy | transitional facade | Prefer `synvoid_proxy` in domain crates |
| serverless | Compatibility path for serverless runtime | facade_existing_crate | synvoid-serverless | transitional facade | Prefer `synvoid_serverless` in domain crates |
| static_files | Compatibility path for static file handling | facade_existing_crate | synvoid-static-files | transitional facade | Prefer `synvoid_static_files` in domain crates |
| block_store | Compatibility path for block-store implementation | facade_existing_crate | synvoid-block-store / synvoid-core primitives | transitional facade | Clarify split between persisted store and core event types |
| app_server | Compatibility path for app-server integrations | facade_existing_crate | synvoid-app-server | transitional facade | Prefer `synvoid_app_server` in domain crates |
| worker | Worker process runtime and composition root | keep_app_root | root app crate | app runtime owner | Future plan decomposes composition root internally |
| supervisor | Supervisor process runtime and command handling | keep_app_root | root app crate | app runtime owner | Future CLI/supervisor command cleanup |
| startup | Process startup helpers | keep_app_root | root app crate | app runtime owner | May split command dispatch later |
| process | IPC/process-mode integration | keep_app_root | root app crate plus synvoid-ipc | mixed but root-owned runtime | Keep runtime glue root-side; use `synvoid-ipc` for shared types |
```

Then fill the remaining modules.

### Phase 2 — Annotate `src/lib.rs` With Ownership Blocks

Do not scatter one-line comments on every module. Instead, group modules under ownership headers.

Target shape:

```rust
// Application/runtime composition modules. These remain root-owned because they
// coordinate processes, workers, supervisor state, sockets, startup, or app-level
// integration.
pub mod startup;
pub mod supervisor;
pub mod worker;
pub mod server;
pub mod process;

// Compatibility facades over dedicated crates. New domain code should import
// the dedicated crate directly; these root paths remain for transitional API
// compatibility while root coupling is reduced.
pub mod config;
pub mod waf;
pub mod http;
pub mod http3;
pub mod mesh;
pub mod tls;
pub mod proxy;

// Mixed/legacy modules pending classification. See
// architecture/root_module_ledger.md before adding new implementation here.
pub mod admin;
pub mod plugin;
pub mod router;
```

Preserve all existing exports. This phase should not break compilation.

If the current order is relied on by tests or causes import warnings, prefer minimal grouping comments without reordering. Reordering `pub mod` entries is acceptable only if it does not cause initialization or macro visibility issues.

### Phase 3 — Collapse Only Trivial Facades

Inspect root modules that are already pure or near-pure re-exports.

For each candidate, if the file is already just re-exporting a crate, make that intent explicit with a module-level doc comment:

```rust
//! Compatibility facade for `synvoid_http3`.
//!
//! New code should import `synvoid_http3` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_http3::*;
```

Do not convert a mixed module to `pub use crate::*` in this pass. If a root module contains root-specific adapters, leave it as mixed and record it in the ledger.

High-confidence candidates to inspect first:

```text
src/http3/mod.rs
src/tunnel/mod.rs
src/app_server/mod.rs
src/platform/mod.rs
src/theme/mod.rs
src/proxy_cache equivalent root path, if any
src/geoip equivalent root path, if any
```

### Phase 4 — Add `AGENTS.override.md` Guidance For Transitional Root Areas

For directories that should not receive new implementation, add or update an `AGENTS.override.md` file.

Example for `src/http3/AGENTS.override.md` if not already present or stale:

```markdown
# HTTP/3 Root Compatibility Path

`src/http3` is a compatibility facade. The canonical HTTP/3 implementation lives in `crates/synvoid-http3`.

Do not add new HTTP/3 server implementation here. Add protocol implementation to `crates/synvoid-http3` and expose only compatibility re-exports from this directory when needed.
```

Do this only for high-confidence extracted modules. Avoid broad agent instructions in directories whose ownership is still mixed.

### Phase 5 — Add Root Import Boundary Guard

Add a focused test, preferably:

```text
tests/root_facade_boundary_guard.rs
```

The guard should prevent newly extracted domain crates from importing the root crate or root paths as a shortcut.

The initial guard can be source-based and intentionally conservative. It should scan files under `crates/` and reject obvious root crate imports:

```rust
#[test]
fn domain_crates_do_not_import_root_synvoid_crate() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = repo.join("crates");
    let mut offenders = Vec::new();

    for path in walk_rs_files(&crates_dir) {
        let text = std::fs::read_to_string(&path).expect("read source file");
        if text.contains("use synvoid::")
            || text.contains("synvoid::config")
            || text.contains("synvoid::waf")
            || text.contains("synvoid::http")
            || text.contains("synvoid::mesh")
        {
            offenders.push(path.strip_prefix(&repo).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "domain crates must import dedicated synvoid-* crates, not root synvoid paths:\n{}",
        offenders.join("\n")
    );
}
```

Implement a simple recursive `walk_rs_files()` helper using `std::fs`, not a new dependency.

Important constraints:

- Skip generated files and `target/`.
- Skip comments only if easy; otherwise keep the first guard simple and fix obvious false positives.
- Do not scan `src/`, because the root app crate is allowed to use its own modules.
- Do not reject dependency names like `synvoid_config`; only reject root-crate path syntax such as `synvoid::`.

If current code already has offenders in `crates/`, either fix the imports if trivial or add a narrow allowlist with comments explaining why the offender cannot be fixed in this pass. The allowlist should be path-specific and small.

### Phase 6 — Prefer Direct Domain-Crate Imports In Obvious Places

After the guard is added, fix only simple import offenders in `crates/`.

Examples:

```rust
// Avoid in crates/:
use synvoid::config::MainConfig;
use synvoid::waf::WafDecision;
use synvoid::mesh::MeshTransport;

// Prefer:
use synvoid_config::MainConfig;
use synvoid_waf::WafDecision;
use synvoid_mesh::MeshTransport;
```

Do not chase complex root adapter imports in this pass. Record those in the ledger as blockers.

### Phase 7 — Add Documentation Linkage

Update `plans/roadmap.md` only if necessary. The likely better place is `AGENTS.md` or an architecture doc index, but avoid large docs churn.

At minimum, add a short note near the repository guide's path correction or architecture section if appropriate:

```markdown
Root crate ownership is tracked in `architecture/root_module_ledger.md`. New domain code should prefer dedicated `synvoid-*` crates over root `synvoid::` compatibility paths unless the ledger marks the root module as `keep_app_root`.
```

If this creates too much unrelated churn in `AGENTS.md`, skip this phase and rely on the ledger plus guard test.

## Suggested File Changes

Expected new files:

```text
architecture/root_module_ledger.md
tests/root_facade_boundary_guard.rs
```

Potentially updated files:

```text
src/lib.rs
src/http3/AGENTS.override.md
src/tunnel/AGENTS.override.md
src/app_server/AGENTS.override.md
AGENTS.md
```

Only update override files for directories verified as compatibility facades.

## Example `src/lib.rs` Header Structure

Use this as a guide, not an exact patch. Preserve feature gates and existing exports.

```rust
// Root application/runtime ownership.
pub mod admin;
pub mod auth;
pub mod listener;
pub mod log_controller;
pub mod logging;
pub mod process;
pub mod sandbox;
pub mod server;
pub mod startup;
pub mod supervisor;
pub mod tcp;
pub mod udp;
pub mod worker;

// Compatibility facades over dedicated crates. Prefer direct `synvoid-*` crate
// imports in new domain code. See architecture/root_module_ledger.md.
pub mod config;
pub mod http;
pub mod http3;
pub mod http_client;
pub mod mesh;
pub mod proxy;
pub mod serverless;
pub mod static_files;
pub mod tls;
pub mod tunnel;
pub mod upload;
pub mod waf;

pub use synvoid_geoip as geoip;
pub use synvoid_integrity as integrity;
pub use synvoid_proxy_cache as proxy_cache;
pub use synvoid_upstream as upstream;
pub use synvoid_utils::serialization;

// Mixed legacy/application adapters pending targeted extraction. See ledger.
pub mod app_server;
pub mod block_store;
pub mod captcha;
pub mod cgi;
pub mod challenge;
pub mod common;
pub mod drain;
pub mod fastcgi;
pub mod filter;
pub mod honeypot_port;
pub mod location_matcher;
pub mod metrics;
pub mod mime;
pub mod php;
pub mod platform;
pub mod plugin;
pub mod protocol;
pub mod router;
pub mod router_adapter;
pub mod serder;
pub mod spin;
pub mod streaming;
pub mod tarpit;
pub mod theme;
pub mod utils;
pub mod vpn_client;
```

If reordering proves noisy, keep current order and add section comments above contiguous groups where possible.

## Example Guard Helper

If the implementation model needs a concrete starting point, use this shape for `tests/root_facade_boundary_guard.rs`:

```rust
use std::path::{Path, PathBuf};

fn walk_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            walk_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn domain_crates_do_not_import_root_synvoid_crate() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = repo.join("crates");
    let mut files = Vec::new();
    walk_rs_files(&crates_dir, &mut files);

    let mut offenders = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("read Rust source");
        if text.contains("use synvoid::") || text.contains("synvoid::") {
            offenders.push(path.strip_prefix(&repo).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "domain crates must not import the root synvoid crate; use dedicated synvoid-* crates instead:\n{}",
        offenders.join("\n")
    );
}
```

If false positives occur in doc comments or string literals, refine the scanner to ignore line comments before adding broad allowlists.

## Verification Commands

Run these after implementation:

```bash
cargo fmt
cargo test --test root_facade_boundary_guard
cargo check --workspace
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

If full workspace check is too slow or blocked by unrelated known issues, at minimum run:

```bash
cargo test --test root_facade_boundary_guard
cargo check -p synvoid
cargo check -p synvoid-http3
cargo check -p synvoid-http
cargo check -p synvoid-waf
cargo check -p synvoid-mesh --features mesh
```

Document any skipped command and the reason in the implementation commit message or follow-up note.

## Review Checklist

Before considering the pass complete, verify:

- `architecture/root_module_ledger.md` exists and includes every `pub mod` or root re-export in `src/lib.rs`.
- `src/lib.rs` has clear ownership grouping comments or module-level guidance.
- No behavior-affecting module moves occurred without a targeted reason.
- The new root-facade guard passes or has a narrow path-specific allowlist.
- Any allowlist entry has a blocker recorded in the ledger.
- New code in `crates/` uses dedicated crate imports where available.
- Compatibility root paths remain available for now.

## Follow-Up Work After This Pass

After this plan lands, the next roadmap handoff should be `Unified Worker Composition Root Decomposition`.

Do not start that work in this pass unless the root-facade guard reveals a small import cleanup directly needed to compile.
