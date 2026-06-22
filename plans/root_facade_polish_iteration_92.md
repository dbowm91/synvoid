# Root Facade Polish — Iteration 92

## Purpose

This is a narrow polishing pass after Iteration 91's root crate facade reduction. Iteration 91 successfully created the root ownership ledger, annotated `src/lib.rs`, added root-facade guidance, and introduced `tests/root_facade_boundary_guard.rs`.

Before moving to the next roadmap phase, clean up the documentation and guardrail edges so the repository does not encode misleading ownership language. This pass should not move implementation code or begin unified worker decomposition.

## Current State

Iteration 91 landed the right structural artifacts:

- `architecture/root_module_ledger.md` records every root module and re-export with ownership classification.
- `src/lib.rs` has ownership grouping comments.
- Pure facade modules received module-level doc comments.
- Several root compatibility directories received `AGENTS.override.md` guidance.
- `tests/root_facade_boundary_guard.rs` rejects root `synvoid::` imports under `crates/`.
- `AGENTS.md` points agents at the root module ledger and guard test.

The remaining issues are small but worth fixing before deeper refactors:

1. The `src/lib.rs` grouping comment says several modules are "Root application/runtime composition modules," but the ledger classifies some of those modules as `split_required`, not permanent root-owned modules.
2. Some directories are described as compatibility facades even though they still have local root-side submodules or adapter code.
3. The root module ledger is useful but could distinguish "pure facade" from "facade with local adapter/submodule" more explicitly.
4. The root facade guard is correct for the first pass, but it could use a small maintenance note and slightly clearer failure guidance.
5. A few `AGENTS.override.md` files may overstate "do not add implementation here" if the directory still contains mixed local adapters.

## Non-Goals

Do not move any implementation files.

Do not delete any root modules.

Do not change runtime behavior, feature gates, public APIs, startup behavior, shutdown behavior, mesh behavior, WAF behavior, or request-path logic.

Do not start the unified worker composition-root decomposition in this pass.

Do not broaden the guard test to scan `src/`; root app code is still allowed to use root modules.

Do not convert mixed modules into re-export-only facades unless they are already demonstrably pure and all local code is stale.

## Desired Outcome

After this pass:

- `src/lib.rs` comments accurately distinguish root-owned modules, split-required modules, and compatibility facades.
- The ownership ledger has a clearer status vocabulary for pure facades versus facade-plus-local-adapter modules.
- `AGENTS.override.md` guidance exists only where it is accurate, and mixed directories have softer guidance.
- The boundary guard test has clear comments explaining what it prevents and how to handle an unavoidable offender.
- No implementation behavior changed.

## Phase 1 — Align `src/lib.rs` Grouping Comments

Update only comments and grouping labels unless a tiny reorder improves readability without semantic churn.

Current shape has one broad block:

```rust
// Root application/runtime composition modules. These remain root-owned because
// they coordinate processes, workers, supervisor state, sockets, startup, or
// app-level integration. See architecture/root_module_ledger.md.
pub mod admin;
pub mod auth;
pub mod captcha;
pub mod challenge;
pub mod common;
pub mod drain;
pub mod filter;
pub mod http;
pub mod http_client;
pub mod listener;
pub mod log_controller;
pub mod logging;
pub mod platform;
pub mod plugin;
pub mod sandbox;
pub mod server;
pub mod startup;
pub mod supervisor;
pub mod tarpit;
pub mod tcp;
pub mod udp;
pub mod utils;
pub mod worker;
```

The problem is that modules such as `auth`, `captcha`, `challenge`, `filter`, `http`, `http_client`, `logging`, `platform`, `plugin`, `tarpit`, and `utils` are ledgered as `split_required`, not permanent root-owned modules.

Replace the broad comment with a more precise one. Recommended wording:

```rust
// Root-owned and mixed application modules. These modules either remain
// process/application composition code, or still contain root-side adapters that
// require targeted extraction before they can become pure domain-crate facades.
// See architecture/root_module_ledger.md for the per-module classification.
```

This avoids lying about permanence while keeping the file simple.

If desired, split into two groups:

```rust
// Root-owned application/runtime composition modules.
pub mod common;
pub mod drain;
pub mod log_controller;
pub mod sandbox;
pub mod server;
pub mod startup;
pub mod supervisor;
pub mod tcp;
pub mod udp;
pub mod worker;

// Mixed application/domain modules. These still expose root-side implementation
// or adapters and need targeted extraction plans before becoming pure facades.
pub mod admin;
pub mod auth;
pub mod captcha;
pub mod challenge;
pub mod filter;
pub mod http;
pub mod http_client;
pub mod logging;
pub mod platform;
pub mod plugin;
pub mod tarpit;
pub mod utils;
```

Prefer the split if it does not introduce noisy ordering problems. Otherwise use the single corrected comment.

## Phase 2 — Refine Ledger Status Vocabulary

Update `architecture/root_module_ledger.md` with clearer status terms.

Add a short section after classification values:

```markdown
Status vocabulary:

- `pure re-export facade`: the root module only re-exports a dedicated crate or crate submodule;
- `facade with local adapter`: the root module mostly re-exports a crate but still contains root-specific adapters, aliases, or submodules;
- `mixed implementation`: the root module contains real implementation that needs a targeted extraction plan;
- `root runtime owner`: the root module remains the current owner of process/runtime composition behavior;
- `stale candidate`: the module appears removable or collapsible after verification.
```

Then adjust rows that currently blur pure facade and mixed status.

High-priority rows to inspect and potentially edit:

- `static_files`: currently says `facade_existing_crate`, but `src/static_files/mod.rs` still has local `file_manager`. Status should be `facade with local adapter/submodule`, not pure facade.
- `proxy`: has a type alias with a root trait bound. Status should not imply pure facade.
- `metrics`: if it contains tests or local wrappers, mark as `facade with local tests` or similar.
- `http3`: if it selectively re-exports rather than glob-re-exporting, keep `selective re-export facade`.
- `process`: pure facade over `synvoid-ipc`; current wording is fine.
- `listener`: verify whether it is truly pure facade over `synvoid-http::listener`; if yes, fine.
- `location_matcher`, `router`, `router_adapter`, `streaming`, `protocol`: verify they are pure facades over `synvoid-proxy`; if yes, fine.
- `honeypot_port`: verify it is pure facade over `synvoid-honeypot`; if yes, fine.

Do not reclassify mixed modules to `facade_existing_crate` just because a target crate exists. The classification should describe current truth, not desired end state.

## Phase 3 — Audit Facade Module Doc Comments

Review the module-level comments added in Iteration 91.

For pure re-export modules, this language is accurate:

```rust
//! Compatibility facade for `synvoid_ipc`.
//!
//! New code should import `synvoid_ipc` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.
```

For modules that still contain local submodules or root adapters, use softer language:

```rust
//! Transitional compatibility surface for `synvoid_static_files`.
//!
//! Most static-file implementation belongs in `synvoid_static_files`. This root
//! module still exposes compatibility shims and local adapters during the
//! modularization transition. See `architecture/root_module_ledger.md` before
//! adding new implementation here.
```

Likely candidates for softer wording:

```text
src/static_files/mod.rs
src/proxy/mod.rs if it has root-specific aliases/adapters
src/http3/mod.rs if selective exports hide root-specific glue
src/metrics/mod.rs if tests/wrappers exist
src/tls/mod.rs if it received facade wording despite local server code
src/http_client/mod.rs if it received facade wording despite QUIC tunnel dispatch
```

Do not add or edit doc comments in large mixed modules unless the current wording is misleading.

## Phase 4 — Audit `AGENTS.override.md` Files

Review the override files created or changed in Iteration 91:

```text
src/app_server/AGENTS.override.md
src/http3/AGENTS.override.md
src/serverless/AGENTS.override.md
src/static_files/AGENTS.override.md
src/theme/AGENTS.override.md
src/tunnel/AGENTS.override.md
```

For directories that are truly pure facades, keep strict wording:

```markdown
Do not add new implementation here. Add implementation to `crates/<crate>` and expose only compatibility re-exports from this directory when needed.
```

For directories with local adapters/submodules, change to transitional wording:

```markdown
Do not add new domain implementation here. Root-local adapters may remain only when they are documented in `architecture/root_module_ledger.md` and cannot yet move without introducing a circular dependency.
```

Likely candidate for transitional wording:

```text
src/static_files/AGENTS.override.md
```

Maybe candidate depending on actual code:

```text
src/http3/AGENTS.override.md
```

Do not create new override files for mixed directories in this polish pass unless there is a clear documented ownership rule.

## Phase 5 — Improve Guard Test Maintainability Comments

Keep `tests/root_facade_boundary_guard.rs` behavior the same unless there is an obvious false-positive bug.

Add comments near the allowlist explaining the intended process:

```rust
// Keep this allowlist empty unless a crate cannot avoid a root `synvoid::` path
// during a staged migration. Every allowlist entry must include a matching
// blocker in `architecture/root_module_ledger.md` and should be removed by the
// next targeted extraction pass.
```

If the current comment says "non-string-literal code" but the heuristic is line-based and approximate, tighten the language:

```rust
// The string-literal check below is intentionally heuristic. It avoids obvious
// false positives in diagnostics/doc examples, but this guard is primarily a
// source-level architectural tripwire, not a Rust parser.
```

Do not add dependencies such as `syn` or `walkdir`.

## Phase 6 — Optional: Add a Tiny Ledger Consistency Test

This is optional. If it is too much churn, skip it.

A small test could check that every public root module in `src/lib.rs` appears in `architecture/root_module_ledger.md`. This would keep the ledger from drifting when new root modules are added.

Suggested test file:

```text
tests/root_module_ledger_guard.rs
```

Simple implementation approach:

1. Read `src/lib.rs`.
2. Extract lines starting with `pub mod `, `pub use synvoid_`, and inline module names like `pub mod buffer {`.
3. Read `architecture/root_module_ledger.md`.
4. Assert each exported module/re-export name appears in the ledger as `| name |` or a documented re-export row.

Example skeleton:

```rust
#[test]
fn root_exports_are_recorded_in_ownership_ledger() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib = std::fs::read_to_string(repo.join("src/lib.rs")).unwrap();
    let ledger = std::fs::read_to_string(repo.join("architecture/root_module_ledger.md")).unwrap();

    let mut missing = Vec::new();
    for line in lib.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("pub mod ") else { continue };
        let name = rest
            .split(|c: char| c == ';' || c == '{' || c.is_whitespace())
            .next()
            .unwrap_or("");
        if name.is_empty() || name == "test_utils" {
            continue;
        }
        let needle = format!("| {} |", name);
        if !ledger.contains(&needle) {
            missing.push(name.to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "root modules missing from architecture/root_module_ledger.md: {}",
        missing.join(", ")
    );
}
```

If this test is added, run it explicitly:

```bash
cargo test --test root_module_ledger_guard
```

This guard is useful but not mandatory. Do not let it derail the polish pass.

## Phase 7 — Verify No Behavior Churn

After changes, run:

```bash
cargo fmt
cargo test --test root_facade_boundary_guard
```

If the optional ledger guard is added:

```bash
cargo test --test root_module_ledger_guard
```

Then run a cheap package check:

```bash
cargo check -p synvoid
```

If time allows, also run:

```bash
cargo check -p synvoid-http3
cargo check -p synvoid-http
cargo check -p synvoid-waf
cargo check -p synvoid-mesh --features mesh
```

Do not require the known-broken `cargo check --no-default-features` path to pass in this polish pass unless the pre-existing `stop_mesh_generation_support` issue has already been fixed independently.

## Acceptance Criteria

The pass is complete when:

- `src/lib.rs` no longer labels split-required modules as if they are all permanent root-owned runtime modules.
- `architecture/root_module_ledger.md` distinguishes pure facades from facade-plus-local-adapter modules.
- `src/static_files` and any other mixed facade directories no longer carry over-strict or misleading facade guidance.
- `tests/root_facade_boundary_guard.rs` remains passing.
- No public API or runtime behavior changed.
- Any optional ledger consistency guard either passes or is intentionally deferred.

## Expected Files To Touch

Likely:

```text
src/lib.rs
architecture/root_module_ledger.md
tests/root_facade_boundary_guard.rs
src/static_files/AGENTS.override.md
src/static_files/mod.rs
```

Possibly:

```text
src/http3/AGENTS.override.md
src/http3/mod.rs
src/proxy/mod.rs
src/metrics/mod.rs
tests/root_module_ledger_guard.rs
```

Avoid touching large implementation modules unless a top-of-file comment is demonstrably misleading.

## Next Phase After This Polish

After this polish pass, proceed to the next roadmap handoff: unified worker composition-root decomposition. That next phase should extract startup planning, supervision loop ownership, shutdown execution, and supervisor notification mapping out of `run_unified_server_worker()` without changing runtime semantics.
