# Architecture Review Plan

**Status**: PENDING - Review to begin (2026-05-23)
**Created**: 2026-05-23

This plan coordinates a comprehensive review of SynVoid architecture documentation, verifying claims against code and identifying improvements.

## Modules and Assignments

| Module | Documents | Subagent |
|--------|-----------|----------|
| **Core/Overview** | `overview.md`, `deep_dive_review.md` | subagent-1 |
| **HTTP/Proxy** | `proxy_deep_dive.md`, `routing_deep_dive.md`, `app_handlers.md`, `layer_3_5_deep_dive.md` | subagent-2 |
| **DNS** | `dns_deep_dive.md` | subagent-3 |
| **Mesh/Networking** | `mesh_deep_dive.md`, `networking_deep_dive.md` | subagent-4 |
| **Platform** | `platform_deep_dive.md`, `process_lifecycle.md`, `worker_architecture.md` | subagent-5 |
| **Config/Admin** | `config_deep_dive.md`, `admin_deep_dive.md` | subagent-6 |
| **WAF** | `waf_deep_dive.md` | subagent-7 |
| **Plugin** | `plugin_deep_dive.md` | subagent-8 |

## Review Workflow

Each subagent will:
1. Read all documents assigned to their module
2. Verify architectural claims against actual code implementation
3. Cross-reference with AGENTS.md for known corrections
4. Identify discrepancies, bugs, or improvement opportunities
5. Write a detailed improvement plan to `plans/<module>_review_plan.md`

## Output Files

Each subagent writes to `plans/<module>_review_plan.md`:
- `plans/core_overview_review_plan.md`
- `plans/http_proxy_review_plan.md`
- `plans/dns_review_plan.md`
- `plans/mesh_networking_review_plan.md`
- `plans/platform_review_plan.md`
- `plans/config_admin_review_plan.md`
- `plans/waf_review_plan.md`
- `plans/plugin_review_plan.md`

## Verification Commands

```bash
cargo test --lib --no-run    # Verify tests compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo fmt && cargo clippy --lib -- -D warnings
```

## Key Reference Documents

- `AGENTS.md` - Known file path corrections and architectural notes
- `src/mesh/AGENTS.override.md` - Mesh subsystem guidance
- `src/dns/AGENTS.override.md` - DNS subsystem guidance
- `src/waf/AGENTS.override.md` - WAF subsystem guidance
- `src/http/AGENTS.override.md` - HTTP server guidance
- `src/http_client/AGENTS.override.md` - HTTP client guidance
- `src/proxy/AGENTS.override.md` - Proxy routing guidance
- `src/config/AGENTS.override.md` - Config subsystem guidance
- `src/admin/AGENTS.override.md` - Admin API guidance
- `src/auth/AGENTS.override.md` - Auth subsystem guidance
- `src/platform/AGENTS.override.md` - Platform abstraction guidance