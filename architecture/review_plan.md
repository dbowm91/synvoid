# Architecture Review Plan

**Status**: COMPLETED - Review complete (2026-05-23)
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

---

## Implementation Summary (2026-05-23)

### Wave 1: Core/Config-Admin

**Completed:**

1. **Module Index Completion** (`architecture/overview.md:332-383`)
   - Added missing modules: `src/bin/`, `src/captcha/`, `src/common/`, `src/drain/`, `src/honeypot_unified/`, `src/integrity/`, `src/mime/`, `src/protocol/`, `src/streaming/`, `src/theme/`, `src/upload/`, `src/worker_pool/`
   - Added MeshProxy to Mesh Networking table

2. **CSRF Constant-Time Fix** (`src/admin/state.rs:736`)
   - Changed `valid_token.session_id_hash == session_hash` to `bool::from(valid_token.session_id_hash.as_bytes().ct_eq(session_hash.as_bytes()))`
   - Now uses `subtle::ConstantTimeEq` for timing-safe comparison

### Wave 2: Plugin

**Completed:**

1. **Spin Routing Documentation** (`architecture/plugin_deep_dive.md:102`)
   - Updated from "Spin routing NOT implemented" to "Spin routing uses longest-prefix-match"
   - Added reference to `src/spin/runtime.rs:273-291` for implementation

2. **Warmup Stub Clarification** (`architecture/plugin_deep_dive.md:70`)
   - Clarified that warmup creates instances with stub implementations
   - Real host functions linked on first actual request

3. **body_receiver Reset** (`architecture/plugin_deep_dive.md:69`)
   - Added `body_receiver` to the list of fields reset by `prepare_for_request()`

### Wave 3: WAF/Platform

**Completed:**

1. **Rate Limiting Architecture** (`architecture/waf_deep_dive.md:9-14`)
   - Added FloodProtector, SYN flood protection, Per-IP connection limiting
   - Documented TokenBucket rate limiting with IPC-4 fix reference
   - eBPF availability (Linux-only with `flood-ebpf` feature)

2. **Bot Detection Updates** (`architecture/waf_deep_dive.md:31-37`)
   - Added CSS honeypot implementation details (`src/challenge/css.rs`)
   - Added JS challenge reference (`src/challenge/js.rs`)

3. **JWT Validation Clarification** (`architecture/waf_deep_dive.md:28`)
   - Changed "JWT & XXE Detection" to "JWT Validation" (jwt.rs is not attack detector)
   - Added XXE Detection as separate item

4. **Performance Section Updates** (`architecture/waf_deep_dive.md:54-59`)
   - Removed Aho-Corasick claim (not actually used)
   - Added Streaming WAF via `StreamingWafCore`
   - Added BufferPool/PooledBuf zero-copy details

5. **CPU Pinning Fix** (`architecture/process_lifecycle.md:47`)
   - Changed from "automatically pinned" to "can be pinned via explicit cpu_affinity parameter"
   - Not supported on macOS/BSD

6. **SO_REUSEPORT Clarification** (`architecture/process_lifecycle.md:46`)
   - Used during upgrades (via upgrade mode), not for initial workers
   - Reference to `src/overseer/upgrade.rs:748`

7. **macOS Seatbelt Fix** (`architecture/platform_deep_dive.md:62`)
   - Changed from "requires macos-sandbox feature" to "planned feature, not yet implemented"

### Verification

All changes compile correctly:
- `cargo check -p synvoid-config --no-default-features --features mesh` ✅
- `cargo fmt` applied
- Code changes verified for correctness

### Remaining Items (Not Actioned)

These items were reviewed but not actioned due to scope constraints:
- DNS AXFR missing record types (BUG-2 in dns_review_plan.md) - requires code change
- Platform process hierarchy diagram updates - lower priority
- Additional docs items from other review plans