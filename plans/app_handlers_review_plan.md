# App Handlers Review Plan

## Objective
Review `architecture/app_handlers.md` for accuracy against current implementation, addressing identified stale items and bugs.

## Bugs to Fix

### BUG-1: Non-existent WasmHandler
- **Location**: `architecture/app_handlers.md:58`
- **Issue**: Document refers to `WasmHandler` which does not exist. The actual implementation is `SpinHttpHandler`.
- **Action**: Replace `WasmHandler` reference with correct `SpinHttpHandler`.

### BUG-2: FastCGI Streaming Claim Contradicts Known Limitation
- **Location**: `architecture/app_handlers.md` (FastCGI section)
- **Issue**: Document claims "Response Streaming" but APP-15 documents this as a known limitation — FastCGI buffers the entire response body.
- **Action**: Remove or correct streaming claim; add note explaining buffering behavior.

## Stale Items to Address

| # | Handler | Issue | Action |
|---|---------|-------|--------|
| 1 | **Static File Handler** | "Built-in Minification" description is misleading — minification occurs via IPC to separate `StaticWorker`, not in-process | Clarify that minification is delegated to StaticWorker |
| 2 | **FastCGI** | "Response Streaming" claim is false — APP-15 known limitation, buffers entire body | Remove streaming claim; document buffering behavior |
| 3 | **Generic WASM** | "Instance Pooling" is vague — pooling exists for WAF plugins, NOT Spin runtime | Specify which WASM backends support instance pooling |
| 4 | **Generic WASM** | "Mesh Distribution" unverified — applies to Serverless backend, not generic WASM | Clarify scope: Mesh distribution applies to Serverless, not generic WASM |
| 5 | **WasmHandler** | Actually `SpinHttpHandler` at line 2423 | Already covered by BUG-1 |

## Files to Audit
- `architecture/app_handlers.md` — primary document
- Cross-reference with `src/mesh/AGENTS.override.md` for WASM/Spin accuracy
- Cross-reference with `src/fastcgi/mod.rs` for streaming limitation details

## Verification Commands
```bash
cargo test --lib --no-run    # Verify no compilation issues
```

## Completion Criteria
- [ ] BUG-1 fixed: `WasmHandler` → `SpinHttpHandler`
- [ ] BUG-2 fixed: FastCGI streaming claim corrected
- [ ] All 5 stale items addressed with accurate descriptions
- [ ] Document reflects actual architecture (StaticWorker delegation, WAF plugin pooling, Serverless Mesh distribution)
