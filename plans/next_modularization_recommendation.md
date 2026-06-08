# Next Modularization Recommendation

## Validation status after workspace-green pass

- Root yara-x removed: YES (moved to `crates/synvoid-upload`)
- Mesh feature now compiles: YES (fixed in SDC-A02)
- Workspace all-targets: **PASSED** — all 4 prior issues resolved in prior work.
- Dead upload duplicates removed: YES (duplicate yara rules, crypto, scanner types consolidated)
- Upload import directness: IMPROVED — 5 files updated to use `synvoid_upload::` directly.
- HTTP/3 object-safety: INVESTIGATED — `Http3RequestWaf` is already object-safe; Strategy A (`Arc<dyn Http3RequestWaf>`) is trivially applicable.

## Workspace-green results summary

All profile checks pass cleanly. `cargo check --workspace --all-targets` passes (warnings only). `cargo test --workspace --no-run` compiles successfully. The four prior failures (myapp-dynamic E0507, synvoid-ipc sha2, admin-ui errors, synvoid-mesh test errors) were all resolved before this pass.

## HTTP/3 readiness

`Http3RequestWaf` at `crates/synvoid-http/src/http3_request_dispatch.rs:28` is fully object-safe:
- Both methods use `#[async_trait]` or plain signatures
- No generic methods, no `Self` returns, no associated types, no `Sized` bounds
- Strategy A (swap `Arc<WafCore>` to `Arc<dyn Http3RequestWaf>`) is trivially applicable when ready

## Next recommended technical pass

1. **HTTP/3 server decoupling** — Strategy A is trivially applicable (single field swap in `src/http3/server.rs`). Can proceed when HTTP/3 editing becomes active.
2. **server-runtime context design** — The per-request context threading pattern could be consolidated.
3. **admin/schema ownership cleanup** — Admin OpenAPI surface sits on root; schema ownership decisions depend on `plans/admin_schema_ownership.md` (MDM-A01).
