# Next Modularization Recommendation

## Validation status after workspace-green pass

- Root yara-x removed: YES (moved to `crates/synvoid-upload`)
- Mesh feature now compiles: YES (fixed in SDC-A02)
- Workspace all-targets: **PASSED** — all 4 prior issues resolved in prior work.
- Dead upload duplicates removed: YES (duplicate yara rules, crypto, scanner types consolidated)
- Upload import migration: **COMPLETE** — all 15 upload call sites use `synvoid_upload::` directly; zero `crate::upload::X` submodule refs remain. Root `src/upload/mod.rs` re-export shim retained for broad caller compatibility. No further action needed for upload imports.
- HTTP/3 object-safety: INVESTIGATED — `Http3RequestWaf` is already object-safe, but Strategy A (`Arc<dyn Http3RequestWaf>`) is **deferred** because `WafAccess` (also used on `self.waf`) has an associated type `StreamingScanner` that kills object-safety. See `plans/hwd_h02_deferred.md`.

## Workspace-green results summary

Full 10-command validation matrix (HWD-F01): **ALL PASS**. Includes `cargo fmt`, all 4 profile checks, 3 per-crate checks (`synvoid-http`, `synvoid-http3`, `synvoid-upload`), `--workspace --all-targets`, and `--workspace --no-run`. Warnings only, no errors. The four prior failures (myapp-dynamic E0507, synvoid-ipc sha2, admin-ui errors, synvoid-mesh test errors) were all resolved before this pass.

## HTTP/3 readiness

`Http3RequestWaf` at `crates/synvoid-http/src/http3_request_dispatch.rs:28` is fully object-safe:
- Both methods use `#[async_trait]` or plain signatures
- No generic methods, no `Self` returns, no associated types, no `Sized` bounds

**However, Strategy A is blocked:** `Http3Server` also calls `WafAccess` methods on `self.waf`, and `WafAccess` has `type StreamingScanner` which is not object-safe. Strategy A is deferred until `WafAccess` is refactored. See `plans/hwd_h02_deferred.md`.

## Next recommended technical pass

1. **HTTP/3 server decoupling** — Strategy A is blocked by `WafAccess` object-safety (not `Http3RequestWaf`). Requires `WafAccess` refactor first. See `plans/hwd_h02_deferred.md`.
2. **server-runtime context design** — The per-request context threading pattern could be consolidated.
3. **admin/schema ownership cleanup** — Admin OpenAPI surface sits on root; schema ownership decisions depend on `plans/admin_schema_ownership.md` (MDM-A01).
