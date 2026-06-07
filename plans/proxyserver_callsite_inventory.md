# ProxyServer Callsite Inventory

> Generated: 2026-06-06
> Purpose: Record the remaining `ProxyServer` call sites after the proxy extraction pass and identify whether any root call sites still need migration.

## Legend

- `SWITCH_TO_SYNVOID_PROXY`: replace a root implementation with the extracted `synvoid-proxy` path
- `KEEP_ROOT_REEXPORT_PATH`: root compatibility shim is acceptable; no further change needed
- `NEEDS_ADAPTER`: root call site still needs a small adapter to match the extracted API
- `TEST_ONLY_UPDATE`: only test fixtures need an update
- `UNKNOWN_INVESTIGATE`: not enough information yet

## Inventory

| File | Current ProxyServer path | Constructor used | Has `Arc<WafCore>`? | Migration action | Notes |
|---|---|---|---|---|---|
| `src/proxy/mod.rs` | `crate::proxy::ProxyServer` is a type alias to `synvoid_proxy::ProxyServer<RootWafProcessor>` | N/A | No | `KEEP_ROOT_REEXPORT_PATH` | Compatibility shim only; no live root implementation remains here. |
| `src/tls/server.rs:1706` | `crate::proxy::ProxyServer` via the root alias | `new_with_tls(...).with_cache(...).with_http2(...)` | No direct `Arc<WafCore>` argument; a `RootWafProcessor` adapter is constructed from root WAF state first | `KEEP_ROOT_REEXPORT_PATH` | Already using the extracted proxy implementation through the root compatibility alias. |

## Notes

- No additional `ProxyServer` implementation sites were found in `src`, `crates`, `tests`, or `examples`.
- The extracted proxy crate is already the canonical implementation path.
