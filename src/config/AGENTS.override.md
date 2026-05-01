# Config Module - AGENTS.override.md

Specialized guidance for configuration patterns.

## Known File Path Corrections

| Wrong Path | Correct Path |
|------------|--------------|
| `src/mesh/proxy.rs:1485` (edge_only) | `src/mesh/transport.rs:986` + `src/config/site/misc.rs:37` |

## Serialization Standards

1. **Prefer Postcard over JSON** for distributed state
2. **Use Typed Structs** with `Archive`, `RkyvSerialize`, `RkyvDeserialize`, `Serialize`, `Deserialize` — never `serde_json::Value`
3. **Unix Timestamps (u64)** for all persisted/network timestamps
4. **Binary Signatures** operate on `&[u8]`
5. **Base64 Encoding**: Always `URL_SAFE_NO_PAD`