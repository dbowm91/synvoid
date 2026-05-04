# Worker Module - AGENTS.override.md

## ExtensionRuntime Pattern

Worker lifecycle extensions (Mesh, DNS, Serverless, Honeypot) are managed via `ExtensionRuntime` trait and `ExtensionRegistry`.

See `skills/extension_runtime.md` for full documentation.

### Key Types

- `ExtensionRuntime` trait in `src/worker/extension.rs`
- `ExtensionRegistry` - manages lifecycle and health
- `ExtensionFailurePolicy` - FailClosed or FailOpen
- `RequestServices` - dependency injection context in `src/worker/context.rs`

### Global Singleton Deprecation

Global singletons (`get_threat_intel()`, `get_yara_rules()`, `get_upload_validator()`) are deprecated. Use `RequestServices` instead:

```rust
// Old (deprecated)
let threat_intel = get_threat_intel().cloned();

// New
let threat_intel = request_services.threat_intel.clone();
```