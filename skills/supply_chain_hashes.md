# Supply Chain Security: pip install --require-hashes

## Problem (FIXED 2026-05-22)

The Granian app server was installing Python packages without hash verification:

```rust
// OLD CODE
Command::new(python_binary)
    .args(["-m", "pip", "install", "granian"])
```

This is a supply chain risk - malicious packages could be installed via typosquatting or man-in-the-middle attacks.

## Solution Implemented

The `require_hashes` field was already present in `AppServerConfig` but was missing from `GranianConfig`, so the `--require-hashes` flag was never passed to pip. Fixed by adding the field to all config layers.

### Configuration Flow

```
SiteAppServerConfig (site/app_server.rs) - has require_hashes: Option<bool>
    ↓ app_server_config() conversion
AppServerConfig (app_server.rs) - has require_hashes: bool
    ↓ From<&AppServerConfig> conversion
GranianConfig (granian.rs) - has require_hashes: bool  ← WAS MISSING
```

### Files Modified

- `crates/synvoid-config/src/site/app_server.rs` — Added `require_hashes: Option<bool>` to `SiteAppServerConfig`
- `crates/synvoid-config/src/site/mod.rs` — Added `require_hashes` field mapping in `app_server_config()`
- `src/app_server/mod.rs` — Already had `require_hashes: bool`
- `src/app_server/granian.rs` — Added `require_hashes: bool` to `GranianConfig` and `From<&AppServerConfig>` impl

### Usage in granian.rs

```rust
let mut args = vec!["-m".to_string(), "pip".to_string(), "install".to_string()];
if self.config.require_hashes {
    args.push("--require-hashes".to_string());
}
args.push("granian".to_string());

let install_output = Command::new(python_binary)
    .args(&args)
    .output()
    .await
    .map_err(|e| format!("Failed to run pip install: {}", e))?;
```

Same pattern applied to `ensure_requirements_installed()`.

## Configuration

In TOML:
```toml
[app_server]
require_hashes = true
```

Or in code:
```rust
let config = AppServerConfig {
    require_hashes: true,
    ..Default::default()
};
```

## Security Notes

- When `require_hashes = true`, pip will refuse to install packages without matching hashes from the requirements file
- This protects against supply chain attacks but requires maintaining a `requirements.txt` with hashes
- Generate hashes with: `pip hash -r package-name`

## Related

See `security_patterns.md` for more supply chain security patterns.