# Supply Chain Security: pip install --require-hashes

## Problem

The Granian app server was installing Python packages without hash verification:

```rust
// OLD CODE
Command::new(python_binary)
    .args(["-m", "pip", "install", "granian"])
```

This is a supply chain risk - malicious packages could be installed via typosquatting or man-in-the-middle attacks.

## Solution

Add `require_hashes` config option and pass `--require-hashes` to pip:

```rust
// AppServerConfig (src/app_server/mod.rs)
pub struct AppServerConfig {
    // ... existing fields ...
    pub require_hashes: bool,  // NEW
}

// Default value is false for backward compatibility
impl Default for AppServerConfig {
    fn default() -> Self {
        Self {
            // ...
            require_hashes: false,
        }
    }
}
```

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

## Files Modified

- `crates/synvoid-config/src/app_server.rs` — Added `require_hashes` field
- `src/app_server/mod.rs` — Added `require_hashes` field  
- `src/app_server/granian.rs` — Pass `--require-hashes` when enabled

## Security Notes

- When `require_hashes = true`, pip will refuse to install packages without matching hashes from the requirements file
- This protects against supply chain attacks but requires maintaining a `requirements.txt` with hashes
- Generate hashes with: `pip hash -r package-name`

## Related

See `security_patterns.md` for more supply chain security patterns.