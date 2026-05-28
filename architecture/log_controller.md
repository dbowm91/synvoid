# Log Controller Architecture

## 1. Purpose and Responsibility

The Log Controller module (`src/log_controller.rs`) provides **runtime-adjustable log level management** using tracing-subscriber with env filter support. Allows changing log verbosity without restart.

**Core Responsibilities:**
- Dynamic log level changes at runtime
- Log level validation (trace/debug/info/warn/error)
- Global log level state management
- Integration with admin API for runtime control

---

## 2. Key Data Structures

```rust
static LOG_LEVEL: LazyLock<RwLock<String>> = LazyLock::new(|| {
    RwLock::new("info".to_string())
});
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `init_logging_with_dynamic_level(level)` | Initialize tracing with env filter |
| `get_log_level() -> String` | Current log level |
| `set_log_level(level) -> Result<String, String>` | Validate and set level |

---

## 4. Integration Points

- **Admin API**: Runtime log level changes via REST endpoint
- **Tracing**: Uses tracing-subscriber EnvFilter for filtering
- **Supervisor**: Initialized at process startup

---

## 5. Key Implementation Details

- **Global State**: Single `RwLock<String>` for thread-safe access
- **Validation**: Only accepts valid tracing levels
- **Non-blocking**: Reads are lock-free via `RwLock` read access
- **Atomic Updates**: Level changes take effect immediately for new log events
