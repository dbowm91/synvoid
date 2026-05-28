# Logging Architecture

## 1. Purpose and Responsibility

The Logging module (`src/logging/`) provides **syslog integration** with configurable facility, level filtering, and platform-specific initialization (Unix syslog, non-Unix tracing fallback).

**Core Responsibilities:**
- Syslog integration for system-level logging
- Configurable facility and level filtering
- Platform-specific initialization
- Fallback to tracing on non-Unix platforms

---

## 2. Key Data Structures

```rust
pub struct SyslogLogger {
    min_level: Level,
    #[cfg(unix)]
    syslog: syslog::Logger<syslog::UnixTransport>,
}

pub struct SyslogConfig {
    pub facility: SyslogFacility,
    pub app_name: String,
    pub pid: bool,
}

pub enum SyslogFacility {
    Daemon,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
    Security,
    Auth,
    User,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `SyslogLogger::new(config, min_level)` | Constructor |
| `log(level, message)` | Log at specified level |
| `emergency()`, `alert()`, `critical()` | High-priority levels |
| `error()`, `warning()`, `notice()` | Medium-priority levels |
| `info()`, `debug()` | Low-priority levels |
| `is_enabled(level) -> bool` | Level filter check |
| `init_syslog(app_name, min_level)` | Quick initialization |
| `init_syslog_with_config(config, min_level)` | Full configuration |

---

## 4. Integration Points

- **Supervisor**: System-level logging for process events
- **Admin API**: Log level changes propagate to syslog
- **Platform**: Unix syslog, non-Unix tracing fallback

---

## 5. Key Implementation Details

- **Platform-specific**: Unix uses native syslog, others use tracing fallback
- **Level Filtering**: Messages below `min_level` are dropped
- **Facility Routing**: Configurable syslog facility for log routing
- **PID Inclusion**: Optional PID in syslog messages
