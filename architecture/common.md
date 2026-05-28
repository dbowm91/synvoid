# Common Utilities Architecture

## 1. Purpose and Responsibility

The Common module (`src/common/`) provides **shared panic handler utilities** that write structured panic logs to file and stderr. A small utility module used at process startup.

**Core Responsibilities:**
- Structured panic logging
- File-based panic log output
- Panic hook installation
- Process identification in logs

---

## 2. Public API

| Method | Description |
|--------|-------------|
| `setup_panic_handler(process_name, log_file)` | Install panic hook with file output |
| `setup_default_panic_handler()` | Convenience wrapper for "synvoid" |

---

## 3. Integration Points

- **Main**: Called at process startup
- **Supervisor**: Panic logging for control plane
- **Worker**: Panic logging for data plane

---

## 4. Key Implementation Details

- **File Permissions**: Panic logs set to `0o600`
- **Structured Output**: Includes location, message, and process name
- **Dual Output**: Writes to both file and stderr
- **Thread-safe**: Panic hooks are process-global
