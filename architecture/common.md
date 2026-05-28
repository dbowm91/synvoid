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

- **Supervisor**: Panic logging for control plane (`src/supervisor/process.rs:325`)
- **Worker**: Panic logging for data plane (`src/worker/mod.rs:46`, `src/worker/unified_server.rs:55`)
- **Mesh Agent**: Panic logging for mesh mode (`src/supervisor/mesh.rs:32`)

> **Note:** `setup_panic_handler` is NOT called directly from `main.rs`. It is called indirectly via supervisor and worker initialization routines.

---

## 4. Key Implementation Details

- **File Permissions**: Panic logs set to `0o600`
- **Structured Output**: Includes location, message, and process name
- **Dual Output**: Writes to both file and stderr
- **Thread-safe**: Panic hooks are process-global
