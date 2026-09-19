# Sandboxing Guide (Phase 46 truthfulness)

SynVoid uses OS-level sandboxing to limit the damage potential of a compromised process. The sandbox restricts what resources (files, network, process creation) a compromised worker/jail process can access.

**Linux is the production recommendation for strict jail isolation.** Other backends are experimental/limited (see support tiers). `SandboxCapabilities::process_limits` means numeric resource bounds (memory/process-count, Job-Objects style), not generic syscall filtering.

## Support tiers

| Platform | Backend | Min requirement | Tier | Native evidence |
|----------|---------|-----------------|------|-----------------|
| Linux | Landlock | Kernel 5.13+ **and** Landlock syscall ABI (probed, not version-text only) | **Supported** | Linux CI (`cargo test -p synvoid-platform`) |
| FreeBSD | Capsicum (capability mode) | FreeBSD 10+ with capsicum(4) | **Experimental** | No OS matrix in CI; `is_supported` probes `cap_getmode` syscall presence |
| OpenBSD | Pledge + Unveil | OpenBSD 5.9+ | **Experimental** | No OS matrix in CI |
| macOS | Seatbelt via deprecated `sandbox_init` | macOS 10.10+, `macos-sandbox` feature **and** runtime `sandbox_init` symbol | **Experimental** (opt-in) | Native child-process tests on macOS host (`sandbox_macos_enforcement`, requires `--features macos-sandbox`); cross-compile alone is not evidence |
| Windows | Job Objects + DEP/ASLR | Windows Vista+ | **Limited** (process limits only) | No OS matrix in CI |
| Other | Stub | — | **Unavailable** | Strict fails closed |

`Platform::supports_sandbox()` is a coarse gate reporting only Linux/musl + FreeBSD + OpenBSD. macOS/Windows availability is per-backend `is_supported()` (Seatbelt: feature + `dlsym` probe; Windows Job Objects: always on Windows). "Compiled with feature" is not "runtime backend available": Strict fails closed when the runtime is absent.

## Sandbox levels

| Level | Description |
|-------|-------------|
| `Off` | No sandboxing applied |
| `Basic` | Minimal restrictions (see per-backend semantics below) |
| `Strict` | Full restrictions via read-path allowlist; requires a backend with `read_path_allowlist`. Otherwise `ProcessSandbox::with_paths` returns `InsufficientCapabilities` (fail closed). Jail children always use `Strict`. |

### Basic semantics (Phase 46)

- **Landlock**: filesystem allowlists enforced (same primitive as Strict); no network/process/child limits (Landlock provides none).
- **Capsicum**: enter capability mode (global-namespace restriction); no path allowlists.
- **Pledge**: unveil allowlists + `pledge("stdio")` syscall restriction.
- **Seatbelt**: `(allow default)` permissive policy with explicit denies for `no_access_paths`; read/write lists emitted as explicit allows for documentation. Claims **no** network/child/process limits in Basic (level-dependent capabilities).
- **Windows**: Job-Object memory limits (256 MB process / 512 MB job, kill-on-close) only; no filesystem/network/child allowlists.

### Strict semantics (Phase 46, jail policy)

- **Landlock**: read/write allowlists enforced; `denied_paths` are logged, not enforced (`deny_paths: false`); no network/process/child limits.
- **Pledge**: unveil `r` / `rwc` allowlists + empty-perm denies + `pledge("stdio")` (denies inet/proc/exec).
- **Seatbelt**: `(deny default)` + `(allow process*)` + `(allow signal)` + explicit file allows + explicit denies + explicit `(deny network*)`; **no** `(allow job-creation)` so child creation stays denied. No numeric resource limits (`process_limits: false`). `(allow process*)` is retained as the minimal lifecycle primitive pending native minimization — do not narrow further without proving the jail still runs. The old Basic profile's contradictory `(allow default)` + `(deny default)` pair is removed; the old `(allow process)` (bare, no wildcard) was an unbound variable caught by native `sandbox_init` failure and is now `(allow process*)`.
- **Capsicum / Windows**: cannot enforce Strict (no read allowlist) — Strict fails closed by design. Capsicum Basic gives capability mode; Windows Basic gives Job-Object limits.

## Backend capabilities (truthful)

### Linux (Landlock)

Landlock provides filesystem path sandboxing by creating a ruleset of allowed file access patterns. Availability = kernel ≥5.13 **and** a live `landlock_create_ruleset` probe (a version-gated kernel may still lack the LSM).

**Capabilities:**
- Read path allowlist: Yes
- Write path allowlist: Yes
- Deny paths: No (no-access paths are logged, not enforced)
- Process limits: No
- Network restrictions: No
- Child process restrictions: No

### FreeBSD (Capsicum)

Capsicum provides capability-mode sandboxing at the syscall level. FD-based: no path allowlists. `is_supported` probes `cap_getmode` syscall presence (not "already in capability mode" — the old `mode != 0` check was backwards). `cap_enter()` permanently enters capability mode.

**Capabilities:**
- Read path allowlist: No (capsicum is FD-based)
- Write path allowlist: No
- Deny paths: No
- Process limits: No (capability confinement is not a numeric memory/CPU limit)
- Network restrictions: Yes (capability-mode global-namespace restriction)
- Child process restrictions: Yes (children inherit capability mode)

Strict requires a read allowlist, so Strict on Capsicum always fails closed.

### OpenBSD (Pledge/Unveil)

OpenBSD uses `pledge(2)` for syscall restrictions and `unveil(2)` for filesystem path restrictions (`r` / `rwc` / empty-perm deny).

**Capabilities:**
- Read path allowlist: Yes
- Write path allowlist: Yes
- Deny paths: Yes
- Process limits: No (syscall filtering is not a numeric limit)
- Network restrictions: Yes (`pledge("stdio")` denies inet)
- Child process restrictions: Yes (`pledge("stdio")` denies proc/exec)

### macOS (Seatbelt) — experimental, deprecated API

Seatbelt here is the CLI/jail `sandbox_init` interface, which Apple has deprecated. It is **not** Apple App Sandbox (entitlements/signed bundles). For a CLI daemon/jail helper, moving to App Sandbox would be an architectural/distribution change, not a drop-in API migration. Long-term options: (1) retain deprecated Seatbelt as opt-in experimental hardening with native tests; (2) ship signed sandboxed helpers with entitlements if distribution supports it; (3) keep Linux as the strict-isolation production recommendation with macOS as development/experimental. Current choice: (1) + (3).

Requires the `macos-sandbox` Cargo feature **and** a runtime `sandbox_init` symbol (probed via `dlsym`). Without both, all capabilities are false and Strict fails closed. FFI passes a real error buffer, converts via `sandbox_free_error` (errno fallback only when the API provides no message).

SBPL path safety: paths are canonicalized when possible (symlink-resolved; falls back to the original when missing) and escaped as double-quoted literals (backslash/quote escaped; controls and non-UTF-8 rejected). Never interpolates `Path::display()` directly. A `)` inside a quoted literal cannot gain an extra expression.

**Capabilities when `macos-sandbox` enabled (level-dependent):**

Strict:
- Read path allowlist: Yes
- Write path allowlist: Yes
- Deny paths: Yes
- Process limits: No (SBPL sets no numeric bounds)
- Network restrictions: Yes (explicit `deny network*` + deny default)
- Child process restrictions: Yes (no `job-creation` allow; creation denied by default)

Basic: read/write/deny Yes; process/network/child No (allow-default permissive).

**Without `macos-sandbox` feature:** All capabilities are false; sandboxing is not enforced; Strict fails closed.

### Windows (Job Objects) — limited

Windows "sandboxing" is process-level resource limiting via Job Objects (256 MB process / 512 MB job, kill-on-close) plus DEP/ASLR mitigations in Strict. Per-file DACL manipulation on listed paths is hardening, **not** a filesystem allowlist: there is no deny-by-default for the rest of the filesystem, no network restriction, and no child-process restriction (active-process limit is 0 = unlimited).

**Capabilities (all levels):**
- Read path allowlist: No
- Write path allowlist: No
- Deny paths: No
- Process limits: Yes
- Network restrictions: No
- Child process restrictions: No

Strict requires a read allowlist, so Strict on Windows always fails closed. Jail `Required` isolation on Windows fails closed unless the test-only `SYNVOID_JAIL_PERMIT_NO_SANDBOX=1` hatch is set (production spawn paths never set it).

## Configuration

```toml
[worker]
sandbox_level = "strict"  # off, basic, or strict
sandbox_read_paths = ["/var/lib/synvoid", "/etc/synvoid"]
sandbox_write_paths = ["/var/lib/synvoid", "/var/log/synvoid"]
sandbox_no_access_paths = ["/etc/passwd", "/etc/shadow"]
```

## Usage Example

```rust
use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

let paths = SandboxPaths::new()
    .add_read_path("/var/lib/synvoid")
    .add_write_path("/var/log/synvoid");

let sandbox = ProcessSandbox::with_paths(SandboxLevel::Strict, paths)?;
```

## Security Notes

- A strict sandbox requires a backend with `read_path_allowlist` capability
- If the backend cannot enforce strict mode, `ProcessSandbox::with_paths()` returns `SandboxError::InsufficientCapabilities`
- Path allowlists use directory inheritance (subpath access is granted if parent is allowed)
- On Linux, denied paths are logged but cannot be fully blocked with Landlock
- On macOS, canonicalize temp paths (`/var` → `/private/var`) before comparing allowlists in tests; the backend canonicalizes automatically
- Never claim Apple App Sandbox equivalence for the `sandbox_init` backend
