# Platform Support

SynVoid is designed for consistent performance across modern operating systems, with a default unified-worker data plane and optional advanced multi-worker features.

## Support Matrix

| Platform | Support Level | Notes |
|----------|--------------|-------|
| Linux (glibc) | Primary | Full socket/affinity support. Routinely verified in CI. |
| Alpine Linux (musl) | Primary | Full feature support. CI runs ubuntu-latest only — musl coverage is aspirational; verify locally before claiming. |
| macOS | Best effort | Full socket feature support. Manually verified. |
| Windows (10+) | Best effort | Modern socket feature support. Manually verified. |
| FreeBSD | Best effort | Full feature support. Manually verified. |

## Sandbox Support (not platform-equivalent)

Sandbox strength is **not** the same on every platform. Never read a checkmark
in this table as "the worker is confined":

| Platform | Mechanism | Tier |
|----------|-----------|------|
| Linux | Landlock + seccomp categorical filter | Production strict-isolation target |
| macOS | Deprecated `sandbox_init` SBPL profiles | Experimental. This is **not** Apple App Sandbox, and it is deprecated by the OS. |
| Windows | Job-object process limits only | No DACL mutation, no AppContainer |
| Capsicum | Path vectors only | Fails closed; `unveil` stays locked |

New sandbox code goes through the guarantee contract
(`SandboxRequest` → `prepare_sandbox` → `enter` → `EnteredSandbox`), never
`can_enforce_strict()`. `IsolationPolicy::Required` fails closed. See
[SANDBOXING.md](./SANDBOXING.md) for the binding support tiers.

## Feature Availability by Platform

### Data-Plane Runtime Features

| Feature | Linux | macOS | FreeBSD | Windows |
|---------|-------|-------|---------|---------|
| `SO_REUSEPORT` | ✅ | ✅ | ✅ | ✅ |
| CPU Core Pinning (`sched_setaffinity`) | ✅ (native) | ❌ | ❌ | ❌ |
| Advanced multi-unified-worker mode (`SO_REUSEPORT`) | ✅ | ✅ | ✅ | ✅ |

CPU pinning is Linux-only: `apply_cpu_affinity` compiles the `sched_setaffinity`
call under `#[cfg(target_os = "linux")]` and merely logs "not supported on this
Unix platform" on other Unix targets. FreeBSD/macOS/Windows all get OS-scheduler
worker distribution.

### Control Plane (gRPC)

| Feature | Linux | macOS | FreeBSD | Windows |
|---------|-------|-------|---------|---------|
| gRPC API (plaintext, loopback default) | ✅ | ✅ | ✅ | ✅ |
| gRPC API over TLS | ✅ | ✅ | ✅ | ✅ |
| gRPC mutual TLS (client cert required) | ❌ | ❌ | ❌ | ❌ |
| Raft Consensus | ✅ | ✅ | ✅ | ✅ |
| Mesh (QUIC) | ✅ | ✅ | ✅ | ✅ |

The control plane binds `127.0.0.1:50051` by default and is **plaintext unless
TLS is configured**. `src/supervisor/api.rs` builds `ServerTlsConfig::new()
.identity(...)` from `cert_path`/`key_path` only — it never requests client
certificates, so the API is server-authenticated TLS, not mTLS. Enable it with
`[supervisor] control_api_tls` (cert + key required).

## Platform-Specific Details

### Linux (glibc/musl)

Linux is the premier platform for SynVoid, offering the most granular performance controls.

**Features:**
- **Deterministic Core Pinning:** Uses `sched_setaffinity` to bind workers to physical CPU cores, eliminating jitter. Linux only.
- **Advanced Sandboxing:** Workers are strictly confined using Landlock + seccomp when an isolation policy is requested. See the sandbox table above for the other platforms.
- **I/O:** Tokio's epoll-based reactor. SynVoid does **not** use `io_uring` — there is no io_uring dependency or code path in the workspace.

### Windows (10, 11, Server 2019+)

Modern Windows versions support socket semantics required for SynVoid's advanced multi-unified-worker mode.

**Differences:**
- **IPC:** Uses Named Pipes (`\\.\pipe\synvoid-*`) instead of Unix Domain Sockets.
- **Sandbox:** Process-limits-only (Job objects). No DACL mutation, no AppContainer.
- **Service Management:** Recommended to run as a Windows Service (`sc.exe`).
- **CPU Pinning:** Uses the OS scheduler for worker distribution; affinity is not applied.

### macOS & BSD

Full support for the default unified-worker model, with advanced `SO_REUSEPORT` mode available.

**Notes:**
- **macOS:** `SO_REUSEPORT` is available for advanced multi-unified-worker deployments. Sandboxing is the experimental, deprecated `sandbox_init` SBPL path — **not** Apple App Sandbox.
- **FreeBSD:** `SO_REUSEPORT` is used through the shared socket-bind helpers (`synvoid-platform::socket_bind`). There is no separate `SO_REUSEPORT_LB` code path; do not claim kernel load-balancing semantics.

## Upgrades

Upgrades are **not** zero-downtime automatically. `[upgrade]` configuration
fields (`health_check_path`, `validation_retries`, `drain_timeout_secs`,
`staged_dir`, …) describe an upgrade contract, but the supervisor contains no
staged-upgrade orchestrator: `src/supervisor/` has no upgrade task and the CLI
has no `--upgrade` flag. `UPGRADE.md` is the honest procedure — stop, replace the
binary, start. For genuinely uninterrupted service, run two instances behind a
load balancer and switch traffic yourself.

## Cargo Feature Flags

Neither row below is a cargo feature. There is no `landlock` feature (the
`landlock` crate is an unconditional Linux dependency of `synvoid-platform`) and
no `grpc-tls` feature exists anywhere in the workspace. The real default feature
set is `socket-handoff`, `mesh`, `dns`, `erased_pool`, `swagger-ui`.

| Knob | Default | Effect |
|------|---------|--------|
| `[supervisor] control_api_tls` | unset | TLS on the gRPC control plane. Unset means plaintext on `127.0.0.1:50051`. |
| `[supervisor] control_api_addr` | `127.0.0.1:50051` | Control-plane bind address. |

## Performance Considerations

### Linux
- Tune `tokio.worker_threads` and `tcp.worker_pool_size` first; increase CPU offload worker count for heavy transforms.
- Landlock and CPU affinity do not announce themselves in `dmesg`. Check the SynVoid log instead: successful pinning logs `Unified Server Worker <id> pinned to CPU core <n>`, and a `CpuSet`/affinity failure logs a warning.

### Windows
- Use Windows Server 2019 or later for optimal socket performance.
- Named pipe latency is slightly higher than Unix sockets; adjust IPC timeouts if needed.

### ICMP Enforcement Lanes (Phase 86 truthfulness tiers)

Root `icmp-filter` forwards no backend sub-features; enable lanes per-crate explicitly.

| Lane | Platform | Crate feature | Tier | Notes |
|------|----------|---------------|------|-------|
| nftables | Linux | `icmp-filter` | supported | Baseline; atomic destroy+add batch; global rate limit; native-qualified 8/8 x2 runs on Ubuntu 24.04 nftables 1.0.9 (Phase 95 proof `36335520434` on `39bfced2`) |
| eBPF (XDP/TC) | Linux | `icmp-ebpf` | experimental | Needs BTF + `CAP_BPF`/root (load) + `CAP_NET_ADMIN`/root (attach) |
| PF | macOS | `icmp-pf` | experimental | Staged anchor reload, not transactional |
| PF | FreeBSD / OpenBSD | `icmp-pf` | experimental | Qualified separately per variant |
| WFP (primary) | Windows | `icmp-wfp` | compile-only | Typed ICMP conditions + transactions; no rate limiting |
| Windows Firewall COM (fallback) | Windows | `icmp-winfw` | compile-only | No transactions/rate limit/readback |
| NetBSD | NetBSD | — | unsupported | Native filter is NPF (future backend), not PF |

Tiers: `supported` (native privileged proof) / `experimental` (compiles, best-effort) / `compile-only` (cross-target check only) / `unsupported` (explicit error). Cross-compilation is never runtime qualification. Native proof matrix belongs to Phase 88.

## Testing

Verification is split between routine CI and manual local checks:
- **Routine CI** (Linux x86_64 only): Unit tests, integration tests, architecture guards, security regression, failure injection via `cargo xtask verify`.
- **Manual local** (all platforms): Cross-compilation checks, feature profile compilation, full test suites via `cargo xtask verify-full`.
