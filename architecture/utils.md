# Utilities (`synvoid-utils`)

## 1. Purpose and Responsibility

`crates/synvoid-utils` hosts small, dependency-light utilities shared by 17+ crates: string interning, buffer pooling, flag primitives, time/IP safety helpers, regex complexity checking, and serialization strategy selection.

## 2. Modules

| Module | Contents |
|--------|----------|
| `arc_str` | `ArcStr` — cheaply cloneable immutable string |
| `buffer` | Sharded-mutex `BufferPool` / `PooledBuf` (`pool.rs`) — ABA-safe replacement for a Treiber stack; tiered buffer sizes to amortize allocation on the proxy/static-file paths |
| `flags` | `RunningFlag`, `DrainFlag` — atomic lifecycle flags shared between supervisor, workers, and tasks |
| `health_state` | `HealthState`, `GlobalHealthState` — Normal/Warning/Critical health classification |
| `ip_utils` | `safe_unix_timestamp`, `current_timestamp`, `now_ms`, `get_first_non_loopback_ip`, `ip_to_slot`, `is_newer_version`, `safe_unix_duration` — saturating, overflow-safe timestamp/IP math |
| `regex_utils` | `check_regex_complexity` — ReDoS screening used before compiling user-supplied regexes (location matching, WAF rules) |
| `serialization` | Serialization strategy selection (postcard/rkyv/JSON) per path |
| `time_utils` | `parse_duration` — human-friendly duration parsing |
| `worker_id` | Thread-local/current worker identity (`CURRENT_WORKER_ID`) |

## 3. Conventions Enforced Here

- **Unix timestamps are u64** and must be produced by `safe_unix_timestamp`/`current_timestamp` (or `synvoid_core::time`); duration math uses `.saturating_sub()`.
- **Buffer pooling**: request-path code should prefer `PooledBuf` over fresh allocations for large body/response buffering.
- **Regex safety**: any user-supplied regex passes complexity checks before compilation.

## 4. Consumers

Root app plus 17 crates including `synvoid-http`, `synvoid-proxy`, `synvoid-block-store`, `synvoid-mesh`. The root re-exports `serialization` at `synvoid_utils::serialization`.

## 5. Related Docs

- [`serder.md`](./serder.md)
- [`core_types.md`](./core_types.md)
- [`buffer_pool`](../.opencode/skills/buffer_pool/SKILL.md) skill note (implementation details of the sharded pool)
