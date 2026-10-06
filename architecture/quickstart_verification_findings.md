# Quickstart Verification Findings (2026-10-06)

Audit record for the README / user-facing documentation review. Unlike the architecture
verification passes, this audit was **empirical**: a release-profile binary was built
(`cargo build --bin synvoid --profile ci`) and every documented quickstart command was
executed against it on macOS 25.6.0 (darwin x86_64), Rust nightly, default features
(`socket-handoff, mesh, dns, erased_pool, swagger-ui`).

Three findings block or mislead the documented quickstart. All three are recorded here
rather than fixed, because this audit was scoped to documentation only. **None of them is a
security regression** — two are availability/ergonomics defects and one is a sharp edge —
but F-1 is severe enough that it should be triaged like a bug.

---

## F-1 — Omitting `[defaults.ratelimit.ip]` rate-limits 100% of traffic (SEVERE)

### Symptom

Every request to every site returns HTTP 429, including the very first request from a
clean process with an empty rate-limit table.

```
$ curl -A "$UA" -H "Host: example.com" http://127.0.0.1:8080/
<!DOCTYPE html>...<title>429 Too Many Requests</title>...   [HTTP 429]
```

Server log:

```
INFO synvoid::waf: Rate limiting IP 127.0.0.1: site_ip_per_second (site: "example.com", retry after: 1000ms)
```

### Root cause

`crates/synvoid-config/src/defaults.rs` attaches a **struct-level** `#[serde(default)]` to
`DefaultsConfig`:

```rust
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DefaultsConfig {
    pub ratelimit: RateLimitDefaults,
    ...
```

That routes a missing or empty `[defaults]` through the hand-written
`impl Default for RateLimitDefaults`, which builds `ip` from the **derived**
`IpRateLimitConfig::default()`:

```rust
impl Default for RateLimitDefaults {
    fn default() -> Self {
        Self { mode: "shared".to_string(), ip: IpRateLimitConfig::default(), ... }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema, ToSchema)]
pub struct IpRateLimitConfig {
    #[serde(default = "default_ip_per_second")]  // = 10
    pub per_second: u32,
    ...
}
```

`IpRateLimitConfig` derives `Default`, so `::default()` yields **all zeros**. The
`#[serde(default = "default_ip_per_second")]` attributes only apply when the field is
*absent from a present table* — they are never consulted by the struct-level default path.
So an omitted `[defaults.ratelimit.ip]` resolves `per_second = 0`, not `10`.

The site limiter then evaluates (`src/waf/ratelimit.rs`):

```rust
if ip_state.per_second.len() >= self.state.config.ip.per_second as usize {
    return RateLimitResult::Limited { limit_type: "site_ip_per_second", ... };
}
```

which degenerates to `len() >= 0` — true for every request, forever.

The same zero-default hazard applies to every other type reached through
`DefaultsConfig::default()`: `GlobalRateLimitConfig` is likewise `#[derive(..., Default, ...)]`
with `#[serde(default = "...")]` fields, so `global.per_second` / `max_connections` also
resolve to `0` rather than `500` / `10000`.

### Why it was not caught

The shipped `config/main.toml` sets `[defaults.ratelimit.ip]` and `[defaults.ratelimit.global]`
explicitly, so the defect is invisible in-tree. It only appears in a **hand-written or
minimal config** — which is exactly what a quickstart teaches. `synvoid --configtest` accepts
the broken configuration: validation is structural, not semantic.

### Evidence

| Config | First request |
|---|---|
| `[defaults]` absent | `429` |
| `[defaults]` empty | `429` |
| `[defaults.ratelimit.ip] per_second = 10` | `200` + upstream body |

### Suggested fix (NOT applied — documentation-only scope)

Give `RateLimitDefaults` a `Default` impl that mirrors the serde defaults, or drop the
struct-level `#[serde(default)]` on `DefaultsConfig` and annotate individual fields. A
cheap guard test asserting `MainConfig::default().defaults.ratelimit.ip.per_second == 10`
would pin it.

### Documentation response (applied)

`README.md`, `docs/GETTING_STARTED.md` §Configuration Gotchas, and
`docs/CONFIGURATION.md` now state that `[defaults.ratelimit.ip]` and
`[defaults.ratelimit.global]` are effectively **required** and show them in every worked
example.

---

## F-2 — Default `strict_protocol_validation = false` yields an empty HTTP reply

### Symptom

With `strict_protocol_validation` left at its default (`false`), the data plane accepts the
connection, logs a normal connection outcome, and writes **zero response bytes**. curl
reports exit 56 (recv failure). No error is logged at any level.

```
$ curl -m 5 http://127.0.0.1:18000/
HTTP 000
$ curl -m 5 ...   # exit code 56
```

With `[http] strict_protocol_validation = true` set, the identical request returns the
upstream's response.

### Mechanism

`src/http/server/accept_loop.rs` branches on `http_config.strict_protocol_validation`:

- **`true`** — the accept loop itself peeks and reads the first bytes of the connection,
  validates that they look like HTTP (rejecting TLS ClientHello and non-HTTP traffic with
  a counter), and hands the replayed bytes to the EggServe H1 driver as `initial_bytes`.
- **`false`** — the accept loop hands the raw stream straight through, leaving first-byte
  handling entirely to the driver.

On this host only the first path produced a response. The default is
`default_strict_protocol_validation() -> false` in `crates/synvoid-config/src/http.rs`, so
the broken path is the one a default deployment gets.

### Scope of the observation

Reproduced consistently on **macOS 25.6.0 (darwin x86_64)**. Not reproduced on Linux in
this pass — no Linux host was available. It is therefore **not established** whether this is
a macOS-specific defect (e.g. interaction with `SO_REUSEPORT`, which the listener does set)
or a general one. Treat the platform attribution as open.

### Documentation response (applied)

`docs/GETTING_STARTED.md` §Configuration Gotchas records the behavior and its platform
caveat; the quickstart config sets `strict_protocol_validation = true`. No claim is made
that this is the only remedy.

---

## F-3 — `curl` is tarpitted by the default scraper patterns

### Symptom

A smoke test with an unmodified `curl` returns **HTTP 200** with the literal body:

```
Tarpit active
```

Server log:

```
INFO synvoid::waf: Tarpitting scraper from 127.0.0.1: scraper_detected - UA: Some("curl/8.7.1"), JA4: None
```

### Mechanism

`defaults.bot.scraper_patterns` includes `curl`, and a matching User-Agent routes the
request to the tarpit (`crates/synvoid-proxy/src/server.rs`, body `"Tarpit active"`). Because
the tarpit answers **200**, a naive `curl -I` check looks like success while returning the
wrong body entirely — a particularly misleading failure mode for a first-run verification.

### Documentation response (applied)

Every verification example in `README.md` and `docs/GETTING_STARTED.md` now passes a
browser-like `User-Agent` via `-A "$UA"`, with an explicit callout explaining why.

---

## F-4 — The shipped systemd unit cannot start SynVoid (SEVERE)

`contrib/systemd/synvoid.service` is the only deployment artifact shipped in-repo, and
`docs/PROCESS_MANAGEMENT.md` tells operators to install it verbatim. It cannot work.

### Reproduction

```
$ synvoid --overseer --foreground --config-path ./config
error: unexpected argument '--overseer' found

Usage: synvoid [OPTIONS]

For more information, try '--help'.
$ echo $?
2
```

`--overseer` is not defined in `crates/synvoid-cli/src/lib.rs`, and clap rejects unknown
arguments, so the process exits before any configuration is read.

### Three further defects in the same unit

| Line | Problem | Evidence |
|---|---|---|
| `Description=MaluWAF` | Stale pre-rename product name | — |
| `Environment=SYNVOID_CONFIG_PATH=/opt/synvoid/config` | Never read; the binary takes `--config-path` | no `SYNVOID_CONFIG_PATH` anywhere in `src/` or `crates/` |
| `WatchdogSec=30s` + `NotifyAccess=all` | SynVoid never calls `sd_notify`, so systemd kills the service every 30s and `Restart=always` turns that into a restart loop | no `sd_notify` anywhere in `src/` or `crates/` |
| `ExecReload=/bin/kill -HUP $MAINPID` | No inbound SIGHUP reload handler; config reload is `synvoid --rehash` | `SIGHUP` appears only as an *outbound* signal in `synvoid-ipc` `ReloadConfig` |

### Corrected `ExecStart`

```ini
ExecStart=/usr/local/bin/synvoid --foreground --config-path /opt/synvoid/config
```

### Documentation response (applied)

`docs/PROCESS_MANAGEMENT.md` now leads its systemd section with this defect, gives the
corrected `ExecStart`, and names the dead `SYNVOID_CONFIG_PATH` and watchdog lines
explicitly.

**Not fixed, because this audit is documentation-only:** the unit file itself still ships
broken. It should be repaired in a follow-up change.

---

## F-5 — The port honeypot is enabled by default and targets the data-plane ports

### Fact

`synvoid_config_model::honeypot_port::HoneypotPortConfig` — the type `MainConfig::honeypot_port`
actually uses — defaults to:

```rust
impl Default for HoneypotPortConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![8080, 8443, 9090],
            protocols: vec!["tcp".to_string(), "udp".to_string()],
            site_scope: "global".to_string(),
        }
    }
}
```

The shipped `config/main.toml` contains no `[honeypot_port]` section, so this default applies.

### Consequences

1. A stock install attempts to bind deception listeners on **8080** (the default HTTP data
   plane port), **8443**, and **9090** (the default metrics port).
2. As an unprivileged process the bind fails; SynVoid logs
   `Failed to initialize port honeypot runner: Permission denied (os error 13)` and continues
   — observed in this pass.
3. As root it can succeed, in which case it contends with the data plane and the Prometheus
   exporter for the same ports.

`docs/HONEYPOT.md` previously said "disabled by default", which was wrong.

### Two-type trap

There are **two** structs named `HoneypotPortConfig` in the config crate:

| Location | Fields | `Default` |
|---|---|---|
| `crates/synvoid-config-model/src/honeypot_port.rs` (**used by `MainConfig`**) | `enabled`, `ports`, `protocols`, `site_scope` | `enabled: true`, ports `[8080, 8443, 9090]` |
| `crates/synvoid-config/src/defaults.rs` (**not referenced by `MainConfig`**) | `enabled`, `ports` | `enabled: false`, ports `[22, 80, 443, 3306, 6379, 8080, 8443]` |

Reading the `defaults.rs` copy yields exactly the wrong answer to "is the honeypot on by
default?". Always resolve the type through `MainConfig`'s import
(`use super::honeypot_port::HoneypotPortConfig`).

### Documentation response (applied)

`docs/HONEYPOT.md` and `docs/CONFIGURATION.md` both state the real default, the real port
list, and the perms/contention consequence, and tell operators to set `enabled = false`
explicitly if they do not want it.

**Not fixed, because this audit is documentation-only:** whether a default-open deception
listener on the production HTTP port is intended is a product decision for the maintainer.

---

## Additional verified facts (no defect)

- `synvoid --generatetoken` prints a **64-character hex** token — satisfies the
  `MIN_TOKEN_LENGTH = 32` check in `crates/synvoid-config/src/admin.rs`.
- `admin.token` shorter than 32 chars, or containing a `WEAK_TOKEN_PATTERNS` entry, is
  **rejected** during validation. Any doc showing a short placeholder token is wrong.
- `admin.bind_address` defaults to `127.0.0.1`; `metrics.bind_address` defaults to
  `127.0.0.1` and a **non-loopback** value is rejected by `MetricsConfig::validate()`.
- Required `main.toml` sections (no serde default): `server`, `fallback`, `admin`,
  `logging`, `metrics`, `defaults`. Omitting `fallback` fails with
  `missing field 'fallback'`.
- The shipped `config/main.toml` **fails `--configtest` on a clean machine** (exit 1):
  `logging.access_log_dir: Access log directory not found: /var/log/synvoid`. It also
  writes threat-level SQLite history to `/var/lib/synvoid`. Both directories must be
  created, or the paths overridden, before first run.
- `--configtest` correctly returns exit code **1** on failure.
- `--checkregex '^(a+)+$'` works and reports the pattern safe.
- A unified worker **cannot** be run standalone: `--unified-server-worker` without a live
  Supervisor exits with `Unified server worker error: Connection refused (os error 61)`.
  Worker/sandbox modes are Supervisor-spawned, not operator-spawned.
- The admin listener did **not** come up in this pass even though `[admin] enabled = true`
  and the port was free; the Supervisor also emitted no log output at all while the worker
  logged normally. Not diagnosed — recorded here so the next pass does not assume the
  admin UI is reachable from a plain `--foreground` start.
- eBPF/XDP flood protection remains unreachable: `EbpfFlood` has no construction site
  outside `src/waf/flood/ebpf_flood.rs`, `flood-ebpf` is not a default feature, and
  `ebpf-flood/` is not a workspace member. Re-confirmed this pass.
- Rate-limit counters persist across restarts in a shared-memory file
  (`$TMPDIR/synvoid-runtime/ratelimit.shm`), so repeated test runs can 429 a fresh process.
  Delete that file between smoke tests.

## Verification commands used

```bash
cargo build --bin synvoid --profile ci
./target/ci/synvoid --version
./target/ci/synvoid --generatetoken
./target/ci/synvoid --checkregex '^(a+)+$'
./target/ci/synvoid --configtest --config-path ./config
./target/ci/synvoid --foreground --config-path ./config
curl -A "$UA" -H "Host: example.com" http://127.0.0.1:8080/
curl -A "$UA" -H "Host: example.com" 'http://127.0.0.1:8080/?id=1%20OR%201=1%20UNION%20SELECT%20u,p,3%20FROM%20users--'
curl http://127.0.0.1:9090/metrics
```

## See also

- [`docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md) — the corrected quickstart
- [`docs/CONFIGURATION.md`](../docs/CONFIGURATION.md) — configuration reference
- [`architecture/agent_knowledge_maintenance.md`](./agent_knowledge_maintenance.md) — the
  recurring audit checklist these findings should be folded into