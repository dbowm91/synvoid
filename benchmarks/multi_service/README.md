# Multi-service benchmark harness (Phase 10, manual-only)

End-to-end, same-host measurements for the workloads that the focused Criterion
benches and `benchmarks/http_transport/` do not cover: many virtual hosts, TLS
and HTTP/2, the WAF request path, chunked uploads, raw TCP/UDP listeners and a
steady-state soak.

**This harness is never a CI gate.** Loopback numbers are host-sensitive by
construction. Run it by hand, keep the dated result directory, and never compare
numbers across hosts, kernels, CPU models or build profiles. A result is
evidence for the exact SHA and host recorded in the file, not a product claim.

## Host assumptions

- Linux on x86_64 is the primary target. TCP/UDP and multi-port probes assume
  loopback routing works (`127.0.0.0/8` on Linux).
- No other heavy process on the same host during a measured run. A browser, a
  container build or another load generator invalidates the run.
- The harness and the subject run on the same host over loopback:
  `client -> 127.0.0.1 -> SynVoid -> 127.0.0.1 -> local upstream`.
  Loopback removes the NIC, the network RTT and most of the kernel's packet
  processing; real deployments normally see lower request rates and higher tail
  latency than these files record.
- The harness starts one SynVoid supervisor per process profile. Worker count
  and Tokio thread count are explicit in the generated config and in the result
  metadata.

## Topology

```
oha / h2load / Python client
        |
        |  HTTP/1.1, TLS+ALPN H2, or QUIC (h3)
        v
127.0.0.1:<http|tls|h3>  SynVoid supervisor
        |                  -> 1 UnifiedServerWorker (or the selected profile)
        |                  -> local static / dynamic upstreams
        v
127.0.0.1:<dynamic|static>  Python stdlib upstreams

TCP/UDP (when wired): client -> 127.0.0.1:<echo-port> -> SynVoid -> echo server
```

The driver allocates every port dynamically, writes the generated config into a
temporary work directory, and isolates the supervisor PID file and IPC socket
with `XDG_DATA_HOME` / `XDG_RUNTIME_DIR`. Nothing is written to the operator's
real SynVoid data directory. Temporary work is deleted unless `--keep-work` is
passed.

## Workloads

| Workload | What it exercises | Status at current HEAD |
|---|---|---|
| `vhost-1` | One site in the router | supported |
| `vhost-100` | 100 generated site files, rotating `Host` | supported |
| `vhost-1000` | 1000 generated site files, rotating `Host` | supported |
| `h1-keepalive` | Plain HTTP/1.1, one connection | supported |
| `h1-concurrent` | Plain HTTP/1.1, many connections | supported |
| `tls-h2` | TLS + ALPN + HTTP/2 | attempted; marked unsupported with the negotiated ALPN value when the endpoint does not negotiate `h2` |
| `h3` | QUIC / HTTP/3 | attempted; skipped with a reason when the client or listener is unavailable |
| `mixed-static-proxy` | Static route and dynamic proxy route in one process | supported |
| `waf-small` | Small request with attack detection enabled | supported |
| `waf-body` | 32 KiB request body through inline WAF body scanning | supported |
| `chunked-upload` | `Transfer-Encoding: chunked` upload | attempted via the Python client; marked unsupported when the probe returns 413 |
| `tcp-echo` | One TCP echo listener | supported; the echo entry sets `filter_enabled = false` because `echo` is a custom protocol |
| `tcp-multi-port` | Several TCP echo ports | supported; same custom-protocol filter setting |
| `udp-echo` | One UDP echo request/response listener | supported; custom-protocol filter disabled in the generated config |
| `udp-multi-port` | Several UDP echo ports | supported; same custom-protocol filter setting |
| `multi-listener` | Multiple `[[http.listeners]]` ports in one process | supported; each planned listener is probed and measured |
| `soak` | 30–60 min steady state, RSS/FD/event-loop lag | supported |

Unsupported workloads are never silently omitted. The driver writes a result
file with `"supported": false`, the checked reason, and lists it in the
summary's unsupported-workload table.

## CLI

```bash
# Smoke: tiny pipeline check on the current checkout. Never evidence.
python3 benchmarks/multi_service/driver.py --smoke

# Full default matrix (all supported workloads, 10 s each, soak 30 min).
python3 benchmarks/multi_service/driver.py

# One process profile, focused workloads.
python3 benchmarks/multi_service/driver.py \
  --process-profiles default \
  --workloads vhost-1,vhost-100,vhost-1000,h1-concurrent,tls-h2,waf-small,waf-body \
  --duration 15

# Tokio thread scaling curve.
python3 benchmarks/multi_service/driver.py \
  --process-profiles threads-1,threads-4,threads-8 --workloads h1-concurrent

# Isolation cost (advanced; not a recommended throughput profile).
python3 benchmarks/multi_service/driver.py --process-profiles workers-2 --workloads h1-concurrent

# Separate detection cost from proxy cost.
python3 benchmarks/multi_service/driver.py --waf-profile off   --workloads waf-small,waf-body
python3 benchmarks/multi_service/driver.py --waf-profile on    --workloads waf-small,waf-body
python3 benchmarks/multi_service/driver.py --waf-profile block --workloads waf-small,waf-body
```

Useful flags:

| Flag | Default | Meaning |
|---|---|---|
| `--binary PATH` | `target/<build-profile>/synvoid` | Subject binary. Must be built from the same checkout SHA. |
| `--build-profile` | `release` | `release`, `ci` or `debug`; recorded, never inferred into a claim. |
| `--process-profiles` | `default` | Comma list of `default`, `threads-1`, `threads-<N>`, `workers-2`. |
| `--waf-profile` | `on` | `off`, `on` or `block`; applied to every site in that server run. |
| `--workloads` | all | Comma/space list; `all` includes `soak`. |
| `--duration` | `10` | Seconds per measured HTTP/TCP/UDP workload. |
| `--soak-seconds` | `1800` | Steady-state soak length (30 min). `--smoke` forces 3 s. |
| `--concurrency` | workload default | Override the HTTP connection count. |
| `--tool` | `auto` | `auto`, `oha`, `python`; chooses the HTTP load generator. |
| `--threads N` | `4` | N for the `threads-N` process profile. |
| `--out DIR` | `benchmarks/multi_service/results` | Results root. |
| `--work-root DIR` | `$TMPDIR` | Temporary server/upstream/workload files. |
| `--keep-work` | off | Keep the generated config and logs for diagnosis. |
| `--skip-server` | off | Only resolve tools and print the plan (no run). |
| `--list-workloads` | off | Print the workload names and exit. |

## Tool detection

`oha` is preferred (JSON output, HTTP/1.1, H2 and an H3 attempt) for the
vhost, TLS/H2/H3 and WAF-body workloads. `h2load` is the first choice for
TLS/H2 when it is available. `wrk` is detected and recorded but not used by the
default matrix because it cannot produce the JSON shape this harness records.

The default `--tool auto` policy uses the built-in `http.client` Python client
for the keep-alive, mixed-static, WAF-small and soak lanes. In this repository's
`oha` build, a fixed-duration run tears connections down at the deadline and
reports client-side resets that would otherwise be misread as subject errors.
The Python client keeps a stable connection set and reports the same metrics;
the result records `client.tool = "python"` so the choice is never hidden.
Explicit `--tool oha` or `--tool python` always wins. Missing tools are reported
in the run metadata and in the workload result, never as an obscure crash.

## Result schema

Every measured workload writes one JSON file under
`results/YYYY-MM-DD/`. The top-level shape is stable (`schema_version =
"synvoid.multi-service-benchmark.v1"`):

```json
{
  "schema_version": "synvoid.multi-service-benchmark.v1",
  "run_id": "2026-11-10T201500Z-abc123",
  "workload": "h1-concurrent",
  "supported": true,
  "unsupported_reason": null,
  "subject": {
    "revision_sha": "…",
    "harness_sha": "…",
    "binary": "/path/to/target/release/synvoid",
    "binary_sha256": "…",
    "build_profile": "release"
  },
  "toolchain": {
    "rustc": "rustc 1.98.1 …",
    "cargo": "cargo 1.98.1 …",
    "load_tool": "oha 0.x",
    "python": "3.12.3"
  },
  "host": {
    "os": "Linux",
    "kernel": "6.8.0",
    "arch": "x86_64",
    "cpu_model": "Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz",
    "cpu_count": 16,
    "memory_bytes": 16616483840
  },
  "topology": {
    "kind": "loopback-same-host",
    "client_host": "127.0.0.1",
    "server_host": "127.0.0.1",
    "notes": "loopback hides NIC and network RTT"
  },
  "process_profile": {
    "name": "default",
    "worker_processes": 1,
    "worker_threads": 16,
    "waf_profile": "on"
  },
  "command": ["oha", "-z", "10s", "-c", "64", "…"],
  "http": {
    "url": "http://127.0.0.1:18080/",
    "method": "GET",
    "host_header": "bench-0000.local",
    "concurrency": 64,
    "duration_secs": 10
  },
  "metrics": {
    "requests": 123456,
    "requests_per_sec": 12345.6,
    "latency_ms": {"p50": 3.1, "p95": 8.2, "p99": 19.4},
    "errors": 0,
    "error_rate": 0.0,
    "status_codes": {"200": 123456}
  },
  "system": {
    "cpu_seconds": 8.2,
    "cpu_percent": 82.0,
    "rss_bytes_start": 12345678,
    "rss_bytes_end": 12345678,
    "rss_bytes_peak": 12345678,
    "fd_start": 42,
    "fd_end": 42,
    "fd_peak": 42,
    "process_count": 3
  },
  "synvoid_metrics": {
    "before": {"synvoid_subject_active_connections": 0},
    "after": {"synvoid_subject_active_connections": 0}
  },
  "admin_stats": {"summary": {}, "sites": [], "sites_total": 1000,
                  "sites_truncated": true, "attacks": {}},
  "tcp_udp": null
}
```

`system.*`, `synvoid_metrics` and `admin_stats` are best-effort: a failed stats
scrape sets those keys to `null` and records the error under `diagnostics`.
Transport-level load errors are counted in `metrics.errors`; expected WAF block
status codes stay visible in `metrics.status_codes`.

The dated directory also contains:

- `<run-id>-RUN.md` — human-readable provenance (SHA, host, toolchain,
  topology, flags);
- `<run-id>-commands.log` — every server/client command line actually executed;
- `<run-id>-summary.md` — per-workload table plus the unsupported-workload table;
- `<run-id>-run.json` — the complete run manifest (all results, tool
  availability, generated config summary, ports);
- `<run-id>-<profile>-<workload>.json` — one result per workload/profile.

## Reproducibility rules

1. Build the subject from the SHA recorded in `subject.revision_sha`
   (`cargo build --release`). Do not rebuild mid-run.
2. Keep the harness files unchanged during a run; `subject.harness_sha` hashes
   everything under `benchmarks/multi_service/` except `results/` and temporary
   work. A changed harness is a new run, not a rerun.
3. Record the exact command line. `<run-id>-commands.log` is authoritative; the JSON
   `command` field is the client command only.
4. Never overwrite a prior result file. The driver adds a numeric suffix when a
   filename already exists.
5. Use the same host, kernel, CPU governor and background-load conditions for
   every repetition that will be compared. Warm up before measuring; the
   driver's timed client workloads include a short warmup for the Python path
   and `oha` warms connections naturally.
6. Do not compare across hosts, architectures, build profiles or container
   runtimes. Loopback results are not production capacity.
7. Run at least three repetitions of a workload before making an ordering
   claim; report the median and the spread.

## TLS fixtures

The driver generates a throwaway self-signed certificate for `localhost` /
`127.0.0.1` with `openssl` into the temporary work directory. Nothing is
committed. If `openssl` is unavailable, TLS/H2 and H3 are marked unsupported
with a reason. The benchmark config is local-only and sets
`admin.secure_cookie = false`; never reuse these templates as a production
deployment.

## Secrets

Committed configs contain **no** admin token and **no** IPC key. The driver
generates both at run time and passes them through
`SYNVOID_ADMIN_TOKEN` / `SYNVOID_IPC_KEY` environment variables, matching the
production configuration contract. The generated config references the env var
names only.

## Ownership

`benchmarks/multi_service/` is a manual performance-evidence surface. Changes
that alter what a workload measures (target paths, body sizes, client tool
semantics, topology) must update this README and the result schema together.
See `OWNERSHIP.md`.
