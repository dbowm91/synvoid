# Multi-service benchmark result directory

The driver writes one directory per UTC day (`YYYY-MM-DD/`) and never overwrites
an existing result file. A complete directory contains:

| File | Purpose |
|---|---|
| `<run-id>-RUN.md` | Revision/harness SHA, host, toolchain, topology, flags, ports |
| `<run-id>-commands.log` | Every server and client command line that ran |
| `<run-id>-summary.md` | Supported workload table + unsupported-workload table |
| `<run-id>-run.json` | Full manifest: metadata, args, ports, all per-workload JSON |
| `<run-id>-<profile>-<workload>.json` | One result per workload/profile; `multi-listener` carries a `listeners` array with one metrics object per bound port |

Quote the directory name and the revision SHA when citing a result. State the
host CPU model and note that the measurement is loopback-only. Never compare a
result with a run from another host, kernel, build profile or container runtime.
