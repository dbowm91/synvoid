# Transport comparison summary (generated)

| workload | lane | reps | median rps | min–max rps | median p50 (us) | median p95 (us) | median p99 (us) | total failures |
|---|---|---|---|---|---|---|---|---|
| stream-concurrent | legacy | 3 | 10796 | 8900–11248 | 132 | 372 | 1101 | 0 |
| stream-concurrent | eggfetch | 3 | 10641 | 9340–11147 | 136 | 359 | 1069 | 0 |

## Adjudication (>5% rule on median rps)

- stream-concurrent: eggfetch median rps -1.4% vs legacy (p95 359us vs 372us) — clear
