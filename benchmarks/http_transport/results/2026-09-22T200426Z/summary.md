# Transport comparison summary (generated)

| workload | lane | reps | median rps | min–max rps | median p50 (us) | median p95 (us) | median p99 (us) | total failures |
|---|---|---|---|---|---|---|---|---|
| stream-concurrent | legacy | 6 | 16634 | 13451–26122 | 182 | 465 | 1141 | 0 |
| stream-concurrent | eggfetch | 6 | 13526 | 10886–24170 | 212 | 583 | 1622 | 0 |

## Adjudication (>5% rule on median rps)

- stream-concurrent: eggfetch median rps -18.7% vs legacy (p95 583us vs 465us) — MATERIAL (>5% rps)
