# Transport comparison summary (generated)

| workload | lane | reps | median rps | min–max rps | median p50 (us) | median p95 (us) | median p99 (us) | total failures |
|---|---|---|---|---|---|---|---|---|
| stream-concurrent | legacy | 3 | 17468 | 16567–18742 | 277 | 904 | 4402 | 0 |
| stream-concurrent | eggfetch | 3 | 15789 | 15693–17039 | 281 | 1067 | 4360 | 0 |

## Adjudication (>5% rule on median rps)

- stream-concurrent: eggfetch median rps -9.6% vs legacy (p95 1067us vs 904us) — MATERIAL (>5% rps)
