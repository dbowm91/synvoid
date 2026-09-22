# Transport comparison summary (generated)

| workload | lane | reps | median rps | min–max rps | median p50 (us) | median p95 (us) | median p99 (us) | total failures |
|---|---|---|---|---|---|---|---|---|
| stream-64k-phases | legacy | 5 | 2355 | 2182–2494 | 248 | 1062 | 4244 | 0 |
| stream-64k-phases | eggfetch | 5 | 2322 | 1985–2719 | 251 | 1125 | 4100 | 0 |

## Adjudication (>5% rule on median rps)

- stream-64k-phases: eggfetch median rps -1.4% vs legacy (p95 1125us vs 1062us) — clear
