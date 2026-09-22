# Transport comparison summary (generated)

| workload | lane | reps | median rps | min–max rps | median p50 (us) | median p95 (us) | median p99 (us) | total failures |
|---|---|---|---|---|---|---|---|---|
| h1-sequential | legacy | 5 | 10342 | 4668–13377 | 46 | 166 | 1153 | 0 |
| h1-sequential | eggfetch | 5 | 8319 | 5789–9978 | 54 | 267 | 1190 | 0 |
| h1-concurrent | legacy | 5 | 42238 | 39816–43239 | 121 | 358 | 1377 | 0 |
| h1-concurrent | eggfetch | 5 | 40921 | 32349–44770 | 127 | 377 | 1684 | 0 |
| h2-multiplexed | legacy | 5 | 37249 | 33589–39566 | 298 | 871 | 3349 | 0 |
| h2-multiplexed | eggfetch | 5 | 39062 | 36075–40646 | 302 | 863 | 2475 | 0 |
| stream-1k | legacy | 5 | 7393 | 4621–9195 | 61 | 273 | 1671 | 0 |
| stream-1k | eggfetch | 5 | 8153 | 7538–10503 | 60 | 264 | 1420 | 0 |
| stream-64k | legacy | 5 | 5187 | 4198–5739 | 123 | 388 | 1433 | 0 |
| stream-64k | eggfetch | 5 | 4695 | 2741–5035 | 132 | 461 | 1714 | 0 |
| stream-1m | legacy | 5 | 502 | 463–509 | 1557 | 4119 | 7434 | 0 |
| stream-1m | eggfetch | 5 | 489 | 474–527 | 1521 | 3911 | 7606 | 0 |
| stream-concurrent | legacy | 5 | 12432 | 11604–12511 | 227 | 666 | 1991 | 0 |
| stream-concurrent | eggfetch | 5 | 11447 | 10571–13062 | 232 | 759 | 2246 | 0 |
| stream-slow-producer | legacy | 5 | 25 | 25–26 | 38110 | 48662 | 54887 | 0 |
| stream-slow-producer | eggfetch | 5 | 26 | 25–26 | 37903 | 46468 | 48464 | 0 |
| early-drop | legacy | 5 | 1605 | 985–2041 | 430 | 1405 | 6314 | 0 |
| early-drop | eggfetch | 5 | 1928 | 1600–2857 | 311 | 1189 | 5138 | 0 |
| cold-construct | legacy | 5 | 0 | 0–0 | 7209217 | 7224384 | 7224384 | 0 |
| cold-construct | eggfetch | 5 | 9 | 8–10 | 105035 | 123129 | 123129 | 0 |

## Adjudication (>5% rule on median rps)

- h1-sequential: eggfetch median rps -19.6% vs legacy (p95 267us vs 166us) — MATERIAL (>5% rps)
- h1-concurrent: eggfetch median rps -3.1% vs legacy (p95 377us vs 358us) — clear
- h2-multiplexed: eggfetch median rps +4.9% vs legacy (p95 863us vs 871us) — clear
- stream-1k: eggfetch median rps +10.3% vs legacy (p95 264us vs 273us) — clear
- stream-64k: eggfetch median rps -9.5% vs legacy (p95 461us vs 388us) — MATERIAL (>5% rps)
- stream-1m: eggfetch median rps -2.7% vs legacy (p95 3911us vs 4119us) — clear
- stream-concurrent: eggfetch median rps -7.9% vs legacy (p95 759us vs 666us) — MATERIAL (>5% rps)
- stream-slow-producer: eggfetch median rps +2.2% vs legacy (p95 46468us vs 48662us) — clear
- early-drop: eggfetch median rps +20.1% vs legacy (p95 1189us vs 1405us) — clear
- cold-construct: eggfetch median rps +6635.8% vs legacy (p95 123129us vs 7224384us) — clear
