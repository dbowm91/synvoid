# Transport comparison summary (generated)

| workload | lane | reps | median rps | min–max rps | median p50 (us) | median p95 (us) | median p99 (us) | total failures |
|---|---|---|---|---|---|---|---|---|
| h1-sequential | legacy | 5 | 8515 | 3199–10562 | 52 | 219 | 1549 | 0 |
| h1-sequential | eggfetch | 5 | 7588 | 4134–10434 | 56 | 269 | 1613 | 0 |
| h1-concurrent | legacy | 5 | 45907 | 40280–50981 | 112 | 338 | 1279 | 0 |
| h1-concurrent | eggfetch | 5 | 43977 | 36655–47296 | 122 | 369 | 1262 | 0 |
| h2-multiplexed | legacy | 5 | 42157 | 37649–46810 | 289 | 723 | 2233 | 0 |
| h2-multiplexed | eggfetch | 5 | 39531 | 33450–42447 | 300 | 855 | 2738 | 0 |
| stream-1k | legacy | 5 | 9570 | 6763–10426 | 50 | 177 | 1221 | 0 |
| stream-1k | eggfetch | 5 | 9185 | 7948–11489 | 53 | 216 | 1235 | 0 |
| stream-64k | legacy | 5 | 6282 | 4877–7751 | 118 | 280 | 499 | 0 |
| stream-64k | eggfetch | 5 | 5905 | 5037–6973 | 119 | 305 | 535 | 0 |
| stream-1m | legacy | 5 | 571 | 514–639 | 1425 | 3519 | 4560 | 0 |
| stream-1m | eggfetch | 5 | 523 | 410–625 | 1538 | 3209 | 4723 | 0 |
| stream-concurrent | legacy | 5 | 15442 | 11443–17061 | 223 | 424 | 702 | 0 |
| stream-concurrent | eggfetch | 5 | 12296 | 6015–13780 | 242 | 455 | 2191 | 0 |
| stream-slow-producer | legacy | 5 | 26 | 25–26 | 37667 | 47858 | 53808 | 0 |
| stream-slow-producer | eggfetch | 5 | 26 | 25–26 | 38176 | 46869 | 51994 | 0 |
| early-drop | legacy | 5 | 1428 | 827–2144 | 557 | 1417 | 3309 | 0 |
| early-drop | eggfetch | 5 | 2258 | 2050–2423 | 373 | 1035 | 1509 | 0 |
| cold-construct | legacy | 5 | 0 | 0–0 | 7016826 | 7253990 | 7253990 | 0 |
| cold-construct | eggfetch | 5 | 8 | 7–9 | 111242 | 137461 | 137461 | 0 |

## Adjudication (>5% rule on median rps)

- h1-sequential: eggfetch median rps -10.9% vs legacy (p95 269us vs 219us) — MATERIAL (>5% rps)
- h1-concurrent: eggfetch median rps -4.2% vs legacy (p95 369us vs 338us) — clear
- h2-multiplexed: eggfetch median rps -6.2% vs legacy (p95 855us vs 723us) — MATERIAL (>5% rps)
- stream-1k: eggfetch median rps -4.0% vs legacy (p95 216us vs 177us) — clear
- stream-64k: eggfetch median rps -6.0% vs legacy (p95 305us vs 280us) — MATERIAL (>5% rps)
- stream-1m: eggfetch median rps -8.4% vs legacy (p95 3209us vs 3519us) — MATERIAL (>5% rps)
- stream-concurrent: eggfetch median rps -20.4% vs legacy (p95 455us vs 424us) — MATERIAL (>5% rps)
- stream-slow-producer: eggfetch median rps +0.3% vs legacy (p95 46869us vs 47858us) — clear
- early-drop: eggfetch median rps +58.2% vs legacy (p95 1035us vs 1417us) — clear
- cold-construct: eggfetch median rps +5589.9% vs legacy (p95 137461us vs 7253990us) — clear
