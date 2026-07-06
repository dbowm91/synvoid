# DNS Benchmark Results Template

## Metadata

| Field | Value |
|-------|-------|
| **Commit SHA** | `git rev-parse HEAD` — paste full 40-char SHA here |
| **Date** | YYYY-MM-DD |
| **Platform/CPU** | e.g. Linux x86_64, AMD Ryzen 9 5900X |
| **RAM** | e.g. 32 GB |
| **Rust version** | e.g. 1.82.0 |
| **Build command** | e.g. `cargo build --release -p synvoid-dns` |
| **Cargo bench command** | e.g. `cargo bench -p synvoid-dns` |

> **How to fill this**: Run `./scripts/dns/run_benchmarks.sh` — it auto-populates the
> environment section in the results file. Then copy the values here, or let the script
> append results directly.

## Cache Performance

| Benchmark | Parameter | Iterations | Time (mean) | Time (stddev) | Throughput |
|-----------|-----------|------------|-------------|---------------|------------|
| cache_insert | capacity=1000 | | | | |
| cache_insert | capacity=10000 | | | | |
| cache_insert | capacity=100000 | | | | |
| cache_lookup | capacity=1000 | | | | |
| cache_lookup | capacity=10000 | | | | |
| cache_lookup_miss | - | | | | |
| cache_transport_classes / lookup_by_transport_class | - | | | | |
| cache_invalidation | records=100 | | | | |
| cache_invalidation | records=1000 | | | | |

## Wire Format Parsing

| Benchmark | Parameter | Iterations | Time (mean) | Time (stddev) | Throughput |
|-----------|-----------|------------|-------------|---------------|------------|
| parse_query_name | short | | | | |
| parse_query_name | medium | | | | |
| parse_query_name | long | | | | |
| parse_dns_message | short | | | | |
| parse_dns_message | medium | | | | |
| parse_dns_message | long | | | | |
| parsed_dns_query | short | | | | |
| parsed_dns_query | medium | | | | |
| parsed_dns_query | long | | | | |
| get_message_id | - | | | | |
| get_message_flags | - | | | | |

## Zone Operations

| Benchmark | Parameter | Iterations | Time (mean) | Time (stddev) | Throughput |
|-----------|-----------|------------|-------------|---------------|------------|
| zone_new | - | | | | |
| zone_insert_records | count=10 | | | | |
| zone_insert_records | count=100 | | | | |
| zone_insert_records | count=1000 | | | | |
| zone_lookup_authoritative | count=100 | | | | |
| zone_lookup_authoritative | count=1000 | | | | |
| zone_lookup_nxdomain | - | | | | |
| zone_increment_serial | - | | | | |
| zone_trie / longest_match_hit | 1000 zones | | | | |
| zone_trie / longest_match_miss | 1000 zones | | | | |

## Coalescer Performance

| Benchmark | Parameter | Iterations | Time (mean) | Time (stddev) | Throughput |
|-----------|-----------|------------|-------------|---------------|------------|
| coalescer_new | - | | | | |
| coalescer_with_config | - | | | | |
| coalescer_key_creation | short | | | | |
| coalescer_key_creation | medium | | | | |
| coalescer_key_creation | long | | | | |
| should_skip_coalescing | regular_a | | | | |
| should_skip_coalescing | regular_aaaa | | | | |
| should_skip_coalescing | axfr | | | | |
| should_skip_coalescing | ixfr | | | | |
| should_skip_coalescing | notify_opcode | | | | |
| should_skip_coalescing | update_opcode | | | | |

## Connection Limits

| Benchmark | Parameter | Iterations | Time (mean) | Time (stddev) | Throughput |
|-----------|-----------|------------|-------------|---------------|------------|
| limits_new | - | | | | |
| limits_try_acquire_connection | max=100 | | | | |
| limits_try_acquire_connection | max=1000 | | | | |
| limits_try_acquire_connection | max=10000 | | | | |
| limits_try_acquire_query | max=1000 | | | | |
| limits_try_acquire_query | max=5000 | | | | |
| limits_try_acquire_query | max=10000 | | | | |
| limits_validate_query_size | size=64 | | | | |
| limits_validate_query_size | size=512 | | | | |
| limits_validate_query_size | size=1024 | | | | |
| limits_validate_query_size | size=4096 | | | | |
| limits_get_degradation_level | - | | | | |

## Notes

- All benchmarks run with `cargo bench -p synvoid-dns`
- Baseline recorded on first run
- Compare subsequent runs against baseline for regression detection
- Criterion outputs mean±stddev by default; record both columns
- Run `./scripts/dns/run_benchmarks.sh` for reproducible env capture with commit SHA
