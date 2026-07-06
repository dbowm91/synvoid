# DNS Benchmark Results Template

## Environment

- **Date**: YYYY-MM-DD
- **OS**: 
- **CPU**: 
- **RAM**: 
- **Rust version**: 
- **Cargo profile**: release

## Cache Performance

| Benchmark | Capacity | Time (ns) | Throughput |
|-----------|----------|-----------|------------|
| cache_insert | 1000 | | |
| cache_insert | 10000 | | |
| cache_insert | 100000 | | |
| cache_lookup | 1000 | | |
| cache_lookup | 10000 | | |
| cache_lookup_miss | - | | |
| sharded_cache_lookup | 1000 | | |
| sharded_cache_lookup | 10000 | | |

## Wire Format Parsing

| Benchmark | Name Length | Time (ns) |
|-----------|-------------|-----------|
| parse_query_name | short | |
| parse_query_name | medium | |
| parse_query_name | long | |
| parsed_dns_query | short | |
| parsed_dns_query | medium | |
| parsed_dns_query | long | |

## Zone Operations

| Benchmark | Record Count | Time (ns) |
|-----------|--------------|-----------|
| zone_new | - | |
| zone_insert_records | 10 | |
| zone_insert_records | 100 | |
| zone_insert_records | 1000 | |
| zone_lookup_authoritative | 100 | |
| zone_lookup_authoritative | 1000 | |
| zone_lookup_nxdomain | - | |
| zone_increment_serial | - | |
| zone_trie_longest_match | 1000 zones | |

## Coalescer Performance

| Benchmark | Time (ns) |
|-----------|-----------|
| coalescer_new | |
| coalescer_key_short | |
| coalescer_key_medium | |
| coalescer_key_long | |
| should_skip_coalescing | |

## Connection Limits

| Benchmark | Max Connections | Time (ns) |
|-----------|-----------------|-----------|
| limits_new | - | |
| limits_try_acquire_connection | 100 | |
| limits_try_acquire_connection | 1000 | |
| limits_try_acquire_query | 1000 | |
| limits_try_acquire_query | 5000 | |
| limits_validate_query_size | 64 | |
| limits_validate_query_size | 4096 | |

## Notes

- All benchmarks run with `cargo bench -p synvoid-dns`
- Baseline recorded on first run
- Compare subsequent runs against baseline for regression detection
