# DNS Operations Diagnostics

## Quick Health Check

### UDP Query Smoke Test
```bash
# Simple A record query against local DNS
dig @127.0.0.1 -p 53 example.com A +short +time=2 +tries=1

# Expected: IP address or NXDOMAIN
# Failure: timeout, SERVFAIL, or connection refused
```

### TCP Query Smoke Test
```bash
# Force TCP with +tcp flag
dig @127.0.0.1 -p 53 example.com A +tcp +short +time=2 +tries=1

# Expected: Same as UDP but over TCP
```

### DoT (DNS over TLS) Smoke Test
```bash
# Using kdig (from knot-dnsutils) or openssl s_client
kdig @127.0.0.1 -p 853 example.com A +short

# Or verify TLS handshake
openssl s_client -connect 127.0.0.1:853 -servername dns.example.com </dev/null 2>/dev/null | head -5
```

### DoH (DNS over HTTPS) Smoke Test
```bash
# Using curl with DNS JSON API
curl -s "https://dns.example.com/dns-query?name=example.com&type=A" \
  -H "Accept: application/dns-json"

# Or using dig with +https
dig @127.0.0.1 https://dns.example.com/dns-query example.com A +short
```

### DoQ (DNS over QUIC) Smoke Test
```bash
# Using qclient orquic-go DNS client (if available)
# Verify QUIC endpoint is reachable
nc -zvu 127.0.0.1 784 -w 2
```

Alternatively, run the automated smoke test: `./scripts/dns_diagnostic_smoke.sh 127.0.0.1 53`

## Zone Health Verification

### Check Loaded Zones
```bash
# Via admin API (if available)
curl -s http://127.0.0.1:8080/api/dns/health | jq '.zones_loaded, .zones_failed'

# Expected: zones_loaded > 0, zones_failed == 0
```

### Verify Zone Contents
```bash
# Query specific zone SOA
dig @127.0.0.1 -p 53 yourzone.com SOA +short

# Expected: primary NS, admin email, serial, refresh, retry, expire, minimum TTL
```

### Zone Reload Verification
```bash
# After zone reload, verify serial increased
dig @127.0.0.1 -p 53 yourzone.com SOA +short | awk '{print $3}'

# Compare with previous serial
```

## DNSSEC Verification

### Check DNSKEY Records
```bash
dig @127.0.0.1 -p 53 yourzone.com DNSKEY +dnssec +short

# Expected: DNSKEY records with flags 256 (ZSK) and 257 (KSK)
```

### Verify RRSIG Present
```bash
dig @127.0.0.1 -p 53 yourzone.com A +dnssec

# Check for: ;; AD: bit set (if validating resolver)
# Check for: RRSIG in Answer section
```

### DS Record Check (Parent Zone)
```bash
dig @127.0.0.1 -p 53 yourzone.com DS +short

# Expected: DS record matching KSK key tag
```

## Cache Inspection

### Cache Hit Rate
```bash
# Via metrics endpoint (Prometheus format)
curl -s http://127.0.0.1:9090/metrics | grep dns_cache_hit_rate

# Healthy: > 80% for typical workloads
```

### Cache Size
```bash
curl -s http://127.0.0.1:9090/metrics | grep dns_cache_insertions_total
```

## Metrics Inspection

### All DNS Metrics
```bash
curl -s http://127.0.0.1:9090/metrics | grep "^dns_"

# Key metrics to watch:
# dns_queries_received_total - Total queries received
# dns_responses_sent_total - Total responses sent  
# dns_cache_hits_total / dns_cache_misses_total - Cache performance
# dns_rate_limited_total - Rate limiting activity
# dns_active_tcp_connections - Current TCP connections
# dns_recursive_upstream_failures_total - Upstream resolver failures
```

### Response Code Distribution
```bash
curl -s http://127.0.0.1:9090/metrics | grep dns_response_code

# Healthy: Mostly NOERROR, some NXDOMAIN
# Warning: High SERVFAIL rate indicates issues
```

## Recursive Resolver Health

### Circuit Breaker Status
```bash
# Check if circuit breaker is open
curl -s http://127.0.0.1:9090/metrics | grep dns_recursive_circuit_breaker

# Circuit breaker open = upstream resolver failures exceeding threshold
```

### Upstream Forward Rate
```bash
curl -s http://127.0.0.1:9090/metrics | grep dns_recursive_upstream_forwards_total
```

## Encrypted Transport Health

### TLS Certificate Validity
```bash
# Check DoT certificate
echo | openssl s_client -connect 127.0.0.1:853 2>/dev/null | openssl x509 -noout -dates

# Check DoH certificate  
echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -dates
```

## Alertable Conditions

| Metric | Condition | Severity | Action |
|--------|-----------|----------|--------|
| `dns_queries_received_total` rate drops to 0 | No traffic reaching DNS | Critical | Check network, listeners, load balancer |
| `dns_responses_sent_total` << `dns_queries_received_total` | Queries not being answered | Critical | Check server logs, memory, CPU |
| `dns_cache_hit_rate` < 50% | Cache underperforming | Warning | Check TTLs, cache size, query patterns |
| `dns_rate_limited_total` increasing | Legitimate traffic being limited | Warning | Review rate limit config |
| `dns_recursive_upstream_failures_total` increasing | Upstream resolver issues | Warning | Check upstream DNS, network |
| `dns_recursive_circuit_breaker_opens_total` > 0 | Circuit breaker tripped | Critical | Upstream DNS unreachable, check network |
| `dns_encode_failures_total` increasing | Response encoding issues | Error | Check zone data, memory |
| `dns_zone_reload_failures_total` increasing | Zone reload failures | Error | Check zone file syntax, permissions |
| `dns_active_tcp_connections` very high | Connection leak or DDoS | Warning | Check connection limits, client behavior |
| `dns_dnssec_signing_failures_total` > 0 | DNSSEC signing broken | Critical | Check keys, HSM, clock sync |

## Structured Log Analysis

### Zone Load Events
```bash
# Successful zone loads
journalctl -u synvoid | grep "zone.*loaded\|zone.*active"

# Zone load failures
journalctl -u synvoid | grep "zone.*failed\|zone.*rejected"
```

### Security Events
```bash
# Transfer attempts
journalctl -u synvoid | grep "SECURITY:"

# UPDATE operations
journalctl -u synvoid | grep "UPDATE"
```

### NOTIFY Events
```bash
journalctl -u synvoid | grep "NOTIFY"
```

## Troubleshooting Flowchart

1. DNS not responding → Check listener bound, network, firewall
2. SERVFAIL on all queries → Check zone files, DNSSEC keys, cache
3. NXDOMAIN for valid names → Check zone records, delegation
4. Slow responses → Check upstream resolver, cache hit rate, RRL
5. Connection refused on DoT/DoH → Check TLS certificates, port config
6. Zone transfer failing → Check TSIG keys, AXFR policy, TCP connectivity
