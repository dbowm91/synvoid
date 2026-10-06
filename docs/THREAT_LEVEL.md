# Threat Level System

SynVoid includes an intelligent threat level system that automatically adjusts protection based on detected attack patterns and traffic behavior.

## Overview

The threat level system:
- **Learns** normal traffic patterns during a learning period
- **Detects** anomalies using statistical analysis
- **Adapts** protection levels automatically
- **Persists** historical data for long-term analysis

## Threat Levels

| Level | Name | Protection | Description |
|-------|------|------------|-------------|
| 1 | Normal | Minimum | Baseline protection |
| 2 | Elevated | Standard | Enhanced monitoring |
| 3 | High | Aggressive | Active blocking |
| 4 | Severe | Aggressive | Strict enforcement |
| 5 | Critical | Maximum | Full lockdown |

## Configuration

### Basic Configuration

```toml
[threat_level]
initial = 1
auto_scale = true
cooldown_secs = 60

[threat_level.escalation]
enabled = true
violations_before_block = 3
violation_window_secs = 300
excluded_ips = ["10.0.0.1", "10.0.0.2"]
```

### Advanced Configuration

```toml
[threat_level]
initial = 1
auto_scale = true

# Auto-scaling windows
scale_up_attacks_per_min = 50
scale_up_window_secs = 60
scale_down_attacks_per_min = 10
scale_down_window_secs = 300
cooldown_secs = 60

# Persistence cadence
persist_interval_normal_secs = 60
persist_interval_attack_secs = 15
auto_deescalate_timeout_mins = 15
```

### Fixed Runtime Parameters

The following are **not** operator-configurable. They are compile-time constants in
`src/waf/threat_level/mod.rs` (`ThreatLevelConfigExtended::from`) and are listed here so
the numbers in this document can be checked against the code:

| Parameter | Fixed value | Description |
|-----------|-------------|-------------|
| `learning_enabled` | `true` | Baseline learning is always on |
| `learning_duration_secs` | `600` | Learning period duration |
| `sigma_scale_up` | `2.0` | Standard deviations for scale up |
| `sigma_scale_down` | `0.5` | Standard deviations for scale down |
| `attack_weight` | `2.0` | Weight applied to the attack score |
| `rate_limit_weight` | `1.5` | Weight applied to the rate-limit score |
| `history_retention_days` | `365` | History retention |
| `history_flush_interval_secs` | `60` | History flush cadence |
| `use_sqlite_history` | `true` | SQLite history storage |

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `initial` | `1` | Starting threat level (1-5) |
| `auto_scale` | `true` | Enable auto-scaling |
| `scale_up_attacks_per_min` | `50` | Attacks/minute required to escalate |
| `scale_up_window_secs` | `60` | Observation window for escalation |
| `scale_down_attacks_per_min` | `10` | Attacks/minute required to de-escalate |
| `scale_down_window_secs` | `300` | Observation window for de-escalation |
| `cooldown_secs` | `60` | Cooldown between level changes |
| `persist_interval_normal_secs` | `60` | Persist cadence under normal traffic |
| `persist_interval_attack_secs` | `15` | Persist cadence under attack |
| `auto_deescalate_timeout_mins` | `15` | Idle time before automatic de-escalation |

There is no `enabled` key: the manager is constructed when the `[threat_level]` section
is present, and `GET /api/threat-level` returns `404` when no manager was built.

### Escalation Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable automatic escalation |
| `violations_before_block` | `3` | Violations before level increase |
| `violation_window_secs` | `300` | Time window for violations |
| `excluded_ips` | `["127.0.0.1", "::1"]` | IPs excluded from escalation |

`excluded_ips` is a plain list key (`excluded_ips = [...]`), not a sub-table.

### Learning Options

| Option | Default | Description |
|--------|---------|-------------|
| `learning_enabled` | `true` | Enable baseline learning (fixed, see above) |
| `learning_duration_secs` | `600` | Learning period duration (fixed, see above) |
| `sigma_scale_up` | `2.0` | Standard deviations for scale up (fixed, see above) |
| `sigma_scale_down` | `0.5` | Standard deviations for scale down (fixed, see above) |

## How It Works

### Baseline Learning

During the learning period, the system establishes a baseline:

1. Monitor normal traffic patterns
2. Record attack frequency
3. Measure rate limit triggers
4. Build statistical model

```
Learning Period (10 minutes)
       |
       v
┌──────────────────────────────────┐
│  Collect metrics:                │
│  - Requests per minute           │
│  - Attack attempts               │
│  - Rate limits triggered         │
│  - Connections per IP            │
└──────────────────────────────────┘
       |
       v
   Baseline Created
```

### Auto-Scaling

After learning, the system automatically adjusts:

```
         Attack Detected
               |
               v
    ┌─────────────────────┐
    │  Calculate Score:   │
    │  attack * 2.0       │
    │  + rate_limit * 1.5 │
    └─────────────────────┘
               |
               v
    ┌─────────────────────┐
    │  Compare to Sigma   │
    │  (baseline * 2.0)   │
    └─────────────────────┘
                |
        ________|________
               |                |
           Above Sigma      Below Sigma
               |                |
               v                v
       Increase Level     Decrease Level
```

## Admin API

### Get Current Threat Level

```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level
```

Response:
```json
{
  "level": 2,
  "score": 15.5,
  "request_score": 12.0,
  "attack_score": 9.0,
  "rate_limit_score": 4.5,
  "throttling_multiplier": 1.5,
  "is_learning": false,
  "learning_progress": 100.0,
  "has_baseline": true,
  "requests_per_second": 120.0,
  "requests_per_minute": 7200.0,
  "attacks_per_minute": 0.5,
  "rate_limit_hits": 2,
  "blocked": false
}
```

### Set Threat Level Manually

```bash
# Set to level 3
curl -X POST -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level/set/3
```

### Enable Auto Mode

```bash
curl -X POST -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level/auto
```

### Get Baseline Stats

```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level/baseline
```

Response:
```json
{
  "baselines": [
    {
      "metric_name": "attack_rate",
      "mean": 0.3,
      "std_dev": 2.5,
      "min_value": 0.0,
      "max_value": 12.0,
      "samples": 5000,
      "computed_at": 1705314600
    }
  ]
}
```

`GET /api/threat-level/baseline` returns a `baselines` array, one entry per tracked metric,
with `metric_name`, `mean`, `std_dev`, `min_value`, `max_value`, `samples` and `computed_at`.
Learning progress is reported by `GET /api/threat-level` as `is_learning` /
`learning_progress`.

### Reset and Relearn

```bash
curl -X POST -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level/reset
```

### History API

```bash
# Get threat history
curl -H "Authorization: Bearer <token>" \
  "http://localhost:8081/api/threat-level/history?limit=100"

# Get history stats
curl -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level/history/stats

# Create backup
curl -X POST -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level/history/backup

# List backups
curl -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level/history/backups

# Prune old history (default 365 days)
curl -X POST -H "Authorization: Bearer <token>" \
  "http://localhost:8081/api/threat-level/history/prune?days=90"

# Delete backup (the backup path is a query parameter)
curl -X DELETE -H "Authorization: Bearer <token>" \
  "http://localhost:8081/api/threat-level/history/backups?path=<backup_path>"
```

## Metrics

The threat level subsystem does **not** export Prometheus series. Use the admin API
(`GET /api/threat-level`, `GET /api/threat-level/baseline`, `GET /api/threat-level/history/stats`) instead.

## Threat Level Actions

Each threat level applies different actions:

| Level | Attack Response | Rate Limit | Block Duration |
|-------|----------------|------------|----------------|
| 1 | Log | Standard | 5 min |
| 2 | Log + Warn | Strict | 15 min |
| 3 | Block | Very Strict | 30 min |
| 4 | Block | Extreme | 1 hour |
| 5 | Block + IP Ban | Extreme | Permanent |

## Visual Representation

```
Threat Level Timeline
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Level:    1    2    3    4    5
          │    │    │    │    │
          │    ┌────┐   │    │
          │    │    │   │    │
          │    │ Attack  │    │
          │    │    │   │    │
          └────┘    │   │    │
                  Scale   │
                      Up   │
                         Scale
                         Up
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Troubleshooting

### Too Many Escalations

```toml
[threat_level]
scale_up_attacks_per_min = 100  # Require more attacks/minute to escalate
cooldown_secs = 300             # Longer cooldown between level changes

[threat_level.escalation]
violations_before_block = 10
```

### Not Escalating

```toml
[threat_level]
scale_up_attacks_per_min = 20  # Escalate on fewer attacks/minute
cooldown_secs = 30             # Shorter cooldown between level changes

[threat_level.escalation]
violations_before_block = 2
```

### Baseline Not Learning

1. Baseline learning is always enabled — there is no key to turn it off
2. Verify sufficient traffic (the learning period is a fixed 600 seconds)
3. Check the data directory passed to the threat level manager is writable

### High Memory Usage

SQLite history can grow large. Prune regularly:

```bash
curl -X POST -H "Authorization: Bearer <token>" \
  "http://localhost:8081/api/threat-level/history/prune?days=90"
```

## Best Practices

1. **Initial Learning** - Let system learn for 10+ minutes
2. **Exclude Internal IPs** - Add your monitoring IPs to excluded list
3. **Monitor Score** - Watch metrics to understand patterns
4. **Gradual Scaling** - Use conservative sigma values initially
5. **Regular Backups** - Backup threat history periodically
6. **Cooldown** - Set appropriate cooldown to prevent flapping

## Real-World Tuning Examples

### E-commerce Site

E-commerce sites face varied traffic patterns with seasonal spikes (Black Friday, Cyber Monday):

```toml
[threat_level]
initial = 1
auto_scale = true
cooldown_secs = 600  # Longer cooldown to prevent flapping during traffic spikes

# Require a higher sustained attack rate before escalating
scale_up_attacks_per_min = 100
scale_up_window_secs = 300

# More aggressive during attacks
[threat_level.escalation]
violations_before_block = 5  # Require more violations before escalating
violation_window_secs = 120  # Shorter window = faster response
```

**Why:** E-commerce has traffic spikes that shouldn't trigger escalations. Longer cooldown prevents the system from bouncing between levels during normal high-traffic periods.

### API Service

APIs typically have consistent traffic with sudden attack spikes:

```toml
[threat_level]
initial = 1
auto_scale = true
cooldown_secs = 300

# Faster response to attacks
scale_up_attacks_per_min = 20
scale_up_window_secs = 30

# Quick de-escalation when the attack stops
scale_down_attacks_per_min = 20
scale_down_window_secs = 120

# Faster window for API attacks
[threat_level.escalation]
violations_before_block = 2
violation_window_secs = 30  # Very responsive to attacks
```

**Why:** APIs need fast response to attacks. Shorter scaling and violation windows mean faster escalation when under attack.

### Blog or Content Site

Content sites have more predictable traffic with lower risk tolerance:

```toml
[threat_level]
initial = 1
auto_scale = true
cooldown_secs = 900  # Very stable - don't change levels frequently

# Conservative scaling
scale_up_attacks_per_min = 200
scale_up_window_secs = 600

# Focus on logging rather than blocking initially
[threat_level.escalation]
violations_before_block = 10  # Many violations before blocking
violation_window_secs = 300
```

**Why:** Content sites prioritize availability. Higher thresholds and more violations before blocking reduce false positives that could block legitimate users.

### Under Active DDoS

If you're currently under attack and need immediate response:

```toml
[threat_level]
initial = 3  # Start at level 3
auto_scale = true
cooldown_secs = 60  # Fast changes

# Very sensitive
scale_up_attacks_per_min = 5
scale_up_window_secs = 10

# Immediate escalation
[threat_level.escalation]
violations_before_block = 1
violation_window_secs = 10
```

**Why:** When under attack, you want the system to respond immediately. This configuration sacrifices some false positive tolerance for faster threat response.

## Understanding the Score

The threat score is calculated from multiple factors:

```
score = (attacks_detected * attack_weight) + (rate_limits_triggered * rate_limit_weight)
```

### Score Components

| Component | Fixed weight | Description |
|-----------|--------------|-------------|
| Attack Detection | `2.0` | Each attack detection adds `2.0` to the score |
| Rate Limiting | `1.5` | Each rate limit trigger adds `1.5` to the score |

Both weights are compile-time constants (`attack_weight: 2.0`, `rate_limit_weight: 1.5` in
`src/waf/threat_level/mod.rs`); they cannot be set from `main.toml`.

### Example Scenarios

**Normal traffic (score ~5-10):**
- Some rate limit hits from heavy users
- Occasional false positive blocks
- Score stays well below baseline

**Under attack (score ~30-100):**
- Multiple attack detections per minute
- Many rate limit triggers
- Score exceeds sigma threshold

**DDoS attack (score >100):**
- Constant attack traffic
- Rate limits constantly triggered
- Maximum threat level reached quickly

## Monitoring the Score

There is no Prometheus series for threat level or score. Read them from the admin API:

```bash
# Current threat level and score
curl -s -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level

# Baseline metrics (mean / std_dev / min / max / samples)
curl -s -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level/baseline
```

`GET /api/threat-level` returns `level`, `score`, `request_score`, `attack_score`,
`rate_limit_score`, `throttling_multiplier`, `is_learning`, `learning_progress`,
`has_baseline`, `requests_per_second`, `requests_per_minute`, `attacks_per_minute`,
`rate_limit_hits` and `blocked`.

Set up alerts for:
- Threat level changes (level 2+)
- Sustained high scores (>20 for more than 5 minutes)
- Rapid escalations (more than 3 per hour)

## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) - Flood protection details
- [RATE_LIMITING.md](./RATE_LIMITING.md) - Rate limiting integration
- [CONFIGURATION.md](./CONFIGURATION.md) - Threat level configuration
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance monitoring
