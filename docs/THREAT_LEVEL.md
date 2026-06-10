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
enabled = true
initial = 1
auto_scale = true
cooldown_secs = 300

[threat_level.escalation]
enabled = true
violations_before_block = 10
violation_window_secs = 60

[threat_level.escalation.excluded_ips]
 = ["10.0.0.1", "10.0.0.2"]
```

### Advanced Configuration

```toml
[threat_level]
initial = 1

# Learning period (baseline learning)
learning_enabled = true
learning_duration_secs = 600

# Scaling parameters
sigma_scale_up = 2.0
sigma_scale_down = 0.5

# Weight configuration
attack_weight = 2.0
rate_limit_weight = 1.5

# History settings
history_retention_days = 365
history_flush_interval_secs = 60

# SQLite storage
use_sqlite_history = true

[threat_level.persistence]
baseline_persist_path = "/var/lib/synvoid/baseline.json"
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable threat level system |
| `initial` | `1` | Starting threat level (1-5) |
| `auto_scale` | `true` | Enable auto-scaling |
| `cooldown_secs` | `300` | Cooldown between level changes |

### Escalation Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable automatic escalation |
| `violations_before_block` | `10` | Violations before level increase |
| `violation_window_secs` | `60` | Time window for violations |
| `excluded_ips` | `[]` | IPs excluded from escalation |

### Learning Options

| Option | Default | Description |
|--------|---------|-------------|
| `learning_enabled` | `true` | Enable baseline learning |
| `learning_duration_secs` | `600` | Learning period duration |
| `sigma_scale_up` | `2.0` | Standard deviations for scale up |
| `sigma_scale_down` | `0.5` | Standard deviations for scale down |

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
  "status": "auto",
  "score": 15.5,
  "baseline_score": 10.0,
  "attack_rate": 0.5,
  "rate_limit_rate": 2.0,
  "last_changed": "2024-01-15T10:30:00Z"
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
  "learning": false,
  "learning_progress": 100,
  "samples_collected": 5000,
  "baseline_attack_rate": 0.3,
  "baseline_rate_limit_rate": 1.2,
  "std_deviation": 2.5
}
```

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

# Delete backup
curl -X DELETE -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/threat-level/history/backups/backup_2024_01_01
```

## Prometheus Metrics

```bash
synvoid_threat_level_current      # Current threat level (1-5)
synvoid_threat_level_score        # Current threat score
synvoid_threat_level_baseline     # Baseline score
synvoid_threat_level_samples      # Samples collected
synvoid_threat_escalations_total  # Total escalations
synvoid_threat_deescalations_total # Total de-escalations
```

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
sigma_scale_up = 3.0  # Increase threshold
attack_weight = 1.5   # Reduce attack weight
```

### Not Escalating

```toml
[threat_level]
sigma_scale_up = 1.5  # Decrease threshold
attack_weight = 3.0   # Increase attack weight
```

### Baseline Not Learning

1. Check learning is enabled
2. Verify sufficient traffic
3. Check persistence path is writable

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
enabled = true
initial = 1
auto_scale = true
cooldown_secs = 600  # Longer cooldown to prevent flapping during traffic spikes

# Allow higher baseline variance during normal operations
sigma_scale_up = 2.5
sigma_scale_down = 0.5

# Longer learning period for traffic patterns
learning_enabled = true
learning_duration_secs = 1800  # 30 minutes

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
enabled = true
initial = 1
auto_scale = true
cooldown_secs = 300

# Faster response to attacks
sigma_scale_up = 1.5  # Lower threshold = faster escalation
attack_weight = 3.0  # Weight attacks more heavily

# Quick de-escalation when attack stops
sigma_scale_down = 0.3

# Faster window for API attacks
[threat_level.escalation]
violations_before_block = 2
violation_window_secs = 30  # Very responsive to attacks
```

**Why:** APIs need fast response to attacks. Shorter violation windows and lower sigma thresholds mean faster escalation when under attack.

### Blog or Content Site

Content sites have more predictable traffic with lower risk tolerance:

```toml
[threat_level]
enabled = true
initial = 1
auto_scale = true
cooldown_secs = 900  # Very stable - don't change levels frequently

# Conservative scaling
sigma_scale_up = 3.0
sigma_scale_down = 0.5

# Focus on logging rather than blocking initially
[threat_level.escalation]
violations_before_block = 10  # Many violations before blocking
violation_window_secs = 300

# Longer learning for consistent traffic
learning_enabled = true
learning_duration_secs = 3600  # 1 hour
```

**Why:** Content sites prioritize availability. Higher thresholds and more violations before blocking reduce false positives that could block legitimate users.

### Under Active DDoS

If you're currently under attack and need immediate response:

```toml
[threat_level]
enabled = true
initial = 3  # Start at level 3
auto_scale = true
cooldown_secs = 60  # Fast changes

# Very sensitive
sigma_scale_up = 1.0
attack_weight = 5.0
rate_limit_weight = 3.0

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

| Component | Weight Range | Description |
|-----------|--------------|-------------|
| Attack Detection | 1.0 - 5.0 | Each attack detection adds to score |
| Rate Limiting | 0.5 - 3.0 | Rate limit violations add to score |

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

Watch these metrics to understand your baseline:

```bash
# Current threat level
curl -s http://localhost:9090/metrics | grep synvoid_threat_level_current

# Current score vs baseline
curl -s http://localhost:9090/metrics | grep synvoid_threat_level_score

# Escalation rate
curl -s http://localhost:9090/metrics | grep synvoid_threat_escalations
```

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
