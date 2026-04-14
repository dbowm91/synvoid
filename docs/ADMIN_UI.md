# Admin Web Interface

MaluWAF includes a comprehensive web-based admin interface built with Yew (WebAssembly), providing real-time monitoring, configuration, and management capabilities.

## Access

The admin UI is served on the admin port (default 8081):

```
http://localhost:8081
```

You will be prompted for the admin token configured in `main.toml`:

```toml
[admin]
enabled = true
port = 8081
token = "your-secure-token"
```

## Pages Overview

| Page | Description |
|------|-------------|
| Dashboard | Real-time system overview with metrics |
| Sites | Manage protected websites |
| Site Editor | Configure individual site settings |
| Upstreams | Monitor upstream server health |
| Request Logs | View detailed request logs |
| Logs | System logs and diagnostics |
| TCP/UDP | TCP/UDP proxy configuration |
| Probes | Network probe statistics |
| Threat Level | Configure threat detection levels |
| Settings | System configuration |

## Theme Support

The admin UI supports multiple color themes:

- **Dark** (default) - Dark background with teal accents
- **Light** - Light background with green accents
- **Ocean** - Blue-themed dark variant
- **Forest** - Green-themed dark variant
- **Sunset** - Orange-themed dark variant

To change themes, click the theme button in the sidebar footer.

## Dashboard

The main dashboard provides an overview of system health and traffic.

### Features

- **Request Statistics** - Total, blocked, stalled, challenged requests
- **Attack Distribution** - Stacked area chart of attack types
- **Threat Level** - Current threat level with controls
- **Active Connections** - Real-time connection count
- **Request Rate** - Requests per second graph
- **Response Codes** - HTTP response code distribution
- **System Resources** - CPU and memory usage gauges
- **Backend Status** - Healthy/unhealthy upstream counts

### Time Windows

Select different time ranges for charts:
- 1m, 5m, 15m, 1h

### Connection Status

The dashboard shows connection status:
- **Live** (green) - WebSocket connected
- **Connecting** (yellow) - Connecting to WebSocket
- **Polling** (blue) - Fallback to HTTP polling
- **Error** (red) - Connection error

## Sites Management

### Features

- **Site List** - View all configured sites in card layout
- **Quick Stats** - Per-site request/block counts
- **Enable/Disable** - Toggle site protection
- **Add Site** - Create new site configuration
- **Delete Site** - Remove site configuration with confirmation dialog

### Delete Confirmation

When deleting a site, a confirmation dialog appears to prevent accidental deletions. This ensures you don't accidentally remove important configurations.

### Per-Site Bandwidth

The Sites Status panel on the dashboard shows bandwidth breakdown for each site. Click on a site row to expand and view detailed ingress/egress metrics:

```
┌─────────────────────────────────────────────────────────────┐
│ Sites Status                                              │
├─────────────────────────────────────────────────────────────┤
│ ● example.com      1.2K req   342 blocked  Healthy     ▼ │
│ ├─ Ingress:     2.4 GB                                  │
│ │   Client:      1.8 GB                                  │
│ │   Proxied:    512 MB                                  │
│ │   Mesh:        128 MB                                  │
│ ├─ Egress:      4.1 GB                                  │
│ │   Response:    890 MB                                  │
│ │   Proxied:    2.9 GB                                  │
│ │   Mesh:        312 MB                                  │
└─────────────────────────────────────────────────────────────┘
```

**Bandwidth Categories:**

- **Ingress (received from clients)**
  - *Client*: Raw request data from end users
  - *Proxied*: Response data from direct origin connections
  - *Mesh*: Response data from mesh peer proxies

- **Egress (sent to clients)**
  - *Response*: Block pages, challenges, error responses
  - *Proxied*: Request data forwarded to direct origins
  - *Mesh*: Request data forwarded to mesh peers

This breakdown helps identify traffic patterns and is essential for environments with bandwidth limits or per-site billing.

## Site Editor

Configure individual site settings including:

- **Domains** - Domain list
- **Upstream** - Backend server configuration
- **Attack Detection** - Enable/disable detection types
- **Rate Limiting** - Per-site rate limits
- **Bot Protection** - Bot detection settings
- **Blocked Paths** - Path blocking rules
- **Custom Headers** - Header manipulation
- **Route Rules** - Path-based configuration

## Request Logs

### Features

- **Real-time Logs** - Live request stream via WebSocket
- **Filtering** - Filter by status, IP, site, attack type
- **Search** - Full-text search across log entries
- **Sorting** - Sort by any column
- **Pagination** - Navigate through large log sets
- **Details** - Expand for full request/response details
- **Export** - Download logs

### Data Table Features

The request logs table includes:
- Searchable columns
- Sortable headers (click to sort)
- Pagination controls
- Empty state handling

## Upstreams

### Features

- **Health Status** - Upstream server status
- **Response Time** - Latency per upstream
- **Request Count** - Total requests per upstream
- **Error Rate** - Failed request percentage

### Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  Upstreams                                                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ http://127.0.0.1:8000                    [Healthy ●]    │   │
│  │ Response Time: 12ms | Requests: 45,231 | Errors: 0.1%  │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │ http://10.0.0.5:8000                     [Degraded ●]   │   │
│  │ Response Time: 234ms | Requests: 12,345 | Errors: 5.2% │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Logs

### Features

- **System Logs** - MaluWAF internal logs
- **Log Levels** - Filter by debug, info, warn, error
- **Search** - Search log entries
- **Download** - Export log files

## TCP/UDP Configuration

### Features

- **TCP Listeners** - View configured TCP proxies
- **UDP Listeners** - View configured UDP proxies
- **Protocol Filters** - Protocol mismatch settings

## Probes

### Features

- **Network Probes** - TCP protocol detection stats
- **Protocol Statistics** - What protocols were detected
- **Stalled Connections** - Protocol mismatch handling

## Threat Level

Configure global threat detection sensitivity levels (0-3):
- Level 0 - Disabled
- Level 1 - Low (critical threats only)
- Level 2 - Medium (recommended)
- Level 3 - High (aggressive blocking)

## Settings

### Features

- **Main Config** - Edit main.toml
- **Attack Detection** - Global detection settings
- **Flood Protection** - Flood settings
- **Logging** - Log configuration
- **Metrics** - Prometheus settings
- **Search** - Quick search across settings

### Form Validation

Input fields now include:
- Required field indicators (red asterisk)
- Error states with red borders
- Error messages below fields
- Disabled states for read-only inputs
- Help text support

## User Feedback

### Toast Notifications

Actions trigger toast notifications in the top-right corner:
- Success (green) - Operations completed successfully
- Error (red) - Operation failed
- Warning (yellow) - Warnings
- Info (blue) - Informational messages

### Loading States

- **Skeleton Loaders** - Animated placeholders during data load
- **Loading Spinners** - Simple spinner for quick operations
- **Empty States** - Helpful messages when no data

### Confirmation Dialogs

Destructive actions (like deleting sites) show confirmation dialogs to prevent accidents.

## Real-time Updates

The admin UI uses WebSocket for real-time updates:

### Metrics WebSocket

```
ws://localhost:8081/api/ws/metrics
```

### Logs WebSocket

```
ws://localhost:8081/api/logs/realtime
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+K` | Quick search |
| `Ctrl+R` | Refresh data |
| `Esc` | Close modal |

## Security

### Authentication

All pages require authentication via admin token. The token is stored in browser session storage.

### HTTPS

For production, enable TLS on admin port:

```toml
[admin]
enabled = true
port = 8443

[tls]
enabled = true
cert_path = "/etc/maluwaf/certs/admin.crt"
key_path = "/etc/maluwaf/certs/admin.key"
```

## Customization

### Theme

The UI supports multiple themes with accent colors. Toggle via the theme button in the sidebar footer. Each theme has:
- Custom accent color
- Matching background shades
- Consistent styling

### Refresh Rate

Configure data refresh intervals in settings.

## Troubleshooting

### UI Not Loading

1. Check admin port is correct
2. Verify admin is enabled in config
3. Check token is correct
4. Review browser console for errors

### Slow Performance

1. Reduce log buffer size
2. Decrease refresh rate
3. Limit displayed entries

### WebSocket Issues

1. Check browser supports WebSocket
2. Verify no proxy blocking websockets
3. Check network connectivity

## Building the Admin UI

The admin UI is built with Trunk:

```bash
# Build admin UI
cd admin-ui
trunk build

# Development with hot reload
trunk serve
```

The built assets are embedded in the MaluWAF binary.

## Technology Stack

- **Framework**: Yew 0.22 (Rust WebAssembly)
- **Styling**: Tailwind CSS 2.2
- **Routing**: yew-router
- **HTTP/WebSocket**: gloo
- **Build Tool**: Trunk
- **Fonts**: Inter (UI), JetBrains Mono (code)

## API Integration

The admin UI communicates with the MaluWAF Admin API. All operations are available via REST endpoints documented in the main README.

## See Also

- [API_REFERENCE.md](./API_REFERENCE.md) - Admin API documentation
- [CONFIGURATION.md](./CONFIGURATION.md) - Admin configuration options
- [GETTING_STARTED.md](./GETTING_STARTED.md) - Quick start guide
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Admin UI issues
