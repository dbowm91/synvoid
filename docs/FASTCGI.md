# FastCGI Support

SynVoid supports direct FastCGI protocol proxying, providing better performance and more features than HTTP proxying for PHP-FPM and other FastCGI applications.

## Why FastCGI?

| Feature             | HTTP Proxy      | FastCGI       |
|---------------------|-----------------|---------------|
| Latency             | Lower           | Lowest        |
| Keep-alive          | Limited         | Full          |
| PHP-FPM Features    | Partial         | Full          |
| Path Info           | Manual          | Auto          |
| Environment         | Limited         | Complete      |

## Configuration

### Basic FastCGI Setup

```toml
# config/sites/example.com.toml
[site]
domains = ["example.com", "www.example.com"]

[site.proxy.upstream]
servers = ["http://127.0.0.1:8000"]

[site.proxy.fastcgi]
socket = "/var/run/php/php-fpm.sock"

[site.proxy.fastcgi.params]
SCRIPT_FILENAME = "/var/www/html/index.php"
SCRIPT_NAME = "/index.php"
```

The FastCGI block lives under `[site.proxy]` — there is no top-level `[site.fastcgi]`
section, and there is no `enabled` flag: the handler is selected because `socket` is set.
`[site.upstream]` and `default = ...` do not exist; upstreams are `[site.proxy.upstream]`
with a `servers` array.

### TCP Connection

```toml
[site.proxy.fastcgi]
socket = "127.0.0.1:9000"
```

### With a Separate HTTP Upstream

FastCGI is one backend inside `[site.proxy]`; the HTTP upstreams are configured on the
same section:

```toml
[site.proxy.upstream]
servers = ["http://127.0.0.1:8000"]
backup_servers = ["http://127.0.0.1:8001"]

[site.proxy.fastcgi]
socket = "/var/run/php/php-fpm.sock"
script_filename = "/var/www/html/index.php"
index = "index.php"
```

There is no `[site.upstream.routes]` or path-prefix routing table; per-path routing is
done with `[site.proxy.locations]`, each of which may carry its own `fastcgi` block.

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `socket` | - | Unix socket path or `host:port` (required; selects FastCGI) |
| `script_filename` | - | Script passed to PHP-FPM |
| `index` | - | Default index file |
| `params` | - | Extra FastCGI params (map) |
| `env_vars` | - | Environment variables (map) |
| `split_path_info` | - | Regex used to split `PATH_INFO` from the script name |
| `try_files` | - | Fallback file list |
| `connect_timeout` / `send_timeout` / `read_timeout` | - | Per-hop timeouts (seconds) |
| `max_connections` | - | Connection cap for this backend |

There is no `enabled`, `document_root`, `document_roots`, `timeout_secs`, or `keep_alive`
key — unknown keys are ignored, so a block written with them silently does nothing.

### FastCGI Parameters

`[site.proxy.fastcgi.params]` is a plain `HashMap<String, String>` that is passed through
to the FastCGI params record. **SynVoid does not expand variables** such as
`$document_root` or `$fastcgi_script_name` — no expansion exists in the request path, so
those strings would be sent to PHP-FPM verbatim. Use literal values (or values your
upstream resolves).

| Parameter | Example | Description |
|-----------|---------|-------------|
| `SCRIPT_FILENAME` | `/var/www/html/index.php` | Full script path |
| `SCRIPT_NAME` | `/index.php` | Script name |
| `REQUEST_METHOD` | `GET/POST` | HTTP method |
| `QUERY_STRING` | `?foo=bar` | Query string |
| `CONTENT_TYPE` | `application/x-www-form-urlencoded` | Content type |
| `CONTENT_LENGTH` | `123` | Content length |
| `REQUEST_URI` | `/path` | Full request URI |
| `REMOTE_ADDR` | `192.168.1.1` | Client IP |
| `SERVER_NAME` | `example.com` | Server name |
| `SERVER_PORT` | `80` | Server port |

Parameters such as `DOCUMENT_ROOT`, `GATEWAY_INTERFACE`, and `SERVER_SOFTWARE` are not
populated automatically — declare them explicitly in `params` if your application needs
them.

## PHP-FPM Configuration

### Pool Configuration (/etc/php-fpm.d/www.conf)

```ini
[www]
listen = /var/run/php/php-fpm.sock
listen.mode = 0660
listen.owner = nginx
listen.group = nginx

pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35

php_admin_value[error_log] = /var/log/php-fpm/www-error.log
slowlog = /var/log/php-fpm/www-slow.log
request_slowlog_timeout = 10s
```

### Environment Variables

```toml
[site.proxy.fastcgi.params]
SCRIPT_FILENAME = "/var/www/html/index.php"
SCRIPT_NAME = "/index.php"

# Custom environment (goes in env_vars, not params)
[site.proxy.fastcgi.env_vars]
MY_CUSTOM_VAR = "value"
APP_ENV = "production"
```

## Multiple PHP Versions

### PHP 7.4

```toml
[site.proxy.fastcgi]
socket = "/var/run/php74/php-fpm.sock"
```

### PHP 8.x

```toml
[site.proxy.fastcgi]
socket = "/var/run/php80/php-fpm.sock"
```

## Routing Examples

### Single Application

```
/var/www/html/
├── index.php
├── wp-config.php
└── ...
```

```toml
[site.proxy.fastcgi]
socket = "/var/run/php/php-fpm.sock"
script_filename = "/var/www/html/index.php"
index = "index.php"
```

### Multiple Applications

```
/var/www/
├── app1/
│   └── index.php
└── app2/
    └── index.php
```

Multiple applications are served with `[[proxy.locations]]`, each pointing at its own
FastCGI handler. Per-location FastCGI settings go **inside** the element as an inline table.

> The array-index sub-table form (`[[proxy.locations]]` followed by
> `[proxy.locations[0].fastcgi]`) is **rejected by SynVoid's TOML parser**, and the table path
> is top-level `proxy`, not `site.proxy`. There is no `[site.fastcgi.document_roots]` mapping
> table and no `root` key on a location.

```toml
[[proxy.locations]]
path = "/app1/"
fastcgi = { socket = "/var/run/php/php-fpm.sock", script_filename = "/var/www/app1/index.php" }

[[proxy.locations]]
path = "/app2/"
```

### Front Controller Pattern (Laravel/Symfony)

```toml
[site.proxy.fastcgi]
socket = "/var/run/php/php-fpm.sock"
script_filename = "/var/www/current/public/index.php"
index = "index.php"
split_path_info = "^/var/www/current/public/(.+)\\.php$"

[site.proxy.fastcgi.params]
SCRIPT_FILENAME = "/var/www/current/public/index.php"
SCRIPT_NAME = "/index.php"

# Laravel-specific
[site.proxy.fastcgi.env_vars]
LARAVEL_ENV = "production"
```

## Comparison: HTTP vs FastCGI

### HTTP Proxy
```
Client -> WAF (HTTP) -> PHP-FPM (via HTTP) -> Response
```

### FastCGI
```
Client -> WAF (FastCGI) -> PHP-FPM -> Response
```

The protocol difference is real (a persistent FastCGI connection avoids per-request
protocol overhead), but SynVoid ships no latency benchmark for either path, so treat
the expected win as directional, not quantified. Measure on your own hardware before
committing to a migration.

## Troubleshooting

### 502 Bad Gateway

1. Check PHP-FPM is running:
```bash
systemctl status php-fpm
```

2. Verify socket permissions:
```bash
ls -la /var/run/php/php-fpm.sock
```

3. Test connection:
```bash
SCRIPT_NAME=/ SCRIPT_FILENAME=/var/www/html/index.php REQUEST_METHOD=GET \
  cgi-fcgi -bind -connect /var/run/php/php-fpm.sock
```

### 504 Gateway Timeout

1. Check PHP-FPM process limits
2. Increase `request_terminate_timeout`
3. Check for slow queries

### File Not Found (404)

1. Verify `SCRIPT_FILENAME` path
2. Check `document_root` matches
3. Ensure file exists in document root

### Permission Denied

```bash
# Fix socket ownership
chown nginx:nginx /var/run/php/php-fpm.sock

# Or configure PHP-FPM to use correct group
listen.group = nginx
```

## Security

### Isolated Pools

Create separate PHP-FPM pools for each site:

```ini
[example_com]
listen = /var/run/php/example_com.sock
listen.owner = nginx
user = example_user
group = example_group
```

### Disable Functions

In php.ini:
```ini
disable_functions = exec,passthru,shell_exec,system
```

### Open BaseDir

```ini
open_basedir = /var/www/html:/tmp:/usr/share
```

## Performance

### PHP-FPM Tuning

```ini
pm = ondemand
pm.max_children = 100
pm.process_idle_timeout = 10s
pm.max_requests = 500
```

### FastCGI Tuning

```toml
[site.proxy.fastcgi]
connect_timeout = 5
send_timeout = 60
read_timeout = 60
max_connections = 256
```

There is no `timeout_secs` or `keep_alive` key on the FastCGI block; unknown keys are
ignored silently.

## Metrics

No `synvoid_fastcgi_*` metric family is registered. FastCGI outcomes are visible through
the admin metrics API and the error-page/status handling (502 / 504 responses).

```bash
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8081/api/metrics
```

## See Also

- [GETTING_STARTED.md](./GETTING_STARTED.md) - PHP application setup workflow
- [CONFIGURATION.md](./CONFIGURATION.md) - FastCGI configuration
- [UPSTREAM_HEALTH.md](./UPSTREAM_HEALTH.md) - Health checking for backends
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging FastCGI issues
