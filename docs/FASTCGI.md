# FastCGI Support

MaluWAF supports direct FastCGI protocol proxying, providing better performance and more features than HTTP proxying for PHP-FPM and other FastCGI applications.

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

[site.upstream]
default = "http://127.0.0.1:8000"

[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"

[site.fastcgi.params]
SCRIPT_FILENAME = "$document_root$fastcgi_script_name"
SCRIPT_NAME = "$fastcgi_script_name"
```

### TCP Connection

```toml
[site.fastcgi]
enabled = true
socket = "127.0.0.1:9000"
```

### With Path Routing

```toml
[site.upstream]
default = "http://127.0.0.1:8000"

[site.upstream.routes]
"/api" = "http://api.internal:9000"
"/wordpress" = "http://wp.internal:9000"

[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"
document_root = "/var/www/html"
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable FastCGI proxy |
| `socket` | - | Unix socket or TCP address |
| `document_root` | - | Document root path |
| `index` | `"index.php"` | Default index file |

### FastCGI Parameters

These are passed to the FastCGI application:

| Parameter | Example | Description |
|-----------|---------|-------------|
| `SCRIPT_FILENAME` | `$document_root$fastcgi_script_name` | Full script path |
| `SCRIPT_NAME` | `$fastcgi_script_name` | Script name |
| `REQUEST_METHOD` | `GET/POST` | HTTP method |
| `QUERY_STRING` | `?foo=bar` | Query string |
| `CONTENT_TYPE` | `application/x-www-form-urlencoded` | Content type |
| `CONTENT_LENGTH` | `123` | Content length |
| `REQUEST_URI` | `/path` | Full request URI |
| `DOCUMENT_ROOT` | `/var/www` | Document root |
| `GATEWAY_INTERFACE` | `CGI/1.1` | Gateway interface |
| `SERVER_SOFTWARE` | `MaluWAF` | Server software |
| `REMOTE_ADDR` | `192.168.1.1` | Client IP |
| `REMOTE_PORT` | `12345` | Client port |
| `SERVER_ADDR` | `10.0.0.1` | Server IP |
| `SERVER_PORT` | `80` | Server port |
| `SERVER_NAME` | `example.com` | Server name |
| `HTTPS` | `on/off` | HTTPS status |

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
[site.fastcgi.params]
SCRIPT_FILENAME = "$document_root$fastcgi_script_name"
SCRIPT_NAME = "$fastcgi_script_name"

# Custom environment
MY_CUSTOM_VAR = "value"
APP_ENV = "production"
```

## Multiple PHP Versions

### PHP 7.4

```toml
[site.fastcgi]
enabled = true
socket = "/var/run/php74/php-fpm.sock"
```

### PHP 8.x

```toml
[site.fastcgi]
enabled = true
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
[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"
document_root = "/var/www/html"
index = "index.php index.html"
```

### Multiple Applications

```
/var/www/
├── app1/
│   └── index.php
└── app2/
    └── index.php
```

```toml
[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"

[site.fastcgi.document_roots]
"/app1" = "/var/www/app1"
"/app2" = "/var/www/app2"
```

### Front Controller Pattern (Laravel/Symfony)

```toml
[site.fastcgi]
enabled = true
socket = "/var/run/php/php-fpm.sock"
document_root = "/var/www/current/public"
index = "index.php"

[site.fastcgi.params]
SCRIPT_FILENAME = "$document_root$fastcgi_script_name"
SCRIPT_NAME = "$fastcgi_script_name"
PATH_INFO = "$fastcgi_path_info"

# Laravel-specific
LARAVEL_ENV = "production"
```

## Comparison: HTTP vs FastCGI

### HTTP Proxy
```
Client -> WAF (HTTP) -> PHP-FPM (via HTTP) -> Response
         ~30ms overhead
```

### FastCGI
```
Client -> WAF (FastCGI) -> PHP-FPM -> Response
         ~5ms overhead
```

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

### WAF FastCGI Tuning

```toml
[site.fastcgi]
timeout_secs = 60
keep_alive = true
```

## Metrics

```bash
maluwaf_fastcgi_requests_total     # Total FastCGI requests
maluwaf_fastcgi_duration_seconds   # Request duration
maluwaf_fastcgi_errors             # Errors
```

## See Also

- [GETTING_STARTED.md](./GETTING_STARTED.md) - PHP application setup workflow
- [CONFIGURATION.md](./CONFIGURATION.md) - FastCGI configuration
- [UPSTREAM_HEALTH.md](./UPSTREAM_HEALTH.md) - Health checking for backends
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging FastCGI issues
