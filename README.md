# traefik-threath-plugin

A Traefik middleware plugin for detecting and blocking potential security threats based on URL patterns and IP tracking.

## Features

- **Threat Detection**: Identifies common attack patterns including:
  - WordPress admin panels (`/wp-admin`, `/wp-login.php`)
  - Database administration interfaces (`/phpmyadmin`, `/adminer`)
  - Common exploit paths (`/.env`, `/.git`, `/config`)
  - Admin interfaces (`/admin`, `/administrator`, `/console`)
  
- **IP Tracking & Blocking**: Tracks suspicious IPs and automatically bans them after multiple threat attempts

- **Prometheus Metrics**: Exports metrics for monitoring:
  - `traefik_threat_plugin_banned_ips_total`: Total number of currently banned IP addresses
  - `traefik_threat_plugin_threat_attempts_total`: Total number of threat attempts detected

- **Configurable**: Customize threat patterns, ban duration, and attempt thresholds

## Installation

Add the plugin to your Traefik static configuration:

### Static Configuration (YAML)

```yaml
experimental:
  plugins:
    traefik-threath-plugin:
      moduleName: github.com/CangioUni/traefik-threath-plugin
      version: v1.0.0
```

### Static Configuration (TOML)

```toml
[experimental.plugins.traefik-threath-plugin]
  moduleName = "github.com/CangioUni/traefik-threath-plugin"
  version = "v1.0.0"
```

### Static Configuration (CLI)

```bash
--experimental.plugins.traefik-threath-plugin.modulename=github.com/CangioUni/traefik-threath-plugin
--experimental.plugins.traefik-threath-plugin.version=v1.0.0
```

## Configuration

### Dynamic Configuration (YAML)

```yaml
http:
  middlewares:
    threat-detector:
      plugin:
        traefik-threath-plugin:
          enabled: true
          maxAttempts: 5
          banDuration: 3600  # seconds (1 hour)
          threatPatterns:
            - "/wp-admin"
            - "/wp-login.php"
            - "/admin"
            - "/phpmyadmin"
            - "/.env"
            - "/.git"
            
  routers:
    my-router:
      rule: "Host(`example.com`)"
      middlewares:
        - threat-detector
      service: my-service
```

### Dynamic Configuration (TOML)

```toml
[http.middlewares.threat-detector.plugin.traefik-threath-plugin]
  enabled = true
  maxAttempts = 5
  banDuration = 3600
  threatPatterns = [
    "/wp-admin",
    "/wp-login.php", 
    "/admin",
    "/phpmyadmin",
    "/.env",
    "/.git"
  ]

[http.routers.my-router]
  rule = "Host(`example.com`)"
  middlewares = ["threat-detector"]
  service = "my-service"
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable or disable the plugin |
| `maxAttempts` | int | `5` | Maximum number of threat attempts before banning an IP |
| `banDuration` | int | `3600` | Duration in seconds for which an IP is banned (default: 1 hour) |
| `threatPatterns` | []string | (see below) | List of URL patterns to detect as threats |

### Default Threat Patterns

If not specified, the plugin uses these default patterns:

- `/wp-admin`
- `/wp-login.php`
- `/wp-login`
- `/admin`
- `/administrator`
- `/phpmyadmin`
- `/pma`
- `/mysql`
- `/db`
- `/adminer`
- `/.env`
- `/config`
- `/backup`
- `/sftp-config.json`
- `/.git`
- `/console`

## Prometheus Metrics

The plugin exposes Prometheus metrics at the `/metrics` endpoint:

```
# HELP traefik_threat_plugin_banned_ips_total Total number of currently banned IP addresses
# TYPE traefik_threat_plugin_banned_ips_total gauge
traefik_threat_plugin_banned_ips_total 5

# HELP traefik_threat_plugin_threat_attempts_total Total number of threat attempts detected
# TYPE traefik_threat_plugin_threat_attempts_total counter
traefik_threat_plugin_threat_attempts_total 42
```

You can scrape these metrics with Prometheus:

```yaml
scrape_configs:
  - job_name: 'traefik'
    static_configs:
      - targets: ['traefik:8080']
```

## How It Works

1. **Request Inspection**: Each incoming request is checked against the configured threat patterns
2. **IP Tracking**: When a threat is detected, the source IP is recorded
3. **Automatic Banning**: After `maxAttempts` threats from the same IP, subsequent requests are blocked with HTTP 403
4. **Ban Expiry**: Bans automatically expire after `banDuration` seconds
5. **Cleanup**: Expired bans are cleaned up automatically every minute

## IP Extraction

The plugin extracts client IPs from:
1. `X-Forwarded-For` header (uses the first IP)
2. `X-Real-IP` header
3. `RemoteAddr` (fallback)

This ensures accurate IP tracking even when behind proxies or load balancers.

## Example Use Case

Protect your application from common attacks:

```yaml
http:
  middlewares:
    security:
      plugin:
        traefik-threath-plugin:
          enabled: true
          maxAttempts: 3  # More strict
          banDuration: 7200  # 2 hours
          threatPatterns:
            - "/wp-admin"
            - "/wp-login"
            - "/.env"
            - "/admin"
            
  routers:
    api:
      rule: "Host(`api.example.com`)"
      middlewares:
        - security
      service: api-service
```

## Development

### Build

```bash
go build -v .
```

### Test

```bash
go test -v ./...
```

### Test with Race Detector

```bash
go test -v -race ./...
```

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
