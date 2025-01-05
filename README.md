# Caddy MIB - Middleware for IP Banning

## Overview
Caddy MIB (Middleware IP Ban) is a custom Caddy HTTP middleware that tracks client IPs generating repetitive errors (such as 404 and 500) and temporarily bans them after exceeding a specified threshold.

The middleware helps mitigate brute force attacks or excessive requests for non-existent resources by blocking IPs that breach the configured error limits.

## Features
- Track specific HTTP error codes (e.g., 404, 500)
- Set maximum allowed error counts per IP before banning
- Define ban duration for violating IPs
- Supports dynamic configuration through Caddyfile
- Debug logging to track IP bans and request status

## Requirements
- Go 1.20 or later
- Caddy v2.9.0 or later

## Installation

### 1. Clone the Repository
```bash
$ git clone https://github.com/fabriziosalmi/caddy-mib.git
$ cd caddy-mib
```

### 2. Build the Caddy Binary with MIB Module
```bash
$ xcaddy build --with github.com/fabriziosalmi/caddy-mib=./
```

### 3. Use the Custom Caddy Build
```bash
$ ./caddy version
```
Ensure the module is included by checking the version output.

## Configuration

### Caddyfile Example
```Caddyfile
:8080 {
    route {
        caddy_mib {
            error_codes 404           # Error codes to track
            max_error_count 5         # Number of errors allowed before ban (1 is added internally)
            ban_duration 10m          # Ban duration for violating IPs
            output stdout             # Log output (stdout/stderr)
        }
        file_server {
            root /var/www/html
        }
    }
    log {
        output stdout
        format json
    }
}
```

### Directive Options
- **error_codes** - List of space-separated HTTP error codes to track (e.g., 404 500).
- **max_error_count** - Maximum allowed errors before banning (internally increments by +1 to ensure tolerance).
- **ban_duration** - Duration to ban IPs (supports values like 1m, 5m, 1h).
- **output** - Log output stream (`stdout` or `stderr`).

## Testing
```bash
for i in {1..7}; do curl -I http://localhost:8080/nonexistent-file; sleep 1; done
```

- 5 requests with 404 will trigger the IP ban.
- Additional requests will return a 403 Forbidden until the ban expires.

## Debugging
Check Caddy logs for detailed IP ban info:
```bash
$ tail -f /var/log/caddy/access.log
```

Look for lines like:
```bash
INFO	http.handlers.caddy_mib	IP banned due to excessive 404 errors
INFO	http.handlers.caddy_mib	IP is currently banned
```

## License
AGPL3 License

## Contributions
Pull requests are welcome! Open an issue for feature suggestions or bug reports.

