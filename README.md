# Caddy MIB - Caddy Middleware for IP Banning

## Overview
**Caddy MIB (Middleware IP Ban)** is a custom Caddy HTTP middleware designed to track client IPs generating repetitive errors (such as `404` or `500`) and temporarily ban them after exceeding a specified threshold. This middleware helps mitigate brute force attacks, excessive requests for non-existent resources, or other abusive behavior by blocking IPs that breach the configured error limits.

---

## Features
- **[Track Specific HTTP Error Codes](#configuration)**: Configure which HTTP error codes (e.g., `404`, `500`) to track.
- **[Set Error Thresholds](#configuration)**: Define the maximum number of errors allowed per IP before banning.
- **[Custom Ban Duration](#configuration)**: Specify how long an IP should be banned (e.g., `10m`, `1h`).
- **[Dynamic Ban Duration](#configuration)**: Increase ban duration exponentially with repeated offenses.
- **[Whitelist Trusted IPs](#configuration)**: Exempt specific IPs from banning, even if they trigger errors.
- **[Dynamic Configuration](#configuration)**: Easily configure the middleware using the Caddyfile.
- **[Debug Logging](#debugging)**: Detailed logs to track IP bans, error counts, and request statuses.
- **[Automatic Unbanning](#overview)**: Banned IPs are automatically unbanned after the ban duration expires.

---

## Requirements
- **Go 1.20 or later**
- **Caddy v2.9.0 or later**

---

## Internal Links
- **[Overview](#overview)**: Learn about the purpose and functionality of Caddy MIB.
- **[Features](#features)**: Explore the key features of the middleware.
- **[Installation](#installation)**: Step-by-step guide to install and build the middleware.
- **[Configuration](#configuration)**: Configure the middleware using the Caddyfile.
- **[Usage](#usage)**: Example scenario and testing instructions.
- **[Debugging](#debugging)**: Understand how to debug and interpret logs.
- **[License](#license)**: View the project's license.
- **[Contributions](#contributions)**: Contribute to the project.
- **[Support](#support)**: Get help and report issues.

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/fabriziosalmi/caddy-mib.git
cd caddy-mib
```

### 2. Build the Caddy Binary with MIB Module
```bash
xcaddy build --with github.com/fabriziosalmi/caddy-mib=./
```

### 3. Verify the Build
```bash
./caddy version
```
Ensure the `caddy-mib` module is included by checking the version output.

---

## Configuration

### Caddyfile Example
```Caddyfile
:8080 {
    route {
        caddy_mib {
            error_codes 404           # Error codes to track (e.g., 404, 500)
            max_error_count 5         # Number of errors allowed before banning
            ban_duration 10m          # Base duration to ban IPs (e.g., 10m, 1h)
            ban_duration_multiplier 2 # Increase ban duration exponentially (e.g., 2x)
            output stdout             # Log output (stdout or stderr)
            whitelist 192.168.1.1     # Whitelist specific IPs (comma-separated)
        }
        file_server {
            root /var/www/html        # Serve files from this directory
        }
    }
    log {
        output stdout
        format json                  # Log in JSON format
    }
}
```

### Directive Options
- **`error_codes`**: List of space-separated HTTP error codes to track (e.g., `404 500`).
- **`max_error_count`**: Maximum number of errors allowed before banning an IP.
- **`ban_duration`**: Base duration to ban IPs (supports values like `1m`, `5m`, `1h`).
- **`ban_duration_multiplier`**: Multiplier to increase ban duration exponentially with repeated offenses (e.g., `2` for 2x increase).
- **`output`**: Log output stream (`stdout` or `stderr`).
- **`whitelist`**: List of IPs to exempt from banning (e.g., `192.168.1.1`).

---

## Usage

### Example Scenario
1. A client repeatedly requests a non-existent resource (`/nonexistent-file`), resulting in `404 Not Found` errors.
2. After 5 such errors, the client's IP is banned for 10 minutes.
3. If the client continues to generate errors, the ban duration increases exponentially (e.g., 20m, 40m, etc.).
4. Whitelisted IPs are never banned, even if they trigger errors.
5. Subsequent requests from the banned IP return `403 Forbidden` until the ban expires.

### Testing
Run the following command to test the middleware:
```bash
for i in {1..7}; do curl -I http://localhost:8080/nonexistent-file; sleep 1; done
```

#### Expected Output:
- The first 5 requests return `404 Not Found`.
- The 6th and 7th requests return `403 Forbidden` (IP banned).

---

## Debugging

### Logs
Check the Caddy logs for detailed information about IP bans and request statuses:
```bash
tail -f /var/log/caddy/access.log
```

#### Example Logs:
```bash
INFO	http.handlers.caddy_mib	IP banned	{"ip": "::1", "error_code": 404, "error_count": 5, "max_error_count": 5, "ban_duration": "10m0s", "ban_expires_at": "2025-01-09T16:21:45.435Z", "path": "/nonexistent-file"}
INFO	http.handlers.caddy_mib	IP is currently banned	{"ip": "::1", "path": "/nonexistent-file", "ban_expires_at": "2025-01-09T16:21:45.435Z"}
INFO	http.handlers.caddy_mib	IP is whitelisted, skipping middleware	{"ip": "192.168.1.1", "path": "/nonexistent-file"}
```

---

## License
This project is licensed under the **AGPL-3.0 License**. See the [LICENSE](LICENSE) file for details.

---

## Contributions
Contributions are welcome! If you have suggestions, bug reports, or feature requests, please:
1. Open an issue on the [GitHub repository](https://github.com/fabriziosalmi/caddy-mib/issues).
2. Submit a pull request with your changes.

---

## Support
If you encounter any issues or have questions, please [open an issue](https://github.com/fabriziosalmi/caddy-mib/issues).
