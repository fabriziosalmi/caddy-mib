# Caddy MIB - Caddy Middleware for IP Banning

## Overview
**Caddy MIB (Middleware IP Ban)** is a custom Caddy HTTP middleware designed to track client IPs generating repetitive errors (such as `404` or `500`) and temporarily ban them after exceeding a specified threshold. This middleware helps mitigate brute force attacks, excessive requests for non-existent resources, or other abusive behavior by blocking IPs that breach the configured error limits.

---

## Features
- **[Track Specific HTTP Error Codes](#configuration)**: Configure which HTTP error codes (e.g., `404`, `500`) to track.
- **[Set Error Thresholds](#configuration)**: Define the maximum number of errors allowed per IP before banning.
- **[Custom Ban Duration](#configuration)**: Specify how long an IP should be banned (e.g., `1m`, `10m`).
- **[Dynamic Ban Duration](#configuration)**: Increase ban duration exponentially with repeated offenses.
- **[Whitelist Trusted IPs](#configuration)**: Exempt specific IPs or CIDR ranges from banning.
- **[CIDR Range Bans](#configuration)**: Ban entire CIDR ranges instead of individual IPs.
- **[Custom Ban Response](#configuration)**: Return a custom response body and header for banned IPs.
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
{
    admin off
    log {
        level debug
        output stdout
        format console
    }
}

:8080 {
    route {
        caddy_mib {
            error_codes 404           # Error codes to track (e.g., 404, 500)
            max_error_count 100       # Number of errors allowed before banning
            ban_duration 1m           # Base duration to ban IPs (e.g., 1m, 10m)
            ban_duration_multiplier 2 # Increase ban duration exponentially (e.g., 2x)
            whitelist 192.168.1.10 10.0.0.0/24 2001:db8::1 # Whitelist specific IPs or CIDR ranges
            log_level debug           # Log level for debugging
            log_request_headers User-Agent X-Forwarded-For # Log specific headers
            custom_response_header "Blocked by Caddy MIB" # Custom header for banned IPs
            ban_response_body "You have been banned due to excessive errors. Please try again later." # Custom ban response
        }
        file_server {
            root /var/www/html # Serve files from this directory
        }
    }
}
```

### Directive Options
- **`error_codes`**: List of space-separated HTTP error codes to track (e.g., `404 500`).
- **`max_error_count`**: Maximum number of errors allowed before banning an IP.
- **`ban_duration`**: Base duration to ban IPs (supports values like `1m`, `5m`, `1h`).
- **`ban_duration_multiplier`**: Multiplier to increase ban duration exponentially with repeated offenses (e.g., `2` for 2x increase).
- **`whitelist`**: List of IPs or CIDR ranges to exempt from banning (e.g., `192.168.1.10 10.0.0.0/24`).
- **`log_level`**: Log level for debugging (e.g., `debug`, `info`, `error`).
- **`log_request_headers`**: List of request headers to log (e.g., `User-Agent`, `X-Forwarded-For`).
- **`custom_response_header`**: Custom header to include in responses for banned IPs.
- **`ban_response_body`**: Custom response body to return for banned IPs.

---

## Usage

### Example Scenario
1. A client repeatedly requests a non-existent resource (`/nonexistent-file`), resulting in `404 Not Found` errors.
2. After 100 such errors, the client's IP is banned for 1 minute.
3. If the client continues to generate errors, the ban duration increases exponentially (e.g., 2m, 4m, etc.).
4. Whitelisted IPs are never banned, even if they trigger errors.
5. Subsequent requests from the banned IP return `403 Forbidden` with the custom ban response until the ban expires.

### Testing with Python
You can use the following Python script to test the middleware:

```python
import subprocess
import time
from datetime import datetime

# Configuration
URL = "http://localhost:8080/nonexistent"  # Endpoint to trigger 404 errors
MAX_ERRORS = 100  # Matches max_error_count in Caddyfile
BAN_DURATION = 120  # Matches ban_duration in Caddyfile (2 minutes)

def send_request():
    """Send a request using curl and return the HTTP status code and response body."""
    try:
        result = subprocess.run(
            ["curl", "-v", URL],
            capture_output=True,
            text=True,
            check=True,
        )
        # Extract HTTP status code
        status_code = int(result.stderr.split("HTTP/1.1 ")[1].split()[0])
        # Extract response body
        response_body = result.stdout
        return status_code, response_body
    except subprocess.CalledProcessError as e:
        # Handle cases where curl fails (e.g., banned IP)
        status_code = int(e.stderr.split("HTTP/1.1 ")[1].split()[0])
        response_body = e.stdout
        return status_code, response_body

def log(message):
    """Log a message with a timestamp."""
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    print(f"{timestamp} {message}")

def test_caddy_mib():
    log("Starting test...")

    # Send requests to trigger errors
    for i in range(MAX_ERRORS + 10):  # Send a few extra requests to test banning
        status_code, response_body = send_request()
        log(f"Request {i + 1}: Status Code = {status_code}")

        if status_code == 403:
            log("IP has been banned.")
            log(f"Ban Response: {response_body.strip()}")
            break

    # Wait for the ban to expire
    log(f"Waiting for ban to expire ({BAN_DURATION} seconds)...")
    time.sleep(BAN_DURATION)

    # Send another request to verify the ban has expired
    status_code, response_body = send_request()
    if status_code != 403:
        log("Ban has expired. IP is no longer banned.")
    else:
        log("IP is still banned.")

if __name__ == "__main__":
    test_caddy_mib()
```

#### Expected Output:
```
2025/01/11 12:42:43.733 Starting test...
2025/01/11 12:42:43.763 Request 1: Status Code = 404
2025/01/11 12:42:43.775 Request 2: Status Code = 404
...
2025/01/11 12:42:44.639 Request 101: Status Code = 403
2025/01/11 12:42:44.640 IP has been banned.
2025/01/11 12:42:44.640 Ban Response: You have been banned due to excessive errors. Please try again later.
2025/01/11 12:42:44.640 Waiting for ban to expire (120 seconds)...
2025/01/11 12:44:44.666 Ban has expired. IP is no longer banned.
```

---

## Debugging

### Logs
Check the Caddy logs for detailed information about IP bans and request statuses:
```bash
tail -f /var/log/caddy/access.log
```

#### Example Logs:
```
2025/01/11 11:42:44.621 INFO http.handlers.caddy_mib IP banned {"client_ip": "::1", "error_code": 404, "ban_expires": "2025/01/11 11:44:44.630"}
2025/01/11 11:44:44.665 INFO http.handlers.caddy_mib cleaned up expired ban {"client_ip": "::1"}
```

---

## License
This project is licensed under the **AGPL-3.0 License**. See the [LICENSE](LICENSE) file for details.

---

## Support
If you encounter any issues or have questions, please [open an issue](https://github.com/fabriziosalmi/caddy-mib/issues).


