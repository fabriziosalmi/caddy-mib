# Caddy MIB - Caddy Middleware for IP Banning

## Overview
**Caddy MIB (Middleware IP Ban)** is a custom Caddy HTTP middleware designed to track client IPs generating repetitive errors (such as `404` or `500`) and temporarily ban them after exceeding a specified threshold. This middleware helps mitigate brute force attacks, excessive requests for non-existent resources, or other abusive behavior by blocking IPs that breach the configured error limits.

---

## Features
- **[Track Specific HTTP Error Codes](#configuration)**: Configure which HTTP error codes (e.g., `404`, `500`) to track.
- **[Set Error Thresholds](#configuration)**: Define the maximum number of errors allowed per IP before banning.
- **[Custom Ban Duration](#configuration)**: Specify how long an IP should be banned (e.g., `5s`, `10s`).
- **[Dynamic Ban Duration](#configuration)**: Increase ban duration exponentially with repeated offenses.
- **[Whitelist Trusted IPs](#configuration)**: Exempt specific IPs or CIDR ranges from banning.
- **[Per-Path Configuration](#configuration)**: Define custom error thresholds and ban durations for specific paths.
- **[Custom Ban Response](#configuration)**: Return a custom response body and header for banned IPs.
- **[Configurable Ban Status Code](#configuration)**: Set a custom HTTP status code for banned IPs (e.g., `403 Forbidden` or `429 Too Many Requests`).
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
            error_codes 404 500 401      # Error codes to track
            max_error_count 10           # Global error threshold (reduced for faster testing)
            ban_duration 5s              # Global ban duration (reduced to 5 seconds)
            ban_duration_multiplier 1    # Global ban duration multiplier
            whitelist 192.168.1.10       # Whitelisted IPs
            log_level debug              # Log level for debugging
            ban_response_body "You have been banned due to excessive errors. Please try again later."
            ban_status_code 429          # Custom status code for banned IPs

            # Per-path configuration for /login
            per_path /login {
                error_codes 404          # Error codes to track for /login
                max_error_count 5        # Error threshold for /login (reduced for faster testing)
                ban_duration 10s         # Ban duration for /login (reduced to 10 seconds)
                ban_duration_multiplier 1
            }

            # Per-path configuration for /api
            per_path /api {
                error_codes 404 500      # Error codes to track for /api
                max_error_count 8        # Error threshold for /api (reduced for faster testing)
                ban_duration 15s         # Ban duration for /api (reduced to 15 seconds)
                ban_duration_multiplier 1
            }
        }
        file_server {
            root /var/www/html           # Serve files from this directory
        }
    }
}
```

### Directive Options
- **`error_codes`**: List of space-separated HTTP error codes to track (e.g., `404 500 401`).
- **`max_error_count`**: Maximum number of errors allowed before banning an IP.
- **`ban_duration`**: Base duration to ban IPs (supports values like `5s`, `10s`, `1m`).
- **`ban_duration_multiplier`**: Multiplier to increase ban duration exponentially with repeated offenses (e.g., `1` for no increase).
- **`whitelist`**: List of IPs or CIDR ranges to exempt from banning (e.g., `192.168.1.10`).
- **`log_level`**: Log level for debugging (e.g., `debug`, `info`, `error`).
- **`ban_response_body`**: Custom response body to return for banned IPs.
- **`ban_status_code`**: Custom HTTP status code to return for banned IPs (e.g., `429`).

#### Per-Path Configuration
- **`per_path`**: Define custom error thresholds and ban durations for specific paths.
  - **`error_codes`**: Error codes to track for the specific path.
  - **`max_error_count`**: Maximum number of errors allowed for the specific path.
  - **`ban_duration`**: Ban duration for the specific path.
  - **`ban_duration_multiplier`**: Multiplier for ban duration on repeated offenses.

---

## Usage

### Example Scenario
1. A client repeatedly requests a non-existent resource (`/nonexistent-file`), resulting in `404 Not Found` errors.
2. After 10 such errors, the client's IP is banned for 5 seconds.
3. If the client continues to generate errors, the ban duration remains the same (no multiplier).
4. Whitelisted IPs (e.g., `192.168.1.10`) are never banned, even if they trigger errors.
5. Subsequent requests from the banned IP return the configured status code (e.g., `429 Too Many Requests`) with the custom ban response until the ban expires.

### Testing with Python
You can use the following Python script to test the middleware:

```python
import subprocess
import time
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configuration
BASE_URL = "http://localhost:8080"
NONEXISTENT_URL = f"{BASE_URL}/nonexistent"  # Endpoint to trigger 404 errors
LOGIN_URL = f"{BASE_URL}/login"             # Endpoint to trigger 401/403 errors
API_URL = f"{BASE_URL}/api"                 # Endpoint to trigger 404/500 errors

# Global settings
GLOBAL_MAX_ERRORS = 10  # Matches max_error_count in Caddyfile
GLOBAL_BAN_DURATION = 5  # Matches ban_duration in Caddyfile (5 seconds)

# Per-path settings
LOGIN_MAX_ERRORS = 5  # Matches max_error_count for /login
LOGIN_BAN_DURATION = 10  # Matches ban_duration for /login (10 seconds)
API_MAX_ERRORS = 8  # Matches max_error_count for /api
API_BAN_DURATION = 15  # Matches ban_duration for /api (15 seconds)

def send_request(url):
    """Send a request using curl and return the HTTP status code and response body."""
    try:
        result = subprocess.run(
            ["curl", "-v", url],
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
        if "HTTP/1.1 " in e.stderr:
            status_code = int(e.stderr.split("HTTP/1.1 ")[1].split()[0])
            response_body = e.stdout
            return status_code, response_body
        else:
            log(f"Error: {e.stderr}")
            return 0, "Server unreachable or other error"
    except Exception as e:
        log(f"Unexpected error: {e}")
        return 0, "Unexpected error"

def log(message):
    """Log a message with a timestamp."""
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    print(f"{timestamp} {message}")

def test_global_ban():
    """Test global error tracking and banning."""
    log("Starting global ban test...")
    success = True

    # Send requests to trigger errors
    for i in range(GLOBAL_MAX_ERRORS + 2):  # Send a few extra requests to test banning
        status_code, response_body = send_request(NONEXISTENT_URL)
        log(f"Request {i + 1}: Status Code = {status_code}")

        if status_code == 429:  # Custom status code for banned IPs
            log("IP has been banned globally.")
            log(f"Ban Response: {response_body.strip()}")
            break
        elif status_code == 0:
            log("Failed to send request. Aborting test.")
            success = False
            return success

    # Wait for the ban to expire
    log(f"Waiting for global ban to expire ({GLOBAL_BAN_DURATION} seconds)...")
    time.sleep(GLOBAL_BAN_DURATION)

    # Send another request to verify the ban has expired
    status_code, response_body = send_request(NONEXISTENT_URL)
    if status_code != 429:
        log("Global ban has expired. IP is no longer banned.")
    else:
        log("IP is still banned globally.")
        success = False

    return success

def test_login_ban():
    """Test per-path error tracking and banning for /login."""
    log("Starting /login ban test...")
    success = True

    # Send requests to trigger errors
    for i in range(LOGIN_MAX_ERRORS + 2):  # Send a few extra requests to test banning
        status_code, response_body = send_request(LOGIN_URL)
        log(f"Request {i + 1}: Status Code = {status_code}")

        if status_code == 429:  # Custom status code for banned IPs
            log("IP has been banned for /login.")
            log(f"Ban Response: {response_body.strip()}")
            break
        elif status_code == 0:
            log("Failed to send request. Aborting test.")
            success = False
            return success

    # Wait for the ban to expire
    log(f"Waiting for /login ban to expire ({LOGIN_BAN_DURATION} seconds)...")
    time.sleep(LOGIN_BAN_DURATION)

    # Send another request to verify the ban has expired
    status_code, response_body = send_request(LOGIN_URL)
    if status_code != 429:
        log("/login ban has expired. IP is no longer banned.")
    else:
        log("IP is still banned for /login.")
        success = False

    return success

def test_api_ban():
    """Test per-path error tracking and banning for /api."""
    log("Starting /api ban test...")
    success = True

    # Send requests to trigger errors
    for i in range(API_MAX_ERRORS + 2):  # Send a few extra requests to test banning
        status_code, response_body = send_request(API_URL)
        log(f"Request {i + 1}: Status Code = {status_code}")

        if status_code == 429:  # Custom status code for banned IPs
            log("IP has been banned for /api.")
            log(f"Ban Response: {response_body.strip()}")
            break
        elif status_code == 0:
            log("Failed to send request. Aborting test.")
            success = False
            return success

    # Wait for the ban to expire
    log(f"Waiting for /api ban to expire ({API_BAN_DURATION} seconds)...")
    time.sleep(API_BAN_DURATION)

    # Send another request to verify the ban has expired
    status_code, response_body = send_request(API_URL)
    if status_code != 429:
        log("/api ban has expired. IP is no longer banned.")
    else:
        log("IP is still banned for /api.")
        success = False

    return success

def print_summary(test_name, success):
    """Print a summary of the test result with colored output."""
    if success:
        print(f"{Fore.GREEN}[PASS]{Style.RESET_ALL} {test_name}")
    else:
        print(f"{Fore.RED}[FAIL]{Style.RESET_ALL} {test_name}")

if __name__ == "__main__":
    # Run all tests and collect results
    results = {
        "Global Ban Test": test_global_ban(),
        "Login Ban Test": test_login_ban(),
        "API Ban Test": test_api_ban(),
    }

    # Print summary
    print("\n=== Test Summary ===")
    for test_name, success in results.items():
        print_summary(test_name, success)
```

#### Expected Output:
```
2025/01/11 12:42:43.733 Starting global ban test...
2025/01/11 12:42:43.763 Request 1: Status Code = 404
2025/01/11 12:42:43.775 Request 2: Status Code = 404
...
2025/01/11 12:42:44.639 Request 11: Status Code = 429
2025/01/11 12:42:44.640 IP has been banned globally.
2025/01/11 12:42:44.640 Ban Response: You have been banned due to excessive errors. Please try again later.
2025/01/11 12:42:44.640 Waiting for global ban to expire (5 seconds)...
2025/01/11 12:42:49.666 Global ban has expired. IP is no longer banned.

=== Test Summary ===
[PASS] Global Ban Test
[PASS] Login Ban Test
[PASS] API Ban Test
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
2025/01/11 11:42:44.621 INFO http.handlers.caddy_mib IP banned {"client_ip": "::1", "error_code": 404, "ban_expires": "2025/01/11 11:42:49.630"}
2025/01/11 11:42:49.665 INFO http.handlers.caddy_mib cleaned up expired ban {"client_ip": "::1"}
```

---

## License
This project is licensed under the **AGPL-3.0 License**. See the [LICENSE](LICENSE) file for details.

---

## Support
If you encounter any issues or have questions, please [open an issue](https://github.com/fabriziosalmi/caddy-mib/issues).
