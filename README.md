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
- **[Debugging](#debugging)**: Detailed logs to track IP bans, error counts, and request statuses.
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

---

## Debugging

### Testing with Python
You can use the [test.py](https://github.com/fabriziosalmi/caddy-mib/blob/main/test.py) script to evaluate your setup:

#### Expected Output:

```bash
caddy-mib % python3 test.py
2025/01/12 01:45:08.286 Starting global ban test...
2025/01/12 01:45:08.297 Request 1: Status Code = 404
2025/01/12 01:45:08.303 Request 2: Status Code = 404
2025/01/12 01:45:08.308 Request 3: Status Code = 404
2025/01/12 01:45:08.314 Request 4: Status Code = 404
2025/01/12 01:45:08.319 Request 5: Status Code = 404
2025/01/12 01:45:08.325 Request 6: Status Code = 404
2025/01/12 01:45:08.330 Request 7: Status Code = 404
2025/01/12 01:45:08.336 Request 8: Status Code = 404
2025/01/12 01:45:08.342 Request 9: Status Code = 429
2025/01/12 01:45:08.342 IP has been banned globally.
2025/01/12 01:45:08.342 Ban Response: You have been banned due to excessive errors. Please try again later.
2025/01/12 01:45:08.342 Expected ban to expire at: 2025/01/12 01:45:18
Global ban expires in: 00:00
2025/01/12 01:45:18.388 Continuing with ban expiration verification...
2025/01/12 01:45:18.410 Verifying ban expiration: Status Code = 404
2025/01/12 01:45:18.410 Global ban has expired. IP is no longer banned.
2025/01/12 01:45:18.410 Starting /login ban test...
2025/01/12 01:45:18.428 Request 1: Status Code = 404
2025/01/12 01:45:18.437 Request 2: Status Code = 404
2025/01/12 01:45:18.444 Request 3: Status Code = 404
2025/01/12 01:45:18.451 Request 4: Status Code = 404
2025/01/12 01:45:18.457 Request 5: Status Code = 404
2025/01/12 01:45:18.464 Request 6: Status Code = 429
2025/01/12 01:45:18.464 IP has been banned for /login.
2025/01/12 01:45:18.464 Ban Response: You have been banned due to excessive errors. Please try again later.
2025/01/12 01:45:18.464 Expected /login ban to expire at: 2025/01/12 01:45:33
/login ban expires in: 00:00
2025/01/12 01:45:33.526 Continuing with ban expiration verification...
2025/01/12 01:45:33.546 Verifying ban expiration: Status Code = 404
2025/01/12 01:45:33.546 /login ban has expired. IP is no longer banned.
2025/01/12 01:45:33.546 Starting /api ban test...
2025/01/12 01:45:33.558 Request 1: Status Code = 404
2025/01/12 01:45:33.567 Request 2: Status Code = 404
2025/01/12 01:45:33.575 Request 3: Status Code = 404
2025/01/12 01:45:33.582 Request 4: Status Code = 404
2025/01/12 01:45:33.589 Request 5: Status Code = 404
2025/01/12 01:45:33.597 Request 6: Status Code = 404
2025/01/12 01:45:33.606 Request 7: Status Code = 404
2025/01/12 01:45:33.612 Request 8: Status Code = 404
2025/01/12 01:45:33.618 Request 9: Status Code = 429
2025/01/12 01:45:33.618 IP has been banned for /api.
2025/01/12 01:45:33.618 Ban Response: You have been banned due to excessive errors. Please try again later.
2025/01/12 01:45:33.618 Expected /api ban to expire at: 2025/01/12 01:45:53
/api ban expires in: 00:00
2025/01/12 01:45:53.698 Continuing with ban expiration verification...
2025/01/12 01:45:53.724 Verifying ban expiration: Status Code = 404
2025/01/12 01:45:53.724 /api ban has expired. IP is no longer banned.
2025/01/12 01:45:53.724 Starting test_specific_404...
2025/01/12 01:45:53.735 Received expected 404 for nonexistent URL. Status Code = 404
2025/01/12 01:45:53.735 Starting test_root_response_with_fab...
2025/01/12 01:45:53.744 Received acceptable status code (404) for root URL with 'fab' user-agent.

=== Test Summary ===
[PASS] Global Ban Test
[PASS] Login Ban Test
[PASS] API Ban Test
[PASS] Specific 404 Test
[PASS] Root Response with fab Test

=== Overall Test Result ===
All tests passed! (100.00%)

=== Test Details ===
Global Ban Test: PASS
Login Ban Test: PASS
API Ban Test: PASS
Specific 404 Test: PASS
Root Response with fab Test: PASS

=== Insights ===
All tests passed, indicating that the rate limiting and banning mechanisms are functioning as expected.
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
