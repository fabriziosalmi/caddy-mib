# Caddy MIB - Middleware IP Ban for Caddy

## Overview
**Caddy MIB (Middleware IP Ban)** is a powerful and flexible custom Caddy HTTP middleware designed to safeguard your web applications by proactively tracking client IP addresses exhibiting repetitive error patterns (e.g., `404 Not Found`, `500 Internal Server Error`). Upon exceeding a configurable error threshold, Caddy MIB temporarily bans the offending IP, effectively mitigating brute-force attacks, preventing abuse of non-existent resources, and limiting other forms of malicious activity. This middleware is an essential tool for any security-conscious web administrator using Caddy.

[![Go](https://github.com/fabriziosalmi/caddy-mib/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-mib/actions/workflows/go.yml) [![CodeQL](https://github.com/fabriziosalmi/caddy-mib/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-mib/actions/workflows/github-code-scanning/codeql) [![Build and test Caddy with MIB](https://github.com/fabriziosalmi/caddy-mib/actions/workflows/main.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-mib/actions/workflows/main.yml)

## Key Features
*   **Error Code Tracking**: Monitor specific HTTP error codes (e.g., 404, 500).
*   **Configurable Error Limits**: Set max errors per IP before banning.
*   **Flexible Ban Times**: Use human-readable formats (e.g., 5s, 10m, 1h).
*   **Exponential Ban Increase**: Ban duration grows for repeat offenders.
*   **Sliding Window Error Tracking**: Reset error counts after a period of inactivity (optional).
*   **Trusted IP Whitelisting**: Exclude specific IPs or CIDRs from bans.
*   **Path-Specific Settings**: Tailor limits and bans per URL path.
*   **Custom Ban Messages**: Set custom response bodies and headers.
*   **Adjustable Ban Status Codes**: Choose between 403 or 429 for banned IPs.
*   **Detailed Logging**: Track IP, error code, ban times, and request data.
*   **Automatic Ban Removal**: Bans are automatically lifted upon expiration.

## Requirements
- **Go 1.20 or later** - For building the custom Caddy module.
- **Caddy v2.9.0 or later** - The Caddy web server and its plugin framework.

---

## Table of Contents
- **[Overview](#overview)**: The core purpose of Caddy MIB.
- **[Key Features](#key-features)**: A detailed breakdown of the middleware's functionalities.
- **[Requirements](#requirements)**: Software dependencies for installation.
- **[Installation](#installation)**: Step-by-step instructions for building and including the module.
- **[Configuration](#configuration)**: Options and examples for customizing Caddy MIB.
- **[Usage](#usage)**: Common use cases and scenarios.
- **[Debugging](#debugging)**: Tips and strategies for troubleshooting issues.
- **[License](#license)**: Legal information regarding the usage and distribution of the software.
- **[Contributions](#contributions)**: How to participate in the development of Caddy MIB.
- **[Support](#support)**: Ways to seek assistance and report issues.

---

## Installation

### 1. Clone the Repository
First, clone the Caddy MIB repository to your local machine:
```bash
git clone https://github.com/fabriziosalmi/caddy-mib.git
cd caddy-mib
```

### 2. Build Caddy with the MIB Module
Use `xcaddy` to compile Caddy with the custom MIB module:
```bash
xcaddy build --with github.com/fabriziosalmi/caddy-mib=./
```

### 3. Verify the Installation
Check the installed Caddy version to confirm the presence of `caddy-mib`:
```bash
./caddy version
```

You should see `caddy-mib` listed among the modules.

---

## Configuration

### Caddyfile Example
Here's a comprehensive example showcasing a range of options:
```caddyfile
{
    admin off # Disable the admin endpoint for production
    log {
        level debug  # Set log level for detailed debugging
        output stdout  # Output logs to the console
        format console # Use human-readable log format
    }
}

:8080 { # Listen on port 8080
    route {
        caddy_mib {
            error_codes 404 500 401  # Track 404, 500, and 401 errors
            max_error_count 10 # Allow up to 10 global errors
            ban_duration 5s # Base ban duration of 5 seconds
            ban_duration_multiplier 1.5 # Increase ban duration for repeat offenders
            error_count_timeout 1h # Reset error count after 1 hour of inactivity (optional)
            whitelist 127.0.0.1 ::1 192.168.1.0/24 # Whitelist local IPs and network
			log_request_headers  User-Agent X-Custom-Header  # Log specified request headers
            log_level debug  # Debug log level for this middleware
            ban_response_body "You have been temporarily blocked due to excessive errors. Please try again later." # Custom ban response message
            ban_status_code 429 # Use the 429 Too Many Requests status code

             cidr_bans 10.0.0.0/8  # CIDR to ban
			 # Custom response header example
            custom_response_header  "This is a custom message,Another message"


            per_path /login {
                error_codes 404  # Track only 404 errors on /login
                max_error_count 5  # Only allow 5 errors before banning
                ban_duration 10s # Ban duration of 10 seconds
                ban_duration_multiplier 2 # Exponential increase in /login ban duration
                error_count_timeout 15m # Reset after 15 minutes for /login (optional)
            }

            per_path /api {
                error_codes 404 500  # Track 404 and 500 errors on /api
                max_error_count 8  # Allow 8 errors before banning
                ban_duration 15s  # 15-second ban duration
                ban_duration_multiplier 1  # No exponential increase in /api ban duration
                error_count_timeout 30m # Reset after 30 minutes for /api (optional)
            }
        }

        handle {
            respond "Hello world!" 404  # Fallback response for unhandled routes
        }
    }
}
```

### Directive Options

-   **`error_codes`** _(Required)_:
    *   Specifies a space-separated list of HTTP error codes to be tracked for rate limiting.
    *   Example: `error_codes 404 500 401`
-   **`max_error_count`** _(Required)_:
    *   The maximum number of errors allowed from a single IP before initiating a ban.
    *   Example: `max_error_count 10`
-   **`ban_duration`** _(Required)_:
    *   The initial duration for which an IP address will be banned.
    *   Example: `ban_duration 5s` (5 seconds), `ban_duration 10m` (10 minutes), `ban_duration 1h` (1 hour)
-   **`ban_duration_multiplier`** _(Optional)_:
    *   A floating-point number to exponentially increase the ban duration upon each subsequent offense.
    *   Example: `ban_duration_multiplier 1.5`
    *   Defaults to `1.0` (no multiplier).
-   **`error_count_timeout`** _(Optional)_:
    *   Time window for counting errors. If the time between errors exceeds this duration, the error count resets to 1 (sliding window behavior).
    *   Useful for preventing permanent error accumulation and avoiding bans from occasional errors spread over long periods.
    *   Example: `error_count_timeout 1h` (1 hour), `error_count_timeout 30m` (30 minutes)
    *   Set to `0` or omit to disable (errors never expire - original behavior).
    *   Can be overridden per-path.
-  **`whitelist`** _(Optional)_:
    *   A space-separated list of IP addresses or CIDR ranges to exclude from being banned.
    *   Example: `whitelist 127.0.0.1 ::1 192.168.1.0/24`
-   **`log_level`** _(Optional)_:
    *   Sets the log level for the middleware.
    *   Supported values: `debug`, `info`, `warn`, `error`.
    *   Example: `log_level debug`
    *   Defaults to Caddy's global log level.
-   **`ban_response_body`** _(Optional)_:
    *   Custom message to display to blocked clients.
    *   Example: `ban_response_body "You have been blocked due to excessive errors."`
    *   If not set, an empty response body will be returned.
-  **`ban_status_code`** _(Optional)_:
    *   The HTTP status code returned for banned requests. Must be either 403 (Forbidden) or 429 (Too Many Requests).
    *   Example: `ban_status_code 429`
    *    Defaults to `403` (Forbidden).
-    **`cidr_bans`** _(Optional)_:
	*	A space-separated list of CIDR ranges to ban
	*	Example `cidr_bans 10.0.0.0/8 172.16.0.0/12`
- **`custom_response_header`** _(Optional)_:
	*    A comma-separated list of custom headers to add to the response, each header will have key as `X-Custom-MIB-Info`.
	*	Example `custom_response_header "Custom header, Another header"`
- **`log_request_headers`** _(Optional)_:
    *   A space-separated list of request headers to log when an IP is banned. Useful for debugging.
    *   Example: `log_request_headers User-Agent X-Forwarded-For`

#### Per-Path Configuration

-   **`per_path <path>`** _(Optional)_:
    *   Configures per-path settings, taking precedence over global configurations.
    *   Reuses all the same options as global ones: `error_codes`, `max_error_count`, `ban_duration`, `ban_duration_multiplier`, and `error_count_timeout`
    *   Each path block must be defined as a Caddyfile block.
    *   If `error_count_timeout` is not specified in a per-path config, it inherits the global value.

---

## Usage

### Example Scenario

1.  A client makes multiple requests to a URL that does not exist on your server, generating `404 Not Found` responses.
2.  The client exceeds the global `max_error_count`, resulting in a global ban.
3.  The client's IP receives a `429 Too Many Requests` response with the custom `ban_response_body`.
4.  The client attempts to access the `/login` endpoint, which is configured with specific error limits and ban duration that are different than the global ones.
5. The client is banned after triggering multiple 404, resulting in a separate ban and `429` response.

### Sliding Window Behavior

When `error_count_timeout` is configured, the middleware implements a sliding window for error tracking:

**Example Configuration:**
```caddyfile
caddy_mib {
    error_codes 404
    max_error_count 5
    ban_duration 10m
    error_count_timeout 1h  # Reset after 1 hour of inactivity
}
```

**Behavior:**
- User hits 3 errors within 10 minutes → count = 3
- User waits 61 minutes (exceeds 1-hour timeout)
- User hits 1 more error → count resets to 1 (not banned)
- User hits 4 more errors quickly → count reaches 5, user is banned

**Without timeout (default):**
- All errors accumulate indefinitely
- After ban expires, hitting just 1 more error triggers immediate re-ban

**Use Cases:**
- **Set timeout**: Protect against concentrated attacks while forgiving occasional errors
- **No timeout**: Stricter enforcement, useful for zero-tolerance scenarios

### Best Practices

*   **Start with a reasonable `max_error_count`**: This should be high enough to avoid banning legitimate users and bots while still protecting against malicious attacks.
*   **Use a moderate `ban_duration`**: Start with a short ban duration and gradually increase it if needed.
*   **Utilize `ban_duration_multiplier` wisely**: Be careful when using exponential multipliers, as they can quickly lead to very long ban times.
*   **Configure `error_count_timeout` for most use cases**: A 1-hour timeout is a good starting point to prevent permanent error accumulation while still catching abuse patterns. Omit for zero-tolerance enforcement.
*   **Whitelist trusted networks**: It's good practice to whitelist internal networks to prevent self-blocking.
*   **Set proper log levels**: Setting `log_level` to `debug` can help during testing, while `info` or `warn` are more suitable for production use.
*	**Use `cidr_bans`**: Use `cidr_bans` in combination with the `whitelist` for more precise configuration.

---

## Debugging

### Testing with Python
The included [test.py](https://github.com/fabriziosalmi/caddy-mib/blob/main/test.py) script allows you to test the module’s functionality.

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

### Logs
Monitor the Caddy logs for insightful debugging information. Tail the Caddy log file:
```bash
tail -f /var/log/caddy/access.log
```

Example log messages:
```
2025/01/11 11:42:44.621 INFO http.handlers.caddy_mib IP banned {"client_ip": "::1", "error_code": 404, "ban_expires": "2025/01/11 11:42:49.630"}
2025/01/11 11:42:49.665 INFO http.handlers.caddy_mib cleaned up expired ban {"client_ip": "::1"}
```
These log lines provide valuable information on when IPs are banned, which error codes trigger a ban, and when bans expire.

---

## Recent Updates

### v1.1.0 (Latest)

**New Features:**
- **Sliding Window Error Tracking**: Added `error_count_timeout` configuration option
  - Prevents permanent error accumulation
  - Resets error counts after a period of inactivity
  - Configurable globally and per-path
  - Backwards compatible (disabled by default)

**Bug Fixes:**
- Fixed error count cleanup when bans expire
  - Previously: Only attempted to delete error counts using IP as key
  - Now: Properly deletes all error counts across all paths for banned IPs
  - Impact: Error counts are now correctly reset after ban expiration

**Testing:**
- Added 6 comprehensive tests covering new functionality
- All 16 tests passing with full coverage

---

## License
This project is licensed under the **AGPL-3.0 License**. Refer to the [LICENSE](LICENSE) file for full details.

---

## Contributions
We welcome contributions from the community! To contribute:

1.  Fork the repository.
2.  Create a feature branch.
3.  Make your changes and add tests.
4.  Submit a pull request.

---

## Others projects

If You like my projects, you may also like these ones:

- [caddy-waf](https://github.com/fabriziosalmi/caddy-waf) Caddy WAF (Regex Rules, IP and DNS filtering, Rate Limiting, GeoIP, Tor, Anomaly Detection) 
- [patterns](https://github.com/fabriziosalmi/patterns) Automated OWASP CRS and Bad Bot Detection for Nginx, Apache, Traefik and HaProxy
- [blacklists](https://github.com/fabriziosalmi/blacklists) Hourly updated domains blacklist 🚫 
- [proxmox-vm-autoscale](https://github.com/fabriziosalmi/proxmox-vm-autoscale) Automatically scale virtual machines resources on Proxmox hosts 
- [UglyFeed](https://github.com/fabriziosalmi/UglyFeed) Retrieve, aggregate, filter, evaluate, rewrite and serve RSS feeds using Large Language Models for fun, research and learning purposes 
- [proxmox-lxc-autoscale](https://github.com/fabriziosalmi/proxmox-lxc-autoscale) Automatically scale LXC containers resources on Proxmox hosts 
- [DevGPT](https://github.com/fabriziosalmi/DevGPT) Code togheter, right now! GPT powered code assistant to build project in minutes
- [websites-monitor](https://github.com/fabriziosalmi/websites-monitor) Websites monitoring via GitHub Actions (expiration, security, performances, privacy, SEO)
- [zonecontrol](https://github.com/fabriziosalmi/zonecontrol) Cloudflare Zones Settings Automation using GitHub Actions 
- [lws](https://github.com/fabriziosalmi/lws) linux (containers) web services
- [cf-box](https://github.com/fabriziosalmi/cf-box) cf-box is a set of Python tools to play with API and multiple Cloudflare accounts.
- [limits](https://github.com/fabriziosalmi/limits) Automated rate limits implementation for web servers 
- [dnscontrol-actions](https://github.com/fabriziosalmi/dnscontrol-actions) Automate DNS updates and rollbacks across multiple providers using DNSControl and GitHub Actions 
- [proxmox-lxc-autoscale-ml](https://github.com/fabriziosalmi/proxmox-lxc-autoscale-ml) Automatically scale the LXC containers resources on Proxmox hosts with AI
- [csv-anonymizer](https://github.com/fabriziosalmi/csv-anonymizer) CSV fuzzer/anonymizer
- [iamnotacoder](https://github.com/fabriziosalmi/iamnotacoder) AI code generation and improvement

---

## Support
For issues or questions regarding Caddy MIB, please open a new issue on our [issue tracker](https://github.com/fabriziosalmi/caddy-mib/issues).
```
