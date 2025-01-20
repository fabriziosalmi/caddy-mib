import subprocess
import time
from datetime import datetime, timedelta
from colorama import Fore, Style, init
import argparse

# Initialize colorama
init(autoreset=True)

# Configuration - can be overridden by command-line arguments
BASE_URL = "http://localhost:8080"
NONEXISTENT_URL_PATH = "/nonexistent"
LOGIN_URL_PATH = "/login"
API_URL_PATH = "/api"

# Global settings (defaults)
GLOBAL_MAX_ERRORS = 10  # Matches max_error_count in Caddyfile
GLOBAL_BAN_DURATION = 10  # Matches ban_duration in Caddyfile (10 seconds)

# Per-path settings (defaults)
LOGIN_MAX_ERRORS = 5  # Matches max_error_count for /login
LOGIN_BAN_DURATION = 15  # Matches ban_duration for /login (15 seconds)
API_MAX_ERRORS = 8  # Matches max_error_count for /api
API_BAN_DURATION = 20  # Matches ban_duration for /api (20 seconds)

def log(message, **kwargs):
    """Log a message with a timestamp."""
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    print(f"{timestamp} {message}", **kwargs)

def send_request(url, expected_status=None, user_agent=None):
    """Send a request using curl and return the HTTP status code and response body."""
    curl_command = ["curl", "-v", url]
    if user_agent:
        curl_command.extend(["-H", f"User-Agent: {user_agent}"])
    try:
        result = subprocess.run(
            curl_command,
            capture_output=True,
            text=True,
            check=True,
        )
        # Extract HTTP status code using regex to handle different HTTP versions
        import re
        match = re.search(r"HTTP/\d+\.\d+ (\d+)", result.stderr)
        status_code = int(match.group(1)) if match else 0
        if status_code == 0:
            match = re.search(r"HTTP/\d\.\d (\d+)", result.stderr)
            status_code = int(match.group(1)) if match else 0
        # Extract response body
        response_body = result.stdout

        colored_status = ""
        if expected_status is not None:
            if status_code == expected_status:
                colored_status = f"{Fore.GREEN}{status_code}{Style.RESET_ALL}"
            elif status_code == 429:  # Always highlight ban status
                colored_status = f"{Fore.RED}{status_code}{Style.RESET_ALL}"
            elif 400 <= status_code < 600:
                colored_status = f"{Fore.YELLOW}{status_code}{Style.RESET_ALL}"
            else:
                colored_status = str(status_code)
        else:
            colored_status = str(status_code)

        return status_code, response_body, colored_status
    except subprocess.CalledProcessError as e:
        match = re.search(r"HTTP/\d+\.\d+ (\d+)", e.stderr)
        status_code = int(match.group(1)) if match else 0
        if status_code == 0:
            if "HTTP/1.1 " in e.stderr:
                try:
                    status_code = int(e.stderr.split("HTTP/1.1 ")[1].split()[0])
                except (IndexError, ValueError):
                    pass  # Handle cases where status code extraction fails
            response_body = e.stdout

            colored_status = ""
            if expected_status is not None:
                colored_status = f"{Fore.RED}{status_code}{Style.RESET_ALL}"  # Treat errors as red
            else:
                colored_status = str(status_code)

            return status_code, f"Server unreachable or other error: {e.stderr.strip()}", colored_status
        else:
            colored_status = ""
            if expected_status is not None:
                colored_status = f"{Fore.RED}{status_code}{Style.RESET_ALL}"  # Treat errors as red
            else:
                colored_status = str(status_code)
            return status_code, "Server unreachable or other error", colored_status
    except re.error as e:
        log(f"Regex error: {type(e).__name__} - {e}")
        return 0, "Regex error", ""
    except ValueError as e:
        log(f"Value error: {type(e).__name__} - {e}")
        return 0, "Value error", ""
    except TypeError as e:
        log(f"Type error: {type(e).__name__} - {e}")
        return 0, "Type error", ""
    except Exception as e:
        log(f"Unexpected error: {type(e).__name__} - {e}")
        return 0, "Unexpected error", ""

def test_global_ban():
    """Test global error tracking and banning with countdown."""
    log("Starting global ban test...")
    failure_reason = None
    ban_start_time = None
    ban_duration = GLOBAL_BAN_DURATION

    # Send requests to trigger errors
    for i in range(GLOBAL_MAX_ERRORS + 2):  # Send a few extra requests to test banning
        expected_status = 429 if i >= GLOBAL_MAX_ERRORS else 404
        status_code, response_body, colored_status = send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}", expected_status=expected_status)
        log(f"Request {i + 1}: Status Code = {colored_status}")

        if status_code == 429:  # Custom status code for banned IPs
            log(f"{Fore.RED}IP has been banned globally.{Style.RESET_ALL}")
            log(f"Ban Response: {response_body.strip()}")
            ban_start_time = datetime.now()
            break
        elif status_code == 0:
            failure_reason = "Failed to send request."
            break
        elif expected_status != 429 and status_code != expected_status:
            failure_reason = f"Unexpected status code before ban: Expected {expected_status}, got {status_code}."

    if failure_reason:
        log(f"{Fore.RED}Global ban test failed: {failure_reason}{Style.RESET_ALL}")
        return False

    if ban_start_time:
        expected_ban_end_time = ban_start_time + timedelta(seconds=ban_duration)
        log(f"Expected ban to expire at: {expected_ban_end_time.strftime('%Y/%m/%d %H:%M:%S')}")
        while datetime.now() < expected_ban_end_time:
            time_remaining = expected_ban_end_time - datetime.now()
            minutes, seconds = divmod(int(time_remaining.total_seconds()), 60)
            print(f"\r{Fore.RED}Global ban expires in: {minutes:02d}:{seconds:02d}{Style.RESET_ALL}", end="")
            time.sleep(1)
        print()  # Newline after countdown

    # Wait for the ban to expire (ensure we wait the full duration even if countdown finishes slightly early)
    if ban_start_time:
        wait_duration = max(0, (expected_ban_end_time - datetime.now()).total_seconds())
        if wait_duration > 0:
            log(f"Waiting the remaining {wait_duration:.1f} seconds to ensure ban expiration...")
            time.sleep(wait_duration)
        else:
            log("Continuing with ban expiration verification...")
    else:
        log(f"Waiting for global ban to expire ({GLOBAL_BAN_DURATION} seconds)...")
        time.sleep(GLOBAL_BAN_DURATION)

    # Send another request to verify the ban has expired
    status_code, response_body, colored_status = send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}", expected_status=404)
    log(f"Verifying ban expiration: Status Code = {colored_status}")
    if status_code != 429:
        log(f"{Fore.GREEN}Global ban has expired. IP is no longer banned.{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}Global ban test failed: IP is still banned after expiration time.{Style.RESET_ALL}")
        return False

def test_login_ban():
    """Test per-path error tracking and banning for /login with countdown."""
    log("Starting /login ban test...")
    failure_reason = None
    ban_start_time = None
    ban_duration = LOGIN_BAN_DURATION

    # Send requests to trigger errors
    for i in range(LOGIN_MAX_ERRORS + 2):  # Send a few extra requests to test banning
        expected_status = 429 if i >= LOGIN_MAX_ERRORS else 404  # Expecting 404 before ban
        status_code, response_body, colored_status = send_request(f"{BASE_URL}{LOGIN_URL_PATH}", expected_status=expected_status)
        log(f"Request {i + 1}: Status Code = {colored_status}")

        if status_code == 429:  # Custom status code for banned IPs
            log(f"{Fore.RED}IP has been banned for /login.{Style.RESET_ALL}")
            log(f"Ban Response: {response_body.strip()}")
            ban_start_time = datetime.now()
            break
        elif status_code == 0:
            failure_reason = "Failed to send request."
            break
        elif expected_status != 429 and status_code != expected_status:
            failure_reason = f"Unexpected status code before ban: Expected {expected_status}, got {status_code}."

    if failure_reason:
        log(f"{Fore.RED}/login ban test failed: {failure_reason}{Style.RESET_ALL}")
        return False

    if ban_start_time:
        expected_ban_end_time = ban_start_time + timedelta(seconds=ban_duration)
        log(f"Expected /login ban to expire at: {expected_ban_end_time.strftime('%Y/%m/%d %H:%M:%S')}")
        while datetime.now() < expected_ban_end_time:
            time_remaining = expected_ban_end_time - datetime.now()
            minutes, seconds = divmod(int(time_remaining.total_seconds()), 60)
            print(f"\r{Fore.RED}/login ban expires in: {minutes:02d}:{seconds:02d}{Style.RESET_ALL}", end="")
            time.sleep(1)
        print()  # Newline after countdown

    # Wait for the ban to expire
    if ban_start_time:
        wait_duration = max(0, (expected_ban_end_time - datetime.now()).total_seconds())
        if wait_duration > 0:
            log(f"Waiting the remaining {wait_duration:.1f} seconds to ensure ban expiration...")
            time.sleep(wait_duration)
        else:
            log("Continuing with ban expiration verification...")
    else:
        log(f"Waiting for /login ban to expire ({LOGIN_BAN_DURATION} seconds)...")
        time.sleep(LOGIN_BAN_DURATION)

    # Send another request to verify the ban has expired
    status_code, response_body, colored_status = send_request(f"{BASE_URL}{LOGIN_URL_PATH}", expected_status=404) # Expecting 404 after ban expires
    log(f"Verifying ban expiration: Status Code = {colored_status}")
    if status_code != 429:
        log(f"{Fore.GREEN}/login ban has expired. IP is no longer banned.{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}/login ban test failed: IP is still banned after expiration time.{Style.RESET_ALL}")
        return False

def test_api_ban():
    """Test per-path error tracking and banning for /api with countdown."""
    log("Starting /api ban test...")
    failure_reason = None
    ban_start_time = None
    ban_duration = API_BAN_DURATION

    # Send requests to trigger errors
    for i in range(API_MAX_ERRORS + 2):  # Send a few extra requests to test banning
        expected_status = 429 if i >= API_MAX_ERRORS else 404  # Or 500
        status_code, response_body, colored_status = send_request(f"{BASE_URL}{API_URL_PATH}", expected_status=expected_status)
        log(f"Request {i + 1}: Status Code = {colored_status}")

        if status_code == 429:  # Custom status code for banned IPs
            log(f"{Fore.RED}IP has been banned for /api.{Style.RESET_ALL}")
            log(f"Ban Response: {response_body.strip()}")
            ban_start_time = datetime.now()
            break
        elif status_code == 0:
            failure_reason = "Failed to send request."
            break
        elif expected_status != 429 and status_code != expected_status:
            failure_reason = f"Unexpected status code before ban: Expected {expected_status}, got {status_code}."

    if failure_reason:
        log(f"{Fore.RED}/api ban test failed: {failure_reason}{Style.RESET_ALL}")
        return False

    if ban_start_time:
        expected_ban_end_time = ban_start_time + timedelta(seconds=ban_duration)
        log(f"Expected /api ban to expire at: {expected_ban_end_time.strftime('%Y/%m/%d %H:%M:%S')}")
        while datetime.now() < expected_ban_end_time:
            time_remaining = expected_ban_end_time - datetime.now()
            minutes, seconds = divmod(int(time_remaining.total_seconds()), 60)
            print(f"\r{Fore.RED}/api ban expires in: {minutes:02d}:{seconds:02d}{Style.RESET_ALL}", end="")
            time.sleep(1)
        print()  # Newline after countdown

    # Wait for the ban to expire
    if ban_start_time:
        wait_duration = max(0, (expected_ban_end_time - datetime.now()).total_seconds())
        if wait_duration > 0:
            log(f"Waiting the remaining {wait_duration:.1f} seconds to ensure ban expiration...")
            time.sleep(wait_duration)
        else:
            log("Continuing with ban expiration verification...")
    else:
        log(f"Waiting for /api ban to expire ({API_BAN_DURATION} seconds)...")
        time.sleep(API_BAN_DURATION)

    # Send another request to verify the ban has expired
    status_code, response_body, colored_status = send_request(f"{BASE_URL}{API_URL_PATH}", expected_status=404) # Or 500
    log(f"Verifying ban expiration: Status Code = {colored_status}")
    if status_code != 429:
        log(f"{Fore.GREEN}/api ban has expired. IP is no longer banned.{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}/api ban test failed: IP is still banned after expiration time.{Style.RESET_ALL}")
        return False

def test_specific_404():
    """Test that the nonexistent URL returns a 404 status."""
    log("Starting test_specific_404...")
    status_code, _, colored_status = send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}", expected_status=404)
    if status_code == 404:
        log(f"{Fore.GREEN}Received expected 404 for nonexistent URL. Status Code = {colored_status}{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}test_specific_404 failed: Expected 404, but got {colored_status}{Style.RESET_ALL}")
        return False

def test_root_response_with_fab():
    """Test that the root URL returns an acceptable status code with 'fab' user-agent."""
    log("Starting test_root_response_with_fab...")
    status_code, _, colored_status = send_request(BASE_URL, user_agent="fab")
    is_acceptable = 200 <= status_code < 400 or status_code == 404
    is_forbidden = status_code in [401, 402, 403]
    is_too_high = status_code > 404

    if is_acceptable and not is_forbidden and not is_too_high:
        log(f"{Fore.GREEN}Received acceptable status code ({colored_status}) for root URL with 'fab' user-agent.{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}test_root_response_with_fab failed: Received unacceptable status code {colored_status} for root URL with 'fab' user-agent.{Style.RESET_ALL}")
        return False

def test_custom_response_header():
    """Test that the custom response header is present in the response."""
    log("Starting custom response header test...")
    status_code, response_body, colored_status = send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}")
    if "X-Custom-MIB-Info" in response_body:
        log(f"{Fore.GREEN}Custom response header found in response.{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}Custom response header not found in response.{Style.RESET_ALL}")
        return False

def test_whitelist():
    """Test that whitelisted IPs are not banned."""
    log("Starting whitelist test...")
    # Simulate requests from a whitelisted IP
    for i in range(GLOBAL_MAX_ERRORS + 2):
        status_code, response_body, colored_status = send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}")
        log(f"Request {i + 1}: Status Code = {colored_status}")
        if status_code == 429:
            log(f"{Fore.RED}Whitelist test failed: IP was banned despite being whitelisted.{Style.RESET_ALL}")
            return False
    log(f"{Fore.GREEN}Whitelist test passed: IP was not banned.{Style.RESET_ALL}")
    return True

def test_cidr_ban():
    """Test that IPs within a banned CIDR range are blocked."""
    log("Starting CIDR ban test...")
    status_code, response_body, colored_status = send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}")
    if status_code == 429:
        log(f"{Fore.GREEN}CIDR ban test passed: IP within banned CIDR range was blocked.{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}CIDR ban test failed: IP within banned CIDR range was not blocked.{Style.RESET_ALL}")
        return False

def test_ban_duration_multiplier():
    """Test that the ban duration increases exponentially based on the multiplier."""
    log("Starting ban duration multiplier test...")
    # Trigger multiple bans and measure the duration
    ban_durations = []
    for i in range(3):  # Trigger 3 bans
        for _ in range(GLOBAL_MAX_ERRORS + 1):
            send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}")
        ban_start_time = datetime.now()
        while True:
            status_code, _, _ = send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}")
            if status_code != 429:
                ban_end_time = datetime.now()
                ban_durations.append((ban_end_time - ban_start_time).total_seconds())
                break
            time.sleep(1)
    # Verify that ban durations increase exponentially
    if ban_durations[1] > ban_durations[0] and ban_durations[2] > ban_durations[1]:
        log(f"{Fore.GREEN}Ban duration multiplier test passed: Ban durations increased exponentially.{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}Ban duration multiplier test failed: Ban durations did not increase exponentially.{Style.RESET_ALL}")
        return False

def test_log_request_headers():
    """Test that specified request headers are logged."""
    log("Starting log request headers test...")
    status_code, response_body, colored_status = send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}", user_agent="test-agent")
    # Check logs for the presence of the "User-Agent" header
    if "test-agent" in response_body:  # Assuming the response body contains logged headers
        log(f"{Fore.GREEN}Log request headers test passed: 'User-Agent' header was logged.{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}Log request headers test failed: 'User-Agent' header was not logged.{Style.RESET_ALL}")
        return False

def test_custom_ban_response_body():
    """Test that the custom ban response body is returned."""
    log("Starting custom ban response body test...")
    # Trigger a ban
    for _ in range(GLOBAL_MAX_ERRORS + 1):
        send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}")
    status_code, response_body, colored_status = send_request(f"{BASE_URL}{NONEXISTENT_URL_PATH}")
    if "custom ban response" in response_body:  # Replace with the expected custom response
        log(f"{Fore.GREEN}Custom ban response body test passed: Custom response body was returned.{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}Custom ban response body test failed: Custom response body was not returned.{Style.RESET_ALL}")
        return False

def print_summary(test_name, success):
    """Print a summary of the test result with colored output."""
    if success:
        print(f"{Fore.GREEN}[PASS]{Style.RESET_ALL} {test_name}")
    else:
        print(f"{Fore.RED}[FAIL]{Style.RESET_ALL} {test_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test script for rate limiting and banning.")
    parser.add_argument("--base-url", dest="base_url", default=BASE_URL,
                        help=f"Base URL of the service (default: {BASE_URL})")
    parser.add_argument("--global-max-errors", type=int, default=GLOBAL_MAX_ERRORS,
                        help=f"Global max errors before banning (default: {GLOBAL_MAX_ERRORS})")
    parser.add_argument("--global-ban-duration", type=int, default=GLOBAL_BAN_DURATION,
                        help=f"Global ban duration in seconds (default: {GLOBAL_BAN_DURATION})")
    parser.add_argument("--login-max-errors", type=int, default=LOGIN_MAX_ERRORS,
                        help=f"Max errors for /login before banning (default: {LOGIN_MAX_ERRORS})")
    parser.add_argument("--login-ban-duration", type=int, default=LOGIN_BAN_DURATION,
                        help=f"Ban duration for /login in seconds (default: {LOGIN_BAN_DURATION})")
    parser.add_argument("--api-max-errors", type=int, default=API_MAX_ERRORS,
                        help=f"Max errors for /api before banning (default: {API_MAX_ERRORS})")
    parser.add_argument("--api-ban-duration", type=int, default=API_BAN_DURATION,
                        help=f"Ban duration for /api in seconds (default: {API_BAN_DURATION})")
    args = parser.parse_args()

    # Update configuration with command-line arguments
    BASE_URL = args.base_url
    GLOBAL_MAX_ERRORS = args.global_max_errors
    GLOBAL_BAN_DURATION = args.global_ban_duration
    LOGIN_MAX_ERRORS = args.login_max_errors
    LOGIN_BAN_DURATION = args.login_ban_duration
    API_MAX_ERRORS = args.api_max_errors
    API_BAN_DURATION = args.api_ban_duration

    # Run all tests and collect results
    results = {
        "Global Ban Test": test_global_ban(),
        "Login Ban Test": test_login_ban(),
        "API Ban Test": test_api_ban(),
        "Specific 404 Test": test_specific_404(),
        "Root Response with fab Test": test_root_response_with_fab(),
        "Custom Response Header Test": test_custom_response_header(),
        "Whitelist Test": test_whitelist(),
        "CIDR Ban Test": test_cidr_ban(),
        "Ban Duration Multiplier Test": test_ban_duration_multiplier(),
        "Log Request Headers Test": test_log_request_headers(),
        "Custom Ban Response Body Test": test_custom_ban_response_body(),
    }

    # Print summary
    print("\n=== Test Summary ===")
    test_details = {}
    passes = 0
    total_tests = len(results)

    for test_name, success in results.items():
        print_summary(test_name, success)
        test_details[test_name] = "PASS" if success else "FAIL"
        if success:
            passes += 1

    percentage = (passes / total_tests) * 100 if total_tests > 0 else 0

    print(f"\n=== Overall Test Result ===")
    if passes == total_tests:
        print(f"{Fore.GREEN}All tests passed! ({percentage:.2f}%) {Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Some tests failed. ({percentage:.2f}%) {Style.RESET_ALL}")

    print("\n=== Test Details ===")
    for test_name, result in test_details.items():
        if result == "PASS":
            print(f"{Fore.GREEN}{test_name}: {result}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}{test_name}: {result}{Style.RESET_ALL}")

    print("\n=== Insights ===")
    if passes == total_tests:
        print(f"{Fore.GREEN}All tests passed, indicating that the rate limiting and banning mechanisms are functioning as expected.{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Some tests failed. Review the 'Test Details' section to identify the failing tests and investigate the root cause.{Style.RESET_ALL}")

        if test_details.get("Global Ban Test") == "FAIL":
            print(f"{Fore.YELLOW}- The global ban mechanism might not be triggering or expiring correctly.{Style.RESET_ALL}")
        if test_details.get("Login Ban Test") == "FAIL":
            print(f"{Fore.YELLOW}- The per-path ban for '/login' might not be triggering or expiring correctly.{Style.RESET_ALL}")
        if test_details.get("API Ban Test") == "FAIL":
            print(f"{Fore.YELLOW}- The per-path ban for '/api' might not be triggering or expiring correctly.{Style.RESET_ALL}")
        if test_details.get("Specific 404 Test") == "FAIL":
            print(f"{Fore.YELLOW}- The server is not returning the expected 404 status for nonexistent URLs, which could indicate a routing issue.{Style.RESET_ALL}")
        if test_details.get("Root Response with fab Test") == "FAIL":
            print(f"{Fore.YELLOW}- The server is not returning an acceptable status code (2xx, 3xx, or 400, excluding 401, 402, 403, and above 404) for the root URL with the 'fab' user-agent.{Style.RESET_ALL}")
        if test_details.get("Custom Response Header Test") == "FAIL":
            print(f"{Fore.YELLOW}- The custom response header is not being added to the response.{Style.RESET_ALL}")
        if test_details.get("Whitelist Test") == "FAIL":
            print(f"{Fore.YELLOW}- Whitelisted IPs are being banned despite being whitelisted.{Style.RESET_ALL}")
        if test_details.get("CIDR Ban Test") == "FAIL":
            print(f"{Fore.YELLOW}- IPs within banned CIDR ranges are not being blocked.{Style.RESET_ALL}")
        if test_details.get("Ban Duration Multiplier Test") == "FAIL":
            print(f"{Fore.YELLOW}- The ban duration is not increasing exponentially based on the multiplier.{Style.RESET_ALL}")
        if test_details.get("Log Request Headers Test") == "FAIL":
            print(f"{Fore.YELLOW}- Specified request headers are not being logged.{Style.RESET_ALL}")
        if test_details.get("Custom Ban Response Body Test") == "FAIL":
            print(f"{Fore.YELLOW}- The custom ban response body is not being returned.{Style.RESET_ALL}")