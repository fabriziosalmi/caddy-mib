import subprocess
import time
from datetime import datetime, timedelta
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configuration
BASE_URL = "http://localhost:8080"
NONEXISTENT_URL = f"{BASE_URL}/nonexistent"  # Endpoint to trigger 404 errors
LOGIN_URL = f"{BASE_URL}/login"             # Endpoint to trigger 404/429 errors
API_URL = f"{BASE_URL}/api"                 # Endpoint to trigger 404/500 errors

# Global settings
GLOBAL_MAX_ERRORS = 10  # Matches max_error_count in Caddyfile
GLOBAL_BAN_DURATION = 10  # Matches ban_duration in Caddyfile (10 seconds)

# Per-path settings
LOGIN_MAX_ERRORS = 5  # Matches max_error_count for /login
LOGIN_BAN_DURATION = 15  # Matches ban_duration for /login (15 seconds)
API_MAX_ERRORS = 8  # Matches max_error_count for /api
API_BAN_DURATION = 20  # Matches ban_duration for /api (20 seconds)

def log(message, **kwargs):
    """Log a message with a timestamp."""
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    print(f"{timestamp} {message}", **kwargs)

def send_request(url, expected_status=None):
    """Send a request using curl and return the HTTP status code and response body."""
    try:
        result = subprocess.run(
            ["curl", "-v", url],
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
        status_code, response_body, colored_status = send_request(NONEXISTENT_URL, expected_status=expected_status)
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
    status_code, response_body, colored_status = send_request(NONEXISTENT_URL, expected_status=404)
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
        status_code, response_body, colored_status = send_request(LOGIN_URL, expected_status=expected_status)
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
    status_code, response_body, colored_status = send_request(LOGIN_URL, expected_status=404) # Expecting 404 after ban expires
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
        status_code, response_body, colored_status = send_request(API_URL, expected_status=expected_status)
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
    status_code, response_body, colored_status = send_request(API_URL, expected_status=404) # Or 500
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
    status_code, _, colored_status = send_request(NONEXISTENT_URL, expected_status=404)
    if status_code == 404:
        log(f"{Fore.GREEN}Received expected 404 for nonexistent URL. Status Code = {colored_status}{Style.RESET_ALL}")
        return True
    else:
        log(f"{Fore.RED}test_specific_404 failed: Expected 404, but got {colored_status}{Style.RESET_ALL}")
        return False

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
        "Specific 404 Test": test_specific_404(),
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
