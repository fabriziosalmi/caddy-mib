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
GLOBAL_BAN_DURATION = 10  # Matches ban_duration in Caddyfile (10 seconds)

# Per-path settings
LOGIN_MAX_ERRORS = 5  # Matches max_error_count for /login
LOGIN_BAN_DURATION = 15  # Matches ban_duration for /login (15 seconds)
API_MAX_ERRORS = 8  # Matches max_error_count for /api
API_BAN_DURATION = 20  # Matches ban_duration for /api (20 seconds)

def log(message):
    """Log a message with a timestamp."""
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    print(f"{timestamp} {message}")

def send_request(url):
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
        match = re.search(r"HTTP/\d\.\d (\d+)", result.stderr)
        status_code = int(match.group(1)) if match else 0
        # Extract response body
        response_body = result.stdout
        return status_code, response_body
    except subprocess.CalledProcessError as e:
        match = re.search(r"HTTP/\d+\.\d+ (\d+)", e.stderr)
        status_code = int(match.group(1)) if match else 0
        if "HTTP/1.1 " in e.stderr:
            status_code = int(e.stderr.split("HTTP/1.1 ")[1].split()[0])
            response_body = e.stdout
            return status_code, f"Server unreachable or other error: {e.stderr.strip()}"
        else:
            log(f"Error: {e.stderr}")
            return 0, "Server unreachable or other error"
    except re.error as e:
        log(f"Regex error: {type(e).__name__} - {e}")
        return 0, "Regex error"
    except ValueError as e:
        log(f"Value error: {type(e).__name__} - {e}")
        return 0, "Value error"
    except TypeError as e:
        log(f"Type error: {type(e).__name__} - {e}")
        return 0, "Type error"
    except Exception as e:
        log(f"Unexpected error: {type(e).__name__} - {e}")
        return 0, "Unexpected error"

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
            return True  # Indicate success for this test
        elif status_code == 0:
            log("Failed to send request. Aborting test.")
            return False

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
            return False

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
            return False

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
