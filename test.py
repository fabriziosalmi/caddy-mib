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
