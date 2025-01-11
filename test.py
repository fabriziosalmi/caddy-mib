import requests
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.box import SIMPLE_HEAVY

# Initialize rich console
console = Console()

# Test configuration
url = "http://localhost:8080/notexistent"
expected_statuses = [404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 403]

# Results storage
results = []

console.print("\n[bold blue]Starting HTTP Tests...[/bold blue]\n")

for i in track(range(101), description="Sending requests...", transient=True):
    try:
        response = requests.get(url, timeout=5)  # Added timeout to avoid potential hangs
        actual_status = response.status_code
        expected_status = expected_statuses[i]
        
        if actual_status == expected_status:
            status = "[green]PASS[/green]"
        else:
            status = "[red]FAIL[/red]"

        results.append({
            "Attempt": i + 1,
            "Expected": expected_status,
            "Received": actual_status,
            "Status": status
        })
    except requests.RequestException as e:
        console.print(f"[red]Error during request {i + 1}:[/red] {e}")
        results.append({
            "Attempt": i + 1,
            "Expected": expected_statuses[i],
            "Received": "Error",
            "Status": "[red]FAIL[/red]"
        })

# Display results in a table
console.print("\n[bold blue]Test Results[/bold blue]\n")
table = Table(title="HTTP Test Results", box=SIMPLE_HEAVY)
table.add_column("Attempt", justify="center")
table.add_column("Expected Status", justify="center")
table.add_column("Received Status", justify="center")
table.add_column("Status", justify="center")

for result in results:
    table.add_row(str(result["Attempt"]), 
                  str(result["Expected"]), 
                  str(result["Received"]), 
                  result["Status"])

console.print(table)

# Final summary
passes = len([r for r in results if r["Status"] == "[green]PASS[/green]"])
console.print(f"\n[bold yellow]Summary:[/bold yellow] {passes}/101 tests passed.")
if passes == 101:
    console.print("[bold green]All tests passed successfully![/bold green]")
else:
    console.print("[bold red]Some tests failed. Please review the results.[/bold red]")
