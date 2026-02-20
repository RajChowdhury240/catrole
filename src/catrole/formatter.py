import csv
import os
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text

from catrole.utils import generate_filename


def print_table(rows: list[dict], entity_type: str, entity_name: str, account: str) -> None:
    """Print a rich table of IAM permissions to the terminal."""
    console = Console()

    if not rows:
        console.print(f"\n[yellow]No permissions found for {entity_type} '{entity_name}' in account {account}.[/yellow]\n")
        return

    title = f"IAM Permissions for {entity_type} \"{entity_name}\" in account {account}"
    table = Table(title=title, show_lines=False, expand=True, title_style="bold cyan")

    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("Policy Name", style="bold white", max_width=30)
    table.add_column("Type", style="magenta", max_width=18)
    table.add_column("Sid", style="white", max_width=30)
    table.add_column("Effect", max_width=8)
    table.add_column("Action", style="cyan", max_width=40)
    table.add_column("Resource", style="green", max_width=50)
    table.add_column("Condition", style="yellow", max_width=40)

    for idx, row in enumerate(rows, 1):
        effect_style = "bold green" if row["Effect"] == "Allow" else "bold red"
        effect_text = Text(row["Effect"], style=effect_style)

        condition_display = row["Condition"] if row["Condition"] != "-" else "-"

        table.add_row(
            str(idx),
            row["PolicyName"],
            row["PolicyType"],
            row.get("Sid", "-"),
            effect_text,
            row["Action"],
            row["Resource"],
            condition_display,
        )

    console.print()
    console.print(table)
    console.print(f"\n[bold]{len(rows)}[/bold] permission entries found.\n")


def save_csv(rows: list[dict], entity_type: str, account: str, name: str) -> str:
    """Save permission rows to a CSV file. Returns the filename."""
    filename = generate_filename(entity_type, account, name)
    filepath = os.path.join(os.getcwd(), filename)

    fieldnames = ["PolicyName", "PolicyType", "Sid", "Effect", "Action", "Resource", "Condition"]

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return filepath


def print_search_results(results: list[dict], pattern: str) -> None:
    """Print org-wide search results as rich tables (roles table + policies table)."""
    console = Console()

    # Collect role rows and policy rows
    role_rows = []
    policy_rows = []

    for r in results:
        for role in r["roles"]:
            role_rows.append({
                "AccountName": r["AccountName"],
                "AccountId": r["AccountId"],
                "RoleName": role["RoleName"],
                "AttachedPolicies": ", ".join(role["AttachedPolicies"]) if role["AttachedPolicies"] else "-",
            })
        for pol in r["policies"]:
            policy_rows.append({
                "AccountName": r["AccountName"],
                "AccountId": r["AccountId"],
                "PolicyArn": pol["PolicyArn"],
            })

    if not role_rows and not policy_rows:
        console.print(f"\n[yellow]No roles or policies matching '{pattern}' found across the organization.[/yellow]\n")
        return

    # Roles table
    if role_rows:
        table = Table(
            title=f"Roles matching \"{pattern}\"",
            expand=True,
            title_style="bold cyan",
        )
        table.add_column("#", style="dim", width=5, justify="right")
        table.add_column("Account Name", style="bold white", max_width=30)
        table.add_column("Account ID", style="magenta", max_width=14)
        table.add_column("Role Name", style="cyan", max_width=40)
        table.add_column("Attached Policies", style="green")

        for idx, row in enumerate(role_rows, 1):
            table.add_row(str(idx), row["AccountName"], row["AccountId"], row["RoleName"], row["AttachedPolicies"])

        console.print()
        console.print(table)
        console.print(f"\n[bold]{len(role_rows)}[/bold] matching role(s) found.\n")

    # Policies table
    if policy_rows:
        table = Table(
            title=f"Policies matching \"{pattern}\"",
            expand=True,
            title_style="bold cyan",
        )
        table.add_column("#", style="dim", width=5, justify="right")
        table.add_column("Account Name", style="bold white", max_width=30)
        table.add_column("Account ID", style="magenta", max_width=14)
        table.add_column("Policy ARN", style="cyan")

        for idx, row in enumerate(policy_rows, 1):
            table.add_row(str(idx), row["AccountName"], row["AccountId"], row["PolicyArn"])

        console.print()
        console.print(table)
        console.print(f"\n[bold]{len(policy_rows)}[/bold] matching policy/policies found.\n")


def save_search_csv(results: list[dict], pattern: str) -> str | None:
    """Save org-wide search results to a CSV. Returns filepath or None if no results."""
    role_rows = []
    policy_rows = []

    for r in results:
        for role in r["roles"]:
            role_rows.append({
                "AccountName": r["AccountName"],
                "AccountId": r["AccountId"],
                "Type": "Role",
                "Name": role["RoleName"],
                "AttachedPolicies": ", ".join(role["AttachedPolicies"]) if role["AttachedPolicies"] else "",
            })
        for pol in r["policies"]:
            policy_rows.append({
                "AccountName": r["AccountName"],
                "AccountId": r["AccountId"],
                "Type": "Policy",
                "Name": pol["PolicyArn"],
                "AttachedPolicies": "",
            })

    all_rows = role_rows + policy_rows
    if not all_rows:
        return None

    safe_pattern = pattern.replace("*", "STAR").replace("?", "Q").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"iam-search_{safe_pattern}_{timestamp}.csv"
    filepath = os.path.join(os.getcwd(), filename)

    fieldnames = ["AccountName", "AccountId", "Type", "Name", "AttachedPolicies"]

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    return filepath
