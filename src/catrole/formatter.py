import csv
import json
import os
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text

from catrole.utils import generate_filename


def _fmt_date(dt) -> str:
    """Format a datetime object or 'Never' string for display."""
    if dt is None or dt == "Never":
        return "Never"
    if isinstance(dt, str):
        return dt
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _permission_table(title: str, rows: list[dict]) -> Table:
    """Build a Rich Table of flattened permission rows."""
    table = Table(title=title, title_style="bold cyan", expand=True, show_lines=False)
    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("Policy Name", style="bold white", max_width=30)
    table.add_column("Type", style="magenta", max_width=18)
    table.add_column("Sid", style="white", max_width=30)
    table.add_column("Effect", max_width=8)
    table.add_column("Action", style="cyan", max_width=40)
    table.add_column("Resource", style="green", max_width=50)
    table.add_column("Condition", style="yellow", max_width=40)

    if not rows:
        table.add_row("", "[dim]None[/dim]", "", "", "", "", "", "")
    else:
        for idx, row in enumerate(rows, 1):
            effect_style = "bold green" if row["Effect"] == "Allow" else "bold red"
            table.add_row(
                str(idx),
                row["PolicyName"],
                row["PolicyType"],
                row.get("Sid", "-"),
                Text(row["Effect"], style=effect_style),
                row["Action"],
                row["Resource"],
                row["Condition"] if row["Condition"] != "-" else "-",
            )
    return table


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


def print_action_search_results(results: list[dict], pattern: str) -> None:
    """Print action search results as a single rich table."""
    console = Console()

    flat_rows = []
    for r in results:
        for match in r["matches"]:
            for row in match["rows"]:
                flat_rows.append({
                    "AccountName": r["AccountName"],
                    "AccountId": r["AccountId"],
                    "RoleName": match["RoleName"],
                    **row,
                })

    if not flat_rows:
        console.print(f"\n[yellow]No roles with action matching '{pattern}' found.[/yellow]\n")
        return

    table = Table(
        title=f"Roles with action matching \"{pattern}\"",
        expand=True,
        title_style="bold cyan",
    )
    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("Account", style="bold white", max_width=25)
    table.add_column("Account ID", style="magenta", max_width=14)
    table.add_column("Role", style="cyan", max_width=30)
    table.add_column("Policy", style="bold white", max_width=25)
    table.add_column("Effect", max_width=8)
    table.add_column("Action", style="cyan", max_width=40)
    table.add_column("Resource", style="green", max_width=45)
    table.add_column("Condition", style="yellow", max_width=35)

    for idx, row in enumerate(flat_rows, 1):
        effect_style = "bold green" if row["Effect"] == "Allow" else "bold red"
        effect_text = Text(row["Effect"], style=effect_style)
        condition_display = row["Condition"] if row["Condition"] != "-" else "-"

        table.add_row(
            str(idx),
            row["AccountName"],
            row["AccountId"],
            row["RoleName"],
            row["PolicyName"],
            effect_text,
            row["Action"],
            row["Resource"],
            condition_display,
        )

    console.print()
    console.print(table)

    role_count = sum(len(r["matches"]) for r in results)
    account_count = len(results)
    console.print(
        f"\n[bold]{len(flat_rows)}[/bold] permission entries across "
        f"[bold]{role_count}[/bold] role(s) in "
        f"[bold]{account_count}[/bold] account(s).\n"
    )


def save_action_search_csv(results: list[dict], pattern: str) -> str | None:
    """Save action search results to CSV. Returns filepath or None if no results."""
    flat_rows = []
    for r in results:
        for match in r["matches"]:
            for row in match["rows"]:
                flat_rows.append({
                    "AccountName": r["AccountName"],
                    "AccountId": r["AccountId"],
                    "RoleName": match["RoleName"],
                    "PolicyName": row["PolicyName"],
                    "PolicyType": row["PolicyType"],
                    "Effect": row["Effect"],
                    "Action": row["Action"],
                    "Resource": row["Resource"],
                    "Condition": row["Condition"],
                })

    if not flat_rows:
        return None

    safe_pattern = pattern.replace("*", "STAR").replace("?", "Q").replace("/", "_").replace(":", "-")
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"iam-action-search_{safe_pattern}_{timestamp}.csv"
    filepath = os.path.join(os.getcwd(), filename)

    fieldnames = ["AccountName", "AccountId", "RoleName", "PolicyName", "PolicyType",
                  "Effect", "Action", "Resource", "Condition"]

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flat_rows)

    return filepath


# ---------------------------------------------------------------------------
# IAM User
# ---------------------------------------------------------------------------

def print_user_details(data: dict, account: str) -> None:
    """Print all details for an IAM user."""
    console = Console()
    user = data["user"]
    user_name = user["UserName"]

    console.print()
    console.print(f"[bold cyan]IAM User:[/bold cyan] [bold white]{user_name}[/bold white]  [dim]Account: {account}[/dim]")
    console.print(f"[dim]ARN:[/dim]              {user['Arn']}")
    console.print(f"[dim]User ID:[/dim]          {user['UserId']}")
    console.print(f"[dim]Path:[/dim]             {user.get('Path', '/')}")
    console.print(f"[dim]Created:[/dim]          {_fmt_date(user.get('CreateDate'))}")
    pwd_last = user.get("PasswordLastUsed")
    console.print(f"[dim]Password Last Used:[/dim] {_fmt_date(pwd_last) if pwd_last else 'Never / console access not enabled'}")
    console.print()

    # Access keys
    access_keys = data["access_keys"]
    ak_table = Table(title=f"Access Keys ({len(access_keys)})", title_style="bold cyan", expand=True)
    ak_table.add_column("#", style="dim", width=4, justify="right")
    ak_table.add_column("Key ID", style="bold white", max_width=22)
    ak_table.add_column("Status", max_width=10)
    ak_table.add_column("Created", style="white", max_width=22)
    ak_table.add_column("Last Used", style="white", max_width=22)
    ak_table.add_column("Region", style="cyan", max_width=18)
    ak_table.add_column("Service", style="green", max_width=25)
    if not access_keys:
        ak_table.add_row("", "[dim]No access keys[/dim]", "", "", "", "", "")
    else:
        for idx, key in enumerate(access_keys, 1):
            status_style = "bold green" if key["Status"] == "Active" else "bold red"
            last_used = key.get("LastUsedDate", "Never")
            ak_table.add_row(
                str(idx),
                key["AccessKeyId"],
                Text(key["Status"], style=status_style),
                _fmt_date(key.get("CreateDate")),
                _fmt_date(last_used),
                key.get("LastUsedRegion", "N/A"),
                key.get("LastUsedService", "N/A"),
            )
    console.print(ak_table)
    console.print()

    # MFA devices
    mfa_devices = data["mfa_devices"]
    mfa_table = Table(title=f"MFA Devices ({len(mfa_devices)})", title_style="bold cyan", expand=True)
    mfa_table.add_column("#", style="dim", width=4, justify="right")
    mfa_table.add_column("Serial Number / ARN", style="bold white")
    mfa_table.add_column("Enabled Date", style="white", max_width=22)
    if not mfa_devices:
        mfa_table.add_row("", "[bold red]No MFA devices — account is not MFA-protected[/bold red]", "")
    else:
        for idx, mfa in enumerate(mfa_devices, 1):
            mfa_table.add_row(str(idx), mfa["SerialNumber"], _fmt_date(mfa.get("EnableDate")))
    console.print(mfa_table)
    console.print()

    # Group memberships
    groups = data["groups"]
    grp_table = Table(title=f"Group Memberships ({len(groups)})", title_style="bold cyan", expand=True)
    grp_table.add_column("#", style="dim", width=4, justify="right")
    grp_table.add_column("Group Name", style="bold white", max_width=40)
    grp_table.add_column("Group ARN", style="cyan")
    if not groups:
        grp_table.add_row("", "[dim]Not a member of any groups[/dim]", "")
    else:
        for idx, grp in enumerate(groups, 1):
            grp_table.add_row(str(idx), grp["GroupName"], grp.get("Arn", "-"))
    console.print(grp_table)
    console.print()

    # Direct permissions
    direct = data["direct_policies"]
    console.print(_permission_table(f'Direct Permissions for "{user_name}"', direct))
    if direct:
        console.print(f"\n[bold]{len(direct)}[/bold] direct permission entries.\n")
    else:
        console.print()

    # Group-inherited permissions
    for grp_name, rows in data["group_policies"].items():
        console.print(_permission_table(f'Permissions via Group "{grp_name}"', rows))
        if rows:
            console.print(f"\n[bold]{len(rows)}[/bold] entries from group [bold]{grp_name}[/bold].\n")
        else:
            console.print()


def save_user_csv(data: dict, account: str, user_name: str) -> str | None:
    """Save user permissions (direct + group-inherited) to CSV. Returns filepath or None."""
    all_rows = []
    for row in data["direct_policies"]:
        all_rows.append({"Source": "Direct", **row})
    for grp_name, rows in data["group_policies"].items():
        for row in rows:
            all_rows.append({"Source": f"Group:{grp_name}", **row})

    if not all_rows:
        return None

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    safe_name = user_name.replace("/", "_")
    filename = f"iam-user_{account}_{safe_name}_{timestamp}.csv"
    filepath = os.path.join(os.getcwd(), filename)

    fieldnames = ["Source", "PolicyName", "PolicyType", "Sid", "Effect", "Action", "Resource", "Condition"]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    return filepath


# ---------------------------------------------------------------------------
# IAM Group
# ---------------------------------------------------------------------------

def print_group_details(data: dict, account: str) -> None:
    """Print all details for an IAM group."""
    console = Console()
    group = data["group"]
    group_name = group["GroupName"]

    console.print()
    console.print(f"[bold cyan]IAM Group:[/bold cyan] [bold white]{group_name}[/bold white]  [dim]Account: {account}[/dim]")
    console.print(f"[dim]ARN:[/dim]      {group['Arn']}")
    console.print(f"[dim]Group ID:[/dim] {group['GroupId']}")
    console.print(f"[dim]Path:[/dim]     {group.get('Path', '/')}")
    console.print(f"[dim]Created:[/dim]  {_fmt_date(group.get('CreateDate'))}")
    console.print()

    # Members
    members = data["members"]
    mem_table = Table(title=f"Members ({len(members)})", title_style="bold cyan", expand=True)
    mem_table.add_column("#", style="dim", width=4, justify="right")
    mem_table.add_column("User Name", style="bold white", max_width=40)
    mem_table.add_column("User ARN", style="cyan")
    mem_table.add_column("Created", style="white", max_width=22)
    if not members:
        mem_table.add_row("", "[dim]No members[/dim]", "", "")
    else:
        for idx, member in enumerate(members, 1):
            mem_table.add_row(
                str(idx),
                member["UserName"],
                member.get("Arn", "-"),
                _fmt_date(member.get("CreateDate")),
            )
    console.print(mem_table)
    console.print()

    # Permissions
    rows = data["policies"]
    console.print(_permission_table(f'Permissions for group "{group_name}"', rows))
    if rows:
        console.print(f"\n[bold]{len(rows)}[/bold] permission entries.\n")
    else:
        console.print()


def save_group_csv(data: dict, account: str, group_name: str) -> str | None:
    """Save group permission rows to CSV. Returns filepath or None."""
    rows = data["policies"]
    if not rows:
        return None

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    safe_name = group_name.replace("/", "_")
    filename = f"iam-group_{account}_{safe_name}_{timestamp}.csv"
    filepath = os.path.join(os.getcwd(), filename)

    fieldnames = ["PolicyName", "PolicyType", "Sid", "Effect", "Action", "Resource", "Condition"]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return filepath


# ---------------------------------------------------------------------------
# IDC Permission Set
# ---------------------------------------------------------------------------

def print_permission_set_details(data: dict, account: str) -> None:
    """Print all details for an AWS Identity Center permission set."""
    console = Console()
    ps = data["permission_set"]
    ps_name = ps["Name"]

    console.print()
    console.print(f"[bold cyan]IDC Permission Set:[/bold cyan] [bold white]{ps_name}[/bold white]  [dim]Account: {account}[/dim]")
    console.print(f"[dim]Permission Set ARN:[/dim] {data['permission_set_arn']}")
    console.print(f"[dim]Instance ARN:[/dim]       {data['instance_arn']}")
    console.print(f"[dim]Identity Store ID:[/dim]  {data.get('identity_store_id', 'N/A')}")
    console.print(f"[dim]Description:[/dim]        {ps.get('Description', '-')}")
    console.print(f"[dim]Session Duration:[/dim]   {ps.get('SessionDuration', 'N/A')}")
    if ps.get("RelayState"):
        console.print(f"[dim]Relay State:[/dim]        {ps['RelayState']}")
    console.print(f"[dim]Created:[/dim]            {_fmt_date(ps.get('CreatedDate'))}")
    console.print()

    # AWS managed policies
    managed = data["managed_policies"]
    m_table = Table(title=f"AWS Managed Policies ({len(managed)})", title_style="bold cyan", expand=True)
    m_table.add_column("#", style="dim", width=4, justify="right")
    m_table.add_column("Policy Name", style="bold white", max_width=40)
    m_table.add_column("Policy ARN", style="cyan")
    if not managed:
        m_table.add_row("", "[dim]None[/dim]", "")
    else:
        for idx, pol in enumerate(managed, 1):
            m_table.add_row(str(idx), pol.get("Name", "-"), pol.get("Arn", "-"))
    console.print(m_table)
    console.print()

    # Customer managed policy references
    cmp = data["customer_managed_policies"]
    cmp_table = Table(title=f"Customer Managed Policy References ({len(cmp)})", title_style="bold cyan", expand=True)
    cmp_table.add_column("#", style="dim", width=4, justify="right")
    cmp_table.add_column("Policy Name", style="bold white", max_width=40)
    cmp_table.add_column("Path", style="cyan", max_width=30)
    if not cmp:
        cmp_table.add_row("", "[dim]None[/dim]", "")
    else:
        for idx, ref in enumerate(cmp, 1):
            cmp_table.add_row(str(idx), ref.get("Name", "-"), ref.get("Path", "/"))
    console.print(cmp_table)
    console.print()

    # Inline policy
    inline = data.get("inline_policy")
    if inline:
        console.print("[bold cyan]Inline Policy:[/bold cyan]")
        try:
            formatted = json.dumps(json.loads(inline), indent=2)
        except Exception:
            formatted = inline
        console.print(f"[dim]{formatted}[/dim]")
    else:
        console.print("[bold cyan]Inline Policy:[/bold cyan] [dim]None[/dim]")
    console.print()

    # Assignments across provisioned accounts
    assignments = data.get("assignments", [])
    n_accounts = len(data["provisioned_accounts"])
    a_table = Table(
        title=f"Assignments ({len(assignments)} total across {n_accounts} provisioned account(s))",
        title_style="bold cyan",
        expand=True,
    )
    a_table.add_column("#", style="dim", width=4, justify="right")
    a_table.add_column("Account ID", style="magenta", max_width=14)
    a_table.add_column("Principal Type", style="bold white", max_width=14)
    a_table.add_column("Principal Name", style="cyan", max_width=40)
    a_table.add_column("Principal ID", style="dim")
    if not assignments:
        placeholder = "[dim]Not provisioned to any accounts[/dim]" if not n_accounts else "[dim]No assignments found[/dim]"
        a_table.add_row("", placeholder, "", "", "")
    else:
        for idx, a in enumerate(assignments, 1):
            a_table.add_row(
                str(idx),
                a["AccountId"],
                a["PrincipalType"],
                a["PrincipalName"],
                a["PrincipalId"],
            )
    console.print(a_table)
    console.print()


def save_permission_set_csv(data: dict, account: str, ps_name: str) -> str | None:
    """Save permission set assignments to CSV. Returns filepath or None."""
    assignments = data.get("assignments", [])
    if not assignments:
        return None

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    safe_name = ps_name.replace("/", "_").replace(" ", "-")
    filename = f"idc-permset_{account}_{safe_name}_{timestamp}.csv"
    filepath = os.path.join(os.getcwd(), filename)

    fieldnames = ["AccountId", "PrincipalType", "PrincipalName", "PrincipalId"]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(assignments)

    return filepath
