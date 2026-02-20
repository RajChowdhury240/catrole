import argparse
import os
import sys

from rich.console import Console

from catrole import __version__
from catrole.auth import assume_role
from catrole.formatter import print_table, save_csv, print_search_results, save_search_csv
from catrole.scanner import scan_policy, scan_role
from catrole.search import search_all_accounts
from catrole.utils import parse_arn, validate_account


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="catrole",
        description="View IAM permissions for a role or policy in an AWS account",
        epilog=(
            "examples:\n"
            "  catrole -R my-readonly-role -a 123456789012 -r MyAppRole\n"
            "  catrole -R my-readonly-role -a 123456789012 -p MyPolicy\n"
            "  catrole -R my-readonly-role -A arn:aws:iam::123456789012:role/MyAppRole\n"
            "  catrole -R my-readonly-role -s '*lambda*'\n"
            "  catrole -R my-readonly-role -s '*admin*' -a 123456789012\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"catrole {__version__}")

    # Cross-account assume role
    parser.add_argument(
        "-R", "--assume-role",
        metavar="ROLE",
        help="IAM role name to assume in the target account(s) for cross-account access "
             "(falls back to ~/.catrole if not provided)",
    )

    # Mode 1: account + role/policy name
    account_group = parser.add_argument_group("account mode")
    account_group.add_argument("-a", "--account", help="AWS account ID (12 digits)")

    target = account_group.add_mutually_exclusive_group()
    target.add_argument("-r", "--role", help="IAM role name to scan")
    target.add_argument("-p", "--policy", help="IAM policy name to scan")

    # Mode 2: direct ARN
    arn_group = parser.add_argument_group("ARN mode")
    arn_group.add_argument("-A", "--arn", help="Full ARN of an IAM role or policy")

    # Mode 3: org-wide search
    search_group = parser.add_argument_group("search mode")
    search_group.add_argument(
        "-s", "--search",
        metavar="PATTERN",
        help="Wildcard pattern to search roles/policies (e.g. '*lambda*', 'admin-*'). "
             "Searches all org accounts, or combine with -a to search a single account",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    assume_role_name = args.assume_role
    if not assume_role_name:
        catrole_file = os.path.expanduser("~/.catrole")
        if os.path.isfile(catrole_file):
            with open(catrole_file) as f:
                assume_role_name = f.read().strip()
        if not assume_role_name:
            parser.error(
                "-R/--assume-role is required (or set a default role in ~/.catrole)"
            )

    # --- Mode 3: Search (org-wide or single account) ---
    if args.search:
        if args.role or args.policy or args.arn:
            parser.error("-s/--search cannot be combined with -r, -p, or -A")

        pattern = args.search
        console = Console()

        account_id = None
        if args.account:
            account_id = validate_account(args.account)
            console.print(f"\n[bold cyan]Searching account {account_id} for pattern:[/bold cyan] [yellow]{pattern}[/yellow]")
        else:
            console.print(f"\n[bold cyan]Searching all org accounts for pattern:[/bold cyan] [yellow]{pattern}[/yellow]")
        console.print(f"[bold cyan]Assuming role:[/bold cyan] [yellow]{assume_role_name}[/yellow]\n")

        def _progress(name, idx, total):
            console.print(f"  [{idx}/{total}] Scanning [bold]{name}[/bold] …", highlight=False)

        results = search_all_accounts(pattern, role_name=assume_role_name, account_id=account_id, progress_callback=_progress)

        # Show errors for accounts that had partial failures
        for r in results:
            if r.get("error"):
                console.print(f"  [dim red]⚠ {r['AccountName']} ({r['AccountId']}): {r['error']}[/dim red]")

        print_search_results(results, pattern)

        csv_path = save_search_csv(results, pattern)
        if csv_path:
            console.print(f"CSV saved to: {csv_path}")
        return

    # --- Mode 1 & 2: Single account scan ---
    if args.arn:
        if args.account or args.role or args.policy:
            parser.error("-A/--arn cannot be used with -a, -r, or -p")
        parsed = parse_arn(args.arn)
        account = parsed["account"]
        entity_type = parsed["type"]
        entity_name = parsed["name"]
    elif args.account:
        account = validate_account(args.account)
        if args.role:
            entity_type = "role"
            entity_name = args.role
        elif args.policy:
            entity_type = "policy"
            entity_name = args.policy
        else:
            parser.error("-a/--account requires either -r/--role or -p/--policy")
    else:
        parser.print_help()
        sys.exit(1)

    # Authenticate
    session = assume_role(account, assume_role_name)

    # Scan
    if entity_type == "role":
        rows = scan_role(session, entity_name)
    else:
        rows = scan_policy(session, entity_name)

    # Output
    print_table(rows, entity_type, entity_name, account)
    if rows:
        csv_path = save_csv(rows, entity_type, account, entity_name)
        print(f"CSV saved to: {csv_path}")


if __name__ == "__main__":
    main()
