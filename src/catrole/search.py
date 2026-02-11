import fnmatch
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from catrole.auth import assume_role

_MAX_WORKERS = 10


def list_active_accounts() -> list[dict]:
    """List all active accounts in the AWS Organization. Returns [{Id, Name}, ...]."""
    try:
        org = boto3.client("organizations")
        accounts = []
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for acct in page["Accounts"]:
                if acct["Status"] == "ACTIVE":
                    accounts.append({"Id": acct["Id"], "Name": acct["Name"]})
        return accounts
    except NoCredentialsError:
        print("[error] No AWS credentials found. Configure your AWS credentials first.", file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to list organization accounts: {code} — {msg}", file=sys.stderr)
        sys.exit(1)


def _match(name: str, pattern: str) -> bool:
    """Case-sensitive fnmatch wildcard matching."""
    return fnmatch.fnmatch(name, pattern)


def _search_account(account: dict, pattern: str, role_name: str) -> dict:
    """Search a single account for roles and policies matching the wildcard pattern.

    Returns:
        {
            "AccountId": str,
            "AccountName": str,
            "roles": [{"RoleName": str, "AttachedPolicies": [str, ...]}, ...],
            "policies": [{"PolicyName": str}, ...],
            "error": str | None,
        }
    """
    account_id = account["Id"]
    account_name = account["Name"]
    result = {
        "AccountId": account_id,
        "AccountName": account_name,
        "roles": [],
        "policies": [],
        "error": None,
    }

    try:
        session = assume_role(account_id, role_name)
    except SystemExit:
        # assume_role calls sys.exit on failure — catch and record as error
        result["error"] = f"Cannot assume {role_name}"
        return result

    iam = session.client("iam")

    # Search roles
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                if _match(role["RoleName"], pattern):
                    # Get attached policies for this role
                    attached = []
                    pol_paginator = iam.get_paginator("list_attached_role_policies")
                    for pol_page in pol_paginator.paginate(RoleName=role["RoleName"]):
                        for pol in pol_page["AttachedPolicies"]:
                            attached.append(pol["PolicyName"])
                    result["roles"].append({
                        "RoleName": role["RoleName"],
                        "AttachedPolicies": attached,
                    })
    except ClientError as e:
        result["error"] = f"Role listing failed: {e.response['Error']['Code']}"

    # Search policies (customer managed only — Local scope)
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for pol in page["Policies"]:
                if _match(pol["PolicyName"], pattern):
                    result["policies"].append({"PolicyArn": pol["Arn"]})
    except ClientError as e:
        if result["error"]:
            result["error"] += f"; Policy listing failed: {e.response['Error']['Code']}"
        else:
            result["error"] = f"Policy listing failed: {e.response['Error']['Code']}"

    return result


def search_all_accounts(pattern: str, role_name: str, account_id: str | None = None, progress_callback=None) -> list[dict]:
    """Search org accounts for roles/policies matching the wildcard pattern.

    Args:
        pattern: Wildcard pattern (e.g. '*lambda*')
        role_name: IAM role name to assume in each account.
        account_id: Optional single account ID to scope the search to.
                    If None, searches all active org accounts.
        progress_callback: Optional callable(account_name, idx, total) for progress updates.

    Returns list of result dicts from _search_account (only those with matches).
    """
    if account_id:
        # Resolve account name via Organizations (falls back to ID)
        account_name = account_id
        try:
            org = boto3.client("organizations")
            desc = org.describe_account(AccountId=account_id)
            account_name = desc["Account"]["Name"]
        except Exception:
            pass
        accounts = [{"Id": account_id, "Name": account_name}]
    else:
        accounts = list_active_accounts()
    total = len(accounts)

    if not accounts:
        print("[warn] No active accounts found in the organization.", file=sys.stderr)
        return []

    results = []

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        future_to_acct = {
            pool.submit(_search_account, acct, pattern, role_name): acct
            for acct in accounts
        }

        for idx, future in enumerate(as_completed(future_to_acct), 1):
            acct = future_to_acct[future]
            if progress_callback:
                progress_callback(acct["Name"], idx, total)

            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "AccountId": acct["Id"],
                    "AccountName": acct["Name"],
                    "roles": [],
                    "policies": [],
                    "error": str(exc),
                }

            # Only keep results that have matches
            if result["roles"] or result["policies"]:
                results.append(result)

    # Sort by account name for consistent output
    results.sort(key=lambda r: r["AccountName"])
    return results
