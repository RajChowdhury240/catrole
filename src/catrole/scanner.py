import fnmatch
import json
import sys
import urllib.parse

import boto3
from botocore.exceptions import ClientError


def _decode_policy_document(document: str | dict) -> dict:
    """Decode a policy document — handles both URL-encoded strings and dicts."""
    if isinstance(document, str):
        return json.loads(urllib.parse.unquote(document))
    return document


def _flatten_statements(policy_name: str, policy_type: str, document: dict) -> list[dict]:
    """Flatten a policy document's statements into individual action/resource rows."""
    rows = []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        sid = stmt.get("Sid", "-")
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", stmt.get("NotAction", []))
        resources = stmt.get("Resource", stmt.get("NotResource", []))
        condition = stmt.get("Condition", None)

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        is_not_action = "NotAction" in stmt
        is_not_resource = "NotResource" in stmt

        condition_str = json.dumps(condition, separators=(",", ":")) if condition else "-"

        for action in actions:
            for resource in resources:
                rows.append({
                    "PolicyName": policy_name,
                    "PolicyType": policy_type,
                    "Sid": sid,
                    "Effect": effect,
                    "Action": f"NotAction: {action}" if is_not_action else action,
                    "Resource": f"NotResource: {resource}" if is_not_resource else resource,
                    "Condition": condition_str,
                })
    return rows


def _get_policy_statements(iam, policy_arn: str, policy_name: str, policy_type: str) -> list[dict]:
    """Fetch and flatten statements from a managed policy."""
    policy = iam.get_policy(PolicyArn=policy_arn)
    version_id = policy["Policy"]["DefaultVersionId"]
    version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    document = _decode_policy_document(version["PolicyVersion"]["Document"])
    return _flatten_statements(policy_name, policy_type, document)


def scan_role(session: boto3.Session, role_name: str) -> list[dict]:
    """Scan all policies attached to a role and return flattened permission rows."""
    iam = session.client("iam")
    rows = []

    try:
        # Attached managed policies (paginated)
        paginator = iam.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for pol in page["AttachedPolicies"]:
                policy_type = "AWS Managed" if pol["PolicyArn"].startswith("arn:aws:iam::aws:") else "Customer Managed"
                rows.extend(_get_policy_statements(iam, pol["PolicyArn"], pol["PolicyName"], policy_type))

        # Inline policies (paginated)
        paginator = iam.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for pol_name in page["PolicyNames"]:
                response = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                document = _decode_policy_document(response["PolicyDocument"])
                rows.extend(_flatten_statements(pol_name, "Inline", document))

    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to scan role '{role_name}': {code} — {msg}", file=sys.stderr)
        sys.exit(1)

    return rows


def scan_policy(session: boto3.Session, policy_identifier: str) -> list[dict]:
    """Scan a standalone policy by name or ARN and return flattened permission rows."""
    iam = session.client("iam")

    # Determine if it's an ARN or a name
    if policy_identifier.startswith("arn:"):
        policy_arn = policy_identifier
    else:
        # Search for the policy by name across all policies
        policy_arn = _find_policy_arn(iam, policy_identifier)

    try:
        policy_name = policy_arn.split("/")[-1]
        policy_type = "AWS Managed" if ":aws:policy/" in policy_arn else "Customer Managed"
        return _get_policy_statements(iam, policy_arn, policy_name, policy_type)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to scan policy '{policy_identifier}': {code} — {msg}", file=sys.stderr)
        sys.exit(1)


def _find_policy_arn(iam, policy_name: str) -> str:
    """Find a policy ARN by name, searching both local and AWS scopes."""
    for scope in ("Local", "AWS"):
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope=scope):
            for pol in page["Policies"]:
                if pol["PolicyName"] == policy_name:
                    return pol["Arn"]

    print(f"[error] Policy '{policy_name}' not found in Local or AWS scopes.", file=sys.stderr)
    sys.exit(1)


def scan_user(session: boto3.Session, user_name: str) -> dict:
    """Scan an IAM user: info, groups, access keys, MFA devices, and all permission rows.

    Returns:
        {
            "user": dict,
            "groups": [dict, ...],
            "access_keys": [dict, ...],
            "mfa_devices": [dict, ...],
            "direct_policies": [row_dict, ...],
            "group_policies": {group_name: [row_dict, ...]},
        }
    """
    iam = session.client("iam")

    try:
        user = iam.get_user(UserName=user_name)["User"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to get user '{user_name}': {code} — {msg}", file=sys.stderr)
        sys.exit(1)

    # Group memberships
    groups = []
    paginator = iam.get_paginator("list_groups_for_user")
    for page in paginator.paginate(UserName=user_name):
        groups.extend(page["Groups"])

    # Access keys + last-used info
    access_keys = []
    paginator = iam.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=user_name):
        for key in page["AccessKeyMetadata"]:
            info = dict(key)
            try:
                lu = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"]).get("AccessKeyLastUsed", {})
                info["LastUsedDate"] = lu.get("LastUsedDate", "Never")
                info["LastUsedRegion"] = lu.get("Region", "N/A")
                info["LastUsedService"] = lu.get("ServiceName", "N/A")
            except ClientError:
                info["LastUsedDate"] = "Unknown"
                info["LastUsedRegion"] = "N/A"
                info["LastUsedService"] = "N/A"
            access_keys.append(info)

    # MFA devices
    mfa_devices = []
    paginator = iam.get_paginator("list_mfa_devices")
    for page in paginator.paginate(UserName=user_name):
        mfa_devices.extend(page["MFADevices"])

    # Direct attached managed policies
    direct_rows = []
    paginator = iam.get_paginator("list_attached_user_policies")
    for page in paginator.paginate(UserName=user_name):
        for pol in page["AttachedPolicies"]:
            policy_type = "AWS Managed" if pol["PolicyArn"].startswith("arn:aws:iam::aws:") else "Customer Managed"
            direct_rows.extend(_get_policy_statements(iam, pol["PolicyArn"], pol["PolicyName"], policy_type))

    # Direct inline policies
    paginator = iam.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=user_name):
        for pol_name in page["PolicyNames"]:
            resp = iam.get_user_policy(UserName=user_name, PolicyName=pol_name)
            document = _decode_policy_document(resp["PolicyDocument"])
            direct_rows.extend(_flatten_statements(pol_name, "Inline", document))

    # Group-inherited policies (attached + inline per group)
    group_policies: dict[str, list[dict]] = {}
    for grp in groups:
        grp_name = grp["GroupName"]
        g_rows: list[dict] = []
        try:
            paginator = iam.get_paginator("list_attached_group_policies")
            for page in paginator.paginate(GroupName=grp_name):
                for pol in page["AttachedPolicies"]:
                    policy_type = "AWS Managed" if pol["PolicyArn"].startswith("arn:aws:iam::aws:") else "Customer Managed"
                    g_rows.extend(_get_policy_statements(iam, pol["PolicyArn"], pol["PolicyName"], policy_type))
        except ClientError:
            pass
        try:
            paginator = iam.get_paginator("list_group_policies")
            for page in paginator.paginate(GroupName=grp_name):
                for pol_name in page["PolicyNames"]:
                    resp = iam.get_group_policy(GroupName=grp_name, PolicyName=pol_name)
                    document = _decode_policy_document(resp["PolicyDocument"])
                    g_rows.extend(_flatten_statements(pol_name, "Inline", document))
        except ClientError:
            pass
        group_policies[grp_name] = g_rows

    return {
        "user": user,
        "groups": groups,
        "access_keys": access_keys,
        "mfa_devices": mfa_devices,
        "direct_policies": direct_rows,
        "group_policies": group_policies,
    }


def scan_group(session: boto3.Session, group_name: str) -> dict:
    """Scan an IAM group: info, members, and all permission rows.

    Returns:
        {
            "group": dict,
            "members": [dict, ...],
            "policies": [row_dict, ...],
        }
    """
    iam = session.client("iam")

    group = None
    members: list[dict] = []
    try:
        resp = iam.get_group(GroupName=group_name)
        group = resp["Group"]
        members.extend(resp["Users"])
        while resp.get("IsTruncated"):
            resp = iam.get_group(GroupName=group_name, Marker=resp["Marker"])
            members.extend(resp["Users"])
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to get group '{group_name}': {code} — {msg}", file=sys.stderr)
        sys.exit(1)

    rows: list[dict] = []

    # Attached managed policies
    try:
        paginator = iam.get_paginator("list_attached_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            for pol in page["AttachedPolicies"]:
                policy_type = "AWS Managed" if pol["PolicyArn"].startswith("arn:aws:iam::aws:") else "Customer Managed"
                rows.extend(_get_policy_statements(iam, pol["PolicyArn"], pol["PolicyName"], policy_type))
    except ClientError as e:
        print(f"[warn] Could not list attached group policies: {e.response['Error']['Code']}", file=sys.stderr)

    # Inline policies
    try:
        paginator = iam.get_paginator("list_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            for pol_name in page["PolicyNames"]:
                resp_pol = iam.get_group_policy(GroupName=group_name, PolicyName=pol_name)
                document = _decode_policy_document(resp_pol["PolicyDocument"])
                rows.extend(_flatten_statements(pol_name, "Inline", document))
    except ClientError as e:
        print(f"[warn] Could not list inline group policies: {e.response['Error']['Code']}", file=sys.stderr)

    return {
        "group": group,
        "members": members,
        "policies": rows,
    }


def _action_matches(policy_action: str, search_pattern: str) -> bool:
    """Bidirectional case-insensitive fnmatch for IAM actions.

    Checks both directions so that a policy action like 's3:*' matches a
    search for 's3:CreateBucket', and a search for 's3:*' matches a
    specific policy action like 's3:CreateBucket'.
    """
    a = policy_action.lower()
    p = search_pattern.lower()
    return fnmatch.fnmatch(a, p) or fnmatch.fnmatch(p, a)


def scan_role_for_action(session: boto3.Session, role_name: str,
                         search_pattern: str, policy_cache: dict | None = None) -> list[dict]:
    """Scan a role's policies and return rows where the action matches the search pattern.

    Args:
        session: Authenticated boto3 session.
        role_name: IAM role to scan.
        search_pattern: Action pattern (e.g. 's3:CreateBucket', 's3:*').
        policy_cache: Optional dict keyed by policy ARN → list[dict] rows,
                      shared across roles in the same account to avoid redundant API calls.

    Returns:
        List of permission row dicts that match the action pattern.
    """
    if policy_cache is None:
        policy_cache = {}

    iam = session.client("iam")
    all_rows = []

    try:
        # Attached managed policies (paginated)
        paginator = iam.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for pol in page["AttachedPolicies"]:
                arn = pol["PolicyArn"]
                if arn in policy_cache:
                    all_rows.extend(policy_cache[arn])
                else:
                    policy_type = "AWS Managed" if arn.startswith("arn:aws:iam::aws:") else "Customer Managed"
                    rows = _get_policy_statements(iam, arn, pol["PolicyName"], policy_type)
                    policy_cache[arn] = rows
                    all_rows.extend(rows)

        # Inline policies (paginated)
        paginator = iam.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for pol_name in page["PolicyNames"]:
                response = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                document = _decode_policy_document(response["PolicyDocument"])
                all_rows.extend(_flatten_statements(pol_name, "Inline", document))

    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to scan role '{role_name}': {code} — {msg}", file=sys.stderr)
        return []

    # Filter rows by action match
    matched = []
    for row in all_rows:
        action_value = row["Action"]
        # Strip NotAction prefix for matching but keep it in output
        raw_action = action_value.removeprefix("NotAction: ")
        if _action_matches(raw_action, search_pattern):
            matched.append(row)

    return matched
