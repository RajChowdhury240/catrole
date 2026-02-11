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
