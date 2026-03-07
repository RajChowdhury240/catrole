import sys

import boto3
from botocore.exceptions import ClientError


def _find_permission_set_arn(sso_admin, instance_arn: str, name: str) -> str | None:
    """Iterate all permission sets in the instance and return the ARN matching name."""
    paginator = sso_admin.get_paginator("list_permission_sets")
    for page in paginator.paginate(InstanceArn=instance_arn):
        for ps_arn in page["PermissionSets"]:
            try:
                desc = sso_admin.describe_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=ps_arn,
                )["PermissionSet"]
                if desc["Name"] == name:
                    return ps_arn
            except ClientError:
                continue
    return None


def scan_permission_set(session: boto3.Session, permission_set_name: str, region: str | None = None) -> dict:
    """Scan an AWS Identity Center permission set and return all details.

    Returns:
        {
            "permission_set": dict,
            "instance_arn": str,
            "permission_set_arn": str,
            "identity_store_id": str,
            "managed_policies": [{"Name": str, "Arn": str}, ...],
            "customer_managed_policies": [{"Name": str, "Path": str}, ...],
            "inline_policy": str | None,
            "provisioned_accounts": [str, ...],
            "assignments": [{"AccountId", "PrincipalType", "PrincipalId", "PrincipalName"}, ...],
        }
    """
    client_kwargs = {"region_name": region} if region else {}
    sso_admin = session.client("sso-admin", **client_kwargs)

    # Discover the SSO instance
    try:
        instances = sso_admin.list_instances()["Instances"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to list SSO instances: {code} — {msg}", file=sys.stderr)
        sys.exit(1)

    if not instances:
        print("[error] No AWS Identity Center instances found in this account.", file=sys.stderr)
        sys.exit(1)

    instance = instances[0]
    instance_arn = instance["InstanceArn"]
    identity_store_id = instance.get("IdentityStoreId", "")

    # Find permission set ARN by name
    try:
        ps_arn = _find_permission_set_arn(sso_admin, instance_arn, permission_set_name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to search permission sets: {code} — {msg}", file=sys.stderr)
        sys.exit(1)

    if not ps_arn:
        print(f"[error] Permission set '{permission_set_name}' not found.", file=sys.stderr)
        sys.exit(1)

    # Describe the permission set
    try:
        ps = sso_admin.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn,
        )["PermissionSet"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to describe permission set: {code} — {msg}", file=sys.stderr)
        sys.exit(1)

    # AWS managed policies
    managed_policies = []
    try:
        paginator = sso_admin.get_paginator("list_managed_policies_in_permission_set")
        for page in paginator.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
            managed_policies.extend(page["AttachedManagedPolicies"])
    except ClientError as e:
        print(f"[warn] Could not list managed policies: {e.response['Error']['Code']}", file=sys.stderr)

    # Customer managed policy references
    customer_managed_policies = []
    try:
        paginator = sso_admin.get_paginator("list_customer_managed_policy_references_in_permission_set")
        for page in paginator.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
            customer_managed_policies.extend(page["CustomerManagedPolicyReferences"])
    except ClientError as e:
        print(f"[warn] Could not list customer managed policies: {e.response['Error']['Code']}", file=sys.stderr)

    # Inline policy
    inline_policy = None
    try:
        resp = sso_admin.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn,
        )
        raw = resp.get("InlinePolicy", "")
        inline_policy = raw if raw else None
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntityException"):
            print(f"[warn] Could not get inline policy: {e.response['Error']['Code']}", file=sys.stderr)

    # Accounts where this permission set is provisioned
    provisioned_accounts = []
    try:
        paginator = sso_admin.get_paginator("list_accounts_for_provisioned_permission_set")
        for page in paginator.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
            provisioned_accounts.extend(page["AccountIds"])
    except ClientError as e:
        print(f"[warn] Could not list provisioned accounts: {e.response['Error']['Code']}", file=sys.stderr)

    # Assignments: for each provisioned account, list principals and resolve names
    assignments = []
    identitystore = session.client("identitystore", **client_kwargs)
    for account_id in provisioned_accounts:
        try:
            paginator = sso_admin.get_paginator("list_account_assignments")
            for page in paginator.paginate(
                InstanceArn=instance_arn,
                AccountId=account_id,
                PermissionSetArn=ps_arn,
            ):
                for a in page["AccountAssignments"]:
                    principal_name = a["PrincipalId"]  # fallback if resolution fails
                    try:
                        if a["PrincipalType"] == "USER":
                            user_resp = identitystore.describe_user(
                                IdentityStoreId=identity_store_id,
                                UserId=a["PrincipalId"],
                            )
                            principal_name = user_resp.get("UserName", a["PrincipalId"])
                        elif a["PrincipalType"] == "GROUP":
                            grp_resp = identitystore.describe_group(
                                IdentityStoreId=identity_store_id,
                                GroupId=a["PrincipalId"],
                            )
                            principal_name = grp_resp.get("DisplayName", a["PrincipalId"])
                    except ClientError:
                        pass
                    assignments.append({
                        "AccountId": account_id,
                        "PrincipalType": a["PrincipalType"],
                        "PrincipalId": a["PrincipalId"],
                        "PrincipalName": principal_name,
                    })
        except ClientError as e:
            print(
                f"[warn] Could not list assignments for account {account_id}: "
                f"{e.response['Error']['Code']}",
                file=sys.stderr,
            )

    return {
        "permission_set": ps,
        "instance_arn": instance_arn,
        "permission_set_arn": ps_arn,
        "identity_store_id": identity_store_id,
        "managed_policies": managed_policies,
        "customer_managed_policies": customer_managed_policies,
        "inline_policy": inline_policy,
        "provisioned_accounts": provisioned_accounts,
        "assignments": assignments,
    }
