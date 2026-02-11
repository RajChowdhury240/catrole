import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def assume_role(account_id: str, role_name: str) -> boto3.Session:
    """Assume the given role in the target account and return a session."""
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    try:
        sts = boto3.client("sts")
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="catrole-session",
            DurationSeconds=3600,
        )
    except NoCredentialsError:
        print("[error] No AWS credentials found. Configure your AWS credentials first.", file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[error] Failed to assume role {role_arn}: {code} — {msg}", file=sys.stderr)
        sys.exit(1)

    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
