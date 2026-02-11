import re
import sys
from datetime import datetime


def parse_arn(arn: str) -> dict:
    """Parse an IAM ARN and extract account, type (role/policy), and name."""
    pattern = r"^arn:aws:iam::(\d{12}):(role|policy)/(.+)$"
    match = re.match(pattern, arn)
    if not match:
        print(f"[error] Invalid IAM ARN format: {arn}", file=sys.stderr)
        print("  Expected: arn:aws:iam::<12-digit-account>:role/<name> or arn:aws:iam::<12-digit-account>:policy/<name>", file=sys.stderr)
        sys.exit(1)
    return {
        "account": match.group(1),
        "type": match.group(2),
        "name": match.group(3),
    }


def generate_filename(entity_type: str, account: str, name: str) -> str:
    """Generate CSV filename: iam-{role|policy}_{account}_{name}_YYYYMMDDHHMMSS.csv"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    safe_name = name.replace("/", "_")
    return f"iam-{entity_type}_{account}_{safe_name}_{timestamp}.csv"


def validate_account(account: str) -> str:
    """Validate AWS account ID is 12 digits."""
    if not re.match(r"^\d{12}$", account):
        print(f"[error] Account ID must be exactly 12 digits, got: {account}", file=sys.stderr)
        sys.exit(1)
    return account
