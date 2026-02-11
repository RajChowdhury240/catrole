# catrole

> catrole is a python pip package which let's you:

AWS IAM Role/Policy permission viewer — see what a role or policy can do.

## Requirements

- Python >= 3.11
- AWS credentials configured (via `~/.aws/credentials`, environment variables, or SSO)
- A cross-account IAM role you can assume in target account(s)

## Installation

### From source (local)

```bash
git clone <repo-url>
cd cat-role
pip install .
```

For development (editable install):

```bash
pip install -e .
```

### From PyPI (remote)

```bash
pip install catrole
```

## Usage

`catrole` requires `-R` to specify an IAM role to assume in the target account.

### Scan a role

```bash
catrole -R my-readonly-role -a 123456789012 -r MyAppRole
```

### Scan a policy

```bash
catrole -R my-readonly-role -a 123456789012 -p MyPolicy
```

### Scan by ARN

```bash
catrole -R my-readonly-role -A arn:aws:iam::123456789012:role/MyAppRole
```

### Search across all org accounts

```bash
catrole -R my-readonly-role -s '*lambda*'
```

### Search within a single account

```bash
catrole -R my-readonly-role -s '*admin*' -a 123456789012
```

Results are printed as a table and automatically saved to a CSV file.

Run `catrole -h` for full help.
