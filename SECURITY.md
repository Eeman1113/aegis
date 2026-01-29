# Security Policy

## Trust Model

This application is a **self-hosted** security dashboard. It runs on infrastructure **you** control and connects to **your** AWS accounts. There is no third-party SaaS, no external telemetry, and no data leaves your environment.

### What this application does

- Reads security posture data from your AWS account via boto3 (Security Hub, GuardDuty, IAM, EC2, S3, CloudTrail, Config, Organizations)
- Stores regression test results in a local SQLite database on the server filesystem
- Renders dashboards in the browser via Streamlit

### What this application does NOT do

- Send any data to external servers, analytics services, or third parties
- Store AWS credentials to disk — credentials exist only in server process memory for the duration of the session
- Run any write/mutate operations against your AWS account — all API calls are read-only (`Describe*`, `List*`, `Get*`)
- Include any obfuscated or minified code — the entire source is readable Python

## Authentication

### Application login

Access to the dashboard is gated by a password. The password itself is never stored — only a SHA-256 hash, set via the `APP_PASSWORD_HASH` environment variable.

Generate a hash:

```bash
python -c "import hashlib; print(hashlib.sha256(b'your-password').hexdigest())"
```

If `APP_PASSWORD_HASH` is not set, the app runs in **dev mode** with no login gate. This is intended for local development only. Never deploy without setting this variable.

### AWS authentication

Three methods are supported, listed from most to least secure:

| Method | How it works | When to use |
|---|---|---|
| **IAM Role / Instance Profile** | boto3 auto-discovers credentials from EC2/ECS metadata service. No secrets in the app. | Production deployments on AWS infrastructure |
| **AWS CLI Profile** | User provides a profile name; boto3 reads from `~/.aws/credentials` on the server. | Server with pre-configured AWS CLI |
| **STS Temporary Credentials** | User pastes access key, secret key, and session token into masked fields. | Short-lived access from outside AWS. Only use tokens from `aws sts get-session-token` or SSO — never long-lived IAM keys. |

**IAM Roles are strongly recommended.** They eliminate credential handling entirely.

### Minimum IAM permissions required

The application only needs read access. A suitable IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "securityhub:GetFindings",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeStandardsControls",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "s3:ListAllMyBuckets",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetPublicAccessBlock",
        "cloudtrail:LookupEvents",
        "cloudtrail:DescribeTrails",
        "config:DescribeComplianceByConfigRule",
        "config:GetDiscoveredResourceCounts",
        "organizations:ListAccounts"
      ],
      "Resource": "*"
    }
  ]
}
```

No write, delete, or mutate permissions are required.

## Audit Logging

Every login, logout, page navigation, and AWS connection event is recorded to `audit.log` on the server with timestamps and user identity. This file is excluded from git via `.gitignore`.

Review logs with:

```bash
cat audit.log
```

## Data Storage

| Data | Location | Sensitivity |
|---|---|---|
| Regression test results | `regression_tests.db` (SQLite, local) | Low — contains test pass/fail status, no customer PII |
| Audit trail | `audit.log` (local) | Medium — contains access timestamps and user identifiers |
| AWS credentials | Server process memory only | High — never written to disk, cleared on session end |
| AWS API responses | Streamlit in-memory cache (TTL 5-10 min) | Medium — security findings cached briefly for performance |

Both `regression_tests.db` and `audit.log` are listed in `.gitignore` and will not be committed.

## Deployment Recommendations

1. **Always use HTTPS.** Streamlit's dev server is plain HTTP. In production, place it behind an ALB/NLB with a TLS certificate, or use a reverse proxy (nginx/Caddy) with Let's Encrypt.

2. **Restrict network access.** Run the app in a private subnet or VPN. Do not expose it to the public internet without additional controls (WAF, IP allowlisting).

3. **Set `APP_PASSWORD_HASH`.** Never deploy without it.

4. **Use IAM Roles.** Attach a role to the EC2 instance or ECS task running the app. Avoid access keys entirely.

5. **Rotate credentials.** If STS temporary credentials are used, they expire automatically. Ensure the session token TTL is short (1 hour default).

6. **Monitor the audit log.** Forward `audit.log` to CloudWatch Logs or your SIEM for alerting on suspicious access patterns.

## Reporting Vulnerabilities

If you discover a security issue in this application, please report it privately rather than opening a public issue. Contact the repository maintainer directly.
