<p align="center">
  <h1 align="center">AEGIS</h1>
  <h3 align="center">イージス</h3>
  <p align="center">Enterprise Security & Quarterly Regression Testing Platform</p>
</p>

---

A self-hosted Streamlit dashboard that connects to your live AWS environment to provide real-time security posture visibility, automated quarterly regression testing, and compliance monitoring across multiple frameworks.

No mock data. No third-party SaaS. All data stays in your infrastructure.

## Features

**Security Dashboard** — Real-time findings from AWS Security Hub and GuardDuty. Severity breakdowns, resource-level drill-down, and threat category analysis.

**Quarterly Regression Testing** — Create test suites, execute automated security checks against your live AWS environment, and track pass/fail trends across quarters. Tests cover IAM, encryption, network security, logging, and compliance controls.

**AWS Environment Health** — Full inventory and audit of EC2 instances, S3 buckets, IAM users, security groups, CloudTrail events, and AWS Config compliance rules. Flags public-facing resources, missing MFA, overly permissive policies, and unencrypted storage.

**Customer Environments** — Multi-account visibility via AWS Organizations. Cross-account security posture scanning through role assumption.

**Compliance** — Maps Security Hub findings to SOC2, CIS AWS Benchmark, HIPAA, PCI-DSS, and NIST 800-53 frameworks. Gap analysis with severity heatmaps and prioritized remediation lists.

**Reports** — Generate quarterly security reports with executive summaries. Export findings, test results, and full reports as CSV or JSON.

## Architecture

```
aegis/
├── app.py                        # Entry point, sidebar, routing
├── config.py                     # Configuration
├── requirements.txt              # Dependencies
├── SECURITY.md                   # Trust model & security policy
├── utils/
│   ├── aws_integration.py        # boto3 calls (Security Hub, GuardDuty, IAM, EC2, S3, CloudTrail, Config, Organizations)
│   ├── auth.py                   # Login gate (SHA-256 hashed password)
│   ├── audit_log.py              # Access logging
│   └── db.py                     # SQLite for regression test persistence
└── pages/
    ├── security_dashboard.py     # Security Hub + GuardDuty
    ├── regression_testing.py     # Test suites, execution, results, trends
    ├── aws_environment.py        # EC2, S3, IAM, SGs, CloudTrail, Config
    ├── customer_environments.py  # AWS Organizations multi-account
    ├── compliance.py             # Framework mapping + gap analysis
    └── reports.py                # Report generation + export
```

## Quick Start

```bash
# Clone
git clone https://github.com/Eeman1113/aegis.git
cd aegis

# Install
pip install -r requirements.txt

# Set a login password
export APP_PASSWORD_HASH=$(python -c "import hashlib; print(hashlib.sha256(b'your-password').hexdigest())")

# Run
streamlit run app.py
```

Configure AWS credentials in the sidebar after login:
- **IAM Role** (recommended) — auto-discovered on EC2/ECS
- **AWS CLI Profile** — reads from `~/.aws/credentials`
- **STS Temporary Credentials** — for short-lived access outside AWS

## AWS Permissions

The app is **read-only**. No write, delete, or mutate calls are made. See [SECURITY.md](SECURITY.md) for the minimum IAM policy.

## Security

- Password-gated login (SHA-256 hash, no plaintext storage)
- Three AWS auth methods ranked by security
- All credentials held in server memory only, never persisted to disk
- Full audit trail of logins, page views, and AWS connections
- No external telemetry or third-party data transmission
- Entire source is readable, unobfuscated Python

Read the full trust model in [SECURITY.md](SECURITY.md).

## Deployment

For production, always:
1. Deploy behind HTTPS (ALB with TLS, or nginx/Caddy with Let's Encrypt)
2. Set `APP_PASSWORD_HASH` environment variable
3. Use IAM Roles instead of access keys
4. Restrict network access (private subnet / VPN)
5. Forward `audit.log` to CloudWatch or your SIEM

## Built With

- [Streamlit](https://streamlit.io) — UI framework
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) — AWS SDK
- [Plotly](https://plotly.com/python/) — Charts and visualizations
- [SQLite](https://www.sqlite.org/) — Local test result persistence

## Author

**Eeman Majumder**

## License

MIT
