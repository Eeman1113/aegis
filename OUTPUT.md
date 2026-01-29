# AEGIS / イージス — Output Detail

Complete breakdown of every screen, data point, and interaction in the application.

---

## Application Flow

```
User opens app
    │
    ▼
┌─────────────────────┐
│   Gate 1: Login     │──── Password checked against SHA-256 hash
│   (password form)   │     stored in APP_PASSWORD_HASH env var
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐     ┌──────────────────────┐
│  Gate 2: AWS Creds  │────▶│  Run in Sample Mode  │
│  (STS credentials)  │     │  (no creds needed)   │
└────────┬────────────┘     └──────────┬───────────┘
         │                             │
         ▼                             ▼
┌─────────────────────────────────────────────────┐
│              Main Dashboard                     │
│  6 pages: Security, Regression, AWS Env,        │
│  Customer Env, Compliance, Reports              │
└─────────────────────────────────────────────────┘
```

---

## Page 1: Security Dashboard

### Tab: Security Hub

**KPI Row (5 metrics):**
| Metric | Source | Example Output |
|--------|--------|----------------|
| CRITICAL | Count of CRITICAL severity findings | `3` |
| HIGH | Count of HIGH severity findings | `12` |
| MEDIUM | Count of MEDIUM severity findings | `28` |
| LOW | Count of LOW severity findings | `19` |
| INFORMATIONAL | Count of INFORMATIONAL findings | `8` |

**Chart: Findings by Severity**
- Bar chart, color-coded: CRITICAL (red), HIGH (orange), MEDIUM (yellow), LOW (green), INFO (gray)
- X-axis: severity levels, Y-axis: count

**Chart: Top Resource Types with Findings**
- Pie chart showing which AWS resource types have the most findings
- Example slices: `AWS::S3::Bucket`, `AWS::EC2::Instance`, `AWS::IAM::User`

**Table: Finding Details**
| Title | Severity | Status | ResourceType | ResourceId | UpdatedAt |
|-------|----------|--------|--------------|------------|-----------|
| S3 bucket does not have server-side encryption enabled | HIGH | FAILED | AWS::S3::Bucket | arn:aws:s3:::acme-temp | 2026-01-28T... |
| IAM root user access key should not exist | CRITICAL | FAILED | AWS::IAM::User | arn:aws:iam::123:root | 2026-01-25T... |
| CloudTrail should be enabled in all regions | MEDIUM | PASSED | AWS::CloudTrail::Trail | arn:aws:cloudtrail:... | 2026-01-27T... |

### Tab: GuardDuty

**KPI Row (4 metrics):**
| Metric | Example |
|--------|---------|
| Total Findings | `18` |
| CRITICAL / HIGH | `5` |
| MEDIUM | `8` |
| LOW | `5` |

**Chart: GuardDuty Findings by Category**
- Bar chart of threat categories extracted from finding types
- Example categories: `UnauthorizedAccess`, `Recon`, `CryptoCurrency`, `Trojan`, `Backdoor`

**Chart: GuardDuty Finding Trend**
- Line chart: X-axis is date, Y-axis is count, colored by severity
- Shows threat activity over time

**Table: Finding Details**
| Title | Type | Severity | ResourceType | Region | CreatedAt |
|-------|------|----------|--------------|--------|-----------|
| UnauthorizedAccess / EC2 — SSHBruteForce | UnauthorizedAccess:EC2/SSHBruteForce | HIGH | Instance | us-east-1 | 2026-01-15T... |
| Recon / EC2 — Portscan | Recon:EC2/Portscan | MEDIUM | Instance | us-east-1 | 2026-01-20T... |

---

## Page 2: Regression Testing

### Tab: Test Suites

**Create New Suite Form:**
- Suite Name (text input)
- Category (dropdown: 10 security categories)
- Description (text area)

**Existing Suites Table:**
| id | name | category | description | created_at |
|----|------|----------|-------------|------------|
| 1 | Core Security Baseline | Authentication & Authorization | Validates MFA, password policy, root account lockdown... | 2026-01-29 |
| 2 | Encryption Audit | Data Encryption (at-rest & in-transit) | Checks S3, EBS, RDS encryption... | 2026-01-29 |

**Sample Mode seeds 6 suites:**
1. Core Security Baseline (Authentication & Authorization)
2. Encryption Audit (Data Encryption)
3. Network Perimeter Check (Network Security)
4. IAM Least Privilege (IAM Policy)
5. Monitoring & Alerting (Logging & Monitoring)
6. Compliance Controls (Compliance Controls)

### Tab: Run Tests

**Execution Form:**
| Field | Options |
|-------|---------|
| Test Suite | Dropdown of created suites |
| Quarter | Q1, Q2, Q3, Q4 |
| Year | 2024, 2025, 2026 |
| Environment | Production, Staging, Development |
| AWS Region | 10 regions |
| Test Categories | Multi-select from 10 categories |

**Live checks executed against AWS (or mock in sample mode):**

| Check | What It Tests | Pass Condition |
|-------|--------------|----------------|
| IAM MFA Enforcement | All IAM users have MFA | 0 users without MFA |
| Access Key Rotation | No user has >1 active key | 0 users with excess keys |
| Security Group Open Ingress | No SG with 0.0.0.0/0 | 0 open security groups |
| S3 Encryption at Rest | All buckets encrypted | 0 unencrypted buckets |
| S3 Versioning | All buckets versioned | 0 buckets without versioning |
| AWS Config Compliance | All Config rules passing | 0 non-compliant rules |
| CloudTrail Multi-Region | Active multi-region trail | At least 1 trail active |

**Execution Result Output:**
| test_name | category | status | duration_seconds | details |
|-----------|----------|--------|------------------|---------|
| IAM MFA Enforcement | Authentication & Authorization | FAILED | 0.5 | 2 users without MFA |
| Security Group Open Ingress | Network Security | FAILED | 0.4 | 3 security groups with 0.0.0.0/0 ingress |
| S3 Encryption at Rest | Data Encryption | PASSED | 0.6 | All buckets encrypted |

### Tab: Results

**Filters:** Quarter, Year, Suite

**Run History Table:**
| id | suite_name | quarter | year | environment | region | status | started_at | completed_at |
|----|-----------|---------|------|-------------|--------|--------|------------|--------------|
| 58 | Core Security Baseline | Q1 | 2026 | Production | us-east-1 | PASSED | 2026-01-29T... | 2026-01-29T... |
| 57 | Core Security Baseline | Q1 | 2026 | Staging | us-west-2 | FAILED | 2026-01-29T... | 2026-01-29T... |

**Drill-down metrics (per run):**
| Metric | Value |
|--------|-------|
| Passed | `5` |
| Failed | `1` |
| Warnings | `1` |

### Tab: Trends

**Chart: Overall Pass Rate by Quarter**
- Line chart with markers
- X-axis: Q1 2025, Q2 2025, ..., Q1 2026
- Y-axis: 0-100%
- Shows improvement trajectory over time

**Chart: Pass Rate by Category**
- Grouped bar chart
- One group per quarter, one bar per category
- Shows which security areas are improving vs lagging

**Chart: Failed Tests Heatmap**
- Color matrix: rows = categories, columns = quarters
- Red = more failures, white = fewer
- Quick visual for persistent problem areas

---

## Page 3: AWS Environment

### Tab: EC2 Instances

**KPIs:**
| Metric | Example |
|--------|---------|
| Total Instances | `13` |
| Running | `10` |
| Stopped | `3` |
| With Public IP | `4` |

**Charts:**
- Pie: Instance state distribution (running/stopped/terminated)
- Bar: Instances by type (t3.micro, m5.large, etc.)

**Table: Full inventory**
| InstanceId | Name | State | InstanceType | LaunchTime | PrivateIp | PublicIp | VpcId |
|-----------|------|-------|--------------|------------|-----------|---------|-------|
| i-0a3f7b... | web-prod-01 | running | t3.medium | 2025-08-15 | 10.0.1.42 | 54.23.1.88 | vpc-abc123 |
| i-1b4e8c... | bastion-prod | running | t3.micro | 2025-03-01 | 10.0.0.10 | 3.91.22.105 | vpc-abc123 |

### Tab: S3 Buckets

**KPIs:**
| Metric | Example |
|--------|---------|
| Total Buckets | `12` |
| Public Access Blocked | `10` |
| Encrypted | `9` |
| Versioning Enabled | `7` |

**Risk Flag:** Red warning showing buckets with security concerns (public access not blocked OR no encryption)

**Table: All buckets with security status**
| BucketName | CreationDate | PublicAccessBlocked | Encryption | Versioning |
|-----------|--------------|---------------------|------------|------------|
| acme-prod-data-lake | 2024-05-10 | True | aws:kms | Enabled |
| acme-temp-processing | 2025-11-20 | False | None | Disabled |

### Tab: IAM Audit

**KPIs:**
| Users | Roles | Policies | Groups | MFA Devices | Account MFA |
|-------|-------|----------|--------|-------------|-------------|
| 14 | 45 | 28 | 8 | 12 | 1 |

**MFA Alert:** Red error listing users WITHOUT MFA:
| UserName | CreateDate | PasswordLastUsed | ActiveAccessKeys |
|----------|-----------|------------------|-----------------|
| deploy-bot | 2024-02-14 | N/A | 2 |
| ci-pipeline | 2024-06-30 | N/A | 1 |

**Policy Audit:** Flags overly permissive policies (Action: *, Resource: *)
| PolicyName | Arn | AttachmentCount | HasStarAction | HasStarResource | OverlyPermissive |
|-----------|-----|-----------------|---------------|-----------------|-----------------|
| DevOpsFullAccess | arn:aws:iam::...policy/DevOps... | 5 | True | True | True |

### Tab: Security Groups

**KPIs:**
| Total Security Groups | Open to Internet (0.0.0.0/0) | Avg Ingress Rules |
|----------------------|------------------------------|-------------------|
| 10 | 3 | 3.2 |

**Alert:** Red warning listing SGs with public ingress:
| GroupId | GroupName | VpcId | OpenPorts |
|---------|-----------|-------|-----------|
| sg-a1b2c3 | bastion-ssh | vpc-abc123 | 22 |
| sg-d4e5f6 | alb-external | vpc-abc123 | 443, 80 |

### Tab: CloudTrail

**Slider:** Hours to look back (1-72, default 24)

**KPIs:**
| Total Events | Unique Users | Event Types |
|-------------|--------------|-------------|
| 42 | 11 | 18 |

**Charts:**
- Bar: Most frequent API calls (DescribeInstances, AssumeRole, PutObject, etc.)
- Pie: Events by user (sarah.chen, ci-pipeline, terraform-deploy, etc.)

**Table: Recent events**
| EventId | EventName | EventSource | EventTime | Username | ResourceType |
|---------|-----------|-------------|-----------|----------|--------------|
| abc123... | AssumeRole | sts.amazonaws.com | 2026-01-29T14:... | ci-pipeline | AWS::IAM::Role |

### Tab: Config

**KPIs:**
| Total Rules | Compliant | Non-Compliant |
|------------|-----------|---------------|
| 14 | 11 | 3 |

**Chart:** Pie chart of compliance status (green/red/gray)

**Alert:** Red warning listing non-compliant rules:
| ConfigRuleName | ComplianceType |
|---------------|----------------|
| s3-bucket-server-side-encryption-enabled | NON_COMPLIANT |
| restricted-ssh | NON_COMPLIANT |

**Chart: Top 20 Resource Types** — bar chart from Config discovered resources
| ResourceType | Count |
|-------------|-------|
| AWS::EC2::Instance | 156 |
| AWS::S3::Bucket | 42 |

---

## Page 4: Customer Environments

### Tab: Organization Accounts

**KPIs:**
| Total Accounts | Active | Suspended |
|---------------|--------|-----------|
| 10 | 10 | 0 |

**Chart:** Pie chart of account status

**Table:**
| AccountId | AccountName | Email | Status | JoinedTimestamp |
|----------|-------------|-------|--------|-----------------|
| 712957802379 | Production | aws-prod@acmecorp.com | ACTIVE | 2023-06-15 |
| 489321076512 | Client A - Prod | client-a@acmecorp.com | ACTIVE | 2024-01-20 |

### Tab: Security Posture (Cross-Account Scan)

**"Scan All Accounts" button** — assumes `OrganizationAccountAccessRole` in each account

**KPIs after scan:**
| Accounts Scanned | Total Findings | Critical/High | Non-Compliant Rules |
|-----------------|----------------|---------------|---------------------|
| 10 | 245 | 38 | 12 |

**Charts:**
- Grouped bar: Security findings per account (total vs critical)
- Stacked bar: Config compliance per account (compliant vs non-compliant)

### Current Account Quick View

Split into two columns showing Security Hub severity counts and Config compliance counts for the connected account.

---

## Page 5: Compliance

### Tab: Overview

**Score Cards (per enabled standard):**
| Standard | Score | Controls |
|---------|-------|----------|
| AWS Foundational Security Best Practices | 79.2% | 67/85 passed |
| CIS AWS Foundations Benchmark v1.4.0 | 79.8% | 71/89 passed |
| PCI DSS v3.2.1 | 67.8% | 42/62 passed |

**Charts:**
- Bar: Standard scores (color-coded red→green by score)
- Stacked bar: Passed vs Failed controls per standard

### Tab: Security Standards

- Full table of enabled standards with scores
- AWS Config rule compliance pie chart (Compliant/Non-Compliant/Not Applicable)
- Full Config rules table

### Tab: Control Status

**Framework mapping** — maps Security Hub finding generators to compliance frameworks:
| Generator Pattern | Mapped Frameworks |
|------------------|-------------------|
| aws-foundational-security-best-practices | SOC2, HIPAA, NIST 800-53 |
| cis-aws-foundations-benchmark | SOC2, CIS AWS Benchmark |
| pci-dss | PCI-DSS |
| nist-800-53 | NIST 800-53 |

**Filter:** Dropdown to select specific framework

**Chart:** Stacked bar — findings by framework and severity (Critical/High/Medium/Low)

**Table:** All findings with framework mapping
| Framework | Title | Severity | Status | ResourceType |
|-----------|-------|----------|--------|--------------|
| SOC2 | S3 bucket does not have encryption | HIGH | FAILED | AWS::S3::Bucket |
| CIS AWS Benchmark | IAM users should have MFA | CRITICAL | FAILED | AWS::IAM::User |

### Tab: Gap Analysis

**KPIs (failed/warning findings):**
| CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL |
|----------|------|--------|-----|---------------|
| 2 | 8 | 14 | 6 | 3 |

**Chart: Gap Heatmap** — color matrix
- Rows: Resource types (AWS::S3::Bucket, AWS::EC2::Instance, etc.)
- Columns: Severity levels
- Color intensity: count of gaps

**Priority Remediation Items Table:**
| Title | Severity | ResourceType | ResourceId |
|-------|----------|--------------|------------|
| IAM root user access key should not exist | CRITICAL | AWS::IAM::User | arn:aws:iam::123:root |
| Security groups should not allow unrestricted port 22 | HIGH | AWS::EC2::SecurityGroup | sg-abc123 |

---

## Page 6: Reports

### Tab: Generate Report

**Inputs:** Quarter + Year

**Generated report sections:**

**Security Hub Summary:**
| Total Findings | CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL |
|---------------|----------|------|--------|-----|---------------|
| 49 | 3 | 12 | 17 | 11 | 6 |

**GuardDuty Summary:**
| Total Threat Findings | Critical + High |
|----------------------|-----------------|
| 18 | 5 |

**AWS Config Compliance:**
| Total Rules | Compliant | Non-Compliant |
|------------|-----------|---------------|
| 14 | 11 | 3 |

**Regression Testing Summary:**
| Test Runs | Total Tests | Passed | Failed | Pass Rate |
|----------|-------------|--------|--------|-----------|
| 12 | 72 | 61 | 11 | 84.7% |

### Tab: Export

**Export options:**
| Format | Content |
|--------|---------|
| Security Hub Findings CSV | All active findings with severity, status, resource |
| GuardDuty Findings CSV | All threat findings with type, severity, resource |
| Config Compliance CSV | All rules with compliance status |
| Regression Test Results CSV | Test results filtered by quarter/year |
| Full Quarterly Report JSON | All sections combined in structured JSON |

Each export triggers a browser download.

### Tab: Historical Comparison

**Chart: Quarterly Test Results & Pass Rate**
- Dual-axis chart
- Bars (stacked): passed (green) + failed (red) test counts
- Line (blue): pass rate percentage on secondary Y-axis
- X-axis: Q1 2025, Q2 2025, ..., Q1 2026

**Chart: Pass Rate Trend by Category**
- Multi-line chart
- One line per test category
- Shows which categories are improving vs declining

**Table:** Full summary data with quarter, year, category, total, passed, failed, pass_rate

---

## Sample Mode Data Characteristics

**Randomization:** Time-based seed (`unix_timestamp % 100000`). Every page load produces different numbers while remaining internally consistent within the session.

**Realism parameters:**

| Data Point | Distribution |
|-----------|-------------|
| Security Hub severities | 5% CRITICAL, 15% HIGH, 35% MEDIUM, 30% LOW, 15% INFO |
| Security Hub statuses | 40% FAILED, 35% PASSED, 15% WARNING, 10% N/A |
| GuardDuty severities | 8% CRITICAL, 20% HIGH, 42% MEDIUM, 30% LOW |
| IAM MFA adoption | ~80% of users have MFA |
| EC2 state distribution | ~75% running, ~25% stopped |
| EC2 public IP | ~30% of instances have public IPs |
| S3 encryption | ~85% encrypted |
| S3 public access blocked | ~90% blocked |
| Security groups open to internet | bastion/ALB groups + ~15% random |
| Config compliance | ~85% compliant rules |
| Organization accounts | 10 accounts, ~95% active |
| Regression pass rates | Q1 2025: ~50-65% → Q1 2026: ~80-95% (improving trend) |

**Finding titles** are real Security Hub control descriptions (30 unique titles).
**GuardDuty types** are real AWS threat type strings (18 unique types).
**Usernames** mix human names and service accounts (17 unique).
**Instance names** follow real naming conventions (web-prod-01, api-prod-02, bastion-prod).
**Bucket names** follow real patterns (acme-prod-data-lake, acme-cloudtrail-logs).
**Config rules** use real AWS Config rule names (18 unique).
**CloudTrail events** use real API call names (20 unique) and event sources (13 unique).

---

## Sidebar Elements

| Element | Live Mode | Sample Mode |
|---------|-----------|-------------|
| Header | `AEGIS \| イージス` | `AEGIS \| イージス` |
| Connection status | Green: `AWS: 123456789012` + ARN | Blue: `Sample Mode` |
| Buttons | `Logout` / `Disconnect` | `Logout` / `Exit Sample` |
| Navigation | 6 radio buttons | 6 radio buttons |
| Footer | `AEGIS v1.0` | `AEGIS v1.0` |

## Banner

Every page shows a centered header:

```
              AEGIS
             イージス
  Enterprise Security & Regression Testing
```

In sample mode, an info banner appears below:
```
ℹ Sample Mode — All data shown is realistic but randomly generated.
  Connect real AWS credentials to see live data.
```

---

## Files Modified / Created

| File | Purpose | Lines |
|------|---------|-------|
| `app.py` | Entry point, login, AWS gate, sample mode, routing | 250 |
| `config.py` | App name, AWS regions, test categories | 52 |
| `utils/aws_integration.py` | Real boto3 API calls (untouched) | 452 |
| `utils/mock_data.py` | Realistic mock data generators | 520 |
| `utils/data_source.py` | Router: mock vs real based on session state | 60 |
| `utils/auth.py` | Password login gate | 55 |
| `utils/audit_log.py` | File-based access logging | 18 |
| `utils/db.py` | SQLite persistence for regression tests | 130 |
| `views/security_dashboard.py` | Security Hub + GuardDuty page | 120 |
| `views/regression_testing.py` | Test suites, execution, results, trends | 230 |
| `views/aws_environment.py` | EC2, S3, IAM, SGs, CloudTrail, Config | 280 |
| `views/customer_environments.py` | Organizations multi-account view | 170 |
| `views/compliance.py` | Framework mapping + gap analysis | 210 |
| `views/reports.py` | Report generation + export | 230 |
| `SECURITY.md` | Trust model, IAM policy, deployment guide | 150 |
| `requirements.txt` | 5 dependencies | 5 |
| `.gitignore` | Blocks secrets, db, logs, caches | 27 |
| **Total** | | **~3,500** |
