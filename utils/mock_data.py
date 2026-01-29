"""High-quality realistic mock data generator.

Every function mirrors utils/aws_integration.py but returns randomized,
realistic data. Uses time-based seeds so data is different on each page load
while remaining internally consistent within a single session.
"""

import random
import string
import hashlib
import pandas as pd
import numpy as np
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Seed — different on each app run, consistent within a session
# ---------------------------------------------------------------------------
_SESSION_SEED = int(datetime.utcnow().timestamp()) % 100000


def _rng(salt: str = "") -> random.Random:
    """Return a seeded RNG unique to the call site."""
    return random.Random(f"{_SESSION_SEED}-{salt}")


def _fake_id(prefix: str, length: int = 17, salt: str = "") -> str:
    r = _rng(salt + prefix)
    chars = string.ascii_lowercase + string.digits
    return prefix + "".join(r.choices(chars, k=length))


def _fake_arn(service: str, resource: str, account: str = "123456789012", region: str = "us-east-1") -> str:
    return f"arn:aws:{service}:{region}:{account}:{resource}"


def _random_ip(r: random.Random, public: bool = True) -> str:
    if public:
        return f"{r.randint(1,223)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}"
    return f"10.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}"


def _recent_time(r: random.Random, hours_back: int = 720) -> str:
    delta = timedelta(hours=r.randint(0, hours_back), minutes=r.randint(0, 59))
    return (datetime.utcnow() - delta).isoformat() + "Z"


# ---------------------------------------------------------------------------
# Realistic name pools
# ---------------------------------------------------------------------------

_FINDING_TITLES = [
    "S3 bucket does not have server-side encryption enabled",
    "IAM root user access key should not exist",
    "CloudTrail should be enabled in all regions",
    "Security groups should not allow unrestricted ingress to port 22",
    "RDS DB instances should have encryption at rest enabled",
    "IAM users should have MFA enabled",
    "EBS volumes should be encrypted at rest",
    "Lambda functions should not have public access",
    "VPC flow logging should be enabled in all VPCs",
    "S3 bucket policy should not allow public read access",
    "IAM password policy should require at least one uppercase letter",
    "ALB should have HTTP to HTTPS redirection configured",
    "Security groups should not allow unrestricted ingress to port 3389",
    "RDS snapshots should not be publicly accessible",
    "CloudFront distributions should have origin access identity enabled",
    "DynamoDB tables should have encryption enabled",
    "Elasticsearch domains should have encryption at rest enabled",
    "EC2 instances should not have public IP addresses",
    "SNS topics should be encrypted at rest",
    "Secrets Manager secrets should be rotated within 90 days",
    "GuardDuty should be enabled",
    "IAM policies should not allow full administrative privileges",
    "S3 buckets should have versioning enabled",
    "KMS keys should have rotation enabled",
    "ECS task definitions should not share the host process namespace",
    "Redshift clusters should have audit logging enabled",
    "CloudWatch log groups should have retention policies",
    "API Gateway REST API stages should have SSL certificates",
    "ECR repositories should have image scanning enabled",
    "WAF WebACL should be associated with ALB",
]

_GUARDDUTY_TYPES = [
    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
    "Recon:EC2/PortProbeUnprotectedPort",
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "Trojan:EC2/BlackholeTraffic",
    "Backdoor:EC2/DenialOfService.Tcp",
    "Recon:EC2/Portscan",
    "UnauthorizedAccess:EC2/SSHBruteForce",
    "Persistence:IAMUser/AnomalousBehavior",
    "Discovery:S3/MaliciousIPCaller.Custom",
    "Exfiltration:S3/AnomalousBehavior",
    "Impact:EC2/WinRMBruteForce",
    "CredentialAccess:IAMUser/AnomalousBehavior",
    "DefenseEvasion:EC2/UnusualNetworkPort",
    "InitialAccess:IAMUser/AnomalousBehavior",
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
    "Recon:IAMUser/MaliciousIPCaller",
    "Impact:EC2/AbusedDomainRequest.Reputation",
]

_USERNAMES = [
    "sarah.chen", "james.wilson", "priya.patel", "marcus.johnson",
    "elena.rodriguez", "david.kim", "fatima.ali", "alex.nguyen",
    "ci-pipeline", "terraform-deploy", "lambda-execution",
    "admin-ops", "security-scanner", "backup-service",
    "root", "deploy-bot", "monitoring-agent",
]

_INSTANCE_NAMES = [
    "web-prod-01", "web-prod-02", "web-prod-03",
    "api-prod-01", "api-prod-02",
    "worker-prod-01", "worker-prod-02", "worker-prod-03",
    "bastion-prod", "nat-gateway-01",
    "db-replica-01", "cache-prod-01",
    "monitoring-01", "jenkins-ci", "staging-web-01",
    "dev-sandbox-01", "ml-training-01", "etl-processor-01",
]

_BUCKET_NAMES = [
    "acme-prod-data-lake", "acme-prod-logs", "acme-app-assets",
    "acme-backup-vault-2024", "acme-cloudtrail-logs",
    "acme-config-snapshots", "acme-ml-training-data",
    "acme-client-uploads", "acme-terraform-state",
    "acme-lambda-deployments", "acme-analytics-exports",
    "acme-dr-replica-west", "acme-compliance-reports",
    "acme-shared-media", "acme-temp-processing",
]

_POLICY_NAMES = [
    "DevOpsFullAccess", "DataScienceS3ReadWrite", "LambdaDeployPolicy",
    "CICDPipelineAccess", "SecurityAuditCustom", "BackupVaultAccess",
    "MonitoringDashboardAccess", "ClientDataReadOnly", "ECSTaskExecutionCustom",
    "CrossAccountAssumeRole", "KMSKeyManagement", "CloudFormationDeploy",
]

_SG_NAMES = [
    "web-tier-prod", "api-tier-prod", "db-tier-prod",
    "bastion-ssh", "monitoring-ingress", "lambda-vpc-sg",
    "ecs-tasks-prod", "redis-cache-sg", "alb-external",
    "internal-services", "vpn-access", "default",
]

_EVENT_NAMES = [
    "DescribeInstances", "AssumeRole", "CreateLogStream",
    "GetBucketAcl", "PutObject", "DescribeSecurityGroups",
    "ListBuckets", "GetCallerIdentity", "DescribeAlarms",
    "RunInstances", "StopInstances", "CreateUser",
    "AttachRolePolicy", "DeleteBucket", "ModifyInstanceAttribute",
    "AuthorizeSecurityGroupIngress", "CreateSnapshot",
    "DescribeSubnets", "GetSecretValue", "UpdateFunctionCode",
]

_EVENT_SOURCES = [
    "ec2.amazonaws.com", "s3.amazonaws.com", "iam.amazonaws.com",
    "sts.amazonaws.com", "lambda.amazonaws.com", "cloudwatch.amazonaws.com",
    "logs.amazonaws.com", "kms.amazonaws.com", "secretsmanager.amazonaws.com",
    "elasticloadbalancing.amazonaws.com", "rds.amazonaws.com",
    "config.amazonaws.com", "cloudtrail.amazonaws.com",
]

_CONFIG_RULES = [
    "s3-bucket-server-side-encryption-enabled",
    "iam-user-mfa-enabled",
    "ec2-instance-no-public-ip",
    "rds-instance-encryption-enabled",
    "vpc-flow-logs-enabled",
    "cloudtrail-enabled",
    "iam-root-access-key-check",
    "s3-bucket-public-read-prohibited",
    "encrypted-volumes",
    "iam-password-policy",
    "restricted-ssh",
    "s3-bucket-versioning-enabled",
    "multi-region-cloudtrail-enabled",
    "rds-snapshot-encrypted",
    "guardduty-enabled-centralized",
    "cloud-watch-log-group-encrypted",
    "elb-tls-https-listeners-only",
    "api-gw-ssl-enabled",
]

_RESOURCE_TYPES = [
    "AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::IAM::User",
    "AWS::IAM::Role", "AWS::IAM::Policy", "AWS::RDS::DBInstance",
    "AWS::Lambda::Function", "AWS::EC2::SecurityGroup",
    "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::CloudTrail::Trail",
    "AWS::EC2::VPC", "AWS::ECS::Service", "AWS::DynamoDB::Table",
    "AWS::KMS::Key", "AWS::SNS::Topic", "AWS::SQS::Queue",
]

_ORG_ACCOUNTS = [
    {"name": "Production", "email": "aws-prod@acmecorp.com"},
    {"name": "Staging", "email": "aws-staging@acmecorp.com"},
    {"name": "Development", "email": "aws-dev@acmecorp.com"},
    {"name": "Security Audit", "email": "aws-security@acmecorp.com"},
    {"name": "Shared Services", "email": "aws-shared@acmecorp.com"},
    {"name": "Data Analytics", "email": "aws-analytics@acmecorp.com"},
    {"name": "Client A - Prod", "email": "client-a@acmecorp.com"},
    {"name": "Client B - Prod", "email": "client-b@acmecorp.com"},
    {"name": "Client C - Prod", "email": "client-c@acmecorp.com"},
    {"name": "Sandbox", "email": "aws-sandbox@acmecorp.com"},
]

_INSTANCE_TYPES = [
    "t3.micro", "t3.small", "t3.medium", "t3.large",
    "m5.large", "m5.xlarge", "m5.2xlarge",
    "c5.large", "c5.xlarge",
    "r5.large", "r5.xlarge",
    "p3.2xlarge",
]

_GENERATORS = [
    "aws-foundational-security-best-practices/v/1.0.0",
    "cis-aws-foundations-benchmark/v/1.4.0",
    "pci-dss/v/3.2.1",
    "nist-800-53/v/5.0.0",
    "aws-foundational-security-best-practices/v/1.0.0",
    "cis-aws-foundations-benchmark/v/1.2.0",
]


# ---------------------------------------------------------------------------
# Mock implementations — mirror aws_integration.py signatures
# ---------------------------------------------------------------------------

def check_aws_connection(region: str | None = None) -> dict:
    r = _rng("conn")
    acct = f"{r.randint(100000000000, 999999999999)}"
    return {
        "connected": True,
        "account": acct,
        "arn": f"arn:aws:iam::{acct}:user/demo-user",
        "user_id": _fake_id("AIDA", 16, "conn"),
    }


def get_security_hub_findings(region: str | None = None, max_results: int = 100) -> pd.DataFrame:
    r = _rng("shub" + str(region))
    n = r.randint(35, min(max_results, 80))
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    sev_weights = [0.05, 0.15, 0.35, 0.30, 0.15]
    statuses = ["FAILED", "PASSED", "WARNING", "NOT_AVAILABLE"]
    status_weights = [0.40, 0.35, 0.15, 0.10]

    rows = []
    for i in range(n):
        ri = random.Random(f"{_SESSION_SEED}-shub-{i}")
        sev = ri.choices(severities, weights=sev_weights)[0]
        res_type = ri.choice(_RESOURCE_TYPES)
        rows.append({
            "Id": _fake_arn("securityhub", f"finding/{_fake_id('', 32, f'shf{i}')}"),
            "Title": ri.choice(_FINDING_TITLES),
            "Severity": sev,
            "Status": ri.choices(statuses, weights=status_weights)[0],
            "ResourceType": res_type,
            "ResourceId": _fake_arn(
                res_type.split("::")[1].lower() if "::" in res_type else "unknown",
                _fake_id("", 12, f"res{i}"),
            ),
            "GeneratorId": ri.choice(_GENERATORS),
            "CreatedAt": _recent_time(ri, 2160),
            "UpdatedAt": _recent_time(ri, 168),
            "Description": f"This control checks whether {ri.choice(_FINDING_TITLES).lower()}.",
        })
    return pd.DataFrame(rows)


def get_security_hub_standards(region: str | None = None) -> pd.DataFrame:
    r = _rng("standards")
    standards = [
        ("arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
         "AWS Foundational Security Best Practices"),
        ("arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0",
         "CIS AWS Foundations Benchmark v1.4.0"),
        ("arn:aws:securityhub:::standards/pci-dss/v/3.2.1",
         "PCI DSS v3.2.1"),
    ]
    rows = []
    for arn, name in standards:
        total = r.randint(40, 120)
        score = r.uniform(62, 96)
        passed = int(total * score / 100)
        failed = total - passed
        rows.append({
            "StandardArn": arn,
            "Status": "READY",
            "TotalControls": total,
            "Passed": passed,
            "Failed": failed,
            "Score": round(score, 1),
        })
    return pd.DataFrame(rows)


def get_guardduty_findings(region: str | None = None, max_results: int = 50) -> pd.DataFrame:
    r = _rng("gd" + str(region))
    n = r.randint(8, min(max_results, 35))
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_weights = [0.08, 0.20, 0.42, 0.30]
    resource_types = ["Instance", "AccessKey", "S3Bucket"]

    rows = []
    for i in range(n):
        ri = random.Random(f"{_SESSION_SEED}-gd-{i}")
        gd_type = ri.choice(_GUARDDUTY_TYPES)
        sev_label = ri.choices(severities, weights=sev_weights)[0]
        sev_score = {"CRITICAL": ri.uniform(8.5, 10), "HIGH": ri.uniform(7, 8.4),
                     "MEDIUM": ri.uniform(4, 6.9), "LOW": ri.uniform(1, 3.9)}[sev_label]
        rows.append({
            "Id": _fake_id("", 32, f"gd{i}"),
            "Title": gd_type.replace("/", " — ").replace(":", " / "),
            "Type": gd_type,
            "Severity": sev_label,
            "SeverityScore": round(sev_score, 1),
            "Region": region or "us-east-1",
            "ResourceType": ri.choice(resource_types),
            "CreatedAt": _recent_time(ri, 1440),
            "UpdatedAt": _recent_time(ri, 72),
            "Description": f"EC2 instance or IAM principal involved in {gd_type.split(':')[0].lower()} activity.",
        })
    return pd.DataFrame(rows)


def get_iam_summary(region: str | None = None) -> dict:
    r = _rng("iamsummary")
    return {
        "Users": r.randint(8, 35),
        "Roles": r.randint(20, 80),
        "Policies": r.randint(15, 60),
        "Groups": r.randint(4, 15),
        "MFADevices": r.randint(5, 30),
        "AccountMFAEnabled": 1,
    }


def get_iam_users(region: str | None = None) -> pd.DataFrame:
    r = _rng("iamusers")
    users = r.sample(_USERNAMES, k=min(len(_USERNAMES), r.randint(8, 14)))
    rows = []
    for i, name in enumerate(users):
        ri = random.Random(f"{_SESSION_SEED}-iamu-{i}")
        has_mfa = ri.random() > 0.2  # 80% have MFA
        active_keys = ri.choice([0, 1, 1, 1, 2])
        create_days = ri.randint(30, 900)
        last_login_days = ri.randint(0, 90)
        rows.append({
            "UserName": name,
            "UserId": _fake_id("AIDA", 16, f"uid{i}"),
            "Arn": f"arn:aws:iam::123456789012:user/{name}",
            "CreateDate": str(datetime.utcnow() - timedelta(days=create_days)),
            "PasswordLastUsed": str(datetime.utcnow() - timedelta(days=last_login_days))
                if ri.random() > 0.15 else "N/A",
            "MFAEnabled": has_mfa,
            "ActiveAccessKeys": active_keys,
        })
    return pd.DataFrame(rows)


def get_iam_policies_audit(region: str | None = None) -> pd.DataFrame:
    r = _rng("iampolicies")
    policies = r.sample(_POLICY_NAMES, k=min(len(_POLICY_NAMES), r.randint(6, 10)))
    rows = []
    for i, name in enumerate(policies):
        ri = random.Random(f"{_SESSION_SEED}-pol-{i}")
        has_star_action = ri.random() < 0.15
        has_star_resource = ri.random() < 0.3
        rows.append({
            "PolicyName": name,
            "Arn": f"arn:aws:iam::123456789012:policy/{name}",
            "AttachmentCount": ri.randint(1, 8),
            "HasStarAction": has_star_action,
            "HasStarResource": has_star_resource,
            "OverlyPermissive": has_star_action and has_star_resource,
        })
    return pd.DataFrame(rows)


def get_ec2_instances(region: str | None = None) -> pd.DataFrame:
    r = _rng("ec2" + str(region))
    names = r.sample(_INSTANCE_NAMES, k=min(len(_INSTANCE_NAMES), r.randint(8, 16)))
    states = ["running", "stopped", "running", "running", "running"]  # bias toward running
    vpcs = [f"vpc-{_fake_id('', 8, f'vpc{j}')}" for j in range(3)]

    rows = []
    for i, name in enumerate(names):
        ri = random.Random(f"{_SESSION_SEED}-ec2-{i}")
        state = ri.choice(states)
        has_public = ri.random() < 0.3
        vpc = ri.choice(vpcs)
        rows.append({
            "InstanceId": f"i-{_fake_id('', 17, f'ec2i{i}')}",
            "Name": name,
            "State": state,
            "InstanceType": ri.choice(_INSTANCE_TYPES),
            "LaunchTime": str(datetime.utcnow() - timedelta(days=ri.randint(1, 365))),
            "PrivateIp": _random_ip(ri, public=False),
            "PublicIp": _random_ip(ri, public=True) if has_public else "N/A",
            "VpcId": vpc,
            "SubnetId": f"subnet-{_fake_id('', 8, f'sub{i}')}",
            "Platform": ri.choice(["Linux/UNIX", "Linux/UNIX", "Linux/UNIX", "Windows"]),
        })
    return pd.DataFrame(rows)


def get_security_groups(region: str | None = None) -> pd.DataFrame:
    r = _rng("sg" + str(region))
    names = r.sample(_SG_NAMES, k=min(len(_SG_NAMES), r.randint(7, 12)))
    vpcs = [f"vpc-{_fake_id('', 8, f'vpc{j}')}" for j in range(3)]

    rows = []
    for i, name in enumerate(names):
        ri = random.Random(f"{_SESSION_SEED}-sg-{i}")
        is_open = name in ("bastion-ssh", "alb-external", "default") or ri.random() < 0.15
        open_ports = []
        if is_open:
            if "ssh" in name or "bastion" in name:
                open_ports = ["22"]
            elif "alb" in name or "web" in name:
                open_ports = ["443", "80"]
            else:
                open_ports = [str(ri.choice([22, 80, 443, 3389, 8080]))]
        rows.append({
            "GroupId": f"sg-{_fake_id('', 8, f'sg{i}')}",
            "GroupName": name,
            "VpcId": ri.choice(vpcs),
            "Description": f"Security group for {name.replace('-', ' ')}",
            "IngressRules": ri.randint(1, 8),
            "EgressRules": ri.randint(1, 3),
            "OpenToInternet": is_open,
            "OpenPorts": ", ".join(open_ports) if open_ports else "None",
        })
    return pd.DataFrame(rows)


def get_s3_buckets(region: str | None = None) -> pd.DataFrame:
    r = _rng("s3")
    names = r.sample(_BUCKET_NAMES, k=min(len(_BUCKET_NAMES), r.randint(8, 14)))
    enc_algos = ["AES256", "aws:kms", "AES256", "aws:kms", "None"]
    versioning_opts = ["Enabled", "Enabled", "Enabled", "Suspended", "Disabled"]

    rows = []
    for i, name in enumerate(names):
        ri = random.Random(f"{_SESSION_SEED}-s3-{i}")
        enc = ri.choice(enc_algos)
        # temp/processing buckets more likely to lack security
        if "temp" in name or "processing" in name:
            enc = ri.choice(["None", "AES256"])
            public_blocked = ri.random() > 0.5
        else:
            public_blocked = ri.random() > 0.1  # 90% blocked
        rows.append({
            "BucketName": name,
            "CreationDate": str(datetime.utcnow() - timedelta(days=ri.randint(30, 800))),
            "PublicAccessBlocked": public_blocked,
            "Encryption": enc,
            "Versioning": ri.choice(versioning_opts),
        })
    return pd.DataFrame(rows)


def get_cloudtrail_events(
    region: str | None = None,
    hours_back: int = 24,
    max_results: int = 50,
) -> pd.DataFrame:
    r = _rng("ct" + str(hours_back))
    n = r.randint(25, min(max_results, 50))

    rows = []
    for i in range(n):
        ri = random.Random(f"{_SESSION_SEED}-ct-{i}")
        event_name = ri.choice(_EVENT_NAMES)
        rows.append({
            "EventId": _fake_id("", 36, f"ct{i}"),
            "EventName": event_name,
            "EventSource": ri.choice(_EVENT_SOURCES),
            "EventTime": str(datetime.utcnow() - timedelta(
                hours=ri.randint(0, hours_back),
                minutes=ri.randint(0, 59),
            )),
            "Username": ri.choice(_USERNAMES),
            "ResourceType": ri.choice(["AWS::EC2::Instance", "AWS::S3::Bucket",
                                        "AWS::IAM::Role", "AWS::Lambda::Function", ""]),
            "ResourceName": _fake_id("", 10, f"ctr{i}") if ri.random() > 0.3 else "",
        })
    return pd.DataFrame(rows)


def get_config_compliance(region: str | None = None) -> pd.DataFrame:
    r = _rng("config" + str(region))
    rules = r.sample(_CONFIG_RULES, k=min(len(_CONFIG_RULES), r.randint(10, 16)))
    compliance_types = ["COMPLIANT", "NON_COMPLIANT", "COMPLIANT", "COMPLIANT",
                        "COMPLIANT", "NOT_APPLICABLE"]

    rows = []
    for rule in rules:
        ri = random.Random(f"{_SESSION_SEED}-cfg-{rule}")
        rows.append({
            "ConfigRuleName": rule,
            "ComplianceType": ri.choice(compliance_types),
        })
    return pd.DataFrame(rows)


def get_config_resource_counts(region: str | None = None) -> pd.DataFrame:
    r = _rng("configrc" + str(region))
    types = r.sample(_RESOURCE_TYPES, k=min(len(_RESOURCE_TYPES), r.randint(10, 16)))
    rows = []
    for rt in types:
        ri = random.Random(f"{_SESSION_SEED}-rc-{rt}")
        rows.append({
            "ResourceType": rt,
            "Count": ri.randint(1, 200),
        })
    return pd.DataFrame(rows)


def get_organization_accounts(region: str | None = None) -> pd.DataFrame:
    r = _rng("org")
    accounts = _ORG_ACCOUNTS.copy()
    rows = []
    for i, acct in enumerate(accounts):
        ri = random.Random(f"{_SESSION_SEED}-org-{i}")
        rows.append({
            "AccountId": f"{ri.randint(100000000000, 999999999999)}",
            "AccountName": acct["name"],
            "Email": acct["email"],
            "Status": "ACTIVE" if ri.random() > 0.05 else "SUSPENDED",
            "JoinedTimestamp": str(datetime.utcnow() - timedelta(days=ri.randint(90, 1000))),
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Regression test sample data seeder
# ---------------------------------------------------------------------------

def seed_sample_regression_data():
    """Populate SQLite with realistic quarterly regression test history."""
    from utils.db import (
        _connect, create_test_suite, create_test_run, complete_test_run,
        add_test_result, get_test_suites,
    )
    from config import TEST_CATEGORIES

    # Check if already seeded
    conn = _connect()
    count = conn.execute("SELECT COUNT(*) FROM test_suites").fetchone()[0]
    conn.close()
    if count > 0:
        return  # Already seeded

    r = random.Random(_SESSION_SEED)

    # Create suites
    suite_defs = [
        ("Core Security Baseline", "Authentication & Authorization",
         "Validates MFA, password policy, root account lockdown, and SSO configuration."),
        ("Encryption Audit", "Data Encryption (at-rest & in-transit)",
         "Checks S3, EBS, RDS, and DynamoDB encryption. Validates TLS for all endpoints."),
        ("Network Perimeter Check", "Network Security & Segmentation",
         "Audits security groups, NACLs, VPC peering, and public-facing resources."),
        ("IAM Least Privilege", "IAM Policy & Least Privilege",
         "Reviews IAM policies for over-permissive access, unused roles, and key rotation."),
        ("Monitoring & Alerting", "Logging & Monitoring",
         "Validates CloudTrail, CloudWatch alarms, VPC flow logs, and GuardDuty."),
        ("Compliance Controls", "Compliance Controls",
         "Maps and verifies SOC2, CIS, and HIPAA controls against AWS Config rules."),
    ]

    suite_ids = []
    for name, cat, desc in suite_defs:
        sid = create_test_suite(name, cat, desc)
        suite_ids.append(sid)

    # Create runs across multiple quarters
    quarters_years = [
        ("Q1", 2025), ("Q2", 2025), ("Q3", 2025), ("Q4", 2025),
        ("Q1", 2026),
    ]
    environments = ["Production", "Staging"]
    regions = ["us-east-1", "us-west-2"]

    test_names_by_category = {
        "Authentication & Authorization": [
            "IAM MFA Enforcement", "Root Account Lockdown", "Password Policy Compliance",
            "SSO Configuration Check", "Session Duration Limits", "Console Login Monitoring",
        ],
        "Data Encryption (at-rest & in-transit)": [
            "S3 Encryption at Rest", "EBS Volume Encryption", "RDS Encryption Check",
            "TLS 1.2+ Enforcement", "KMS Key Rotation", "S3 Bucket Versioning",
        ],
        "Network Security & Segmentation": [
            "Security Group Open Ingress", "NACL Review", "VPC Peering Audit",
            "Public Subnet Resources", "NAT Gateway Configuration", "DNS Query Logging",
        ],
        "IAM Policy & Least Privilege": [
            "Overly Permissive Policies", "Unused IAM Roles", "Access Key Rotation",
            "Cross-Account Role Audit", "Service Control Policies", "Permission Boundaries",
        ],
        "Logging & Monitoring": [
            "CloudTrail Multi-Region", "VPC Flow Logs", "CloudWatch Alarm Coverage",
            "GuardDuty Enabled", "S3 Access Logging", "Config Recorder Active",
        ],
        "Compliance Controls": [
            "AWS Config Compliance", "SOC2 Control Mapping", "CIS Benchmark Score",
            "HIPAA Eligibility Check", "PCI Scope Validation", "Remediation SLA Tracking",
        ],
    }

    for q, y in quarters_years:
        for suite_id, (_, cat, _) in zip(suite_ids, suite_defs):
            for env in environments:
                region = r.choice(regions)
                run_id = create_test_run(suite_id, q, y, env, region, "scheduled")

                tests = test_names_by_category.get(cat, ["Generic Test"])
                has_failure = False
                # Improve pass rates over time
                quarter_idx = quarters_years.index((q, y))
                base_pass_rate = 0.65 + (quarter_idx * 0.06)  # improves each quarter
                if env == "Staging":
                    base_pass_rate -= 0.05  # staging slightly worse

                for test_name in tests:
                    ri = random.Random(f"{_SESSION_SEED}-tr-{q}{y}{suite_id}{env}{test_name}")
                    passed = ri.random() < min(base_pass_rate, 0.95)
                    status = "PASSED" if passed else ri.choice(["FAILED", "FAILED", "WARNING"])
                    if status == "FAILED":
                        has_failure = True
                    duration = round(ri.uniform(0.1, 3.5), 2)

                    details_map = {
                        "PASSED": "All checks passed successfully.",
                        "FAILED": f"Found {ri.randint(1, 8)} non-compliant resources.",
                        "WARNING": f"{ri.randint(1, 3)} resources need attention within 30 days.",
                    }

                    add_test_result(run_id, test_name, cat, status, duration, details_map[status])

                complete_test_run(run_id, "FAILED" if has_failure else "PASSED")
