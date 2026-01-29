"""Real AWS integration layer using boto3.

All functions hit live AWS APIs. Credentials are collected from the user
via the Streamlit sidebar and stored in session state.
Falls back to environment variables / CLI profile / IAM role if nothing
is entered in the UI.
"""

import boto3
import pandas as pd
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, NoCredentialsError
import streamlit as st

from config import AWS_REGION, AWS_PROFILE


def _get_session(region: str | None = None) -> boto3.Session:
    kwargs = {}
    auth_method = st.session_state.get("aws_auth_method", "IAM Role / Instance Profile")

    if auth_method == "Access Keys (STS Temporary Only)":
        access_key = st.session_state.get("aws_access_key_id", "").strip()
        secret_key = st.session_state.get("aws_secret_access_key", "").strip()
        session_token = st.session_state.get("aws_session_token", "").strip()
        if access_key and secret_key:
            kwargs["aws_access_key_id"] = access_key
            kwargs["aws_secret_access_key"] = secret_key
            if session_token:
                kwargs["aws_session_token"] = session_token

    elif auth_method == "AWS CLI Profile":
        profile = st.session_state.get("aws_cli_profile", "").strip()
        if profile:
            kwargs["profile_name"] = profile
        elif AWS_PROFILE:
            kwargs["profile_name"] = AWS_PROFILE

    # IAM Role / Instance Profile: no explicit credentials needed,
    # boto3 automatically uses the instance metadata service.

    kwargs["region_name"] = region or st.session_state.get("aws_region", AWS_REGION)
    return boto3.Session(**kwargs)


def _client(service: str, region: str | None = None):
    return _get_session(region).client(service)


# ---------------------------------------------------------------------------
# Connection health
# ---------------------------------------------------------------------------

def check_aws_connection(region: str | None = None) -> dict:
    """Return caller identity or error information."""
    try:
        sts = _client("sts", region)
        identity = sts.get_caller_identity()
        return {
            "connected": True,
            "account": identity["Account"],
            "arn": identity["Arn"],
            "user_id": identity["UserId"],
        }
    except (NoCredentialsError, ClientError) as e:
        return {"connected": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Security Hub
# ---------------------------------------------------------------------------

@st.cache_data(ttl=300)
def get_security_hub_findings(region: str | None = None, max_results: int = 100) -> pd.DataFrame:
    """Pull findings from AWS Security Hub."""
    client = _client("securityhub", region)
    findings = []
    paginator = client.get_paginator("get_findings")
    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    }
    for page in paginator.paginate(
        Filters=filters,
        MaxResults=max_results,
    ):
        findings.extend(page.get("Findings", []))
        if len(findings) >= max_results:
            break

    if not findings:
        return pd.DataFrame()

    rows = []
    for f in findings[:max_results]:
        rows.append({
            "Id": f.get("Id", ""),
            "Title": f.get("Title", ""),
            "Severity": f.get("Severity", {}).get("Label", "INFORMATIONAL"),
            "Status": f.get("Compliance", {}).get("Status", ""),
            "ResourceType": (f.get("Resources", [{}])[0].get("Type", "") if f.get("Resources") else ""),
            "ResourceId": (f.get("Resources", [{}])[0].get("Id", "") if f.get("Resources") else ""),
            "GeneratorId": f.get("GeneratorId", ""),
            "CreatedAt": f.get("CreatedAt", ""),
            "UpdatedAt": f.get("UpdatedAt", ""),
            "Description": f.get("Description", ""),
        })
    return pd.DataFrame(rows)


@st.cache_data(ttl=300)
def get_security_hub_standards(region: str | None = None) -> pd.DataFrame:
    """Get enabled security standards and their scores."""
    client = _client("securityhub", region)
    resp = client.get_enabled_standards()
    standards = resp.get("StandardsSubscriptions", [])
    rows = []
    for s in standards:
        arn = s.get("StandardsArn", "")
        status = s.get("StandardsStatus", "")
        # Get control results for each standard
        try:
            controls_resp = client.describe_standards_controls(
                StandardsSubscriptionArn=s.get("StandardsSubscriptionArn", "")
            )
            controls = controls_resp.get("Controls", [])
            passed = sum(1 for c in controls if c.get("ComplianceStatus") == "PASSED")
            failed = sum(1 for c in controls if c.get("ComplianceStatus") == "FAILED")
            total = len(controls)
        except ClientError:
            passed = failed = total = 0

        rows.append({
            "StandardArn": arn,
            "Status": status,
            "TotalControls": total,
            "Passed": passed,
            "Failed": failed,
            "Score": round(passed / total * 100, 1) if total > 0 else 0,
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# GuardDuty
# ---------------------------------------------------------------------------

@st.cache_data(ttl=300)
def get_guardduty_findings(region: str | None = None, max_results: int = 50) -> pd.DataFrame:
    """Pull findings from AWS GuardDuty."""
    client = _client("guardduty", region)

    # Get detector id
    detectors = client.list_detectors().get("DetectorIds", [])
    if not detectors:
        return pd.DataFrame()

    detector_id = detectors[0]
    criteria = {"Criterion": {"service.archived": {"Eq": ["false"]}}}
    finding_ids_resp = client.list_findings(
        DetectorId=detector_id,
        FindingCriteria=criteria,
        MaxResults=max_results,
    )
    finding_ids = finding_ids_resp.get("FindingIds", [])
    if not finding_ids:
        return pd.DataFrame()

    details = client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids,
    )
    rows = []
    for f in details.get("Findings", []):
        rows.append({
            "Id": f.get("Id", ""),
            "Title": f.get("Title", ""),
            "Type": f.get("Type", ""),
            "Severity": f.get("Severity", {}).get("Label", ""),
            "SeverityScore": f.get("Severity", {}).get("Normalized", 0),
            "Region": f.get("Region", ""),
            "ResourceType": f.get("Resource", {}).get("ResourceType", ""),
            "CreatedAt": f.get("CreatedAt", ""),
            "UpdatedAt": f.get("UpdatedAt", ""),
            "Description": f.get("Description", ""),
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

@st.cache_data(ttl=600)
def get_iam_summary(region: str | None = None) -> dict:
    """Get IAM account summary."""
    client = _client("iam", region)
    resp = client.get_account_summary()
    return resp.get("SummaryMap", {})


@st.cache_data(ttl=600)
def get_iam_users(region: str | None = None) -> pd.DataFrame:
    """List IAM users with key metadata."""
    client = _client("iam", region)
    paginator = client.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        for u in page["Users"]:
            # Check MFA
            mfa_resp = client.list_mfa_devices(UserName=u["UserName"])
            has_mfa = len(mfa_resp.get("MFADevices", [])) > 0
            # Check access keys
            keys_resp = client.list_access_keys(UserName=u["UserName"])
            access_keys = keys_resp.get("AccessKeyMetadata", [])
            active_keys = [k for k in access_keys if k["Status"] == "Active"]

            users.append({
                "UserName": u["UserName"],
                "UserId": u["UserId"],
                "Arn": u["Arn"],
                "CreateDate": str(u["CreateDate"]),
                "PasswordLastUsed": str(u.get("PasswordLastUsed", "N/A")),
                "MFAEnabled": has_mfa,
                "ActiveAccessKeys": len(active_keys),
            })
    return pd.DataFrame(users)


@st.cache_data(ttl=600)
def get_iam_policies_audit(region: str | None = None) -> pd.DataFrame:
    """Audit customer-managed policies for overly permissive access."""
    client = _client("iam", region)
    paginator = client.get_paginator("list_policies")
    rows = []
    for page in paginator.paginate(Scope="Local", OnlyAttached=True):
        for pol in page["Policies"]:
            version = client.get_policy_version(
                PolicyArn=pol["Arn"],
                VersionId=pol["DefaultVersionId"],
            )
            doc = version["PolicyVersion"]["Document"]
            statements = doc.get("Statement", []) if isinstance(doc, dict) else []
            has_star_action = any(
                s.get("Action") == "*" or s.get("Action") == ["*"]
                for s in statements if isinstance(s, dict)
            )
            has_star_resource = any(
                s.get("Resource") == "*" or s.get("Resource") == ["*"]
                for s in statements if isinstance(s, dict)
            )
            rows.append({
                "PolicyName": pol["PolicyName"],
                "Arn": pol["Arn"],
                "AttachmentCount": pol["AttachmentCount"],
                "HasStarAction": has_star_action,
                "HasStarResource": has_star_resource,
                "OverlyPermissive": has_star_action and has_star_resource,
            })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# EC2
# ---------------------------------------------------------------------------

@st.cache_data(ttl=300)
def get_ec2_instances(region: str | None = None) -> pd.DataFrame:
    """List all EC2 instances with key details."""
    client = _client("ec2", region)
    paginator = client.get_paginator("describe_instances")
    rows = []
    for page in paginator.paginate():
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                rows.append({
                    "InstanceId": inst["InstanceId"],
                    "Name": name,
                    "State": inst["State"]["Name"],
                    "InstanceType": inst["InstanceType"],
                    "LaunchTime": str(inst.get("LaunchTime", "")),
                    "PrivateIp": inst.get("PrivateIpAddress", ""),
                    "PublicIp": inst.get("PublicIpAddress", "N/A"),
                    "VpcId": inst.get("VpcId", ""),
                    "SubnetId": inst.get("SubnetId", ""),
                    "Platform": inst.get("PlatformDetails", "Linux/UNIX"),
                })
    return pd.DataFrame(rows)


@st.cache_data(ttl=300)
def get_security_groups(region: str | None = None) -> pd.DataFrame:
    """List security groups and flag risky rules (0.0.0.0/0 ingress)."""
    client = _client("ec2", region)
    paginator = client.get_paginator("describe_security_groups")
    rows = []
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            open_ingress = []
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = rule.get("FromPort", "All")
                        open_ingress.append(str(port))
                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        port = rule.get("FromPort", "All")
                        open_ingress.append(str(port))
            rows.append({
                "GroupId": sg["GroupId"],
                "GroupName": sg["GroupName"],
                "VpcId": sg.get("VpcId", ""),
                "Description": sg.get("Description", ""),
                "IngressRules": len(sg.get("IpPermissions", [])),
                "EgressRules": len(sg.get("IpPermissionsEgress", [])),
                "OpenToInternet": len(open_ingress) > 0,
                "OpenPorts": ", ".join(open_ingress) if open_ingress else "None",
            })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

@st.cache_data(ttl=600)
def get_s3_buckets(region: str | None = None) -> pd.DataFrame:
    """List S3 buckets and check public access / encryption."""
    client = _client("s3", region)
    buckets = client.list_buckets().get("Buckets", [])
    rows = []
    for b in buckets:
        name = b["Name"]
        # Check public access block
        try:
            pab = client.get_public_access_block(Bucket=name)
            config = pab["PublicAccessBlockConfiguration"]
            is_public_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
        except ClientError:
            is_public_blocked = False

        # Check encryption
        try:
            enc = client.get_bucket_encryption(Bucket=name)
            encryption = enc["ServerSideEncryptionConfiguration"]["Rules"][0][
                "ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except (ClientError, KeyError, IndexError):
            encryption = "None"

        # Check versioning
        try:
            ver = client.get_bucket_versioning(Bucket=name)
            versioning = ver.get("Status", "Disabled")
        except ClientError:
            versioning = "Unknown"

        rows.append({
            "BucketName": name,
            "CreationDate": str(b.get("CreationDate", "")),
            "PublicAccessBlocked": is_public_blocked,
            "Encryption": encryption,
            "Versioning": versioning,
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------

@st.cache_data(ttl=300)
def get_cloudtrail_events(
    region: str | None = None,
    hours_back: int = 24,
    max_results: int = 50,
) -> pd.DataFrame:
    """Pull recent CloudTrail management events."""
    client = _client("cloudtrail", region)
    start = datetime.utcnow() - timedelta(hours=hours_back)
    resp = client.lookup_events(
        StartTime=start,
        EndTime=datetime.utcnow(),
        MaxResults=max_results,
    )
    rows = []
    for event in resp.get("Events", []):
        rows.append({
            "EventId": event.get("EventId", ""),
            "EventName": event.get("EventName", ""),
            "EventSource": event.get("EventSource", ""),
            "EventTime": str(event.get("EventTime", "")),
            "Username": event.get("Username", ""),
            "ResourceType": (event.get("Resources", [{}])[0].get("ResourceType", "")
                             if event.get("Resources") else ""),
            "ResourceName": (event.get("Resources", [{}])[0].get("ResourceName", "")
                             if event.get("Resources") else ""),
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# AWS Config
# ---------------------------------------------------------------------------

@st.cache_data(ttl=300)
def get_config_compliance(region: str | None = None) -> pd.DataFrame:
    """Get AWS Config rule compliance summary."""
    client = _client("config", region)
    resp = client.describe_compliance_by_config_rule()
    rows = []
    for rule in resp.get("ComplianceByConfigRules", []):
        rows.append({
            "ConfigRuleName": rule.get("ConfigRuleName", ""),
            "ComplianceType": rule.get("Compliance", {}).get("ComplianceType", ""),
        })
    return pd.DataFrame(rows)


@st.cache_data(ttl=300)
def get_config_resource_counts(region: str | None = None) -> pd.DataFrame:
    """Get discovered resource counts from AWS Config."""
    client = _client("config", region)
    resp = client.get_discovered_resource_counts()
    rows = []
    for rc in resp.get("resourceCounts", []):
        rows.append({
            "ResourceType": rc.get("resourceType", ""),
            "Count": rc.get("count", 0),
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Organizations / Multi-account (for customer environments)
# ---------------------------------------------------------------------------

@st.cache_data(ttl=600)
def get_organization_accounts(region: str | None = None) -> pd.DataFrame:
    """List accounts in the AWS Organization."""
    client = _client("organizations", region)
    paginator = client.get_paginator("list_accounts")
    rows = []
    for page in paginator.paginate():
        for acct in page["Accounts"]:
            rows.append({
                "AccountId": acct["Id"],
                "AccountName": acct.get("Name", ""),
                "Email": acct.get("Email", ""),
                "Status": acct.get("Status", ""),
                "JoinedTimestamp": str(acct.get("JoinedTimestamp", "")),
            })
    return pd.DataFrame(rows)
