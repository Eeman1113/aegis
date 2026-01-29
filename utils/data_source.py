"""Data source router — transparently delegates to real AWS or mock data.

Views import from here instead of aws_integration directly.
The active source is determined by st.session_state["sample_mode"].
"""

import streamlit as st

from utils import aws_integration as _real
from utils import mock_data as _mock


def _src():
    if st.session_state.get("sample_mode"):
        return _mock
    return _real


def check_aws_connection(region=None):
    return _src().check_aws_connection(region)

def get_security_hub_findings(region=None, max_results=100):
    return _src().get_security_hub_findings(region, max_results)

def get_security_hub_standards(region=None):
    return _src().get_security_hub_standards(region)

def get_guardduty_findings(region=None, max_results=50):
    return _src().get_guardduty_findings(region, max_results)

def get_iam_summary(region=None):
    return _src().get_iam_summary(region)

def get_iam_users(region=None):
    return _src().get_iam_users(region)

def get_iam_policies_audit(region=None):
    return _src().get_iam_policies_audit(region)

def get_ec2_instances(region=None):
    return _src().get_ec2_instances(region)

def get_security_groups(region=None):
    return _src().get_security_groups(region)

def get_s3_buckets(region=None):
    return _src().get_s3_buckets(region)

def get_cloudtrail_events(region=None, hours_back=24, max_results=50):
    return _src().get_cloudtrail_events(region, hours_back, max_results)

def get_config_compliance(region=None):
    return _src().get_config_compliance(region)

def get_config_resource_counts(region=None):
    return _src().get_config_resource_counts(region)

def get_organization_accounts(region=None):
    return _src().get_organization_accounts(region)


# Re-export for views that use these directly
def _client(service, region=None):
    return _real._client(service, region)

def _get_session(region=None):
    return _real._get_session(region)
