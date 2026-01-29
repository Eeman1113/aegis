"""Customer Environments — multi-account view via AWS Organizations."""

import streamlit as st
import pandas as pd
import plotly.express as px

from config import AWS_REGIONS
from utils.aws_integration import (
    get_organization_accounts,
    check_aws_connection,
    get_security_hub_findings,
    get_config_compliance,
    _get_session,
    _client,
)


def _get_account_security_posture(account_id: str, region: str) -> dict:
    """Attempt to get security posture for a specific account.
    Requires cross-account role assumption or organization-level access.
    """
    posture = {
        "account_id": account_id,
        "security_hub_findings": 0,
        "critical_findings": 0,
        "config_compliant": 0,
        "config_non_compliant": 0,
    }
    try:
        # Try to assume role in target account
        sts = _client("sts", region)
        role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="SecurityDashboard",
        )["Credentials"]

        # Create session with assumed role credentials
        import boto3
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )

        # Security Hub findings count
        try:
            sh = session.client("securityhub")
            resp = sh.get_findings(
                Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
                MaxResults=100,
            )
            findings = resp.get("Findings", [])
            posture["security_hub_findings"] = len(findings)
            posture["critical_findings"] = sum(
                1 for f in findings
                if f.get("Severity", {}).get("Label") in ("CRITICAL", "HIGH")
            )
        except Exception:
            pass

        # Config compliance
        try:
            config = session.client("config")
            resp = config.describe_compliance_by_config_rule()
            rules = resp.get("ComplianceByConfigRules", [])
            posture["config_compliant"] = sum(
                1 for r in rules if r.get("Compliance", {}).get("ComplianceType") == "COMPLIANT"
            )
            posture["config_non_compliant"] = sum(
                1 for r in rules if r.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT"
            )
        except Exception:
            pass

    except Exception:
        # Cross-account role assumption not available — return zeros
        pass

    return posture


def render():
    st.header("Customer Environments")

    region = st.sidebar.selectbox("AWS Region", AWS_REGIONS, key="cust_region")

    # Check connection first
    conn = check_aws_connection(region)
    if not conn["connected"]:
        st.error(f"AWS connection failed: {conn['error']}")
        st.info("Configure AWS credentials (environment variables, AWS CLI profile, or IAM role) to use this page.")
        return

    st.success(f"Connected: {conn['arn']} | Account: {conn['account']}")

    tab_org, tab_posture = st.tabs(["Organization Accounts", "Security Posture"])

    # ------------------------------------------------------------------
    # Organization Accounts
    # ------------------------------------------------------------------
    with tab_org:
        st.subheader("AWS Organization Accounts")
        try:
            df = get_organization_accounts(region=region)
            if df.empty:
                st.info("No organization accounts found. This AWS account may not be part of an Organization.")
            else:
                cols = st.columns(3)
                cols[0].metric("Total Accounts", len(df))
                cols[1].metric("Active", len(df[df["Status"] == "ACTIVE"]))
                cols[2].metric("Suspended", len(df[df["Status"] == "SUSPENDED"]))

                # Status breakdown
                fig = px.pie(
                    df, names="Status", title="Account Status Distribution",
                    color="Status",
                    color_discrete_map={"ACTIVE": "#28a745", "SUSPENDED": "#dc3545"},
                )
                st.plotly_chart(fig, use_container_width=True)

                st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Failed to list organization accounts: {e}")
            st.info("This may require AWS Organizations access. Ensure your account is the management account or has delegated access.")

    # ------------------------------------------------------------------
    # Cross-Account Security Posture
    # ------------------------------------------------------------------
    with tab_posture:
        st.subheader("Cross-Account Security Posture")
        st.info(
            "This view attempts to assume the OrganizationAccountAccessRole in each member account "
            "to pull Security Hub and Config data. Accounts without this role will show zeros."
        )

        try:
            df = get_organization_accounts(region=region)
            if df.empty:
                st.warning("No organization accounts to assess.")
            else:
                account_ids = df[df["Status"] == "ACTIVE"]["AccountId"].tolist()

                if st.button("Scan All Accounts", type="primary"):
                    posture_data = []
                    progress = st.progress(0)
                    for i, acct_id in enumerate(account_ids):
                        progress.progress((i + 1) / len(account_ids))
                        posture = _get_account_security_posture(acct_id, region)
                        # Merge account name
                        acct_name = df[df["AccountId"] == acct_id]["AccountName"].values
                        posture["account_name"] = acct_name[0] if len(acct_name) > 0 else ""
                        posture_data.append(posture)

                    df_posture = pd.DataFrame(posture_data)

                    # Summary metrics
                    cols = st.columns(4)
                    cols[0].metric("Accounts Scanned", len(df_posture))
                    cols[1].metric("Total Findings", df_posture["security_hub_findings"].sum())
                    cols[2].metric("Critical/High", df_posture["critical_findings"].sum())
                    cols[3].metric("Non-Compliant Rules", df_posture["config_non_compliant"].sum())

                    # Per-account findings chart
                    fig = px.bar(
                        df_posture,
                        x="account_name",
                        y=["security_hub_findings", "critical_findings"],
                        title="Security Findings by Account",
                        barmode="group",
                        labels={"value": "Count", "account_name": "Account"},
                    )
                    st.plotly_chart(fig, use_container_width=True)

                    # Config compliance
                    fig2 = px.bar(
                        df_posture,
                        x="account_name",
                        y=["config_compliant", "config_non_compliant"],
                        title="Config Compliance by Account",
                        barmode="stack",
                        color_discrete_map={"config_compliant": "#28a745", "config_non_compliant": "#dc3545"},
                    )
                    st.plotly_chart(fig2, use_container_width=True)

                    st.dataframe(df_posture, use_container_width=True, hide_index=True)

        except Exception as e:
            st.error(f"Failed to assess security posture: {e}")

    # ------------------------------------------------------------------
    # Current Account Quick View (always works)
    # ------------------------------------------------------------------
    st.divider()
    st.subheader("Current Account — Quick Security View")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Security Hub Findings**")
        try:
            findings = get_security_hub_findings(region=region, max_results=20)
            if findings.empty:
                st.info("No Security Hub findings.")
            else:
                sev_counts = findings["Severity"].value_counts()
                st.dataframe(sev_counts.reset_index().rename(columns={"index": "Severity", "Severity": "Count"}),
                    use_container_width=True, hide_index=True)
        except Exception as e:
            st.warning(f"Security Hub not available: {e}")

    with col2:
        st.markdown("**Config Compliance**")
        try:
            config = get_config_compliance(region=region)
            if config.empty:
                st.info("No Config rules.")
            else:
                comp_counts = config["ComplianceType"].value_counts()
                st.dataframe(comp_counts.reset_index().rename(columns={"index": "Status", "ComplianceType": "Count"}),
                    use_container_width=True, hide_index=True)
        except Exception as e:
            st.warning(f"AWS Config not available: {e}")
