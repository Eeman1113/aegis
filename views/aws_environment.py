"""AWS Environment — EC2, S3, IAM, Security Groups, CloudTrail, Config monitoring."""

import streamlit as st
import pandas as pd
import plotly.express as px

from config import AWS_REGIONS, SEVERITY_COLORS
from utils.aws_integration import (
    get_ec2_instances,
    get_security_groups,
    get_s3_buckets,
    get_iam_users,
    get_iam_summary,
    get_iam_policies_audit,
    get_cloudtrail_events,
    get_config_compliance,
    get_config_resource_counts,
)


def render():
    st.header("AWS Environment Health")

    region = st.sidebar.selectbox("AWS Region", AWS_REGIONS, key="aws_env_region")

    tab_compute, tab_storage, tab_iam, tab_network, tab_trail, tab_config = st.tabs([
        "EC2 Instances", "S3 Buckets", "IAM Audit", "Security Groups", "CloudTrail", "Config"
    ])

    # ------------------------------------------------------------------
    # EC2
    # ------------------------------------------------------------------
    with tab_compute:
        st.subheader("EC2 Instance Inventory")
        try:
            df = get_ec2_instances(region=region)
            if df.empty:
                st.info("No EC2 instances found in this region.")
            else:
                # KPIs
                cols = st.columns(4)
                cols[0].metric("Total Instances", len(df))
                cols[1].metric("Running", len(df[df["State"] == "running"]))
                cols[2].metric("Stopped", len(df[df["State"] == "stopped"]))
                public_count = len(df[df["PublicIp"] != "N/A"])
                cols[3].metric("With Public IP", public_count)

                # State distribution
                fig = px.pie(
                    df, names="State", title="Instance State Distribution",
                    color_discrete_sequence=px.colors.qualitative.Safe,
                )
                st.plotly_chart(fig, use_container_width=True)

                # Instance type breakdown
                type_counts = df["InstanceType"].value_counts().reset_index()
                type_counts.columns = ["InstanceType", "Count"]
                fig2 = px.bar(type_counts, x="InstanceType", y="Count", title="Instances by Type")
                st.plotly_chart(fig2, use_container_width=True)

                st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Failed to fetch EC2 data: {e}")

    # ------------------------------------------------------------------
    # S3
    # ------------------------------------------------------------------
    with tab_storage:
        st.subheader("S3 Bucket Security")
        try:
            df = get_s3_buckets(region=region)
            if df.empty:
                st.info("No S3 buckets found.")
            else:
                cols = st.columns(4)
                cols[0].metric("Total Buckets", len(df))
                cols[1].metric("Public Access Blocked",
                    len(df[df["PublicAccessBlocked"] == True]))
                cols[2].metric("Encrypted",
                    len(df[df["Encryption"] != "None"]))
                cols[3].metric("Versioning Enabled",
                    len(df[df["Versioning"] == "Enabled"]))

                # Flag risky buckets
                risky = df[(df["PublicAccessBlocked"] == False) | (df["Encryption"] == "None")]
                if not risky.empty:
                    st.warning(f"{len(risky)} bucket(s) have security concerns:")
                    st.dataframe(risky, use_container_width=True, hide_index=True)

                st.subheader("All Buckets")
                st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Failed to fetch S3 data: {e}")

    # ------------------------------------------------------------------
    # IAM
    # ------------------------------------------------------------------
    with tab_iam:
        st.subheader("IAM Security Audit")
        try:
            summary = get_iam_summary(region=region)
            if summary:
                cols = st.columns(4)
                cols[0].metric("Users", summary.get("Users", 0))
                cols[1].metric("Roles", summary.get("Roles", 0))
                cols[2].metric("Policies", summary.get("Policies", 0))
                cols[3].metric("Groups", summary.get("Groups", 0))

                mfa_col1, mfa_col2 = st.columns(2)
                with mfa_col1:
                    st.metric("MFA Devices", summary.get("MFADevices", 0))
                with mfa_col2:
                    st.metric("Account MFA Enabled", summary.get("AccountMFAEnabled", 0))

            # User details
            st.subheader("IAM Users Detail")
            users = get_iam_users(region=region)
            if not users.empty:
                no_mfa = users[~users["MFAEnabled"]]
                if not no_mfa.empty:
                    st.error(f"{len(no_mfa)} user(s) WITHOUT MFA:")
                    st.dataframe(no_mfa[["UserName", "CreateDate", "PasswordLastUsed", "ActiveAccessKeys"]],
                        use_container_width=True, hide_index=True)
                else:
                    st.success("All IAM users have MFA enabled.")

                st.dataframe(users, use_container_width=True, hide_index=True)
            else:
                st.info("No IAM users found (likely using federated/SSO access).")

            # Policy audit
            st.subheader("Policy Audit — Overly Permissive Policies")
            policies = get_iam_policies_audit(region=region)
            if not policies.empty:
                risky = policies[policies["OverlyPermissive"]]
                if not risky.empty:
                    st.error(f"{len(risky)} overly permissive policies detected (Action: *, Resource: *):")
                    st.dataframe(risky, use_container_width=True, hide_index=True)
                else:
                    st.success("No overly permissive customer-managed policies found.")
                st.dataframe(policies, use_container_width=True, hide_index=True)
            else:
                st.info("No attached customer-managed policies.")

        except Exception as e:
            st.error(f"Failed to fetch IAM data: {e}")

    # ------------------------------------------------------------------
    # Security Groups
    # ------------------------------------------------------------------
    with tab_network:
        st.subheader("Security Group Audit")
        try:
            df = get_security_groups(region=region)
            if df.empty:
                st.info("No security groups found in this region.")
            else:
                cols = st.columns(3)
                cols[0].metric("Total Security Groups", len(df))
                open_count = len(df[df["OpenToInternet"]])
                cols[1].metric("Open to Internet (0.0.0.0/0)", open_count)
                cols[2].metric("Avg Ingress Rules",
                    round(df["IngressRules"].mean(), 1))

                if open_count > 0:
                    st.error("Security groups with public ingress (0.0.0.0/0):")
                    open_sgs = df[df["OpenToInternet"]]
                    st.dataframe(
                        open_sgs[["GroupId", "GroupName", "VpcId", "OpenPorts"]],
                        use_container_width=True, hide_index=True,
                    )

                st.subheader("All Security Groups")
                st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Failed to fetch security groups: {e}")

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------
    with tab_trail:
        st.subheader("Recent CloudTrail Events")
        hours_back = st.slider("Hours to look back", 1, 72, 24, key="ct_hours")
        try:
            df = get_cloudtrail_events(region=region, hours_back=hours_back)
            if df.empty:
                st.info("No CloudTrail events found.")
            else:
                cols = st.columns(3)
                cols[0].metric("Total Events", len(df))
                cols[1].metric("Unique Users", df["Username"].nunique())
                cols[2].metric("Event Types", df["EventName"].nunique())

                # Top events
                event_counts = df["EventName"].value_counts().head(15).reset_index()
                event_counts.columns = ["EventName", "Count"]
                fig = px.bar(
                    event_counts, x="EventName", y="Count",
                    title="Most Frequent API Calls",
                )
                fig.update_xaxes(tickangle=45)
                st.plotly_chart(fig, use_container_width=True)

                # By user
                user_counts = df["Username"].value_counts().reset_index()
                user_counts.columns = ["Username", "Count"]
                fig2 = px.pie(user_counts, names="Username", values="Count", title="Events by User")
                st.plotly_chart(fig2, use_container_width=True)

                st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Failed to fetch CloudTrail events: {e}")

    # ------------------------------------------------------------------
    # AWS Config
    # ------------------------------------------------------------------
    with tab_config:
        st.subheader("AWS Config Compliance")
        try:
            df = get_config_compliance(region=region)
            if df.empty:
                st.info("No AWS Config rules configured in this region.")
            else:
                cols = st.columns(3)
                compliant = len(df[df["ComplianceType"] == "COMPLIANT"])
                non_compliant = len(df[df["ComplianceType"] == "NON_COMPLIANT"])
                cols[0].metric("Total Rules", len(df))
                cols[1].metric("Compliant", compliant)
                cols[2].metric("Non-Compliant", non_compliant)

                fig = px.pie(
                    df, names="ComplianceType", title="Config Rule Compliance",
                    color="ComplianceType",
                    color_discrete_map={"COMPLIANT": "#28a745", "NON_COMPLIANT": "#dc3545", "NOT_APPLICABLE": "#6c757d"},
                )
                st.plotly_chart(fig, use_container_width=True)

                if non_compliant > 0:
                    st.error("Non-compliant rules:")
                    st.dataframe(
                        df[df["ComplianceType"] == "NON_COMPLIANT"],
                        use_container_width=True, hide_index=True,
                    )

                st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Failed to fetch Config data: {e}")

        st.subheader("Discovered Resource Inventory")
        try:
            rc = get_config_resource_counts(region=region)
            if not rc.empty:
                fig = px.bar(
                    rc.sort_values("Count", ascending=False).head(20),
                    x="ResourceType", y="Count",
                    title="Top 20 Resource Types",
                )
                fig.update_xaxes(tickangle=45)
                st.plotly_chart(fig, use_container_width=True)
                st.dataframe(rc, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Failed to fetch resource counts: {e}")
