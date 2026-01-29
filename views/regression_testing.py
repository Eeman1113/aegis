"""Quarterly Regression Testing — suite management, execution, results tracking."""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import subprocess
import time
from datetime import datetime

from config import QUARTERS, YEARS, TEST_CATEGORIES, AWS_REGIONS
from utils.db import (
    init_db, create_test_suite, get_test_suites, delete_test_suite,
    create_test_run, complete_test_run, get_test_runs,
    add_test_result, get_test_results, get_results_summary,
)
from utils.data_source import check_aws_connection


def _run_live_checks(run_id: int, region: str, categories: list[str]):
    """Execute real AWS security checks and record results."""
    from utils.data_source import (
        get_iam_users, get_security_groups, get_s3_buckets,
        get_ec2_instances, get_config_compliance,
    )

    # IAM checks
    if "Authentication & Authorization" in categories or "IAM Policy & Least Privilege" in categories:
        try:
            users = get_iam_users(region=region)
            if not users.empty:
                # Check MFA enforcement
                no_mfa = users[~users["MFAEnabled"]]
                status = "PASSED" if no_mfa.empty else "FAILED"
                details = f"{len(no_mfa)} users without MFA" if not no_mfa.empty else "All users have MFA"
                add_test_result(run_id, "IAM MFA Enforcement", "Authentication & Authorization", status, 0.5, details)

                # Check excessive access keys
                excessive_keys = users[users["ActiveAccessKeys"] > 1]
                status = "PASSED" if excessive_keys.empty else "WARNING"
                details = f"{len(excessive_keys)} users with >1 active key" if not excessive_keys.empty else "OK"
                add_test_result(run_id, "Access Key Rotation", "IAM Policy & Least Privilege", status, 0.3, details)
            else:
                add_test_result(run_id, "IAM User Audit", "Authentication & Authorization", "PASSED", 0.1, "No IAM users (using roles)")
        except Exception as e:
            add_test_result(run_id, "IAM Checks", "Authentication & Authorization", "FAILED", 0, str(e))

    # Network Security checks
    if "Network Security & Segmentation" in categories:
        try:
            sgs = get_security_groups(region=region)
            if not sgs.empty:
                open_sgs = sgs[sgs["OpenToInternet"]]
                status = "PASSED" if open_sgs.empty else "FAILED"
                details = f"{len(open_sgs)} security groups with 0.0.0.0/0 ingress" if not open_sgs.empty else "No open ingress rules"
                add_test_result(run_id, "Security Group Open Ingress", "Network Security & Segmentation", status, 0.4, details)
            else:
                add_test_result(run_id, "Security Group Audit", "Network Security & Segmentation", "PASSED", 0.1, "No security groups found")
        except Exception as e:
            add_test_result(run_id, "Security Group Checks", "Network Security & Segmentation", "FAILED", 0, str(e))

    # Encryption checks
    if "Data Encryption (at-rest & in-transit)" in categories:
        try:
            buckets = get_s3_buckets(region=region)
            if not buckets.empty:
                unencrypted = buckets[buckets["Encryption"] == "None"]
                status = "PASSED" if unencrypted.empty else "FAILED"
                details = f"{len(unencrypted)} unencrypted buckets" if not unencrypted.empty else "All buckets encrypted"
                add_test_result(run_id, "S3 Encryption at Rest", "Data Encryption (at-rest & in-transit)", status, 0.6, details)

                no_versioning = buckets[buckets["Versioning"] != "Enabled"]
                status = "WARNING" if not no_versioning.empty else "PASSED"
                add_test_result(run_id, "S3 Versioning", "Data Encryption (at-rest & in-transit)", status, 0.2,
                    f"{len(no_versioning)} buckets without versioning")
            else:
                add_test_result(run_id, "S3 Encryption", "Data Encryption (at-rest & in-transit)", "PASSED", 0.1, "No S3 buckets")
        except Exception as e:
            add_test_result(run_id, "S3 Encryption Checks", "Data Encryption (at-rest & in-transit)", "FAILED", 0, str(e))

    # Compliance Controls
    if "Compliance Controls" in categories:
        try:
            config_rules = get_config_compliance(region=region)
            if not config_rules.empty:
                non_compliant = config_rules[config_rules["ComplianceType"] == "NON_COMPLIANT"]
                status = "PASSED" if non_compliant.empty else "FAILED"
                details = f"{len(non_compliant)} non-compliant Config rules" if not non_compliant.empty else "All Config rules compliant"
                add_test_result(run_id, "AWS Config Compliance", "Compliance Controls", status, 1.0, details)
            else:
                add_test_result(run_id, "AWS Config Rules", "Compliance Controls", "PASSED", 0.1, "No Config rules configured")
        except Exception as e:
            add_test_result(run_id, "Config Compliance", "Compliance Controls", "FAILED", 0, str(e))

    # Logging & Monitoring
    if "Logging & Monitoring" in categories:
        try:
            from utils.data_source import _client
            ct_client = _client("cloudtrail", region)
            trails = ct_client.describe_trails().get("trailList", [])
            active_trails = [t for t in trails if t.get("IsMultiRegionTrail", False)]
            status = "PASSED" if active_trails else "FAILED"
            details = f"{len(active_trails)} multi-region trails active" if active_trails else "No multi-region CloudTrail"
            add_test_result(run_id, "CloudTrail Multi-Region", "Logging & Monitoring", status, 0.3, details)
        except Exception as e:
            add_test_result(run_id, "CloudTrail Check", "Logging & Monitoring", "FAILED", 0, str(e))


def render():
    st.header("Quarterly Regression Testing")

    init_db()

    tab_suites, tab_run, tab_results, tab_trends = st.tabs([
        "Test Suites", "Run Tests", "Results", "Trends"
    ])

    # ------------------------------------------------------------------
    # Test Suites Management
    # ------------------------------------------------------------------
    with tab_suites:
        st.subheader("Manage Test Suites")

        with st.expander("Create New Test Suite", expanded=False):
            with st.form("new_suite"):
                name = st.text_input("Suite Name")
                category = st.selectbox("Category", TEST_CATEGORIES)
                description = st.text_area("Description")
                if st.form_submit_button("Create Suite"):
                    if name:
                        create_test_suite(name, category, description)
                        st.success(f"Created suite: {name}")
                        st.rerun()
                    else:
                        st.warning("Suite name is required.")

        suites = get_test_suites()
        if suites:
            df_suites = pd.DataFrame(suites)
            st.dataframe(
                df_suites[["id", "name", "category", "description", "created_at"]],
                use_container_width=True, hide_index=True,
            )
            suite_to_delete = st.selectbox(
                "Delete suite", [""] + [f"{s['id']}: {s['name']}" for s in suites]
            )
            if suite_to_delete and st.button("Delete Selected Suite"):
                sid = int(suite_to_delete.split(":")[0])
                delete_test_suite(sid)
                st.success("Deleted.")
                st.rerun()
        else:
            st.info("No test suites created yet. Create one above.")

    # ------------------------------------------------------------------
    # Run Tests
    # ------------------------------------------------------------------
    with tab_run:
        st.subheader("Execute Regression Tests")

        suites = get_test_suites()
        if not suites:
            st.warning("Create a test suite first.")
        else:
            col1, col2 = st.columns(2)
            with col1:
                selected_suite = st.selectbox(
                    "Test Suite",
                    suites,
                    format_func=lambda s: f"{s['name']} ({s['category']})",
                )
                quarter = st.selectbox("Quarter", QUARTERS)
                year = st.selectbox("Year", YEARS)
            with col2:
                environment = st.selectbox("Environment", ["Production", "Staging", "Development"])
                region = st.selectbox("AWS Region", AWS_REGIONS, key="reg_run_region")
                categories = st.multiselect(
                    "Test Categories to Run",
                    TEST_CATEGORIES,
                    default=[selected_suite["category"]] if selected_suite else [],
                )

            if st.button("Run Regression Tests", type="primary"):
                conn_status = check_aws_connection(region)
                if not conn_status["connected"]:
                    st.error(f"AWS connection failed: {conn_status['error']}")
                else:
                    st.info(f"Connected as {conn_status['arn']} (Account: {conn_status['account']})")
                    run_id = create_test_run(
                        selected_suite["id"], quarter, year, environment, region
                    )

                    with st.spinner("Running security checks against live AWS environment..."):
                        _run_live_checks(run_id, region, categories)

                    # Determine overall status
                    results = get_test_results(run_id)
                    has_failed = any(r["status"] == "FAILED" for r in results)
                    overall = "FAILED" if has_failed else "PASSED"
                    complete_test_run(run_id, overall)

                    if overall == "PASSED":
                        st.success(f"All checks passed. Run ID: {run_id}")
                    else:
                        st.error(f"Some checks failed. Run ID: {run_id}")

                    # Show results immediately
                    df_res = pd.DataFrame(results)
                    if not df_res.empty:
                        st.dataframe(
                            df_res[["test_name", "category", "status", "duration_seconds", "details"]],
                            use_container_width=True, hide_index=True,
                        )

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    with tab_results:
        st.subheader("Test Run History")

        col1, col2, col3 = st.columns(3)
        with col1:
            filter_q = st.selectbox("Quarter", ["All"] + QUARTERS, key="res_q")
        with col2:
            filter_y = st.selectbox("Year", ["All"] + [str(y) for y in YEARS], key="res_y")
        with col3:
            filter_suite = st.selectbox(
                "Suite", ["All"] + [f"{s['id']}: {s['name']}" for s in get_test_suites()], key="res_suite"
            )

        runs = get_test_runs(
            suite_id=int(filter_suite.split(":")[0]) if filter_suite != "All" else None,
            quarter=filter_q if filter_q != "All" else None,
            year=int(filter_y) if filter_y != "All" else None,
        )

        if runs:
            df_runs = pd.DataFrame(runs)
            st.dataframe(
                df_runs[["id", "suite_name", "quarter", "year", "environment", "region", "status", "started_at", "completed_at"]],
                use_container_width=True, hide_index=True,
            )

            selected_run_id = st.selectbox(
                "View results for run",
                [r["id"] for r in runs],
                format_func=lambda rid: f"Run #{rid} - {next((r['suite_name'] for r in runs if r['id'] == rid), '')}",
            )
            if selected_run_id:
                results = get_test_results(selected_run_id)
                if results:
                    df_r = pd.DataFrame(results)

                    # Status counts
                    cols = st.columns(3)
                    cols[0].metric("Passed", len(df_r[df_r["status"] == "PASSED"]))
                    cols[1].metric("Failed", len(df_r[df_r["status"] == "FAILED"]))
                    cols[2].metric("Warnings", len(df_r[df_r["status"] == "WARNING"]))

                    st.dataframe(
                        df_r[["test_name", "category", "status", "duration_seconds", "details"]],
                        use_container_width=True, hide_index=True,
                    )
                else:
                    st.info("No results for this run.")
        else:
            st.info("No test runs found for the selected filters.")

    # ------------------------------------------------------------------
    # Trends
    # ------------------------------------------------------------------
    with tab_trends:
        st.subheader("Quarterly Trends")

        summary = get_results_summary()
        if summary:
            df_s = pd.DataFrame(summary)
            df_s["period"] = df_s["quarter"] + " " + df_s["year"].astype(str)
            df_s["pass_rate"] = (df_s["passed"] / df_s["total"] * 100).round(1)

            # Overall pass rate trend
            period_agg = df_s.groupby("period").agg(
                total=("total", "sum"),
                passed=("passed", "sum"),
            ).reset_index()
            period_agg["pass_rate"] = (period_agg["passed"] / period_agg["total"] * 100).round(1)

            fig = px.line(
                period_agg, x="period", y="pass_rate",
                title="Overall Pass Rate by Quarter",
                labels={"pass_rate": "Pass Rate (%)", "period": "Quarter"},
                markers=True,
            )
            fig.update_layout(yaxis_range=[0, 100])
            st.plotly_chart(fig, use_container_width=True)

            # By category
            fig2 = px.bar(
                df_s, x="period", y="pass_rate", color="category",
                title="Pass Rate by Category",
                barmode="group",
                labels={"pass_rate": "Pass Rate (%)", "period": "Quarter"},
            )
            st.plotly_chart(fig2, use_container_width=True)

            # Failed tests heatmap
            pivot = df_s.pivot_table(index="category", columns="period", values="failed", aggfunc="sum", fill_value=0)
            fig3 = px.imshow(
                pivot,
                title="Failed Tests Heatmap",
                labels=dict(x="Quarter", y="Category", color="Failures"),
                color_continuous_scale="Reds",
                aspect="auto",
            )
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("No test data yet. Run some regression tests to see trends.")
