"""Reports — Quarterly report generation, export, and summary views."""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
from datetime import datetime

from config import QUARTERS, YEARS, AWS_REGIONS, SEVERITY_LEVELS
from utils.db import get_test_runs, get_test_results, get_results_summary, init_db
from utils.data_source import (
    get_security_hub_findings,
    get_guardduty_findings,
    get_config_compliance,
    check_aws_connection,
)


def _build_quarterly_report_data(quarter: str, year: int, region: str) -> dict:
    """Aggregate all data for a quarterly report."""
    report = {
        "quarter": quarter,
        "year": year,
        "region": region,
        "generated_at": datetime.utcnow().isoformat(),
        "sections": {},
    }

    # Security Hub summary
    try:
        findings = get_security_hub_findings(region=region, max_results=100)
        if not findings.empty:
            sev_counts = findings["Severity"].value_counts().to_dict()
            report["sections"]["security_hub"] = {
                "total_findings": len(findings),
                "by_severity": sev_counts,
                "top_resource_types": findings["ResourceType"].value_counts().head(5).to_dict(),
            }
        else:
            report["sections"]["security_hub"] = {"total_findings": 0}
    except Exception as e:
        report["sections"]["security_hub"] = {"error": str(e)}

    # GuardDuty summary
    try:
        gd = get_guardduty_findings(region=region, max_results=50)
        if not gd.empty:
            report["sections"]["guardduty"] = {
                "total_findings": len(gd),
                "by_severity": gd["Severity"].value_counts().to_dict(),
            }
        else:
            report["sections"]["guardduty"] = {"total_findings": 0}
    except Exception as e:
        report["sections"]["guardduty"] = {"error": str(e)}

    # Config compliance
    try:
        config = get_config_compliance(region=region)
        if not config.empty:
            comp_counts = config["ComplianceType"].value_counts().to_dict()
            report["sections"]["config"] = {
                "total_rules": len(config),
                "by_status": comp_counts,
            }
        else:
            report["sections"]["config"] = {"total_rules": 0}
    except Exception as e:
        report["sections"]["config"] = {"error": str(e)}

    # Regression test results for this quarter
    runs = get_test_runs(quarter=quarter, year=year)
    if runs:
        all_results = []
        for run in runs:
            results = get_test_results(run["id"])
            all_results.extend(results)

        if all_results:
            df_r = pd.DataFrame(all_results)
            report["sections"]["regression"] = {
                "total_runs": len(runs),
                "total_tests": len(all_results),
                "passed": len(df_r[df_r["status"] == "PASSED"]),
                "failed": len(df_r[df_r["status"] == "FAILED"]),
                "warnings": len(df_r[df_r["status"] == "WARNING"]),
                "pass_rate": round(len(df_r[df_r["status"] == "PASSED"]) / len(df_r) * 100, 1) if len(df_r) > 0 else 0,
                "by_category": df_r.groupby("category")["status"].value_counts().unstack(fill_value=0).to_dict(),
            }
        else:
            report["sections"]["regression"] = {"total_runs": len(runs), "total_tests": 0}
    else:
        report["sections"]["regression"] = {"total_runs": 0, "total_tests": 0}

    return report


def render():
    st.header("Quarterly Reports")

    init_db()

    region = st.sidebar.selectbox("AWS Region", AWS_REGIONS, key="report_region")

    tab_generate, tab_export, tab_history = st.tabs([
        "Generate Report", "Export Data", "Historical Comparison"
    ])

    # ------------------------------------------------------------------
    # Generate Report
    # ------------------------------------------------------------------
    with tab_generate:
        st.subheader("Generate Quarterly Security Report")

        col1, col2 = st.columns(2)
        with col1:
            quarter = st.selectbox("Quarter", QUARTERS, key="rpt_q")
        with col2:
            year = st.selectbox("Year", YEARS, key="rpt_y")

        if st.button("Generate Report", type="primary"):
            conn = check_aws_connection(region)
            if not conn["connected"]:
                st.error(f"AWS connection required: {conn['error']}")
            else:
                with st.spinner("Collecting data from AWS and test database..."):
                    report = _build_quarterly_report_data(quarter, year, region)

                st.success(f"Report generated for {quarter} {year}")

                # --- Display report ---
                st.markdown(f"## {quarter} {year} Security Report")
                st.markdown(f"**Region:** {region} | **Generated:** {report['generated_at']}")

                # Security Hub section
                st.markdown("---")
                st.markdown("### Security Hub Summary")
                sh = report["sections"].get("security_hub", {})
                if "error" in sh:
                    st.warning(f"Security Hub: {sh['error']}")
                else:
                    cols = st.columns(len(SEVERITY_LEVELS) + 1)
                    cols[0].metric("Total Findings", sh.get("total_findings", 0))
                    sev = sh.get("by_severity", {})
                    for i, s in enumerate(SEVERITY_LEVELS):
                        cols[i + 1].metric(s, sev.get(s, 0))

                # GuardDuty section
                st.markdown("---")
                st.markdown("### GuardDuty Summary")
                gd = report["sections"].get("guardduty", {})
                if "error" in gd:
                    st.warning(f"GuardDuty: {gd['error']}")
                else:
                    cols = st.columns(2)
                    cols[0].metric("Total Threat Findings", gd.get("total_findings", 0))
                    gd_sev = gd.get("by_severity", {})
                    crit_high = gd_sev.get("CRITICAL", 0) + gd_sev.get("HIGH", 0)
                    cols[1].metric("Critical + High", crit_high)

                # Config section
                st.markdown("---")
                st.markdown("### AWS Config Compliance")
                cfg = report["sections"].get("config", {})
                if "error" in cfg:
                    st.warning(f"Config: {cfg['error']}")
                else:
                    cols = st.columns(3)
                    cols[0].metric("Total Rules", cfg.get("total_rules", 0))
                    status = cfg.get("by_status", {})
                    cols[1].metric("Compliant", status.get("COMPLIANT", 0))
                    cols[2].metric("Non-Compliant", status.get("NON_COMPLIANT", 0))

                # Regression section
                st.markdown("---")
                st.markdown("### Regression Testing Summary")
                reg = report["sections"].get("regression", {})
                cols = st.columns(5)
                cols[0].metric("Test Runs", reg.get("total_runs", 0))
                cols[1].metric("Total Tests", reg.get("total_tests", 0))
                cols[2].metric("Passed", reg.get("passed", 0))
                cols[3].metric("Failed", reg.get("failed", 0))
                cols[4].metric("Pass Rate", f"{reg.get('pass_rate', 0)}%")

                # Store in session for export
                st.session_state["last_report"] = report

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    with tab_export:
        st.subheader("Export Data")

        export_type = st.selectbox("Data to Export", [
            "Security Hub Findings",
            "GuardDuty Findings",
            "Config Compliance",
            "Regression Test Results",
            "Full Quarterly Report (JSON)",
        ])

        col1, col2 = st.columns(2)
        with col1:
            exp_quarter = st.selectbox("Quarter", QUARTERS, key="exp_q")
        with col2:
            exp_year = st.selectbox("Year", YEARS, key="exp_y")

        if st.button("Export"):
            if export_type == "Security Hub Findings":
                try:
                    df = get_security_hub_findings(region=region)
                    if not df.empty:
                        csv = df.to_csv(index=False)
                        st.download_button(
                            "Download CSV", csv,
                            file_name=f"security_hub_findings_{region}_{datetime.utcnow().strftime('%Y%m%d')}.csv",
                            mime="text/csv",
                        )
                    else:
                        st.info("No data to export.")
                except Exception as e:
                    st.error(str(e))

            elif export_type == "GuardDuty Findings":
                try:
                    df = get_guardduty_findings(region=region)
                    if not df.empty:
                        csv = df.to_csv(index=False)
                        st.download_button(
                            "Download CSV", csv,
                            file_name=f"guardduty_findings_{region}_{datetime.utcnow().strftime('%Y%m%d')}.csv",
                            mime="text/csv",
                        )
                    else:
                        st.info("No data to export.")
                except Exception as e:
                    st.error(str(e))

            elif export_type == "Config Compliance":
                try:
                    df = get_config_compliance(region=region)
                    if not df.empty:
                        csv = df.to_csv(index=False)
                        st.download_button(
                            "Download CSV", csv,
                            file_name=f"config_compliance_{region}_{datetime.utcnow().strftime('%Y%m%d')}.csv",
                            mime="text/csv",
                        )
                    else:
                        st.info("No data to export.")
                except Exception as e:
                    st.error(str(e))

            elif export_type == "Regression Test Results":
                runs = get_test_runs(quarter=exp_quarter, year=exp_year)
                all_results = []
                for run in runs:
                    results = get_test_results(run["id"])
                    for r in results:
                        r["suite_name"] = run["suite_name"]
                        r["quarter"] = run["quarter"]
                        r["year"] = run["year"]
                        r["environment"] = run["environment"]
                    all_results.extend(results)
                if all_results:
                    df = pd.DataFrame(all_results)
                    csv = df.to_csv(index=False)
                    st.download_button(
                        "Download CSV", csv,
                        file_name=f"regression_results_{exp_quarter}_{exp_year}.csv",
                        mime="text/csv",
                    )
                else:
                    st.info("No regression test data for this period.")

            elif export_type == "Full Quarterly Report (JSON)":
                conn = check_aws_connection(region)
                if conn["connected"]:
                    with st.spinner("Building full report..."):
                        report = _build_quarterly_report_data(exp_quarter, exp_year, region)
                    import json
                    json_str = json.dumps(report, indent=2, default=str)
                    st.download_button(
                        "Download JSON", json_str,
                        file_name=f"quarterly_report_{exp_quarter}_{exp_year}.json",
                        mime="application/json",
                    )
                else:
                    st.error(f"AWS connection required: {conn['error']}")

    # ------------------------------------------------------------------
    # Historical Comparison
    # ------------------------------------------------------------------
    with tab_history:
        st.subheader("Quarter-over-Quarter Comparison")

        summary = get_results_summary()
        if summary:
            df_s = pd.DataFrame(summary)
            df_s["period"] = df_s["quarter"] + " " + df_s["year"].astype(str)
            df_s["pass_rate"] = (df_s["passed"] / df_s["total"] * 100).round(1)

            # Overall trend
            period_agg = df_s.groupby("period").agg(
                total=("total", "sum"),
                passed=("passed", "sum"),
                failed=("failed", "sum"),
            ).reset_index()
            period_agg["pass_rate"] = (period_agg["passed"] / period_agg["total"] * 100).round(1)

            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=period_agg["period"], y=period_agg["passed"],
                name="Passed", marker_color="#28a745",
            ))
            fig.add_trace(go.Bar(
                x=period_agg["period"], y=period_agg["failed"],
                name="Failed", marker_color="#dc3545",
            ))
            fig.add_trace(go.Scatter(
                x=period_agg["period"], y=period_agg["pass_rate"],
                name="Pass Rate (%)", yaxis="y2",
                mode="lines+markers", marker_color="#007bff",
            ))
            fig.update_layout(
                title="Quarterly Test Results & Pass Rate",
                barmode="stack",
                yaxis=dict(title="Test Count"),
                yaxis2=dict(title="Pass Rate (%)", overlaying="y", side="right", range=[0, 100]),
            )
            st.plotly_chart(fig, use_container_width=True)

            # Category comparison across quarters
            fig2 = px.line(
                df_s, x="period", y="pass_rate", color="category",
                title="Pass Rate Trend by Category",
                markers=True,
                labels={"pass_rate": "Pass Rate (%)", "period": "Quarter"},
            )
            fig2.update_layout(yaxis_range=[0, 100])
            st.plotly_chart(fig2, use_container_width=True)

            st.dataframe(df_s, use_container_width=True, hide_index=True)
        else:
            st.info("No historical test data yet. Run regression tests to see comparisons.")
