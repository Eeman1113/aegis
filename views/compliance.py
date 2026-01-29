"""Compliance Dashboard — SOC2, CIS, HIPAA, PCI-DSS, NIST framework mapping."""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from config import COMPLIANCE_FRAMEWORKS, AWS_REGIONS, SEVERITY_COLORS
from utils.data_source import (
    get_security_hub_findings,
    get_security_hub_standards,
    get_config_compliance,
)


# Mapping of Security Hub generator IDs to compliance frameworks
FRAMEWORK_MAPPING = {
    "SOC2": [
        "aws-foundational-security-best-practices",
        "cis-aws-foundations-benchmark",
    ],
    "CIS AWS Benchmark": [
        "cis-aws-foundations-benchmark",
    ],
    "HIPAA": [
        "aws-foundational-security-best-practices",
    ],
    "PCI-DSS": [
        "pci-dss",
    ],
    "NIST 800-53": [
        "nist-800-53",
        "aws-foundational-security-best-practices",
    ],
}


def _map_finding_to_frameworks(generator_id: str) -> list[str]:
    """Map a Security Hub finding generator to compliance frameworks."""
    gen_lower = generator_id.lower()
    matched = []
    for framework, patterns in FRAMEWORK_MAPPING.items():
        for pattern in patterns:
            if pattern in gen_lower:
                matched.append(framework)
                break
    if not matched:
        matched.append("General")
    return matched


def render():
    st.header("Compliance Dashboard")

    region = st.sidebar.selectbox("AWS Region", AWS_REGIONS, key="comp_region")

    tab_overview, tab_standards, tab_controls, tab_gaps = st.tabs([
        "Overview", "Security Standards", "Control Status", "Gap Analysis"
    ])

    # ------------------------------------------------------------------
    # Overview
    # ------------------------------------------------------------------
    with tab_overview:
        st.subheader("Compliance Overview")

        try:
            standards = get_security_hub_standards(region=region)
            if standards.empty:
                st.info("No security standards enabled in Security Hub. Enable standards to see compliance scores.")
            else:
                # Score cards
                cols = st.columns(len(standards))
                for i, (_, row) in enumerate(standards.iterrows()):
                    arn = row["StandardArn"]
                    name = arn.split("/")[-1] if "/" in arn else arn
                    score = row["Score"]
                    cols[i].metric(
                        name[:30],
                        f"{score}%",
                        delta=f"{row['Passed']}/{row['TotalControls']} passed",
                    )

                # Score bar chart
                standards["StandardName"] = standards["StandardArn"].apply(
                    lambda x: x.split("/")[-1] if "/" in x else x
                )
                fig = px.bar(
                    standards,
                    x="StandardName",
                    y="Score",
                    color="Score",
                    color_continuous_scale=["#dc3545", "#ffc107", "#28a745"],
                    range_color=[0, 100],
                    title="Security Standard Scores",
                    labels={"Score": "Score (%)", "StandardName": "Standard"},
                )
                fig.update_layout(yaxis_range=[0, 100])
                st.plotly_chart(fig, use_container_width=True)

                # Passed vs Failed breakdown
                fig2 = px.bar(
                    standards,
                    x="StandardName",
                    y=["Passed", "Failed"],
                    title="Controls: Passed vs Failed",
                    barmode="stack",
                    color_discrete_map={"Passed": "#28a745", "Failed": "#dc3545"},
                )
                st.plotly_chart(fig2, use_container_width=True)

        except Exception as e:
            st.error(f"Failed to fetch security standards: {e}")

    # ------------------------------------------------------------------
    # Security Standards Details
    # ------------------------------------------------------------------
    with tab_standards:
        st.subheader("Enabled Security Standards")
        try:
            standards = get_security_hub_standards(region=region)
            if not standards.empty:
                st.dataframe(standards, use_container_width=True, hide_index=True)
            else:
                st.info("No standards enabled.")
        except Exception as e:
            st.error(f"Failed to fetch standards: {e}")

        st.subheader("AWS Config Rule Compliance")
        try:
            config = get_config_compliance(region=region)
            if not config.empty:
                comp_counts = config["ComplianceType"].value_counts().reset_index()
                comp_counts.columns = ["ComplianceType", "Count"]
                fig = px.pie(
                    comp_counts,
                    names="ComplianceType",
                    values="Count",
                    title="Config Rule Compliance Status",
                    color="ComplianceType",
                    color_discrete_map={
                        "COMPLIANT": "#28a745",
                        "NON_COMPLIANT": "#dc3545",
                        "NOT_APPLICABLE": "#6c757d",
                        "INSUFFICIENT_DATA": "#ffc107",
                    },
                )
                st.plotly_chart(fig, use_container_width=True)
                st.dataframe(config, use_container_width=True, hide_index=True)
            else:
                st.info("No AWS Config rules configured.")
        except Exception as e:
            st.error(f"Failed to fetch Config compliance: {e}")

    # ------------------------------------------------------------------
    # Control Status — mapped to frameworks
    # ------------------------------------------------------------------
    with tab_controls:
        st.subheader("Controls by Compliance Framework")

        try:
            findings = get_security_hub_findings(region=region, max_results=100)
            if findings.empty:
                st.info("No findings to map to frameworks.")
            else:
                # Map findings to frameworks
                framework_rows = []
                for _, f in findings.iterrows():
                    frameworks = _map_finding_to_frameworks(f.get("GeneratorId", ""))
                    for fw in frameworks:
                        framework_rows.append({
                            "Framework": fw,
                            "Title": f["Title"],
                            "Severity": f["Severity"],
                            "Status": f["Status"],
                            "ResourceType": f.get("ResourceType", ""),
                        })

                df_fw = pd.DataFrame(framework_rows)

                selected_fw = st.selectbox("Filter by Framework", ["All"] + sorted(df_fw["Framework"].unique().tolist()))
                if selected_fw != "All":
                    df_fw = df_fw[df_fw["Framework"] == selected_fw]

                # Summary by framework
                fw_summary = df_fw.groupby("Framework").agg(
                    Total=("Title", "count"),
                    Critical=("Severity", lambda x: (x == "CRITICAL").sum()),
                    High=("Severity", lambda x: (x == "HIGH").sum()),
                    Medium=("Severity", lambda x: (x == "MEDIUM").sum()),
                    Low=("Severity", lambda x: (x == "LOW").sum()),
                ).reset_index()

                fig = px.bar(
                    fw_summary,
                    x="Framework",
                    y=["Critical", "High", "Medium", "Low"],
                    title="Findings by Framework and Severity",
                    barmode="stack",
                    color_discrete_map={
                        "Critical": "#dc3545",
                        "High": "#fd7e14",
                        "Medium": "#ffc107",
                        "Low": "#28a745",
                    },
                )
                st.plotly_chart(fig, use_container_width=True)

                st.dataframe(df_fw, use_container_width=True, hide_index=True)

        except Exception as e:
            st.error(f"Failed to map controls: {e}")

    # ------------------------------------------------------------------
    # Gap Analysis
    # ------------------------------------------------------------------
    with tab_gaps:
        st.subheader("Compliance Gap Analysis")

        try:
            findings = get_security_hub_findings(region=region, max_results=100)
            if findings.empty:
                st.info("No findings available for gap analysis.")
            else:
                # Failed / non-compliant findings grouped by resource type
                failed = findings[findings["Status"].isin(["FAILED", "WARNING", ""])]
                if failed.empty:
                    st.success("No compliance gaps detected. All findings are passing.")
                else:
                    st.warning(f"{len(failed)} findings with gaps detected.")

                    # By severity
                    sev_counts = failed["Severity"].value_counts().reindex(
                        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], fill_value=0
                    )
                    cols = st.columns(5)
                    for i, sev in enumerate(sev_counts.index):
                        cols[i].metric(sev, sev_counts[sev])

                    # Gap matrix: Resource Type x Severity
                    if "ResourceType" in failed.columns:
                        gap_matrix = failed.groupby(["ResourceType", "Severity"]).size().unstack(fill_value=0)
                        # Reorder columns
                        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
                            if sev not in gap_matrix.columns:
                                gap_matrix[sev] = 0
                        gap_matrix = gap_matrix[["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]]

                        fig = px.imshow(
                            gap_matrix,
                            title="Gap Heatmap: Resource Type x Severity",
                            labels=dict(x="Severity", y="Resource Type", color="Count"),
                            color_continuous_scale="Reds",
                            aspect="auto",
                        )
                        st.plotly_chart(fig, use_container_width=True)

                    # Top gaps to remediate
                    st.subheader("Priority Remediation Items")
                    priority = failed[failed["Severity"].isin(["CRITICAL", "HIGH"])].sort_values(
                        "Severity", ascending=True
                    )
                    if not priority.empty:
                        display_cols = ["Title", "Severity", "ResourceType", "ResourceId"]
                        available = [c for c in display_cols if c in priority.columns]
                        st.dataframe(priority[available], use_container_width=True, hide_index=True)
                    else:
                        st.success("No CRITICAL or HIGH severity gaps.")

        except Exception as e:
            st.error(f"Failed to perform gap analysis: {e}")
