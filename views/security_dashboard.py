"""Security Dashboard — Security Hub findings, GuardDuty alerts, vulnerability overview."""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from config import SEVERITY_LEVELS, SEVERITY_COLORS, AWS_REGIONS
from utils.data_source import (
    get_security_hub_findings,
    get_guardduty_findings,
)


def render():
    st.header("Security Dashboard")

    region = st.sidebar.selectbox("AWS Region", AWS_REGIONS, key="sec_region")

    tab_hub, tab_gd = st.tabs(["Security Hub", "GuardDuty"])

    # ------------------------------------------------------------------
    # Security Hub
    # ------------------------------------------------------------------
    with tab_hub:
        st.subheader("Security Hub Findings")
        try:
            df = get_security_hub_findings(region=region)
            if df.empty:
                st.info("No Security Hub findings returned. Verify Security Hub is enabled in this region.")
            else:
                # KPI row
                cols = st.columns(len(SEVERITY_LEVELS))
                for i, sev in enumerate(SEVERITY_LEVELS):
                    count = len(df[df["Severity"] == sev])
                    cols[i].metric(sev, count)

                # Severity distribution chart
                sev_counts = df["Severity"].value_counts().reindex(SEVERITY_LEVELS, fill_value=0)
                fig = px.bar(
                    x=sev_counts.index,
                    y=sev_counts.values,
                    color=sev_counts.index,
                    color_discrete_map=SEVERITY_COLORS,
                    labels={"x": "Severity", "y": "Count"},
                    title="Findings by Severity",
                )
                fig.update_layout(showlegend=False)
                st.plotly_chart(fig, use_container_width=True)

                # By resource type
                if "ResourceType" in df.columns:
                    rt_counts = df["ResourceType"].value_counts().head(10)
                    fig2 = px.pie(
                        values=rt_counts.values,
                        names=rt_counts.index,
                        title="Top Resource Types with Findings",
                    )
                    st.plotly_chart(fig2, use_container_width=True)

                # Findings table
                st.subheader("Finding Details")
                display_cols = ["Title", "Severity", "Status", "ResourceType", "ResourceId", "UpdatedAt"]
                available_cols = [c for c in display_cols if c in df.columns]
                st.dataframe(df[available_cols], use_container_width=True, hide_index=True)

        except Exception as e:
            st.error(f"Failed to fetch Security Hub findings: {e}")

    # ------------------------------------------------------------------
    # GuardDuty
    # ------------------------------------------------------------------
    with tab_gd:
        st.subheader("GuardDuty Findings")
        try:
            df_gd = get_guardduty_findings(region=region)
            if df_gd.empty:
                st.info("No GuardDuty findings. Either GuardDuty is not enabled or no threats detected.")
            else:
                # KPI row
                cols = st.columns(4)
                cols[0].metric("Total Findings", len(df_gd))
                cols[1].metric("CRITICAL / HIGH",
                    len(df_gd[df_gd["Severity"].isin(["CRITICAL", "HIGH"])]))
                cols[2].metric("MEDIUM",
                    len(df_gd[df_gd["Severity"] == "MEDIUM"]))
                cols[3].metric("LOW",
                    len(df_gd[df_gd["Severity"] == "LOW"]))

                # Threat type breakdown
                if "Type" in df_gd.columns:
                    # Extract top-level category from type string
                    df_gd["ThreatCategory"] = df_gd["Type"].apply(
                        lambda x: x.split(":")[0] if ":" in str(x) else str(x)
                    )
                    cat_counts = df_gd["ThreatCategory"].value_counts()
                    fig = px.bar(
                        x=cat_counts.index,
                        y=cat_counts.values,
                        labels={"x": "Threat Category", "y": "Count"},
                        title="GuardDuty Findings by Category",
                        color=cat_counts.values,
                        color_continuous_scale="Reds",
                    )
                    fig.update_layout(showlegend=False)
                    st.plotly_chart(fig, use_container_width=True)

                # Severity over time
                if "CreatedAt" in df_gd.columns:
                    df_gd["CreatedDate"] = pd.to_datetime(df_gd["CreatedAt"], errors="coerce").dt.date
                    timeline = df_gd.groupby(["CreatedDate", "Severity"]).size().reset_index(name="Count")
                    if not timeline.empty:
                        fig2 = px.line(
                            timeline, x="CreatedDate", y="Count", color="Severity",
                            title="GuardDuty Finding Trend",
                            color_discrete_map=SEVERITY_COLORS,
                        )
                        st.plotly_chart(fig2, use_container_width=True)

                # Table
                st.subheader("Finding Details")
                display_cols = ["Title", "Type", "Severity", "ResourceType", "Region", "CreatedAt"]
                available_cols = [c for c in display_cols if c in df_gd.columns]
                st.dataframe(df_gd[available_cols], use_container_width=True, hide_index=True)

        except Exception as e:
            st.error(f"Failed to fetch GuardDuty findings: {e}")
