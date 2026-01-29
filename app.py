"""Enterprise Security & Quarterly Regression Testing Platform.

Main Streamlit entry point with sidebar navigation.
Secured with login gate, IAM role / profile / STS auth, and audit logging.
"""

import streamlit as st

from config import APP_TITLE, APP_NAME, APP_NAME_JP, AWS_REGIONS, AWS_REGION
from utils.aws_integration import check_aws_connection
from utils.auth import check_login, logout
from utils.audit_log import log_event
from utils.db import init_db

# Page configuration
st.set_page_config(
    page_title=APP_TITLE,
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Login gate — blocks everything until authenticated
# ---------------------------------------------------------------------------
if not check_login():
    st.stop()

# Initialize database
init_db()

# Log session start (only once per session)
if not st.session_state.get("_session_logged"):
    log_event(st.session_state.get("auth_user", "unknown"), "session_start")
    st.session_state["_session_logged"] = True

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
st.sidebar.markdown(f"## {APP_NAME} | {APP_NAME_JP}")

# Logout button
if st.sidebar.button("Logout"):
    log_event(st.session_state.get("auth_user", "unknown"), "logout")
    logout()
    st.rerun()

st.sidebar.divider()

# AWS Authentication — secure methods only
with st.sidebar.expander("AWS Connection", expanded=not st.session_state.get("aws_access_key_id")):
    auth_method = st.radio(
        "Authentication Method",
        ["IAM Role / Instance Profile", "AWS CLI Profile", "Access Keys (STS Temporary Only)"],
        key="aws_auth_method",
        help="IAM Roles are the recommended method. Access keys should only be temporary STS credentials.",
    )

    if auth_method == "AWS CLI Profile":
        st.text_input(
            "Profile Name",
            key="aws_cli_profile",
            placeholder="default",
            help="Profile from ~/.aws/credentials",
        )

    elif auth_method == "Access Keys (STS Temporary Only)":
        st.warning("Only use temporary credentials from `aws sts get-session-token` or SSO. Never paste long-lived IAM keys.")
        st.text_input("Access Key ID", type="password", key="aws_access_key_id", placeholder="ASIA...")
        st.text_input("Secret Access Key", type="password", key="aws_secret_access_key")
        st.text_input("Session Token (required for STS)", type="password", key="aws_session_token")

    st.selectbox(
        "Default Region",
        AWS_REGIONS,
        index=AWS_REGIONS.index(AWS_REGION),
        key="aws_region",
    )

    st.caption("Credentials are held in server memory for this session only. Never stored to disk.")

# AWS connection status
conn = check_aws_connection()
if conn["connected"]:
    st.sidebar.success(f"AWS: {conn['account']}")
    st.sidebar.caption(f"{conn['arn']}")
    if not st.session_state.get("_aws_logged"):
        log_event(st.session_state.get("auth_user", "unknown"), "aws_connect",
                  f"account={conn['account']}")
        st.session_state["_aws_logged"] = True
else:
    st.sidebar.error("AWS: Not connected")
    st.sidebar.caption("Configure connection above")

st.sidebar.divider()

# Navigation
page = st.sidebar.radio(
    "Navigation",
    [
        "Security Dashboard",
        "Regression Testing",
        "AWS Environment",
        "Customer Environments",
        "Compliance",
        "Reports",
    ],
    label_visibility="collapsed",
)

st.sidebar.divider()
st.sidebar.caption(f"{APP_NAME} v1.0")

# ---------------------------------------------------------------------------
# Centered logo header
# ---------------------------------------------------------------------------
cols = st.columns([1, 2, 1])
with cols[1]:
    st.markdown(f"# {APP_NAME}")
    st.markdown(f"### {APP_NAME_JP}")
    st.caption("Enterprise Security & Regression Testing")

st.divider()

# ---------------------------------------------------------------------------
# Page routing
# ---------------------------------------------------------------------------
log_event(st.session_state.get("auth_user", "unknown"), "page_view", f"page={page}")

if page == "Security Dashboard":
    from views.security_dashboard import render
    render()

elif page == "Regression Testing":
    from views.regression_testing import render
    render()

elif page == "AWS Environment":
    from views.aws_environment import render
    render()

elif page == "Customer Environments":
    from views.customer_environments import render
    render()

elif page == "Compliance":
    from views.compliance import render
    render()

elif page == "Reports":
    from views.reports import render
    render()
