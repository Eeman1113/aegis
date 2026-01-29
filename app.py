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

    if auth_method == "IAM Role / Instance Profile":
        st.markdown(
            "**No credentials needed.** Auto-discovered from the "
            "EC2/ECS instance metadata.\n\n"
            "**How to set up:**\n"
            "1. [Create an IAM Role](https://console.aws.amazon.com/iam/home#/roles$new) "
            "with read-only security permissions\n"
            "2. [Attach the role to your EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html) "
            "or ECS task\n"
            "3. Select your region below and you're connected"
        )

    elif auth_method == "AWS CLI Profile":
        st.markdown(
            "**How to set up:**\n"
            "1. [Install AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)\n"
            "2. Run `aws configure` or `aws configure sso` in your terminal\n"
            "3. Find your profiles in `~/.aws/credentials` "
            "([docs](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html))\n"
            "4. Enter the profile name below"
        )
        st.text_input(
            "Profile Name",
            key="aws_cli_profile",
            placeholder="default",
            help="Profile from ~/.aws/credentials",
        )

    elif auth_method == "Access Keys (STS Temporary Only)":
        st.warning("Only use temporary credentials. Never paste long-lived IAM keys.")
        st.markdown(
            "**How to get temporary credentials:**\n"
            "1. Open the [IAM Console](https://console.aws.amazon.com/iam/home#/users) "
            "and find your user\n"
            "2. Run in your terminal:\n"
            "   ```\n"
            "   aws sts get-session-token\n"
            "   ```\n"
            "3. Copy the `AccessKeyId`, `SecretAccessKey`, and `SessionToken` from the output\n"
            "4. Paste them below\n\n"
            "Or use [SSO login](https://docs.aws.amazon.com/cli/latest/userguide/sso-configure-profile-token.html) "
            "and copy credentials from your "
            "[SSO start page](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtogetcredentials.html)."
        )
        st.text_input("Step 1 \u2014 Access Key ID", type="password", key="aws_access_key_id", placeholder="ASIA...")
        st.text_input("Step 2 \u2014 Secret Access Key", type="password", key="aws_secret_access_key")
        st.text_input("Step 3 \u2014 Session Token", type="password", key="aws_session_token",
                       help="Required for STS temporary credentials")

    st.selectbox(
        "Region",
        AWS_REGIONS,
        index=AWS_REGIONS.index(AWS_REGION),
        key="aws_region",
        help="[See all AWS regions](https://docs.aws.amazon.com/general/latest/gr/rande.html)",
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
