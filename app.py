"""Enterprise Security & Quarterly Regression Testing Platform.

Main Streamlit entry point with sidebar navigation.
Secured with login gate, AWS credential gate, and audit logging.
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
# Gate 1 — Login
# ---------------------------------------------------------------------------
if not check_login():
    st.stop()

# ---------------------------------------------------------------------------
# Gate 2 — AWS Credentials (blocks app until connected)
# ---------------------------------------------------------------------------
if not st.session_state.get("aws_connected"):
    cols = st.columns([1, 2, 1])
    with cols[1]:
        st.markdown(f"# {APP_NAME}")
        st.markdown(f"### {APP_NAME_JP}")
        st.caption("Enterprise Security & Regression Testing")
        st.divider()

        st.markdown("### Connect to AWS")
        st.markdown(
            "Enter your temporary STS credentials to continue. "
            "All credentials are held in server memory only and never stored to disk."
        )

        st.markdown(
            "**How to get temporary credentials:**\n"
            "1. Open the [IAM Console](https://console.aws.amazon.com/iam/home#/users) "
            "and find your user\n"
            "2. Run in your terminal:\n"
            "   ```\n"
            "   aws sts get-session-token\n"
            "   ```\n"
            "3. Copy the `AccessKeyId`, `SecretAccessKey`, and `SessionToken` "
            "from the output and paste below\n\n"
            "Or copy credentials from your "
            "[AWS SSO start page](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtogetcredentials.html)"
        )

        with st.form("aws_creds_form"):
            access_key = st.text_input(
                "Step 1 — Access Key ID",
                type="password",
                placeholder="ASIA...",
                help="Starts with ASIA for temporary credentials",
            )
            secret_key = st.text_input(
                "Step 2 — Secret Access Key",
                type="password",
                help="From the `aws sts get-session-token` output",
            )
            session_token = st.text_input(
                "Step 3 — Session Token",
                type="password",
                help="Required for temporary STS credentials",
            )
            region = st.selectbox(
                "Step 4 — AWS Region",
                AWS_REGIONS,
                index=AWS_REGIONS.index(AWS_REGION),
                help="[See all AWS regions](https://docs.aws.amazon.com/general/latest/gr/rande.html)",
            )

            submitted = st.form_submit_button("Connect", type="primary", use_container_width=True)

            if submitted:
                if not access_key or not secret_key:
                    st.error("Access Key ID and Secret Access Key are required.")
                else:
                    st.session_state["aws_access_key_id"] = access_key
                    st.session_state["aws_secret_access_key"] = secret_key
                    st.session_state["aws_session_token"] = session_token
                    st.session_state["aws_region"] = region
                    st.session_state["aws_auth_method"] = "Access Keys (STS Temporary Only)"

                    conn = check_aws_connection()
                    if conn["connected"]:
                        st.session_state["aws_connected"] = True
                        log_event(
                            st.session_state.get("auth_user", "unknown"),
                            "aws_connect",
                            f"account={conn['account']}",
                        )
                        st.rerun()
                    else:
                        # Clear bad credentials
                        for k in ["aws_access_key_id", "aws_secret_access_key", "aws_session_token"]:
                            st.session_state.pop(k, None)
                        st.error(f"Connection failed: {conn.get('error', 'Unknown error')}")
                        st.markdown(
                            "**Troubleshooting:**\n"
                            "- Check that all 3 values are copied correctly\n"
                            "- Ensure the token hasn't expired "
                            "([default TTL is 12 hours](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html))\n"
                            "- Verify your IAM user has [STS permissions](https://console.aws.amazon.com/iam/home#/users)"
                        )

    st.stop()

# ---------------------------------------------------------------------------
# App starts here — AWS is connected
# ---------------------------------------------------------------------------
init_db()

# Log session start (only once per session)
if not st.session_state.get("_session_logged"):
    log_event(st.session_state.get("auth_user", "unknown"), "session_start")
    st.session_state["_session_logged"] = True

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
st.sidebar.markdown(f"## {APP_NAME} | {APP_NAME_JP}")

# Connection info
conn = check_aws_connection()
if conn["connected"]:
    st.sidebar.success(f"AWS: {conn['account']}")
    st.sidebar.caption(f"{conn['arn']}")

# Logout / Disconnect
col1, col2 = st.sidebar.columns(2)
with col1:
    if st.button("Logout", use_container_width=True):
        log_event(st.session_state.get("auth_user", "unknown"), "logout")
        logout()
        st.session_state.pop("aws_connected", None)
        st.rerun()
with col2:
    if st.button("Disconnect", use_container_width=True):
        log_event(st.session_state.get("auth_user", "unknown"), "aws_disconnect")
        for k in ["aws_access_key_id", "aws_secret_access_key", "aws_session_token", "aws_connected"]:
            st.session_state.pop(k, None)
        st.rerun()

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
