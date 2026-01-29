"""Authentication and session management.

Uses a hashed password stored in environment variable APP_PASSWORD_HASH.
Generate a hash with: python -c "import hashlib; print(hashlib.sha256(b'your-password').hexdigest())"
"""

import hashlib
import os
import streamlit as st


def _get_password_hash() -> str | None:
    return os.environ.get("APP_PASSWORD_HASH")


def check_login() -> bool:
    """Show login form and return True if authenticated."""
    if st.session_state.get("authenticated"):
        return True

    expected_hash = _get_password_hash()

    # If no password hash is configured, warn but allow access (dev mode)
    if not expected_hash:
        st.session_state["authenticated"] = True
        st.session_state["auth_user"] = "dev-mode"
        return True

    from config import APP_NAME, APP_NAME_JP

    cols = st.columns([1, 2, 1])
    with cols[1]:
        st.markdown(f"# {APP_NAME}")
        st.markdown(f"### {APP_NAME_JP}")
        st.caption("Enterprise Security & Regression Testing")
        st.divider()

    with st.form("login_form"):
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            entered_hash = hashlib.sha256(password.encode()).hexdigest()
            if entered_hash == expected_hash:
                st.session_state["authenticated"] = True
                st.session_state["auth_user"] = "authenticated-user"
                st.rerun()
            else:
                st.error("Invalid password.")

    return False


def logout():
    """Clear authentication state."""
    for key in ["authenticated", "auth_user", "aws_access_key_id",
                "aws_secret_access_key", "aws_session_token"]:
        st.session_state.pop(key, None)
