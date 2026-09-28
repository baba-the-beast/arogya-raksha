"""
Phase 4 — Multi-Factor Authentication (TOTP / RFC 6238) Tests.

Covers:
- Secret generation and standard otpauth:// URI formatting
- Time-based token verification
- Multi-step login flow: password check -> MFA challenge -> authenticated session
- Protection against invalid TOTP codes
- Admin grace login and MFA enrollment wizard
"""
import pyotp
import pytest

from app.extensions import db
from app.models.user import User
from app.services.auth_service import AuthService
from tests.conftest import login_client


def test_totp_secret_and_uri_generation():
    """AuthService generates valid Base32 secret and valid otpauth URI."""
    secret = AuthService.generate_totp_secret()
    assert len(secret) == 32
    # Verify it can be parsed by pyotp
    uri = AuthService.get_totp_uri("doctor_alice", secret)
    assert uri.startswith("otpauth://totp/ArogyaRaksha:doctor_alice")
    assert f"secret={secret}" in uri


def test_totp_code_verification_success_and_failure():
    """Valid TOTP code verifies successfully; invalid or expired code is rejected."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    assert AuthService.verify_totp(secret, valid_code) is True
    assert AuthService.verify_totp(secret, "000000") is False
    assert AuthService.verify_totp(secret, "") is False


def test_login_flow_with_totp_enabled_user(client, app):
    """Users with totp_enabled=True are redirected to /login/mfa before receiving a session."""
    secret = pyotp.random_base32()
    mfa_user = User(
        username="mfa_doc",
        password_hash=AuthService.hash_password("DoctorPass#123"),
        role="Doctor",
        is_active=True,
        totp_secret=secret,
        totp_enabled=True,
    )
    db.session.add(mfa_user)
    db.session.commit()

    # Step 1: Submit username + password
    resp = client.post("/login", data={
        "username": "mfa_doc",
        "password": "DoctorPass#123"
    }, follow_redirects=False)

    assert resp.status_code == 302
    assert resp.location.endswith("/login/mfa")

    # Verify user is NOT yet authenticated in session
    with client.session_transaction() as sess:
        assert sess.get("user_id") is None
        assert sess.get("mfa_pending_user_id") is not None

    # Step 2: Submit INVALID code -> 401
    bad_resp = client.post("/login/mfa", data={"totp_code": "999999"}, follow_redirects=True)
    assert bad_resp.status_code == 401
    assert "Invalid or expired" in bad_resp.data.decode()

    # Step 3: Submit VALID code -> 302 -> dashboard
    good_code = pyotp.TOTP(secret).now()
    good_resp = client.post("/login/mfa", data={"totp_code": good_code}, follow_redirects=True)
    assert good_resp.status_code == 200
    assert "Welcome back" in good_resp.data.decode()

    # Verify user is now authenticated
    with client.session_transaction() as sess:
        assert sess.get("user_id") is not None
        assert sess.get("username") == "mfa_doc"
        assert sess.get("mfa_pending_user_id") is None


def test_admin_mfa_setup_and_confirmation(client, app):
    """Admin can configure TOTP MFA via setup wizard and confirmation code."""
    login_client(client, "test_admin", "AdminPass#123")

    # Access setup wizard
    resp = client.get("/admin/settings/mfa")
    assert resp.status_code == 200
    assert "Set up two-factor authentication" in resp.data.decode()

    with client.session_transaction() as sess:
        secret = sess.get("pending_totp_secret")
        assert secret is not None

    # Confirm with correct code
    valid_code = pyotp.TOTP(secret).now()
    confirm_resp = client.post("/admin/settings/mfa/confirm", data={"totp_code": valid_code}, follow_redirects=True)
    assert confirm_resp.status_code == 200
    assert "Multi-Factor Authentication has been successfully activated" in confirm_resp.data.decode()

    # Verify user now has totp_enabled=True in DB
    admin = User.query.filter_by(username="test_admin").first()
    assert admin.totp_enabled is True
    assert admin.totp_secret == secret


def test_admin_grace_login_redirect_when_enforced(client, app):
    """When MFA_ENFORCE_ADMIN is True, an Admin without TOTP is redirected to setup upon accessing admin routes."""
    app.config["MFA_ENFORCE_ADMIN"] = True
    login_client(client, "test_admin", "AdminPass#123")

    # Attempt to view audit log
    resp = client.get("/admin/audit", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.location.endswith("/admin/settings/mfa")
    app.config["MFA_ENFORCE_ADMIN"] = False
