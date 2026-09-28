"""
Security Tests for Clean URL Password Reset Workflow and Open Redirect Defenses.
"""
from itsdangerous import URLSafeTimedSerializer

from app.models.tenant import Tenant
from app.models.user import User
from app.routes.auth import is_safe_redirect_url


def test_open_redirect_url_validator(app):
    """
    Test that is_safe_redirect_url() rejects all variations of external,
    protocol-relative, encoded, backslash, and null-byte bypasses.
    """
    with app.test_request_context("/"):
        # Legitimate internal paths
        assert is_safe_redirect_url("/dashboard") is True
        assert is_safe_redirect_url("/patients/123") is True
        assert is_safe_redirect_url("/admin/audit?page=2") is True

        # Empty or None
        assert is_safe_redirect_url("") is False
        assert is_safe_redirect_url(None) is False

        # External URLs with scheme
        assert is_safe_redirect_url("https://evil.com") is False
        assert is_safe_redirect_url("http://evil.com/attack") is False
        assert is_safe_redirect_url("ftp://evil.com") is False
        assert is_safe_redirect_url("javascript:alert(1)") is False

        # Protocol-relative URLs
        assert is_safe_redirect_url("//evil.com") is False
        assert is_safe_redirect_url("//evil.com/phish") is False
        assert is_safe_redirect_url("/\\evil.com") is False
        assert is_safe_redirect_url("\\\\evil.com") is False
        assert is_safe_redirect_url("\\evil.com") is False

        # URL-encoded bypasses
        assert is_safe_redirect_url("%2fevil.com") is False
        assert is_safe_redirect_url("%5cevil.com") is False
        assert is_safe_redirect_url("/%2f/evil.com") is False

        # Control characters and null bytes
        assert is_safe_redirect_url("/dashboard\nhttps://evil.com") is False
        assert is_safe_redirect_url("/dashboard\r\nSet-Cookie: evil=1") is False
        assert is_safe_redirect_url("/dashboard\x00evil") is False


def test_clean_url_password_reset_flow(client):
    """
    Test the high-assurance clean URL password reset flow:
    1. GET /auth/reset-password/<token> validates token and 302 redirects to /auth/reset-password.
    2. Session ticket _reset_ticket is stored.
    3. POST /auth/reset-password consumes ticket, resets password, and invalidates ticket.
    4. Replaying POST /auth/reset-password is rejected.
    """
    from app.extensions import db
    from app.services.auth_service import AuthService

    with client.application.app_context():
        if not db.session.get(Tenant, "tenant-default"):
            db.session.add(Tenant(id="tenant-default", name="Default Clinic"))
        user = User.query.filter_by(username="reset_flow_user").first()
        if not user:
            user = User(
                username="reset_flow_user",
                password_hash=AuthService.hash_password("OldPassword#1234"),
                role="Doctor",
                tenant_id="tenant-default",
                is_active=True,
            )
            db.session.add(user)
            db.session.commit()

        valid_token = AuthService.create_password_reset_token("reset_flow_user")
        assert valid_token is not None

    # 1. Access GET /reset-password/<token>
    resp = client.get(f"/reset-password/{valid_token}")
    assert resp.status_code == 302
    assert "/reset-password" in resp.headers["Location"]
    assert valid_token not in resp.headers["Location"]  # Token stripped from URL!

    # 2. Follow redirect to clean GET /reset-password
    clean_get_resp = client.get("/reset-password")
    assert clean_get_resp.status_code == 200
    assert b"Set New Password" in clean_get_resp.data

    # 3. Submit new password to clean POST /reset-password
    post_resp = client.post(
        "/reset-password",
        data={
            "password": "BrandNewSecurePassword#9999",
            "confirm_password": "BrandNewSecurePassword#9999",
        },
        follow_redirects=False,
    )
    assert post_resp.status_code == 302
    assert "/login" in post_resp.headers["Location"]

    # Verify user can log in with new password
    with client.application.app_context():
        db.session.expire_all()
        updated_user = User.query.filter_by(username="reset_flow_user").first()
        assert AuthService.verify_password(updated_user.password_hash, "BrandNewSecurePassword#9999") is True

    # 4. Attempt to replay POST /reset-password (ticket should be consumed)
    replay_resp = client.post(
        "/reset-password",
        data={
            "password": "AnotherNewPassword#1111",
            "confirm_password": "AnotherNewPassword#1111",
        },
        follow_redirects=False,
    )
    # Must redirect back to forgot-password because reset ticket is invalid/consumed
    assert replay_resp.status_code == 302
    assert "/forgot-password" in replay_resp.headers["Location"]
