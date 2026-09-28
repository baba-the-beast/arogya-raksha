"""
Phase 4 — Password Reset Flow Tests.

Covers:
- Secure token generation with SHA-256 hash storage
- Constant-response pattern protecting against username enumeration
- Token expiry and single-use enforcement
- Password policy enforcement during reset
- Automatic session revocation upon password update
"""
import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.extensions import db
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.services.auth_service import AuthService
from tests.conftest import login_client


def test_password_reset_token_creation_and_enumeration_defense(app, client):
    """
    Submitting valid or invalid username returns identical generic message.
    Tokens are only generated in DB for valid active users.
    """
    # Valid user
    token_valid = AuthService.create_password_reset_token("test_doctor")
    assert token_valid is not None
    assert len(token_valid) >= 32

    # Token is stored as hash, not plaintext
    token_hash = hashlib.sha256(token_valid.encode("utf-8")).hexdigest()
    record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
    assert record is not None
    assert record.used is False
    assert record.is_valid() is True

    # Invalid username returns None
    token_invalid = AuthService.create_password_reset_token("nonexistent_user_123")
    assert token_invalid is None

    # HTTP route returns generic response for both
    resp = client.post("/forgot-password", data={"username": "test_doctor"}, follow_redirects=True)
    assert resp.status_code == 200
    assert "If an active account matches" in resp.data.decode()

    resp_fake = client.post("/forgot-password", data={"username": "fake_user_456"}, follow_redirects=True)
    assert resp_fake.status_code == 200
    assert "If an active account matches" in resp_fake.data.decode()


def test_password_reset_success_and_session_invalidation(app, client):
    """
    Completing password reset updates hash, invalidates the token,
    and increments session_version (revoking all sessions).
    """
    user = User.query.filter_by(username="test_nurse").first()
    initial_version = user.session_version
    raw_token = AuthService.create_password_reset_token("test_nurse")

    # Reset password with valid new password satisfying complexity
    resp = client.post(f"/reset-password/{raw_token}", data={
        "password": "NewNursePass#2026"
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert "Password has been successfully updated" in resp.data.decode()

    updated_user = User.query.filter_by(username="test_nurse").first()
    # Password hash changed
    assert AuthService.verify_password(updated_user.password_hash, "NewNursePass#2026") is True
    # Old password no longer works
    assert AuthService.verify_password(updated_user.password_hash, "NursePass#123") is False
    # Session version incremented
    assert updated_user.session_version == initial_version + 1


def test_password_reset_token_single_use(app, client):
    """Reset token cannot be reused after initial completion."""
    raw_token = AuthService.create_password_reset_token("test_doctor")

    # First reset succeeds
    resp1 = client.post(f"/reset-password/{raw_token}", data={"password": "FirstNewPass#123"}, follow_redirects=True)
    assert "Password has been successfully updated" in resp1.data.decode()

    # Re-using the same token fails
    resp2 = client.post(f"/reset-password/{raw_token}", data={"password": "SecondNewPass#123"}, follow_redirects=True)
    assert "invalid or has expired" in resp2.data.decode()


def test_password_reset_token_expiry(app):
    """Expired reset token is rejected."""
    raw_token = AuthService.create_password_reset_token("test_doctor")
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()

    # Manually backdate expiration to 1 hour ago
    record.expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1)
    db.session.commit()

    success, msg = AuthService.verify_and_use_password_reset_token(raw_token, "ValidPass#123")
    assert success is False
    assert "expired" in msg.lower()


def test_password_reset_enforces_complexity(app, client):
    """Resetting password with weak password fails with complexity error."""
    raw_token = AuthService.create_password_reset_token("test_doctor")

    resp = client.post(f"/reset-password/{raw_token}", data={"password": "weak"}, follow_redirects=True)
    assert resp.status_code == 400
    assert "at least 8 characters" in resp.data.decode()
