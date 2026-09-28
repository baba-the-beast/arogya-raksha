"""
Automated unit tests for Authentication and Session Security (FR1, FR2, NFR3).
"""
import pytest
from flask import session

from app.models.audit_log import AuditLog
from app.services.auth_service import AuthService
from tests.conftest import login_client


def test_scrypt_password_hashing(app):
    """Verify password hashing uses scrypt and produces secure hashes."""
    password = "SuperSecretPassword#2026"
    pwd_hash = AuthService.hash_password(password)

    assert pwd_hash.startswith("scrypt:")
    assert AuthService.verify_password(pwd_hash, password) is True
    assert AuthService.verify_password(pwd_hash, "WrongPassword") is False

def test_login_success(client):
    """Test valid credentials create authenticated session and log LOGIN_SUCCESS."""
    response = client.post("/login", data={
        "username": "test_doctor",
        "password": "DoctorPass#123"
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Signed in as Doctor" in response.data

    # Verify audit log
    with client.application.app_context():
        log = AuditLog.query.filter_by(action="LOGIN_SUCCESS").order_by(AuditLog.id.desc()).first()
        assert log is not None
        assert log.username == "test_doctor"
        assert log.status == "SUCCESS"

def test_login_failure_wrong_password(client):
    """Test wrong password returns 401 and logs LOGIN_FAILURE."""
    response = client.post("/login", data={
        "username": "test_doctor",
        "password": "WrongPassword#999"
    })

    assert response.status_code == 401
    assert b"Invalid username or password" in response.data

    with client.application.app_context():
        log = AuditLog.query.filter_by(action="LOGIN_FAILURE").order_by(AuditLog.id.desc()).first()
        assert log is not None
        assert log.username == "test_doctor"
        assert log.status == "FAILURE"

def test_login_disabled_account(client):
    """Test that disabled user cannot log in (returns 401)."""
    response = client.post("/login", data={
        "username": "disabled_doc",
        "password": "DocDisabled#123"
    })

    assert response.status_code == 401
    assert b"Account has been disabled" in response.data

    with client.application.app_context():
        log = AuditLog.query.filter_by(action="LOGIN_FAILURE", status="DENIED").first()
        assert log is not None
        assert log.username == "disabled_doc"

def test_session_fixation_defense(client):
    """Test that session is regenerated and old session keys are cleared upon login."""
    with client.session_transaction() as sess:
        sess["pre_login_token"] = "attacker_controlled_value"

    client.post("/login", data={
        "username": "test_doctor",
        "password": "DoctorPass#123"
    })

    with client.session_transaction() as sess:
        assert "pre_login_token" not in sess
        assert sess.get("username") == "test_doctor"

def test_logout(client):
    """Test logout terminates session and logs LOGOUT."""
    login_client(client, "test_doctor", "DoctorPass#123")
    response = client.post("/logout", follow_redirects=True)

    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert "user_id" not in sess

    with client.application.app_context():
        log = AuditLog.query.filter_by(action="LOGOUT").first()
        assert log is not None
        assert log.username == "test_doctor"

def test_username_rate_limiting_account_lockout():
    """Verify username-keyed rate limiting locks out account even when source IP alternates (BUG-02)."""
    from app import create_app
    from app.config import TestConfig
    from app.extensions import db
    from app.models.user import User

    class LockoutTestConfig(TestConfig):
        TESTING = True
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = True
        RATELIMIT_USER_LOCKOUT = "5 per 15 minutes"
        RATELIMIT_STORAGE_URI = "memory://"
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    app = create_app(LockoutTestConfig)
    with app.app_context():
        db.create_all()
        # Create test user
        user = User(
            username="target_clinician",
            password_hash=AuthService.hash_password("DocSecurePass#2026"),
            role="Doctor",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()

        test_client = app.test_client()

        # Submit 5 failed attempts from 5 distinct source IPs
        for i in range(1, 6):
            resp = test_client.post(
                "/login",
                data={"username": "target_clinician", "password": "WrongPassword#999"},
                environ_base={"REMOTE_ADDR": f"198.51.100.{i}"}
            )
            assert resp.status_code == 401

        # 6th attempt from a fresh 6th source IP must be blocked by username lockout
        resp_blocked = test_client.post(
            "/login",
            data={"username": "target_clinician", "password": "WrongPassword#999"},
            environ_base={"REMOTE_ADDR": "198.51.100.99"}
        )
        assert resp_blocked.status_code == 429
        assert b"Account Locked" in resp_blocked.data or b"temporarily locked" in resp_blocked.data

        # Verify audit log recorded ACCOUNT_LOCKOUT
        lockout_log = AuditLog.query.filter_by(
            action="ACCOUNT_LOCKOUT",
            username="target_clinician"
        ).first()
        assert lockout_log is not None
        assert lockout_log.status == "BLOCKED"
        assert lockout_log.resource_type == "USER"


def test_password_complexity_and_length_validation(app):
    """
    Verify password policy enforcement (BUG-08):
    - Minimum length (config PASSWORD_MIN_LENGTH, default 8)
    - Maximum length (128 characters to mitigate scrypt DoS)
    - Uppercase letter requirement
    - Lowercase letter requirement
    - Digit requirement
    """
    # Missing uppercase
    with pytest.raises(ValueError, match="uppercase"):
        AuthService.hash_password("lowercase123!")

    # Missing lowercase
    with pytest.raises(ValueError, match="lowercase"):
        AuthService.hash_password("UPPERCASE123!")

    # Missing digit
    with pytest.raises(ValueError, match="digit"):
        AuthService.hash_password("NoDigitsAllowed!")

    # Under minimum length (7 chars)
    with pytest.raises(ValueError, match="at least 8"):
        AuthService.hash_password("Short1!")

    # Over maximum length (> 128 chars)
    too_long = "Pass1" + ("x" * 125)  # 130 characters
    with pytest.raises(ValueError, match="cannot exceed 128"):
        AuthService.hash_password(too_long)

    # Valid boundary password: exactly 8 chars
    hash_8 = AuthService.hash_password("Abcde123")
    assert hash_8.startswith("scrypt:")

    # Valid boundary password: exactly 128 chars
    pass_128 = "A1" + ("b" * 126)
    assert len(pass_128) == 128
    hash_128 = AuthService.hash_password(pass_128)
    assert hash_128.startswith("scrypt:")

