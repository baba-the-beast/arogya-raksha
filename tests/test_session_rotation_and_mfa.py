"""
Security Tests for Server-Side Session Management, Session Fixation Defenses,
Timeout Policies, and MFA Verification Rate Limiting.
"""
import time

from app.security.session_store import (
    MemorySessionStore,
    ServerSessionData,
    ServerSideSession,
    get_session_store,
    set_session_store,
)


def test_session_regeneration_rotates_sid_and_purges_old_store_entry(app):
    """
    Test that session.regenerate() creates a fresh SID and explicitly purges
    the old session ID from the session store to prevent session fixation.
    """
    with app.test_request_context():
        store = MemorySessionStore()
        set_session_store(store)

        old_sid = "initial-fixation-probe-sid-1111"
        data = ServerSessionData(
            session_id=old_sid,
            user_id=42,
            username="dr_alice",
            auth_state="PASSWORD_AUTHENTICATED",
        )
        store.save(data)

        # Initialize ServerSideSession
        sess = ServerSideSession(
            initial={"user_id": 42, "username": "dr_alice", "_sid": old_sid},
            sid=old_sid,
            server_data=data,
        )

        assert store.get(old_sid) is not None

        # Regenerate session
        new_sid = sess.regenerate()

        # Old SID must be purged from store
        assert new_sid != old_sid
        assert store.get(old_sid) is None

        # New SID must exist in store and retain migrated data
        new_data = store.get(new_sid)
        assert new_data is not None
        assert new_data.user_id == 42
        assert new_data.username == "dr_alice"
        assert sess.sid == new_sid
        assert sess["_sid"] == new_sid
        assert sess.modified is True


def test_session_idle_and_absolute_timeouts(app):
    """
    Test that ServerSessionData.is_expired() accurately evaluates idle and absolute timeouts.
    """
    with app.app_context():
        now = time.time()
        # Active session: created 100s ago, active 10s ago -> not expired
        active_sess = ServerSessionData(
            session_id="active-sess",
            created_at=now - 100,
            last_active_at=now - 10,
        )
        assert active_sess.is_expired(idle_seconds=900, absolute_seconds=28800) is False

        # Idle timeout expired: last active 901s ago (> 900s)
        idle_sess = ServerSessionData(
            session_id="idle-sess",
            created_at=now - 1000,
            last_active_at=now - 901,
        )
        assert idle_sess.is_expired(idle_seconds=900, absolute_seconds=28800) is True

        # Absolute timeout expired: created 28801s ago (> 8h), even if recently active
        abs_sess = ServerSessionData(
            session_id="abs-sess",
            created_at=now - 28801,
            last_active_at=now - 5,
        )
        assert abs_sess.is_expired(idle_seconds=900, absolute_seconds=28800) is True


def test_mfa_verify_rate_limiting():
    """
    Test that POST /login/mfa enforces rate limiting (5 per minute) to prevent brute-force attacks.
    """
    from app import create_app
    from app.config import TestConfig
    from app.extensions import db
    from app.models.tenant import Tenant
    from app.models.user import User
    from app.services.auth_service import AuthService

    class MfaRateLimitConfig(TestConfig):
        TESTING = True
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = True
        RATELIMIT_STORAGE_URI = "memory://"
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    rate_app = create_app(MfaRateLimitConfig)
    with rate_app.app_context():
        db.create_all()
        db.session.add(Tenant(id="tenant-default", name="Default Clinic", code="DEF-01"))
        user = User(
            username="mfa_test_user",
            password_hash=AuthService.hash_password("ValidPassword#1234"),
            role="Doctor",
            tenant_id="tenant-default",
            is_active=True,
            totp_enabled=True,
        )
        user.totp_secret = "JBSWY3DPEHPK3PXP"
        db.session.add(user)
        db.session.commit()
        user_id = user.id

        client = rate_app.test_client()

        # Set up session in MFA_PENDING state
        with client.session_transaction() as sess:
            sess["_mfa_user_id"] = user_id
            sess["_auth_state"] = "MFA_PENDING"

        # Send 5 attempts (should get 200 or 302, invalid code flash)
        for _ in range(5):
            resp = client.post(
                "/login/mfa",
                data={"totp_code": "000000"},
                follow_redirects=True,
            )
            assert resp.status_code == 200

        # 6th attempt should be blocked with 429 Too Many Requests
        resp_rate_limited = client.post(
            "/login/mfa",
            data={"totp_code": "000000"},
        )
        assert resp_rate_limited.status_code == 429
