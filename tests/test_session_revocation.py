"""
Phase 4 — Server-Side Session Revocation Tests.

Covers:
- Active session validity under matching session_version
- Immediate revocation across all devices when UserService.revoke_all_sessions() is called
- Automatic session revocation when an administrator disables an account
- Immediate access rejection on protected routes after revocation
"""
import pytest

from app.extensions import db
from app.models.user import User
from app.services.user_service import UserService
from tests.conftest import login_client


def test_session_validity_with_current_version(client):
    """Authenticated user with matching session_version accesses protected endpoints."""
    login_client(client, "test_doctor", "DoctorPass#123")
    resp = client.get("/patients")
    assert resp.status_code == 200


def test_revoke_all_sessions_invalidates_active_session(client, app):
    """
    Incrementing user.session_version causes get_current_user() to return None
    and clears the session cookie on the next request.
    """
    login_client(client, "test_doctor", "DoctorPass#123")

    # Confirm session is currently active
    resp1 = client.get("/patients")
    assert resp1.status_code == 200

    # Administrator or system revokes all sessions
    doc = User.query.filter_by(username="test_doctor").first()
    UserService.revoke_all_sessions(doc.id)

    # Next request with the old session cookie must be rejected (redirected to /login)
    resp2 = client.get("/patients", follow_redirects=False)
    assert resp2.status_code == 302
    assert resp2.location.endswith("/login?next=%2Fpatients") or "/login" in resp2.location

    # Verify session was wiped
    with client.session_transaction() as sess:
        assert sess.get("user_id") is None


def test_disabling_user_triggers_immediate_session_revocation(client, app):
    """When an administrator disables an account, all existing active sessions are terminated immediately."""
    login_client(client, "test_nurse", "NursePass#123")

    # Confirm nurse session works
    resp1 = client.get("/patients")
    assert resp1.status_code == 200

    # Admin disables the nurse account
    admin = User.query.filter_by(username="test_admin").first()
    nurse = User.query.filter_by(username="test_nurse").first()
    UserService.toggle_user_active(nurse.id, admin.id)

    # Nurse's active session is now rejected
    resp2 = client.get("/patients", follow_redirects=False)
    assert resp2.status_code == 302
    assert "/login" in resp2.location
