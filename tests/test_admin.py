"""
Automated unit tests for Administrative Controls and Account Lifecycle (FR8, FR9).
"""
from app.models.user import User
from tests.conftest import login_client


def test_admin_create_user(client):
    """Admin creates a new user account with role and scrypt password hash."""
    login_client(client, "test_admin", "AdminPass#123")

    response = client.post("/admin/users", data={
        "username": "new_specialist",
        "password": "SpecialistPass#2026",
        "role": "Doctor"
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"new_specialist" in response.data

    with client.application.app_context():
        u = User.query.filter_by(username="new_specialist").first()
        assert u is not None
        assert u.role == "Doctor"
        assert u.password_hash.startswith("scrypt:")

def test_admin_toggle_user_active(client):
    """Admin disables an active user account, revoking login."""
    login_client(client, "test_admin", "AdminPass#123")

    # Disable test_doctor (id=1)
    response = client.post("/admin/users/1/toggle", follow_redirects=True)
    assert response.status_code == 200
    assert b"has been disabled" in response.data

    # Verify doctor can no longer log in
    client.post("/logout")
    login_resp = client.post("/login", data={
        "username": "test_doctor",
        "password": "DoctorPass#123"
    })
    assert login_resp.status_code == 401
    assert b"Account has been disabled" in login_resp.data

def test_admin_cannot_disable_self(client):
    """Admin is prevented from disabling their own account to avoid lockout."""
    login_client(client, "test_admin", "AdminPass#123")

    with client.application.app_context():
        admin_user = User.query.filter_by(username="test_admin").first()
        admin_id = admin_user.id

    response = client.post(f"/admin/users/{admin_id}/toggle", follow_redirects=True)
    assert b"Administrators cannot disable their own account" in response.data

    with client.application.app_context():
        from app.extensions import db
        admin_user = db.session.get(User, admin_id)
        assert admin_user.is_active is True
