"""
Automated unit tests for Server-Side Role-Based Access Control (FR2, FR3, FR6, §5, §10).
Verifies direct URL access enforcement: a role attempting unauthorized actions must receive 403 Forbidden.
"""
from app.models.audit_log import AuditLog
from tests.conftest import login_client


def test_unauthenticated_access_denied(client):
    """Test unauthenticated requests are redirected or rejected with 401."""
    response = client.get("/patients")
    # Redirects to /login?next=...
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

def test_doctor_permissions(client):
    """Doctor can READ, CREATE, UPDATE patients, but cannot access ADMIN areas."""
    login_client(client, "test_doctor", "DoctorPass#123")

    # Allowed routes (200 OK)
    assert client.get("/patients").status_code == 200
    assert client.get("/patients/1").status_code == 200
    assert client.get("/patients/new").status_code == 200
    assert client.get("/patients/1/edit").status_code == 200

    # Forbidden routes (403 Forbidden + ACCESS_DENIED audit log)
    resp_users = client.get("/admin/users")
    assert resp_users.status_code == 403
    assert b"access to this page" in resp_users.data

    resp_audit = client.get("/admin/audit")
    assert resp_audit.status_code == 403

def test_nurse_permissions(client):
    """
    Nurse can READ and CREATE patients, but attempting to EDIT a record must yield 403 (FR3, §10).
    Nurse cannot access ADMIN areas.
    """
    login_client(client, "test_nurse", "NursePass#123")

    # Allowed routes
    assert client.get("/patients").status_code == 200
    assert client.get("/patients/1").status_code == 200
    assert client.get("/patients/new").status_code == 200

    # FORBIDDEN: Nurse attempts to access record editor (Section 10 requirement)
    resp_edit = client.get("/patients/1/edit")
    assert resp_edit.status_code == 403
    assert b"access to this page" in resp_edit.data

    # Verify ACCESS_DENIED logged in audit trail
    with client.application.app_context():
        log = AuditLog.query.filter_by(
            action="ACCESS_DENIED",
            username="test_nurse",
            resource_id="PATIENT_UPDATE"
        ).order_by(AuditLog.id.desc()).first()
        assert log is not None
        assert log.status == "DENIED"

    # Forbidden admin areas
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/audit").status_code == 403

def test_admin_permissions(client):
    """Admin can READ patients, MANAGE USERS, and READ AUDIT, but cannot edit clinical records."""
    login_client(client, "test_admin", "AdminPass#123")

    # Allowed routes
    assert client.get("/patients").status_code == 200
    assert client.get("/patients/1").status_code == 200
    assert client.get("/admin/users").status_code == 200
    assert client.get("/admin/audit").status_code == 200

    # Forbidden clinical modifications for Admin (clinical separation of duties)
    assert client.get("/patients/new").status_code == 403
    assert client.get("/patients/1/edit").status_code == 403
