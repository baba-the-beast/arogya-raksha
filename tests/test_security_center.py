"""Security Center authorization, tenant isolation, and operational posture tests."""
from app.extensions import db
from app.models.outbox import OutboxEvent
from app.models.tenant import Tenant
from app.models.user import User
from app.services.auth_service import AuthService
from app.services.outbox_service import OutboxService
from tests.conftest import login_client


def test_security_center_requires_audit_permission(client):
    login_client(client, "test_doctor", "DoctorPass#123")
    response = client.get("/admin/security")
    assert response.status_code == 403


def test_security_center_renders_authoritative_sections(client):
    login_client(client, "test_admin", "AdminPass#123")
    response = client.get("/admin/security")
    assert response.status_code == 200
    assert b"Security controls" in response.data
    assert b"MFA coverage" in response.data
    assert b"Alert delivery" in response.data
    assert b"Session policy" in response.data
    assert b"Audit integrity" in response.data


def test_security_center_isolates_events_and_outbox_by_tenant(client, app):
    with app.app_context():
        other = Tenant(id="tenant-other", name="Other Hospital", code="OTH-01", is_active=True)
        db.session.add(other)
        db.session.flush()
        other_admin = User(
            username="other_admin",
            password_hash=AuthService.hash_password("OtherAdmin#123"),
            role="Admin",
            is_active=True,
            tenant_id=other.id,
        )
        db.session.add(other_admin)
        db.session.commit()

        # A foreign-tenant queue failure must never change this tenant's visible queue health.
        db.session.add(OutboxEvent(
            tenant_id=other.id,
            event_type="SECURITY_ALERT",
            payload_json="{}",
            status="DEAD_LETTER",
            retry_count=5,
            max_retries=5,
        ))
        db.session.commit()

    login_client(client, "test_admin", "AdminPass#123")
    response = client.get("/admin/security")
    assert response.status_code == 200
    assert b"0 dead-letter" in response.data
    assert b"Other Hospital" not in response.data


def test_outbox_uses_authenticated_tenant_context(client, app):
    with app.app_context():
        other = Tenant(id="tenant-context", name="Context Hospital", code="CTX-01", is_active=True)
        db.session.add(other)
        user = User(
            username="context_admin",
            password_hash=AuthService.hash_password("ContextAdmin#123"),
            role="Admin",
            is_active=True,
            tenant_id=other.id,
        )
        db.session.add(user)
        db.session.commit()

    login_client(client, "context_admin", "ContextAdmin#123")
    with client.application.test_request_context("/"):
        # This direct service assertion uses an explicit server-trusted context because the
        # production callers pass through an authenticated request/session.
        from flask import session
        session["tenant_id"] = "tenant-context"
        event = OutboxService.record_event("SECURITY_ALERT", {"message": "test"})
        assert event.tenant_id == "tenant-context"
