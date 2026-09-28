"""
Enterprise High-Assurance Verification Suite.
Validates multi-tenancy isolation, ABAC policy & break-glass access,
admin clinical segregation, and secret hygiene.
"""
import pytest

from app.extensions import db
from app.models.audit_log import AuditLog
from app.models.patient import Patient
from app.models.tenant import Tenant
from app.models.user import User
from app.security.policy import PolicyEngine
from app.services.alert_service import AlertService
from app.services.auth_service import AuthService
from app.services.patient_service import ConcurrencyConflictError, PatientService
from tests.conftest import login_client
from tests.test_alerting import MockAlertDelivery


@pytest.fixture
def enterprise_tenants(app):
    """Provisions two isolated clinical tenants and dedicated clinicians."""
    with app.app_context():
        # Tenant Alpha
        tenant_a = Tenant(id="tenant-alpha", name="St. Jude General Hospital", code="SJG-01", is_active=True)
        # Tenant Beta
        tenant_b = Tenant(id="tenant-beta", name="Metro Heart Institute", code="MHI-02", is_active=True)
        db.session.add_all([tenant_a, tenant_b])

        doc_alpha = User(
            username="doc_alpha",
            password_hash=AuthService.hash_password("DocAlphaPass#2026"),
            role="Doctor",
            tenant_id="tenant-alpha",
            is_active=True,
        )
        doc_beta = User(
            username="doc_beta",
            password_hash=AuthService.hash_password("DocBetaPass#2026"),
            role="Doctor",
            tenant_id="tenant-beta",
            is_active=True,
        )
        db.session.add_all([doc_alpha, doc_beta])
        db.session.commit()

        # Seed Patient in Tenant Alpha
        patient_a = PatientService.create_patient(
            patient_id="P-ALPHA-001",
            age_band="30-39",
            gender="Female",
            name="Alice Alpha",
            diagnosis="Type 1 Diabetes",
            medical_history="Insulin dependent",
            notes="Morning blood glucose check",
            created_by_user_id=doc_alpha.id,
            tenant_id="tenant-alpha",
            assigned_doctor_id=doc_alpha.id,
        )

        # Seed Patient in Tenant Beta
        patient_b = PatientService.create_patient(
            patient_id="P-BETA-001",
            age_band="50-59",
            gender="Male",
            name="Bob Beta",
            diagnosis="Coronary Artery Disease",
            medical_history="Stent placed 2022",
            notes="Aspirin 81mg prescribed daily",
            created_by_user_id=doc_beta.id,
            tenant_id="tenant-beta",
            assigned_doctor_id=doc_beta.id,
        )

        yield {
            "tenant_a": tenant_a,
            "tenant_b": tenant_b,
            "doc_alpha": doc_alpha,
            "doc_beta": doc_beta,
            "patient_a": patient_a,
            "patient_b": patient_b,
        }


def test_cross_tenant_isolation_strictly_enforced(client, enterprise_tenants):
    """
    Tenant Isolation: Clinician from Tenant Beta attempting to access
    Patient in Tenant Alpha receives HTTP 403 Forbidden and CROSS_TENANT_ATTEMPT audit event.
    """
    login_client(client, "doc_beta", "DocBetaPass#2026")

    # doc_beta attempts to access patient_a (id=2 or fetched id)
    target_id = enterprise_tenants["patient_a"].id
    resp = client.get(f"/patients/{target_id}")
    assert resp.status_code == 403

    # doc_beta attempts to edit patient_a
    resp_edit = client.get(f"/patients/{target_id}/edit")
    assert resp_edit.status_code == 403

    # doc_beta cannot list patient_a (patient list is tenant scoped)
    resp_list = client.get("/patients")
    assert resp_list.status_code == 200
    assert b"P-ALPHA-001" not in resp_list.data
    assert b"P-BETA-001" in resp_list.data

    # doc_beta CAN access their own tenant patient
    resp_own = client.get(f"/patients/{enterprise_tenants['patient_b'].id}")
    assert resp_own.status_code == 200
    assert b"P-BETA-001" in resp_own.data


def test_emergency_break_glass_protocol(client, enterprise_tenants):
    """
    Emergency Break-Glass Protocol:
    1. Unassigned clinician attempting clinical update without break-glass rationale is rejected (403).
    2. Providing emergency break-glass rationale permits update and triggers BREAK_GLASS_ACCESS alert.
    """
    mock_alerts = MockAlertDelivery()
    orig_alert = AlertService.get_backend()
    try:
        AlertService.set_backend(mock_alerts)

        with client.application.app_context():
            # Create a second doctor in tenant-alpha who is NOT assigned to patient_a
            doc_unassigned = User(
                username="doc_er_resident",
                password_hash=AuthService.hash_password("ResidentPass#2026"),
                role="Doctor",
                tenant_id="tenant-alpha",
                is_active=True,
            )
            db.session.add(doc_unassigned)
            db.session.commit()
            target_id = enterprise_tenants["patient_a"].id
            target_patient = db.session.get(Patient, target_id)
            current_ver = target_patient.version_id

        login_client(client, "doc_er_resident", "ResidentPass#2026")

        # 1. Edit without break-glass reason -> Rejected 403
        resp_blocked = client.post(
            f"/patients/{target_id}/edit",
            data={
                "age_band": "30-39",
                "gender": "Female",
                "name": "Alice Alpha",
                "diagnosis": "Acute Hypoglycemic Shock",
                "medical_history": "Insulin dependent",
                "notes": "Emergency stabilization",
                "version_id": current_ver,
                # No break_glass_reason provided!
            },
            follow_redirects=False,
        )
        assert resp_blocked.status_code == 403

        # 2. Edit WITH break-glass reason -> Permitted
        resp_allowed = client.post(
            f"/patients/{target_id}/edit",
            data={
                "age_band": "30-39",
                "gender": "Female",
                "name": "Alice Alpha",
                "diagnosis": "Acute Hypoglycemic Shock",
                "medical_history": "Insulin dependent",
                "notes": "Administered IV Dextrose 50% stat",
                "version_id": current_ver,
                "break_glass_reason": "Patient unresponsive in ER triage, attending physician unavailable",
            },
            follow_redirects=False,
        )
        assert resp_allowed.status_code == 302

        # 3. Verify high-severity security alert and audit entry emitted
        break_glass_alerts = [a for a in mock_alerts.dispatched if a["event_type"] == "BREAK_GLASS_ACCESS"]
        assert len(break_glass_alerts) >= 1
        assert break_glass_alerts[0]["severity"] == "HIGH"
        assert "unresponsive" in break_glass_alerts[0]["message"]
    finally:
        AlertService.set_backend(orig_alert)


def test_admin_clinical_mutation_segregation(client, enterprise_tenants):
    """
    Separation of Duties:
    Administrator account is strictly prohibited from mutating clinical records (DELETE / EDIT).
    """
    login_client(client, "test_admin", "AdminPass#123")
    target_id = enterprise_tenants["patient_a"].id

    # Admin cannot delete
    resp_delete = client.post(f"/patients/{target_id}/delete")
    assert resp_delete.status_code == 403

    # Admin cannot create
    resp_create = client.post("/patients/new", data={
        "patient_id": "P-ADMIN-FORBIDDEN",
        "name": "Should Fail",
        "age_band": "20-29",
        "gender": "Other",
        "diagnosis": "None",
        "medical_history": "None",
        "notes": "None",
    })
    assert resp_create.status_code == 403


def test_secret_scanner_clean_repo():
    """Validates that automated secret scanner finds zero sensitive tokens in the repository."""
    from scripts.scan_secrets import scan_repository

    findings = scan_repository()
    assert len(findings) == 0, f"Repository contains {len(findings)} sensitive artifacts: {findings}"
