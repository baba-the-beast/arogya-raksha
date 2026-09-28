"""
Phase 5 — Patient Record Soft-Delete & RBAC Gating Tests.

Covers:
- Soft-delete exclusion from listing and detail lookup
- Preservation of ciphertext at rest for compliance/audit
- RBAC gating: Doctor only (Nurse & Admin blocked with 403)
- Audit log entry creation (PATIENT_DELETE)
"""
import pytest

from app.extensions import db
from app.models.audit_log import AuditLog
from app.models.patient import Patient
from app.services.patient_service import PatientService
from tests.conftest import login_client


def test_soft_delete_excludes_patient_from_active_views(client):
    """Soft-deleted patients do not appear in registry listing or detail lookups."""
    # Seed a specific patient
    patient = PatientService.create_patient(
        patient_id="P-DEL-001",
        age_band="50-59",
        gender="Male",
        name="Delete Me",
        diagnosis="Temporary",
        medical_history="None",
        notes="To be archived",
    )
    record_id = patient.id

    # Verify visible initially
    assert PatientService.get_patient_by_id(record_id, tenant_id="tenant-default") is not None
    active_ids = [p["id"] for p in PatientService.list_patients(per_page=100).items]
    assert record_id in active_ids

    # Soft-delete the patient
    PatientService.soft_delete_patient(record_id, user_id=1, tenant_id="tenant-default")

    # Record is now excluded from clinical operations
    assert PatientService.get_patient_by_id(record_id, tenant_id="tenant-default") is None
    active_ids_after = [p["id"] for p in PatientService.list_patients(per_page=100).items]
    assert record_id not in active_ids_after

    # Record still exists in database with deleted_at set (audit preservation)
    raw_record = db.session.get(Patient, record_id)
    assert raw_record is not None
    assert raw_record.deleted_at is not None
    assert len(raw_record.encrypted_data) > 0


def test_soft_delete_rbac_enforcement(client):
    """
    POST /patients/<id>/delete is permitted for Doctor,
    and strictly blocked (HTTP 403) for Nurse and Admin.
    """
    # Create target record
    p = PatientService.create_patient(
        patient_id="P-RBAC-DEL",
        age_band="30-39",
        gender="Female",
        name="RBAC Subject",
        diagnosis="Active",
        medical_history="None",
        notes="RBAC delete test",
    )

    # 1. Nurse attempts delete -> 403 Forbidden
    login_client(client, "test_nurse", "NursePass#123")
    resp_nurse = client.post(f"/patients/{p.id}/delete")
    assert resp_nurse.status_code == 403

    # 2. Admin attempts delete -> 403 Forbidden
    login_client(client, "test_admin", "AdminPass#123")
    resp_admin = client.post(f"/patients/{p.id}/delete")
    assert resp_admin.status_code == 403

    # 3. Doctor attempts delete -> 302 Success
    login_client(client, "test_doctor", "DoctorPass#123")
    resp_doctor = client.post(f"/patients/{p.id}/delete", follow_redirects=True)
    assert resp_doctor.status_code == 200
    assert "archived" in resp_doctor.data.decode().lower()

    # Verify deleted_at is set
    assert PatientService.get_patient_by_id(p.id, tenant_id="tenant-default") is None


def test_cannot_edit_or_delete_already_deleted_patient(app):
    """Attempting to update or re-delete an already soft-deleted patient raises ValueError."""
    p = PatientService.create_patient(
        patient_id="P-ALREADY-DEL",
        age_band="20-29",
        gender="Other",
        name="Subject",
        diagnosis="Condition",
        medical_history="None",
        notes="Notes",
    )
    PatientService.soft_delete_patient(p.id, tenant_id="tenant-default")

    with pytest.raises(ValueError) as exc1:
        PatientService.soft_delete_patient(p.id, tenant_id="tenant-default")
    assert "not found" in str(exc1.value).lower()

    with pytest.raises(ValueError) as exc2:
        PatientService.update_patient(
            record_id=p.id,
            age_band="20-29",
            gender="Other",
            name="New Name",
            diagnosis="New Diag",
            medical_history="New Hist",
            notes="New Note",
            tenant_id="tenant-default"
        )
    assert "not found" in str(exc2.value).lower()


def test_soft_delete_audit_event_logged(app):
    """PATIENT_DELETE audit event is recorded when patient is soft-deleted."""
    p = PatientService.create_patient(
        patient_id="P-AUDIT-DEL",
        age_band="40-49",
        gender="Male",
        name="Audited",
        diagnosis="Normal",
        medical_history="None",
        notes="Audit check",
    )
    PatientService.soft_delete_patient(p.id, user_id=42, tenant_id="tenant-default")

    log = AuditLog.query.filter_by(action="PATIENT_DELETE", resource_id=p.patient_id).first()
    assert log is not None
    assert log.status == "SUCCESS"
    assert log.user_id == 42
