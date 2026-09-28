"""
Automated unit tests for Patient Record Management and Encrypted Storage (FR3, FR4, FR7, NFR1, NFR2).
"""
from app.models.audit_log import AuditLog
from app.models.patient import Patient
from app.services.patient_service import PatientService
from tests.conftest import login_client


def test_patient_encryption_at_rest(client):
    """Verify sensitive fields are strictly encrypted at rest in the database (never stored plaintext)."""
    login_client(client, "test_doctor", "DoctorPass#123")

    response = client.post("/patients/new", data={
        "patient_id": "P-REST-999",
        "age_band": "50-59",
        "gender": "Male",
        "name": "Classified Patient Name",
        "diagnosis": "Top Secret Health Condition",
        "medical_history": "Confidential history details",
        "notes": "Doctor strictly private notes"
    }, follow_redirects=True)

    assert response.status_code == 200

    # Query SQLite database directly via SQLAlchemy
    with client.application.app_context():
        p = Patient.query.filter_by(patient_id="P-REST-999").first()
        assert p is not None

        # Verify plaintext does NOT exist in any model column or DB row
        assert "Classified Patient Name" not in p.encrypted_data
        assert "Top Secret Health Condition" not in p.encrypted_data
        assert "Confidential history details" not in p.encrypted_data

        # Verify ciphertext, nonce, and auth tag are populated
        assert len(p.encrypted_data) > 0
        assert len(p.nonce) == 24  # 12 bytes hex
        assert len(p.auth_tag) == 32  # 16 bytes hex

def test_patient_detail_decryption(client):
    """Verify authorized Doctor can view decrypted patient record."""
    login_client(client, "test_doctor", "DoctorPass#123")
    response = client.get("/patients/1")

    assert response.status_code == 200
    assert b"Alice Smith" in response.data
    assert b"Seasonal Allergies" in response.data

def test_patient_tamper_detection_in_route(client):
    """Verify that tampered database ciphertext causes 400 error, displays tamper warning, and logs TAMPER_DETECTED."""
    # Deliberately tamper with patient 1's ciphertext
    with client.application.app_context():
        PatientService.tamper_record_ciphertext(1)

    login_client(client, "test_doctor", "DoctorPass#123")
    response = client.get("/patients/1")

    # Hard fail: status code 400 and clear tamper alert
    assert response.status_code == 400
    assert b"failed its integrity check" in response.data
    assert b"Alice Smith" not in response.data  # No corrupted or fabricated data displayed!

    # Verify audit log recorded TAMPER_DETECTED
    with client.application.app_context():
        log = AuditLog.query.filter_by(action="TAMPER_DETECTED").first()
        assert log is not None
        assert log.status == "ALERT"

def test_patient_update_route(client):
    """Verify Doctor can edit patient details via POST /patients/<id>/edit."""
    login_client(client, "test_doctor", "DoctorPass#123")
    response = client.post("/patients/1/edit", data={
        "age_band": "30-39",
        "gender": "Female",
        "name": "Alice Smith Updated",
        "diagnosis": "Seasonal Allergies and Mild Asthma",
        "medical_history": "Allergic to dust",
        "notes": "Inhaler added to regimen",
        "version_id": "1",
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Alice Smith Updated" in response.data
    assert b"Seasonal Allergies and Mild Asthma" in response.data

def test_patient_update_without_version_is_rejected(client):
    """An edit that does not carry the version it was rendered from must not silently overwrite."""
    login_client(client, "test_doctor", "DoctorPass#123")
    response = client.post("/patients/1/edit", data={
        "age_band": "30-39",
        "gender": "Female",
        "name": "Stale Overwrite",
        "diagnosis": "x",
        "medical_history": "x",
        "notes": "x",
    })
    assert response.status_code == 400
    assert b"missing its record version" in response.data

def test_patient_tamper_demo_route(client):
    """Verify Doctor can trigger viva tamper simulation endpoint."""
    login_client(client, "test_doctor", "DoctorPass#123")
    # Simulate bit flip in ciphertext
    resp = client.post("/patients/1/tamper-demo", data={"tamper_type": "ciphertext"}, follow_redirects=True)
    # The subsequent redirect to detail should now fail with 400 because of tamper detection
    assert resp.status_code == 400
    assert b"failed its integrity check" in resp.data

def test_dashboard_route(client):
    """Verify dashboard redirects to login when unauthenticated, and displays metrics when logged in."""
    assert client.get("/dashboard").status_code == 302
    login_client(client, "test_doctor", "DoctorPass#123")
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert b"Welcome back" in resp.data
    assert b"Your patients" in resp.data

def test_patient_input_bounds_and_format_validation(client):
    """Verify max-length and format bounds are strictly validated on patient intake (BUG-03)."""
    import pytest
    login_client(client, "test_doctor", "DoctorPass#123")

    # 1. Service layer direct validation
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        PatientService.create_patient(
            patient_id="P-OVERSIZE-1",
            age_band="20-29",
            gender="Male",
            name="Valid Name",
            diagnosis="A" * (10 * 1024 + 1),  # Over 10KB
            medical_history="Normal",
            notes="Normal"
        )

    with pytest.raises(ValueError, match="exceeds maximum allowed length"):
        PatientService.create_patient(
            patient_id="P-OVERSIZE-2",
            age_band="20-29",
            gender="Male",
            name="N" * 129,  # Over 128 chars
            diagnosis="Normal",
            medical_history="Normal",
            notes="Normal"
        )

    with pytest.raises(ValueError, match="alphanumeric"):
        PatientService.create_patient(
            patient_id="P-INVALID/ID$",  # Malformed special characters
            age_band="20-29",
            gender="Male",
            name="Valid Name",
            diagnosis="Normal",
            medical_history="Normal",
            notes="Normal"
        )

    with pytest.raises(ValueError, match="exceeds maximum allowed length of 64"):
        PatientService.create_patient(
            patient_id="P-" + "X" * 65,  # Over 64 chars
            age_band="20-29",
            gender="Male",
            name="Valid Name",
            diagnosis="Normal",
            medical_history="Normal",
            notes="Normal"
        )

    # 2. Route layer handles ValueError with 400 Bad Request
    resp_oversize = client.post("/patients/new", data={
        "patient_id": "P-ROUTE-OVERSIZE",
        "age_band": "20-29",
        "gender": "Male",
        "name": "N" * 200,
        "diagnosis": "Normal",
        "medical_history": "Normal",
        "notes": "Normal"
    })
    assert resp_oversize.status_code == 400
    assert b"exceeds maximum allowed length" in resp_oversize.data

    resp_malformed = client.post("/patients/new", data={
        "patient_id": "P-MALFORMED*ID!",
        "age_band": "20-29",
        "gender": "Male",
        "name": "Normal Name",
        "diagnosis": "Normal",
        "medical_history": "Normal",
        "notes": "Normal"
    })
    assert resp_malformed.status_code == 400
    assert b"alphanumeric" in resp_malformed.data

