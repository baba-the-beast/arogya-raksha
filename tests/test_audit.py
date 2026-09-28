"""
Automated unit tests for Tamper-Evident Audit Logging and Hash Chaining (FR5, FR9, NFR4, §7.1).
"""
from app.extensions import db
from app.models.audit_log import AuditLog
from app.services.audit_service import AuditService
from tests.conftest import login_client


def test_audit_log_records_events(client):
    """Verify security actions append entries to the audit trail."""
    with client.application.app_context():
        initial_count = AuditLog.query.count()

    # Perform actions
    login_client(client, "test_doctor", "DoctorPass#123")
    client.get("/patients/1")

    with client.application.app_context():
        new_count = AuditLog.query.count()
        assert new_count > initial_count

        read_log = AuditLog.query.filter_by(action="PATIENT_READ").first()
        assert read_log is not None
        assert read_log.resource_id == "P-TEST-001"

def test_no_phi_in_audit_log(client):
    """Verify patient sensitive notes, medical histories, or passwords never leak into audit logs (NFR1)."""
    login_client(client, "test_doctor", "DoctorPass#123")
    client.post("/patients/new", data={
        "patient_id": "P-PHI-CHECK",
        "age_band": "20-29",
        "gender": "Female",
        "name": "SuperSecretPatientName",
        "diagnosis": "ConfidentialPsychologicalAssessment",
        "medical_history": "HighlyConfidentialMedicalRecordHistory",
        "notes": "SecretNotesNeverToAppearInLogs"
    })

    with client.application.app_context():
        logs = AuditLog.query.all()
        for log in logs:
            combined = f"{log.action} {log.details or ''} {log.resource_id or ''}"
            assert "SuperSecretPatientName" not in combined
            assert "ConfidentialPsychologicalAssessment" not in combined
            assert "SecretNotesNeverToAppearInLogs" not in combined

def test_audit_hash_chain_verification_intact(client):
    """Verify cryptographic hash chain passes verification when untampered."""
    with client.application.app_context():
        is_valid, corrupted_id, total, errors = AuditService.verify_chain()
        assert is_valid is True
        assert corrupted_id is None
        assert total > 0
        assert len(errors) == 0

def test_audit_hash_chain_tamper_detection(client):
    """Verify that an unauthorized modification to an audit log row breaks the hash chain (Tamper Detection)."""
    with client.application.app_context():
        # Insert a couple of audit entries
        AuditService.log_event(action="TEST_ACTION_1", status="SUCCESS")
        entry2 = AuditService.log_event(action="TEST_ACTION_2", status="SUCCESS")

        # Simulate direct DB attacker tampering with entry2 details
        entry2.details = "ATTACKER_ALTERED_AUDIT_DETAILS"
        db.session.commit()

        # Run hash chain verification
        is_valid, corrupted_id, total, errors = AuditService.verify_chain()

        assert is_valid is False
        assert corrupted_id == entry2.id
        assert len(errors) > 0
        assert f"Data tamper at record #{entry2.id}" in errors[0]

def test_client_ip_spoofing_defense(client):
    """Verify spoofed X-Forwarded-For headers from untrusted peers are ignored (BUG-01)."""
    # 1. Untrusted peer sends spoofed X-Forwarded-For
    with client.application.test_request_context(
        "/",
        environ_base={"REMOTE_ADDR": "192.168.1.50"},
        headers={"X-Forwarded-For": "203.0.113.195"}
    ):
        # Default TRUSTED_PROXY_IPS is empty -> must ignore XFF and use remote_addr
        ip = AuditService.get_client_ip()
        assert ip == "192.168.1.50"

    # 2. Configure trusted proxy allowlist
    client.application.config["TRUSTED_PROXY_IPS"] = ["10.0.0.1", "192.168.1.50"]
    try:
        # Trusted proxy peer forwards genuine client IP
        with client.application.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "192.168.1.50"},
            headers={"X-Forwarded-For": "203.0.113.195, 10.0.0.1"}
        ):
            ip = AuditService.get_client_ip()
            assert ip == "203.0.113.195"

        # Another untrusted peer still cannot spoof even when allowlist is active
        with client.application.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "172.16.0.99"},
            headers={"X-Forwarded-For": "203.0.113.195"}
        ):
            ip = AuditService.get_client_ip()
            assert ip == "172.16.0.99"
    finally:
        client.application.config["TRUSTED_PROXY_IPS"] = []

