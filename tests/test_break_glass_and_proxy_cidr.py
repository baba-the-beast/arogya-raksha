"""
Security Tests for Structured Break-Glass Emergency Overrides,
Proxy CIDR Subnet Allowlisting, and Audit Hash Chain Schema Evolution.
"""
from app.models.audit_log import AuditLog
from app.models.patient import Patient
from app.models.user import User
from app.security.policy import (
    AUTHORIZED_BREAK_GLASS_REASONS,
    PolicyEngine,
    validate_break_glass_reason,
)
from app.services.audit_service import AuditService


def test_validate_break_glass_reason_rules():
    """
    Test validation rules for authorized emergency break-glass reason codes
    and clinical justifications.
    """
    # 1. Standard authorized reason codes
    for code in AUTHORIZED_BREAK_GLASS_REASONS:
        valid, msg = validate_break_glass_reason(code)
        assert valid is True
        assert code in msg

    # Lowercase code matching
    valid, msg = validate_break_glass_reason("emergency_resuscitation")
    assert valid is True
    assert "EMERGENCY_RESUSCITATION" in msg

    # 2. Free-text justification >= 15 characters
    valid, msg = validate_break_glass_reason("Patient unresponsive in ER, attending physician unavailable")
    assert valid is True
    assert "Patient unresponsive" in msg

    # 3. Short justifications (< 15 characters)
    valid, msg = validate_break_glass_reason("emergency")
    assert valid is False
    assert "too short" in msg

    valid, msg = validate_break_glass_reason("need to see")
    assert valid is False
    assert "too short" in msg

    # 4. Empty or whitespace
    valid, msg = validate_break_glass_reason("")
    assert valid is False
    valid, msg = validate_break_glass_reason("   ")
    assert valid is False
    valid, msg = validate_break_glass_reason(None)
    assert valid is False


def test_policy_engine_break_glass_authorization(app):
    """
    Test PolicyEngine evaluation with valid and invalid break-glass justifications.
    """
    from app.extensions import db
    with app.app_context():
        doc_primary = User(username="dr_primary", role="Doctor", tenant_id="tenant-apollo", is_active=True)
        doc_covering = User(username="dr_covering", role="Doctor", tenant_id="tenant-apollo", is_active=True)
        doc_primary.id = 101
        doc_covering.id = 102

        patient = Patient(
            patient_id="PT-12345",
            tenant_id="tenant-apollo",
            assigned_doctor_id=doc_primary.id,
            created_by=doc_primary.id,
        )

        # 1. Update attempt without break-glass reason -> DENIED
        dec_no_reason = PolicyEngine.authorize_patient_access(
            user=doc_covering,
            patient=patient,
            action="UPDATE",
            break_glass_reason=None,
        )
        assert dec_no_reason.allowed is False
        assert "not assigned" in dec_no_reason.reason

        # 2. Update attempt with invalid short break-glass reason -> DENIED (and logged)
        dec_short = PolicyEngine.authorize_patient_access(
            user=doc_covering,
            patient=patient,
            action="UPDATE",
            break_glass_reason="too short",
        )
        assert dec_short.allowed is False
        assert "Break-glass rejected" in dec_short.reason

        # 3. Update attempt with authorized code -> ALLOWED (is_break_glass=True)
        dec_code = PolicyEngine.authorize_patient_access(
            user=doc_covering,
            patient=patient,
            action="UPDATE",
            break_glass_reason="TRAUMA_OVERRIDE",
        )
        assert dec_code.allowed is True
        assert dec_code.is_break_glass is True
        assert "TRAUMA_OVERRIDE" in dec_code.reason

        # 4. Update attempt with valid clinical free-text -> ALLOWED
        dec_text = PolicyEngine.authorize_patient_access(
            user=doc_covering,
            patient=patient,
            action="UPDATE",
            break_glass_reason="Acute cardiac arrest protocol initiated by covering physician",
        )
        assert dec_text.allowed is True
        assert dec_text.is_break_glass is True


def test_proxy_cidr_allowlist_matching(client):
    """
    Test that AuditService.get_client_ip() correctly matches CIDR subnet allowlists
    (e.g. 172.16.0.0/12, 10.0.0.0/8) and rejects untrusted IPs.
    """
    client.application.config["TRUSTED_PROXY_IPS"] = [
        "172.16.0.0/12",
        "10.0.0.0/8",
        "192.168.100.1",
    ]
    try:
        # IP in 172.16.0.0/12 (e.g., Docker container at 172.20.1.5)
        with client.application.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "172.20.1.5"},
            headers={"X-Forwarded-For": "203.0.113.88"},
        ):
            ip = AuditService.get_client_ip()
            assert ip == "203.0.113.88"

        # IP in 10.0.0.0/8 (e.g., K8s pod network at 10.244.2.15)
        with client.application.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "10.244.2.15"},
            headers={"X-Forwarded-For": "198.51.100.42, 10.244.0.1"},
        ):
            ip = AuditService.get_client_ip()
            assert ip == "198.51.100.42"

        # Exact match IP
        with client.application.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "192.168.100.1"},
            headers={"X-Forwarded-For": "198.51.100.99"},
        ):
            ip = AuditService.get_client_ip()
            assert ip == "198.51.100.99"

        # Untrusted peer not in any CIDR
        with client.application.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "192.168.1.55"},
            headers={"X-Forwarded-For": "203.0.113.88"},
        ):
            ip = AuditService.get_client_ip()
            assert ip == "192.168.1.55"  # Spoofed XFF ignored!
    finally:
        client.application.config["TRUSTED_PROXY_IPS"] = []


def _legacy_entry(prev_hash, action, schema):
    from datetime import UTC, datetime
    entry = AuditLog(
        user_id=1,
        username="admin",
        action=action,
        status="SUCCESS",
        prev_hash=prev_hash,
        record_hash="",
        tenant_id="tenant-default",
        timestamp=datetime.now(UTC).replace(tzinfo=None),
    )
    entry.record_hash = entry.calculate_hash_v1() if schema == 1 else entry.calculate_hash_v2()
    return entry


def test_audit_hash_chain_legacy_then_keyed(app):
    """
    Legacy unkeyed records (schema v1 / v2) written before the keyed upgrade still verify,
    and new records are sealed with the keyed HMAC schema v3.
    """
    from app.extensions import db
    from app.models.audit_log import GENESIS_HASH

    with app.app_context():
        AuditLog.query.delete()
        db.session.commit()
        AuditService.invalidate_verification_cache()

        e1 = _legacy_entry(GENESIS_HASH, "V2_LEGACY_TEST", schema=2)
        db.session.add(e1)
        db.session.commit()
        e2 = _legacy_entry(e1.record_hash, "V1_LEGACY_TEST", schema=1)
        db.session.add(e2)
        db.session.commit()
        AuditService.invalidate_verification_cache()

        e3 = AuditService.log_event(action="V3_KEYED", status="SUCCESS")
        assert e3.record_hash == e3.calculate_hash_v3(AuditService._chain_key())
        assert e3.record_hash != e3.calculate_hash_v2()

        is_valid, corrupted_id, total, errors = AuditService.verify_chain(force_recheck=True)
        assert is_valid is True
        assert corrupted_id is None
        assert total == 3
        assert len(errors) == 0


def test_audit_hash_chain_rejects_unkeyed_after_keyed(app):
    """
    Once keyed records exist, an unkeyed (recomputable) hash is a downgrade: someone rewrote
    the chain without the audit key. verify_chain() must flag it.
    """
    from app.extensions import db

    with app.app_context():
        AuditLog.query.delete()
        db.session.commit()
        AuditService.invalidate_verification_cache()

        keyed = AuditService.log_event(action="V3_KEYED", status="SUCCESS")
        forged = _legacy_entry(keyed.record_hash, "FORGED_UNKEYED", schema=2)
        db.session.add(forged)
        db.session.commit()

        is_valid, corrupted_id, _, errors = AuditService.verify_chain(force_recheck=True)
        assert is_valid is False
        assert corrupted_id == forged.id
        assert "Data tamper" in errors[0]
