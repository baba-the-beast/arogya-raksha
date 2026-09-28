"""
High-Assurance Security & Architecture Regression Tests.
Validates P0 remediations, AEAD context binding, OCC concurrency,
encrypted MFA at rest, outbox durability, and defense-in-depth controls.
"""
import logging
import uuid

import pytest

from app.extensions import db
from app.models.outbox import OutboxEvent
from app.models.user import User
from app.observability.logging import PHIRedactionFilter
from app.services.auth_service import AuthService
from app.services.crypto_service import CryptoService, IntegrityTamperedError
from app.services.outbox_service import OutboxService
from app.services.patient_service import ConcurrencyConflictError, PatientService
from tests.conftest import login_client


def test_aead_context_binding_prevents_ciphertext_transplantation(app):
    """
    AEAD Context Binding (P0-3):
    Ensures ciphertext encrypted for Patient A cannot be transplanted to Patient B
    without triggering a GMAC authentication verification failure.
    """
    with app.app_context():
        sensitive_payload = {
            "name": "Target Patient",
            "diagnosis": "Confidential Diagnosis",
            "medical_history": "Classified History",
            "notes": "Physician private notes"
        }

        # Encrypt with canonical AAD bound to patient record P-101
        aad_patient_a = CryptoService.build_record_aad(patient_record_id="P-101", key_version=1)
        ciphertext, nonce, tag, kv = CryptoService.encrypt_record(
            sensitive_payload,
            key_version=1,
            aad=aad_patient_a
        )

        # 1. Verification with legitimate Patient A AAD succeeds
        decrypted = CryptoService.decrypt_record(ciphertext, nonce, tag, key_version=kv, aad=aad_patient_a)
        assert decrypted["name"] == "Target Patient"

        # 2. Transplantation Attack: Attempt to decrypt using Patient B's AAD context
        aad_patient_b = CryptoService.build_record_aad(patient_record_id="P-202", key_version=1)
        with pytest.raises(IntegrityTamperedError) as exc_info:
            CryptoService.decrypt_record(ciphertext, nonce, tag, key_version=kv, aad=aad_patient_b)
        assert "Integrity check failed" in str(exc_info.value)

        # 3. Context Stripping Attack: Attempt to decrypt without any AAD
        with pytest.raises(IntegrityTamperedError):
            CryptoService.decrypt_record(ciphertext, nonce, tag, key_version=kv, aad=None)


def test_totp_secret_encrypted_at_rest(app):
    """
    Plaintext MFA Storage Remediation (P0-4):
    Verifies that TOTP secrets are encrypted at rest using AES-256-GCM
    and that raw Base32 secret strings never exist in database columns.
    """
    with app.app_context():
        raw_secret = "JBSWY3DPEHPK3PXP"  # Standard Base32 TOTP secret

        user = User(
            username="mfa_encrypted_user",
            password_hash=AuthService.hash_password("DoctorPass#123"),
            role="Doctor",
            is_active=True,
            totp_secret=raw_secret,
            totp_enabled=True
        )
        db.session.add(user)
        db.session.commit()

        # Property getter decrypts transparently
        assert user.totp_secret == raw_secret

        # Direct database storage check: assert raw plaintext is NEVER stored
        assert user.totp_secret_encrypted is not None
        assert raw_secret not in user.totp_secret_encrypted
        assert len(user.totp_secret_nonce) == 24  # 12 bytes = 24 hex chars
        assert len(user.totp_secret_tag) == 32    # 16 bytes = 32 hex chars
        assert user._legacy_totp_secret is None


def test_open_redirect_attacks_rejected(client):
    """
    Open Redirect Vulnerability (P0-5):
    Verifies that protocol-relative, absolute, or scheme-relative URLs
    in the 'next' parameter are neutralized and fallback to /dashboard.
    """
    # 1. Protocol-relative URL bypass attempt: //evil.example.com
    resp = client.post("/login", data={
        "username": "test_doctor",
        "password": "DoctorPass#123",
        "next": "//evil.example.com"
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")

    client.post("/logout")

    # 2. Scheme-relative backslash attempt: /\evil.example.com
    resp = client.post("/login", data={
        "username": "test_doctor",
        "password": "DoctorPass#123",
        "next": "/\\evil.example.com"
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")

    client.post("/logout")

    # 3. Absolute URL with scheme: https://attacker.com
    resp = client.post("/login", data={
        "username": "test_doctor",
        "password": "DoctorPass#123",
        "next": "https://attacker.com"
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")

    client.post("/logout")

    # 4. Legitimate relative path is permitted
    resp = client.post("/login", data={
        "username": "test_doctor",
        "password": "DoctorPass#123",
        "next": "/patients"
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/patients")


def test_logout_strictly_requires_post(client):
    """
    Logout CSRF Hardening (P0-6):
    GET /logout must be rejected with HTTP 405 Method Not Allowed.
    Only POST /logout terminates the session.
    """
    login_client(client, "test_doctor", "DoctorPass#123")

    # GET /logout is disallowed
    get_resp = client.get("/logout")
    assert get_resp.status_code == 405

    # POST /logout succeeds
    post_resp = client.post("/logout", follow_redirects=False)
    assert post_resp.status_code == 302
    assert post_resp.headers["Location"].endswith("/login")


def test_optimistic_concurrency_control_prevents_lost_updates(client, app):
    """
    Optimistic Concurrency Control (OCC - P0-8):
    When two clinicians edit the same record concurrently,
    the second update using a stale version_id must fail with 409 Conflict.
    """
    with app.app_context():
        # Retrieve test patient seeded in conftest
        patient = PatientService.get_patient_by_id(1, tenant_id="tenant-default")
        initial_version = patient["version_id"]

    login_client(client, "test_doctor", "DoctorPass#123")

    # Clinician A updates successfully with version 1
    resp_a = client.post("/patients/1/edit", data={
        "age_band": "30-39",
        "gender": "Female",
        "name": "Alice Smith Updated",
        "diagnosis": "Seasonal Allergies - Resolved",
        "medical_history": "No chronic conditions",
        "notes": "Clinician A modification",
        "version_id": initial_version
    }, follow_redirects=False)
    assert resp_a.status_code == 302

    # Clinician B attempts update with stale version 1 -> Must return 409 Conflict
    resp_b = client.post("/patients/1/edit", data={
        "age_band": "30-39",
        "gender": "Female",
        "name": "Alice Smith Stale Edit",
        "diagnosis": "Different diagnosis by Clinician B",
        "medical_history": "No chronic conditions",
        "notes": "Clinician B modification",
        "version_id": initial_version
    }, follow_redirects=False)
    assert resp_b.status_code == 409
    assert b"Concurrency conflict" in resp_b.data


def test_transactional_outbox_pattern(app):
    """
    Transactional Outbox Pattern (P0-7):
    Verifies that critical events are atomically recorded to outbox_events table
    and processed reliably with state transitions (PENDING -> PROCESSED or DEAD_LETTER).
    """
    with app.app_context():
        # 1. Record event within a transaction
        event = OutboxService.record_event(
            event_type="TEST_SECURITY_EVENT",
            payload={"message": "Test alert payload", "severity": "LOW"},
            idempotency_key=str(uuid.uuid4()),
            max_retries=2
        )
        db.session.commit()

        assert event.status == "PENDING"
        assert event.retry_count == 0

        # 2. Process outbox queue
        processed = OutboxService.process_pending_events(batch_size=10)
        assert processed >= 1

        db.session.refresh(event)
        assert event.status == "PROCESSED"
        assert event.processed_at is not None

        # 3. Dead letter testing
        failing_event = OutboxEvent(
            event_type="FAILING_EVENT",
            payload_json="{}",
            status="PENDING",
            retry_count=1,
            max_retries=2
        )
        db.session.add(failing_event)
        db.session.commit()

        # Simulate failed dispatch
        def failing_dispatch(ev):
            return False

        orig_dispatch = OutboxService.dispatch_event
        OutboxService.dispatch_event = staticmethod(failing_dispatch)
        try:
            OutboxService.process_pending_events()
            db.session.refresh(failing_event)
            assert failing_event.status == "DEAD_LETTER"
            assert failing_event.retry_count == 2
        finally:
            OutboxService.dispatch_event = orig_dispatch


def test_kubernetes_probes_livez_and_readyz(client):
    """
    Kubernetes Probes:
    /livez returns 200 alive without touching database.
    /readyz returns 200 ready when database and keys are healthy.
    """
    # Liveness probe
    live_resp = client.get("/livez")
    assert live_resp.status_code == 200
    assert live_resp.get_json()["status"] == "alive"

    # Readiness probe
    ready_resp = client.get("/readyz")
    assert ready_resp.status_code == 200
    data = ready_resp.get_json()
    assert data["status"] == "ready"
    assert data["checks"]["database"] == "connected"
    assert data["checks"]["crypto"] == "ready"


def test_request_id_correlation(client):
    """
    Distributed Request Tracing (Phase 4):
    Requests echo back client-provided X-Request-ID or assign a fresh UUID.
    """
    # 1. Custom incoming Request ID
    resp = client.get("/livez", headers={"X-Request-ID": "audit-trace-correlation-999"})
    assert resp.headers.get("X-Request-ID") == "audit-trace-correlation-999"

    # 2. Auto-generated Request ID
    resp_auto = client.get("/livez")
    assert "X-Request-ID" in resp_auto.headers
    assert len(resp_auto.headers["X-Request-ID"]) >= 32


def test_phi_redaction_logging_filter():
    """
    Automated PHI Redaction Filter:
    Ensures sensitive clinical fields and credit cards are scrubbed from log pipelines.
    """
    flt = PHIRedactionFilter()

    # Dictionary scrub
    raw_dict = {
        "username": "dr_alice",
        "diagnosis": "Stage 2 Acute Bronchitis",
        "password": "SecretPassword#123",
        "notes": "Patient reports shortness of breath",
        "safe_counter": 42
    }
    scrubbed = flt.scrub_dict(raw_dict)
    assert scrubbed["username"] == "dr_alice"
    assert scrubbed["diagnosis"] == "[REDACTED_PHI]"
    assert scrubbed["password"] == "[REDACTED_PHI]"
    assert scrubbed["notes"] == "[REDACTED_PHI]"
    assert scrubbed["safe_counter"] == 42

    # String regex scrub (Credit Card / SSN)
    raw_text = "Clinician entered card 4111 2222 3333 4444 and SSN 123-45-6789"
    scrubbed_text = flt.scrub_text(raw_text)
    assert "4111" not in scrubbed_text
    assert "123-45-6789" not in scrubbed_text
    assert "[REDACTED_SENSITIVE]" in scrubbed_text

    # LogRecord filtering coverage
    record = logging.LogRecord("test", logging.INFO, "path", 1, "Testing credit card 4111 2222 3333 4444", (), None)
    record.args = {"password": "SuperSecretPassword!", "public": "safe"}
    assert flt.filter(record) is True
    assert "[REDACTED_SENSITIVE]" in record.msg
    assert record.args["password"] == "[REDACTED_PHI]"
    assert record.args["public"] == "safe"


def test_structured_json_logging_and_configuration(app):
    """Verifies StructuredJsonFormatter produces valid JSON and enriches context."""
    import json

    from app.observability.logging import StructuredJsonFormatter, configure_observability

    formatter = StructuredJsonFormatter()
    record = logging.LogRecord("test_logger", logging.WARNING, "test.py", 42, "Warning event occurred", (), None)
    record.extra = {"action": "TEST_ACTION"}
    record.alert = {"event_type": "ALERT_TEST"}

    with app.test_request_context("/patients"):
        from flask import g
        g.request_id = "req-12345"
        formatted_json = formatter.format(record)
        parsed = json.loads(formatted_json)
        assert parsed["logger"] == "test_logger"
        assert parsed["level"] == "WARNING"
        assert parsed["request_id"] == "req-12345"
        assert parsed["action"] == "TEST_ACTION"

    orig_handlers = list(logging.getLogger().handlers)
    orig_level = logging.getLogger().level
    try:
        configure_observability(app)
    finally:
        logging.getLogger().handlers = orig_handlers
        logging.getLogger().level = orig_level


def test_metrics_collection_and_telemetry(app, client):
    """Verifies operational metrics registry and Flask middleware integration."""
    from app.observability.metrics import init_metrics, metrics

    init_metrics(app)
    metrics.record_request("/patients", 200, 15.5)
    metrics.record_auth_failure("INVALID_CREDENTIALS")
    metrics.record_audit_verification(True)
    metrics.record_audit_verification(False)

    summary = metrics.get_summary()
    assert summary["auth_failures"]["INVALID_CREDENTIALS"] >= 1
    assert summary["audit_verifications"]["success"] >= 1
    assert summary["audit_verifications"]["failure"] >= 1
    assert "/patients:200" in summary["request_counts"]

    # Trigger via client request
    client.get("/livez")
    summary_after = metrics.get_summary()
    assert any("livez" in k for k in summary_after["request_counts"])


def test_cli_commands_bootstrap_and_audit(app):
    """Verifies CLI commands backend functions init-db, bootstrap-admin, seed-demo, and verify-audit."""
    from app.services.audit_service import AuditService
    from scripts.init_db import apply_migrations, bootstrap_admin, seed_demo_data

    with app.app_context():
        # 1. verify-audit
        valid, broken_id, total, errors = AuditService.verify_chain()
        assert valid is True
        assert total >= 1

        # 2. bootstrap-admin
        admin = bootstrap_admin(username="cli_admin", password="AdminPass#123", app=app)
        assert admin is not None
        assert admin.username == "cli_admin"

        # 3. seed-demo
        seed_demo_data(app=app)

        # 4. apply_migrations
        apply_migrations()


def test_health_probe_failure_modes(client, monkeypatch):
    """Tests failure branches of readiness and health probes."""
    from app.services.crypto_service import CryptoService, KeyProvider

    class BrokenKeyProvider(KeyProvider):
        def get_key(self, version: int) -> bytes:
            return b"short"

        def get_current_key(self) -> tuple[int, bytes]:
            return 1, b"too-short-key"

        def current_version(self) -> int:
            return 1

    orig_provider = CryptoService._provider
    CryptoService.set_key_provider(BrokenKeyProvider())
    try:
        resp = client.get("/readyz")
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["status"] == "not_ready"
    finally:
        CryptoService.set_key_provider(orig_provider)


def test_outbox_idempotency_and_models(app):
    """Tests OutboxEvent model representations and idempotency."""
    with app.app_context():
        key = "idemp-test-unique-key-123"
        ev1 = OutboxService.record_event("TEST_IDEMP", {"data": 1}, idempotency_key=key)
        db.session.commit()

        # Duplicate submission with identical idempotency_key must return existing record
        ev2 = OutboxService.record_event("TEST_IDEMP", {"data": 2}, idempotency_key=key)
        assert ev1.id == ev2.id
        assert repr(ev1).startswith("<OutboxEvent")


def test_user_model_properties_and_repr(app):
    """Tests User model methods, dictionary exports, and TOTP unset."""
    with app.app_context():
        u = User(username="test_user_props", password_hash="hash", role="Nurse")
        db.session.add(u)
        db.session.commit()

        assert repr(u) == "<User test_user_props (Nurse)>"
        d = u.to_dict()
        assert d["username"] == "test_user_props"
        assert d["role"] == "Nurse"

        # Setting TOTP to None clears encrypted fields
        u.totp_secret = "JBSWY3DPEHPK3PXP"
        assert u.totp_secret == "JBSWY3DPEHPK3PXP"
        u.totp_secret = None
        assert u.totp_secret is None
        assert u.totp_secret_encrypted is None
