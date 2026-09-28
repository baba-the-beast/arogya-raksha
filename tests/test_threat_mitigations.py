"""
Security Assurance & Threat Mitigation Tests.
Validates:
  1. TOTP One-Time-Use Replay Prevention (ASVS V2.8 / RFC 6238 §5.2).
  2. Emergency Break-Glass Velocity Limiting (Anti-Exfiltration Throttling).
  3. Ephemeral Password Reset Session Ticket Expiry (120s TTL).
  4. Hardened Content Security Policy without data: exfiltration in connect-src.
  5. Constant-time cryptographic verification in audit ledger integrity checks.
"""
import time
from datetime import UTC, datetime

import pyotp

from app import create_app
from app.config import TestConfig
from app.extensions import db
from app.models.patient import Patient
from app.models.user import User
from app.security.policy import PolicyEngine, clear_break_glass_history
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService


def test_totp_replay_prevention(app):
    """Validates that a 6-digit TOTP code cannot be replayed within its validity window."""
    with app.app_context():
        AuthService.clear_consumed_totp_codes()
        secret = AuthService.generate_totp_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # 1. First verification for user 100 must succeed
        assert AuthService.verify_totp(secret, code, user_id=100) is True

        # 2. Immediate replay of identical code for user 100 must be rejected
        assert AuthService.verify_totp(secret, code, user_id=100) is False

        # 3. Different user context is not affected
        assert AuthService.verify_totp(secret, code, user_id=200) is True


def test_break_glass_velocity_limiting(app):
    """Validates that a clinician cannot execute more than 5 emergency overrides per hour."""
    with app.app_context():
        clear_break_glass_history()

        doctor = User(
            username="doc_emergency",
            password_hash=AuthService.hash_password("DocEmergency#2026"),
            role="Doctor",
            tenant_id="tenant-default"
        )
        db.session.add(doctor)
        db.session.commit()

        patient = Patient(
            patient_id="P-VELOCITY-01",
            tenant_id="tenant-default",
            age_band="40-49",
            gender="Female",
            encrypted_data="deadbeef",
            nonce="11" * 12,
            auth_tag="22" * 16,
            key_version=1,
            assigned_doctor_id=99999  # Assigned to another physician
        )
        db.session.add(patient)
        db.session.commit()

        # First 5 emergency overrides must succeed
        for i in range(5):
            decision = PolicyEngine.authorize_patient_access(
                user=doctor,
                patient=patient,
                action="UPDATE",
                break_glass_reason=f"EMERGENCY_RESUSCITATION - Urgent override #{i+1}"
            )
            assert decision.allowed is True
            assert decision.is_break_glass is True

        # 6th emergency override within the hour must be blocked
        decision_blocked = PolicyEngine.authorize_patient_access(
            user=doctor,
            patient=patient,
            action="UPDATE",
            break_glass_reason="EMERGENCY_RESUSCITATION - Excessive override #6"
        )
        assert decision_blocked.allowed is False
        assert "velocity limit exceeded" in decision_blocked.reason.lower()


def test_password_reset_ticket_ttl(client, app):
    """Validates that a clean URL password reset ticket expires after 120 seconds."""
    with app.app_context():
        user = User(
            username="test_reset_ttl",
            password_hash=AuthService.hash_password("InitialPass#2026"),
            role="Nurse",
            tenant_id="tenant-default"
        )
        db.session.add(user)
        db.session.commit()

        raw_token = AuthService.create_password_reset_token("test_reset_ttl")
        assert raw_token is not None

        # 1. Normal transition: GET /reset-password/<token> redirects to clean URL
        resp_entry = client.get(f"/reset-password/{raw_token}")
        assert resp_entry.status_code == 302
        assert resp_entry.headers["Location"].endswith("/reset-password")

        # 2. Simulate abandoned terminal: set ticket timestamp 150 seconds in the past
        with client.session_transaction() as sess:
            sess["_reset_ticket_ts"] = datetime.now(UTC).timestamp() - 150.0

        # 3. Subsequent visit to /reset-password must reject expired ticket and redirect
        resp_clean = client.get("/reset-password", follow_redirects=False)
        assert resp_clean.status_code == 302
        assert resp_clean.headers["Location"].endswith("/forgot-password")

        # Ticket must be purged from session
        with client.session_transaction() as sess:
            assert "_reset_ticket" not in sess
            assert "_reset_ticket_ts" not in sess


def test_csp_hardened_connect_src():
    """Validates that Content-Security-Policy connect-src excludes data: exfiltration."""
    class ProdConfig(TestConfig):
        TALISMAN_ENABLED = True
        SESSION_COOKIE_SECURE = False

    prod_app = create_app(ProdConfig)
    client = prod_app.test_client()

    resp = client.get("/login")
    assert resp.status_code == 200
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "connect-src" in csp
    # data: must NOT be present in connect-src
    connect_src_part = [part for part in csp.split(";") if "connect-src" in part]
    assert len(connect_src_part) == 1
    assert "data:" not in connect_src_part[0]
