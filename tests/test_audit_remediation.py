"""
Regression tests for the codebase audit remediation:
care-team workflow, tenant isolation, password reset delivery, outbox worker, session store,
proxy/IP handling, version-bound AAD, keyed audit chain, fail-closed caches and deployment config.
"""
import json
import logging

import pytest

from app.config import TestConfig
from app.extensions import db
from app.models.audit_log import AuditLog
from app.models.outbox import OutboxEvent
from app.models.patient import Patient
from app.models.tenant import Tenant
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.crypto_service import CryptoService, IntegrityTamperedError
from app.services.outbox_service import OutboxService
from app.services.patient_service import PatientService
from tests.conftest import login_client


def _ids(app):
    with app.app_context():
        return {u.username: u.id for u in User.query.all()}


@pytest.fixture
def second_doctor(app):
    with app.app_context():
        doc = User(username="test_doctor_two", password_hash=AuthService.hash_password("DoctorTwo#123"),
                   role="Doctor", is_active=True)
        db.session.add(doc)
        db.session.commit()
        return doc.id


@pytest.fixture
def other_tenant(app):
    """A second tenant with its own doctor and admin."""
    with app.app_context():
        db.session.add(Tenant(id="tenant-beta", name="Beta Clinic", code="BETA-01", is_active=True))
        db.session.add_all([
            User(username="beta_doctor", password_hash=AuthService.hash_password("BetaDoc#123"),
                 role="Doctor", tenant_id="tenant-beta", is_active=True),
            User(username="beta_admin", password_hash=AuthService.hash_password("BetaAdmin#123"),
                 role="Admin", tenant_id="tenant-beta", is_active=True),
        ])
        db.session.commit()


def _edit_form(version, **extra):
    data = {"age_band": "30-39", "gender": "Female", "name": "Edited Name", "diagnosis": "Edited Dx",
            "medical_history": "h", "notes": "n", "version_id": str(version)}
    data.update(extra)
    return data


# ── Care-team workflow ────────────────────────────────────────────────────────

def test_doctor_creating_patient_is_assigned_attending(app):
    ids = _ids(app)
    with app.app_context():
        assert db.session.get(Patient, 1).assigned_doctor_id == ids["test_doctor"]


def test_nurse_intake_is_editable_by_any_doctor(app, client, second_doctor):
    ids = _ids(app)
    with app.app_context():
        p = PatientService.create_patient("P-NURSE-01", "30-39", "Female", "Nina", "dx", "h", "n",
                                          created_by_user_id=ids["test_nurse"])
        assert p.assigned_doctor_id is None
        record_id = p.id

    login_client(client, "test_doctor_two", "DoctorTwo#123")
    assert client.get(f"/patients/{record_id}/edit").status_code == 200
    resp = client.post(f"/patients/{record_id}/edit", data=_edit_form(1), follow_redirects=True)
    assert resp.status_code == 200
    assert b"Edited Name" in resp.data


def test_nurse_can_assign_attending_doctor_at_intake(app, client):
    ids = _ids(app)
    login_client(client, "test_nurse", "NursePass#123")
    resp = client.post("/patients/new", data={
        "patient_id": "P-ASSIGN-01", "age_band": "30-39", "gender": "Male", "name": "Sam",
        "diagnosis": "dx", "medical_history": "", "notes": "",
        "assigned_doctor_id": str(ids["test_doctor"]),
    })
    assert resp.status_code == 302
    with app.app_context():
        p = Patient.query.filter_by(patient_id="P-ASSIGN-01").one()
        assert p.assigned_doctor_id == ids["test_doctor"]


def test_assigning_a_non_doctor_is_rejected(app):
    ids = _ids(app)
    with app.app_context():
        with pytest.raises(ValueError, match="active Doctor"):
            PatientService.create_patient("P-BAD-ASSIGN", "30-39", "Male", "X", "d", "h", "n",
                                          created_by_user_id=ids["test_nurse"],
                                          assigned_doctor_id=ids["test_nurse"])


def test_unassigned_doctor_gets_break_glass_flow(app, client, second_doctor):
    login_client(client, "test_doctor_two", "DoctorTwo#123")
    detail = client.get("/patients/1")
    assert detail.status_code == 200
    assert b"Declare and edit" in detail.data
    assert b">Archive<" not in detail.data

    assert client.get("/patients/1/edit").status_code == 403
    assert client.post("/patients/1/delete").status_code == 403

    edit = client.get("/patients/1/edit?break_glass_reason=CALL_COVERAGE")
    assert edit.status_code == 200
    assert b'name="break_glass_reason" value="CALL_COVERAGE"' in edit.data

    resp = client.post("/patients/1/edit", data=_edit_form(1, break_glass_reason="CALL_COVERAGE"),
                       follow_redirects=True)
    assert resp.status_code == 200
    assert b"Edited Name" in resp.data
    with app.app_context():
        assert AuditLog.query.filter_by(action="BREAK_GLASS_ACCESS").count() >= 1


# ── Tamper demo hardening ─────────────────────────────────────────────────────

def test_tamper_demo_cannot_touch_other_tenant(app, client, other_tenant):
    login_client(client, "beta_doctor", "BetaDoc#123")
    resp = client.post("/patients/1/tamper-demo", data={"tamper_type": "tag"})
    assert resp.status_code == 403
    login_client(client, "test_doctor", "DoctorPass#123")
    assert client.get("/patients/1").status_code == 200  # record intact


def test_tamper_demo_disabled_unless_opted_in(app, client):
    app.config["ENABLE_TAMPER_DEMO"] = False
    login_client(client, "test_doctor", "DoctorPass#123")
    assert client.post("/patients/1/tamper-demo", data={"tamper_type": "tag"}).status_code == 404
    assert b"Tamper simulation" not in client.get("/patients/1").data


# ── Tenant-scoped patient IDs ─────────────────────────────────────────────────

def test_same_mrn_allowed_in_different_tenants(app, client, other_tenant):
    login_client(client, "beta_doctor", "BetaDoc#123")
    resp = client.post("/patients/new", data={
        "patient_id": "P-TEST-001", "age_band": "30-39", "gender": "Male", "name": "Other Tenant",
        "diagnosis": "dx", "medical_history": "", "notes": "",
    })
    assert resp.status_code == 302
    with app.app_context():
        assert Patient.query.filter_by(patient_id="P-TEST-001").count() == 2


def test_duplicate_and_archived_mrn_in_same_tenant_give_clean_errors(app, client):
    login_client(client, "test_doctor", "DoctorPass#123")
    form = {"patient_id": "P-TEST-001", "age_band": "30-39", "gender": "Male", "name": "Dup",
            "diagnosis": "dx", "medical_history": "", "notes": ""}
    resp = client.post("/patients/new", data=form)
    assert resp.status_code == 400
    assert b"already exists" in resp.data

    client.post("/patients/1/delete")
    resp = client.post("/patients/new", data=form)
    assert resp.status_code == 400
    assert b"archived record" in resp.data
    assert b"IntegrityError" not in resp.data


# ── Session store ─────────────────────────────────────────────────────────────

def test_anonymous_probe_requests_do_not_create_sessions(app):
    from app.security.session_store import get_session_store
    store = get_session_store()
    before = len(store._store)
    for _ in range(20):
        resp = app.test_client().get("/livez")
        assert "Set-Cookie" not in resp.headers
    assert len(store._store) == before


def test_session_is_persisted_once_it_holds_state(app):
    from app.security.session_store import get_session_store
    store = get_session_store()
    before = len(store._store)
    resp = app.test_client().get("/login")  # renders a CSRF token into the session
    assert "Set-Cookie" in resp.headers
    assert len(store._store) == before + 1


# ── Password reset delivery via the outbox ────────────────────────────────────

def test_reset_token_is_sealed_in_outbox_and_delivered(app, client, caplog):
    with app.app_context():
        raw = AuthService.create_password_reset_token("test_doctor")
        event = OutboxEvent.query.filter_by(event_type="PASSWORD_RESET_DISPATCH").one()
        assert raw not in event.payload_json
        assert "sealed_token" in json.loads(event.payload_json)

        with caplog.at_level(logging.WARNING, logger="notification.service"):
            OutboxService.process_pending_events()
        assert f"/reset-password/{raw}" in caplog.text
        assert db.session.get(OutboxEvent, event.id).status == "PROCESSED"

    # The delivered link completes the flow end to end
    client.get(f"/reset-password/{raw}")
    resp = client.post("/reset-password", data={"password": "BrandNewPass#2026"}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"successfully updated" in resp.data
    assert b"Signed in as Doctor" in login_client(client, "test_doctor", "BrandNewPass#2026").data


def test_reset_email_sent_via_smtp_when_configured(app, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            self.host = host

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            pass

        def login(self, u, p):
            pass

        def send_message(self, msg):
            sent.append(msg)

    monkeypatch.setattr("app.services.notification_service.smtplib.SMTP", FakeSMTP)
    app.config.update(SMTP_HOST="smtp.test", APP_BASE_URL="https://arogya.example")
    with app.app_context():
        user = User.query.filter_by(username="test_doctor").one()
        user.email = "doctor@hospital.test"
        db.session.commit()
        raw = AuthService.create_password_reset_token("test_doctor")
        OutboxService.process_pending_events()
        assert OutboxEvent.query.filter_by(event_type="PASSWORD_RESET_DISPATCH").one().status == "PROCESSED"

    assert len(sent) == 1
    assert sent[0]["To"] == "doctor@hospital.test"
    assert f"https://arogya.example/reset-password/{raw}" in sent[0].get_content()


def test_reset_fails_without_channel_in_production(app, monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    with app.app_context():
        AuthService.create_password_reset_token("test_doctor")
        OutboxService.process_pending_events()
        event = OutboxEvent.query.filter_by(event_type="PASSWORD_RESET_DISPATCH").one()
        assert event.status == "FAILED"


def test_process_outbox_cli(app, runner):
    with app.app_context():
        AuthService.create_password_reset_token("test_doctor")
    result = runner.invoke(args=["process-outbox"])
    assert result.exit_code == 0
    assert "delivered" in result.output
    with app.app_context():
        assert OutboxEvent.query.filter(OutboxEvent.status != "PROCESSED").count() == 0


# ── Admin tenant isolation & user management ─────────────────────────────────

def test_admin_sees_and_manages_only_own_tenant(app, client, other_tenant):
    ids = _ids(app)
    login_client(client, "beta_admin", "BetaAdmin#123")
    users_page = client.get("/admin/users")
    assert users_page.status_code == 200
    assert b"beta_doctor" in users_page.data
    assert b"test_doctor" not in users_page.data

    client.post(f"/admin/users/{ids['test_doctor']}/toggle")
    with app.app_context():
        assert db.session.get(User, ids["test_doctor"]).is_active is True

    client.post("/admin/users", data={"username": "beta_nurse", "password": "BetaNurse#123",
                                      "role": "Nurse", "email": "nurse@beta.test"})
    with app.app_context():
        created = User.query.filter_by(username="beta_nurse").one()
        assert created.tenant_id == "tenant-beta"
        assert created.email == "nurse@beta.test"

    audit_page = client.get("/admin/audit")
    assert b"P-TEST-001" not in audit_page.data


def test_username_validation(app):
    from app.services.user_service import UserService
    with app.app_context():
        with pytest.raises(ValueError, match="3-30 characters"):
            UserService.create_user("x" * 90, "ValidPass#123", "Nurse")
        with pytest.raises(ValueError, match="Email"):
            UserService.create_user("valid_name", "ValidPass#123", "Nurse", email="not-an-email")


def test_non_admin_can_enroll_mfa(client):
    login_client(client, "test_doctor", "DoctorPass#123")
    assert client.get("/admin/settings/mfa").status_code == 200


def test_bootstrap_admin_cli_never_uses_default_password(app, runner, monkeypatch):
    captured = {}
    monkeypatch.setattr("scripts.init_db.bootstrap_admin",
                        lambda username, password, app: captured.update(password=password))
    runner.invoke(args=["bootstrap-admin"])
    assert captured == {"password": None}


# ── Proxy / client IP handling ────────────────────────────────────────────────

def test_client_ip_uses_rightmost_untrusted_hop(app):
    app.config["TRUSTED_PROXY_IPS"] = ["10.0.0.0/8"]
    try:
        # Client forged "1.1.1.1"; the ingress appended the real peer 203.0.113.9
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.1.2.3"},
                                      headers={"X-Forwarded-For": "1.1.1.1, 203.0.113.9"}):
            assert AuditService.get_client_ip() == "203.0.113.9"
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.1.2.3"},
                                      headers={"X-Forwarded-For": "not-an-ip"}):
            assert AuditService.get_client_ip() == "10.1.2.3"
    finally:
        app.config["TRUSTED_PROXY_IPS"] = []


def test_oversized_login_username_is_audited_not_crashing(app, client):
    resp = client.post("/login", data={"username": "u" * 300, "password": "whatever"})
    assert resp.status_code == 401
    with app.app_context():
        entry = AuditLog.query.filter_by(action="LOGIN_FAILURE").order_by(AuditLog.id.desc()).first()
        assert len(entry.username) == 80
        assert len(entry.resource_id) == 64


# ── Version-bound AAD ─────────────────────────────────────────────────────────

def test_old_ciphertext_cannot_be_replayed_over_newer_version(app):
    ids = _ids(app)
    with app.app_context():
        p = db.session.get(Patient, 1)
        old = (p.encrypted_data, p.nonce, p.auth_tag)
        PatientService.update_patient(1, "30-39", "Female", "New", "New Dx", "h", "n",
                                      updated_by_user_id=ids["test_doctor"], expected_version=1)
        p = db.session.get(Patient, 1)
        assert p.version_id == 2 and p.crypto_schema == 2
        p.encrypted_data, p.nonce, p.auth_tag = old
        db.session.commit()
        with pytest.raises(IntegrityTamperedError):
            PatientService.get_patient_by_id(1, tenant_id="tenant-default")


def _make_legacy_record(patient_id):
    """Writes a pre-upgrade (crypto_schema 1) record, as older releases did."""
    aad = CryptoService.build_record_aad(patient_record_id=patient_id, tenant_id="tenant-default", key_version=1)
    ct, n, t, kv = CryptoService.encrypt_record(
        {"name": "Legacy", "diagnosis": "d", "medical_history": "h", "notes": "n"}, key_version=1, aad=aad)
    p = Patient(patient_id=patient_id, tenant_id="tenant-default", age_band="30-39", gender="Male",
                encrypted_data=ct, nonce=n, auth_tag=t, key_version=kv, version_id=1, crypto_schema=1)
    db.session.add(p)
    db.session.commit()
    return p.id


def test_legacy_aad_records_readable_until_disabled_and_upgraded_by_rotation(app):
    from scripts.rotate_keys import rotate_patient_keys
    with app.app_context():
        record_id = _make_legacy_record("P-LEGACY-01")
        assert PatientService.get_patient_by_id(record_id, "tenant-default")["name"] == "Legacy"

        app.config["CRYPTO_ALLOW_LEGACY_AAD"] = False
        with pytest.raises(IntegrityTamperedError):
            PatientService.get_patient_by_id(record_id, "tenant-default")

        assert rotate_patient_keys(target_version=1) >= 1
        assert db.session.get(Patient, record_id).crypto_schema == 2
        assert PatientService.get_patient_by_id(record_id, "tenant-default")["name"] == "Legacy"


# ── Fail-closed security caches ───────────────────────────────────────────────

def test_totp_code_cannot_be_replayed(app):
    import pyotp
    with app.app_context():
        secret = AuthService.generate_totp_secret()
        code = pyotp.TOTP(secret).now()
        assert AuthService.verify_totp(secret, code, user_id=1) is True
        assert AuthService.verify_totp(secret, code, user_id=1) is False


def test_totp_fails_closed_when_replay_cache_down(app, monkeypatch):
    import pyotp

    from app.services.cache_service import CacheService, CacheUnavailableError

    def boom(*a, **k):
        raise CacheUnavailableError("redis down")

    monkeypatch.setattr(CacheService, "add_if_absent", classmethod(lambda cls, *a, **k: boom()))
    with app.app_context():
        secret = AuthService.generate_totp_secret()
        assert AuthService.verify_totp(secret, pyotp.TOTP(secret).now(), user_id=1) is False


def test_break_glass_fails_closed_when_velocity_tracker_down(app, second_doctor, monkeypatch):
    from app.security.policy import PolicyEngine
    from app.services.cache_service import CacheService, CacheUnavailableError

    def boom(cls, key, strict=False):
        if strict:
            raise CacheUnavailableError("redis down")
        return []

    monkeypatch.setattr(CacheService, "lrange", classmethod(boom))
    with app.app_context():
        doc2 = db.session.get(User, second_doctor)
        decision = PolicyEngine.authorize_patient_access(doc2, db.session.get(Patient, 1), "UPDATE",
                                                         break_glass_reason="CALL_COVERAGE")
        assert decision.allowed is False
        assert "temporarily unavailable" in decision.reason


def test_totp_secret_follows_current_key_version(app):
    with app.app_context():
        app.config["CURRENT_KEY_VERSION"] = 2
        user = db.session.get(User, 1)
        user.totp_secret = "JBSWY3DPEHPK3PXP"
        db.session.commit()
        assert user.totp_key_version == 2
        assert user.totp_secret == "JBSWY3DPEHPK3PXP"


# ── HTTPS enforcement vs health probes ────────────────────────────────────────

def test_https_redirect_exempts_health_probes():
    from app import create_app

    class HttpsConfig(TestConfig):
        TALISMAN_ENABLED = True
        SESSION_COOKIE_SECURE = True

    app = create_app(HttpsConfig)
    with app.app_context():
        db.create_all()
        client = app.test_client()
        assert client.get("/livez").status_code == 200
        assert client.get("/readyz").status_code == 200
        resp = client.get("/login")
        assert resp.status_code == 301
        assert resp.headers["Location"].startswith("https://")
        assert client.get("/login", headers={"X-Forwarded-Proto": "https"}).status_code == 200
        db.drop_all()
