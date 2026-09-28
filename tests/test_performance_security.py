"""
Automated unit and integration tests for Performance Optimizations and Security Hardening:
- Composite & demographic database query indexes (Patient & PasswordResetToken)
- Audit log streaming verification & memoization with write invalidation
- Centralized error handlers: 400, 405, and CSRF error
- Anti-caching headers on dynamic PHI endpoints vs long-lived static asset caching
- Database connection pool configuration
"""
import time

from flask import abort

from app import create_app
from app.config import Config, TestConfig
from app.models.audit_log import AuditLog
from app.models.password_reset_token import PasswordResetToken
from app.models.patient import Patient
from app.services.audit_service import AuditService
from tests.conftest import login_client


def test_performance_indexes_defined_on_models():
    """Verify composite and demographic query performance indexes are declared on models."""
    patient_indexes = {idx.name for idx in Patient.__table__.indexes}
    assert "ix_patients_deleted_created" in patient_indexes
    assert "ix_patients_age_band" in patient_indexes
    assert "ix_patients_gender" in patient_indexes

    token_indexes = {idx.name for idx in PasswordResetToken.__table__.indexes}
    assert "ix_password_reset_tokens_user_expires" in token_indexes


def test_audit_verify_chain_memoization_and_invalidation(client):
    """Verify verify_chain uses memoization and is invalidated on new writes."""
    with client.application.app_context():
        # Clear any prior cache
        AuditService.invalidate_verification_cache()
        assert AuditService._cached_verification is None

        # Seed initial event
        AuditService.log_event(action="MEMO_TEST_1", status="SUCCESS")

        # First verification
        valid, bad_id, total, errors = AuditService.verify_chain(force_recheck=True)
        assert valid is True
        assert bad_id is None
        assert total > 0

        # Simulate setting a cached result
        cached_tuple = (True, None, 999, [])
        AuditService._cached_verification = cached_tuple
        AuditService._last_verification_time = time.time()

        # In non-testing / production simulation, verify_chain returns memoized result
        client.application.config["TESTING"] = False
        try:
            memoized_res = AuditService.verify_chain()
            assert memoized_res == cached_tuple

            # Appending a new audit event via log_event must invalidate the cache
            AuditService.log_event(action="MEMO_TEST_2", status="SUCCESS")
            assert AuditService._cached_verification is None
        finally:
            client.application.config["TESTING"] = True
            AuditService.invalidate_verification_cache()


def test_error_handler_400_bad_request():
    """Verify custom 400 error handler responds with branded status."""
    app = create_app(TestConfig)
    @app.route("/test-trigger-400")
    def trigger_400():
        abort(400, description="Custom malformed parameter syntax")

    with app.test_client() as test_client:
        res = test_client.get("/test-trigger-400")
        assert res.status_code == 400
        assert b"Bad Request" in res.data
        assert b"Custom malformed parameter syntax" in res.data


def test_error_handler_405_method_not_allowed(client):
    """Verify custom 405 handler returns clean error response on wrong HTTP method."""
    # /patients/<id>/delete only accepts POST
    res = client.get("/patients/1/delete")
    assert res.status_code == 405
    assert b"Method Not Allowed" in res.data


def test_csrf_error_handler_and_auditing(client):
    """Verify CSRF failure triggers custom 400 response and logs security audit event."""
    client.application.config["WTF_CSRF_ENABLED"] = True
    try:
        # POST without CSRF token
        res = client.post("/login", data={"username": "doctor_alice", "password": "DocSecurePass#2026"})
        assert res.status_code == 400
        assert b"CSRF Token Invalid" in res.data

        with client.application.app_context():
            csrf_log = AuditLog.query.filter_by(action="CSRF_VALIDATION_FAILURE").first()
            assert csrf_log is not None
            assert csrf_log.status == "BLOCKED"
    finally:
        client.application.config["WTF_CSRF_ENABLED"] = False


def test_anti_caching_headers_on_dynamic_routes(client):
    """Verify dynamic views send no-store Cache-Control headers to protect clinical PHI."""
    client.application.config["TALISMAN_ENABLED"] = True
    login_client(client, "test_doctor", "DoctorPass#123")

    res = client.get("/patients")
    assert res.status_code == 200
    cache_ctrl = res.headers.get("Cache-Control", "")
    assert "no-store" in cache_ctrl
    assert "no-cache" in cache_ctrl
    assert "must-revalidate" in cache_ctrl
    assert res.headers.get("Pragma") == "no-cache"


def test_database_connection_pool_configuration():
    """Verify production SQLAlchemy engine pool options are configured with keepalives."""
    options = Config.SQLALCHEMY_ENGINE_OPTIONS
    assert options.get("pool_pre_ping") is True
    assert options.get("pool_recycle") == 300
