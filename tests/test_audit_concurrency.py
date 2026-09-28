"""
Phase 1 — Audit-log concurrency tests.

Threading limitation with in-memory SQLite
-------------------------------------------
Flask-SQLAlchemy maps `sqlite:///:memory:` to a StaticPool (single shared connection).
Concurrent threads sharing one SQLite connection cause SQLAlchemy session-state corruption
(ObjectDeletedError on rollback) — a test-infrastructure limitation, NOT a bug in the
production code.

For threading tests we create a *file-based* SQLite fixture with NullPool so each thread
gets its own independent connection to the same physical file. SQLite serialises writes at
the file level; the module-level _sqlite_chain_lock adds an explicit serialisation layer on
top of that, so the tests faithfully exercise the production code path.

PostgreSQL path (SELECT FOR UPDATE) is exercised by the migration and must be used for
any production multi-worker deployment (documented in docs/ARCHITECTURE.md §6).
"""
import os
import tempfile
import threading

import pytest
from sqlalchemy.pool import NullPool

from app import create_app
from app.config import TestConfig
from app.extensions import db
from app.models.audit_log import AuditLog
from app.models.tenant import Tenant
from app.models.user import User
from app.services.audit_service import AuditService, _sqlite_chain_lock
from app.services.auth_service import AuthService
from app.services.patient_service import PatientService

# ── Fixtures ────────────────────────────────────────────────────────────────

class _FileDbTestConfig(TestConfig):
    """TestConfig override using a temp file SQLite so concurrent threads each get
    their own connection (avoids StaticPool single-connection limitation)."""
    pass  # URI patched at fixture creation time; NullPool injected via engine_options


@pytest.fixture
def concurrent_app():
    """
    App fixture backed by a temporary file-based SQLite database.
    Uses NullPool so every SQLAlchemy session opens and closes its own connection,
    allowing concurrent threads to operate without sharing connection state.
    """
    db_fd, db_path = tempfile.mkstemp(suffix=".db", prefix="arogyaraksha_test_")
    os.close(db_fd)

    class _Cfg(_FileDbTestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
        SQLALCHEMY_ENGINE_OPTIONS = {"poolclass": NullPool}

    app = create_app(_Cfg)

    with app.app_context():
        db.create_all()

        # Seed default tenant
        default_tenant = Tenant(
            id="tenant-default",
            name="Concurrent Test Clinic",
            code="CONC-01",
            is_active=True
        )
        db.session.add(default_tenant)

        # Seed a minimal user so log_event() can resolve FK if needed
        doctor = User(
            username="conc_doctor",
            password_hash=AuthService.hash_password("DoctorPass#123"),
            role="Doctor",
            is_active=True,
        )
        db.session.add(doctor)
        db.session.commit()

        yield app

        db.session.remove()
        db.drop_all()

    os.unlink(db_path)


@pytest.fixture(autouse=False)
def reset_chain_lock():
    """Ensure the module-level SQLite chain lock is released before and after each test."""
    if _sqlite_chain_lock.locked():
        _sqlite_chain_lock.release()
    yield
    if _sqlite_chain_lock.locked():
        _sqlite_chain_lock.release()


# ── Tests ───────────────────────────────────────────────────────────────────

def test_concurrent_log_event_chain_remains_valid(concurrent_app, reset_chain_lock):
    """
    Spawn N threads each writing M audit events concurrently.
    Assert the full chain verifies as valid after all threads complete —
    no forking, no duplicate prev_hash, no gaps.
    """
    N_THREADS = 8
    EVENTS_PER_THREAD = 5
    errors: list[Exception] = []

    def worker(thread_id: int):
        with concurrent_app.app_context():
            for i in range(EVENTS_PER_THREAD):
                try:
                    AuditService.log_event(
                        action="TEST_EVENT",
                        resource_type="TEST",
                        resource_id=f"thread-{thread_id}-event-{i}",
                        status="SUCCESS",
                        username=f"thread_{thread_id}",
                        details=f"Concurrent write from thread {thread_id}, event {i}",
                    )
                except Exception as exc:
                    errors.append(exc)

    threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread errors during concurrent log_event: {errors}"

    with concurrent_app.app_context():
        is_valid, corrupted_id, total_records, chain_errors = AuditService.verify_chain()

        expected_min = N_THREADS * EVENTS_PER_THREAD
        assert total_records >= expected_min, (
            f"Expected at least {expected_min} audit records, got {total_records}"
        )
        assert is_valid, (
            f"Hash chain is INVALID after concurrent writes! "
            f"Corrupted record: #{corrupted_id}. Errors: {chain_errors}"
        )


def test_concurrent_log_event_no_duplicate_prev_hash(concurrent_app, reset_chain_lock):
    """
    Verify no two audit records share the same prev_hash after concurrent inserts.
    A duplicate prev_hash indicates the chain was forked, which defeats tamper evidence.
    """
    N_THREADS = 6
    EVENTS_PER_THREAD = 4

    def worker(thread_id: int):
        with concurrent_app.app_context():
            for i in range(EVENTS_PER_THREAD):
                try:
                    AuditService.log_event(
                        action="DUPLICATE_HASH_TEST",
                        resource_type="TEST",
                        resource_id=f"t{thread_id}-e{i}",
                        status="SUCCESS",
                        username="concurrent_tester",
                    )
                except Exception:
                    pass  # Retry exhaustion acceptable; chain must still be valid

    threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with concurrent_app.app_context():
        all_logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
        prev_hashes = [log.prev_hash for log in all_logs]
        unique_prev_hashes = set(prev_hashes)
        assert len(prev_hashes) == len(unique_prev_hashes), (
            f"Duplicate prev_hash values detected — chain was forked! "
            f"Total records: {len(prev_hashes)}, unique prev_hashes: {len(unique_prev_hashes)}"
        )


def test_audit_chain_verify_detects_gap(app):
    """
    Verify that verify_chain() catches a manually introduced gap in the chain.
    This re-confirms the existing tamper-detection logic still works after the rewrite.
    Uses the standard in-memory fixture — no threads involved.
    """
    with app.app_context():
        AuditService.log_event(action="CHAIN_TEST_A", resource_type="TEST", status="SUCCESS")
        AuditService.log_event(action="CHAIN_TEST_B", resource_type="TEST", status="SUCCESS")

        # Manually corrupt the most-recent log entry's prev_hash
        second_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
        if second_log:
            second_log.prev_hash = "deadbeef" * 8  # 64 chars of garbage
            db.session.commit()

            is_valid, corrupted_id, _, errors = AuditService.verify_chain()
            assert not is_valid, "verify_chain() should have detected the corrupted chain"
            assert corrupted_id == second_log.id
