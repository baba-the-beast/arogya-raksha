"""
Audit Service providing immutable, tamper-evident security event logging with SHA-256 hash chaining.

Concurrency design
------------------
`log_event()` must guarantee that the read-last-row → compute-hash → insert sequence is atomic.
On PostgreSQL this is achieved with `SELECT ... FOR UPDATE` inside a savepoint, so the selected
tail row is row-locked until the insert commits. On SQLite (dev-only) a module-level threading
Lock serialises writers within the same process.

If a concurrent writer beats us to the same `prev_hash` (detected by a UNIQUE constraint
violation on `prev_hash`), we roll back to the savepoint, re-read the new tail, and retry
up to MAX_CHAIN_RETRIES times. If all retries fail, we log at CRITICAL and raise so the
caller sees the failure rather than silently swallowing a dropped audit event.

SQLite is explicitly NOT safe for concurrent multi-process writers. This is documented in
docs/ARCHITECTURE.md — use PostgreSQL for any deployment with Gunicorn workers > 1.
"""
import hmac
import ipaddress
import logging
import threading
from datetime import UTC, datetime

from flask import current_app, request, session
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.audit_log import GENESIS_HASH, AuditLog

logger = logging.getLogger(__name__)

# Module-level lock used for SQLite (dev-only) to serialise concurrent writers
# in the same process. On PostgreSQL the DB-level row lock makes this a no-op.
_sqlite_chain_lock = threading.Lock()

MAX_CHAIN_RETRIES = 5


class AuditService:
    """Manages recording and verification of security-relevant audit events."""

    _cached_verification: tuple[bool, int | None, int, list[str]] | None = None
    _last_verification_time: float = 0.0
    _cache_ttl_seconds: float = 30.0
    _is_postgres_dialect: bool | None = None

    @classmethod
    def invalidate_verification_cache(cls) -> None:
        """Invalidates the memoized audit chain verification result."""
        cls._cached_verification = None
        cls._last_verification_time = 0.0
        cls._is_postgres_dialect = None

    @staticmethod
    def _is_trusted_proxy_ip(ip_str: str, trusted_list: list[str]) -> bool:
        """Determines whether ip_str matches an exact IP or CIDR network in trusted_list."""
        if not ip_str or not trusted_list:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for entry in trusted_list:
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if addr == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                continue
        return False

    @classmethod
    def get_client_ip(cls) -> str:
        """
        Extracts the client IP address safely.
        X-Forwarded-For is only honored when request.remote_addr matches a configured
        TRUSTED_PROXY_IPS allowlist (exact IP or CIDR network); otherwise request.remote_addr
        is used directly (BUG-01).

        Proxies append to X-Forwarded-For, so everything left of the last trusted hop is
        client-controlled. The header is walked right-to-left, skipping trusted proxies, and the
        first untrusted, well-formed address is returned.
        """
        if not request:
            return "127.0.0.1"
        remote_addr = request.remote_addr or "127.0.0.1"
        trusted_proxies = current_app.config.get("TRUSTED_PROXY_IPS", []) if current_app else []
        xff = request.headers.get("X-Forwarded-For")
        if not (trusted_proxies and xff and cls._is_trusted_proxy_ip(remote_addr, trusted_proxies)):
            return remote_addr

        client_ip = remote_addr
        for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
            try:
                ipaddress.ip_address(hop)
            except ValueError:
                break  # Malformed entry: stop and keep the last verified hop
            client_ip = hop
            if not cls._is_trusted_proxy_ip(hop, trusted_proxies):
                break
        return client_ip

    @classmethod
    def _is_postgres(cls) -> bool:
        """Returns True when the active DB dialect is PostgreSQL."""
        if cls._is_postgres_dialect is not None:
            return cls._is_postgres_dialect
        try:
            cls._is_postgres_dialect = (db.engine.dialect.name == "postgresql")
            return cls._is_postgres_dialect
        except Exception:
            return False

    @classmethod
    def _chain_key(cls) -> bytes:
        """HKDF subkey (purpose 'audit_chain') that keys the audit hash chain (schema v3)."""
        from app.services.crypto_service import CryptoService
        version = current_app.config.get("AUDIT_CHAIN_KEY_VERSION", 1)
        return CryptoService.get_key_provider().get_key(version, purpose="audit_chain")

    @classmethod
    def _fetch_tail_locked(cls) -> str:
        """
        Fetches the prev_hash of the current chain tail.

        PostgreSQL: issues `SELECT ... FOR UPDATE` on the highest-id row, row-locking it
        for the duration of the current transaction so no concurrent writer can insert with
        the same prev_hash until we commit.

        SQLite: relies on the module-level _sqlite_chain_lock (must be held by caller).
        """
        if cls._is_postgres():
            row = db.session.execute(
                text(
                    "SELECT record_hash FROM audit_logs "
                    "ORDER BY id DESC LIMIT 1 FOR UPDATE"
                )
            ).fetchone()
            return row[0] if row else GENESIS_HASH
        else:
            last_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
            return last_log.record_hash if last_log else GENESIS_HASH

    @classmethod
    def log_event(
        cls,
        action: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        status: str = "SUCCESS",
        user_id: int | None = None,
        username: str | None = None,
        details: str | None = None,
        ip_address: str | None = None,
        auto_commit: bool = True,
        tenant_id: str | None = None,
    ) -> AuditLog:
        """
        Appends an immutable security event to the audit log, chaining it with the
        preceding record's hash.

        Transaction boundary (P0-Transaction Architecture):
        - auto_commit=True (default): commits transaction immediately.
        - auto_commit=False: flushes entry into current transaction, allowing composite
          operations (mutation + audit + outbox) to commit atomically.
        """
        # Resolve user context from session if not explicitly provided
        if user_id is None and session and "user_id" in session:
            user_id = session.get("user_id")
        if username is None and session and "username" in session:
            username = session.get("username")
        if tenant_id is None and session and "tenant_id" in session:
            tenant_id = session.get("tenant_id")
        if tenant_id is None:
            tenant_id = "tenant-default"

        # Resolve IP address
        if ip_address is None:
            try:
                ip_address = cls.get_client_ip()
            except RuntimeError:
                ip_address = "127.0.0.1"

        # Sanitize details to prevent accidental PHI leakage
        if details and len(details) > 255:
            details = details[:252] + "..."
        # Clamp caller/attacker-supplied values to column widths so oversized input
        # (e.g. a 200-char login username) cannot abort the audit write on PostgreSQL.
        username = username[:80] if username else username
        resource_id = str(resource_id)[:64] if resource_id is not None else None
        resource_type = resource_type[:32] if resource_type else resource_type
        ip_address = ip_address[:45] if ip_address else ip_address
        action = action[:64]

        now_utc = datetime.now(UTC).replace(tzinfo=None)

        use_postgres = cls._is_postgres()
        chain_key = cls._chain_key()

        def _attempt_insert(prev_hash: str) -> AuditLog:
            log_entry = AuditLog(
                user_id=user_id,
                username=username,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                status=status,
                details=details,
                timestamp=now_utc,
                prev_hash=prev_hash,
                record_hash="",
                tenant_id=tenant_id,
            )
            log_entry.record_hash = log_entry.calculate_hash(chain_key)
            db.session.add(log_entry)
            db.session.flush()  # raises IntegrityError now rather than at commit
            return log_entry

        if use_postgres:
            # PostgreSQL path: use savepoints for per-retry rollback
            for attempt in range(1, MAX_CHAIN_RETRIES + 1):
                try:
                    with db.session.begin_nested():  # creates a SAVEPOINT
                        prev_hash = cls._fetch_tail_locked()
                        log_entry = _attempt_insert(prev_hash)
                    if auto_commit:
                        db.session.commit()
                    break
                except IntegrityError:
                    # begin_nested() has already rolled back to the savepoint. A full
                    # session rollback here would discard the caller's uncommitted work
                    # (e.g. the patient insert this event describes) while the audit row
                    # still commits on retry.
                    logger.warning(
                        "Audit chain conflict on attempt %d/%d for action=%s — retrying",
                        attempt, MAX_CHAIN_RETRIES, action,
                    )
                    if attempt == MAX_CHAIN_RETRIES:
                        logger.critical(
                            "AUDIT CHAIN FAILURE: all %d retries exhausted for action=%s "
                            "user=%s. Audit entry was NOT written. Immediate investigation required.",
                            MAX_CHAIN_RETRIES, action, username or "anonymous",
                        )
                        raise RuntimeError(
                            f"Audit log write failed after {MAX_CHAIN_RETRIES} retries "
                            f"(action={action}). Chain integrity could not be maintained."
                        ) from None
        else:
            # SQLite path: module-level lock serialises writers within the process
            with _sqlite_chain_lock:
                for attempt in range(1, MAX_CHAIN_RETRIES + 1):
                    try:
                        prev_hash = cls._fetch_tail_locked()
                        log_entry = _attempt_insert(prev_hash)
                        if auto_commit:
                            db.session.commit()
                        break
                    except IntegrityError:
                        db.session.rollback()
                        logger.warning(
                            "Audit chain conflict (SQLite) attempt %d/%d action=%s",
                            attempt, MAX_CHAIN_RETRIES, action,
                        )
                        if attempt == MAX_CHAIN_RETRIES:
                            logger.critical(
                                "AUDIT CHAIN FAILURE (SQLite): all retries exhausted action=%s",
                                action,
                            )
                            raise RuntimeError(
                                f"Audit log write failed after {MAX_CHAIN_RETRIES} retries "
                                f"(action={action})."
                            ) from None
                    except Exception as e:
                        db.session.rollback()
                        logger.error("Failed to commit audit log entry: %s", e)
                        raise

        # Invalidate verification memoization cache on new write
        cls.invalidate_verification_cache()

        logger.info(
            "AUDIT [%s] User=%s Action=%s Resource=%s:%s Status=%s IP=%s",
            log_entry.id, username or "anonymous", action,
            resource_type, resource_id, status, ip_address,
        )
        return log_entry

    @classmethod
    def verify_chain(cls, force_recheck: bool = False) -> tuple[bool, int | None, int, list[str]]:
        """
        Cryptographically verifies the entire audit log hash chain.
        Streams records using yield_per(1000) for bounded O(1) memory usage.
        In production, memoizes verification for 30s or until invalidated by log_event().
        Returns:
            (is_valid: bool, corrupted_record_id: Optional[int], total_records: int, error_messages: List[str])
        """
        import time
        is_testing = current_app.config.get("TESTING", False) if current_app else False
        if not force_recheck and not is_testing and cls._cached_verification is not None:
            if time.time() - cls._last_verification_time < cls._cache_ttl_seconds:
                return cls._cached_verification

        query = AuditLog.query.order_by(AuditLog.id.asc()).yield_per(1000)

        chain_key = cls._chain_key()
        expected_prev_hash = GENESIS_HASH
        errors = []
        total_records = 0
        # Unkeyed legacy hashes (v1/v2) are only accepted before the first keyed (v3)
        # record; afterwards an unkeyed hash means someone recomputed the chain without the key.
        keyed_seen = False

        for record in query:
            total_records += 1
            # 1. Verify that prev_hash matches the previous record's hash
            if record.prev_hash != expected_prev_hash:
                err = (
                    f"Chain break at record #{record.id}: "
                    f"prev_hash {record.prev_hash[:16]}... != expected {expected_prev_hash[:16]}..."
                )
                errors.append(err)
                res = (False, record.id, total_records, errors)
                cls._cached_verification = res
                cls._last_verification_time = time.time()
                return res

            # 2. Verify record_hash: keyed schema v3, or legacy v2/v1 only before the first v3 record
            recomputed_v3 = record.calculate_hash_v3(chain_key)
            if hmac.compare_digest(record.record_hash, recomputed_v3):
                keyed_seen = True
                matches = True
            elif keyed_seen:
                matches = False
            else:
                matches = (
                    hmac.compare_digest(record.record_hash, record.calculate_hash_v2())
                    or hmac.compare_digest(record.record_hash, record.calculate_hash_v1())
                )
            if not matches:
                err = (
                    f"Data tamper at record #{record.id}: "
                    f"stored hash {record.record_hash[:16]}... != recomputed {recomputed_v3[:16]}..."
                )
                errors.append(err)
                res = (False, record.id, total_records, errors)
                cls._cached_verification = res
                cls._last_verification_time = time.time()
                return res

            expected_prev_hash = record.record_hash

        res = (True, None, total_records, [])
        cls._cached_verification = res
        cls._last_verification_time = time.time()
        return res
