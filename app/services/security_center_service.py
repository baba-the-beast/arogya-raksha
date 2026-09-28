"""Tenant-scoped operational security posture aggregation."""
from datetime import UTC, datetime, timedelta

from flask import current_app, session
from sqlalchemy import func

from app.models.audit_log import AuditLog
from app.models.outbox import OutboxEvent
from app.models.user import User
from app.security.session_store import RedisSessionStore, get_session_store
from app.services.audit_service import AuditService


class SecurityCenterService:
    """Builds a read-only security view without exposing secrets or raw payloads."""

    FLAGGED = ("FAILURE", "DENIED", "BLOCKED", "ALERT")

    @classmethod
    def get_posture(cls, tenant_id: str) -> dict:
        now = datetime.now(UTC).replace(tzinfo=None)
        since = now - timedelta(hours=24)

        users = User.query.filter(User.tenant_id == tenant_id)
        active_users = users.filter(User.is_active.is_(True))
        active_count = active_users.count()
        mfa_count = active_users.filter(User.totp_enabled.is_(True)).count()

        logs = AuditLog.query.filter(AuditLog.tenant_id == tenant_id)
        flagged = logs.filter(AuditLog.status.in_(cls.FLAGGED), AuditLog.timestamp >= since)
        auth_failures = logs.filter(
            AuditLog.timestamp >= since,
            AuditLog.action.in_(("LOGIN_FAILURE", "MFA_FAILURE", "ACCOUNT_LOCKOUT")),
        ).count()
        denials = logs.filter(
            AuditLog.timestamp >= since,
            AuditLog.status.in_(("DENIED", "BLOCKED")),
        ).count()
        emergency = logs.filter(
            AuditLog.timestamp >= since,
            AuditLog.action.like("%BREAK_GLASS%"),
        ).count()

        outbox = OutboxEvent.query.filter(OutboxEvent.tenant_id == tenant_id)
        queue_counts = dict(
            outbox.with_entities(OutboxEvent.status, func.count(OutboxEvent.id))
            .group_by(OutboxEvent.status).all()
        )
        pending = queue_counts.get("PENDING", 0) + queue_counts.get("CLAIMED", 0)
        failed = queue_counts.get("FAILED", 0)
        dead_letter = queue_counts.get("DEAD_LETTER", 0)

        chain_valid, broken_id, chain_total, chain_errors = AuditService.verify_chain()
        session_health = cls._session_health()

        if not chain_valid or dead_letter:
            overall = "critical"
        elif failed or flagged.count() or (active_count and mfa_count < active_count) or not session_health["available"]:
            overall = "attention"
        else:
            overall = "protected"

        recent_events = flagged.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(12).all()
        return {
            "overall": overall,
            "generated_at": now,
            "window_hours": 24,
            "authentication": {
                "failures": auth_failures,
                "denials": denials,
                "active_users": active_count,
            },
            "mfa": {
                "enabled": mfa_count,
                "eligible": active_count,
                "coverage": round((mfa_count / active_count) * 100) if active_count else 100,
            },
            "sessions": session_health,
            "outbox": {
                "pending": pending,
                "failed": failed,
                "dead_letter": dead_letter,
                "processed": queue_counts.get("PROCESSED", 0),
            },
            "audit": {
                "valid": chain_valid,
                "total": chain_total,
                "broken_id": broken_id,
                "errors": chain_errors[:3],
            },
            "events": {
                "flagged": flagged.count(),
                "emergency": emergency,
                "recent": recent_events,
            },
        }

    @staticmethod
    def _session_health() -> dict:
        store = get_session_store()
        backend = "Distributed Redis" if isinstance(store, RedisSessionStore) else "Local development store"
        available = True
        if isinstance(store, RedisSessionStore):
            try:
                available = bool(store._get_client().ping())
            except Exception:
                available = False

        server_data = getattr(session, "server_data", None)
        return {
            "available": available,
            "backend": backend,
            "mfa_verified": bool(getattr(server_data, "mfa_state", None) == "VERIFIED" or session.get("mfa_state") == "VERIFIED"),
            "idle_minutes": max(1, current_app.config.get("SESSION_IDLE_TIMEOUT_SECONDS", 900) // 60),
            "absolute_hours": max(1, current_app.config.get("SESSION_ABSOLUTE_TIMEOUT_SECONDS", 28800) // 3600),
        }
