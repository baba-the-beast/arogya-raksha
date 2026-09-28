"""
Transactional Outbox Service (P0-7).
Ensures guaranteed at-least-once asynchronous event delivery (alerts, audit events, webhooks).
"""
import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.extensions import db
from app.models.outbox import OutboxEvent

logger = logging.getLogger("outbox.service")


class OutboxService:
    """Manages transactional outbox event creation and background processing."""

    @classmethod
    def record_event(
        cls,
        event_type: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
        max_retries: int = 5,
        tenant_id: str | None = None,
    ) -> OutboxEvent:
        """
        Saves an outbox event within the current database transaction.
        Must be committed by the calling transaction to ensure atomicity.
        """
        if tenant_id is None:
            # Tenant identity is accepted only from the authenticated server-side session,
            # never from event payloads controlled by a client.
            try:
                from flask import has_request_context, session
                if has_request_context():
                    tenant_id = session.get("tenant_id")
            except RuntimeError:
                tenant_id = None
        tenant_id = tenant_id or "tenant-default"

        if idempotency_key:
            existing = OutboxEvent.query.filter_by(idempotency_key=idempotency_key).first()
            if existing:
                return existing

        event = OutboxEvent(
            tenant_id=tenant_id,
            event_type=event_type,
            payload_json=json.dumps(payload, default=str),
            status="PENDING",
            retry_count=0,
            max_retries=max_retries,
            idempotency_key=idempotency_key,
            created_at=datetime.now(UTC)
        )
        db.session.add(event)
        return event

    @classmethod
    def dispatch_event(cls, event: OutboxEvent) -> bool:
        """
        Dispatches a single outbox event to its corresponding integration destination.
        """
        payload = json.loads(event.payload_json)

        # Route by event type
        if event.event_type in ("SECURITY_ALERT", "TAMPER_DETECTED", "ACCOUNT_LOCKOUT"):
            from app.services.alert_service import AlertService
            return AlertService.trigger_alert(
                event_type=event.event_type,
                message=payload.get("message", "Outbox security event"),
                metadata=payload.get("metadata", {}),
                severity=payload.get("severity", "CRITICAL")
            )
        elif event.event_type == "PASSWORD_RESET_DISPATCH":
            return cls._dispatch_password_reset(payload)
        else:
            # Default dispatch: record audit/telemetry
            logger.info("Dispatched generic outbox event %d (%s)", event.id, event.event_type)
            return True

    @classmethod
    def _dispatch_password_reset(cls, payload: dict[str, Any]) -> bool:
        """
        Dispatches password reset instructions via the notification adapter.
        Unseals the reset token, builds the link, and delivers it out-of-band.
        Tokens that were already used or have expired are acknowledged without sending.
        """
        from flask import current_app

        from app.extensions import db
        from app.models.password_reset_token import PasswordResetToken
        from app.models.user import User
        from app.services.crypto_service import CryptoService
        from app.services.notification_service import NotificationService

        user_id = payload.get("user_id")
        token_hash = payload.get("token_hash")
        sealed = payload.get("sealed_token")
        if not (user_id and token_hash and sealed):
            logger.error("Password reset outbox payload is incomplete (user_id=%s); dropping.", user_id)
            return True

        token_record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
        user = db.session.get(User, user_id)
        if not token_record or not token_record.is_valid() or not user or not user.is_active:
            logger.info("Password reset for user_id=%s no longer valid; skipping delivery.", user_id)
            return True

        raw_token = CryptoService.open_outbox_secret(sealed, context=f"reset:{user_id}:{token_hash}")
        reset_url = f"{current_app.config.get('APP_BASE_URL', '').rstrip('/')}/reset-password/{raw_token}"
        return NotificationService.send_password_reset(user.username, user.email, reset_url)

    @classmethod
    def process_pending_events(cls, batch_size: int = 50) -> int:
        """
        Processes a batch of pending or retryable failed outbox events using a non-blocking
        claim-and-release worker pattern (Section 35).
        1. Atomically claims rows using FOR UPDATE SKIP LOCKED (or SQLite table locks).
        2. Sets status='CLAIMED' and immediately commits to release database connection locks.
        3. Executes external HTTP / delivery integrations outside of database transactions.
        4. Atomically commits outcomes (PROCESSED or FAILED/DEAD_LETTER) with jittered exponential backoff.
        Returns the number of successfully processed events.
        """
        import secrets
        from datetime import timedelta

        now = datetime.now(UTC)
        lease_timeout = timedelta(seconds=120)

        # ── Phase 1: Atomic Claim ─────────────────────────────────────────
        query = OutboxEvent.query.filter(
            (OutboxEvent.status.in_(["PENDING", "FAILED"])) |
            ((OutboxEvent.status == "CLAIMED") & (OutboxEvent.last_attempt_at < now - lease_timeout)),
            OutboxEvent.retry_count < OutboxEvent.max_retries
        ).order_by(OutboxEvent.created_at.asc())

        try:
            if db.engine.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
        except Exception as e:
            logger.debug("Database dialect check skipped: %s", e)

        raw_events = query.limit(batch_size).all()
        if not raw_events:
            return 0

        eligible_events = []
        for event in raw_events:
            if event.retry_count > 0 and event.last_attempt_at and event.status != "CLAIMED":
                jitter = secrets.choice([0.1, 0.2, 0.3, 0.4, 0.5])
                backoff_seconds = (2 ** min(event.retry_count, 6)) + jitter
                last_attempt = event.last_attempt_at
                if last_attempt.tzinfo is None:
                    last_attempt = last_attempt.replace(tzinfo=UTC)
                if now < last_attempt + timedelta(seconds=backoff_seconds):
                    continue

            event.status = "CLAIMED"
            event.last_attempt_at = now
            eligible_events.append(event)

        # Release database locks before performing external HTTP/delivery calls
        db.session.commit()

        # ── Phase 2: External Dispatch & Outcome Recording ────────────────
        successful = 0
        for event in eligible_events:
            delivery_ok = False
            err_msg = None
            try:
                delivery_ok = cls.dispatch_event(event)
            except Exception as e:
                logger.exception("Error during external dispatch of outbox event %d", event.id)
                err_msg = str(e)

            # Update outcome in separate quick transaction
            event_row = db.session.get(OutboxEvent, event.id)
            if not event_row:
                continue

            if delivery_ok:
                event_row.status = "PROCESSED"
                event_row.processed_at = datetime.now(UTC)
                event_row.error_log = None
                successful += 1
            else:
                event_row.retry_count += 1
                if event_row.retry_count >= event_row.max_retries:
                    event_row.status = "DEAD_LETTER"
                else:
                    event_row.status = "FAILED"
                raw_err = err_msg or "Delivery returned False"
                if len(raw_err) > 255:
                    raw_err = raw_err[:252] + "..."
                event_row.error_log = raw_err

            db.session.commit()

        return successful
