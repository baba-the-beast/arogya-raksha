"""
Transactional Outbox model ensuring atomic event durability and reliable delivery.
"""
from datetime import UTC, datetime

from app.extensions import db


class OutboxEvent(db.Model):
    """
    Transactional Outbox event for reliable, at-least-once delivery of notifications,
    security alerts, and external integration events (P0-7).
    """
    __tablename__ = "outbox_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    payload_json = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(32), default="PENDING", nullable=False, index=True)  # PENDING, PROCESSED, FAILED, DEAD_LETTER
    retry_count = db.Column(db.Integer, default=0, nullable=False)
    max_retries = db.Column(db.Integer, default=5, nullable=False)
    idempotency_key = db.Column(db.String(128), unique=True, nullable=True, index=True)
    error_log = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    processed_at = db.Column(db.DateTime, nullable=True)
    last_attempt_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<OutboxEvent {self.id}: {self.event_type} [{self.status}]>"
