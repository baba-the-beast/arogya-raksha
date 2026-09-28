import hashlib
import hmac
import json
from datetime import UTC, datetime

from sqlalchemy import Index, UniqueConstraint

from app.extensions import db

GENESIS_HASH = "0" * 64

class AuditLog(db.Model):
    """
    Immutable audit log model with cryptographic hash-chaining.
    Every security-relevant event is recorded and sealed with SHA-256(prev_hash + fields).

    Concurrency safety: prev_hash has a UNIQUE constraint so that concurrent inserts
    racing to append the same chain tail will produce an IntegrityError on the loser,
    which AuditService.log_event() catches and retries with the updated tail.
    """
    __tablename__ = "audit_logs"
    __table_args__ = (
        UniqueConstraint("prev_hash", name="uq_audit_logs_prev_hash"),
        # Composite index for admin audit filter queries (Phase 2)
        Index("ix_audit_logs_action_timestamp", "action", "timestamp"),
    )

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(32), db.ForeignKey("tenants.id"), nullable=True, default="tenant-default", index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(80), nullable=True)  # Captured even for failed logins
    action = db.Column(db.String(64), nullable=False, index=True)
    resource_type = db.Column(db.String(32), nullable=True)
    resource_id = db.Column(db.String(64), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # "SUCCESS", "FAILURE", "DENIED", "ALERT"
    details = db.Column(db.String(255), nullable=True) # NEVER sensitive data, only operational notes
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False, index=True)

    # Tamper-evident Hash Chain fields
    prev_hash = db.Column(db.String(64), nullable=False)
    record_hash = db.Column(db.String(64), nullable=False)

    user = db.relationship("User", foreign_keys=[user_id])
    tenant = db.relationship("Tenant", foreign_keys=[tenant_id])

    def calculate_hash_v1(self) -> str:
        """Legacy v1 delimiter-concatenation SHA-256 digest."""
        if self.timestamp:
            ts_clean = self.timestamp.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts_clean = ""
        payload = (
            f"{self.prev_hash}|{self.user_id or ''}|{self.username or ''}|{self.action}|"
            f"{self.resource_type or ''}|{self.resource_id or ''}|{self.ip_address or ''}|"
            f"{self.status}|{self.details or ''}|{self.tenant_id or ''}|{ts_clean}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _canonical_bytes(self, schema_version: int) -> bytes:
        ts_clean = self.timestamp.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else ""
        canonical_dict = {
            "action": self.action,
            "details": self.details or "",
            "ip_address": self.ip_address or "",
            "prev_hash": self.prev_hash,
            "resource_id": self.resource_id or "",
            "resource_type": self.resource_type or "",
            "schema_version": schema_version,
            "status": self.status,
            "tenant_id": self.tenant_id or "tenant-default",
            "timestamp": ts_clean,
            "user_id": self.user_id,
            "username": self.username or "",
        }
        canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return canonical_json.encode("utf-8")

    def calculate_hash_v2(self) -> str:
        """Legacy RFC 8785 canonical JSON unkeyed SHA-256 digest (schema v2)."""
        return hashlib.sha256(self._canonical_bytes(2)).hexdigest()

    def calculate_hash_v3(self, key: bytes) -> str:
        """
        Keyed HMAC-SHA256 digest over canonical JSON (schema v3). Without the key, an attacker
        with database write access cannot recompute a valid chain after editing or deleting rows.
        """
        return hmac.new(key, self._canonical_bytes(3), hashlib.sha256).hexdigest()

    def calculate_hash(self, key: bytes) -> str:
        """Calculates the authoritative digest for new records (keyed schema v3)."""
        return self.calculate_hash_v3(key)

    def __repr__(self):
        return f"<AuditLog #{self.id} {self.action} by {self.username} [{self.status}]>"
