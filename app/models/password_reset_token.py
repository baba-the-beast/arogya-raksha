"""
Password Reset Token Model (Phase 4).
Stores cryptographic hashes of one-time password reset tokens with strict expiry and usage flags.
"""
from datetime import UTC, datetime

from sqlalchemy import Index

from app.extensions import db


class PasswordResetToken(db.Model):
    """Stores hashed tokens for password reset verification."""
    __tablename__ = "password_reset_tokens"
    __table_args__ = (
        Index("ix_password_reset_tokens_user_expires", "user_id", "expires_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship("User", backref=db.backref("password_reset_tokens", lazy="dynamic"))

    def is_valid(self) -> bool:
        """Returns True if the token has not been used and has not expired."""
        now = datetime.now(UTC).replace(tzinfo=None)
        exp = self.expires_at.replace(tzinfo=None) if self.expires_at else now
        return (not self.used) and (now < exp)

    def __repr__(self):
        return f"<PasswordResetToken user_id={self.user_id} used={self.used}>"
