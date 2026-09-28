from datetime import UTC, datetime

from app.extensions import db


class User(db.Model):
    """User account model for authentication and RBAC."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    # Out-of-band contact for password reset delivery
    email = db.Column(db.String(255), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # "Doctor", "Nurse", "Admin"
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    tenant_id = db.Column(db.String(32), db.ForeignKey("tenants.id"), default="tenant-default", nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    # Incremented on disable/forced-logout to immediately invalidate all live sessions (Phase 4)
    session_version = db.Column(db.Integer, default=1, nullable=False)

    # Multi-Factor Authentication (Phase 4 & P0-4: Encrypted at Rest using AES-256-GCM)
    totp_secret_encrypted = db.Column(db.String(255), nullable=True)
    totp_secret_nonce = db.Column(db.String(64), nullable=True)
    totp_secret_tag = db.Column(db.String(64), nullable=True)
    totp_key_version = db.Column(db.Integer, default=1, nullable=False)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, **kwargs):
        # Allow setting totp_secret through constructor cleanly
        totp_secret_val = kwargs.pop("totp_secret", None)
        super().__init__(**kwargs)
        if totp_secret_val is not None:
            self.totp_secret = totp_secret_val

    @property
    def totp_secret(self) -> str | None:
        """
        Decrypts and returns the Base32 TOTP secret from authenticated storage.
        Distinguishes explicitly between:
          - Not enrolled: returns None (no ciphertext present)
          - Corrupted/Tampered: raises IntegrityTamperedError (never masks as unconfigured)
        """
        if self.totp_secret_encrypted and self.totp_secret_nonce and self.totp_secret_tag:
            from app.services.crypto_service import CryptoService, IntegrityTamperedError
            try:
                return CryptoService.decrypt_totp_secret(
                    self.totp_secret_encrypted,
                    self.totp_secret_nonce,
                    self.totp_secret_tag,
                    key_version=getattr(self, "totp_key_version", 1)
                )
            except IntegrityTamperedError:
                import logging
                logging.getLogger("security.mfa").critical(
                    "SECURITY CRITICAL: TOTP secret MAC failure or tamper detected for user_id=%s", self.id
                )
                raise
            except Exception as e:
                import logging
                logging.getLogger("security.mfa").error(
                    "TOTP secret decryption failed for user_id=%s: %s", self.id, e
                )
                raise
        return None

    @totp_secret.setter
    def totp_secret(self, plaintext_secret: str | None) -> None:
        """Encrypts raw Base32 TOTP secret using AES-256-GCM before database write."""
        if not plaintext_secret:
            self.totp_secret_encrypted = None
            self.totp_secret_nonce = None
            self.totp_secret_tag = None
            return

        from app.services.crypto_service import CryptoService
        # Encrypt under the currently active key version (not a hard-coded v1) and record it,
        # so TOTP secrets follow key rotation like every other encrypted asset.
        key_version = CryptoService.get_key_provider().current_version(purpose="totp_secret")
        enc, nonce, tag = CryptoService.encrypt_totp_secret(plaintext_secret, key_version=key_version)
        self.totp_key_version = key_version
        self.totp_secret_encrypted = enc
        self.totp_secret_nonce = nonce
        self.totp_secret_tag = tag
        self._legacy_totp_secret = None  # Ensure plaintext is never persisted

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "session_version": self.session_version,
        }
