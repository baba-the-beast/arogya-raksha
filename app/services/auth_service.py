"""
Authentication Service managing user credentials, scrypt password verification, session fixation protection, and login/logout auditing.
"""
import hashlib
import logging
import re
import secrets
from datetime import UTC, datetime

from flask import current_app, has_app_context, has_request_context, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.models.user import User
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

class AuthService:
    """Provides secure authentication operations."""

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hashes password using scrypt (memory-hard, resistant to GPU/ASIC brute forcing).
        Validates password complexity and bounds (BUG-08):
        - Minimum length (config PASSWORD_MIN_LENGTH, default 8)
        - Maximum length (128 characters to prevent DoS against scrypt's memory cost)
        - At least 1 uppercase letter, 1 lowercase letter, 1 digit.
        """
        from app.config import Config

        if not password:
            raise ValueError("Password cannot be empty.")

        if has_app_context():
            min_length = current_app.config.get("PASSWORD_MIN_LENGTH", Config.PASSWORD_MIN_LENGTH)
            max_length = current_app.config.get("PASSWORD_MAX_LENGTH", Config.PASSWORD_MAX_LENGTH)
        else:
            min_length = Config.PASSWORD_MIN_LENGTH
            max_length = Config.PASSWORD_MAX_LENGTH

        if len(password) < min_length:
            raise ValueError(f"Password must be at least {min_length} characters long.")
        if len(password) > max_length:
            raise ValueError(f"Password cannot exceed {max_length} characters.")
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", password):
            raise ValueError("Password must contain at least one digit.")

        return generate_password_hash(password, method="scrypt")

    DUMMY_SCRYPT_HASH = generate_password_hash("dummy_constant_time_pass", method="scrypt")

    @staticmethod
    def verify_password(password_hash: str, password: str) -> bool:
        """Verifies candidate password against stored scrypt hash using constant-time comparison."""
        if not password_hash or not password:
            return False
        return check_password_hash(password_hash, password)

    @classmethod
    def authenticate_user(
        cls,
        username: str,
        password: str,
        ip_address: str | None = None,
        establish_session: bool = True
    ) -> tuple[User | None, str | None]:
        """
        Authenticates a user by username and password.
        Uses constant-time comparison on dummy hash when user is non-existent to eliminate user enumeration timing vectors.
        """
        if not username or not password:
            return None, "Username and password are required."

        user = User.query.filter_by(username=username).first()

        if not user:
            # Timing attack mitigation: compute scrypt verification on dummy hash
            cls.verify_password(cls.DUMMY_SCRYPT_HASH, password)
            AuditService.log_event(
                action="LOGIN_FAILURE",
                resource_type="AUTH",
                resource_id=username,
                status="FAILURE",
                username=username,
                details="Invalid credentials provided",
                ip_address=ip_address
            )
            return None, "Invalid username or password."

        if not cls.verify_password(user.password_hash, password):
            AuditService.log_event(
                action="LOGIN_FAILURE",
                resource_type="AUTH",
                resource_id=username,
                status="FAILURE",
                username=username,
                details="Invalid credentials provided",
                ip_address=ip_address
            )
            return None, "Invalid username or password."

        if not user.is_active:
            AuditService.log_event(
                action="LOGIN_FAILURE",
                resource_type="AUTH",
                resource_id=username,
                status="DENIED",
                user_id=user.id,
                username=user.username,
                details="Account is disabled",
                ip_address=ip_address
            )
            return None, "Account has been disabled. Please contact the administrator."

        if establish_session:
            cls.establish_user_session(user, ip_address=ip_address)

        return user, None

    @classmethod
    def establish_user_session(cls, user: User, ip_address: str | None = None) -> None:
        """
        Sets authenticated session variables with server-side state,
        rotates session ID (session fixation defense), and commits last_login_at timestamp.
        """
        session.clear()
        if hasattr(session, "regenerate"):
            session.regenerate()
        else:
            session["_sid"] = secrets.token_hex(32)
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role
        session["tenant_id"] = getattr(user, "tenant_id", "tenant-default") or "tenant-default"
        session["session_version"] = user.session_version
        session["auth_state"] = "FULLY_AUTHENTICATED"
        session["mfa_state"] = "VERIFIED" if user.totp_enabled else None
        session.permanent = True

        user.last_login_at = datetime.now(UTC)
        db.session.commit()

        AuditService.log_event(
            action="LOGIN_SUCCESS",
            resource_type="AUTH",
            resource_id=str(user.id),
            status="SUCCESS",
            user_id=user.id,
            username=user.username,
            details=f"Successful authentication for role {user.role}",
            ip_address=ip_address,
            tenant_id=getattr(user, "tenant_id", "tenant-default")
        )

    @classmethod
    def logout_user(cls) -> None:
        """Terminates session and records audit event."""
        user_id = session.get("user_id")
        username = session.get("username")

        if user_id:
            AuditService.log_event(
                action="LOGOUT",
                resource_type="AUTH",
                resource_id=str(user_id),
                status="SUCCESS",
                user_id=user_id,
                username=username,
                details="User logged out"
            )

        session.clear()
        if has_request_context() and hasattr(request, "_cached_user"):
            request._cached_user = None

    # ── Multi-Factor Authentication (TOTP / RFC 6238) ───────────────────────

    @staticmethod
    def generate_totp_secret() -> str:
        """Generates a high-entropy Base32 secret for TOTP MFA."""
        import pyotp
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(username: str, secret: str) -> str:
        """Generates standard otpauth:// URI for authenticator app enrollment."""
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name="ArogyaRaksha")

    @classmethod
    def clear_consumed_totp_codes(cls) -> None:
        """Utility to clear consumed replay cache (used in test fixtures)."""
        from app.services.cache_service import CacheService
        CacheService.clear_memory()

    @classmethod
    def verify_totp(cls, secret: str, code: str, user_id: int | str | None = None) -> bool:
        """
        Verifies a 6-digit TOTP code against the user's secret (RFC 6238 / ASVS V2.8).
        Allows 1-step window (±30 seconds) clock drift.
        Enforces one-time-use replay prevention: once verified for a user, that same
        code cannot be used again within the 90-second validity window.
        """
        import pyotp
        if not secret or not code:
            return False
        cleaned_code = code.strip().replace(" ", "")
        totp = pyotp.TOTP(secret)
        is_valid = bool(totp.verify(cleaned_code, valid_window=1))
        if not is_valid:
            return False

        if user_id is not None:
            from app.services.cache_service import CacheService, CacheUnavailableError
            replay_key = f"totp_consumed:{user_id}:{cleaned_code}"

            # Atomic check-and-consume (SET NX) with 90s TTL covering the ±30s validity window.
            # Fails closed: if the replay cache is unreachable the code is rejected.
            try:
                first_use = CacheService.add_if_absent(replay_key, True, ttl_seconds=90)
            except CacheUnavailableError:
                logger.error("TOTP replay cache unavailable; rejecting code for user_id=%s", user_id)
                return False
            if not first_use:
                logger.warning(
                    "SECURITY ALERT: TOTP replay attempt detected for user_id=%s with code=%s",
                    user_id, cleaned_code[:2] + "****"
                )
                return False

        return True

    # ── Password Reset Flow (Phase 4) ───────────────────────────────────────

    @classmethod
    def create_password_reset_token(cls, username: str) -> str | None:
        """
        Generates a secure, single-use password reset token with 15-minute expiration.
        Stores SHA-256 hash of token in the database.
        Returns the raw token string (or None if user not found).
        """
        from datetime import timedelta

        from app.models.password_reset_token import PasswordResetToken

        user = User.query.filter_by(username=username.strip()).first()
        if not user or not user.is_active:
            # Audit the attempt but don't leak non-existence
            AuditService.log_event(
                action="PASSWORD_RESET_ATTEMPT",
                resource_type="USER",
                resource_id=username.strip() or "anonymous",
                status="DENIED",
                details="Password reset requested for non-existent or inactive user"
            )
            return None

        # Generate 32-byte cryptographically secure random token
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=15)

        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            used=False
        )
        db.session.add(reset_token)

        # Dispatch reset token via outbox for out-of-band delivery. The raw token is needed by
        # the dispatcher to build the link, so it is sealed with AES-256-GCM (purpose-separated
        # key, AAD bound to user + token hash) rather than stored in plaintext.
        from app.services.crypto_service import CryptoService
        from app.services.outbox_service import OutboxService
        sealed = CryptoService.seal_outbox_secret(raw_token, context=f"reset:{user.id}:{token_hash}")
        OutboxService.record_event(
            event_type="PASSWORD_RESET_DISPATCH",
            payload={
                "user_id": user.id,
                "username": user.username,
                "token_hash": token_hash,
                "sealed_token": sealed,
                "expires_at": expires_at.isoformat()
            }
        )

        AuditService.log_event(
            action="PASSWORD_RESET_REQUESTED",
            resource_type="USER",
            resource_id=str(user.id),
            status="SUCCESS",
            user_id=user.id,
            username=user.username,
            details=f"Password reset token issued for user '{user.username}', expires in 15m",
            auto_commit=False,
            tenant_id=getattr(user, "tenant_id", "tenant-default")
        )
        db.session.commit()
        return raw_token

    @classmethod
    def verify_and_use_password_reset_token(cls, raw_token: str, new_password: str) -> tuple[bool, str]:
        """
        Atomically validates and consumes reset token using compare-and-swap update.
        Enforces password complexity, increments session_version (revoking all live sessions),
        invalidates other outstanding tokens for the user, and records audit event.
        """
        from app.models.password_reset_token import PasswordResetToken

        if not raw_token:
            return False, "Invalid or missing reset token."

        token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
        now_utc = datetime.now(UTC).replace(tzinfo=None)

        # Atomic compare-and-swap: exactly one concurrent request can consume this token
        affected = (
            PasswordResetToken.query.filter(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.used.is_(False),
                PasswordResetToken.expires_at > now_utc
            ).update({"used": True}, synchronize_session=False)
        )

        if affected != 1:
            db.session.rollback()
            return False, "This password reset link is invalid or has expired."

        # Fetch the token record to find user_id
        token_record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
        if not token_record:
            db.session.rollback()
            return False, "This password reset link is invalid or has expired."

        user = db.session.get(User, token_record.user_id)
        if not user or not user.is_active:
            db.session.rollback()
            return False, "Associated user account is invalid or inactive."

        # Validate complexity and hash new password
        try:
            new_hash = cls.hash_password(new_password)
        except ValueError as e:
            db.session.rollback()
            return False, str(e)

        # Update credentials and revoke all active sessions
        user.password_hash = new_hash
        user.session_version += 1

        # Invalidate any other outstanding reset tokens for this user
        PasswordResetToken.query.filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used.is_(False)
        ).update({"used": True}, synchronize_session=False)

        AuditService.log_event(
            action="PASSWORD_RESET_SUCCESS",
            resource_type="USER",
            resource_id=str(user.id),
            status="SUCCESS",
            user_id=user.id,
            username=user.username,
            details=f"Password reset successfully for user '{user.username}'. All sessions revoked.",
            auto_commit=False,
            tenant_id=getattr(user, "tenant_id", "tenant-default")
        )
        db.session.commit()
        return True, "Password has been successfully updated. You may now log in."
