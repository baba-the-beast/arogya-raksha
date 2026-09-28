"""
User Management Service for Admin operations (FR8): Create, disable, and list user accounts.
"""
import logging
import re

from app.extensions import db
from app.models.user import User
from app.security.permissions import ALL_ROLES
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

logger = logging.getLogger(__name__)

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,30}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")


class UserService:
    """Provides administrative user account management operations, scoped to the admin's tenant."""

    @classmethod
    def list_users(cls, tenant_id: str | None = None) -> list[User]:
        """Lists user accounts ordered by creation, restricted to tenant_id when given."""
        query = User.query
        if tenant_id is not None:
            query = query.filter(User.tenant_id == tenant_id)
        return query.order_by(User.id.asc()).all()

    @classmethod
    def get_user_by_id(cls, user_id: int) -> User | None:
        """Retrieves a user by ID."""
        return db.session.get(User, user_id)

    @classmethod
    def create_user(
        cls,
        username: str,
        password: str,
        role: str,
        created_by_admin_id: int | None = None,
        tenant_id: str = "tenant-default",
        email: str | None = None,
    ) -> User:
        """Creates a new user account in tenant_id with scrypt password hashing."""
        username = username.strip()
        if not username:
            raise ValueError("Username cannot be empty.")
        if not USERNAME_PATTERN.match(username):
            raise ValueError("Username must be 3-30 characters: letters, digits, underscores, or hyphens.")
        email = (email or "").strip() or None
        if email and (len(email) > 255 or not EMAIL_PATTERN.match(email)):
            raise ValueError("Email address is not valid.")
        if role not in ALL_ROLES:
            raise ValueError(f"Invalid role '{role}'. Allowed roles: {', '.join(ALL_ROLES)}")

        existing = User.query.filter_by(username=username).first()
        if existing:
            raise ValueError(f"Username '{username}' is already taken.")

        password_hash = AuthService.hash_password(password)

        user = User(
            username=username,
            password_hash=password_hash,
            role=role,
            email=email,
            tenant_id=tenant_id,
            is_active=True
        )

        db.session.add(user)
        db.session.flush()

        AuditService.log_event(
            action="USER_CREATE",
            resource_type="USER",
            resource_id=str(user.id),
            status="SUCCESS",
            user_id=created_by_admin_id,
            details=f"Created new user account '{username}' with role '{role}'",
            auto_commit=False,
            tenant_id=tenant_id,
        )
        db.session.commit()

        return user

    @classmethod
    def toggle_user_active(cls, user_id: int, admin_user_id: int, tenant_id: str | None = None) -> User:
        """
        Toggles a user account's active state (Enable / Disable). Prevents self-disable.
        When tenant_id is given, users outside that tenant are treated as non-existent.
        """
        if user_id == admin_user_id:
            raise ValueError("Administrators cannot disable their own account.")

        user = db.session.get(User, user_id)
        if not user or (tenant_id is not None and user.tenant_id != tenant_id):
            raise ValueError(f"User #{user_id} not found.")

        user.is_active = not user.is_active
        if not user.is_active:
            # Immediate session revocation upon account disable (Phase 4)
            user.session_version += 1

        action = "USER_ENABLE" if user.is_active else "USER_DISABLE"
        db.session.commit()

        AuditService.log_event(
            action=action,
            resource_type="USER",
            resource_id=str(user.id),
            status="SUCCESS",
            user_id=admin_user_id,
            details=f"Admin #{admin_user_id} changed user '{user.username}' status to is_active={user.is_active}"
        )

        return user

    @classmethod
    def revoke_all_sessions(cls, user_id: int) -> User:
        """
        Increments user.session_version to immediately invalidate all active sessions
        for the given user across all browsers/devices.
        """
        user = db.session.get(User, user_id)
        if not user:
            raise ValueError(f"User #{user_id} not found.")

        user.session_version += 1
        db.session.commit()

        AuditService.log_event(
            action="SESSION_REVOCATION",
            resource_type="USER",
            resource_id=str(user.id),
            status="SUCCESS",
            user_id=user.id,
            username=user.username,
            details=f"All active sessions revoked for user '{user.username}' (new version {user.session_version})"
        )
        return user
