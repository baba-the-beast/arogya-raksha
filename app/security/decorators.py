"""
Security and RBAC decorators enforcing server-side authentication and authorization.
"""
from functools import wraps

from flask import abort, has_request_context, redirect, request, session, url_for

from app.models.user import User
from app.security.permissions import has_permission
from app.services.audit_service import AuditService


def get_current_user():
    """
    Fetches currently authenticated user model or None.
    Memoizes resolution on Flask request._cached_user within active request context
    to eliminate redundant DB roundtrips and session lookups across multiple decorators,
    route handlers, and template context processors without bleeding into outer app contexts.
    """
    if has_request_context() and hasattr(request, "_cached_user"):
        return request._cached_user

    user = _resolve_current_user()
    if has_request_context():
        request._cached_user = user
    return user


def _resolve_current_user():
    # Ensure MFA state is not pending
    auth_state = session.get("auth_state")
    if auth_state == "MFA_PENDING":
        return None

    user_id = session.get("user_id")
    if not user_id:
        return None
    from app.extensions import db
    user = db.session.get(User, user_id)
    if not user or not user.is_active:
        # Clear invalid or disabled session
        session.clear()
        return None

    # Server-side session revocation check (Phase 4)
    sess_version = session.get("session_version")
    if sess_version is None or sess_version != user.session_version:
        session.clear()
        return None

    return user

def login_required(f):
    """Enforces that caller is authenticated before accessing the endpoint."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            # Audit unauthenticated attempt
            AuditService.log_event(
                action="UNAUTHENTICATED_ACCESS",
                resource_type="ENDPOINT",
                resource_id=request.path,
                status="DENIED",
                details="Unauthenticated attempt to access protected resource"
            )
            if request.is_json or request.path.startswith("/api/"):
                abort(401)
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def require_permission(permission_name: str):
    """
    Enforces that the authenticated user possesses the specific RBAC permission.
    Rejects unauthorized access with HTTP 403 and records an audit log entry.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                AuditService.log_event(
                    action="UNAUTHENTICATED_ACCESS",
                    resource_type=permission_name,
                    resource_id=request.path,
                    status="DENIED",
                    details=f"Unauthenticated attempt to access permission {permission_name}"
                )
                if request.is_json or request.path.startswith("/api/"):
                    abort(401)
                return redirect(url_for("auth.login", next=request.url))

            if not has_permission(user.role, permission_name):
                # Hard-deny: write audit log and abort 403 Forbidden
                AuditService.log_event(
                    action="ACCESS_DENIED",
                    resource_type="PERMISSION",
                    resource_id=permission_name,
                    status="DENIED",
                    user_id=user.id,
                    username=user.username,
                    details=f"User '{user.username}' with role '{user.role}' denied permission '{permission_name}' at {request.path}",
                    tenant_id=getattr(user, "tenant_id", "tenant-default")
                )
                abort(403)

            # Option A Grace Login: Admin must set up MFA before accessing general admin functions
            if user.role == "Admin" and not user.totp_enabled:
                from flask import current_app
                if current_app.config.get("MFA_ENFORCE_ADMIN", True):
                    if request.endpoint not in ("admin.setup_mfa", "admin.confirm_mfa", "auth.logout", "static"):
                        return redirect(url_for("admin.setup_mfa"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_resource_permission(action: str):
    """
    Evaluates resource-level authorization (ABAC) and tenant isolation via PolicyEngine.
    Action: 'READ', 'UPDATE', 'CREATE', 'DELETE'
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                abort(401)

            from app.extensions import db
            from app.models.patient import Patient
            from app.security.policy import PolicyEngine

            record_id = kwargs.get("record_id")
            patient = db.session.get(Patient, record_id) if record_id else None
            if record_id and not patient:
                abort(404)

            json_reason = None
            if request.is_json:
                json_data = request.get_json(silent=True)
                if isinstance(json_data, dict):
                    json_reason = json_data.get("break_glass_reason")
            break_glass_reason = (
                request.form.get("break_glass_reason")
                or request.args.get("break_glass_reason")
                or json_reason
            )
            decision = PolicyEngine.authorize_patient_access(
                user=user,
                patient=patient,
                action=action,
                break_glass_reason=break_glass_reason
            )

            if not decision.allowed:
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator
