"""
Admin routes handling user management (FR8) and audit log inspection (FR9).
"""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.models.audit_log import AuditLog
from app.security.decorators import get_current_user, login_required, require_permission
from app.security.permissions import ALL_ROLES, AUDIT_READ, USER_MANAGE
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.user_service import UserService

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/users", methods=["GET", "POST"])
@require_permission(USER_MANAGE)
def manage_users():
    """Admin user account management: listing and creation."""
    user = get_current_user()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()
        email = request.form.get("email", "").strip()

        try:
            new_user = UserService.create_user(
                username=username,
                password=password,
                role=role,
                created_by_admin_id=user.id,
                tenant_id=user.tenant_id,
                email=email,
            )
            flash(f"User account '{new_user.username}' created successfully with role '{new_user.role}'.", "success")
            return redirect(url_for("admin.manage_users"))
        except ValueError as e:
            flash(str(e), "danger")

    users = UserService.list_users(tenant_id=user.tenant_id)
    return render_template("admin/users.html", users=users, user=user, roles=ALL_ROLES)

@admin_bp.route("/users/<int:target_user_id>/toggle", methods=["POST"])
@require_permission(USER_MANAGE)
def toggle_user(target_user_id: int):
    """Admin can disable or enable a user account. Prevents self-disable."""
    admin = get_current_user()
    try:
        updated_user = UserService.toggle_user_active(target_user_id, admin.id, tenant_id=admin.tenant_id)
        status = "activated" if updated_user.is_active else "disabled"
        flash(f"User '{updated_user.username}' has been {status}.", "info")
    except ValueError as e:
        flash(str(e), "danger")
    return redirect(url_for("admin.manage_users"))

@admin_bp.route("/settings/mfa", methods=["GET"])
@login_required
def setup_mfa():
    """MFA setup wizard for any signed-in user (mandatory for Admins): generates secret and QR-code URI."""
    from flask import session
    user = get_current_user()
    secret = session.get("pending_totp_secret")
    if not secret:
        secret = AuthService.generate_totp_secret()
        session["pending_totp_secret"] = secret

    otp_uri = AuthService.get_totp_uri(user.username, secret)
    return render_template("admin/mfa_setup.html", user=user, secret=secret, otp_uri=otp_uri)

@admin_bp.route("/settings/mfa/confirm", methods=["POST"])
@login_required
def confirm_mfa():
    """Validates 6-digit TOTP confirmation code and activates MFA on the caller's account."""
    from flask import session

    from app.extensions import db
    user = get_current_user()
    secret = session.get("pending_totp_secret")
    code = request.form.get("totp_code", "").strip()

    if not secret:
        flash("MFA session expired. Please restart the setup.", "danger")
        return redirect(url_for("admin.setup_mfa"))

    if AuthService.verify_totp(secret, code, user_id=user.id):
        user.totp_secret = secret
        user.totp_enabled = True
        db.session.commit()
        session.pop("pending_totp_secret", None)

        AuditService.log_event(
            action="MFA_ENROLL_SUCCESS",
            resource_type="USER",
            resource_id=str(user.id),
            status="SUCCESS",
            user_id=user.id,
            username=user.username,
            details=f"User '{user.username}' successfully enrolled and activated TOTP MFA"
        )
        flash("Multi-Factor Authentication has been successfully activated for your account.", "success")
        if user.role == "Admin":
            return redirect(url_for("admin.manage_users"))
        return redirect(url_for("patient.dashboard"))
    else:
        AuditService.log_event(
            action="MFA_ENROLL_FAILURE",
            resource_type="USER",
            resource_id=str(user.id),
            status="FAILURE",
            user_id=user.id,
            username=user.username,
            details=f"User '{user.username}' entered invalid TOTP code during enrollment"
        )
        flash("Invalid verification code. Please check your authenticator and try again.", "danger")
        return redirect(url_for("admin.setup_mfa"))

@admin_bp.route("/security", methods=["GET"])
@require_permission(AUDIT_READ)
def security_center():
    """Tenant-scoped security posture backed by authoritative operational records."""
    user = get_current_user()
    from app.services.security_center_service import SecurityCenterService
    posture = SecurityCenterService.get_posture(user.tenant_id)
    return render_template("admin/security_center.html", user=user, posture=posture)


@admin_bp.route("/audit", methods=["GET"])
@require_permission(AUDIT_READ)
def view_audit_log():
    """Displays immutable audit log with pagination, date-range and action-type filters."""
    user = get_current_user()

    # ── Pagination params ─────────────────────────────────────────────────
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = max(1, min(int(request.args.get("per_page", 50)), 200))
    except (ValueError, TypeError):
        per_page = 50

    # ── Filter params ─────────────────────────────────────────────────────
    action_type = request.args.get("action_type", "").strip().upper()
    date_from_str = request.args.get("date_from", "").strip()
    date_to_str = request.args.get("date_to", "").strip()

    from datetime import datetime as _dt
    date_from = None
    date_to = None
    filter_error = None
    try:
        if date_from_str:
            date_from = _dt.strptime(date_from_str, "%Y-%m-%d")
        if date_to_str:
            # Include the full end day
            date_to = _dt.strptime(date_to_str, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59
            )
    except ValueError:
        filter_error = "Invalid date format — use YYYY-MM-DD."

    # ── Build query (scoped to the admin's tenant) ────────────────────────
    query = AuditLog.query.filter(AuditLog.tenant_id == user.tenant_id).order_by(AuditLog.id.desc())

    if action_type:
        query = query.filter(AuditLog.action == action_type)
    if date_from:
        query = query.filter(AuditLog.timestamp >= date_from)
    if date_to:
        query = query.filter(AuditLog.timestamp <= date_to)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items

    # ── Distinct action types for filter dropdown ─────────────────────────
    action_types = [
        row[0] for row in
        AuditLog.query.filter(AuditLog.tenant_id == user.tenant_id)
        .with_entities(AuditLog.action).distinct().order_by(AuditLog.action).all()
    ]

    force_verify = request.args.get("verify", "").lower() in ("true", "1")
    # Verify cryptographic hash chain across audit table (uses cached checkpoint status unless force requested)
    is_valid, corrupted_id, total_records, errors = AuditService.verify_chain(force_recheck=force_verify)

    return render_template(
        "admin/audit_log.html",
        logs=logs,
        pagination=pagination,
        user=user,
        chain_valid=is_valid,
        corrupted_id=corrupted_id,
        total_records=total_records,
        chain_errors=errors,
        action_types=action_types,
        action_type=action_type,
        date_from=date_from_str,
        date_to=date_to_str,
        filter_error=filter_error,
    )
