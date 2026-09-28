"""
Patient routes handling clinical record CRUD operations under strict server-side RBAC.
"""
import logging
import os

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.security.decorators import get_current_user, require_permission, require_resource_permission
from app.security.permissions import PATIENT_CREATE, PATIENT_DELETE, PATIENT_READ, PATIENT_UPDATE, has_permission
from app.security.policy import AUTHORIZED_BREAK_GLASS_REASONS, PolicyEngine
from app.services.crypto_service import IntegrityTamperedError
from app.services.patient_service import ConcurrencyConflictError, PatientService

logger = logging.getLogger(__name__)

patient_bp = Blueprint("patient", __name__)


def _tamper_demo_enabled() -> bool:
    """The viva tamper simulation is opt-in (ENABLE_TAMPER_DEMO) and never available in production."""
    flask_env = os.getenv("FLASK_ENV", "").lower() or os.getenv("ENV", "").lower()
    if flask_env == "production" or current_app.config.get("ENV") == "production":
        return False
    return bool(current_app.config.get("ENABLE_TAMPER_DEMO", False))

@patient_bp.route("/")
def landing_page():
    """Entry point: signed-in users go to Home, everyone else to sign-in."""
    if get_current_user():
        return redirect(url_for("patient.dashboard"))
    return redirect(url_for("auth.login"))

@patient_bp.route("/dashboard")
def dashboard():
    """Role-aware home: caseload for clinicians, accounts and security events for admins."""
    user = get_current_user()
    if not user:
        return redirect(url_for("auth.login"))

    summary = None
    admin = None
    if user.role in ("Doctor", "Nurse"):
        summary = PatientService.dashboard_summary(user)
    elif user.role == "Admin":
        from datetime import UTC, datetime, timedelta

        from app.models.audit_log import AuditLog
        from app.models.user import User
        since = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=24)
        tenant_logs = AuditLog.query.filter(AuditLog.tenant_id == user.tenant_id)
        flagged = tenant_logs.filter(AuditLog.status.in_(("FAILURE", "DENIED", "BLOCKED", "ALERT")))
        users = User.query.filter(User.tenant_id == user.tenant_id)
        admin = {
            "active_users": users.filter(User.is_active.is_(True)).count(),
            "disabled_users": users.filter(User.is_active.is_(False)).count(),
            "without_mfa": users.filter(User.is_active.is_(True), User.totp_enabled.is_(False)).count(),
            "flagged_24h": flagged.filter(AuditLog.timestamp >= since).count(),
            "recent_flagged": flagged.order_by(AuditLog.id.desc()).limit(6).all(),
        }
    # Expose only non-sensitive, server-verified controls. This is deliberately derived on
    # the backend rather than claimed by client-side UI, and never includes key material.
    security_posture = {
        "encryption": bool(current_app.config.get("MASTER_ENCRYPTION_KEY")),
        "mfa": bool(user.totp_enabled),
        "secure_transport": bool(current_app.config.get("SESSION_COOKIE_SECURE")) or current_app.debug,
        "session_minutes": max(1, current_app.config.get("SESSION_IDLE_TIMEOUT_SECONDS", 900) // 60),
    }
    security_posture["score"] = sum((
        security_posture["encryption"], security_posture["mfa"], security_posture["secure_transport"]
    ))
    return render_template(
        "dashboard/index.html", user=user, summary=summary, admin=admin,
        security_posture=security_posture,
    )

@patient_bp.route("/patients", methods=["GET"])
@require_permission(PATIENT_READ)
def list_patients():
    """Lists patients (clear fields only) with server-side pagination and search."""
    user = get_current_user()
    can_create = has_permission(user.role, PATIENT_CREATE)
    can_update = has_permission(user.role, PATIENT_UPDATE)
    can_delete = has_permission(user.role, PATIENT_DELETE)

    # Query params for pagination and server-side filtering
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = max(1, min(int(request.args.get("per_page", 25)), 100))
    except (ValueError, TypeError):
        per_page = 25

    q = request.args.get("q", "").strip()
    age_band = request.args.get("age_band", "").strip()
    gender = request.args.get("gender", "").strip()
    user_tenant = getattr(user, "tenant_id", "tenant-default") or "tenant-default"

    pagination = PatientService.list_patients(
        page=page, per_page=per_page, q=q, age_band=age_band, gender=gender, tenant_id=user_tenant
    )

    return render_template(
        "patient/list.html",
        pagination=pagination,
        patients=pagination.items,  # kept for backward-compat with template
        user=user,
        can_create=can_create,
        can_update=can_update,
        can_delete=can_delete,
        q=q,
        age_band=age_band,
        gender=gender,
    )

@patient_bp.route("/patients/new", methods=["GET", "POST"])
@require_permission(PATIENT_CREATE)
def create_patient():
    """Enforces PATIENT_CREATE permission and encrypts sensitive fields at rest."""
    user = get_current_user()

    if request.method == "POST":
        patient_id = request.form.get("patient_id", "").strip()
        age_band = request.form.get("age_band", "").strip()
        gender = request.form.get("gender", "").strip()
        name = request.form.get("name", "").strip()
        diagnosis = request.form.get("diagnosis", "").strip()
        medical_history = request.form.get("medical_history", "").strip()
        notes = request.form.get("notes", "").strip()
        user_tenant = getattr(user, "tenant_id", "tenant-default") or "tenant-default"
        assigned_raw = request.form.get("assigned_doctor_id", "").strip()
        assigned_doctor_id = int(assigned_raw) if assigned_raw.isdigit() else None
        doctors = PatientService.list_assignable_doctors(user_tenant)

        try:
            patient = PatientService.create_patient(
                patient_id=patient_id,
                age_band=age_band,
                gender=gender,
                name=name,
                diagnosis=diagnosis,
                medical_history=medical_history,
                notes=notes,
                created_by_user_id=user.id,
                tenant_id=user_tenant,
                assigned_doctor_id=assigned_doctor_id,
            )
            flash(f"Patient record '{patient.patient_id}' successfully encrypted and saved.", "success")
            return redirect(url_for("patient.detail_patient", record_id=patient.id))
        except ValueError as e:
            db.session.rollback()
            flash(str(e), "danger")
            return render_template("patient/create.html", user=user, form=request.form, doctors=doctors), 400
        except IntegrityError:
            # Lost a race with a concurrent registration of the same Patient ID
            db.session.rollback()
            flash("That Patient ID is already registered in your organization.", "danger")
            return render_template("patient/create.html", user=user, form=request.form, doctors=doctors), 409
        except Exception:
            db.session.rollback()
            logger.exception("Unexpected error creating patient record")
            flash("An unexpected error occurred while saving the record. No data was stored.", "danger")
            return render_template("patient/create.html", user=user, form=request.form, doctors=doctors), 500

    user_tenant = getattr(user, "tenant_id", "tenant-default") or "tenant-default"
    return render_template("patient/create.html", user=user, form={},
                           doctors=PatientService.list_assignable_doctors(user_tenant))

@patient_bp.route("/patients/<int:record_id>", methods=["GET"])
@require_permission(PATIENT_READ)
@require_resource_permission("READ")
def detail_patient(record_id: int):
    """Retrieves and decrypts a patient record. Hard-fails with alert on tampered records."""
    user = get_current_user()
    can_update = has_permission(user.role, PATIENT_UPDATE)
    can_delete = has_permission(user.role, PATIENT_DELETE)

    user_tenant = getattr(user, "tenant_id", "tenant-default") or "tenant-default"

    try:
        patient_data = PatientService.get_patient_by_id(record_id, tenant_id=user_tenant)
        if not patient_data:
            abort(404)
        # Edits of a patient assigned to another doctor need a break-glass declaration; the page
        # offers that form instead of an edit button that would only return 403.
        needs_break_glass = can_update and not PolicyEngine.authorize_patient_access(
            user, patient_data, "UPDATE").allowed
        return render_template(
            "patient/detail.html",
            patient=patient_data,
            user=user,
            can_update=can_update,
            can_delete=can_delete and not needs_break_glass,
            needs_break_glass=needs_break_glass,
            break_glass_reasons=AUTHORIZED_BREAK_GLASS_REASONS if needs_break_glass else {},
            tamper_demo_enabled=_tamper_demo_enabled(),
            tamper_error=None
        )
    except IntegrityTamperedError as e:
        # Hard fail on tampering - Refuse to display forged or corrupted data
        return render_template(
            "patient/detail.html",
            patient={"id": record_id, "patient_id": f"REC-#{record_id}"},
            user=user,
            can_update=can_update,
            can_delete=can_delete,
            needs_break_glass=False,
            break_glass_reasons={},
            tamper_demo_enabled=False,
            tamper_error=str(e)
        ), 400

@patient_bp.route("/patients/<int:record_id>/edit", methods=["GET", "POST"])
@require_permission(PATIENT_UPDATE)
@require_resource_permission("UPDATE")
def edit_patient(record_id: int):
    """Allows authorized roles (Doctor only) to modify existing clinical records."""
    user = get_current_user()
    user_tenant = getattr(user, "tenant_id", "tenant-default") or "tenant-default"

    # Load and decrypt current data for the form
    try:
        patient_data = PatientService.get_patient_by_id(record_id, tenant_id=user_tenant)
        if not patient_data:
            abort(404)
    except IntegrityTamperedError as e:
        flash(f"Cannot edit corrupted/tampered record: {e}", "danger")
        return redirect(url_for("patient.detail_patient", record_id=record_id))

    break_glass_reason = (request.form.get("break_glass_reason") or request.args.get("break_glass_reason") or "").strip()

    if request.method == "POST":
        age_band = request.form.get("age_band", "").strip()
        gender = request.form.get("gender", "").strip()
        name = request.form.get("name", "").strip()
        diagnosis = request.form.get("diagnosis", "").strip()
        medical_history = request.form.get("medical_history", "").strip()
        notes = request.form.get("notes", "").strip()
        version_id_raw = request.form.get("version_id")
        expected_version = int(version_id_raw) if version_id_raw and version_id_raw.isdigit() else None
        if expected_version is None:
            # Without the version the form was rendered from, a stale form could silently overwrite
            # a colleague's newer edit.
            flash("This form is missing its record version. Reload the record and try again.", "danger")
            return render_template("patient/edit.html", patient=patient_data, user=user,
                                   break_glass_reason=break_glass_reason), 400

        try:
            PatientService.update_patient(
                record_id=record_id,
                age_band=age_band,
                gender=gender,
                name=name,
                diagnosis=diagnosis,
                medical_history=medical_history,
                notes=notes,
                updated_by_user_id=user.id,
                expected_version=expected_version,
                tenant_id=user_tenant
            )
            flash("Patient record re-encrypted with fresh IV/nonce and updated successfully.", "success")
            return redirect(url_for("patient.detail_patient", record_id=record_id))
        except ConcurrencyConflictError as e:
            flash(str(e), "danger")
            return render_template("patient/edit.html", patient=patient_data, user=user,
                                   break_glass_reason=break_glass_reason), 409
        except ValueError as e:
            db.session.rollback()
            flash(str(e), "danger")
            return render_template("patient/edit.html", patient=patient_data, user=user,
                                   break_glass_reason=break_glass_reason), 400

    return render_template("patient/edit.html", patient=patient_data, user=user,
                           break_glass_reason=break_glass_reason)

@patient_bp.route("/patients/<int:record_id>/tamper-demo", methods=["POST"])
@require_permission(PATIENT_UPDATE)
@require_resource_permission("UPDATE")
def tamper_demo(record_id: int):
    """
    Demonstration route for viva examiners to intentionally inject ciphertext or auth tag tampering.
    Disabled unless ENABLE_TAMPER_DEMO is set, never available in production, and limited to
    records the caller may edit in their own tenant.
    """
    if not _tamper_demo_enabled():
        abort(404)

    user = get_current_user()
    user_tenant = getattr(user, "tenant_id", "tenant-default") or "tenant-default"
    tamper_type = request.form.get("tamper_type", "ciphertext")
    try:
        if tamper_type == "tag":
            PatientService.tamper_record_tag(record_id, tenant_id=user_tenant)
            flash("Simulation: Authentication Tag modified in database! Reloading record should now trigger AES-GCM MAC verification failure.", "warning")
        else:
            PatientService.tamper_record_ciphertext(record_id, tenant_id=user_tenant)
            flash("Simulation: Ciphertext bit-flipped in database! Reloading record should now trigger AES-GCM MAC verification failure.", "warning")
    except ValueError as e:
        flash(f"Simulation failed: {e}", "danger")
    return redirect(url_for("patient.detail_patient", record_id=record_id))

@patient_bp.route("/patients/<int:record_id>/delete", methods=["POST"])
@require_permission(PATIENT_DELETE)
@require_resource_permission("DELETE")
def delete_patient(record_id: int):
    """Soft-deletes a patient record. Strictly restricted to Doctor role (PATIENT_DELETE)."""
    user = get_current_user()
    user_tenant = getattr(user, "tenant_id", "tenant-default") or "tenant-default"

    try:
        PatientService.soft_delete_patient(record_id, user.id, tenant_id=user_tenant)
        flash("Patient record has been securely archived and marked as deleted.", "info")
    except ValueError as e:
        flash(str(e), "danger")
    return redirect(url_for("patient.list_patients"))
