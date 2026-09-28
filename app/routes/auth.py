"""
Authentication routes for login and logout with rate limiting and CSRF protection.
"""
import urllib.parse
from datetime import UTC, datetime

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for

from app.extensions import limiter
from app.routes.errors import make_error_response
from app.security.decorators import get_current_user
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

auth_bp = Blueprint("auth", __name__)


def is_safe_redirect_url(target: str | None) -> bool:
    """
    Validates redirect targets to strictly enforce relative, same-origin redirection (P0-5).
    Rejects:
      - None, non-string, or empty string
      - Protocol-relative URLs (e.g. '//evil.com', '/\\evil.com', '\\evil.com')
      - URL-encoded backslash or slash variants (e.g. '%2f%2fevil.com', '%5c%5cevil.com')
      - Absolute URLs with scheme or netloc (e.g. 'https://evil.com', 'javascript:', 'data:')
      - URLs with CRLF, tabs, null bytes or control characters
    """
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    if not target.startswith("/") or target.startswith("//") or target.startswith("/\\"):
        return False

    # Check for control characters, tabs, newlines, null bytes
    if any(ord(c) < 32 or ord(c) == 127 for c in target):
        return False

    if "\\" in target:
        return False

    # Check unquoted representation to detect encoded bypasses (%2f, %5c, %00)
    unquoted = urllib.parse.unquote(target)
    if not unquoted.startswith("/") or unquoted.startswith("//") or unquoted.startswith("/\\") or "\\" in unquoted:
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in unquoted):
        return False

    try:
        parsed = urllib.parse.urlsplit(target)
    except Exception:
        return False

    if parsed.scheme or parsed.netloc:
        return False

    return True


def get_login_username() -> str:
    """Extracts submitted username from form data for account lockout rate-limiting."""
    return request.form.get("username", "").strip().lower() or "anonymous"

def handle_account_lockout(request_limit):
    """Audit logs account lockout when a username exceeds maximum allowed failed attempts (BUG-02)."""
    g.is_account_lockout = True
    username = request.form.get("username", "").strip() or "anonymous"
    from app.services.alert_service import AlertService
    AlertService.trigger_alert(
        event_type="ACCOUNT_LOCKOUT",
        message=f"Account '{username}' locked out: exceeded maximum failed login attempts",
        metadata={"username": username, "ip_address": request.remote_addr},
        severity="HIGH"
    )

    AuditService.log_event(
        action="ACCOUNT_LOCKOUT",
        resource_type="USER",
        resource_id=username,
        username=username,
        status="BLOCKED",
        details=f"Account locked out: exceeded maximum failed login attempts ({current_app.config.get('RATELIMIT_USER_LOCKOUT', '5 per 15 minutes')})"
    )
    return make_error_response(
        429,
        "Account Locked",
        "This account has been temporarily locked due to excessive failed login attempts. Please try again later."
    )

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # IP-based rate limiting
@limiter.limit(
    lambda: current_app.config.get("RATELIMIT_USER_LOCKOUT", "5 per 15 minutes"),
    key_func=get_login_username,
    methods=["POST"],
    deduct_when=lambda r: r.status_code == 401,
    on_breach=handle_account_lockout
)
def login():
    """User login endpoint enforcing credentials verification, rate limiting, and MFA."""
    # If already logged in, redirect to dashboard
    if get_current_user():
        return redirect(url_for("patient.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.args.get("next") or request.form.get("next")

        # Authenticate credentials without immediately establishing full session if MFA is required
        user, error = AuthService.authenticate_user(username, password, establish_session=False)
        if error:
            flash(error, "danger")
            return render_template("auth/login.html", username=username), 401

        # Check for mandatory or enrolled Multi-Factor Authentication (Phase 4)
        if user.totp_enabled:
            session.clear()
            session["mfa_pending_user_id"] = user.id
            session["mfa_next_url"] = next_url
            return redirect(url_for("auth.mfa_verify"))

        # Complete session establishment
        AuthService.establish_user_session(user)
        flash(f"Welcome back, {user.username}! Signed in as {user.role}.", "success")

        # Option A Grace Login: First-time admin without MFA is guided to setup
        if user.role == "Admin" and not user.totp_enabled and current_app.config.get("MFA_ENFORCE_ADMIN", True):
            flash("Admin accounts require Multi-Factor Authentication. Please configure your authenticator to continue.", "warning")
            return redirect(url_for("admin.setup_mfa"))

        if next_url and is_safe_redirect_url(next_url):
            return redirect(next_url)
        return redirect(url_for("patient.dashboard"))

    return render_template("auth/login.html")

@auth_bp.route("/login/mfa", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def mfa_verify():
    """Second-factor TOTP verification before issuing authenticated session."""
    pending_user_id = session.get("mfa_pending_user_id")
    if not pending_user_id:
        return redirect(url_for("auth.login"))

    from app.extensions import db
    from app.models.user import User
    user = db.session.get(User, pending_user_id)
    if not user or not user.is_active or not user.totp_enabled:
        session.clear()
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("totp_code", "").strip()
        next_url = session.get("mfa_next_url")

        if AuthService.verify_totp(user.totp_secret, code, user_id=user.id):
            session.pop("mfa_pending_user_id", None)
            session.pop("mfa_next_url", None)
            AuthService.establish_user_session(user)

            AuditService.log_event(
                action="MFA_SUCCESS",
                resource_type="AUTH",
                resource_id=str(user.id),
                status="SUCCESS",
                user_id=user.id,
                username=user.username,
                details="TOTP MFA verification succeeded"
            )

            flash(f"Welcome back, {user.username}! Signed in as {user.role}.", "success")
            if next_url and is_safe_redirect_url(next_url):
                return redirect(next_url)
            return redirect(url_for("patient.dashboard"))
        else:
            AuditService.log_event(
                action="MFA_FAILURE",
                resource_type="AUTH",
                resource_id=str(user.id),
                status="FAILURE",
                user_id=user.id,
                username=user.username,
                details="Invalid TOTP MFA verification code entered"
            )
            flash("Invalid or expired authenticator code. Please try again.", "danger")
            return render_template("auth/mfa.html", username=user.username), 401

    return render_template("auth/mfa.html", username=user.username)

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def forgot_password():
    """Password reset request flow with constant-time response and out-of-band dispatch."""
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        AuthService.create_password_reset_token(identifier)
        flash(
            "If an active account matches the submitted username, password reset instructions have been dispatched out-of-band.",
            "info"
        )
        return render_template("auth/forgot_password.html", reset_dispatched=True)

    return render_template("auth/forgot_password.html", reset_dispatched=False)

@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("20 per 15 minutes")
def reset_password(token: str):
    """
    Password reset token entry point (Section 21 & 22).
    GET: Validates token, stores an opaque ephemeral reset ticket in server session,
    and immediately redirects (302) to the clean URL '/reset-password'.
    This prevents the token from leaking into browser history, Referer headers, or logs.
    POST: Retained for backward-compatibility with direct API clients and automated tests.
    """
    import hashlib

    from app.models.password_reset_token import PasswordResetToken

    token_hash = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
    token_record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()

    if not token_record or not token_record.is_valid():
        flash("This password reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        # Clean URL pattern: store token in server-side session ticket with 120s TTL and redirect
        session["_reset_ticket"] = token.strip()
        session["_reset_ticket_ts"] = datetime.now(UTC).timestamp()
        return redirect(url_for("auth.reset_password_clean"))

    # Direct POST handling for backward compatibility
    new_password = request.form.get("password", "")
    success, message = AuthService.verify_and_use_password_reset_token(token, new_password)
    if success:
        flash(message, "success")
        return redirect(url_for("auth.login"))
    else:
        flash(message, "danger")
        return render_template("auth/reset_password.html", token=token), 400


@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password_clean():
    """
    Clean URL password reset form and submission endpoint.
    Operates without secret tokens in the query string or URL path.
    Enforces a strict 120-second ephemeral lifetime on the reset ticket.
    """
    import hashlib

    from app.models.password_reset_token import PasswordResetToken

    token = session.get("_reset_ticket")
    ticket_ts = session.get("_reset_ticket_ts")
    now_ts = datetime.now(UTC).timestamp()

    if not token or not ticket_ts or (now_ts - ticket_ts > 120):
        session.pop("_reset_ticket", None)
        session.pop("_reset_ticket_ts", None)
        flash("Password reset session expired or invalid. Please request a new link.", "warning")
        return redirect(url_for("auth.forgot_password"))

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    token_record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
    if not token_record or not token_record.is_valid():
        session.pop("_reset_ticket", None)
        session.pop("_reset_ticket_ts", None)
        flash("This password reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        success, message = AuthService.verify_and_use_password_reset_token(token, new_password)
        session.pop("_reset_ticket", None)
        session.pop("_reset_ticket_ts", None)
        if success:
            flash(message, "success")
            return redirect(url_for("auth.login"))
        else:
            flash(message, "danger")
            return render_template("auth/reset_password.html", token=""), 400

    return render_template("auth/reset_password.html", token="")

@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Terminates session and records audit event. Restricted to POST to prevent logout CSRF (P0-6)."""
    AuthService.logout_user()
    flash("You have been securely signed out.", "info")
    return redirect(url_for("auth.login"))
