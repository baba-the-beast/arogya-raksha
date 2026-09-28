"""
Centralized error handlers preventing information leakage (tracebacks, SQL syntax, or server details).
"""
import logging

from flask import Blueprint, g, jsonify, render_template, request
from flask_wtf.csrf import CSRFError

from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

errors_bp = Blueprint("errors", __name__)


def make_error_response(status_code: int, error_name: str, message: str):
    """Returns JSON or HTML depending on request Accept header / context."""
    request_id = getattr(g, "request_id", None)
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({
            "error": error_name,
            "status": status_code,
            "message": message,
            "request_id": request_id,
        }), status_code
    return render_template(
        f"errors/{status_code}.html",
        status_code=status_code,
        error_name=error_name,
        message=message,
        request_id=request_id,
    ), status_code


@errors_bp.app_errorhandler(CSRFError)
def csrf_error_handler(e):
    """Handles CSRF validation failures securely without leaking token internals."""
    logger.warning("CSRF validation failure on %s from IP %s: %s", request.path, request.remote_addr, e.description)
    AuditService.log_event(
        action="CSRF_VALIDATION_FAILURE",
        resource_type="SECURITY",
        resource_id=request.path,
        status="BLOCKED",
        details="CSRF token missing, invalid, or expired"
    )
    return make_error_response(
        400,
        "CSRF Token Invalid",
        "Your session or form security token has expired or is invalid. Please refresh the page and try again."
    )


@errors_bp.app_errorhandler(400)
def bad_request_error(e):
    return make_error_response(400, "Bad Request", getattr(e, "description", "The server could not process the request."))


@errors_bp.app_errorhandler(401)
def unauthorized_error(e):
    return make_error_response(401, "Unauthorized", "You must authenticate before accessing this resource.")


@errors_bp.app_errorhandler(403)
def forbidden_error(e):
    return make_error_response(403, "Forbidden", "You do not have the required role permissions to perform this action.")


@errors_bp.app_errorhandler(404)
def not_found_error(e):
    return make_error_response(404, "Not Found", "The requested resource could not be found.")


@errors_bp.app_errorhandler(405)
def method_not_allowed_error(e):
    return make_error_response(405, "Method Not Allowed", "The HTTP method is not supported for this endpoint.")


@errors_bp.app_errorhandler(429)
def ratelimit_handler(e):
    """Audit rate limit violations and return 429 response."""
    if getattr(g, "is_account_lockout", False):
        return make_error_response(
            429,
            "Account Locked",
            "This account has been temporarily locked due to excessive failed login attempts. Please try again later."
        )
    AuditService.log_event(
        action="RATE_LIMIT_EXCEEDED",
        resource_type="NETWORK",
        resource_id=request.path,
        status="BLOCKED",
        details="Too many requests within configured time window"
    )
    return make_error_response(429, "Too Many Requests", "Rate limit exceeded. Please wait before retrying.")


@errors_bp.app_errorhandler(500)
def internal_error(e):
    logger.error("Internal Server Error at %s: %s", request.path, e, exc_info=True)
    return make_error_response(500, "Internal Server Error", "A secure internal error occurred. Please contact the administrator.")
