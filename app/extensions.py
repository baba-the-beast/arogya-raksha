from flask_limiter import Limiter
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect


def client_ip_key() -> str:
    """Rate-limit key: the real client IP, resolved through the trusted-proxy allowlist."""
    from app.services.audit_service import AuditService
    return AuditService.get_client_ip()


db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=client_ip_key,
    default_limits=["120 per minute"]
)
