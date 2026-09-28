from app.routes.admin import admin_bp
from app.routes.auth import auth_bp
from app.routes.errors import errors_bp
from app.routes.health import health_bp
from app.routes.patient import patient_bp

__all__ = ["auth_bp", "patient_bp", "admin_bp", "errors_bp", "health_bp"]
