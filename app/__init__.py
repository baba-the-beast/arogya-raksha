"""
Application factory initializing Flask, extensions, blueprints, and security controls.
"""
import logging
import os
import uuid

import click
from flask import Flask, g, request

from app.config import Config
from app.extensions import csrf, db, limiter
from app.security.decorators import get_current_user
from app.security.headers import init_talisman
from app.security.permissions import has_permission

logger = logging.getLogger(__name__)


def create_app(config_class=Config):
    """Flask Application Factory."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Fast-fail startup check for key material in non-test configurations (BUG-05 & P0-1)
    if not app.config.get("TESTING"):
        secret = app.config.get("SECRET_KEY")
        if not secret or secret == "fallback-secret-key-for-dev-only-32bytes!" or len(secret) < 32:
            raise RuntimeError(
                "Insecure configuration: SECRET_KEY is missing or using known insecure fallback value. "
                "Configure a strong SECRET_KEY in your environment."
            )
        master_key = app.config.get("MASTER_ENCRYPTION_KEY")
        if not master_key or master_key == b"\x00" * 32 or master_key == bytes.fromhex("0" * 64):
            raise RuntimeError(
                "Insecure configuration: MASTER_ENCRYPTION_KEY is missing or using known zero-byte fallback value. "
                "Configure a valid 32-byte hex-encoded MASTER_ENCRYPTION_KEY in your environment."
            )

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Server-Side Session Interface (Phase 4 / P0-4)
    from app.security.session_store import ServerSideSessionInterface
    app.session_interface = ServerSideSessionInterface()

    # Observability: Structured JSON logging with PHI redaction filter
    from app.observability.logging import configure_observability
    configure_observability(app)

    # Observability: Performance & Telemetry metrics
    from app.observability.metrics import init_metrics
    init_metrics(app)

    # Initialize security headers via Flask-Talisman
    init_talisman(app)

    # Request ID correlation middleware (Phase 4)
    @app.before_request
    def set_request_correlation():
        incoming_id = request.headers.get("X-Request-ID")
        if incoming_id and len(incoming_id) <= 128 and all(c.isalnum() or c in "-_" for c in incoming_id):
            g.request_id = incoming_id
        else:
            g.request_id = str(uuid.uuid4())

    @app.after_request
    def add_correlation_header(response):
        if hasattr(g, "request_id"):
            response.headers["X-Request-ID"] = g.request_id
        return response

    # Production fail-closed validation (Zero implicit trust)
    flask_env = os.getenv("FLASK_ENV", "").lower() or str(app.config.get("ENV", "")).lower()
    if flask_env == "production":
        storage_uri = str(app.config.get("RATELIMIT_STORAGE_URI", ""))
        if storage_uri.startswith("memory://"):
            logger.warning(
                "SECURITY WARNING: RATELIMIT_STORAGE_URI is set to 'memory://' in production. "
                "This will cause rate limits to be tracked per-process and will not be shared across multi-worker WSGI servers. "
                "Configure a centralized Redis URI in production."
            )
            if not app.config.get("TESTING"):
                raise RuntimeError(
                    "CRITICAL: RATELIMIT_STORAGE_URI must use a centralized distributed backend (e.g. Redis) in production. "
                    "In-memory rate limiting is forbidden across multi-worker WSGI processes."
                )
        if not app.config.get("TESTING"):
            db_url = str(app.config.get("SQLALCHEMY_DATABASE_URI", ""))
            if not db_url or "sqlite" in db_url.lower():
                raise RuntimeError(
                    "CRITICAL: Production deployment requires PostgreSQL. "
                    "SQLite is strictly disallowed in production. Configure DATABASE_URL."
                )
            redis_uri = os.getenv("SESSION_REDIS_URL") or os.getenv("REDIS_URL")
            if not redis_uri:
                raise RuntimeError(
                    "CRITICAL: Distributed session store (SESSION_REDIS_URL / REDIS_URL) must be configured in production."
                )

    # Register Blueprints
    from app.routes.admin import admin_bp
    from app.routes.auth import auth_bp
    from app.routes.errors import errors_bp
    from app.routes.health import health_bp
    from app.routes.patient import patient_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(patient_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(errors_bp)
    app.register_blueprint(health_bp)

    # Context processors to supply current_user and permission checks to all Jinja2 templates
    @app.context_processor
    def inject_auth_context():
        user = get_current_user()
        is_production = os.getenv("FLASK_ENV", "").lower() == "production" or app.config.get("ENV") == "production"
        return {
            "current_user": user,
            "has_permission": has_permission,
            # Single source for demographic options used by filters and forms
            "AGE_BANDS": ["0-9", "10-19", "20-29", "30-39", "40-49", "50-59", "60-69", "70-79", "80+"],
            "GENDERS": ["Female", "Male", "Other", "Undisclosed"],
            # Seeded demo credentials are only listed on the sign-in page outside production
            "show_demo_accounts": not is_production and not app.config.get("TESTING"),
        }

    # Register CLI commands
    @app.cli.command("init-db")
    def init_db_command():
        """Applies schema migrations to target database without dropping schema."""
        from scripts.init_db import apply_migrations
        apply_migrations()

    @app.cli.command("bootstrap-admin")
    def bootstrap_admin_command():
        """Provisions an initial administrator account."""
        from scripts.init_db import bootstrap_admin
        # None -> bootstrap_admin reads BOOTSTRAP_ADMIN_PASSWORD or generates a random one.
        # Never fall back to a well-known password.
        bootstrap_admin(username="admin", password=None, app=app)

    @app.cli.command("process-outbox")
    @click.option("--loop", is_flag=True, help="Keep polling instead of processing one batch.")
    @click.option("--interval", default=5.0, show_default=True, help="Seconds between polls in --loop mode.")
    @click.option("--batch-size", default=50, show_default=True)
    def process_outbox_command(loop, interval, batch_size):
        """Delivers pending transactional-outbox events (alerts, password reset links)."""
        import time

        from app.services.outbox_service import OutboxService
        while True:
            try:
                processed = OutboxService.process_pending_events(batch_size=batch_size)
                if processed:
                    print(f"[outbox] delivered {processed} event(s)")
            except Exception:
                db.session.rollback()
                logger.exception("Outbox worker batch failed")
            if not loop:
                break
            time.sleep(interval)

    @app.cli.command("seed-demo")
    def seed_demo_command():
        """Seeds initial demo clinician accounts and patient record (non-production only)."""
        from scripts.init_db import seed_demo_data
        seed_demo_data(app=app)

    @app.cli.command("verify-audit")
    def verify_audit_command():
        """Cryptographically verify the audit trail hash chain."""
        with app.app_context():
            from app.services.audit_service import AuditService
            valid, broken_id, total, errors = AuditService.verify_chain()
            if valid:
                print(f"[SUCCESS] Audit trail is intact. Total blocks verified: {total}")
            else:
                print(f"[FAIL] Audit integrity violation detected at record #{broken_id}!")
                for err in errors:
                    print(f"  - {err}")

    return app
