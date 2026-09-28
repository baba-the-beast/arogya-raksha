import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from flask import has_app_context

from app.extensions import db
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.patient_service import PatientService


def apply_migrations():
    """Applies latest Alembic migrations to target database without dropping schema."""
    ini_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    alembic_cfg = AlembicConfig(ini_path)
    print("[*] Applying Alembic migrations (upgrade head)...")
    alembic_command.upgrade(alembic_cfg, "head")
    print("[+] Schema is up-to-date with Alembic head.")


def bootstrap_admin(username: str = "admin", password: str | None = None, app=None):
    """
    Explicitly bootstraps the initial Administrator account without demo clinician data.
    Enforces that production uses a non-deterministic password passed via environment or generated securely.
    """
    import secrets

    flask_env = os.getenv("FLASK_ENV", "").lower() or os.getenv("ENV", "").lower()
    is_prod = flask_env == "production"

    if not password:
        password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")

    if not password:
        password = secrets.token_urlsafe(24 if is_prod else 16)
        print("[NOTICE] Generated bootstrap administrator password:")
        print(f"  Username: {username}")
        print(f"  Password: {password}")
        if is_prod:
            print("[SECURITY NOTICE] Store this password securely. It will not be displayed again.")

    should_push = not has_app_context() and app is not None
    context_manager = app.app_context() if should_push else None
    if context_manager:
        context_manager.__enter__()

    try:
        apply_migrations()
        existing = User.query.filter_by(username=username).first()
        if existing:
            print(f"[!] Admin user '{username}' already exists. Skipping creation.")
            return existing

        admin = User(
            username=username,
            password_hash=AuthService.hash_password(password),
            role="Admin",
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()

        AuditService.log_event(
            action="BOOTSTRAP_ADMIN",
            resource_type="USER",
            resource_id=str(admin.id),
            status="SUCCESS",
            username=username,
            details=f"Initial bootstrap administrator '{username}' provisioned"
        )
        print(f"[+] Successfully provisioned administrator: '{username}'")
        return admin
    finally:
        if context_manager:
            context_manager.__exit__(None, None, None)


def seed_demo_data(app=None):
    """
    Populates default demo clinician accounts and a baseline encrypted patient record.
    Strictly blocked in production environments to prevent credential leakage.
    """
    flask_env = os.getenv("FLASK_ENV", "").lower()
    env = os.getenv("ENV", "").lower()
    if flask_env == "production" or env == "production":
        raise RuntimeError("CRITICAL: seed_demo_data is strictly blocked in production environments!")

    should_push = not has_app_context() and app is not None
    context_manager = app.app_context() if should_push else None
    if context_manager:
        context_manager.__enter__()

    try:
        apply_migrations()
        if User.query.count() == 0:
            print("[*] Seeding default accounts (Doctor, Nurse, Admin)...")

            doctor = User(
                username="doctor_alice",
                password_hash=AuthService.hash_password("DocSecurePass#2026"),
                role="Doctor",
                is_active=True
            )
            nurse = User(
                username="nurse_bob",
                password_hash=AuthService.hash_password("NursePass#2026"),
                role="Nurse",
                is_active=True
            )
            admin = User(
                username="admin_charlie",
                password_hash=AuthService.hash_password("AdminMaster#2026"),
                role="Admin",
                is_active=True
            )

            db.session.add_all([doctor, nurse, admin])
            db.session.commit()

            AuditService.log_event(
                action="SYSTEM_INIT",
                resource_type="SYSTEM",
                resource_id="0",
                status="SUCCESS",
                username="system",
                details="Initial system database and accounts seeded"
            )

            print("[+] Seeded users:")
            print("    - Doctor: doctor_alice / DocSecurePass#2026")
            print("    - Nurse:  nurse_bob    / NursePass#2026")
            print("    - Admin:  admin_charlie / AdminMaster#2026")

            # Seed an initial encrypted patient record
            print("[*] Seeding initial encrypted patient record (AES-256-GCM)...")
            PatientService.create_patient(
                patient_id="P-2026-001",
                age_band="40-49",
                gender="Female",
                name="Jane Doe",
                diagnosis="Type 2 Diabetes Mellitus with Mild Neuropathy",
                medical_history="Hypertension diagnosed 2018. Penicillin allergy.",
                notes="Fasting blood sugar: 145 mg/dL. Prescribed Metformin 500mg BID. Stable vitals.",
                created_by_user_id=doctor.id
            )
            print("[+] Seeded encrypted patient: P-2026-001 (Jane Doe)")
        else:
            print("[!] Database already initialized. Skipping user seeding.")

        print("[OK] Database ready.")
    finally:
        if context_manager:
            context_manager.__exit__(None, None, None)


def initialize_database(app=None):
    """
    Applies schema migrations and, in non-production, seeds baseline demo accounts if empty.
    """
    flask_env = os.getenv("FLASK_ENV", "").lower()
    env = os.getenv("ENV", "").lower()
    if flask_env == "production" or env == "production":
        apply_migrations()
    else:
        seed_demo_data(app)


if __name__ == "__main__":
    from app import create_app
    app = create_app()
    initialize_database(app)
