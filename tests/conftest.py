"""
Pytest fixtures for ArogyaRaksha test suite.
"""
import pytest

from app import create_app
from app.config import TestConfig
from app.extensions import db
from app.models.tenant import Tenant
from app.models.user import User
from app.services.auth_service import AuthService
from app.services.patient_service import PatientService


@pytest.fixture
def app():
    """Create and configure a clean application instance for each test."""
    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()
        # Seed default tenant for multi-tenancy foreign keys
        default_tenant = Tenant(
            id="tenant-default",
            name="Default Health Clinic",
            code="DEF-01",
            is_active=True
        )
        db.session.add(default_tenant)
        db.session.commit()

        # Seed standard users
        doctor = User(
            username="test_doctor",
            password_hash=AuthService.hash_password("DoctorPass#123"),
            role="Doctor",
            is_active=True
        )
        nurse = User(
            username="test_nurse",
            password_hash=AuthService.hash_password("NursePass#123"),
            role="Nurse",
            is_active=True
        )
        admin = User(
            username="test_admin",
            password_hash=AuthService.hash_password("AdminPass#123"),
            role="Admin",
            is_active=True
        )
        disabled_user = User(
            username="disabled_doc",
            password_hash=AuthService.hash_password("DocDisabled#123"),
            role="Doctor",
            is_active=False
        )
        db.session.add_all([doctor, nurse, admin, disabled_user])
        db.session.commit()

        # Seed test patient record
        PatientService.create_patient(
            patient_id="P-TEST-001",
            age_band="30-39",
            gender="Female",
            name="Alice Smith",
            diagnosis="Seasonal Allergies",
            medical_history="No chronic conditions",
            notes="Cetirizine 10mg prescribed daily",
            created_by_user_id=doctor.id
        )

        yield app

        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """Test client for HTTP requests."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """CLI runner for Click commands."""
    return app.test_cli_runner()

def login_client(client, username, password):
    """Helper to log in via POST /login."""
    client.post("/logout")
    return client.post("/login", data={
        "username": username,
        "password": password
    }, follow_redirects=True)
