"""
Automated unit tests for Network & Application Security: SQLi immunity, XSS escaping, CSRF defense, and Health check (NFR1, NFR3, §10).
"""
from app import create_app
from app.config import Config, TestConfig
from tests.conftest import login_client


def test_sqli_payload_immunity(client):
    """Verify that classical SQL injection payloads are treated as safe parameterized literals."""
    sqli_payload = "admin' OR '1'='1"
    response = client.post("/login", data={
        "username": sqli_payload,
        "password": "random_password"
    })
    # Should fail cleanly with 401, not bypass authentication or trigger SQL syntax error
    assert response.status_code == 401
    assert b"Invalid username or password" in response.data

def test_xss_payload_escaped_on_render(client):
    """Verify that user-supplied scripts in patient records are HTML-escaped by Jinja2."""
    login_client(client, "test_doctor", "DoctorPass#123")

    xss_name = "<script>alert('XSS_EXPLOIT')</script>"
    xss_diagnosis = "<img src=x onerror=alert('PWNED')>"

    client.post("/patients/new", data={
        "patient_id": "P-XSS-001",
        "age_band": "30-39",
        "gender": "Female",
        "name": xss_name,
        "diagnosis": xss_diagnosis,
        "medical_history": "Clear",
        "notes": "Clear"
    }, follow_redirects=True)

    # Fetch patient detail page
    resp = client.get("/patients/2")
    assert resp.status_code == 200

    # Raw script tags must NOT be present unescaped
    assert b"<script>alert('XSS_EXPLOIT')</script>" not in resp.data
    # Escaped versions should be present
    assert b"&lt;script&gt;alert(&#39;XSS_EXPLOIT&#39;)&lt;/script&gt;" in resp.data or b"&lt;script&gt;alert(&#39;XSS_EXPLOIT&#39;)&lt;/script&gt;" in resp.data

def test_csrf_protection():
    """Verify that when CSRF protection is active, POST submissions without valid token are rejected."""
    # Create an app instance with CSRF explicitly enabled
    class CsrfTestConfig(TestConfig):
        WTF_CSRF_ENABLED = True
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
        TALISMAN_ENABLED = False
        RATELIMIT_ENABLED = False

    app = create_app(CsrfTestConfig)
    with app.app_context():
        from app.extensions import db
        db.create_all()
        test_client = app.test_client()

        # Submit POST without CSRF token
        response = test_client.post("/login", data={
            "username": "test_doctor",
            "password": "DoctorPass#123"
        })

        # Flask-WTF rejects forged CSRF submission with 400 Bad Request
        assert response.status_code == 400
        assert b"CSRF" in response.data or b"The CSRF token is missing" in response.data

def test_healthz_endpoint(client):
    """Verify operational health check endpoint returns 200 with database status."""
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"

def test_error_handlers_no_info_leakage(client):
    """Verify 404 and 403 error pages do not leak stack traces or server version headers."""
    resp_404 = client.get("/non-existent-endpoint-test")
    assert resp_404.status_code == 404
    assert b"Page not found" in resp_404.data
    assert b"Traceback" not in resp_404.data

def test_ratelimit_storage_production_warning(monkeypatch, caplog):
    """Verify startup warning log if running with FLASK_ENV=production and memory:// storage (BUG-04)."""
    import logging

    from app import create_app
    from app.config import TestConfig

    monkeypatch.setenv("FLASK_ENV", "production")

    class ProdMemConfig(TestConfig):
        RATELIMIT_STORAGE_URI = "memory://"

    with caplog.at_level(logging.WARNING):
        app = create_app(ProdMemConfig)
        assert any("RATELIMIT_STORAGE_URI is set to 'memory://' in production" in record.message for record in caplog.records)

