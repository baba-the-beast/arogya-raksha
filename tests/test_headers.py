"""
Phase 6 — Security Headers & CSP Nonce Verification Tests.

Covers:
- Modern security headers: Permissions-Policy, COOP, CORP, X-Permitted-Cross-Domain-Policies
- Strict Content-Security-Policy (CSP) with dynamic cryptographic nonces
- Absence of 'unsafe-inline' in script-src
- Frame options and anti-clickjacking controls
- Template script tag nonce injection
"""
import pytest

from app import create_app
from app.config import Config, TestConfig


@pytest.fixture
def talisman_client():
    """Client configured with Talisman enabled to test production header emission."""
    class ProductionHeadersConfig(TestConfig):
        TALISMAN_ENABLED = True
        SESSION_COOKIE_SECURE = False

    prod_app = create_app(ProductionHeadersConfig)
    return prod_app.test_client()


def test_modern_security_headers_present(client):
    """Permissions-Policy, COOP, and CORP headers are emitted on responses."""
    resp = client.get("/login")
    assert resp.status_code == 200

    # Permissions-Policy
    assert "Permissions-Policy" in resp.headers
    perm_policy = resp.headers["Permissions-Policy"]
    assert "camera=()" in perm_policy
    assert "microphone=()" in perm_policy
    assert "geolocation=()" in perm_policy

    # Cross-Origin Isolation
    assert resp.headers.get("Cross-Origin-Opener-Policy") == "same-origin"
    assert resp.headers.get("Cross-Origin-Resource-Policy") == "same-origin"
    assert resp.headers.get("X-Permitted-Cross-Domain-Policies") == "none"


def test_strict_csp_with_nonce_and_no_unsafe_inline_in_script_src(talisman_client):
    """
    When Talisman is active, Content-Security-Policy enforces dynamic cryptographic nonces
    and completely disallows 'unsafe-inline' in script-src.
    """
    resp = talisman_client.get("/login")
    assert resp.status_code == 200

    csp = resp.headers.get("Content-Security-Policy")
    assert csp is not None

    # Check script-src policy
    script_directive = [d.strip() for d in csp.split(";") if d.strip().startswith("script-src")]
    assert len(script_directive) == 1, "script-src directive must exist in CSP"
    script_policy = script_directive[0]

    # Must contain dynamic nonce
    assert "'nonce-" in script_policy, "script-src must include a cryptographic nonce"

    # Must NOT contain unsafe-inline
    assert "'unsafe-inline'" not in script_policy, "script-src must NOT contain 'unsafe-inline'"

    # Frame options & MIME sniffing
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_template_renders_script_nonce(client):
    """Templates inject the per-request nonce into inline and external script tags."""
    resp = client.get("/patients")
    # Redirects to /login if unauthenticated, so check login page or authenticated page
    login_resp = client.get("/login")
    assert login_resp.status_code == 200
    content = login_resp.data.decode()
    assert "nonce=" in content


def test_operational_errors_include_safe_request_id(client):
    """Error pages provide a support identifier without exposing implementation details."""
    response = client.get("/route-that-does-not-exist")
    assert response.status_code == 404
    assert b"Request ID" in response.data
    assert response.headers["X-Request-ID"].encode() in response.data


def test_json_errors_include_request_id(client):
    response = client.get("/api/route-that-does-not-exist", headers={"Accept": "application/json"})
    assert response.status_code == 404
    assert response.json["request_id"] == response.headers["X-Request-ID"]
