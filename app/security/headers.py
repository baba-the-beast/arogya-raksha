"""
Security headers configuration using Flask-Talisman and modern W3C security headers (Phase 6).
Enforces strict Content-Security-Policy (CSP) with cryptographic nonces (no 'unsafe-inline' in script-src),
Permissions-Policy, and Cross-Origin isolation policies (COOP/CORP).
"""
import secrets

from flask import g
from flask_talisman import Talisman


def init_talisman(app):
    """Configure comprehensive security headers for all HTTP/HTTPS responses."""
    # Register per-request cryptographic nonce generator and Jinja2 context processor
    @app.before_request
    def set_request_nonce():
        if not hasattr(g, "csp_nonce") or not g.csp_nonce:
            g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def inject_csp_nonce():
        return {
            "csp_nonce": lambda: getattr(g, "talisman_nonce", None) or getattr(g, "csp_nonce", "")
        }

    # Modern W3C security headers & anti-caching policy (Phase 6 & Hardening)
    @app.after_request
    def set_modern_security_headers(response):
        # Permissions-Policy: Restrict browser hardware/sensor APIs
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        # Cross-Origin-Opener-Policy (COOP): Isolate browsing context from cross-origin windows
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        # Cross-Origin-Resource-Policy (CORP): Block cross-origin reads of static assets/responses
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # X-Permitted-Cross-Domain-Policies: Disallow Adobe Flash/Acrobat cross-domain policies
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        response.headers.setdefault("X-Robots-Tag", "noindex, nofollow, noarchive")
        response.headers.setdefault("Origin-Agent-Cluster", "?1")

        # Cache-Control: Protect PHI & session views from browser disk & intermediate proxy caches
        from flask import request
        if request.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "public, max-age=86400, must-revalidate")
        else:
            response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            response.headers.setdefault("Pragma", "no-cache")

        return response

    if not app.config.get("TALISMAN_ENABLED", True):
        return None

    # Strict CSP without 'unsafe-inline' in script-src; cryptographic nonces enforced
    csp = {
        "default-src": "'self'",
        "script-src": [
            "'self'",
        ],
        "style-src": [
            "'self'",
        ],
        "font-src": [
            "'self'",
        ],
        "img-src": [
            "'self'",
            "data:",
        ],
        "connect-src": [
            "'self'",
        ],
        "worker-src": "'none'",
        "object-src": "'none'",
        "base-uri": "'none'",
        "form-action": "'self'",
        "frame-src": "'none'",
        "frame-ancestors": "'none'",  # Anti-clickjacking
    }

    force_https = app.config.get("SESSION_COOKIE_SECURE", False)

    # HTTPS redirect is done here rather than by Talisman so that orchestrator health probes,
    # which hit the pod directly over plain HTTP, are not redirected to an https:// port the
    # pod does not serve (which would make liveness/readiness fail or become meaningless).
    probe_paths = ("/livez", "/readyz", "/healthz")

    @app.before_request
    def enforce_https():
        from flask import redirect, request
        if not force_https or app.debug or request.path in probe_paths:
            return None
        if request.is_secure or request.headers.get("X-Forwarded-Proto", "http") == "https":
            return None
        if request.url.startswith("http://"):
            return redirect(request.url.replace("http://", "https://", 1), code=301)
        return None

    talisman = Talisman(
        app,
        content_security_policy=csp,
        content_security_policy_nonce_in=["script-src"],
        force_https=False,
        strict_transport_security=force_https,
        strict_transport_security_max_age=31536000 if force_https else 0,
        frame_options="DENY",
        referrer_policy="no-referrer",
        x_content_type_options=True,
    )
    return talisman
