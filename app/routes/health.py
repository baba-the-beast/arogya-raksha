"""
Health and readiness endpoints for container orchestration and operational monitoring.
Compliant with Kubernetes liveness and readiness probe semantics.
"""
import logging
import os

from flask import Blueprint, current_app, jsonify
from sqlalchemy import text

from app.extensions import db
from app.services.crypto_service import CryptoService

health_bp = Blueprint("health", __name__)
logger = logging.getLogger(__name__)


@health_bp.route("/livez", methods=["GET"])
def livez():
    """
    Kubernetes Liveness Probe: Confirms the process is running and event loop is responsive.
    Strictly isolated from external dependencies (no database/redis calls) to prevent
    cascading pod restarts during upstream hiccups.
    """
    return jsonify({
        "status": "alive",
        "service": "ArogyaRaksha"
    }), 200


@health_bp.route("/readyz", methods=["GET"])
def readyz():
    """
    Kubernetes Readiness Probe: Validates whether the application can accept user traffic.
    Verifies:
      1. Primary relational database connectivity.
      2. Active cryptographic key provider readiness.
    Fails closed with HTTP 503 without leaking stack traces or internal topology.
    """
    checks = {
        "database": "unavailable",
        "crypto": "unready"
    }

    # 1. Database check
    try:
        db.session.execute(text("SELECT 1"))
        checks["database"] = "connected"
    except Exception:
        logger.exception("Readiness check: Database probe failed")
        return jsonify({
            "status": "not_ready",
            "checks": checks
        }), 503

    # 2. Cryptographic key availability check
    try:
        active_v, active_key = CryptoService.get_key_provider().get_current_key()
        if active_key and len(active_key) == 32:
            checks["crypto"] = "ready"
        else:
            checks["crypto"] = "invalid_key_length"
            return jsonify({
                "status": "not_ready",
                "checks": checks
            }), 503
    except Exception:
        logger.exception("Readiness check: Cryptographic key provider probe failed")
        return jsonify({
            "status": "not_ready",
            "checks": checks
        }), 503

    # 3. Distributed Cache & Session Store check (if configured)
    redis_url = os.getenv("SESSION_REDIS_URL") or os.getenv("REDIS_URL") or (current_app.config.get("REDIS_URL") if current_app else None)
    if redis_url:
        try:
            import redis
            r = redis.from_url(redis_url, socket_timeout=2)
            if r.ping():
                checks["redis"] = "connected"
            else:
                checks["redis"] = "unresponsive"
                return jsonify({"status": "not_ready", "checks": checks}), 503
        except Exception:
            logger.exception("Readiness check: Redis probe failed")
            checks["redis"] = "unavailable"
            return jsonify({"status": "not_ready", "checks": checks}), 503

    return jsonify({
        "status": "ready",
        "checks": checks
    }), 200


@health_bp.route("/healthz", methods=["GET"])
def healthz():
    """
    General health check (backwards-compatible with Docker healthchecks and monitoring tools).
    """
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        logger.exception("Database health check failed")
        return jsonify({"status": "error", "database": "unhealthy"}), 500

    return jsonify({
        "status": "healthy",
        "database": "connected",
        "service": "ArogyaRaksha"
    }), 200
