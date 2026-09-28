"""
Automated validation of Phase 7 deployment configuration files:
- Dockerfile (multi-stage, non-root user arogya, /healthz check, sync gunicorn)
- docker-compose.yml (web, postgres:16-alpine, redis:7-alpine, ratelimit storage)
- Procfile (web process definition)
- gunicorn.conf.py (sync worker architecture)
- .github/workflows/ci.yml (CI lint & coverage gate)
- requirements.txt (production dependencies)
"""
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_configuration():
    """Verify Dockerfile enforces multi-stage build, non-root user arogya, and health checks."""
    dockerfile_path = REPO_ROOT / "Dockerfile"
    assert dockerfile_path.exists(), "Dockerfile must exist at repository root"
    content = dockerfile_path.read_text(encoding="utf-8")

    # Multi-stage validation
    assert "AS builder" in content, "Dockerfile must define a builder stage"
    assert "AS runner" in content, "Dockerfile must define a runner stage"

    # Non-root user validation
    assert "10001" in content, "Dockerfile must configure non-root UID 10001"
    assert "USER arogya" in content, "Dockerfile must drop root privileges to arogya user"

    # Port & Healthcheck validation
    assert "EXPOSE 5000" in content, "Dockerfile must expose port 5000"
    assert "/healthz" in content, "Dockerfile HEALTHCHECK must target /healthz"

    # Worker choice: sync workers strictly required for PyCryptodome safety
    cmd_line = [line for line in content.splitlines() if line.strip().startswith("CMD")][-1]
    assert "gunicorn" in cmd_line
    assert "-w" in cmd_line and "4" in cmd_line
    assert "gevent" not in cmd_line, "Async workers (gevent) must NOT be invoked in CMD"


def test_docker_compose_configuration():
    """Verify docker-compose.yml defines web, PostgreSQL 16, and Redis 7 with correct networking."""
    compose_path = REPO_ROOT / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist at repository root"

    with open(compose_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    services = data.get("services", {})
    assert "web" in services, "compose must contain web service"
    assert "db" in services, "compose must contain db service"
    assert "redis" in services, "compose must contain redis service"

    # DB service checks
    db_service = services["db"]
    assert "postgres:16" in db_service.get("image", ""), "db must use postgres:16"
    assert "healthcheck" in db_service, "db service must define a healthcheck"

    # Redis service checks
    redis_service = services["redis"]
    assert "redis:7" in redis_service.get("image", ""), "redis must use redis:7"
    assert "healthcheck" in redis_service, "redis service must define a healthcheck"

    # Web service checks
    web_service = services["web"]
    env = web_service.get("environment", [])
    env_str = " ".join(env) if isinstance(env, list) else " ".join(f"{k}={v}" for k, v in env.items())
    assert "redis://redis:6379/0" in env_str, "web must configure RATELIMIT_STORAGE_URI to Redis"
    assert "postgresql" in env_str, "web must configure DATABASE_URL to PostgreSQL"

    depends = web_service.get("depends_on", {})
    assert "db" in depends
    assert "redis" in depends


def test_procfile_configuration():
    """Verify Procfile specifies gunicorn with 4 sync workers."""
    procfile_path = REPO_ROOT / "Procfile"
    assert procfile_path.exists(), "Procfile must exist"
    content = procfile_path.read_text(encoding="utf-8").strip()
    assert content.startswith("web: gunicorn")
    assert "-w 4" in content


def test_gunicorn_conf_mandates_sync_workers():
    """Verify gunicorn.conf.py explicitly configures synchronous worker class."""
    conf_path = REPO_ROOT / "gunicorn.conf.py"
    assert conf_path.exists(), "gunicorn.conf.py must exist"
    content = conf_path.read_text(encoding="utf-8")
    assert 'worker_class = "sync"' in content
    assert "PyCryptodome" in content


def test_ci_workflow_configuration():
    """Verify GitHub Actions CI workflow configures linting and coverage gate."""
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_path.exists(), ".github/workflows/ci.yml must exist"

    with open(ci_path, encoding="utf-8") as f:
        ci_data = yaml.safe_load(f)

    assert "on" in ci_data or True in ci_data
    jobs = ci_data.get("jobs", {})
    assert "test-and-lint" in jobs

    # Check steps for ruff and pytest coverage
    steps = jobs["test-and-lint"].get("steps", [])
    step_runs = " ".join(step.get("run", "") for step in steps)
    assert "ruff check" in step_runs
    assert "pytest" in step_runs
    assert "--cov-fail-under=80" in step_runs


def test_requirements_include_production_dependencies():
    """Verify requirements.txt contains gunicorn, pyotp, redis, and psycopg."""
    req_path = REPO_ROOT / "requirements.txt"
    assert req_path.exists()
    content = req_path.read_text(encoding="utf-8").lower()
    assert "gunicorn" in content
    assert "pyotp" in content
    assert "redis" in content
    assert "psycopg" in content


def test_healthz_endpoint(client):
    """Verify /healthz endpoint responds with 200 OK and database connected status."""
    res = client.get("/healthz")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["service"] == "ArogyaRaksha"

