import os
from datetime import timedelta

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base application configuration with security defaults."""
    SECRET_KEY = os.getenv("SECRET_KEY")

    # AES-256 Master Key (hex-encoded 32 bytes = 64 characters)
    _raw_key = os.getenv("MASTER_ENCRYPTION_KEY")
    MASTER_ENCRYPTION_KEY = None
    if _raw_key:
        try:
            _parsed = bytes.fromhex(_raw_key.strip())
            if len(_parsed) == 32:
                MASTER_ENCRYPTION_KEY = _parsed
        except Exception:
            pass

    CURRENT_KEY_VERSION = 1

    # Key Registry for multi-version key management and zero-downtime rotation (Phase 3)
    KEY_REGISTRY = {}
    if MASTER_ENCRYPTION_KEY:
        KEY_REGISTRY[1] = MASTER_ENCRYPTION_KEY
    _raw_registry = os.getenv("KEY_REGISTRY_JSON")
    if _raw_registry:
        try:
            import json as _json
            parsed_reg = _json.loads(_raw_registry)
            for v_str, hex_k in parsed_reg.items():
                k_bytes = bytes.fromhex(hex_k)
                if len(k_bytes) == 32:
                    KEY_REGISTRY[int(v_str)] = k_bytes
        except Exception:
            pass

    # Support individual ENCRYPTION_KEY_v<N> env vars as alternative
    for env_k, env_v in os.environ.items():
        if env_k.startswith("ENCRYPTION_KEY_v"):
            try:
                v_num = int(env_k.replace("ENCRYPTION_KEY_v", ""))
                k_bytes = bytes.fromhex(env_v.strip())
                if len(k_bytes) == 32:
                    KEY_REGISTRY[v_num] = k_bytes
            except (ValueError, TypeError):
                pass

    _default_v = max(KEY_REGISTRY.keys()) if KEY_REGISTRY else 1
    CURRENT_KEY_VERSION = int(os.getenv("CURRENT_KEY_VERSION", str(_default_v)))

    # Database (Swap path between SQLite dev and PostgreSQL prod)
    _raw_db_url = os.getenv("DATABASE_URL", "sqlite:///healthcare.db")
    # Only the psycopg (v3) driver is installed; route driver-less URLs to it
    if _raw_db_url.startswith("postgres://"):
        _raw_db_url = _raw_db_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif _raw_db_url.startswith("postgresql://"):
        _raw_db_url = _raw_db_url.replace("postgresql://", "postgresql+psycopg://", 1)
    SQLALCHEMY_DATABASE_URI = _raw_db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Engine connection options & pool resilience
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "300")),
    }
    if not _raw_db_url.startswith("sqlite"):
        SQLALCHEMY_ENGINE_OPTIONS["pool_size"] = int(os.getenv("DB_POOL_SIZE", "10"))
        SQLALCHEMY_ENGINE_OPTIONS["max_overflow"] = int(os.getenv("DB_MAX_OVERFLOW", "20"))

    # Session Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FORCE_HTTPS", "False").lower() in ("true", "1", "yes")
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.getenv("SESSION_LIFETIME_MINUTES", "30"))
    )

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    # Rate Limiting
    RATELIMIT_DEFAULT = "120 per minute"
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_USER_LOCKOUT = os.getenv("RATELIMIT_USER_LOCKOUT", "5 per 15 minutes")

    # Security Headers Flag
    TALISMAN_ENABLED = True

    # Proxy / Network Configuration (BUG-01)
    _raw_proxies = os.getenv("TRUSTED_PROXY_IPS", "")
    TRUSTED_PROXY_IPS = [ip.strip() for ip in _raw_proxies.split(",") if ip.strip()]

    # Password Policy (BUG-08)
    PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "8"))
    PASSWORD_MAX_LENGTH = 128

    # Session Timeouts (Centralized)
    SESSION_IDLE_TIMEOUT_SECONDS = int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "900"))       # 15 minutes
    SESSION_ABSOLUTE_TIMEOUT_SECONDS = int(os.getenv("SESSION_ABSOLUTE_TIMEOUT_SECONDS", "28800"))  # 8 hours

    # MFA Policy (Phase 4)
    MFA_ENFORCE_ADMIN = os.getenv("MFA_ENFORCE_ADMIN", "True").lower() in ("true", "1", "yes")

    # Password reset delivery: public base URL used to build reset links, and SMTP relay
    APP_BASE_URL = os.getenv("APP_BASE_URL", "http://127.0.0.1:5000").rstrip("/")
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "True").lower() in ("true", "1", "yes")
    MAIL_FROM = os.getenv("MAIL_FROM", "no-reply@arogyaraksha.local")

    # Viva tamper-simulation endpoint. Off unless explicitly enabled; never available in production.
    ENABLE_TAMPER_DEMO = os.getenv("ENABLE_TAMPER_DEMO", "False").lower() in ("true", "1", "yes")

    # Accept patient ciphertexts written before record-version AAD binding (crypto_schema=1).
    # Set to False once scripts/rotate_keys.py has upgraded every record.
    CRYPTO_ALLOW_LEGACY_AAD = os.getenv("CRYPTO_ALLOW_LEGACY_AAD", "True").lower() in ("true", "1", "yes")

    # Key version whose HKDF subkey keys the audit hash chain (HMAC). Must be retained after rotation.
    AUDIT_CHAIN_KEY_VERSION = int(os.getenv("AUDIT_CHAIN_KEY_VERSION", "1"))

class DevelopmentConfig(Config):
    """Local development configuration using SQLite and safe defaults."""
    ENV = "development"
    DEBUG = True
    SESSION_COOKIE_SECURE = False

class ProductionConfig(Config):
    """
    Hardened Production configuration enforcing zero implicit trust.
    Fails closed when any mandatory secrets or infrastructure parameters are omitted.
    """
    ENV = "production"
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    TALISMAN_ENABLED = True

    def __init__(self):
        super().__init__()
        # 1. Fail closed on database
        db_uri = self.SQLALCHEMY_DATABASE_URI or ""
        if not db_uri or db_uri.startswith("sqlite"):
            raise RuntimeError(
                "CRITICAL: Production database must be PostgreSQL. "
                "SQLite is strictly disallowed in production. Set DATABASE_URL."
            )

        # 2. Fail closed on secrets
        if not self.SECRET_KEY or len(self.SECRET_KEY) < 32 or "dev" in self.SECRET_KEY.lower():
            raise RuntimeError("CRITICAL: Strong SECRET_KEY (>= 32 bytes) must be configured in production.")

        if not self.MASTER_ENCRYPTION_KEY or len(self.MASTER_ENCRYPTION_KEY) != 32:
            raise RuntimeError("CRITICAL: Valid 32-byte MASTER_ENCRYPTION_KEY must be configured in production.")

        # 3. Fail closed on Redis
        redis_uri = os.getenv("SESSION_REDIS_URL") or os.getenv("REDIS_URL")
        if not redis_uri:
            raise RuntimeError("CRITICAL: Distributed session store (SESSION_REDIS_URL / REDIS_URL) must be configured in production.")

class TestConfig(Config):
    """Configuration for automated test suite."""
    TESTING = True
    SECRET_KEY = "test-secret-key-for-unit-testing-32bytes!!"
    WTF_CSRF_ENABLED = False  # Allows route testing without manual CSRF injection in every call, or tested specifically
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False
    TALISMAN_ENABLED = False
    # Known test master encryption key (32 bytes)
    MASTER_ENCRYPTION_KEY = b"0123456789abcdef0123456789abcdef"
    KEY_REGISTRY = {
        1: b"0123456789abcdef0123456789abcdef",
        2: b"fedcba9876543210fedcba9876543210",
    }
    CURRENT_KEY_VERSION = 1
    MFA_ENFORCE_ADMIN = False
    ENABLE_TAMPER_DEMO = True
    SMTP_HOST = None
