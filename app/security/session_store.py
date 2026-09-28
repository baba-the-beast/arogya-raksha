"""
Server-Side Session Store Architecture for ArogyaRaksha.
Replaces client-side cookie state with opaque random session identifiers.
Enforces:
  - 15-minute idle timeout & 8-hour absolute session timeout
  - Explicit session rotation on login, MFA verification, and privilege changes
  - Individual and global session revocation
  - Distributed Redis backend in production with thread-safe in-memory fallback in dev/test
"""
import json
import logging
import os
import secrets
import threading
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from flask import current_app
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict

logger = logging.getLogger("security.session")


@dataclass
class ServerSessionData:
    """Server-side session payload."""
    session_id: str
    user_id: int | None = None
    username: str | None = None
    role: str | None = None
    tenant_id: str = "tenant-default"
    auth_state: str = "UNAUTHENTICATED"  # UNAUTHENTICATED, PASSWORD_AUTHENTICATED, MFA_PENDING, FULLY_AUTHENTICATED, REVOKED
    mfa_state: str | None = None         # None, PENDING, VERIFIED
    session_version: int = 1
    created_at: float = 0.0              # Unix timestamp for absolute timeout
    last_active_at: float = 0.0          # Unix timestamp for idle timeout
    ip_address: str | None = None
    user_agent: str | None = None
    data: dict[str, Any] = None

    def __post_init__(self):
        if self.created_at == 0.0:
            now = datetime.now(UTC).timestamp()
            self.created_at = now
            self.last_active_at = now
        if self.data is None:
            self.data = {}

    def is_expired(self, idle_seconds: int | None = None, absolute_seconds: int | None = None) -> bool:
        """Evaluates idle (default 15m) and absolute (default 8h) timeouts against centralized config."""
        if idle_seconds is None:
            idle_seconds = current_app.config.get("SESSION_IDLE_TIMEOUT_SECONDS", 900) if current_app else 900
        if absolute_seconds is None:
            absolute_seconds = current_app.config.get("SESSION_ABSOLUTE_TIMEOUT_SECONDS", 28800) if current_app else 28800
        now = datetime.now(UTC).timestamp()
        if now - self.last_active_at > idle_seconds:
            return True
        if now - self.created_at > absolute_seconds:
            return True
        return False


class SessionStore(ABC):
    """Abstract interface for server-side session persistence."""

    @abstractmethod
    def save(self, session: ServerSessionData, ttl_seconds: int = 28800) -> None:
        pass

    @abstractmethod
    def get(self, session_id: str) -> ServerSessionData | None:
        pass

    @abstractmethod
    def delete(self, session_id: str) -> None:
        pass

    @abstractmethod
    def delete_all_for_user(self, user_id: int) -> int:
        pass


class MemorySessionStore(SessionStore):
    """Thread-safe in-memory session store for testing and single-worker development."""

    PURGE_EVERY_N_SAVES = 256

    def __init__(self):
        self._store: dict[str, ServerSessionData] = {}
        self._lock = threading.Lock()
        self._saves_since_purge = 0

    def save(self, session: ServerSessionData, ttl_seconds: int = 28800) -> None:
        with self._lock:
            self._store[session.session_id] = session
            self._saves_since_purge += 1
            if self._saves_since_purge >= self.PURGE_EVERY_N_SAVES:
                self._saves_since_purge = 0
                self._purge_expired_locked()

    def _purge_expired_locked(self) -> None:
        """Drops expired sessions that were never accessed again (caller holds the lock)."""
        expired = [sid for sid, sess in self._store.items() if sess.is_expired()]
        for sid in expired:
            del self._store[sid]

    def get(self, session_id: str) -> ServerSessionData | None:
        with self._lock:
            session = self._store.get(session_id)
            if not session:
                return None
            if session.is_expired():
                del self._store[session_id]
                return None
            session.last_active_at = datetime.now(UTC).timestamp()
            return session

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._store.pop(session_id, None)

    def delete_all_for_user(self, user_id: int) -> int:
        count = 0
        with self._lock:
            to_delete = [sid for sid, sess in self._store.items() if sess.user_id == user_id]
            for sid in to_delete:
                del self._store[sid]
                count += 1
        return count


class RedisSessionStore(SessionStore):
    """Production distributed session store utilizing Redis."""

    def __init__(self, redis_client=None):
        self.client = redis_client
        self.prefix = "arogya:session:"

    def _get_client(self):
        if self.client:
            return self.client
        import redis
        url = (os.getenv("SESSION_REDIS_URL") or current_app.config.get("REDIS_URL")
               or os.getenv("REDIS_URL", "redis://localhost:6379/1"))
        self.client = redis.from_url(url, decode_responses=True)
        return self.client

    def save(self, session: ServerSessionData, ttl_seconds: int = 28800) -> None:
        try:
            r = self._get_client()
            key = f"{self.prefix}{session.session_id}"
            payload = json.dumps(asdict(session))
            r.setex(key, ttl_seconds, payload)
            if session.user_id:
                r.sadd(f"arogya:user_sessions:{session.user_id}", session.session_id)
        except Exception as e:
            logger.error("RedisSessionStore save failed: %s", e)

    def get(self, session_id: str) -> ServerSessionData | None:
        try:
            r = self._get_client()
            key = f"{self.prefix}{session_id}"
            val = r.get(key)
            if not val:
                return None
            data = json.loads(val)
            session = ServerSessionData(**data)
            if session.is_expired():
                self.delete(session_id)
                return None
            session.last_active_at = datetime.now(UTC).timestamp()
            self.save(session)
            return session
        except Exception as e:
            logger.error("RedisSessionStore get failed: %s", e)
            return None

    def delete(self, session_id: str) -> None:
        try:
            r = self._get_client()
            r.delete(f"{self.prefix}{session_id}")
        except Exception as e:
            logger.error("RedisSessionStore delete failed: %s", e)

    def delete_all_for_user(self, user_id: int) -> int:
        try:
            r = self._get_client()
            user_key = f"arogya:user_sessions:{user_id}"
            session_ids = r.smembers(user_key)
            count = 0
            for sid in session_ids:
                r.delete(f"{self.prefix}{sid}")
                count += 1
            r.delete(user_key)
            return count
        except Exception as e:
            logger.error("RedisSessionStore delete_all_for_user failed: %s", e)
            return 0


# ── Global Session Store Instance ─────────────────────────────────────────────

_session_store_instance: SessionStore | None = None


def get_session_store() -> SessionStore:
    """Returns the active SessionStore backend. Fails closed in production if Redis is missing."""
    global _session_store_instance
    if _session_store_instance is None:
        redis_uri = os.getenv("SESSION_REDIS_URL") or os.getenv("REDIS_URL")
        flask_env = os.getenv("FLASK_ENV", "").lower()
        if flask_env == "production":
            if not redis_uri:
                raise RuntimeError(
                    "CRITICAL: Production deployment requires distributed Redis session storage. "
                    "Set SESSION_REDIS_URL or REDIS_URL."
                )
            _session_store_instance = RedisSessionStore()
        else:
            _session_store_instance = MemorySessionStore()
    return _session_store_instance


def set_session_store(store: SessionStore | None) -> None:
    global _session_store_instance
    _session_store_instance = store


# ── Flask Session Interface Integration ──────────────────────────────────────

class ServerSideSession(CallbackDict, SessionMixin):
    """Proxy object implementing Flask's Session interface on server-side state."""

    def __init__(self, initial=None, sid=None, server_data=None, is_new=False):
        def on_update(self):
            self.modified = True
        super().__init__(initial, on_update)
        self.sid = sid
        self.server_data = server_data
        self.modified = False
        # True until the session has been written to the store at least once
        self.is_new = is_new

    def regenerate(self) -> str:
        """
        Atomically regenerates the session identifier, migrating existing data
        and explicitly invalidating the previous session ID from server-side storage.
        Prevents session fixation and fulfills Section 17 requirements.
        """
        old_sid = self.sid
        new_sid = secrets.token_hex(32)
        store = get_session_store()

        if old_sid:
            store.delete(old_sid)

        self.sid = new_sid
        self["_sid"] = new_sid
        if self.server_data:
            self.server_data.session_id = new_sid
            store.save(self.server_data)
        self.modified = True
        return new_sid


class ServerSideSessionInterface(SessionInterface):
    """
    Flask SessionInterface storing all sensitive state server-side.
    The browser receives an opaque session identifier cookie only.
    """

    session_class = ServerSideSession

    def generate_sid(self) -> str:
        return secrets.token_hex(32)

    def open_session(self, app, request) -> ServerSideSession:
        cookie_name = app.config.get("SESSION_COOKIE_NAME", "session_id")
        sid = request.cookies.get(cookie_name)
        store = get_session_store()

        if sid:
            server_data = store.get(sid)
            if server_data:
                # Synchronize user fields into dictionary view
                session_dict = dict(server_data.data or {})
                if server_data.user_id is not None:
                    session_dict["user_id"] = server_data.user_id
                if server_data.username is not None:
                    session_dict["username"] = server_data.username
                if server_data.role is not None:
                    session_dict["role"] = server_data.role
                if server_data.tenant_id is not None:
                    session_dict["tenant_id"] = server_data.tenant_id
                if server_data.session_version is not None:
                    session_dict["session_version"] = server_data.session_version
                if server_data.auth_state is not None:
                    session_dict["auth_state"] = server_data.auth_state
                session_dict["_sid"] = sid
                return self.session_class(session_dict, sid=sid, server_data=server_data)

        # Create new unauthenticated server-side session. It is NOT persisted here: health
        # probes, bots and static requests would otherwise create a store entry per request.
        # save_session() writes it only once it carries real state (CSRF token, login, ...).
        new_sid = self.generate_sid()
        new_server_data = ServerSessionData(
            session_id=new_sid,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None
        )
        initial_dict = {"_sid": new_sid, "auth_state": "UNAUTHENTICATED"}
        return self.session_class(initial_dict, sid=new_sid, server_data=new_server_data, is_new=True)

    def save_session(self, app, session, response) -> None:
        cookie_name = app.config.get("SESSION_COOKIE_NAME", "session_id")
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)

        # If session was cleared/deleted
        if not session:
            sid = getattr(session, "sid", None)
            if sid:
                get_session_store().delete(sid)
            response.delete_cookie(cookie_name, domain=domain, path=path)
            return

        sid = getattr(session, "sid", None) or session.get("_sid")
        if not sid:
            return

        # Skip persisting (and issuing a cookie for) a brand-new session that holds no state
        is_empty = set(session.keys()) <= {"_sid", "auth_state"}
        if getattr(session, "is_new", False) and is_empty \
                and session.get("auth_state", "UNAUTHENTICATED") == "UNAUTHENTICATED":
            return

        # Synchronize modified dictionary back to server-side record
        store = get_session_store()
        server_data = store.get(sid) or ServerSessionData(session_id=sid)

        server_data.user_id = session.get("user_id")
        server_data.username = session.get("username")
        server_data.role = session.get("role")
        server_data.tenant_id = session.get("tenant_id", "tenant-default")
        server_data.session_version = session.get("session_version", 1)
        server_data.auth_state = session.get("auth_state", "UNAUTHENTICATED")
        server_data.mfa_state = session.get("mfa_state")
        server_data.last_active_at = datetime.now(UTC).timestamp()

        # Isolate custom user keys from session
        custom_data = {k: v for k, v in session.items() if k not in ("user_id", "username", "role", "tenant_id", "session_version", "auth_state", "mfa_state", "_sid")}
        server_data.data = custom_data

        store.save(server_data)
        session.is_new = False

        # Write opaque session identifier cookie to client
        httponly = True
        samesite = app.config.get("SESSION_COOKIE_SAMESITE", "Lax")
        secure = app.config.get("SESSION_COOKIE_SECURE", False)

        response.set_cookie(
            cookie_name,
            sid,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite
        )
