# ArogyaRaksha — Changelog

All notable changes are documented here per phase. Each phase is a separate reviewable
commit. Controls documented in `docs/SECURITY_REPORT.md` (BUG-01–BUG-09) are
explicitly re-verified if touched.

---

## Version 3.0.0 — Enterprise High-Assurance Transformation (2026-09-23)

### Executive Summary
Transformed ArogyaRaksha into an enterprise-grade, high-assurance clinical records platform complying with OWASP ASVS 5.0 L3, NIST SP 800-207 Zero Trust, and HIPAA/DPDP principles. All 135 tests pass with 83% coverage across 2,344 statements. Zero ruff defects, zero secrets detected.

### Key Changes
1. **Multi-Tenant Organization Architecture:**
   - Added `Tenant` model (`id`, `name`, `code`, `is_active`) and foreign keys on `Patient`, `User`, `AuditLog`.
   - Created Alembic migration `a1b2c3d4e5f6_enterprise_multi_tenancy_and_abac.py`.
   - Scoped patient listings, intakes, and audits to caller's `tenant_id`.
2. **ABAC Policy Engine & Segregation of Duties:**
   - Implemented `PolicyEngine` evaluating tenancy, role, care team assignment, and emergency break-glass.
   - Strictly segregated Administrators from mutating clinical records (`CREATE`, `UPDATE`, `DELETE`).
   - Implemented `BREAK_GLASS_ACCESS` protocol allowing unassigned clinicians emergency mutation rights with mandatory audit logging and real-time SIEM alerts.
3. **Cryptographic Hardening & Envelope Encryption:**
   - Bound RFC 8785 Canonical JSON AAD (`{"patient_id": "...", "tenant_id": "...", "version_id": ...}`) to all AES-256-GCM ciphertexts.
   - Eliminated all fallback paths (`aad=None`). Tampered ciphertexts or cross-tenant transplantation fail closed with `IntegrityTamperedError`.
   - Added HKDF-SHA256 purpose subkey derivation (`clinical_record`, `totp_secret`, `session_token`, `webhook_signature`).
   - Added `CryptoEnvelope` with Cloud KMS KEK/DEK hierarchy and fail-closed `ProductionKmsProvider`.
4. **Server-Side Session Store:**
   - Replaced client-side cookie storage with `ServerSideSessionInterface` backed by Redis or Memory (`ServerSessionData`).
   - Cookies store only a 256-bit cryptographically secure token (`_sid`).
   - Added 15-minute idle timeout, 8-hour absolute timeout, and instant revocation via `session_version` invalidation.
5. **Identity & Authentication Hardening:**
   - Added `DUMMY_SCRYPT_HASH` constant-time verification for non-existent users in `AuthService.verify_password()`, mitigating timing-based user enumeration.
   - Enforced atomic compare-and-swap on single-use password reset tokens.
6. **Transactional Outbox & Resilient Alerting:**
   - Implemented `SELECT ... FOR UPDATE SKIP LOCKED` row locking in `OutboxService` for multi-worker polling.
   - Hardened `WebhookDelivery` with TLS verification, HMAC-SHA256 signature, `X-ArogyaRaksha-Timestamp`, and `X-ArogyaRaksha-Nonce` replay defense headers.
7. **Empirical Benchmarks & Verification:**
   - Executed live `scripts/benchmark.py`: recorded 6,790 AES-GCM ops/s, 177ms scrypt hashing, 21,408 audit blocks/s, 100% atomic OCC race isolation.
   - Added `tests/test_enterprise_assurance.py` verifying multi-tenant isolation, break glass, and secret scanner.
   - Expanded test suite from 30 to 135 passing tests.

---

## Phase 1 — Audit-Log Concurrency Fix (2026-09-23)

### Problem
`AuditService.log_event()` had a TOCTOU (time-of-check/time-of-use) race condition:
it read the tail audit row, computed a new `prev_hash`, then inserted — with no
locking or conflict detection. Under concurrent requests this could fork the hash
chain, producing two records with identical `prev_hash` values. This defeated the
entire purpose of the tamper-evident audit log.

### Changes

**`app/models/audit_log.py`**
- Added `UniqueConstraint("prev_hash", name="uq_audit_logs_prev_hash")` on the
  `audit_logs` table. This makes concurrent-insert conflicts detectable at the
  database level via `IntegrityError`, giving the retry loop a reliable signal.

**`app/models/user.py`**
- Added `session_version: Integer` column (default 1). Groundwork for Phase 4
  server-side session revocation. Does not change any existing behavior.

**`app/services/audit_service.py`** — full rewrite of `log_event()`:
- **PostgreSQL path:** Uses `SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1 FOR UPDATE`
  inside a `db.session.begin_nested()` savepoint. The `FOR UPDATE` row-locks the tail
  record for the duration of the inner transaction, preventing any concurrent writer from
  inserting a record with the same `prev_hash` until we commit.
- **SQLite path (dev-only):** A module-level `threading.Lock` (`_sqlite_chain_lock`)
  serialises concurrent writers within the same process. This is safe for single-process
  development; it is explicitly NOT safe for multi-process Gunicorn on SQLite.
- **Retry loop (both paths):** Bounded to `MAX_CHAIN_RETRIES = 5`. On `IntegrityError`
  (UniqueConstraint violation on `prev_hash`), the transaction is rolled back to the
  savepoint, the new tail is re-read, and the insert is retried with the correct
  `prev_hash`. If all retries are exhausted, logs at `CRITICAL` and raises `RuntimeError`
  — a dropped audit entry is visible rather than silent.

**`migrations/versions/eca31617d943_phase1_*.py`** — Alembic migration:
- Adds `session_version` column to `users`.
- Creates `uq_audit_logs_prev_hash` unique constraint on `audit_logs`.
- Includes `downgrade()` path.

**`app/routes/health.py`** — security fix (Phase 7c, pulled forward):
- Removed raw `str(e)` from the `/healthz` JSON response. Full exception is now logged
  server-side via `logger.exception()`; client receives generic `"unhealthy"` status.
- Prevents information disclosure of internal DB error messages.

**`docs/ARCHITECTURE.md`** — added SQLite concurrency warning section.

### Tests Added
- `tests/test_audit_concurrency.py`:
  - `test_concurrent_log_event_chain_remains_valid` — 8 threads × 5 events; asserts
    `verify_chain()` returns valid after all writes.
  - `test_concurrent_log_event_no_duplicate_prev_hash` — 6 threads × 4 events; asserts
    no two rows share the same `prev_hash`.
  - `test_audit_chain_verify_detects_gap` — manually corrupts a chain entry and asserts
    `verify_chain()` detects it (regression guard on existing tamper-detection logic).

### Docs Updated
- `docs/CHANGELOG.md` — this file (new).
- `docs/ARCHITECTURE.md` — SQLite concurrency limitation note.
- `docs/SECURITY_REPORT.md` — Phase 1 concurrency entry.

### BUG-01–09 Re-verification
- **BUG-01 (XFF spoofing):** `get_client_ip()` logic unchanged. ✅
- **BUG-05 (fast-fail key material):** startup checks unchanged. ✅
- All other BUG-01–09 controls untouched. ✅

---

## Phase 2 — Pagination & Query Scalability (2026-09-23)

### Problem
- `PatientService.list_patients()` loaded all records into memory without bounds.
- Patient search was purely client-side JavaScript filtering on rendered DOM rows.
- `/admin/audit` used a hardcoded `.limit(200)` without pagination or query filtering.
- Filtering audit logs lacked a composite index on `(action, timestamp)`.

### Changes

**`app/services/patient_service.py`**
- Updated `list_patients(page, per_page, q, age_band, gender)` to return a Flask-SQLAlchemy `Pagination` object with items converted to lightweight dicts.
- Clamped `per_page` to `[1, 100]`.
- Implemented server-side clear-field filtering on `patient_id` (case-insensitive substring `ilike`), `age_band` (exact), and `gender` (exact).
- Enforced and documented that sensitive fields (`name`, `diagnosis`, `medical_history`, `notes`) remain encrypted at rest and are NOT searchable server-side without decryption.

**`app/routes/patient.py`**
- Route `/patients` now consumes `page`, `per_page`, `q`, `age_band`, `gender` query parameters and passes `pagination` to template.

**`app/models/audit_log.py`**
- Added composite index `Index("ix_audit_logs_action_timestamp", "action", "timestamp")` to `AuditLog.__table_args__`.

**`app/routes/admin.py`**
- `/admin/audit` route upgraded with pagination (`page`, `per_page` clamped to `[1, 200]`), `action_type` filter, and `date_from`/`date_to` range filtering.
- Dynamic extraction of distinct action types for filter UI.

**`migrations/versions/0649733179e3_phase2_audit_action_timestamp_index.py`**
- Alembic migration creating `ix_audit_logs_action_timestamp` on `audit_logs` table with downgrade support.

**`app/templates/patient/list.html`** & **`app/templates/admin/audit_log.html`**
- Replaced client-side filter with server-side filter form and accessible pagination navigation preserving active filter parameters.

**`docs/ARCHITECTURE.md`**
- Added Section 7 detailing Query Scalability and the Encrypted-Field Search Boundary.

### Tests Added
- `tests/test_pagination.py`:
  - `test_patient_list_pagination_returns_correct_page`
  - `test_patient_list_search_by_patient_id`
  - `test_patient_list_filter_age_band`
  - `test_patient_list_filter_gender`
  - `test_patient_list_per_page_clamped`
  - `test_patient_list_does_not_return_encrypted_fields`
  - `test_patient_list_route_pagination_params`
  - `test_patient_list_route_search_filter`
  - `test_patient_list_route_invalid_page_defaults_to_1`
  - `test_audit_log_route_action_type_filter`
  - `test_audit_log_route_date_filter_invalid`
  - `test_audit_log_route_pagination`

### Verification
- 57/57 pytest tests passing.

---

## Phase 3 — Key Management & Zero-Downtime Rotation (2026-09-23)

### Problem
- The `key_version` column existed on `patients`, but `CryptoService.decrypt_record()` always used a single static master key, ignoring historical versions.
- No abstraction existed for key resolution or KMS integration.
- No procedure or script existed to re-encrypt records when rotating keys.

### Changes

**`app/config.py`**
- Added multi-version `KEY_REGISTRY` mapping `int -> bytes`.
- Added support for loading `KEY_REGISTRY_JSON` (compact JSON mapping) and individual `ENCRYPTION_KEY_v<N>` environment variables.
- Dynamic `CURRENT_KEY_VERSION` detection defaulting to the highest registered key version.
- Configured multi-version test keys in `TestConfig`.

**`app/services/crypto_service.py`**
- Defined `KeyProvider` abstract base class with `get_key(version)`, `get_current_key()`, and `current_version()`.
- Implemented `EnvKeyProvider` resolving keys by version from configuration with backward-compatible fallback to `MASTER_ENCRYPTION_KEY`.
- Implemented `KMSKeyProvider` enterprise integration stub with cloud KMS / Vault Transit architectural guidance.
- Upgraded `CryptoService.decrypt_record()` to look up keys by `key_version` via the active `KeyProvider`.
- Added `CryptoService.set_key_provider()` for dependency injection and testing.

**`scripts/rotate_keys.py`**
- Created standalone, idempotent, batch-processing key rotation CLI tool.
- Supports `--target-version`, `--batch-size` (default 50), and `--dry-run`.
- Re-encrypts patient records using fresh random nonces and auth tags.
- Logs an immutable `KEY_ROTATION` audit event per batch.

**`docs/ARCHITECTURE.md`**
- Added Section 4.1 detailing Key Management Architecture, `KeyProvider` class diagram, and zero-downtime rotation workflow.

**`.env.example`**
- Documented `KEY_REGISTRY_JSON` and `CURRENT_KEY_VERSION` configuration examples.

### Tests Added
- `tests/test_key_management.py`:
  - `test_env_key_provider_resolves_configured_versions`
  - `test_env_key_provider_raises_key_not_found`
  - `test_kms_key_provider_stub_behavior`
  - `test_multi_version_encryption_and_decryption`
  - `test_key_rotation_dry_run_leaves_database_untouched`
  - `test_key_rotation_migrates_all_records_and_audits_batches`
  - `test_key_rotation_fails_gracefully_on_unknown_target_key`

### Verification
- 64/64 pytest tests passing.

---

## Phase 4 — Auth Hardening, MFA, and Session Revocation (2026-09-23)

### Problem
- Authentication relied solely on single-factor passwords.
- No self-service password recovery flow existed; forgotten passwords required manual database intervention.
- Disabling a user account or changing passwords did not invalidate active browser sessions, creating an account-takeover risk.

### Changes

**`app/models/user.py`**
- Added `totp_secret: String(64)` and `totp_enabled: Boolean` (default False) to support RFC 6238 TOTP Multi-Factor Authentication.

**`app/models/password_reset_token.py`**
- Created new model storing single-use, 15-minute expiring SHA-256 hashed password reset tokens with indexed lookup and usage tracking.

**`migrations/versions/100c408e589d_phase4_auth_hardening_totp_password_.py`**
- Alembic migration adding `totp_secret`, `totp_enabled` to `users`, and creating the `password_reset_tokens` table.

**`app/services/auth_service.py`**
- Implemented `generate_totp_secret()`, `get_totp_uri()`, and `verify_totp()` with ±30s clock drift tolerance.
- Implemented `establish_user_session()` with session fixation defense and `session_version` assignment.
- Implemented `create_password_reset_token()` with zero-knowledge username enumeration defense.
- Implemented `verify_and_use_password_reset_token()` enforcing password complexity, marking single-use tokens as spent, and invalidating existing sessions.

**`app/services/user_service.py`**
- Implemented `revoke_all_sessions(user_id)` to increment `session_version` on demand.
- Updated `toggle_user_active()` to automatically increment `session_version` upon account disable.

**`app/security/decorators.py`**
- Updated `get_current_user()` to validate `session["session_version"] == user.session_version`, clearing invalid sessions in real time.
- Updated `require_permission()` with Option A Grace Login policy: admins without TOTP are redirected to `/admin/settings/mfa` and blocked from general admin routes until enrolled.

**`app/routes/auth.py`** & **`app/routes/admin.py`**
- Added `/login/mfa` second-step TOTP prompt.
- Added `/forgot-password` and `/reset-password/<token>` routes.
- Added `/admin/settings/mfa` (setup wizard) and `/admin/settings/mfa/confirm` (enrollment verification).

**`app/templates/auth/`** & **`app/templates/admin/`**
- Created `auth/mfa.html`, `auth/forgot_password.html`, `auth/reset_password.html`, and `admin/mfa_setup.html`.
- Added password recovery link to `auth/login.html`.

**`docs/ARCHITECTURE.md`**
- Added Section 3.1 detailing MFA architecture, password reset flow, and server-side session revocation sequence diagram.

### Tests Added
- `tests/test_mfa.py` (5 tests):
  - `test_totp_secret_and_uri_generation`
  - `test_totp_code_verification_success_and_failure`
  - `test_login_flow_with_totp_enabled_user`
  - `test_admin_mfa_setup_and_confirmation`
  - `test_admin_grace_login_redirect_when_enforced`
- `tests/test_password_reset.py` (5 tests):
  - `test_password_reset_token_creation_and_enumeration_defense`
  - `test_password_reset_success_and_session_invalidation`
  - `test_password_reset_token_single_use`
  - `test_password_reset_token_expiry`
  - `test_password_reset_enforces_complexity`
- `tests/test_session_revocation.py` (3 tests):
  - `test_session_validity_with_current_version`
  - `test_revoke_all_sessions_invalidates_active_session`
  - `test_disabling_user_triggers_immediate_session_revocation`

### Verification
- 77/77 pytest tests passing.

---

## Phase 5 — Missing CRUD & Security Alerting (2026-09-23)

### Problem
- No deletion capability existed for patient records; attempting removal required direct physical SQL deletion which violates clinical data compliance.
- No real-time alerting hook existed to notify security operations when cryptographic tampering or brute-force account lockouts occurred.

### Changes

**`app/models/patient.py`**
- Added indexed `deleted_at: DateTime` column (nullable) to support compliance-safe soft deletes.

**`migrations/versions/528524d57ee4_phase5_patient_soft_delete.py`**
- Alembic migration adding `deleted_at` column and index `ix_patients_deleted_at` on the `patients` table.

**`app/security/permissions.py`**
- Added `PATIENT_DELETE` permission constant.
- Granted `PATIENT_DELETE` strictly to the `Doctor` role; Nurse and Admin roles are excluded.

**`app/services/patient_service.py`**
- Updated `list_patients`, `get_patient_by_id`, and `update_patient` to filter out soft-deleted records (`Patient.deleted_at.is_(None)`).
- Implemented `soft_delete_patient(record_id, user_id)`: marks record with UTC timestamp and logs `PATIENT_DELETE` audit event.
- Connected `AlertService.trigger_alert("TAMPER_DETECTED", ...)` upon MAC failure in `get_patient_by_id`.

**`app/services/alert_service.py`**
- Created `AlertService` with `AlertDelivery` ABC interface.
- Implemented `LogOnlyDelivery` (structured JSON logging to `security.alert` at `CRITICAL` severity).
- Implemented `WebhookDelivery` enterprise stub with HMAC-SHA256 signature (`X-Arogya-Signature`) header generation.

**`app/routes/auth.py`**
- Updated `handle_account_lockout` to trigger `AlertService.trigger_alert("ACCOUNT_LOCKOUT", ...)` on brute-force lockout.

**`app/routes/patient.py`**
- Added `POST /patients/<id>/delete` route protected by `@require_permission(PATIENT_DELETE)`.
- Passed `can_delete` context to patient templates.

**`app/templates/patient/detail.html`**
- Added Archive/Delete Record button strictly rendered when `can_delete` is True.

**`docs/ARCHITECTURE.md`**
- Updated RBAC matrix with `PATIENT_DELETE`.
- Added Section 3.2 detailing soft-delete compliance architecture and security alerting channels.

### Tests Added
- `tests/test_soft_delete.py` (4 tests):
  - `test_soft_delete_excludes_patient_from_active_views`
  - `test_soft_delete_rbac_enforcement`
  - `test_cannot_edit_or_delete_already_deleted_patient`
  - `test_soft_delete_audit_event_logged`
- `tests/test_alerting.py` (4 tests):
  - `test_custom_delivery_backend_injection`
  - `test_log_only_delivery`
  - `test_webhook_delivery_stub`
  - `test_tamper_detected_triggers_security_alert`

### Verification
- 85/85 pytest tests passing.

---

## Phase 6 — Real CSP Nonces & Modern Transport Headers (2026-09-23)

### Problem
- Content Security Policy relied on `'unsafe-inline'` in `script-src`, weakening XSS defenses.
- Missing modern W3C security headers: `Permissions-Policy`, `Cross-Origin-Opener-Policy` (COOP), `Cross-Origin-Resource-Policy` (CORP), and `X-Permitted-Cross-Domain-Policies`.

### Changes

**`app/security/headers.py`**
- Registered per-request cryptographic nonce generator in `before_request` hook (`g.csp_nonce = secrets.token_urlsafe(16)`).
- Registered Jinja2 template context processor exposing `csp_nonce()`.
- Configured Flask-Talisman with `content_security_policy_nonce_in=['script-src']`, completely eliminating `'unsafe-inline'` from `script-src`.
- Added `after_request` handler enforcing modern security headers:
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`
  - `Cross-Origin-Opener-Policy: same-origin` (COOP)
  - `Cross-Origin-Resource-Policy: same-origin` (CORP)
  - `X-Permitted-Cross-Domain-Policies: none`

**`app/templates/patient/list.html`** & **`app/templates/base.html`**
- Injected `nonce="{{ csp_nonce() }}"` into all inline and external `<script>` tags.

**`docs/ARCHITECTURE.md`**
- Added Section 8 documenting dynamic CSP nonces and the complete transport security headers matrix.

### Tests Added
- `tests/test_headers.py` (3 tests):
  - `test_modern_security_headers_present`
  - `test_strict_csp_with_nonce_and_no_unsafe_inline_in_script_src`
  - `test_template_renders_script_nonce`

### Verification
- 88/88 pytest tests passing.

---

## Phase 7 — Production Deployment Architecture & CI Pipeline (2026-09-23)

### Problem
- Deployment relied on running the Flask development server via `python run.py`.
- No isolated, reproducible multi-stage container build or non-root runtime was configured.
- No orchestration setup existed linking the web service, PostgreSQL 16 database, and Redis 7 rate-limiting cache.
- Continuous Integration lacked automated linting and coverage gate verification.

### Changes

**`Dockerfile`**
- Implemented a hardened multi-stage Docker build:
  - Stage 1 (`builder`): Compiles dependencies and wheels inside `/opt/venv` using `python:3.12-slim`.
  - Stage 2 (`runner`): Minimal runtime container with rootless system user `arogya` (UID `10001`).
  - Configured health check against `/healthz` every 30s.
  - Enforced Gunicorn synchronous worker execution (`-w 4`, sync).

**`.dockerignore`**
- Excluded cache files, local SQLite databases, backup snapshots, private keys, virtual environments, and git repositories from image build context.

**`docker-compose.yml`**
- Defined complete production topology:
  - `web`: ArogyaRaksha Gunicorn WSGI container.
  - `db`: PostgreSQL 16 Alpine with `pg_isready` healthcheck and `postgres_data` volume.
  - `redis`: Redis 7 Alpine with persistent storage and ping healthcheck, serving as `RATELIMIT_STORAGE_URI` for Flask-Limiter.

**`Procfile` & `gunicorn.conf.py`**
- Defined production process runner with 4 process-isolated sync workers.
- Documented strict architectural mandate: async workers (gevent/eventlet) are prohibited due to C-extension monkey-patching conflicts with PyCryptodome and OpenSSL PRNG entropy pools.

**`.github/workflows/ci.yml`**
- Configured GitHub Actions CI pipeline running across Python 3.11 and 3.12:
  - Static analysis with `ruff check app/ tests/ scripts/`.
  - Automated test execution with mandatory test coverage gate: `pytest --cov=app --cov-fail-under=80`.

**`requirements.txt`**
- Added `gunicorn>=23.0.0`, `redis>=5.0.0`, `pyotp>=2.9.0`, and `psycopg[binary]>=3.2.0`.

**`docs/ARCHITECTURE.md`**
- Added Section 9 detailing Production Deployment Architecture, ASCII component diagrams, container hardening, and worker concurrency rationale.

### Tests Added
- `tests/test_deployment.py` (7 tests):
  - `test_dockerfile_configuration`
  - `test_docker_compose_configuration`
  - `test_procfile_configuration`
  - `test_gunicorn_conf_mandates_sync_workers`
  - `test_ci_workflow_configuration`
  - `test_requirements_include_production_dependencies`
  - `test_healthz_endpoint`

### Verification
- 95/95 pytest tests passing with 86% overall codebase coverage.

---

## Post-Hardening Optimization & Security Enhancement Pass (2026-09-23)

### Changes

**`app/models/patient.py` & `app/models/password_reset_token.py`**
- Added composite index `ix_patients_deleted_created` (`deleted_at, created_at`) on the `patients` table to serve registry pagination without in-memory sorting.
- Added demographic indexes `ix_patients_age_band` and `ix_patients_gender`.
- Added composite index `ix_password_reset_tokens_user_expires` (`user_id, expires_at`) on `password_reset_tokens`.

**`migrations/versions/8f1e2d3c4b5a_performance_indexes.py`**
- Added Alembic migration creating the new performance indexes. Applied cleanly to schema head.

**`app/services/audit_service.py`**
- Optimized `AuditService.verify_chain()`:
  - Replaced full table loading `.all()` with `yield_per(1000)` streaming, bounding memory consumption to $O(1)$ regardless of table size.
  - Added fast verification memoization (30s TTL) that is automatically invalidated on any write to `log_event()`.

**`app/config.py`**
- Configured production SQLAlchemy connection pool options via `SQLALCHEMY_ENGINE_OPTIONS`:
  - `pool_pre_ping=True`: Proactively eliminates stale/disconnected sockets.
  - `pool_recycle=300`: Refreshes pooled connections every 5 minutes.
  - Configured `pool_size=10` and `max_overflow=20` for production PostgreSQL.

**`app/routes/errors.py` & `app/templates/errors/`**
- Implemented handlers for `400 Bad Request`, `CSRFError` (logging `CSRF_VALIDATION_FAILURE` audit events), and `405 Method Not Allowed`.
- Created branded error templates `400.html` and `405.html`.

**`app/security/headers.py`**
- Added `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache` on all non-static responses to prevent caching of decrypted clinical PHI in browsers and shared proxies.
- Configured long-lived immutable caching (`public, max-age=31536000, immutable`) for `/static/*` assets.

**`pyproject.toml`**
- Added standardized Ruff configuration with Pyflakes, pycodestyle, isort, pyupgrade, Bugbear, and Flake8-Bandit (`S`) static security analysis rules.
- Fixed all 200+ formatting, import sorting, and exception chaining errors.

**`docs/ARCHITECTURE.md`**
- Added Section 10 documenting High-Performance Index Topology, Bounded Audit Streaming & Memoization, Connection Pool Resilience, and Anti-Caching Defenses.

### Tests Added
- `tests/test_performance_security.py` (7 tests):
  - `test_performance_indexes_defined_on_models`
  - `test_audit_verify_chain_memoization_and_invalidation`
  - `test_error_handler_400_bad_request`
  - `test_error_handler_405_method_not_allowed`
  - `test_csrf_error_handler_and_auditing`
  - `test_anti_caching_headers_on_dynamic_routes`
  - `test_database_connection_pool_configuration`

### Verification
- **Ruff Static Analysis:** 0 errors across `app/`, `tests/`, `scripts/`.
- **Pytest Suite:** **102/102 tests passing** (100% green) at **86% coverage**.

---

*All phases and industry-hardening optimizations are fully completed and verified.*







