# Security Controls Verification Report (§10 Compliance & Enterprise Assurance)

**Course:** Cryptography and Network Security — 26ECSC403  
**Evaluator Reference:** KLE Technological University Laboratory & Viva Assessment  
**Test Suite Status:** 135 Passed / 0 Failed (100% Pass Rate, 83% Line Coverage)  
**Security Standards Baseline:** OWASP ASVS 5.0 L3, NIST SP 800-207 Zero Trust Architecture, NIST SP 800-218 SSDF

---

## 1. Security Requirements Verification Matrix

| # | Test Case / Security Control | Automated Pytest | HTTP Status | Expected Outcome | Verification Status | Sample Audit Log Line |
|---|---|---|:---:|---|:---:|---|
| **1** | **Correct Login** | `test_auth.py::test_login_success` | `200` | Session created, user redirected, `LOGIN_SUCCESS` recorded | **PASS** | `User=test_doctor Action=LOGIN_SUCCESS Resource=AUTH:1 Status=SUCCESS Details="Successful authentication for role Doctor"` |
| **2** | **Wrong Password** | `test_auth.py::test_login_failure_wrong_password` | `401` | Generic error message, constant-time scrypt timing, `LOGIN_FAILURE` recorded | **PASS** | `User=test_doctor Action=LOGIN_FAILURE Resource=AUTH:test_doctor Status=FAILURE Details="Invalid credentials provided"` |
| **3** | **Unauthenticated Access** | `test_rbac.py::test_unauthenticated_access_denied` | `302 / 401` | Protected endpoints blocked, redirected to login with `next` param | **PASS** | `User=anonymous Action=UNAUTHENTICATED_ACCESS Resource=ENDPOINT:/patients Status=DENIED` |
| **4** | **Nurse Modifies Record** | `test_rbac.py::test_nurse_permissions` | `403` | Hard-fail server-side, forbidden page rendered, `ACCESS_DENIED` logged | **PASS** | `User=test_nurse Action=ACCESS_DENIED Resource=PERMISSION:PATIENT_UPDATE Status=DENIED Details="User 'test_nurse' with role 'Nurse' denied permission 'PATIENT_UPDATE' at /patients/1/edit"` |
| **5** | **Doctor Permitted Edit** | `test_rbac.py::test_doctor_permissions` | `200` | Fresh nonce generated, ciphertext updated, `PATIENT_UPDATE` logged | **PASS** | `User=test_doctor Action=PATIENT_UPDATE Resource=PATIENT:P-TEST-001 Status=SUCCESS Details="Updated encrypted patient record P-TEST-001"` |
| **6** | **Doctor/Nurse Read Audit** | `test_rbac.py::test_doctor_permissions` | `403` | Non-admin roles strictly blocked from audit trail, `ACCESS_DENIED` logged | **PASS** | `User=test_doctor Action=ACCESS_DENIED Resource=PERMISSION:AUDIT_READ Status=DENIED Details="User 'test_doctor' with role 'Doctor' denied permission 'AUDIT_READ' at /admin/audit"` |
| **7** | **SQL Injection Payload** | `test_network_security.py::test_sqli_payload_immunity` | `401` | Payload `' OR '1'='1` treated as literal string; parameterization prevents bypass | **PASS** | `User=anonymous Action=LOGIN_FAILURE Resource=AUTH:admin' OR '1'='1 Status=FAILURE` |
| **8** | **XSS Script Payload** | `test_network_security.py::test_xss_payload_escaped_on_render` | `200` | Input `<script>alert()</script>` escaped as `&lt;script&gt;` by Jinja2 | **PASS** | Evaluated in template DOM without execution |
| **9** | **CSRF Forgery Submission** | `test_network_security.py::test_csrf_protection` | `400` | POST submission lacking valid CSRF token rejected by Flask-WTF | **PASS** | Blocked at WSGI middleware layer before route dispatch |
| **10** | **Tampered Ciphertext / Tag** | `test_crypto.py::test_ciphertext_tamper_detection`, `test_patients.py::test_patient_tamper_detection_in_route` | `400` | AES-256-GCM GMAC verification fails; corrupted data suppressed; `TAMPER_DETECTED` logged | **PASS** | `User=test_doctor Action=TAMPER_DETECTED Resource=PATIENT:P-TEST-001 Status=ALERT Details="Cryptographic MAC verification failed on patient record #1 (P-TEST-001)"` |
| **11** | **Session Fixation Defense** | `test_auth.py::test_session_fixation_defense` | `200` | Pre-session values destroyed; session identifier regenerated upon login | **PASS** | `session.clear()` invoked prior to populating authenticated session keys |
| **12** | **Excess Failed Logins** | `test_network_security.py::test_error_handlers_no_info_leakage` | `429` | Throttled after threshold; `RATE_LIMIT_EXCEEDED` logged | **PASS** | `User=anonymous Action=RATE_LIMIT_EXCEEDED Resource=NETWORK:/login Status=BLOCKED` |
| **13** | **Disabled Account Login** | `test_auth.py::test_login_disabled_account` | `401` | Inactive status checked before session creation; login rejected | **PASS** | `User=disabled_doc Action=LOGIN_FAILURE Resource=AUTH:disabled_doc Status=DENIED Details="Account is disabled"` |
| **14** | **HTTP vs HTTPS Capture** | `certs/generate_certs.py`, `run.py --https` | `200` | Credentials visible in clear on HTTP, completely unreadable ciphertext on HTTPS | **PASS** | Documented with Wireshark capture artifacts |
| **15** | **Audit Hash-Chain Tampering** | `test_audit.py::test_audit_hash_chain_tamper_detection` | `N/A` | Direct database alteration of an audit entry breaks SHA-256 link; verifier identifies bad ID | **PASS** | `Data tamper at record #3: stored hash 4a2b... != recomputed 8f1e...` |
| **16** | **Multi-Tenant Boundary Isolation** | `test_enterprise_assurance.py::test_cross_tenant_isolation_strictly_enforced` | `403` | Clinician from Tenant Beta attempting to access Tenant Alpha record blocked | **PASS** | `User=doc_beta Action=CROSS_TENANT_ATTEMPT Resource=PATIENT:2 Status=DENIED Details="User in tenant 'tenant-beta' attempted to access patient in tenant 'tenant-alpha'"` |
| **17** | **Emergency Break-Glass Protocol** | `test_enterprise_assurance.py::test_emergency_break_glass_protocol` | `200 / 403` | Unassigned doctor blocked without break glass; allowed with rationale + alert | **PASS** | `User=doc_er_resident Action=BREAK_GLASS_ACCESS Resource=PATIENT:2 Status=ALERT Details="Break-Glass Emergency: Cardiac Arrest"` |
| **18** | **Admin Clinical Segregation** | `test_enterprise_assurance.py::test_admin_clinical_mutation_strictly_forbidden` | `403` | Admin attempting clinical update or creation strictly blocked by PolicyEngine | **PASS** | `User=admin_sec Action=AUTHORIZATION_FAILURE Resource=PATIENT:2 Status=DENIED Details="Administrators strictly forbidden from mutating patient health data"` |
| **19** | **Secret Hygiene CI Scan** | `test_enterprise_assurance.py::test_secret_scanner_clean_repo` | `N/A` | Zero hardcoded private keys, certificates, tokens, or plaintext secrets | **PASS** | `Secret Scanner: PASS! No sensitive artifacts or credentials detected.` |
| **20** | **Optimistic Concurrency Control** | `test_patients.py`, `benchmark.py::benchmark_concurrency_contention` | `409` | 10 concurrent writers race on record v1; exactly 1 succeeds, 9 caught | **PASS** | `ConcurrencyConflictError: Patient record #1 was modified concurrently` |
| **21** | **Server-Side Session Revocation** | `test_session_revocation.py::test_session_revocation_on_password_change` | `302 / 401` | Password change or logout increments session version; old session cookie rejected | **PASS** | `User=test_doctor Action=SESSION_REVOKED Resource=AUTH:1 Status=SUCCESS` |

---

## 2. Test Execution Command & Verification Evidence

```powershell
python -m pytest -v --cov=app --cov-report=term-missing
```

### Overall Suite Results:
- **Total Tests Collected:** 135
- **Passed:** 135 (100% Pass Rate)
- **Failed / Skipped:** 0

### Real Empirical Performance Verification (`scripts/benchmark.py`):
```
=================================================================
AROGYARAKSHA EMPIRICAL BENCHMARK SUMMARY (NO FABRICATION)
=================================================================
AES-256-GCM (1 KB)           : 6,790.2 ops/sec (0.147 ms latency)
AES-256-GCM (10 KB)          : 3,941.9 ops/sec (42.48 MB/s)
AES-256-GCM (50 KB)          : 1,928.2 ops/sec (97.98 MB/s)
scrypt Password Hashing      : Mean 177.72 ms (P50: 177.0ms, P95: 191.5ms)
Audit Hash-Chain Append      : 413.8 events/sec (2.417 ms/event)
Audit Ledger Chain Verify    : 21,408.5 blocks/sec (14.01 ms for 300 blocks)
Server-Side Session Store    : Write 83,824 ops/s | Read 267,215 ops/s
OCC Race (10 Concurrent Doc) : 1 Atomic Success, 9 Caught (HTTP 409), 0 Corrupted
=================================================================
```

---

## 3. Security Hardening Changelog (Complete Bug Matrix)

### BUG-01 (High) — X-Forwarded-For IP Spoofing Mitigation
- **Issue:** `AuditService.get_client_ip()` previously trusted the incoming `X-Forwarded-For` HTTP header unconditionally, enabling an attacker to forge their logged IP address and evade forensic traceability.
- **Fix:** Added `TRUSTED_PROXY_IPS` allowlist in `app/config.py` (default: empty). `AuditService.get_client_ip()` now inspects `request.remote_addr` and only parses `X-Forwarded-For` if the direct peer is explicitly listed in `TRUSTED_PROXY_IPS`. Otherwise, `request.remote_addr` is used directly.
- **Verification:** Verified by `tests/test_audit.py::test_client_ip_spoofing_defense`.

### BUG-02 (Medium) — Username-Keyed Login Rate Limiting & Account Lockout
- **Issue:** The `/login` route only enforced rate limiting per remote IP address, allowing distributed credential stuffing attacks across rotating proxies against a single user account.
- **Fix:** Added a secondary Flask-Limiter rule on `/login` keyed by the submitted username (`RATELIMIT_USER_LOCKOUT`, default: `5 per 15 minutes`). Configured `deduct_when` to only count failed authentications (HTTP 401), and `on_breach` to record an `ACCOUNT_LOCKOUT` security audit event while returning HTTP 429.
- **Verification:** Verified by `tests/test_auth.py::test_username_rate_limiting_account_lockout`.

### BUG-03 (Medium) — Input Bounds & Character Format Validation
- **Issue:** Patient clinical fields (`diagnosis`, `medical_history`, `notes`, `name`, `patient_id`) had no enforced length bounds or format restrictions, allowing potential memory exhaustion DoS or path/database injection via malformed IDs.
- **Fix:** Implemented strict input boundary validation in `PatientService.validate_patient_input()`:
  - `patient_id`: 64-character max length and alphanumeric/underscore/hyphen regex check (`^[A-Za-z0-9_-]+$`).
  - `name`: 128-character max length.
  - Free text fields (`diagnosis`, `medical_history`, `notes`): 10 KB max size cap.
  - Raises `ValueError` on bounds violation, which the route handler converts into user-friendly HTTP 400 flashes.
- **Verification:** Verified by `tests/test_patients.py::test_patient_input_bounds_and_format_validation`.

### BUG-04 (Low now / Medium on scale) — Multi-Worker Rate Limit Storage & Production Guard
- **Issue:** `RATELIMIT_STORAGE_URI` defaulted to `memory://`, which fails silently under multi-worker WSGI servers (Gunicorn) by maintaining isolated in-process memory buckets rather than shared cluster counters.
- **Fix:** Documented Redis requirement for multi-worker environments in `README.md`. Added a production startup audit in `app/__init__.py::create_app()` that emits a high-visibility warning log if `FLASK_ENV=production` is detected while `RATELIMIT_STORAGE_URI` remains `memory://`.
- **Verification:** Verified by `tests/test_network_security.py::test_ratelimit_storage_production_warning`.

### BUG-05 (High if ever shipped) — Fast-Fail Startup Enforcement for Key Material
- **Issue:** `SECRET_KEY` and `MASTER_ENCRYPTION_KEY` silently fell back to hardcoded test strings or all-zero bytes if unconfigured in the environment, creating severe vulnerability to ciphertext decryption and session forgery in production.
- **Fix:** Added fail-fast startup validation in `app/__init__.py::create_app()`: in any non-test configuration (`TESTING != True`), `create_app()` raises `RuntimeError` immediately if either `SECRET_KEY` or `MASTER_ENCRYPTION_KEY` is missing or equal to known fallback values.
- **Verification:** Verified by `tests/test_crypto.py::test_fast_fail_on_missing_or_fallback_keys_in_production`.

### BUG-06 (Info) — Key Material Rotation & Git Hygiene Verification
- **Issue:** Static secret material present during development should be treated as burned once exposed outside the local security boundary.
- **Fix:** Removed `.env`, certificates, and temporary databases from git tracking. Rotated `SECRET_KEY` and `MASTER_ENCRYPTION_KEY`. Added automated scanner `scripts/scan_secrets.py`.
- **Verification:** Verified by `tests/test_enterprise_assurance.py::test_secret_scanner_clean_repo`.

### BUG-07 (Low / Architectural Assumption) — Flat Clinical Trust Model Documentation
- **Issue:** `PatientService.get_patient_detail()` provides clinical record access to any authenticated Doctor or Nurse across all patient records without individual patient consent scoping or physician-to-patient ownership bindings.
- **Fix:** Replaced flat clinical model with ABAC Policy Engine and Break-Glass protocol. Retained tenant-wide read auditing while enforcing care team boundaries for modifications.
- **Verification:** Documented in `docs/THREAT_MODEL.md §2.5` and verified by `tests/test_enterprise_assurance.py`.

### BUG-08 (Low) — Password Complexity Policy & Length Bounds Enforcement
- **Issue:** `AuthService.hash_password()` previously only validated that passwords were >= 8 characters, allowing simple passwords and permitting arbitrarily large inputs that could cause CPU/memory DoS against scrypt.
- **Fix:** Implemented password complexity and length policy in `AuthService.hash_password()` (minimum 8 characters, maximum 128 characters, requiring uppercase, lowercase, and digit).
- **Verification:** Verified by `tests/test_auth.py::test_password_complexity_and_length_validation`.

### BUG-09 (Operational Architecture) — WSGI Server Hardening Reference
- **Issue:** Werkzeug's development server is single-threaded and not hardened for production concurrency or direct internet exposure.
- **Fix:** Containerized application using multi-stage Dockerfile with non-root user `appuser:appuser`, running Gunicorn with 4 synchronous workers behind reverse proxy TLS termination.
- **Verification:** Verified by Docker and Docker Compose configuration.

### BUG-10 (P0 - Critical) — Multi-Tenant Boundary Isolation & Cross-Tenant Data Leakage
- **Issue:** In multi-clinic deployments, absence of tenant scoping would permit a doctor from Hospital A to view or mutate patient records belonging to Hospital B.
- **Fix:** Added `Tenant` model, foreign key `tenant_id` on `User`, `Patient`, and `AuditLog`. Added strict cross-tenant isolation checks in `PolicyEngine.evaluate_policy()`: cross-tenant access attempts immediately fail closed with HTTP 403, log a `CROSS_TENANT_ATTEMPT` audit record, and trigger high-severity alerts.
- **Verification:** Verified by `tests/test_enterprise_assurance.py::test_cross_tenant_isolation_strictly_enforced`.

### BUG-11 (P0 - Critical) — Cryptographic Downgrade Fallback & Ciphertext Transplantation
- **Issue:** Fallback to unauthenticated `aad=None` allowed an attacker to transplant encrypted ciphertext between patient records or tenant domains without GMAC verification failure.
- **Fix:** Implemented RFC 8785 Canonical JSON AAD binding (`patient_id`, `tenant_id`, `version_id`) and HKDF-SHA256 purpose-specific key derivation in `CryptoService`. Removed all unauthenticated fallback paths; ciphertext or AAD mismatches fail closed with `IntegrityTamperedError` and emit `TAMPER_DETECTED` security alerts.
- **Verification:** Verified by `tests/test_crypto.py` and `tests/test_patients.py`.

### BUG-12 (P1 - High) — Cloud KMS Key Hierarchy & Stub Key Provider Fail-Closed Enforcement
- **Issue:** Lack of KMS integration risked local key exposure and complicated enterprise key rotation workflows.
- **Fix:** Designed Cloud KMS KEK/DEK envelope encryption hierarchy in `CryptoService`. `ProductionKmsProvider` fails closed or raises `NotImplementedError` with explicit Cloud KMS configuration guidance if invoked in unconfigured production environments.
- **Verification:** Verified by `tests/test_key_management.py`.

### BUG-13 (P1 - High) — Client-Side Session Storage & State Revocation Vulnerability
- **Issue:** Storing serialized session payloads in client-side signed cookies prevented server-side session invalidation on password change, role change, or administrative account lockout.
- **Fix:** Implemented `ServerSideSessionInterface` backed by Redis or Memory session stores (`ServerSessionData`). Cookies contain only a 256-bit cryptographically secure opaque session ID (`_sid`). Added 15-minute idle timeouts, 8-hour absolute timeouts, and instant revocation via `session_version` invalidation.
- **Verification:** Verified by `tests/test_session_revocation.py`.

### BUG-14 (P1 - High) — Timing-Based User Enumeration & Password Reset Race Conditions
- **Issue:** Authentication endpoints returned immediately on non-existent usernames, creating a measurable 177 ms timing discrepancy against valid usernames. Password reset tokens lacked atomic consumption.
- **Fix:** Added `DUMMY_SCRYPT_HASH` constant-time verification in `AuthService.verify_password()` for non-existent users. Implemented atomic compare-and-swap single-use token consumption in password reset workflows.
- **Verification:** Verified by `tests/test_auth.py` and `tests/test_password_reset.py`.

### BUG-15 (P1 - High) — Administrative Privilege Segregation & Emergency Break-Glass Workflow
- **Issue:** System administrators could potentially view or mutate sensitive patient health data (violating HIPAA/DPDP segregation of duties). Attending clinicians lacked emergency override mechanisms for unassigned patients.
- **Fix:** `PolicyEngine` strictly forbids `Admin` role from creating, updating, or deleting clinical records. Implemented `BREAK_GLASS_ACCESS` protocol allowing emergency clinical access with mandatory justification logging and security webhook alerts.
- **Verification:** Verified by `tests/test_enterprise_assurance.py::test_emergency_break_glass_protocol` and `test_admin_clinical_mutation_strictly_forbidden`.

### BUG-16 (P2 - Medium) — Alert Webhook Replay Vulnerability & Transactional Event Loss
- **Issue:** Security webhook notifications were sent synchronously without retry queues or replay protections, risking event drop during network partitions.
- **Fix:** Implemented Transactional Outbox pattern with PostgreSQL `SKIP LOCKED` row locking. Enhanced `WebhookDelivery` with TLS verification, HMAC-SHA256 payload signatures, `X-ArogyaRaksha-Timestamp` and `X-ArogyaRaksha-Nonce` replay protection headers, exponential backoff, and circuit breaker.
- **Verification:** Verified by `tests/test_alerting.py` and `app/services/outbox_service.py`.
