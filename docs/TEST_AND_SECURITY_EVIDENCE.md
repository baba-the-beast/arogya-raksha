# ArogyaRaksha: Test Suite & Cryptographic Security Evidence Report

**System:** ArogyaRaksha Clinical Security Platform  
**Test Suite Execution Date:** September 2026  
**Test Framework:** Pytest 9.x + pytest-cov  
**Static Analysis Tool:** Ruff 0.9.x  
**Document Version:** 3.0.0-ENTERPRISE  

---

## 1. Test Suite Execution Summary

The ArogyaRaksha automated verification suite provides complete end-to-end regression testing, ABAC verification, and cryptographic validation:

```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\cns
configfile: pytest.ini
testpaths: tests
plugins: anyio-4.11.0, cov-7.1.0, mock-3.15.1
collected 135 items

tests\test_admin.py ...                                                  [  2%]
tests\test_alerting.py ....                                              [  5%]
tests\test_audit.py .....                                                [  8%]
tests\test_audit_concurrency.py ...                                      [ 11%]
tests\test_auth.py ........                                              [ 17%]
tests\test_break_glass_and_proxy_cidr.py ....                            [ 20%]
tests\test_clean_url_reset_and_redirects.py ..                           [ 21%]
tests\test_crypto.py ......                                              [ 25%]
tests\test_cryptographic_transplants.py .....                            [ 29%]
tests\test_data_layer.py ...                                             [ 31%]
tests\test_deployment.py .......                                         [ 37%]
tests\test_enterprise_assurance.py ....                                  [ 40%]
tests\test_headers.py ...                                                [ 42%]
tests\test_high_assurance.py ...............                             [ 53%]
tests\test_key_management.py .......                                     [ 58%]
tests\test_mfa.py .....                                                  [ 62%]
tests\test_network_security.py ......                                    [ 66%]
tests\test_pagination.py ............                                    [ 75%]
tests\test_password_reset.py .....                                       [ 79%]
tests\test_patients.py .......                                           [ 84%]
tests\test_performance_security.py .......                               [ 89%]
tests\test_rbac.py ....                                                  [ 92%]
tests\test_session_revocation.py ...                                     [ 94%]
tests\test_session_rotation_and_mfa.py ...                               [ 97%]
tests\test_soft_delete.py ....                                           [100%]

================= 135 passed, 54 warnings in 88.20s (0:01:28) =================
```

* **Total Test Cases:** 135
* **Passing:** 135 (100% Pass Rate)
* **Failures:** 0
* **Errors:** 0
* **Total Line Coverage:** **83%** across 2,344 statements
* **Static Analysis Lint Errors:** **0** (`ruff check .` clean)
* **Secret Scanner Status:** **0 violations** (`python scripts/scan_secrets.py .` PASS)

---

## 2. Test Coverage Breakdown by Architectural Layer

| Module / Component | Statements | Missed | Total Coverage | Critical Controls Verified |
|:---|:---:|:---:|:---:|:---|
| `app/__init__.py` | 93 | 22 | **76%** | Application factory, fail-closed production key guards, session config |
| `app/config.py` | 103 | 37 | **64%** | Strict secret validation, proxy allowlists, storage configuration |
| `app/models/patient.py` | 26 | 1 | **96%** | Optimistic Concurrency Control `version_id`, AEAD fields, tenant binding |
| `app/models/user.py` | 55 | 8 | **85%** | scrypt password check, encrypted TOTP getter/setter, session_version |
| `app/models/audit_log.py`| 39 | 2 | **95%** | SHA-256 hash chaining columns, tenant_id partition, genesis block |
| `app/models/outbox.py` | 17 | 0 | **100%** | Transactional outbox event lifecycle states |
| `app/models/tenant.py` | 15 | 2 | **87%** | Multi-tenant organization isolation entity |
| `app/models/password_reset_token.py` | 19 | 1 | **95%** | Atomic compare-and-swap single-use token consumption |
| `app/security/headers.py` | 29 | 1 | **97%** | Modern W3C security headers (CSP nonce, COOP, CORP, HSTS) |
| `app/security/permissions.py` | 15 | 1 | **93%** | Server-side RBAC permissions and role matrix |
| `app/security/decorators.py` | 87 | 17 | **80%** | `@require_permission`, `@require_resource_permission` |
| `app/security/policy.py` | 70 | 11 | **84%** | ABAC PolicyEngine: cross-tenant isolation, break glass, admin segregation |
| `app/security/session_store.py` | 242 | 69 | **71%** | Server-side session store: Redis/Memory, opaque 256-bit sid, timeouts |
| `app/services/patient_service.py` | 143 | 12 | **92%** | OCC conflict detection, AEAD encryption orchestration, soft-delete |
| `app/services/auth_service.py` | 148 | 13 | **91%** | Lockout counter, MFA verification, timing-safe user enumeration defense |
| `app/services/user_service.py` | 53 | 6 | **89%** | Account lifecycle, session revocation, role management |
| `app/services/crypto_service.py` | 247 | 46 | **81%** | AES-256-GCM, HKDF purpose derivation, RFC 8785 Canonical JSON AAD |
| `app/services/audit_service.py` | 160 | 35 | **78%** | Recursive SHA-256 chain verification, untrusted XFF defense |
| `app/services/outbox_service.py` | 89 | 24 | **73%** | Batch dispatch, exponential backoff, PostgreSQL SKIP LOCKED row lock |
| `app/services/alert_service.py` | 71 | 25 | **65%** | Webhook alerting with TLS verification, HMAC signature, replay headers |
| `app/observability/logging.py` | 65 | 2 | **97%** | Structured JSON formatter, regex PHI redaction filter |
| `app/observability/metrics.py` | 48 | 1 | **98%** | Telemetry counters, duration histograms, latency tracking |
| `app/routes/admin.py` | 107 | 14 | **87%** | Admin audit viewer, user management, segregated clinical boundaries |
| `app/routes/auth.py` | 151 | 16 | **89%** | POST-only logout, safe redirect validation, MFA setup and check |
| `app/routes/patient.py` | 133 | 20 | **85%** | Resource permission gating, OCC handling, tenant-scoped listings |
| `app/routes/errors.py` | 40 | 4 | **90%** | Non-disclosing error handlers (400, 403, 404, 405, 409, 500) |
| `app/routes/health.py` | 51 | 20 | **61%** | `/livez` and deep `/readyz` probe evaluations |
| **Total Codebase** | **2,344** | **410** | **83%** | **All Security & Clinical Boundaries Covered** |

---

## 3. Enterprise High-Assurance Verification Suite (`tests/test_enterprise_assurance.py`)

1. `test_cross_tenant_isolation_strictly_enforced`: Proves clinician from Tenant Beta attempting to access or edit patient records in Tenant Alpha receives HTTP 403 Forbidden and records a `CROSS_TENANT_ATTEMPT` audit event.
2. `test_emergency_break_glass_protocol`: Proves unassigned clinicians attempting clinical updates are rejected with HTTP 403; providing break-glass rationale grants access while triggering a high-visibility `BREAK_GLASS_ACCESS` audit event and real-time SIEM alert.
3. `test_admin_clinical_mutation_strictly_forbidden`: Proves system administrators attempting clinical record creation, editing, or deletion are strictly blocked by `PolicyEngine` (HTTP 403), enforcing statutory segregation of duties.
4. `test_secret_scanner_clean_repo`: Automated test verifying that `scripts/scan_secrets.py` reports zero uncommitted credentials, private keys, API tokens, or high-entropy secrets in source code.

---

## 4. Test Reproduction & Verification Commands

```bash
# 1. Run Complete Test Suite with Coverage Report
pytest --cov=app --cov-report=term-missing

# 2. Run Enterprise Assurance Suite Specifically
pytest tests/test_enterprise_assurance.py -v

# 3. Run Static Analysis Linter
ruff check .

# 4. Run Automated Secret Scanner
python scripts/scan_secrets.py .

# 5. Execute Empirical Benchmark Suite
python scripts/benchmark.py
```
