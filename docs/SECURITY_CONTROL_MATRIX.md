# ArogyaRaksha: Comprehensive Security Control Compliance Matrix

**System:** ArogyaRaksha High-Assurance Clinical Security Platform  
**Target Standards:** OWASP ASVS 5.0 (L3), NIST SP 800-207 (Zero Trust), NIST SP 800-218 (SSDF), HIPAA Security Rule (45 CFR § 164.312), DPDP Act 2023  
**Classification:** Regulatory Compliance & Technical Assurance Matrix  
**Document Version:** 2.0.0-PROD  

---

## 1. Regulatory & Industry Framework Mapping

| Requirement Identifier | Standard / Framework Reference | System Control Description | Codebase Implementation | Verification Test Reference | Status |
|:---|:---|:---|:---|:---|:---:|
| **ASVS-V2.1** | OWASP ASVS 5.0 (Authentication) | Memory-hard password hashing with salt | `werkzeug.security` `scrypt` ($N=32768, r=8, p=1$) | `tests/test_auth.py::test_scrypt_password_hashing` | **COMPLIANT** |
| **ASVS-V2.8** | OWASP ASVS 5.0 (Authenticator) | Time-based one-time password (TOTP) MFA with encrypted secret storage | RFC 6238 TOTP with AES-256-GCM encrypted secret at rest in `User.totp_secret` | `tests/test_high_assurance.py::test_totp_secret_encrypted_at_rest` | **COMPLIANT** |
| **ASVS-V3.2** | OWASP ASVS 5.0 (Session Mgmt) | Session fixation defense & cookie flags | `session.regenerate_id()` on login; `HttpOnly`, `SameSite=Lax`, `Secure` cookies | `tests/test_auth.py::test_session_fixation_defense` | **COMPLIANT** |
| **ASVS-V3.7** | OWASP ASVS 5.0 (Session Mgmt) | Safe logout mechanism | HTTP `POST`-only logout route rejecting CSRF-vulnerable `GET` requests | `tests/test_high_assurance.py::test_logout_post_only` | **COMPLIANT** |
| **ASVS-V4.1** | OWASP ASVS 5.0 (Access Control) | Server-side role-based access control (RBAC) | `@require_permission` decorator validating role matrix (Doctor, Nurse, Admin) | `tests/test_rbac.py::test_nurse_cannot_edit_patient` | **COMPLIANT** |
| **ASVS-V5.1** | OWASP ASVS 5.0 (Input Validation) | Safe redirection defense | `is_safe_redirect_url` rejecting external and scheme-relative URLs | `tests/test_high_assurance.py::test_open_redirect_mitigation` | **COMPLIANT** |
| **ASVS-V5.3** | OWASP ASVS 5.0 (Output Encoding) | Cross-site scripting (XSS) prevention | Jinja2 auto-escaping + Strict Content Security Policy via `Flask-Talisman` | `tests/test_security.py::test_xss_protection` | **COMPLIANT** |
| **ASVS-V6.2** | OWASP ASVS 5.0 (Cryptography) | Authenticated encryption at rest (AEAD) | AES-256-GCM with 96-bit CSPRNG nonces and 128-bit GMAC tags | `tests/test_crypto.py::test_aes_256_gcm_encryption` | **COMPLIANT** |
| **ASVS-V6.3** | OWASP ASVS 5.0 (Cryptography) | Cryptographic context binding (Anti-splicing) | AAD binding tenant, patient ID, and key version into GMAC computation | `tests/test_high_assurance.py::test_aead_context_binding_patient_id` | **COMPLIANT** |
| **ASVS-V7.1** | OWASP ASVS 5.0 (Error Handling) | Information disclosure prevention | Generic error handlers returning sanitized messages without stack traces | `tests/test_security.py::test_error_handlers_no_info_leakage` | **COMPLIANT** |
| **ASVS-V7.2** | OWASP ASVS 5.0 (Audit Logging) | Immutable, tamper-evident audit logs | Append-only recursive SHA-256 hash chaining of all security and clinical events | `tests/test_audit.py::test_audit_hash_chain_tamper_detection` | **COMPLIANT** |
| **ASVS-V8.3** | OWASP ASVS 5.0 (Data Protection) | Sensitive data leakage prevention in logs | `PhiRedactionFilter` regex masking names, phone numbers, and clinical terms | `tests/test_high_assurance.py::test_phi_redaction_in_structured_logs` | **COMPLIANT** |
| **ASVS-V11.2**| OWASP ASVS 5.0 (Business Logic) | Optimistic Concurrency Control (OCC) | `version_id` verification on record update; raises 409 Conflict on collision | `tests/test_high_assurance.py::test_optimistic_concurrency_conflict` | **COMPLIANT** |
| **ASVS-V13.1**| OWASP ASVS 5.0 (API Architecture) | Transactional Outbox pattern | Atomic persistence of domain events with reliable background delivery | `tests/test_high_assurance.py::test_outbox_event_persistence` | **COMPLIANT** |
| **ASVS-V14.2**| OWASP ASVS 5.0 (Configuration) | Fail-closed secret decoupling | Application terminates on startup if secrets are default or low-entropy | `tests/test_high_assurance.py::test_fail_closed_missing_secrets` | **COMPLIANT** |
| **ASVS-V4.2** | OWASP ASVS 5.0 (Access Control) | Multi-tenant boundary isolation | Partitioned `Tenant` schema and fail-closed cross-tenant blocking in `PolicyEngine` | `tests/test_enterprise_assurance.py::test_cross_tenant_isolation_strictly_enforced` | **COMPLIANT** |
| **ASVS-V4.3** | OWASP ASVS 5.0 (Access Control) | Segregation of clinical & administrative duties | System administrators strictly prohibited from clinical data mutations | `tests/test_enterprise_assurance.py::test_admin_clinical_mutation_strictly_forbidden` | **COMPLIANT** |
| **ASVS-V4.4** | OWASP ASVS 5.0 (Access Control) | Emergency break-glass override protocol | Justified break-glass access for unassigned clinicians with mandatory logging and SIEM alert | `tests/test_enterprise_assurance.py::test_emergency_break_glass_protocol` | **COMPLIANT** |
| **ASVS-V2.9** | OWASP ASVS 5.0 (Authentication) | Constant-time user enumeration defense | `DUMMY_SCRYPT_HASH` verification for non-existent users guaranteeing identical ~177ms latency | `tests/test_auth.py::test_login_failure_wrong_password` | **COMPLIANT** |
| **ASVS-V3.8** | OWASP ASVS 5.0 (Session Mgmt) | Server-side session store & instant revocation | 256-bit opaque cookie token; Redis/Memory storage; session_version invalidation | `tests/test_session_revocation.py::test_session_revocation_on_password_change` | **COMPLIANT** |

---

## 2. NIST SP 800-207 Zero Trust Architecture (ZTA) Alignment

| NIST ZTA Tenet | System Implementation | Validation Mechanism |
|:---|:---|:---|
| **1. All data sources and computing services are resources** | Clinical data, audit logs, authentication endpoints, and internal micro-services are modeled as isolated resources. | Verified by Kubernetes NetworkPolicies restricting inter-service communication. |
| **2. All communication is secured regardless of network location** | Internal pod communication enforces TLS; all external communication requires TLS 1.3 / HSTS. | Verified by Talisman HTTPS enforcement and secure cookies. |
| **3. Access to individual enterprise resources is granted on a per-session basis** | RBAC decorators re-evaluate authenticated session, role status, and account activity on every single HTTP request. | Verified by `@require_permission` decorator execution on every endpoint. |
| **4. Access to resources is determined by dynamic policy** | Access checks factor in user role, active account status (`is_active`), lockout state, and requested resource identifier. | Verified by unit tests asserting account deactivation halts immediate access. |
| **5. Continuous monitoring and measurement of asset integrity** | Every database read verifies AEAD GMAC tags and AAD context; background monitors continuously verify audit hash chains. | Verified by `verify_chain()` and `IntegrityTamperedError` alerts. |

---

## 3. HIPAA Security Rule (45 CFR Part 164) Alignment

| HIPAA Citation | Required Specification | System Technical Safeguard |
|:---|:---|:---|
| **§ 164.312(a)(1)** | Access Control | Unique user IDs; role-based access control; automatic session expiration. |
| **§ 164.312(a)(2)(iv)** | Encryption and Decryption | AES-256-GCM authenticated encryption for all diagnostic and treatment data at rest. |
| **§ 164.312(b)** | Audit Controls | Tamper-evident SHA-256 chained audit logs tracking all reads, updates, and logins. |
| **§ 164.312(c)(1)** | Data Integrity | AEAD Galois MAC verification prevents bit-flipping and undetected record tampering. |
| **§ 164.312(d)** | Person or Entity Authentication | Multi-factor authentication (TOTP) + `scrypt` password verification. |
| **§ 164.312(e)(1)** | Transmission Security | End-to-end TLS 1.3 transport encryption with HSTS and strict cipher suites. |

---

## 4. Digital Personal Data Protection (DPDP) Act 2023 Alignment

| DPDP Principle | Technical Control Implementation |
|:---|:---|
| **Purpose Limitation** | Clinical staff access records strictly within clinical role scope; administrative accounts are prohibited from decrypting clinical data. |
| **Data Minimization** | Logging framework enforces `PhiRedactionFilter`, preventing diagnostic or personal identifiers from appearing in telemetry or log streams. |
| **Storage Limitation** | Clinical data retention policies enforced; audit logs archived according to statutory requirements. |
| **Reasonable Security Safeguards** | Defense-in-depth architecture spanning container rootless isolation, CSP nonces, rate limiting, and authenticated cryptography. |
