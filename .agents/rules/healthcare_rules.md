---
description: "Core engineering, security, and architectural rules for the CNS/ArogyaRaksha healthcare application."
trigger: always_on
---

# ArogyaRaksha Project Rules

These rules enforce the architectural and security decisions established during the production-hardening of the ArogyaRaksha clinical platform. Do not deviate from these patterns.

## 1. Healthcare-Sensitive Data
- **Context-Bound AEAD Encryption:** All PHI and clinical records must be encrypted at rest using AES-256-GCM. The Authentication Associated Data (AAD) must deterministically bind `patient_id`, `tenant_id`, `domain`, `purpose`, `crypto_version`, and `key_version`.
- **Zero PHI in Logs:** Never log patient identifying information, clinical notes, or decrypted payloads.

## 2. Authorization & Tenant Isolation
- **Strict DAO Isolation:** The Data Access Object (DAO) layer (`PatientRepository`) must explicitly require `tenant_id` on every read and write operation. Cross-tenant data leaks must be blocked at the SQLAlchemy query level via `AND tenant_id = ?`.
- **Structured Break-Glass:** Emergency access (break-glass) must supply a valid reason code (e.g., `EMERGENCY_RESUSCITATION`) and a clinical justification of at least 15 characters.
- **ABAC/RBAC Segregation:** Clinical mutations require role-based permissions (e.g., Doctor) combined with resource-level context.

## 3. Authentication
- **Session Fixation Defense:** Always call `session.regenerate()` to rotate session identifiers upon successful login, MFA verification, or privilege elevation.
- **Clean URL Reset Flow:** Password reset tokens must never appear in URL paths or be persisted in the browser history. Use server-side opaque tickets (`/reset-password`) for the final execution step.
- **TOTP MFA:** MFA is mandatory for workforce roles accessing PHI.

## 4. Secrets Management
- **No Hardcoded Credentials:** Never hardcode bootstrap passwords or API keys. Use `BOOTSTRAP_ADMIN_PASSWORD` from the environment.
- **KMS Envelope Encryption:** Encryption keys must be versioned and managed by a dedicated KMS provider.
- **Fail-Closed Configuration:** The application must fail closed if production secrets (`SECRET_KEY`, `MASTER_ENCRYPTION_KEY`, DB/Redis URLs) are missing.

## 5. Logging & Audit
- **Structured Canonical Auditing:** Audit hashes must use schema version 2 (RFC 8785 canonical JSON with sorted keys and microsecond UTC timestamps).
- **JSON Telemetry:** Use structured JSON logging with `PHIRedactionFilter` applied globally.
- **No Sensitive Log Data:** Passwords, tokens, TOTP codes, and session IDs must never be logged.

## 6. API Design & Rate Limiting
- **Defensive Error Handling:** Never leak stack traces, SQL errors, or cryptography internals to the client.
- **Rate Limiting:** Critical authentication boundaries (like `mfa_verify`) must be rate-limited (e.g., `5 per minute`).
- **Open Redirect Mitigation:** Reject all encoded bypasses, backslash variants (`\`, `/\`, `//`), control characters, and protocol prefixes in redirect URLs.

## 7. Database Access & Concurrency
- **Optimistic Concurrency Control (OCC):** All clinical updates must enforce atomic compare-and-swap OCC using `version_id`.
- **Transactional Outbox Worker:** Background events (emails, alerts) must be inserted into an outbox table within the same transaction as the business mutation.
- **Non-Blocking Delivery:** The outbox worker must claim pending events using `FOR UPDATE SKIP LOCKED` to prevent clustered race conditions.

## 8. Testing & QA
- **Strict Quality Gates:** Code must maintain $\ge 80\%$ test coverage (`pytest --cov`).
- **Vulnerability Scanning:** Ensure `scripts/scan_secrets.py` passes flawlessly in CI.
- **No Bypasses for Tests:** Do not mock or disable security controls (like MAC validation) merely to make tests pass.

## 9. Frontend Security
- **Asset Caching:** Use `public, max-age=86400, must-revalidate` for non-fingerprinted static assets to prevent stale state lockups.
- **Secure Cookies:** `SESSION_COOKIE_SECURE = True` must be strictly enforced in production.
- **Proxy CIDR Trust:** Do not blindly trust `X-Forwarded-For`. IP extraction must validate against explicitly trusted CIDR blocks using Python's `ipaddress` module.

## 10. Docker & Kubernetes Security
- **Explicit Network Policies:** Implement default-deny egress policies. Explicitly allowlist external databases and Redis endpoints via Kubernetes NetworkPolicies (`deploy/k8s/networkpolicy.yaml`).
- **Fail-Closed Probes:** Liveness (`/livez`) and readiness (`/readyz`) probes must assert database and cache connectivity accurately without bypassing security gates.

## 11. Code Quality
- **Static Analysis:** All Python code must pass `ruff check .` with zero errors.
- **Data Transfer Objects:** Use Pydantic DTOs for payload validation across the service boundary.
- **Exception Clarity:** Do not use bare `except:` or raise generic exceptions without context (`raise ... from e`).
