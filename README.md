# ArogyaRaksha: High-Assurance Clinical Security Platform

[![Security Standards](https://img.shields.io/badge/Security-OWASP%20ASVS%205.0%20(L3)-blue.svg)](docs/SECURITY_CONTROL_MATRIX.md)
[![Zero Trust](https://img.shields.io/badge/Architecture-NIST%20SP%20800--207%20Zero%20Trust-green.svg)](docs/FINAL_ARCHITECTURE.md)
[![Cryptography](https://img.shields.io/badge/Crypto-AES--256--GCM%20%2B%20AAD-purple.svg)](docs/CRYPTOGRAPHY_SPEC.md)
[![Tests](https://img.shields.io/badge/Tests-169%20Passed%20(83%25%20Coverage)-success.svg)](docs/TEST_AND_SECURITY_EVIDENCE.md)
[![License](https://img.shields.io/badge/Compliance-HIPAA%20%2F%20DPDP%202023-orange.svg)](docs/SECURITY_CONTROL_MATRIX.md)

**ArogyaRaksha** is an industrial-hardened, defense-in-depth clinical information system engineered to enforce strict confidentiality, integrity, and non-repudiation across Protected Health Information (PHI). 

Originally developed for *Cryptography and Network Security* (26ECSC403) at KLE Technological University by:
* **Apeksha A Dambal** — Authentication & Role-Based Access Control (RBAC)
* **Priyanshu Khatri** — Cryptography (AES-256-GCM, AAD Binding & Key Management)
* **Niteen Singh** — Network Security, SRE / Infrastructure, Audit Logging & Testing

The system has been transformed from an academic demonstration into a production-grade, high-assurance healthcare platform adhering to **OWASP ASVS 5.0 (Level 3)**, **NIST SP 800-207 (Zero Trust)**, **NIST SP 800-218 (SSDF)**, and **HIPAA Security Rule (45 CFR § 164.312)**.

---

## 1. Core Security & Architectural Capabilities

1. **Authenticated Encryption with Associated Data (AEAD) at Rest:**
   - Patient diagnostic notes and treatment regimens are encrypted at rest using **AES-256-GCM** (NIST SP 800-38D) with unique 96-bit CSPRNG nonces and 128-bit GMAC tags.
   - **RFC 8785 Canonical JSON AAD Binding:** Additional Authenticated Data (`{"rid": patient_id, "tid": tenant_id, "kv": key_version, "ver": version_id, ...}`) binds ciphertext to patient, tenant, key and record version, preventing cross-record / cross-tenant splicing and replay of an older ciphertext over a newer version (`crypto_schema = 2`). Rows written before this binding (`crypto_schema = 1`) stay readable while `CRYPTO_ALLOW_LEGACY_AAD=True`; `scripts/rotate_keys.py` upgrades them, after which the flag should be turned off.
   - **HKDF-SHA256 Purpose Subkey Derivation:** Derives independent subkeys for TOTP secrets, sealed outbox secrets and the audit-chain HMAC. Clinical records use the versioned master key directly (kept for compatibility with existing ciphertexts).
2. **Multi-Tenant Organization Isolation & ABAC Policy Engine:**
   - Dedicated `Tenant` entity with foreign key data partitioning across `Patient`, `User`, and `AuditLog`.
   - `PolicyEngine` evaluates user roles, tenancy, care-team relationships, and emergency break-glass protocol.
   - Administrators strictly segregated from mutating clinical records (`CREATE`, `UPDATE`, `DELETE`).
   - `BREAK_GLASS_ACCESS` workflow allowing emergency clinical overrides with mandatory audit logging and real-time SIEM alerts.
   - Care team: the **assigned attending doctor** may edit/archive a record (a doctor creating a record is assigned by default; nurses pick the doctor at intake). Unassigned intakes can be picked up by any doctor in the tenant; other doctors must declare break-glass from the record page. Patient IDs (MRNs) are unique per tenant.
   - Administrators manage users and audit logs of **their own tenant only**. TOTP MFA can be enabled by every user and is mandatory for admins.
3. **Server-Side Session Store & Identity Governance:**
   - Cookies store only a 256-bit cryptographically secure opaque session ID (`_sid`).
   - Passwords hashed using memory-hard **scrypt** ($N=32768, r=8, p=1$) with `DUMMY_SCRYPT_HASH` constant-time verification defeating user enumeration.
   - Multi-Factor Authentication (**RFC 6238 TOTP**) with Base32 secrets encrypted at rest via AES-256-GCM.
   - Session revocation via `session_version` invalidation; 15-minute idle timeout and 8-hour absolute timeout.
4. **Optimistic Concurrency Control (OCC):**
   - High-concurrency protection via integer `version_id` verification on chart updates, preventing silent clinical overwrites and returning HTTP 409 Conflict upon collision.
5. **Reliable Telemetry via Transactional Outbox:**
   - Atomic persistence of clinical mutations and domain events (`OutboxEvent`) within the exact same database transaction, dispatched by the `flask process-outbox --loop` worker (Procfile `worker`, compose `worker`, `deploy/k8s/worker-deployment.yaml`) using PostgreSQL `SKIP LOCKED` row locking with exponential backoff and dead-letter queueing.
   - Password reset links are delivered through the outbox: the one-time token is sealed with AES-256-GCM in the event payload and sent by SMTP (`SMTP_HOST`, user `email`). Without SMTP, non-production environments log the link to the console; production retries and dead-letters instead.
6. **Tamper-Evident Recursive Audit Chain:**
   - Append-only keyed hash chain ($Block_N = \text{HMAC-SHA256}_{K_{audit}}(Block_{N-1} \parallel Fields)$) capturing staff ID, action, resource, IP, tenant and timestamp. Without the HKDF audit key, rows cannot be edited, deleted or re-chained undetected; legacy unkeyed rows are only accepted before the first keyed row. Keep key version `AUDIT_CHAIN_KEY_VERSION` (default 1) available after rotation.
   - Untrusted proxy defense: `X-Forwarded-For` is honored only from `TRUSTED_PROXY_IPS` peers and walked right-to-left, so client-supplied entries cannot spoof the audited IP. Rate limits key on the same resolved client IP.
7. **Observability & Privacy Safeguards:**
   - Structured JSON logging with `X-Request-ID` correlation engine.
   - In-flight **Automated PHI Redaction Filter** masking Indian mobile numbers, dates of birth, and diagnostic keywords with `[REDACTED_PHI]`.
   - Built-in Prometheus-compatible metrics registry and Kubernetes liveness (`/livez`) and deep readiness (`/readyz`) health probes.
8. **Hardened Container & Kubernetes Infrastructure:**
   - Rootless unprivileged execution (`UID=10001`, `GID=10001`), read-only root filesystem, dropped Linux capabilities.
   - Complete Kubernetes manifests (`deploy/k8s/`) including default-deny NetworkPolicies, HPA, and PodDisruptionBudgets.

---

## 2. Architecture Overview

```mermaid
graph TD
    Client[Clinical Client / Browser] -->|TLS 1.3 / mTLS| Ingress[Kubernetes Ingress Controller]
    
    subgraph Edge & Security Middleware
        Ingress --> Talisman[Flask-Talisman: CSP, HSTS, X-Frame-Options]
        Talisman --> Limiter[Flask-Limiter: Redis-Backed Sliding Window]
        Limiter --> CSRF[Flask-WTF: Cryptographic Form Token Verification]
        CSRF --> SessionGuard[Session Integrity Guard & Fixation Defense]
        SessionGuard --> RBAC[@require_permission: Doctor, Nurse, Admin]
    end

    subgraph Service & Cryptographic Core
        RBAC --> PatientService[PatientService: Clinical Chart Logic]
        RBAC --> AuthService[AuthService: scrypt & MFA Verification]
        PatientService --> CryptoService[CryptoService: AES-256-GCM + AAD Binding]
        PatientService --> AuditService[AuditService: SHA-256 Recursive Chain]
        PatientService --> OutboxService[OutboxService: Atomic Transactional Outbox]
    end

    subgraph Persistence & Infrastructure Tier
        CryptoService --> DB[(PostgreSQL 16 Cluster / SQLite Dev)]
        AuditService --> DB
        OutboxService --> DB
        Limiter --> Redis[(Redis 7 Cache)]
    end
```

---

## 3. Technology Stack

| Layer | Component | Security Rationale |
|:---|:---|:---|
| **Runtime & Framework** | Python 3.12/3.14, Flask 3.1 | Microframework allowing explicit, auditable security control pipelines. |
| **WSGI Server** | Gunicorn (4 sync workers) | Synchronous process model preserves OS CSPRNG entropy across forks. |
| **Data Persistence** | PostgreSQL 16 (Prod) / SQLite (Dev) | Relational schema managed via Alembic migrations (`flask init-db`). |
| **Cryptography** | PyCryptodome (`AES.MODE_GCM`) | AEAD confidentiality and integrity with AAD context binding. |
| **Password Derivation**| Werkzeug (`scrypt`) | Memory-hard key derivation resistant to GPU/ASIC cracking arrays. |
| **Session & CSRF** | Flask-WTF (`CSRFProtect`) | Cryptographic synchronizer tokens on all state-changing endpoints. |
| **Security Headers** | Flask-Talisman | Strict Content Security Policy (CSP), HSTS, Clickjacking defense. |
| **Rate Limiting** | Flask-Limiter (Redis-backed) | Sliding window throttling mitigating credential stuffing. |
| **Observability** | Python Logging + Custom Regex Filter | RFC 8259 JSON format with automated in-flight PHI masking. |
| **Container Runtime** | Docker / Kubernetes (Rootless) | Non-root UID 10001, read-only rootfs, default-deny network policies. |

---

## 4. Quickstart & Installation

### Option A: Local Development (Python Virtual Environment)

#### 1. Clone & Set Up Virtual Environment
```bash
git clone https://github.com/cns-org/arogya-raksha.git
cd arogya-raksha
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

#### 2. Configure Environment Variables
Copy `.env.example` to `.env` and generate secure secrets:
```bash
cp .env.example .env
# Ensure SECRET_KEY and MASTER_ENCRYPTION_KEY are set with 64-character hex strings
```

#### 3. Run Database Migrations & Seed Default Data
```bash
# Apply Alembic schema migrations (upgrade head)
flask init-db

# Bootstrap initial administrative user. Uses BOOTSTRAP_ADMIN_PASSWORD if set,
# otherwise generates and prints a random password once.
flask bootstrap-admin

# (Optional) Seed demo clinical records (BLOCKED in production mode)
flask seed-demo
```

#### 4. Run Development Server
```bash
# Standard HTTP mode
python run.py --port 5000

# Secure HTTPS mode (with local self-signed TLS certificates)
python run.py --https --port 5000
```
Visit: [https://127.0.0.1:5000](https://127.0.0.1:5000)

#### 5. Run the Outbox Worker (alerts & password reset delivery)
```bash
flask process-outbox --loop
```

---

### Option B: Docker Compose (App + PostgreSQL + Redis)

```bash
# Set POSTGRES_PASSWORD, SECRET_KEY and MASTER_ENCRYPTION_KEY in .env, then start everything.
# The one-shot `migrate` service applies the schema before `web` and `worker` start.
docker-compose up -d --build
docker-compose exec web flask bootstrap-admin
```
Access the application at [http://localhost:5000](http://localhost:5000).

---

### Option C: Kubernetes Deployment (`deploy/k8s/`)

Deploy to a hardened Kubernetes cluster:
```bash
# 1. Create dedicated namespace
kubectl create namespace arogya

# 2. Configure Secrets and ConfigMaps
kubectl apply -f deploy/k8s/configmap.yaml -n arogya
kubectl apply -f deploy/k8s/secret.example.yaml -n arogya

# 3. Apply Network Policies (Default Deny + Whitelisted Ingress/Egress)
kubectl apply -f deploy/k8s/networkpolicy.yaml -n arogya

# 4. Apply schema migrations (re-run before every rollout) and wait for completion
kubectl apply -f deploy/k8s/migrate-job.yaml -n arogya
kubectl wait --for=condition=complete job/arogya-migrate -n arogya --timeout=300s

# 5. Deploy Application, Outbox Worker, Autoscaler, and Pod Disruption Budget
kubectl apply -f deploy/k8s/deployment.yaml -n arogya
kubectl apply -f deploy/k8s/worker-deployment.yaml -n arogya
kubectl apply -f deploy/k8s/service.yaml -n arogya
kubectl apply -f deploy/k8s/ingress.yaml -n arogya
kubectl apply -f deploy/k8s/hpa.yaml -n arogya
kubectl apply -f deploy/k8s/pdb.yaml -n arogya
```

---

## 5. Default Evaluator Accounts

| Role | Username | Password | Permissions Granted |
|:---|:---|:---|:---|
| **Doctor** | `doctor_alice` | `DocSecurePass#2026` | Read Patients, Create Patients, Edit/Update Clinical Records |
| **Nurse** | `nurse_bob` | `NursePass#2026` | Read Patients, Create Patients & assign the attending doctor (*Cannot Edit Existing Records*) |
| **Admin** | `admin_charlie` | `AdminMaster#2026` | Manage Users (Create/Disable), Audit Trail & Chain Verification (*Cannot View Clinical PHI*) |

---

## 6. Automated Verification & Security Evidence

Run the complete 169-test high-assurance verification suite:
```bash
# Run pytest with code coverage analysis (169 passed, 83% coverage)
pytest --cov=app --cov-report=term-missing

# Run Ruff static analysis security check (0 errors)
ruff check .

# Run automated credential and secret scanner
python scripts/scan_secrets.py .

# Run empirical performance benchmark suite
python scripts/benchmark.py

# Run cryptographic key rotation drill
python scripts/rotate_keys.py

# Verify audit trail hash chain integrity
python -c "from app import create_app; from app.services.audit_service import AuditService; app=create_app('testing'); with app.app_context(): valid, err = AuditService.verify_chain(); assert valid; print('Audit chain verified successfully!')"
```

### Empirical Benchmark Summary (`scripts/benchmark.py`)
```
Operation / Benchmark              | Throughput      | Mean Latency | Verification Result
-----------------------------------+-----------------+--------------+--------------------------
AES-256-GCM Encrypt/Decrypt (1 KB) | 6,790.2 ops/sec | 0.147 ms     | Hardware accelerated
AES-256-GCM Encrypt/Decrypt (10 KB)| 3,941.9 ops/sec | 0.254 ms     | 42.48 MB/s
scrypt Password Hashing (N=32768)  | 5.62 ops/sec    | 177.72 ms    | P95: 191.5ms, 32MB RAM
Audit Hash-Chain Append            | 413.8 events/s  | 2.417 ms     | SHA-256 link & DB commit
Audit Ledger Chain Verification    | 21,408.5 blk/s  | 0.047 ms/blk | 300 blocks in 14.01 ms
Server-Side Session Store (Write)  | 83,824.1 ops/s  | 11.93 µs     | 256-bit opaque cookie token
Server-Side Session Store (Read)   | 267,215.3 ops/s | 3.74 µs      | Session state retrieval
OCC Race Contention (10 Threads)   | 100% atomic     | 0 lost edits | 1 Commit, 9 Conflicts
```

---

## 7. Comprehensive Documentation Suite

For detailed technical specifications, operational runbooks, and compliance audits, consult the `docs/` directory:

* 📐 [**System Architecture Specification**](docs/FINAL_ARCHITECTURE.md) — Comprehensive technical architecture, Zero Trust boundaries, multi-tenancy, and data pipelines.
* 🛡️ [**STRIDE Threat Model**](docs/THREAT_MODEL.md) — Threat matrix, attack trees, and mitigation proofs across all clinical assets.
* 🔐 [**Cryptographic Specification**](docs/CRYPTOGRAPHY_SPEC.md) — AEAD AES-256-GCM, RFC 8785 Canonical JSON AAD, HKDF derivation, and Cloud KMS envelope.
* 📋 [**Security Incident Runbook**](docs/SECURITY_RUNBOOK.md) — Standard operating procedures for tamper alerts, lockout storms, and key compromises.
* 💾 [**Disaster Recovery Plan**](docs/DISASTER_RECOVERY.md) — RPO/RTO specifications, database backup scripts, and cold restoration runbooks.
* 📊 [**Observability & Health Probes**](docs/OBSERVABILITY.md) — Structured JSON logging, regex PHI redaction, and Kubernetes liveness/readiness probes.
* 🚀 [**Release Engineering & DevSecOps**](docs/RELEASE_PROCESS.md) — Multi-stage rootless containerization, CI/CD gates, and zero-downtime migrations.
* 📑 [**Security Control Compliance Matrix**](docs/SECURITY_CONTROL_MATRIX.md) — Traceability matrix mapped to OWASP ASVS 5.0, NIST SP 800-207, and HIPAA.
* ⚡ [**Performance & Optimization Report**](docs/PERFORMANCE_REPORT.md) — Real empirical benchmarks, hardware acceleration, and database index tuning.
* 🧪 [**Test & Security Evidence Report**](docs/TEST_AND_SECURITY_EVIDENCE.md) — test evidence, coverage breakdown, and reproduction guides.
* 🔍 [**Final Security Audit & Gap Analysis**](docs/FINAL_SECURITY_AUDIT.md) — Comprehensive verification of all remediated vulnerabilities.
