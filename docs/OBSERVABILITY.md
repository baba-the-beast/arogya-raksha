# ArogyaRaksha: Observability, Telemetry & Health Probe Architecture

**System:** ArogyaRaksha Clinical Security Platform  
**Components:** Structured JSON Logging, In-Flight PHI Redaction, Metrics Registry, Health Probes  
**Document Version:** 2.0.0-PROD  

---

## 1. Observability Overview

ArogyaRaksha implements a defense-in-depth observability framework designed to provide granular operational visibility to SRE and SOC teams while mathematically preventing Protected Health Information (PHI) from leaking into log aggregators, indexing engines, or third-party monitoring platforms.

```
+-----------------------------------------------------------------------------------+
|                              Incoming HTTP Request                                |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |   X-Request-ID Correlation    |
                         +-------------------------------+
                                         |
                                         v
                 +-----------------------+-----------------------+
                 |                                               |
                 v                                               v
     +-----------------------+                       +-----------------------+
     |   Structured JSON     |                       |  Metrics Registry     |
     |   Formatter Engine    |                       |  (Prometheus format)  |
     +-----------------------+                       +-----------------------+
                 |                                               |
                 v                                               v
     +-----------------------+                       +-----------------------+
     |   PHI Redaction       |                       |  /readyz & /livez     |
     |   Regex Filter        |                       |  K8s Health Probes    |
     +-----------------------+                       +-----------------------+
                 |                                               |
                 v                                               v
         stdout / SIEM                                 K8s Kubelet / Prometheus
```

---

## 2. Structured JSON Logging Architecture

### 2.1 Schema Definition (`app/observability/logging.py`)
All application logs are rendered in strict RFC 8259 JSON format on `sys.stdout`. Every log line includes standard metadata:

```json
{
  "timestamp": "2026-09-23T03:45:12.104Z",
  "level": "INFO",
  "logger": "arogya.services.patient",
  "message": "Patient clinical record retrieved successfully",
  "request_id": "c7a82e81-b547-4952-bf66-0d32240bfa09",
  "ip": "192.168.1.105",
  "method": "GET",
  "path": "/patients/101",
  "user_id": 14,
  "role": "Doctor",
  "duration_ms": 12.4
}
```

### 2.2 Correlation Engine (`X-Request-ID`)
1. Every incoming HTTP request is inspected for an existing `X-Request-ID` header supplied by an ingress proxy or API gateway.
2. If missing, `app.before_request` generates a cryptographically random UUIDv4 and binds it to Flask's request context `g.request_id`.
3. The `X-Request-ID` is echoed back on every response header and injected into every log statement emitted during the request lifecycle, enabling distributed tracing across microservices.

---

## 3. In-Flight PHI Redaction Filter (`PhiRedactionFilter`)

Healthcare logging must adhere to HIPAA Safe Harbor and DPDP data minimization principles. The application attaches a custom logging filter that parses log records before string formatting:

### Redaction Rules & Regular Expressions:
* **Indian Mobile / Phone Numbers:** Matches standard 10-digit mobile numbers prefixed with optional `+91` or `0`:
  ```regex
  (?:\+91[-\s]?|0)?[6-9]\d{9}\b
  ```
* **Dates of Birth:** Matches ISO and standard date formats:
  ```regex
  \b(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})\b
  ```
* **Clinical Diagnostic & Treatment Keywords:** Identifies sensitive clinical terminology:
  ```regex
  (?i)\b(diabetes|hypertension|carcinoma|leukemia|asthma|tuberculosis|hiv|covid|chemotherapy|insulin|paracetamol)\b
  ```

Whenever a regex match occurs in `record.msg` or `record.args`, the matching substring is automatically replaced with `[REDACTED_PHI]` before serialization to stdout.

---

## 4. Metrics Registry (`app/observability/metrics.py`)

ArogyaRaksha maintains an in-memory telemetry registry recording key application indicators:

| Metric Name | Type | Labels | Description |
|:---|:---:|:---|:---|
| `http_requests_total` | Counter | `method`, `endpoint`, `status` | Cumulative volume of HTTP requests |
| `http_request_duration_seconds` | Histogram | `endpoint` | Latency distribution (p50, p95, p99) |
| `auth_failures_total` | Counter | `reason`, `ip` | Rate of failed logins or lockout events |
| `tamper_detection_events_total` | Counter | `source`, `record_id` | Count of GMAC MAC or AAD verification failures |
| `occ_conflicts_total` | Counter | `resource` | Count of optimistic concurrency conflicts (HTTP 409) |
| `cross_tenant_attempts_total` | Counter | `source_tenant`, `target_tenant` | Blocked cross-tenant access attempts |
| `break_glass_access_total` | Counter | `user`, `patient_id` | Emergency overrides invoked by unassigned clinicians |
| `outbox_pending_events` | Gauge | `aggregate_type` | Current queue depth of undelivered outbox messages |
| `outbox_dead_letter_events` | Gauge | `aggregate_type` | Count of failed outbox messages in DEAD_LETTER state |

---

## 5. Kubernetes Health Probes (`app/routes/health.py`)

To ensure high availability and prevent unready pods from receiving clinical traffic, the platform exposes dedicated probe endpoints:

### 5.1 Liveness Probe (`GET /livez`)
* **Objective:** Verifies that the Python WSGI process event loop is active and responsive.
* **Checks:** Non-blocking shallow check returning immediate HTTP 200:
  ```json
  {"status": "alive"}
  ```
* **Kubernetes Action:** If this endpoint fails 3 consecutive times, Kubelet automatically terminates and restarts the container.

### 5.2 Readiness Probe (`GET /readyz`)
* **Objective:** Verifies that the pod can actively process clinical transactions.
* **Checks:**
  1. Executes `SELECT 1` query against the database to confirm pool availability.
  2. Verifies Redis connectivity (if rate limiting or session store is configured for Redis).
* **Response (Healthy):**
  ```json
  {
    "status": "ready",
    "checks": {
      "database": "connected",
      "redis": "connected"
    }
  }
  ```
* **Response (Degraded - HTTP 503 Service Unavailable):**
  ```json
  {
    "status": "not_ready",
    "checks": {
      "database": "disconnected: operational error timeout",
      "redis": "connected"
    }
  }
  ```
* **Kubernetes Action:** An unready pod is immediately pulled from the Service load balancer endpoint pool until health is restored.

---

## 6. Recommended Prometheus Alerting Rules

```yaml
groups:
  - name: arogya_alerts
    rules:
      - alert: CriticalDataTamperDetected
        expr: increase(tamper_detection_events_total[1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Cryptographic MAC Tampering Detected"
          description: "ArogyaRaksha detected an AEAD GMAC or AAD mismatch. Immediate forensic triage required."

      - alert: CrossTenantAccessAttempt
        expr: increase(cross_tenant_attempts_total[1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Cross-Tenant Boundary Breach Attempt"
          description: "Unauthorized access across tenant isolation boundaries was blocked. Immediate SOC investigation required."

      - alert: BreakGlassAccessDeclared
        expr: increase(break_glass_access_total[5m]) > 0
        for: 0m
        labels:
          severity: high
        annotations:
          summary: "Emergency Break-Glass Clinical Override"
          description: "An unassigned clinician invoked emergency override. Reconcile with ED logs within 24h."

      - alert: HighAuthFailureRate
        expr: sum(rate(auth_failures_total[5m])) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Potential Credential Stuffing Attack"
          description: "Elevated authentication failures (>10/min) detected across clinical login endpoints."
```
