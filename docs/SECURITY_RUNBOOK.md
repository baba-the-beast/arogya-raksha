# ArogyaRaksha: Production Security Incident Response Runbook

**System:** ArogyaRaksha Clinical Security Platform  
**Target Audience:** Security Operations Center (SOC), DevSecOps Engineers, On-Call SREs  
**Classification:** Standard Operating Procedures (SOP)  
**Document Version:** 2.0.0-PROD  

---

## 1. Incident Severity Classification & Escalation Matrix

| Severity Level | Definition | Response SLA | Required Responders | Communication Protocol |
|:---:|:---|:---:|:---|:---|
| **P0 - CRITICAL** | Active data tampering (`TAMPER_DETECTED`), Master Key compromise, audit chain breach, or mass exfiltration. | **< 15 minutes** | Lead Security Architect, Clinical Director, Infrastructure Lead | Immediate voice conference, hourly stakeholder updates |
| **P1 - HIGH** | Brute force credential stuffing attack, partial outage of authentication, widespread OCC conflicts. | **< 1 hour** | On-Call SRE, Application Security Engineer | Dedicated incident channel (#incident-active) |
| **P2 - MEDIUM** | Single account lockout anomaly, sporadic rate limit hits, outbox dead-letter queue spike. | **< 4 hours** | Primary On-Call Engineer | Ticket tracking with Jira / PagerDuty |
| **P3 - LOW** | Minor cosmetic header alert, low-frequency 404/405 scans from known scrapers. | **< 24 hours** | Security Operations Analyst | Daily operational review |

---

## 2. Standard Operating Procedures (SOPs)

---

### SOP-01: Response to `TAMPER_DETECTED` (Cryptographic MAC Failure)

#### 1. Identification & Triggers
* **Alert Trigger:** Application logs emit `CRITICAL` alert: `TAMPER_DETECTED: Cryptographic MAC verification failed for patient_id=X`.
* **Root Cause:** A database row's encrypted ciphertext, nonce, tag, or AAD context was altered by an external actor, direct SQL injection, disk corruption, or cross-record ciphertext splicing.

#### 2. Immediate Containment Actions
1. **Isolate Database Node:** If direct database tampering is suspected, immediately restrict database write access:
   ```bash
   # Identify the affected patient record
   kubectl logs -n arogya -l app=arogya-backend --tail=1000 | grep "TAMPER_DETECTED"
   ```
2. **Quarantine the Record:** Mark the clinical record as quarantined in the database to prevent clinical staff from relying on corrupted medical data:
   ```sql
   -- Mark record quarantined (read-only flag)
   UPDATE patients SET is_quarantined = TRUE WHERE id = <PATIENT_ID>;
   ```
3. **Capture Forensic State:** Snapshot the active database volume and capture memory dump of running pods before pod restart or redeployment.

#### 3. Eradication & Recovery
1. Restore the affected record from the latest verified immutable backup taken prior to the timestamp of the tamper event:
   ```bash
   python scripts/backup_db.py --restore --backup-file=/backups/db_backup_<TIMESTAMP>.dump
   ```
2. Verify cryptographic integrity of the restored record:
   ```bash
   python -c "from app import create_app; from app.services.patient_service import PatientService; app=create_app('production'); with app.app_context(): print(PatientService.get_patient_detail(<PATIENT_ID>))"
   ```
3. Document forensic findings and report to the Chief Information Security Officer (CISO).

---

### SOP-02: Audit Hash Chain Tamper Detection (`CHAIN_BREACH`)

#### 1. Identification & Triggers
* **Alert Trigger:** Scheduled audit verification script returns `FAIL: Hash chain verification failed at Record ID: N`.
* **Root Cause:** An adversary or unauthorized database operator modified, deleted, or inserted a row in the `audit_logs` table.

#### 2. Triage & Investigation
1. Run full chain verification with verbose output:
   ```bash
   python -c "from app import create_app; from app.services.audit_service import AuditService; app=create_app('production'); with app.app_context(): is_valid, err = AuditService.verify_chain(); print('Valid:', is_valid, 'Error:', err)"
   ```
2. Note the record ID $N$ where validation failed.
3. Compare record $N$ and preceding records against the immutable external SIEM log stream (Elasticsearch / Splunk / CloudWatch):
   ```bash
   # Query SIEM logs using correlation ID and timestamp of record N
   curl -X GET "https://siem.internal/api/logs?from=<TIMESTAMP_START>&to=<TIMESTAMP_END>&filter=audit"
   ```
4. Identify discrepancy:
   - **Scenario A (Row Deletion):** Record ID $N$ has `previous_hash` pointing to ID $N-2$. Record $N-1$ was deleted.
   - **Scenario B (Row Modification):** Recomputed hash of Record $N$ does not match stored `current_hash`. Data fields were manipulated.

#### 3. Remediation
1. Export forensic evidence for regulatory compliance and audit disclosures.
2. Invalidate compromised staff sessions active during the tamper window.
3. Re-synchronize missing log entries from write-ahead SIEM archive.

---

### SOP-03: Credential Stuffing & Account Lockout Storm

#### 1. Identification & Triggers
* **Alert Trigger:** Metric `auth_failures_total` spikes $>50$ failures/min; multiple staff accounts trigger `locked_until`.

#### 2. Immediate Containment
1. **Block Source IP Subnets at Ingress:**
   ```bash
   # Inspect top attacking IPs from structured logs
   kubectl logs -n arogya -l app=arogya-backend --tail=5000 | jq -r 'select(.event=="LOGIN_FAILED") | .ip' | sort | uniq -c | sort -nr | head -10
   
   # Add offending CIDR blocks to Ingress WAF blocklist
   kubectl edit ingress arogya-ingress -n arogya
   ```
2. **Tighten Rate Limits Dynamically:**
   Update `RATELIMIT_DEFAULT` in `deploy/k8s/configmap.yaml` to `5 per minute` and trigger rolling update.

#### 3. Clinical Staff Account Restoration
To unlock a clinician whose account was locked by malicious automated attempts:
1. Verify clinician identity via verified out-of-band communication (hospital badge / video call).
2. Reset lockout status in production database:
   ```python
   from app import create_app
   from app.models.user import User
   from app.extensions import db

   app = create_app('production')
   with app.app_context():
       user = User.query.filter_by(username="dr_sharma").first()
       user.failed_login_attempts = 0
       user.locked_until = None
       db.session.commit()
       print(f"User {user.username} unlocked.")
   ```

---

### SOP-04: Emergency Master Key Rotation (`KEY_COMPROMISE`)

#### 1. Identification & Triggers
* **Alert Trigger:** Exposure of `MASTER_ENCRYPTION_KEY` in git repository, build log, or compromised server node.

#### 2. Procedure
1. **Generate New Cryptographic Key:**
   ```bash
   NEW_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
   ```
2. **Update Kubernetes Secret with Dual-Key Configuration:**
   Add `MASTER_ENCRYPTION_KEY_V2=$NEW_KEY` and set `ACTIVE_KEY_VERSION=2` in secret manifest.
   ```bash
   kubectl set env deployment/arogya-backend -n arogya MASTER_ENCRYPTION_KEY_V2=$NEW_KEY ACTIVE_KEY_VERSION=2
   ```
3. **Execute Re-Encryption Job:**
   Run the batch re-encryption script against all existing patient records:
   ```bash
   kubectl run key-rotation-job --image=arogya-backend:2.0.0 --restart=Never --env-from=secret/arogya-secrets -- python scripts/rotate_keys.py
   ```
4. **Decommission Compromised Key:**
   Once `scripts/rotate_keys.py` reports 100% records converted to Version 2, remove the original compromised key from Kubernetes secrets and restart all deployment pods.

---

### SOP-05: Response to `CROSS_TENANT_ATTEMPT` (Multi-Tenant Boundary Breach)

#### 1. Identification & Triggers
* **Alert Trigger:** `CROSS_TENANT_ATTEMPT` audit event logged; SIEM alert fired with `SEVERITY: HIGH`.
* **Root Cause:** A user account belonging to Organization A attempted to access or modify a patient record belonging to Organization B (either via manipulated URL parameters or compromised session).

#### 2. Immediate Containment
1. Check the user's recent request sequence:
   ```bash
   kubectl logs -n arogya -l app=arogya-backend --tail=1000 | grep "CROSS_TENANT_ATTEMPT"
   ```
2. If repetitive automated cross-tenant parameter probing is detected:
   - Immediately suspend the offending user account:
     ```python
     user.is_active = False
     user.session_version += 1  # Invalidates active sessions immediately
     ```
   - Block originating IP subnet at ingress WAF.

---

### SOP-06: Emergency `BREAK_GLASS_ACCESS` Audit Reconciliation

#### 1. Identification & Triggers
* **Alert Trigger:** `BREAK_GLASS_ACCESS` alert received by Clinical Director and SOC with stated clinical justification.
* **Objective:** Ensure emergency overrides are verified against hospital admissions and emergency department logs within 24 hours.

#### 2. Procedure
1. Extract declared justification and affected patient ID from audit trail:
   ```sql
   SELECT timestamp, username, resource_id, details FROM audit_logs WHERE action = 'BREAK_GLASS_ACCESS' ORDER BY id DESC LIMIT 10;
   ```
2. Cross-reference clinical emergency logs: verify if the clinician was actively attending an emergency case with the patient.
3. If legitimate emergency: mark incident ticket as verified.
4. If unauthorized or abusive: revoke clinician credentials and escalate to Medical Directorate.

---

## 3. Post-Incident Review (PIR) Template

Every P0 or P1 incident must conclude with a blameless Post-Incident Review within 48 hours:
1. **Executive Summary:** Brief synopsis of what occurred, duration, and clinical impact.
2. **Timeline:** UTC timestamped sequence of events from trigger to full resolution.
3. **Root Cause Analysis (5 Whys):** Deep systemic determination of root cause.
4. **Detection Effectiveness:** Did alerts fire within SLA? Were false alarms present?
5. **Action Items:** Preventive engineering tickets with assigned owners and deadlines.

