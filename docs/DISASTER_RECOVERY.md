# ArogyaRaksha: Disaster Recovery & Business Continuity Plan

**System:** ArogyaRaksha Clinical Security Platform  
**Target Audience:** SREs, Systems Administrators, Database Administrators (DBA), Compliance Officers  
**Regulatory Standards:** HIPAA Disaster Recovery Plan (45 CFR § 164.308(a)(7)(ii)(B)), DPDP Act 2023  
**Document Version:** 2.0.0-PROD  

---

## 1. Disaster Recovery Objectives & Classification

In healthcare environments, unexpected service disruption can imperil patient safety. ArogyaRaksha defines explicit recovery boundaries:

| Metric | Target Objective | Technical Mechanism |
|:---|:---:|:---|
| **Recovery Point Objective (RPO)** | **$\le 15$ minutes** | Continuous PostgreSQL Write-Ahead Logging (WAL) + hourly differential snapshots + daily full backups. |
| **Recovery Time Objective (RTO)** | **$\le 30$ minutes** | Declarative Kubernetes manifest reconciliation (`kubectl apply`) + automated database restore pipeline. |
| **Data Integrity Verification** | **100% Cryptographic Match** | SHA-256 audit chain check + AEAD GCM tag validation across restored patient sample. |

---

## 2. Backup Strategy & Procedures

### 2.1 Backup Script Implementation (`scripts/backup_db.py`)
ArogyaRaksha includes a unified, database-agnostic backup engine capable of operating against production PostgreSQL instances or local SQLite edge databases:

```bash
# PostgreSQL Production Full Backup
python scripts/backup_db.py --type=postgres --output-dir=/var/backups/arogya

# SQLite Development / Edge Backup (Uses SQLite Online Backup API)
python scripts/backup_db.py --type=sqlite --output-dir=/var/backups/arogya
```

### 2.2 Backup Storage & Lifecycle Matrix
* **Hot Storage (On-Cluster):** Hourly snapshots retained on Ceph / NVMe persistent volume for 24 hours.
* **Warm Storage (Cloud Object Storage):** Encrypted backups replicated to S3 / Cloud Storage with Object Lock (WORM - Write Once, Read Many) enabled.
* **Cold Storage (Archive):** Monthly consolidated archives stored in air-gapped immutable storage with 7-year statutory clinical retention.

---

## 3. Step-by-Step Restoration Runbook

### 3.1 Scenario 1: Complete PostgreSQL Database Restoration

#### Step 1: Provision Clean Database Instance
```bash
# Ensure target PostgreSQL server is provisioned and listening
pg_isready -h postgres.internal -p 5432
```

#### Step 2: Drop Corrupted Database & Re-create Clean Schema
```bash
psql -h postgres.internal -U postgres -c "DROP DATABASE IF EXISTS arogya_db;"
psql -h postgres.internal -U postgres -c "CREATE DATABASE arogya_db OWNER arogya_user;"
```

#### Step 3: Stream Encrypted Backup into Target Instance
```bash
# Decrypt backup archive and restore schema & data
gpg --decrypt /var/backups/arogya/arogya_db_2026_09_23.dump.gpg | \
  pg_restore -h postgres.internal -U arogya_user -d arogya_db --clean --if-exists --no-owner
```

#### Step 4: Validate Migration State
```bash
# Verify Alembic migration head matches codebase expectation
flask db current
# Output must indicate: 9a2b3c4d5e6f (head)
```

---

### 3.2 Scenario 2: SQLite Edge Node Restoration

#### Step 1: Terminate Local Service Process
```bash
sudo systemctl stop arogya-backend
```

#### Step 2: Swap Corrupted Database File with Verified Snapshot
```bash
# Move corrupted file aside for forensic review
mv /var/lib/arogya/healthcare.db /var/lib/arogya/healthcare_corrupt_$(date +%s).db

# Copy verified backup file into target path
cp /var/backups/arogya/healthcare_snapshot.db /var/lib/arogya/healthcare.db
chmod 600 /var/lib/arogya/healthcare.db
chown arogya:arogya /var/lib/arogya/healthcare.db
```

#### Step 3: Restart Service Process
```bash
sudo systemctl start arogya-backend
```

---

## 4. Post-Restoration Verification & Cryptographic Health Check

A restoration is never declared successful until all four health checkpoints pass unconditionally:

### 1. Database Connection & Schema Check
```bash
python -c "from app import create_app; from app.extensions import db; app=create_app('production'); with app.app_context(): db.session.execute('SELECT 1'); print('Database Connectivity: PASS')"
```

### 2. Audit Trail Cryptographic Hash Chain Verification
```bash
python -c "from app import create_app; from app.services.audit_service import AuditService; app=create_app('production'); with app.app_context(): valid, err = AuditService.verify_chain(); assert valid, f'Audit Breach: {err}'; print('Audit Hash Chain: PASS')"
```

### 3. AEAD Ciphertext Decryption & Context Binding Verification
```bash
python -c "from app import create_app; from app.models.patient import Patient; from app.services.patient_service import PatientService; app=create_app('production'); with app.app_context(): p = Patient.query.first(); detail = PatientService.get_patient_detail(p.id); assert 'diagnosis' in detail; print(f'Clinical Decryption Check (Patient ID {p.id}): PASS')"
```

### 4. Health Probe Verification
```bash
curl -f http://localhost:8000/readyz
# Output: {"status": "ready", "database": "connected"}
```

---

## 5. Semi-Annual Disaster Recovery Drill Schedule

To guarantee business continuity under disaster conditions, disaster recovery simulations are scheduled semi-annually:
1. **Q1 Drill (Cloud Provider Failover):** Simulate complete zone outage, failover Kubernetes cluster to secondary cloud region.
2. **Q3 Drill (Ransomware / Corruption Scenario):** Deliberately corrupt database volume, execute full restore from immutable cold backup, and measure total elapsed RTO.
