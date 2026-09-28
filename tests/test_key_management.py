"""
Phase 3 — Key Management & Zero-Downtime Rotation Tests.

Covers:
- KeyProvider interface and EnvKeyProvider multi-version lookup
- KMSKeyProvider enterprise stub behavior
- Multi-version ciphertext decryption (historical key resolution)
- Key rotation CLI workflow (scripts/rotate_keys.py) with batching and audit logging
"""
import pytest

from app.models.audit_log import AuditLog
from app.models.patient import Patient
from app.services.crypto_service import (
    CryptoError,
    CryptoService,
    EnvKeyProvider,
    KeyNotFoundError,
    KMSKeyProvider,
)
from app.services.patient_service import PatientService
from scripts.rotate_keys import rotate_patient_keys

# ── KeyProvider Tests ────────────────────────────────────────────────────────

def test_env_key_provider_resolves_configured_versions(app):
    """EnvKeyProvider retrieves keys for all registered versions."""
    with app.app_context():
        provider = EnvKeyProvider()
        key1 = provider.get_key(1)
        key2 = provider.get_key(2)

        assert len(key1) == 32
        assert len(key2) == 32
        assert key1 != key2

        v, current_key = provider.get_current_key()
        assert v == 1
        assert current_key == key1


def test_env_key_provider_raises_key_not_found(app):
    """EnvKeyProvider raises KeyNotFoundError when requesting unknown key version."""
    with app.app_context():
        provider = EnvKeyProvider()
        with pytest.raises(KeyNotFoundError) as exc_info:
            provider.get_key(999)
        assert "version 999" in str(exc_info.value)


def test_kms_key_provider_stub_behavior():
    """KMSKeyProvider stub raises NotImplementedError with guidance message."""
    kms = KMSKeyProvider()
    assert kms.current_version() == 1
    with pytest.raises(NotImplementedError) as exc_info:
        kms.get_key(1)
    assert "Cloud KMS" in str(exc_info.value)


# ── Multi-Version Encryption/Decryption Tests ────────────────────────────────

def test_multi_version_encryption_and_decryption(app):
    """Records encrypted under different historical keys can all be decrypted seamlessly."""
    with app.app_context():
        provider = EnvKeyProvider()
        payload_v1 = {"name": "Historical Alice", "diagnosis": "Condition A"}
        payload_v2 = {"name": "Modern Bob", "diagnosis": "Condition B"}

        # Encrypt with version 1
        c1, n1, t1, v1 = CryptoService.encrypt_record(payload_v1, key_version=1, provider=provider)
        assert v1 == 1

        # Encrypt with version 2
        c2, n2, t2, v2 = CryptoService.encrypt_record(payload_v2, key_version=2, provider=provider)
        assert v2 == 2

        # Decrypt using version resolution from registry
        d1 = CryptoService.decrypt_record(c1, n1, t1, key_version=1, provider=provider)
        d2 = CryptoService.decrypt_record(c2, n2, t2, key_version=2, provider=provider)

        assert d1["name"] == "Historical Alice"
        assert d2["name"] == "Modern Bob"


# ── Key Rotation CLI Tests ───────────────────────────────────────────────────

def test_key_rotation_dry_run_leaves_database_untouched(app):
    """Dry run counts pending records without modifying their key_version or ciphertexts."""
    with app.app_context():
        patient = Patient.query.first()
        orig_ciphertext = patient.encrypted_data
        orig_version = patient.key_version

        count = rotate_patient_keys(target_version=2, dry_run=True, app=app)
        assert count >= 1

        # Re-fetch from DB and verify unchanged
        from app.extensions import db
        p_after = db.session.get(Patient, patient.id)
        assert p_after.encrypted_data == orig_ciphertext
        assert p_after.key_version == orig_version


def test_key_rotation_migrates_all_records_and_audits_batches(app):
    """
    rotate_patient_keys re-encrypts all records in batches, updates key_version,
    records KEY_ROTATION audit entries, and allows seamless reading afterward.
    """
    with app.app_context():
        # Ensure we have at least 3 records on key version 1
        for i in range(1, 4):
            try:
                PatientService.create_patient(
                    patient_id=f"P-ROT-{i:03d}",
                    age_band="40-49",
                    gender="Other",
                    name=f"Rotation Subject {i}",
                    diagnosis=f"Diagnosis {i}",
                    medical_history="None",
                    notes="Test note",
                )
            except ValueError:
                pass

        # Execute key rotation to version 2 with a small batch size of 2 to test batching
        total_rotated = rotate_patient_keys(target_version=2, batch_size=2, dry_run=False, app=app)
        assert total_rotated >= 3

        # All records in DB must now be on key version 2
        non_rotated = Patient.query.filter(Patient.key_version != 2).count()
        assert non_rotated == 0

        # Every record can be decrypted cleanly via PatientService.get_patient_by_id
        for p in Patient.query.all():
            decrypted = PatientService.get_patient_by_id(p.id, tenant_id="tenant-default")
            assert decrypted is not None
            assert decrypted["key_version"] == 2
            assert "name" in decrypted and len(decrypted["name"]) > 0

        # Verify KEY_ROTATION audit events were logged
        rotation_logs = AuditLog.query.filter_by(action="KEY_ROTATION").all()
        assert len(rotation_logs) >= 1
        assert all(log.status == "SUCCESS" for log in rotation_logs)

        # Re-running rotation is idempotent and rotates 0 records
        idempotent_count = rotate_patient_keys(target_version=2, batch_size=50, app=app)
        assert idempotent_count == 0


def test_key_rotation_fails_gracefully_on_unknown_target_key(app):
    """Attempting rotation to a non-existent key version returns error code -1."""
    with app.app_context():
        res = rotate_patient_keys(target_version=999, app=app)
        assert res == -1
