"""
Cryptographic Assurance Tests: Context-Bound AEAD & Anti-Transplant Protections.
Verifies that AES-256-GCM ciphertexts cannot be transplanted across:
  - Different patient IDs
  - Different tenants
  - Different cryptographic purposes / AAD contexts
  - Tampered nonces, ciphertexts, or authentication tags
"""
import pytest

from app.services.crypto_service import CryptoService, IntegrityTamperedError


def test_patient_id_transplant_rejected(app):
    """
    Test that ciphertext encrypted for Patient A CANNOT be decrypted
    for Patient B (Authoritative Patient ID Context Binding via RFC 8785 AAD).
    """
    with app.app_context():
        sensitive_data = {"diagnosis": "Patient suffers from severe acute respiratory distress"}
        patient_a_id = "patient-uuid-1111"
        patient_b_id = "patient-uuid-2222"
        tenant_id = "tenant-apollo"

        ct, nonce, tag, kv = CryptoService.encrypt_patient_record(
            patient_id=patient_a_id,
            tenant_id=tenant_id,
            sensitive_data=sensitive_data,
        )

        decrypted = CryptoService.decrypt_patient_record(
            patient_id=patient_a_id,
            tenant_id=tenant_id,
            ciphertext_hex=ct,
            nonce_hex=nonce,
            auth_tag_hex=tag,
            key_version=kv,
        )
        assert decrypted == sensitive_data

        with pytest.raises(IntegrityTamperedError, match="Integrity check failed"):
            CryptoService.decrypt_patient_record(
                patient_id=patient_b_id,
                tenant_id=tenant_id,
                ciphertext_hex=ct,
                nonce_hex=nonce,
                auth_tag_hex=tag,
                key_version=kv,
            )


def test_tenant_transplant_rejected(app):
    """
    Test that ciphertext encrypted under Tenant A CANNOT be decrypted
    under Tenant B (Cross-Tenant Cryptographic Isolation via RFC 8785 AAD).
    """
    with app.app_context():
        sensitive_data = {"medical_history": "Confidential psychiatric intake notes"}
        patient_id = "patient-uuid-common"
        tenant_a = "hospital-metro"
        tenant_b = "hospital-rural"

        ct, nonce, tag, kv = CryptoService.encrypt_patient_record(
            patient_id=patient_id,
            tenant_id=tenant_a,
            sensitive_data=sensitive_data,
        )

        with pytest.raises(IntegrityTamperedError, match="Integrity check failed"):
            CryptoService.decrypt_patient_record(
                patient_id=patient_id,
                tenant_id=tenant_b,
                ciphertext_hex=ct,
                nonce_hex=nonce,
                auth_tag_hex=tag,
                key_version=kv,
            )


def test_purpose_context_transplant_rejected(app):
    """
    Test that ciphertext encrypted for clinical records cannot be decrypted under a different purpose.
    (Cross-Purpose Substitution Defense via Key Derivation and AAD).
    """
    with app.app_context():
        sensitive_data = {"allergies": "Penicillin allergy - severe anaphylaxis"}
        patient_id = "patient-uuid-3333"
        tenant_id = "tenant-apollo"

        ct, nonce, tag, kv = CryptoService.encrypt_patient_record(
            patient_id=patient_id,
            tenant_id=tenant_id,
            sensitive_data=sensitive_data,
            purpose="clinical_record",
        )

        with pytest.raises(IntegrityTamperedError, match="Integrity check failed"):
            CryptoService.decrypt_patient_record(
                patient_id=patient_id,
                tenant_id=tenant_id,
                ciphertext_hex=ct,
                nonce_hex=nonce,
                auth_tag_hex=tag,
                key_version=kv,
                purpose="totp_secret",
            )


def test_ciphertext_bit_flipping_tamper_detection(app):
    """
    Test that flipping even a single character in the ciphertext is detected
    by AES-256-GCM authentication verification (IntegrityTamperedError).
    """
    with app.app_context():
        sensitive_data = {"treatment_plan": "Critical cardiac medication dosage: 50mg"}
        patient_id = "patient-uuid-4444"
        tenant_id = "tenant-default"

        ct, nonce, tag, kv = CryptoService.encrypt_patient_record(
            patient_id=patient_id,
            tenant_id=tenant_id,
            sensitive_data=sensitive_data,
        )

        tampered_char = "0" if ct[0] != "0" else "1"
        tampered_ct = tampered_char + ct[1:]

        with pytest.raises(IntegrityTamperedError, match="Integrity check failed"):
            CryptoService.decrypt_patient_record(
                patient_id=patient_id,
                tenant_id=tenant_id,
                ciphertext_hex=tampered_ct,
                nonce_hex=nonce,
                auth_tag_hex=tag,
                key_version=kv,
            )


def test_nonce_corruption_rejection(app):
    """
    Test that corrupting the 12-byte IV/nonce results in immediate decryption failure.
    """
    with app.app_context():
        sensitive_data = {"notes": "Patient exhibits stable vitals"}
        patient_id = "patient-uuid-5555"
        tenant_id = "tenant-default"

        ct, nonce, tag, kv = CryptoService.encrypt_patient_record(
            patient_id=patient_id,
            tenant_id=tenant_id,
            sensitive_data=sensitive_data,
        )

        tampered_nonce = ("0" if nonce[0] != "0" else "1") + nonce[1:]

        with pytest.raises(IntegrityTamperedError, match="Integrity check failed"):
            CryptoService.decrypt_patient_record(
                patient_id=patient_id,
                tenant_id=tenant_id,
                ciphertext_hex=ct,
                nonce_hex=tampered_nonce,
                auth_tag_hex=tag,
                key_version=kv,
            )
