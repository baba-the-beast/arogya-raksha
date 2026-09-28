"""
Automated unit tests for AES-256-GCM Cryptographic Service (FR4, FR7, NFR1, NFR2).
"""
import pytest

from app.services.crypto_service import CryptoError, CryptoService, IntegrityTamperedError


def test_aes_gcm_encryption_decryption(app):
    """Test standard AES-256-GCM encryption and decryption round-trip."""
    with app.app_context():
        sensitive_data = {
            "name": "Bruce Wayne",
            "diagnosis": "Multiple Fractures",
            "medical_history": "Childhood trauma, highly athletic",
            "notes": "Recovering well in private suite."
        }

        ciphertext_hex, nonce_hex, auth_tag_hex, key_version = CryptoService.encrypt_record(sensitive_data)

        assert ciphertext_hex is not None
        assert len(nonce_hex) == 24  # 12 bytes = 24 hex characters
        assert len(auth_tag_hex) == 32  # 16 bytes = 32 hex characters
        assert key_version == 1

        decrypted = CryptoService.decrypt_record(ciphertext_hex, nonce_hex, auth_tag_hex, key_version)
        assert decrypted == sensitive_data
        assert decrypted["name"] == "Bruce Wayne"

def test_fresh_nonce_per_encryption(app):
    """Test that every encryption generates a distinct 12-byte random nonce (prevent IV reuse)."""
    with app.app_context():
        payload = {"name": "Clark Kent", "diagnosis": "None"}
        _, nonce1, _, _ = CryptoService.encrypt_record(payload)
        _, nonce2, _, _ = CryptoService.encrypt_record(payload)

        assert nonce1 != nonce2, "Cryptographic nonces must never be reused across encryptions!"

def test_ciphertext_tamper_detection(app):
    """Test that modifying even a single character of ciphertext triggers an IntegrityTamperedError (FR7)."""
    with app.app_context():
        payload = {"name": "Diana Prince", "diagnosis": "Exhaustion"}
        ciphertext_hex, nonce_hex, auth_tag_hex, key_version = CryptoService.encrypt_record(payload)

        # Flip the first hex character of the ciphertext
        tampered_char = "0" if ciphertext_hex[0] != "0" else "1"
        tampered_ciphertext = tampered_char + ciphertext_hex[1:]

        with pytest.raises(IntegrityTamperedError) as excinfo:
            CryptoService.decrypt_record(tampered_ciphertext, nonce_hex, auth_tag_hex, key_version)
        assert "Integrity check failed" in str(excinfo.value)

def test_auth_tag_tamper_detection(app):
    """Test that altering the GMAC authentication tag triggers an IntegrityTamperedError (FR7)."""
    with app.app_context():
        payload = {"name": "Barry Allen", "diagnosis": "Hyper-metabolism"}
        ciphertext_hex, nonce_hex, auth_tag_hex, key_version = CryptoService.encrypt_record(payload)

        # Corrupt the authentication tag
        tampered_tag = ("0" if auth_tag_hex[0] != "0" else "1") + auth_tag_hex[1:]

        with pytest.raises(IntegrityTamperedError) as excinfo:
            CryptoService.decrypt_record(ciphertext_hex, nonce_hex, tampered_tag, key_version)
        assert "Integrity check failed" in str(excinfo.value)

def test_malformed_cryptographic_inputs(app):
    """Test that malformed hex strings or invalid lengths raise CryptoError cleanly."""
    with app.app_context():
        with pytest.raises(CryptoError):
            CryptoService.decrypt_record("invalid-non-hex!", "00"*12, "00"*16)

        with pytest.raises(CryptoError):
            # Nonce wrong length (8 bytes instead of 12)
            CryptoService.decrypt_record("00"*10, "00"*8, "00"*16)

def test_fast_fail_on_missing_or_fallback_keys_in_production():
    """Verify app creation fails fast (RuntimeError) without proper keys in prod config (BUG-05)."""
    from app import create_app
    from app.config import Config

    # 1. Fallback / missing SECRET_KEY in non-test config
    class InsecureSecretConfig(Config):
        TESTING = False
        SECRET_KEY = "fallback-secret-key-for-dev-only-32bytes!"
        MASTER_ENCRYPTION_KEY = b"1" * 32

    with pytest.raises(RuntimeError, match="SECRET_KEY is missing or using known insecure fallback"):
        create_app(InsecureSecretConfig)

    # 2. Missing / all-zero MASTER_ENCRYPTION_KEY in non-test config
    class InsecureMasterKeyConfig(Config):
        TESTING = False
        SECRET_KEY = "a-real-secure-production-secret-key-1234"
        MASTER_ENCRYPTION_KEY = b"\x00" * 32

    with pytest.raises(RuntimeError, match="MASTER_ENCRYPTION_KEY is missing or using known zero-byte fallback"):
        create_app(InsecureMasterKeyConfig)

