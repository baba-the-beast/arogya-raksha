"""
Key Rotation CLI Script (Phase 3)
==================================
Performs zero-downtime, batch re-encryption of patient records from historical key
versions to a target key version (typically the current active version).

Features:
- Idempotent and resumable: records already on target key version (and AAD schema 2) are skipped.
- Upgrades legacy rows (crypto_schema 1) to version-bound AAD (crypto_schema 2). Once no
  schema 1 rows remain, set CRYPTO_ALLOW_LEGACY_AAD=False.
- Batched commits: prevents long-held locks and excessive memory consumption.
- Comprehensive audit trail: logs a KEY_ROTATION audit event per batch.
- Supports dry-run inspection mode.

Usage:
    python scripts/rotate_keys.py --target-version 2 --batch-size 50
    python scripts/rotate_keys.py --dry-run
"""
import argparse
import os
import sys
from datetime import UTC, datetime

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import or_

from app import create_app
from app.extensions import db
from app.models.patient import Patient
from app.services.audit_service import AuditService
from app.services.crypto_service import CryptoService, KeyNotFoundError


def rotate_patient_keys(target_version: int, batch_size: int = 50, dry_run: bool = False, app=None) -> int:
    """
    Re-encrypts all patient records not yet on target_version using fresh nonces and auth tags.
    Returns total number of records successfully rotated.
    """
    ctx = app.app_context() if app else None
    if ctx:
        ctx.__enter__()

    try:
        provider = CryptoService.get_key_provider()

        # Validate that the target key exists in the registry
        try:
            target_key = provider.get_key(target_version)
        except KeyNotFoundError:
            print(f"[!] Error: Target key version {target_version} not found in KEY_REGISTRY.")
            print("    Configure the key in KEY_REGISTRY_JSON or ENCRYPTION_KEY_v<N> before rotating.")
            return -1

        pending_query = Patient.query.filter(
            or_(Patient.key_version != target_version, Patient.crypto_schema < 2)
        )
        total_pending = pending_query.count()

        if total_pending == 0:
            print(f"[+] All patient records are already on key version {target_version} with version-bound AAD. Nothing to rotate.")
            return 0

        print(f"[*] Found {total_pending} record(s) needing rotation to key version {target_version}.")
        if dry_run:
            print("[*] Dry run mode active: No database changes will be committed.")
            return total_pending

        total_rotated = 0
        batch_num = 0

        while True:
            # Fetch next batch (always query records still on old versions)
            batch = pending_query.order_by(Patient.id.asc()).limit(batch_size).all()
            if not batch:
                break

            batch_num += 1
            start_id = batch[0].id
            end_id = batch[-1].id

            for patient in batch:
                tenant_id = getattr(patient, "tenant_id", "tenant-default") or "tenant-default"
                # 1. Decrypt using historical version recorded on the row with bound AAD
                legacy = (patient.crypto_schema or 1) < 2
                aad_historical = CryptoService.build_record_aad(
                    patient_record_id=patient.patient_id,
                    tenant_id=tenant_id,
                    key_version=patient.key_version,
                    record_version=None if legacy else patient.version_id,
                )
                plaintext_dict = CryptoService.decrypt_record(
                    ciphertext_hex=patient.encrypted_data,
                    nonce_hex=patient.nonce,
                    auth_tag_hex=patient.auth_tag,
                    key_version=patient.key_version,
                    provider=provider,
                    aad=aad_historical
                )

                # 2. Re-encrypt under target_version with fresh random nonce and new target AAD
                aad_target = CryptoService.build_record_aad(
                    patient_record_id=patient.patient_id,
                    tenant_id=tenant_id,
                    key_version=target_version,
                    record_version=patient.version_id,
                )
                ciphertext_hex, nonce_hex, auth_tag_hex, v = CryptoService.encrypt_record(
                    sensitive_data=plaintext_dict,
                    key=target_key,
                    key_version=target_version,
                    provider=provider,
                    aad=aad_target
                )

                # 3. Update patient row
                patient.encrypted_data = ciphertext_hex
                patient.nonce = nonce_hex
                patient.auth_tag = auth_tag_hex
                patient.key_version = v
                patient.crypto_schema = 2
                patient.updated_at = datetime.now(UTC)

            # Commit batch transaction
            db.session.commit()
            total_rotated += len(batch)

            # Write single audit event per batch (prevents audit flood)
            AuditService.log_event(
                action="KEY_ROTATION",
                resource_type="PATIENT_BATCH",
                resource_id=f"v{target_version}",
                status="SUCCESS",
                username="system/key_rotation_cli",
                details=f"Rotated to key version {target_version}: batch #{batch_num} ({len(batch)} records, IDs {start_id}..{end_id})"
            )

            print(f"[+] Batch #{batch_num} complete: rotated {len(batch)} records ({total_rotated}/{total_pending} total).")

        print(f"[SUCCESS] Key rotation complete: {total_rotated} patient record(s) re-encrypted to key version {target_version}.")
        return total_rotated

    finally:
        if ctx:
            ctx.__exit__(None, None, None)


def main():
    parser = argparse.ArgumentParser(description="ArogyaRaksha Patient Record Key Rotation CLI")
    parser.add_argument(
        "--target-version",
        type=int,
        default=None,
        help="Target key version to re-encrypt records with (defaults to CURRENT_KEY_VERSION)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Number of records to re-encrypt per transaction batch (default: 50)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate rotation without modifying database"
    )

    args = parser.parse_args()
    app = create_app()

    with app.app_context():
        target_v = args.target_version or app.config.get("CURRENT_KEY_VERSION", 1)
        res = rotate_patient_keys(
            target_version=target_v,
            batch_size=args.batch_size,
            dry_run=args.dry_run,
            app=app
        )
        if res < 0:
            sys.exit(1)


if __name__ == "__main__":
    main()
