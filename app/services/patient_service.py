"""
Patient Service managing patient record lifecycle, AES-256-GCM encryption/decryption, and audit logging.
"""
import logging
import re
from typing import Any

from app.extensions import db
from app.models.patient import Patient
from app.services.audit_service import AuditService
from app.services.crypto_service import CryptoService, IntegrityTamperedError

logger = logging.getLogger(__name__)


class ConcurrencyConflictError(ValueError):
    """Raised when an update conflicts with a concurrent update (OCC failure - P0-8)."""
    pass


class PatientService:
    """Orchestrates patient record operations with strict encryption at rest and audit trails."""

    # Input bounds (BUG-03)
    MAX_PATIENT_ID_LENGTH = 64
    MAX_NAME_LENGTH = 128
    MAX_FREE_TEXT_LENGTH = 10 * 1024  # 10 KB
    PATIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")

    @classmethod
    def _validate_with_pydantic(
        cls,
        patient_id: str | None = None,
        name: str | None = None,
        diagnosis: str | None = None,
        medical_history: str | None = None,
        notes: str | None = None,
        age_band: str | None = None,
        gender: str | None = None
    ) -> None:
        """Validates length and format bounds for patient fields (BUG-03) using Pydantic."""
        from pydantic import ValidationError

        from app.schemas.patient import PatientCreate, PatientUpdate

        try:
            if patient_id is not None:
                PatientCreate(
                    patient_id=patient_id,
                    name=name or "stub",
                    diagnosis=diagnosis or "stub",
                    medical_history=medical_history or "stub",
                    notes=notes or "stub",
                    age_band=age_band or "stub",
                    gender=gender or "stub"
                )
            else:
                PatientUpdate(
                    name=name or "stub",
                    diagnosis=diagnosis or "stub",
                    medical_history=medical_history or "stub",
                    notes=notes or "stub",
                    age_band=age_band or "stub",
                    gender=gender or "stub"
                )
        except ValidationError as e:
            # Map Pydantic errors to simple ValueError for backward compatibility with tests
            for err in e.errors():
                loc = err["loc"][0]
                msg = err["msg"]
                typ = err["type"]
                if loc == "patient_id":
                    if typ == "string_too_long":
                        raise ValueError("Patient ID exceeds maximum allowed length of 64 characters.") from e
                    raise ValueError(f"Patient ID error: {msg}") from e
                if loc == "name":
                    if typ == "string_too_long":
                        raise ValueError("Patient Name exceeds maximum allowed length of 128 characters.") from e
                    raise ValueError(f"Patient Name error: {msg}") from e

                # Match expected strings for other fields
                if typ == "string_too_long":
                    # Capitalize first letter of loc, replace underscore with space
                    field_name = loc.replace("_", " ").title()
                    raise ValueError(f"{field_name} exceeds maximum allowed size of {err['ctx']['max_length']} bytes.") from e

                raise ValueError(f"{loc.capitalize()} error: {msg}") from e

    @classmethod
    def validate_patient_input(
        cls,
        patient_id: str | None = None,
        name: str | None = None,
        diagnosis: str | None = None,
        medical_history: str | None = None,
        notes: str | None = None
    ) -> None:
        """Legacy wrapper mapping to new Pydantic logic."""
        if patient_id is not None and not patient_id.strip():
            raise ValueError("Patient ID cannot be empty.")
        if name is not None and not name.strip():
            raise ValueError("Patient Name cannot be empty.")

        cls._validate_with_pydantic(
            patient_id=patient_id,
            name=name,
            diagnosis=diagnosis,
            medical_history=medical_history,
            notes=notes
        )

    # ── Architectural boundary (Phase 2) ─────────────────────────────────────
    # Server-side search is ONLY over clear (non-encrypted) fields:
    # patient_id, age_band, gender.  Name, diagnosis, medical_history, and
    # notes are encrypted at rest (AES-256-GCM) and CANNOT be searched
    # server-side without decrypting every record — which is explicitly
    # avoided for performance, privacy, and side-channel reasons.
    # This boundary is documented in docs/ARCHITECTURE.md §7.
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def list_patients(
        cls,
        page: int = 1,
        per_page: int = 25,
        q: str = "",
        age_band: str = "",
        gender: str = "",
        tenant_id: str | None = None,
    ) -> "flask_sqlalchemy.Pagination":  # noqa: F821  (type hint only)
        """
        Returns a paginated list of patient summaries using non-PHI clear fields scoped to tenant.
        Server-side search is limited to patient_id (prefix match), age_band (exact),
        and gender (exact) — never over encrypted fields.
        """
        per_page = max(1, min(per_page, 100))
        query = Patient.query.filter(Patient.deleted_at.is_(None)).order_by(Patient.created_at.desc())

        if tenant_id:
            query = query.filter(Patient.tenant_id == tenant_id.strip())
        if q:
            # Prefix search leverages B-Tree index on patient_id
            query = query.filter(Patient.patient_id.ilike(f"{q.strip()}%"))
        if age_band:
            query = query.filter(Patient.age_band == age_band.strip())
        if gender:
            query = query.filter(Patient.gender == gender.strip())

        from sqlalchemy.orm import joinedload
        query = query.options(joinedload(Patient.assigned_doctor))
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        # Convert ORM objects to lightweight dicts so callers never accidentally
        # trigger lazy-load of encrypted fields.
        pagination.items = [
            {
                "id": p.id,
                "patient_id": p.patient_id,
                "age_band": p.age_band or "N/A",
                "gender": p.gender or "N/A",
                "created_at": p.created_at,
                "updated_at": p.updated_at,
                "assigned_doctor_id": p.assigned_doctor_id,
                "assigned_doctor_name": p.assigned_doctor.username if p.assigned_doctor else None,
            }
            for p in pagination.items
        ]
        return pagination

    @classmethod
    def dashboard_summary(cls, user) -> dict[str, Any]:
        """Clear-field counts and the user's recently updated patients for the home screen."""
        tenant_id = getattr(user, "tenant_id", "tenant-default") or "tenant-default"
        active = Patient.query.filter(Patient.deleted_at.is_(None), Patient.tenant_id == tenant_id)
        mine = active.filter(Patient.assigned_doctor_id == user.id)
        return {
            "total": active.count(),
            "assigned_to_me": mine.count(),
            "unassigned": active.filter(Patient.assigned_doctor_id.is_(None)).count(),
            "my_recent": [
                {"id": p.id, "patient_id": p.patient_id, "age_band": p.age_band, "gender": p.gender,
                 "updated_at": p.updated_at}
                for p in mine.order_by(Patient.updated_at.desc()).limit(5)
            ],
        }

    @classmethod
    def _record_aad(cls, patient: Patient, tenant_id: str) -> bytes:
        """
        Rebuilds the AAD a stored ciphertext was sealed with. crypto_schema 2 binds version_id
        (anti-replay); legacy schema 1 rows are accepted only while CRYPTO_ALLOW_LEGACY_AAD is on.
        """
        from flask import current_app
        if (patient.crypto_schema or 1) >= 2:
            record_version = patient.version_id
        elif current_app.config.get("CRYPTO_ALLOW_LEGACY_AAD", True):
            record_version = None
        else:
            raise IntegrityTamperedError(
                "Legacy (non version-bound) ciphertext rejected by policy. Re-encrypt with scripts/rotate_keys.py."
            )
        return CryptoService.build_record_aad(
            patient_record_id=patient.patient_id,
            tenant_id=tenant_id,
            key_version=patient.key_version,
            record_version=record_version,
        )

    @classmethod
    def list_assignable_doctors(cls, tenant_id: str) -> list:
        """Active doctors in the tenant, for the attending-physician picker."""
        from app.models.user import User
        return (User.query.filter_by(role="Doctor", is_active=True, tenant_id=tenant_id)
                .order_by(User.username.asc()).all())

    @classmethod
    def _resolve_assigned_doctor(cls, assigned_doctor_id: int | None, creator_id: int | None,
                                 tenant_id: str) -> int | None:
        """Validates the chosen attending doctor; a doctor creating a record is assigned by default."""
        from app.models.user import User
        if assigned_doctor_id is None:
            if creator_id is not None:
                creator = db.session.get(User, creator_id)
                if creator and creator.role == "Doctor":
                    return creator.id
            return None
        doctor = db.session.get(User, assigned_doctor_id)
        if not doctor or doctor.role != "Doctor" or not doctor.is_active or doctor.tenant_id != tenant_id:
            raise ValueError("Assigned doctor must be an active Doctor in your organization.")
        return doctor.id

    @classmethod
    def get_patient_by_id(cls, record_id: int, tenant_id: str) -> dict[str, Any] | None:
        """
        Retrieves and decrypts a specific patient record, strictly scoped by tenant_id.
        Raises IntegrityTamperedError if ciphertext or auth tag fails GCM verification.
        """
        from app.repositories.patient_repository import PatientRepository
        patient = PatientRepository.get_by_id(record_id, tenant_id)
        if not patient:
            return None

        try:
            aad = cls._record_aad(patient, tenant_id)
            sensitive_data = CryptoService.decrypt_record(
                ciphertext_hex=patient.encrypted_data,
                nonce_hex=patient.nonce,
                auth_tag_hex=patient.auth_tag,
                key_version=patient.key_version,
                aad=aad
            )
        except IntegrityTamperedError as e:
            # Immediate fail closed (P0-Crypto Context Binding): zero fallback to unauthenticated/no-AAD decryption
            from app.services.alert_service import AlertService
            from app.services.outbox_service import OutboxService
            AlertService.trigger_alert(
                event_type="TAMPER_DETECTED",
                message=f"Cryptographic MAC verification failed on patient record #{patient.id} ({patient.patient_id})",
                metadata={"patient_id": patient.patient_id, "record_id": patient.id, "tenant_id": tenant_id},
                severity="CRITICAL"
            )
            OutboxService.record_event(
                event_type="TAMPER_DETECTED",
                payload={
                    "message": f"Cryptographic MAC verification failed on patient record #{patient.id} ({patient.patient_id})",
                    "patient_id": patient.patient_id,
                    "record_id": patient.id,
                    "tenant_id": tenant_id
                }
            )

            AuditService.log_event(
                action="TAMPER_DETECTED",
                resource_type="PATIENT",
                resource_id=patient.patient_id,
                status="ALERT",
                details=f"Cryptographic MAC verification failed on patient record #{patient.id} ({patient.patient_id})",
                tenant_id=tenant_id
            )
            raise e

        # Audit successful read
        AuditService.log_event(
            action="PATIENT_READ",
            resource_type="PATIENT",
            resource_id=patient.patient_id,
            status="SUCCESS",
            details=f"Decrypted and viewed record {patient.patient_id}",
            tenant_id=tenant_id
        )

        return {
            "id": patient.id,
            "patient_id": patient.patient_id,
            "tenant_id": tenant_id,
            "age_band": patient.age_band,
            "gender": patient.gender,
            "department": getattr(patient, "department", "General"),
            "assigned_doctor_id": getattr(patient, "assigned_doctor_id", None),
            "assigned_doctor_name": patient.assigned_doctor.username if patient.assigned_doctor else None,
            "name": sensitive_data.get("name", ""),
            "diagnosis": sensitive_data.get("diagnosis", ""),
            "medical_history": sensitive_data.get("medical_history", ""),
            "notes": sensitive_data.get("notes", ""),
            "key_version": patient.key_version,
            "version_id": getattr(patient, "version_id", 1),
            "created_at": patient.created_at,
            "updated_at": patient.updated_at,
            "created_by": patient.created_by,
            "created_by_name": patient.creator.username if patient.creator else None,
        }

    @classmethod
    def create_patient(
        cls,
        patient_id: str,
        age_band: str,
        gender: str,
        name: str,
        diagnosis: str,
        medical_history: str,
        notes: str,
        created_by_user_id: int | None = None,
        tenant_id: str = "tenant-default",
        assigned_doctor_id: int | None = None,
        department: str = "General",
    ) -> Patient:
        """
        Encrypts sensitive fields with AES-256-GCM and persists the new patient record via DAO.
        Binds organizational tenant_id into AAD context and records atomic outbox and audit events.
        """
        from app.repositories.patient_repository import PatientRepository
        from app.schemas.patient import PatientCreate

        if not patient_id or not name:
            raise ValueError("Patient ID and Patient Name are required.")

        cls.validate_patient_input(
            patient_id=patient_id,
            name=name,
            diagnosis=diagnosis,
            medical_history=medical_history,
            notes=notes
        )

        # Create DTO
        dto = PatientCreate(
            patient_id=patient_id.strip(),
            name=name.strip(),
            age_band=age_band,
            gender=gender,
            diagnosis=diagnosis.strip(),
            medical_history=medical_history.strip(),
            notes=notes.strip(),
            department=department,
            assigned_doctor_id=assigned_doctor_id
        )

        existing = PatientRepository.get_by_patient_id(dto.patient_id, tenant_id, include_deleted=True)
        if existing:
            if existing.deleted_at is not None:
                raise ValueError(f"Patient ID '{dto.patient_id}' belongs to an archived record and cannot be reused.")
            raise ValueError(f"Patient ID '{dto.patient_id}' already exists.")

        dto.assigned_doctor_id = cls._resolve_assigned_doctor(assigned_doctor_id, created_by_user_id, tenant_id)

        sensitive_payload = {
            "name": dto.name,
            "diagnosis": dto.diagnosis,
            "medical_history": dto.medical_history,
            "notes": dto.notes,
        }

        key_version = CryptoService.get_key_provider().current_version()
        aad = CryptoService.build_record_aad(
            patient_record_id=dto.patient_id,
            tenant_id=tenant_id,
            key_version=key_version,
            record_version=1,
        )
        ciphertext_hex, nonce_hex, auth_tag_hex, key_version = CryptoService.encrypt_record(
            sensitive_payload,
            key_version=key_version,
            aad=aad
        )

        patient = PatientRepository.create(
            dto=dto,
            created_by_user_id=created_by_user_id,
            tenant_id=tenant_id,
            ciphertext=ciphertext_hex,
            nonce=nonce_hex,
            auth_tag=auth_tag_hex,
            key_version=key_version
        )

        from app.services.outbox_service import OutboxService
        OutboxService.record_event(
            event_type="PATIENT_CREATE",
            payload={
                "patient_id": patient.patient_id,
                "tenant_id": patient.tenant_id,
                "created_by": created_by_user_id
            }
        )

        AuditService.log_event(
            action="PATIENT_CREATE",
            resource_type="PATIENT",
            resource_id=patient.patient_id,
            status="SUCCESS",
            user_id=created_by_user_id,
            details=f"Created encrypted patient record {patient.patient_id}",
            auto_commit=False,
            tenant_id=tenant_id
        )

        db.session.commit()
        return patient

    @classmethod
    def update_patient(
        cls,
        record_id: int,
        age_band: str,
        gender: str,
        name: str,
        diagnosis: str,
        medical_history: str,
        notes: str,
        updated_by_user_id: int | None = None,
        expected_version: int | None = None,
        tenant_id: str = "tenant-default"
    ) -> Patient:
        """
        Updates an existing patient record via DAO, encrypting the new payload with a fresh nonce,
        bound AAD context, and executing atomic compare-and-swap Optimistic Concurrency Control (OCC).
        """
        from app.repositories.patient_repository import ConcurrencyConflictError, PatientRepository
        from app.schemas.patient import PatientUpdate

        patient = PatientRepository.get_by_id(record_id, tenant_id)
        if not patient:
            raise ValueError(f"Patient record #{record_id} not found in this tenant.")

        cls.validate_patient_input(
            patient_id=None,
            name=name,
            diagnosis=diagnosis,
            medical_history=medical_history,
            notes=notes
        )

        dto = PatientUpdate(
            name=name.strip(),
            age_band=age_band,
            gender=gender,
            diagnosis=diagnosis.strip(),
            medical_history=medical_history.strip(),
            notes=notes.strip(),
            expected_version=expected_version
        )

        tenant_id = getattr(patient, "tenant_id", "tenant-default") or "tenant-default"

        sensitive_payload = {
            "name": dto.name,
            "diagnosis": dto.diagnosis,
            "medical_history": dto.medical_history,
            "notes": dto.notes,
        }

        # The write is conditioned on base_version and produces base_version + 1, which is bound
        # into the AAD so this ciphertext can never be replayed over a later version of the record.
        base_version = expected_version if expected_version is not None else patient.version_id

        # Encrypt with fresh random nonce and bound AAD context
        key_version = CryptoService.get_key_provider().current_version()
        aad = CryptoService.build_record_aad(
            patient_record_id=patient.patient_id,
            tenant_id=tenant_id,
            key_version=key_version,
            record_version=base_version + 1,
        )
        ciphertext_hex, nonce_hex, auth_tag_hex, key_version = CryptoService.encrypt_record(
            sensitive_payload,
            key_version=key_version,
            aad=aad
        )

        try:
            patient = PatientRepository.update(
                record_id=record_id,
                dto=dto,
                ciphertext=ciphertext_hex,
                nonce=nonce_hex,
                auth_tag=auth_tag_hex,
                key_version=key_version,
                tenant_id=tenant_id,
                base_version=base_version,
            )
        except ConcurrencyConflictError as e:
            # Raise service-level exception
            from app.services.patient_service import ConcurrencyConflictError as SvcConflictError
            raise SvcConflictError(str(e)) from e

        from app.services.outbox_service import OutboxService
        OutboxService.record_event(
            event_type="PATIENT_UPDATE",
            payload={
                "patient_id": patient.patient_id,
                "record_id": patient.id,
                "version_id": patient.version_id,
                "tenant_id": tenant_id,
                "updated_by": updated_by_user_id
            }
        )

        AuditService.log_event(
            action="PATIENT_UPDATE",
            resource_type="PATIENT",
            resource_id=patient.patient_id,
            status="SUCCESS",
            user_id=updated_by_user_id,
            details=f"Updated encrypted patient record {patient.patient_id} (version {patient.version_id})",
            auto_commit=False,
            tenant_id=tenant_id
        )

        db.session.commit()
        return patient

    @classmethod
    def soft_delete_patient(cls, record_id: int, user_id: int | None = None, tenant_id: str = "tenant-default") -> bool:
        """
        Soft-deletes a patient record by setting deleted_at timestamp.
        Preserves encrypted ciphertext for medical records compliance while removing from active clinical views.
        The archive, its outbox event and its audit entry commit atomically.
        """
        from app.repositories.patient_repository import PatientRepository
        from app.services.outbox_service import OutboxService

        patient = PatientRepository.soft_delete(record_id, tenant_id)
        OutboxService.record_event(
            event_type="PATIENT_DELETE",
            payload={"patient_id": patient.patient_id, "record_id": patient.id,
                     "tenant_id": tenant_id, "deleted_by": user_id},
        )
        AuditService.log_event(
            action="PATIENT_DELETE",
            resource_type="PATIENT",
            resource_id=patient.patient_id,
            status="SUCCESS",
            user_id=user_id,
            details=f"Patient record #{record_id} ({patient.patient_id}) soft-deleted by user #{user_id}",
            auto_commit=False,
            tenant_id=tenant_id,
        )
        db.session.commit()
        return True

    @classmethod
    def _get_for_tamper(cls, record_id: int, tenant_id: str | None) -> Patient | None:
        if tenant_id is None:
            return db.session.get(Patient, record_id)
        from app.repositories.patient_repository import PatientRepository
        return PatientRepository.get_by_id(record_id, tenant_id)

    @classmethod
    def tamper_record_ciphertext(cls, record_id: int, tenant_id: str | None = None) -> None:
        """
        Deliberately flips bytes in stored ciphertext to demonstrate tamper detection during tests/viva.
        When tenant_id is given (web route), only records of that tenant can be touched.
        """
        patient = cls._get_for_tamper(record_id, tenant_id)
        if not patient:
            raise ValueError("Patient not found.")
        # Flip characters in ciphertext
        original = patient.encrypted_data
        flipped = ("0" if original[0] != "0" else "1") + original[1:]
        patient.encrypted_data = flipped
        db.session.commit()

    @classmethod
    def tamper_record_tag(cls, record_id: int, tenant_id: str | None = None) -> None:
        """
        Deliberately flips bytes in stored GCM auth tag to demonstrate tamper detection during tests/viva.
        """
        patient = cls._get_for_tamper(record_id, tenant_id)
        if not patient:
            raise ValueError("Patient not found.")
        original = patient.auth_tag
        flipped = ("0" if original[0] != "0" else "1") + original[1:]
        patient.auth_tag = flipped
        db.session.commit()
