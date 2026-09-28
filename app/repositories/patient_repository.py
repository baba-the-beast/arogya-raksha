from datetime import UTC, datetime

from app.extensions import db
from app.models.patient import Patient
from app.schemas.patient import PatientCreate, PatientUpdate


class ConcurrencyConflictError(ValueError):
    """Raised when an update conflicts with a concurrent update (OCC failure)."""
    pass

class PatientRepository:
    """Data Access Object (DAO) for Patient records, isolating SQLAlchemy operations."""

    @staticmethod
    def get_by_id(record_id: int, tenant_id: str) -> Patient | None:
        patient = db.session.get(Patient, record_id)
        if patient and patient.deleted_at is None and patient.tenant_id == tenant_id:
            return patient
        return None

    @staticmethod
    def get_by_patient_id(patient_id: str, tenant_id: str, include_deleted: bool = False) -> Patient | None:
        query = Patient.query.filter_by(patient_id=patient_id, tenant_id=tenant_id)
        if not include_deleted:
            query = query.filter(Patient.deleted_at.is_(None))
        return query.first()

    @staticmethod
    def create(
        dto: PatientCreate,
        created_by_user_id: int | None,
        tenant_id: str,
        ciphertext: str,
        nonce: str,
        auth_tag: str,
        key_version: int
    ) -> Patient:
        patient = Patient(
            patient_id=dto.patient_id,
            tenant_id=tenant_id,
            age_band=dto.age_band,
            gender=dto.gender,
            department=dto.department,
            assigned_doctor_id=dto.assigned_doctor_id,
            encrypted_data=ciphertext,
            nonce=nonce,
            auth_tag=auth_tag,
            key_version=key_version,
            version_id=1,
            crypto_schema=2,
            created_by=created_by_user_id
        )
        db.session.add(patient)
        db.session.flush()
        return patient

    @staticmethod
    def update(
        record_id: int,
        dto: PatientUpdate,
        ciphertext: str,
        nonce: str,
        auth_tag: str,
        key_version: int,
        tenant_id: str,
        base_version: int,
    ) -> Patient:
        """
        Atomic compare-and-swap update. Always conditioned on base_version (the version the
        caller read, or the client's expected_version) so concurrent writers can never silently
        overwrite each other, and the new version (base_version + 1) matches the one bound into
        the ciphertext's AAD.
        """
        patient = PatientRepository.get_by_id(record_id, tenant_id)
        if not patient:
            raise ValueError(f"Patient record #{record_id} not found in this tenant.")

        now_utc = datetime.now(UTC)
        current_version = patient.version_id

        stmt = (
            db.update(Patient)
            .where(Patient.id == record_id)
            .where(Patient.tenant_id == tenant_id)
            .where(Patient.version_id == base_version)
            .values(
                age_band=dto.age_band,
                gender=dto.gender,
                encrypted_data=ciphertext,
                nonce=nonce,
                auth_tag=auth_tag,
                key_version=key_version,
                crypto_schema=2,
                version_id=base_version + 1,
                updated_at=now_utc,
            )
        )

        result = db.session.execute(stmt)
        if result.rowcount == 0:
            db.session.rollback()
            raise ConcurrencyConflictError(
                f"Concurrency conflict: Patient record #{record_id} was modified by another clinician "
                f"(expected version {base_version}, current {current_version}). "
                "Please reload the record and re-apply changes."
            )

        db.session.expire(patient)
        return db.session.get(Patient, record_id)

    @staticmethod
    def soft_delete(record_id: int, tenant_id: str) -> Patient:
        patient = PatientRepository.get_by_id(record_id, tenant_id)
        if not patient:
            raise ValueError(f"Patient record #{record_id} not found in this tenant.")

        patient.deleted_at = datetime.now(UTC)
        return patient
