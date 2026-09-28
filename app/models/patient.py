from datetime import UTC, datetime

from sqlalchemy import Index

from app.extensions import db


class Patient(db.Model):
    """
    Patient record model storing sensitive health fields encrypted at rest using AES-256-GCM.
    Clear fields (patient_id, age_band, gender) support listing/demographics without exposing PHI.
    """
    __tablename__ = "patients"
    __table_args__ = (
        Index("ix_patients_deleted_created", "deleted_at", "created_at"),
        Index("ix_patients_age_band", "age_band"),
        Index("ix_patients_gender", "gender"),
        # Patient IDs / MRNs are unique per tenant, not globally: two hospitals may reuse an MRN
        Index("uq_patients_tenant_patient_id", "tenant_id", "patient_id", unique=True),
    )

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(32), db.ForeignKey("tenants.id"), default="tenant-default", nullable=False, index=True)
    patient_id = db.Column(db.String(64), nullable=False, index=True)
    age_band = db.Column(db.String(20), nullable=True)  # e.g. "20-29", "40-49"
    gender = db.Column(db.String(20), nullable=True)    # e.g. "Female", "Male", "Other"
    department = db.Column(db.String(50), default="General", nullable=True)

    # AES-256-GCM Cryptographic fields (Stored as hex strings for universal DB portability)
    encrypted_data = db.Column(db.Text, nullable=False)  # Hex ciphertext of JSON payload
    nonce = db.Column(db.String(64), nullable=False)     # Hex of 12-byte random IV/nonce
    auth_tag = db.Column(db.String(64), nullable=False)  # Hex of 16-byte GCM authentication tag
    key_version = db.Column(db.Integer, default=1, nullable=False)
    # AAD layout: 1 = legacy (patient/tenant/key bound), 2 = also bound to version_id (anti-replay)
    crypto_schema = db.Column(db.Integer, default=2, nullable=False, server_default="1")
    # Optimistic Concurrency Control (OCC - P0-8)
    version_id = db.Column(db.Integer, default=1, nullable=False)

    # Metadata & Tracking
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    assigned_doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    # Soft delete timestamp (Phase 5)
    deleted_at = db.Column(db.DateTime, nullable=True, index=True)

    # Relationships
    creator = db.relationship("User", foreign_keys=[created_by], backref="created_patients")
    assigned_doctor = db.relationship("User", foreign_keys=[assigned_doctor_id], backref="assigned_patients")

    def __repr__(self):
        return f"<Patient {self.patient_id} ({self.tenant_id})>"

