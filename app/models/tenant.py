"""
Tenant Model for Enterprise Multi-Tenancy.
Provides strict organizational and clinical data isolation.
"""
from datetime import UTC, datetime

from app.extensions import db


class Tenant(db.Model):
    """
    Tenant entity representing an isolated healthcare organization, hospital, or clinic.
    """
    __tablename__ = "tenants"

    id = db.Column(db.String(32), primary_key=True)  # e.g. "tenant-default", "tenant-alpha"
    name = db.Column(db.String(128), nullable=False)
    code = db.Column(db.String(32), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)

    # Relationships
    users = db.relationship("User", backref="tenant", lazy="dynamic")
    patients = db.relationship("Patient", backref="tenant", lazy="dynamic")

    def __repr__(self):
        return f"<Tenant {self.id}: {self.name}>"

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "code": self.code,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
        }
