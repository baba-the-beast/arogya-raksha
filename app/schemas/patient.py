import re

from pydantic import BaseModel, Field, field_validator


class PatientBase(BaseModel):
    age_band: str = Field(..., max_length=20)
    gender: str = Field(..., max_length=20)
    name: str = Field(..., min_length=1, max_length=128)
    diagnosis: str = Field(..., max_length=10240)
    medical_history: str = Field(..., max_length=10240)
    notes: str = Field(..., max_length=10240)
    department: str = Field("General", max_length=50)

    @field_validator("name", "diagnosis", "medical_history", "notes", mode="before")
    def strip_whitespace(cls, v):
        if isinstance(v, str):
            return v.strip()
        return v

class PatientCreate(PatientBase):
    patient_id: str = Field(..., min_length=1, max_length=64)
    assigned_doctor_id: int | None = None

    @field_validator("patient_id")
    def validate_patient_id(cls, v):
        v = v.strip()
        if not re.match(r"^[A-Za-z0-9_-]+$", v):
            raise ValueError("Patient ID must contain only alphanumeric characters, underscores, or hyphens.")
        return v

class PatientUpdate(PatientBase):
    expected_version: int | None = None
