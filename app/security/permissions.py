"""Role-Based Access Control (RBAC) Permission Definitions and Matrix."""

# Permission Constants
PATIENT_READ = "PATIENT_READ"
PATIENT_CREATE = "PATIENT_CREATE"
PATIENT_UPDATE = "PATIENT_UPDATE"
PATIENT_DELETE = "PATIENT_DELETE"
USER_MANAGE = "USER_MANAGE"
AUDIT_READ = "AUDIT_READ"

# Role Constants
ROLE_DOCTOR = "Doctor"
ROLE_NURSE = "Nurse"
ROLE_ADMIN = "Admin"

ALL_ROLES = [ROLE_DOCTOR, ROLE_NURSE, ROLE_ADMIN]

# Permission Matrix (Strictly per §5 & §10)
ROLE_PERMISSIONS = {
    ROLE_DOCTOR: {
        PATIENT_READ,
        PATIENT_CREATE,
        PATIENT_UPDATE,
        PATIENT_DELETE,
    },
    ROLE_NURSE: {
        PATIENT_READ,
        PATIENT_CREATE,
    },
    ROLE_ADMIN: {
        PATIENT_READ,
        USER_MANAGE,
        AUDIT_READ,
    },
}

def has_permission(role: str, permission: str) -> bool:
    """Check if a given role possesses the specified permission."""
    if not role or role not in ROLE_PERMISSIONS:
        return False
    return permission in ROLE_PERMISSIONS[role]
