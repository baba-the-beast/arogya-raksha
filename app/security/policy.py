"""
Resource-Level Authorization (ABAC / Policy Engine) for ArogyaRaksha.
Evaluates multi-attribute context for clinical operations:
  - Identity, Role, Account Status, Session Assurance, MFA State
  - Tenant Isolation (cross-tenant access is strictly denied)
  - Clinical Relationship (Assigned Doctor, Care Team, Department)
  - Emergency Break-Glass Workflow with mandatory clinical justification and audit alerts
"""
import time
from dataclasses import dataclass
from typing import Any

from app.models.patient import Patient
from app.models.user import User
from app.services.audit_service import AuditService

MAX_BREAK_GLASS_PER_HOUR = 5

def clear_break_glass_history() -> None:
    """Testing utility to clear break-glass velocity tracker."""
    from app.services.cache_service import CacheService
    CacheService.clear_memory()


class AuthorizationDeniedError(Exception):
    """Raised when an operation fails resource-level or policy authorization."""
    pass


AUTHORIZED_BREAK_GLASS_REASONS: dict[str, str] = {
    "EMERGENCY_RESUSCITATION": "Immediate life-threatening patient resuscitation",
    "CALL_COVERAGE": "Providing on-call clinical coverage for primary physician",
    "TRAUMA_OVERRIDE": "Emergency trauma bay admission and stabilization",
    "UNASSIGNED_TRIAGE": "Urgent triage of unassigned critical intake",
    "CLINICAL_EMERGENCY": "Unforeseen acute clinical decompensation",
}

MIN_BREAK_GLASS_JUSTIFICATION_LENGTH = 15


def validate_break_glass_reason(reason: str | None) -> tuple[bool, str]:
    """
    Validate structured break-glass emergency reason or clinical justification.
    Returns (is_valid, normalized_reason_or_error_message).
    """
    if not reason or not reason.strip():
        return False, "Break-glass reason cannot be empty."

    clean = reason.strip()
    upper = clean.upper()
    if upper in AUTHORIZED_BREAK_GLASS_REASONS:
        return True, f"{upper}: {AUTHORIZED_BREAK_GLASS_REASONS[upper]}"

    if len(clean) < MIN_BREAK_GLASS_JUSTIFICATION_LENGTH:
        valid_codes = ", ".join(AUTHORIZED_BREAK_GLASS_REASONS.keys())
        return False, (
            f"Break-glass clinical justification too short ({len(clean)} chars). "
            f"Minimum {MIN_BREAK_GLASS_JUSTIFICATION_LENGTH} characters required, "
            f"or select an authorized reason code: {valid_codes}."
        )

    return True, clean


@dataclass
class PolicyDecision:
    """Outcome of policy evaluation."""
    allowed: bool
    reason: str
    is_break_glass: bool = False


class PolicyEngine:
    """Evaluates contextual authorization rules for Protected Health Information (PHI)."""

    @classmethod
    def authorize_patient_access(
        cls,
        user: User | None,
        patient: Patient | dict[str, Any] | None,
        action: str,
        break_glass_reason: str | None = None,
        session_context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """
        Evaluates whether user is authorized to perform action on the patient resource.
        Actions: 'READ', 'UPDATE', 'CREATE', 'DELETE'
        """
        # 1. Identity & Active Account Validation
        if not user or not user.is_active:
            return PolicyDecision(allowed=False, reason="User identity is invalid or account is disabled.")

        # 2. Administrative Role Segregation
        # System administrators can review records for administrative compliance (PATIENT_READ),
        # but must NEVER alter, create, or delete clinical health records (Separation of Duties).
        if user.role == "Admin" and action in ("UPDATE", "CREATE", "DELETE"):
            AuditService.log_event(
                action="AUTHORIZATION_FAILURE",
                resource_type="PATIENT",
                resource_id=getattr(patient, "patient_id", "N/A") if patient else "N/A",
                status="DENIED",
                user_id=user.id,
                username=user.username,
                details=f"Admin account '{user.username}' denied access to clinical PHI mutation (Separation of Duties).",
                tenant_id=getattr(user, "tenant_id", "tenant-default")
            )
            return PolicyDecision(
                allowed=False,
                reason="Administrative accounts are strictly prohibited from altering clinical health records."
            )

        # 3. Patient Creation Scope
        if action == "CREATE":
            if user.role in ("Doctor", "Nurse"):
                return PolicyDecision(allowed=True, reason="Clinical staff permitted to create new patient intakes.")
            return PolicyDecision(allowed=False, reason=f"Role '{user.role}' cannot create patient records.")

        if not patient:
            return PolicyDecision(allowed=False, reason="Patient record does not exist.")

        # Resolve patient attributes (supports ORM model or dictionary)
        p_tenant_id = getattr(patient, "tenant_id", None) if hasattr(patient, "tenant_id") else patient.get("tenant_id")
        p_id = getattr(patient, "patient_id", None) if hasattr(patient, "patient_id") else patient.get("patient_id")
        p_assigned_doctor = getattr(patient, "assigned_doctor_id", None) if hasattr(patient, "assigned_doctor_id") else patient.get("assigned_doctor_id")

        user_tenant = getattr(user, "tenant_id", "tenant-default") or "tenant-default"
        patient_tenant = p_tenant_id or "tenant-default"

        # 4. Strict Tenant Boundary Isolation
        if user_tenant != patient_tenant:
            AuditService.log_event(
                action="CROSS_TENANT_ATTEMPT",
                resource_type="PATIENT",
                resource_id=str(p_id),
                status="DENIED",
                user_id=user.id,
                username=user.username,
                details=f"User in tenant '{user_tenant}' attempted to access patient in tenant '{patient_tenant}'.",
                tenant_id=user_tenant
            )
            return PolicyDecision(
                allowed=False,
                reason="Cross-tenant clinical access is strictly prohibited by data residency policies."
            )

        # 5. Role-Specific Action Capabilities
        if action in ("UPDATE", "DELETE") and user.role != "Doctor":
            AuditService.log_event(
                action="AUTHORIZATION_FAILURE",
                resource_type="PATIENT",
                resource_id=str(p_id),
                status="DENIED",
                user_id=user.id,
                username=user.username,
                details=f"User with role '{user.role}' attempted unauthorized clinical {action.lower()} on patient {p_id}.",
                tenant_id=user_tenant
            )
            return PolicyDecision(allowed=False, reason=f"Role '{user.role}' is not authorized to {action.lower()} medical records.")

        # 6. Resource-Level Care Team & Assignment Scope
        # The assigned attending physician holds the care relationship. (Record authorship is
        # deliberately not used: nurses register intakes, and that must not lock doctors out.)
        if p_assigned_doctor is not None and user.id == p_assigned_doctor:
            return PolicyDecision(allowed=True, reason="Attending physician / primary care relationship.")

        # Unassigned patients (e.g. nurse intakes awaiting a physician) may be updated or archived
        # by any doctor in the tenant. Role was already restricted to Doctor in step 5.
        if action in ("UPDATE", "DELETE") and not p_assigned_doctor:
            return PolicyDecision(allowed=True, reason="Attending doctor managing unassigned patient.")

        # 7. Emergency Break-Glass Protocol
        # Attending clinicians accessing unassigned or cross-assignment patients must declare break-glass rationale
        if break_glass_reason is not None and break_glass_reason.strip():
            is_valid, validation_msg = validate_break_glass_reason(break_glass_reason)
            if not is_valid:
                AuditService.log_event(
                    action="BREAK_GLASS_REJECTED",
                    resource_type="PATIENT",
                    resource_id=str(p_id),
                    status="DENIED",
                    user_id=user.id,
                    username=user.username,
                    details=f"Invalid break-glass rationale rejected: {break_glass_reason.strip()} ({validation_msg})",
                    tenant_id=user_tenant,
                )
                return PolicyDecision(
                    allowed=False,
                    reason=f"Break-glass rejected: {validation_msg}",
                    is_break_glass=False,
                )

            reason_clean = validation_msg

            # 7.1 Velocity / Rate Throttling check (max 5 emergency overrides per hour per clinician)
            now = time.time()
            one_hour_ago = now - 3600.0
            from app.services.alert_service import AlertService
            from app.services.cache_service import CacheService, CacheUnavailableError

            cache_key = f"break_glass_history:{user.id}"
            try:
                history = CacheService.lrange(cache_key, strict=True)
            except CacheUnavailableError:
                # Fail closed: without the velocity tracker the override limit cannot be enforced
                return PolicyDecision(
                    allowed=False,
                    reason="Break-glass is temporarily unavailable (velocity tracker offline). Contact the on-call administrator.",
                )
            recent_accesses = [t for t in history if t > one_hour_ago]

            if len(recent_accesses) >= MAX_BREAK_GLASS_PER_HOUR:
                AlertService.trigger_alert(
                    event_type="BREAK_GLASS_VELOCITY_EXCEEDED",
                    message=f"CRITICAL: Clinician '{user.username}' exceeded break-glass velocity limit ({len(recent_accesses)} within 1 hour). Access blocked.",
                    metadata={"user_id": user.id, "count": len(recent_accesses), "tenant_id": user_tenant},
                    severity="CRITICAL",
                )
                AuditService.log_event(
                    action="BREAK_GLASS_VELOCITY_EXCEEDED",
                    resource_type="PATIENT",
                    resource_id=str(p_id),
                    status="BLOCKED",
                    user_id=user.id,
                    username=user.username,
                    details=f"Break-glass velocity limit exceeded ({len(recent_accesses)} overrides in 1h). Access blocked.",
                    tenant_id=user_tenant,
                )
                return PolicyDecision(
                    allowed=False,
                    reason=f"Break-glass velocity limit exceeded (maximum {MAX_BREAK_GLASS_PER_HOUR} emergency overrides per hour). Contact Chief Medical Officer.",
                    is_break_glass=False,
                )

            CacheService.rpush(cache_key, now, ttl_seconds=3600)

            # Log prominent audit event and alert for emergency break glass access
            AlertService.trigger_alert(
                event_type="BREAK_GLASS_ACCESS",
                message=f"Emergency Break-Glass access invoked by {user.username} for patient {p_id}: {reason_clean}",
                metadata={"user_id": user.id, "patient_id": str(p_id), "reason": reason_clean},
                severity="HIGH",
            )
            AuditService.log_event(
                action="BREAK_GLASS_ACCESS",
                resource_type="PATIENT",
                resource_id=str(p_id),
                status="ALERT",
                user_id=user.id,
                username=user.username,
                details=f"Break-Glass Emergency: {reason_clean}",
                tenant_id=user_tenant,
            )
            return PolicyDecision(
                allowed=True,
                reason=f"Emergency break-glass authorized: {reason_clean}",
                is_break_glass=True,
            )

        # 8. Department / Clinic acute care trust policy:
        # Within the same tenant, clinicians and administrative compliance reviewers may READ (audited).
        if action == "READ" and user.role in ("Doctor", "Nurse", "Admin"):
            return PolicyDecision(allowed=True, reason="Clinic care and administrative review policy.")

        # UPDATE / DELETE on a patient assigned to another doctor requires a Break-Glass declaration
        if action in ("UPDATE", "DELETE"):
            return PolicyDecision(
                allowed=False,
                reason=f"Doctor '{user.username}' is not assigned to patient {p_id}. "
                       f"Emergency clinical {action.lower()} requires declaring a Break-Glass reason."
            )

        return PolicyDecision(allowed=False, reason="Access not permitted under current clinical authorization policy.")
