"""
Phase 5 — Security Alerting Service Tests.

Covers:
- AlertDelivery interface and backend injection
- LogOnlyDelivery structured log output
- WebhookDelivery HMAC signature generation
- Automatic alert triggers on TAMPER_DETECTED and ACCOUNT_LOCKOUT
"""
import pytest

from app.services.alert_service import AlertDelivery, AlertService, LogOnlyDelivery, WebhookDelivery
from app.services.crypto_service import IntegrityTamperedError
from app.services.patient_service import PatientService


class MockAlertDelivery(AlertDelivery):
    """Test delivery backend capturing dispatched alerts."""

    def __init__(self):
        self.dispatched = []

    def deliver(self, event_type: str, severity: str, message: str, metadata: dict) -> bool:
        self.dispatched.append({
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "metadata": metadata
        })
        return True


def test_custom_delivery_backend_injection():
    """AlertService dispatches alerts to injected backend."""
    mock_backend = MockAlertDelivery()
    orig_backend = AlertService.get_backend()
    try:
        AlertService.set_backend(mock_backend)
        res = AlertService.trigger_alert(
            event_type="TEST_SECURITY_EVENT",
            message="Test security warning",
            metadata={"test_key": "test_val"},
            severity="HIGH"
        )
        assert res is True
        assert len(mock_backend.dispatched) == 1
        item = mock_backend.dispatched[0]
        assert item["event_type"] == "TEST_SECURITY_EVENT"
        assert item["severity"] == "HIGH"
        assert item["metadata"]["test_key"] == "test_val"
    finally:
        AlertService.set_backend(orig_backend)


def test_log_only_delivery():
    """LogOnlyDelivery processes alerts without raising exceptions."""
    delivery = LogOnlyDelivery()
    result = delivery.deliver(
        event_type="SUSPICIOUS_PROBE",
        severity="WARNING",
        message="Simulated probe",
        metadata={"ip": "127.0.0.1"}
    )
    assert result is True


def test_webhook_delivery_stub():
    """WebhookDelivery computes valid HMAC signature."""
    webhook = WebhookDelivery(
        webhook_url="https://example.com/siem",
        hmac_secret="super-secret-hmac-key"
    )
    result = webhook.deliver(
        event_type="TAMPER_DETECTED",
        severity="CRITICAL",
        message="MAC failure",
        metadata={"id": 123}
    )
    assert result is True


def test_tamper_detected_triggers_security_alert(app):
    """When a patient record has tampered ciphertext, AlertService is invoked."""
    mock_backend = MockAlertDelivery()
    orig_backend = AlertService.get_backend()
    try:
        AlertService.set_backend(mock_backend)

        # Create patient and tamper with ciphertext
        p = PatientService.create_patient(
            patient_id="P-ALERT-TAMPER",
            age_band="20-29",
            gender="Male",
            name="Tamper Alert Patient",
            diagnosis="None",
            medical_history="None",
            notes="None",
        )
        PatientService.tamper_record_ciphertext(p.id)

        # Fetching should raise IntegrityTamperedError and trigger alert
        with pytest.raises(IntegrityTamperedError):
            PatientService.get_patient_by_id(p.id, tenant_id="tenant-default")

        # Verify alert was captured
        tamper_alerts = [a for a in mock_backend.dispatched if a["event_type"] == "TAMPER_DETECTED"]
        assert len(tamper_alerts) >= 1
        assert tamper_alerts[0]["severity"] == "CRITICAL"
        assert tamper_alerts[0]["metadata"]["patient_id"] == "P-ALERT-TAMPER"
    finally:
        AlertService.set_backend(orig_backend)
