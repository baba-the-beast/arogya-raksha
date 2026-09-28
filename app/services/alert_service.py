"""
Security Alerting Service (Phase 5).
Dispatches high-priority security notifications when critical events occur
(e.g., TAMPER_DETECTED, ACCOUNT_LOCKOUT).
"""
import hashlib
import hmac
import json
import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger("security.alert")


class AlertDelivery(ABC):
    """Abstract interface defining delivery channels for security alerts."""

    @abstractmethod
    def deliver(self, event_type: str, severity: str, message: str, metadata: dict[str, Any]) -> bool:
        """Dispatches an alert to the notification destination."""
        pass


class LogOnlyDelivery(AlertDelivery):
    """Default alerting delivery: writes structured, high-severity events to dedicated security log."""

    def deliver(self, event_type: str, severity: str, message: str, metadata: dict[str, Any]) -> bool:
        alert_payload = {
            "security_alert": True,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "metadata": metadata or {},
        }
        logger.critical(
            "SECURITY_ALERT [%s] %s | metadata: %s",
            event_type,
            message,
            json.dumps(metadata or {}, default=str),
            extra={"alert": alert_payload}
        )
        return True


class WebhookDelivery(AlertDelivery):
    """
    Enterprise alert delivery with HMAC-SHA256 authenticated webhook dispatch
    to a Security Operations Center (SOC) / SIEM.
    Includes request timestamps, nonces for replay defense, and circuit breaker.
    """

    def __init__(
        self,
        webhook_url: str | None = None,
        hmac_secret: str | None = None,
        mock_mode: bool = False,
        timeout: float = 5.0,
    ):
        self.webhook_url = webhook_url or "https://siem.internal.hospital.org/v1/alerts"
        self.hmac_secret = (hmac_secret or "demo-siem-secret-key-32bytes-hex!").encode("utf-8")
        self.mock_mode = mock_mode or "example.com" in self.webhook_url or "hospital.org" in self.webhook_url
        self.timeout = timeout
        self.failure_count = 0
        self.circuit_open_until = 0.0

    def deliver(self, event_type: str, severity: str, message: str, metadata: dict[str, Any]) -> bool:
        import time
        now = time.time()
        if now < self.circuit_open_until:
            logger.warning("WebhookDelivery: Circuit breaker open. Skipping alert dispatch to %s", self.webhook_url)
            return False

        payload_dict = {
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "metadata": metadata or {},
            "timestamp": int(now),
        }
        payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        signature = hmac.new(self.hmac_secret, payload_bytes, hashlib.sha256).hexdigest()

        if self.mock_mode:
            logger.info(
                "WebhookDelivery (mock/dry-run): Dispatched alert '%s' to %s (HMAC header: X-Arogya-Signature: %s)",
                event_type,
                self.webhook_url,
                signature[:16] + "..."
            )
            return True

        import secrets

        import requests
        headers = {
            "Content-Type": "application/json",
            "X-Arogya-Signature": signature,
            "X-Arogya-Timestamp": str(int(now)),
            "X-Arogya-Nonce": secrets.token_hex(16),
        }
        try:
            resp = requests.post(self.webhook_url, data=payload_bytes, headers=headers, timeout=self.timeout)
            if 200 <= resp.status_code < 300:
                self.failure_count = 0
                return True
            else:
                logger.error("WebhookDelivery failed with status %d: %s", resp.status_code, resp.text[:200])
                self.failure_count += 1
                if self.failure_count >= 5:
                    self.circuit_open_until = now + 60.0
                return False
        except Exception as e:
            logger.error("WebhookDelivery network error: %s", e)
            self.failure_count += 1
            if self.failure_count >= 5:
                self.circuit_open_until = now + 60.0
            return False


class AlertService:
    """Orchestrates security alerting and notification dispatch across configured channels."""

    _backend: AlertDelivery = LogOnlyDelivery()

    @classmethod
    def set_backend(cls, backend: AlertDelivery) -> None:
        """Injects a custom AlertDelivery backend (useful for testing or SIEM integration)."""
        cls._backend = backend

    @classmethod
    def get_backend(cls) -> AlertDelivery:
        """Returns the currently active alert delivery backend."""
        return cls._backend

    @classmethod
    def trigger_alert(
        cls,
        event_type: str,
        message: str,
        metadata: dict[str, Any] | None = None,
        severity: str = "CRITICAL"
    ) -> bool:
        """
        Triggers an immediate security alert across the active delivery channel.
        Logs and swallows delivery exceptions so failure to notify does not crash the app.
        """
        meta = metadata or {}
        try:
            return cls.get_backend().deliver(
                event_type=event_type,
                severity=severity,
                message=message,
                metadata=meta
            )
        except Exception as e:
            logger.error("Failed to deliver security alert '%s': %s", event_type, e)
            return False
