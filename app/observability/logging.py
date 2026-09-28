"""
Structured JSON Logging & Automated PHI Redaction Filter (Phase 6).
Ensures zero accidental leakage of Protected Health Information (PHI)
or cryptographic secrets into stdout, files, or SIEM log pipelines.
"""
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

from flask import g, has_request_context, session

# Sensitive key names whose values must always be sanitized
SENSITIVE_KEYS = {
    "password", "secret", "token", "auth_tag", "nonce",
    "master_key", "key_registry", "medical_history", "diagnosis",
    "notes", "payload", "encrypted_data", "cipher"
}

# Regex patterns matching credit card PANs, SSNs, Aadhaar-like 12-digit IDs
SENSITIVE_PATTERNS = [
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),  # Credit card / PAN
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),     # SSN
    re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),  # Aadhaar 12-digit
]


class PHIRedactionFilter(logging.Filter):
    """
    Log filter that intercepts log records and scrubs any inadvertent
    PHI, medical text, passwords, or tokens from message strings and metadata dictionaries.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.scrub_text(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = self.scrub_dict(record.args)
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(
                    self.scrub_text(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )

        # Scrub any extra dict attributes attached to the LogRecord
        for attr in ("extra", "alert", "metadata"):
            val = getattr(record, attr, None)
            if isinstance(val, dict):
                setattr(record, attr, self.scrub_dict(val))

        return True

    @classmethod
    def scrub_text(cls, text: str) -> str:
        """Applies pattern-based regex redaction to strings."""
        if not text:
            return text
        scrubbed = text
        for pattern in SENSITIVE_PATTERNS:
            scrubbed = pattern.sub("[REDACTED_SENSITIVE]", scrubbed)
        return scrubbed

    @classmethod
    def scrub_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively redacts sensitive dictionary keys."""
        cleaned = {}
        for k, v in data.items():
            if any(sens in k.lower() for sens in SENSITIVE_KEYS):
                cleaned[k] = "[REDACTED_PHI]"
            elif isinstance(v, dict):
                cleaned[k] = cls.scrub_dict(v)
            elif isinstance(v, str):
                cleaned[k] = cls.scrub_text(v)
            else:
                cleaned[k] = v
        return cleaned


class StructuredJsonFormatter(logging.Formatter):
    """
    High-assurance JSON log formatter formatting records for ingestion by
    Elasticsearch, Splunk, Datadog, or Grafana Loki.
    Automatically enriches events with request ID correlation and actor identity.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "process": record.process,
            "thread": record.threadName,
        }

        # Enrich with Flask request correlation context when in active request
        if has_request_context():
            log_entry["request_id"] = getattr(g, "request_id", None)
            log_entry["user_id"] = session.get("user_id")
            log_entry["username"] = session.get("username")
            log_entry["role"] = session.get("role")

        # Include structured alert or extra fields
        if hasattr(record, "alert"):
            log_entry["alert"] = record.alert
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            log_entry.update(record.extra)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def configure_observability(app):
    """Initializes structured logging and registers PHI redaction filter across handlers."""
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    handler.addFilter(PHIRedactionFilter())

    root_logger = logging.getLogger()
    # Avoid duplicate handlers during testing re-initialization
    if not any(isinstance(h, logging.StreamHandler) and isinstance(h.formatter, StructuredJsonFormatter) for h in root_logger.handlers):
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.INFO)
