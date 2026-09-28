"""
Out-of-band notification delivery (password reset links).

Delivery channels:
  - SMTP relay when SMTP_HOST is configured and the user has an email address.
  - Development console fallback (non-production only): the link is written to the
    application log so local testers can complete the reset flow.
In production without a working channel, delivery fails so the outbox retries and
eventually dead-letters the event instead of silently dropping it.
"""
import logging
import os
import smtplib
from email.message import EmailMessage

from flask import current_app

logger = logging.getLogger("notification.service")


def _is_production() -> bool:
    return (os.getenv("FLASK_ENV", "").lower() == "production"
            or str(current_app.config.get("ENV", "")).lower() == "production")


class NotificationService:
    """Sends account notifications through the configured channel."""

    @classmethod
    def send_password_reset(cls, username: str, email: str | None, reset_url: str) -> bool:
        cfg = current_app.config
        if cfg.get("SMTP_HOST") and email:
            msg = EmailMessage()
            msg["Subject"] = "ArogyaRaksha password reset"
            msg["From"] = cfg.get("MAIL_FROM")
            msg["To"] = email
            msg.set_content(
                f"Hello {username},\n\n"
                f"A password reset was requested for your account. Use this link within 15 minutes:\n\n"
                f"{reset_url}\n\n"
                "If you did not request this, contact your administrator.\n"
            )
            try:
                with smtplib.SMTP(cfg["SMTP_HOST"], cfg.get("SMTP_PORT", 587), timeout=10) as smtp:
                    if cfg.get("SMTP_USE_TLS", True):
                        smtp.starttls()
                    if cfg.get("SMTP_USERNAME"):
                        smtp.login(cfg["SMTP_USERNAME"], cfg.get("SMTP_PASSWORD") or "")
                    smtp.send_message(msg)
                logger.info("Password reset email sent for user '%s'", username)
                return True
            except (OSError, smtplib.SMTPException) as e:
                logger.error("Password reset email delivery failed for user '%s': %s", username, e)
                return False

        if not _is_production():
            logger.warning("DEV ONLY - password reset link for '%s': %s", username, reset_url)
            return True

        logger.error(
            "No delivery channel for password reset of user '%s' (SMTP_HOST %s, email %s)",
            username, "set" if cfg.get("SMTP_HOST") else "unset", "set" if email else "missing",
        )
        return False
