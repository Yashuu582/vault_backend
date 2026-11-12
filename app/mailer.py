"""Outgoing email. Without SMTP configured, development builds log the message instead."""

import logging
import smtplib
from email.message import EmailMessage

from .config import get_settings

log = logging.getLogger("balancevault.mail")


def send_password_reset(to_email: str, full_name: str, link: str, ttl_minutes: int) -> None:
    settings = get_settings()

    if not settings.smtp_host:
        if settings.environment == "production":
            log.error("SMTP is not configured - cannot send the password reset email to %s", to_email)
        else:
            log.warning("SMTP not configured (dev) - password reset link for %s: %s", to_email, link)
        return

    msg = EmailMessage()
    msg["Subject"] = "Reset your BalanceVault password"
    msg["From"] = settings.smtp_from
    msg["To"] = to_email
    msg.set_content(
        f"Hi {full_name},\n\n"
        f"We received a request to reset your BalanceVault password.\n"
        f"Open this link to choose a new password (valid for {ttl_minutes} minutes):\n\n"
        f"{link}\n\n"
        "If you did not request this, you can ignore this email. Your password will not change.\n"
    )
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password or "")
            smtp.send_message(msg)
        log.info("Password reset email sent to %s", to_email)
    except Exception:
        log.exception("Failed to send the password reset email to %s", to_email)
