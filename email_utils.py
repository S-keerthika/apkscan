"""
email_utils.py — sends the account-verification email via plain SMTP.

Works with any SMTP provider: Gmail (with an App Password), SendGrid/
Mailgun/Resend's SMTP relay, or the mailbox that comes with your GoDaddy/
Hostinger domain (e.g. smtp.hostinger.com, smtpout.secureserver.net).
No extra dependency — smtplib is in the Python standard library.
"""
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import streamlit as st


def _secret(key: str, default: str = "") -> str:
    try:
        return st.secrets.get(key, os.getenv(key, default))
    except Exception:
        return os.getenv(key, default)


def _smtp_config():
    return {
        "host": _secret("SMTP_HOST"),
        "port": int(_secret("SMTP_PORT", "587")),
        "user": _secret("SMTP_USER"),
        "password": _secret("SMTP_PASSWORD"),
        "from_email": _secret("FROM_EMAIL") or _secret("SMTP_USER"),
        "from_name": _secret("FROM_NAME", "APK Scanner Pro"),
        "app_base_url": _secret("APP_BASE_URL", "http://localhost:8501"),
    }


def build_verification_link(token: str) -> str:
    cfg = _smtp_config()
    base = cfg["app_base_url"].rstrip("/")
    return f"{base}/?verify={token}"


def send_verification_email(to_email: str, token: str) -> bool:
    """Returns True if the email was handed off to the SMTP server OK."""
    cfg = _smtp_config()
    if not cfg["host"] or not cfg["user"] or not cfg["password"]:
        st.error(
            "Email isn't configured yet (missing SMTP_HOST/SMTP_USER/SMTP_PASSWORD "
            "in .streamlit/secrets.toml) — the account was created, but no "
            "verification email could be sent. Add SMTP settings, or ask an admin "
            "to verify this account manually."
        )
        return False

    link = build_verification_link(token)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Activate your APK Scanner Pro account"
    msg["From"] = f"{cfg['from_name']} <{cfg['from_email']}>"
    msg["To"] = to_email

    text_body = (
        f"Welcome to APK Scanner Pro!\n\n"
        f"Confirm your email to activate your account:\n{link}\n\n"
        f"If you didn't create this account, you can ignore this email."
    )
    html_body = f"""
    <div style="font-family: 'Inter', Arial, sans-serif; max-width: 480px; margin: auto;">
      <div style="background: linear-gradient(135deg, #1E3A8A, #2563EB, #38BDF8);
                  border-radius: 14px; padding: 28px; text-align: center; color: white;">
        <h1 style="margin: 0; font-size: 22px;">🛡️ APK Scanner Pro</h1>
        <p style="margin: 6px 0 0; color: #DBEAFE; font-size: 14px;">Confirm your email to get started</p>
      </div>
      <div style="padding: 28px 8px;">
        <p style="color:#0F172A;">Welcome! One quick step before you can log in — confirm this is your email address.</p>
        <div style="text-align:center; margin: 24px 0;">
          <a href="{link}"
             style="background: linear-gradient(135deg, #2563EB, #1D4ED8); color: white;
                    padding: 12px 28px; border-radius: 10px; text-decoration: none;
                    font-weight: 600; display: inline-block;">
            Activate My Account
          </a>
        </div>
        <p style="color:#64748B; font-size: 12px;">
          Or paste this link into your browser:<br>
          <a href="{link}" style="color:#2563EB;">{link}</a>
        </p>
        <p style="color:#94A3B8; font-size: 12px; margin-top: 24px;">
          Didn't sign up for this? You can safely ignore this email.
        </p>
      </div>
    </div>
    """

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        context = ssl.create_default_context()
        if cfg["port"] == 465:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=context, timeout=15) as server:
                server.login(cfg["user"], cfg["password"])
                server.sendmail(cfg["from_email"], to_email, msg.as_string())
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as server:
                server.starttls(context=context)
                server.login(cfg["user"], cfg["password"])
                server.sendmail(cfg["from_email"], to_email, msg.as_string())
        return True
    except Exception as e:
        st.error(f"Account created, but the verification email couldn't be sent: {e}")
        return False
