import os
import hashlib
import secrets
import supabase
import httpx
import certifi
from datetime import datetime, timezone

from supabase import create_client, Client
from supabase import ClientOptions


_supabase_client = None


def get_supabase() -> Client:
    global _supabase_client

    if _supabase_client is not None:
        return _supabase_client

    try:
        import streamlit as st

        supabase_url = st.secrets["SUPABASE_URL"]
        supabase_key = st.secrets["SUPABASE_SECRET_KEY"]

    except Exception:
        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_SECRET_KEY")

    if not supabase_url or not supabase_key:
        raise RuntimeError(
            "Supabase credentials are not configured. "
            "Set SUPABASE_URL and SUPABASE_SECRET_KEY."
        )

    # macOS system CA bundle.
    # SSL certificate verification remains ENABLED.
    http_client = httpx.Client(
        verify=certifi.where(),
        timeout=120.0,
        follow_redirects=True,
        http2=True,
    )

    options = ClientOptions(
        postgrest_client_timeout=120,
        httpx_client=http_client,
    )

    _supabase_client = create_client(
        supabase_url,
        supabase_key,
        options=options,
    )

    # Explicitly configure PostgREST to use the same HTTP client.
    _supabase_client.postgrest.session = http_client

    return _supabase_client


def init_db():
    """
    Initialize the Supabase connection.

    The tables are already created in Supabase, so unlike SQLite,
    we do not create tables from Python.
    """
    get_supabase()
    return True


def hash_password(password):
    """
    Hash password using PBKDF2-HMAC-SHA256 with a random salt.
    """
    salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    ).hex()

    return f"{salt}${password_hash}"


def verify_password(password, stored_hash):
    """
    Verify a password against the stored PBKDF2 hash.
    """
    try:
        salt, password_hash = stored_hash.split("$")

        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000
        ).hex()

        return secrets.compare_digest(
            calculated_hash,
            password_hash
        )

    except Exception:
        return False


def create_user(email, password, role="user", name=None, auto_verify=False):
    """
    Create a customer account in Supabase.

    Returns the verification token (str) on success, so the caller can email
    it — or None if the account already exists / creation failed.
    `auto_verify=True` skips email verification entirely (used for the CLI
    admin-creation script, where there's no signup email flow to confirm).
    """
    supabase = get_supabase()

    email = email.lower().strip()

    if not name:
        name = email.split("@")[0]

    token = None if auto_verify else secrets.token_urlsafe(32)

    try:
        response = (
            supabase
            .table("users")
            .insert({
                "name": name,
                "email": email,
                "password_hash": hash_password(password),
                "role": role,
                "profile_picture": None,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_verified": auto_verify,
                "verification_token": token,
                "verification_sent_at": None if auto_verify else datetime.now(timezone.utc).isoformat(),
            })
            .execute()
        )

        if not response.data:
            return None
        return "verified" if auto_verify else token

    except Exception as e:
        error_text = str(e).lower()

        # Duplicate email
        if (
            "duplicate" in error_text
            or "unique" in error_text
            or "already exists" in error_text
        ):
            return None

        raise


def authenticate_user(email, password):
    """
    Authenticate a customer against the Supabase users table.

    Returns:
      - a user dict on success
      - None on a wrong email/password
      - the string "unverified" when credentials are correct but the
        account's email hasn't been confirmed yet
    """
    supabase = get_supabase()

    email = email.lower().strip()

    try:
        response = (
            supabase
            .table("users")
            .select(
                "id, name, email, password_hash, role, "
                "profile_picture, created_at, is_verified"
            )
            .eq("email", email)
            .limit(1)
            .execute()
        )

    except Exception:
        return None

    if not response.data:
        return None

    row = response.data[0]

    stored_hash = row.get("password_hash")

    if not stored_hash:
        return None

    if not verify_password(password, stored_hash):
        return None

    if not row.get("is_verified", False):
        return "unverified"

    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "email": row.get("email"),
        "role": row.get("role", "user"),
        "profile_picture": row.get("profile_picture"),
        "created_at": row.get("created_at")
    }


def verify_email_token(token: str) -> bool:
    """Activates the account matching this verification token, if any."""
    if not token:
        return False
    supabase = get_supabase()
    try:
        res = (
            supabase.table("users")
            .select("id")
            .eq("verification_token", token)
            .limit(1)
            .execute()
        )
        if not res.data:
            return False

        user_id = res.data[0]["id"]
        supabase.table("users").update({
            "is_verified": True,
            "verification_token": None,
        }).eq("id", user_id).execute()
        return True
    except Exception:
        return False


def resend_verification(email: str):
    """Issues a fresh token for an existing, not-yet-verified account."""
    supabase = get_supabase()
    email = email.lower().strip()
    try:
        res = (
            supabase.table("users")
            .select("id, is_verified")
            .eq("email", email)
            .limit(1)
            .execute()
        )
        if not res.data or res.data[0].get("is_verified"):
            return None

        token = secrets.token_urlsafe(32)
        supabase.table("users").update({
            "verification_token": token,
            "verification_sent_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", res.data[0]["id"]).execute()
        return token
    except Exception:
        return None