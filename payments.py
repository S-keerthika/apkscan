import os
import razorpay
import streamlit as st
import streamlit.components.v1 as components
from datetime import datetime, timedelta, timezone
from auth import get_supabase

KEY_ID = st.secrets.get("RAZORPAY_KEY_ID", os.getenv("RAZORPAY_KEY_ID", ""))
KEY_SECRET = st.secrets.get("RAZORPAY_KEY_SECRET", os.getenv("RAZORPAY_KEY_SECRET", ""))

client = razorpay.Client(auth=(KEY_ID, KEY_SECRET)) if KEY_ID and KEY_SECRET else None

# Premium is sold as a 1-day pass, not a monthly subscription.
PREMIUM_DURATION = timedelta(days=1)
PRICE_INR = 59
PRICE_USD = 5


def verify_payment_signature(order_id: str, payment_id: str, signature: str) -> bool:
    """
    Verifies the Razorpay payment signature server-side.

    This MUST run before a payment is trusted and a subscription is upgraded —
    without it, anyone could forge a success callback and get Pro for free.
    """
    if not client:
        return False
    try:
        client.utility.verify_payment_signature({
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature,
        })
        return True
    except razorpay.errors.SignatureVerificationError:
        return False
    except Exception:
        return False


def create_payment_order(amount: int, currency: str = "INR") -> dict:
    """Creates a Razorpay order in INR (paise) or USD (cents)."""
    if not client:
        st.error("Razorpay API keys are missing.")
        return None
    try:
        order_data = {
            "amount": amount * 100,  # Convert to smallest currency subunit (paise/cents)
            "currency": currency,
            "payment_capture": 1,
        }
        order = client.order.create(data=order_data)
        return order
    except Exception as e:
        st.error(f"Razorpay order creation failed: {e}")
        return None


def sync_user_subscription(user_id: int, plan_tier: str = "pro"):
    """Activates a 1-day Premium pass for the user after a verified payment."""
    supabase = get_supabase()
    expires_at = (datetime.now(timezone.utc) + PREMIUM_DURATION).isoformat()
    try:
        supabase.table("subscriptions").upsert({
            "user_id": user_id,
            "plan_tier": plan_tier,
            "status": "active",
            "scans_remaining": 999999,
            "premium_expires_at": expires_at,
        }).execute()
        return True
    except Exception as e:
        st.error(f"Failed to update subscription record: {e}")
        return False


def get_subscription_status(user_id: int) -> dict:
    """
    Returns the user's current plan, self-healing an expired Premium pass
    back to 'free' the moment it's checked (no cron job needed).

    Shape: {"plan_tier": "free"|"pro", "expired": bool, "expires_at": str|None}
    """
    supabase = get_supabase()
    try:
        res = supabase.table("subscriptions").select("*").eq("user_id", user_id).execute()
        if not res.data:
            return {"plan_tier": "free", "expired": False, "expires_at": None}

        sub = res.data[0]
        plan_tier = sub.get("plan_tier", "free")
        expires_at_raw = sub.get("premium_expires_at")

        if plan_tier == "pro" and expires_at_raw:
            expires_at = datetime.fromisoformat(expires_at_raw)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if datetime.now(timezone.utc) >= expires_at:
                # 1-day pass ran out — drop back to free so scanning is
                # gated again and the pricing page asks them to renew.
                supabase.table("subscriptions").update({
                    "plan_tier": "free",
                    "status": "expired",
                }).eq("user_id", user_id).execute()
                return {"plan_tier": "free", "expired": True, "expires_at": expires_at_raw}

            return {"plan_tier": "pro", "expired": False, "expires_at": expires_at_raw}

        return {"plan_tier": plan_tier, "expired": False, "expires_at": expires_at_raw}
    except Exception:
        # Fail open to "free" rather than crashing the page on a DB hiccup.
        return {"plan_tier": "free", "expired": False, "expires_at": None}


def check_and_decrement_scan_limit(user_id: int) -> bool:
    """Checks if a standard user has remaining scans. Returns True if scan is allowed."""
    supabase = get_supabase()
    try:
        status = get_subscription_status(user_id)
        if status["plan_tier"] == "pro":
            return True

        res = supabase.table("subscriptions").select("*").eq("user_id", user_id).execute()

        if not res.data:
            # First scan for new user: record and allow
            supabase.table("subscriptions").insert({
                "user_id": user_id,
                "plan_tier": "free",
                "status": "active",
                "scans_remaining": 0,  # 1 scan used immediately
            }).execute()
            return True

        sub = res.data[0]
        scans_remaining = sub.get("scans_remaining", 0)
        
        # Block if no remaining scans left
        if scans_remaining <= 0:
            return False

        # Decrement scan count for free tier
        supabase.table("subscriptions").update({
            "scans_remaining": scans_remaining - 1
        }).eq("user_id", user_id).execute()
        
        return True
    except Exception as e:
        st.warning(f"Scan quota check failed: {e}")
        return True


def render_razorpay_checkout_button(order_id: str, amount: int, currency: str, user_email: str):
    """Embeds the Razorpay Checkout modal with accurate currency rendering."""
    currency_symbol = "₹" if currency == "INR" else "$"
    
    html_code = f"""
    <!DOCTYPE html>
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {{ margin: 0; padding: 0; font-family: -apple-system, sans-serif; }}
          #rzp-button {{
            background-color: #2563EB;
            color: white;
            padding: 14px 28px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
          }}
          #rzp-button:hover {{ background-color: #1D4ED8; }}
        </style>
      </head>
      <body>
        <button id="rzp-button">
            Pay {currency_symbol}{amount} ({currency}) with Razorpay
        </button>
        <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
        <script>
        var options = {{
            "key": "{KEY_ID}",
            "amount": "{amount * 100}",
            "currency": "{currency}",
            "name": "APK Security Scanner",
            "description": "1-Day Premium Pass",
            "order_id": "{order_id}",
            "prefill": {{
                "email": "{user_email}"
            }},
            "theme": {{
                "color": "#2563EB"
            }},
            "handler": function (response){{
                // Hand the payment result back to Streamlit via a query-param
                // reload, so the Python side can verify the signature and
                // actually activate the subscription (never trust the client).
                var params = new URLSearchParams(window.top.location.search);
                params.set("payment_order_id", response.razorpay_order_id);
                params.set("payment_id", response.razorpay_payment_id);
                params.set("payment_signature", response.razorpay_signature);
                window.top.location.search = params.toString();
            }},
            "modal": {{
                "ondismiss": function() {{
                    console.log("Checkout closed by user.");
                }}
            }}
        }};
        var rzp1 = new Razorpay(options);
        rzp1.on('payment.failed', function (response){{
            alert("Payment failed: " + response.error.description);
        }});
        document.getElementById('rzp-button').onclick = function(e){{
            rzp1.open();
            e.preventDefault();
        }};
        </script>
      </body>
    </html>
    """
    components.html(html_code, height=650)