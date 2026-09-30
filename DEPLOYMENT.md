# Deploying APK Scanner Pro to your GoDaddy / Hostinger domain

## Read this first: shared hosting won't work

GoDaddy's and Hostinger's **shared hosting** plans (the cheap cPanel ones) only run PHP
and short-lived scripts — they can't keep a Python process alive or handle the
WebSocket connection Streamlit needs to stream results to the browser. Uploading
this app there will not work, no matter how it's configured.

You have two realistic options:

| Option | Effort | Cost | Domain stays at GoDaddy/Hostinger? |
|---|---|---|---|
| **A. VPS** (Hostinger VPS or GoDaddy VPS/dedicated) | Medium — you manage the server | ~$5–15/mo | Yes, point DNS at it |
| **B. A Python host** (Render, Railway, Streamlit Community Cloud) + point your domain at it | Low | Often free–$7/mo | Yes, just a CNAME/A record |

Below are complete steps for **Option A**, since that's what "host on GoDaddy/Hostinger"
usually means. Option B is faster if you'd rather skip server administration — steps for
that are at the bottom.

---

## Option A — VPS deployment (Ubuntu 22.04/24.04)

### 1. Buy/enable a VPS
Both GoDaddy and Hostinger sell VPS plans separately from their shared hosting —
order one (Ubuntu 22.04 or 24.04 LTS image), note its **public IPv4 address**.

### 2. Point your domain at the VPS
In your domain's DNS zone (GoDaddy: *My Products → DNS*; Hostinger: *hPanel → DNS Zone Editor*):
- Add an **A record**: Host `@`, Value `<your VPS IP>`, TTL default
- Add an **A record**: Host `www`, Value `<your VPS IP>`

DNS propagation can take a few minutes to a few hours.

### 3. SSH in and install prerequisites
```bash
ssh root@<your-vps-ip>

apt update && apt upgrade -y
apt install -y python3.11 python3.11-venv python3-pip nginx git ufw
```

### 4. Upload the project (skip the local `venv/` folder — it's macOS-built and won't run on Linux)
From your own machine:
```bash
rsync -av --exclude 'venv' --exclude '__pycache__' --exclude '.DS_Store' \
  "./apkscan copy/" root@<your-vps-ip>:/opt/apkscanner/
```

### 5. Create a fresh Linux virtual environment and install dependencies
```bash
cd /opt/apkscanner
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 6. Set production secrets
Edit `/opt/apkscanner/.streamlit/secrets.toml` on the server with your **live**
Supabase and Razorpay keys (use Razorpay's live keys, not test keys, once you're ready
to accept real payments). Never commit this file to git or ship it in a public zip.

Also update your Razorpay dashboard's allowed origins/webhook URL and your Supabase
project's allowed redirect URLs to `https://yourdomain.com` once DNS is live.

### 7. Create a systemd service so the app survives reboots/crashes
`/etc/systemd/system/apkscanner.service`:
```ini
[Unit]
Description=APK Scanner Pro (Streamlit)
After=network.target

[Service]
User=root
WorkingDirectory=/opt/apkscanner
Environment="PATH=/opt/apkscanner/venv/bin"
ExecStart=/opt/apkscanner/venv/bin/streamlit run app.py \
  --server.port 8501 \
  --server.address 127.0.0.1 \
  --server.headless true \
  --server.enableCORS false \
  --server.enableXsrfProtection true \
  --browser.gatherUsageStats false
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
```bash
systemctl daemon-reload
systemctl enable apkscanner
systemctl start apkscanner
systemctl status apkscanner   # confirm it's "active (running)"
```

### 8. Configure nginx as a reverse proxy (with WebSocket support)
`/etc/nginx/sites-available/apkscanner`:
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    client_max_body_size 420M;   # must be >= MAX_UPLOAD_MB (400) in app.py

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
```
```bash
ln -s /etc/nginx/sites-available/apkscanner /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx
```

### 9. Add free HTTPS with Let's Encrypt
```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d yourdomain.com -d www.yourdomain.com
```
Certbot edits the nginx config to redirect HTTP → HTTPS and auto-renews the
certificate; no further action needed.

### 10. Lock down the firewall
```bash
ufw allow OpenSSH
ufw allow 'Nginx Full'   # opens 80 + 443 only — 8501 stays unreachable from outside
ufw enable
```

### 11. Verify
Visit `https://yourdomain.com` — you should land on the login screen. Sign up,
run a scan, and test the Pro checkout flow end-to-end with Razorpay **test** keys
before switching to live keys.

**Updating the app later:** `rsync` your changed files to `/opt/apkscanner/`, then
`systemctl restart apkscanner`.

---

## Option B — Fastest path (no server to manage)

1. Push this project (without `venv/`, `.streamlit/secrets.toml`, or `users.db`) to
   a **private** GitHub repo.
2. Deploy it on [Streamlit Community Cloud](https://streamlit.io/cloud), [Render](https://render.com),
   or [Railway](https://railway.app) — each builds `requirements.txt` and gives you a
   `https://something.streamlit.app` (or similar) URL. Add `SUPABASE_URL`,
   `SUPABASE_SECRET_KEY`, `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET` as that platform's
   environment/secrets settings.
3. In your GoDaddy/Hostinger DNS zone, add a **CNAME record** for `www` (or an A record
   if the platform gives you a static IP) pointing at the URL/IP that platform gives you.
4. Most of these platforms will also auto-issue HTTPS for your custom domain once the
   CNAME/A record resolves — follow the "custom domain" instructions in whichever
   platform you pick.

---

## Before you go live — a few things worth fixing/checking

- **`payments.py` / `app.py`**: fixed in this pass — the Razorpay checkout button used to
  just show a JS alert on success and never actually updated the user's plan in Supabase.
  It now redirects back with the payment signature, verifies it server-side with
  `client.utility.verify_payment_signature`, and only then calls `sync_user_subscription`.
  Test this end-to-end with Razorpay test cards before flipping to live keys.
- **`.streamlit/secrets.toml`**: contains your live API keys. Make sure your `.gitignore`
  excludes it (see below) if you push this to GitHub for Option B.
- **`users.db`**: removed — it was a leftover local SQLite file from before the app
  moved to Supabase; nothing in the code reads it anymore.
- Add a `.gitignore` with at least:
  ```
  venv/
  __pycache__/
  .streamlit/secrets.toml
  *.pyc
  ```

## Email verification — required Supabase migration + SMTP setup

New accounts now have to confirm their email before they can log in. This needs:

**1. Add three columns to the `users` table** (Supabase SQL editor):
```sql
alter table users add column if not exists is_verified boolean not null default false;
alter table users add column if not exists verification_token text;
alter table users add column if not exists verification_sent_at timestamptz;
```

**2. Fill in SMTP settings** in `.streamlit/secrets.toml` — `SMTP_HOST`, `SMTP_PORT`,
`SMTP_USER`, `SMTP_PASSWORD`, `FROM_EMAIL`, and `APP_BASE_URL` (set this to your real
domain once deployed, e.g. `https://yourdomain.com` — verification links are built from
it). Any SMTP provider works:
- **Your GoDaddy/Hostinger mailbox** — e.g. `smtp.hostinger.com:587` or
  `smtpout.secureserver.net:587` with your email account's own credentials. Simplest if
  you're already hosting the domain there.
- **Gmail** — `smtp.gmail.com:587`, but you must use a 16-character **App Password**
  (Google Account → Security → 2-Step Verification → App Passwords), not your normal
  Gmail password.
- **A transactional email service** (SendGrid, Mailgun, Resend, etc.) — better deliverability
  at scale; use the SMTP relay credentials they give you.

**3. Existing accounts**: anyone created before this change will have `is_verified = false`
by default and will get locked out until verified. Either have them use "Resend
verification email" on the login screen, or verify them directly in Supabase:
```sql
update users set is_verified = true where email = 'someone@example.com';
```

**4. Admin accounts** created via `create_admin.py` skip verification automatically —
no email step needed for those.
