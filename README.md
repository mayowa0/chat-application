-m venv .venv# Chat App (Flask + Socket.IO)

This folder includes fixes and guidance to get your app running reliably.

## Quickstart

```bash
# 1) Create venv
python -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate

# 2) Install deps
pip install -r requirements.txt

# 3) Configure secrets
cp .env.example .env
# edit .env and set SECRET_KEY and email SMTP creds (or leave empty to log OTP to console)

# 4) Run
python app.py
# open http://127.0.0.1:5000
```

## Notes

- DB will be created at `instance/chat.db` automatically.
- OTP and temp signup data are stored server-side (Flask-Session), not in client cookies.
- Socket.IO allows any origin in dev. Tighten `cors_allowed_origins` for production.
- Never commit your real `.env` to version control.
