# se_project

## Creative Work Timestamp & Ownership Registry

A full-stack system for registering, timestamping, and verifying ownership of creative content. Creators use a local Streamlit dashboard to fingerprint and RSA-sign their work; a separate Flask site lets anyone browse and search the resulting public registry.

## 🔐 Features

- Register creative works with cryptographic timestamps
- Generate SimHash fingerprints & detect near-duplicate/plagiarized content
- Issue RSA-signed ownership certificates
- Verify certificates using digital signature validation
- Browse and search a public registry of all registered works
- Creator dashboard (Streamlit) for registration, verification, plagiarism checks, and backups
- Public-facing read-only website (Flask) for viewing the registry

## 🛠 Tech stack

- **Creator dashboard:** Streamlit (`cr_2.py`)
- **Public website:** Flask (`app.py`), served via Gunicorn/WSGI in production
- **Database:** SQLite (`creative_registry.db`), shared locally between both apps
- **Security:** RSA-2048 (PKCS#1 v1.5) signatures, SHA-256 hashing, SimHash similarity fingerprinting

## 🏗 How it fits together

`cr_2.py` and `app.py` are two independent apps that share one local `creative_registry.db` file:

1. Run `cr_2.py` (Streamlit) locally to register a work — it hashes the content, checks for near-duplicates, signs the result with `private.pem`, and writes a row to `creative_registry.db`.
2. Run `app.py` (Flask) to browse/search the same database — it's read-only and never writes to the registry.

Both need to point at the same `creative_registry.db` and the same keypair to work together.

## 🚀 Setup

```bash
pip install -r requirements.txt streamlit

# Generate a keypair from the dashboard sidebar the first time, then:
streamlit run cr_2.py     # creator dashboard: register, verify, check plagiarism
python app.py              # public registry site (or: gunicorn wsgi:application)
```

`private.pem`, `public.pem`, and `creative_registry.db` are gitignored on purpose — keep them out of version control and provision them separately for any deployment.

## ⚠️ Known limitations

- **Identity isn't verified.** Anyone can type any name into the "Creator" field — the registry currently proves *who submitted first*, not *who actually made the work*.
- **Certificates sign only the content fingerprint**, not the creator/title/license/timestamp fields stored alongside it — those fields aren't yet cryptographically bound to the signature.
- **SQLite is a single local file.** It works well for local/demo use, but isn't suited to serverless deployment (e.g. Vercel), where the filesystem doesn't persist writes between requests. A hosted database is needed for a live, always-current public deployment.

## 🎯 Use case

Perfect for authors, developers, designers, musicians, and researchers who want a simple way to timestamp and prove authorship of digital content.
