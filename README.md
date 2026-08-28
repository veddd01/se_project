# Creative Work Timestamp & Ownership Registry

A full-stack application for registering and verifying creative works using cryptographic fingerprints, digital signatures, and similarity detection.

## Overview

The project provides two local interfaces backed by the same SQLite database:

- **Creator dashboard:** Streamlit application for registering works, generating fingerprints, signing certificates, verifying ownership, and checking for similar works.
- **Public registry:** Flask application for browsing and searching registered works.

The implementation uses SHA-256 fingerprints, SimHash similarity detection, and RSA-2048 signatures. The registry database and RSA key files are intentionally excluded from version control.

## Features

- Register creative works with timestamps and metadata
- Generate SHA-256 fingerprints and SimHash values
- Detect near-duplicate content using SimHash distance
- Generate and verify RSA-2048 signatures
- Create downloadable ownership certificates
- Browse and search the public registry
- Maintain registry data in SQLite

## Tech Stack

- **Python**
- **Streamlit** — creator dashboard
- **Flask** — public registry
- **SQLite** — local persistence
- **PyCryptodome** — RSA/AES cryptographic operations
- **SimHash** — similarity detection
- **Gunicorn** — WSGI serving

## Architecture

```text
                 ┌──────────────────────┐
                 │   Creator Dashboard  │
                 │      Streamlit       │
                 └──────────┬───────────┘
                            │
                 register / verify / check
                            │
                            ▼
                 ┌──────────────────────┐
                 │   SQLite Registry    │
                 │ creative_registry.db │
                 └──────────┬───────────┘
                            │
                       read / search
                            │
                            ▼
                 ┌──────────────────────┐
                 │   Public Registry    │
                 │        Flask         │
                 └──────────────────────┘
```

For registration, the application derives a content fingerprint, computes a SimHash value for similarity checks, signs the fingerprint with an RSA private key, and stores the resulting registry record. The public Flask application reads the shared registry without performing registration writes.

## Project Structure

```text
se_project/
├── app.py
├── cr_2.py
├── requirements.txt
├── wsgi.py
├── vercel.json
├── templates/
├── .gitignore
└── README.md
```

## Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/veddd01/se_project.git
cd se_project
python -m venv .venv
```

Activate the virtual environment.

**Windows**

```bash
.venv\Scripts\activate
```

**macOS/Linux**

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Start the creator dashboard

```bash
streamlit run cr_2.py
```

Use the dashboard to generate an RSA keypair if required, register works, verify certificates, and perform similarity checks.

### 2. Start the public registry

In a second terminal:

```bash
python app.py
```

The Flask application serves the read-only registry locally.

For WSGI deployment, the repository also includes `wsgi.py` and Gunicorn support.

## Security Notes

- `private.pem` and `public.pem` are ignored by Git.
- SQLite database files are ignored by Git.
- Do not commit private keys, credentials, or generated registry data.
- The current implementation is intended for local/demo use rather than a production identity-verification service.

## Limitations

- Creator identity is user-supplied and is not independently verified.
- RSA signatures currently cover the generated content fingerprint rather than every metadata field.
- SQLite is appropriate for local/demo use but is not a substitute for a production hosted database.

## Future Improvements

- Bind all certificate metadata to the signed payload
- Add authenticated creator identities
- Move persistence to a hosted relational database
- Expand automated tests for cryptographic and registry workflows
- Add deployment-oriented configuration and observability

## Author

**Vedant** — [GitHub](https://github.com/veddd01)
