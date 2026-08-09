# CyberShield AI - Backend API Service

Flask-based REST API service for the CyberShield AI platform.

## Architecture

The backend follows a modular layered architecture:

```
Routes (app/routes)
   |--> Services (app/services)
            |--> Utilities / domain logic (app/utils)
```

Future phases add two more layers behind the services:

- Database: Routes -> Services -> Repositories -> Supabase
- ML: Routes -> Services -> ML inference layer -> Model files

Current structure:

- `app.py`: Application entry point (loads `.env`, creates app, runs server).
- `app/__init__.py`: Flask application factory (config, CORS, logging, error
  handling, security headers, blueprint registration).
- `app/routes/`: Thin Flask blueprints. No business logic lives here.
- `app/services/`: Core domain and business logic (password, crypto, scanner,
  email, log, report, auth, SQL playground).
- `app/utils/`: Response helpers, validators, and security utilities.
- `app/config/`: Environment-driven configuration.
- `app/middleware/`: Centralized error handling, auth decorator, request
  logging, and HTTP security headers.
- `app/models/`, `app/database/`, `app/ml/`, `app/reports/`: Reserved for later
  phases (Supabase, ML inference, PDF generation). Currently placeholders.
- `tests/`: Deterministic pytest suite (no database, no ML required).

## Setup & Running

1. Create a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Environment variables:

   ```bash
   cp .env.example .env        # then edit .env (never commit it)
   ```

4. Run the local server:

   ```bash
   python app.py
   ```

   The API listens on `http://localhost:5000` by default. The frontend dev
   server proxies `/api` requests to this port.

## Running Tests

```bash
python -m pytest
```

All tests are deterministic and do not require Supabase or ML models.

## Implemented Endpoints

Authentication is delegated to Supabase Auth, which React calls directly
(`/auth/v1/signup`, `/auth/v1/token`, `/auth/v1/logout`, `/auth/v1/user`).
Flask does not implement login/register routes; every protected endpoint below
requires a valid Supabase access JWT in the `Authorization` header, which Flask
verifies and resolves to the authenticated user ID (`auth.uid()`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Service liveness and dependency status |
| GET | `/api/version` | Backend + API version information |
| POST | `/api/scanner/website` | Passive website security scan |
| POST | `/api/email/analyze` | Phishing detection (deterministic placeholder) |
| POST | `/api/password/analyze` | Password strength analysis |
| POST | `/api/logs/analyze` | Log analysis (deterministic placeholder) |
| POST | `/api/crypto/hash` | One-way hashing (MD5/SHA-1/SHA-256/SHA-512) |
| POST | `/api/crypto/encrypt` | AES-256-GCM encryption |
| POST | `/api/crypto/decrypt` | AES-256-GCM decryption |
| POST | `/api/crypto/encode` | base64 / hex encoding (educational) |
| POST | `/api/crypto/decode` | base64 / hex decoding (educational) |
| POST | `/api/sql/demo` | Educational SQL injection comparison (no SQL executed) |
| GET | `/api/reports` | List in-memory reports |
| POST | `/api/reports/generate` | Generate an in-memory report |

## Response Format

All responses use a consistent JSON envelope:

```json
{
  "success": true,
  "message": "OK",
  "data": { ... }
}
```

Errors:

```json
{
  "success": false,
  "message": "Human-readable message",
  "error": { "code": "VALIDATION_ERROR", "details": null }
}
```

## Phase Status

Deterministic now: password analyzer, cryptography lab, SQL playground,
website scanner, phishing/log analyzers (rule-based placeholders), reports
(in-memory).

Waiting for ML phase: phishing email classification and log anomaly detection
will swap the deterministic placeholders for trained models without changing
the API contract.

Waiting for Supabase phase: report persistence, scan history, and profile
data. User authentication is already delegated to Supabase Auth; Flask only
verifies Supabase access JWTs on protected endpoints.
