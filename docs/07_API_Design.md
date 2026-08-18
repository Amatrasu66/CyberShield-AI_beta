# API Design

## Authentication
Handled by Supabase Auth, called directly from React:
- POST /auth/v1/signup
- POST /auth/v1/token?grant_type=password
- POST /auth/v1/logout
- GET /auth/v1/user

React holds the Supabase session and sends the access JWT to Flask as `Authorization: Bearer <JWT>`.

## Authorization
Flask verifies the Supabase Auth JWT and reads the user ID from the token
(`sub` claim = `auth.uid()`). Only endpoints marked **authenticated** below
require a valid JWT; requests without a valid token return 401. Public
endpoints (health, version, and the legacy SQL demo) do not require a token.
The Cryptography Lab backend endpoints are **authenticated** (protected with
`@require_auth` in `backend/app/routes/crypto_routes.py`).

Every endpoint below is **currently implemented** unless explicitly marked
planned, deprecated, or legacy.

## System (public)
- `GET /api/health` — liveness check
- `GET /api/version` — backend/API version info

## Auth
- `GET /api/auth/me` — **authenticated**; returns the authenticated user's profile keyed off the verified JWT `sub`. `/me` is the only Flask auth endpoint; signup/login/logout/session refresh belong to Supabase Auth.

## Website Scanner
- `POST /api/scanner/website` — **authenticated**

## Email Detector
- `POST /api/email/analyze` — **authenticated**. Currently uses a deterministic heuristic analyzer; ML inference is planned (see 11_ML_Architecture.md).

## Password Analyzer
- `POST /api/password/analyze` — **authenticated**
- `POST /api/password/generate` — **authenticated** (types: `passphrase` or `random`)

## Log Analyzer
- `POST /api/logs/analyze` — **authenticated**. Currently uses a deterministic rule-based analyzer; ML inference is planned (see 11_ML_Architecture.md).

## Dashboard
- `GET /api/dashboard` — **authenticated**

Returns the authenticated user's aggregated security overview: metric cards
(security score, scans completed, threats detected, assets monitored), recent
scans, a synthesized activity feed, and a 12-day scan trend. All data is
derived from the user's own scan and report tables via user-scoped, RLS-preserving
reads. `user_id` always comes from the verified JWT; query parameters and the
request body are ignored.

## Reports
- `GET /api/reports` — **authenticated**
- `POST /api/reports/generate` — **authenticated** (generates a PDF stored in a private Supabase Storage bucket)

## Cryptography Lab
All Cryptography Lab endpoints are **authenticated** and operate on
sized-limited input (default ceiling `CRYPTO_MAX_INPUT_LENGTH` = 100,000
characters; passphrases must be at least 8 characters). No plaintext,
passphrases, keys, ciphertext, salts, or nonces are logged or stored.
The interactive Cryptography Lab UI runs entirely in the browser via the Web
Crypto API and does **not** call these endpoints; they exist as an authenticated
backend equivalent.

- `POST /api/crypto/hash` — **authenticated**.
  - Request: `{ "text": string, "algorithm": "sha256" | "sha512" | "sha1" | "md5" }` (`algorithm` defaults to `sha256`).
  - Response: `{ operation: "hash", algorithm, digest, digest_length_bits, reversible: false, warning }`. SHA-1 / MD5 are exposed for educational/deprecation study and return a deprecation warning.
- `POST /api/crypto/encrypt` — **authenticated**.
  - Request: `{ "plaintext": string, "passphrase": string }` (passphrase min 8 characters).
  - Response: `{ operation: "encrypt", algorithm: "AES-256-GCM", key_derivation, ciphertext, salt, nonce, tag, reversible: true, note }`. Key is derived with PBKDF2-HMAC-SHA256 (600,000 iterations); salt (16 bytes), nonce (12 bytes), and GCM tag are returned as base64 for decryption.
- `POST /api/crypto/decrypt` — **authenticated**.
  - Request: `{ "ciphertext": string, "passphrase": string, "salt": string, "nonce": string, "tag": string }` (all base64; salt/nonce/tag lengths validated).
  - Response: `{ operation: "decrypt", algorithm: "AES-256-GCM", plaintext, reversible: true }`, or a 4xx validation error for wrong passphrase/corrupted/tampered data (GCM tag check).
- `POST /api/crypto/encode` — **authenticated** (base64 / hex; encoding only, not encryption).
  - Request: `{ "text": string, "encoding": "base64" | "hex" }` (`encoding` defaults to `base64`).
  - Response: `{ operation: "encode", encoding, encoded, note }`.
- `POST /api/crypto/decode` — **authenticated** (base64 / hex decoding).
  - Request: `{ "text": string, "encoding": "base64" | "hex" }`.
  - Response: `{ operation: "decode", encoding, decoded, note }`, or a 4xx validation error for invalid input.

Not implemented and not documented as planned endpoints:
HMAC, RSA, digital signatures, standalone key generation, and additional
crypto modules. The browser exposes HMAC-SHA256 client-side only via the Web
Crypto engine; there is no HMAC API endpoint.

## SQL Injection Playground
Isolated educational sandbox. No SQL is executed against Supabase/PostgreSQL;
`/run` executes fixed templates inside a fresh in-memory `sqlite3 ":memory:"`
database that persists only for a single request. The sandbox has no arbitrary
SQL entry point: callers control only a scenario id and a payload string.
- `POST /api/sql/demo` — **public, legacy**; never executes SQL. It renders
  comparative query strings for study with no database touched.
  - Request: `{ "input": string }` (bounded by the configured `CRYPTO_MAX_INPUT_LENGTH`, default 100,000 characters).
  - Response: `{ demo: "login", input, vulnerable_pattern_detected, detected_patterns, outcome, unsafe_query, safe_query, explanations }`.
- `POST /api/sql/run` — **authenticated**; runs one fixed sandbox scenario
  (`login`, `union`, `boolean`, `comment`) with a caller-controlled `payload`.
  - Request: `{ "scenario": string (max 64), "payload": string (max 2048) }`.
  - Response: `{ scenario, input, vulnerable_query, safe_query, vulnerable_result, safe_result, explanation, sandbox }`. `vulnerable_result`/`safe_result` contain `{ rows, columns, data, execution_status }` and, on rejection, a generic `rejection_reason`. `sandbox` labels the isolation guarantee (`"in-memory sqlite (isolated, non-persistent)"`).
- `GET /api/sql/scenarios` — **authenticated**; lists the fixed scenario catalog
  (id, name, description, example payload, vulnerable/secure templates, explanations, mitigation).

The SQL Playground is not a general SQL console, an arbitrary SQL executor, or
a Supabase SQL interface.