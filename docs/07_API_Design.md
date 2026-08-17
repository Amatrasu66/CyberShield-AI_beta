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
endpoints (health, version, the legacy SQL demo, and the Cryptography Lab
endpoints) do not require a token.

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
All Cryptography Lab endpoints are public and operate on sized-limited input.
No plaintext, passphrases, keys, ciphertext, salts, or nonces are logged or stored.
- `POST /api/crypto/hash` — SHA-256 / SHA-512 (SHA-1 / MD5 exposed for educational/deprecation study)
- `POST /api/crypto/encrypt` — AES-256-GCM with a PBKDF2-HMAC-SHA256-derived key
- `POST /api/crypto/decrypt` — decrypt payloads produced by `/api/crypto/encrypt`
- `POST /api/crypto/encode` — base64 / hex (encoding only; not encryption)
- `POST /api/crypto/decode` — base64 / hex decoding

Not implemented and not documented as planned endpoints:
HMAC, RSA, digital signatures, standalone key generation, and additional
crypto modules. The browser exposes HMAC-SHA256 client-side only via the Web
Crypto engine; there is no HMAC API endpoint.

## SQL Injection Playground
Isolated educational sandbox. No SQL is executed against Supabase/PostgreSQL;
`/run` executes fixed templates inside a fresh in-memory `sqlite3 ":memory:"`
database that persists only for a single request.
- `POST /api/sql/demo` — **public, legacy**; older illustrative demo. Never executes SQL; renders comparative query strings for study.
- `POST /api/sql/run` — **authenticated**; runs one fixed sandbox scenario (`login`, `union`, `boolean`, `comment`) with a caller-controlled `payload` against the ephemeral in-memory SQLite database (vulnerable interpolation path vs. secure parameterized path).
- `GET /api/sql/scenarios` — **authenticated**; lists the fixed scenario catalog.

The SQL Playground is not a general SQL console, an arbitrary SQL executor, or
a Supabase SQL interface.