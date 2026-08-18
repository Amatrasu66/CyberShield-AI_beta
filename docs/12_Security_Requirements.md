# Security Requirements

- Environment variables for secrets (server-only; never ship service-role credentials)
- Authentication delegated to Supabase Auth (bcrypt managed by Supabase)
- No password hashes stored in the application database
- Supabase Auth JWTs for user sessions
- Flask verifies the Supabase JWT and reads the user ID from the token
- RLS on all application tables restricted by auth.uid()
- Normal user-scoped access preserves RLS; service-role/secret credentials are server-only for elevated operations
- Parameterized SQL queries
- Input validation
- Secure file uploads (private Supabase Storage bucket with signed access for PDFs)
- HTTPS in production

## SQL Playground Isolation
- SQL endpoints `/api/sql/run` and `/api/sql/scenarios` are authenticated.
- No arbitrary SQL execution: only fixed scenario IDs with fixed SQL templates are accepted.
- Every run uses a fresh in-memory `sqlite3 ":memory:"` database; no persistence, no PostgreSQL, no Supabase access, no network.
- SQLite authorizer denies writes, DDL, ATTACH/DETACH, PRAGMA, and `load_extension`; reads are restricted to the demo tables.
- Payload length limit, query work budget (progress handler), max result rows, max result cell size, JSON-safe cells, and generic rejection messages (no sqlite internals leaked).

## Cryptography Lab
- Sensitive values are never persisted: plaintext, passphrases, keys, ciphertext, salts, nonces, and HMAC keys are kept in memory and returned in responses only.
- Browser-side Web Crypto architecture: the frontend crypto engine executes client-side and never sends plaintext, passphrases, or keys to the backend. The Cryptography Lab UI does not call `/api/crypto/*`; every interactive operation runs locally in the page.
- Backend crypto endpoints (`/api/crypto/hash`, `/encrypt`, `/decrypt`, `/encode`, `/decode`) are **authenticated** (`@require_auth`) and sized-limited; they log and store nothing.
- Use of vetted primitives only: AES-256-GCM, PBKDF2-HMAC-SHA256, and cryptographically secure randomness (`crypto.getRandomValues()` / `os.urandom`).
- The browser AES passphrase is capped at **512 characters** (enforced by the engine itself, not only by the input field); PBKDF2 remains at **600,000 iterations** and AES remains **AES-256-GCM**. Do not document a reduced iteration count.
- SHA-1 and MD5 are exposed solely for educational/deprecation demonstrations and must be described as deprecated and inappropriate for new security-sensitive systems.
