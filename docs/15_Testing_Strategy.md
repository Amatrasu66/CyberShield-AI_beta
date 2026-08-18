# Testing Strategy

## Current Status
- The backend suite currently collects **910** tests (`python -m pytest --collect-only`) and a full `python -m pytest -q` run passes (verified exit code 0).
- Key suites include: `test_sql_lab_redteam.py` (316), `test_sql_lab.py` (166),
  `test_sql_playground.py` (40), `test_crypto.py` (19), `test_route_auth.py` (33),
  `test_password.py` (58), `test_scanner.py` (31), `test_email.py` (31),
  `test_dashboard.py` (34), `test_reports.py` (38), plus auth, logs, JWT/RS256,
  RLS scoping, Supabase client fake, report storage, security utils, and
  error-handling suites.
- Tests run fully offline: the Supabase client is replaced with a deterministic
  in-memory fake and JWT verification uses an in-test RSA key, so no network,
  database, or ML models are required.
- The crypto backend endpoints now require authentication, so `test_crypto.py`
  and `test_route_auth.py` cover the authenticated happy paths and the 401
  rejection of unauthenticated `/api/crypto/*` calls.

## Frontend Verification (no test framework)
- The frontend has **no automated test framework installed** (no Vitest, Jest,
  or React Testing Library). Component/UI behavior is verified manually.
- The browser crypto engine ships an in-repo Node-runnable self-test:
  `node frontend/src/lib/cryptoEngine.selftest.ts` reports **72 passed, 0 failed**
  (verified), covering Web Crypto support, UTF-8/hex/base64 round-trips, SHA-256/
  SHA-512 vectors, AES-256-GCM encrypt/decrypt + tamper/wrong-passphrase rejection,
  the 512-character passphrase boundary, HMAC-SHA256 sign/verify, randomness, and
  the unsupported-browser guard.
- `npx tsc --noEmit` passes (verified), and `npm run build` produces a production
  build (verified; only a chunk-size advisory warning is emitted).

## Objectives
- Verify functionality of every module.
- Validate API responses.
- Ensure ML predictions work correctly (once ML inference is implemented).
- Test database integration.
- Verify report generation.

## Testing Types
- Unit Testing
- Integration Testing
- API Testing
- UI Testing
- Security Testing
- Performance Testing

## Acceptance Criteria
- All APIs return expected responses.
- UI is responsive.
- Reports generate successfully.
- Authentication works securely.
