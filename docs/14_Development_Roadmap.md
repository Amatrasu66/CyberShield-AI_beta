# Development Roadmap

Status labels: **COMPLETED** (implemented and verified in the repository at HEAD `c5c3c0c`), **NEXT** (next implementation step), **LATER** (defined direction, not yet implemented), **PLANNED** (defined direction, deliberately deferred until the core is stable).

## COMPLETED
- Backend core services (auth, dashboard, scanner, email, password, logs, reports) and Supabase/JWT authentication.
- SQL Injection Playground sandbox (`backend/app/services/sql_lab_service.py`).
- SQL API integration (`POST /api/sql/run`, `GET /api/sql/scenarios`; legacy public `POST /api/sql/demo`).
- SQL security/red-team audit (`test_sql_lab.py`, `test_sql_lab_redteam.py`).
- SQL Playground frontend (`frontend/src/pages/SQLPlaygroundPage.tsx`).
- Backend Cryptography Lab service (SHA-256/SHA-512, AES-256-GCM, PBKDF2-HMAC-SHA256, base64/hex).
- Browser cryptography engine (`frontend/src/lib/cryptoEngine.ts` + in-repo selftest).
- Cryptography Lab UI (`frontend/src/pages/CryptographyLabPage.tsx` at `/cryptography-lab`).
- Cryptography security hardening: all backend crypto endpoints are authenticated, the browser engine enforces a 512-character AES passphrase cap, PBKDF2 remains 600,000 iterations, and AES remains AES-256-GCM.
- Dashboard, reports, and workspace pages.

## NEXT
- Documentation/tutorial system: a section explaining how the toolkit works and how to use each module.

## LATER
- Remaining core cybersecurity module improvements.
- Final crypto security audit (deep review pass; the delivered hardening is already in place).
- Decide and implement future AI/ML functionality only after the core functionality is stable (trained inference is not implemented today).
- Professional landing page after the core application is complete.
- Final deployment hardening and deployment.

## PLANNED (not currently implemented)
- Trained AI/ML inference for the email detector and log analyzer (modules exist as placeholders; see 11_ML_Architecture.md).