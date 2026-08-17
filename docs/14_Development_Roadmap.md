# Development Roadmap

Status labels: **DONE** (implemented and verified in the repository at HEAD `cacfb9c`), **NEXT** (next implementation step), **PLANNED** (defined direction, not yet implemented).

## Completed
- Backend core services (auth, dashboard, scanner, email, password, logs, reports) and Supabase/JWT authentication.
- SQL Injection Playground sandbox (`backend/app/services/sql_lab_service.py`).
- SQL API integration (`POST /api/sql/run`, `GET /api/sql/scenarios`; legacy public `POST /api/sql/demo`).
- SQL security/red-team audit (`test_sql_lab.py`, `test_sql_lab_redteam.py`).
- SQL Playground frontend (`frontend/src/pages/SQLPlaygroundPage.tsx`).
- Backend Cryptography Lab service (SHA-256/SHA-512, AES-256-GCM, PBKDF2-HMAC-SHA256, base64/hex).
- Browser cryptography engine (`frontend/src/lib/cryptoEngine.ts` + in-repo selftest).
- Dashboard, reports, and workspace pages.

## Next
- **Cryptography Lab UI** (`/cryptography-lab` currently routes to a generic placeholder page).
- Cryptography security/red-team verification and manual/integration testing.

## Planned
- Final crypto security audit.
- Continue core cybersecurity modules as required.
- Documentation/tutorial section explaining how the toolkit works and how to use each module.
- Decide and implement future AI functionality only after the core functionality is stable.
- Professional landing page after the core application is complete.
- Final deployment hardening and deployment.

## Out of Scope Until Core Is Stable
- Trained AI/ML inference for the email detector and log analyzer (modules exist as placeholders; see 11_ML_Architecture.md).