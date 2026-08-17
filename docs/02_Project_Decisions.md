# Project Decisions

| Area | Decision |
|------|----------|
| Frontend | React + TypeScript + Tailwind CSS |
| Backend | Flask |
| Database | Supabase (PostgreSQL) |
| Authentication | Supabase Auth (auth.users) |
| App user data | public.profiles linked 1:1 to auth.users.id |
| Session model | Supabase Auth JWTs; React holds the session |
| API auth | Flask verifies Supabase Auth JWTs from the access token |
| DB access | RLS with auth.uid() for user-scoped access; service-role credentials server-only |
| AI | Scikit-learn (inference planned; ML modules are placeholders) |
| SQL Playground | Isolated in-memory SQLite sandbox; no production database, no PostgreSQL, no network |
| Cryptography backend | AES-256-GCM, PBKDF2-HMAC-SHA256, SHA-256/SHA-512 (SHA-1/MD5 for education only), base64/hex |
| Cryptography frontend | Browser Web Crypto API; sensitive material never sent to the backend |
| Deployment | Vercel + Render |
| Version Control | GitHub |

## Guiding Principles
- Modular code
- AI only where it adds value
- Security-first design
- Documentation-driven development
