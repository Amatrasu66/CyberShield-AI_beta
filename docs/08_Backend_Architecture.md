# Backend Architecture

Framework: Flask

## Layers
- Routes
- Middleware (JWT verification)
- Services
- ML Inference (placeholders; no model loaded at runtime)
- Database
- Utilities

## Responsibilities
- Validate requests
- Verify Supabase Auth JWTs on protected endpoints
- Extract the user ID from the token (sub claim = `auth.uid()`)
- Run business logic scoped to the authenticated user
- Call ML models (planned; placeholders only today)
- Store results via RLS-preserving access; use service-role credentials only for elevated operations
- Run isolated sandboxes (SQL Playground in-memory SQLite; Cryptography Lab operates without persistence)
- Return JSON responses
