# Backend Architecture

Framework: Flask

## Layers
- Routes
- Auth (JWT verification)
- Services
- ML Inference
- Database
- Utilities

## Responsibilities
- Validate requests
- Verify Supabase Auth JWTs on protected endpoints
- Extract the user ID from the token (sub claim = `auth.uid()`)
- Run business logic scoped to the authenticated user
- Call ML models
- Store results via RLS-preserving access; use service-role credentials only for elevated operations
- Return JSON responses
