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
