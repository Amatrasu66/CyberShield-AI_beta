# System Architecture

```text
React (Vercel)
      |
 REST API
      |
Flask (Render)
   |        |
Supabase   ML Models
```

## Data Flow
1. User submits data.
2. Flask validates request.
3. Business logic executes.
4. Optional ML prediction (planned; not yet implemented).
5. Result stored in Supabase.
6. Response returned to frontend.

## Isolated Components
- The SQL Injection Playground is an isolated educational sandbox: it runs fixed
  scenario templates against a fresh in-memory `sqlite3 ":memory:"` database per
  request and never touches Supabase, PostgreSQL, or the network. No SQL from
  the playground is ever executed against the production database.
- The browser cryptography engine runs client-side (Web Crypto API) and does not
  send plaintext, passphrases, or keys to the backend.
