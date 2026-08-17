# AI Agent Rules

## Purpose
This document defines mandatory rules for AI coding agents (Google Antigravity, Stitch, etc.).

## Mandatory Rules
- Never change the project architecture.
- Never replace Flask with another backend framework.
- Always use React + TypeScript + Tailwind CSS.
- Always use Supabase as the database.
- Never hardcode secrets or API keys.
- Read all documentation in the /docs directory before generating code.
- Generate modular, maintainable code.
- Keep business logic separate from UI.
- Do not introduce additional libraries unless necessary.
- Follow API contracts exactly.
- Do not rename files or folders without explicit approval.
- Derive implementation status from the actual repository; never document
  planned features as implemented and never claim untested capabilities.
- Do not rebuild the SQL Playground as a PostgreSQL/Supabase live-execution
  console: it is an isolated in-memory SQLite educational sandbox, and its
  documented isolation constraints must be preserved.
- Do not introduce persistence for cryptography plaintext, passphrases, keys,
  ciphertext, salts, nonces, or HMAC keys.
- Do not mark the email detector or log analyzer as AI/ML-powered: they use
  deterministic heuristics/rules today, with ML inference planned. AI training
  is not implemented.
