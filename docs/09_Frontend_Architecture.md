# Frontend Architecture

Framework: React + TypeScript

## Main Pages
- Login / Register / Forgot Password (`AuthPage`)
- Dashboard
- Website Scanner
- Email Detector
- Password Analyzer
- Log Analyzer
- SQL Playground (implemented: `SQLPlaygroundPage.tsx`)
- Cryptography Lab (planned UI; `/cryptography-lab` currently routes to a generic placeholder page)
- Reports
- Profile / Settings
- NotFound

## Client Libraries
- `src/lib/cryptoEngine.ts` — browser Web Crypto engine (SHA-256/SHA-512, AES-256-GCM, PBKDF2-SHA256, HMAC-SHA256, base64/hex, secure random). Runs client-side; sensitive crypto material is never sent to the backend.
- `src/lib/cryptoEngine.selftest.ts` — in-repo selftest for the crypto engine.

## State Management
Prefer Context API (`AuthProvider`) initially.
Use reusable components throughout.