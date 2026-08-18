# Tech Stack

## Frontend
- React
- TypeScript
- Tailwind CSS
- Vite
- Chart.js (~installed dependency)
- Web Crypto API (browser cryptography engine for the Cryptography Lab: SHA-256/SHA-512, AES-256-GCM, PBKDF2-SHA256, HMAC-SHA256, base64/hex, secure random). The lab is browser-first and runs entirely client-side; the interactive UI does not call the backend crypto API.

## Backend
- Python
- Flask
- cryptography (PyPI): AES-256-GCM, PBKDF2-HMAC-SHA256 (backend crypto endpoints are authenticated)
- hashlib (stdlib): SHA-256, SHA-512, SHA-1, MD5
- sqlite3 (stdlib): isolated in-memory sandbox for the SQL Playground

## Machine Learning (planned)
- Scikit-learn
- Pandas
- NumPy
- Joblib
- Inference modules exist as placeholders; no model is loaded at runtime today.

## Database
- Supabase (PostgreSQL)

## Deployment
- Vercel
- Render

## Tools
- GitHub
- Google Colab
- VS Code