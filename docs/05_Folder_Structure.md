# Folder Structure

```text
CyberShield-AI/
├── frontend/
├── backend/
├── docs/
├── datasets/
├── models/
├── assets/
├── prompts/
└── branding/
```

## Frontend (`frontend/`)
- React + TypeScript + Tailwind CSS + Vite
- `src/components/` — reusable UI components
- `src/pages/` — route pages (Dashboard, WebsiteScanner, EmailDetector, PasswordAnalyzer, LogAnalyzer, SQLPlayground, CryptographyLab, Reports, Workspace pages, Auth)
- `src/lib/` — client libraries, incl. `cryptoEngine.ts` and `cryptoEngine.selftest.ts` (Web Crypto engine)
- `src/types/` — TypeScript interfaces, incl. `crypto.ts`
- `src/context/` — React context (AuthProvider)
- `src/services/` — API client code

## Backend (`backend/`)
- Flask application factory
- `app/routes/` — blueprints (auth, dashboard, scanner, email, password, logs, crypto, sql, reports, system)
- `app/services/` — business logic (incl. `sql_lab_service.py`, `crypto_service.py`)
- `app/ml/` — ML inference modules (placeholders; no model loaded at runtime)
- `app/middleware/` — JWT authentication middleware
- `app/utils/` — helpers, validators, security utilities
- `app/config/` — configuration
- `tests/` — pytest suite (910 collected tests)

## Database
- Supabase (PostgreSQL); the SQL Playground uses a transient in-memory SQLite sandbox instead of the production database.

## Reports
- Generated PDFs stored in a private Supabase Storage bucket.