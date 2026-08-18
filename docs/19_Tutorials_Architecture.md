# 19 — Tutorials & Cyber Academy Architecture

> Version: 2026-08-18 · Status: design spec for the **planned** Tutorials / Cyber Academy
> documentation system, with every repository-specific claim verified against the source.

This document defines the architecture of the **future** CyberShield AI Tutorials /
Cyber Academy documentation system. It is written before any tutorial UI exists, so it
starts from an accurate, source-verified map of the current application — the tutorials
must teach the tools that actually exist — and then specifies how the education layer will
be structured, stored, and presented.

The final sections are a Stitch mapping guide so the design system can be extracted and
re-applied consistently.

---

## 1. Purpose

The Tutorials / Cyber Academy is a **documentation and education feature**. It exists to
explain, for every CyberShield AI tool:

- **what** the tool does,
- **why** the tool exists (the threat it addresses),
- **how to use it** (step by step),
- **what the input means**,
- **what the output means**,
- **what security concepts** are involved,
- **how the underlying module works** (source-accurate),
- **important security concepts** around the tool,
- **limitations** (what the tool cannot do),
- **common mistakes**,
- **safe and ethical usage**,
- **relevant examples**.

The Tutorials system is **primarily documentation-based**. It is **not** an interactive
attack-training engine, and no heavy "Cyber Academy" engine is planned unless the
repository explicitly grows to support one.

---

## 2. Goals

1. **Teach the real system.** Every tutorial must match the verified behavior of the
   current modules (§5–§8). No fictional capabilities.
2. **Lower the learning curve.** An intern, student, or new analyst can understand any
   tool's purpose, inputs, outputs, and underlying mechanism in a few minutes.
3. **Keep it safe.** Tutorials reinforce the existing safety boundaries: educational,
   non-destructive analysis, sandboxed SQL, browser-local cryptography.
4. **Stay consistent.** Tutorial content reuses the same deterministic content model,
   design tokens, and page structure as the rest of the app (§11, §12).
5. **Be future-proof.** New tools (e.g. real AI/ML features) get tutorial areas when they
   are actually implemented, without re-architecting the content model.

---

## 3. Scope & implementation boundaries

### Implemented today (in the repository)

- All current security tools and their authenticated backends (Website Scanner, Email /
  Phishing Detector, Password Analyzer, Log Analyzer, SQL Playground, Cryptography Lab,
  Reports, Dashboard, Authentication).
- No Tutorials / Cyber Academy page, route, content store, or lesson renderer exists yet.

### Planned (specified by this document, not yet built)

- A tutorials area in the frontend, one tutorial per current tool, plus platform-level
  tutorials (dashboard, authentication/account, future AI/ML).
- A content-storage model and navigation structure for those tutorials.

### Explicitly out of scope

- No interactive attack-training engine.
- No new backend endpoints for "lessons", "progress", or "certificates".
- No modification to the current security tools to fit the tutorials.
- No claims of capabilities that do not exist in the code (see §9 "Source-of-truth rule").

---

## 4. Source-of-truth rule

For every technical claim in this document:

1. Check the source code first.
2. If the source code confirms it, document it.
3. If the source code does not confirm it, mark it as **planned/future** or omit it.
4. Never turn a planned feature into an implemented feature.
5. Never infer an implementation merely from a filename or from older documentation.

---

## 5. The current system (verified source of truth)

### 5.1 Orientation (30 seconds)

```
Browser (React 18 + Vite 5 + Tailwind 3.4, react-router-dom 6)
   │  BrowserRouter (SPA) + Supabase Auth (client-side sign-in)
   ▼
/api (Vite dev proxy → http://localhost:5000)
   │  Bearer <Supabase JWT>
   ▼
Flask app (create_app factory)
   ├─ Middleware: JWT auth decorators, request logging, security headers, JSON error envelope
   ├─ Routes: /api/system, /auth, /dashboard, /scanner, /email, /password, /logs, /crypto, /sql, /reports
   └─ Services: auth, scanner, email, password, log, sql (+ sql_lab), crypto, report, dashboard, pdf_extractor
        │  reads/writes via user-scoped Supabase client (RLS scopes every query to auth.uid())
        ▼
Supabase = PostgreSQL + Auth (auth.users, public.profiles) + Row Level Security + Storage (report-pdfs)
```

High-level flow for a scan:

1. User signs in with Supabase Auth (React). Session token is stored.
2. The page calls an API through `frontend/src/services/apiClient.ts` with
   `Authorization: Bearer <JWT>`.
3. Flask verifies the JWT (`require_auth`), validates the payload, and calls a service.
4. The service performs the **educational, non-destructive** analysis and returns a summary.
5. Summarized results are persisted to the matching `*_scans` table via a **user-scoped**
   Supabase client (never the admin client for user data).
6. The Dashboard aggregates those rows back into metrics, activity, and trend charts.

### 5.2 Verified facts (with evidence)

These statements were confirmed directly from the code during the audit:

| Fact | Evidence |
|---|---|
| Frontend runs on Vite, port **3000**, proxies `/api` → `http://localhost:5000` | `frontend/vite.config.ts` |
| Backend entry point is `app.py` → `create_app()` factory, port **5000** | `backend/app.py`, `backend/app/__init__.py` |
| Frontend uses **BrowserRouter** (SPA), not HashRouter | `frontend/src/main.tsx` |
| Supabase client **throws at import** if `VITE_SUPABASE_URL`/`VITE_SUPABASE_ANON_KEY` are missing | `frontend/src/services/supabaseClient.ts` |
| API uses a consistent JSON envelope `{success, message, data, meta}` / error `{success, error:{code,details}}` | `backend/app/utils/helpers.py` |
| Global error handlers normalize 400/404/405/413/415/500 — no raw stack traces leak | `backend/app/middleware/error_handler.py` |
| Every response gets hardened security headers (nosniff, `X-Frame-Options: DENY`, CSP `default-src 'none'`) | `backend/app/middleware/request_logger.py` |
| Request logs contain **only** method/path/status/duration — never bodies | `backend/app/middleware/request_logger.py` |
| Auth = **Supabase JWT verification** (PyJWT, configurable algorithm/audience/issuer/JWKS); no local password storage | `backend/app/middleware/auth_middleware.py`, `backend/app/utils/security.py` |
| All user-data DB reads/writes use a **user-scoped client** (`get_user_supabase_client`) so RLS scopes to `auth.uid()` | `backend/app/database/` |
| `user_id` always comes from the verified JWT, never from request body/query | `backend/app/services/dashboard_service.py` (header comment) |
| Password/email/log **raw content is never persisted** — only derived artifacts; the password service stores **no hash at all**, only aggregate metrics | `backend/app/services/password_service.py`, `backend/app/services/email_service.py`, `backend/app/services/log_service.py` |
| SQL: the **legacy** public `POST /api/sql/demo` never executes SQL; the **authenticated** lab (`POST /api/sql/run`, `GET /api/sql/scenarios`) executes **fixed SQL templates** against a fresh in-memory SQLite database | `backend/app/services/sql_service.py`, `backend/app/services/sql_lab_service.py`, `backend/app/routes/sql_routes.py` |
| Scanner is a real HTTP client (requests, timeouts, redirect caps) that enforces **no private-IP** scanning and no credential/cookie exfiltration | `backend/app/services/scanner_service.py`, `backend/app/utils/validators.py` |
| The interactive **Cryptography Lab is browser-first**: it runs SHA-256/SHA-512, Base64/Hex, AES-256-GCM, HMAC-SHA256 and CSPRNG via the Web Crypto API and **does not call** `/api/crypto/*`. The backend crypto service (SHA-1/MD5 deprecated, SHA-256/512, AES-256-GCM, PBKDF2-HMAC-SHA256, Base64/Hex) exists and is authenticated but is a separate, unused-by-the-lab surface | `frontend/src/lib/cryptoEngine.ts`, `frontend/src/pages/CryptographyLabPage.tsx`, `backend/app/services/crypto_service.py`, `backend/app/routes/crypto_routes.py` |
| PDF reports are generated in-memory with **ReportLab** and stored via Supabase Storage (private bucket, signed URLs) | `backend/app/reports/pdf_generator.py`, `backend/app/reports/storage.py` |
| Backend test suite collects **910 tests** (pytest) across **20 test files + `conftest.py`**; e.g. `tests/test_scanner.py` alone has 31 tests | `backend/pytest.ini`, `python -m pytest --collect-only` |
| Frontend has **no unit-test framework** — verification is `eslint` (`--max-warnings 0`) + `tsc && vite build` | `frontend/package.json` |
| Design tokens are Material-3-style dark theme defined in Tailwind config (see §12) | `frontend/tailwind.config.js` |
| Runtime inputs are bounded by env-driven limits (email ≤ 50 KB, log ≤ 500 KB, URL ≤ 2048, payload ≤ 1 MB) | `backend/app/config/settings.py`, `backend/app/utils/validators.py` |
| ML models are **placeholders/stubs** (`app/ml/`, `models/*.pkl.placeholder`); the `.pkl` paths are configured but the models are not load-bearing | `backend/app/ml/*`, `backend/app/config/settings.py`, `models/README.md` |
| There is **no DESIGN.md** yet; Stitch integration is greenfield (this document is the starting spec) | repo root scan |
| **No Tutorials / Cyber Academy exists yet** — this document is the design spec (§15) | repo scan (`frontend/src/pages`, `frontend/src/App.tsx`) |

### 5.3 Repository map (current)

```text
CyberShield-AI/
├── frontend/                 # React 18 + TypeScript + Vite 5 SPA
│   ├── src/
│   │   ├── App.tsx           # Route definitions (auth + protected console routes)
│   │   ├── main.tsx          # BrowserRouter + AuthProvider entry
│   │   ├── components/       # AppShell, Sidebar, Topbar, NewScanModal, LoadingStates,
│   │   │                     # EmptyStates, AuthGuards (RequireAuth/RequireGuest), PageHeader, ui
│   │   ├── context/AuthContext.tsx
│   │   ├── pages/            # Dashboard, WebsiteScanner, EmailDetector, PasswordAnalyzer,
│   │   │                     # LogAnalyzer, Reports, SQLPlayground, CryptographyLab,
│   │   │                     # AuthPage, WorkspacePages (Profile/Settings/NotFound), ToolPage
│   │   ├── services/         # apiClient.ts (fetch + Bearer), supabaseClient.ts
│   │   ├── styles/globals.css
│   │   ├── types/            # index.ts (shared interfaces), crypto.ts (crypto engine types)
│   │   ├── utils/cn.ts       # clsx + tailwind-merge
│   │   ├── data/mockData.ts  # deterministic demo fallback + nav data
│   │   ├── data/cryptoContent.ts  # crypto lab module + concept content spec
│   │   └── lib/cryptoEngine.ts    # browser Web Crypto engine (hashing/AES/HMAC/random/encoding)
│   ├── vite.config.ts        # port 3000, /api proxy → :5000
│   ├── tailwind.config.js    # the entire design token system (§12)
│   └── package.json
├── backend/
│   ├── app.py                # entry: load_dotenv → create_app → run(:5000)
│   ├── requirements.txt
│   ├── pytest.ini            # testpaths=tests, pythonpath=., addopts=-q
│   ├── integration_test_{dashboard,me,report_pipeline}.py
│   ├── app/
│   │   ├── __init__.py       # create_app factory (config, CORS, middleware, blueprints)
│   │   ├── config/settings.py
│   │   ├── errors.py         # ApiError hierarchy (ValidationError, ServiceUnavailableError, …)
│   │   ├── database/         # supabase_client.py (3 client factories), schema.sql (SQL + RLS)
│   │   ├── utils/            # helpers.py (envelope), validators.py (bounds, is_private_host),
│   │   │                     # security.py (bcrypt + Supabase JWT verification)
│   │   ├── middleware/       # auth_middleware, error_handler, request_logger
│   │   ├── routes/           # system, auth, dashboard, scanner, email, password, logs, crypto, sql, reports
│   │   ├── services/         # auth, scanner, email, password, log, sql, sql_lab, crypto,
│   │   │                     # report, dashboard, pdf_extractor
│   │   ├── reports/          # pdf_generator.py (ReportLab), storage.py (Supabase Storage)
│   │   ├── models/           # scan_model.py, report_model.py, user_model.py
│   │   ├── ml/               # PhishingDetectorModel, LogAnalyzerModel (placeholders), train_models.py
│   │   └── (blueprints registered in routes/__init__.py under /api)
│   └── tests/                # 910 collected tests, 20 test files + conftest.py
├── docs/                     # 00–19, this architecture doc is #19
├── datasets/                 # emails/, logs/, passwords/, urls/ — each contains a README placeholder only
├── models/                   # .pkl.placeholder files + README (not load-bearing)
├── branding/, assets/        # brand & visual assets
└── prompts/                  # structured AI dev prompts (backend, database, deployment, frontend, ml)
```

---

## 6. Frontend architecture (current)

### 6.1 Boot & routing
- `main.tsx` mounts `<App/>` inside `<BrowserRouter>` with an `AuthProvider`.
- `App.tsx` defines the route groups:
  - Public auth routes (wrapped in `RequireGuest`): `/login`, `/register`, `/forgot-password`.
  - Everything else is wrapped in `RequireAuth` + `AppShell` (persistent sidebar + content):
    `/dashboard`, `/website-scanner`, `/phishing-detector`, `/password-analyzer`,
    `/log-analyzer`, `/sql-playground`, `/cryptography-lab`, `/reports`, `/profile`,
    `/settings`, and `*` → NotFound.
  - `/` redirects to `/dashboard`.
- The shell is a persistent left **Sidebar** with navigation + a `grid-glow` backdrop and
  dark surfaces.

### 6.2 State & data
- **Auth state**: `AuthContext` wraps the Supabase session (sign-in/out, current user). The
  API client attaches the access token to every request.
- **API access**: `services/apiClient.ts` — a thin `fetch` wrapper around `/api` that
  appends `Authorization: Bearer`, parses the envelope, and throws structured
  `ApiClientError`s on failure (`get`, `post`, `postForm`).
- **Demo fallback**: `data/mockData.ts` supplies deterministic sample payloads and the
  navigation data so pages render meaningfully even when the backend is unreachable.

### 6.3 Pages & routes (actual, from `frontend/src/App.tsx`)
| Route | Page | Core interactions |
|---|---|---|
| `/dashboard` | DashboardPage | `GET /api/dashboard`; 4 metric cards, recent scans, activity feed, 12-day trend chart (Chart.js) |
| `/website-scanner` | WebsiteScannerPage | NewScanModal URL input → `POST /api/scanner/website`; per-check statuses + score/grade |
| `/phishing-detector` | EmailDetectorPage | paste email or upload a PDF → `POST /api/email/analyze`; indicators + risk verdict |
| `/password-analyzer` | PasswordAnalyzerPage | `POST /api/password/analyze` (entropy/strength/checklist) + `POST /api/password/generate` (passphrase/random) |
| `/log-analyzer` | LogAnalyzerPage | paste log → `POST /api/logs/analyze`; IP/method/status breakdown, anomalies, threat score |
| `/sql-playground` | SQLPlaygroundPage | `GET /api/sql/scenarios` + `POST /api/sql/run` (in-memory SQLite sandbox, §7.5) |
| `/cryptography-lab` | CryptographyLabPage | browser-only modules: hashing, encoding, AES-256-GCM, HMAC-SHA256, secure randomness (§7.6) |
| `/reports` | ReportsPage | `GET /api/reports`, `POST /api/reports/generate` → PDF + signed URL |
| `/profile` | ProfilePage | static account identity display (demo) |
| `/settings` | SettingsPage | static preference controls (demo) |
| `/login` · `/register` · `/forgot-password` | AuthPage | Supabase sign-in / sign-up / password reset (client-side) |
| `*` | NotFoundPage | 404 |

### 6.4 Shared components
`AppShell`, `Sidebar`, `Topbar`, `NewScanModal`, `LoadingStates`, `EmptyStates`,
`AuthGuards` (`RequireAuth`/`RequireGuest`), `PageHeader`, and small UI atoms in
`components/ui.tsx`. Global CSS classes: `.panel`, `.eyebrow`, `.grid-glow` (§12).

---

## 7. Backend request lifecycle & services

### 7.1 Request lifecycle
1. **Entry**: `python app.py` → `create_app()` in `backend/app/__init__.py`.
2. **Config**: `config/settings.py` reads env (`.env.example` documents every key).
3. **CORS**: `flask_cors` restricted to `/api/*`, origins from `CORS_ORIGINS` env.
4. **Middleware registration**: error handlers → security headers → request logging → blueprints.
5. **Routing**: blueprints mounted under `/api` (`routes/__init__.py`):
   `system`, `auth`, `dashboard`, `scanner`, `email`, `password`, `logs`, `crypto`, `sql`, `reports`.
6. **Auth gate**: protected routes use `@require_auth`; the Supabase JWT is verified
   (algorithm/audience/issuer configurable, JWKS-fetched), and `get_current_user_id()`
   returns the verified `auth.uid()`.
7. **Validation**: `utils/validators.py` enforces payload-size and field bounds; services
   raise `ApiError` subclasses that the error handler renders into the standard envelope.
8. **Service**: performs the analysis (see below). For scans, results are summarized, then
   written through `database/supabase_client.py::get_user_supabase_client(token)` — RLS
   scopes every row to `auth.uid()`.
9. **Response**: `success_response(data, message)` → JSON envelope.

### 7.2 Scanner — `services/scanner_service.py`
`ScannerService.scan_website(url)`:
- URL must be `http`/`https`; redirect cap, request timeout, max response size enforced.
- **Private/loopback/link-local/reserved address rejection** (via `utils/validators.py::is_private_host`)
  unless explicitly allowed — prevents SSRF against internal networks.
- Checks: HTTPS enforcement, TLS certificate validity, **6 security headers**
  (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`), cookie flags (`Secure`,
  `HttpOnly`, `SameSite`), CORS posture, information disclosure (`Server`/`X-Powered-By`),
  and response status/size warnings.
- Output: `checks[]` (name/status passed|warning|failed|info/detail/recommendation), a
  weighted `score` (0–100), `grade` (A–F), `risk_level`, `summary`. All non-destructive.
- Only completed (reachable) scans are persisted to `website_scans`.

### 7.3 Email / Phishing Detector — `services/email_service.py`
`EmailService.analyze_email(content)`:
- Accepts pasted text or text extracted from an uploaded PDF (`services/pdf_extractor.py`,
  `pypdf`; no OCR — image-only PDFs are rejected).
- Runs deterministic heuristic checks (urgency language, credential requests, generic
  greetings, spam-style calls to action, embedded links, suspicious TLDs, punctuation /
  capitalization), producing indicators, a `risk_score` (0–100), `risk_level`
  (safe/suspicious/phishing), `confidence`, and an `analyzer` id.
- The `app/ml/PhishingDetectorModel` is a **placeholder**; today's analysis is fully
  rule-based.
- Persists only a summary row to `email_scans` (subject, sender, label, confidence,
  indicators); **raw email content is never persisted**.

### 7.4 Password Analyzer — `services/password_service.py`
`PasswordService.analyze_password(password)`:
- Computes length, character classes, pool-based entropy (bits), crack-time category,
  `in_common_list`, a 0–100 `strength_score`, `strength` label, prioritized
  `recommendations`, structured `weaknesses`, a `score_breakdown`, and a `security_checklist`.
- Common-password detection uses **inline sets** (`COMMON_WEAK_PASSWORDS`, dictionary-word
  heuristics) — **not** a bundled file dataset. `datasets/passwords/` contains only a
  README placeholder and is not loaded by the service.
- Persists only derived metrics to `password_scans` (length, entropy, score, label,
  character flags, `breached` = matches the inline common list). **Neither the plaintext
  password nor any password hash is ever persisted.**
- `PasswordGenerator.generate_passphrase` / `generate_random_password` (`POST /api/password/generate`)
  use `secrets.SystemRandom` for CSPRNG-based generation.

### 7.5 SQL Playground — `services/sql_service.py` + `services/sql_lab_service.py`
Two distinct surfaces:

1. **Legacy demo (public, non-executing)** — `POST /api/sql/demo`,
   `SQLPlaygroundService.run_demo(input)`: **no SQL executes and no database is ever
   connected**. It renders an "unsafe" concatenated query string vs. a parameterized
   version and reports which SQL metacharacter patterns the input triggered. Purely
   illustrative.

2. **Authenticated educational lab** — `POST /api/sql/run` + `GET /api/sql/scenarios`,
   `SQLLabService.run_scenario(scenario_id, payload)`:
   - The caller supplies **only** `scenario` (allowlisted) + `payload` (≤ 2048 chars).
   - Every call opens a **fresh, isolated** `sqlite3.connect(":memory:")` database,
     seeded with fixed demo tables (`users`, `products`, `orders`), and closes it on exit.
   - Each run executes two paths: the fixed **vulnerable** template (payload interpolated)
     and the **secure** template (payload bound via parameters), so students see injection
     succeed and parameterization neutralize it.
   - Scenarios: `login` (auth bypass), `union` (UNION-based extraction), `boolean`
     (blind boolean-based), `comment` (comment-based filter bypass).
   - Sandbox controls: fixed scenario allowlist; fresh in-memory DB per call; connection
     isolation; a sqlite authorizer (SELECT on the demo tables only, **deny** writes/DDL,
     `ATTACH`/`DETACH`, `PRAGMA`, `load_extension`); a progress handler (work budget
     `SQL_MAX_STEPS = 100_000`); row limits (`SQL_MAX_RESULT_ROWS = 100`); engine-level
     cell-size limits (`SQLITE_LIMIT_LENGTH`, 1 MB); sanitized generic rejection messages;
     JSON-safe bounded result cells; no persistence; no PostgreSQL; no Supabase; no
     network; and **no arbitrary-SQL entry point** (`run_sql`/`query` deliberately absent).

### 7.6 Cryptography Lab — browser engine + backend service
- **Frontend (browser-first)**: `frontend/src/lib/cryptoEngine.ts` implements the
  interactive lab using the **Web Crypto API**:
  - SHA-256, SHA-512 (hashing, with an avalanche-effect comparison),
  - Base64 and Hex (encode/decode — "encoding is not encryption"),
  - AES-256-GCM (256-bit key derived from a passphrase via PBKDF2-HMAC-SHA256,
    600,000 iterations; fresh 16-byte salt + 12-byte nonce; 128-bit authentication tag),
  - HMAC-SHA256 (sign/verify + CSPRNG key generation),
  - secure randomness via `crypto.getRandomValues()`.
  - `CryptographyLabPage.tsx` renders these modules from `data/cryptoContent.ts`
    (module + concept content). Everything runs **locally**; plaintext, passphrases, and
    keys never leave the browser, and the page **does not call `/api/crypto/*`**.
- **Backend**: `services/crypto_service.py` exposes an **authenticated, separate** API
  surface (`POST /api/crypto/{hash,encrypt,decrypt,encode,decode}`, all `@require_auth`):
  - `hash_text`: MD5, SHA-1 (both flagged deprecated/educational), SHA-256, SHA-512.
  - `encrypt_text`/`decrypt_text`: AES-256-GCM with PBKDF2-HMAC-SHA256 (600,000
    iterations).
  - `encode`/`decode`: Base64, Hex.
  - Inputs capped at `CRYPTO_MAX_INPUT_LENGTH` (default 100,000).
  - The interactive lab does **not** use these endpoints; they are documented as the
    authenticated programmatic surface.

### 7.7 Reports — `services/report_service.py` + `reports/`
- `ReportService.generate_report(config, user_id)` reads the user's most recent scan from
  each of the four `*_scans` tables, builds a JSON-serializable snapshot, renders a PDF
  **in-memory with ReportLab** (`reports/pdf_generator.py`), uploads it to the **private**
  `report-pdfs` Supabase Storage bucket (`reports/storage.py`, `ReportStorageService`),
  and inserts a `public.reports` row. Access is only ever via **signed URLs**; the bucket
  is never public and `get_public_url` is never used. Object keys are namespaced
  `<user_id>/<report_id>.pdf` with traversal protection.
- `ReportService.list_reports(user_id)` lists the user's reports with a freshly signed URL
  per row.
- Route surface: `GET /api/reports`, `POST /api/reports/generate` (both authenticated).

### 7.8 Dashboard — `services/dashboard_service.py`
`DashboardService.get_dashboard(user_id)` aggregates the four `*_scans` tables + `reports`:
- `security_score` (avg of website scans), `scans_completed` (total + this week),
  `threats_detected` (risk-level-based per table type), `assets_monitored` (distinct targets).
- `recent_scans`, `activity`, and a 12-day `trend` (UTC, includes zero days).

### 7.9 Auth — `services/auth_service.py` + `routes/auth_routes.py`
- Supabase Auth owns sign-up, sign-in, sessions, and password hashing; React calls Supabase
  Auth directly. The Flask API exposes only `GET /api/auth/me`
  (`AuthService.get_profile`), which reads `public.profiles` keyed off the verified JWT
  `sub` claim through the user-scoped client.

---

## 8. Database schema (from `backend/app/database/schema.sql` + services)

| Table | Purpose | Key columns |
|---|---|---|
| `auth.users` | Supabase-managed identities | `id`, email, metadata |
| `public.profiles` | 1:1 user profile | `id → auth.users.id`, `full_name`, `role`, timestamps |
| `public.website_scans` | scanner results | `user_id`, `target_url`, `security_score`, `risk_level`, `findings` |
| `public.email_scans` | email analysis | `user_id`, `subject`, `sender_email`, `predicted_label`, `confidence`, `risk_level`, `indicators` |
| `public.password_scans` | password analysis | `user_id`, `password_length`, `entropy`, `strength_score`, `strength_label`, char flags, `breached` |
| `public.log_scans` | log analysis | `user_id`, `event_count`, `anomaly_count`, `findings`, `risk_level` |
| `public.reports` | generated audit reports | `user_id`, `title`, `report_type`, `storage_path`, `report_data` |

RLS policies scope every table to `auth.uid()`. Raw sensitive inputs (email text, log
lines, plaintext passwords, password hashes) are never stored.

---

## 9. Security model (defense in depth)

1. **Transport**: HTTPS everywhere in prod; hardened response headers on every Flask response.
2. **AuthN/Z**: Supabase Auth + server-side JWT verification; RLS per user; JWT-derived
   identity only.
3. **Input safety**: payload limit (1 MB), per-feature length caps,
   `check_payload_size_limit`.
4. **SSRF guard**: the scanner rejects private/loopback/link-local/reserved targets by default.
5. **No data exfiltration**: the scanner does not send credentials; report and scan payloads
   are summarized; raw email/log content and plaintext passwords (and password hashes) are
   never persisted.
6. **No secret leakage**: 500s are logged server-side, clients get a generic envelope;
   request logs exclude bodies; `.env` files are gitignored.
7. **SQL sandbox**: the authenticated lab executes only fixed templates inside an isolated,
   fresh in-memory SQLite DB under an authorizer + progress handler + size caps with no
   arbitrary-SQL entry point. The legacy public demo never executes SQL at all.
8. **CSP**: `default-src 'none'; frame-ancestors 'none'` on API responses (the browser SPA
   is served via the Vite proxy with its own headers).
9. **Cryptography**: the interactive lab runs client-side only (Web Crypto) so no secret
   material transits the API; the backend crypto endpoints are authenticated and
   size-bounded.

---

## 10. Testing strategy

- **Backend**: pytest (`backend/pytest.ini`: `testpaths=tests`, `pythonpath=.`).
  **910 tests collected across 20 test files + `conftest.py`.** Example coverage:
  `tests/test_scanner.py` (31 tests), plus dedicated suites for email, password, logs,
  SQL playground + SQL lab red-team, crypto, reports, report storage, dashboard, auth,
  route auth, RLS scoping, supabase client/JWT, validators, security utils, error
  handling, and health. Standalone integration scripts: `integration_test_dashboard.py`,
  `integration_test_me.py`, `integration_test_report_pipeline.py`.
- **Frontend**: no unit-test framework. Quality gates are `npm run lint` (eslint,
  `--max-warnings 0`) and `npm run build` (`tsc && vite build`).
- **Verification commands**: see §16.

---

## 11. Content representation & determinism (tool contract)

These rules keep screenshots, exports, and Stitch regeneration **deterministic**:

1. **No client-side markdown rendering.** There is no `react-markdown` dependency and none
   should be added. All content is structured JSON/TSX/React elements (`types/index.ts`,
   `types/crypto.ts`, `data/mockData.ts`, crypto spec in `data/cryptoContent.ts`).
2. **Single source of demo content** is `mockData.ts`; it is deterministic (no
   timestamps/randoms that change output between runs).
3. **Canonical page structure** is defined by the page components + their props/type contracts.
4. **Tokens only**: colors/fonts/radii must come from `tailwind.config.js` — never ad-hoc hex.
5. **Two-surface theme only**: the app is dark-only (`darkMode: 'class'`, one palette). No
   theme-dependent content swaps.
6. **Data-shape contract**: backend responses always use the envelope from §7.1; pages read
   `.data`, never raw internals.

**Consequence for the Tutorials system**: tutorial content must follow the same model —
structured content (like `data/cryptoContent.ts`) rendered by React components, not a new
markdown-rendering dependency.

---

## 12. Visual & design specification (the token system)

Extracted verbatim from `frontend/tailwind.config.js` + `frontend/src/styles/globals.css`.

### Colors (dark, Material-3 style)
| Token | Hex |
|---|---|
| `background`, `surface` | `#13131b` |
| `surface-lowest` | `#0d0d15` |
| `surface-low` | `#1b1b23` |
| `surface-container` | `#1f1f27` |
| `surface-high` | `#292932` |
| `surface-bright` | `#393841` |
| `on-surface` | `#e4e1ed` |
| `on-surface-variant` | `#c7c4d7` |
| `outline` | `#908fa0` |
| `outline-variant` | `#464554` |
| `primary` (DEFAULT) | `#c0c1ff` |
| `primary-container` | `#8083ff` |
| `primary-foreground` | `#1000a9` |
| `secondary` | `#89ceff` |
| `success` | `#72dfa5` |
| `danger` | `#ffb4ab` |
| `warning` | `#ffb783` |

### Typography
- `font-display`: **Geist** (headings, display) — loaded from Google Fonts.
- `font-body`: **Inter** (body, labels).
- `font-mono`: **JetBrains Mono** (code, eyebrows, technical readouts).

### Shape & effects
- Radius: `0.25rem` default (controls), `0.5rem` `lg` (panels/cards), `0.75rem` `xl`.
- `.panel`: `rounded-lg border bg-surface-container` — the canonical container.
- `.eyebrow`: mono, `10–11px`, uppercase, `letter-spacing 0.16em`, `on-surface-variant`.
- `.grid-glow`: 32×32px grid of `rgba(192,193,255,0.035)` lines — the signature backdrop.
- Layout: persistent left sidebar + content column; metric cards up top on the Dashboard.

---

## 13. Stitch mapping guide

When extracting the design into Stitch (or regenerating screens from it), use this mapping:

| Stitch concept | CyberShield value |
|---|---|
| `colorMode` | `DARK` |
| `customColor` (seed) | `#c0c1ff` (primary) |
| `overridePrimaryColor` | `#c0c1ff` |
| `overrideSecondaryColor` | `#89ceff` |
| `overrideNeutralColor` | `#13131b` (background/surface seed) |
| `headlineFont` | `GEIST` |
| `bodyFont` | `INTER` |
| `labelFont` | `INTER` |
| mono usage (eyebrows/code) | JetBrains Mono via designMd note |
| `roundness` | `ROUND_EIGHT` (cards `0.5rem` dominate; note 4px controls in designMd) |
| Screens | Dashboard, WebsiteScanner, EmailDetector, PasswordAnalyzer, LogAnalyzer, Reports, SQLPlayground, CryptographyLab, Auth (+ planned Tutorials screens when built) |
| `deviceType` | `DESKTOP` (dashboard/tools), `AGNOSTIC` where width-independent |
| Design MD | This document §11–§12 (determinism contract + token table) is the source of truth |

Suggested workflow: create the Stitch design system with the theme above (or upload a
`DESIGN.md` generated from this section), then generate/edit screens by prompting with the
exact token names (`surface-container`, `primary`, `.eyebrow`, `.grid-glow`) to guarantee
byte-identical palettes, fonts, and radii.

---

## 14. Tutorials system architecture (planned)

### 14.1 What it is (and is not)

- **Is**: a documentation/education layer that explains each real CyberShield AI tool, its
  inputs/outputs, the security concepts behind it, how the underlying module works, its
  limitations, common mistakes, and safe/ethical use.
- **Is not**: an interactive attack-training engine, a gamified "Academy" with progress
  tracking, or a set of new backend lesson/progress endpoints. Those are out of scope
  unless the repository explicitly grows to support them.

### 14.2 Tutorial areas (mapped to actual modules)

Each area maps 1:1 to an existing tool/service so every statement can be verified:

| # | Tutorial area | Backs on | Backend service / module |
|---|---|---|---|
| 1 | Website Scanner | `/website-scanner` | `services/scanner_service.py` |
| 2 | Email / Phishing Detector | `/phishing-detector` | `services/email_service.py`, `services/pdf_extractor.py` |
| 3 | Password Analyzer | `/password-analyzer` | `services/password_service.py` |
| 4 | Log Analyzer | `/log-analyzer` | `services/log_service.py` |
| 5 | Reports | `/reports` | `services/report_service.py`, `reports/` |
| 6 | Cryptography Lab | `/cryptography-lab` | `lib/cryptoEngine.ts`, `data/cryptoContent.ts`, `services/crypto_service.py` |
| 7 | SQL Playground | `/sql-playground` | `services/sql_lab_service.py`, `services/sql_service.py` |
| 8 | Dashboard | `/dashboard` | `services/dashboard_service.py` |
| 9 | Authentication / account | `/login`, `/register`, `/forgot-password`, `/profile`, `/settings` | Supabase Auth, `services/auth_service.py` |
| 10 | AI/ML functionality | (none yet) | `app/ml/*` — only when actually implemented |

### 14.3 Content structure of a tutorial

Every tutorial is a structured lesson following a single template:

1. **Overview** — what the tool does and why it exists.
2. **When to use it** — realistic scenarios and safe/ethical boundaries.
3. **How to use it** — step-by-step walkthrough of the actual UI.
4. **Inputs** — what each field means and its limits (e.g. email ≤ 50 KB, log ≤ 500 KB,
   URL ≤ 2048 chars, SQL payload ≤ 2048 chars).
5. **Outputs** — what each result section means (e.g. check statuses, risk levels, scores,
   confidence, threat score, signed report URLs).
6. **How the module works** — the real service/engine behavior (verified, source-accurate).
7. **Security concepts** — the principles the tool demonstrates.
8. **Limitations** — what the tool cannot do (e.g. ML is placeholder; the crypto lab is
   browser-local; the SQL lab only runs fixed templates; password checks use an inline
   common-password list, not a breach dataset).
9. **Common mistakes** — how students misuse the tool or misread results.
10. **Safe & ethical usage** — authorization, no scanning of systems you don't own, no real
    secrets in the labs, no persisting of sensitive input.
11. **Examples** — deterministic sample inputs with expected outputs.

### 14.4 Information architecture & navigation model (planned)

- Proposed routes (not implemented):
  - `/tutorials` — index of all tutorial areas.
  - `/tutorials/:area` — one tutorial area (e.g. `/tutorials/website-scanner`).
  - `/tutorials/:area/:lesson` — an individual lesson within an area.
- The Tutorials area sits inside the existing authenticated `AppShell` (sidebar + content)
  and inherits `RequireAuth`, the same `PageHeader` pattern, and the shared token classes.
- A sidebar entry (or a sub-navigation within the Tutorials page) mirrors the ten areas in
  §14.2. Navigation data is added to `data/mockData.ts` so the shell, screenshots, and
  Stitch regeneration stay deterministic.

### 14.5 Content storage strategy (planned)

- Tutorial content is **structured data**, not a new markdown pipeline. Follow the
  `data/cryptoContent.ts` precedent: typed content modules (`types/tutorials.ts` +
  `data/tutorialContent.ts`) rendered by dedicated React components.
- This preserves the §11 determinism contract (no `react-markdown`, no server-rendered
  lesson content, no timestamps/randomness).
- The content lives in the frontend as code-owned data; no new backend tables or endpoints
  are introduced for tutorials.

### 14.6 Frontend architecture for tutorials (planned)

- New page components under `frontend/src/pages/tutorials/` (e.g. `TutorialsIndexPage`,
  `TutorialAreaPage`, `TutorialLessonPage`), plus a small set of reusable lesson-rendering
  components (`components/tutorials/`) that render the structured lesson sections in §14.3.
- Routes added in `App.tsx` inside the protected console group.
- Design: reuse `.eyebrow`, `.panel`/`Card`, `PageHeader`, token colors/fonts only — no
  new ad-hoc styling.
- Accessibility: semantic headings, focus-visible rings, contrast-safe tokens, keyboard
  navigable content, `aria` labels (mirroring existing page patterns).
- Responsive: the same column/grid utilities already used across the app (mobile-first,
  stacked on small screens, side-by-side panels at `lg`/`xl`).

### 14.7 Relationship with existing tools

- Each tutorial references the live page it teaches (e.g. "open `/cryptography-lab` and
  try…"), so the tutorial is a guided companion rather than a static substitute.
- Any statement about behavior must remain verifiable against the modules in §7 — if the
  tool changes, the tutorial changes with it.

### 14.8 Security considerations

- Tutorials never encourage unauthorized testing: the scanner is for your own/authorized
  sites, the SQL lab only runs inside the isolated in-memory sandbox, and the crypto lab
  keeps secrets in the browser.
- Tutorial copy must not claim capabilities that don't exist (no "breach database lookup",
  no arbitrary SQL execution, no RSA/ChaCha20, no model-backed AI yet).
- No lesson content is ever user-generated at runtime; content is code-owned and static.

### 14.9 Accessibility

- AA contrast (existing on-surface/on-surface-variant tokens), semantic document order,
  descriptive links/headings, reduced-motion respect for any transitions, and
  screen-reader-safe structure for the lesson components.

### 14.10 Responsive design

- Tutorial index: responsive card grid. Lesson pages: single reading column on mobile,
  optional two-column (content + concepts) on wide screens — matching existing page
  patterns.

### 14.11 Future extensibility

- New tools get a new entry in the §14.2 table + a `tutorialContent.ts` module when they
  are implemented. The content model is the extension point, not new infrastructure.
- If the repository later adds a real ML-backed analyzer (replacing the placeholders in
  `app/ml/`), area #10 becomes implementable and must describe the actual model behavior.

### 14.12 Implementation plan (phases)

1. **Phase A — content model**: add `types/tutorials.ts` + `data/tutorialContent.ts`
   covering all ten areas from verified §7 module behavior. No UI yet.
2. **Phase B — navigation & pages**: add `/tutorials`, `/tutorials/:area`,
   `/tutorials/:area/:lesson` inside the protected shell; render the structured content.
3. **Phase C — polish**: accessibility pass, responsive tuning, Stitch screen generation
   from the §13 design system, and cross-linking tutorials ↔ live tools.

---

## 15. Known gaps & discrepancies (verified)

1. **README vs deployment**: `README.md` advertises Vercel/Render; `docs/13_Deployment_Guide.md`
   and repo configs describe nginx + gunicorn on a VPS. `docs/13` is authoritative.
2. **ML is placeholder**: `app/ml/` classes and `models/*.pkl.placeholder` are stubs;
   README "AI" copy overstates the current implementation. The rule-based analyzers are the
   real engine today.
3. **Frontend test coverage is zero**: 910 backend tests but no frontend unit tests; only
   eslint + `tsc` build gates.
4. **No DESIGN.md / Stitch asset exists yet** — §13 is the blueprint for adding it.
5. **Some older docs (00/04/12)** describe aspirational features not yet in code (e.g. parts
   of the ML/roadmap claims). Cross-check anything critical against the code + this doc.
6. **Tutorials / Cyber Academy is not implemented** — §14 is the design spec; nothing under
   it exists in the repository yet.

---

## 16. Command cheat-sheet

```bash
# Backend
cd backend
.\venv\Scripts\activate
python app.py                                   # dev server :5000
python -m pytest -q                             # full suite (910 tests)
python -m pytest tests/test_scanner.py -q       # scanner suite (31 tests)
python -m pytest tests/test_sql_lab_redteam.py -q   # SQL sandbox red-team suite
python integration_test_dashboard.py            # manual e2e checks

# Frontend
cd frontend
npm install
npm run dev                                     # dev server :3000 (proxies /api)
npm run lint                                    # eslint, 0 warnings allowed
npm run build                                   # tsc && vite build

# Health
curl http://localhost:5000/api/system/health
```
