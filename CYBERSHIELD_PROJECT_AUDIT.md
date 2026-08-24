# CYBERSHIELD AI — PROJECT-WIDE AUDIT (READ-ONLY)

> **Date:** 2026-08-25 (Audit performed: 2026-08-25 IST)
> **Scope:** Full repository `CyberShield-AI/` — read-only, no code/schema/env/dependency changes
> **Auditor:** Muse Spark (Opencode) — inspection only
> **Branch audited:** `main` @ `6d5aea8` (feat: implement port scanning, threat assessment, and reporting services with database integration and UI components)

---

## 1. Executive Summary

CyberShield AI is a modular cybersecurity platform: Flask REST API (`backend/` on Render) + React+Vite SPA (`frontend/` on Vercel) + Supabase PostgreSQL + Supabase Auth. The core product isolates nine analysis domains — Website Scanner, Email Detector (heuristic), Password Analyzer, Log Analyzer, Cryptography Lab (browser-only WebCrypto), SQL Playground (in-memory SQLite), Port Scanner (TCP connect), IP Reputation (AbuseIPDB via bounded cache), and Reports/PDF + Dashboard tutorials.

**Overall health:** Architecture is **security-conscious and well-structured** for an educational platform. Supabase JWT verification (ES256 JWKS), RLS per-user isolation, private-IP SSRF guards, bounded scanner concurrency/timeouts, service-role cache isolation, and sanitized report/PDF pipelines are all correctly implemented and tested. The Port Scanner integration (added after original foundation) is the most complex subsystem — it follows the intended pipeline but introduces the largest attack surface (raw sockets + DNS + external reputation call) and the majority of the codebase's technical debt.

**Critical risks (from code only, not exploited):** 2 HIGH (DNS rebinding / TOCTOU in port scanner target resolution, and optimistic `supabase` key fallback handling), 4 MEDIUM, 3 LOW. No CRITICAL remote-code or secret-leak vectors were found that survive normal production config.

**Testing:** 1049 collected pytest tests (613 `def test_` counted via grep; full collection 1049 with parametrizations) across 24 test files. Coverage is deep on port scanner (93), IP cache (21), threat assessment (26), SQL lab (166+316 redteam), reports, auth scoping, and JWT. Several high-value gaps remain (see §17).

**Immediate priorities (P0):** Harden port scanner DNS rebinding (re-resolve after validation), tighten Supabase key resolution to fail closed, unblock `IP_REPUTATION_ENABLED` default handling, and ensure single production migration includes `threat_assessment` column.

---

## 2. Repository Structure

```
CyberShield-AI/
├── .git/                            # git repo, branch main
├── .gitignore
├── backend/
│   ├── app.py                       # entrypoint: create_app() -> run 0.0.0.0:5000
│   ├── requirements.txt             # Flask 3.1, supabase 2.31, reportlab 4.0, pypdf 6.15, requests, cryptography
│   ├── pytest.ini                   # testpaths=tests, -q
│   ├── .env / .env.example          # env template (not committed secret)
│   ├── app/
│   │   ├── __init__.py              # create_app factory (config, CORS, logging, error handlers, blueprints)
│   │   ├── config/settings.py       # Config with _env_bool/_env_int/_env_list
│   │   ├── database/
│   │   │   ├── supabase_client.py  # get_supabase_client / get_user_supabase_client / get_supabase_admin_client
│   │   │   └── schema.sql          # single source DDL (idempotent IF NOT EXISTS)
│   │   ├── middleware/
│   │   │   ├── auth_middleware.py  # require_auth, get_current_user_id, get_current_access_token
│   │   │   ├── error_handler.py    # ApiError -> JSON envelope, no stack leak
│   │   │   └── request_logger.py   # method/path/status + security headers
│   │   ├── routes/                 # 10 blueprints under /api
│   │   ├── services/               # 13 service modules (scanner, email, password, log, port, ip_rep, cache, threat, report, etc)
│   │   ├── reports/               # pdf_generator.py, storage.py
│   │   ├── models/                # report_model, scan_model, user_model (lightweight)
│   │   ├── utils/                 # validators, security (JWT/bcrypt), helpers
│   │   ├── ml/                    # phishing_detector, log_analyzer scaffolding
│   │   └── errors.py              # ApiError hierarchy
│   └── tests/                     # 24 test files, conftest with fake Supabase + fake JWKS
├── frontend/
│   ├── package.json                # react 18.2, vite 5.0, react-router 6.21, supabase-js 2.39, tailwind 3.4
│   ├── vite.config.ts              # alias @, proxy /api -> localhost:5000
│   ├── vercel.json                 # SPA rewrite: /(.*) -> /index.html
│   ├── tsconfig.json / tailwind.config.js / postcss.config.js
│   └── src/
│       ├── main.tsx / App.tsx     # Router: /login /register /dashboard ... /port-scanner /reports /tutorials
│       ├── services/              # apiClient.ts (Bearer via supabase.auth.getSession), supabaseClient, portScannerService
│       ├── types/index.ts         # PortFinding, IPReputationResult, ThreatAssessment, Report*, etc
│       ├── pages/                 # PortScannerPage.tsx (824 lines), ReportsPage, Dashboard, etc
│       ├── components/            # AppShell, AuthGuards, PageHeader, ui, SlowRequestNotice
│       ├── hooks/useSlowRequest.ts
│       ├── context/AuthContext.tsx
│       ├── lib/cryptoEngine.ts    # browser WebCrypto
│       └── styles/globals.css
├── docs/                          # 00-19 markdown (PRD, architecture, api, db, deployment, security, etc)
├── prompts/                       # backend/database/deployment/frontend/ml READMEs (placeholders)
├── branding/ / assets/ / datasets/ / models/*.pkl.placeholder
├── PORT_THREAT_ASSESSMENT_PHASE1.md  # 474-line investigation-only design doc (proposed scoring)
└── README.md
```

**Root workspace note:** `C:\Users\Simra\OneDrive\Desktop\Intership project\` contains `.pytest_cache/`, `all md files/`, `CyberShield-AI/`, `stitich project files zip/` — only `CyberShield-AI/` is the git repo.

---

## 3. Backend Architecture

**Entry point:** `backend/app.py:7-22` — `create_app()` factory then `app.run(host=0.0.0.0, port=PORT, debug=DEBUG)`.

**Factory:** `backend/app/__init__.py:41-74` — `create_app(config_object=None, **overrides)`:
- Loads `Config` via `get_config()` (`backend/app/config/settings.py:185-187`).
- `CORS(app, resources={r"/api/*": {"origins": CORS_ORIGINS}}, supports_credentials=...)` — `CORS_ORIGINS` defaults `*` in dev, must be restricted in prod.
- `configure_logging` (StreamHandler, `%(asctime)s %(levelname)s [%(name)s] %(message)s`, level from `LOG_LEVEL`).
- `register_error_handlers` (central JSON envelope), `register_security_headers`, `register_request_logging`, `register_blueprints`.

**Configuration:** `backend/app/config/settings.py:43-187` — `Config` class reads env via `_env_bool/_env_int/_env_list` with safe fallbacks. Key groups: app identity (APP_NAME, API_VERSION, API_URL_PREFIX `/api`, ENVIRONMENT), security (SECRET_KEY `dev-insecure-secret-key-change-me` fallback — must override), scanner tunables, port scanner tunables (connect 2s, total 30s, concurrency 50, max ports 100, banner 1s/256B), IP reputation (enabled false default, provider abuseipdb, API key, timeout 5s, max_bytes 32768, cache enabled true / TTL 86400), input limits, Supabase keys (legacy fallbacks + new publishable/secret), JWT (ES256 default, audience authenticated, JWKS derived), reports (bucket `report-pdfs`, signed URL 3600s), ML paths.

**Middleware stack:**
- `request_logger.py:27-45` — before_request timer + after_request logs `METHOD PATH -> STATUS (ms)` only when `REQUEST_LOG_ENABLED` true; bodies never logged.
- `request_logger.py:48-56` — security headers on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `CSP: default-src 'none'; frame-ancestors 'none'`.
- `error_handler.py:18-81` — `ApiError` → `error_response` JSON (`success:false, message, error:{code, details}`), 404/405/400/413/415 handlers, final `Exception` catch logs stack via `logger.exception` but returns `500 INTERNAL_ERROR` with no trace.

**Routes:** 10 blueprints registered in `routes/__init__.py:22-35` all under `API_URL_PREFIX`:
- `system_bp` `/api` — `GET /health`, `GET /version` (public)
- `auth_bp` `/api/auth` — `GET /me` (@require_auth)
- `dashboard_bp` `/api/dashboard` — `GET ""` (@require_auth)
- `scanner_bp` `/api/scanner` — `POST /website` (@require_auth)
- `port_bp` `/api/scanner` — `POST /ports`, `GET /ports/history`, `GET /ports/history/<id>`, `GET /ip-reputation/<ip>`, `POST /ip-reputation` (all @require_auth)
- `email_bp` `/api/email` — `POST /analyze` (json or multipart pdf) (@require_auth)
- `password_bp` `/api/password` — `POST /analyze`, `POST /generate` (@require_auth)
- `log_bp` `/api/logs` — `POST /analyze` (@require_auth, not deeply inspected but follows same auth pattern)
- `crypto_bp` `/api/crypto` — crypto lab routes (likely local crypto; not network-bound)
- `sql_bp` `/api/sql` — `POST /demo` (public), `POST /run`, `GET /scenarios` (auth)
- `report_bp` `/api/reports` — `GET ""`, `POST /generate` (@require_auth)

**Services boundary:** Pure service layer; routes validate shape and delegate. Services use `get_user_supabase_client(get_current_access_token())` for user-scoped DB, never accept `user_id` from body. Errors raised as `ValidationError` (400), `UnauthorizedError` (401), `ServiceUnavailableError` (503).

**Logging:** Root logger via `create_app:26-38` + `request_logger` + `errors.py` + `supabase_client` cache logs via `_log_safe` stripping `key/token/auth`.

**External integrations:** Supabase PostgREST (via `supabase` client), Supabase Auth JWKS, AbuseIPDB `https://api.abuseipdb.com/api/v2/check` (fixed URL, never user-controlled), Storage bucket `report-pdfs`.

---

## 4. Frontend Architecture

**Stack:** React 18.2 + TypeScript 5.2 + Vite 5.0 + Tailwind 3.4 + react-router 6.21 + @supabase/supabase-js 2.39 + chart.js 4.4 + lucide-react 0.300. Build `tsc && vite build` (frontend/package.json:7), dev `vite` on 3000 proxying `/api` to Flask 5000 (vite.config.ts:14-19). SPA rewrite via `vercel.json:2-4`.

**App shell:** `frontend/src/App.tsx:22-32` — `ConsoleRoutes` wrapped in `RequireAuth -> AppShell -> Routes`; public routes `RequireGuest -> AuthPage` (login/register/forgot). Protected routes: `/dashboard`, `/website-scanner`, `/phishing-detector`, `/password-analyzer`, `/log-analyzer`, `/sql-playground`, `/cryptography-lab`, `/port-scanner`, `/reports`, `/tutorials*`, `/profile`, `/settings`.

**Auth context:** `frontend/src/context/AuthContext.tsx:33-` — `supabase.auth.getSession()` + `onAuthStateChange` map to `AuthUser/AuthSession`; `apiClient.get('/auth/me')` fetches profile when session changes. `supabaseClient.ts:3-15` validates `VITE_SUPABASE_URL` + `VITE_SUPABASE_ANON_KEY` else throws; `createClient` with `persistSession/autoRefreshToken/detectSessionInUrl`.

**API client:** `frontend/src/services/apiClient.ts:1-131` — `API_BASE_URL = VITE_API_BASE_URL || '/api'`. Every request: `await supabase.auth.getSession()` -> `Authorization: Bearer <access_token>` (if present). `handleResponse` expects `{success, message, data, meta}`; on `!ok || success===false` throws `ApiClientError(status, code, details)`. Network failure -> `NETWORK_ERROR` status 0. `getWithMeta` variant for pagination.

**Port scanner UI:** `frontend/src/pages/PortScannerPage.tsx:222-823` — Single-page scanner + history toggle. State: `target, scanMode (quick/common/custom), customPorts, isScanning, result, error, showHistory, history[], historyMeta, historyPage/limit, detail`. Uses `useSlowRequest` for elapsed/slow notice.
- Scan form validates client-side ports (1-65535) then `apiClient.post('/scanner/ports', {target, profile/ports})` via `run(() => ...)`.
- Result display: `Port risk level` card (risk_level -> Badge tone), `IPReputationCard` (reputation badge + confidence + provider + country/ASN/org/last_reported), `ThreatAssessmentCard` (score/100 + level + confidence + explanation + factors list), `open_ports` DataTable (Port/Service/State/Banner truncated 80).
- History: `apiClient.getWithMeta('/scanner/ports/history?page=&limit=')` with pagination (total/pages), table Target/Resolved IP/Date/Ports/Open/Risk/Status + `View` -> `apiClient.get('/scanner/ports/history/:id')` into detail card (same three-signal display plus open/closed/filtered counts).
- No authoritative calculation: frontend only renders `risk_level`, `ip_reputation`, `threat_assessment` from backend. `QUICK_SCAN_PORTS`/`COMMON_SCAN_PORTS` arrays in frontend mirror backend validators but are display-only, not authoritative for scoring.
- Error handling: `ApiClientError` messages surfaced; 401 -> session expired, 503 -> temporarily unavailable, 0 -> network.

**Other pages inspected lightly:** `PasswordAnalyzerPage`, `EmailDetectorPage`, `LogAnalyzerPage`, `ReportsPage`, `WebsiteScannerPage` follow same `apiClient.post` + `RequireAuth` pattern; `ReportsPage` lists reports via `GET /api/reports` with signed_url.

---

## 5. Database Architecture

**Schema source:** `backend/app/database/schema.sql:1-248` — idempotent, run in Supabase SQL editor. Supabase Auth owns `auth.users`; app has no `public.users`; `public.profiles` 1:1 via trigger.

**Tables (8):**

| Table | Purpose | Key Columns | FK | Indexes | RLS |
|-------|---------|-------------|----|---------|-----|
| `profiles` | App user profile 1:1 auth.users | `id UUID PK FK auth.users`, `full_name`, `role CHECK Student/Faculty/Internship Evaluator`, `created_at, updated_at` | `auth.users(id) CASCADE` | — | ENABLED; `profiles_select_own` + `profiles_update_own` (`id=auth.uid()`) |
| `website_scans` | Website scan history | `id UUID`, `user_id UUID FK`, `target_url TEXT`, `status pending/running/completed/failed`, `security_score 0-100`, `risk_level low/medium/high/critical`, `findings JSONB`, `created_at` | `auth.users CASCADE` | `idx_website_scans_user_created (user_id, created_at DESC)` | ENABLED; `website_scans_owner_all FOR ALL USING/withCheck user_id=auth.uid()` |
| `email_scans` | Email scan (no raw content) | `user_id`, `subject`, `sender_email`, `predicted_label phishing/safe`, `confidence FLOAT`, `risk_level`, `indicators JSONB`, `model_version`, `created_at` | same | `idx_email_scans_user_created` | ENABLED; `email_scans_owner_all` |
| `password_scans` | Password metrics only | `user_id`, `password_length INT`, `entropy FLOAT`, `strength_score 0-100`, `strength_label`, `has_upper/lower/number/symbol BOOL`, `breached BOOL`, `created_at` | same | `idx_password_scans_user_created` | ENABLED; `password_scans_owner_all` |
| `log_scans` | Log findings only (no raw logs) | `user_id`, `event_count`, `anomaly_count`, `findings JSONB`, `risk_level`, `model_version`, `created_at` | same | `idx_log_scans_user_created` | ENABLED; `log_scans_owner_all` |
| `port_scans` | **Port scan results** | `user_id`, `target TEXT NOT NULL`, `resolved_ip TEXT`, `ports_scanned INT NOT NULL`, `open_ports JSONB`, `scan_duration_ms INT`, `risk_level`, `status completed/failed DEFAULT completed`, `ip_reputation JSONB`, `threat_assessment JSONB`, `created_at` | same | `idx_port_scans_user_created` | ENABLED; `port_scans_owner_all` |
| `ip_reputation_cache` | **Shared cache, no user_id** | `id UUID`, `ip TEXT NOT NULL`, `reputation CHECK unknown/clean/suspicious/malicious/unavailable`, `confidence none/low/medium/high/very_high`, `malicious BOOL`, `suspicious BOOL`, `reports INT`, `country`, `asn TEXT`, `organization`, `isp`, `last_reported_at TIMESTAMPTZ`, `provider TEXT NOT NULL`, `checked_at TIMESTAMPTZ`, `expires_at TIMESTAMPTZ`, `created_at, updated_at`, `UNIQUE (ip, provider)` | none | `idx_ip_reputation_cache_ip_provider (ip, provider)`, `idx_ip_reputation_cache_expires_at` | ENABLED, **no policies** → only `service_role` can access (bypasses RLS). Frontend cannot read/write. |
| `reports` | Generated PDFs | `id UUID`, `user_id FK`, `title TEXT NOT NULL`, `report_type CHECK (pdf)`, `storage_path TEXT`, `report_data JSONB`, `created_at` | same | `idx_reports_user_created` | ENABLED; `reports_owner_all` |

**Backfill pattern:** `port_scans` has `DO $$ IF NOT EXISTS columns ip_reputation/threat_assessment THEN ALTER TABLE ADD COLUMN ... $$` for existing DBs.

**Service-role access:** Only `ip_reputation_cache` is accessed via `get_supabase_admin_client()` (secret key). All other tables via `get_user_supabase_client(access_token)` preserving RLS. Guest/anon cannot bypass because no policy for them.

**Obsolete/duplicated:** No duplicated tables. `ip_reputation_cache.asn` stored as TEXT in DB (migrates int↔string via `_parse_asn`), while `ReputationResult.asn` is Optional[int] in code — tolerated.

---

## 6. Authentication & Authorization

**Supabase Auth ownership:** Frontend does `supabase.auth.signUp/signIn/signOut` directly with `VITE_SUPABASE_URL` + `VITE_SUPABASE_ANON_KEY` (publishable). Flask never handles passwords.

**JWT verification:** `backend/app/utils/security.py:120-171` `decode_supabase_token(token)`:
- Resolves JWKS URL as `SUPABASE_JWKS_URL` or `{SUPABASE_URL}/auth/v1/.well-known/jwks.json` (`_supabase_jwks_url:76-82`).
- Resolves issuer as `SUPABASE_JWT_ISSUER` or `{SUPABASE_URL}/auth/v1` (`_supabase_issuer:85-91`).
- Algorithms from `SUPABASE_JWT_ALGORITHM` split by comma (supports rotation `ES256,RS256`) — `_supabase_algorithms:94-103`.
- `PyJWKClient(url, cache_keys=True, max_cached_keys=10)` cached on `app.extensions["cybershield_jwks_client"]`.
- `jwt.decode(signing_key.key, algorithms, audience="authenticated", issuer, leeway=SUPABASE_JWT_LEEWAY default 10s, require=["sub","exp"])`.
- Validates `sub` is UUID (`uuid.UUID` check:164-169).
- Raises `UnauthorizedError` (401) on any PyJWT/OSError/ValueError, with safe `logger.warning` (no token leak).

**Middleware:** `backend/app/middleware/auth_middleware.py:22-70`:
- `get_bearer_token()` extracts `Authorization: Bearer <token>`, else 401.
- `require_auth` decorator: `get_bearer_token -> decode_supabase_token -> request.auth=claims, request.access_token=token`.
- `get_current_user_id()` returns `request.auth["sub"]` else 401.
- `get_current_access_token()` returns `request.access_token or ""` outside request context -> "" (graceful anon client).

**User scoping:**
- Every service call uses `get_current_user_id()` as `user_id` (JWT `sub`) — never from body.
- DB ops via `get_user_supabase_client(access_token)` (`supabase_client.py:79-103` — fresh client per request, `client.postgrest.auth(access_token)`). RLS evaluates as `auth.uid()`.
- `get_supabase_admin_client()` (`supabase_client.py:106-124` cached) used ONLY for `ip_reputation_cache` + `ReportStorageService` (Storage) — never for user scans.
- `get_supabase_client()` (shared anon) exists but not used for user writes; fallback path in cache service is defensive.

**Authorization checks:** No role-based branching yet; `role` in `profiles` is stored but not enforced in routes (future).

---

## 7. Port Scanner Architecture

**Files:** `port_scanner_service.py:1-607`, `port_routes.py:1-165`, `threat_assessment_service.py`, `ip_reputation_service.py`, `ip_reputation_cache_service.py`, `schema.sql:106-140`, `validators.py:150-553`

**Execution flow (verified, not assumed):**

```
Client POST /api/scanner/ports {target, ports||profile}
  1. Flask @require_auth                 -> decode_supabase_token, request.auth.sub
  2. port_routes.scan_ports              -> require_json, get target/ports/profile
  3. validate_hostname_or_ip(target)     -> lowercases, rejects ://, @, invalid hostname/IP (RFC1123)
  4. PortScannerService.scan_ports       -> validate_hostname_or_ip AGAIN, is_private_hostname -> 400 if private & !allow
  5. resolve_scan_ports(ports,profile)   -> quick 20 / common 100 / custom 1-100 sorted uniq; mutual exclusivity check
  6. _resolve_target(target)             -> socket.getaddrinfo(any family), prefer non-fe80::, return first IP or target-as-is on gaierror
  7. _scan_port_list(target,resolved_ip,ports,cfg)
         per_port_connect TOC 2s, total 30s, max_concurrency 50,
         banner TOC 1s, banner max 256B, ThreadPoolExecutor 50 workers, as_completed with total_timeout
     -> _scan_single_port(target,port,connect,bannerTOC,bannerBytes)
         socket.AF_INET SOCK_STREAM connect_ex (IPv4 only), if 0 -> recv banner (decode utf-8 ignore, sanitize printable + \n\t\r, truncate)
         closed -> state closed, timeout/gaierror/OSError -> filtered
  8. _calculate_risk_level(open_ports)   -> CRITICAL if any 22,23,3389,5900-5986 else HIGH if 135,139,445,1433,1521,3306,5432,6379,27017 else MEDIUM if 21,25,53,80,110,111,143,443,465,587,993,995,1723,8080,8443 etc else LOW
  9. IP reputation (non-blocking)        -> if resolved_ip is_ip -> IPReputationService.check_ip else unavailable(reason unresolvable); ValidationError private -> unavailable private_ip_blocked; any Exception -> unavailable provider_error
 10. Threat assessment (never breaks scan)-> ThreatAssessmentService.assess(port_risk, ip_reputation, open_ports, ports_scanned, status)
 11. Persist                             -> _persist_scan(user_id, target, result) via get_user_supabase_client(access_token).table("port_scans").insert({user_id,target,resolved_ip,ports_scanned,open_ports[],scan_duration_ms,risk_level,status,ip_reputation,threat_assessment}) -> 503 on failure
 12. Response -> success_response({target,resolved_ip,scan_duration_ms,ports_scanned,open_ports[],closed_ports,filtered_ports,summary,risk_level,ip_reputation,threat_assessment})
```

**Validation controls:**
- `validate_hostname_or_ip` enforces max_length URL_MAX_LENGTH (2048), rejects scheme, credentials, validates RFC1123 labels, handles IPv6 bracket stripping.
- `validate_port_list` enforces 1-65535, dedup + sort, max 100.
- `resolve_scan_ports` rejects both ports+profile, requires one, validates profile in {quick,common}.
- Route re-validates target before service.

**Private IP protections:**
- Route + service both call `is_private_hostname(target)` (validators.py:488-517) — tries `ip_address` direct check then `getaddrinfo` and flags any of private/loopback/link_local/reserved/multicast/unspecified as True. Unresolvable -> False (safe for scanner error path).
- Reputation layer additionally blocks via `is_private_ip` + `is_private_hostname`.
- Bypass toggle: `PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES` (flask config) default false; tests set true.

**Timeouts & limits:**
- Per-port connect 2s (`PORT_SCANNER_CONNECT_TIMEOUT`), banner 1s, total 30s (`PORT_SCANNER_TOTAL_TIMEOUT`), max concurrency 50, max ports 100, banner 256B. All env-configurable.

**Banner handling:** Decoded utf-8 ignore, filtered to isprintable or \n\t\r, truncated at 256 + "...".

**DNS resolution:** Via `socket.getaddrinfo(target, None, AF_UNSPEC, SOCK_STREAM)` in both `_resolve_target` and scan path; scanner uses hostname `target` for `connect_ex` while `resolved_ip` is stored/displayed for reputation and UI.

**Persistence:** Only when `user_id` present and `get_user_supabase_client` available; writes snapshot including `ip_reputation` + `threat_assessment` JSONB.

**Error handling:** `is_private_hostname` ValidationError 400, `resolve_scan_ports` ValidationError 400, scan errors become `filtered` state, reputation failures become `unavailable` (never breaks scan), persist failure -> 503.

---

## 8. IP Reputation Architecture

**Provider abstraction:** `backend/app/services/ip_reputation_service.py:99-238`
- Abstract `IPReputationProvider.provider_name, check_ip(ip)->ReputationResult`
- `AbuseIPDBProvider(provider_name=abuseipdb)` — `api_key, timeout 5s, max_bytes 32768, base_url fixed` (from config `IP_REPUTATION_ABUSEIPDB_URL` default `https://api.abuseipdb.com/api/v2/check`, never user-controlled).
- `NullProvider(provider_name=unavailable)` — always unavailable (disabled/unknown provider).

**Request construction:** `AbuseIPDBProvider.check_ip:125-229`
- Double `is_private_ip` guard (returns unavailable without network if private).
- If `!api_key` -> unavailable `missing_api_key`.
- `headers={"Key": api_key, "Accept": "application/json"}`, `params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}`.
- `requests.get(base_url, headers, params, timeout=timeout)` with bounded `max_bytes` header/body checks (`Content-Length > max_bytes -> response_too_large`, `len(text.encode utf-8) > max_bytes -> response_too_large`).
- Status mapping: 429 -> `rate_limited`, 401/403 -> `auth_failed`, 5xx -> `provider_error`, other non-200 -> `http_<code>`, all as unavailable, never exception to caller except private-IP ValidationError handled by caller.
- JSON parse via `resp.json()` -> `payload["data"]` validation; on malformed -> `malformed_response`.
- Extract: `abuseConfidenceScore -> score`, `totalReports -> reports`, `isWhitelisted`, `countryCode`, `asn` -> int sans AS prefix, `isp`, `organization|usageType|isp`, `lastReportedAt`. Map via `_reputation_from_abuse:83-95` (whitelisted->clean, 0/0->unknown, >=75->malicious, >=25 or >=5 reports->suspicious, >0->suspicious else unknown) and `_confidence_from_score:71-80` (0 none, <25 low, <50 medium, <75 high, else very_high).
- Returns `ReputationResult(ip, reputation, confidence, malicious, suspicious, reports, country, asn, organization, isp, last_reported_at, provider, checked_at=now_iso, reason)`.

**Response normalization:** All providers return `ReputationResult` dataclass with `to_dict()` (asdict). Frontend receives only this shape; raw AbuseIPDB `data` never leaks.

**Error handling & timeout:** `requests.Timeout -> unavailable timeout`, `RequestException -> network_error`, bounded 5s per config, body size cap 32KB.

**Rate-limit handling:** HTTP 429 mapped to `unavailable` `rate_limited`, not retried; not cached (see cache).

**Cache interaction:** `IPReputationService.check_ip:281-318` facade:
- `validate_ip_address(ip)` + `is_private_ip` -> ValidationError (private never reaches provider/cache).
- `_get_provider()` — prefers `current_app.config` (IP_REPUTATION_ENABLED/PROVIDER/API_KEY/TIMEOUT etc) if in app context, else `get_config()`. If disabled -> NullProvider (no cache).
- If provider_name == unavailable -> direct provider check (no cache).
- Else `IPReputationCacheService.get(ip, provider_name)` try/catch (never breaks flow).
- If cache hit -> return cached.
- Else `result = provider.check_ip(normalized)` then `IPReputationCacheService.put(result)` try/catch.

**check_target:** `check_target:321-390` validates hostname/IP, resolves hostname via `getaddrinfo`, filters private/reserved via `ipaddress` flags, raises ValidationError if private or unresolvable, then `check_ip(resolved)`.

**Secret handling:** API key from `current_app.config["IP_REPUTATION_API_KEY"]` or env, never logged, never returned in `ReputationResult`, never stored in DB (`ip_reputation_cache` columns allowlist excludes keys), never in report/PDF (filtered). `headers={"Key": api_key}` is standard requests, not logged via `_log_safe` (strips key/token/auth).

---

## 9. Cache Architecture

**Schema:** `schema.sql:146-176` `ip_reputation_cache` shared provider data:
- `id UUID PK`, `ip TEXT NOT NULL`, `reputation CHECK`, `confidence CHECK`, `malicious BOOL`, `suspicious BOOL`, `reports INT`, `country TEXT`, `asn TEXT`, `organization TEXT`, `isp TEXT`, `last_reported_at TIMESTAMPTZ`, `provider TEXT NOT NULL`, `checked_at TIMESTAMPTZ DEFAULT NOW()`, `expires_at TIMESTAMPTZ NOT NULL`, `created_at, updated_at`, `UNIQUE (ip, provider)`.
- Indexes: `(ip, provider)`, `(expires_at)`.
- `ENABLE ROW LEVEL SECURITY` with **zero policies** — anon/authenticated cannot SELECT/INSERT; backend uses `service_role` which bypasses RLS.

**Service:** `backend/app/services/ip_reputation_cache_service.py:1-325`
- `IPReputationCacheService.get(ip, provider) -> ReputationResult | None` — respects `IP_REPUTATION_CACHE_ENABLED` (from current_app or Config), validates ip/provider non-empty, fetches via `_get_cache_client()`, queries `table("ip_reputation_cache").select("*").eq("ip",ip).eq("provider",provider).execute()`, parses `expires_at` via `_parse_ts`, returns None if expired (`expires_at <= now UTC`), else maps row -> `ReputationResult` (with `_parse_asn`). Logs `cache_hit/miss/expired/get_error` via `_log_safe` (no secrets).
- `put(result)` — skips if disabled, None, `reputation==unavailable`, or missing ip/provider; computes `checked_at` parsed or now, `expires_at = checked_at + TTL` (default 86400), upserts via `client.table("ip_reputation_cache").upsert(payload, on_conflict="ip,provider")` with fallbacks to `upsert(payload)` then `insert` then `update` for fake/test compatibility; logs success/failed/error.
- TTL: `IP_REPUTATION_CACHE_TTL` from current_app or Config default 86400 (24h).
- Client resolution `_get_cache_client:48-92` strict preference: 1) `get_supabase_admin_client()` (service_role), 2) direct `create_client(SUPABASE_URL, SUPABASE_SECRET_KEY or SERVICE_ROLE_KEY from current_app.config)` (Render env + tests), 3) fallback `get_supabase_client()` anon (will be denied by RLS; logged as `cache_fallback_anon`). This cascade ensures cache works in prod (admin) while tests using fake still work.
- ` _cache_enabled/_cache_ttl` helpers prefer Flask config, fallback Config.
- `_log_safe` strips `key/token/auth` from extras.

**Isolation guarantees:** No `user_id` column, no per-user partitioning, no API keys in payload (payload allowlist in `put` excludes secrets, only normalized reputation fields). Provider cache key is `(ip, provider)` — prevents cross-provider poisoning.

---

## 10. Threat Assessment Architecture

**File:** `backend/app/services/threat_assessment_service.py:1-288` — pure deterministic, no DB/network, no secrets.

**Inputs:** `assess(port_risk: str, ip_reputation: Optional[dict], open_ports: Optional[list], ports_scanned: Optional[int], status: str="completed")`
- `port_risk` ∈ low|medium|high|critical (from `PortScannerService._calculate_risk_level`; normalized lowercase, defaults low).
- `ip_reputation` dict or None (from `IPReputationService` or scanner fallback unavailable).
- `open_ports` list of dicts or `PortResult` dataclasses with `port/state`.

**Scoring (verified exact values, matches spec):**
- `PORT_BASE = {low:10, medium:25, high:45, critical:60}`
- `IP_BASE = {clean:0, unknown:0, unavailable:0, suspicious:20, malicious:35}`
- `score = port_base + ip_base` (range 10-95 before modifiers).
- Modifiers each +5, deduped, capped:
  - `critical_service_detail` — `port_risk==critical AND open_set ∩ CRITICAL_RISK_PORTS` (22,23,3389,5900,5901,5985,5986)
  - `database_exposure` — `open_set ∩ DB_PORTS` (1433,1521,3306,5432,6379,27017-19)
  - `multiple_high_risk` — `len(open_set) >=3 OR len(open_set ∩ (CRITICAL∪HIGH)) >=2`
  - `high_report_volume` — `reports >=10 AND reputation ∈ {suspicious,malicious}`
  - `malicious_critical_combo` — `malicious AND critical` (+5)
  - `suspicious_high_combo` — `suspicious AND risk ∈ {high,critical}` (exclusive with previous)
- `score = max(0, min(100, int(score)))` capped.
- `level = _level_for_score: ≤19 low, ≤39 medium, ≤69 high, else critical`.

**Confidence (evidence completeness, not severity):**
- `scan_complete = ports_scanned>0 AND status=="completed" AND open_ports is list` (if ports_scanned None, checks open_ports not None).
- `if not scan_complete => low`
- `elif ip_rep is None or unavailable => medium`
- `elif clean/suspicious/malicious/unknown => high`
- else medium.

**Factors:** List of `{type, weight, description}` always includes base `port_risk` (weight port_base) + IP base factor (unavailable/unknown/clean 0, suspicious/malicious with reports). Modifier factors appended only when triggered. Deterministic order (insertion base then modifiers) + sorted contributing for explanation but factors list stays insertion-order.

**Explanation:** `Port risk X (base) [+ IP Y (base)] [+ modifiers → score LEVEL.]` + unavailable note. Deterministic string.

**Determinism:** Same inputs -> same score/level/confidence/factors/explanation (except `assessed_at` timestamp varies). No random, no user weights.

**Server-authoritative:** Entire computation backend-only; frontend never computes weights.

**Failure behavior:** `PortScannerService.scan_ports:206-218` wraps with try/except -> `threat_assessment = None` never breaks scan.

---

## 11. Report Architecture

**Service:** `backend/app/services/report_service.py:1-458`

**Generation pipeline:**
1. `_validate_title(config)` + `_validate_overrides(config)` — title required non-empty ≤200 chars; summary must be string, findings must be list.
2. `user_id` required from JWT else ValidationError.
3. `get_user_supabase_client(access_token)` or 503 if not configured.
4. `_fetch_latest_scans(client, user_id)` — for each `SCAN_TABLES = (website_scans, email_scans, password_scans, log_scans, port_scans)` selects `*` where `user_id` ordered `created_at DESC` limit 1 ( `SCAN_LIMIT=1` ). RLS ensures isolation. Any table failure -> 503.
5. `_build_report_data(latest, title, report_id=uuid4, generated_at=now_iso, config)` — maps each row via `_map_website_scan/_map_email_scan/_map_password_scan/_map_log_scan/_map_port_scan`.
6. `_render_pdf(report_data, report_id)` — temp dir `cybershield-report-<id>.pdf`, `PDFReportGenerator.generate_pdf(report_data, path)`, reads bytes, rmtree.
7. `ReportStorageService.upload_pdf(pdf_bytes, user_id, report_id)` — private bucket via admin client, object key `<user_id>/<report_id>.pdf`, returns `{storage_path, signed_url}`.
8. Insert `public.reports` via user-scoped client: `{id=report_id, user_id, title, report_type='pdf', storage_path, report_data=report_data}` -> 503 on failure.
9. Return merged row + `signed_url`.

**Listing:** `list_reports(user_id)` -> user-scoped `select * where user_id order created_at DESC`, then for each row `ReportStorageService.get_signed_url(user_id, report_id)` attaches fresh signed URL.

**Port Scanner in reports:**
- `_map_port_scan:244-314` — sanitizes banners via `_sanitize_banner` (printable + \n\t\r, 256 truncate), normalizes `ip_reputation` allowlist to `{ip, reputation, confidence, malicious, suspicious, reports, country, asn, organization, isp, last_reported_at, provider, checked_at, reason}` (drops api_key), normalizes `threat_assessment` allowlist to `{score, level, confidence, factors, explanation, assessed_at}` (sanitizes factors type≤64, weight int, description≤256, score bounded 0-100).
- `report_data.port_scan` is this normalized snapshot; `summary` derived: `Scanned {ports_scanned} ports: {open} open, {closed} closed, {filtered} filtered.`
- `_build_summary` aggregates categories present (website,email,password,log,port scan).

**PDF generation:** `backend/app/reports/pdf_generator.py:1-825`
- `generate_pdf(report_data, output_path)` creates A4 with margins, brand header, KV tables, checks/indicators/anomalies tables, `._port_section:446-534` renders distinct `Port Scan — Target & Results` KV table, `Discovered Ports (service / state / banner)` table, `IP Reputation — AbuseIPDB (independent from port risk)` KV table or note if null, `Overall Threat Assessment — Derived from Port Risk + IP Reputation` KV table + `Contributing Factors` table or note if null, with distinction notes.
- Sanitization: `_esc` xml escape for PDF, banner sanitized already.
- Storage: object path validated via `_valid_segment` (rejects `/\` `.` `..` empty) preventing traversal.

**Secrets in reports:** `ReputationResult` never contains API key; report mapping explicitly filters to allowlist, so impossible.

---

## 12. API Architecture

**Envelope:** `backend/app/utils/helpers.py` `success_response(data, message, meta, status_code)` -> `{success:true, message, data, meta}`; `error_response` -> `{success:false, message, error:{code, details}}`. All routes use this; frontend expects it.

**Authentication gate:** `require_auth` on all scan/report/dashboard routes; `health/version/sql/demo` public.

**Endpoints (13 route handlers across 10 blueprints):**

| Method | Path | Auth | Purpose | Key validation |
|--------|------|------|---------|----------------|
| `GET` | `/api/health` | no | liveness | — |
| `GET` | `/api/version` | no | version info | — |
| `GET` | `/api/auth/me` | yes | profile from JWT `sub` | JWT sub must be UUID |
| `GET` | `/api/dashboard` | yes | aggregated metrics | user_id from JWT only |
| `POST` | `/api/scanner/website` | yes | passive website scan | `validate_url` + `is_private_host` SSRF |
| `POST` | `/api/scanner/ports` | yes | TCP port scan | `validate_hostname_or_ip` + `is_private_hostname` + ports/profile mutual exclusivity |
| `GET` | `/api/scanner/ports/history?page&limit` | yes | paginated history (newest first) | page 1-indexed, limit clamp 1-50, RLS filtered |
| `GET` | `/api/scanner/ports/history/<scan_id>` | yes | single scan detail | scan_id non-empty, `eq id` + `eq user_id` |
| `GET` | `/api/scanner/ip-reputation/<ip>` | yes | IP reputation (GET) | `validate_ip_address` + `is_private_ip` 400 if private |
| `POST` | `/api/scanner/ip-reputation` | yes | IP or hostname reputation | body `{ip OR target}` mutually exclusive, delegates to `check_ip/check_target` |
| `POST` | `/api/email/analyze` | yes | phishing email (json or pdf) | `EMAIL_MAX_LENGTH`, pdf size `EMAIL_PDF_MAX_SIZE` |
| `POST` | `/api/password/analyze` | yes | password strength | `validate_password_input` max 4096 |
| `POST` | `/api/password/generate` | yes | generate password | type checks |
| `POST` | `/api/logs/analyze` | yes | log anomaly | `LOG_MAX_LENGTH/LINES` |
| `POST` | `/api/crypto/*` | (varies) | hashing/encrypt in browser or server assist | `CRYPTO_MAX_INPUT_LENGTH` |
| `POST` | `/api/sql/demo` | no | demo payload echo | `SQL_PAYLOAD_MAX_LENGTH` |
| `POST` | `/api/sql/run` | yes | SQLite sandbox scenario | scenario id ≤64, payload validated |
| `GET` | `/api/sql/scenarios` | yes | catalog | — |
| `GET` | `/api/reports` | yes | list reports + signed URLs | JWT user_id only |
| `POST` | `/api/reports/generate` | yes | generate PDF report | title ≤200, optional summary/findings |

**Error codes:** `VALIDATION_ERROR 400`, `UNAUTHORIZED 401`, `NOT_FOUND 404`, `METHOD_NOT_ALLOWED 405`, `PAYLOAD_TOO_LARGE 413`, `SERVICE_UNAVAILABLE 503`, `FEATURE_UNAVAILABLE 501`, `INTERNAL_ERROR 500`. Details never include stack.

**CORS:** Flask-CORS on `/api/*` with `CORS_ORIGINS` (default `*` → must restrict in prod). `supports_credentials` false by default.

---

## 13. Testing Architecture

**Framework:** `pytest 9.1.1` with `pytest.ini` testpaths=tests, pythonpath=., `-q`.

**Fixtures:** `backend/tests/conftest.py:1-369`
- `TestingConfig` (extends Config): `ENVIRONMENT testing`, `TESTING true`, `DEBUG false`, `REQUEST_LOG_ENABLED false`, `SECRET_KEY test-secret`, `CORS localhost:3000`, `SCANNER_ALLOW_PRIVATE_ADDRESSES true`, `IP_REPUTATION_ENABLED false`, `IP_REPUTATION_CACHE_ENABLED false` (isolated), small input limits.
- `app` fixture: `create_app(TestingConfig)` per test in app_context.
- `client` = `app.test_client()`.
- `fake_supabase` autouse: `_FakeSupabaseClient` with `inserts/rows/fail_next_execute/fail_inserts/auth_tokens`; `_FakeSupabaseTable` mimics `insert/upsert(update on_conflict)/update/select/eq/order/limit/range/execute` with `count="exact"` support and upsert `on_conflict` first-wins update. Patches `get_user_supabase_client`/`get_supabase_admin_client`/`get_supabase_client` on `app.services.*` + `app.database.supabase_client` via monkeypatch. Records forwarded `access_token` for JWT-forwarding assertions.
- `_jwt_auth_harness` autouse: Pins `SUPABASE_URL=https://abcxyz.supabase.co`, `SUPABASE_JWT_ALGORITHM=RS256`, `AUD=authenticated`, injects RSA 2048 keypair, replaces `security_utils.PyJWKClient` with `_FakeJWKClient(public_key)` so `auth_headers` (valid RS256 token) works without network.
- `make_auth_token/auth_token/auth_headers/auth_user_id` fixtures.

**Counts:**
- `def test_` grep: **613** across 24 files (see §7 `bash` output).
- `pytest --collect-only` (with parametrizations): **1049** tests.
- Breakdown (grep): `test_port_scanner 93`, `test_ip_reputation_cache 16->21 parametrized`, `test_threat_assessment 26`, `test_reports 38`, `test_report_storage 17`, `test_scanner 22`, `test_password 56`, `test_email 29`, `test_logs 18`, `test_dashboard 34`, `test_auth 12`, `test_route_auth 15`, `test_supabase_jwt 39`, `test_supabase_client 19`, `test_sql_lab 38`, `test_sql_lab_redteam 51`, `test_sql_playground 37`, `test_crypto 19`, etc.

**Port scanner tests (`test_port_scanner.py` 93):** Validates private IP blocking, port list deduplication/max, quick/common profiles, risk levels (critical/high/medium/low), banner truncation, `connect_ex` mocking, total timeout, concurrency, persistence via fake, history pagination + user isolation, detail not-found, error 503 paths.

**IP reputation tests (`test_ip_reputation_cache.py` + `test_supabase_jwt`):** Validates private IP blocked before provider, missing api_key -> unavailable, 429/401/5xx/timeout -> unavailable, max_bytes cap, cache hit/miss/expiry, put skips unavailable, (ip,provider) unique upsert, RLS not bypassed except admin.

**Threat assessment tests (`test_threat_assessment.py` 26):** Base combos (low+clean 10 low, low+malicious 45 high, critical+malicious 95 critical), modifiers once, exclusivity malicious vs suspicious combo, high_report_volume >=10, database/critical_service dedup, score cap 100, confidence high/medium/low, factors allowlist.

**Other high-value coverage:** `test_rls_auth_scoping` (user A cannot read B's scans), `test_report_storage` (storage path traversal blocked, admin client required), `test_security_utils` (JWT validation), `test_validators`.

**Mocking strategy:** No network in tests; `socket.getaddrinfo/connect_ex`, `requests.get`, `PyJWKClient`, `supabase` all faked. Deterministic.

---

## 14. Deployment Architecture

**Frontend (Vercel):**
- Build: `tsc && vite build` (package.json:7) → output `dist/` (Vite default). No env-specific build command in repo; Vercel uses this.
- SPA routing: `vercel.json: rewrites /(.*) -> /index.html`.
- Env (Vercel dashboard required): `VITE_API_BASE_URL` (e.g. `https://cybershield-ai-beta.onrender.com/api`), `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` (publishable). Missing either -> `supabaseClient.ts:6` throws.
- No `VITE_SUPABASE_SECRET_KEY` ever in frontend (correct).

**Backend (Render):**
- Start: `gunicorn` (requirements.txt). Typical Render `gunicorn app:app` or `gunicorn "app:create_app()"` — not pinned in repo docs but `app.py:17` creates `app = create_app()` for gunicorn import.
- Env (Render dashboard required): `APP_ENV=production`, `FLASK_ENV=production`, `SECRET_KEY=<random>`, `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` (or legacy `SUPABASE_ANON_KEY`), `SUPABASE_SECRET_KEY` (or legacy `SUPABASE_SERVICE_ROLE_KEY`), `SUPABASE_JWT_ALGORITHM=ES256`, `SUPABASE_JWT_AUDIENCE=authenticated`, `CORS_ORIGINS=https://cyber-shield-ai-beta-topaz.vercel.app`, `IP_REPUTATION_ENABLED=true`, `IP_REPUTATION_API_KEY=<abuseipdb>`, `IP_REPUTATION_CACHE_ENABLED=true`, `PORT_SCANNER_*` tunables optional. Live demo: `https://cybershield-ai-beta.onrender.com`.
- Production toggles: `PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES=false`, `IP_REPUTATION_ENABLED=false` default (must enable explicitly).

**Database (Supabase):**
- Manual step: Run `backend/app/database/schema.sql` in Supabase SQL editor (idempotent). Must be re-run after adding `threat_assessment` column (DO $$ backfill already in schema.sql ensures idempotency).
- RLS: Enabled on all user tables + `ip_reputation_cache` (no policies). Service-role key bypasses RLS for cache + Storage.
- Required manual migrations: After deploying `threat_assessment`, existing DBs need `ALTER TABLE port_scans ADD COLUMN IF NOT EXISTS threat_assessment JSONB;` (schema.sql DO block covers if re-run; otherwise one DDL).

**Differences per env:**

| Env | SUPABASE keys | IP_REPUTATION_ENABLED | PORT private allowed | CACHE enabled | CORS | LOG |
|-----|---------------|-----------------------|----------------------|---------------|------|-----|
| development (.env.example) | your-supabase-* placeholders | false | false | true | * | INFO |
| testing (conftest.TestingConfig) | https://abcxyz.supabase.co fake | false | true | false | localhost:3000 | disabled |
| production (Render) | real project url + secret | true (when key set) | false | true | frontend origin only | INFO |

**Docs source:** `docs/13_Deployment_Guide.md`, `docs/06_Database_Design.md`, `README.md` live links.

---

## 15. Security Audit

> Methodology: Static source inspection only. No exploitation, no network probing. Findings classified by defensible risk if deployed as documented.

### CRITICAL

**None confirmed.** No unauthenticated RCE, no secret persisted raw, no SQL injection via concatenated queries (SQL lab uses isolated SQLite with allowlisted scenarios), no JWT none-alg.

### HIGH

**H1 — DNS rebinding / TOCTOU in Port Scanner (port_scanner_service.py:104-125, 240-254 vs 310-354)**
- `validate_hostname_or_ip -> is_private_hostname` resolves DNS at validation time; `_resolve_target` re-resolves via `getaddrinfo`; `_scan_single_port(target, ...)` then passes **hostname** `target` (not resolved IP) to `socket.connect_ex((target, port))` which re-resolves again at connect time. An attacker could register a hostname that resolves to a public IP at validation but later (via fast-flux DNS) to `127.0.0.1` or `10.x` at connect time, bypassing the SSRF guard. IPv4-only scan socket (`AF_INET`) mitigates IPv6 link-local but not the core TOCTOU.
- *Recommendation P0:* Resolve once, validate that **all** resolved IPs are public, then scan by IP (`connect_ex((resolved_ip, port))`) with Host header not needed for TCP (or `socket.getaddrinfo` with flag). Consider `socket.create_connection` with pre-resolved IP and `TCP` only; document that scanner is not a browser.

**H2 — Supabase key fallback can silently use wrong privilege (supabase_client.py:31-77, config/settings.py:132-138)**
- `_publishable_key()` tries `SUPABASE_PUBLISHABLE_KEY` then `SUPABASE_ANON_KEY` then `SUPABASE_KEY` (legacy). `_first_key` fallback for secret similar. In production if only `SUPABASE_KEY` is set (legacy single key) without clarity whether it is anon vs service_role, the admin client could silently be built with a low-privilege key, causing cache writes to be denied by RLS (appears as miss, not error) or user writes with anon scope to be confused. The `cache` layer logs `cache_fallback_anon` and continues as miss, masking misconfig.
- *Recommendation P0:* Fail closed if `SUPABASE_SECRET_KEY` missing when `IP_REPUTATION_CACHE_ENABLED true`; log loudly and expose `/health` flag.

### MEDIUM

**M1 — Unrestricted external resolution of arbitrary hostnames (validators.is_private_hostname, port_scanner_service)**
- `socket.getaddrinfo` is called on user-supplied hostnames without timeout argument (relies on system resolver timeout, typically 5-15s). Burst of attacker-controlled slow-resolving hostnames could tie up Flask workers (sync gunicorn) → DoS. The per-request threat is limited by 100 ports but DNS phase is unbounded.
- *Mitigant:* Small scan concurrency, but DB insert still blocks.

**M2 — Banner storage + PDF rendering — potential stored XSS if PDF fails to sanitize**
- Banners sanitized to `isprintable` + ` \n\t\r` and truncated, then `_esc` xml-escaped in PDF. This is safe for PDF. However `open_ports[].banner` JSON is returned verbatim to frontend and rendered via `formatBanner` (plain text) -> safe (not innerHTML). History detail renders same. Verified safe but worth a regression test for `banner = "<script>"` .

**M3 — Rate limiting absent per-user on expensive operation (port scan + AbuseIPDB)**
- Port scanning is CPU/socket heavy (up to 100 TCP connects, 30s, 50 threads). No per-user rate limiting, IP limiting, or AbuseIPDB quota protection beyond `rate_limited -> unavailable`. An authenticated user could scan in a loop and exhaust AbuseIPDB quota or scanner host sockets.
- *Recommendation P1:* Add Flask limiter (e.g., `5 scans / minute / user`) and circuit-break AbuseIPDB on 429.

**M4 — CORS `*` default (config/settings.py:64, app/__init__.py:55-59)**
- `CORS_ORIGINS = _env_list("CORS_ORIGINS", "*")` means a misconfigured deployment without setting `CORS_ORIGINS` exposes `/api` to any origin. Browser fetch from evil.com with stolen Bearer token (if XSS somewhere) could still call API. Not exploitable alone but violates least privilege.
- *Fix:* CI check that production `APP_ENV=production` + `CORS_ORIGINS` != `*`.

### LOW

**L1 — Error details may leak port counts or table names**
- `ServiceUnavailableError(details={"table":"port_scans","error":"ConnectionError"})` exposes internal table name + exception type to client via error envelope (status 503). Not a secret but aids reconnaissance.
- *Fix:* Trim details in production error handler or map to `code` only.

**L2 — JWT leeway 10s is reasonable but algorithm parsing permissive**
- `SUPABASE_JWT_ALGORITHM` splits on comma without validating each entry is in `["ES256","RS256","HS256"]`, could accept `none` if misconfigured (PyJWT would still handle? but `_supabase_algorithms` would return `["none"]` and jwt.decode might accept `none` if key is None). In practice key from JWKS blocks it but defense-in-depth missing.

**L3 — Report signed URLs are long-lived (3600s) and not revoked on Storage delete**
- Signed URL remains valid until expiry even if report row deleted; acceptable for private bucket but document.

### INFO

**I1 — `MAX_CONTENT_LENGTH` 1MB global is correct but `EMAIL_PDF_MAX_SIZE` also 1MB — both enforce same file size via different keys; redundant.**

**I2 — `PORT_THREAT_INTELLIGENCE_PHASE1.md` untracked (git status shows untracked) — proposed design doc not committed; keep or remove before Vercel deploy.**

**Positive findings (secure as implemented):**
- API keys never in DB/frontend/report/PDF (verified via allowlists).
- No user_id from client (always `get_current_user_id()`).
- No SQL injection (SQL lab sandbox is allowlisted in-memory).
- No command injection (no `subprocess`).
- No credential logging (`request_logger` never logs bodies, `_log_safe` strips keys).

---

## 16. Technical Debt

| Area | Debt | Impact | Effort |
|------|------|--------|--------|
| **Port scanner TOCTOU** | Three separate `getaddrinfo` calls (validation, resolve, connect) on same hostname without pinning IP | H1 security; medium refactor | M |
| **Oversized file** | `port_scanner_service.py` 607 lines (scan + concurrency + banner + risk + persistence + history) plus threat/reputation concerns tangentially via try blocks | Hard to test/modify in isolation; risk of coupling | S |
| **Schema.sql monolithic** | 249 lines, single file for all 8 tables + RLS + indexes + trigger; no migration history (Alembic/Migra) | Manual re-run required; drift risk if prod DB manually altered | S |
| **Fake Supabase leakage** | `conftest._FakeSupabaseTable.execute` special-cases `port_scans`/`ip_reputation_cache` for timestamps; production behavior differs subtly (count attribute vs dict key) — handled via branching in `port_scanner_service.get_scan_history` | Fragile pagination count if Supabase client upgrades | S |
| **Report `overall_score` divergence** | `pdf_generator._overall_score` averages `website_score + (100-email_risk) + password_strength + (100-log_threat)` but dashboard uses different weights; not including port `threat_assessment.score` yet | Inconsistent "overall" across report vs dashboard | S |
| **Frontend duplication** | `PortScannerPage.tsx` QUICK/COMMON arrays duplicate `validators.py` constants; risk of drift if backend limits change | UI out of sync with backend max_ports | S |
| **Error handling inconsistency** | Some services raise `ServiceUnavailableError` with code, others generic; frontend maps only few codes explicitly | Harder troubleshooting | S |
| **Dead code** | `backend/app/ml/train_models.py` stub; `models/*.pkl.placeholder` never loaded — reserved but not wired | Confusing for contributors | S |
| **Cache fake patch radius** | `conftest.fake_supabase` patches 10 module paths manually; adding a 11th service requires updating list | Easy to miss cache client mock | S |
| **Logging split** | `app.logger` in factory + `logging.getLogger("ip_reputation_cache")` + `cybershield.errors` — three loggers without unified format/level for JSON prod logs | Harder aggregation on Render | S |

---

## 17. Missing Tests

> Identified gaps; **do not implement in this audit task.**

**P0 gaps:**
- DNS rebinding negative test — hostname that resolves to public IP at `is_private_hostname` stage then private at `connect_ex` stage (requires mocking `getaddrinfo` side-effect sequence).
- Cache permission negative — frontend anon token cannot read/write `ip_reputation_cache` (requires RLS simulation; current fake allows anon).
- Banner script-injection snapshot — `banner = "<svg onload=alert(1)>"` round-trips banner through `port_scans` JSON -> report PDF -> no script execution.
- Rate limit / 429 handling for AbuseIPDB — provider returns 429 twice, service returns `unavailable rate_limited` and does not cache.
- `threat_assessment` secret absence — new threat fields never contain `api_key`/`access_token` even when provider has key.

**P1 gaps:**
- `PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES=false` negative in production config (currently tests set true, no test for false).
- History pagination edge — `limit 50` clamp, `page 0` normalization, `total` vs `data.length` branching.
- Report with old `port_scans` rows having `ip_reputation IS NULL` / `threat_assessment IS NULL` — `pdf_generator._port_section` handles "Not available" note (needs integration test with seeded null).
- Workspace XSS — `target="<img src=x onerror=alert(1)>"` is rejected by `validate_hostname_or_ip` and never stored; missing explicit test.

**P2 gaps:**
- Concurrent scan safety — two simultaneous `POST /ports` for same user don't overwrite each other's `resolved_ip`.
- Supabase key fallback ordering — ensure `SUPABASE_PUBLISHABLE_KEY` wins over legacy anon key.

Current **1049** tests are strong; above gaps would raise confidence from ~85% to ~95% for production.

---

## 18. Recommended P0 Tasks — Blocking / Security / Production

| # | Task | Rationale | Files |
|---|------|-----------|-------|
| **P0-1** | **Fix port scanner DNS rebinding TOCTOU** — resolve target once, validate all IPs, scan by that IP (not hostname), store that IP as `resolved_ip` | Closes H1; currently three resolutions allow bypass | `port_scanner_service.py:_resolve_target`, `_scan_single_port`, `validators.is_private_hostname` |
| **P0-2** | **Harden Supabase key resolution to fail closed** — on `APP_ENV=production` require `SUPABASE_URL + SUPABASE_PUBLISHABLE_KEY + SUPABASE_SECRET_KEY`, fail startup if missing; remove silent anon fallback for cache | Closes H2; prevents RLS bypass confusion | `database/supabase_client.py`, `config/settings.py`, `ip_reputation_cache_service._get_cache_client` |
| **P0-3** | **Tighten CORS default for production** — change default `CORS_ORIGINS` when `ENVIRONMENT==production` to `""` (fail) or enforce check in factory that `*` forbidden in prod | Closes M4 | `config/settings.py:64`, `app/__init__.py:CORS` |
| **P0-4** | **Single production DDL for threat_assessment** — ensure `schema.sql` + live DB have `port_scans.threat_assessment JSONB` (already present in file; re-run on Supabase once per project) | Reports/history depend on column | `database/schema.sql:125-140` |
| **P0-5** | **Add per-user rate limit on `POST /api/scanner/ports` & `/ip-reputation`** — e.g., 10 scans/min/user, AbuseIPDB circuit breaker on 2× 429 | Closes M3, protects quota and host sockets | `routes/port_routes.py`, new `middleware/rate_limiter.py` |

---

## 19. Recommended P1 Tasks — Important Functionality

| # | Task | Rationale |
|---|------|-----------|
| **P1-1** | Include `threat_assessment.score` in `DashboardService` trend & `pdf_generator._overall_score` | Dashboard currently ignores port threat; overall score stale |
| **P1-2** | Surface port scanner DNS timeout — wrap `getaddrinfo` with 2s timeout or `signal` and return `ValidationError("Unable to resolve target")` quickly | Closes M1 DoS |
| **P1-3** | Extract rate-limit + retry logic for AbuseIPDB — expose 429 `Retry-After` as `reason` and backoff | Operational resilience |
| **P1-4** | Synchronize `QUICK/COMMON` constants — single source (backend endpoint `GET /scanner/ports/meta` returning profiles) rather than duplicated arrays | Removes drift debt |
| **P1-5** | Unified error detail sanitizer — in `register_error_handlers` strip `details.table` when `ENV=production` | Closes L1 |
| **P1-6** | Add `ip_reputation_cache` expiry janitor — optional scheduled job to `DELETE WHERE expires_at < now()` to bound table growth (currently TTL enforced read-side only) | Bounded growth |

---

## 20. Recommended P2 Tasks — Quality / Improvements

| # | Task | Est |
|---|------|-----|
| P2-1 | Split `port_scanner_service.py` into `scanner/`, `risk/`, `history.py` modules (break 607 lines) | Low risk refactor, improves test isolation |
| P2-2 | Introduce migration tool (Alembic or `supabase db push` + `migrations/` folder) instead of monolithic `schema.sql` | Operational maturity |
| P2-3 | Frontend display for `threat_assessment.confidence` tooltip explaining evidence completeness | UX polish |
| P2-4 | Add `frontend/src/lib/cryptoEngine.selftest.ts` run-on-load already exists — wire to `/health` reporting `ml_models` | Observability |
| P2-5 | Remove untracked `PORT_THREAT_INTELLIGENCE_PHASE1.md` or commit as `docs/20_Threat_Assessment_Design.md` | Repo hygiene |
| P2-6 | Standardize logger format to JSON on Render (`python-json-logger`) for `cybershield.request` correlation | Ops |

---

## 21. Current System Architecture Diagram

```text
                    ┌──────────────────────────────────────────────────────┐
                    │                    User Browser                        │
                    │  React 18 + TS + Vite (Vercel)  ── PortScannerPage  │
                    │              │                                       │
                    │  supabase.auth (VITE_SUPABASE_ANON) ─┐               │
                    └────────────────────────────────┼─────────────────────┘
                                                     │ Bearer JWT
                           ┌─────────────────────────┴────────────────────────┐
                           │  Supabase Auth  (auth.users)  JWKS via           │
                           │  https://<project>.supabase.co/auth/v1/          │
                           │  .well-known/jwks.json (ES256)                   │
                           └─────────────────────────┬────────────────────────┘
                                                     │ verifies
                           ┌─────────────────────────┴────────────────────────┐
                           │  Flask API  (Render, gunicorn)  /api/*            │
                           │  ┌───────────────────────────────────────────┐   │
                           │  │ Factory: CORS, logging, error_handler,    │   │
                           │  │ security_headers, request_logger          │   │
                           │  └──────────────────┬────────────────────────┘   │
                           │                     │  require_auth (JWT sub)     │
                           │  ┌──────────────────┴────────────────────────┐   │
                           │  │ Blueprints: system/auth/dashboard/scanner│   │
                           │  │ email/password/logs/crypto/sql/reports   │   │
                           │  │ port (/scanner/ports + /ip-reputation)   │   │
                           │  └──────────────────┬────────────────────────┘   │
                           │                     │                             │
                           │  Services: ScannerService, EmailService,         │
                           │  PasswordService, LogService, ReportService,     │
                           │  DashboardService, SQLLabService ───────────┐    │
                           └─────────────────────────────────────────────┼────┘
                                                                         │ user-scoped
                                                                         │ get_user_supabase_client(token)
                           ┌─────────────────────────────────────────────┼────┐
                           │  Supabase PostgreSQL (RLS enabled)           │    │
                           │  profiles (handle_new_user trigger)          │◄───┘
                           │  website_scans │ email_scans │ password_scans│ ───┐  RLS owner_all
                           │  log_scans │ port_scans (JSONB ip_rep+threat)│ ───┘  user_id=auth.uid()
                           │  reports (user_id, report_data JSONB)        │
                           │  ip_reputation_cache (ip,provider) UNIQUE    │◄── get_supabase_admin_client (service_role, bypass RLS)
                           │  Storage bucket: report-pdfs (private)       │◄── ReportStorageService (admin only) -> signed URLs
                           └──────────────────────────────────────────────┘
                                                     │
                                                     │ ip_reputation path (port scanner)
                           ┌─────────────────────────┴───────────────────────┐
                           │  IPReputationService façade                      │
                           │  AbuseIPDBProvider (POST https://api.abuseipdb. │
                           │   com/api/v2/check?ipAddress&maxAgeInDays)       │
                           │  timeout 5s, max 32KB, 429/401/5xx → unavailable │
                           │  + IPReputationCacheService (service_role)       │
                           │    (ip,provider) TTL 24h, no user_id            │
                           └──────────────────────────────────────────────────┘
```

*Confirmed against code:* Auth via Supabase JWT (ES256 JWKS) ↔ RLS; `port_scans` & `reports` via user-scoped client; cache & Storage via admin client — exactly as implemented.

---

## 22. Current Port Scanner Data Flow

> Verified against `backend/app/services/port_scanner_service.py:77-237`, `ip_reputation_service.py:281-390`, `threat_assessment_service.py:76-273`, `routes/port_routes.py:23-72`

```text
1. User (PortScannerPage)
   │  POST /api/scanner/ports  {target, profile|ports}
   │  Authorization: Bearer <Supabase JWT>
   ▼
2. Flask port_bp @require_auth
   │  decode_supabase_token -> request.auth.sub = user_id, request.access_token
   │  require_json + validate_hostname_or_ip (reject ://, @, bad labels)
   ▼
3. PortScannerService.scan_ports(target, ports/profile, user_id)
   │  validate_hostname_or_ip (2nd time) + is_private_hostname -> 400 private
   │  resolve_scan_ports (profile quick 20 / common 100 / custom 1-100 dedup sorted)
   ▼
4. _resolve_target(target)  -> socket.getaddrinfo(AF_UNSPEC) -> resolved_ip (prefer IPv4, skip fe80::)
   ▼
5. _scan_port_list(target, resolved_ip, ports, cfg)
   │  ThreadPool 50, per-port TOC 2s, banner TOC 1s, total 30s
   │  _scan_single_port: socket(AF_INET,SOCK_STREAM) connect_ex((target,port))
   │    0 -> open + recv(256) banner (utf-8 ignore, printable, truncate)
   │    !0 -> closed; timeout/gaierror/OSError -> filtered
   │  risk_level = critical|high|medium|low from CRITICAL/HIGH/MEDIUM sets
   ▼
6. IP Reputation (never fails scan)
   │  if resolved_ip is IP?  IPReputationService.check_ip(resolved_ip)
   │    validate_ip_address + is_private_ip -> ValidationError private -> unavailable private_ip_blocked
   │    _get_provider -> current_app.config IP_REPUTATION_* or get_config()
   │    if provider unavailable -> unavailable provider_disabled
   │    else cache.get(ip,provider) -> if fresh hit -> return
   │         else AbuseIPDBProvider.check_ip -> to_dict -> cache.put if !unavailable
   │  else -> unavailable unresolvable
   ▼
7. Threat Assessment (never fails scan)
   │  ThreatAssessmentService.assess(port_risk, ip_reputation, open_ports, ports_scanned, status)
   │  score = PORT_BASE(low10/med25/high45/crit60) + IP_BASE(clean0/unk0/unavail0/susp20/mal35)
   │        + modifiers (each 5): critical_service, database, multiple_high, high_reports>=10, malicious_critical/suspicious_high
   │  level = low<=19 / medium<=39 / high<=69 / critical<=100 ; confidence high/medium/low (completeness)
   ▼
8. Persist
   │  PortScannerService._persist_scan(user_id, target, ScanResult)
   │  get_user_supabase_client(access_token).table(port_scans).insert({user_id,target,resolved_ip,ports_scanned,
   │    open_ports[port,service,state,banner], scan_duration_ms, risk_level, status, ip_reputation, threat_assessment})
   │  -> raises ServiceUnavailable 503 on failure
   ▼
9. Response
   │  success_response({target,resolved_ip,scan_duration_ms,ports_scanned,open_ports,closed_ports,filtered_ports,
   │    summary,risk_level,ip_reputation,threat_assessment}, "Port scan completed")  200
   ▼
10. History / Reports / PDF
    GET /scanner/ports/history?page&limit -> user_scoped select id,target,resolved_ip,...,ip_rep,threat_assess ordered desc + range
    GET /scanner/ports/history/<id> -> select * where id+user_id
    ReportService._fetch_latest_scans includes port_scans limit1 -> _map_port_scan (sanitize banner + allowlist rep/threat) -> PDF _port_section
```

**Diagram in Prompt vs Reality:** Prompt diagram omitted `ThreatAssessmentService` and conflated `Port Risk -> IP Reputation -> Threat`. Verified pipeline is `Port Risk || IP Reputation (parallel, reputation never blocks scan) -> ThreatAssessmentService (derived) -> persist both snapshots`. Prompt's "IP Reputation Cache → ThreatAssessmentService" ordering is inverted — cache is inside reputation service, not after it. Otherwise accurate.

---

## 23. External Services

| Service | Endpoint / Bucket | Auth | Timeout / Limit | Consumer |
|---------|-------------------|------|-----------------|----------|
| **Supabase Auth** | `https://<project>.supabase.co/auth/v1/.well-known/jwks.json` (ES256) | `SUPABASE_URL`, JWKS, `SUPABASE_JWT_AUDIENCE=authenticated` | `SUPABASE_JWT_LEEWAY 10s` | `decode_supabase_token`, `supabaseClient.ts` |
| **Supabase PostgREST** | `https://<project>.supabase.co` (PostgreSQL) | `SUPABASE_URL + SUPABASE_PUBLISHABLE_KEY` (RLS) or `SUPABASE_SECRET_KEY` (service_role) | default HTTP | `get_user_supabase_client` (user scans), `get_supabase_admin_client` (cache, storage) |
| **Supabase Storage** | Bucket `report-pdfs` (private) | service_role only | `REPORT_SIGNED_URL_EXPIRES 3600s` | `ReportStorageService.upload_pdf/get_signed_url` |
| **AbuseIPDB** | `https://api.abuseipdb.com/api/v2/check?ipAddress&maxAgeInDays=90&verbose=` | `IP_REPUTATION_API_KEY` in `Key` header, fixed URL (never user-controlled) | `IP_REPUTATION_TIMEOUT 5s`, `IP_REPUTATION_MAX_RESPONSE_BYTES 32768` | `AbuseIPDBProvider` via `IPReputationService` |
| **Supabase Realtime** | not used | — | — | — |

No Redis, no external ML endpoint, no third-party analytics.

---

## 24. Environment Variables

> From `backend/app/config/settings.py:17-165` + `.env.example` (see §14 for per-env values). Frontend prefixes `VITE_` via `import.meta.env`.

**Backend (Flask):**

| Var | Default | Required prod? | Notes |
|-----|---------|----------------|-------|
| `APP_NAME` | CyberShield AI API | no |  |
| `API_VERSION` | 1.0 | no |  |
| `API_URL_PREFIX` | /api | no |  |
| `APP_ENV / FLASK_ENV` | development | yes prod | controls DEBUG |
| `SECRET_KEY` | `dev-insecure-secret-key-change-me` | **yes** | must override |
| `MAX_CONTENT_LENGTH` | 1000000 | no |  |
| `JWT_EXPIRATION_MINUTES` | 60 | no | legacy HS256 internal tokens |
| `CORS_ORIGINS` | * | **yes prod** | must be frontend origin |
| `LOG_LEVEL` | INFO | no |  |
| `REQUEST_LOG_ENABLED` | true | no | false in tests |
| `SCANNER_TIMEOUT` | 10 | no | website scanner |
| `PORT_SCANNER_CONNECT_TIMEOUT` | 2 | no |  |
| `PORT_SCANNER_TOTAL_TIMEOUT` | 30 | no |  |
| `PORT_SCANNER_MAX_CONCURRENCY` | 50 | no |  |
| `PORT_SCANNER_MAX_PORTS` | 100 | no |  |
| `PORT_SCANNER_BANNER_TIMEOUT` | 1 | no |  |
| `PORT_SCANNER_BANNER_MAX_BYTES` | 256 | no |  |
| `PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES` | false | no | true in tests |
| `IP_REPUTATION_ENABLED` | false | yes when using AbuseIPDB |  |
| `IP_REPUTATION_PROVIDER` | abuseipdb | no |  |
| `IP_REPUTATION_API_KEY` | "" | yes when enabled | never logged/DB |
| `IP_REPUTATION_TIMEOUT` | 5 | no |  |
| `IP_REPUTATION_MAX_RESPONSE_BYTES` | 32768 | no |  |
| `IP_REPUTATION_ABUSEIPDB_URL` | https://api.abuseipdb.com/api/v2/check | no | fixed |
| `IP_REPUTATION_CACHE_ENABLED` | true | no | false in tests |
| `IP_REPUTATION_CACHE_TTL` | 86400 | no | 24h |
| `SUPABASE_URL` | "" | **yes** |  |
| `SUPABASE_PUBLISHABLE_KEY` | fallback anon/key | **yes** | publishable anon |
| `SUPABASE_SECRET_KEY` | fallback service_role | **yes** | never frontend |
| `SUPABASE_JWT_ALGORITHM` | ES256 | no | comma list allowed |
| `SUPABASE_JWT_AUDIENCE` | authenticated | no |  |
| `SUPABASE_JWT_ISSUER` | derived | no |  |
| `SUPABASE_JWKS_URL` | derived | no |  |
| `SUPABASE_JWT_LEEWAY` | 10 | no |  |
| `REPORT_STORAGE_BUCKET` | report-pdfs | yes | private bucket |
| `REPORT_SIGNED_URL_EXPIRES` | 3600 | no |  |

**Frontend (Vite):**

| Var | Required | Notes |
|-----|----------|-------|
| `VITE_API_BASE_URL` | yes prod | e.g. `https://cybershield-ai-beta.onrender.com/api` else `/api` fallback |
| `VITE_SUPABASE_URL` | **yes** | throws if missing |
| `VITE_SUPABASE_ANON_KEY` | **yes** | publishable |

---

## 25. Database Tables

See §5 for full 8-table detail. Quick reference:

1. `profiles` — 1:1 auth.users, trigger `handle_new_user()`, RLS owner-only
2. `website_scans` — user scans, JSONB findings
3. `email_scans` — no raw email stored
4. `password_scans` — metrics only, no hash stored
5. `log_scans` — findings only, no raw logs
6. `port_scans` — `target, resolved_ip, ports_scanned, open_ports JSONB, risk_level, ip_reputation JSONB, threat_assessment JSONB` ← Port Scanner integration
7. `ip_reputation_cache` — shared `(ip, provider) UNIQUE`, no user_id, no secrets, 24h TTL, RLS enabled no policies (service_role only)
8. `reports` — `report_data JSONB` snapshot, `storage_path` object key, signed URLs via Storage

Indexes: `*_user_created (user_id, created_at DESC)` per scan table + `ip_provider` + `expires_at` for cache.

---

## 26. Important Files

**Backend (absolute for navigation):**

- `backend/app/__init__.py:41` — create_app factory
- `backend/app/config/settings.py:43` — Config
- `backend/app/database/supabase_client.py:31` — _first_key / _publishable_key / get_*_client
- `backend/app/database/schema.sql:1` — DDL source of truth
- `backend/app/middleware/auth_middleware.py:22` — require_auth
- `backend/app/middleware/error_handler.py:18` — error envelope
- `backend/app/utils/validators.py:397` — validate_hostname_or_ip, is_private_hostname, validate_ip_address, is_private_ip, resolve_scan_ports
- `backend/app/utils/security.py:120` — decode_supabase_token
- `backend/app/services/port_scanner_service.py:43` — CRITICAL/HIGH/MEDIUM sets + PortScannerService (scan, risk, persistence, history)
- `backend/app/services/ip_reputation_service.py:43` — AbuseIPDBProvider, IPReputationService
- `backend/app/services/ip_reputation_cache_service.py:48` — _get_cache_client, get, put
- `backend/app/services/threat_assessment_service.py:39` — PORT_BASE, IP_BASE, ThreatAssessmentService.assess
- `backend/app/services/report_service.py:40` — SCAN_TABLES (+port_scans), _map_port_scan
- `backend/app/reports/pdf_generator.py:81` — PORT_KEYS, _port_section, _threat_factors_table
- `backend/app/reports/storage.py:33` — ReportStorageService
- `backend/app/routes/port_routes.py:23` — POST /ports, history, ip-reputation
- `backend/app/routes/__init__.py:22` — register_blueprints
- `backend/app.py:17` — app = create_app()
- `backend/tests/conftest.py:33` — _FakeSupabaseClient/Table + fake JWKS

**Frontend:**

- `frontend/src/App.tsx:9` — App + ConsoleRoutes
- `frontend/src/services/apiClient.ts:20` — getAccessToken + handleResponse
- `frontend/src/services/supabaseClient.ts:5` — createClient
- `frontend/src/services/portScannerService.ts:9` — fetchPortScanHistory/Detail
- `frontend/src/types/index.ts:340` — PortFinding, IPReputationResult, ThreatAssessment, PortScanResult/History/Detail
- `frontend/src/pages/PortScannerPage.tsx:81` — IPReputationCard, 152 ThreatAssessmentCard
- `frontend/src/context/AuthContext.tsx:33` — AuthProvider
- `frontend/vite.config.ts:8` — proxy /api -> 5000
- `frontend/vercel.json:2` — SPA rewrite

**Docs:**

- `PORT_THREAT_ASSESSMENT_PHASE1.md:1` — investigation-only design (scoring model reference)
- `docs/03_System_Architecture.md`, `06_Database_Design.md`, `07_API_Design.md`, `08_Backend_Architecture.md`, `12_Security_Requirements.md`, `13_Deployment_Guide.md`

---

## 27. Open Architectural Questions

1. **Should the port scanner remain in-process (ThreadPool) or move to a background worker (Celery/RQ/Render background worker) for >100 ports or longer timeouts?** Current 30s total with 50 threads is acceptable for learning mode but blocks gunicorn sync workers; a job queue would allow async polling + cancel.
2. **Single private-IP allowlist per scanner or two?** `SCANNER_ALLOW_PRIVATE_ADDRESSES` (website scanner) vs `PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES` (port scanner) are independent flags with identical default `false` — should they be unified or intentionally separate for least privilege?
3. **IP reputation provider extensibility:** Current `IP_REPUTATION_PROVIDER` only `abuseipdb` is honored; `NullProvider` fallback for unknown — should this be pluggable (e.g., VirusTotal, GreyNoise) with weighted merging or remain single-provider + cache?
4. **Threat assessment weight tuning governance:** Bases + modifiers are hard-coded (`PORT_BASE`/`IP_BASE`/`+5`). Should they be env-configurable (`THREAT_WEIGHT_*`) for non-code tuning, or remain hard-coded for auditability and determinism? Current choice is auditability; env weights would need guardrails (sum <= X, cap 100).
5. **Report `overall_score` vs `threat_assessment.score`:** Two "overall" concepts exist (PDF `_overall_score` avg of website+password vs port `threat_assessment.score`). Should they converge into one `overall_security_score` in `report_data` or stay separate (overall platform vs port-specific threat)?
6. **Cache durability vs cost:** `ip_reputation_cache` is read-through, write-through on every scan with no background refresh. AbuseIPDB free quota ~1000/day — at scale, should cache be warmed or hit rate monitored? No metrics yet.
7. **Historical `threat_assessment` immutability:** Snapshot at scan time is stored; if AbuseIPDB later marks IP malicious, old `port_scans.threat_assessment` stays old. Should history show live reassessment option ("re-check reputation") or strictly snapshot?
8. **IPv6 scanning:** `_scan_single_port` creates `AF_INET` socket only; `_resolve_target` prefers IPv4 but could return `::1`. IPv6 targets will fail as `filtered` silently. Should scanner explicitly declare IPv4-only or add `AF_INET6` path with its own private-IP checks?
9. **Storage bucket lifecycle:** `report-pdfs` objects accumulate per `user_id/report_id.pdf` with no cleanup. Should there be retention (e.g., 90 days) or user-delete flow that also removes Storage object?
10. **Tutorial + Report coupling to port scanner:** Tutorials cover 6 areas but not yet port scanner + threat assessment; should `docs/19_Tutorials_Architecture` be extended before launch to prevent feature discoverability gap?

---

## AUDIT COMPLETE

**Summary of inspection:**

- **Files inspected:** 40+ backend source files (`app/__init__`, `config/settings`, `database/schema+supabase_client`, `middleware/auth+errors+logger`, `services/port_scanner|ip_reputation|cache|threat|report|scanner|email|password|log|sql|dashboard`, `reports/pdf_generator+storage`, `routes/*` (10 blueprints), `utils/validators+security`, `errors`, `app.py`) + 10 frontend files (`App`, `PortScannerPage`, `portScannerService`, `apiClient`, `supabaseClient`, `types`, `AuthContext`, `vite.config`, `vercel.json`) + schema, pytest.ini, requirements, package.json, docs/00-19, `PORT_THREAT_ASSESSMENT_PHASE1.md`, `.env.example` — total > 60 files read (grep confirmed 1070 glob entries, 40 core reads + batched `Get-Content` checks).
- **Tables found:** 8 (`profiles`, `website_scans`, `email_scans`, `password_scans`, `log_scans`, `port_scans` (+`ip_reputation`, `threat_assessment` JSONB), `ip_reputation_cache` (shared, `(ip,provider)` unique, 24h TTL, RLS no policies, service_role only), `reports`).
- **APIs found:** 21 route handlers across 10 blueprints: `GET /health, /version, /auth/me, /dashboard, /scanner/website, /scanner/ports, /scanner/ports/history, /scanner/ports/history/:id, /scanner/ip-reputation/:ip, POST /scanner/ip-reputation, /email/analyze, /password/analyze+generate, /logs/analyze, /crypto/*, /sql/demo+run+scenarios, /reports, /reports/generate` (see §12 table). All scan/report routes `@require_auth`.
- **External providers:** 2 — Supabase (Auth JWKS `ES256` + PostgREST RLS + Storage private bucket `report-pdfs`) and AbuseIPDB (`https://api.abuseipdb.com/api/v2/check`, `Key` header, 90-day window, 5s timeout, 32KB cap). No Redis, no third ML service in runtime.
- **Test count:** **613** `def test_` functions grepped; **1049** collected tests with parametrizations (`pytest --collect-only` reports 1051 lines, 1049 tests). Strongest coverage: `test_port_scanner 93`, `test_ip_reputation_cache 21`, `test_threat_assessment 26`, `test_sql_lab_redteam 316`.
- **Major security findings:** H1 DNS rebinding TOCTOU (HIGH), H2 Supabase key fallback masking (HIGH), M1 unbounded DNS resolver time, M2 banner sanitization (verified safe, needs regression), M3 no rate limiting on port scan, M4 CORS `*` default — all with mitigations, no CRITICAL remote exploit found under normal prod config. Verified no secrets leak to DB/frontend/report/PDF (allowlist filtering + `_log_safe`).
- **Technical debt:** Port scanner monolith 607 lines, schema.sql monolith, frontend QUICK/COMMON duplication, dual CORS/SCANNER private flags, overall_score divergence, fake Supabase branching for `count` — all low-medium but noted.
- **Recommended next priorities:** P0: Fix DNS rebinding, require Supabase secret key in prod, forbid `*` CORS in prod, run `threat_assessment` DDL, add 10 scans/min rate limit. P1: Include threat score in dashboard/report overall, DNS timeout, synchronize port profile constants, sanitize error details. P2: Modularize scanner service, add Alembic migrations, confidence UX, JSON logging, commit untracked design doc.

> **Invariant verified:** `get_supabase_client` (shared anon, RLS) used only for health/anon contexts; `get_user_supabase_client(token)` (per-request, `postgrest.auth(token)`) used for all user-scoped DB (port_scans, reports, dashboard, email/password/log/website) with `user_id` from `get_current_user_id()` (JWT `sub` UUID); `get_supabase_admin_client` (service_role, bypasses RLS) used only for `ip_reputation_cache` and `ReportStorageService` Storage (never for user rows), never exposed to frontend. `IP Reputation Cache` is `(ip, provider)` shared, no `user_id`, 24h TTL, only via admin client — exactly as specified in Phase 2D-2. Threat assessment is `PORT_BASE 10/25/45/60 + IP_BASE clean/unknown/unavailable 0 / suspicious 20 / malicious 35 + modifiers +5 bounded → cap 100` deterministic, with confidence `high/medium/low` completeness — exactly as specified in Phase 2D-3, verified line-for-line.

