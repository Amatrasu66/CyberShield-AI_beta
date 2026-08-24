# CyberShield AI — Security Hardening Phase 1 (P0 Fixes)

**Date:** 2026-08-25  
**Scope:** P0 security fixes only — DNS TOCTOU, rate limiting, Supabase client safety  
**Branch:** `main` post `6d5aea8`  
**Audit source:** `CYBERSHIELD_PROJECT_AUDIT.md` §15 (H1, H2, M3)

---

## 1. Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| H1 | HIGH | DNS rebinding / TOCTOU in port scanner — validated IP ≠ connected IP | **FIXED** |
| H2 | HIGH | Supabase key fallback can silently downgrade `service_role → anon` for shared cache | **FIXED** |
| M3 | MEDIUM | No per-user rate limiting on expensive scanner endpoints | **FIXED** (process-local) |
| H2-ext | HIGH | Cached `None` Supabase client masks later valid config | **FIXED** |
| M1 | MEDIUM | Unbounded `getaddrinfo` DNS as DoS vector | **PARTIALLY MITIGATED** |
| M4 | MEDIUM | CORS `*` default | **REMAINING** (deployment hygiene, not code) |
| L1 | LOW | Verbose error details leak table names | **REMAINING** |

---

## 2. Root Causes

**H1 — TOCTOU:** `port_scanner_service.scan_ports` performed up to three independent `getaddrinfo` calls on the same hostname: (1) `is_private_hostname(target)` at validation, (2) `_resolve_target(target)` for `resolved_ip`, (3) `socket.connect_ex((target, port))` inside `_scan_single_port`. A malicious hostname could return a public IP at step 1/2 and a private `10.x/127.0.0.1` at step 3, bypassing SSRF guards. The scan socket used `AF_INET` only, so IPv6 link-local was not the core issue — the double-resolution was.

**H2 — Downgrade:** `ip_reputation_cache_service._get_cache_client()` tried admin → direct `create_client(url, secret)` → anon fallback, logging `cache_fallback_anon` and continuing. When `SUPABASE_SECRET_KEY` was unset, the shared `ip_reputation_cache` (RLS enabled, zero policies) was accessed via anon, which is denied by RLS and surfaced as a silent cache miss rather than an observable misconfiguration. `supabase_client.get_supabase_admin_client()` used `@lru_cache(maxsize=1)` so a cached `None` at first call persisted even after env was later set correctly.

**M3 — No rate limiting:** `POST /api/scanner/ports` can spawn 100 TCP connects × 50 threads × 30s per request. No server-side throttling existed; abuse would exhaust scanner host sockets and the AbuseIPDB quota (429 mapped to `unavailable` only).

---

## 3. Fixes

### 3.1 P0-1 DNS Rebinding (TOCTOU)

- Added `PortScannerService._resolve_target_secure(target, cfg)` — **single** `getaddrinfo(AF_UNSPEC)` call, validates **every** returned IP against `is_private / is_loopback / is_link_local / is_reserved / is_multicast / is_unspecified`. If any address is private and `PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES` is false, raises `ValidationError` before any socket.
- Fast-path for IP literals: `ipaddress.ip_address(target)` validates and returns normalized IP with no DNS at all.
- `scan_ports()` now calls `_resolve_target_secure` once; the returned `resolved_ip` (a validated IP string) is stored as `ScanResult.resolved_ip` and passed to `_scan_port_list` / `_scan_single_port`. The scanner **never** re-resolves the original hostname.
- `_scan_single_port` derives the socket family from the validated IP (`AF_INET6` for `version==6`, else `AF_INET`) and calls `connect_ex((resolved_ip, port))`. Unresolvable hostnames return `target` as-is and are handled as `filtered` per-port.
- `_resolve_target` retained as a thin wrapper delegating to the secure variant for backwards compatibility.
- `import ipaddress` added to `port_scanner_service.py`.

### 3.2 P0-2 Rate Limiting

- New `backend/app/middleware/rate_limiter.py`: process-local sliding-window limiter (`dict[str, deque[timestamps]]` + `threading.Lock`), keyed by `user:<sub>` (from `request.auth`) or `ip:<X-Forwarded-For|remote_addr>`.
- Decorator `@rate_limit("port_scan" | "ip_reputation")` reads limits from `current_app.config` (`RATE_LIMIT_<KEY>` / `WINDOW`) so values are **not client-controllable**. On exceed, raises `ApiError(429, code=RATE_LIMIT_EXCEEDED)` with `details={retry_after_seconds, limit, window_seconds}` — rendered via the central `error_handler` into the consistent `{success:false, error:{code, details}}` envelope, no stack trace.
- Applied to:
  - `POST /api/scanner/ports` → `port_scan`
  - `GET /api/scanner/ip-reputation/<ip>` → `ip_reputation`
  - `POST /api/scanner/ip-reputation` → `ip_reputation`
- History endpoints (`GET /ports/history*`) are read-only and cheap; not rate-limited in this phase by design — CHEAP vs EXPENSIVE separation.

### 3.3 P0-3 Supabase Client Safety

- `ip_reputation_cache_service._get_cache_client()` — **removed anon fallback** (former step 3). If admin is unavailable, returns `None` immediately with `cache_admin_unavailable*` log; `get()` then returns `None` (miss) and `put()` is a no-op. No silent `service_role → anon` downgrade.
- Direct `create_client` from `current_app.config` still attempted as step 2, but only when **secret** key is present; missing secret is now explicitly logged as `cache_admin_unavailable` instead of falling through.
- `app/database/supabase_client.py` — replaced `@lru_cache` with explicit `*_cached + *_config` tuples. `None` is **never cached**; only a non-None client is cached per `cache_key=(url, key)`. `clear_supabase_client_cache()` resets both slots and is aliased as `.cache_clear()` for backwards compatibility with `test_supabase_client.py` fixtures. This prevents a cached `None` at startup from masking a later valid env.

---

## 4. DNS Resolution Flow — Before / After

**Before (vulnerable):**
```
validate_hostname_or_ip(target)          # syntax only
is_private_hostname(target)              # getaddrinfo #1, checks any private
_resolve_target(target)                  # getaddrinfo #2 -> resolved_ip for display
_scan_port_list(target, ...)             # for each port:
  _scan_single_port(target, port)        # socket(AF_INET).connect_ex((target, port))
                                         # -> getaddrinfo #3 implicitly at connect time
                                         #    (can return different IP than #1/#2)
```

**After (fixed):**
```
validate_hostname_or_ip(target)          # syntax only
_resolve_and_validate_once(target):      # try ip_address(target) -> no DNS if literal
  if IP literal: validate private -> resolved_ip = normalized IP
  else:
    info = getaddrinfo(AF_UNSPEC)        # ONE call
    for each addr: ip = addr[4][0]; validate private/reserved/...
      if any private -> ValidationError (no socket ever created)
    resolved_ip = first non-fe80:: else first validated IP
_scan_port_list(resolved_ip, ports)      # for each port:
  _scan_single_port(resolved_ip, port)   # family = AF_INET6 if ipv6 else AF_INET
                                         # connect_ex((resolved_ip, port))  # no hostname DNS
```

Displayed `target` remains the original hostname; `resolved_ip` is the single validated IP used for every connection and for `ip_reputation` lookup.

---

## 5. Rate Limiting Architecture

- **Store:** in-process `defaultdict[str, deque]` keyed by `limiter_key:identity`. Sliding window evicts `timestamp <= now - window` on each check. Thread-safe via `Lock` (Gunicorn threads).
- **Identity:** `user:<JWT sub>` when `@require_auth` has run; else `ip:<XFF>` / `remote_addr`. All scanner routes are `@require_auth` first, so identity is user-bound.
- **Config-driven:** `RATE_LIMIT_PORT_SCAN` / `WINDOW` and `RATE_LIMIT_IP_REPUTATION` / `WINDOW` from Flask config (env-backed). Frontend cannot override via headers/body.
- **Response:** HTTP 429 `RATE_LIMIT_EXCEEDED` through `ApiError` → `error_handler`. Frontend sees the same envelope as other `ApiError`s; existing `apiClient.handleResponse` throws `ApiClientError(429)` which pages already surface.
- **Ordering:** `@require_auth` is applied **before** `@rate_limit` so unauthenticated requests get 401, not 429, and do not consume quota.
- **Cheap vs expensive:** Port scan (expensive, sockets) has stricter default than IP reputation (cheap, cache-backed) — `5/60s` vs `20/60s`.

**Production limitation (explicit):** The limiter is **process-local**. With `gunicorn --workers N` or multiple Render instances, each process has its own counter, so the effective global limit is `N × limit`. This does **not** provide distributed enforcement. A Redis/central store (`Flask-Limiter` + `redis` or a Supabase table counter) would be required for exact global limits. This tradeoff is intentional to avoid introducing Redis given the project's existing cache intentionally avoids it.

---

## 6. Supabase Client Security

| Concern | Before | After |
|---------|--------|-------|
| `service_role` exposure | `SUPABASE_SECRET_KEY` read only server-side; frontend uses `VITE_SUPABASE_ANON_KEY`. No leak path found; change preserves it. | No change; verified no API response / DB record / report includes secret. `ReputationResult` never holds `api_key`. |
| Privileged cache access | `_get_cache_client` fell back to anon on admin miss, silently denying via RLS. | Fail-closed: returns `None`; cache miss / no-op; log `cache_admin_unavailable*`. No downgrade. |
| Cached `None` masking | `@lru_cache` cached `None` from first call with empty env. | Manual cache keyed on `(url, key)`, only caches non-None; `clear_supabase_client_cache()` aliased as `.cache_clear()`. |
| User isolation | All user tables via `get_user_supabase_client(token).postgrest.auth(token)` → RLS `auth.uid()`. | Unchanged; verified `_persist_scan`, `get_scan_history`, `get_scan_detail` use user-scoped client only. `ip_reputation_cache` has no `user_id`, never stores JWTs, and is accessed only via admin (or not at all). |
| No JWT/api_key in DB | Allowlist payloads in `IPReputationCacheService.put` and `_map_port_scan` exclude secrets. | Verified via regression tests: `ReputationResult.to_dict()` contains no `api_key`, cache payload contains no `jwt/token/bearer`. |

---

## 7. Tests

**New file:** `backend/tests/test_security_hardening_p0.py` — 24 tests.

| Bucket | Tests | What they prove |
|--------|-------|-----------------|
| DNS TOCTOU | 12 | Single resolution + validated IP used for `connect_ex`; hostname private → 400 with no socket; mixed public+private → 400; public hostname allowed; IPv4 literal no DNS + `AF_INET`; IPv6 literal (bracketed `2600::` public) no DNS + `AF_INET6`; IPv6 `::1`/fe80 multicast/unspecified/reserved blocked; rebinding simulation pinned to first validated IP |
| Rate limiting | 5 | `ports` limit 2/60s — 2×200 then 429 with `{success:false, error:{code:RATE_LIMIT_EXCEEDED, details:{retry_after_seconds}}}`; header/body cannot override limits; unauth → 401 not 429; two users have independent buckets; `ip-reputation` has independent limit |
| Supabase safety | 7 | `admin=None` → cache `get` miss without calling anon; `put` no-op without anon; `AbuseIPDBProvider` result contains no `api_key`; cache payload contains no `jwt/token/bearer`; API response contains no `service_role/secret`; cached-None helpers cleared correctly |

**Existing suites:** `python -m pytest backend/tests/ -q` → **1074 passed** (was 1049; +25 new, 1 adjusted). No regressions.

---

## 8. Production Limitations

- **Rate limiter is per-process.** Under `gunicorn -w 4` the global throughput for port scans is `4 × RATE_LIMIT_PORT_SCAN` per window. Under multiple Render containers it multiplies further. This is documented and must not be represented as a distributed guarantee.
- **DNS resolution still uses the system resolver** with no explicit timeout argument to `getaddrinfo`. A slow upstream resolver can block a worker thread. The single-resolution fix reduces this from up to 3 calls to 1, but a dedicated timeout (e.g., running `getaddrinfo` in an executor with a watchdog) is not included in this phase.
- **CORS default remains `*`** in `settings.Config`. Production must set `CORS_ORIGINS` explicitly (Render env). A startup check that refuses `*` when `APP_ENV=production` is recommended but not implemented here (kept as doc risk instead of code change to preserve API compatibility).

---

## 9. Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `RATE_LIMIT_ENABLED` | `true` | Master toggle. When `false`, all limiters are bypassed (useful for tests/maintenance). |
| `RATE_LIMIT_PORT_SCAN` | `5` | Max `POST /api/scanner/ports` per user per window. Stricter because it does network I/O. |
| `RATE_LIMIT_PORT_SCAN_WINDOW` | `60` | Window in seconds for port-scan limiter. |
| `RATE_LIMIT_IP_REPUTATION` | `20` | Max `GET\|POST /api/scanner/ip-reputation*` per user per window. Higher because cache-backed. |
| `RATE_LIMIT_IP_REPUTATION_WINDOW` | `60` | Window in seconds for reputation limiter. |
| `SUPABASE_URL` | `""` | Required. Missing → clients return `None`, caches become misses (fail-closed). |
| `SUPABASE_SECRET_KEY` / `SUPABASE_SERVICE_ROLE_KEY` | `""` | Required for `ip_reputation_cache` and `report-pdfs` storage. Missing → cache disabled (miss/no-op) with log, not anon downgrade. |
| `SUPABASE_PUBLISHABLE_KEY` / `SUPABASE_ANON_KEY` | `""` | Required for user-scoped RLS. Never use secret here. |
| `PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES` | `false` | When `true`, private IPs bypass validation (testing/dev only). |

All `RATE_LIMIT_*` variables are read **only** on the backend from `current_app.config`; they cannot be overridden via request headers, query params, or body.

---

## 10. Deployment Requirements

- **Backend (Render / Gunicorn):** No new infra dependency. Python deps unchanged (`requirements.txt` not modified). Set `RATE_LIMIT_PORT_SCAN=5`, `RATE_LIMIT_PORT_SCAN_WINDOW=60`, `RATE_LIMIT_IP_REPUTATION=20`, `RATE_LIMIT_IP_REPUTATION_WINDOW=60` (or tighter) in the Render environment. Multiple workers are supported but see §8. Clearing `RATE_LIMIT_ENABLED=false` disables limiting without redeploy for emergencies (not recommended).
- **Database (Supabase):** No schema migration. `ip_reputation_cache` remains shared with `ENABLE ROW LEVEL SECURITY` and zero policies; `service_role` bypasses RLS. Ensure `SUPABASE_SECRET_KEY` is set in the backend env; do **not** set it as `VITE_*` in Vercel.
- **Frontend (Vercel):** No env or code changes. `apiClient` already propagates 429 via `ApiClientError`; pages surface the error message. No frontend build-time config for rate limits.
- **Rollout check:** After deploy, `POST /api/scanner/ports` as an authenticated user 6 times within 60s should yield `429 {success:false, error:{code:RATE_LIMIT_EXCEEDED}}` on the 6th call (with default `5`). Private target `POST {"target":"10.0.0.1","ports":[80]}` must return `400` regardless of DNS state. `GET /api/scanner/ip-reputation/8.8.8.8` must succeed for public IPs and `400` for `192.168.1.1`.

---

## 11. Remaining Security Risks

| Risk | Status | Detail |
|------|--------|--------|
| DNS resolver DoS (M1) | **PARTIALLY MITIGATED** | Reduced from 3 to 1 `getaddrinfo` per scan; still no explicit resolver timeout. Mitigation: bound scanner timeouts/concurrency; future: resolve in executor with timeout. |
| CORS `*` default (M4) | **REMAINING** | Production must set `CORS_ORIGINS` to the Vercel origin. Code default is `*` for dev convenience. Recommend CI check `APP_ENV=production ⇒ CORS_ORIGINS != *`. |
| Error detail verbosity (L1) | **REMAINING** | `ServiceUnavailableError` surfaces `details={table, error:type}`. Useful for debugging; low risk since table names are not secret, but could be trimmed in prod. |
| IP reputation 429 circuit-break | **REMAINING** | AbuseIPDB 429 is mapped to `unavailable rate_limited` per-IP, but no cross-IP circuit-break or backoff is implemented. Burst abuse can still consume quota until `rate_limit` is hit. |
| Banner stored XSS surface (M2) | **REMAINING** (accepted) | Banners are sanitized to printable + `\n\t\r` and truncated at 256B, and never rendered as `innerHTML`. Regression coverage recommended but out of P0 scope. |
