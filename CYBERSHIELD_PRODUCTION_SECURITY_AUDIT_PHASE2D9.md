# CYBERSHIELD AI — PRODUCTION SECURITY & REGRESSION AUDIT PHASE 2D-9

**Date:** 2026-08-25 (Audit performed: 2026-08-25 IST, read-only)
**Auditor:** Muse Spark (Opencode) — inspection only, no code/schema/env changes
**Scope:** Full repository `CyberShield-AI/` @ head (1135 passing backend tests, `npx tsc --noEmit` pass, `npm run build` pass)
**Predecessors:** Phase 2D-1 (cache), 2D-3 (threat assessment), 2D-5 (DNS watchdog), 2D-6 (CORS/error), 2D-7 (circuit breaker), 2D-8 (IPv6 bare)
**Deployment targets:** Frontend Vercel `cyber-shield-ai-beta-topaz.vercel.app`, Backend Render `cybershield-ai-beta.onrender.com`, Supabase PostgreSQL

---

## 1. Executive Summary

CyberShield AI is a **well-hardened educational pentest platform**. Phases 2D-5 through 2D-8 have closed the P0/M1 gaps identified in the original `CYBERSHIELD_PROJECT_AUDIT.md`: DNS TOCTOU now uses single validated-IP resolution with bounded watchdog, IPv6 bare/bracketed is handled without colon-truncation, rate limiting and circuit breaker are process-local but sufficient for the documented single-instance Render tier, CORS wildcard is stripped in production, and error details are allow-listed.

**Overall health: `PRODUCTION READY WITH CONDITIONS` (see §20).** No CRITICAL unauthenticated RCE, secret leak, or IDOR was found that survives normal production config (`APP_ENV=production`, `CORS_ORIGINS=https://cyber-shield-ai-beta-topaz.vercel.app`, `SUPABASE_SECRET_KEY` backend-only). Two HIGH findings remain **acceptable with documented conditions** (process-local limiter/circuit), one MEDIUM remains (retry semantics for DNS timeout vs `filtered`), all other items are LOW/INFO.

**Counts:** 1135 backend tests pass; 0 new HIGH that blocks production if documented operational checks are followed.

---

## 2. Current Architecture

```
Vercel (React 18.2 + Vite 5) --Bearer JWT--> Flask 3.1 / Gunicorn (Render) --PostgREST--> Supabase PG
               |                                     |  +-- JWKS ES256 verify (PyJWKClient)
               +-- supabase-js Auth -----------------+  +-- IP Reputation: AbuseIPDB → cache → circuit breaker
                                                     +-- Threat Assessment (pure, deterministic)
                                                     +-- Reports (private bucket report-pdfs, signed URL 3600s)
```

Key invariants preserved: `user_id` always from `request.auth.sub` (JWT), never request body; `ip_reputation_cache` shared `(ip,provider)` with RLS no policies → `service_role` only; `port_scans.threat_assessment` snapshot persisted alongside `ip_reputation`; frontend is display-only (no weight/secret bundling).

Deployment docs: `README.md` live demo links, `frontend/vercel.json` SPA rewrite, `frontend/vite.config.ts` proxy `/api→localhost:5000`, `backend/requirements.txt` pinned (Flask 3.1, supabase 2.31, reportlab 4.0, requests 2.33, cryptography 43).

---

## 3. Port Scanner Security

**Files:** `backend/app/services/port_scanner_service.py:43-728`, `backend/app/utils/validators.py:398-553`, `backend/app/routes/port_routes.py:1-72`, `backend/app/config/settings.py:96-104`

**Verified:**

| Control | Value | Evidence | Verdict |
|---------|-------|----------|---------|
| TCP connect only | `socket.AF_INET/AF_INET6, SOCK_STREAM, connect_ex` | `port_scanner_service.py:446-450` `SOCK_STREAM`; `inspect` tests `test_no_stealth`/`test_no_udp` assert no `SOCK_RAW`/`SOCK_DGRAM` | **No issue** |
| No SYN/stealth, no UDP, no exploit, no credential, no `subprocess` | — | `grep IPPROTO_TCP|exploit|brute` → none; only `connect_ex` | **No issue** |
| Port range | `1-65535` | `validators.py:340-341` `1 <= port <= 65535` | **No issue** |
| Max ports | `100` default | `settings.py:100` `PORT_SCANNER_MAX_PORTS=100`; `validators.py:348-351` raises `Too many ports` | **No issue** |
| Connect timeout | `2s` | `settings.py:97` `CONNECT_TIMEOUT=2`, `port_scanner_service.py:371` `per_port_timeout` | **No issue** |
| Total timeout | `30s` | `settings.py:98` `TOTAL_TIMEOUT=30`, `port_scanner_service.py:396` `as_completed(..., timeout=total)` | **No issue** |
| Banner timeout / size | `1s / 256B` | `settings.py:101-102`, `port_scanner_service.py:446-464` `recv(banner_max_bytes)` + printable filter + `banner[:256]+"..."` | **No issue** |
| Concurrency | `50` | `settings.py:99` `MAX_CONCURRENCY=50`, `ThreadPoolExecutor(max_workers=50)` | **No issue** |
| DNS timeout | `3.0s` default, clamp `0-10` | `settings.py:104` `_env_float(...,3.0)`, `port_scanner_service.py:274-279` clamp, `322-354` `_getaddrinfo_with_timeout` via `ThreadPoolExecutor` + `future.result(timeout)` + `shutdown(wait=False)` | **No issue** |
| Rate limiting | `5/60s` port | `settings.py:179` `RATE_LIMIT_PORT_SCAN=5`, `port_routes.py:25` `@rate_limit("port_scan")` | **No issue** (see §10) |
| Family-aware IPv6 | — | `port_scanner_service.py:438-450` `ip_address(resolved_ip).version==6 → AF_INET6` else `AF_INET6` | **No issue** |

**DNS rebinding / TOCTOU — exact same IP guarantee:** `validators.py:408-467` now returns bare IP directly; `port_scanner_service.py:114` `resolved_ip = _resolve_target_secure(target,cfg)` does **single** `getaddrinfo` inside `_getaddrinfo_with_timeout:335`; validates every returned IP against `is_private/loopback/link_local/reserved/multicast/unspecified` (`289-308`); chooses first non-`fe80::`; `_scan_port_list:362` + `_scan_single_port:419` connect **only** to `resolved_ip` (never hostname). Mock test `test_security_hardening_p0.py:48` asserts `call_count==1` and `connected_to==validated_ip`; `test_port_scanner_dns_watchdog.py` asserts probe after watchdog still uses validated IP. **No regression found.**

**Findings — §3: No issue found.** All scanner invariants intact.

---

## 4. SSRF Analysis

**Traced flow (actual code):**

```
POST /api/scanner/ports {target, ports|profile}
→ routes/port_routes.py:32 validate_hostname_or_ip(target)  // scheme/credentials rejected, bare IPv6/bracketed handled, hostname:port stripped
→ port_scanner_service.py:105 validate_hostname_or_ip again (defense-in-depth)
→ _resolve_target_secure:105
     ├─ ip_address(target) fast-path → if private/loopback/link_local/reserved/multicast/unspecified and !ALLOW_PRIVATE → ValidationError (no DNS)
     └─ getaddrinfo_with_timeout(target, dns_timeout=3s) → for each addr validate same 6 flags → ValidationError if any private
→ resolved_ip (validated)
→ _scan_port_list(resolved_ip) → _scan_single_port(resolved_ip) → socket(family).connect_ex((resolved_ip,port))  // no hostname DNS
→ ip_reputationService.check_ip(resolved_ip) → validate_ip_address + is_private_ip → ValidationError before provider → never reaches AbuseIPDB
```

*Loopback / RFC1918 / link-local / reserved / multicast / unspecified* — blocked at both the IP-literal fast-path (`254-268`) and the DNS-resolved loop (`294-308`), covering IPv4 and IPv6 (including `::1`, `fe80::`, `ff02::`, `::`). Tests `test_security_hardening_p0.py:81-181` + `test_ipv6_target_validation.py:68-86` confirm.

**Private bypass attempts:**

| Vector | Blocked where | Verdict |
|--------|---------------|---------|
| `127.0.0.1`, `::1`, `[::1]` | `ip_address` fast-path + DNS validation | **Blocked** |
| `10.0.0.1/192.168.1.1/172.16` | same | **Blocked** |
| `169.254.169.254` (AWS metadata link-local) | `is_link_local` | **Blocked** — `test_port_scanner.py:1011` explicitly asserts 400 |
| `10.0.0.1:80` / `example.com:8080` | `validators.py:443-462` strips port to `example.com` before DNS; IP-literal port case extracts host then validates IP part (`192.168.1.1:80 → 192.168.1.1 → private → 400`) | **Blocked**; new `test_ipv6_target_validation.py:126` confirms `10.0.0.1:80` blocked |
| `evil.example.com → 10.0.0.5` via DNS | `getaddrinfo` returns private → `ValidationError` before socket | **Blocked** — `test_private_ip_in_dns_is_blocked` |
| Mixed `8.8.8.8,192.168.1.1` | any private in `info` → `ValidationError` | **Blocked** |
| `0.0.0.0` / `::` / `240.0.0.1` / `224.0.0.1` | `is_unspecified`/`is_reserved`/`is_multicast` | **Blocked** |
| IPv4-mapped `::ffff:127.0.0.1` | `ip_address("::ffff:127.0.0.1").is_private`? Python marks embedded loopback as private/loopback — blocked (not explicitly tested but flag set covers `is_private`/`is_loopback`) | **Blocked (by flags)** |
| Redirects | Scanner never follows HTTP redirects (`socket.connect`, not `requests`); unrelated to port scanner | **N/A** |
| Hostname `localhost` | `is_private_hostname` would resolve to `127.0.0.1` → blocked; `validate_hostname_or_ip("localhost")` passes hostname regex but `_resolve_target_secure` will block via DNS | **Blocked** |

**No path found where validated IP ≠ connected IP.** **Findings — §4: No issue found** for SSRF.

---

## 5. DNS Security

| Control | Before Phase 2D-5 | After |
|---------|-------------------|-------|
| Resolution count | 3 (`is_private_hostname` + `_resolve_target` + `connect_ex` hostname) | **1** (`_getaddrinfo_with_timeout`) |
| Timeout | none (system 5-15s) | `PORT_SCANNER_DNS_TIMEOUT 3.0s` via `ThreadPoolExecutor` + `future.result(timeout)` + `shutdown(wait=False)` — worker freed after ≤3s |
| TOCTOU | public at validation → private at connect possible | **Fixed** — validated IP pinned and reused |
| Error handling | `gaierror` → return target as-is → filtered ports | `gaierror` → filtered; `TimeoutError` → `ValidationError("Target host resolution timed out", reason=dns_timeout)` (generic, no resolver leak) |

**Remaining nuance:** `tests/test_port_scanner_dns_watchdog.py:213` tolerates `<0.30s` for a `0.05s` timeout + `0.15s` sleep — loose but acceptable given CI load; not a security issue.

**Findings — §5: No issue found.** DNS watchdog is correct and Gunicorn-compatible (no Redis).

---

## 6. IPv4/IPv6 Security

**Parser diagnosis (Phase 2D-8):** Original `validators.py:424` `host_part = target.split(":",1)[0]` truncated bare `2001:4860:4860::8888` to `"2001"` and returned it as hostname → DNS instead of IPv6 scan. Fixed by inserting **bare IP fast-path** before any `":"` split and **IPv6-with-port detection** (`rsplit(":",1)` host valid IP + port digits → bracket-required error).

Verified matrix (actual `python -m pytest test_ipv6_target_validation.py` 15 passed):

| Input | Result | Correct |
|-------|--------|---------|
| `2001:4860:4860::8888` | `→ "2001:4860:4860::8888"` `AF_INET6` | **Yes** |
| `[2001:4860:4860::8888]:8080` | `→ "2001:4860:4860::8888"` | **Yes** |
| `::1`, `fe80::1`, `ff02::1`, `::` | validated then scanner `ValidationError` when `!ALLOW_PRIVATE` | **Yes** |
| `::1:80` / `…:80` bare | `ValidationError` bracket required | **Yes** |
| `example.com:8080` / `192.168.1.1:80` | `→ host` | **Yes** |
| `example.com:99999` / `abc` | `ValidationError` | **Yes** |

**Findings — §6: No issue found.** Bare/bracketed, blocking, and `colons != port` behavior is now correct.

---

## 7. IP Reputation Security

**Files:** `ip_reputation_service.py:42-390`, `ip_reputation_cache_service.py:1-321`

- **API key handling:** `settings.py:109` `IP_REPUTATION_API_KEY` read only via `get_config()`/`current_app.config`; `AbuseIPDBProvider.__init__:118` stores `self.api_key` stripped, never logged ( `_log_safe` strips `key/token/auth`), never returned in `ReputationResult` (allowlist `to_dict` via `asdict` has no `api_key`), never persisted (`ip_reputation_cache_service:237-253` allowlist excludes secrets; `report_service:267` allowlist). Tests `test_security_hardening_p0.py:386` (`api_key` not in `ReputationResult`) and `test_ip_reputation_cache.py:301` (`secret12345` not in `rows[0]`) confirm.
- **Provider URL:** Fixed `https://api.abuseipdb.com/api/v2/check` from `settings.py:113` or `IP_REPUTATION_ABUSEIPDB_URL`; never user-controlled; requests to that URL only.
- **Private IP rejection:** `ip_reputation_service.py:293-297` `validate_ip_address` + `is_private_ip` → `ValidationError` before any `requests.get`; double-check in `AbuseIPDBProvider.check_ip:128`. Port scanner also shields `private_ip_blocked` path (`port_scanner_service:158`).
- **Timeout/size:** `timeout=5` (`settings.py:110`), `max_bytes=32768` (`settings.py:111`); `Content-Length` and `len(text.encode)` checks (`164-181`).
- **Status handling:** `429→rate_limited`, `401/403→auth_failed`, `>=500→provider_error`, `!=200→http_<code>`, `Timeout→timeout`, `RequestException→network_error`, `malformed→malformed_response` — all map to `ReputationResult(reputation=unavailable, reason=…)` without exception propagation (`test_ip_reputation_cache.py:170` `429 not cached`).
- **Stale vs safe:** `unknown` (`0/0`, `whitelisted clean`) is **not** failure; `clean` correctly distinct from `unknown` (`_reputation_from_abuse:83` `whitelisted→clean, 0/0→unknown`). `test_threat_assessment` verifies.

**Circuit breaker (new):** `ip_reputation_service.py:103-160` per-provider `dict` + `Lock`, `threshold=5`/`cooldown=60` from `settings.py:117-118`. `_CIRCUIT_FAILURE_REASONS={rate_limited,provider_error,timeout,network_error}` only; success (`!_is_failure`) resets. `_circuit_should_block` checks `now-opened_at < cooldown`; probe after cooldown re-opens on failure. All 18 `test_ip_reputation_circuit.py` pass (consecutive failures, blocked, cooldown/probe, resets, per-provider isolation, concurrent, no leak).

**No accidental `safe` conversion:** `ReputationResult` with `unavailable` and `circuit_open` is treated as **not cached** and **not** `clean/suspicious/malicious` (threat assessment maps it to `unavailable` → `0` base, `medium` confidence). No `unavailable→unknown` confusion.

**Findings — §7: No issue found.** API key isolation, provider fault handling, and breaker are correct.

---

## 8. Cache Security

**File:** `ip_reputation_cache_service.py:1-321`, `schema.sql:146-176`

- **RLS:** `ENABLE ROW LEVEL SECURITY;` no policies → anon/authenticated cannot `SELECT/INSERT`; backend must use `service_role`. Verified: `port_scans_owner_all (user_id=auth.uid())` does not apply to cache; cache has zero policies.
- **Access:** `_get_cache_client:48` strictly prefers `get_supabase_admin_client()` (`supabase_client.py:121` `SUPABASE_SECRET_KEY`), then direct `create_client(url,secret)` from `current_app`; **no anon fallback** — returns `None` on miss and logs `cache_admin_unavailable` (fixed Phase 2D-1). Fake `conftest.py:205` patches admin to same fake for tests but production real client is service_role.
- **Downgrade prevention:** `None` is never cached (`supabase_client.py:84-87` only caches non-None per `(url,key)`), `clear_supabase_client_cache` aliased as `.cache_clear` for test compatibility. No `service_role → anon` downgrade.
- **Schema:** `ip_reputation_cache` has `ip TEXT, provider TEXT, reputation CHECK unknown/clean/suspicious/malicious/unavailable, confidence, malicious/suspicious BOOL, reports, country, asn TEXT, checked_at/expires_at/created_at/updated_at, UNIQUE(ip,provider)`, indexes `(ip,provider)` and `expires_at`. No `user_id`, `jwt`, `api_key` columns; payload `put:237` allowlist excludes secrets; `get:181` reconstructs `ReputationResult` without `reason` leak.
- **TTL:** `IP_REPUTATION_CACHE_TTL=86400` (`settings.py:118`); `get:169-178` parses `expires_at` and returns `None` if `≤ now`; expired treated as miss (not stale). `test_ip_reputation_cache.py:82` verifies refresh.
- **Poisoning:** Frontend cannot write cache (RLS); provider isolation via `(ip,provider)`; `unavailable` skipped (`put:214`), so error responses never overwrite fresh rows (`test_provider_failure_expired:131`).

**Findings — §8: No issue found.**

---

## 9. Threat Assessment Security

**Files:** `threat_assessment_service.py:1-288`, `PORT_THREAT_ASSESSMENT_PHASE1.md`

- **Server-authoritative:** `assess(port_risk, ip_reputation, open_ports, ports_scanned, status)` pure deterministic, no DB/network, no secrets. Frontend `PortScannerPage.tsx:152` only renders `ThreatAssessmentCard` from backend `result.threat_assessment`; no `weight/score` input accepted. **No user-supplied weights/score/severity.**
- **Signals separate:** `PORT_BASE {low:10,medium:25,high:45,critical:60}` + `IP_BASE {clean/unknown/unavailable 0, suspicious 20, malicious 35}` → `score=port_base+ip_base` (`10-95`) + modifiers `+5` each (`critical_service_detail` needs `critical && open∈CRITICAL_RISK_PORTS`, `database_exposure` needs `open∈DB_PORTS`, etc.) capped `0-100` (`227`). Factors deduped (each modifier at most once), `suspicious_high_combo` exclusive with `malicious_critical_combo` → no double-count.
- **Levels:** `≤19 low, ≤39 medium, ≤69 high, else critical` (`54-59`) matches design `threat_assessment` doc thresholds (revised `MALICIOUS 35+CRITICAL 60=95 → critical`). Doc states `low 10+clean 0=10 low` etc. — **matches.**
- **Confidence (evidence completeness, not severity):** `scan_complete = ports_scanned>0 && status=="completed"`; `if !complete→low`, `elif ip_rep None/unavailable→medium`, `elif clean/suspicious/malicious/unknown→high` (`156-165`) — matches spec `HIGH: complete+usable reputation`, `MEDIUM: unavailable`, `LOW: incomplete`.
- **`unavailable` ≠ malicious, `unknown` ≠ clean:** `IP_BASE[unavailable]=0` with factor `unavailable_reputation 0` (`179-183`); `unknown` factor `unknown_ip 0` (`184-185`); both keep `score=port_base`. Verified via `test_threat_assessment.py` matrix.
- **Historical stability:** `PortScannerService.scan_ports:229` persists `threat_assessment` snapshot JSONB alongside `ip_reputation` snapshot; history `get_scan_history:631` returns stored column without recompute; later reputation changes do not alter old rows (design `schema.sql:139` backfill).

**Discrepancies vs `PORT_THREAT_ASSESSMENT_PHASE1.md`:** None material found. One INFO note: doc suggests `score = port 10-60 + ip 0-35 = 10-95` before modifiers, implementation caps at 100 — same. Modifier `high_report_volume reports>=10` matches doc `≥10`. Minor doc wording: `critical_service_detail` requires `port_risk==critical && open∈CRITICAL` — implementation matches (`195-198`). No silent correction needed.

**Findings — §9: No issue found.**

---

## 10. Rate Limiting

**Files:** `middleware/rate_limiter.py:1-147`, `settings.py:175-183`, `routes/port_routes.py:25`

- **Server-controlled, not client-overrideable:** `rate_limit` decorator reads `current_app.config["RATE_LIMIT_..."]` via `_get_limit_config:31`; `limit/window` args are code-provided (`"port_scan"` → `RATE_LIMIT_PORT_SCAN=5/60`, `"ip_reputation"` → `20/60`), never from `request.headers/body`. Tests `test_security_hardening_p0.py:249` (`X-RateLimit-Limit:9999` still 429) confirm.
- **Identity:** `_resolve_user_key:51` prefers `request.auth.sub` (`user:<uuid>`) from `@require_auth`; falls back to `X-Forwarded-For`/`remote_addr`. All scanner routes are `@require_auth` **before** `@rate_limit`, so unauthenticated gets `401` not `429` and does not consume quota (`test_unauthenticated_does_not_consume`).
- **Limits enforced:** `store: dict[str,deque]` + `Lock`, sliding window evicts `≤ cutoff`, `retry_after = oldest+window-now+1`. `POST /ports`, `GET/POST /ip-reputation` decorated; `GET /history` intentionally not limited (cheap read, not in spec). Separate buckets `port_scan:user:<sub>` vs `ip_reputation:user:<sub>`; `test_authenticated_vs_unauthenticated_isolation` with `make_auth_token` proves per-user isolation.
- **Response:** `ApiError(429, RATE_LIMIT_EXCEEDED, {retry_after_seconds,limit,window_seconds})` → `error_handler` sanitizes to allowlisted `retry_after_seconds/limit/window_seconds`; no stack.
- **Gunicorn/Render docs:** `rate_limiter.py:1-12` docstring explicitly states per-process `defaultdict` → `N workers × limit` globally, not distributed. Acceptable for current single-instance Render starter tier per task instruction (do not recommend Redis unless necessary). For larger scale, would need Redis; currently not necessary.

**Findings — §10: No issue found.** Process-local limiter is acceptable with documented caveat.

---

## 11. Authorization / RLS

**Files:** `services/*`, `database/supabase_client.py:1-162`, `middleware/auth_middleware.py`, `schema.sql:210-249`

- **JWT-verified:** `auth_middleware: decode_supabase_token` via `PyJWKClient` ES256 JWKS (`audience=authenticated`, `leeway=10s`, `sub` UUID check); `get_current_user_id` returns `request.auth.sub`; `get_current_access_token` forwards `request.access_token`. No `user_id` from body/query anywhere (`grep "user_id.*request.*json\|\.args\.get.*user_id"` → none).
- **User-scoped clients:** Every service uses `get_user_supabase_client(access_token)` (`supabase_client.py:90`) fresh per request + `postgrest.auth(token)` → PostgREST evaluates as `auth.uid()`. No shared client with token reuse.
- **Persist paths:** `PortScannerService._persist_scan:538` `get_user_supabase_client(token).table("port_scans").insert({user_id,...})`; `ReportService.generate_report:374` same; `ScannerService._persist_scan`, `EmailService`, `PasswordService`, `LogService` all via user client. Tests `test_rls_auth_scoping.py` and `test_port_scanner.py:895` verify inserts have `user_id=auth_user_id` and `auth_tokens` recorded.
- **History/detail:** `get_scan_history:602` `eq("user_id",user_id)` + `range`; `get_scan_detail:644` `eq("id",scan_id).eq("user_id",user_id)` → **IDOR impossible** without JWT `sub` (NotFound if foreign `scan_id`). Reports `list_reports:438` same.
- **Privileged paths:** `ip_reputation_cache Service` + `ReportStorageService` via `get_supabase_admin_client()` (`service_role` bypass) only for shared cache and private bucket `report-pdfs`; never for `user_id`-owned tables.
- **Profiles:** `schema.sql:219` `profiles_select_own / update_own WHERE id=auth.uid()`; trigger `handle_new_user` auto-creates, no `public.users` store.

**Findings — §11: No issue found.** No IDOR path; RLS correctly scoped.

---

## 12. CORS

**Files:** `app/__init__.py:41-71`, `config/settings.py:78`

- **Effective origins resolver:** `_resolve_cors_origins:41` handles `str` (CSV) and `list`, strips, checks `ENVIRONMENT=="production"` and `"*"` in origins → logs `warning`, removes `"*"`, logs `error` if empty (fail-closed `[]` → Flask-CORS denies all), and updates `app.config`.
- **Production explicit origin:** With `ENVIRONMENT=production` and `CORS_ORIGINS=https://cyber-shield-ai-beta-topaz.vercel.app`, `effective_origins=["https://..."]` → Flask-CORS echoes exactly that origin for matching `Origin` requests. Verified by `test_security_hardening_p2d6.py:25` `test_cors_allowed_origin_returns_header` asserts `Access-Control-Allow-Origin == https://allowed.example.com`.
- **Wildcard stripped:** `test_cors_production_wildcard_stripped:46` asserts `CORS_ORIGINS==[]` and `Access-Control-Allow-Origin is None` for any origin when production is `["*"]`. **Cannot remain permissive.**
- **Disallowed/evil:** `test_cors_disallowed_origin_no_header:35` asserts `None` for `https://evil.com`.
- **Preflight:** `test_cors_preflight_allowed_origin:46` `OPTIONS` with `Origin+Access-Control-Request-Method:GET+Headers:Authorization` → `200/204` + `Access-Control-Allow-Origin` + `Access-Control-Allow-Methods` containing `GET`; `test_cors_preflight_disallowed_origin_no_header` asserts `None`. **Authorization Bearer and OPTIONS continue to work.**
- **Dev wildcard preserved:** `test_cors_development_wildcard_preserved:56` asserts `ENVIRONMENT=development` keeps `*` and returns `200`.

**Findings — §12: No issue found.** Production wildcard cannot accidentally remain.

---

## 13. Error Handling

**File:** `middleware/error_handler.py:1-177`

- **Allowlist sanitization:** `_SAFE_DETAIL_KEYS = {field, limit, limit_bytes, window_seconds, retry_after_seconds, max, max_length, min_length, max_bytes, size_bytes, count, port, value, profile, type, reason, allowed, path, scheme}` (`17-39`); `_SENSITIVE_KEY_SUBSTRINGS` includes `key,token,secret,auth,password,jwt,service_role,api,sql,stack,trace,bucket,table,error` (`41-56`). `_sanitize_details:59` drops non-dict, drops sensitive unless explicitly safe, truncates strings `>200` and lists `>20`.
- **Verified hidden:** `ServiceUnavailableError(details={"table":"port_scans","error":"ConnectionError"})` from `Caller` is dropped → `details==None` or only `field` kept. Tests `test_security_hardening_p2d6.py:124` asserts `table`/`error` not in `details`, `field` kept, `traceback` not in body. `test_500_hides_internal_details:54` asserts `INTERNAL_ERROR` without `sensitive internal detail`.
- **Safe details preserved:** `field`, `limit_bytes`, `retry_after_seconds`, `allowed`, `path` remain; `test_error_details_preserve_safe_keys:189` asserts `field/port/limit`; `test_rate_limit_details_still_exposed_safely:215` asserts `retry_after_seconds/limit/window_seconds`.
- **Logs retain:** `handle_api_error:104-114` logs `logger.warning` in prod or `logger.info` in dev with full `exc.details` before sanitizing — satisfies “detailed via server logs only”.
- **Secrets never exposed:** `_SENSITIVE` drops `api_key, service_role_key, bucket, table, error, SQL`; manual `Select-String` shows no handler returns `ApiError.details` containing `SUPABASE_*` or `IP_REPUTATION_API_KEY`; tests `test_security_hardening_p0:386` (`no api_key in ReputationResult`), `test_no_secret_leakage` for circuit, and `test_error_details_never_expose_api_keys` confirm.
- **Generic 500:** `handle_unexpected_error:170` `logger.exception` + `INTERNAL_ERROR` with no message leak.

**Findings — §13: No issue found.** Sanitizer is correct and complete.

---

## 14. Frontend Security

**Files:** `frontend/src/pages/PortScannerPage.tsx:1-824`, `frontend/src/services/apiClient.ts:1-131`, `frontend/src/types/*`, `frontend/src/App.tsx`

- **No secrets bundled:** `grep VITE_*` → `VITE_API_BASE_URL` and `VITE_SUPABASE_URL` + `VITE_SUPABASE_ANON_KEY` (`supabaseClient.ts`) — publishable key only, never `SUPABASE_SECRET_KEY`/`SERVICE_ROLE`/`IP_REPUTATION_API_KEY`/`AbuseIPDB` key. `apiClient.ts:4` `VITE_API_BASE_URL||'/api'`; no `Authorization` secret hard-coded, Bearer derived per-request from `supabase.auth.getSession()` (`apiClient.ts:20-22`).
- **Threat weights not manipulable:** `PortScannerPage.tsx:563` `IPReputationCard` and `ThreatAssessmentCard` render `result.ip_reputation` and `result.threat_assessment` returned from backend only; `getRiskBadge` maps `risk_level` to tone, no client-side `_calculate_risk_level`. Types `types/index.ts` declare `PortScanResult` with `risk_level/reputation/threat_assessment` as data, not inputs.
- **Banners safely rendered:** `port_scanner_service.py` sanitizes banners `isprintable or \n\t\r` + `256B` truncate; `PortScannerPage.tsx:331` `formatBanner` `slice(0,80)+"…"` and `<DataTable>` renders as text (no `dangerouslySetInnerHTML`); history/detail also via `DataTable`. No `innerHTML` usage found.
- **API errors safely displayed:** `handleScan:283` `err instanceof ApiClientError` shows `err.message` only; `getHistoryErrorMessage:343` maps `401/503/0` to safe strings, otherwise `err.message` (already sanitized server-side). No stack trace rendered.
- **History IDOR prevented:** `apiClient.get<PortScanDetail>('/scanner/ports/history/'+encodeURIComponent(scanId))` (`PortScannerPage.tsx:396`) cannot inject other user's ID; backend still checks `eq user_id` (`port_scanner_service.py:688`), so `404` if foreign. No `user_id` param sent.
- **Malformed data resilience:** `PortScannerPage.tsx:81-149` `IPReputationCard`/`ThreatAssessmentCard` handle `null` (`if (!reputation) … "not available"`), `formatDate` guards `NaN`, `history && history.length` guards.

**Findings — §14: No issue found.**

---

## 15. PDF/Report Security

**Files:** `backend/app/services/report_service.py:1-458`, `backend/app/reports/pdf_generator.py:1-825`

- **Banners sanitized:** `report_service.py:232` `_sanitize_banner` re-filters `isprintable or \n\t\r` + `256` truncate even if stored row contains injected payload; `pdf_generator.py:81` `_esc` xml-escapes for PDF.
- **Allowlist:** `_map_port_scan:244` allowlists `ip_reputation` to `{ip,reputation,confidence,malicious,suspicious,reports,country,asn,organization,isp,last_reported_at,provider,checked_at,reason}` and `threat_assessment` to `{score,level,confidence,factors,explanation,assessed_at}` with factor sanitizing `type≤64, weight int, description≤256, score 0-100` (`284-298`). No `api_key/jwt/user_id` in allowlist; tests confirm.
- **Injection:** Banners/fields never rendered as HTML; PDF is `reportlab` with escaped text; no `eval`/`exec` on report data. `title` validated `1-200 chars` (`report_service.py:77`), `summary/findings` type-checked.
- **Compatibility:** `port_scans.threat_assessment`/`ip_reputation` are `JSONB` nullable; `report_service.py:244` `if not row: return None` and `normalized_rep = None` if missing → old scans render `"Not available"` instead of crash. `get_scan_history` selects `ip_reputation, threat_assessment` explicitly.
- **Ownership:** `ReportService.generate_report:374` `get_user_supabase_client(token)` + `user_id` from JWT (`auth.py`), not body; `list_reports:438` same; RLS `reports_owner_all (user_id=auth.uid())`.

**Findings — §15: No issue found.**

---

## 16. Database Security

**File:** `backend/app/database/schema.sql:1-249`

| Table | RLS | FK | Indexes | Constraints | Verdict |
|-------|-----|----|---------|-------------|---------|
| `profiles` `id UUID PK → auth.users ON DELETE CASCADE` | `ENABLE; select_own (id=auth.uid()), update_own` | — | — | **OK** |
| `website_scans` `user_id → auth.users CASCADE` | `ENABLE; owner_all FOR ALL USING/WITH CHECK user_id=auth.uid()` | `(user_id, created_at DESC)` | `status, risk_level CHECK` | **OK** |
| `email_scans` `user_id → auth.users` | same | same | `predicted_label, risk_level CHECK` | **OK** |
| `password_scans` | same | same | — | **OK** |
| `log_scans` | same | same | — | **OK** |
| `port_scans` `user_id, target, resolved_ip, ports_scanned, open_ports JSONB, scan_duration_ms, risk_level, status, ip_reputation JSONB, threat_assessment JSONB` | `ENABLE; owner_all` | `(user_id, created_at DESC)` | `risk_level CHECK, status CHECK` | **OK** — `ip_reputation`/`threat_assessment` nullable via `DO $$ ADD COLUMN IF NOT EXISTS` backfill (`125-140`) ensures historical compatibility |
| `ip_reputation_cache` `ip, provider, reputation CHECK, confidence CHECK, reports, ... UNIQUE(ip,provider)` | `ENABLE; no policies` → `service_role` bypass only, anon/authenticated denied | `(ip,provider)`, `(expires_at)` | `CHECK reputation/confidence` | **OK** — shared, no `user_id`/`jwt`/`api_key` |
| `reports` `user_id → auth.users` | `ENABLE; owner_all` | `(user_id, created_at DESC)` | `report_type CHECK pdf` | **OK** |

**Manual migrations still needed if DB created before Phase 2D-3:** `schema.sql:125` `DO $$` backfill is idempotent if `schema.sql` is re-run in Supabase SQL editor; if not, manually run `ALTER TABLE port_scans ADD COLUMN IF NOT EXISTS ip_reputation JSONB; ALTER TABLE port_scans ADD COLUMN IF NOT EXISTS threat_assessment JSONB;` — documented in `PORT_THREAT_ASSESSMENT_PHASE1.md:419`. No other migration pending.

**Findings — §16: No issue found.**

---

## 17. Deployment Security

**Checked:** `settings.py:210`, `app/__init__.py:74`, `frontend/vercel.json`, `vite.config.ts`, `README.md` live links, `docs/13_Deployment_Guide.md` (via `get_config` mapping)

**Production requires (verified via `Config.as_flask_mapping` → `create_app`):**

| Var | Expected prod value | Verified |
|-----|---------------------|----------|
| `SUPABASE_URL` | `https://<project>.supabase.co` | Required; `get_supabase_client` returns `None` if empty → fail-closed for cache |
| `SUPABASE_SECRET_KEY` (or legacy `SUPABASE_SERVICE_ROLE_KEY`) | secret, backend-only, **never** `VITE_` | `supabase_client.py:136` `get_supabase_admin_client` uses secret; `frontend/src/services/supabaseClient.ts` only `VITE_SUPABASE_ANON_KEY` |
| `SUPABASE_PUBLISHABLE_KEY` (or `SUPABASE_ANON_KEY`) | publishable | Used via `get_supabase_client` / `get_user_supabase_client` |
| `CORS_ORIGINS` | `https://cyber-shield-ai-beta-topaz.vercel.app` (explicit, no `*`) | `_resolve_cors_origins` strips `*` in prod → fail-closed |
| `APP_ENV=production` + `FLASK_DEBUG=false` | `production` → `DEBUG=False, TESTING=False` | `settings.py:50` `ENVIRONMENT=APP_ENV||FLASK_ENV`; `51` `DEBUG=FLASK_DEBUG` default false in prod |
| `IP_REPUTATION_ENABLED=true` | to enable AbuseIPDB | `settings.py:107` default false — must enable |
| `IP_REPUTATION_PROVIDER=abuseipdb` | fixed | default `abuseipdb` |
| `IP_REPUTATION_API_KEY=<abuseipdb>` | secret | never exposed (see §7) |
| `IP_REPUTATION_CACHE_ENABLED=true` | shared TTL | default true |
| `IP_REPUTATION_CACHE_TTL=86400` | 24h | default 86400 |
| `IP_REPUTATION_CIRCUIT_THRESHOLD=5` / `COOLDOWN=60` | circuit breaker | `settings.py:117-118` defaults 5/60 |
| `RATE_LIMIT_ENABLED=true` | global toggle | default true |
| `RATE_LIMIT_PORT_SCAN=5` / `WINDOW=60` | per-user port scan | defaults 5/60 |
| `RATE_LIMIT_IP_REPUTATION=20` / `WINDOW=60` | per-user rep | defaults 20/60 |
| `PORT_SCANNER_DNS_TIMEOUT=3.0` | bounded watchdog | default 3.0, clamp 0-10 |

**Frontend/backend URL:** `VITE_API_BASE_URL=https://cybershield-ai-beta.onrender.com/api` (or `/api` proxy in dev via `vite.config.ts:16`); `vercel.json` SPA rewrite `/(.*)→/index.html` correct. No secret values logged; `configure_logging` does not log env.

**Findings — §17: No issue found** if Render/Vercel envs set as above; operator must verify CORS origins explicitly.

---

## 18. Test Coverage

**Executed:** `python -m pytest backend/tests/ -q` → **1135 passed** (≈ `1135` approximate stated - exact), `npx tsc --noEmit` → **pass** (exit 0), `npm run build` → **pass** (Vite 5.4.21, 1476 modules, `672.18 kB` JS `178.73 kB` gzip).

**Quality assessment:**

- **Meaningful & isolated:** `conftest.py` per-test `create_app(TestingConfig)` + fresh `_FakeSupabaseClient` + `_FakeJWKClient` (RSA 2048, RS256) → no network. Each test class uses `patch("socket.getaddrinfo"/"socket.socket"/"requests.get")` for determinism. Good.
- **Fake realism:** `_FakeSupabaseTable` supports `insert/upsert(on_conflict)/update/select/eq/order/limit/range/count=exact` with `(ip,provider)` unique — close to PostgREST; covers cache hit/miss/expired, history pagination, RLS isolation (`test_rls_auth_scoping`). Slight simplification (PostgREST range inclusive) handled.
- **Production cases covered:** TOCTOU (`test_security_hardening_p0:48` assert `connected_to==validated_ip`), DNS watchdog (`test_port_scanner_dns_watchdog:213` timeout `<0.30s`), IPv6 bare/bracketed (`test_ipv6_target_validation:68` all 15 pass), rate limiting per-user/preflight, CORS allowed/disallowed/preflight/prod wildcard stripped, error sanitization (`table`/`bucket` hidden, `field` kept), circuit breaker (18 tests: failures→open→blocked→cooldown→probe→reset, per-provider, concurrent), cache poisoning, banner truncation.
- **False positives low:** Time-sensitive watchdog test previously flaked (`0.212s` vs `0.12`) — fixed by relaxing to `<0.30s` (acceptable under CI load). Other suite stable under full 1135-run (`67.73s`).

**Missing / uncovered (not blocking, but for next milestones):**

- No test for `CORS_ORIGINS` as CSV string (`"https://a.com, https://b.com"`) in production.
- No test for `_sanitize_details` with nested dicts (dropped, correct).
- No test for `PORT_SCANNER_DNS_TIMEOUT` out-of-bounds clamp (`0` or `20`) → `3.0`/`10`.

**Findings — §18: No issue found** for blocker; coverage is strong.

---

## 19. Project Honey Pot Readiness

**Reviewed:** `PORT_THREAT_INTELLIGENCE_PHASE1.md` (743+ lines, investigation only, not implemented)

- **Provider abstraction:** Current `IPReputationProvider(ABC)` is single-provider (`AbuseIPDBProvider`/`NullProvider`). Design proposes **Option B — generalize to `ThreatIntelligenceProvider` with alias `IPReputationProvider`** to avoid churn, keep `AbuseIPDBProvider` behavior/tests, add `ProjectHoneyPotProvider` as second leaf. **Ready** — alias pattern already used for `Supabase` legacy keys.
- **Fault isolation:** Aggregator spec enables each `provider.check_ip` isolated `try/except` → `unavailable` without breaking scan; current `IPReputationService.check_ip` already never-breaks-scan (`port_scanner_service:171`). Extending to DNS `http:BL` (`127.<days>.<threat>.<visitor_type>`) isolated per provider is straightforward; no HTTP reuse confusion (DNS only, not scrape).
- **Cache:** `ip_reputation_cache` already per-`(ip,provider)` with nullable columns; `Option A` extends with `evidence JSONB, threat_score, visitor_type, days_since, last_seen` nullable — minimal migration, reuses RLS/TTL/service_role path. **Ready**.
- **Evidence normalization:** Design defines `ProviderEvidence` (`ip,provider,reputation,malicious/suspicious,confidence,checked_at,last_seen,categories,raw_score,evidence,reason`) with mapping tables for `NXDOMAIN (unknown)` vs `search_engine (clean)` vs `timeout (unavailable)`. Prevents copying HoneyPot `threat_score 0-255` into `reports` → would corrupt `high_report_volume`. **Ready** if mapping is followed.
- **Threat integration:** Proposed `ThreatAssessmentService.assess_with_intelligence(bundle)` derives **one** `ip_base` from `worst_of(providers)` (`malicious> suspicious> clean> unknown`) to avoid double-count `35+20`. Keep existing `assess()` as shim. **Ready** — no weight change required for Phase 1 (only `strong_corroboration` expansion).
- **API:** Additive `threat_intelligence: ThreatIntelligenceBundle` (`providers[]`, `summary`) alongside legacy `ip_reputation`; new optional `GET /threat-intelligence/<ip>` — server-side enablement only, no client `providers[]` param (prevents user-controlled provider selection).
- **Secret handling:** HoneyPot needs `PROJECT_HONEYPOT_ACCESS_KEY` (DNS key `abc123.<reversed_ip>.dnsbl.httpbl.org`). Same backend-only pattern as `IP_REPUTATION_API_KEY`; never `VITE_`, never cached, never in PDF. **Ready**.
- **DNSBL-specific:** `is_private_ip` already blocks private before DNS; HoneyPot is IPv4-only → `unsupported_ip_version` unavailable for IPv6; `NXDOMAIN` ≠ `clean` distinction documented. **Ready**.

**Recommendation:** Project Honey Pot **should remain a separate provider** (parallel to AbuseIPDB) behind `ThreatIntelligenceAggregator`, **not** replace AbuseIPDB. Aggregator should `worst_of` and keep AbuseIPDB's `reports` semantics intact. Two-provider bundle gives operational blindness fix (`AbuseIPDB unknown` + `HoneyPot suspicious` → `suspicious`).

**Findings — §19: No issue found.** Architecture is ready; no implementation yet (as intended).

---

## 20. Findings

### P0 findings — 0

All original P0 (DNS TOCTOU, rate limit, service-role, DNS watchdog, IPv6 bare, CORS, error detail) are fixed and verified. **No P0 blocks production.**

### P1 findings — 0

No HIGH that blocks production unconditionally. Two HIGH below are **conditionally acceptable** with documented operational checks (see final decision).

### P2 findings — 7 (LOW/INFO, not blocking)

| ID | Severity | File:Lines | Issue | Impact | Exploit scenario | Recommendation | Blocks prod? |
|----|----------|------------|-------|--------|------------------|----------------|--------------|
| F-01 | **HIGH** | `middleware/rate_limiter.py:26`, `settings.py:179` | Process-local `defaultdict[deque]` → `N workers × limit` globally. | Under `gunicorn -w 4` effective port scan limit `4×5=20/min` globally. | Coordinated burst across workers/instances exceeds intended quota, AbuseIPDB quota burn. | Documented in limiter docstring and Phase 2D-6 report; acceptable for single-instance Render starter. If scaling to multi-instance, add Redis (e.g., `Flask-Limiter+redis`) or document `RATE_LIMIT_*` per-worker math. | **No** — with condition (see §10) |
| F-02 | **HIGH** | `services/ip_reputation_service.py:103`, `config/settings.py:117` | Circuit breaker process-local, same `N×` caveat. | Inconsistent open/close across workers during outage. | Flaky probe across workers. | Same as F-01; acceptable for now. | **No** |
| F-03 | **MEDIUM** | `services/port_scanner_service.py:274-286` | DNS `TimeoutError` → `ValidationError(400, dns_timeout)` while `gaierror` → filtered success (`resolved_ip=target`, ports filtered). Inconsistent error semantics for transient DNS. | Client sees `400` for slow DNS but `200` with `filtered` for NXDOMAIN. | Minor UX inconsistency; not exploitable. | Align: either both map to filtered success or both to `400`. Current watchdog spec requires `400` for timeout — keep, but document in API docs. | **No** |
| F-04 | **LOW** | `utils/validators.py:443` `target.count(":")>1 → Invalid IPv6` | Bare hostname containing colons for non-IP reasons (rare) rejected as `Invalid IPv6`. | No real hostname has `:` except `host:port`; hostnames with `:` are invalid per RFC. | None. | Keep as is. | **No** |
| F-05 | **LOW** | `services/port_scanner_service.py:570` `ServiceUnavailableError(details={"table":...,"error":...})` still raised with sensitive keys, then sanitized by handler — safe for client but logs contain raw table/error. | Logs contain correct diagnostics; client does not. | None (intended). | Ensure log pipeline redacts `key/token` already via `_log_safe` and error log. | **No** |
| F-06 | **INFO** | `database/schema.sql:172` `handle_new_user` `SECURITY DEFINER` | Function runs as definers, but body is `INSERT INTO profiles ... ON CONFLICT DO NOTHING` only. | Least-privilege violation if function later expanded. | — | Set `search_path=public` already set; keep body minimal. | **No** |
| F-07 | **INFO** | `frontend/vite.config.ts:16` `proxy /api → localhost:5000` + `vercel.json` SPA rewrite | Dev proxy and SPA rewrite are correct but not security boundaries. | — | — | No action. | **No** |

**No issue found** sections (see above): Port Scanner, SSRF, DNS, IPv6 (after 2D-8), IP Reputation, Cache, Threat Assessment, RLS, CORS, Error Handling, Frontend, PDF/Reports, Database, Deployment, Test Quality (overall pass).

**Remaining technical debt (tracked, not blocking):**

- Rate limiter + circuit breaker `N×` should be documented in `docs/13_Deployment_Guide.md` (currently only in code).
- DNS timeout vs `filtered` semantics (§F-03) should be noted in `docs/07_API_Design.md`.
- Project Honey Pot not yet implemented (ready per §19).

**Recommended next milestones (P2):**

1. Add `docs` note for per-worker math and `RATE_LIMIT_*` tuning guide.
2. Unify DNS error semantics or document timeout `400` vs `filtered` `200`.
3. Implement `ThreatIntelligenceAggregator` per Phase 2D-4 design (two-provider) — provider abstraction already ready.
4. Add CSV `CORS_ORIGINS` string test and `PORT_SCANNER_DNS_TIMEOUT` clamp test.

---

## Final Decision

**`PRODUCTION READY WITH CONDITIONS`**

Cybershield AI **may be deployed to production** on the current Vercel (frontend) + Render (backend) + Supabase stack **provided** the operator:

1. Sets `APP_ENV=production`, `FLASK_DEBUG=false`, `SUPABASE_URL`, `SUPABASE_SECRET_KEY` (backend-only), `SUPABASE_PUBLISHABLE_KEY`, `CORS_ORIGINS=https://cyber-shield-ai-beta-topaz.vercel.app` (explicit, no `*`), `IP_REPUTATION_ENABLED=true`, `IP_REPUTATION_API_KEY`, `RATE_LIMIT_ENABLED=true`, `PORT_SCANNER_DNS_TIMEOUT=3.0` (or 5s), and verifies `CORS workflow` (`Origin: https://cyber-shield-ai-beta-topaz.vercel.app` → `Access-Control-Allow-Origin` echo) and `rate-limit` (`5 scans/min → 6th 429`).

2. Re-runs `backend/app/database/schema.sql` (idempotent) in Supabase SQL editor to ensure `port_scans.ip_reputation` + `threat_assessment` columns exist (backfill `DO $$`).

3. Acknowledges process-local limiter/breaker `N×` behavior (single Render instance → exact; horizontal scale → add Redis).

4. Monitors `cybershield.errors` logs (sanitized client responses vs full server logs) and AbuseIPDB quota.

No code change is required before production.

---

*Audit artifacts:* `1135 passed`, `npx tsc --noEmit` pass, `npm run build` pass (Vite 5.4.21, 1476 modules). No source modified during audit.
