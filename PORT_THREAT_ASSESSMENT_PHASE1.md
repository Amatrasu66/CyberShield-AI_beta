# PORT THREAT ASSESSMENT — PHASE 2D-3 DESIGN (INVESTIGATION ONLY)

> **Status:** Design / Investigation Phase Only — No implementation in this task.  
> **Predecessors:** TCP Port Scanner (`PortScannerService:43-46`), IP Reputation (`IPReputationService` → `AbuseIPDBProvider`/`NullProvider` → `ReputationResult`), Bounded Cache (`IPReputationCacheService` → `ip_reputation_cache` 24h TTL), Persistence (`port_scans.ip_reputation` JSONB), PDF (`port_scan` in `report_data`).

---

## 1. Current Architecture Findings

**Backend Services Inspected**

* **`backend/app/services/port_scanner_service.py:43-70,374-385`** — `CRITICAL_RISK_PORTS={22,23,3389,5900…}`, `HIGH={135,139,445,1433,1521,3306,5432,6379,27017…}`, `MEDIUM={21,25,53,80,111,143,443…}`. `_calculate_risk_level()` returns `critical` if any critical open, else `high`, else `medium`, else `low`. `ScanResult` dataclass holds `target,resolved_ip,scan_duration_ms,ports_scanned,open_ports,closed/filtered counts,summary,risk_level,ip_reputation?`. `_persist_scan()` writes `ip_reputation` snapshot via `get_user_supabase_client(get_current_access_token())` → RLS `port_scans_owner_all` (`user_id=auth.uid()`). History queries `ip_reputation` column.
* **`backend/app/services/ip_reputation_service.py:42-65,83-230,242-390`** — `ReputationResult` (`reputation` ∈ `unknown| clean|suspicious|malicious|unavailable`, `confidence` `none|low|medium|high|very_high`, `malicious/suspicious` bool, `reports,country,asn,org,isp,last_reported_at,provider,checked_at,reason`). `_reputation_from_abuse()` whitelisted→`clean`, 0/0→`unknown`, ≥75→`malicious`, ≥25 or ≥5 reports→`suspicious`. `AbuseIPDBProvider.check_ip()` bounded `timeout=5s`, `max_bytes=32768`, handles 429/401/5xx/malformed → `unavailable`. `NullProvider` → `unavailable`. `_get_provider()` prefers `current_app.config` (`IP_REPUTATION_*`) fallback `get_config()`. `check_ip()` validates `validate_ip_address` + `is_private_ip` → `ValidationError`, then `provider.check_ip` with cache integration.
* **`backend/app/services/ip_reputation_cache_service.py:21-325`** — Shared `ip_reputation_cache` keyed `(ip,provider)`, `expires_at = checked_at+TTL`, `get()` returns fresh only if `expires_at>now`, `put()` skips `unavailable`, uses `service_role` (`get_supabase_admin_client()` → direct `create_client` from `current_app` as fallback, logs `cache_hit/miss/expired/put_success/put_failed`), never exposes `user_id/api_key`.
* **`backend/app/routes/port_routes.py:11-68,110-164`** — `POST /api/scanner/ports` validates `validate_hostname_or_ip`, calls `PortScannerService.scan_ports(user_id=get_current_user_id())`, returns `success_response` envelope with `risk_level` + `ip_reputation`. `GET /ports/history`, `GET /ports/history/<id>`, `GET /ip-reputation/<path:ip>`, `POST /ip-reputation` all `@require_auth`, `user_id` from JWT only.
* **`backend/app/services/report_service.py:40-47,93-285`** — `SCAN_TABLES` includes `port_scans`, `_fetch_latest_scans` limit 1 per table, `_map_port_scan()` sanitizes banners, allow-lists reputation fields, `_build_summary` adds `port scan`, `report_data.port_scan` added, `_render_pdf` via `PDFReportGenerator`.
* **`backend/app/reports/pdf_generator.py:81-86,274-279,440-510`** — `PORT_KEYS`, `_build_story` adds `6. Port Scanner and IP Reputation` + `7. Risk & Findings`, `_port_section()` distinct `Port Scan — Target & Results` vs `IP Reputation — AbuseIPDB`, `_port_table()` escaped banners, `RISK≠REPUTATION` note.
* **`backend/app/database/schema.sql:106-133,164,201`** — `port_scans` with `ip_reputation JSONB` + backfill, `ip_reputation_cache` (`ip,provider` UNIQUE, indexes `(ip,provider)`, `expires_at`, `ENABLE RLS` no policies → service_role only), `indexes`/`RLS` consistent.
* **`backend/app/config/settings.py:91-103`** — `_env_bool/_env_int`, `IP_REPUTATION_ENABLED/PROVIDER/API_KEY/TIMEOUT/MAX_RESPONSE_BYTES/ABUSEIPDB_URL`, `IP_REPUTATION_CACHE_ENABLED=true`, `TTL=86400`.
* **`backend/app/utils/validators.py:488-527`** — `validate_ip_address`, `is_private_ip` (private/loopback/link-local/reserved/multicast/unspecified), `is_private_hostname`.
* **`backend/tests/conftest.py:56-133,179-193`** — `_FakeSupabaseTable` supports `select(count=exact)`, `range`, `upsert(on_conflict)`, `update`; `fake_supabase` patches `get_user_supabase_client` + `get_supabase_admin_client` for `ip_reputation*` modules; `TestingConfig` sets `IP_REPUTATION_CACHE_ENABLED=False` to isolate.
* **`frontend/src/pages/PortScannerPage.tsx`** — `useSlowRequest`, `PageHeader/Card/Badge/DataTable`, separate `Port risk level` card vs `IPReputationCard` (distinct eyebrow, `ReputationBadge`/`ConfidenceBadge`, `reports/country/asn/org/lastReported/provider/checked`), history detail shows stored `ip_reputation` or “Not available”, no combined score.
* **`frontend/src/types/index.ts:322-408`** — `IPReputationState`, `IPReputationResult`, `PortScanResult.ip_reputation?`, `ReportPortScanData`, `ReportData.port_scan`.
* **Existing scoring utilities:** Only `PortScannerService._calculate_risk_level` (port-category based) and `ReputationResult` mapping; no combined model exists.

**Key Invariant Preserved:** `port risk` and `ip reputation` are independent, stored as `risk_level` + `ip_reputation` snapshot, never merged.

---

## 2. Existing Risk / Reputation Flow

```
User → POST /api/scanner/ports {target, ports|profile} → @require_auth (JWT sub)
  → validate_hostname_or_ip → is_private_hostname → resolve_scan_ports
  → _resolve_target (getaddrinfo) → _scan_port_list (ThreadPool 50, 2s per-port, 30s total)
  → _calculate_risk_level (critical/high/medium/low)
  → IPReputationService.check_ip(resolved_ip)
        → validate_ip_address → is_private_ip → ValidationError private
        → _get_provider() → IPReputationCacheService.get(ip,provider) if fresh → return
        → else AbuseIPDBProvider.check_ip → _reputation_from_abuse / _confidence_from_score
        → IPReputationCacheService.put (if !unavailable) → upsert (ip,provider)
  → ScanResult(..., risk_level, ip_reputation.to_dict())
  → _persist_scan via user-scoped client → port_scans row (RLS)
  → success_response({risk_level, ip_reputation, ...}) // still no threat_assessment
History: GET /history → order created_at desc, range, open_port_count derived.
Reports: _fetch_latest_scans port_scans limit1 → _map_port_scan → PDF 6. Port Scanner and IP Reputation.
```

---

## 3. Proposed Architecture

**Question A/B/C Answer: A — Dedicated `ThreatAssessmentService`**

**Rationale:** Separation of concerns, existing `PortScannerService` is already 590 lines with scanning/concurrency/persistence/history; adding scoring would violate SRP. `IPReputationService` is provider abstraction. Combined assessment is *derived* from both signals, not owned by either. Existing `ReportService` already aggregates multiple scans; consistent pattern is small services per domain.

**Proposed:**

```
PortScannerService.scan_ports
  → IPReputationService.check_ip (cached)
  → ThreatAssessmentService.assess(port_risk, ip_reputation, open_ports)
        ↓
  ScanResult.threat_assessment → persist port_scans.threat_assessment JSONB
  ↓
  API → History → PDF → Frontend (all read snapshot)
```

* **`backend/app/services/threat_assessment_service.py`** (new, ~150 lines, pure deterministic, no DB/network)
  * `ThreatAssessmentService.assess(port_scan: dict|ScanResult, ip_rep: dict|ReputationResult) -> ThreatAssessment`
  * `ThreatLevel = low|medium|high|critical` (maps to 0-100 score)
  * No Supabase import except via caller; testable in isolation.

* **`PortScannerService` stays scanning-focused:** after `ip_reputation` lookup, call `ThreatAssessmentService.assess(...)`, attach to `ScanResult.threat_assessment`, persist.

* **Cache remains untouched** – `IPReputationCacheService` still only for reputation.

* Alternative B (logic inside `PortScannerService`) rejected: would bloat scanner, couple scoring to scanning, hinder unit testing and future provider changes.

* No new DB table; reuse `port_scans`.

---

## 4. Scoring Model — Revised Base-Signal + Bounded Modifiers

**Principles:** Deterministic, bounded `0-100` integer, explainable, no fake precision, no double-count, handles missing/unavailable, base signals dominate, modifiers small and bounded.

**Base signals (mutually exclusive, mandatory):**

| Base | Value | Condition |
|---|---|---|
| **Port risk** | `LOW 10` | `risk_level == low` |
| | `MEDIUM 25` | `risk_level == medium` |
| | `HIGH 45` | `risk_level == high` |
| | `CRITICAL 60` | `risk_level == critical` |
| **IP reputation** | `CLEAN 0` | `reputation == clean` |
| | `UNKNOWN 0` | `reputation == unknown` |
| | `UNAVAILABLE 0` | `reputation == unavailable` or `None` |
| | `SUSPICIOUS 20` | `reputation == suspicious` |
| | `MALICIOUS 35` | `reputation == malicious` |

*Base score = `port_base + ip_base`. Range `10-95` before modifiers (e.g., `LOW+CLEAN=10`, `CRITICAL+MALICIOUS=95`). Even `MALICIOUS+CRITICAL` is `95` → already `CRITICAL` without modifiers, satisfying “malicious + critical → CRITICAL”.*

**Bounded evidence modifiers (each 0 or small weight, at most once, orthogonal to base):**

| Modifier | Weight | Trigger | Deduplication |
|---|---|---|---|
| `critical_service_detail` | **+5** | open `22,23,3389,5900,5901,5985,5986` **and** `risk_level==critical` — elaborates which critical service | Not double-counted with base `CRITICAL 60` because base already reflects critical; modifier is capped at 5 and only for *specific* critical service, not for any critical (base) alone. Count once even if multiple critical ports. |
| `database_exposure` | **+5** | open `DB subset` `{1433,1521,3306,5432,6379,27017,27018,27019}` | `HIGH` already includes DB; modifier adds only 5, not 20, to avoid double count. If `critical_service_detail` and `database_exposure` both true (e.g., 3389+3306) both apply (distinct evidence). |
| `multiple_high_risk` | **+5** | `open_count ≥3` **or** `≥2 distinct high/critical services` | Attack surface breadth; counts once. |
| `high_report_volume` | **+5** | `reports ≥10` and `reputation ∈ {suspicious,malicious}` | Corroboration; 0 if `reports<10` or `clean/unknown/unavailable`. |
| `malicious_critical_combo` | **+5** | `reputation==malicious` **and** `risk_level==critical` | Combo bonus for strongest alignment; mutually exclusive with `suspicious_high_combo`. |
| `suspicious_high_combo` | **+5** | `reputation==suspicious` **and** `risk_level ∈ {high,critical}` | Lower combo; exclusive with `malicious_critical_combo`. |

*Total modifiers ≤ `5+5+5+5+5 =25` but real max `≈15` due to exclusivity and `reports` condition. Max score `95+15=110 → capped to 100`.*

**No double-count rules:**

* `port_base` already encodes `risk_level` → modifiers for `critical_service_detail` / `database_exposure` add only +5 each, not full critical/high weight again.
* `malicious` vs `suspicious` exclusive.
* `malicious_critical_combo` vs `suspicious_high_combo` exclusive.
* Each modifier counted once per scan even if multiple ports qualify.

**Example:** `CRITICAL (60) + MALICIOUS (35) + critical_service_detail (5) + malicious_critical_combo (5) = 105 → 100 CRITICAL` via cap. `LOW (10) + CLEAN (0) =10 LOW`.

---

## 5. Score Calculation Rules (Deterministic Pseudocode)

```python
def assess(port_risk: str, ip_rep: dict|None, open_ports: list) -> ThreatAssessment:
    # Base
    port_base = {"low":10, "medium":25, "high":45, "critical":60}[port_risk]
    ip_rep_val = (ip_rep or {}).get("reputation")  # may be None
    ip_base = {"clean":0, "unknown":0, "unavailable":0, "suspicious":20, "malicious":35}.get(ip_rep_val, 0)

    score = port_base + ip_base
    factors = []
    # Base factors always added for explainability
    factors.append({"type":"port_risk", "weight":port_base, "description":f"Port risk {port_risk.upper()}"})
    if ip_rep_val in ("suspicious","malicious"):
        factors.append({"type":f"{ip_rep_val}_ip", "weight":ip_base, "description":f"IP {ip_rep_val} ({ip_rep.get('reports',0)} reports)"})
    elif ip_rep_val in ("unavailable","unknown","clean",None):
        # weight 0 factor for traceability, not counted in score already
        factors.append({"type":f"ip_{ip_rep_val or 'missing'}", "weight":0, "description":f"IP {ip_rep_val or 'missing'} — no score contribution"})

    open_set = {p["port"] for p in open_ports if p.get("state")=="open"}
    # Modifiers
    if open_set & CRITICAL_RISK_PORTS and port_risk=="critical":
        score += 5
        factors.append({"type":"critical_service_detail","weight":5,"description":f"Critical service {sorted(open_set & CRITICAL_RISK_PORTS)} exposed"})
    db_ports = {1433,1521,3306,5432,6379,27017,27018,27019}
    if open_set & db_ports:
        score += 5
        factors.append({"type":"database_exposure","weight":5,"description":f"Database {sorted(open_set & db_ports)} exposed"})
    if len(open_set) >=3 or len(open_set & (CRITICAL_RISK_PORTS|HIGH_RISK_PORTS)) >=2:
        score += 5
        factors.append({"type":"multiple_high_risk","weight":5,"description":f"{len(open_set)} open ports / multiple high-risk"})
    if (ip_rep or {}).get("reports",0) >=10 and ip_rep_val in ("suspicious","malicious"):
        score += 5
        factors.append({"type":"high_report_volume","weight":5,"description":f"High report volume {ip_rep['reports']}"})
    if ip_rep_val=="malicious" and port_risk=="critical":
        score += 5
        factors.append({"type":"malicious_critical_combo","weight":5,"description":"Malicious IP + critical port risk alignment"})
    elif ip_rep_val=="suspicious" and port_risk in ("high","critical"):
        score += 5
        factors.append({"type":"suspicious_high_combo","weight":5,"description":"Suspicious IP with high/critical port risk"})

    score = max(0, min(100, int(score)))  # bounded
    level = "low" if score<=19 else "medium" if score<=39 else "high" if score<=69 else "critical"
    # Confidence separate (see §7)
    confidence = _confidence(port_risk, ip_rep, open_ports, scan_complete)
    explanation = _explanation(score, level, port_risk, ip_rep_val, factors, confidence)
    return ThreatAssessment(score, level, confidence, factors, explanation, assessed_at=now_iso())
```

**Exact rules for enumerated cases:**

* **No open ports (`open_set empty`):** `port_base` still applies (`low 10` if no critical/high/medium open → `low`), so `LOW+CLEAN=10`, `LOW+MALICIOUS=45` (`10+35`) → `high` even with no opens, which is intended (malicious IP alone raises). Modifiers requiring open ports (`critical_service_detail`, `database_exposure`, `multiple_high_risk`, `web combo` if kept) not triggered.
* **Clean IP:** `ip_base 0`, no `suspicious/malicious` factor, score = `port_base` + modifiers (if any). `LOW+CLEAN=10` low, `CRITICAL+CLEAN=60` high (needs modifiers to reach critical).
* **Unknown IP:** `0`, same as clean but confidence `medium` (unknown = no data, not clean). No score contribution.
* **Unavailable reputation (`None`, `unavailable`, missing API key, timeout, 429, 5xx):** `ip_base 0`, factor `unavailable_reputation` weight 0, `confidence=medium`, score from ports only. Never punished.
* **Suspicious IP:** `+20`, plus `high_report_volume` if `reports≥10`, plus `suspicious_high_combo` if port high/critical.
* **Malicious IP:** `+35`, plus `high_report_volume`, plus `malicious_critical_combo` if critical.
* **High report count (`≥10`):** Only `+5` when `suspicious|malicious`; `clean/unknown` with 0-9 reports → 0.
* **Critical services:** Modifier triggers only if `risk_level==critical` *and* critical set intersect; counted once even if `22,3389` both open.
* **Database exposure:** Trigger if DB subset intersect; counts once even if `3306,5432` both open; not double-counted with `critical_service_detail` (distinct evidence, both small 5).
* **Duplicate evidence:** Each modifier type at most once per assessment; `open_set` deduped.
* **Score cap:** `min(100, max(0, score))` integer.
* **Deterministic explanations:** Base + sorted factor types → stable `explanation` string, e.g., `"Malicious IP (35) + critical port risk (60) + critical service detail (5) → 100 CRITICAL. Reports 27 corroborate maliciousness."`

---

## 6. Severity Thresholds (Revised)

| Score | Level | Justification |
|---|---|---|
| **0-19** | `low` | `LOW (10)+CLEAN (0)=10` low; no critical/high, at most 1 low-risk port. |
| **20-39** | `medium` | `MEDIUM (25)+CLEAN=25` medium; `LOW+SUSPICIOUS (30)` medium. |
| **40-69** | `high` | `HIGH (45)+CLEAN=45` high; `LOW+MALICIOUS=45` high; `MEDIUM+SUSPICIOUS=45` high. |
| **70-100** | `critical` | `CRITICAL+MALICIOUS=95`→100 critical (with modifiers); `CRITICAL+SUSPICIOUS=80` critical; `HIGH+MALICIOUS=80` critical; requires strong alignment. |

**Why new thresholds with new base:** New base `MALICIOUS 35+CRITICAL 60=95` guarantees `critical` (needs ≥70). Old model `MALICIOUS 40+CRITICAL 25=65` only `high`. New model fixes that with `60+35=95`. `SUSPICIOUS 20+CRITICAL 60=80` also critical, intentional. `SUSPICIOUS 20+HIGH 45=65` stays `high` (needs combo +5 to reach 70 critical if desired, otherwise high). This keeps `critical` exclusive to strongest combos.

---

## 7. Confidence Model — Revised (Evidence Completeness, Not Severity)

**HIGH (complete evidence):** `scan_complete == True` (port scan finished, `ports_scanned`>0, `scan_duration_ms` present) **and** `ip_rep.reputation ∈ {clean, suspicious, malicious, unknown}` **with** `unknown` only when explicitly “no data” (0 reports, not `unavailable`) is considered usable signal (still high, because provider answered). All required fields present.

**MEDIUM (degraded, one signal missing):** `scan_complete` true but `reputation ∈ {unavailable} or None` **or** `reputation==unknown` with 0 reports treated as usable but *degraded* if combined with partial scan? Simple rule: `unavailable` or `None` → `medium`. Score still from ports only. Explanation notes “Reputation unavailable – assessment based on port evidence only (reason: timeout/429/missing key)”.

**LOW (materially incomplete):** `ports_scanned ==0` or `open_ports` is `None`/unparseable, **or** scan `status != completed`, **or** both `port scan incomplete` and `reputation unavailable`. This is rare (scanner always completes).

**Implementation:** `_confidence(port_complete: bool, ip_rep_val: str|None) -> "high"|"medium"|"low"` deterministic:

```python
if not port_complete: return "low"
if ip_rep_val in ("clean","suspicious","malicious"): return "high"
if ip_rep_val == "unknown": return "high"  # provider answered no data → still complete, not degraded
if ip_rep_val in ("unavailable", None): return "medium"
return "medium"
```

**Documentation:** Final rules stored in `ThreatAssessmentService.CONFIDENCE_RULES` docstring, not inferred.

---

## 8. Factor Model

```typescript
interface ThreatFactor {
  type: "port_risk" | "clean_ip" | "unknown_ip" | "unavailable_reputation" | "suspicious_ip" | "malicious_ip" | "critical_service_detail" | "database_exposure" | "multiple_high_risk" | "high_report_volume" | "malicious_critical_combo" | "suspicious_high_combo";
  weight: number; // 0-60 (base) or 0-5 (modifier), 0 for info
  description: string; // e.g., "Port risk CRITICAL (60)", "Malicious IP (35) — 27 reports, confidence high", "Database 3306 exposed (+5)"
  evidence?: string; // e.g., "ports=[22,3389], reports=27"
}
```

* Base factors always present (`port_risk`, `*_ip`) for traceability even when weight 0.
* Modifier factors only when triggered.
* `unavailable_reputation` weight 0, description “IP reputation unavailable (reason: timeout) – not counted, confidence medium”.

---

## 9. API Changes

**Existing `POST /api/scanner/ports` response (backward compatible):**

```json
{
  "success": true,
  "message": "Port scan completed",
  "data": {
    "target": "example.com",
    "resolved_ip": "93.184.216.34",
    "scan_duration_ms": 123,
    "ports_scanned": 20,
    "open_ports": [...],
    "closed_ports": 12,
    "filtered_ports": 3,
    "summary": "Scanned 20 ports …",
    "risk_level": "high",
    "ip_reputation": { ... }, // existing
    "threat_assessment": {     // NEW, nullable for old scans
      "score": 85,
      "level": "critical",
      "confidence": "high",
      "factors": [ { "type":"port_risk", "weight":60, ... }, { "type":"malicious_ip", "weight":35, ... }, ... ],
      "explanation": "Malicious IP (35) plus critical port risk (60) with critical service and high reports → 100 CRITICAL (capped).",
      "assessed_at": "2026-08-23T12:00:00Z"
    }
  }
}
```

* `threat_assessment` is **additive**, not replacement. Old clients ignore it.
* `GET /ip-reputation/*` unchanged (no threat).

**History**

* `GET /api/scanner/ports/history` – each item now includes `threat_assessment` (or `null` for pre-feature rows) alongside `ip_reputation`. Select adds `threat_assessment` to `id, ..., ip_reputation, threat_assessment, created_at`.
* `GET /api/scanner/ports/history/<id>` – `select *` already returns new column; `open_port_count` etc. remain.

**No secrets:** `threat_assessment` contains only `score/level/factors` with port numbers/service names already public; no `api_key/jwt/user_id`.

---

## 10. Database Changes

**Minimal additive column in `port_scans`:**

```sql
ALTER TABLE port_scans ADD COLUMN IF NOT EXISTS threat_assessment JSONB;
-- JSON shape: { score int 0-100, level text check, confidence text, factors jsonb, explanation text, assessed_at timestamptz }
-- No new table.
-- Optional check constraint for level: CHECK (threat_assessment->>'level' IN ('low','medium','high','critical'))
-- Index not needed (not queried, only returned).
```

* Historical rows: `threat_assessment` = `NULL` → interpreted as “not available”.
* Reproducibility: snapshot stored at scan time (ports + reputation snapshot + assessment). Future reputation changes do not alter history.

**Migration Required:** Yes, one `ALTER TABLE` idempotent. `schema.sql` updated to include column in `CREATE TABLE port_scans` + `DO $$ ADD COLUMN IF NOT EXISTS threat_assessment $$` backfill for existing DBs (same pattern as `ip_reputation`).

---

## 11. History Changes

* `PortScannerService.get_scan_history()` select adds `threat_assessment`; `ScanResult.threat_assessment` added.
* `get_scan_detail()` already `select *` → includes it.
* Frontend gracefully handles `null` → “Threat assessment not available for this scan.” (old scans).

---

## 12. Frontend Changes

**Existing `PortScannerPage.tsx` layout:** Two-col scan+port-risk + `IPReputationCard` + open ports table. **Add third card** `ThreatAssessmentCard` between reputation and ports, clearly separated:

* **Eyebrow:** `Overall Threat`
* **Score:** `85 / 100` large, `Badge` tone `low->success, medium->warning, high->danger, critical->danger` (reuse `Badge`).
* **Confidence:** `high/medium/low` badge with tooltip “Evidence completeness”.
* **Explanation:** 1-2 sentence paragraph.
* **Factors:** `DataTable` or `factors.map` pills: `weight` + `description` (e.g., `+35 Malicious IP — 27 reports, confidence very_high`).
* **Visual separation:** Port Risk (blue), IP Reputation (amber), Overall (navy) with distinct `eyebrow` and border.

**History Detail:** Show stored `threat_assessment` card or fallback note.

**Types:** `frontend/src/types/index.ts` add `ThreatFactor`, `ThreatAssessment`, extend `PortScanResult/HistoryItem/Detail.threat_assessment?`, `ReportPortScanData`.

**Services:** `portScannerService.ts` no change (just types); `apiClient` unchanged.

---

## 13. PDF Report Changes

* `backend/app/reports/pdf_generator.py`: `PORT_KEYS` already, `report_service._map_port_scan` will include `threat_assessment`.
* `_port_section()` already renders port + IP reputation; **add sub-section** “Overall Threat Assessment” after them:
  * KV table: `Overall Score / Level / Confidence / Explanation`
  * Factors table: `Weight | Type | Description`
  * Note still: “Port risk and IP reputation remain independent; overall amplifies both.”
* `_build_story` keeps `6. Port Scanner and IP Reputation` (now with overall) → `7. Risk & Findings` unchanged.
* `_map_port_scan` sanitizes `explanation` via `_esc`.

---

## 14. Security Considerations

* **No scanner change:** `validate_hostname_or_ip`, `is_private_hostname`, `is_private_ip` still block private before cache/provider/assessment.
* **No provider change:** `AbuseIPDBProvider` timeout/429/401/5xx → `unavailable` still not cached.
* **Cache intact:** `ip_reputation_cache` still `(ip,provider)` shared, RLS `ENABLE` no policies, `service_role` via `get_supabase_admin_client` + direct `current_app` fallback, logging `cache_hit/miss/put_success` (no secrets).
* **No secrets:** `ThreatAssessment` contains only derived numbers/strings from `open_ports`/`reputation`; `api_key/jwt/user_id/provider secrets` never included. `to_dict()` allow-list.
* **RLS intact:** `port_scans` still `user_id=auth.uid()`, new `threat_assessment` column inherits policy.
* **No user_id in cache**, no `cached` flag to frontend unless needed.
* **Sanitization:** banners already sanitized in `port_scanner_service._scan_single_port`; `_map_port_scan` re-sanitizes; PDF `_esc`.

---

## 15. Test Plan

**Scoring (pure unit, no DB, deterministic):**
* `low (10) + clean (0)` → `10 low, confidence high, factors [port_risk 10, clean 0]`
* `low (10) + unknown (0)` → `10 low, confidence high (unknown is usable), no modifier`
* `low (10) + suspicious (20) =30` → `medium`
* `low (10) + malicious (35)=45` → `high`
* `high (45) + clean (0)=45` → `high`
* `high (45) + malicious (35)=80` → `critical` (without modifiers already critical)
* `critical (60) + malicious (35)=95` → `critical`, plus `critical_service_detail 5 + malicious_critical_combo 5 → 100 critical (capped)`
* `critical (60)+suspicious (20)=80` → `critical`
* `no open ports (low 10) + clean` → `10 low`
* `unavailable` or `None` → `port_base` only, `0` ip, `confidence medium`, factor `unavailable 0`, e.g., `critical 60+unavailable 0=60 high, medium confidence`
* `high report count (≥10)` + `suspicious` → `+5`
* `critical services {22,3389}` → `critical_service_detail` counted once
* `database {3306,5432}` → `database_exposure` once even if two DB ports
* `score cap` `95+10→100`
* `deterministic` same input → same `score/level/factors` order
* `explanation` contains base + modifiers

**Security/Persistence/API/Reports:**
* No `api_key/jwt/user_id` in `threat_assessment` JSON or PDF
* Old rows `threat_assessment IS NULL` still deserialize
* `generate_report` includes `port_scan.threat_assessment` when present
* `GET /history` returns `threat_assessment` or `null` per row, isolation per `user_id`
* `POST /ports` backward compat: old clients ignore new field, response shape `risk_level`+`ip_reputation` unchanged

**Regression:**
* `python -m pytest backend/tests/test_port_scanner.py` (risk levels)
* `test_ip_reputation_cache.py` (21)
* `test_reports.py` (38, update heading to include overall)
* `conftest` fake add `threat_assessment` column

---

## 16. Documentation Changes

* `README.md` — Features: add “Overall Threat Assessment (deterministic base+modifiers, port + reputation, explainable)” .
* `docs/06_Database_Design.md` — `port_scans` add `threat_assessment JSONB` description, example JSON.
* `docs/07_API_Design.md` — `POST /ports` response add `threat_assessment` schema, `GET /history` add field, note `null` for old scans.
* `docs/08_Backend_Architecture.md` — new `ThreatAssessmentService` in diagram, flow `Scanner → Reputation → Assessment → Persist`, cache untouched.
* `docs/09_Frontend_Architecture.md` — `PortScannerPage` three-signal UI, `types` new interfaces.
* `docs/12_Security_Requirements.md` — no secrets in assessment, RLS unchanged, private IP still blocked.
* `docs/15_Testing_Strategy.md` — scoring matrix (base+modifiers), deterministic tests, confidence completeness.

No `docs/schema.sql` change until approved (but proposed).

---

## 17. Deployment Considerations

* No new env vars (scoring uses existing `PORT_SCANNER_*` and `IP_REPUTATION_*`). Optional `THREAT_SCORE_WEIGHT_*` not needed; keep deterministic in code.
* No Vercel/Render config change.
* No Redis.
* PDF generation unchanged except new section; storage bucket already.

---

## 18. Migration Requirements

* **Supabase:** One idempotent DDL:

```sql
ALTER TABLE port_scans ADD COLUMN IF NOT EXISTS threat_assessment JSONB;
-- Optional backfill not needed; old rows remain NULL.
-- Update schema.sql CREATE TABLE to include threat_assessment JSONB + DO $$ backfill.
```

* No `ip_reputation_cache` migration.

---

## 19. Backward Compatibility

* **API:** Additive `threat_assessment` nullable; clients ignoring unknown fields unaffected. `risk_level` and `ip_reputation` unchanged.
* **DB:** New column nullable → old rows read as `null`, `get_scan_history`/`detail` handle `None`.
* **Reports:** `report_data.port_scan.threat_assessment` optional; old reports `port_scan` without it still render (“Not available”).
* **Frontend:** Types `threat_assessment?` optional, UI fallback note.

---

## 20. Risks / Limitations

* Base weights `60+35=95` already critical, modifiers may be redundant for that combo but needed for `suspicious+high` edge; cap prevents overflow.
* `unknown` 0 weight – could be considered `medium` confidence unknown; chosen to avoid punishing lack of data, confidence `high` for unknown (provider answered).
* Score granularity coarse (5-point modifiers) – intentional to avoid fake precision.
* No ML – future could learn weights, but current deterministic is auditable.
* Cache still 24h TTL – overall score snapshot at scan time may become stale, but historical reproducibility intended.

---

## 21. Recommended Implementation Phases

**Phase 1 (Next):** `ThreatAssessmentService` with base+modifiers as above + `port_scans.threat_assessment` column + `PortScannerService` integration + API/history + PDF `Overall` sub-section + frontend card + tests (as per §15) + docs.

**Phase 2 (Future):** Tunable weights via `THREAT_WEIGHT_*` env (no code change), confidence visualization (evidence completeness badge), trend chart of `threat_score` over time, report `overall_score` in `_overall_score`.

**Not in scope:** Combined risk replacing `risk_level`, AbuseIPDB change, cache change, Redis.

---

**PHASE 2D-3 DESIGN REVISION COMPLETE — READY FOR IMPLEMENTATION**

**Exact files that would be changed in implementation phase:**

* `backend/app/services/threat_assessment_service.py` **NEW** — base `LOW 10/MEDIUM 25/HIGH 45/CRITICAL 60`, IP `CLEAN/UNKNOWN/UNAVAILABLE 0/SUSPICIOUS 20/MALICIOUS 35`, modifiers `critical_service_detail 5 / database_exposure 5 / multiple_high_risk 5 / high_report_volume 5 / malicious_critical_combo 5 / suspicious_high_combo 5`, cap 100, confidence `high=complete+usable, medium=unavailable/unknown, low=incomplete`
* `backend/app/services/port_scanner_service.py` (add `threat_assessment` to `ScanResult`, call `ThreatAssessmentService`, persist)
* `backend/app/database/schema.sql` (add `threat_assessment JSONB` + backfill `DO $$`)
* `backend/app/services/report_service.py` (`_map_port_scan` add `threat_assessment` passthrough)
* `backend/app/reports/pdf_generator.py` (`_port_section` add Overall sub-section + `_threat_table` helper)
* `backend/app/routes/port_routes.py` (include `threat_assessment` in `POST /ports` response dict – already via `ScanResult`)
* `frontend/src/types/index.ts` (`ThreatFactor`, `ThreatAssessment`, extend `PortScanResult/History/Detail/ReportPortScanData`)
* `frontend/src/pages/PortScannerPage.tsx` (add `ThreatAssessmentCard`, keep three-signal separation, confidence as completeness)
* `backend/tests/test_threat_assessment.py` **NEW** covering all enumerated rules + `conftest.py` fake (threat column) + `test_reports.py` heading
* `docs/*` (06,07,08,09,12,15) – documentation only after approval

