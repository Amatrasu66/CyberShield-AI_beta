# PORT THREAT INTELLIGENCE AGGREGATION — PHASE 2D-4 DESIGN (INVESTIGATION ONLY)

> **Status:** Design / Investigation Phase Only — No implementation in this task.  
> **Predecessors:** Port Scanner (Phase 2A `PortScannerService`), Port Scan Persistence (Phase 2C-1 `port_scans` RLS), Port Scan History (Phase 2C-2 `get_scan_history`/`get_scan_detail`), IP Reputation / AbuseIPDB (Phase 2D-1 `IPReputationService` → `AbuseIPDBProvider`/`NullProvider` → `ReputationResult`), Bounded IP Reputation Cache (Phase 2D-2 `IPReputationCacheService` → `ip_reputation_cache` 24h TTL), Threat Assessment (Phase 2D-3 `ThreatAssessmentService` → `port_scans.threat_assessment` JSONB).  
> **Current Revision Verified:** 2026-08-25 via direct file inspection (see §2).

---

## 1. Problem

### 1.1 Observed Failure

```
Target: IP present in Project Honey Pot http:BL with historical malicious/suspicious evidence
AbuseIPDB: UNKNOWN (0 reports, score 0)
CyberShield pipeline: Port Scanner → Port Risk + IPReputationService(AbuseIPDB) → ThreatAssessmentService
Result:
  IP Reputation: UNKNOWN (0 points)
  Overall Threat: LOW
  Score: 10/100  (LOW 10 + UNKNOWN 0, no modifiers)
```

Technically consistent with the current model (`UNKNOWN` contributes `0` in `threat_assessment_service.py:46-52`), but **operationally blind**: single-provider IP reputation treats absence of AbuseIPDB data as absence of evidence. A known-bad IP in another reputable feed is invisible.

### 1.2 Root Cause

- `IPReputationService._get_provider()` (`ip_reputation_service.py:246-279`) is single-provider: `abuseipdb` or `NullProvider`. No abstraction for multiple independent feeds.
- `ThreatAssessmentService.assess()` (`threat_assessment_service.py:77-83`) consumes exactly one `ip_reputation: Optional[dict]` — cannot distinguish "AbuseIPDB unknown + HoneyPot malicious".
- Cache `ip_reputation_cache` (`schema.sql:146-165`, `ip_reputation_cache_service.py:141-325`) is keyed `(ip, provider)` but schema/fields are AbuseIPDB-specific (`reports`, `country`, `asn`), not provider-agnostic.
- No Project Honey Pot integration exists; DNS-based http:BL contract (see §5) has no HTTP-fetch reuse.

### 1.3 Goal

Introduce a **provider-independent Threat Intelligence Aggregation layer** that:

1. Preserves the existing pipeline verbatim when only AbuseIPDB is enabled.
2. Adds Project Honey Pot (DNS http:BL) as a second independent signal without tight coupling.
3. Keeps future providers (VirusTotal, GreyNoise, OTX — out of scope) addable with no `ThreatAssessmentService` changes.
4. Maintains invariants: SSRF/private-IP blocking, fixed provider endpoints, `RLS`/`service_role` cache, no secret leakage, deterministic scoring, backward compatibility.

**Non-goals (this phase):** Final scoring weights, arbitrary DNS server control, user-supplied providers/keys, IPv6 http:BL, scraping `projecthoneypot.org`.

---

## 2. Current Architecture Findings (Verified)

### Files inspected

- `backend/app/services/ip_reputation_service.py` (390 lines)
- `backend/app/services/ip_reputation_cache_service.py` (325 lines)
- `backend/app/services/port_scanner_service.py` (607 lines)
- `backend/app/services/threat_assessment_service.py` (288 lines)
- `backend/app/routes/port_routes.py` (165 lines)
- `backend/app/database/schema.sql` (249 lines)
- `backend/app/config/settings.py` (187 lines)
- `backend/app/services/report_service.py` (458 lines)
- `backend/app/reports/pdf_generator.py` (825 lines)
- `backend/app/utils/validators.py` (553 lines)
- `backend/tests/conftest.py` (369 lines)
- `backend/tests/test_threat_assessment.py` (285 lines), `test_ip_reputation_cache.py` (350 lines)
- `frontend/src/types/index.ts` (444 lines)
- `frontend/src/pages/PortScannerPage.tsx` (824 lines)
- `frontend/src/services/portScannerService.ts` (28 lines)
- `PORT_THREAT_ASSESSMENT_PHASE1.md` (474 lines)

### 2.1 `ReputationResult` (`ip_reputation_service.py:42-65`)

```python
@dataclass
class ReputationResult:
    ip: str
    reputation: str          # unknown | clean | suspicious | malicious | unavailable
    confidence: Optional[str] # none | low | medium | high | very_high
    malicious: bool = False
    suspicious: bool = False
    reports: int = 0
    country: Optional[str] = None
    asn: Optional[int] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    last_reported_at: Optional[str] = None
    provider: str = "unknown"
    checked_at: Optional[str] = None
    reason: Optional[str] = None  # unavailable reason, not stack
```

- `to_dict()` via `asdict` — no secret filtering here (service layer allow-lists).
- `_reputation_from_abuse(score, reports, whitelisted)` and `_confidence_from_score(score)` are AbuseIPDB-specific; they impose `reports`/`score` semantics that do not transfer to HoneyPot's `days/threat/visitor_type`.

### 2.2 Provider Abstraction (`ip_reputation_service.py:100-238`)

- `IPReputationProvider(ABC)` with `provider_name` + `check_ip(ip) -> ReputationResult`.
- `AbuseIPDBProvider`: bounded `timeout 5`, `max_bytes 32768`, fixed `base_url` from `get_config().IP_REPUTATION_ABUSEIPDB_URL`, `requests.get`, handles `429→rate_limited`, `401/403→auth_failed`, `5xx→provider_error`, `Timeout→timeout`, malformed→`unavailable` with `reason`. Double-checks `is_private_ip` and missing `api_key` → `unavailable` without network.
- `NullProvider(provider_name="unavailable")` → `reason="provider_disabled"`.
- `IPReputationService` facade: `_get_provider()` prefers `current_app.config` then `get_config()`; `check_ip()` validates `validate_ip_address` + `is_private_ip` → `ValidationError`, cache `get` → `provider.check_ip` → `put` (skips `unavailable`). `check_target()` resolves hostname via `socket.getaddrinfo`, filters private/loopback/link-local/reserved/multicast/unspecified, re-validates before provider.

**Key constraint for 2D-4:** `ReputationResult.reports` and `confidence`/`country`/`asn` are meaningfully populated only for AbuseIPDB. Project Honey Pot has `days_since_activity`, `threat_score 0-255`, `visitor_type` bitset — forcing those into `reports` would be semantically dishonest and break scoring assumptions (`high_report_volume` modifier depends on `reports>=10`).

### 2.3 Cache (`ip_reputation_cache_service.py:21-106, IPReputationCacheService:140-315`, `schema.sql:146-176`)

- Table `ip_reputation_cache` (`ip, provider` UNIQUE, indexes `(ip,provider)` + `expires_at`, `ENABLE RLS` **no policies** → frontend blocked, backend via `get_supabase_admin_client()` / direct `create_client(url, secret)` fallback, logging without secrets).
- `_get_cache_client()` strictly prefers `service_role`; `anon` fallback only for local dev without secret (still blocked by RLS).
- `get(ip, provider)` returns `ReputationResult` only if `expires_at > now`; `put(result)` skips `reputation=="unavailable"`, `upsert` on `(ip, provider)` with multi-fallback (`on_conflict`, plain `upsert`, `insert`, `update`) for fake compatibility. Payload allow-list: `ip,reputation,confidence,malicious,suspicious,reports,country,asn,organization,isp,last_reported_at,provider,checked_at,expires_at,updated_at`.
- TTL: `IP_REPUTATION_CACHE_TTL` default `86400` (`TTL-controlled, provider-specific, no user_id, never stores secrets, safe against stale` — claim verified).

### 2.4 Port Scanner (`port_scanner_service.py:43-607`)

- `ScanResult(target, resolved_ip, scan_duration_ms, ports_scanned, open_ports, closed/filtered, summary, risk_level, ip_reputation?, threat_assessment?)`
- `scan_ports(target, ports|profile, config, user_id)` validates target before any socket, SSRF block via `is_private_hostname`, resolves `target → resolved_ip` via `getaddrinfo`, `_scan_port_list` with `ThreadPoolExecutor(max_concurrency)`, per-port `connect_timeout 2s`, `total_timeout 30s`, banner `256` bytes sanitized.
- Risk derived from `CRITICAL_RISK_PORTS={22,23,3389,5900,5901,5985,5986}`, `HIGH_RISK_PORTS={135,139,445,1433,1521,3306,5432,6379,27017,27018,27019}`, `MEDIUM_RISK_PORTS` — `.assess` overlay in Phase 2D-3.
- IP reputation lookup is **best-effort**: after scan, `IPReputationService.check_ip(resolved_ip)`; `ValidationError` private → `unavailable private_ip_blocked`, any exception → `unavailable provider_error`. Never breaks scan.
- Threat assessment (`ThreatAssessmentService.assess(port_risk, ip_reputation, open_ports, ports_scanned)`) derived deterministically; attached to `ScanResult.threat_assessment`; persisted via `_persist_scan` through `get_user_supabase_client(get_current_access_token())` → RLS `port_scans_owner_all (user_id=auth.uid())`.
- History queries `port_scans` via user-scoped client; detail/history `open_port_count` derived.

### 2.5 Threat Assessment (`threat_assessment_service.py:1-288`)

- Pure logic, no DB/network. `PORT_BASE={low:10, medium:25, high:45, critical:60}`, `IP_BASE={clean:0, unknown:0, unavailable:0, suspicious:20, malicious:35}`. Modifiers `+5` each (deduplicated, capped): `critical_service_detail`, `database_exposure`, `multiple_high_risk`, `high_report_volume (reports>=10)`, `malicious_critical_combo`, `suspicious_high_combo` (exclusive). Cap `0-100`, `LEVEL_THRESHOLDS: 0-19 low, 20-39 medium, 40-69 high, 70-100 critical`. Confidence is **evidence completeness**: `low = incomplete scan`, `medium = complete but reputation unavailable`, `high = complete + usable reputation (clean/suspicious/malicious/unknown)`. Explanation deterministic, sorted contributing factors.

### 2.6 Routes (`port_routes.py:1-165`)

- `POST /api/scanner/ports` `@require_auth` validates `target` via `validate_hostname_or_ip`, calls `PortScannerService.scan_ports(user_id=get_current_user_id())`, returns envelope with `risk_level`, `ip_reputation`, `threat_assessment`.
- `GET /ports/history`, `GET /ports/history/<id>`, `GET /ip-reputation/<path:ip>`, `POST /ip-reputation` all `@require_auth`, `user_id` from JWT only. IP endpoints validate `validate_ip_address` + `is_private_ip` before service.

### 2.7 Schema (`schema.sql:106-176`)

- `port_scans` already has `ip_reputation JSONB` + `threat_assessment JSONB` with idempotent `DO $$ ADD COLUMN IF NOT EXISTS $$` backfill (Phase 2D-3).
- `ip_reputation_cache` shared, `ENABLE RLS` no policies, `UNIQUE(ip,provider)`.

### 2.8 Config (`settings.py:91-104`)

- `IP_REPUTATION_ENABLED=false`, `IP_REPUTATION_PROVIDER="abuseipdb"`, `IP_REPUTATION_API_KEY`, `IP_REPUTATION_TIMEOUT=5`, `IP_REPUTATION_MAX_RESPONSE_BYTES=32768`, `IP_REPUTATION_ABUSEIPDB_URL` fixed, `IP_REPUTATION_CACHE_ENABLED=true`, `IP_REPUTATION_CACHE_TTL=86400`.

### 2.9 Reports (`report_service.py:40-314`, `pdf_generator.py:446-533`)

- `SCAN_TABLES` includes `port_scans`; `_map_port_scan` allow-lists reputation fields `{ip,reputation,confidence,malicious,suspicious,reports,country,asn,organization,isp,last_reported_at,provider,checked_at,reason}` and threat `{score,level,confidence,factors,explanation,assessed_at}` with factor sanitization; `pdf_generator._port_section` headings: `6. Port Scanner and IP Reputation` with subheads `Port Scan — Target & Results` / `IP Reputation — AbuseIPDB (independent from port risk)` / `Overall Threat Assessment — Derived from Port Risk + IP Reputation`. Already distinct `PORT RISK ≠ REPUTATION` notes.

### 2.10 Frontend (`types/index.ts:340-444`, `PortScannerPage.tsx:31-220`)

- `IPReputationState`, `IPReputationResult`, `ThreatAssessment`, `PortScanResult` (`ip_reputation?`, `threat_assessment?`). `PortScannerPage` shows `Port risk level` card → `IPReputationCard` (independent eyebrow, `ReputationBadge`/`ConfidenceBadge`, `reports/country/asn`) → `ThreatAssessmentCard` (derived eyebrow, score/level, confidence as evidence completeness) → `Open ports` table. History/detail fallbacks `"Not available"` for old scans.

---

## 3. Proposed Architecture

```
                        Target IP (validated public IPv4)
                              │
                              ▼
                 ThreatIntelligenceAggregator
                 (alias: ThreatIntelligenceService)
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
  AbuseIPDBProvider    ProjectHoneyPotProvider   FutureProvider
   (HTTP REST)            (DNS http:BL)             │
         │                    │                    │
   ip_reputation_cache   ip_reputation_cache       │
   (ip,provider)          (ip,provider)             │
         │                    │                    │
         └────────────────────┼────────────────────┘
                              ▼
                Normalized Evidence Bundle
                { provider -> ProviderEvidence }[]
                              │
                              ▼
              ThreatAssessmentService.assess(
                 port_risk, open_ports, evidence_bundle)
                              │
                              ▼
                Overall Threat (score/level/confidence/factors)
```

**Why this graph:**

- Aggregator is the **only** new orchestrator; it owns validation (once), provider enablement, cache fan-out, fault isolation, and deterministic bundling. Port scanner calls aggregator instead of `IPReputationService` directly; `IPReputationService` remains for the single-IP endpoints (or delegates to aggregator with one provider).
- Providers stay leaf nodes; they know their wire format only.
- Cache remains per-`(ip,provider)` but is now shared across aggregator fans.

**Change surface (smallest safe):**

| Component | Change |
|---|---|
| New `threat_intelligence_service.py` (Aggregator) | New file, ~120 lines, no schema change, depends on providers + cache service |
| New `project_honeypot_provider.py` (or inside `threat_intelligence` package) | New file, ~150 lines, DNS only, no HTTP |
| Extend `ip_reputation_cache` schema | Add nullable `evidence JSONB` + provider-specific columns (see §7) |
| `IPReputationService` | Minimal: either (a) kept as legacy facade delegating to aggregator for `check_ip(target)` with single provider, or (b) deprecated in favor of aggregator for scan path. **Recommendation (a)** — keep for `/ip-reputation` backward compat. |
| `ThreatAssessmentService` | Overload: new `assess_with_intelligence(port_risk, open_ports, evidence_bundle)` alongside existing `assess(port_risk, ip_reputation, ...)`; no breaking change to callers that still pass single reputation. |
| `PortScannerService` | 3-line change: `IPReputationService.check_ip` → `ThreatIntelligenceAggregator.check_ip` and attach `threat_intelligence` bundle to `ScanResult` + persist |
| `schema.sql` | `ALTER` for cache extension + `port_scans.threat_intelligence JSONB` (optional; see §10) |

No direct Vercel/Render config, no Redis, no new RLS policies (cache inherits `service_role` bypass).

---

## 4. Provider Abstraction

### 4.1 Options Evaluated

| Option | Shape | Pros | Cons |
|---|---|---|---|
| **A. Keep `IPReputationProvider` unchanged, add parallel `ThreatIntelligenceProvider`** | Two protocols, `AbuseIPDBProvider: IPReputationProvider`, `ProjectHoneyPotProvider: ThreatIntelligenceProvider`, Aggregator accepts `ThreatIntelligenceProvider[]` where each provider's `check_ip` returns a distinct normalized type | Zero change to AbuseIPDB code/tests; HoneyPot not forced into `reports` semantics | Two protocols diverge; minor drift unless unified later |
| **B. Rename/generalize `IPReputationProvider` → `ThreatIntelligenceProvider` with alias** | `ThreatIntelligenceProvider(ABC)` replaces `IPReputationProvider`; alias `IPReputationProvider = ThreatIntelligenceProvider` for backward compat; `AbuseIPDBProvider` implements generic method | Single abstraction; fresh mental model; smallest long-term maintenance | Slight churn (rename imports) but alias removes breakage |
| **C. Single generic provider returning `ProviderEvidence` plus `ReputationResult` shim** | Generic provider returns `ProviderEvidence` with common fields; `IPReputationService` converts `ProviderEvidence[abuseipdb]` → legacy `ReputationResult` via adapter | Clean future direction | More migration code than needed for Phase 1 |

### 4.2 Recommendation: **Option B — Generalize with Alias (Preserve AbuseIPDB Behavior)**

1. **Introduce `ThreatIntelligenceProvider`** in a new module `app/services/threat_intelligence/provider.py` (or reuse `ip_reputation_service.py` if colocated, but new file is cleaner):

```python
class ThreatIntelligenceProvider(ABC):
    provider_name: str = "unknown"
    @abstractmethod
    def check_ip(self, ip: str) -> "ProviderEvidence": ...
```

2. **Keep `IPReputationProvider` as alias** for backward compatibility:

```python
IPReputationProvider = ThreatIntelligenceProvider  # alias, not new logic
```

3. **Migrate `AbuseIPDBProvider`** to return `ProviderEvidence` internally while **preserving `ReputationResult` shape via adapter** for legacy callers (`GET /ip-reputation`). The provider's HTTP logic remains unchanged; only the return is wrapped.

4. **Add `ProjectHoneyPotProvider: ThreatIntelligenceProvider`** (see §5).

5. **Aggregator depends on `ThreatIntelligenceProvider[]`** — provider discovery reads `current_app.config` (`THREAT_INTELLIGENCE_ENABLED`, `IP_REPUTATION_ENABLED` legacy) and constructs the enabled list; caller never names providers.

**Why this is smallest architectural change:**

- AbuseIPDB behavior/tests (`test_ip_reputation_cache.py` 350 lines, `test_threat_assessment.py`) continue to assert `ReputationResult` fields (`reputation`, `reports`, `confidence`) — alias ensures `IPReputationProvider` imports don't break.
- Adding a second protocol (`Option A`) would require the cache and assessment to handle two disjoint result types; generalizing one protocol with a superset normalized model (see §5) avoids duplication.
- No `ThreatAssessmentService` coupling: it depends on `ProviderEvidence[]`, not on concrete providers.

### 4.3 Provider-Specific Data Isolation

- Each provider defines its **own** evidence schema under a common envelope (see §5.2).
- `ThreatAssessmentService` reads only the **normalized core** (`reputation` ∈ `unknown|clean|suspicious|malicious|unavailable`, `malicious/suspicious` bool, `confidence` as evidence completeness). Provider-specific enrichment (`abuse_reports`, `honeypot_threat_score`, `honeypot_categories`) is carried in `evidence` but never drives scoring unless explicitly allow-listed and approved (see §9).
- Raw wire data (`AbuseIPDB JSON`, DNS octets) is **never** returned to frontend; only normalized evidence plus bounded derived fields.

---

## 5. Normalized Provider Result

### 5.1 Problem with Blind Copy of AbuseIPDB Fields

AbuseIPDB reports `abuseConfidenceScore 0-100` + `totalReports` (count), `countryCode`, `isWhitelisted`. Project Honey Pot reports `days_since_last_activity` (0-? capped), `threat_score 0-255`, `visitor_type` bitset (`search_engine/suspicious/harvester/comment_spammer`). Copying HoneyPot's `threat_score 92` into `reports=92` would corrupt `high_report_volume` logic and mislead UI ("92 reports").

### 5.2 Proposed Envelope

```python
@dataclass
class ProviderEvidence:
    # Identity
    ip: str
    provider: str          # "abuseipdb" | "projecthoneypot" | future
    # Normalized core — every provider MUST populate; assessment reads only this
    reputation: str        # unknown | clean | suspicious | malicious | unavailable
    malicious: bool
    suspicious: bool
    confidence: str        # none | low | medium | high | very_high  (evidence completeness, not severity — see §5.4)
    # Temporal
    checked_at: str        # ISO8601 UTC when evidence produced
    last_seen: Optional[str] = None  # ISO8601 of last activity if known (honeypot: last activity; abuseipdb: lastReportedAt)
    # Provider-augmented signals (nullable, provider-scoped, NOT required)
    categories: list[str] = field(default_factory=list)  # normalized tags: e.g., ["suspicious","harvester"]
    raw_score: Optional[int] = None   # provider-native score (0-100 for AbuseIPDB, 0-255 for HP) for debugging, not scoring unless approved
    evidence: Optional[dict] = None   # bounded JSON for UI (see per-provider)
    reason: Optional[str] = None      # unavailable reason: timeout, dns_error, missing_key, etc.
```

**Field semantics (every field justified):**

| Field | Why required | Populated by |
|---|---|---|
| `provider` | Disambiguates bundle entries; cache key `(ip,provider)` | All providers |
| `reputation` (5-state) | Sole assessment input; `unknown` = no data, `unavailable` = error/disabled | All providers, per mapping tables §5.5 and §6 |
| `malicious`/`suspicious` bool | Back-compat with `ReputationResult`; deterministic assessment modifiers | Derived from `reputation` |
| `confidence` | Existing frontend badge; for HoneyPot derived from `threat_score` + recency (see §5.4) | Per provider |
| `checked_at` | Cache TTL origin; shows staleness | All |
| `last_seen` | HoneyPot `days_since` → absolute timestamp; AbuseIPDB `lastReportedAt` | Each provider if known |
| `categories` | HoneyPot `visitor_type` bitset → normalized tags (`["suspicious","harvester","comment_spammer","search_engine"]`); AbuseIPDB `[]` unless future enrichment | Per provider |
| `raw_score` | HoneyPot `threat_score 0-255` vs AbuseIPDB `0-100`; kept raw for transparency, **not** double-counted | Per provider |
| `evidence` | Bounded provider-specific UI block: AbuseIPDB `{reports, country, asn, isp, organization, is_whitelisted}`, HoneyPot `{days_since_activity, threat_score, visitor_type, visitor_type_flags}` | Per provider |
| `reason` | `unavailable`/`unknown` explanation: `nxdomain`, `timeout`, `dns_error`, `missing_access_key`, `private_ip_blocked` | On non-success |

### 5.3 Legacy `ReputationResult` Compatibility

`ReputationResult` is **kept** as the wire type for `GET /ip-reputation/*` and `POST /ip-reputation` (backward compat). New `ProviderEvidence` wraps it:

```python
def evidence_to_legacy(ev: ProviderEvidence) -> ReputationResult:
    # AbuseIPDB: direct mapping
    # HoneyPot: synthesized — reports=0, country/asn None, reputation mapped per §6
```

Port scan response keeps `ip_reputation` (AbuseIPDB legacy) for old clients, and adds `threat_intelligence` bundle (new). See §11.

### 5.4 Confidence Notes for Multi-Provider

- `confidence` on `ProviderEvidence` is **provider-internal evidence completeness** (how sure the provider is of its signal), **not** global assessment confidence. E.g., AbuseIPDB `very_high` when `score>=75`; HoneyPot `high` when `threat_score>=70` and `days<30` and `harvester|comment_spammer`.
- Global assessment `confidence` (`ThreatAssessmentService`) remains `high/medium/low` per evidence completeness **across** the bundle (see §9). Do not let UI imply `confidence=high` means "safe".
- Display as **"Evidence Confidence"** per spec (see §12).

---

## 6. Project Honey Pot Normalization

### 6.1 Wire Contract

- Lookup: `<ACCESS_KEY>.<REVERSED_IPV4>.dnsbl.httpbl.org` — e.g., key `abc123` for `1.2.9.127` → `abc123.127.9.2.1.dnsbl.httpbl.org`.
- Response (if positive): `127.<days>.<threat>.<visitor_type>`. First octet must be `127`; others untrusted until validated.
- `NXDOMAIN` / no answer = no evidence (NOT clean).
- Must not scrape `projecthoneypot.org` HTML; must use DNS only.

### 6.2 Exact Normalized Mapping

| HoneyPot Wire Result | Raw Fields | Normalized `ProviderEvidence` |
|---|---|---|
| **NXDOMAIN / NODATA / empty** | DNS `NXDOMAIN` or `NOERROR` with 0 answers | `reputation="unknown"`, `confidence="none"`, `malicious=false`, `suspicious=false`, `categories=[]`, `raw_score=None`, `last_seen=None`, `evidence={"days_since_activity": null, "threat_score": null, "visitor_type": null}`, `reason="no_result"` |
| **Valid `127.D.T.V`** with `D=days`, `T=threat 0-255`, `V=visitor_type 0-7` | Example `127.4.92.5` (`D=4,T=92,V=5=SUSPICIOUS+COMMENT_SPAMMER`) | Map `V` bitset: `0→search_engine`, `1→suspicious`, `2→harvester`, `4→comment_spammer`; combinations additive. `reputation`: `0→clean` (search engine); `V∈{1,2,4,3,5,6,7}→` see below; `malicious/suspicious` derived; `confidence` from `T` (see §6.3); `raw_score=T`; `last_seen = checked_at - D days` (ISO); `evidence={days_since_activity:D, threat_score:T, visitor_type:V, visitor_type_flags: categories}` |
| **`V=0` (Search Engine)** | `127.D.T.0` | `reputation="clean"`, `confidence="none"` (or low if `T>0` but spec says search engine is benign), `suspicious=false, malicious=false`, `categories=["search_engine"]`, `reason=null` |
| **`V=1` Suspicious** | | `reputation="suspicious"`, `suspicious=true`, `categories=["suspicious"]` |
| **`V=2` Harvester** | | `reputation="suspicious"` (harvester is reconnaissance, not yet spam) → `suspicious=true`; if `T>=75` and fresh, may be `malicious=true` pending approval (see Open Questions §18); default `suspicious` to avoid overcounting |
| **`V=4` Comment Spammer** | | `reputation="suspicious"` by default; `malicious` only if `T>=70` and `D<=14` (fresh, high threat) — configurable, but Phase 1 proposal: `V=4` alone → `suspicious` |
| **`V=3,5,6,7` Combined** | Bitset OR | Union of tags: `3→["suspicious","harvester"]`, `5→["suspicious","comment_spammer"]`, `6→["harvester","comment_spammer"]`, `7→["suspicious","harvester","comment_spammer"]`. `reputation`: if any `harvester` or `comment_spammer` present **with** `T>=50` → `suspicious` (conservative). `malicious` is **not** automatically true for combined — requires high `T` threshold (see below). |
| **DNS timeout** (`socket.timeout` / `dns.resolver.Timeout`) | | `reputation="unavailable"`, `confidence="none"`, `reason="timeout"` — **not cached** (see §7) |
| **DNS error** (`SERVFAIL`, `REFUSED`, `socket.gaierror` from DNS) | | `reputation="unavailable"`, `reason="dns_error"` — not cached |
| **Malformed response** (octets ≠4, first≠127, `T`/`D`/`V` non-int, `V`>7) | | `reputation="unavailable"`, `reason="malformed_response"` — not cached |
| **Missing access key** (`get_config().PROJECT_HONEYPOT_ACCESS_KEY` empty) | | `reputation="unavailable"`, `reason="missing_access_key"` — not cached, never performs lookup |
| **Private/reserved/multicast/loopback IP** | `is_private_ip` true | Reject before DNS; raise `ValidationError` (same as AbuseIPDB path), never reaches provider |
| **IPv6** | `ipaddress.ip_address` is v6 | `reputation="unavailable"`, `reason="unsupported_ip_version"` — HoneyPot http:BL is IPv4-only per spec; do not synthesize |

### 6.3 Reputation & Confidence Derivation for HoneyPot

**Reputation from visitor type + threat score (conservative Phase 1):**

```python
def hp_reputation(visitor_type: int, threat: int, days: int) -> str:
    if visitor_type == 0:
        return "clean"
    if threat >= 75 and days <= 7 and (visitor_type & 0b110):  # harvester/comment_spammer high & fresh
        return "malicious"  # narrow, requires both high threat and freshness
    if visitor_type & 0b111:  # any suspicious/harvester/spammer
        return "suspicious"
    return "unknown"  # unreachable; NXDOMAIN already handled
```

**Confidence from threat score (mirrors AbuseIPDB but scaled 0-255):**

```python
def hp_confidence(threat: int, days: int) -> str:
    if threat == 0:
        return "none"
    if threat < 25:  # 0-24
        return "low"
    if threat < 50:
        return "medium"
    if threat < 75:
        return "high"
    return "very_high"
    # Staleness downgrade: if days > 60, cap at medium regardless (old evidence)
    # Applied as post-step: if days>60 and confidence in (high,very_high): confidence="medium"
```

Rationale: HoneyPot `threat_score 0-255` is not AbuseIPDB `0-100`; direct numeric reuse would inflate. Scale via buckets, not linear.

### 6.4 Critical Distinction: `NO_RESULT` vs `CLEAN` vs `UNAVAILABLE`

- **NO_RESULT (NXDOMAIN)** → `unknown` / `NO_DATA` — explicitly **not** `clean`. UI must say *"No data — not certified clean"* (per HoneyPot docs: *"NXDOMAIN does NOT certify non-malicious"*).
- **DNS failure / timeout** → `unavailable` — **not** `clean`, **not** `unknown`; signals transient provider error, not IP state.
- **Search Engine (`V=0`)** → `clean` — only case where positive DNS answer maps to `clean`; still distinct from `unknown` and `unavailable`.

---

## 7. Cache Design

### 7.1 Options Evaluating `ip_reputation_cache`

Existing table: `ip_reputation_cache (ip TEXT, provider TEXT, reputation TEXT, confidence TEXT, malicious BOOL, suspicious BOOL, reports INT, country, asn, organization, isp, last_reported_at, provider, checked_at, expires_at, updated_at, UNIQUE(ip,provider))`, RLS enabled no policies, service-role writes.

| Option | Schema | Pros | Cons |
|---|---|---|---|
| **A. Extend `ip_reputation_cache` for multiple providers** | `ALTER TABLE ... ADD COLUMN evidence JSONB, threat_score INT, visitor_type INT, days_since INT, last_seen TIMESTAMPTZ` (all nullable); keep existing columns nullable | Smallest migration; reuses existing `(ip,provider)` unique, indexes, RLS, service-role path, TTL logic, logging | Mixed columns (AbuseIPDB columns NULL for HoneyPot and vice versa) — but `evidence JSONB` absorbs provider-specific overflow |
| **B. Create generic `threat_intelligence_cache`** | New table `threat_intelligence_cache` with generic `evidence JSONB`, same keys `(ip,provider)` | Clean slate; no mixed schema | Duplicates logic, requires second service, second RLS, second TTL config; abandons proven `IPReputationCacheService` battle-tested flow |
| **C. Create provider-specific tables (`abuseipdb_cache`, `honeypot_cache`)** | One table per provider | Strong typing | Maximal churn, N services, N migrations, harder aggregation |

### 7.2 Recommendation: **Option A — Extend `ip_reputation_cache`** (Simplest Safe)

**Migration (idempotent):**

```sql
ALTER TABLE ip_reputation_cache
  ADD COLUMN IF NOT EXISTS evidence JSONB,
  ADD COLUMN IF NOT EXISTS threat_score INT,
  ADD COLUMN IF NOT EXISTS visitor_type INT,
  ADD COLUMN IF NOT EXISTS days_since_activity INT,
  ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;
-- Existing columns remain: reports etc. nullable for HP.
-- Optional: ensure provider scope
-- CREATE INDEX IF NOT EXISTS idx_ip_reputation_cache_evidence ON ip_reputation_cache USING GIN (evidence);
```

**Service handling:**

- Keep `IPReputationCacheService` as the sole cache service; rename internally to `ThreatIntelligenceCacheService` with alias `IPReputationCacheService = ThreatIntelligenceCacheService` (same pattern as provider).
- `get(ip, provider)` now deserializes `evidence` + provider-specific columns into `ProviderEvidence`; legacy callers (`IPReputationService.check_ip`) still receive `ReputationResult` via adapter.
- `put(evidence: ProviderEvidence)` does:
  - `if evidence.reputation == "unavailable": skip` (same skip as today — do not cache negative infrastructure errors).
  - `if evidence.reputation == "unknown" and evidence.reason == "no_result"`: **Phase 1 proposal: DO cache `unknown`** with `TTL = 24h` (or shorter `6h` for HoneyPot if desired) — AbuseIPDB currently caches `unknown` (because `ReputationResult.reputation="unknown"` is not `unavailable`). HoneyPot's `NXDOMAIN` as `unknown` should also be cached to avoid DNS amplification. Open question §18 asks whether HoneyPot `unknown` deserves shorter TTL.
  - Compute `expires_at = checked_at + TTL_provider` where TTL may be provider-specific: `THREAT_INTELLIGENCE_CACHE_TTL` default `86400`, or `PROJECT_HONEYPOT_CACHE_TTL` if overridden; simplest is **single TTL** for Phase 1 (keep `IP_REPUTATION_CACHE_TTL=86400`) to avoid config sprawl.
  - `upsert(evidence→payload, on_conflict="ip,provider")` where `payload` includes `evidence JSONB` + normalized core + provider-specific nullable columns.

**Invariants preserved (verified against current service):**

- Server-side only, shared, no `user_id`, no secrets — payload allow-list adds `evidence` but still excludes `access_key/api_key`.
- `RLS` enabled no policies; backend `service_role` only.
- `TTL` controlled (`IP_REPUTATION_CACHE_TTL` or new `THREAT_INTELLIGENCE_CACHE_TTL` alias).
- `provider`-specific isolation via `(ip,provider)` unique; multiple providers for same IP coexist.
- Safe against stale data: `expires_at <= now` → miss; expired → refreshed via provider; provider failure (`unavailable`) never overwrites fresh cached row (verified in `test_provider_failure_expired`).

**Alternative if schema purity demanded:** If reviewers reject mixed columns, fallback is `evidence JSONB` alone (no typed `threat_score` columns) — all HoneyPot fields live inside `evidence`. The `reports/country/asn` columns simply stay `NULL` for `provider='projecthoneypot'`. Still Option A, just fewer columns.

---

## 8. Aggregator Behavior

### 8.1 Interface

```python
class ThreatIntelligenceAggregator:  # alias ThreatIntelligenceService
    @staticmethod
    def check_ip(ip: str) -> ThreatIntelligenceBundle: ...
    @staticmethod
    def check_target(target: str) -> ThreatIntelligenceBundle: ...

@dataclass
class ThreatIntelligenceBundle:
    ip: str                         # normalized IP that was checked
    checked_at: str                 # ISO of bundle creation
    providers: list[ProviderEvidence]  # one per enabled provider (order deterministic by provider name)
    summary: dict                   # derived deterministic aggregate for assessment (see 8.2)
    errors: list[dict] = field(default_factory=list)  # per-provider unavailable reasons, non-fatal
```

`ThreatIntelligenceBundle` is what `PortScannerService` receives and persists (see §10).

### 8.2 Step-by-Step Behavioral Specification

1. **Validate IP.** `validate_ip_address(ip)` → normalized `str`. Failure → `ValidationError` (bubbles; scanner not reached).
2. **Reject private/reserved/multicast/etc.** `is_private_ip(normalized)` → `ValidationError` (`"Private or reserved IP addresses cannot be checked"`). Never reaches providers or cache.
3. **Determine enabled providers.** Build ordered list `enabled = []`:
   - If `IP_REPUTATION_ENABLED` and `IP_REPUTATION_PROVIDER=="abuseipdb"` and `IP_REPUTATION_API_KEY` set → add `AbuseIPDBProvider`.
   - If `PROJECT_HONEYPOT_ENABLED` and `PROJECT_HONEYPOT_ACCESS_KEY` set → add `ProjectHoneyPotProvider`.
   - If none enabled → return single `ProviderEvidence(provider="unavailable", reputation="unavailable", reason="all_providers_disabled")` bundle (keeps `ThreatAssessmentService` confidence `medium`).
   - **Deterministic order:** sort by `provider_name` (`abuseipdb` < `projecthoneypot` < future). Do not use set iteration.
   - **Note:** Aggregator never allows user-controlled provider selection; enablement is backend `current_app.config` only.
4. **Query providers independently with cache.**
   - For each `provider` in `enabled`:
     ```python
     cached = CacheService.get(normalized, provider.provider_name)
     if cached is not None:
         evidence = cached
     else:
         evidence = provider.check_ip(normalized)  # bounded, never raises; returns unavailable on failure
         CacheService.put(evidence)  # skips unavailable internally
     bundle.providers.append(evidence)
     ```
   - **Cache is per-provider** — AbuseIPDB hit + HoneyPot miss → one provider call only.
5. **Never allow one provider failure to break the entire scan.**
   - Each `provider.check_ip` is isolated `try/except`; provider-internal failure returns `unavailable` with `reason`; aggregator continues.
   - Bundle always contains one entry per enabled provider (even if `unavailable`), so assessment can show partial completeness.
6. **Return normalized evidence.** All entries are `ProviderEvidence` (never raw DNS/HTTP). Bundle timestamp is `min(evidence.checked_at)`.
7. **Clearly distinguish 5-state reputation** per provider entry via `reputation` field.
8. **Preserve provider-specific evidence.** Each `ProviderEvidence.evidence` retains its wire-mapped fields (see §5.2) for frontend/report fidelity.
9. **Provide deterministic aggregation summary.**
   ```python
   bundle.summary = {
       "overall_reputation": _worst_of(map(lambda e: e.reputation, providers)),  # malicious > suspicious > unknown > clean > unavailable
       "evidence_confidence": _highest_evidence_confidence(...)  # max provider confidence
       "malicious": any(e.malicious for e in providers),
       "suspicious": any(e.suspicious for e in providers),
       "sources_checked": len(enabled),
       "sources_available": count(e.reputation != "unavailable"),
       "last_seen": max(e.last_seen for e in providers if e.last_seen)  # most recent
   }
   ```

**Example bundle for prompt scenario:**

```json
{
  "ip": "1.2.3.4",
  "checked_at": "2026-08-25T10:00:00Z",
  "providers": [
    {
      "provider": "abuseipdb",
      "reputation": "unknown",
      "confidence": "none",
      "malicious": false,
      "suspicious": false,
      "last_seen": null,
      "categories": [],
      "raw_score": 0,
      "evidence": {"reports": 0, "country": null},
      "reason": null,
      "checked_at": "2026-08-25T10:00:00Z"
    },
    {
      "provider": "projecthoneypot",
      "reputation": "suspicious",
      "confidence": "very_high",
      "malicious": false,
      "suspicious": true,
      "last_seen": "2026-08-21T10:00:00Z",
      "categories": ["suspicious","harvester"],
      "raw_score": 92,
      "evidence": {"days_since_activity": 4, "threat_score": 92, "visitor_type": 3, "visitor_type_flags": ["suspicious","harvester"]},
      "reason": null,
      "checked_at": "2026-08-25T10:00:00Z"
    }
  ],
  "summary": {
    "overall_reputation": "suspicious",
    "malicious": false,
    "suspicious": true,
    "sources_checked": 2,
    "sources_available": 2,
    "last_seen": "2026-08-21T10:00:00Z"
  }
}
```

### 8.3 IP vs Target

- `check_ip`: direct validation path above.
- `check_target(target)`: reuse `validate_hostname_or_ip` + `socket.getaddrinfo` + `is_private_ip` exactly as `IPReputationService.check_target()` does today, then delegate to `check_ip(resolved)`.
- Aggregator **never** resolves HoneyPot via HTTP; the DNS lookup for HoneyPot uses the **same** resolved IP reversed, not a second resolution.

---

## 9. ThreatAssessment Integration

### 9.1 Current vs New

- **Current (`threat_assessment_service.py:73-83`):** `assess(port_risk, ip_reputation: Optional[dict], open_ports, ports_scanned)` — single reputation `IP_BASE`.
- **New:** Aggregator bundle replaces single `ip_reputation`. Assessment must consume **multiple** intelligence sources without double-counting overlapping evidence.

### 9.2 Options Evaluated

| Option | Input to `ThreatAssessmentService` | Scoring Implication |
|---|---|---|
| **A. Aggregated reputation signal** (`overall_reputation` string) | `assess(port_risk, aggregate={"reputation": summary.overall_reputation})` + pass bundle for modifiers only | Minimal change to existing scoring: `PORT_BASE + IP_BASE(aggregate)` exactly as today, but evidence from multiple providers already reduced to one worst-case. Risk: loses per-provider nuance (e.g., HoneyPot `days` freshness). |
| **B. Structured intelligence evidence** (`bundle: ThreatIntelligenceBundle`) | New method `assess_with_intelligence(port_risk, open_ports, bundle)` plus legacy `assess(...)` shim | Assessment reads bundle deterministically: derives a **single** `derived_ip_reputation` internally via evidence-combination rules, then feeds existing `PORT_BASE/IP_BASE` + provider-aware modifiers. Prevents double-count (one IP base, not N). |
| **C. Per-provider scoring weights** (`abuse_score + honeypot_score`) | `assess(port_risk, {abuseipdb: ..., honeypot: ...})` each with weight | Introduces double-count pathology: `AbuseIPDB malicious (35) + HoneyPot suspicious (20) = 55` for same IP, inflating score. Requires tunable weights — premature without production calibration. |

### 9.3 Recommendation: **Option B — Structured Evidence, Deterministic Single-Derived Signal**

- Keep `assess(...)` for backward compat (calls `assess_with_intelligence` with a synthetic single-entry bundle when `ip_reputation` provided).
- New `assess_with_intelligence(port_risk: str, open_ports, bundle: ThreatIntelligenceBundle, ports_scanned, status)` computes:

```python
def _derive_ip_signal(bundle: ThreatIntelligenceBundle) -> tuple[str, int, int]:
    # 1. Filter unavailable
    usable = [e for e in bundle.providers if e.reputation != "unavailable"]
    if not usable:
        return ("unavailable", 0, 0)
    # 2. Worst-case reputation across usable providers (deterministic ranking)
    rank = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}
    # HoneyPot search_engine clean (V=0) is legitimate clean
    worst = max(usable, key=lambda e: rank.get(e.reputation, -1))
    derived = worst.reputation  # malicious | suspicious | clean | unknown
    # 3. Evidence strength for modifiers: strongest corroborating provider, not sum
    # e.g., for high_report_volume use max reports/threat alignment; for confidence cap
    # Prevent double-count: ip_base is derived ONCE
    ip_base = IP_BASE[derived]
    return (derived, ip_base, rank[derived])
```

**Evidence-combination strategy (deterministic, prevents double-count):**

- **One `ip_base` only** — derived from `worst_of(providers)` (`malicious > suspicious > clean > unknown`, `unavailable` excluded). Example: `AbuseIPDB malicious (35)` + `HoneyPot suspicious (20)` → `derived = malicious → ip_base 35`, **not** `35+20`.
- **No additive stacking of provider malicious bonuses.** This is the anti-double-count rule.
- **Modifiers are provider-aware but deduplicated:**
  - `high_report_volume` today checks `reports>=10`. For HoneyPot we introduce **analogous but distinct** modifier: `high_honeypot_threat` when HoneyPot `threat_score >= 70` and `days_since <= 30` and `derived ∈ {suspicious, malicious}` → `+5` **instead of** stacking with `high_report_volume` → they are **mutually exclusive per provider** but Phase 1 recommends **one shared `strong_corroboration` modifier**: `+5` if any provider shows strong corroboration (`reports>=10` OR `threat_score>=70` fresh). Count at most once.
  - `suspicious_high_combo` / `malicious_critical_combo` now check `derived_reputation` (already worst-case), not per-provider.
  - New modifier candidate (optional, not yet weighted): `honeypot_fresh_threat` indicating `days <= 7` — proposal is to **not** add a new weight in Phase 1, just carry in `evidence` and `explanation`, to keep scoring approval separate (see §10).
- **Deterministic ordering:** Factors sorted `type` then `description` so same bundle → same `explanation` byte-for-byte, required by `test_deterministic_explanation`.

**API to assessment:**

```python
# In PortScannerService.scan_ports:
bundle = ThreatIntelligenceAggregator.check_ip(resolved_ip)
threat_assessment = ThreatAssessmentService.assess_with_intelligence(
    port_risk=risk_level,
    open_ports=open_ports,
    bundle=bundle,
    ports_scanned=len(port_list),
    status="completed",
)
```

### 9.4 Existing Scoring Rules That Would Need Change

Current rules (§15 of `PORT_THREAT_ASSESSMENT_PHASE1.md`) — affected entries:

1. **`high_report_volume` (+5 if `reports>=10` and malicious/suspicious)** — must generalize to `strong_corroboration` (HoneyPot `threat_score>=70` fresh) OR keep two separate but deduplicate (at most one). Minimal change: expand condition to `reports>=10 OR (honeypot_threat>=70 and days<=30)`, still `+5` once.
2. **No new `ip_base` weights for HoneyPot categories** — reuse same `IP_BASE` via derived reputation; do NOT introduce `HARVESTER 15` etc. separately.
3. **Modifier `database_exposure` etc. unchanged** — orthogonal.
4. **Confidence mapping** (`high` when usable, `medium` when unavailable) — extend to bundle: `high` if any usable reputation (`clean|suspicious|malicious|unknown`), `medium` if **all** providers `unavailable`, `low` if scan incomplete. `unknown` from HoneyPot remains usable (not degraded) consistent with current `unknown high`.

If honeypot-specific modifiers are deferred, Phase 1 scoring change is **one line** in `high_report_volume` condition. New scoring weights require separate approval (see §10).

---

## 10. Scoring — Current vs Proposed

### 10.1 Current Scoring (Phase 2D-3, `threat_assessment_service.py:39-58`)

| Base | Weight | Modifier | Weight |
|---|---|---|---|
| `low` | 10 | `critical_service_detail` | +5 |
| `medium` | 25 | `database_exposure` | +5 |
| `high` | 45 | `multiple_high_risk` | +5 |
| `critical` | 60 | `high_report_volume` (>=10) | +5 |
| `clean/unknown/unavailable` | 0 | `malicious_critical_combo` | +5 |
| `suspicious` | 20 | `suspicious_high_combo` | +5 (exclusive) |
| `malicious` | 35 | — | — |
| | | **cap** | **0-100** |

### 10.2 New Evidence Types Available After 2D-4

- `categories`: `suspicious` vs `harvester` vs `comment_spammer` vs `search_engine` vs combinations; freshness `days_since_activity`; intensity `threat_score 0-255`.
- These **do not** automatically map to `high_report_volume` — they are distinct signal shapes. Proposal is to surface them in `evidence` and `explanation` without immediate weight.

### 10.3 Double-Counting Problems

| Problem | Example | Why double-count |
|---|---|---|
| Two malicious labels for same IP | AbuseIPDB `malicious` + HoneyPot `suspicious (harvester, T70)` each adding `35` and `20` | Same IP, overlapping evidence; should not be additive |
| `reports` + `threat_score` both triggering bonuses | `reports=15` and `threat=92` each `+5` | Distinct metrics for same underlying host behavior |

**Mitigation (approved strategy from §9.3):** Derive **one** `ip_base` from worst reputation; corroboration modifiers at most **one** `+5` regardless of how many providers corroborate.

### 10.4 Proposed Scoring Model — No Final Weights Yet (Requires Approval)

**Phase 1 (no new weights):**

- Keep all base + modifier weights identical to 2D-3.
- Expand `high_report_volume` condition to unified `strong_corroboration`:
  ```python
  strong = (reports >= 10) or (hp_threat >= 70 and hp_days <= 30)
  if strong and derived in ("suspicious","malicious"):
      score += 5
  ```
- Carry HoneyPot categories into `explanation` only (e.g., `"HoneyPot SUSPICIOUS (harvester, threat 92, seen 4d ago)"`), not score.

**Phase 2 (candidate, not approved):**

| Candidate Modifier | Trigger | Weight | Interaction |
|---|---|---|---|
| `honeypot_fresh_high_threat` | `visitor_type ∈ {harvester,comment_spammer}` and `threat >= 70` and `days <= 7` | +5 | Mutually exclusive with `strong_corroboration` (choose max) |
| `stale_evidence_penalty` | HoneyPot `days > 60` with no other corroboration | -5 (discount) | Controversial — may be deferred |

**Gate:** Phase 2 weights must be calibrated on HoneyPot dataset (precision/recall vs AbuseIPDB ground truth) before merge. Phase 1 recommendation: **change nothing except `strong_corroboration` expansion**, to keep threat deltas auditable.

### 10.5 Thresholds Unchanged

`LEVEL_THRESHOLDS` (`0-19 low`, `20-39 medium`, `40-69 high`, `70-100 critical`) remain — derived `ip_base` fits same range. HoneyPot `suspicious` with `critical` ports → `60+20=80` critical (same as AbuseIPDB suspicious+critical).

---

## 11. API

### 11.1 `POST /api/scanner/ports`

**Current (`port_routes.py:23-72`):** returns `risk_level`, `ip_reputation`, `threat_assessment`.

**Recommended evolution — Additive `threat_intelligence` bundle, backward-compatible `ip_reputation`:**

```json
{
  "success": true,
  "message": "Port scan completed",
  "data": {
    "target": "example.com",
    "resolved_ip": "1.2.3.4",
    "scan_duration_ms": 123,
    "ports_scanned": 20,
    "open_ports": [...],
    "closed_ports": 12,
    "filtered_ports": 3,
    "summary": "...",
    "risk_level": "low",
    "ip_reputation": {
      // LEGACY — preserved verbatim for old clients (AbuseIPDB only)
      "ip": "1.2.3.4",
      "reputation": "unknown",
      "confidence": "none",
      "malicious": false,
      "suspicious": false,
      "reports": 0,
      "provider": "abuseipdb",
      "checked_at": "..."
    },
    "threat_intelligence": {
      // NEW — provider-independent bundle
      "ip": "1.2.3.4",
      "checked_at": "...",
      "providers": [
        {"provider": "abuseipdb",      "reputation": "unknown",    "confidence": "none",      "malicious": false, "suspicious": false, "categories": [], "raw_score": 0,  "evidence": {"reports":0}, "last_seen": null},
        {"provider": "projecthoneypot","reputation": "suspicious", "confidence": "very_high","malicious": false, "suspicious": true,  "categories": ["suspicious","harvester"], "raw_score": 92, "evidence": {"days_since_activity":4,"threat_score":92,"visitor_type":3}, "last_seen":"2026-08-21T..."}
      ],
      "summary": {"overall_reputation":"suspicious","evidence_confidence":"very_high","sources_checked":2,"sources_available":2}
    },
    "threat_assessment": {
      "score": 30,
      "level": "medium",
      "confidence": "high",
      "factors": [...],
      "explanation": "Port risk LOW (10) + IP SUSPICIOUS (20) — Project Honey Pot suspicious/harvester (threat 92, 4d ago) + AbuseIPDB unknown.",
      "assessed_at": "..."
    }
  }
}
```

- Old clients ignore `threat_intelligence`; `ip_reputation` remains AbuseIPDB-only so their display does not break.
- New clients show `threat_intelligence.providers` table plus derived `summary`.
- Persistence: `port_scans` stores both `ip_reputation` (legacy JSONB) plus new `threat_intelligence JSONB` (bundle snapshot). Assessment reads bundle snapshot for reproducibility.

**Route implementation:** `port_routes.py:49-72` changes 3 lines: after `PortScannerService.scan_ports`, `result_dict["threat_intelligence"] = result.threat_intelligence` (new attribute on `ScanResult`).

### 11.2 `GET /api/scanner/ip-reputation/<ip>` and `POST /api/scanner/ip-reputation`

**Kept unchanged** for backward compat — they return `ReputationResult` (AbuseIPDB only). Adding HoneyPot to those single-IP endpoints would change their contract; they remain single-provider.

**New endpoint (optional, not required for scan flow):**

- `GET /api/scanner/threat-intelligence/<ip>` — returns `ThreatIntelligenceBundle` for any public IP (requires auth, same validation, no `user_id` from client).

Alternative without new endpoint: `POST /ip-reputation` accepts `{"target":"example.com", "providers":["abuseipdb","projecthoneypot"]}` — but **rejected** because it leaks provider selection to the client (see §14). If a unified endpoint is desired, it should be `GET /threat-intelligence/<ip>` with server-side enablement only, not user-supplied `providers` array.

**Recommendation:** **Do not add new endpoints in Phase 1** unless product requests direct HoneyPot query UI. The port scan bundle already exposes multi-provider evidence. Direct lookup can be Phase 2 (`GET /threat-intelligence/<ip>` with no provider param).

### 11.3 History/Detail

- `GET /ports/history` `select` adds `threat_intelligence` column alongside `threat_assessment`; list items show `summary` or provider table if requested.
- `GET /ports/history/<id>` `select *` already returns new column; `open_port_count` etc. unchanged.

---

## 12. Frontend

### 12.1 Current Three-Signal UI (`PortScannerPage.tsx:31-220`)

1. **Port Risk** card (`risk_level` + badge)
2. **IP Reputation** card (`IPReputationCard`: `reputation` badge, `ConfidenceBadge`, `reports/country/asn/org/lastReported/provider/checked`)
3. **Overall Threat** card (`ThreatAssessmentCard`: score/level, `ThreatConfidenceBadge` with "Evidence completeness", factors table, explanation)

History/detail mirrors with fallbacks `"Not available"` for pre-feature rows.

### 12.2 Proposed Multi-Provider Appearance

**Add fourth signal but preserve separation — four cards, not collapsed:**

```
1. PORT RISK       — as today
2. IP REPUTATION   — AbuseIPDB  (legacy card kept)
3. THREAT INTELLIGENCE   — NEW, provider table (see below)
4. OVERALL THREAT  — as today, eyebrow "Derived from Port Risk + Threat Intelligence"
```

**Threat Intelligence card spec (`ThreatIntelligenceCard`):**

- **Eyebrow:** `THREAT INTELLIGENCE` + sub-label `Provider-independent evidence`
- **Summary row:** Two `Badge`s: `Overall: SUSPICIOUS` (derived worst-case), `Evidence Confidence: VERY_HIGH` + `Badge` `Sources: 2 checked / 2 available`
- **Provider rows (deterministic order by provider):**
  - Row `AbuseIPDB`: `UNKNOWN` (primary), `none` confidence, `0 reports` — note *"No reputation data reported"*
  - Row `Project Honey Pot — http:BL`: `SUSPICIOUS` (warning), `very_high`, `Threat 92`, `Last seen 4 days ago (2026-08-21)`, `Categories: Suspicious, Harvester` — tags as `Badge`s (`Harvester` amber)
  - For `UNAVAILABLE`: badge `UNAVAILABLE` + note `Reason: timeout` (muted, not counted); for `UNKNOWN`: "No data — not certified clean (per HoneyPot docs)"
- **Do-nots:**
  - Never show `UNKNOWN = SAFE` (use phrasing "No data" not "Safe").
  - Never let `Evidence Confidence` read as confidence the IP is harmless — label column `Evidence Confidence` (per spec) not `Confidence`, with tooltip "Strength of available evidence".

**Existing `IPReputationCard` vs new card:** Keep AbuseIPDB card for continuity (legacy `ip_reputation`); threat intelligence card is the multi-provider view. Once product migrates, legacy card can become a collapsed subsection inside threat intelligence.

### 12.3 Types (`types/index.ts:340-444`)

**Additions (no breaking change):**

```typescript
export type ProviderName = 'abuseipdb' | 'projecthoneypot' | 'unavailable';

export interface ProviderEvidence {
  readonly ip: string;
  readonly provider: ProviderName;
  readonly reputation: IPReputationState;
  readonly malicious: boolean;
  readonly suspicious: boolean;
  readonly confidence: string | null; // none|low|medium|high|very_high
  readonly categories: readonly string[]; // honeypot: harvester etc.
  readonly raw_score: number | null; // 92 for HP, 0-100 for AbuseIPDB
  readonly evidence: Record<string, unknown> | null;
  readonly last_seen: string | null;
  readonly checked_at: string;
  readonly reason?: string | null;
}

export interface ThreatIntelligenceBundle {
  readonly ip: string;
  readonly checked_at: string;
  readonly providers: readonly ProviderEvidence[];
  readonly summary: {
    readonly overall_reputation: IPReputationState;
    readonly evidence_confidence: string;
    readonly sources_checked: number;
    readonly sources_available: number;
    readonly last_seen: string | null;
    readonly malicious: boolean;
    readonly suspicious: boolean;
  };
}

export interface PortScanResult {
  // ... existing
  readonly ip_reputation?: IPReputationResult | null; // kept
  readonly threat_intelligence?: ThreatIntelligenceBundle | null; // new
  readonly threat_assessment?: ThreatAssessment | null;
}
```

`ReportPortScanData` and `PortScanHistoryItem`/`PortScanDetail` extend with `threat_intelligence?`.

### 12.4 Services

`frontend/src/services/portScannerService.ts` — no logic change; types only. `apiClient` unchanged.

---

## 13. PDF / Report

### 13.1 Current (`pdf_generator.py:446-533`)

- Section `6. Port Scanner and IP Reputation` with subheads `Port Scan — Target & Results` (KV + `port_table`), `IP Reputation — AbuseIPDB (independent from port risk)` (KV of `ip,reputation,confidence,malicious,suspicious,reports,country,asn,organization,isp,lastReported,provider,checked_at`), `Overall Threat Assessment — Derived from Port Risk + IP Reputation` (KV `score/level/confidence/explanation`, `_threat_factors_table`), note "Port risk and IP reputation remain independent; overall amplifies both."

### 13.2 Proposed Mutation — Backward Compatible

**New heading:** `6. Port Scanner and Threat Intelligence`

**Subsections:**

```
6.1 Port Scan — Target & Results          (unchanged)
6.2 AbuseIPDB                             (renamed from "IP Reputation — AbuseIPDB"; same KV)
6.3 Project Honey Pot / http:BL           (NEW)
     KV:
       IP Address
       Reputation (unknown/clean/suspicious/malicious/unavailable)
       Evidence Confidence
       Categories (badges as text: Suspicious, Harvester, etc.)
       Threat Score (0-255 raw) — labeled "HoneyPot threat score"
       Days Since Last Activity
       Visitor Type (raw 0-7) + Flags
       Last Seen (derived from days)
       Provider
       Checked At
     NOTES:
       "NXDOMAIN: no http:BL data — does NOT certify clean per HoneyPot docs."
       "Unavailable (timeout/dns_error) — not counted, not clean."

6.4 Overall Threat Assessment             (unchanged structure, eyebrow updated)
     KV now: "Derived from Port Risk + Threat Intelligence"
     Explanation must mention contributing providers:
       "Port risk LOW (10) + Project Honey Pot suspicious/harvester (threat 92, 4d ago) + AbuseIPDB unknown → 30 MEDIUM."
```

- **Null safety:** `6.3` when `threat_intelligence` absent (old scan) → note same as 6.2 fallback but with provider distinction: *"Not available — this scan was created before Project Honey Pot was enabled or the provider returned no data (`NXDOMAIN`)."* This makes old reports render without error.
- **Ordering:** Deterministic `providers` sorted by name ensures PDF ordering stable.
- **Sanitization:** Reuse `_esc` for all strings; `reports` etc. already ints.
- **Finding inclusion:** `_findings_section` remains unchanged; port/honeypot findings can be added as optional Phase 2.

**`report_service.py:234-314` (_map_port_scan):**

- Allow-list expands to include `threat_intelligence` bundle:
  ```python
  normalized_ti = {k: v for k, v in (row.get("threat_intelligence") or {}).items()
                   if k in {"ip","checked_at","providers","summary"}}
  # Per-provider allow-list: {provider, reputation, confidence, malicious, suspicious, categories, raw_score, evidence, last_seen, checked_at, reason}
  ```
- Providers evidence allow-lists exclude any key containing `key/token/auth`.

---

## 14. Security Controls

### 14.1 Attack Surface Matrix

| Threat | Control |
|---|---|
| **SSRF (scanner abused to probe internal networks)** | Unchanged: `validate_hostname_or_ip` + `is_private_hostname` before scan; `is_private_ip` before any cache/provider/DNS. Aggregator re-validates even if scanner already did. |
| **Private IP blocking (reputation/intel leakage)** | `validate_ip_address` + `is_private_ip` → `ValidationError` in `check_ip` and `check_target` before DNS. HoneyPot provider never queried for private IPs. |
| **DNS query safety (Project Honey Pot)** | DNS query is **server-side only**, never user-supplied. Hostname is `<access_key>.<reversed_ip>.dnsbl.httpbl.org` where `access_key` is `PROJECT_HONEYPOT_ACCESS_KEY` from env (never client-supplied) and `reversed_ip` is server-validated IPv4. Use `dns.resolver` (or `socket.gethostbyname` fallback) with bounded `PROJECT_HONEYPOT_TIMEOUT` (default `3s`). Do not use HTTP fetch/shell. |
| **Arbitrary DNS server control** | **Forbidden.** No `PROJECT_HONEYPOT_DNS_SERVER` env; resolver uses system default. User never supplies `provider URL`, `DNS server`, or `access key`. Reject any PR that adds such param. |
| **User-controlled provider selection** | Forbidden. Enablement is `THREAT_INTELLIGENCE_ENABLED`/`PROJECT_HONEYPOT_ENABLED` booleans from server `current_app.config` only. No `?providers=` query param, no body-supplied provider list. Aggregator's `enabled = [...]` is not client-tunable. |
| **API/access key protection** | `PROJECT_HONEYPOT_ACCESS_KEY` and `IP_REPUTATION_API_KEY` live only in `backend/.env` + server `current_app.config`; never serialized into `ProviderEvidence`, `payload`, cache row, `Report PDF`, or API response. Cache `payload` allow-list excludes any `*key*`. Logging via `_log_safe` redacts `key/token/auth`. |
| **DNS response validation** | Strict: response must be 4-octet IPv4, first octet `127`; second/third/fourth are `0-255` ints parsed as `days/threat/visitor_type`; `visitor_type >7` or non-int → `malformed_response` (`unavailable`). Non-`127` first octet → `malformed_response`. Extra A records ignored; first valid only. |
| **Malformed DNS responses** | Mapped to `unavailable reason="malformed_response"`, not `clean` or `unknown`; not cached. |
| **Provider timeouts / failures** | Per-provider isolated `try/except` (Timeout/DNS error/network/5xx/429 → `unavailable` with reason, `reason` surfaced per provider, not as stack). Aggregator continues with remaining providers; port scan never fails because of reputation/honeypot. |
| **Rate limiting** | HoneyPot: no known rate limit on DNS, but scan-side global `PORT_SCANNER_MAX_PORTS` + `IP_REPUTATION_CACHE_TTL` already deduplicate DNS queries via cache. AbuseIPDB 429 → `rate_limited` reason. Future: lightweight per-IP token bucket in aggregator (not required Phase 1) if DNS volume observed. |
| **Cache poisoning** | Mitigated by: (a) `service_role` writes only, (b) no user-controlled `cache contents`, (c) `put` skips `unavailable`, (d) `(ip,provider)` unique, (e) TTL short (86400) with no `Cache-Control` passthrough, (f) scores from provider treated as `raw_score` not re-weighted from cache value. Attacker cannot plant fake rows via API. |
| **Cross-user isolation / RLS** | `port_scans` rows: `user_id=auth.uid()` RLS, `threat_intelligence` bundle stored inside that row inherits policy. Cache: `ENABLE RLS` no policies → user-role denied; backend `service_role` only. No `user_id` in cache. |
| **Service-role usage** | `_get_cache_client()` strictly prefers `get_supabase_admin_client()` → `current_app.config["SUPABASE_SECRET_KEY"]`; fallback only logs `cache_fallback_anon` and will be blocked by RLS, turning into miss. Never expose `SUPABASE_SECRET_KEY` to frontend. |
| **Logging secrets** | `_log_safe` filter drops `*key*/*token*/*auth*` keys; HoneyPot DNS query logging must emit `redacted_access_key.<reversed_ip>.dnsbl.httpbl.org` or just `ip`/`provider` tags, never full key. PDF `_esc` escapes but also never includes raw `evidence` with key. |

### 14.2 Never-Exposed Guarantees

User (authenticated) can never supply or read:

- `provider URL`, `DNS server`, `access key`, `API key`, `JWT`, `service_role key`, `cache row` (except via aggregated bundle response), `scoring weights`.

Enforced by allow-list serialization in `report_service._map_port_scan` and PDF `evidence` mapping, plus route validation not accepting provider fields.

---

## 15. Configuration — Minimal Required

**Add only what is load-bearing for HoneyPot; do not add `THREAT_INTELLIGENCE_ENABLED` unless aggregator enablement needs a global kill-switch (it does — see below).**

| Env | Type | Default | Required? | Notes |
|---|---|---|---|---|
| `THREAT_INTELLIGENCE_ENABLED` | bool | `false` | **Yes** (global kill switch) | Master gate for aggregator. If `false`, scan returns legacy `ip_reputation` only (or `unavailable`); no provider queries. Allows emergency disable without touching provider keys. |
| `PROJECT_HONEYPOT_ENABLED` | bool | `false` | **Yes** | Per-provider gate. Even with master `true`, honeypot only runs if `true` and `access_key` set. |
| `PROJECT_HONEYPOT_ACCESS_KEY` | string | `""` | **Yes** if enabled | Backend-only secret. Missing → `unavailable reason=missing_access_key`, never queried. |
| `PROJECT_HONEYPOT_TIMEOUT` | int (s) | `3` | No — defaults `3s` | DNS query timeout. Keep small to not block scan. |
| `PROJECT_HONEYPOT_CACHE_TTL` | int (s) | `(IP_REPUTATION_CACHE_TTL)` | No — reuse `IP_REPUTATION_CACHE_TTL=86400` by default | Provider-specific TTL optional; Phase 1 recommend **reusing single TTL** to reduce config sprawl; add only if calibrating honeypot staleness differs. |
| `IP_REPUTATION_ENABLED` / `IP_REPUTATION_API_KEY` / `IP_REPUTATION_TIMEOUT` | — | — | Already exist | Left unchanged for AbuseIPDB. |

**Do NOT add:**

- `PROJECT_HONEYPOT_DNS_SERVER`, `PROJECT_HONEYPOT_URL`, `THREAT_SCORING_WEIGHTS`, `CACHE_TABLE_NAME`, per-request provider selection.

All secrets stay backend-only (`current_app.config`, `get_config()`); frontend `Config` never exposes them.

---

## 16. Testing Strategy

### 16.1 Project Honey Pot Provider Unit Tests (pure, no network — mock `socket.gethostbyname` / `dns.resolver`)

| Case | Wire Input | Expected Normalized |
|---|---|---|
| `NXDOMAIN / no result` | `socket.gaierror` or `NXDOMAIN` | `reputation="unknown"`, `reason="no_result"`, not `clean` |
| `suspicious V=1` | `127.10.20.1` | `suspicious`, `categories=["suspicious"]`, `raw_score=20`, `days=10` |
| `harvester V=2` | `127.5.60.2` | `suspicious`, `["harvester"]` |
| `comment_spammer V=4` | `127.2.70.4` | `suspicious`, `["comment_spammer"]` |
| `combined 3/5/6/7` | `127.4.92.3` etc. | union categories (see §6.2) |
| `search_engine V=0` | `127.30.0.0` | `clean`, `["search_engine"]` |
| `high threat 92` | `127.4.92.5` | same but `confidence=very_high` |
| `low threat 5` | `127.30.5.1` | `confidence=low` |
| `stale D>60` | `127.61.90.1` | `confidence` capped `medium` (if applied) |
| `DNS timeout` | `socket.timeout` | `unavailable reason="timeout"`, not cached |
| `DNS error SERVFAIL` | `dns.resolver.NoAnswer` | `unavailable dns_error`, not cached |
| `malformed 127.abc.92.1` | non-int octets | `unavailable malformed_response` |
| `malformed first≠127` | `192.4.92.1` | `unavailable malformed_response` |
| `missing access key` | `PROJECT_HONEYPOT_ACCESS_KEY=""` | `unavailable missing_access_key`, no DNS call |
| `private IP blocked` | `10.0.0.1`, `127.0.0.1` | `ValidationError` before provider |
| `IPv6 rejected` | `::1`, `2001:db8::1` | `unavailable unsupported_ip_version` |
| `API key never exposed` | any | assert `access_key` not in `evidence`, not in cache row, not in logs |

Mock shape:

```python
with patch("app.services.project_honeypot_provider.socket.gethostbyname", return_value="127.4.92.3"):
    ev = ProjectHoneyPotProvider(check_ip("1.2.3.4"))
```

### 16.2 Aggregator Tests

| Case | Providers | Bundle |
|---|---|---|
| `AbuseIPDB only` | `IP_REP=true, HP=false` | `providers=[abuseipdb]`, `summary` derived |
| `HoneyPot only` | `IP_REP=false, HP=true` | `providers=[honeypot]` |
| `Both available` | both `true` | `providers=[abuseipdb, honeypot]` ordered, `summary.overall=worst` |
| `One unavailable` | honeypot timeout | `honeypot reputation=unavailable`, abuse `unknown` still present, no scan failure |
| `Both unavailable` | timeout + 429 | both `unavailable`, `summary.sources_available=0`, assessment confidence `medium` |
| `Conflicting results` | `abuse unknown` + `hp suspicious` | `overall=suspicious`, not additive |
| `Duplicate evidence` | `abuse malicious + hp suspicious` | `derived=malicious`, `ip_base=35` once |
| `Deterministic output` | same IPs twice | byte-identical `providers` order, `checked_at` stable per run |

### 16.3 Cache Tests

Reuse patterns from `test_ip_reputation_cache.py` (provider isolation, TTL, hit/miss/expired/failed, no secret storage) extending with:

- Same IP different providers → 2 rows, `provider` isolation preserved.
- `(ip,provider)` uniqueness for `projecthoneypot` — `upsert` not duplicate.
- TTL per provider: if `PROJECT_HONEYPOT_CACHE_TTL` added, test `expires_at = checked_at + ttl`.
- `unavailable` not cached; `unknown/no_result` cached (or not — see open question).
- No `access_key/api_key` in cache rows.

### 16.4 Regression

- `python -m pytest backend/tests/test_port_scanner.py` — risk levels, `_persist_scan`, `_resolve_target`.
- `test_ip_reputation_cache.py` (21 tests) — unchanged behavior for `abuseipdb` unknown/clean/malicious/429/disabled.
- `test_threat_assessment.py` (20+ tests) — base `10/25/45/60`, modifiers, `high_report_volume`, `confidence`.
- `test_reports.py` (38 tests) — report generation includes `port_scan.threat_assessment` heading `6. Port Scanner...` now expects `6.4`.
- `conftest.fake_supabase` add seeded `threat_intelligence` column handling (like `threat_assessment`).
- Frontend `npm run build` type-check: `PortScannerPage` with new card compiles (`tsc --noEmit`).

---

## 17. Migration Strategy

### 17.1 Database

```sql
-- Cache extension (idempotent)
ALTER TABLE ip_reputation_cache
  ADD COLUMN IF NOT EXISTS evidence JSONB,
  ADD COLUMN IF NOT EXISTS threat_score INT CHECK (threat_score >=0 AND threat_score <=255),
  ADD COLUMN IF NOT EXISTS visitor_type INT CHECK (visitor_type >=0 AND visitor_type <=7),
  ADD COLUMN IF NOT EXISTS days_since_activity INT CHECK (days_since_activity >=0),
  ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;

-- Port scan bundle snapshot (nullable — old scans remain readable)
ALTER TABLE port_scans
  ADD COLUMN IF NOT EXISTS threat_intelligence JSONB;

-- Update schema.sql CREATE TABLE definitions accordingly
-- and add DO $$ ADD COLUMN IF NOT EXISTS threat_intelligence $$ backfill block
-- mirroring existing ip_reputation/threat_assessment pattern.
```

- Historical rows with `threat_intelligence IS NULL` remain valid; `_map_port_scan` treats `None` as "not available".
- No backfill of honeypot evidence for old scans — snapshot only at new scan time.
- Cache extension is additive: existing rows keep `evidence=null` until refreshed.

### 17.2 Application

1. Deploy code with feature flags OFF (`THREAT_INTELLIGENCE_ENABLED=false`, `PROJECT_HONEYPOT_ENABLED=false`) — zero behavior change.
2. Set `PROJECT_HONEYPOT_ACCESS_KEY` (secret manager) and verify via `GET /threat-intelligence/<test-ip>` if added, otherwise via scan of known HoneyPot IP (`1.1.1.1` safe; use test fixture).
3. Enable `THREAT_INTELLIGENCE_ENABLED=true` + `PROJECT_HONEYPOT_ENABLED=true` in staging, run regression suite + manual scan of known IP (`2.1.9.127` example from spec — HoneyPot docs example IP; do not use production unknown).
4. Production enable behind same flags; monitor DNS latency via logs (`threat_intel.cache_hit/miss`, provider `reason`).

---

## 18. Backward Compatibility

| Layer | Old Behavior | New Behavior | Breaking? |
|---|---|---|---|
| `POST /scanner/ports` shape | `risk_level`, `ip_reputation`, `threat_assessment` | Same plus new optional `threat_intelligence` | **No** — old clients ignore unknown field; `ip_reputation` unchanged shape |
| `ip_reputation` value | AbuseIPDB only | Still AbuseIPDB only (legacy) | No |
| `port_scans` rows | `ip_reputation JSONB`, `threat_assessment JSONB` | Adds `threat_intelligence JSONB nullable` | No — `NULL` reads as not-available |
| `ip_reputation_cache` | Holds `abuseipdb` rows | Holds `abuseipdb` + `projecthoneypot` rows keyed `(ip,provider)` | No — same unique, existing rows valid |
| Reports `report_data.port_scan` | Contains `ip_reputation`/`threat_assessment` | Same plus `threat_intelligence` optional | No — old reports without field still render |
| Frontend types | `PortScanResult.ip_reputation?` | Adds optional `threat_intelligence?` | No — `?` optional |
| Auth/RLS | `user_id=auth.uid()` on `port_scans` | Same; cache still `service_role` | No |

---

## 19. Open Questions (Require Decision Before Implementation)

1. **HoneyPot `unknown/no_result` caching TTL** — Current proposal caches `unknown` (NXDOMAIN) for `86400` like AbuseIPDB. Alternative: shorter `21600` (6h) for HoneyPot because `days_since` freshness decays faster. Decision impacts DNS volume vs staleness. **Proposed default: reuse `86400`; add `PROJECT_HONEYPOT_CACHE_TTL` only if tuning needed.**
2. **HoneyPot search engine (`V=0`) semantics** — Mapped to `clean` in §6.2. Confirm that `clean` from search engine should contribute `0` to score and not trigger `suspicious` modifiers. Alternative: separate `search_engine` reputation that is not `clean` (avoid confusing real search engine traffic with normal hosts).
3. **Harvester as `suspicious` vs `malicious`** — Current mapping: `harvester` alone → `suspicious`. Some consumers treat harvester as `malicious`. Confirm threshold `threat>=75 + days<=7` for `malicious` is acceptable; otherwise scope creep to `+5` weight.
4. **New scoring weights / `honeypot_fresh_high_threat` modifier** — §10 proposes deferring new weights. Confirm Phase 1 ships with **no weight change** except unified `strong_corroboration`. If product expects `10/100` fixed for `Abuse UNKNOWN + HoneyPot T92/4d` scenario, that score (`LOW+suspicious=30 medium`) may still disappoint; decide whether Phase 1 should demonstrate the failure is fixed without raising `critical` immediately.
5. **`GET /threat-intelligence/<ip>` existence** — If omitted in Phase 1, direct honeypot lookup has no API. Confirm deferral to Phase 2 is acceptable.
6. **`evidence JSONB` GIN index necessity** — Proposal adds optional GIN index for future filtering; adds migration cost. Omit if not querying evidence server-side.
7. **HoneyPot Terms of Service compliance** — Verify the organization holds a valid `http:BL` `ACCESS_KEY`, agrees to query volume limits, and will not redistribute raw DNS data. Implementation must gate on this.
8. **IPv6 handling preference** — Proposal returns `unavailable unsupported_ip_version` for IPv6. Alternative: skip honeypot for IPv6 and rely solely on AbuseIPDB. Confirm.
9. **`reason` vocabulary canonicalization** — Current spec enumerates `no_result, timeout, dns_error, malformed_response, missing_access_key, unsupported_ip_version`. Confirm shared enum with AbuseIPDB reasons (`rate_limited`, `auth_failed`, `provider_error`) is acceptable for bundle `errors`.

---

## 20. Implementation Phases (Ordered, Separated for Review)

### Phase 2D-4.1 — Provider & Normalization (No DB Change)

- Create `backend/app/services/threat_intelligence/provider.py` (abstract `ThreatIntelligenceProvider`)
- Create `backend/app/services/threat_intelligence/project_honeypot_provider.py` implementing §6 mapping + DNS safety (§14)
- Alias `IPReputationProvider = ThreatIntelligenceProvider`; wrap `AbuseIPDBProvider` to return `ProviderEvidence`
- Unit tests: provider §16.1 (16+ cases) green without DB

### Phase 2D-4.2 — Cache Extension (Idempotent Migration)

- `ALTER ip_reputation_cache ADD COLUMN evidence JSONB ...` (see §17)
- Extend `IPReputationCacheService` → `ThreatIntelligenceCacheService` with provider-name keyed deserialization
- Cache tests §16.3 green; existing `test_ip_reputation_cache` still green

### Phase 2D-4.3 — Aggregator

- `backend/app/services/threat_intelligence/aggregator.py` (`ThreatIntelligenceAggregator`)
- Integrate `validate_ip_address` + `is_private_ip` + enabled list + per-provider cache fan-out + fault isolation
- Aggregator tests §16.2 green

### Phase 2D-4.4 — Assessment Integration & Scan Path

- `ThreatAssessmentService.assess_with_intelligence` + bundle derivation (§9.3) + `strong_corroboration` change
- `PortScannerService.ScanResult` adds `threat_intelligence`; `_persist_scan` includes bundle
- Route `POST /scanner/ports` adds `threat_intelligence` to response envelope
- Schema `port_scans ADD COLUMN threat_intelligence JSONB`
- Threat assessment regression + port scanner persistence tests green

### Phase 2D-4.5 — Reports / PDF / Frontend (Parallel, No Blocking)

- `report_service._map_port_scan` + `pdf_generator._port_section 6.1-6.4`
- `PortScannerPage.tsx` `ThreatIntelligenceCard` + `types/index.ts` bundle interfaces
- PDF snapshot tests updated; `npm run build` type-check green

### Phase 2D-4.6 — Config & Docs

- `settings.py` add `THREAT_INTELLIGENCE_ENABLED`, `PROJECT_HONEYPOT_*`
- `docs/06_Database_Design.md`, `07_API_Design.md`, `08_Backend_Architecture.md`, `09_Frontend_Architecture.md`, `12_Security_Requirements.md`, `15_Testing_Strategy.md` updated only after approval

**Gate between 4.1 and 4.2:** Review §§4-7 design decisions; approve cache column set (mixed nullable vs `evidence JSONB` only).
**Gate between 4.4 and 4.5:** Approve scoring — Phase 1 no-new-weights vs candidate weights.

---

## 21. Summary Checklist

| Area | Proposed Change | Verdict |
|---|---|---|
| Provider abstraction | Generalize `IPReputationProvider` → `ThreatIntelligenceProvider` with alias | Preserves AbuseIPDB, isolates HoneyPot |
| Normalized result | `ProviderEvidence` envelope with 5-state reputation + `categories/raw_score/evidence/last_seen` | No dishonest field copying |
| HoneyPot mapping | `NXDOMAIN→unknown`, `timeout/dns_error/malformed/missing_key→unavailable`, visitor bitset → categories, `search_engine→clean` | Respects HoneyPot `NXDOMAIN ≠ CLEAN` |
| Cache | Extend `ip_reputation_cache` with `evidence JSONB` + nullable typed cols, keep `(ip,provider)` unique/RLS/service_role/TTL | Option A simplest safe |
| Aggregator | `ThreatIntelligenceAggregator.check_ip/target`, deterministic `providers[]` + `summary`, fault-isolated, never user-tunable | Correct isolation |
| Assessment | `assess_with_intelligence(bundle)` deriving **one** `ip_base` from worst reputation, single `strong_corroboration +5` | Prevents double-count |
| Scoring | Phase 1: expand `high_report_volume` to unified corroboration only; new HoneyPot weights deferred | Approved-separately gate |
| API | `POST /scanner/ports` additive `threat_intelligence` bundle; `ip_reputation` legacy kept | Backward compatible |
| Frontend | Keep `IPReputationCard`, add `ThreatIntelligenceCard` (provider table, Evidence Confidence, not-safe UNKNOWN) + new types | Distinct signals |
| PDF | `6. Port Scanner and Threat Intelligence` (6.1-6.4), new 6.3 HoneyPot KV, fallback for old scans | Preserves old reports |
| Security | SSRF/private block, fixed DNS host, no user-controlled provider/DNS/key, response validation, `service_role` cache, no secret leakage | Explicit per §14 |
| Config | 4 env vars (`THREAT_INTELLIGENCE_ENABLED`, `PROJECT_HONEYPOT_ENABLED`, `PROJECT_HONEYPOT_ACCESS_KEY`, `PROJECT_HONEYPOT_TIMEOUT`) | Minimal |
| Tests | 16 provider cases + 8 aggregator + 8 cache + regression | Covers §16 |
| Migration | Two `ADD COLUMN IF NOT EXISTS` statements; no backfill | Safe, reversible via flags |
| Open decisions | 9 questions (TTL, search_engine, harvester threshold, scoring, endpoint, index, ToS, IPv6, reason vocabulary) | Need approval |

---

**Files that would be changed in implementation (not in this design task):**

- `backend/app/services/threat_intelligence/provider.py` **NEW**
- `backend/app/services/threat_intelligence/project_honeypot_provider.py` **NEW**
- `backend/app/services/threat_intelligence/aggregator.py` **NEW**
- `backend/app/services/ip_reputation_service.py` (alias + AbuseIPDB wrap to `ProviderEvidence`)
- `backend/app/services/ip_reputation_cache_service.py` (extend to generic, add `evidence`)
- `backend/app/services/threat_assessment_service.py` (add `assess_with_intelligence`, unify corroboration)
- `backend/app/services/port_scanner_service.py` (attach bundle + persist)
- `backend/app/database/schema.sql` (`ip_reputation_cache` + `port_scans` `ALTER`s + backfill blocks)
- `backend/app/config/settings.py` (4 env vars)
- `backend/app/routes/port_routes.py` (add `threat_intelligence` to response; optional new endpoint)
- `backend/app/services/report_service.py` (`_map_port_scan` `threat_intelligence` allow-list)
- `backend/app/reports/pdf_generator.py` (`_port_section` 6.1-6.4, helper)
- `frontend/src/types/index.ts` (`ProviderEvidence`, `ThreatIntelligenceBundle`)
- `frontend/src/pages/PortScannerPage.tsx` (`ThreatIntelligenceCard`)
- `backend/tests/conftest.py` (`threat_intelligence` column fake)
- `backend/tests/test_project_honeypot.py` + `test_threat_intelligence_aggregator.py` **NEW**

**No file was modified in this task — design only.**

