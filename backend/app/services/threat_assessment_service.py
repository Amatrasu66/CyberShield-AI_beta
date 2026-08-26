"""
Threat Assessment Service — Combined deterministic scoring.

Dedicated service for overall threat assessment derived from
port risk and IP reputation. Keeps port risk and IP reputation
as independent signals; overall is a third derived signal.

Scoring is additive, bounded 0-100, explainable, no fake precision.

Port base: LOW 10, MEDIUM 25, HIGH 45, CRITICAL 60
IP base: CLEAN 0, UNKNOWN 0, UNAVAILABLE 0, SUSPICIOUS 20, MALICIOUS 35
Modifiers (+5 each, deduplicated, capped):
  - critical_service_detail
  - database_exposure
  - multiple_high_risk
  - high_report_volume (reports >=10)
  - malicious_critical_combo
  - suspicious_high_combo (exclusive with previous)

Confidence is evidence completeness, not severity:
  HIGH: complete scan + usable reputation (clean/suspicious/malicious/unknown)
  MEDIUM: complete scan but reputation unavailable/None
  LOW: incomplete scan

No DB, no network, pure logic.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

# Reuse port categories from scanner for consistency
from .port_scanner_service import CRITICAL_RISK_PORTS, HIGH_RISK_PORTS

# Database ports subset for modifier
DB_PORTS = {1433, 1521, 3306, 5432, 6379, 27017, 27018, 27019}

PORT_BASE = {
    "low": 10,
    "medium": 25,
    "high": 45,
    "critical": 60,
}

IP_BASE = {
    "clean": 0,
    "unknown": 0,
    "unavailable": 0,
    "suspicious": 20,
    "malicious": 35,
}

LEVEL_THRESHOLDS = [
    (19, "low"),
    (39, "medium"),
    (69, "high"),
    (100, "critical"),
]


def _level_for_score(score: int) -> str:
    for thresh, level in LEVEL_THRESHOLDS:
        if score <= thresh:
            return level
    return "critical"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatAssessmentService:
    """Dedicated service for overall threat assessment."""

    @staticmethod
    def assess(
        port_risk: str,
        ip_reputation: Optional[dict],
        open_ports: Optional[list],
        ports_scanned: Optional[int] = None,
        status: str = "completed",
    ) -> dict:
        """
        Deterministic overall assessment.

        Args:
            port_risk: low|medium|high|critical (from PortScannerService)
            ip_reputation: ReputationResult dict or None (may be unavailable)
            open_ports: list of port dicts with port/state, may be empty
            ports_scanned: int for completeness check
            status: scan status string

        Returns:
            dict with score, level, confidence, factors, explanation, assessed_at
            No secrets, no JWT, no user_id.
        """
        # Normalize inputs
        port_risk_norm = (port_risk or "low").strip().lower()
        if port_risk_norm not in PORT_BASE:
            port_risk_norm = "low"
        port_base = PORT_BASE[port_risk_norm]

        ip_rep = ip_reputation if isinstance(ip_reputation, dict) else None
        ip_rep_val = (ip_rep.get("reputation") if ip_rep else None)
        if ip_rep_val is not None:
            ip_rep_val = str(ip_rep_val).strip().lower()
        # Treat None/missing as unavailable for scoring but keep distinct for confidence
        ip_rep_for_score = ip_rep_val if ip_rep_val in IP_BASE else "unavailable" if ip_rep_val is None else "unavailable"
        # Actually map: if ip_rep is None -> unavailable (0), if ip_rep_val not in IP_BASE -> unavailable
        if ip_rep is None:
            ip_rep_for_score = "unavailable"
        elif ip_rep_val not in IP_BASE:
            ip_rep_for_score = "unavailable"
        else:
            ip_rep_for_score = ip_rep_val

        ip_base = IP_BASE.get(ip_rep_for_score, 0)

        # Open ports handling
        if open_ports is None:
            open_list = []
        else:
            open_list = list(open_ports)
        # Extract open ports set for modifiers
        open_set = set()
        for p in open_list:
            try:
                if isinstance(p, dict):
                    if str(p.get("state", "")).lower() == "open":
                        port_num = int(p.get("port"))
                        open_set.add(port_num)
                else:
                    # PortResult dataclass
                    if getattr(p, "state", "") == "open":
                        open_set.add(int(getattr(p, "port")))
            except Exception:
                continue

        # Determine completeness for confidence
        # Complete scan: ports_scanned not None and >0 and status completed and open_ports is list
        scan_complete = True
        if ports_scanned is not None:
            try:
                if int(ports_scanned) <= 0:
                    scan_complete = False
            except Exception:
                scan_complete = False
        else:
            # If ports_scanned is None, check open_ports is list (at least present)
            if open_ports is None:
                scan_complete = False
        if status is not None and str(status).strip().lower() != "completed":
            scan_complete = False

        # Confidence based on evidence completeness, not severity
        if not scan_complete:
            confidence = "low"
        else:
            if ip_rep is None or ip_rep_for_score == "unavailable":
                confidence = "medium"
            elif ip_rep_for_score in ("clean", "suspicious", "malicious", "unknown"):
                confidence = "high"
            else:
                confidence = "medium"

        # Build factors and score
        score = port_base + ip_base
        factors = []

        # Base factors (always for explainability, even if weight 0)
        factors.append({
            "type": "port_risk",
            "weight": port_base,
            "description": f"Port risk {port_risk_norm.upper()}",
        })
        # IP base factor
        if ip_rep is None:
            factors.append({"type": "unavailable_reputation", "weight": 0, "description": "IP reputation unavailable — not counted"})
        elif ip_rep_for_score == "unavailable":
            # Use reason if available
            reason = ip_rep.get("reason") or "unavailable"
            factors.append({"type": "unavailable_reputation", "weight": 0, "description": f"IP reputation unavailable ({reason}) — not counted, confidence medium"})
        elif ip_rep_for_score == "unknown":
            factors.append({"type": "unknown_ip", "weight": 0, "description": "IP reputation unknown (no data) — not counted"})
        elif ip_rep_for_score == "clean":
            factors.append({"type": "clean_ip", "weight": 0, "description": "IP reputation clean — not counted"})
        elif ip_rep_for_score == "suspicious":
            factors.append({"type": "suspicious_ip", "weight": ip_base, "description": f"Suspicious IP ({ip_rep.get('reports',0)} reports)"})
        elif ip_rep_for_score == "malicious":
            factors.append({"type": "malicious_ip", "weight": ip_base, "description": f"Malicious IP ({ip_rep.get('reports',0)} reports, confidence {ip_rep.get('confidence','none')})"})

        # Modifiers - deduplicated, each at most once
        # critical_service_detail: requires risk_level critical and any critical port
        if port_risk_norm == "critical" and (open_set & CRITICAL_RISK_PORTS):
            score += 5
            crit_ports = sorted(open_set & CRITICAL_RISK_PORTS)
            factors.append({"type": "critical_service_detail", "weight": 5, "description": f"Critical service(s) {crit_ports} exposed"})
        # database_exposure
        if open_set & DB_PORTS:
            score += 5
            db_ports = sorted(open_set & DB_PORTS)
            factors.append({"type": "database_exposure", "weight": 5, "description": f"Database service(s) {db_ports} exposed"})
        # multiple_high_risk
        high_critical_set = CRITICAL_RISK_PORTS | HIGH_RISK_PORTS
        if len(open_set) >= 3 or len(open_set & high_critical_set) >= 2:
            score += 5
            factors.append({"type": "multiple_high_risk", "weight": 5, "description": f"Multiple high-risk services ({len(open_set)} open, {len(open_set & high_critical_set)} high/critical)"})
        # high_report_volume
        reports = 0
        try:
            reports = int(ip_rep.get("reports", 0)) if ip_rep else 0
        except Exception:
            reports = 0
        if reports >= 10 and ip_rep_for_score in ("suspicious", "malicious"):
            score += 5
            factors.append({"type": "high_report_volume", "weight": 5, "description": f"High report volume ({reports} reports)"})
        # combo modifiers exclusive
        if ip_rep_for_score == "malicious" and port_risk_norm == "critical":
            score += 5
            factors.append({"type": "malicious_critical_combo", "weight": 5, "description": "Malicious IP + critical port risk alignment"})
        elif ip_rep_for_score == "suspicious" and port_risk_norm in ("high", "critical"):
            score += 5
            factors.append({"type": "suspicious_high_combo", "weight": 5, "description": f"Suspicious IP with {port_risk_norm} port risk"})

        # Cap
        score = max(0, min(100, int(score)))
        level = _level_for_score(score)

        # Deterministic explanation: base + modifiers
        # Sort factors by type for deterministic order? Keep insertion order but base first then modifiers sorted
        # For explanation, list contributing weights >0
        contributing = [f for f in factors if f["weight"] > 0]
        # Sort contributing by weight descending then type for determinism
        contributing_sorted = sorted(contributing, key=lambda x: (-x["weight"], x["type"]))
        parts = [f"{c['description']} ({c['weight']})" for c in contributing_sorted]
        if not parts:
            parts_str = "No high-risk signals"
        else:
            parts_str = " + ".join(parts)
        # Handle unavailable note
        unavailable_note = ""
        if ip_rep_for_score == "unavailable" or ip_rep is None:
            unavailable_note = " Reputation unavailable — assessment based on port evidence only."
            # confidence already medium
        elif ip_rep_for_score == "unknown":
            unavailable_note = " No reputation data — score from ports only."

        explanation = f"Port risk {port_risk_norm.upper()} ({port_base})"
        if ip_rep_for_score in ("suspicious", "malicious"):
            explanation += f" + IP {ip_rep_for_score.upper()} ({ip_base})"
        # Add modifiers note if any
        if any(f["type"] in ("critical_service_detail","database_exposure","multiple_high_risk","high_report_volume","malicious_critical_combo","suspicious_high_combo") for f in factors):
            explanation += f" + modifiers → {score} {level.upper()}.{unavailable_note}"
        else:
            explanation += f" → {score} {level.upper()}.{unavailable_note}"
        # Ensure deterministic: explanation includes score and level
        # For no open ports, still base applies: LOW 10
        if not open_set and port_risk_norm == "low":
            # No open ports case is already covered by base, but make explicit
            if len(factors) == 2 and all(f["weight"] in (0,10) for f in factors):
                explanation = f"No open ports; port risk {port_risk_norm.upper()} ({port_base}) → {score} {level.upper()}.{unavailable_note}"

        assessed_at = _now_iso()

        return {
            "score": score,
            "level": level,
            "confidence": confidence,
            "factors": factors,
            "explanation": explanation.strip(),
            "assessed_at": assessed_at,
        }

    @staticmethod
    def assess_with_intelligence(
        port_risk: str,
        bundle: Optional[dict],
        open_ports: Optional[list] = None,
        ports_scanned: Optional[int] = None,
        status: str = "completed",
    ) -> dict:
        """Assess using multi-provider threat intelligence bundle.

        Falls back to single-ip path if bundle is None/empty.
        Deterministic: derives single ip_base from worst_of(providers) to avoid double-count.
        """
        if not isinstance(bundle, dict) or not bundle.get("providers"):
            # No intelligence — treat as unavailable
            return ThreatAssessmentService.assess(port_risk, None, open_ports, ports_scanned, status)

        providers = bundle.get("providers") or []
        # Filter unavailable
        usable = [p for p in providers if isinstance(p, dict) and p.get("reputation") != "unavailable"]
        if not usable:
            # All unavailable -> treat as unavailable for scoring but keep medium confidence
            return ThreatAssessmentService.assess(port_risk, {"reputation": "unavailable", "reason": "all_providers_unavailable"}, open_ports, ports_scanned, status)

        # Worst-of ranking
        rank = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}
        worst = max(usable, key=lambda p: rank.get(str(p.get("reputation", "unknown")).lower(), -1))
        derived_rep = str(worst.get("reputation", "unknown")).lower()
        if derived_rep not in IP_BASE:
            derived_rep = "unknown"

        # Build synthetic ip_reputation for base scoring (keep reports from abuse, threat from honeypot)
        synthetic = {
            "reputation": derived_rep,
            "confidence": worst.get("confidence") or "none",
            "reports": 0,
            "threat_score": None,
            "days_since_activity": None,
            "provider": "threat_intelligence",
        }
        # Collect strongest signals for modifier
        max_reports = 0
        max_threat = 0
        min_days = None
        honeypot_categories = []
        for p in providers:
            if not isinstance(p, dict):
                continue
            # reports from abuse
            try:
                r = int(p.get("reports") or (p.get("evidence") or {}).get("reports") or 0)
                if r > max_reports:
                    max_reports = r
            except Exception:
                pass
            # threat from honeypot
            try:
                ev = p.get("evidence") or {}
                t = p.get("threat_score") if p.get("threat_score") is not None else ev.get("threat_score")
                if t is not None:
                    t = int(t)
                    if t > max_threat:
                        max_threat = t
            except Exception:
                pass
            # days
            try:
                ev2 = p.get("evidence") or {}
                d = p.get("days_since_activity") if p.get("days_since_activity") is not None else ev2.get("days_since_activity")
                if d is not None:
                    d = int(d)
                    if min_days is None or d < min_days:
                        min_days = d
            except Exception:
                pass
            # categories
            cats = p.get("categories") or (p.get("evidence") or {}).get("visitor_type_flags") or []
            for c in cats:
                if c not in honeypot_categories:
                    honeypot_categories.append(c)
        synthetic["reports"] = max_reports
        synthetic["threat_score"] = max_threat if max_threat else None
        synthetic["days_since_activity"] = min_days
        synthetic["honeypot_categories"] = honeypot_categories
        synthetic["worst_provider"] = worst.get("provider")

        # Call base assess with synthetic, but expand high_report_volume to include honeypot corroboration
        # We need to avoid double counting: strong_corroboration is single +5
        result = ThreatAssessmentService.assess(port_risk, synthetic, open_ports, ports_scanned, status)

        # Post-process: if honeypot showed high threat fresh, ensure factor reflects intelligence
        # The base assess already handled reports>=10. If honeypot threat>=70 and days<=30 and suspicious/malicious, add strong_corroboration if not already added
        has_high_report = any(f.get("type") == "high_report_volume" for f in result.get("factors", []))
        if not has_high_report and derived_rep in ("suspicious", "malicious"):
            try:
                if max_threat >= 70 and (min_days is None or min_days <= 30):
                    # Add unified strong_corroboration but keep weight 5, avoid double count
                    # Only if not already counted via reports
                    result["score"] = min(100, result["score"] + 5)
                    result["level"] = _level_for_score(result["score"])
                    result["factors"].append({
                        "type": "high_report_volume",
                        "weight": 5,
                        "description": f"High threat evidence (honeypot threat {max_threat}, {min_days}d ago)" if min_days is not None else f"High threat evidence (honeypot threat {max_threat})",
                    })
                    # Update explanation to include new score
                    # Rebuild explanation suffix
                    result["explanation"] = result["explanation"].replace(f" → {result['score']-5} ", f" → {result['score']} ").replace(f" → {result['score']-5}", f" → {result['score']}")
                    if "modifiers" not in result["explanation"] and " → " in result["explanation"]:
                        pass
            except Exception:
                pass

        # Add honeypot context to explanation if derived from honeypot
        if worst.get("provider") == "project_honeypot" and derived_rep in ("suspicious", "malicious"):
            # Append honeypot evidence note to factors if not already
            cats_str = ", ".join(honeypot_categories) if honeypot_categories else "honeypot"
            # Ensure factor description reflects source
            for f in result["factors"]:
                if f.get("type") in ("suspicious_ip", "malicious_ip"):
                    # Enhance description to mention honeypot
                    if "honeypot" not in f["description"].lower() and "project" not in f["description"].lower():
                        f["description"] = f"{f['description']} — Project Honey Pot {cats_str} (threat {max_threat})"

        # Ensure deterministic factor ordering for test stability
        # Keep base order but sort modifiers for determinism already in assess; we added factor at end — ok

        return result

    @staticmethod
    def assess_from_scan(scan_result) -> dict:
        """Convenience for ScanResult dataclass or dict."""
        # Extract fields handling both dict and dataclass
        def _get(obj, key, default=None):
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)
        port_risk = _get(scan_result, "risk_level", "low")
        # Prefer intelligence bundle if present
        bundle = _get(scan_result, "threat_intelligence")
        if isinstance(bundle, dict) and bundle.get("providers"):
            open_ports = _get(scan_result, "open_ports", [])
            ports_scanned = _get(scan_result, "ports_scanned")
            status = _get(scan_result, "status", "completed")
            return ThreatAssessmentService.assess_with_intelligence(port_risk, bundle, open_ports, ports_scanned, status)
        ip_rep = _get(scan_result, "ip_reputation")
        open_ports = _get(scan_result, "open_ports", [])
        ports_scanned = _get(scan_result, "ports_scanned")
        status = _get(scan_result, "status", "completed")
        return ThreatAssessmentService.assess(port_risk, ip_rep, open_ports, ports_scanned, status)
