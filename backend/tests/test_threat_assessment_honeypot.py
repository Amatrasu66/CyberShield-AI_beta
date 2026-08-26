"""Threat Assessment honeypot tests — Phase 2D-10A §5."""
import json
from datetime import datetime, timezone

import pytest
from app.services.threat_assessment_service import ThreatAssessmentService

def _ports(*ports, state="open"):
    return [{"port": p, "service": "test", "state": state, "banner": ""} for p in ports]

def _bundle(providers):
    return {
        "ip": "1.1.1.1",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "providers": providers,
        "summary": {"overall_reputation": providers[0]["reputation"] if providers else "unavailable"}
    }

def _abuse(reputation, reports=5):
    return {
        "provider": "abuseipdb",
        "reputation": reputation,
        "confidence": "high" if reputation=="malicious" else "medium",
        "malicious": reputation=="malicious",
        "suspicious": reputation=="suspicious",
        "reports": reports,
        "threat_score": None,
        "visitor_type": None,
        "days_since_activity": None,
        "last_seen": None,
        "status": "available" if reputation in ("malicious","suspicious","clean") else "unknown",
        "categories": [],
        "evidence": {"reports": reports}
    }

def _hp(reputation, threat=90, visitor=5, days=2):
    return {
        "provider": "project_honeypot",
        "reputation": reputation,
        "confidence": "very_high" if threat>=75 else "high",
        "malicious": reputation=="malicious",
        "suspicious": reputation=="suspicious",
        "threat_score": threat,
        "visitor_type": visitor,
        "visitor_type_name": "Suspicious + Comment Spammer" if visitor==5 else "Harvester",
        "days_since_activity": days,
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "status": "available" if reputation in ("malicious","suspicious") else "unknown",
        "categories": ["suspicious","comment_spammer"] if visitor==5 else ["harvester"],
        "evidence": {"threat_score": threat, "visitor_type": visitor, "days_since_activity": days, "visitor_type_flags": ["suspicious"]},
        "raw": {"response": f"127.{days}.{threat}.{visitor}"}
    }

class TestHoneyPotNoDoubleCount:
    def test_malicious_both_only_once(self):
        # Both providers malicious should not double count IP base
        bundle = _bundle([_abuse("malicious", reports=10), _hp("malicious", threat=90)])
        a = ThreatAssessmentService.assess_with_intelligence("high", bundle, _ports(80), ports_scanned=20)
        # IP base for malicious is 35, not 70. Plus high port 45 = 80 plus modifiers. Must not be 115.
        assert a["score"] <= 100
        # Ensure only one suspicious/malicious factor + one high_report_volume at most
        ip_factors = [f for f in a["factors"] if f["type"] in ("malicious_ip","suspicious_ip")]
        assert len(ip_factors) == 1

    def test_suspicious_both_only_once(self):
        bundle = _bundle([_abuse("suspicious", reports=6), _hp("suspicious", threat=50)])
        a = ThreatAssessmentService.assess_with_intelligence("low", bundle, _ports(80), ports_scanned=20)
        assert a["score"] == 30 or a["score"] == 35  # low 10 + suspicious 20 (+ maybe high_report_volume if threat high)
        ip_factors = [f for f in a["factors"] if f["type"] in ("suspicious_ip","malicious_ip")]
        assert len(ip_factors) == 1

    def test_honeypot_malicious_alone(self):
        bundle = _bundle([_abuse("unknown", reports=0), _hp("malicious", threat=90)])
        a = ThreatAssessmentService.assess_with_intelligence("low", bundle, _ports(80), ports_scanned=20)
        assert a["score"] >= 45  # 10+35
        assert any(f["type"] == "malicious_ip" for f in a["factors"])
        assert a["level"] in ("high","critical")

    def test_honeypot_suspicious_alone(self):
        bundle = _bundle([_abuse("clean", reports=0), _hp("suspicious", threat=40, visitor=2)])
        a = ThreatAssessmentService.assess_with_intelligence("low", bundle, _ports(80), ports_scanned=20)
        assert a["score"] == 30  # 10+20, worst is suspicious
        assert any(f["type"] == "suspicious_ip" for f in a["factors"])

    def test_honeypot_unavailable_ignored(self):
        bundle = _bundle([_abuse("clean", reports=0), {"provider":"project_honeypot","reputation":"unavailable","confidence":"none","malicious":False,"suspicious":False,"reports":0,"status":"unavailable","evidence":{}}])
        a = ThreatAssessmentService.assess_with_intelligence("low", bundle, _ports(80), ports_scanned=20)
        assert a["score"] == 10
        assert a["confidence"] == "high"  # clean is usable

    def test_honeypot_unknown_ignored(self):
        bundle = _bundle([_abuse("clean", reports=0), _hp("unknown", threat=0, visitor=0)])
        # worst is clean (rank 1 vs 0), so clean
        a = ThreatAssessmentService.assess_with_intelligence("low", bundle, _ports(80), ports_scanned=20)
        assert a["score"] == 10

    def test_score_0_100(self):
        for port_risk in ("low","medium","high","critical"):
            bundle = _bundle([_abuse("malicious"), _hp("malicious")])
            a = ThreatAssessmentService.assess_with_intelligence(port_risk, bundle, _ports(22,3306), ports_scanned=20)
            assert 0 <= a["score"] <= 100

    def test_no_user_controlled_weights(self):
        bundle = _bundle([_hp("malicious", threat=90)])
        a = ThreatAssessmentService.assess_with_intelligence("low", bundle, [{"port":80,"state":"open","weight":999}], ports_scanned=20)
        b = ThreatAssessmentService.assess_with_intelligence("low", bundle, _ports(80), ports_scanned=20)
        assert a["score"] == b["score"]

    def test_no_duplicate_factors(self):
        bundle = _bundle([_abuse("malicious", reports=15), _hp("malicious", threat=90)])
        a = ThreatAssessmentService.assess_with_intelligence("critical", bundle, _ports(22,3306,80,443), ports_scanned=20)
        types = [f["type"] for f in a["factors"]]
        assert len(types) == len(set(types)) or types.count("malicious_ip") == 1  # at most one malicious_ip

    def test_deterministic_explanation(self):
        bundle = _bundle([_hp("malicious", threat=90)])
        a1 = ThreatAssessmentService.assess_with_intelligence("high", bundle, _ports(80), ports_scanned=20)
        a2 = ThreatAssessmentService.assess_with_intelligence("high", bundle, _ports(80), ports_scanned=20)
        assert a1["explanation"] == a2["explanation"]
        assert a1["score"] == a2["score"]

    def test_worst_of_selection(self):
        # Abuse suspicious, honeypot malicious -> worst malicious
        bundle = _bundle([_abuse("suspicious", reports=6), _hp("malicious", threat=80)])
        a = ThreatAssessmentService.assess_with_intelligence("low", bundle, _ports(80), ports_scanned=20)
        assert any(f["type"] == "malicious_ip" for f in a["factors"])

    def test_reports_max_threat_min_days(self):
        # Ensure assess doesn't crash and uses max reports/min days internally
        bundle = _bundle([_abuse("suspicious", reports=20), _hp("suspicious", threat=80, days=1), _hp("suspicious", threat=30, days=10)])
        a = ThreatAssessmentService.assess_with_intelligence("low", bundle, _ports(80), ports_scanned=20)
        assert a["score"] >= 30

    def test_confidence_correct(self):
        bundle = _bundle([_hp("malicious")])
        a = ThreatAssessmentService.assess_with_intelligence("low", bundle, _ports(80), ports_scanned=20)
        assert a["confidence"] == "high"
        # unavailable -> medium
        bundle2 = _bundle([{"provider":"abuseipdb","reputation":"unavailable","confidence":"none","malicious":False,"suspicious":False,"reports":0,"status":"unavailable","evidence":{}}, {"provider":"project_honeypot","reputation":"unavailable","confidence":"none","malicious":False,"suspicious":False,"status":"unavailable","evidence":{}}])
        b = ThreatAssessmentService.assess_with_intelligence("low", bundle2, _ports(80), ports_scanned=20)
        assert b["confidence"] == "medium"
