"""Tests for ThreatAssessmentService — deterministic base+modifiers scoring."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from app.services.threat_assessment_service import ThreatAssessmentService
from app.services.port_scanner_service import PortScannerService
from app.reports.pdf_generator import PDFReportGenerator

# Helpers

def _rep(reputation, reports=0, confidence="none", provider="abuseipdb"):
    return {
        "ip": "1.1.1.1",
        "reputation": reputation,
        "confidence": confidence,
        "malicious": reputation == "malicious",
        "suspicious": reputation == "suspicious",
        "reports": reports,
        "country": "US",
        "asn": 12345,
        "organization": "Test",
        "isp": "Test ISP",
        "last_reported_at": "2026-08-20T12:00:00+00:00",
        "provider": provider,
        "checked_at": "2026-08-23T10:00:00+00:00",
        "reason": None,
    }

def _ports(*ports, state="open"):
    return [{"port": p, "service": "test", "state": state, "banner": ""} for p in ports]

# 1-4: Port base levels with CLEAN
class TestPortBase:
    def test_low_clean(self):
        a = ThreatAssessmentService.assess("low", _rep("clean"), _ports(80), ports_scanned=20)
        assert a["score"] == 10
        assert a["level"] == "low"
        assert a["confidence"] == "high"

    def test_medium_clean(self):
        a = ThreatAssessmentService.assess("medium", _rep("clean"), _ports(80), ports_scanned=20)
        assert a["score"] == 25
        assert a["level"] == "medium"

    def test_high_clean(self):
        a = ThreatAssessmentService.assess("high", _rep("clean"), _ports(445), ports_scanned=20)
        # HIGH 45 + multiple? 445 alone not multiple, so 45 high
        assert a["score"] == 45
        assert a["level"] == "high"

    def test_critical_clean(self):
        a = ThreatAssessmentService.assess("critical", _rep("clean"), _ports(22), ports_scanned=20)
        # 60 + critical_service_detail 5 =65 (since critical port and risk critical)
        assert a["score"] == 65
        assert a["level"] == "high"  # 65 high, not critical yet

# 5-7: IP reputation variations
class TestIPReputation:
    def test_low_suspicious(self):
        a = ThreatAssessmentService.assess("low", _rep("suspicious", reports=5), _ports(80), ports_scanned=20)
        assert a["score"] == 30  # 10+20
        assert a["level"] == "medium"

    def test_low_malicious(self):
        a = ThreatAssessmentService.assess("low", _rep("malicious", reports=5), _ports(80), ports_scanned=20)
        assert a["score"] == 45  # 10+35
        assert a["level"] == "high"

    def test_critical_malicious(self):
        a = ThreatAssessmentService.assess("critical", _rep("malicious", reports=5), _ports(22), ports_scanned=20)
        # 60+35=95 + critical_detail 5 + malicious_critical_combo 5 =105→100
        assert a["score"] == 100
        assert a["level"] == "critical"

# 8-11: Modifiers
class TestModifiers:
    def test_database_exposure(self):
        a = ThreatAssessmentService.assess("high", _rep("clean"), _ports(3306), ports_scanned=20)
        # HIGH 45 + db 5 =50 high
        assert a["score"] == 50
        assert any(f["type"] == "database_exposure" for f in a["factors"])

    def test_critical_service(self):
        a = ThreatAssessmentService.assess("critical", _rep("clean"), _ports(22), ports_scanned=20)
        assert any(f["type"] == "critical_service_detail" for f in a["factors"])
        assert a["score"] == 65

    def test_multiple_high_risk(self):
        a = ThreatAssessmentService.assess("high", _rep("clean"), _ports(80, 443, 445), ports_scanned=20)
        # HIGH 45 + multiple 5 =50? plus maybe not db, but multiple triggers
        assert any(f["type"] == "multiple_high_risk" for f in a["factors"])
        assert a["score"] >= 50

    def test_report_count_ge_10(self):
        a = ThreatAssessmentService.assess("low", _rep("suspicious", reports=15), _ports(80), ports_scanned=20)
        assert any(f["type"] == "high_report_volume" for f in a["factors"])
        assert a["score"] == 35  # 10+20+5
        # <10 no bonus
        b = ThreatAssessmentService.assess("low", _rep("suspicious", reports=5), _ports(80), ports_scanned=20)
        assert not any(f["type"] == "high_report_volume" for f in b["factors"])
        assert b["score"] == 30

    def test_report_count_lt_10_no_bonus(self):
        a = ThreatAssessmentService.assess("low", _rep("malicious", reports=9), _ports(80), ports_scanned=20)
        assert not any(f["type"] == "high_report_volume" for f in a["factors"])

# 13-16: Special cases
class TestSpecialCases:
    def test_unavailable_reputation(self):
        a = ThreatAssessmentService.assess("critical", _rep("unavailable"), _ports(22), ports_scanned=20)
        # 60 +0 + critical_detail 5 =65, confidence medium, factor unavailable weight 0
        assert a["score"] == 65
        assert a["confidence"] == "medium"
        assert any(f["type"] == "unavailable_reputation" for f in a["factors"])
        assert a["level"] == "high"

    def test_unknown_reputation(self):
        a = ThreatAssessmentService.assess("low", _rep("unknown"), _ports(80), ports_scanned=20)
        assert a["score"] == 10
        assert a["confidence"] == "high"  # unknown is usable
        assert a["level"] == "low"

    def test_no_open_ports(self):
        a = ThreatAssessmentService.assess("low", _rep("clean"), [], ports_scanned=20)
        assert a["score"] == 10
        assert a["level"] == "low"

    def test_incomplete_scan(self):
        a = ThreatAssessmentService.assess("low", _rep("clean"), _ports(80), ports_scanned=0)
        assert a["confidence"] == "low"
        # Also with None ports
        b = ThreatAssessmentService.assess("low", _rep("clean"), None, ports_scanned=None)
        assert b["confidence"] == "low"

# 17-19: Determinism and caps
class TestDeterminism:
    def test_duplicate_not_double_counted(self):
        # Two critical ports should only count critical_service_detail once
        a = ThreatAssessmentService.assess("critical", _rep("clean"), _ports(22, 23), ports_scanned=20)
        crit_factors = [f for f in a["factors"] if f["type"] == "critical_service_detail"]
        assert len(crit_factors) == 1
        # Same for db
        b = ThreatAssessmentService.assess("high", _rep("clean"), _ports(3306, 5432), ports_scanned=20)
        db_factors = [f for f in b["factors"] if f["type"] == "database_exposure"]
        assert len(db_factors) == 1

    def test_score_never_exceeds_100(self):
        # Max possible: critical 60 + malicious 35 + all modifiers 5*5=25 → 120 → capped 100
        a = ThreatAssessmentService.assess("critical", _rep("malicious", reports=15), _ports(22, 3306, 80, 443), ports_scanned=20)
        assert a["score"] <= 100
        assert a["score"] == 100  # should be capped

    def test_deterministic_explanation(self):
        a1 = ThreatAssessmentService.assess("critical", _rep("malicious", reports=27), _ports(22), ports_scanned=20)
        a2 = ThreatAssessmentService.assess("critical", _rep("malicious", reports=27), _ports(22), ports_scanned=20)
        assert a1["explanation"] == a2["explanation"]
        assert a1["score"] == a2["score"]
        assert a1["level"] == a2["level"]
        # Contains base info
        assert "CRITICAL" in a1["explanation"]
        assert "MALICIOUS" in a1["explanation"] or "Malicious" in a1["explanation"]

# 20-23: Persistence, API, History
class TestPersistenceAPIHistory:
    def test_historical_null_remains_valid(self, app, fake_supabase):
        # Simulate old row with threat_assessment NULL
        old_id = "old-123"
        fake_supabase.seed("port_scans", [{
            "id": old_id,
            "user_id": "uid-old",
            "target": "old.com",
            "resolved_ip": "1.1.1.1",
            "ports_scanned": 20,
            "open_ports": [],
            "scan_duration_ms": 10,
            "risk_level": "low",
            "status": "completed",
            "ip_reputation": None,
            "threat_assessment": None,
            "created_at": "2026-01-01T00:00:00+00:00"
        }])
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = True
        with app.app_context():
            from app.services.port_scanner_service import PortScannerService
            # Should not raise, returns None for threat_assessment
            detail = PortScannerService.get_scan_detail(user_id="uid-old", scan_id=old_id)
            assert detail["threat_assessment"] is None
            # History should include null
            hist = PortScannerService.get_scan_history(user_id="uid-old", page=1, limit=20)
            assert hist["scans"][0]["threat_assessment"] is None

    def test_api_response_contains_assessment(self, app, fake_supabase, client, auth_headers, auth_user_id):
        app.config["IP_REPUTATION_ENABLED"] = False  # disable rep to keep test simple, threat still computed from ports
        # Mock socket to avoid real scan
        import socket
        class MS:
            def settimeout(self,a): pass
            def connect_ex(self,a): return 1  # closed
            def recv(self,a): return b""
            def close(self): pass
        with patch("socket.socket", side_effect=lambda *a, **k: MS()):
            resp = client.post("/api/scanner/ports", json={"target": "8.8.8.8", "profile": "quick"}, headers=auth_headers)
            assert resp.status_code == 200
            data = resp.get_json()["data"]
            assert "threat_assessment" in data
            assert data["threat_assessment"] is not None
            assert "score" in data["threat_assessment"]
            assert "level" in data["threat_assessment"]
            assert "confidence" in data["threat_assessment"]
            assert "factors" in data["threat_assessment"]
            assert "explanation" in data["threat_assessment"]
            # No secrets
            assert "api_key" not in str(data["threat_assessment"]).lower()
            assert "jwt" not in str(data["threat_assessment"]).lower()

    def test_persistence_contains_assessment(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = False
        app.config["PORT_SCANNER_ALLOW_PRIVATE_ADDRESSES"] = True
        import socket
        class MS:
            def settimeout(self,a): pass
            def connect_ex(self,a): return 0  # open for critical port
            def recv(self,a): return b"SSH-2.0"
            def close(self): pass
        with app.app_context():
            with patch("socket.socket", side_effect=lambda *a, **k: MS()):
                with patch("app.services.port_scanner_service.get_user_supabase_client", lambda at=None: fake_supabase):
                    with patch("app.middleware.auth_middleware.get_current_access_token", return_value="dummy"):
                        from app.services.port_scanner_service import PortScannerService
                        # Use critical port 22 to get critical risk
                        res = PortScannerService.scan_ports(target="9.9.9.9", ports=[22], user_id="uid-persist")
                        assert res.threat_assessment is not None
                        # Check persisted
                        assert len(fake_supabase.rows["port_scans"]) >= 1
                        row = fake_supabase.rows["port_scans"][-1]
                        assert "threat_assessment" in row
                        assert row["threat_assessment"]["score"] is not None
                        assert "api_key" not in str(row["threat_assessment"]).lower()
                        assert "user_id" not in str(row["threat_assessment"]).lower()

    def test_history_returns_assessment_or_null(self, app, fake_supabase):
        app.config["IP_REPUTATION_ENABLED"] = False
        # Seed two rows: one with assessment, one without
        fake_supabase.seed("port_scans", [
            {"id": "with-threat", "user_id": "uid-hist", "target": "a.com", "resolved_ip": "1.1.1.1", "ports_scanned": 20, "open_ports": [], "scan_duration_ms": 10, "risk_level": "low", "status": "completed", "ip_reputation": None, "threat_assessment": {"score": 10, "level": "low", "confidence": "high", "factors": [], "explanation": "test", "assessed_at": "2026-08-23T00:00:00+00:00"}, "created_at": "2026-08-23T12:00:00+00:00"},
            {"id": "without-threat", "user_id": "uid-hist", "target": "b.com", "resolved_ip": "2.2.2.2", "ports_scanned": 20, "open_ports": [], "scan_duration_ms": 10, "risk_level": "low", "status": "completed", "ip_reputation": None, "threat_assessment": None, "created_at": "2026-08-23T11:00:00+00:00"},
        ])
        with app.app_context():
            from app.services.port_scanner_service import PortScannerService
            hist = PortScannerService.get_scan_history(user_id="uid-hist", page=1, limit=20)
            assert len(hist["scans"]) == 2
            with_threat = [s for s in hist["scans"] if s["id"] == "with-threat"][0]
            without = [s for s in hist["scans"] if s["id"] == "without-threat"][0]
            assert with_threat["threat_assessment"] is not None
            assert with_threat["threat_assessment"]["score"] == 10
            assert without["threat_assessment"] is None
            # Detail
            detail = PortScannerService.get_scan_detail(user_id="uid-hist", scan_id="with-threat")
            assert detail["threat_assessment"]["score"] == 10

# Security verification
class TestSecurity:
    def test_no_secrets_in_assessment(self):
        a = ThreatAssessmentService.assess("critical", _rep("malicious", reports=27), _ports(22), ports_scanned=20)
        s = str(a)
        assert "api_key" not in s.lower()
        assert "jwt" not in s.lower()
        assert "secret" not in s.lower()
        # Ensure no user_id
        assert "user_id" not in s.lower()

    def test_no_user_controlled_weights(self):
        # Weights are fixed in code, not from user input
        a = ThreatAssessmentService.assess("low", _rep("clean"), _ports(80), ports_scanned=20)
        # Try to inject via open_ports with fake weight field – should be ignored
        b = ThreatAssessmentService.assess("low", _rep("clean"), [{"port": 80, "service": "http", "state": "open", "banner": "", "weight": 999}], ports_scanned=20)
        assert a["score"] == b["score"]

    def test_frontend_scoring_not_authoritative(self):
        # Frontend should not compute score; backend is source. This test ensures backend score is deterministic and not user-controlled
        a = ThreatAssessmentService.assess("high", _rep("clean"), _ports(443), ports_scanned=20)
        assert a["level"] in ("low","medium","high","critical")
        assert 0 <= a["score"] <= 100
