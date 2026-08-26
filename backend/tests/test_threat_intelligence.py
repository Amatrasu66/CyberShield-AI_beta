"""Aggregator tests — Phase 2D-10A §4 + §2 secret leakage."""
import json
import socket
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

import pytest

from app.services.project_honeypot_provider import ProjectHoneyPotProvider, ProviderEvidence
from app.services.ip_reputation_service import ReputationResult

FAKE_KEY = "test-secret-key"
PUBLIC_IP = "8.8.8.8"

def _enable_both(app):
    app.config["IP_REPUTATION_ENABLED"] = True
    app.config["IP_REPUTATION_PROVIDER"] = "abuseipdb"
    app.config["IP_REPUTATION_API_KEY"] = "abuse-key"
    app.config["IP_REPUTATION_CACHE_ENABLED"] = True
    app.config["THREAT_INTELLIGENCE_ENABLED"] = True
    app.config["PROJECT_HONEYPOT_ENABLED"] = True
    app.config["PROJECT_HONEYPOT_ACCESS_KEY"] = FAKE_KEY

def _mock_abuse_result(reputation="malicious", reports=5, confidence="high"):
    return ReputationResult(
        ip=PUBLIC_IP, reputation=reputation, confidence=confidence,
        malicious=reputation=="malicious", suspicious=reputation=="suspicious",
        reports=reports, provider="abuseipdb", checked_at=datetime.now(timezone.utc).isoformat()
    )

def _hp_ev(reputation="malicious", threat=90, visitor=5, status="available"):
    return ProviderEvidence(
        ip=PUBLIC_IP, provider="project_honeypot", status=status, reputation=reputation,
        confidence="very_high" if threat>=75 else "high" if threat>=50 else "medium",
        threat_score=threat if reputation!="unknown" else None,
        visitor_type=visitor if reputation!="unknown" else None,
        visitor_type_name="Suspicious + Comment Spammer" if visitor==5 else None,
        days_since_activity=2, checked_at=datetime.now(timezone.utc).isoformat(),
        raw={"response": f"127.2.{threat}.{visitor}"} if reputation!="unknown" else {"response": "nxdomain"},
        malicious=reputation=="malicious", suspicious=reputation=="suspicious",
        categories=["suspicious","comment_spammer"] if reputation=="malicious" else [],
        evidence={"threat_score": threat, "visitor_type": visitor}
    )


class TestAggregatorBasic:
    def test_abuse_malicious_honey_unknown_overall_malicious(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.return_value = _mock_abuse_result("malicious")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", side_effect=socket.gaierror(-2, "Name or service not known")):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            assert bundle["summary"]["overall_reputation"] == "malicious"

    def test_abuse_unknown_honey_malicious_overall_malicious(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                # Return unknown
                mock_instance.check_ip.return_value = _mock_abuse_result("unknown", reports=0, confidence="none")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.90.5"):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            assert bundle["summary"]["overall_reputation"] == "malicious"

    def test_both_suspicious_overall_suspicious(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.return_value = _mock_abuse_result("suspicious", reports=6)
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.30.2"):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            assert bundle["summary"]["overall_reputation"] == "suspicious"

    def test_abuse_clean_honey_unknown_not_malicious(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.return_value = _mock_abuse_result("clean", reports=0, confidence="none")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", side_effect=socket.gaierror(-2, "Name or service not known")):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            assert bundle["summary"]["overall_reputation"] != "malicious"
            assert bundle["summary"]["overall_reputation"] in ("clean", "unknown")

    def test_abuse_unavailable_honey_malicious_still_returned(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            # Simulate Abuse provider returning unavailable via circuit or error
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.return_value = ReputationResult(ip=PUBLIC_IP, reputation="unavailable", confidence="none", provider="abuseipdb", checked_at=datetime.now(timezone.utc).isoformat(), reason="timeout")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.90.5"):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            # honeypot evidence must still be present
            providers = {p["provider"]: p for p in bundle["providers"]}
            assert "project_honeypot" in providers
            assert providers["project_honeypot"]["reputation"] == "malicious"

    def test_abuse_malicious_honey_unavailable_abuse_still_returned(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.return_value = _mock_abuse_result("malicious")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", side_effect=socket.timeout("timeout")):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            providers = {p["provider"]: p for p in bundle["providers"]}
            assert "abuseipdb" in providers
            assert providers["abuseipdb"]["reputation"] == "malicious"

    def test_both_unavailable_no_false_clean(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.return_value = ReputationResult(ip=PUBLIC_IP, reputation="unavailable", confidence="none", provider="abuseipdb", checked_at=datetime.now(timezone.utc).isoformat(), reason="timeout")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", side_effect=socket.timeout("timeout")):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            assert bundle["summary"]["overall_reputation"] == "unavailable"
            assert bundle["summary"]["overall_reputation"] != "clean"
            assert bundle["sources_available"] == 0

    def test_provider_exception_other_still_executes(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.side_effect = RuntimeError("boom")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.90.5"):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            # abuse should be unavailable but honeypot still present
            assert any(p["provider"] == "project_honeypot" and p["reputation"] == "malicious" for p in bundle["providers"])
            assert any(p["provider"] == "abuseipdb" for p in bundle["providers"])

    def test_deterministic_ordering(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.return_value = _mock_abuse_result("suspicious")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.30.2"):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    b1 = ThreatIntelligenceService.check_ip(PUBLIC_IP)
                    # clear cache to force re-evaluation
                    fake_supabase.rows["ip_reputation_cache"] = [r for r in fake_supabase.rows["ip_reputation_cache"] if r["ip"] != PUBLIC_IP]
                    b2 = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            assert [p["provider"] for p in b1["providers"]] == [p["provider"] for p in b2["providers"]]
            assert b1["summary"]["overall_reputation"] == b2["summary"]["overall_reputation"]

    def test_no_duplicate_provider_entries(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.return_value = _mock_abuse_result("clean")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.80.2"):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            providers = [p["provider"] for p in bundle["providers"]]
            assert len(providers) == len(set(providers))

    def test_no_secret_in_bundle(self, app, fake_supabase):
        _enable_both(app)
        with app.app_context():
            with patch("app.services.ip_reputation_service.IPReputationService._get_provider") as mock_prov:
                mock_instance = MagicMock()
                mock_instance.provider_name = "abuseipdb"
                mock_instance.check_ip.return_value = _mock_abuse_result("malicious")
                mock_prov.return_value = mock_instance
                with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.4.92.5"):
                    from app.services.threat_intelligence_service import ThreatIntelligenceService
                    bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
            assert FAKE_KEY not in json.dumps(bundle)
            for p in bundle["providers"]:
                assert FAKE_KEY not in json.dumps(p)
                assert FAKE_KEY not in json.dumps(p.get("raw") or {})
