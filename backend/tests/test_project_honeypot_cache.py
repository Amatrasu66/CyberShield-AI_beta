"""Cache tests for Project Honey Pot — Phase 2D-10A §3 + §2 secret leakage."""
import json
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest

from app.services.project_honeypot_provider import ProjectHoneyPotProvider, ProviderEvidence
from app.services.ip_reputation_cache_service import IPReputationCacheService

FAKE_KEY = "test-secret-key"
PUBLIC_IP = "9.9.9.9"


def _hp_provider():
    return ProjectHoneyPotProvider(access_key=FAKE_KEY, timeout=3)


class TestHoneyPotCacheMissHit:
    def test_first_lookup_calls_dns_and_writes(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["THREAT_INTELLIGENCE_ENABLED"] = True
        app.config["PROJECT_HONEYPOT_ENABLED"] = True
        app.config["PROJECT_HONEYPOT_ACCESS_KEY"] = FAKE_KEY
        app.config["IP_REPUTATION_ENABLED"] = False  # only honeypot
        with app.app_context():
            with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.80.2") as mock_dns:
                from app.services.threat_intelligence_service import ThreatIntelligenceService
                bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
                assert mock_dns.call_count == 1
                rows = [r for r in fake_supabase.rows.get("ip_reputation_cache", []) if r["provider"] == "project_honeypot" and r["ip"] == PUBLIC_IP]
                assert len(rows) == 1
                assert rows[0]["reputation"] in ("suspicious", "malicious")

    def test_second_lookup_cache_hit_no_provider(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["THREAT_INTELLIGENCE_ENABLED"] = True
        app.config["PROJECT_HONEYPOT_ENABLED"] = True
        app.config["PROJECT_HONEYPOT_ACCESS_KEY"] = FAKE_KEY
        app.config["IP_REPUTATION_ENABLED"] = False
        with app.app_context():
            with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.80.2"):
                from app.services.threat_intelligence_service import ThreatIntelligenceService
                ThreatIntelligenceService.check_ip(PUBLIC_IP)
            with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.90.4") as mock_dns2:
                from app.services.threat_intelligence_service import ThreatIntelligenceService
                bundle2 = ThreatIntelligenceService.check_ip(PUBLIC_IP)
                assert mock_dns2.call_count == 0
                # still same reputation from cache (80 threat)
                hp = [p for p in bundle2["providers"] if p["provider"] == "project_honeypot"][0]
                assert hp["threat_score"] == 80

    def test_expired_cache_calls_provider_again(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["THREAT_INTELLIGENCE_ENABLED"] = True
        app.config["PROJECT_HONEYPOT_ENABLED"] = True
        app.config["PROJECT_HONEYPOT_ACCESS_KEY"] = FAKE_KEY
        app.config["IP_REPUTATION_ENABLED"] = False
        with app.app_context():
            with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.80.2"):
                from app.services.threat_intelligence_service import ThreatIntelligenceService
                ThreatIntelligenceService.check_ip(PUBLIC_IP)
            # expire
            row = [r for r in fake_supabase.rows["ip_reputation_cache"] if r["provider"] == "project_honeypot"][0]
            row["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
            with patch.object(ProjectHoneyPotProvider, "_dns_lookup", return_value="127.2.90.4") as mock_dns:
                from app.services.threat_intelligence_service import ThreatIntelligenceService
                bundle = ThreatIntelligenceService.check_ip(PUBLIC_IP)
                assert mock_dns.call_count == 1
                hp = [p for p in bundle["providers"] if p["provider"] == "project_honeypot"][0]
                assert hp["threat_score"] == 90

    def test_unavailable_not_cached(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        # Put an unavailable ProviderEvidence directly
        with app.app_context():
            ev = ProviderEvidence(ip=PUBLIC_IP, provider="project_honeypot", status="unavailable", reputation="unavailable", confidence="none", reason="timeout", checked_at=datetime.now(timezone.utc).isoformat(), raw={})
            IPReputationCacheService.put(ev)
            rows = [r for r in fake_supabase.rows.get("ip_reputation_cache", []) if r["provider"] == "project_honeypot" and r["ip"] == PUBLIC_IP]
            assert len(rows) == 0

    def test_nxdomain_unknown_follows_policy_cached(self, app, fake_supabase):
        # UNKNOWN should be cached (not unavailable)
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        with app.app_context():
            ev = ProviderEvidence(ip=PUBLIC_IP, provider="project_honeypot", status="unknown", reputation="unknown", confidence="none", threat_score=None, visitor_type=None, reason="no_result", checked_at=datetime.now(timezone.utc).isoformat(), raw={"response": "nxdomain"}, evidence={"days_since_activity": None, "threat_score": None, "visitor_type": None, "visitor_type_flags": []})
            IPReputationCacheService.put(ev)
            rows = [r for r in fake_supabase.rows.get("ip_reputation_cache", []) if r["provider"] == "project_honeypot"]
            assert len(rows) == 1
            # get should return it
            cached = IPReputationCacheService.get(PUBLIC_IP, "project_honeypot")
            assert cached is not None
            assert cached.reputation == "unknown"

    def test_different_provider_keys_no_overwrite(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        with app.app_context():
            from app.services.ip_reputation_service import ReputationResult
            rr = ReputationResult(ip=PUBLIC_IP, reputation="clean", confidence="high", provider="abuseipdb", checked_at=datetime.now(timezone.utc).isoformat())
            IPReputationCacheService.put(rr)
            ev = ProviderEvidence(ip=PUBLIC_IP, provider="project_honeypot", status="available", reputation="malicious", confidence="very_high", threat_score=90, visitor_type=5, visitor_type_name="Suspicious + Comment Spammer", days_since_activity=2, last_seen=datetime.now(timezone.utc).isoformat(), checked_at=datetime.now(timezone.utc).isoformat(), raw={"response": "127.2.90.5"}, categories=["suspicious", "comment_spammer"], evidence={"threat_score": 90, "visitor_type": 5})
            IPReputationCacheService.put(ev)
            rows = [r for r in fake_supabase.rows["ip_reputation_cache"] if r["ip"] == PUBLIC_IP]
            assert len(rows) == 2
            providers = {r["provider"] for r in rows}
            assert providers == {"abuseipdb", "project_honeypot"}
            # each get returns correct
            a = IPReputationCacheService.get(PUBLIC_IP, "abuseipdb")
            b = IPReputationCacheService.get(PUBLIC_IP, "project_honeypot")
            assert a.provider == "abuseipdb"
            assert b.provider == "project_honeypot"
            assert a.reputation == "clean"
            assert b.reputation == "malicious"

    def test_cache_contains_no_access_key(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        with app.app_context():
            ev = ProviderEvidence(ip=PUBLIC_IP, provider="project_honeypot", status="available", reputation="malicious", confidence="very_high", threat_score=92, visitor_type=5, checked_at=datetime.now(timezone.utc).isoformat(), raw={"response": "127.4.92.5"}, categories=["suspicious"], evidence={"threat_score": 92, "visitor_type": 5})
            IPReputationCacheService.put(ev)
            assert FAKE_KEY not in json.dumps(fake_supabase.rows.get("ip_reputation_cache", []))

    def test_cache_contains_normalized_evidence(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        with app.app_context():
            ev = ProviderEvidence(ip=PUBLIC_IP, provider="project_honeypot", status="available", reputation="malicious", confidence="very_high", threat_score=88, visitor_type=6, visitor_type_name="Harvester + Comment Spammer", days_since_activity=5, last_seen=datetime.now(timezone.utc).isoformat(), checked_at=datetime.now(timezone.utc).isoformat(), raw={"response": "127.5.88.6"}, categories=["harvester", "comment_spammer"], evidence={"days_since_activity": 5, "threat_score": 88, "visitor_type": 6, "visitor_type_flags": ["harvester", "comment_spammer"]})
            IPReputationCacheService.put(ev)
            cached = IPReputationCacheService.get(PUBLIC_IP, "project_honeypot")
            assert cached is not None
            assert cached.threat_score == 88
            assert cached.visitor_type == 6
            assert cached.days_since_activity == 5
            assert "harvester" in cached.categories
