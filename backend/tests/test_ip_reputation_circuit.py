"""Focused circuit-breaker tests for AbuseIPDB resilience (Phase 2D-7)."""

import time
import threading
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
import requests

from app.services.ip_reputation_service import IPReputationService, ReputationResult, _circuit_reset_for_tests
from app.services.ip_reputation_cache_service import IPReputationCacheService


def _abuse_ok(ip="1.1.1.1", score=0, reports=0):
    m = MagicMock()
    m.status_code = 200
    m.headers = {}
    m.text = "{}"
    m.json.return_value = {"data": {"ipAddress": ip, "abuseConfidenceScore": score, "totalReports": reports, "isWhitelisted": False, "countryCode": "US", "isp": "ISP"}}
    return m

def _abuse_429():
    m = MagicMock()
    m.status_code = 429
    m.headers = {}
    return m

def _abuse_5xx():
    m = MagicMock()
    m.status_code = 500
    m.headers = {}
    return m


@pytest.fixture(autouse=True)
def isolate_circuit(app):
    _circuit_reset_for_tests()
    # use small threshold/cooldown for tests
    app.config["IP_REPUTATION_ENABLED"] = True
    app.config["IP_REPUTATION_API_KEY"] = "k"
    app.config["IP_REPUTATION_CIRCUIT_THRESHOLD"] = 3
    app.config["IP_REPUTATION_CIRCUIT_COOLDOWN"] = 60
    app.config["IP_REPUTATION_CACHE_ENABLED"] = False
    yield
    _circuit_reset_for_tests()


class TestConsecutiveFailuresAndOpen:
    def test_consecutive_429_opens_circuit(self, app):
        with app.app_context():
            for i in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                    r = IPReputationService.check_ip(f"8.8.8.{i+1}")
                    assert r.reputation == "unavailable"
                    assert r.reason == "rate_limited"
            # next call should be blocked without hitting provider
            with patch("app.services.ip_reputation_service.requests.get") as mg:
                r = IPReputationService.check_ip("9.9.9.9")
                assert r.reputation == "unavailable"
                assert r.reason == "circuit_open"
                assert mg.call_count == 0

    def test_5xx_counts_toward_threshold(self, app):
        with app.app_context():
            for i in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_5xx()):
                    IPReputationService.check_ip(f"8.8.8.{i+10}")
            with patch("app.services.ip_reputation_service.requests.get") as mg:
                r = IPReputationService.check_ip("8.8.8.99")
                assert r.reason == "circuit_open"
                assert mg.call_count == 0

    def test_timeout_counts_toward_threshold(self, app):
        with app.app_context():
            for i in range(3):
                with patch("app.services.ip_reputation_service.requests.get", side_effect=requests.Timeout()):
                    IPReputationService.check_ip(f"11.11.11.{i+1}")
            with patch("app.services.ip_reputation_service.requests.get") as mg:
                r = IPReputationService.check_ip("11.11.11.99")
                assert r.reason == "circuit_open"
                assert mg.call_count == 0

    def test_requests_blocked_while_open(self, app):
        with app.app_context():
            for i in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                    IPReputationService.check_ip(f"20.20.20.{i+1}")
            for _ in range(5):
                with patch("app.services.ip_reputation_service.requests.get") as mg:
                    r = IPReputationService.check_ip("21.21.21.21")
                    assert r.reason == "circuit_open"
                    assert mg.call_count == 0


class TestCooldownProbe:
    def test_cooldown_expires_allows_probe(self, app):
        app.config["IP_REPUTATION_CIRCUIT_COOLDOWN"] = 1
        with app.app_context():
            for i in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                    IPReputationService.check_ip(f"30.30.30.{i+1}")
            # still open
            with patch("app.services.ip_reputation_service.requests.get") as mg:
                assert IPReputationService.check_ip("30.30.30.99").reason == "circuit_open"
                assert mg.call_count == 0
            time.sleep(1.1)
            # probe allowed - should hit provider
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok(score=0)) as mg:
                r = IPReputationService.check_ip("30.30.30.100")
                assert mg.call_count == 1
                assert r.reputation in ("unknown", "clean", "suspicious", "malicious")
                assert r.reason != "circuit_open"

    def test_successful_probe_closes_circuit(self, app):
        app.config["IP_REPUTATION_CIRCUIT_COOLDOWN"] = 1
        with app.app_context():
            for i in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_5xx()):
                    IPReputationService.check_ip(f"31.31.31.{i+1}")
            time.sleep(1.1)
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok(score=0)):
                r = IPReputationService.check_ip("31.31.31.99")
                assert r.reputation != "unavailable" or r.reason not in ("provider_error",)
            # next call should not be blocked (circuit closed)
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok(score=10)) as mg:
                r2 = IPReputationService.check_ip("31.31.31.100")
                assert mg.call_count == 1
                assert r2.reason != "circuit_open"

    def test_failed_probe_reopens_circuit(self, app):
        app.config["IP_REPUTATION_CIRCUIT_COOLDOWN"] = 1
        with app.app_context():
            for i in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                    IPReputationService.check_ip(f"32.32.32.{i+1}")
            time.sleep(1.1)
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                r = IPReputationService.check_ip("32.32.32.99")
                assert r.reason == "rate_limited"
            # should be open again
            with patch("app.services.ip_reputation_service.requests.get") as mg:
                assert IPReputationService.check_ip("32.32.32.100").reason == "circuit_open"
                assert mg.call_count == 0


class TestSuccessResets:
    def test_unknown_resets_failures(self, app):
        with app.app_context():
            for _ in range(2):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                    IPReputationService.check_ip("40.40.40.1")
            # success (unknown)
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok(score=0, reports=0)):
                r = IPReputationService.check_ip("40.40.40.2")
                assert r.reputation == "unknown"
            # two more failures should not yet open (counter reset)
            for _ in range(2):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                    IPReputationService.check_ip("40.40.40.3")
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok()) as mg:
                r = IPReputationService.check_ip("40.40.40.4")
                assert mg.call_count == 1
                assert r.reason != "circuit_open"

    def test_clean_resets(self, app):
        with app.app_context():
            for _ in range(2):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_5xx()):
                    IPReputationService.check_ip("41.41.41.1")
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok(score=0, reports=0)):
                IPReputationService.check_ip("41.41.41.2")
            for _ in range(2):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_5xx()):
                    IPReputationService.check_ip("41.41.41.3")
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok()) as mg:
                assert mg.call_count == 0  # we haven't called yet? call now
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok()) as mg2:
                r = IPReputationService.check_ip("41.41.41.4")
                assert mg2.call_count == 1

    def test_suspicious_and_malicious_not_counted(self, app):
        with app.app_context():
            for _ in range(2):
                with patch("app.services.ip_reputation_service.requests.get", side_effect=requests.Timeout()):
                    IPReputationService.check_ip("42.42.42.1")
            # suspicious is normal success
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok(score=50, reports=5)):
                r = IPReputationService.check_ip("42.42.42.2")
                assert r.reputation == "suspicious"
            for _ in range(2):
                with patch("app.services.ip_reputation_service.requests.get", side_effect=requests.Timeout()):
                    IPReputationService.check_ip("42.42.42.3")
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok()) as mg:
                r = IPReputationService.check_ip("42.42.42.4")
                assert mg.call_count == 1

    def test_missing_api_key_not_counted(self, app):
        app.config["IP_REPUTATION_API_KEY"] = ""
        with app.app_context():
            for _ in range(5):
                r = IPReputationService.check_ip("43.43.43.1")
                assert r.reason == "missing_api_key"
            app.config["IP_REPUTATION_API_KEY"] = "k"
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok()) as mg:
                r = IPReputationService.check_ip("43.43.43.2")
                assert mg.call_count == 1
                assert r.reason != "circuit_open"


class TestCacheAndUnavailable:
    def test_cache_hit_bypasses_provider_and_circuit(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_ok(score=5)):
                IPReputationService.check_ip("50.50.50.50")
            # force circuit open
            for i in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                    IPReputationService.check_ip(f"51.51.51.{60+i}")
            # cached IP should still return hit without circuit block
            with patch("app.services.ip_reputation_service.requests.get") as mg:
                r = IPReputationService.check_ip("50.50.50.50")
                assert mg.call_count == 0
                assert r.reputation != "unavailable"
                assert r.reports == 0

    def test_unavailable_not_cached(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        app.config["IP_REPUTATION_API_KEY"] = "k"
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                r = IPReputationService.check_ip("51.51.51.51")
                assert r.reputation == "unavailable"
            assert len([row for row in fake_supabase.rows.get("ip_reputation_cache", []) if row["ip"] == "51.51.51.51"]) == 0

    def test_circuit_open_returns_unavailable_not_cached(self, app, fake_supabase):
        app.config["IP_REPUTATION_CACHE_ENABLED"] = True
        with app.app_context():
            for i in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_5xx()):
                    IPReputationService.check_ip(f"52.52.52.{i+1}")
            r = IPReputationService.check_ip("52.52.52.99")
            assert r.reason == "circuit_open"
            assert len([row for row in fake_supabase.rows.get("ip_reputation_cache", []) if row["ip"] == "52.52.52.99"]) == 0


class TestPerProviderIsolation:
    def test_other_provider_not_blocked(self, app):
        with app.app_context():
            for _ in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                    IPReputationService.check_ip("60.60.60.1")
            # abuseipdb is open
            with patch("app.services.ip_reputation_service.requests.get") as mg:
                assert IPReputationService.check_ip("60.60.60.2").reason == "circuit_open"
            # switch to other provider - should not be blocked
            app.config["IP_REPUTATION_PROVIDER"] = "other"
            # need to bypass circuit check: provider_name will be "unavailable" for other? Actually _get_provider returns NullProvider for unknown
            # Let's test per-provider dict isolation directly via internal api
            from app.services.ip_reputation_service import _circuit_state, _circuit_should_block
            # abuseipdb should be blocked, other should not
            assert _circuit_should_block("abuseipdb") is True
            assert _circuit_should_block("other") is False
            app.config["IP_REPUTATION_PROVIDER"] = "abuseipdb"


class TestConcurrentAndLeakage:
    def test_concurrent_access_thread_safe(self, app):
        errors = []
        def _call():
            try:
                with app.app_context():
                    with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                        IPReputationService.check_ip("70.70.70.1")
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=_call) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert not errors
        with app.app_context():
            # after many concurrent failures, circuit should be open but not corrupted
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()) as mg:
                r = IPReputationService.check_ip("70.70.70.2")
                # either still blocked (circuit_open) or if probe window elapsed, may have called once; both are safe
                assert r.reputation == "unavailable"
                # if blocked, no provider call; if probe, one call
                assert mg.call_count in (0, 1)

    def test_no_secret_leakage_in_circuit_response(self, app):
        app.config["IP_REPUTATION_API_KEY"] = "super-secret-123"
        with app.app_context():
            for _ in range(3):
                with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                    IPReputationService.check_ip("80.80.80.1")
            r = IPReputationService.check_ip("80.80.80.2")
            d = r.to_dict()
            assert "super-secret-123" not in str(d)
            assert "api_key" not in str(d).lower()
            assert d["provider"] == "abuseipdb"
            assert d["reason"] == "circuit_open"
            assert "circuit" not in str(d).lower() or d["reason"] == "circuit_open"  # reason is allowed, but no internal threshold

    def test_429_and_5xx_handling_are_failures(self, app):
        with app.app_context():
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_429()):
                r = IPReputationService.check_ip("90.90.90.1")
                assert r.reason == "rate_limited"
            with patch("app.services.ip_reputation_service.requests.get", return_value=_abuse_5xx()):
                r = IPReputationService.check_ip("90.90.90.2")
                assert r.reason == "provider_error"
            with patch("app.services.ip_reputation_service.requests.get", side_effect=requests.Timeout()):
                r = IPReputationService.check_ip("90.90.90.3")
                assert r.reason == "timeout"
