"""Tests for the password analyzer service and endpoint."""

import pytest

from app.errors import ServiceUnavailableError
from app.services.password_service import PasswordService, PasswordGenerator


class TestPasswordService:
    def test_weak_short_password(self):
        result = PasswordService.analyze_password("abc")
        assert result["length"] == 3
        assert result["strength"] == "Weak"
        assert result["strength_score"] < 40
        assert result["crack_time_estimate"] == "instantly"
        assert result["recommendations"]

    def test_strong_password(self):
        result = PasswordService.analyze_password("Tr0ub4dor&3xample!Secure")
        assert result["strength"] == "Strong"
        assert result["strength_score"] >= 85
        assert result["classes_used"] == 4
        assert result["entropy_bits"] > 100

    def test_character_class_detection(self):
        result = PasswordService.analyze_password("Abc123!@")
        assert result["uppercase"] is True
        assert result["lowercase"] is True
        assert result["digits"] is True
        assert result["special"] is True
        assert set(result["char_classes"]) == {"uppercase", "lowercase", "digits", "special"}

    def test_common_weak_password_flagged(self):
        result = PasswordService.analyze_password("password")
        assert result["in_common_list"] is True
        assert result["strength"] == "Weak"

    def test_entropy_is_deterministic(self):
        a = PasswordService.analyze_password("CorrectHorseBattery")
        b = PasswordService.analyze_password("CorrectHorseBattery")
        assert a["entropy_bits"] == b["entropy_bits"]
        assert a["strength_score"] == b["strength_score"]

    def test_no_raw_password_in_result(self):
        secret = "S3cr3t!Pa55word"
        result = PasswordService.analyze_password(secret)
        assert secret not in str(result)


class TestWeaknessDetection:
    def test_short_password_weakness(self):
        result = PasswordService.analyze_password("abc")
        weaknesses = result["weaknesses"]
        assert any(w["code"] == "TOO_SHORT" for w in weaknesses)

    def test_common_password_weakness(self):
        result = PasswordService.analyze_password("password")
        weaknesses = result["weaknesses"]
        assert any(w["code"] == "COMMON_PASSWORD" for w in weaknesses)

    def test_repeated_characters_weakness(self):
        result = PasswordService.analyze_password("aaa12345")
        weaknesses = result["weaknesses"]
        assert any(w["code"] == "REPEATED_CHARACTERS" for w in weaknesses)

    def test_repeated_substring_weakness(self):
        result = PasswordService.analyze_password("abcabc123")
        weaknesses = result["weaknesses"]
        assert any(w["code"] == "REPEATED_SUBSTRING" for w in weaknesses)

    def test_sequential_pattern_weakness(self):
        result = PasswordService.analyze_password("abc12345")
        weaknesses = result["weaknesses"]
        assert any(w["code"] == "SEQUENTIAL_PATTERN" for w in weaknesses)

    def test_keyboard_pattern_weakness(self):
        result = PasswordService.analyze_password("qwerty123")
        weaknesses = result["weaknesses"]
        assert any(w["code"] == "KEYBOARD_PATTERN" for w in weaknesses)

    def test_predictable_year_weakness(self):
        result = PasswordService.analyze_password("mypass2024")
        weaknesses = result["weaknesses"]
        assert any(w["code"] == "PREDICTABLE_YEAR" for w in weaknesses)

    def test_possible_personal_info_weakness(self):
        result = PasswordService.analyze_password("john1990")
        weaknesses = result["weaknesses"]
        assert any(w["code"] in ("PREDICTABLE_YEAR", "DATE_PATTERN", "PHONE_PATTERN") for w in weaknesses)

    def test_score_breakdown_structure(self):
        result = PasswordService.analyze_password("CorrectHorseBatteryStaple!9")
        breakdown = result["score_breakdown"]
        assert isinstance(breakdown, list)
        assert len(breakdown) >= 5
        for factor in breakdown:
            assert "factor" in factor
            assert "score" in factor
            assert "status" in factor
            assert factor["status"] in ("good", "warning", "danger")

    def test_security_checklist_structure(self):
        result = PasswordService.analyze_password("CorrectHorseBatteryStaple!9")
        checklist = result["security_checklist"]
        assert isinstance(checklist, list)
        assert len(checklist) >= 6
        for item in checklist:
            assert "item" in item
            assert "passed" in item
            assert "status" in item
            assert item["status"] in ("passed", "failed", "advisory")
            assert "details" in item
            if item["status"] == "advisory":
                assert item["passed"] is None
            else:
                assert isinstance(item["passed"], bool)

    def test_advisory_items_are_not_reported_as_passed(self):
        result = PasswordService.analyze_password("CorrectHorseBatteryStaple!9")
        checklist = result["security_checklist"]
        advisory = [item for item in checklist if item["status"] == "advisory"]
        advisory_items = {
            "Use a unique password for each account",
            "Consider using a password manager",
            "Enable multi-factor authentication (MFA)",
        }
        assert {item["item"] for item in advisory} == advisory_items
        assert all(item["passed"] is None for item in advisory)
        assert not any(item["status"] == "passed" for item in advisory)
        for item in advisory:
            assert "cannot" in item["details"].lower() or "Recommendation" in item["details"]

    def test_existing_behavior_compatible(self):
        # Ensure all existing fields are still present
        result = PasswordService.analyze_password("Tr0ub4dor&3xample!Secure")
        assert "length" in result
        assert "char_classes" in result
        assert "uppercase" in result
        assert "lowercase" in result
        assert "digits" in result
        assert "special" in result
        assert "classes_used" in result
        assert "entropy_bits" in result
        assert "crack_time_estimate" in result
        assert "in_common_list" in result
        assert "strength_score" in result
        assert "strength" in result
        assert "recommendations" in result

    def test_plaintext_never_persisted(self, fake_supabase):
        secret = "S3cr3t!Pa55word"
        PasswordService.analyze_password(secret, user_id="33333333-3333-4333-8333-333333333333")
        payload = fake_supabase.inserts["password_scans"][-1]
        assert secret not in str(payload)
        assert "hash" not in payload
        assert "bcrypt" not in str(payload).lower()


class TestPasswordEndpoint:
    def test_analyze_password_endpoint(self, client, auth_headers):
        response = client.post(
            "/api/password/analyze",
            json={"password": "CorrectHorseBatteryStaple!9"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        data = body["data"]
        assert "strength" in data
        assert "entropy_bits" in data
        assert "recommendations" in data

    def test_missing_password(self, client, auth_headers):
        response = client.post("/api/password/analyze", json={}, headers=auth_headers)
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"

    def test_password_too_long(self, client, auth_headers):
        response = client.post(
            "/api/password/analyze", json={"password": "x" * 100}, headers=auth_headers
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"

    def test_non_string_password(self, client, auth_headers):
        response = client.post(
            "/api/password/analyze", json={"password": 12345}, headers=auth_headers
        )
        assert response.status_code == 400

    @pytest.mark.parametrize("payload", [
        None,
        "not a dict",
        {"password": None},
    ])
    def test_invalid_payloads(self, client, auth_headers, payload):
        response = client.post("/api/password/analyze", json=payload, headers=auth_headers)
        assert response.status_code == 400


class TestPasswordPersistence:
    USER_ID = "33333333-3333-4333-8333-333333333333"

    def test_persists_completed_scan(self, fake_supabase):
        result = PasswordService.analyze_password(
            "Tr0ub4dor&3xample!Secure", user_id=self.USER_ID
        )
        payload = fake_supabase.inserts["password_scans"][-1]
        assert payload["user_id"] == self.USER_ID
        assert payload["password_length"] == result["length"]
        assert payload["entropy"] == result["entropy_bits"]
        assert payload["strength_score"] == result["strength_score"]
        assert payload["strength_label"] == result["strength"]
        assert payload["has_upper"] == result["uppercase"]
        assert payload["has_lower"] == result["lowercase"]
        assert payload["has_number"] == result["digits"]
        assert payload["has_symbol"] == result["special"]
        assert payload["breached"] == result["in_common_list"]
        assert set(payload) == {
            "user_id", "password_length", "entropy", "strength_score",
            "strength_label", "has_upper", "has_lower", "has_number",
            "has_symbol", "breached",
        }

    def test_persists_weak_breached_password(self, fake_supabase):
        result = PasswordService.analyze_password("password", user_id=self.USER_ID)
        payload = fake_supabase.inserts["password_scans"][-1]
        assert payload["breached"] is True
        assert payload["strength_label"] == "Weak"

    def test_never_stores_plaintext_password_or_hash(self, fake_supabase):
        secret = "S3cr3t!Pa55word"
        PasswordService.analyze_password(secret, user_id=self.USER_ID)
        payload = fake_supabase.inserts["password_scans"][-1]
        assert secret not in str(payload)
        assert "hash" not in payload
        assert "bcrypt" not in str(payload).lower()

    def test_skips_persistence_without_user(self, fake_supabase):
        result = PasswordService.analyze_password("CorrectHorseBatteryStaple!9")
        assert result["strength_score"] is not None
        assert "password_scans" not in fake_supabase.inserts

    def test_skips_persistence_when_client_unconfigured(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.password_service.get_user_supabase_client", lambda access_token=None: None
        )
        result = PasswordService.analyze_password(
            "CorrectHorseBatteryStaple!9", user_id=self.USER_ID
        )
        assert result["strength_score"] is not None

    def test_database_failure_raises_service_unavailable(self, fake_supabase):
        fake_supabase.fail_next_execute = True
        with pytest.raises(ServiceUnavailableError):
            PasswordService.analyze_password(
                "CorrectHorseBatteryStaple!9", user_id=self.USER_ID
            )

    def test_persistence_preserves_analysis_result(self, fake_supabase):
        password = "CorrectHorseBatteryStaple!9"
        result = PasswordService.analyze_password(password, user_id=self.USER_ID)
        assert result["length"] == len(password)
        assert result["entropy_bits"] > 0
        assert result["strength"] in {"Weak", "Fair", "Good", "Strong"}
        assert "recommendations" in result
        assert result["in_common_list"] is False


class TestPasswordPersistenceEndpoint:
    def test_analyze_endpoint_persists_scan(
        self, client, auth_headers, fake_supabase, auth_user_id
    ):
        response = client.post(
            "/api/password/analyze",
            json={"password": "CorrectHorseBatteryStaple!9"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        payload = fake_supabase.inserts["password_scans"][-1]
        assert payload["user_id"] == auth_user_id
        assert payload["password_length"] == len("CorrectHorseBatteryStaple!9")
        assert payload["has_upper"] is True
        assert payload["has_lower"] is True
        assert payload["has_number"] is True
        assert payload["has_symbol"] is True
        assert payload["breached"] is False
        assert "password" not in payload

    def test_analyze_endpoint_ignores_user_id_from_body(
        self, client, auth_headers, auth_user_id, fake_supabase
    ):
        response = client.post(
            "/api/password/analyze",
            json={
                "password": "CorrectHorseBatteryStaple!9",
                "user_id": "99999999-9999-4999-8999-999999999999",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        payload = fake_supabase.inserts["password_scans"][-1]
        assert payload["user_id"] == auth_user_id

    def test_analyze_endpoint_database_failure_returns_503(
        self, client, auth_headers, fake_supabase
    ):
        fake_supabase.fail_next_execute = True
        response = client.post(
            "/api/password/analyze",
            json={"password": "CorrectHorseBatteryStaple!9"},
            headers=auth_headers,
        )
        assert response.status_code == 503
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "SERVICE_UNAVAILABLE"


class TestPasswordGenerator:
    def test_passphrase_default_words(self):
        result = PasswordGenerator.generate_passphrase()
        assert result["type"] == "passphrase"
        assert result["words"] == 5
        assert result["delimiter"] == "-"
        assert len(result["password"]) > 0
        assert result["password"].count("-") == 4

    def test_passphrase_custom_words(self):
        for words in [4, 5, 6]:
            result = PasswordGenerator.generate_passphrase(words=words)
            assert result["words"] == words
            assert result["password"].count("-") == words - 1

    def test_passphrase_custom_delimiter(self):
        result = PasswordGenerator.generate_passphrase(words=4, delimiter=".")
        assert result["delimiter"] == "."
        assert result["password"].count(".") == 3

    def test_passphrase_uniqueness(self):
        # Generate multiple passphrases and ensure they're different
        passphrases = set()
        for _ in range(20):
            result = PasswordGenerator.generate_passphrase(words=5)
            passphrases.add(result["password"])
        # With ~180 words and 5 words, collisions are extremely unlikely
        assert len(passphrases) == 20

    def test_passphrase_invalid_word_count(self):
        with pytest.raises(ValueError):
            PasswordGenerator.generate_passphrase(words=3)
        with pytest.raises(ValueError):
            PasswordGenerator.generate_passphrase(words=7)

    def test_random_password_default_length(self):
        result = PasswordGenerator.generate_random_password()
        assert result["type"] == "random"
        assert result["length"] == 20
        assert len(result["password"]) == 20

    def test_random_password_custom_length(self):
        for length in [8, 16, 32, 64]:
            result = PasswordGenerator.generate_random_password(length=length)
            assert result["length"] == length
            assert len(result["password"]) == length

    def test_random_password_variability(self):
        passwords = set()
        for _ in range(20):
            result = PasswordGenerator.generate_random_password(length=20)
            passwords.add(result["password"])
        assert len(passwords) == 20

    def test_random_password_invalid_length(self):
        with pytest.raises(ValueError):
            PasswordGenerator.generate_random_password(length=7)
        with pytest.raises(ValueError):
            PasswordGenerator.generate_random_password(length=65)

    def test_random_password_charset(self):
        result = PasswordGenerator.generate_random_password(length=64)
        # All characters should be from the allowed charset
        allowed = set(
            "abcdefghijkmnopqrstuvwxyz"
            "ABCDEFGHJKLMNPQRSTUVWXYZ"
            "23456789"
            "!@#$%^&*_-+=?"
        )
        assert all(c in allowed for c in result["password"])

    def test_generated_password_never_persisted(self, fake_supabase):
        # Generate passwords and verify they're not persisted
        passphrase = PasswordGenerator.generate_passphrase(words=5)
        random_pwd = PasswordGenerator.generate_random_password(length=20)
        
        # Neither should appear in any persisted data
        for table_data in fake_supabase.inserts.values():
            for row in table_data:
                assert passphrase["password"] not in str(row)
                assert random_pwd["password"] not in str(row)


class TestPasswordGenerationEndpoint:
    def test_generate_passphrase_endpoint(self, client, auth_headers):
        response = client.post(
            "/api/password/generate",
            json={"type": "passphrase", "words": 5},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        data = body["data"]
        assert data["type"] == "passphrase"
        assert data["words"] == 5
        assert "password" in data
        assert data["password"].count("-") == 4

    def test_generate_passphrase_custom_words(self, client, auth_headers):
        response = client.post(
            "/api/password/generate",
            json={"type": "passphrase", "words": 4},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        data = body["data"]
        assert data["words"] == 4
        assert data["password"].count("-") == 3

    def test_generate_random_password_endpoint(self, client, auth_headers):
        response = client.post(
            "/api/password/generate",
            json={"type": "random", "length": 20},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        data = body["data"]
        assert data["type"] == "random"
        assert data["length"] == 20
        assert len(data["password"]) == 20

    def test_generate_random_password_custom_length(self, client, auth_headers):
        response = client.post(
            "/api/password/generate",
            json={"type": "random", "length": 32},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        data = body["data"]
        assert data["length"] == 32
        assert len(data["password"]) == 32

    def test_generate_invalid_type(self, client, auth_headers):
        response = client.post(
            "/api/password/generate",
            json={"type": "invalid"},
            headers=auth_headers,
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"

    def test_generate_invalid_word_count(self, client, auth_headers):
        response = client.post(
            "/api/password/generate",
            json={"type": "passphrase", "words": 3},
            headers=auth_headers,
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"

    def test_generate_invalid_length(self, client, auth_headers):
        response = client.post(
            "/api/password/generate",
            json={"type": "random", "length": 7},
            headers=auth_headers,
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"

    def test_generate_missing_type(self, client, auth_headers):
        response = client.post(
            "/api/password/generate",
            json={"words": 5},
            headers=auth_headers,
        )
        assert response.status_code == 400
        body = response.get_json()
        assert body["success"] is False
        assert body["error"]["code"] == "VALIDATION_ERROR"

    def test_generate_requires_auth(self, client):
        response = client.post(
            "/api/password/generate",
            json={"type": "passphrase", "words": 5},
        )
        assert response.status_code == 401

    def test_generated_password_not_persisted(self, client, auth_headers, fake_supabase):
        response = client.post(
            "/api/password/generate",
            json={"type": "passphrase", "words": 5},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        generated = body["data"]["password"]

        # Verify nothing was persisted
        assert "password_scans" not in fake_supabase.inserts
        # Or if it was called, the generated password is not in it
        for table_data in fake_supabase.inserts.values():
            for row in table_data:
                assert generated not in str(row)

    def test_existing_analysis_unchanged(self, client, auth_headers):
        # Ensure the analyze endpoint still works correctly
        response = client.post(
            "/api/password/analyze",
            json={"password": "CorrectHorseBatteryStaple!9"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["success"] is True
        data = body["data"]
        assert "strength" in data
        assert "entropy_bits" in data
        assert "weaknesses" in data
        assert "score_breakdown" in data
        assert "security_checklist" in data
