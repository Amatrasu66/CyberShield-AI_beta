"""Tests for the cryptography lab service and endpoints."""

import base64

import pytest

from app.services.crypto_service import CryptoService


class TestHash:
    def test_sha256_known_vector(self):
        result = CryptoService.hash_text("hello", "sha256")
        assert result["operation"] == "hash"
        assert result["algorithm"] == "sha256"
        assert result["digest"] == (
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert result["reversible"] is False

    def test_sha512_digest_length(self):
        result = CryptoService.hash_text("x", "sha512")
        assert result["digest_length_bits"] == 512

    def test_deprecated_algorithms_warned(self):
        md5 = CryptoService.hash_text("x", "md5")
        sha1 = CryptoService.hash_text("x", "sha1")
        assert md5["warning"] is not None
        assert sha1["warning"] is not None

    def test_unsupported_algorithm_rejected(self):
        with pytest.raises(Exception) as exc:
            CryptoService.hash_text("x", "crc32")
        assert exc.value.status_code == 400


class TestEncryptDecrypt:
    def test_round_trip(self):
        payload = CryptoService.encrypt_text("secret message", "a-strong-passphrase-9")
        decrypted = CryptoService.decrypt_text(
            payload["ciphertext"],
            "a-strong-passphrase-9",
            payload["salt"],
            payload["nonce"],
            payload["tag"],
        )
        assert decrypted["plaintext"] == "secret message"
        assert payload["operation"] == "encrypt"
        assert payload["algorithm"] == "AES-256-GCM"

    def test_wrong_passphrase_fails(self):
        payload = CryptoService.encrypt_text("secret", "a-strong-passphrase-9")
        with pytest.raises(Exception) as exc:
            CryptoService.decrypt_text(
                payload["ciphertext"],
                "wrong-passphrase!",
                payload["salt"],
                payload["nonce"],
                payload["tag"],
            )
        assert exc.value.status_code == 400

    def test_short_passphrase_rejected(self):
        with pytest.raises(Exception) as exc:
            CryptoService.encrypt_text("hi", "short")
        assert exc.value.status_code == 400

    def test_ciphertext_is_encrypted(self):
        payload = CryptoService.encrypt_text("my very secret data", "a-strong-passphrase-9")
        assert payload["ciphertext"] != base64.b64encode(b"my very secret data").decode()

    def test_encryption_nondeterministic(self):
        a = CryptoService.encrypt_text("same", "a-strong-passphrase-9")
        b = CryptoService.encrypt_text("same", "a-strong-passphrase-9")
        assert a["ciphertext"] != b["ciphertext"]


class TestEncodeDecode:
    def test_base64_round_trip(self):
        encoded = CryptoService.encode("hello world", "base64")
        decoded = CryptoService.decode(encoded["encoded"], "base64")
        assert decoded["decoded"] == "hello world"

    def test_hex_round_trip(self):
        encoded = CryptoService.encode("hello", "hex")
        decoded = CryptoService.decode(encoded["encoded"], "hex")
        assert decoded["decoded"] == "hello"

    def test_invalid_base64_rejected(self):
        with pytest.raises(Exception) as exc:
            CryptoService.decode("###not-base64###", "base64")
        assert exc.value.status_code == 400


class TestCryptoEndpoints:
    def test_hash_endpoint(self, client, auth_headers):
        response = client.post(
            "/api/crypto/hash", json={"text": "abc", "algorithm": "sha256"}, headers=auth_headers
        )
        assert response.status_code == 200
        assert response.get_json()["data"]["digest_length_bits"] == 256

    def test_encrypt_decrypt_endpoint_round_trip(self, client, auth_headers):
        enc = client.post(
            "/api/crypto/encrypt",
            json={"plaintext": "secret", "passphrase": "a-strong-passphrase-9"},
            headers=auth_headers,
        )
        assert enc.status_code == 200
        payload = enc.get_json()["data"]
        dec = client.post("/api/crypto/decrypt", json={
            "ciphertext": payload["ciphertext"],
            "passphrase": "a-strong-passphrase-9",
            "salt": payload["salt"],
            "nonce": payload["nonce"],
            "tag": payload["tag"],
        }, headers=auth_headers)
        assert dec.status_code == 200
        assert dec.get_json()["data"]["plaintext"] == "secret"

    def test_encrypt_requires_passphrase(self, client, auth_headers):
        response = client.post(
            "/api/crypto/encrypt",
            json={"plaintext": "hi", "passphrase": "short"},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_hash_unknown_algorithm(self, client, auth_headers):
        response = client.post(
            "/api/crypto/hash", json={"text": "x", "algorithm": "nope"}, headers=auth_headers
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"

    def test_encode_endpoint(self, client, auth_headers):
        response = client.post(
            "/api/crypto/encode", json={"text": "hello", "encoding": "base64"}, headers=auth_headers
        )
        assert response.status_code == 200
        assert response.get_json()["data"]["encoded"] == "aGVsbG8="

    def test_decode_endpoint(self, client, auth_headers):
        response = client.post(
            "/api/crypto/decode", json={"text": "aGVsbG8=", "encoding": "base64"}, headers=auth_headers
        )
        assert response.status_code == 200
        assert response.get_json()["data"]["decoded"] == "hello"

    def test_decode_invalid_input(self, client, auth_headers):
        response = client.post(
            "/api/crypto/decode", json={"text": "!!invalid!!", "encoding": "base64"}, headers=auth_headers
        )
        assert response.status_code == 400
