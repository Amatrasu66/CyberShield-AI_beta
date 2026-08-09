"""
Cryptography Lab Service.

Educational cryptography operations only:

- Hashing: one-way digests (SHA-256, SHA-512, and deprecated SHA-1/MD5).
- Encryption / Decryption: symmetric AES-256-GCM with a passphrase-derived key.
- Encoding / Decoding: base64 and hex (not security mechanisms; for study).

The operations are intentionally isolated and sized-limited. No secrets are
logged or stored. The module is structured so additional algorithms can be
added without changing the API contract.
"""

import base64
import binascii
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..errors import ValidationError

PBKDF2_ITERATIONS = 600_000
AES_KEY_LENGTH = 32  # AES-256
GCM_NONCE_LENGTH = 12
SALT_LENGTH = 16

HASH_ALGORITHMS = {
    "md5": {"constructor": hashlib.md5, "deprecated": True},
    "sha1": {"constructor": hashlib.sha1, "deprecated": True},
    "sha256": {"constructor": hashlib.sha256, "deprecated": False},
    "sha512": {"constructor": hashlib.sha512, "deprecated": False},
}

ENCODINGS = ("base64", "hex")


class CryptoService:
    """Educational cryptography operations. All methods are deterministic except
    where cryptographic randomness is required (salt/nonce for encryption)."""

    # ------------------------------------------------------------------ Hashing
    @staticmethod
    def hash_text(text: str, algorithm: str) -> dict:
        """Return a one-way digest of ``text``."""
        if algorithm not in HASH_ALGORITHMS:
            raise ValidationError(
                f"Unsupported hash algorithm '{algorithm}'. "
                f"Supported: {', '.join(sorted(HASH_ALGORITHMS))}",
                details={"field": "algorithm"},
            )
        digest = HASH_ALGORITHMS[algorithm]["constructor"](text.encode("utf-8")).hexdigest()
        return {
            "operation": "hash",
            "algorithm": algorithm,
            "digest": digest,
            "digest_length_bits": len(digest) * 4,
            "reversible": False,
            "warning": (
                "Deprecated: do not use for new systems."
                if HASH_ALGORITHMS[algorithm]["deprecated"]
                else None
            ),
        }

    # -------------------------------------------------------- Encryption/decryption
    @staticmethod
    def encrypt_text(plaintext: str, passphrase: str) -> dict:
        """Encrypt ``plaintext`` with AES-256-GCM using a derived key."""
        _validate_passphrase(passphrase)
        salt = os.urandom(SALT_LENGTH)
        nonce = os.urandom(GCM_NONCE_LENGTH)
        key = _derive_key(passphrase, salt)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        tag = ciphertext[-16:]
        ct_body = ciphertext[:-16]
        return {
            "operation": "encrypt",
            "algorithm": "AES-256-GCM",
            "key_derivation": f"PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS} iterations)",
            "ciphertext": _b64(ct_body),
            "salt": _b64(salt),
            "nonce": _b64(nonce),
            "tag": _b64(tag),
            "reversible": True,
            "note": "Keep the passphrase, salt, nonce, and tag to decrypt.",
        }

    @staticmethod
    def decrypt_text(ciphertext_b64: str, passphrase: str, salt_b64: str, nonce_b64: str, tag_b64: str) -> dict:
        """Decrypt an AES-256-GCM payload produced by :meth:`encrypt_text`."""
        _validate_passphrase(passphrase)
        try:
            ct_body = base64.b64decode(ciphertext_b64, validate=True)
            salt = base64.b64decode(salt_b64, validate=True)
            nonce = base64.b64decode(nonce_b64, validate=True)
            tag = base64.b64decode(tag_b64, validate=True)
        except (binascii.Error, ValueError):
            raise ValidationError("Encrypted payload fields must be valid base64", details={"field": "ciphertext"})

        if len(salt) != SALT_LENGTH or len(nonce) != GCM_NONCE_LENGTH:
            raise ValidationError("Invalid salt or nonce length", details={"field": "ciphertext"})

        key = _derive_key(passphrase, salt)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ct_body + tag, None)
        except InvalidTag:
            raise ValidationError("Decryption failed: incorrect passphrase or corrupted data")
        except Exception:
            raise ValidationError("Decryption failed: malformed encrypted payload")

        return {
            "operation": "decrypt",
            "algorithm": "AES-256-GCM",
            "plaintext": plaintext.decode("utf-8", errors="replace"),
            "reversible": True,
        }

    # ------------------------------------------------------------- Encoding
    @staticmethod
    def encode(data: str, encoding: str) -> dict:
        """Encode text using base64 or hex (educational)."""
        _validate_encoding(encoding)
        raw = data.encode("utf-8")
        if encoding == "base64":
            encoded = base64.b64encode(raw).decode("ascii")
        else:
            encoded = raw.hex()
        return {
            "operation": "encode",
            "encoding": encoding,
            "encoded": encoded,
            "note": "Encoding is not encryption; it provides no secrecy.",
        }

    @staticmethod
    def decode(data: str, encoding: str) -> dict:
        """Decode base64 or hex back to text (educational)."""
        _validate_encoding(encoding)
        try:
            if encoding == "base64":
                raw = base64.b64decode(data.encode("ascii"), validate=True)
            else:
                raw = bytes.fromhex(data)
        except (binascii.Error, ValueError):
            raise ValidationError(
                f"Invalid {encoding} input; could not decode", details={"field": "data"}
            )
        return {
            "operation": "decode",
            "encoding": encoding,
            "decoded": raw.decode("utf-8", errors="replace"),
            "note": "Decoding reveals the original bytes; it is not decryption.",
        }


def _validate_passphrase(passphrase):
    if not isinstance(passphrase, str) or len(passphrase) < 8:
        raise ValidationError("Passphrase must be at least 8 characters", details={"field": "passphrase"})


def _validate_encoding(encoding):
    if encoding not in ENCODINGS:
        raise ValidationError(
            f"Unsupported encoding '{encoding}'. Supported: {', '.join(ENCODINGS)}",
            details={"field": "encoding"},
        )


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
