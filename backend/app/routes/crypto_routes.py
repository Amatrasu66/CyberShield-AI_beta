"""
Cryptography Lab Routes.

POST /api/crypto/hash
POST /api/crypto/encrypt
POST /api/crypto/decrypt
POST /api/crypto/encode
POST /api/crypto/decode
"""

from flask import Blueprint

from ..services import CryptoService
from ..utils.helpers import success_response
from ..utils.validators import require_json, validate_string

crypto_bp = Blueprint("crypto", __name__)


def _crypto_max():
    from flask import current_app

    return current_app.config.get("CRYPTO_MAX_INPUT_LENGTH", 100_000)


@crypto_bp.post("/hash")
def hash_text():
    data = require_json()
    text = data.get("text")
    algorithm = data.get("algorithm", "sha256")
    validate_string(text, "text", _crypto_max(), min_length=1)
    validate_string(algorithm, "algorithm", 32, min_length=1)
    result = CryptoService.hash_text(text, algorithm)
    return success_response(result, "Hash computed")


@crypto_bp.post("/encrypt")
def encrypt_text():
    data = require_json()
    plaintext = data.get("plaintext")
    passphrase = data.get("passphrase")
    validate_string(plaintext, "plaintext", _crypto_max(), min_length=1)
    validate_string(passphrase, "passphrase", _crypto_max())
    result = CryptoService.encrypt_text(plaintext, passphrase)
    return success_response(result, "Encryption completed")


@crypto_bp.post("/decrypt")
def decrypt_text():
    data = require_json()
    ciphertext = data.get("ciphertext")
    passphrase = data.get("passphrase")
    salt = data.get("salt")
    nonce = data.get("nonce")
    tag = data.get("tag")
    for field in ("ciphertext", "passphrase", "salt", "nonce", "tag"):
        validate_string(data.get(field), field, _crypto_max())
    result = CryptoService.decrypt_text(ciphertext, passphrase, salt, nonce, tag)
    return success_response(result, "Decryption completed")


@crypto_bp.post("/encode")
def encode_text():
    data = require_json()
    text = data.get("text")
    encoding = data.get("encoding", "base64")
    validate_string(text, "text", _crypto_max(), min_length=1)
    validate_string(encoding, "encoding", 16, min_length=1)
    result = CryptoService.encode(text, encoding)
    return success_response(result, "Encoding completed")


@crypto_bp.post("/decode")
def decode_text():
    data = require_json()
    text = data.get("text")
    encoding = data.get("encoding", "base64")
    validate_string(text, "text", _crypto_max(), min_length=1)
    validate_string(encoding, "encoding", 16, min_length=1)
    result = CryptoService.decode(text, encoding)
    return success_response(result, "Decoding completed")
