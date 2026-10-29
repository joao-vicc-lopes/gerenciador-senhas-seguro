"""Cryptographic helpers. No external requests or remote processing."""
import base64
import hashlib
import hmac
import json

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROUNDS = 480_000
VERIFICATION = b"AUTENTICADO"


class VaultCorruptedError(ValueError):
    """The vault file contains malformed or unauthenticated data."""


def derive_key(password: str, salt: bytes) -> bytes:
    if len(salt) != 16:
        raise VaultCorruptedError("Invalid salt length")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ROUNDS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def record_id(key: bytes, site: str) -> str:
    """Opaque deterministic keyed index; site names are not exposed in the JSON."""
    raw_key = base64.urlsafe_b64decode(key)
    return hmac.new(raw_key, b"vault-record-index-v3\0" + site.encode("utf-8"), hashlib.sha256).hexdigest()


def encrypt_record(engine: Fernet, site: str, login: str, secret: str) -> str:
    payload = json.dumps({"site": site, "login": login, "senha": secret}, ensure_ascii=False).encode("utf-8")
    return engine.encrypt(payload).decode("ascii")


def decrypt_record(engine: Fernet, key: bytes, index: str, token: str) -> dict:
    try:
        result = json.loads(engine.decrypt(token.encode("ascii")).decode("utf-8"))
        if (not isinstance(result, dict) or set(result) != {"site", "login", "senha"}
                or not all(isinstance(v, str) for v in result.values())
                or record_id(key, result["site"]) != index):
            raise VaultCorruptedError("Invalid or misplaced credential")
        return result
    except (InvalidToken, UnicodeError, TypeError, KeyError, ValueError) as exc:
        raise VaultCorruptedError("Invalid encrypted credential") from exc


def check_master_strength(password: str) -> bool:
    """Offline basic policy, not a breached-password database check."""
    value = password.casefold()
    return (len(password) >= 12 and not password.isspace()
            and not any(p in value for p in ("password", "123456", "qwerty", "senha123"))
            and len(set(value)) > 3)