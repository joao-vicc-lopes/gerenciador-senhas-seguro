"""POSIX filesystem synchronization, encrypted backup snapshots, and recovery.

A separate stable lock file is used because locking the replaced vault inode
would not protect later readers/writers. Requires fcntl (Linux/macOS).
"""
from contextlib import contextmanager
import base64
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time

from .crypto import VaultCorruptedError


@contextmanager
def locked(vault_path: str, exclusive: bool = False):
    path = Path(vault_path + ".lock")
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fp:
        result = json.load(fp)
    if not isinstance(result, dict) or not isinstance(result.get("STATUS"), str):
        raise VaultCorruptedError("Missing or invalid STATUS")
    version = result.get("__FORMAT_VERSION__")
    if version == 3:
        if set(result) != {"STATUS", "__FORMAT_VERSION__", "__RECORDS__"} or not isinstance(result["__RECORDS__"], dict):
            raise VaultCorruptedError("Malformed v3 vault")
        if any(not isinstance(k, str) or len(k) != 64 or any(ch not in "0123456789abcdef" for ch in k)
               or not isinstance(v, str) for k, v in result["__RECORDS__"].items()):
            raise VaultCorruptedError("Invalid v3 record envelope")
    elif version == 2:
        if set(result) != {"STATUS", "__FORMAT_VERSION__", "__VAULT_DATA__"} or not isinstance(result["__VAULT_DATA__"], str):
            raise VaultCorruptedError("Malformed v2 vault")
    elif version is not None:
        raise VaultCorruptedError("Unsupported vault version")
    return result


def sync_directory(parent: Path) -> None:
    """Durably persist a rename on Linux where directory fsync is supported."""
    fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path: str, value: dict) -> None:
    target = Path(path)
    temp = None
    try:
        fd, temp = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=target.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(value, fp, indent=2, ensure_ascii=False)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temp, target)
        temp = None
        sync_directory(target.parent)
    finally:
        if temp is not None:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass


def write_salt_exclusive(path: str, salt: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as fp:
        fp.write(salt)
        fp.flush()
        os.fsync(fp.fileno())
    sync_directory(Path(path).parent)


def write_backup(path: str, salt: bytes, original: bytes) -> None:
    """Previous committed vault state and its salt, sealed within a private backup file.

    Vault content is already encrypted; backup contains no plaintext credentials.
    """
    payload = {"backup_format": 1, "salt": base64.b64encode(salt).decode("ascii"),
               "vault": base64.b64encode(original).decode("ascii")}
    atomic_json(path + ".bak", payload)


def read_backup(path: str) -> tuple[bytes, bytes]:
    with open(path + ".bak", encoding="utf-8") as fp:
        backup = json.load(fp)
    if not isinstance(backup, dict) or set(backup) != {"backup_format", "salt", "vault"} or backup["backup_format"] != 1:
        raise VaultCorruptedError("Invalid backup envelope")
    try:
        salt = base64.b64decode(backup["salt"], validate=True)
        vault = base64.b64decode(backup["vault"], validate=True)
        if len(salt) != 16:
            raise VaultCorruptedError("Invalid backup salt")
        return salt, vault
    except (TypeError, ValueError) as exc:
        raise VaultCorruptedError("Invalid backup data") from exc


def restore_bytes(path: str, raw: bytes) -> None:
    """Atomic bytes replacement, used only after full backup validation."""
    target = Path(path)
    temp = None
    try:
        fd, temp = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=target.parent)
        with os.fdopen(fd, "wb") as fp:
            fp.write(raw)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temp, target)
        temp = None
        sync_directory(target.parent)
    finally:
        if temp is not None:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass