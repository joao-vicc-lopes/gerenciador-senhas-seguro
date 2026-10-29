"""Vault business logic: format migration, transaction boundaries, recovery."""
import base64
import json
import os
from pathlib import Path
import time
from contextlib import contextmanager

from cryptography.fernet import Fernet, InvalidToken
from .crypto import (VERIFICATION, VaultCorruptedError, check_master_strength,
                     decrypt_record, derive_key, encrypt_record, record_id)
from . import storage


class VaultService:
    def __init__(self, vault_path: str, salt_path: str, trace=None):
        self.path, self.salt_path = str(vault_path), str(salt_path)
        self.trace = trace or (lambda stage, ms: None)

    @contextmanager
    def _timed_lock(self, exclusive=False):
        start = time.perf_counter_ns()
        with storage.locked(self.path, exclusive):
            self.trace("lock_wait", (time.perf_counter_ns() - start) / 1e6)
            yield

    def _read_salt(self):
        salt = Path(self.salt_path).read_bytes()
        if len(salt) != 16:
            raise VaultCorruptedError("Invalid salt length")
        return salt

    @staticmethod
    def _verify(data, engine):
        try:
            if engine.decrypt(data["STATUS"].encode("ascii")) != VERIFICATION:
                raise VaultCorruptedError("Verification failed")
        except (InvalidToken, KeyError, ValueError, TypeError, UnicodeError) as exc:
            raise VaultCorruptedError("Wrong master password or corrupted vault") from exc

    @classmethod
    def _legacy_records(cls, data, engine):
        """Decrypt the entire v1/v2 collection only when migrating old formats."""
        try:
            if data.get("__FORMAT_VERSION__") == 2:
                entries = json.loads(engine.decrypt(data["__VAULT_DATA__"].encode("ascii")).decode("utf-8"))
            else:
                entries = {}
                for site, record in data.items():
                    if site == "STATUS":
                        continue
                    entries[site] = {"login": record["login"],
                                     "senha": engine.decrypt(record["senha"].encode("ascii")).decode("utf-8")}
            if not isinstance(entries, dict):
                raise VaultCorruptedError("Invalid legacy collection")
            for site, record in entries.items():
                if (not isinstance(site, str) or not isinstance(record, dict)
                    or not isinstance(record.get("login"), str) or not isinstance(record.get("senha"), str)):
                    raise VaultCorruptedError("Invalid legacy credential")
            return entries
        except (InvalidToken, ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise VaultCorruptedError("Legacy records are corrupt") from exc

    @classmethod
    def _to_v3(cls, data, engine, key):
        if data.get("__FORMAT_VERSION__") == 3:
            return dict(data["__RECORDS__"])
        old = cls._legacy_records(data, engine)
        return {record_id(key, site): encrypt_record(engine, site, entry["login"], entry["senha"])
                for site, entry in old.items()}

    @classmethod
    def _validate_all(cls, data, engine, key):
        cls._verify(data, engine)
        if data.get("__FORMAT_VERSION__") == 3:
            for index, token in data["__RECORDS__"].items():
                decrypt_record(engine, key, index, token)
        else:
            cls._legacy_records(data, engine)

    def create(self, password: str) -> bool:
        if not check_master_strength(password):
            raise ValueError("Choose 12+ characters, avoid common passwords and repetition")
        with self._timed_lock(exclusive=True):
            existing = (os.path.exists(self.path), os.path.exists(self.salt_path))
            if all(existing):
                return False
            if any(existing):
                raise VaultCorruptedError("Vault or salt is missing; refusing overwrite")
            salt = os.urandom(16)
            key = derive_key(password, salt)
            engine = Fernet(key)
            data = {"STATUS": engine.encrypt(VERIFICATION).decode("ascii"),
                    "__FORMAT_VERSION__": 3, "__RECORDS__": {}}
            made_salt = False
            try:
                storage.write_salt_exclusive(self.salt_path, salt)
                made_salt = True
                storage.atomic_json(self.path, data)
            except BaseException:
                if made_salt and not os.path.exists(self.path):
                    os.unlink(self.salt_path)
                raise
            return True

    def authenticate(self, password: str) -> bytes:
        with self._timed_lock():
            key = derive_key(password, self._read_salt())
            data = storage.read_json(self.path)
            self._verify(data, Fernet(key))
            # In v3 only a record-specific decrypt is necessary at lookup time.
            if data.get("__FORMAT_VERSION__") != 3:
                self._legacy_records(data, Fernet(key))
            return key

    def add(self, key: bytes, site: str, login: str, secret: str) -> None:
        if (not isinstance(site, str) or not site.strip() or site == "STATUS"
                or not isinstance(login, str) or not isinstance(secret, str)):
            raise ValueError("Invalid credential fields")
        with self._timed_lock(exclusive=True):
            t0 = time.perf_counter_ns()
            raw = Path(self.path).read_bytes()
            data = storage.read_json(self.path)
            salt = self._read_salt()
            engine = Fernet(key)
            self._verify(data, engine)
            self.trace("read_validate", (time.perf_counter_ns() - t0) / 1e6)
            t0 = time.perf_counter_ns()
            entries = self._to_v3(data, engine, key)
            index = record_id(key, site)
            if index in entries:
                decrypt_record(engine, key, index, entries[index])  # reject corrupt target
            self.trace("decrypt_migrate", (time.perf_counter_ns() - t0) / 1e6)
            t0 = time.perf_counter_ns()
            entries[index] = encrypt_record(engine, site, login, secret)
            new_data = {"STATUS": data["STATUS"], "__FORMAT_VERSION__": 3, "__RECORDS__": entries}
            self.trace("encrypt_record", (time.perf_counter_ns() - t0) / 1e6)
            t0 = time.perf_counter_ns()
            storage.write_backup(self.path, salt, raw)
            self.trace("backup_fsync", (time.perf_counter_ns() - t0) / 1e6)
            t0 = time.perf_counter_ns()
            storage.atomic_json(self.path, new_data)
            self.trace("vault_fsync", (time.perf_counter_ns() - t0) / 1e6)

    def get(self, key: bytes, site: str) -> dict | None:
        with self._timed_lock():
            data = storage.read_json(self.path)
            engine = Fernet(key)
            self._verify(data, engine)
            if data.get("__FORMAT_VERSION__") == 3:
                idx = record_id(key, site)
                token = data["__RECORDS__"].get(idx)
                return decrypt_record(engine, key, idx, token) if token is not None else None
            credentials = self._legacy_records(data, engine)
            old = credentials.get(site)
            return {"site": site, **old} if old else None

    def recover(self, password: str) -> None:
        """Explicit, authenticated rollback to previous commit; never auto-restores."""
        with self._timed_lock(exclusive=True):
            salt, raw = storage.read_backup(self.path)
            # Do not trust backup envelope or only the token: validate every record.
            parsed = json.loads(raw.decode("utf-8"))
            if not isinstance(parsed, dict) or not isinstance(parsed.get("STATUS"), str):
                raise VaultCorruptedError("Invalid backup vault")
            # Reuse strict format validation from a sandbox by inspecting the structure.
            if parsed.get("__FORMAT_VERSION__") == 3:
                if (set(parsed) != {"STATUS", "__FORMAT_VERSION__", "__RECORDS__"}
                        or not isinstance(parsed["__RECORDS__"], dict)):
                    raise VaultCorruptedError("Malformed backup records")
            elif parsed.get("__FORMAT_VERSION__") == 2:
                if not isinstance(parsed.get("__VAULT_DATA__"), str):
                    raise VaultCorruptedError("Malformed v2 backup")
            elif parsed.get("__FORMAT_VERSION__") is not None:
                raise VaultCorruptedError("Invalid backup version")
            key = derive_key(password, salt)
            self._validate_all(parsed, Fernet(key), key)
            # Restore salt first, then vault; the original backup is never touched.
            if not Path(self.salt_path).exists() or Path(self.salt_path).read_bytes() != salt:
                storage.restore_bytes(self.salt_path, salt)
            storage.restore_bytes(self.path, raw)